#![feature(core_intrinsics)]
use crate::arch::MachDep;
use crate::budget::{Budget, BudgetManager, ProcType};
use crate::debug::{DebugManager, DebugManagerInitError};
use crate::dmem::DmemManager;
use crate::ee::{native, EntryArg, RawFn};
use crate::errno::EEXIST;
use crate::errno::EINVAL;
use crate::evf::EvfManager;
use crate::fs::{Fs, FsInitError, MkdirError, MountError, MountFlags, MountOpts, VPath};
use crate::gc::GcManager;
use crate::hid::HidManager;
use crate::ipmi::IpmiManager;
use crate::kqueue::KernelQueueManager;
use crate::log::{print, LOGGER};
use crate::memory::{MemoryManager, MemoryManagerError};
use crate::namedobj::NamedObjManager;
use crate::net::NetManager;
use crate::osem::OsemManager;
use crate::process::{VProc, VProcInitError, VThread};
use crate::regmgr::RegMgr;
use crate::rng::RngManager;
use crate::rtld::{LoadFlags, ModuleFlags, RuntimeLinker};
use crate::shm::SharedMemoryManager;
use crate::syscalls::Syscalls;
use crate::sysctl::Sysctl;
use crate::time::TimeManager;
use crate::tty::{TtyInitError, TtyManager};
use crate::ucred::{AuthAttrs, AuthCaps, AuthInfo, AuthPaid, Gid, Ucred, Uid};
use crate::umtx::UmtxManager;
use clap::{Parser, ValueEnum};
use gmtx::{Gutex, GutexGroup};
use hv::Hypervisor;
use libc::{memcpy, socket};
use llt::{OsThread, SpawnError};
use macros::vpath;
use param::Param;
use serde::Deserialize;
use std::borrow::{Borrow, BorrowMut};
use std::cell::{Cell, Ref, RefCell};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::error::Error;
use std::fs::{create_dir_all, remove_dir_all, File};
use std::io::Write;
use std::mem::size_of;
use std::ops::DerefMut;
use std::os::raw::c_void;
use std::path::PathBuf;
use std::process::{ExitCode, Termination};
use std::rc::Weak;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::SystemTime;
use syscalls::{SysErr, SysIn, SysOut};
use sysinfo::{MemoryRefreshKind, System};
use thiserror::Error;

mod arch;
mod arnd;
mod budget;
mod debug;
mod dmem;
mod ee;
mod errno;
mod evf;
mod fs;
mod gc;
mod hid;
mod idt;
mod ipmi;
mod kqueue;
mod log;
mod memory;
mod namedobj;
mod net;
mod osem;
mod process;
mod regmgr;
mod rng;
mod rtld;
mod shm;
mod signal;
mod syscalls;
mod sysctl;
mod time;
mod tty;
mod ucred;
mod umtx;

fn main() -> Exit {
    start().into()
}

fn start() -> Result<(), KernelError> {
    // Begin logger.
    log::init();

    // Load arguments.
    let args = if std::env::args().any(|a| a == "--debug") {
        let file = File::open(".kernel-debug").map_err(KernelError::FailedToOpenDebugConfig)?;

        serde_yaml::from_reader(file).map_err(KernelError::FailedToParseDebugConfig)?
    } else {
        Args::try_parse()?
    };

    // Initialize debug dump.
    if let Some(path) = &args.debug_dump {
        // Remove previous dump.
        if args.clear_debug_dump {
            if let Err(e) = remove_dir_all(path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    warn!(e, "Failed to remove {}", path.display());
                }
            }
        }

        // Create a directory.
        if let Err(e) = create_dir_all(path) {
            warn!(e, "Failed to create {}", path.display());
        }

        // Create log file for us.
        let log = path.join("obliteration.log");

        match File::create(&log) {
            Ok(v) => LOGGER.get().unwrap().set_file(v),
            Err(e) => warn!(e, "Failed to create {}", log.display()),
        }
    }

    // Get path to param.sfo.
    let mut path = args.game.join("sce_sys");

    path.push("param.sfo");

    // Open param.sfo.
    let param = File::open(&path).map_err(KernelError::FailedToOpenGameParam)?;

    // Load param.sfo.
    let param = Arc::new(Param::read(param)?);

    // Get auth info for the process.
    let auth =
        AuthInfo::from_title_id(param.title_id()).ok_or(KernelError::InvalidTitleId(path))?;

    // Show basic information.
    let mut log = info!();
    let mut hwinfo = System::new_with_specifics(
        sysinfo::RefreshKind::new()
            .with_memory(sysinfo::MemoryRefreshKind::new())
            .with_cpu(sysinfo::CpuRefreshKind::new()),
    );
    hwinfo.refresh_memory_specifics(MemoryRefreshKind::new().with_ram());

    // Init information
    writeln!(log, "Starting Obliteration Kernel.").unwrap();
    writeln!(log, "System directory    : {}", args.system.display()).unwrap();
    writeln!(log, "Game directory      : {}", args.game.display()).unwrap();

    if let Some(v) = &args.debug_dump {
        writeln!(log, "Debug dump directory: {}", v.display()).unwrap();
    }

    // Param information
    writeln!(log, "Application Title   : {}", param.title().unwrap()).unwrap();
    writeln!(log, "Application ID      : {}", param.title_id()).unwrap();
    writeln!(log, "Application Category: {}", param.category()).unwrap();
    writeln!(
        log,
        "Application Version : {}",
        param.app_ver().unwrap_or(&String::from("UNKNOWN"))
    )
    .unwrap();

    // Hardware information
    writeln!(
        log,
        "Operating System    : {} {}",
        System::long_os_version().unwrap_or_else(|| "Unknown OS".to_string()),
        if cfg!(target_os = "windows") {
            System::kernel_version().unwrap_or_else(|| "Unknown Kernel".to_string())
        } else {
            "".to_string()
        }
    )
    .unwrap();
    writeln!(log, "CPU Information     : {}", hwinfo.cpus()[0].brand()).unwrap();
    writeln!(
        log,
        "Memory Available    : {}/{} MB",
        hwinfo.available_memory() / 1048576,
        hwinfo.total_memory() / 1048576
    )
    .unwrap();
    writeln!(log, "Pro mode            : {}", args.pro).unwrap();

    print(log);

    // Setup kernel credential.
    let cred = Arc::new(Ucred::new(
        Uid::ROOT,
        Uid::ROOT,
        vec![Gid::ROOT],
        AuthInfo {
            paid: AuthPaid::KERNEL,
            caps: AuthCaps::new([0x4000000000000000, 0, 0, 0]),
            attrs: AuthAttrs::new([0, 0, 0, 0]),
            unk: [0; 64],
        },
    ));

    // Initialize foundations.
    let mut syscalls = Syscalls::new();
    let fs = Fs::new(args.system, &cred, &mut syscalls)?;

    // TODO: Check permission of /mnt on the PS4.
    let path = vpath!("/mnt");

    if let Err(e) = fs.mkdir(path, 0o555, None) {
        match e {
            MkdirError::CreateFailed(e) if e.errno() == EEXIST => {}
            e => return Err(KernelError::CreateDirectoryFailed(path, e)),
        }
    }

    // TODO: Get mount options from the PS4.
    let mut opts = MountOpts::new();

    opts.insert("fstype", "tmpfs");
    opts.insert("fspath", path.to_owned());

    if let Err(e) = fs.mount(opts, MountFlags::empty(), None) {
        return Err(KernelError::MountFailed(path, e));
    }

    // Initialize memory management.
    let mm = MemoryManager::new(&mut syscalls)?;

    let mut log = info!();

    writeln!(log, "Page size             : {:#x}", mm.page_size()).unwrap();
    writeln!(
        log,
        "Allocation granularity: {:#x}",
        mm.allocation_granularity()
    )
    .unwrap();
    writeln!(
        log,
        "Main stack            : {:p}:{:p}",
        mm.stack().start(),
        mm.stack().end()
    )
    .unwrap();

    print(log);

    // Select execution engine.
    match args.execution_engine.unwrap_or_default() {
        #[cfg(target_arch = "x86_64")]
        ExecutionEngine::Native => run(
            args.debug_dump,
            &param,
            auth,
            syscalls,
            &fs,
            &mm,
            crate::ee::native::NativeEngine::new(),
        ),
        #[cfg(not(target_arch = "x86_64"))]
        ExecutionEngine::Native => {
            error!("Native execution engine cannot be used on your machine.");
            Err(KernelError::NativeExecutionEngineNotSupported)
        }
    }
}

thread_local! {
    static LOCKS: RefCell<BTreeMap<usize, MutexGuard<'static, bool>>> = RefCell::new(BTreeMap::new());
}

struct MutexHolder {
    lock: Arc<Mutex<bool>>,
    guard: Gutex<RefCell<Option<MutexGuard<'static, bool>>>>,
}

unsafe impl Send for MutexHolder {}

impl MutexHolder {
    pub fn new(init: bool) -> MutexHolder {
        let gg = GutexGroup::new();
        Self {
            lock: Arc::new(Mutex::new(init)),
            guard: gg.spawn(RefCell::new(None)),
        }
    }

    pub fn lock(&self) -> () {
        let g = self.lock.lock().unwrap();

        let static_guard = Self::extend_lifetime(g);
        self.guard.write().replace(Some(static_guard));

        // static_guard
    }

    pub fn into_inner<'a>(&self) -> MutexGuard<'a, bool> {
        let g = self.guard.write();

        let guard = g.replace(None);

        guard.unwrap()
        // g.into_inner().unwrap()
    }

    // pub fn unlock(&self) -> () {
    //     let mut guard = self.guard.write();

    //     // assert!((*guard).is_some());
    //     // let arc = &*guard;

    //     match arc {
    //         Some(m) => drop(m),
    //         _ => unreachable!(),
    //     }
    //     *guard = None;
    // }

    fn extend_lifetime<'a, A>(g: MutexGuard<'a, A>) -> MutexGuard<'static, A> {
        unsafe { std::mem::transmute(g) }
    }
}

struct SyscallsStubs {
    cvs: Gutex<BTreeMap<usize, Condvar>>,
    mutexes: Gutex<BTreeMap<usize, MutexHolder>>,
}

#[repr(C)]
struct ThrParam {
    start_func: *const c_void,
    arg: *const c_void,
    stack_base: usize,
    stack_size: usize,
    tls_base: usize,
    tls_size: usize,
    child_tid: *const usize,
    parent_tid: *const usize,
    flags: i32,
    rtp: usize,
    spare_1: usize,
    spare_2: usize,
    spare_3: usize,
}

impl SyscallsStubs {
    fn stub(self: &Arc<Self>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let arg1: usize = i.args[0].into();
        let arg2: usize = i.args[1].into();
        let arg3: usize = i.args[2].into();
        let arg4: usize = i.args[3].into();
        let arg5: usize = i.args[4].into();
        let arg6: usize = i.args[5].into();
        warn!(
            "stubbed syscall_{}({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x})",
            i.id, arg1, arg2, arg3, arg4, arg5, arg6
        );

        Ok(0.into())
    }

    fn new(syscalls: &mut Syscalls) -> () {
        let gg = GutexGroup::new();
        let stubs = Arc::new(Self {
            cvs: gg.spawn(BTreeMap::new()),
            mutexes: gg.spawn(BTreeMap::new()),
        });
        // syscalls.register(209, &stubs, |_, _, i| {
        //     #[repr(C)]
        //     #[derive(Debug)]
        //     struct PollFd {
        //         pub fd: i32,
        //         pub events: i16,
        //         pub revents: i16,
        //     }

        //     let arg1: *const PollFd = i.args[0].into();
        //     let nfds: usize = i.args[1].into();
        //     let timeout: i64 = i.args[2].into();

        //     let fds = unsafe { std::slice::from_raw_parts(arg1, nfds) };

        //     warn!("stubbed sys_poll({:?}, {}, {})", fds, nfds, timeout);

        //     Ok(nfds.into())
        // });
        syscalls.register(331, &stubs, |_, _, _| {
            warn!("stubbed sys_sched_yield");
            Ok(0.into())
        });
        syscalls.register(203, &stubs, |_, _, _| {
            warn!("stubbed sys_mlock");
            Ok(0.into())
        });
        syscalls.register(95, &stubs, |_, _, _| {
            warn!("stubbed sys_fsync");
            Ok(0.into())
        });
        // syscalls.register(232, &stubs, |_, _, i| {
        //     let clock_id: i32 = i.args[0].try_into().unwrap();
        //     let ts: *mut ::libc::timespec = i.args[1].into();

        //     unsafe {
        //         ::libc::clock_gettime(clock_id, ts);
        //     }

        //     Ok(0.into())
        // });
        syscalls.register(548, &stubs, Self::stub);
        // syscalls.register(136, &stubs, Self::stub);
        syscalls.register(234, &stubs, Self::stub);
        // syscalls.register(480, &stubs, Self::stub);
        // syscalls.register(188, &stubs, Self::stub);
        // syscalls.register(538, &stubs, Self::stub);
        // syscalls.register(362, &stubs, Self::stub);
        // syscalls.register(141, &stubs, Self::stub);
        syscalls.register(612, &stubs, Self::stub);
        // syscalls.register(483, &stubs, Self::stub);
        syscalls.register(670, &stubs, Self::stub);
        syscalls.register(455, &stubs, |_, _, i| {
            let thr_param: *const ThrParam = i.args[0].into();
            let thr_param_size: usize = i.args[1].into();

            info!(
                "stubbed sys_thr_new({:#x}, {:#x})",
                thr_param as usize, thr_param_size
            );

            assert_eq!(size_of::<ThrParam>(), 0x68);

            if thr_param_size > 0x68 {
                return Err(SysErr::Raw(EINVAL));
            }

            let params: &ThrParam = unsafe { &*thr_param };

            fn create_thread(
                start_func: *const c_void,
                arg: usize,
                stack_base: usize,
                stack_size: usize,
                tls_base: usize,
                tls_size: usize,
                child_tid: *mut usize,
                parent_tid: *mut usize,
                flags: i32,
                rtp: usize,
                spare_1: usize,
                spare_2: usize,
                spare_3: usize,
            ) -> Result<SysOut, SysErr> {
                info!("create_thread({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x})",
                    start_func as usize, arg as usize, stack_base, stack_size, tls_base, tls_size,
                    child_tid as usize, parent_tid as usize, flags, rtp, spare_1, spare_2, spare_3);

                let new_td = VThread::new(VThread::current().unwrap().proc().clone(), VThread::current().unwrap().cred());
                new_td.pcb_mut().set_fsbase(tls_base);
                let entry = native::RawFn { md: Arc::new(()), addr: start_func as usize };
                let entry = move || unsafe { entry.exec1(arg) };

                let ret = unsafe {new_td.start(stack_base as *mut u8, stack_size, entry)};

                match ret {
                    Ok(ret) => unsafe {
                        if !child_tid.is_null() {
                            *child_tid = ret as usize;
                        }
                        if !parent_tid.is_null() {
                            *parent_tid = ret as usize;
                        }

                        Ok(0.into())
                    },
                    Err(_) => Err(SysErr::Raw(EINVAL))
                }
            }

            return create_thread(
                params.start_func,
                params.arg as usize,
                params.stack_base,
                params.stack_size,
                params.tls_base,
                params.tls_size,
                params.child_tid as *mut usize,
                params.parent_tid as *mut usize,
                params.flags,
                params.rtp,
                params.spare_1,
                params.spare_2,
                params.spare_3,
            );

            // Ok(0.into())
        });
        syscalls.register(454, &stubs, |s, _, i| {
            let obj: usize = i.args[0].into();
            let op: usize = i.args[1].into();
            let val: usize = i.args[2].into();
            let uaddr: usize = i.args[3].into();
            let uaddr2: usize = i.args[4].into();
            let arg6: usize = i.args[5].into();
            warn!(
                "stubbed sys_umtx_op({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x})",
                obj, op, val, uaddr, uaddr2, arg6
            );

            if op > 22 {
                // UMTX_MAX_OP
                return Err(SysErr::Raw(EINVAL));
            }

            match op {
                // UMTX_OP_MUTEX_LOCK
                0x5 => {
                    let umutex = obj;

                    let mut mutexes = s.mutexes.write();
                    let entry = mutexes.entry(umutex);
                    let mutex = match entry {
                        Entry::Occupied(ref e) => e.get(),
                        Entry::Vacant(e) => {
                            let mutex = MutexHolder::new(false);
                            e.insert(mutex)
                        }
                    };

                    let guard = mutex.lock();
                    drop(mutexes);

                    return Ok(0.into());
                    // todo!("UMTX_OP_MUTEX_LOCK")
                }
                // UMTX_OP_CV_WAIT
                0x8 => {
                    let ucond = obj;
                    let flags = val;
                    let umutex = uaddr;
                    let timeout = uaddr2;

                    if timeout != 0 {
                        todo!("UMTX_OP_CV_WAIT with timeout");
                    }

                    let mut cvs = s.cvs.write();
                    let entry = cvs.entry(ucond);
                    let cv = match entry {
                        Entry::Vacant(e) => {
                            let cv = Condvar::new();
                            e.insert(cv)
                        }
                        Entry::Occupied(ref e) => e.get(),
                    };

                    let mut mutexes = s.mutexes.write();
                    let entry = mutexes.entry(umutex);
                    let mutex = match entry {
                        Entry::Vacant(e) => {
                            let mutex = MutexHolder::new(false);
                            e.insert(mutex)
                            // panic!("mutex for cv does not exist")
                        }
                        Entry::Occupied(ref mutex) => mutex.get(),
                    };
                    mutex.lock();
                    let mut guard = mutex.into_inner();

                    drop(mutexes);
                    // drop(cvs);
                    while !*guard {
                        guard = cv.wait(guard).unwrap();
                    }

                    return Ok(0.into());
                    // todo!("UMTX_OP_CV_WAIT")
                }
                _ => todo!("unknown umtx_op: {:#x}", op),
            }
        });
        // syscalls.register(544, &stubs, Self::stub);
        syscalls.register(638, &stubs, Self::stub);
        syscalls.register(272, &stubs, Self::stub);
        // syscalls.register(546, &stubs, Self::stub);
        // syscalls.register(478, &stubs, Self::stub);
        // syscalls.register(488, &stubs, |_, _, i| {
        //     let arg1: usize = i.args[0].into();
        //     let arg2: usize = i.args[1].into();
        //     let arg3: usize = i.args[2].into();
        //     let arg4: usize = i.args[3].into();
        //     let arg5: usize = i.args[4].into();
        //     warn!(
        //         "stubbed sys_cpuset_setaffinity({:#x}, {:#x}, {:#x}, {:#x}, {:#x})",
        //         arg1, arg2, arg3, arg4, arg5
        //     );

        //     Ok(0.into())
        // });
        // syscalls.register(542, &stubs, Self::stub);
        // syscalls.register(545, &stubs, Self::stub);
        // syscalls.register(572, &stubs, |_, _| Ok(1.into()));
        syscalls.register(643, &stubs, Self::stub);
        syscalls.register(654, &stubs, Self::stub);
        syscalls.register(74, &stubs, Self::stub);
        // syscalls.register(189, &stubs, Self::stub);
        // syscalls.register(482, &stubs, |_, _, i| {
        //     let name: &str = unsafe { i.args[0].to_str(255)?.unwrap() };
        //     info!("stubbed sys_shm_open({})", name);
        //     Ok(666.into())
        // });
        // syscalls.register(97, &stubs, |_, _, i| {
        //     let domain = i.args[0].try_into().unwrap();
        //     let ty = i.args[1].try_into().unwrap();
        //     let protocol = i.args[2].try_into().unwrap();
        //     warn!("stubbed sys_socket({:?}, {:?}, {:?})", domain, ty, protocol);
        //     let fd = unsafe { socket(domain, ty, protocol) };

        //     Ok(fd.into())
        // });
        syscalls.register(98, &stubs, |_, _, _| Ok((-1).into()));
        syscalls.register(99, &stubs, |_, _, i| {
            let arg1: usize = i.args[0].into();
            let arg2: usize = i.args[1].into();
            let arg3: usize = i.args[2].into();
            let arg4: usize = i.args[3].into();
            warn!(
                "stubbed sys_netcontrol({:#x}, {:#x}, {:#x}, {:#x})",
                arg1, arg2, arg3, arg4
            );

            Ok(0.into())
        });
        // syscalls.register(113, &stubs, |_, _, _| Ok(666.into()));
        syscalls.register(114, &stubs, Self::stub);
        // syscalls.register(133, &stubs, |_, _, i| {
        //     let arg1: usize = i.args[0].into();
        //     warn!("stubbed sys_sendto({:#x})", arg1);

        //     let len: usize = i.args[2].into();

        //     Ok(len.into())
        // });
        // syscalls.register(116, &stubs, Self::stub);
        // syscalls.register(622, &stubs, Self::stub);
        // syscalls.register(550, &stubs, Self::stub);
        // syscalls.register(540, &stubs, Self::stub);
        syscalls.register(539, &stubs, Self::stub);
        // syscalls.register(549, &stubs, Self::stub);
        // syscalls.register(551, &stubs, Self::stub);
    }
}

fn run<E: crate::ee::ExecutionEngine>(
    dump: Option<PathBuf>,
    param: &Arc<Param>,
    auth: AuthInfo,
    mut syscalls: Syscalls,
    fs: &Arc<Fs>,
    mm: &Arc<MemoryManager>,
    ee: Arc<E>,
) -> Result<(), KernelError> {
    // Initialize TTY system.
    #[allow(unused_variables)] // TODO: Remove this when someone use tty.
    let tty = TtyManager::new()?;

    // let dipsw = Dipsw::new();
    // let _ = SblService::new();

    // Initialize kernel components.
    #[allow(unused_variables)] // TODO: Remove this when someone use debug.
    let debug = DebugManager::new()?;
    RegMgr::new(&mut syscalls);
    let machdep = MachDep::new(&mut syscalls);
    let budget = BudgetManager::new(&mut syscalls);

    SharedMemoryManager::new(mm, &mut syscalls);
    TimeManager::new(&mut syscalls);
    KernelQueueManager::new(&mut syscalls);
    NetManager::new(&mut syscalls);
    DmemManager::new(&fs, mm, &mut syscalls);
    Sysctl::new(mm, &machdep, &mut syscalls);
    SyscallsStubs::new(&mut syscalls);
    GcManager::new();
    RngManager::new();
    HidManager::new();

    // TODO: Get correct budget name from the PS4.
    let budget_id = budget.create(Budget::new("big app", ProcType::BigApp));
    let proc = VProc::new(
        auth,
        budget_id,
        ProcType::BigApp,
        1,         // See sys_budget_set on the PS4.
        fs.root(), // TODO: Change to a proper value once FS rework is done.
        "QXuNNl0Zhn",
        &mut syscalls,
    )?;

    NamedObjManager::new(&mut syscalls, &proc);
    UmtxManager::new(&mut syscalls);
    IpmiManager::new(&mut syscalls, &proc);
    OsemManager::new(&mut syscalls, &proc);
    EvfManager::new(&mut syscalls, &proc);

    // Initialize runtime linker.
    info!("Initializing runtime linker.");

    let ld = RuntimeLinker::new(fs, mm, &ee, &mut syscalls, dump.as_deref())
        .map_err(|e| KernelError::RuntimeLinkerInitFailed(e.into()))?;

    ee.set_syscalls(syscalls);

    // Print application module.
    let app = ld.app();
    let mut log = info!();

    writeln!(log, "Application   : {}", app.path()).unwrap();
    app.print(log);

    // Preload libkernel.
    let mut flags = LoadFlags::UNK1;
    let path = vpath!("/system/common/lib/libkernel.sprx");

    if proc.budget_ptype() == ProcType::BigApp {
        flags |= LoadFlags::BIG_APP;
    }

    info!("Loading {path}.");

    let libkernel = ld
        .load(&proc, path, flags, false, true)
        .map_err(|e| KernelError::FailedToLoadLibkernel(e.into()))?;

    libkernel.flags_mut().remove(ModuleFlags::UNK2);
    libkernel.print(info!());

    ld.set_kernel(libkernel);

    // Preload libSceLibcInternal.
    let path = vpath!("/system/common/lib/libSceLibcInternal.sprx");

    info!("Loading {path}.");

    let libc = ld
        .load(&proc, path, flags, false, true)
        .map_err(|e| KernelError::FailedToLoadLibSceLibcInternal(e.into()))?;

    libc.flags_mut().remove(ModuleFlags::UNK2);
    libc.print(info!());

    drop(libc);

    // Get eboot.bin.
    if app.file_info().is_none() {
        todo!("statically linked eboot.bin");
    }

    // Setup hypervisor.
    let hv = Hypervisor::new().map_err(KernelError::CreateHypervisorFailed)?;

    // Get entry point.
    let boot = ld.kernel().unwrap();
    let mut arg = Box::pin(EntryArg::<E>::new(&proc, mm, app.clone()));
    let entry = unsafe { boot.get_function(boot.entry().unwrap()) };
    let entry = move || unsafe { entry.exec1(arg.as_mut().as_vec().as_ptr()) };

    // Spawn main thread.
    info!("Starting application.");

    // TODO: Check how this constructed.
    let cred = Arc::new(Ucred::new(
        Uid::ROOT,
        Uid::ROOT,
        vec![Gid::ROOT],
        AuthInfo::SYS_CORE.clone(),
    ));

    let main = VThread::new(proc, &cred);
    let stack = mm.stack();
    let main: OsThread = unsafe { main.start(stack.start(), stack.len(), entry) }?;

    // Begin Discord Rich Presence before blocking current thread.
    if let Err(e) = discord_presence(param) {
        warn!(e, "Failed to setup Discord rich presence");
    }

    // Wait for main thread to exit. This should never return.
    join_thread(main).map_err(KernelError::FailedToJoinMainThread)?;

    Ok(())
}

fn discord_presence(param: &Param) -> Result<(), DiscordPresenceError> {
    use discord_rich_presence::activity::{Activity, Assets, Timestamps};
    use discord_rich_presence::{DiscordIpc, DiscordIpcClient};

    // Initialize new Discord IPC with our ID.
    info!("Initializing Discord rich presence.");

    let mut client = DiscordIpcClient::new("1168617561244565584")
        .map_err(DiscordPresenceError::FailedToCreateIpc)?;

    // Attempt to have IPC connect to user's Discord, will fail if user doesn't have Discord running.
    if client.connect().is_err() {
        // No Discord running should not be a warning.
        return Ok(());
    }

    // Create details about game.
    let details = format!("Playing {} - {}", param.title().unwrap(), param.title_id());
    let start = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Send activity to Discord.
    let payload = Activity::new()
        .details(&details)
        .assets(
            Assets::new()
                .large_image("obliteration-icon")
                .large_text("Obliteration"),
        )
        .timestamps(Timestamps::new().start(start.try_into().unwrap()));

    client
        .set_activity(payload)
        .map_err(DiscordPresenceError::FailedToUpdatePresence)?;

    // Keep client alive forever.
    Box::leak(client.into());

    Ok(())
}

#[cfg(unix)]
fn join_thread(thr: OsThread) -> Result<(), std::io::Error> {
    let err = unsafe { libc::pthread_join(thr, std::ptr::null_mut()) };

    if err != 0 {
        Err(std::io::Error::from_raw_os_error(err))
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn join_thread(thr: OsThread) -> Result<(), std::io::Error> {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{WaitForSingleObject, INFINITE};

    if unsafe { WaitForSingleObject(thr, INFINITE) } != WAIT_OBJECT_0 {
        return Err(std::io::Error::last_os_error());
    }

    assert_ne!(unsafe { CloseHandle(thr) }, 0);

    Ok(())
}

#[derive(Parser, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Args {
    #[arg(long)]
    system: PathBuf,

    #[arg(long)]
    game: PathBuf,

    #[arg(long)]
    eboot: Option<PathBuf>,

    #[arg(long)]
    debug_dump: Option<PathBuf>,

    #[arg(long)]
    #[serde(default)]
    clear_debug_dump: bool,

    #[arg(long)]
    #[serde(default)]
    pro: bool,

    #[arg(long, short)]
    execution_engine: Option<ExecutionEngine>,
}

#[derive(Clone, ValueEnum, Deserialize)]
enum ExecutionEngine {
    Native,
}

impl Default for ExecutionEngine {
    #[cfg(target_arch = "x86_64")]
    fn default() -> Self {
        ExecutionEngine::Native
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn default() -> Self {
        ExecutionEngine::Llvm
    }
}

#[derive(Debug, Error)]
enum DiscordPresenceError {
    #[error("failed to create Discord IPC")]
    FailedToCreateIpc(#[source] Box<dyn Error>),

    #[error("failed to update Discord presence")]
    FailedToUpdatePresence(#[source] Box<dyn Error>),
}

#[derive(Debug, Error)]
enum KernelError {
    #[error("couldn't open .kernel-debug")]
    FailedToOpenDebugConfig(#[source] std::io::Error),

    #[error("couldn't parse .kernel-debug")]
    FailedToParseDebugConfig(#[source] serde_yaml::Error),

    #[error("couldn't parse arguments")]
    FailedToParseArgs(#[from] clap::Error),

    #[error("couldn't open param.sfo")]
    FailedToOpenGameParam(#[source] std::io::Error),

    #[error("couldn't read param.sfo ")]
    FailedToReadGameParam(#[from] param::ReadError),

    #[error("{0} has an invalid title identifier")]
    InvalidTitleId(PathBuf),

    #[error("filesystem initialization failed")]
    FilesystemInitFailed(#[from] FsInitError),

    #[error("couldn't create {0}")]
    CreateDirectoryFailed(&'static VPath, #[source] MkdirError),

    #[error("couldn't mount {0}")]
    MountFailed(&'static VPath, #[source] MountError),

    #[error("memory manager initialization failed")]
    MemoryManagerInitFailed(#[from] MemoryManagerError),

    #[cfg(not(target_arch = "x86_64"))]
    #[error("the native execution engine is only supported on x86_64")]
    NativeExecutionEngineNotSupported,

    #[error("tty initialization failed")]
    TtyInitFailed(#[from] TtyInitError),

    #[error("debug manager initialization failed")]
    DebugManagerInitFailed(#[from] DebugManagerInitError),

    #[error("virtual process initialization failed")]
    VProcInitFailed(#[from] VProcInitError),

    #[error("runtime linker initialization failed")]
    RuntimeLinkerInitFailed(#[source] Box<dyn Error>),

    #[error("libkernel couldn't be loaded")]
    FailedToLoadLibkernel(#[source] Box<dyn Error>),

    #[error("libSceLibcInternal couldn't be loaded")]
    FailedToLoadLibSceLibcInternal(#[source] Box<dyn Error>),

    #[error("couldn't create a hypervisor")]
    CreateHypervisorFailed(#[from] hv::NewError),

    #[error("main thread couldn't be created")]
    FailedToCreateMainThread(#[from] SpawnError),

    #[error("failed to join with main thread")]
    FailedToJoinMainThread(#[source] std::io::Error),
}

/// We have to use this for a custom implementation of the [`Termination`] trait, because
/// we need to log the error using our own error! macro instead of [`std::fmt::Debug::fmt`],
/// which is what the default implementation of Termination uses for [`Result<T: Termination, E: Debug>`].
enum Exit {
    Ok,
    Err(KernelError),
}

impl Termination for Exit {
    fn report(self) -> ExitCode {
        match self {
            Exit::Ok => ExitCode::SUCCESS,
            Exit::Err(e) => {
                error!(e, "Error while running kernel");
                ExitCode::FAILURE
            }
        }
    }
}

impl From<Result<(), KernelError>> for Exit {
    fn from(r: Result<(), KernelError>) -> Self {
        match r {
            Ok(_) => Exit::Ok,
            Err(e) => Exit::Err(e),
        }
    }
}
