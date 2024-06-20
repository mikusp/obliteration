use super::{
    AppInfo, Binaries, CpuLevel, CpuMask, CpuSet, CpuWhich, FileDesc, Limits, ResourceLimit,
    ResourceType, SignalActs, SpawnError, VProcGroup, VThread, NEXT_ID,
};
use crate::budget::ProcType;
use crate::dev::DmemContainer;
use crate::ee::native;
use crate::errno::{Errno, EINVAL, ERANGE, ESRCH};
use crate::fs::Vnode;
use crate::idt::Idt;
use crate::ipmi::IpmiObject;
use crate::syscalls::{SysErr, SysIn, SysOut, Syscalls};
use crate::sysent::ProcAbi;
use crate::ucred::{AuthInfo, Gid, Privilege, Ucred, Uid};
use crate::vm::Vm;
use crate::{error, info, warn};
use bitflags::bitflags;
use gmtx::{Gutex, GutexGroup, GutexReadGuard, GutexWriteGuard};
use libc::pthread_exit;
use macros::Errno;
use std::any::Any;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::mem::size_of;
use std::mem::zeroed;
use std::num::NonZeroI32;
use std::ops::Deref;
use std::ptr::null;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Arc, OnceLock};
use thiserror::Error;

/// An implementation of `proc` structure.
///
/// Currently this struct represent the main application process. We will support multiple processes
/// once we have migrated the PS4 code to run inside a virtual machine.
#[derive(Debug)]
pub struct VProc {
    id: NonZeroI32,                        // p_pid
    threads: Gutex<Vec<Arc<VThread>>>,     // p_threads
    cred: Arc<Ucred>,                      // p_ucred
    group: Gutex<Option<Arc<VProcGroup>>>, // p_pgrp
    abi: OnceLock<ProcAbi>,                // p_sysent
    vm: Arc<Vm>,                           // p_vmspace
    sigacts: Gutex<SignalActs>,            // p_sigacts
    files: Arc<FileDesc>,                  // p_fd
    system_path: String,                   // p_randomized_path
    limits: Limits,                        // p_limit
    comm: Gutex<Option<String>>,           // p_comm
    bin: Gutex<Option<Binaries>>,          // p_dynlib?
    objects: Gutex<Idt<Arc<dyn Any + Send + Sync>>>,
    gnt: Gutex<HashMap<String, Arc<dyn Any + Send + Sync>>>,
    ipmi_map: Gutex<Vec<IpmiObject>>,
    budget_id: usize,
    budget_ptype: ProcType,
    dmem_container: Gutex<DmemContainer>,
    app_info: AppInfo,
    ptc: u64,
    uptc: AtomicPtr<u8>,
}

impl VProc {
    pub(super) fn new(
        auth: AuthInfo,
        budget_id: usize,
        budget_ptype: ProcType,
        dmem_container: DmemContainer,
        root: Arc<Vnode>,
        system_path: impl Into<String>,
        mut sys: Syscalls,
    ) -> Result<Arc<Self>, SpawnError> {
        let cred = if auth.caps.is_system() {
            // TODO: The groups will be copied from the parent process, which is SceSysCore.
            Ucred::new(Uid::ROOT, Uid::ROOT, vec![Gid::ROOT], auth)
        } else {
            let uid = Uid::new(1).unwrap();
            Ucred::new(uid, uid, vec![Gid::new(1).unwrap()], auth)
        };

        let gg = GutexGroup::new();
        let limits = Limits::load()?;

        let vp = Arc::new(Self {
            id: Self::new_id(),
            threads: gg.spawn(Vec::new()),
            cred: Arc::new(cred),
            group: gg.spawn(None),
            abi: OnceLock::new(),
            vm: Vm::new(&mut sys)?,
            sigacts: gg.spawn(SignalActs::new()),
            files: FileDesc::new(root),
            system_path: system_path.into(),
            objects: gg.spawn(Idt::new(0x1000)),
            gnt: gg.spawn(HashMap::new()),
            ipmi_map: gg.spawn(vec![]),
            budget_id,
            budget_ptype,
            dmem_container: gg.spawn(dmem_container),
            limits,
            comm: gg.spawn(None), //TODO: Find out how this is actually set
            bin: gg.spawn(None),
            app_info: AppInfo::new(),
            ptc: 0,
            uptc: AtomicPtr::new(null_mut()),
        });

        // TODO: Move all syscalls here to somewhere else.
        sys.register(331, &vp, Self::sys_sched_yield);
        sys.register(431, &vp, Self::sys_thr_exit);
        sys.register(455, &vp, Self::sys_thr_new);
        sys.register(466, &vp, Self::sys_rtprio_thread);
        sys.register(487, &vp, Self::sys_cpuset_getaffinity);
        sys.register(488, &vp, Self::sys_cpuset_setaffinity);
        sys.register(587, &vp, Self::sys_get_authinfo);
        sys.register(612, &vp, Self::sys_get_proc_type_info);

        vp.abi.set(ProcAbi::new(sys)).unwrap();

        Ok(vp)
    }

    pub fn id(&self) -> NonZeroI32 {
        self.id
    }

    pub fn threads(&self) -> GutexReadGuard<Vec<Arc<VThread>>> {
        self.threads.read()
    }

    pub fn threads_mut(&self) -> GutexWriteGuard<Vec<Arc<VThread>>> {
        self.threads.write()
    }

    pub fn cred(&self) -> &Arc<Ucred> {
        &self.cred
    }

    pub fn group_mut(&self) -> GutexWriteGuard<Option<Arc<VProcGroup>>> {
        self.group.write()
    }

    pub fn abi(&self) -> &ProcAbi {
        self.abi.get().unwrap()
    }

    pub fn vm(&self) -> &Arc<Vm> {
        &self.vm
    }

    pub fn sigacts_mut(&self) -> GutexWriteGuard<SignalActs> {
        self.sigacts.write()
    }

    pub fn files(&self) -> &Arc<FileDesc> {
        &self.files
    }

    pub fn system_path(&self) -> &str {
        &self.system_path
    }

    pub fn limit(&self, ty: ResourceType) -> &ResourceLimit {
        &self.limits[ty]
    }

    pub fn name(&self) -> GutexReadGuard<Option<String>> {
        self.comm.read()
    }

    pub fn set_name(&self, name: Option<&str>) {
        *self.comm.write() = name.map(|n| n.to_owned());
    }

    pub fn bin(&self) -> GutexReadGuard<Option<Binaries>> {
        self.bin.read()
    }

    pub fn bin_mut(&self) -> GutexWriteGuard<Option<Binaries>> {
        self.bin.write()
    }

    pub fn objects(&self) -> GutexReadGuard<'_, Idt<Arc<dyn Any + Send + Sync>>> {
        self.objects.read()
    }

    pub fn objects_mut(&self) -> GutexWriteGuard<'_, Idt<Arc<dyn Any + Send + Sync>>> {
        self.objects.write()
    }

    pub fn budget_id(&self) -> usize {
        self.budget_id
    }

    pub fn budget_ptype(&self) -> ProcType {
        self.budget_ptype
    }

    pub fn dmem_container(&self) -> GutexReadGuard<'_, DmemContainer> {
        self.dmem_container.read()
    }

    pub fn dmem_container_mut(&self) -> GutexWriteGuard<'_, DmemContainer> {
        self.dmem_container.write()
    }

    pub fn gnt_mut(&self) -> GutexWriteGuard<'_, HashMap<String, Arc<dyn Any + Send + Sync>>> {
        self.gnt.write()
    }

    pub fn ipmi_map_mut(&self) -> GutexWriteGuard<'_, Vec<IpmiObject>> {
        self.ipmi_map.write()
    }

    pub fn app_info(&self) -> &AppInfo {
        &self.app_info
    }

    pub fn ptc(&self) -> u64 {
        self.ptc
    }

    pub fn uptc(&self) -> &AtomicPtr<u8> {
        &self.uptc
    }

    pub fn sdk_ver(&self) -> Option<u32> {
        (&self.bin().as_ref().map(|bin| bin.app().sdk_ver())).clone()
    }

    fn sys_sched_yield(self: &Arc<Self>, _: &VThread, _: &SysIn) -> Result<SysOut, SysErr> {
        std::thread::yield_now();
        Ok(SysOut::ZERO)
    }

    fn sys_thr_exit(self: &Arc<Self>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        error!("stubbed sys_thr_exit");

        unsafe { pthread_exit(std::ptr::null_mut()) };
    }

    fn sys_thr_new(self: &Arc<Self>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let param: *const ThrParam = i.args[0].into();
        let param_size: i32 = i.args[1].try_into().unwrap();

        if param_size < 0 && param_size as usize > size_of::<ThrParam>() {
            return Err(SysErr::Raw(EINVAL));
        }

        // The given param size seems to so far only be 0x68, we can handle this when we encounter it.
        if param_size as usize != size_of::<ThrParam>() {
            todo!("thr_new with param_size != sizeof(ThrParam)");
        }

        unsafe {
            self.thr_new(td, &*param)?;
        }

        Ok(SysOut::ZERO)
    }

    unsafe fn thr_new(&self, td: &VThread, param: &ThrParam) -> Result<SysOut, CreateThreadError> {
        if param.rtprio != null() {
            warn!("thr_new with non-null rtp");
        }

        self.create_thread(
            td,
            param.start_func,
            param.arg,
            param.stack_base,
            param.stack_size,
            param.tls_base,
            param.tls_size,
            param.child_tid,
            param.parent_tid,
            param.flags,
            param.rtprio,
            param.name,
        )
    }

    #[allow(unused_variables)] // TODO: Remove this when implementing.
    unsafe fn create_thread(
        &self,
        td: &VThread,
        start_func: fn(usize),
        arg: usize,
        stack_base: usize,
        stack_size: usize,
        tls_base: *const u8,
        tls_size: usize,
        child_tid: *mut i64,
        parent_tid: *mut i64,
        flags: i32,
        rtprio: *const RtPrio,
        name: usize,
    ) -> Result<SysOut, CreateThreadError> {
        let thr_name = if name != 0 {
            Some(unsafe { CStr::from_ptr(name as _).to_str().unwrap() })
        } else {
            None
        };

        info!(
            "create_thread({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:?})",
            start_func as usize,
            arg as usize,
            stack_base,
            stack_size,
            tls_base as usize,
            tls_size,
            child_tid as usize,
            parent_tid as usize,
            flags,
            rtprio as usize,
            thr_name
        );
        let new_td = VThread::new(VThread::current().unwrap().proc().clone());
        new_td.pcb_mut().set_fsbase(tls_base as _);
        let entry = native::RawFn {
            md: Arc::new(()),
            addr: start_func as usize,
        };
        let entry = move || unsafe { entry.exec1(arg) };
        // let stack_ptr = {
        //     let top = (stack_base) & 0xffffffffffffc000;

        //     top
        // };
        info!("create thread stack top: {:#x}", stack_base);
        let ret = unsafe { new_td.start(stack_base as *mut u8, stack_size, entry) };
        match ret {
            Ok(ret) => unsafe {
                if let Some(n) = thr_name {
                    let cs = CString::new(String::from_utf8(n.bytes().take(15).collect()).unwrap())
                        .unwrap();
                    info!("setting thread name for {}: {:#?}", ret, cs);
                    libc::pthread_setname_np(ret, cs.as_ptr());
                }

                if !child_tid.is_null() {
                    *child_tid = ret as _;
                }
                if !parent_tid.is_null() {
                    *parent_tid = ret as _;
                }
                Ok(0.into())
            },
            Err(e) => Err(CreateThreadError::SpawnError(e)),
        }
    }

    fn sys_rtprio_thread(self: &Arc<Self>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let function: RtpFunction = TryInto::<i32>::try_into(i.args[0]).unwrap().try_into()?;
        let lwpid: i32 = i.args[1].try_into().unwrap();
        let rtp: *mut RtPrio = i.args[2].into();
        let rtp = unsafe { &mut *rtp };

        if function == RtpFunction::Set {
            error!("rtprio_thread with function = 1");
            return Ok(SysOut::ZERO);
        }

        if function == RtpFunction::Unk && td.cred().is_system() {
            todo!("rtprio_thread with function = 2");
        } else if lwpid != 0 && lwpid != td.id().get() {
            return Err(SysErr::Raw(ESRCH));
        } else if function == RtpFunction::Lookup {
            rtp.ty = td.pri_class();
            rtp.prio = match td.pri_class() & 0xfff7 {
                2..=4 => td.base_user_pri(),
                _ => 0,
            };
        } else {
            todo!("rtprio_thread with function = {function:?}");
        }

        Ok(SysOut::ZERO)
    }

    fn sys_cpuset_getaffinity(self: &Arc<Self>, _: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        // Get arguments.
        let level: CpuLevel = TryInto::<i32>::try_into(i.args[0]).unwrap().try_into()?;
        let which: CpuWhich = TryInto::<i32>::try_into(i.args[1]).unwrap().try_into()?;
        let id: i64 = i.args[2].into();
        let cpusetsize: usize = i.args[3].into();
        let mask: *mut u8 = i.args[4].into();

        // TODO: Refactor this for readability.
        if cpusetsize.wrapping_sub(8) > 8 {
            return Err(SysErr::Raw(ERANGE));
        }

        let td = self.cpuset_which(which, id)?;
        let mut buf = vec![0u8; cpusetsize];

        match level {
            CpuLevel::Which => match which {
                CpuWhich::Tid => {
                    let v = td.cpuset().mask().bits[0].to_ne_bytes();
                    buf[..v.len()].copy_from_slice(&v);
                }
                v => todo!("sys_cpuset_getaffinity with which = {v:?}"),
            },
            v => todo!("sys_cpuset_getaffinity with level = {v:?}"),
        }

        // TODO: What is this?
        let x = u32::from_ne_bytes(buf[..4].try_into().unwrap());
        let y = (x >> 1 & 0x55) + (x & 0x55) * 2;
        let z = (y >> 2 & 0xfffffff3) + (y & 0x33) * 4;

        unsafe {
            std::ptr::write_unaligned::<u64>(
                buf.as_mut_ptr() as _,
                (z >> 4 | (z & 0xf) << 4) as u64,
            );

            std::ptr::copy_nonoverlapping(buf.as_ptr(), mask, cpusetsize);
        }

        Ok(SysOut::ZERO)
    }

    fn sys_cpuset_setaffinity(self: &Arc<Self>, _: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let level: CpuLevel = TryInto::<i32>::try_into(i.args[0]).unwrap().try_into()?;
        let which: CpuWhich = TryInto::<i32>::try_into(i.args[1]).unwrap().try_into()?;
        let id: i64 = i.args[2].into();
        let cpusetsize: usize = i.args[3].into();
        let mask: *const u8 = i.args[4].into();

        // TODO: Refactor this for readability.
        if cpusetsize.wrapping_sub(8) > 8 {
            return Err(SysErr::Raw(ERANGE));
        }

        let mask = unsafe { std::slice::from_raw_parts(mask, cpusetsize) };

        info!(
            "sys_cpuset_setaffinity({:?}, {:?}, {}, {:?})",
            level, which, id, mask
        );

        match level {
            CpuLevel::Which => match which {
                CpuWhich::Tid => self.cpuset_setthread(id, mask),
                v => todo!("sys_cpuset_setaffinity with which = {v:?}"),
            },
            v => todo!("sys_cpuset_setaffinity with level = {v:?}"),
        }
    }

    /// See `cpuset_which` on the PS4 for a reference.
    fn cpuset_which(&self, which: CpuWhich, id: i64) -> Result<Arc<VThread>, SysErr> {
        let td = match which {
            CpuWhich::Tid => {
                if id == -1 {
                    let id = VThread::current().unwrap().id();
                    let threads = self.threads.read();
                    let td = threads
                        .iter()
                        .find(|t| t.id().get() == id.get())
                        .ok_or(SysErr::Raw(ESRCH))?
                        .clone();

                    Some(td)
                } else {
                    let threads = self.threads.read();
                    let td = threads
                        .iter()
                        .find(|t| t.id().get() == id as i32)
                        .ok_or(SysErr::Raw(ESRCH))?
                        .clone();

                    Some(td)
                }
            }
            v => todo!("cpuset_which with which = {v:?}"),
        };

        match td {
            Some(v) => Ok(v),
            None => todo!("cpuset_which with td = NULL"),
        }
    }

    fn cpuset_setthread(&self, id: i64, mask: &[u8]) -> Result<SysOut, SysErr> {
        return Ok(SysOut::ZERO);

        let td = self.cpuset_which(CpuWhich::Tid, id)?;
        let mut cpuset = td.cpuset_mut();
        let nset = self.cpuset_shadow(&cpuset, mask)?;

        *cpuset = nset.clone();
        unsafe {
            if libc::sched_setaffinity(
                td.id().get().try_into().unwrap(),
                mask.len(),
                mask.as_ptr() as _,
            ) != 0
            {
                Err(SysErr::Raw(
                    NonZeroI32::new(std::io::Error::last_os_error().raw_os_error().unwrap())
                        .unwrap(),
                ))
            } else {
                Ok(SysOut::ZERO)
            }
        }
    }

    fn cpuset_shadow(&self, _current_cpuset: &CpuSet, mask: &[u8]) -> Result<CpuSet, SysErr> {
        //TODO: compute shadowing from parent
        let cpuset = u64::from_le_bytes(
            mask.clone()
                .take(..8)
                .unwrap()
                .try_into()
                .expect("cpuset_shadow: incorrect mask"),
        );

        Ok(CpuSet::new(CpuMask { bits: [cpuset; 1] }))
    }

    fn sys_get_authinfo(self: &Arc<Self>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        // Get arguments.
        let pid: i32 = i.args[0].try_into().unwrap();
        let buf: *mut AuthInfo = i.args[1].into();

        // Check if PID is our process.
        if pid != 0 && pid != self.id.get() {
            return Err(SysErr::Raw(ESRCH));
        }

        // Check privilege.
        let mut info: AuthInfo = unsafe { zeroed() };

        if td.priv_check(Privilege::SCE686).is_ok() {
            info = self.cred.auth().clone();
        } else {
            // TODO: Refactor this for readability.
            let paid = self.cred.auth().paid.get().wrapping_add(0xc7ffffffeffffffc);

            if paid < 0xf && ((0x6001u32 >> (paid & 0x3f)) & 1) != 0 {
                info.paid = self.cred.auth().paid;
            }

            info.caps = self.cred.auth().caps.clone();
            info.caps.clear_non_type();
        }

        // Copy into.
        if buf.is_null() {
            todo!("get_authinfo with buf = null");
        } else {
            unsafe { *buf = info };
        }

        Ok(SysOut::ZERO)
    }

    fn sys_get_proc_type_info(self: &Arc<Self>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let info = unsafe { &mut *Into::<*mut ProcTypeInfo>::into(i.args[0]) };

        info!("Getting process type information.");

        if info.len != size_of::<ProcTypeInfo>() {
            return Err(SysErr::Raw(EINVAL));
        }

        *info = td.proc().get_proc_type_info();

        Ok(SysOut::ZERO)
    }

    fn get_proc_type_info(&self) -> ProcTypeInfo {
        let cred = self.cred();

        let mut flags = ProcTypeInfoFlags::empty();

        flags.set(
            ProcTypeInfoFlags::IS_JIT_COMPILER_PROCESS,
            cred.is_jit_compiler_process(),
        );
        flags.set(
            ProcTypeInfoFlags::IS_JIT_APPLICATION_PROCESS,
            cred.is_jit_application_process(),
        );
        flags.set(
            ProcTypeInfoFlags::IS_VIDEOPLAYER_PROCESS,
            cred.is_videoplayer_process(),
        );
        flags.set(
            ProcTypeInfoFlags::IS_DISKPLAYERUI_PROCESS,
            cred.is_diskplayerui_process(),
        );
        flags.set(
            ProcTypeInfoFlags::HAS_USE_VIDEO_SERVICE_CAPABILITY,
            cred.has_use_video_service_capability(),
        );
        flags.set(
            ProcTypeInfoFlags::IS_WEBCORE_PROCESS,
            cred.is_webcore_process(),
        );
        flags.set(
            ProcTypeInfoFlags::HAS_SCE_PROGRAM_ATTRIBUTE,
            cred.has_sce_program_attribute(),
        );
        flags.set(
            ProcTypeInfoFlags::IS_DEBUGGABLE_PROCESS,
            cred.is_debuggable_process(),
        );

        ProcTypeInfo {
            len: size_of::<ProcTypeInfo>(),
            ty: self.budget_ptype.into(),
            flags,
        }
    }

    fn new_id() -> NonZeroI32 {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);

        // Just in case if the user manage to spawn 2,147,483,647 threads in a single run so we
        // don't encountered a weird bug.
        assert!(id > 0);

        NonZeroI32::new(id).unwrap()
    }
}

#[repr(C)]
struct ThrParam {
    start_func: fn(usize),
    arg: usize,
    stack_base: usize,
    stack_size: usize,
    tls_base: *const u8,
    tls_size: usize,
    child_tid: *mut i64,
    parent_tid: *mut i64,
    flags: i32,
    rtprio: *const RtPrio,
    name: usize,
    spare: [usize; 2],
}

const _: () = assert!(size_of::<ThrParam>() == 0x68);

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(i32)]
enum RtpFunction {
    Lookup = 0,
    Set = 1,
    Unk = 2,
}

impl TryFrom<i32> for RtpFunction {
    type Error = SysErr;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        let rtp = match value {
            0 => RtpFunction::Lookup,
            1 => RtpFunction::Set,
            2 => RtpFunction::Unk,
            _ => return Err(SysErr::Raw(EINVAL)),
        };

        Ok(rtp)
    }
}

/// Outout of sys_rtprio_thread.
#[repr(C)]
struct RtPrio {
    ty: u16,
    prio: u16,
}

/// Outout of sys_get_proc_type_info.
#[repr(C)]
struct ProcTypeInfo {
    len: usize,
    ty: u32,
    flags: ProcTypeInfoFlags,
}

bitflags! {
    #[repr(transparent)]
    struct ProcTypeInfoFlags: u32 {
        const IS_JIT_COMPILER_PROCESS = 0x1;
        const IS_JIT_APPLICATION_PROCESS = 0x2;
        const IS_VIDEOPLAYER_PROCESS = 0x4;
        const IS_DISKPLAYERUI_PROCESS = 0x8;
        const HAS_USE_VIDEO_SERVICE_CAPABILITY = 0x10;
        const IS_WEBCORE_PROCESS = 0x20;
        const HAS_SCE_PROGRAM_ATTRIBUTE = 0x40;
        const IS_DEBUGGABLE_PROCESS = 0x80;
    }
}

#[derive(Debug, Error, Errno)]
pub enum CreateThreadError {
    #[error("couldn't spawn a thread")]
    #[errno(EINVAL)]
    SpawnError(#[from] llt::SpawnError),
}
