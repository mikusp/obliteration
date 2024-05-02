use bitflags::bitflags;
use gmtx::{Gutex, GutexGroup};

use crate::{
    errno::{EINVAL, EPERM},
    info,
    process::VThread,
    syscalls::{SysArg, SysErr, SysIn, SysOut, Syscalls},
    time::TimeSpec,
    umtx::{
        condvar::Condvar,
        futex::{futex_wait, Timespec},
        mutex::Mutex,
    },
    warn,
};
use std::{
    collections::{hash_map::Entry, HashMap, VecDeque},
    hint,
    num::TryFromIntError,
    ptr,
    sync::{
        atomic::{AtomicI64, AtomicU32, Ordering},
        mpsc::{channel, Sender},
        Arc,
    },
};

mod condvar;
mod futex;
mod mutex;

pub(super) struct UmtxManager {
    waiters: Gutex<HashMap<usize, VecDeque<WaitingThread>>>,
}

impl UmtxManager {
    pub fn new(sys: &mut Syscalls) -> Arc<Self> {
        let gg = GutexGroup::new();
        let umtx = Arc::new(UmtxManager {
            waiters: gg.spawn(HashMap::new()),
        });

        sys.register(454, &umtx, Self::sys__umtx_op);

        umtx
    }

    #[allow(non_snake_case)]
    fn sys__umtx_op(self: &Arc<Self>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let op: i32 = i.args[1].try_into().unwrap();

        if let Some(op) = OP_TABLE.get(op as usize) {
            op(self, td, i)
        } else {
            Err(SysErr::Raw(EINVAL))
        }
    }
}

struct WaitingThread {
    tx: Sender<()>,
}

static OP_TABLE: [fn(&Arc<UmtxManager>, &VThread, &SysIn) -> Result<SysOut, SysErr>; 23] = [
    lock_umtx,         // UMTX_OP_LOCK
    unlock_umtx,       // UMTX_OP_UNLOCK
    wait,              // UMTX_OP_WAIT
    wake,              // UMTX_OP_WAKE
    trylock_umutex,    // UMTX_OP_MUTEX_TRYLOCK
    lock_umutex,       // UMTX_OP_MUTEX_LOCK
    unlock_umutex,     // UMTX_OP_MUTEX_UNLOCK
    set_ceiling,       // UMTX_OP_SET_CEILING
    cv_wait,           // UMTX_OP_CV_WAIT
    cv_signal,         // UMTX_OP_CV_SIGNAL
    cv_broadcast,      // UMTX_OP_CV_BROADCAST
    wait_uint,         // UMTX_OP_WAIT_UINT
    rw_rdlock,         // UMTX_OP_RW_RDLOCK
    rw_wrlock,         // UMTX_OP_RW_WRLOCK
    rw_unlock,         // UMTX_OP_RW_UNLOCK
    wait_uint_private, // UMTX_OP_WAIT_UINT_PRIVATE
    wake_private,      // UMTX_OP_WAKE_PRIVATE
    wait_umutex,       // UMTX_OP_UMUTEX_WAIT
    wake_umutex,       // UMTX_OP_UMUTEX_WAKE
    sem_wait,          // UMTX_OP_SEM_WAIT
    sem_wake,          // UMTX_OP_SEM_WAKE
    nwake_private,     // UMTX_OP_NWAKE_PRIVATE
    wake2_umutex,      // UMTX_OP_UMUTEX_WAKE2
];

#[allow(unused_variables)] // TODO: remove when implementing
fn lock_umtx(mgr: &Arc<UmtxManager>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

#[allow(unused_variables)] // TODO: remove when implementing
fn unlock_umtx(mgr: &Arc<UmtxManager>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

#[allow(unused_variables)] // TODO: remove when implementing
fn wait(mgr: &Arc<UmtxManager>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    let obj: *const i64 = i.args[0].into();
    let val: i64 = i.args[2].into();
    let timeout: *const Timespec = i.args[3].into();

    info!("sys__umtx_wait({:#x}, {:#x})", obj as usize, val);

    if timeout != ptr::null() {
        todo!("wait: timeout")
    }

    // let atomic = unsafe { AtomicI64::from_ptr(obj as _) };

    // loop {
    //     let value = atomic.load(Ordering::Relaxed);

    //     if value != val {
    //         break;
    //     }

    //     hint::spin_loop();
    // }

    let mut waiters = mgr.waiters.write();

    let rx = match waiters.entry(obj as usize) {
        Entry::Occupied(mut e) => {
            let queue = e.get_mut();
            let (tx, rx) = channel();

            queue.push_back(WaitingThread { tx });

            rx
        }
        Entry::Vacant(v) => {
            let (tx, rx) = channel();
            let mut queue = VecDeque::new();
            queue.push_back(WaitingThread { tx });
            v.insert(queue);

            rx
        }
    };

    let _ = rx.recv().map_err(|_| SysErr::Raw(EINVAL))?;

    Ok(SysOut::ZERO)
}

#[allow(unused_variables)] // TODO: remove when implementing
fn wake(mgr: &Arc<UmtxManager>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

#[allow(unused_variables)] // TODO: remove when implementing
fn trylock_umutex(mgr: &Arc<UmtxManager>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

#[allow(unused_variables)] // TODO: remove when implementing
fn lock_umutex(mgr: &Arc<UmtxManager>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

#[allow(unused_variables)] // TODO: remove when implementing
fn unlock_umutex(mgr: &Arc<UmtxManager>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    let mutex_ptr: *const Umutex = i.args[0].into();

    info!("sys__umtx_mutex_unlock({:#x})", mutex_ptr as usize);

    let inner_mutex = unsafe { Mutex::from_ptr(mutex_ptr as _) };

    unsafe {
        inner_mutex.unlock();
    }

    Ok(SysOut::ZERO)
}

#[allow(unused_variables)] // TODO: remove when implementing
fn set_ceiling(mgr: &Arc<UmtxManager>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

fn cv_wait(mgr: &Arc<UmtxManager>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    let ucond_ptr: *const Ucond = i.args[0].into();
    let flags: CvWaitFlags = i.args[2].try_into().unwrap();
    let mutex_ptr: *const Umutex = i.args[3].into();
    let timeout: *const TimeSpec = i.args[4].into();

    info!(
        "sys__umtx_cv_wait({:#x}, {:?}, {:#x}, {:#x})",
        ucond_ptr as usize, flags, mutex_ptr as usize, timeout as usize
    );

    if timeout != ptr::null() {
        todo!("cv_wait: timeout is not null")
    }

    let inner_cv = unsafe { Condvar::from_ptr(ucond_ptr as _) };
    let inner_mutex = unsafe { Mutex::from_ptr(mutex_ptr as _) };

    unsafe { inner_cv.wait(&inner_mutex) };

    Ok(SysOut::ZERO)
}

#[allow(unused_variables)] // TODO: remove when implementing
fn cv_signal(mgr: &Arc<UmtxManager>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

#[allow(unused_variables)] // TODO: remove when implementing
fn cv_broadcast(mgr: &Arc<UmtxManager>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

fn wait_uint(mgr: &Arc<UmtxManager>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    let obj: *const u32 = i.args[0].into();
    let val: u32 = i.args[2].try_into().unwrap();

    info!("sys__umtx_wait_uint({:#x}, {:#x}", obj as usize, val);

    unsafe {
        let futex = AtomicU32::from_ptr(obj as _);
        futex_wait(futex, val, None);
    }

    Ok(SysOut::ZERO)
}

#[allow(unused_variables)] // TODO: remove when implementing
fn rw_rdlock(mgr: &Arc<UmtxManager>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

#[allow(unused_variables)] // TODO: remove when implementing
fn rw_wrlock(mgr: &Arc<UmtxManager>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

#[allow(unused_variables)] // TODO: remove when implementing
fn rw_unlock(mgr: &Arc<UmtxManager>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

#[allow(unused_variables)] // TODO: remove when implementing
fn wait_uint_private(mgr: &Arc<UmtxManager>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    let obj: *const u32 = i.args[0].into();
    let val: u32 = i.args[2].try_into().unwrap();
    let timeout: *const Timespec = i.args[3].into();

    info!(
        "sys__umtx_wait_uint_private({:#x}, {:#x})",
        obj as usize, val
    );

    if timeout != ptr::null() {
        todo!("wait: timeout")
    }

    // let atomic = unsafe { AtomicI64::from_ptr(obj as _) };

    // loop {
    //     let value = atomic.load(Ordering::Relaxed);

    //     if value != val {
    //         break;
    //     }

    //     hint::spin_loop();
    // }

    let mut waiters = mgr.waiters.write();

    let rx = match waiters.entry(obj as usize) {
        Entry::Occupied(mut e) => {
            let queue = e.get_mut();
            let (tx, rx) = channel();

            queue.push_back(WaitingThread { tx });

            rx
        }
        Entry::Vacant(v) => {
            let (tx, rx) = channel();
            let mut queue = VecDeque::new();
            queue.push_back(WaitingThread { tx });
            v.insert(queue);

            rx
        }
    };

    let _ = rx.recv().map_err(|_| SysErr::Raw(EINVAL))?;

    Ok(SysOut::ZERO)
}

#[allow(unused_variables)] // TODO: remove when implementing
fn wake_private(mgr: &Arc<UmtxManager>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

#[allow(unused_variables)] // TODO: remove when implementing
fn wait_umutex(mgr: &Arc<UmtxManager>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    let mutex_ptr: *const Umutex = i.args[0].into();

    info!("sys__umtx_wait_umutex({:#x})", mutex_ptr as usize);

    let inner_mutex = unsafe { Mutex::from_ptr(mutex_ptr as _) };

    inner_mutex.wait();

    Ok(SysOut::ZERO)
}

#[allow(unused_variables)] // TODO: remove when implementing
fn wake_umutex(mgr: &Arc<UmtxManager>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    let mutex_ptr: *const Umutex = i.args[0].into();

    info!("sys__umtx_wake_umutex({:#x})", mutex_ptr as usize);

    let inner_mutex = unsafe { Mutex::from_ptr(mutex_ptr as _) };

    unsafe {
        inner_mutex.wake();
    }

    Ok(SysOut::ZERO)
}

fn sem_wait(mgr: &Arc<UmtxManager>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    let sem_ptr: *const Usem2 = i.args[0].into();
    let arg_size: u32 = i.args[3].try_into().unwrap();
    let arg: usize = i.args[4].into();

    info!(
        "sys__umtx_sem_wait({:#x}, {:#x}, {:#x})",
        sem_ptr as usize, arg_size, arg
    );

    let inner_count = unsafe { AtomicU32::from_ptr(sem_ptr as _) };

    loop {
        if inner_count.load(Ordering::Relaxed) > 0 {
            break;
        }
        hint::spin_loop();
    }

    Ok(SysOut::ZERO)
}

#[allow(unused_variables)] // TODO: remove when implementing
fn sem_wake(mgr: &Arc<UmtxManager>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

#[allow(unused_variables)] // TODO: remove when implementing
fn nwake_private(mgr: &Arc<UmtxManager>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    let obj: *const usize = i.args[0].into();
    let val: usize = i.args[2].into();

    let keys = unsafe { std::slice::from_raw_parts(obj, val) };
    info!("sys__umtx_nwake_private({:#?})", keys);

    let mut waiters = mgr.waiters.write();

    for key in keys {
        match waiters.entry(obj as usize) {
            Entry::Occupied(mut e) => {
                let queue = e.get_mut();

                queue.retain(|wt| {
                    let _ = wt.tx.send(());
                    false
                });

                e.remove()
            }
            Entry::Vacant(v) => return Err(SysErr::Raw(EPERM)),
        };
    }

    return Ok(SysOut::ZERO);
}

#[allow(unused_variables)] // TODO: remove when implementing
fn wake2_umutex(mgr: &Arc<UmtxManager>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

#[repr(C)]
#[derive(Debug)]
struct Ucond {
    has_waiters: u32,
    flags: u32,
    clock_id: u32,
}

#[repr(C)]
#[derive(Debug)]
struct Umutex {
    owner: i32,
    flags: u32,
    ceilings: [u32; 2],
    rb_lnk: usize,
}

#[repr(C)]
#[derive(Debug)]
struct Usem2 {
    count: u32,
    flags: u32,
}

bitflags! {
    #[repr(C)]
    #[derive(Debug)]
    pub struct CvWaitFlags: u32 {
        const AbsTime = 0x02;
        const ClockId = 0x04;
    }
}

impl TryFrom<SysArg> for CvWaitFlags {
    type Error = TryFromIntError;

    fn try_from(value: SysArg) -> Result<Self, Self::Error> {
        Ok(Self::from_bits_retain(value.get().try_into()?))
    }
}
