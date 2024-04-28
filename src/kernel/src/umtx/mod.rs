use bitflags::bitflags;

use crate::{
    errno::EINVAL,
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
    hint,
    num::TryFromIntError,
    ptr,
    sync::{
        atomic::{AtomicI64, AtomicU32, Ordering},
        Arc,
    },
};

mod condvar;
mod futex;
mod mutex;

pub(super) struct UmtxManager {}

impl UmtxManager {
    pub fn new(sys: &mut Syscalls) -> Arc<Self> {
        let umtx = Arc::new(UmtxManager {});

        sys.register(454, &umtx, Self::sys__umtx_op);

        umtx
    }

    #[allow(non_snake_case)]
    fn sys__umtx_op(self: &Arc<Self>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let op: i32 = i.args[1].try_into().unwrap();

        if let Some(op) = OP_TABLE.get(op as usize) {
            op(td, i)
        } else {
            Err(SysErr::Raw(EINVAL))
        }
    }
}

static OP_TABLE: [fn(&VThread, &SysIn) -> Result<SysOut, SysErr>; 23] = [
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
fn lock_umtx(td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

#[allow(unused_variables)] // TODO: remove when implementing
fn unlock_umtx(td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

#[allow(unused_variables)] // TODO: remove when implementing
fn wait(td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    let obj: *const i64 = i.args[0].into();
    let val: i64 = i.args[2].into();
    let timeout: *const Timespec = i.args[3].into();

    info!("sys__umtx_wait({:#x}, {:#x})", obj as usize, val);

    if timeout != ptr::null() {
        todo!("wait: timeout")
    }

    let atomic = unsafe { AtomicI64::from_ptr(obj as _) };

    loop {
        let value = atomic.load(Ordering::Relaxed);

        if value != val {
            break;
        }

        hint::spin_loop();
    }

    Ok(SysOut::ZERO)
}

#[allow(unused_variables)] // TODO: remove when implementing
fn wake(td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

#[allow(unused_variables)] // TODO: remove when implementing
fn trylock_umutex(td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

#[allow(unused_variables)] // TODO: remove when implementing
fn lock_umutex(td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

#[allow(unused_variables)] // TODO: remove when implementing
fn unlock_umutex(td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    let mutex_ptr: *const Umutex = i.args[0].into();

    info!("sys__umtx_mutex_unlock({:#x})", mutex_ptr as usize);

    let inner_mutex = unsafe { Mutex::from_ptr(mutex_ptr as _) };

    unsafe {
        inner_mutex.unlock();
    }

    Ok(SysOut::ZERO)
}

#[allow(unused_variables)] // TODO: remove when implementing
fn set_ceiling(td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

fn cv_wait(td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
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
fn cv_signal(td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

#[allow(unused_variables)] // TODO: remove when implementing
fn cv_broadcast(td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

fn wait_uint(_: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
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
fn rw_rdlock(td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

#[allow(unused_variables)] // TODO: remove when implementing
fn rw_wrlock(td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

#[allow(unused_variables)] // TODO: remove when implementing
fn rw_unlock(td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

#[allow(unused_variables)] // TODO: remove when implementing
fn wait_uint_private(td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

#[allow(unused_variables)] // TODO: remove when implementing
fn wake_private(td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

#[allow(unused_variables)] // TODO: remove when implementing
fn wait_umutex(td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    let mutex_ptr: *const Umutex = i.args[0].into();

    info!("sys__umtx_wait_umutex({:#x})", mutex_ptr as usize);

    let inner_mutex = unsafe { Mutex::from_ptr(mutex_ptr as _) };

    inner_mutex.wait();

    Ok(SysOut::ZERO)
}

#[allow(unused_variables)] // TODO: remove when implementing
fn wake_umutex(td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    let mutex_ptr: *const Umutex = i.args[0].into();

    info!("sys__umtx_wake_umutex({:#x})", mutex_ptr as usize);

    let inner_mutex = unsafe { Mutex::from_ptr(mutex_ptr as _) };

    unsafe {
        inner_mutex.wake();
    }

    Ok(SysOut::ZERO)
}

fn sem_wait(td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
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
fn sem_wake(td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

#[allow(unused_variables)] // TODO: remove when implementing
fn nwake_private(td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
    todo!()
}

#[allow(unused_variables)] // TODO: remove when implementing
fn wake2_umutex(td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
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
