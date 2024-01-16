use crate::syscalls::{SysErr, SysOut};
use std::{io::Error, num::NonZeroI32};

#[repr(C)]
#[derive(Debug)]
pub struct Timespec {
    pub seconds: i64,     // tv_sec
    pub nanoseconds: i64, // tv_nsec
}

impl Timespec {
    pub fn nanosleep(ts: &Timespec) -> Result<SysOut, SysErr> {
        match Self::raw_nanosleep(ts) {
            Err(error) => Err(SysErr::Raw(unsafe {
                NonZeroI32::new_unchecked(error.raw_os_error().unwrap())
            })),
            Ok(_) => Ok(0.into()),
        }
    }

    #[cfg(unix)]
    fn raw_nanosleep(ts: &Timespec) -> Result<std::ffi::c_int, Error> {
        use std::mem::zeroed;

        let mut req = ::libc::timespec {
            tv_sec: ts.seconds,
            tv_nsec: ts.nanoseconds,
        };

        let mut rem = unsafe { zeroed() };

        loop {
            let ret = unsafe { ::libc::nanosleep(&req, &mut rem) };

            if ret == 0 {
                return Ok(0.into());
            } else {
                if Error::last_os_error().raw_os_error().unwrap() == ::libc::EINTR {
                    req = rem;
                    rem = unsafe { zeroed() }
                } else {
                    return Err(Error::last_os_error());
                }
            }
        }
    }

    #[cfg(windows)]
    fn raw_nanosleep(ts: &Timespec) -> Result<std::ffi::c_int, Error> {
        use std::sync::{Arc, Condvar, Mutex};
        use windows_sys::Win32::Foundation::{BOOLEAN, HANDLE};
        use windows_sys::Win32::System::Threading::{CreateTimerQueueTimer, WT_EXECUTEONLYONCE};

        pub type Timer = HANDLE;

        let pair: Arc<(Mutex<bool>, Condvar)> = Arc::new((Mutex::new(false), Condvar::new()));
        let pair2 = pair.clone();

        unsafe extern "system" fn callback(arg: *mut ::core::ffi::c_void, _: BOOLEAN) {
            let pair2: Arc<(Mutex<bool>, Condvar)> = Arc::from_raw(arg as _);
            let (lock, cvar) = &*pair2;
            let mut triggered = lock.lock().unwrap();
            *triggered = true;
            cvar.notify_one();
        }

        let milliseconds = ts.seconds * 1000 + ts.nanoseconds / 1000000;

        let timerhandle = HANDLE::default();
        let ret = CreateTimerQueueTimer(
            &mut timerhandle,
            0,
            Some(callback),
            Some(Arc::into_raw(pair2)),
            milliseconds as u32,
            0,
            WT_EXECUTEONLYONCE,
        );

        let (lock, cvar) = &*pair;
        let mut triggered = lock.lock().unwrap();
        while !*triggered {
            triggered = cvar.wait(triggered).unwrap();
        }

        if ret > 0 {
            return Ok(0.into());
        } else {
            return Err(Error::last_os_error());
        }
    }
}
