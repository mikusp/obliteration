use std::sync::atomic::AtomicU32;
use std::time::Duration;

/// Wait for a futex_wake operation to wake us.
///
/// Returns directly if the futex doesn't hold the expected value.
///
/// Returns false on timeout, and true in all other cases.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn futex_wait(futex: &AtomicU32, expected: u32, timeout: Option<Duration>) -> bool {
    use std::ptr::null;
    use std::sync::atomic::Ordering::Relaxed;

    // Calculate the timeout as an absolute timespec.
    //
    // Overflows are rounded up to an infinite timeout (None).
    let timespec = timeout
        .and_then(|d| Timespec::now(libc::CLOCK_MONOTONIC).checked_add_duration(&d))
        .and_then(|t| t.to_timespec());

    loop {
        // No need to wait if the value already changed.
        if futex.load(Relaxed) != expected {
            return true;
        }

        let r = unsafe {
            // Use FUTEX_WAIT_BITSET rather than FUTEX_WAIT to be able to give an
            // absolute time rather than a relative time.
            libc::syscall(
                libc::SYS_futex,
                futex as *const AtomicU32,
                libc::FUTEX_WAIT_BITSET | libc::FUTEX_PRIVATE_FLAG,
                expected,
                timespec
                    .as_ref()
                    .map_or(null(), |t| t as *const libc::timespec),
                null::<u32>(), // This argument is unused for FUTEX_WAIT_BITSET.
                !0u32,         // A full bitmask, to make it behave like a regular FUTEX_WAIT.
            )
        };

        match (r < 0).then(|| std::io::Error::last_os_error().raw_os_error().unwrap()) {
            Some(libc::ETIMEDOUT) => return false,
            Some(libc::EINTR) => continue,
            _ => return true,
        }
    }
}

/// Wake up one thread that's blocked on futex_wait on this futex.
///
/// Returns true if this actually woke up such a thread,
/// or false if no thread was waiting on this futex.
///
/// On some platforms, this always returns false.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn futex_wake(futex: &AtomicU32) -> bool {
    let ptr = futex as *const AtomicU32;
    let op = libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG;
    unsafe { libc::syscall(libc::SYS_futex, ptr, op, 1) > 0 }
}

/// Wake up all threads that are waiting on futex_wait on this futex.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn futex_wake_all(futex: &AtomicU32) {
    let ptr = futex as *const AtomicU32;
    let op = libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG;
    unsafe {
        libc::syscall(libc::SYS_futex, ptr, op, i32::MAX);
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
struct Nanoseconds(u32);

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Timespec {
    tv_sec: i64,
    tv_nsec: Nanoseconds,
}

impl Timespec {
    pub fn now(clock: libc::clockid_t) -> Timespec {
        use std::mem::MaybeUninit;

        let mut t = MaybeUninit::uninit();
        if (unsafe { libc::clock_gettime(clock, t.as_mut_ptr()) }) == -1 {
            panic!("Timespec::now()")
        };
        Timespec::from(unsafe { t.assume_init() })
    }

    const fn new(tv_sec: i64, tv_nsec: i64) -> Timespec {
        assert!(tv_nsec >= 0 && tv_nsec < NSEC_PER_SEC as i64);
        // SAFETY: The assert above checks tv_nsec is within the valid range
        Timespec {
            tv_sec,
            tv_nsec: unsafe { Nanoseconds(tv_nsec as u32) },
        }
    }

    pub fn checked_add_duration(&self, other: &Duration) -> Option<Timespec> {
        let mut secs = self.tv_sec.checked_add_unsigned(other.as_secs())?;

        // Nano calculations can't overflow because nanos are <1B which fit
        // in a u32.
        let mut nsec = other.subsec_nanos() + self.tv_nsec.0;
        if nsec >= NSEC_PER_SEC as u32 {
            nsec -= NSEC_PER_SEC as u32;
            secs = secs.checked_add(1)?;
        }
        Some(Timespec::new(secs, nsec.into()))
    }

    #[allow(dead_code)]
    pub fn to_timespec(&self) -> Option<libc::timespec> {
        Some(libc::timespec {
            tv_sec: self.tv_sec.try_into().ok()?,
            tv_nsec: self.tv_nsec.0.try_into().ok()?,
        })
    }
}

const NSEC_PER_SEC: u64 = 1_000_000_000;

impl From<libc::timespec> for Timespec {
    fn from(t: libc::timespec) -> Timespec {
        Timespec::new(t.tv_sec as i64, t.tv_nsec as i64)
    }
}
