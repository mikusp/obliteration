use crate::time::TimeSpec;

/// An implementation of the `stat` structure.
#[repr(C)]
pub struct Stat {
    dev: i32,
    ino: u32,
    pub mode: u16,
    nlink: u16,
    uid: u32,
    gid: u32,
    rdev: i32,
    atime: TimeSpec,
    mtime: TimeSpec,
    ctime: TimeSpec,
    pub size: i64,
    block_count: i64,
    pub block_size: u32,
    flags: u32,
    gen: u32,
    _spare: i32,
    birthtime: TimeSpec,
}

impl Stat {
    /// This is what would happen when calling `bzero` on a `stat` structure.
    pub fn zeroed() -> Self {
        unsafe { std::mem::zeroed() }
    }

    pub fn from_native(st: libc::stat) -> Stat {
        Stat {
            dev: st.st_dev as _,
            ino: st.st_ino as _,
            mode: st.st_mode as _,
            nlink: st.st_nlink as _,
            uid: st.st_uid,
            gid: st.st_gid,
            rdev: st.st_rdev as _,
            atime: TimeSpec {
                sec: st.st_atime,
                nsec: st.st_atime_nsec,
            },
            mtime: TimeSpec {
                sec: st.st_mtime,
                nsec: st.st_mtime_nsec,
            },
            ctime: TimeSpec {
                sec: st.st_ctime,
                nsec: st.st_ctime_nsec,
            },
            size: st.st_size,
            block_count: st.st_blocks,
            block_size: st.st_blksize as _,
            flags: 0,
            gen: 0,
            _spare: 0,
            birthtime: TimeSpec {
                sec: st.st_ctime,
                nsec: st.st_ctime_nsec,
            },
        }
    }
}
