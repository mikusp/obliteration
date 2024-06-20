use super::dirent::Dirent;
use crate::errno::{Errno, ENODEV, ENOTTY};
use crate::fs::{
    FileBackend, IoCmd, IoLen, IoVec, IoVecMut, Mode, OpenFlags, PollEvents, Stat, TruncateLength,
    VFile,
};
use crate::process::VThread;
use crate::time::TimeSpec;
use crate::ucred::{Gid, Ucred, Uid};
use crate::{error, info};
use bitflags::bitflags;
use gmtx::{Gutex, GutexGroup, GutexReadGuard, GutexWriteGuard};
use macros::Errno;
use std::fmt::Debug;
use std::sync::{Arc, Weak};
use thiserror::Error;

/// An implementation of `cdev` and `cdev_priv` structures.
#[derive(Debug)]
pub struct CharacterDevice {
    driver: Box<dyn DeviceDriver>,             // si_devsw
    unit: i32,                                 // si_drv0
    name: String,                              // si_name
    uid: Uid,                                  // si_uid
    gid: Gid,                                  // si_gid
    mode: Mode,                                // si_mode
    ctime: TimeSpec,                           // si_ctime
    atime: TimeSpec,                           // si_atime
    mtime: TimeSpec,                           // si_mtime
    cred: Option<Arc<Ucred>>,                  // si_cred
    max_io: usize,                             // si_iosize_max
    flags: DeviceFlags,                        // si_flags
    inode: i32,                                // cdp_inode
    dirents: Gutex<Vec<Option<Weak<Dirent>>>>, // cdp_dirents + cdp_maxdirent
}

impl CharacterDevice {
    /// See `devfs_alloc` on the PS4 for a reference.
    pub(super) fn new(
        unit: i32,
        name: impl Into<String>,
        uid: Uid,
        gid: Gid,
        mode: Mode,
        cred: Option<Arc<Ucred>>,
        flags: DeviceFlags,
        inode: i32,
        driver: impl DeviceDriver,
    ) -> Self {
        let gg = GutexGroup::new();
        let now = TimeSpec::now();

        Self {
            driver: Box::new(driver),
            inode,
            unit,
            name: name.into(),
            uid,
            gid,
            mode,
            ctime: now,
            atime: now,
            mtime: now,
            cred,
            max_io: 0x10000,
            flags,
            dirents: gg.spawn(vec![None]),
        }
    }

    pub fn open(
        self: &Arc<Self>,
        mode: OpenFlags,
        devtype: i32,
        td: Option<&VThread>,
    ) -> Result<(), Box<dyn Errno>> {
        self.driver.open(self, mode, devtype, td)
    }

    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    pub fn uid(&self) -> Uid {
        self.uid
    }

    pub fn gid(&self) -> Gid {
        self.gid
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn flags(&self) -> DeviceFlags {
        self.flags
    }

    pub(super) fn inode(&self) -> i32 {
        self.inode
    }

    pub(super) fn dirents(&self) -> GutexReadGuard<Vec<Option<Weak<Dirent>>>> {
        self.dirents.read()
    }

    pub(super) fn dirents_mut(&self) -> GutexWriteGuard<Vec<Option<Weak<Dirent>>>> {
        self.dirents.write()
    }
}

/// Implementation of `devfs_ops_f`.
#[derive(Debug)]
pub struct CdevFileBackend(pub Arc<CharacterDevice>);

impl CdevFileBackend {
    pub fn new(dev: Arc<CharacterDevice>) -> Self {
        Self(dev)
    }
}

impl FileBackend for CdevFileBackend {
    fn name(&self) -> Option<String> {
        Some(self.0.clone().name.clone())
    }
    fn is_seekable(&self) -> bool {
        true
    }

    fn read(
        &self,
        file: &VFile,
        off: u64,
        buf: &mut [IoVecMut],
        td: Option<&VThread>,
    ) -> Result<IoLen, Box<dyn Errno>> {
        let mut handled = false;

        use crate::fs::VnodeItem::Device;
        file.vnode().and_then(|vn| {
            vn.item().clone().and_then(|item| match item {
                Device(cdev) => {
                    if cdev.name == "urandom" {
                        handled = true;
                    } else {
                        error!("read from {}", cdev.name);
                    }

                    None::<()>
                }
                _ => None,
            })
        });

        if !handled {
            error!("cdev read");
        }

        return Ok(buf.first().unwrap().len());
    }

    fn write(
        &self,
        file: &VFile,
        off: u64,
        buf: &[IoVec],
        td: Option<&VThread>,
    ) -> Result<IoLen, Box<dyn Errno>> {
        let mut printed = false;
        use crate::fs::VnodeItem::Device;
        file.vnode().and_then(|vn| {
            vn.item().clone().and_then(|item| match item {
                Device(cdev) => {
                    if cdev.name == "console" || cdev.name == "deci_tty6" {
                        for b in buf {
                            let cstr: &[u8] = &*b;
                            info!("{}", String::from_utf8(Vec::from(cstr)).unwrap());
                        }
                        printed = true;
                    } else {
                        error!("write to {}", cdev.name);
                    }

                    None::<()>
                }
                _ => None,
            })
        });

        if !printed {
            error!("cdev write");
        }

        return Ok(buf.first().unwrap().len());
    }

    fn ioctl(&self, file: &VFile, cmd: IoCmd, td: Option<&VThread>) -> Result<(), Box<dyn Errno>> {
        match cmd {
            IoCmd::FIODTYPE(_) => todo!(),
            IoCmd::FIODGNAME(_) => todo!(),
            _ => self.0.driver.ioctl(&self.0, cmd, td)?,
        }

        Ok(())
    }

    fn poll(&self, file: &VFile, events: PollEvents, td: &VThread) -> PollEvents {
        todo!()
    }

    fn stat(&self, file: &VFile, td: Option<&VThread>) -> Result<Stat, Box<dyn Errno>> {
        todo!()
    }

    fn truncate(
        &self,
        file: &VFile,
        length: TruncateLength,
        td: Option<&VThread>,
    ) -> Result<(), Box<dyn Errno>> {
        todo!()
    }
}

bitflags! {
    /// Flags for [`Cdev`].
    #[derive(Debug, Clone, Copy)]
    pub struct DeviceFlags: u32 {
        const SI_ETERNAL = 0x01;
        const SI_ALIAS = 0x02;
    }
}

bitflags! {
    /// Flags for [`CdevSw`].
    #[derive(Debug, Clone, Copy)]
    pub struct DriverFlags: u32 {
        const D_NEEDMINOR = 0x00800000;
        const D_INIT = 0x80000000;
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct FioDeviceGetNameArg {
    len: i32,
    buf: *mut u8,
}

/// An implementation of the `cdevsw` structure.
pub trait DeviceDriver: Debug + Sync + Send + 'static {
    #[allow(unused_variables)]
    fn open(
        &self,
        dev: &Arc<CharacterDevice>,
        mode: OpenFlags,
        devtype: i32,
        td: Option<&VThread>,
    ) -> Result<(), Box<dyn Errno>> {
        Ok(())
    }

    #[allow(unused_variables)]
    fn read(
        &self,
        dev: &Arc<CharacterDevice>,
        off: Option<u64>, // TODO: Check if we actually need this for a character device.
        buf: &mut [IoVecMut],
        td: Option<&VThread>,
    ) -> Result<IoLen, Box<dyn Errno>> {
        Err(Box::new(DefaultDeviceError::ReadNotSupported))
    }

    #[allow(unused_variables)]
    fn write(
        &self,
        dev: &Arc<CharacterDevice>,
        off: Option<u64>, // TODO: Check if we actually need this for a character device.
        buf: &[IoVec],
        td: Option<&VThread>,
    ) -> Result<IoLen, Box<dyn Errno>> {
        Err(Box::new(DefaultDeviceError::WriteNotSupported))
    }

    #[allow(unused_variables)]
    fn ioctl(
        &self,
        dev: &Arc<CharacterDevice>,
        cmd: IoCmd,
        td: Option<&VThread>,
    ) -> Result<(), Box<dyn Errno>> {
        Err(Box::new(DefaultDeviceError::IoctlNotSupported))
    }
}

#[derive(Debug, Error, Errno)]
pub enum DefaultDeviceError {
    #[error("read not supported")]
    #[errno(ENODEV)]
    ReadNotSupported,

    #[error("write not supported")]
    #[errno(ENODEV)]
    WriteNotSupported,

    #[error("ioctl not supported")]
    #[errno(ENODEV)]
    IoctlNotSupported,

    #[error("command not supported")]
    #[errno(ENOTTY)]
    CommandNotSupported,
}
