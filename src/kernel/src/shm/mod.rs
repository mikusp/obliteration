use crate::errno::{self, Errno, EINVAL, EMFILE, ENOENT};
use crate::fs::{
    check_access, Access, AccessError, DefaultFileBackendError, FileBackend, IoCmd, IoLen, IoVec,
    IoVecMut, Mode, OpenFlags, PollEvents, Stat, TruncateLength, VFile, VFileFlags, VFileType,
    VPathBuf,
};
use crate::process::VThread;
use crate::syscalls::{SysErr, SysIn, SysOut, Syscalls};
use crate::ucred::{Gid, Ucred, Uid};
use crate::vm::{MappingFlags, MmapError, Protections, VmObject};
use crate::{error, info};
use bitflags::Flags;
use macros::Errno;
use std::any::Any;
use std::convert::Infallible;
use std::ops::Deref;
use std::sync::Arc;
use thiserror::Error;

pub struct SharedMemoryManager {}

impl SharedMemoryManager {
    pub fn new(sys: &mut Syscalls) -> Arc<Self> {
        let shm = Arc::new(Self {});

        sys.register(482, &shm, Self::sys_shm_open);
        sys.register(483, &shm, Self::sys_shm_unlink);

        shm
    }

    fn sys_shm_open(self: &Arc<Self>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let path = unsafe { i.args[0].to_shm_path() }?.expect("invalid shm path");
        let flags: OpenFlags = i.args[1].try_into().unwrap();
        let mode: u32 = i.args[2].try_into().unwrap();

        info!("...=sys_shm_open({:?}, {}, {})", path, flags, mode);

        if (flags & OpenFlags::O_ACCMODE).union(OpenFlags::O_RDWR) != OpenFlags::O_RDWR {
            return Err(SysErr::Raw(EINVAL));
        }

        if flags.bits() & 0xffdff1fc != 0 {
            return Err(SysErr::Raw(EINVAL));
        }

        let filedesc = td.proc().files();

        #[allow(unused_variables)] // TODO: remove when implementing.
        let mode = mode & filedesc.cmask() & 0o777;
        let path_ = path.clone();

        let fd = filedesc.alloc_without_budget::<ShmError>(|_| match path.clone() {
            ShmPath::Anon => {
                todo!()
            }
            ShmPath::Path(ref vpath) => {
                if !vpath.starts_with('/') {
                    return Err(ShmError::InvalidPath);
                }

                if td.cred().is_webcore_process() && !vpath.starts_with("/SceWebCore/") {
                    return Err(ShmError::InvalidShmForWebProcess(vpath.clone()));
                }

                // TODO: find shm in hashtable

                if flags.intersects(OpenFlags::O_CREAT) {
                    let file_flags = if flags.intersects(OpenFlags::O_RDWR) {
                        VFileFlags::READ | VFileFlags::WRITE
                    } else if flags.intersects(OpenFlags::O_WRONLY) {
                        VFileFlags::WRITE
                    } else {
                        VFileFlags::READ
                    };

                    let shm_fd = memfd::MemfdOptions::default()
                        .create(vpath.to_string())
                        .map_err(|_| ShmError::CreateFailed)?;

                    let shm = SharedMemory {
                        path,
                        uid: td.cred().effective_uid(),
                        gid: *td.cred().groups().first().unwrap(),
                        mode: Mode::new(mode as u16).unwrap(),
                        shm_fd,
                    };

                    Ok(VFile::new(
                        VFileType::SharedMemory,
                        file_flags,
                        None,
                        Box::new(shm),
                    ))
                } else {
                    Err(ShmError::NotFound(vpath.clone()))
                }
            }
        })?;

        info!("{}=sys_shm_open({:?}, {}, {})", fd, path_, flags, mode);

        Ok(fd.into())
    }

    #[allow(unused_variables)] // TODO: remove when implementing.
    fn sys_shm_unlink(self: &Arc<Self>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        todo!("sys_shm_unlink")
    }

    pub fn mmap(file: Arc<VFile>, len: usize, offset: i64) -> Result<VmObject, MmapError> {
        let backend = file.backend().as_ref() as &dyn Any;
        let shmfd: &SharedMemory = (backend as &dyn Any)
            .downcast_ref()
            .expect("shm handle is not shm");

        // use std::os::fd::AsRawFd;

        // let addr = unsafe {
        //     libc::mmap(
        //         std::ptr::null_mut(),
        //         len,
        //         libc::PROT_READ | libc::PROT_WRITE,
        //         libc::MAP_SHARED,
        //         shmfd.shm_fd.as_raw_fd(),
        //         offset,
        //     )
        // };

        // if addr == libc::MAP_FAILED {
        //     Err(MmapError::NoMem(len))
        // } else {
        //     Ok(addr as usize)
        // }

        Ok(VmObject {})
    }
}

#[derive(Clone, Debug)]
pub enum ShmPath {
    Anon,
    Path(VPathBuf),
}

/// An implementation of the `shmfd` structure.
#[derive(Debug)]
#[allow(unused_variables)] // TODO: remove when used.
pub struct SharedMemory {
    path: ShmPath,
    uid: Uid,
    gid: Gid,
    mode: Mode,
    pub shm_fd: memfd::Memfd,
}

impl SharedMemory {
    /// See `shm_do_truncate` on the PS4 for a reference.
    fn do_truncate(&self, length: TruncateLength) -> Result<(), TruncateError> {
        info!("shm_do_truncate({:?}, {:#x})", self.path, length.0);

        use std::os::fd::AsRawFd;

        if unsafe { libc::ftruncate(self.shm_fd.as_raw_fd(), length.0) } < 0 {
            Err(TruncateError::TruncateError)
        } else {
            Ok(())
        }
    }

    /// See `shm_access` on the PS4 for a reference.
    #[allow(dead_code)] // TODO: remove when used.
    fn access(&self, cred: &Ucred, flags: VFileFlags) -> Result<(), AccessError> {
        let mut access = Access::empty();

        if flags.intersects(VFileFlags::READ) {
            access |= Access::READ;
        }

        if flags.intersects(VFileFlags::WRITE) {
            access |= Access::WRITE;
        }

        check_access(cred, self.uid, self.gid, self.mode, access, false)?;

        Ok(())
    }

    pub fn fd(&self) -> i32 {
        use std::os::fd::AsRawFd;

        self.shm_fd.as_raw_fd()
    }
}

impl FileBackend for SharedMemory {
    fn is_seekable(&self) -> bool {
        todo!()
    }

    fn read(
        &self,
        _: &VFile,
        _: u64,
        _: &mut [IoVecMut],
        _: Option<&VThread>,
    ) -> Result<IoLen, Box<dyn Errno>> {
        Err(Box::new(DefaultFileBackendError::OperationNotSupported))
    }

    fn write(
        &self,
        _: &VFile,
        _: u64,
        _: &[IoVec],
        _: Option<&VThread>,
    ) -> Result<IoLen, Box<dyn Errno>> {
        Err(Box::new(DefaultFileBackendError::OperationNotSupported))
    }

    #[allow(unused_variables)] // remove when implementing
    fn ioctl(&self, file: &VFile, cmd: IoCmd, td: Option<&VThread>) -> Result<(), Box<dyn Errno>> {
        todo!()
    }

    #[allow(unused_variables)] // TODO: remove when implementing
    fn poll(&self, file: &VFile, events: PollEvents, td: &VThread) -> PollEvents {
        todo!()
    }

    #[allow(unused_variables)] // remove when implementing
    fn stat(&self, file: &VFile, td: Option<&VThread>) -> Result<Stat, Box<dyn Errno>> {
        let mut stat = Stat::zeroed();

        stat.block_size = 0x4000;

        todo!()
    }

    fn truncate(
        &self,
        _: &VFile,
        length: TruncateLength,
        _: Option<&VThread>,
    ) -> Result<(), Box<dyn Errno>> {
        self.do_truncate(length)?;

        Ok(())
    }
}

#[derive(Debug, Error, Errno)]
pub enum TruncateError {
    #[error("truncate error")]
    #[errno(EINVAL)]
    TruncateError,
}

#[derive(Debug, Error, Errno)]
pub enum ShmError {
    #[error("path doesn't start with /")]
    #[errno(EINVAL)]
    InvalidPath,

    #[error("webcore process cannot open shm {0}")]
    #[errno(ENOENT)]
    InvalidShmForWebProcess(VPathBuf),

    #[error("shm not found {0}")]
    #[errno(ENOENT)]
    NotFound(VPathBuf),

    #[error("creating memfd failed")]
    #[errno(EMFILE)]
    CreateFailed,
}
