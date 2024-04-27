use crate::budget::BudgetType;
use crate::errno::{Errno, EBADF, ENOTSOCK};
use crate::error;
use crate::fs::{FileBackend, IoLen, VFile, VFileFlags, VFileType, Vnode};
use crate::kqueue::KernelQueue;
use crate::net::{Socket, SocketFileBackend};
use gmtx::{Gutex, GutexGroup};
use macros::Errno;
use std::any::Any;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::ffi::CStr;
use std::num::{NonZeroI32, TryFromIntError};
use std::ops::Deref;
use std::sync::Arc;
use thiserror::Error;

/// An implementation of `filedesc` structure.
#[derive(Debug)]
pub struct FileDesc {
    files: Gutex<Vec<Option<Arc<VFile>>>>, // fd_ofiles + fd_nfiles
    cwd: Gutex<Arc<Vnode>>,                // fd_cdir
    root: Gutex<Arc<Vnode>>,               // fd_rdir
    kqueue_list: Gutex<VecDeque<Arc<KernelQueue>>>, // fd_kqlist
    cmask: u32,                            // fd_cmask
}

#[derive(Debug)]
struct StdTty {}

impl FileBackend for StdTty {
    fn write(
        &self,
        file: &VFile,
        off: u64,
        buf: &[crate::fs::IoVec],
        td: Option<&super::VThread>,
    ) -> Result<crate::fs::IoLen, Box<dyn Errno>> {
        let mut len = 0;
        let mut string = "".to_string();
        for iovec in buf {
            string = string + &String::from_utf8_lossy(iovec.deref());
            len = len + iovec.len().get();
        }
        eprint!("{}", string);

        Ok(IoLen::from_usize(len)?)
    }
    fn ioctl(
        &self,
        file: &VFile,
        cmd: crate::fs::IoCmd,
        td: Option<&super::VThread>,
    ) -> Result<(), Box<dyn Errno>> {
        todo!()
    }
    fn is_seekable(&self) -> bool {
        false
    }
    fn name(&self) -> Option<String> {
        todo!()
    }
    fn poll(
        &self,
        file: &VFile,
        events: crate::fs::PollEvents,
        td: &super::VThread,
    ) -> crate::fs::PollEvents {
        todo!()
    }
    fn read(
        &self,
        file: &VFile,
        off: u64,
        buf: &mut [crate::fs::IoVecMut],
        td: Option<&super::VThread>,
    ) -> Result<crate::fs::IoLen, Box<dyn Errno>> {
        todo!()
    }
    fn stat(
        &self,
        file: &VFile,
        td: Option<&super::VThread>,
    ) -> Result<crate::fs::Stat, Box<dyn Errno>> {
        todo!()
    }
    fn truncate(
        &self,
        file: &VFile,
        length: crate::fs::TruncateLength,
        td: Option<&super::VThread>,
    ) -> Result<(), Box<dyn Errno>> {
        todo!()
    }
}

impl FileDesc {
    pub(super) fn new(root: Arc<Vnode>) -> Arc<Self> {
        let gg = GutexGroup::new();

        let stderr = VFile::new(
            VFileType::Vnode,
            VFileFlags::WRITE,
            None,
            Box::new(StdTty {}),
        );

        let filedesc = Self {
            // TODO: the first 3 file descriptors should probably be ttyconsdev
            // set stdin, stdout, stderr !!!!!!
            files: gg.spawn(vec![None, None, Some(Arc::new(stderr))]),
            cwd: gg.spawn(root.clone()),
            root: gg.spawn(root),
            kqueue_list: gg.spawn(VecDeque::new()),
            cmask: 0o22, // TODO: verify this
        };

        Arc::new(filedesc)
    }

    pub fn cwd(&self) -> Arc<Vnode> {
        self.cwd.read().clone()
    }

    pub fn root(&self) -> Arc<Vnode> {
        self.root.read().clone()
    }

    pub fn insert_kqueue(&self, kq: Arc<KernelQueue>) {
        self.kqueue_list.write().push_front(kq);
    }

    pub fn cmask(&self) -> u32 {
        self.cmask
    }

    #[allow(unused_variables)] // TODO: remove when implementing; add budget argument
    pub fn alloc_with_budget<E: Errno>(
        &self,
        constructor: impl FnOnce(i32) -> Result<VFile, E>,
        _budget: BudgetType,
    ) -> Result<i32, FileAllocError<E>> {
        // TODO: check budget

        self.alloc_without_budget(constructor)
    }

    #[allow(unused_variables)] // TODO: remove when implementing;
    pub fn alloc_without_budget<E: Errno>(
        &self,
        constructor: impl FnOnce(i32) -> Result<VFile, E>,
    ) -> Result<i32, FileAllocError<E>> {
        // TODO: Implement fdalloc.
        let mut files = self.files.write();

        for i in 0..=(i32::MAX) as usize {
            if i == files.len() {
                let file = constructor(i as i32).map_err(FileAllocError::Inner)?;

                files.push(Some(Arc::new(file)));
            } else if files[i].is_none() {
                let file = constructor(i as i32).map_err(FileAllocError::Inner)?;

                files[i] = Some(Arc::new(file));
            } else {
                continue;
            }

            return Ok(i as i32);
        }

        // This should never happen.
        panic!("Too many files has been opened.");
    }

    /// See `finstall` on the PS4 for a reference.
    pub fn alloc(&self, file: Arc<VFile>) -> i32 {
        // TODO: Implement fdalloc.
        let mut files = self.files.write();

        for i in 0..=(i32::MAX) as usize {
            if i == files.len() {
                files.push(Some(file));
            } else if files[i].is_none() {
                files[i] = Some(file);
            } else {
                continue;
            }

            return i as i32;
        }

        // This should never happen.
        panic!("Too many files has been opened.");
    }

    // TODO: (maybe) implement capabilities

    /// See `getsock_cap` on the PS4 for a reference.
    pub fn get_socket(&self, fd: i32) -> Result<Arc<Socket>, GetSocketError> {
        let file = self.get(fd)?;

        let (VFileType::Socket | VFileType::IpcSocket) = file.ty() else {
            return Err(GetSocketError::NotSocket);
        };

        let so: &SocketFileBackend = (file.backend().as_ref() as &dyn Any)
            .downcast_ref()
            .expect("socket");
        Ok(so.0.clone())
    }

    /// See `fget` on the PS4 for a reference.
    pub fn get(&self, fd: i32) -> Result<Arc<VFile>, GetFileError> {
        self.get_internal(fd, VFileFlags::empty())
    }

    /// See `fget_write` on the PS4 for a reference.
    pub fn get_for_write(&self, fd: i32) -> Result<Arc<VFile>, GetFileError> {
        self.get_internal(fd, VFileFlags::WRITE)
    }

    /// See `fget_read` on the PS4 for a reference.
    pub fn get_for_read(&self, fd: i32) -> Result<Arc<VFile>, GetFileError> {
        self.get_internal(fd, VFileFlags::READ)
    }

    /// See `_fget` and `fget_unlocked` on the PS4 for a reference.
    fn get_internal(&self, fd: i32, flags: VFileFlags) -> Result<Arc<VFile>, GetFileError> {
        let fd: usize = fd.try_into()?;

        let files = self.files.write();

        let file = files
            .get(fd as usize)
            .ok_or(GetFileError::FdOutOfRange)? // None means the file descriptor is out of range
            .as_ref()
            .ok_or(GetFileError::NoFile)?; // Some(None) means the file descriptor is not associated with a file

        match flags {
            VFileFlags::WRITE | VFileFlags::READ if !file.flags().intersects(flags) => {
                return Err(GetFileError::BadFlags(flags, file.flags()));
            }
            _ => {}
        }

        Ok(file.clone())
    }

    /// See `kern_close` on the PS4 for a reference.
    pub fn free(&self, fd: i32) -> Result<(), FreeError> {
        let fd: usize = fd.try_into()?;

        let mut files = self.files.write();

        // TODO: implement knote_fdclose

        if let Some(file) = files.get_mut(fd) {
            *file = None;

            Ok(())
        } else {
            Err(FreeError::NoFile)
        }
    }
}

#[derive(Debug, Error, Errno)]
pub enum GetSocketError {
    #[error("failed to get file")]
    GetFileError(#[from] GetFileError),

    #[error("file is not a socket")]
    #[errno(ENOTSOCK)]
    NotSocket,
}

#[derive(Debug, Error, Errno)]
pub enum GetFileError {
    #[error("got negative file descriptor")]
    #[errno(EBADF)]
    NegativeFd,

    #[error("file descriptor is out of range")]
    #[errno(EBADF)]
    FdOutOfRange,

    #[error("no file assoiated with file descriptor")]
    #[errno(EBADF)]
    NoFile,

    #[error("bad flags associated with file descriptor: expected {0:?}, file has {1:?}")]
    #[errno(EBADF)]
    BadFlags(VFileFlags, VFileFlags),
}

impl From<TryFromIntError> for GetFileError {
    fn from(_: TryFromIntError) -> Self {
        GetFileError::NegativeFd
    }
}

#[derive(Debug, Error)]
pub enum FileAllocError<E: Errno = Infallible> {
    #[error(transparent)]
    Inner(E),
}

impl<E: Errno> Errno for FileAllocError<E> {
    fn errno(&self) -> NonZeroI32 {
        match self {
            Self::Inner(e) => e.errno(),
        }
    }
}

#[derive(Debug, Error, Errno)]
pub enum FreeError {
    #[error("negative file descriptor provided")]
    #[errno(EBADF)]
    NegativeFd,

    #[error("no file associated with file descriptor")]
    #[errno(EBADF)]
    NoFile,
}

impl From<TryFromIntError> for FreeError {
    fn from(_: TryFromIntError) -> Self {
        FreeError::NegativeFd
    }
}
