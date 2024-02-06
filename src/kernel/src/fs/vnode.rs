use super::{unixify_access, Access, IoCmd, Mode, Mount, OpenFlags, VFile};
use crate::errno::{Errno, ENOTDIR, EOPNOTSUPP, EPERM};
use crate::process::VThread;
use crate::ucred::{Gid, Uid};
use gmtx::{Gutex, GutexGroup, GutexWriteGuard};
use std::any::Any;
use std::io::SeekFrom;
use std::num::NonZeroI32;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use thiserror::Error;

/// An implementation of `vnode`.
///
/// Each file/directory in the filesystem have a unique vnode. In other words, each file/directory
/// must have only one active vnode. The filesystem must use some mechanism to make sure a
/// file/directory have only one vnode.
#[derive(Debug)]
pub struct Vnode {
    fs: Arc<Mount>,                                  // v_mount
    ty: VnodeType,                                   // v_type
    tag: &'static str,                               // v_tag
    op: &'static VopVector,                          // v_op
    data: Arc<dyn Any + Send + Sync>,                // v_data
    item: Gutex<Option<Arc<dyn Any + Send + Sync>>>, // v_un
}

impl Vnode {
    /// See `getnewvnode` on the PS4 for a reference.
    pub fn new(
        fs: &Arc<Mount>,
        ty: VnodeType,
        tag: &'static str,
        op: &'static VopVector,
        data: Arc<dyn Any + Send + Sync>,
    ) -> Self {
        let gg = GutexGroup::new();

        ACTIVE.fetch_add(1, Ordering::Relaxed);

        Self {
            fs: fs.clone(),
            ty,
            tag,
            op,
            data,
            item: gg.spawn(None),
        }
    }

    pub fn fs(&self) -> &Arc<Mount> {
        &self.fs
    }

    pub fn ty(&self) -> &VnodeType {
        &self.ty
    }

    pub fn is_directory(&self) -> bool {
        matches!(self.ty, VnodeType::Directory(_))
    }

    pub fn is_character(&self) -> bool {
        matches!(self.ty, VnodeType::Character)
    }

    pub fn data(&self) -> &Arc<dyn Any + Send + Sync> {
        &self.data
    }

    pub fn item(&self) -> Option<Arc<dyn Any + Send + Sync>> {
        self.item.read().clone()
    }

    pub fn item_mut(&self) -> GutexWriteGuard<Option<Arc<dyn Any + Send + Sync>>> {
        self.item.write()
    }

    pub fn access(
        self: &Arc<Vnode>,
        td: Option<&VThread>,
        access: Access,
    ) -> Result<(), Box<dyn Errno>> {
        self.get_op(|v| v.access)(self, td, access)
    }

    pub fn accessx(
        self: &Arc<Self>,
        td: Option<&VThread>,
        access: Access,
    ) -> Result<(), Box<dyn Errno>> {
        self.get_op(|v| v.accessx)(self, td, access)
    }

    pub fn getattr(self: &Arc<Self>) -> Result<VnodeAttrs, Box<dyn Errno>> {
        self.get_op(|v| v.getattr)(self)
    }

    pub fn lookup(
        self: &Arc<Self>,
        td: Option<&VThread>,
        name: &str,
    ) -> Result<Arc<Self>, Box<dyn Errno>> {
        self.get_op(|v| v.lookup)(self, td, name)
    }

    pub fn open(
        self: &Arc<Self>,
        td: Option<&VThread>,
        flags: OpenFlags,
        file: Option<&mut VFile>,
    ) -> Result<(), Box<dyn Errno>> {
        self.get_op(|v| v.open)(self, td, flags, file)
    }

    pub fn read(
        self: &Arc<Self>,
        td: Option<&VThread>,
        buf: &mut [u8],
    ) -> Result<usize, Box<dyn Errno>> {
        self.get_op(|v| v.read)(self, td, buf)
    }

    pub fn write(
        self: &Arc<Self>,
        td: Option<&VThread>,
        buf: &[u8],
    ) -> Result<usize, Box<dyn Errno>> {
        self.get_op(|v| v.write)(self, td, buf)
    }

    pub fn ioctl(
        self: &Arc<Self>,
        cmd: IoCmd,
        buf: &mut [u8],
        td: Option<&VThread>,
    ) -> Result<i64, Box<dyn Errno>> {
        self.get_op(|v| v.ioctl)(self, td, cmd, buf)
    }

    pub fn seek(
        self: &Arc<Self>,
        pos: SeekFrom,
        td: Option<&VThread>,
    ) -> Result<u64, Box<dyn Errno>> {
        self.get_op(|v| v.seek)(self, td, pos)
    }

    fn get_op<F>(&self, f: fn(&'static VopVector) -> Option<F>) -> F {
        let mut vec = Some(self.op);

        while let Some(v) = vec {
            if let Some(f) = f(v) {
                return f;
            }

            vec = v.default;
        }

        panic!(
            "Invalid vop_vector for vnode from '{}' filesystem.",
            self.tag
        );
    }
}

impl Drop for Vnode {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::Relaxed);
    }
}

/// An implementation of `vtype`.
#[derive(Debug)]
pub enum VnodeType {
    Directory(bool), // VDIR
    Character,       // VCHR
    RegularFile,     // VREG
}

/// An implementation of `vop_vector` structure.
///
/// We don't support `vop_bypass` because it required the return type for all operations to be the
/// same.
#[derive(Debug)]
pub struct VopVector {
    pub default: Option<&'static Self>, // vop_default
    pub access: Option<VopAccess>,      // vop_access
    pub accessx: Option<VopAccessX>,    // vop_accessx
    pub getattr: Option<VopGetAttr>,    // vop_getattr
    pub lookup: Option<VopLookup>,      // vop_lookup
    pub open: Option<VopOpen>,          // vop_open
    pub read: Option<VopRead>,          // vop_read
    pub write: Option<VopWrite>,        // vop_write
    pub ioctl: Option<VopIoctl>,        // vop_ioctl
    pub seek: Option<VopSeek>,          // vop_seek
}

pub type VopAccess = fn(&Arc<Vnode>, Option<&VThread>, Access) -> Result<(), Box<dyn Errno>>;
pub type VopAccessX = fn(&Arc<Vnode>, Option<&VThread>, Access) -> Result<(), Box<dyn Errno>>;
pub type VopGetAttr = fn(&Arc<Vnode>) -> Result<VnodeAttrs, Box<dyn Errno>>;
pub type VopLookup = fn(&Arc<Vnode>, Option<&VThread>, &str) -> Result<Arc<Vnode>, Box<dyn Errno>>;
pub type VopOpen =
    fn(&Arc<Vnode>, Option<&VThread>, OpenFlags, Option<&mut VFile>) -> Result<(), Box<dyn Errno>>;
pub type VopRead = fn(&Arc<Vnode>, Option<&VThread>, &mut [u8]) -> Result<usize, Box<dyn Errno>>;
pub type VopWrite = fn(&Arc<Vnode>, Option<&VThread>, &[u8]) -> Result<usize, Box<dyn Errno>>;
pub type VopIoctl =
    fn(&Arc<Vnode>, Option<&VThread>, IoCmd, &mut [u8]) -> Result<i64, Box<dyn Errno>>;
pub type VopSeek = fn(&Arc<Vnode>, Option<&VThread>, SeekFrom) -> Result<u64, Box<dyn Errno>>;

/// An implementation of `vattr` struct.
pub struct VnodeAttrs {
    uid: Uid,   // va_uid
    gid: Gid,   // va_gid
    mode: Mode, // va_mode
    size: u64,  // va_size
}

impl VnodeAttrs {
    pub fn new(uid: Uid, gid: Gid, mode: Mode, size: u64) -> Self {
        Self {
            uid,
            gid,
            mode,
            size,
        }
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
}

/// Represents an error when [`DEFAULT_VNODEOPS`] is failed.
#[derive(Debug, Error)]
enum DefaultError {
    #[error("operation not supported")]
    NotSupported,

    #[error("operation not permitted")]
    NotPermitted,

    #[error("the vnode is not a directory")]
    NotDirectory,
}

impl Errno for DefaultError {
    fn errno(&self) -> NonZeroI32 {
        match self {
            Self::NotSupported => EOPNOTSUPP,
            Self::NotPermitted => EPERM,
            Self::NotDirectory => ENOTDIR,
        }
    }
}

/// An implementation of `default_vnodeops`.
pub static DEFAULT_VNODEOPS: VopVector = VopVector {
    default: None,
    access: Some(|vn, td, access| vn.accessx(td, access)),
    accessx: Some(accessx),
    getattr: Some(|_| Err(Box::new(DefaultError::NotSupported))), // Inline vop_bypass.
    lookup: Some(|_, _, _| Err(Box::new(DefaultError::NotDirectory))),
    open: None,
    read: None,
    write: None,
    ioctl: None,
    seek: None,
};

fn accessx(vn: &Arc<Vnode>, td: Option<&VThread>, access: Access) -> Result<(), Box<dyn Errno>> {
    let access = match unixify_access(access) {
        Some(v) => v,
        None => return Err(Box::new(DefaultError::NotPermitted)),
    };

    if access.is_empty() {
        return Ok(());
    }

    // This can create an infinity loop. Not sure why FreeBSD implement like this.
    vn.access(td, access)
}

static ACTIVE: AtomicUsize = AtomicUsize::new(0); // numvnodes
