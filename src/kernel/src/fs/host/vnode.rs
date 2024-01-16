use super::file::HostFile;
use super::{get_vnode, GetVnodeError, ReadError, SeekError};
use crate::errno::{Errno, EIO, ENOENT, ENOTDIR};
use crate::fs::{
    Access, Mode, OpenFlags, VFile, Vnode, VnodeAttrs, VnodeType, VopVector, DEFAULT_VNODEOPS,
};
use crate::info;
use crate::process::VThread;
use crate::ucred::{Gid, Uid};
use std::borrow::Cow;
use std::io::SeekFrom;
use std::num::NonZeroI32;
use std::sync::Arc;
use thiserror::Error;

pub static VNODE_OPS: VopVector = VopVector {
    default: Some(&DEFAULT_VNODEOPS),
    access: Some(access),
    accessx: None,
    getattr: Some(getattr),
    lookup: Some(lookup),
    open: Some(open),
    read: Some(read),
    write: None,
    ioctl: None,
    seek: Some(seek),
    stat: Some(stat),
};

fn access(_: &Arc<Vnode>, _: Option<&VThread>, _: Access) -> Result<(), Box<dyn Errno>> {
    // TODO: Check how the PS4 check file permission for exfatfs.
    Ok(())
}

fn getattr(vn: &Arc<Vnode>) -> Result<VnodeAttrs, Box<dyn Errno>> {
    // Get file size.
    let host = vn.data().downcast_ref::<HostFile>().unwrap();
    let size = match host.len() {
        Ok(v) => v,
        Err(e) => return Err(Box::new(GetAttrError::GetSizeFailed(e))),
    };

    // TODO: Check how the PS4 assign file permissions for exfatfs.
    let mode = match vn.ty() {
        VnodeType::Directory(_) => Mode::new(0o555).unwrap(),
        VnodeType::RegularFile => Mode::new(0o644).unwrap(),
        VnodeType::Character => unreachable!(), // The character device should only be in the devfs.
    };

    Ok(VnodeAttrs::new(Uid::ROOT, Gid::ROOT, mode, size))
}

fn lookup(vn: &Arc<Vnode>, td: Option<&VThread>, name: &str) -> Result<Arc<Vnode>, Box<dyn Errno>> {
    // Check if directory.
    match vn.ty() {
        VnodeType::Directory(root) => {
            if name == ".." && *root {
                return Err(Box::new(LookupError::DotdotOnRoot));
            }
        }
        _ => return Err(Box::new(LookupError::NotDirectory)),
    }

    // Check if directory is accessible.
    if let Err(e) = vn.access(td, Access::EXEC) {
        return Err(Box::new(LookupError::AccessDenied(e)));
    }

    // Check name.
    if name == "." {
        return Ok(vn.clone());
    }

    let host = vn.data().downcast_ref::<HostFile>().unwrap();
    let path = match name {
        ".." => Cow::Borrowed(host.path().parent().unwrap()),
        _ => {
            if name.contains(|c| c == '/' || c == '\\') {
                return Err(Box::new(LookupError::InvalidName));
            }

            Cow::Owned(host.path().join(name))
        }
    };

    // Get vnode.
    let vn = match get_vnode(vn.fs(), Some(&path)) {
        Ok(v) => v,
        Err(e) => return Err(Box::new(LookupError::GetVnodeFailed(e))),
    };

    Ok(vn)
}

fn open(
    vn: &Arc<Vnode>,
    td: Option<&VThread>,
    flags: OpenFlags,
    file: Option<&mut VFile>,
) -> Result<(), Box<dyn Errno>> {
    info!("host open");

    Ok(())
}

fn read(vn: &Arc<Vnode>, td: Option<&VThread>, buf: &mut [u8]) -> Result<usize, Box<dyn Errno>> {
    let host = vn.data().downcast_ref::<HostFile>().unwrap();

    match host.read(buf) {
        Ok(read_bytes) => Ok(read_bytes),
        Err(error) => Err(Box::new(ReadError::ReadFailed(error))),
    }
}

fn seek(vn: &Arc<Vnode>, td: Option<&VThread>, pos: SeekFrom) -> Result<u64, Box<dyn Errno>> {
    let host = vn.data().downcast_ref::<HostFile>().unwrap();

    match host.seek(pos) {
        Ok(new_pos) => Ok(new_pos),
        Err(error) => Err(Box::new(SeekError::SeekFailed(error))),
    }
}

fn stat(vn: &Arc<Vnode>, td: Option<&VThread>, buf: &mut [u8]) -> Result<u64, Box<dyn Errno>> {
    let host = vn.data().downcast_ref::<HostFile>().unwrap();
    match host.stat(buf) {
        Ok(res) => Ok(res),
        Err(error) => Err(Box::new(ReadError::ReadFailed(error))),
    }
}

/// Represents an error when [`getattr()`] was failed.
#[derive(Debug, Error)]
enum GetAttrError {
    #[error("cannot get file size")]
    GetSizeFailed(#[source] std::io::Error),
}

impl Errno for GetAttrError {
    fn errno(&self) -> NonZeroI32 {
        match self {
            Self::GetSizeFailed(_) => EIO,
        }
    }
}

/// Represents an error when [`lookup()`] was failed.
#[derive(Debug, Error)]
enum LookupError {
    #[error("current file is not a directory")]
    NotDirectory,

    #[error("cannot resolve '..' on the root directory")]
    DotdotOnRoot,

    #[error("access denied")]
    AccessDenied(#[source] Box<dyn Errno>),

    #[error("name contains unsupported characters")]
    InvalidName,

    #[error("cannot get vnode")]
    GetVnodeFailed(#[source] GetVnodeError),
}

impl Errno for LookupError {
    fn errno(&self) -> NonZeroI32 {
        match self {
            Self::NotDirectory => ENOTDIR,
            Self::DotdotOnRoot | Self::GetVnodeFailed(_) => EIO,
            Self::AccessDenied(e) => e.errno(),
            Self::InvalidName => ENOENT,
        }
    }
}
