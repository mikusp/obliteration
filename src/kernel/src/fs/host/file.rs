use std::io::{Error, SeekFrom};
use std::mem::zeroed;
use std::path::{Path, PathBuf};

use crate::info;

/// Encapsulate a raw file or directory on the host.
pub struct HostFile {
    path: PathBuf,
    raw: RawFile,
}

impl HostFile {
    pub fn open<P: Into<PathBuf>>(path: P) -> Result<Self, Error> {
        let path = path.into();
        // info!("HostFile::open {path:?}");
        let raw = Self::raw_open(&path)?;

        Ok(Self { path, raw })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let result = Self::raw_read(self, buf);

        result
    }

    pub fn seek(&self, pos: SeekFrom) -> Result<u64, Error> {
        let result = Self::raw_seek(self, pos);

        result
    }

    #[cfg(unix)]
    pub fn stat(&self, buf: &mut [u8]) -> Result<u64, Error> {
        if unsafe { libc::fstat(self.raw, buf.as_mut_ptr().cast()) } < 0 {
            return Err(Error::last_os_error());
        }

        Ok(0)
    }

    #[cfg(unix)]
    pub fn is_directory(&self) -> Result<bool, Error> {
        use libc::{fstat, S_IFDIR, S_IFMT};

        let mut stat = unsafe { zeroed() };

        if unsafe { fstat(self.raw, &mut stat) } < 0 {
            return Err(Error::last_os_error());
        }

        Ok((stat.st_mode & S_IFMT) == S_IFDIR)
    }

    #[cfg(windows)]
    pub fn is_directory(&self) -> Result<bool, Error> {
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, FILE_ATTRIBUTE_DIRECTORY,
        };

        let mut info = unsafe { zeroed() };

        if unsafe { GetFileInformationByHandle(self.raw, &mut info) } == 0 {
            return Err(Error::last_os_error());
        }

        Ok((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
    }

    #[cfg(unix)]
    pub fn len(&self) -> Result<u64, Error> {
        use libc::fstat;

        let mut stat = unsafe { zeroed() };

        if unsafe { fstat(self.raw, &mut stat) } < 0 {
            return Err(Error::last_os_error());
        }

        Ok(stat.st_size.try_into().unwrap())
    }

    #[cfg(windows)]
    pub fn len(&self) -> Result<u64, Error> {
        use windows_sys::Win32::Storage::FileSystem::GetFileSizeEx;

        let mut size = 0;

        if unsafe { GetFileSizeEx(self.raw, &mut size) } == 0 {
            return Err(Error::last_os_error());
        }

        Ok(size.try_into().unwrap())
    }

    #[cfg(unix)]
    fn raw_open(path: &Path) -> Result<RawFile, Error> {
        use libc::{O_NOCTTY, O_RDONLY};
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let fd = unsafe { libc::open(path.as_ptr(), O_RDONLY | O_NOCTTY) };

        if fd < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(fd)
        }
    }

    #[cfg(windows)]
    fn raw_open(path: &Path) -> Result<RawFile, Error> {
        use std::os::windows::ffi::OsStrExt;
        use std::ptr::null;
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, OPEN_EXISTING,
        };

        let mut path: Vec<u16> = path.as_os_str().encode_wide().collect();
        path.push(0);

        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                0,
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            Err(Error::last_os_error())
        } else {
            Ok(handle)
        }
    }

    #[cfg(unix)]
    fn raw_read(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let bytes_read = unsafe { libc::read(self.raw, buf.as_mut_ptr().cast(), buf.len()) };

        if bytes_read < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(bytes_read.try_into().unwrap())
        }
    }

    #[cfg(unix)]
    fn raw_seek(&self, pos: SeekFrom) -> Result<u64, Error> {
        let offset = match pos {
            SeekFrom::Current(off) => off,
            SeekFrom::End(off) => off,
            SeekFrom::Start(off) => off.try_into().unwrap(),
        };
        let whence = match pos {
            SeekFrom::Current(_) => libc::SEEK_CUR,
            SeekFrom::End(_) => libc::SEEK_END,
            SeekFrom::Start(_) => libc::SEEK_SET,
        };

        let ret = unsafe { libc::lseek(self.raw, offset, whence) };

        if ret < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(ret.try_into().unwrap())
        }
    }
}

impl Drop for HostFile {
    #[cfg(unix)]
    fn drop(&mut self) {
        use libc::close;

        if unsafe { close(self.raw) } < 0 {
            let e = Error::last_os_error();
            panic!("Failed to close {}: {}.", self.path.display(), e);
        }
    }

    #[cfg(windows)]
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;

        if unsafe { CloseHandle(self.raw) } == 0 {
            let e = Error::last_os_error();
            panic!("Failed to close {}: {}.", self.path.display(), e);
        }
    }
}

#[cfg(unix)]
type RawFile = std::ffi::c_int;

#[cfg(windows)]
type RawFile = windows_sys::Win32::Foundation::HANDLE;
