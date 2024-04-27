use std::ptr;

use crate::warn;

use super::storage::Storage;
use super::Addr;
use super::MemoryType;
use super::Protections;

#[derive(Debug, PartialOrd, PartialEq, Ord, Eq, Clone, Copy)]
pub struct PhysAddr(pub usize);

#[derive(Debug, Clone, Copy, PartialOrd, PartialEq, Eq)]
pub(super) struct DmemAllocation {
    pub phys_addr: PhysAddr,
    pub len: usize,
    pub mem_type: MemoryType,
}

impl DmemAllocation {
    pub fn end(&self) -> PhysAddr {
        PhysAddr(self.phys_addr.0 + self.len)
    }
}

impl Ord for DmemAllocation {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.phys_addr.0.cmp(&other.phys_addr.0)
    }
}

impl Storage for DmemAllocation {
    fn addr(&self) -> Addr {
        Addr::PhysAddr(self.phys_addr)
    }
    fn ptr(&self) -> *mut u8 {
        ptr::null_mut()
    }
    fn decommit(&self, addr: *mut u8, len: usize) -> Result<(), std::io::Error> {
        todo!()
    }
    fn protect(
        &self,
        addr: *mut u8,
        len: usize,
        prot: super::Protections,
    ) -> Result<(), std::io::Error> {
        warn!("Dmem::protect({:#x}, {:#x}, {})", addr as usize, len, prot);

        Ok(())
    }
    fn lock(&self, addr: *mut u8, len: usize) -> Result<(), std::io::Error> {
        todo!()
    }
}

#[derive(Debug)]
pub(super) struct DmemInterface {
    #[cfg(target_os = "linux")]
    pub memfd: memfd::Memfd,
    #[cfg(target_os = "windows")]
    pub handle: HANDLE,
    #[cfg(target_os = "macos")]
    pub fd: std::os::fd::OwnedFd,
}

impl DmemInterface {
    #[cfg(target_os = "linux")]
    pub fn new(size: usize) -> Result<DmemInterface, Box<dyn std::error::Error>> {
        let opts = memfd::MemfdOptions::default().allow_sealing(true);
        let mfd = opts.create("dmem")?;

        mfd.as_file().set_len(size as u64)?;

        // Add seals to prevent further resizing.
        mfd.add_seals(&[memfd::FileSeal::SealShrink, memfd::FileSeal::SealGrow])?;

        // Prevent further sealing changes.
        mfd.add_seal(memfd::FileSeal::SealSeal)?;

        Ok(DmemInterface { memfd: mfd })
    }

    #[cfg(target_os = "windows")]
    fn new(size: usize) -> Result<DmemInterface, Box<dyn std::error::Error>> {
        use std::ptr;
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::System::Memory::{CreateFileMappingA, PAGE_READWRITE};

        let handle = unsafe {
            CreateFileMappingA(
                INVALID_HANDLE_VALUE,
                ptr::null(),
                PAGE_READWRITE,
                (size >> 32) as u32,
                size as u32,
                ptr::null(),
            )
        };

        if handle == 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        Ok(DmemInterface { handle })
    }

    #[cfg(target_os = "macos")]
    fn new(size: usize) -> Result<DmemInterface, Box<dyn std::error::Error>> {
        todo!()
    }

    #[cfg(target_os = "linux")]
    pub fn map(
        &self,
        addr: usize,
        len: usize,
        prot: Protections,
        phys_addr: PhysAddr,
    ) -> Option<usize> {
        info!(
            "DmemInterface::map({:#x}, {:#x}, {}, {:#x})",
            addr, len, prot, phys_addr.0
        );
        use std::os::fd::AsRawFd;

        use libc::{c_void, MAP_FIXED, MAP_SHARED};

        use crate::info;

        let ret = unsafe {
            libc::mmap(
                addr as *mut c_void,
                len,
                prot.into_host(),
                MAP_SHARED | MAP_FIXED,
                self.memfd.as_raw_fd(),
                phys_addr.0 as i64,
            )
        };

        if ret != ptr::null_mut() {
            Some(ret as _)
        } else {
            None
        }
    }

    #[cfg(target_os = "windows")]
    pub fn map(
        &self,
        addr: usize,
        len: usize,
        prot: Protections,
        phys_addr: PhysAddr,
    ) -> Option<usize> {
        use crate::info;
        use std::os::raw::c_void;
        use windows_sys::Win32::System::Memory::{MapViewOfFileEx, FILE_MAP_READ, FILE_MAP_WRITE};

        info!(
            "DmemInterface::map({:#x}, {:#x}, {}, {:#x})",
            addr, len, prot, phys_addr.0
        );

        let protection_flags = match prot {
            Protections::CPU_READ => FILE_MAP_READ,
            Protections::CPU_WRITE | Protections::RW => FILE_MAP_WRITE,
            _ => todo!(),
        };

        let ret = unsafe {
            MapViewOfFileEx(
                self.handle,
                protection_flags,
                (phys_addr.0 >> 32) as u32,
                (phys_addr.0 & 0xFFFF_FFFF) as u32,
                len as usize,
                addr as *const c_void,
            )
        };

        if ret.Value != ptr::null_mut() {
            Some(ret.Value as _)
        } else {
            None
        }
    }

    #[cfg(target_os = "macos")]
    pub fn map(
        &self,
        addr: usize,
        len: usize,
        prot: Protections,
        phys_addr: PhysAddr,
    ) -> Option<usize> {
        todo!()
    }
}
