use crate::{
    errno::{Errno, EINVAL, EPERM},
    fs::{CharacterDevice, DeviceDriver, IoCmd},
    info,
    process::VThread,
    syscalls::SysErr,
    warn,
};
use macros::Errno;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug)]
pub struct Dmem {
    total_size: usize, // TODO: Should be 0x13C_000_000
    container: DmemContainer,
}

impl Dmem {
    pub fn new(total_size: usize, container: DmemContainer) -> Self {
        Self {
            total_size,
            container,
        }
    }

    fn get_avail(
        dmem: DmemContainer,
        start: usize,
        end: usize,
        align: usize,
    ) -> Result<usize, IoctlErr> {
        if align != 0 && align - 1 & align != 0 {
            return Err(IoctlErr::InvalidParameters);
        }

        let alignment = if align > 0x4000 { align } else { 0x4000 };

        let mut start = !(start >> 63) & start;
        if start > 0x5000000000 {
            start = 0x5000000000;
        }

        let mut end = !(end >> 63) & end;
        if end >= 0x5000000001 {
            end = 0x5000000000;
        }

        warn!("{}, {:#x}", start, end);

        Ok(end - start)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DmemContainer {
    Zero,
    One,
    Two,
}

impl TryFrom<i32> for DmemContainer {
    type Error = SysErr;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Zero),
            1 => Ok(Self::One),
            2 => Ok(Self::Two),
            _ => Err(SysErr::Raw(EINVAL)),
        }
    }
}

impl DeviceDriver for Dmem {
    fn ioctl(
        &self,
        _: &Arc<CharacterDevice>,
        cmd: IoCmd,
        td: Option<&VThread>,
    ) -> Result<(), Box<dyn Errno>> {
        let td = td.unwrap();

        let cred = td.cred();

        if cred.is_unk1() || cred.is_unk2() {
            return Err(Box::new(IoctlErr::InsufficientCredentials));
        }

        let proc_dmem_container = td.proc().dmem_container();

        if self.container != DmemContainer::Two
            && self.container != *proc_dmem_container
            && !cred.is_system()
        {
            return Err(Box::new(IoctlErr::InsufficientCredentials));
        }

        match cmd {
            // TODO: properly implement this
            IoCmd::DMEMTOTAL(size) => *size = self.total_size,
            IoCmd::DMEMGETPRT(_prt) => todo!(),
            IoCmd::DMEMGETAVAIL(avail) => {
                let start = avail.start_or_phys_out;
                let dmem_container = if self.container != DmemContainer::Two {
                    if avail.start_or_phys_out < 0x3000000000 {
                        self.container
                    } else if avail.start_or_phys_out > 0x301fffffff {
                        self.container
                    } else {
                        DmemContainer::Two
                    }
                } else {
                    DmemContainer::Two
                };

                let (phys_addr, size) = td
                    .proc()
                    .vm()
                    .get_avail_dmem(dmem_container, start, avail.end, avail.align)
                    .map_err(|_| IoctlErr::InvalidParameters)?;

                info!("dmem_get_avail: addr {:#x}, size {:#x}", phys_addr.0, size);

                avail.start_or_phys_out = phys_addr.0;
                avail.size_out = size;
            }
            IoCmd::DMEMALLOC(alloc) => {
                let phys_addr = td
                    .proc()
                    .vm()
                    .allocate_dmem(alloc.start_or_phys_out, alloc.end, alloc.len, alloc.align)
                    .map_err(|_| IoctlErr::InvalidParameters)?;

                alloc.start_or_phys_out = phys_addr.0
            }
            IoCmd::DMEMALLOCMAIN(alloc) => {
                let phys_addr = td
                    .proc()
                    .vm()
                    .allocate_dmem(alloc.start_or_phys_out, alloc.end, alloc.len, alloc.align)
                    .map_err(|_| IoctlErr::InvalidParameters)?;

                alloc.start_or_phys_out = phys_addr.0
            }
            IoCmd::DMEMQUERY(_query) => todo!(),
            _ => todo!(),
        }

        Ok(())
    }
}

#[derive(Error, Debug, Errno)]
enum IoctlErr {
    #[error("bad credentials")]
    #[errno(EPERM)]
    InsufficientCredentials,

    #[error("bad parameters")]
    #[errno(EINVAL)]
    InvalidParameters,
}

#[repr(C)]
#[derive(Debug)]
pub struct PrtAperture {
    addr: usize,
    len: usize,
    id: i64,
}

#[repr(C)]
#[derive(Debug)]
pub struct DmemAvailable {
    start_or_phys_out: usize,
    end: usize,
    align: usize,
    size_out: usize,
}

#[repr(C)]
#[derive(Debug)]
pub struct DmemAllocate {
    start_or_phys_out: usize,
    end: usize,
    len: usize,
    align: usize,
    mem_type: i32,
}

#[repr(C)]
#[derive(Debug)]
pub struct DmemQuery {
    dmem_container: i32,
    flags: i32,
    unk: usize,
    phys_addr: usize,
    info_out: usize,
    info_size: usize,
}
