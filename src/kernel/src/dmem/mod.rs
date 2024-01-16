use byteorder::{LittleEndian, WriteBytesExt};
use thiserror::Error;

use crate::errno::{Errno, EINVAL};
use crate::fs::{
    make_dev, Cdev, CdevSw, DriverFlags, FileBackend, Fs, IoCmd, MakeDev, Mode, OpenFlags, VFile,
};
use crate::memory::MemoryManager;
use crate::process::VThread;
use crate::syscalls::{SysErr, SysIn, SysOut, Syscalls};
use crate::ucred::{Gid, Uid};
use crate::{info, warn};
use human_bytes::human_bytes;
use std::io::Write;
use std::mem::{self, size_of, zeroed};
use std::sync::Arc;

pub use self::blockpool::*;

mod blockpool;

/// An implementation of direct memory system on the PS4.
#[derive(Debug)]
pub struct DmemManager {
    fs: Arc<Fs>,
    mm: Arc<MemoryManager>,
}

impl DmemManager {
    pub fn new(fs: &Arc<Fs>, mm: &Arc<MemoryManager>, sys: &mut Syscalls) -> Arc<Self> {
        let dmem = Arc::new(Self {
            fs: fs.clone(),
            mm: mm.clone(),
        });

        let dmem0 = Arc::new(CdevSw::new(DriverFlags::D_INIT, Self::dmem_open));

        make_dev(
            &dmem0,
            0,
            "dmem0",
            Uid::ROOT,
            Gid::ROOT,
            Mode::new(0o511).unwrap(),
            None,
            MakeDev::MAKEDEV_ETERNAL,
        )
        .unwrap();

        make_dev(
            &dmem0,
            0,
            "dmem1",
            Uid::ROOT,
            Gid::ROOT,
            Mode::new(0o511).unwrap(),
            None,
            MakeDev::MAKEDEV_ETERNAL,
        )
        .unwrap();

        make_dev(
            &dmem0,
            0,
            "dmem2",
            Uid::ROOT,
            Gid::ROOT,
            Mode::new(0o511).unwrap(),
            None,
            MakeDev::MAKEDEV_ETERNAL,
        )
        .unwrap();

        let dce = Arc::new(CdevSw::new(DriverFlags::D_INIT, |_, _, _, _| Ok(())));

        make_dev(
            &dce,
            0,
            "dce",
            Uid::ROOT,
            Gid::ROOT,
            Mode::new(0o666).unwrap(),
            None,
            MakeDev::empty(),
        )
        .unwrap();

        sys.register(586, &dmem, Self::sys_dmem_container);
        sys.register(653, &dmem, Self::sys_blockpool_open);

        dmem
    }

    fn dmem_open(
        _cdev: &Arc<Cdev>,
        _flags: OpenFlags,
        _mode: i32,
        _td: Option<&VThread>,
    ) -> Result<(), Box<dyn Errno>> {
        // TODO: check ucreds as on the PS4

        Ok(())
    }

    fn dmem_ioctl(
        dev: &Arc<Cdev>,
        cmd: IoCmd,
        mut buf: &mut [u8],
        td: Option<&VThread>,
    ) -> Result<i64, Box<dyn Errno>> {
        warn!(
            "dmem_ioctl({:?},
            {:?},
            {:?},
            {:?})",
            dev, cmd, buf, td
        );

        //TODO check creds
        static mut FOO: u64 = 8 * 1024 * 1024 * 1024;

        match cmd {
            // dmem size
            a if a == IoCmd::try_from_raw_parts(0x4008800a, buf.as_mut_ptr()).unwrap() => {
                let dmem_size: i64 = unsafe { FOO as i64 };
                buf.write_i64::<LittleEndian>(dmem_size)
                    .map_err(|_| Box::new(DmemIoctlError::InvalidBuffer) as Box<dyn Errno>)
                    .map(|_| 0i64)
            }
            // available dmem
            a if a == IoCmd::try_from_raw_parts(0xc0208016, buf.as_mut_ptr()).unwrap() => {
                #[repr(C)]
                struct Args {
                    pub search_start: u64,
                    pub search_end: u64,
                    pub alignment: u64,
                    pub size: u64,
                }

                let ret = Args {
                    search_start: 0,
                    search_end: 8 * 1024 * 1024 * 1024,
                    alignment: 2048,
                    size: unsafe { FOO },
                };

                unsafe {
                    buf.write(std::slice::from_raw_parts(
                        &ret as *const Args as *const u8,
                        size_of::<Args>(),
                    ))
                    .unwrap();
                }

                Ok(0.into())
            }
            // allocate dmem
            a if a == IoCmd::try_from_raw_parts(0xc0288001, buf.as_mut_ptr()).unwrap() => {
                #[repr(C)]
                struct Args {
                    pub search_start: u64,
                    pub search_end: u64,
                    pub length: u64,
                    pub alignment: u64,
                    pub mem_type: u32,
                }

                let args = unsafe { &*(buf.as_ptr() as *const Args) };

                let phys_addr = Self::allocate_direct_memory(
                    args.search_start,
                    args.search_end,
                    args.length,
                    args.alignment,
                    args.mem_type,
                )?;

                unsafe {
                    FOO = FOO - args.length;
                }

                unsafe {
                    std::ptr::write(buf.as_mut_ptr().cast(), phys_addr as u64);
                }

                Ok(0.into())
            }
            a if a == IoCmd::try_from_raw_parts(0xc0288011, buf.as_mut_ptr()).unwrap() => {
                info!("stubbed dmem_ioctl 0x80288011");
                Ok(0.into())
            }
            a if a == IoCmd::try_from_raw_parts(0x80288012, buf.as_mut_ptr()).unwrap() => {
                #[repr(C)]
                struct Args {
                    pub device_index: u32,
                    pub flags: u32,
                    pub unk: u32,
                    pub offset: u64,
                    pub info: usize,
                    pub info_size: usize,
                }

                let args = unsafe { &*(buf.as_ptr() as *const Args) };

                Self::direct_memory_query(args.device_index, args.flags, args.unk, args.offset);

                //TODO write to info

                Ok(0.into())
            }
            _ => todo!("dmem_ioctl {:?}", cmd),
        }
    }

    fn allocate_direct_memory(
        search_start: u64,
        search_end: u64,
        length: u64,
        alignment: u64,
        mem_type: u32,
    ) -> Result<u64, Box<dyn Errno>> {
        info!(
            "allocate_direct_memory({:#x}, {:#x}, {:#x} ({}), {} ({}), {})",
            search_start,
            search_end,
            length,
            human_bytes(length as f64),
            alignment,
            human_bytes(alignment as f64),
            mem_type
        );
        let mut ret: usize = 0;
        let ret_ptr: *mut usize = &mut ret;
        unsafe {
            libc::posix_memalign(
                ret_ptr as *mut *mut libc::c_void,
                alignment as usize,
                length as usize,
            );
        }

        warn!("malloced dmem: {:#x}", ret);

        Ok(ret as u64)
    }

    fn direct_memory_query(
        device_index: u32,
        flags: u32,
        unk: u32,
        offset: u64,
    ) -> Result<(), SysErr> {
        info!(
            "direct_memory_query({:#x}, {:#x}, {:#x}, {:#x})",
            device_index, flags, unk, offset
        );

        Ok(())
    }

    fn sys_dmem_container(self: &Arc<Self>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let td = VThread::current().unwrap();
        let set: i32 = i.args[0].try_into().unwrap();
        let get: i32 = td.proc().dmem_container().try_into().unwrap();

        if set != -1 {
            todo!("sys_dmem_container with update != -1");
        }

        Ok(get.into())
    }

    fn sys_blockpool_open(self: &Arc<Self>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let flags: u32 = i.args[0].try_into().unwrap();

        if flags & 0xffafffff != 0 {
            return Err(SysErr::Raw(EINVAL));
        }

        // todo!("sys_blockpool_open on new FS")
        Ok(0.into())
    }
}

impl FileBackend for DmemManager {
    fn ioctl(
        self: &Arc<Self>,
        file: &VFile,
        cmd: IoCmd,
        td: Option<&VThread>,
    ) -> Result<(), Box<dyn Errno>> {
        todo!()
    }

    fn stat(
        self: &Arc<Self>,
        file: &VFile,
        td: Option<&VThread>,
    ) -> Result<crate::fs::Stat, Box<dyn Errno>> {
        todo!()
    }
}

#[derive(Debug, Error)]
pub enum DmemIoctlError {
    #[error("buf is invalid")]
    InvalidBuffer,
}

impl Errno for DmemIoctlError {
    fn errno(&self) -> std::num::NonZeroI32 {
        match self {
            Self::InvalidBuffer => EINVAL,
        }
    }
}
