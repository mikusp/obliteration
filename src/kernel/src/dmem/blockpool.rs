use crate::budget::ProcType;
use crate::dev::DmemContainer;
use crate::errno::{Errno, EINVAL, ENOMEM};
use crate::fs::{DefaultFileBackendError, FileBackend, IoCmd, PollEvents, Stat, VFile};
use crate::info;
use crate::process::VThread;
use crate::syscalls::SysErr;
use crate::vm::PhysAddr;
use std::sync::Arc;

#[derive(Debug)]
pub struct BlockPool {
    pub dmem_container: DmemContainer,
    pub ptype: ProcType,
    pub start: usize,
    pub end: usize,
    pub addr: usize,
}

impl BlockPool {
    // pub fn new() -> Arc<Self> {
    //     Arc::new(Self {})
    // }

    fn expand(
        self: &Arc<Self>,
        len: i64,
        search_start: usize,
        search_end: usize,
        align: usize,
        td: Option<&VThread>,
    ) -> Result<Option<PhysAddr>, SysErr> {
        if len as i16 != 0 || align & 0x1f000000 != align {
            return Err(SysErr::Raw(EINVAL));
        }

        let unk_align = if align == 0 {
            0x10
        } else {
            if align < 0x10000000 {
                return Err(SysErr::Raw(EINVAL));
            } else {
                align >> 0x18
            }
        };

        if len == 0 {
            return Ok(None);
        } else if len < 0 {
            return Err(SysErr::Raw(ENOMEM));
        } else {
            // adjust search and start according to data in the vfile
            td.unwrap()
                .proc()
                .vm()
                .dmem()
                .allocate(
                    search_start,
                    search_end,
                    len as usize,
                    1 << (unk_align & 0x3f),
                )
                .map(|addr| Some(addr))
            // do more bookkeeping from blockpool_ioctl
        }
    }
}

impl FileBackend for BlockPool {
    #[allow(unused_variables)] // TODO: remove when implementing
    fn ioctl(
        self: &Arc<Self>,
        file: &VFile,
        cmd: IoCmd,
        td: Option<&VThread>,
    ) -> Result<(), Box<dyn Errno>> {
        match cmd {
            IoCmd::BPOOLEXPAND(args) => {
                match self.expand(
                    args.len,
                    args.search_start,
                    args.search_end,
                    args.alignment,
                    td,
                ) {
                    Ok(phys_addr) => {
                        phys_addr.map(|addr| {
                            args.search_start = addr.0;
                        });
                        Ok(())
                    }
                    Err(err) => todo!(),
                }
            }
            IoCmd::BPOOLSTATS(out) => todo!(),
            _ => Err(Box::new(DefaultFileBackendError::IoctlNotSupported)),
        }
    }

    #[allow(unused_variables)] // TODO: remove when implementing
    fn poll(self: &Arc<Self>, file: &VFile, events: PollEvents, td: &VThread) -> PollEvents {
        todo!()
    }

    fn stat(self: &Arc<Self>, _: &VFile, _: Option<&VThread>) -> Result<Stat, Box<dyn Errno>> {
        let mut stat = Stat::zeroed();

        stat.block_size = 0x10000;
        stat.mode = 0o130000;

        todo!()
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct BlockpoolExpandArgs {
    len: i64,
    search_start: usize,
    search_end: usize,
    alignment: usize,
}

#[repr(C)]
#[derive(Debug)]
pub struct BlockpoolStats {
    avail_flushed: i32,
    avail_cached: i32,
    allocated_flushed: i32,
    allocated_cached: i32,
}
