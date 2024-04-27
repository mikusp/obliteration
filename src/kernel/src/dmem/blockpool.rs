use gmtx::Gutex;
use humansize::{format_size, format_size_i, make_format, DECIMAL};

use crate::budget::ProcType;
use crate::dev::DmemContainer;
use crate::errno::{Errno, EINVAL, ENOMEM};
use crate::fs::{DefaultFileBackendError, FileBackend, IoCmd, PollEvents, Stat, VFile};
use crate::info;
use crate::process::VThread;
use crate::syscalls::SysErr;
use crate::vm::{MemoryType, PhysAddr};
use std::any::Any;
use std::sync::Arc;

#[derive(Debug)]
pub struct BlockPool {
    pub dmem_container: DmemContainer,
    pub ptype: ProcType,
    pub start: usize,
    pub end: usize,
    pub addr: usize,
    pub available_flushed_blocks: Gutex<usize>,
    pub phys_addr: Gutex<Option<PhysAddr>>,
    pub budget: Gutex<usize>,
}

impl BlockPool {
    // pub fn new() -> Arc<Self> {
    //     Arc::new(Self {})
    // }

    fn expand(
        &self,
        len: i64,
        mut search_start: usize,
        mut search_end: usize,
        align: usize,
        td: Option<&VThread>,
    ) -> Result<Option<PhysAddr>, SysErr> {
        info!("BlockPool::expand({len:#x} ({}), {search_start:#x} ({}), {search_end:#x} ({}), {align:#x} ({}))",
            format_size_i(len, DECIMAL), format_size(search_start, DECIMAL), format_size(search_end, DECIMAL), format_size(align, DECIMAL));

        if len as i16 != 0
            || (align & 0xFFFF_FFFF) as u32 & 0x1f000000 != (align & 0xFFFF_FFFF) as u32
        {
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
            if search_start <= self.start {
                search_start = self.start;
            }
            if search_end >= self.end {
                search_end = self.end;
            }
            // adjust search and start according to data in the vfile
            let addr = td.unwrap().proc().vm().allocate_dmem(
                search_start,
                search_end,
                len as usize,
                MemoryType::WcGarlic,
                1 << (unk_align & 0x3f),
            )?;

            info!("expanded {:#x}", addr.0);

            let blocks: usize = len as usize >> 0x10;
            let mut afb = self.available_flushed_blocks.write();
            *afb = *afb + blocks;
            *self.phys_addr.write() = Some(addr);

            let offset_from_start = addr.0 - self.start;
            let mut block_offset = offset_from_start >> 0x10;
            let mut last_block = blocks + block_offset;
            let uvar4 = last_block >> 6;
            for i in 0..2 {
                let mut fill = false;
                let alignment = block_offset >> 6;
                if block_offset & 0x3f == 0 {
                    if alignment < uvar4 {
                        let fill_len = uvar4 - alignment;

                        // sth

                        fill = true;
                    }

                    if last_block & 0x3f == 0
                    /* more conditions */
                    {
                        if !fill {
                            break;
                        }
                    }
                } else {
                    let search_end = if alignment != uvar4 {
                        !0
                    } else {
                        !(!0 << (last_block as u8 & 0x3f))
                    };

                    //TODO: ignore for now
                }

                last_block = (last_block + 0x3f) >> 6;
                block_offset = block_offset >> 6;
            }

            return Ok(Some(addr));
            // do more bookkeeping from blockpool_ioctl
        }
    }
}

impl FileBackend for BlockPool {
    fn is_seekable(&self) -> bool {
        todo!()
    }

    #[allow(unused_variables)] // TODO: remove when implementing
    fn ioctl(&self, file: &VFile, cmd: IoCmd, td: Option<&VThread>) -> Result<(), Box<dyn Errno>> {
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
                    Err(err) => Err(Box::new(DefaultFileBackendError::InvalidValue)),
                }
            }
            IoCmd::BPOOLSTATS(out) => todo!(),
            _ => Err(Box::new(DefaultFileBackendError::IoctlNotSupported)),
        }
    }

    #[allow(unused_variables)] // TODO: remove when implementing
    fn poll(&self, file: &VFile, events: PollEvents, td: &VThread) -> PollEvents {
        todo!()
    }

    fn stat(&self, _: &VFile, _: Option<&VThread>) -> Result<Stat, Box<dyn Errno>> {
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
