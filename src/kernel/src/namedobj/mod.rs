use crate::errno::EINVAL;
use crate::idt::Entry;
use crate::process::VThread;
use crate::syscalls::{SysErr, SysIn, SysOut, Syscalls};
use crate::{info, warn};
use std::sync::Arc;

pub struct NamedObjManager {}

impl NamedObjManager {
    pub fn new(sys: &mut Syscalls) -> Arc<Self> {
        let namedobj = Arc::new(Self {});

        sys.register(557, &namedobj, Self::sys_namedobj_create);
        sys.register(558, &namedobj, |_, _, _| {
            warn!("stubbed sys_namedobj_delete");
            Ok(0.into())
        });
        sys.register(601, &namedobj, |_, _, i| {
            let op = i.args[0].get();
            warn!("stubbed sys_mdbg_service {:#x}", i.args[0].get());

            if op == 0xA {
                unsafe {
                    info!("mdbg 0xA, writing 0");
                    *(i.args[2].get() as *mut u32) = 0;
                }
            }

            Ok(0.into())
        });

        namedobj
    }

    fn sys_namedobj_create(self: &Arc<Self>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        // Get arguments.
        let name = unsafe { i.args[0].to_str(32) }?.ok_or(SysErr::Raw(EINVAL))?;
        let data: usize = i.args[1].into();
        let flags: u32 = i.args[2].try_into().unwrap();

        // Allocate the entry.
        let mut table = td.proc().objects_mut();

        let obj = NamedObj::new(name, data);

        let id = table.alloc({
            Entry::new(
                Some(name.to_owned()),
                Arc::new(obj),
                (flags as u16) | 0x1000,
            )
        });

        info!(
            "Named object '{}' (ID = {}) was created with data = {:#x} and flags = {:#x}.",
            name, id, data, flags
        );

        Ok(id.into())
    }
}

#[derive(Debug)]
pub struct NamedObj {
    name: String,
    data: usize,
}

impl NamedObj {
    pub fn new(name: impl Into<String>, data: usize) -> Self {
        Self {
            name: name.into(),
            data,
        }
    }
}
