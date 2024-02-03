use crate::errno::EINVAL;
use crate::fs::{make_dev, CdevSw, DriverFlags, Fs, MakeDev, Mode};
use crate::process::VThread;
use crate::syscalls::{SysErr, SysIn, SysOut, Syscalls};
use crate::ucred::{Gid, Uid};
use std::sync::Arc;

/// An implementation of direct memory system on the PS4.
pub struct DmemManager {
    fs: Arc<Fs>,
}

impl DmemManager {
    pub fn new(fs: &Arc<Fs>, sys: &mut Syscalls) -> Arc<Self> {
        let dmem = Arc::new(Self { fs: fs.clone() });

        let dmem0 = Arc::new(CdevSw::new(
            DriverFlags::from_bits_retain(0x80000000),
            None,
            None,
        ));

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

        sys.register(586, &dmem, Self::sys_dmem_container);
        sys.register(653, &dmem, Self::sys_blockpool_open);

        dmem
    }

    fn sys_dmem_container(self: &Arc<Self>, i: &SysIn) -> Result<SysOut, SysErr> {
        let td = VThread::current().unwrap();
        let set: i32 = i.args[0].try_into().unwrap();
        let get: i32 = td.proc().dmem_container().try_into().unwrap();

        if set != -1 {
            todo!("sys_dmem_container with update != -1");
        }

        Ok(get.into())
    }

    fn sys_blockpool_open(self: &Arc<Self>, i: &SysIn) -> Result<SysOut, SysErr> {
        let flags: u32 = i.args[0].try_into().unwrap();

        if flags & 0xffafffff != 0 {
            return Err(SysErr::Raw(EINVAL));
        }

        // todo!("sys_blockpool_open on new FS")
        Ok(0.into())
    }
}
