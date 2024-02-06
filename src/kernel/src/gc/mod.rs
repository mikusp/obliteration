use std::sync::Arc;

use crate::{
    errno::Errno,
    fs::{make_dev, Cdev, CdevSw, DriverFlags, MakeDev, Mode, OpenFlags},
    process::VThread,
    ucred::{Gid, Uid},
};

pub struct GcManager {}

impl GcManager {
    pub fn new() -> Arc<Cdev> {
        let gc_devsw = Arc::new(CdevSw::new(
            DriverFlags::from_bits_retain(0x80000000),
            Some(Self::gc_open),
            None,
        ));

        let gc = make_dev(
            &gc_devsw,
            0,
            "gc",
            Uid::ROOT,
            Gid::ROOT,
            Mode::new(0o666).unwrap(),
            None,
            MakeDev::MAKEDEV_ETERNAL,
        );

        let rng_cdevsw = Arc::new(CdevSw::new(
            DriverFlags::from_bits_retain(0x80000000),
            Some(|_, _, _, _| Ok(())),
            None,
        ));

        let rng = make_dev(
            &rng_cdevsw,
            0,
            "rng",
            Uid::ROOT,
            Gid::ROOT,
            Mode::new(0o444).unwrap(),
            None,
            MakeDev::MAKEDEV_ETERNAL,
        );

        return gc.unwrap();
    }

    fn gc_open(
        gc: &Arc<Cdev>,
        flags: OpenFlags,
        mode: i32,
        td: Option<&VThread>,
    ) -> Result<(), Box<dyn Errno>> {
        Ok(())
    }
}
