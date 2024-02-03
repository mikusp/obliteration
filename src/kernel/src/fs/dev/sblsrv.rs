use crate::fs::{make_dev, Mode, VPath};
use crate::ucred::{Gid, Uid};
use macros::vpath;
use std::fmt::{Display, Formatter};
use std::sync::Arc;

use super::{CdevSw, DriverFlags, MakeDev};

/// An implementation of `/dev/sbl_srv`.
#[derive(Debug)]
pub struct SblService {}

impl SblService {
    pub const PATH: &'static VPath = vpath!("/dev/sbl_srv");

    pub fn new() -> Arc<Self> {
        let sbl_srv_cdevsw = Arc::new(CdevSw::new(
            DriverFlags::from_bits_retain(0x80000000),
            Some(|_, _, _, _| Ok(())),
            None,
        ));

        let _ = make_dev(
            &sbl_srv_cdevsw,
            0,
            "sbl_srv",
            Uid::ROOT,
            Gid::ROOT,
            Mode::new(0o600).unwrap(),
            None,
            MakeDev::MAKEDEV_ETERNAL,
        );
        Arc::new(Self {})
    }
}

impl Display for SblService {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Self::PATH.fmt(f)
    }
}
