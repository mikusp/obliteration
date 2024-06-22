use thiserror::Error;

use crate::{
    errno::Errno,
    error,
    fs::{
        make_dev, CharacterDevice, DeviceDriver, DriverFlags, IoCmd, MakeDevError, MakeDevFlags,
        Mode,
    },
    process::VThread,
    ucred::{Gid, Uid},
    warn,
};
use std::sync::Arc;

#[derive(Debug)]
struct Idata {}

impl Idata {
    fn new() -> Self {
        Self {}
    }
}

impl DeviceDriver for Idata {
    #[allow(unused_variables)]
    fn ioctl(
        &self,
        dev: &Arc<CharacterDevice>,
        cmd: IoCmd,
        td: Option<&VThread>,
    ) -> Result<(), Box<dyn Errno>> {
        let td = td.unwrap();

        match cmd {
            IoCmd::IDATAISSPECIALWAKE(_) => error!("stubbed idataIsSpecialWake"),
            _ => todo!(),
        }

        Ok(())
    }
}

pub struct IdataManager {
    idata: Arc<CharacterDevice>,
}

impl IdataManager {
    pub fn new() -> Result<Arc<Self>, IdataInitError> {
        let idata = make_dev(
            Idata::new(),
            DriverFlags::from_bits_retain(0x80000000),
            0,
            "idata",
            Uid::ROOT,
            Gid::ROOT,
            Mode::new(0o600).unwrap(),
            None,
            MakeDevFlags::MAKEDEV_ETERNAL,
        )?;

        Ok(Arc::new(Self { idata }))
    }
}

/// Represents an error when [`IdataManager`] fails to initialize.
#[derive(Debug, Error)]
pub enum IdataInitError {
    #[error("cannot create idata device")]
    CreateIdataFailed(#[from] MakeDevError),
}
