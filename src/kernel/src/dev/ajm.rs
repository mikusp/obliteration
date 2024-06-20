use thiserror::Error;

use crate::errno::Errno;
use crate::fs::{
    make_dev, CharacterDevice, DeviceDriver, DriverFlags, IoCmd, IoLen, IoVecMut, MakeDevError,
    MakeDevFlags, Mode,
};
use crate::process::VThread;
use crate::ucred::{Gid, Uid};
use crate::warn;
use std::sync::Arc;

#[derive(Debug)]
struct Ajm {}

impl Ajm {
    pub fn new() -> Self {
        Self {}
    }
}

impl DeviceDriver for Ajm {
    #[allow(unused_variables)] // TODO: remove when implementing
    fn read(
        &self,
        dev: &Arc<CharacterDevice>,
        off: Option<u64>,
        buf: &mut [IoVecMut],
        td: Option<&VThread>,
    ) -> Result<IoLen, Box<dyn Errno>> {
        todo!()
    }

    #[allow(unused_variables)] // TODO: remove when implementing
    fn ioctl(
        &self,
        dev: &Arc<CharacterDevice>,
        cmd: IoCmd,
        td: Option<&VThread>,
    ) -> Result<(), Box<dyn Errno>> {
        match cmd {
            IoCmd::AJMUNK1(_) => warn!("stubbed AJMUNK1"),
            _ => todo!(),
        }

        Ok(())
    }
}

pub struct AjmManager {
    ajm: Arc<CharacterDevice>,
}

impl AjmManager {
    pub fn new() -> Result<Arc<Self>, AjmInitError> {
        let ajm = make_dev(
            Ajm::new(),
            DriverFlags::from_bits_retain(0x80000000),
            0,
            "ajm",
            Uid::ROOT,
            Gid::ROOT,
            Mode::new(0o420).unwrap(),
            None,
            MakeDevFlags::MAKEDEV_ETERNAL,
        )?;

        Ok(Arc::new(Self { ajm }))
    }
}

/// Represents an error when [`AjmManager`] fails to initialize.
#[derive(Debug, Error)]
pub enum AjmInitError {
    #[error("cannot create ajm device")]
    CreateAjmFailed(#[from] MakeDevError),
}
