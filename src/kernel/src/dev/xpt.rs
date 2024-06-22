use thiserror::Error;

use crate::errno::Errno;
use crate::fs::{
    make_dev, CharacterDevice, DeviceDriver, DriverFlags, IoCmd, IoLen, IoVecMut, MakeDevError,
    MakeDevFlags, Mode,
};
use crate::process::VThread;
use crate::ucred::{Gid, Uid};
use crate::{error, warn};
use std::sync::Arc;

#[derive(Debug)]
struct Xpt {}

impl Xpt {
    pub fn new() -> Self {
        Self {}
    }
}

impl DeviceDriver for Xpt {
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
            IoCmd::DEVUNK3(_) => error!("stubbed XPTUNK"),
            _ => todo!(),
        }

        Ok(())
    }
}

pub struct XptManager {
    xpt0: Arc<CharacterDevice>,
}

impl XptManager {
    pub fn new() -> Result<Arc<Self>, XptInitError> {
        let xpt0 = make_dev(
            Xpt::new(),
            DriverFlags::from_bits_retain(0x80000000),
            0,
            "xpt0",
            Uid::ROOT,
            Gid::new(5).unwrap(),
            Mode::new(0o666).unwrap(),
            None,
            MakeDevFlags::empty(),
        )?;

        Ok(Arc::new(Self { xpt0 }))
    }
}

/// Represents an error when [`XptManager`] fails to initialize.
#[derive(Debug, Error)]
pub enum XptInitError {
    #[error("cannot create xpt0 device")]
    CreateXptFailed(#[from] MakeDevError),
}
