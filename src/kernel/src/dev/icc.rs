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
struct Icc {}

impl Icc {
    pub fn new() -> Self {
        Self {}
    }
}

impl DeviceDriver for Icc {
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
            IoCmd::ICCCONFUNK1(_) => warn!("ignoring ICCCONFUNK1"),
            IoCmd::ICCCONFUNK2(_) => warn!("ignoring ICCCONFUNK2"),
            IoCmd::ICCINDSETDYNLEDBOOT => warn!("ignoring ICCINDSETDYNLEDBOOT"),
            _ => todo!(),
        }

        Ok(())
    }
}

pub struct IccManager {
    icc_configuration: Arc<CharacterDevice>,
    icc_indicator: Arc<CharacterDevice>,
}

impl IccManager {
    pub fn new() -> Result<Arc<Self>, IccInitError> {
        let icc_configuration = make_dev(
            Icc::new(),
            DriverFlags::from_bits_retain(0x80000004),
            0,
            "icc_configuration",
            Uid::ROOT,
            Gid::ROOT,
            Mode::new(0o600).unwrap(),
            None,
            MakeDevFlags::empty(),
        )?;

        let icc_indicator = make_dev(
            Icc::new(),
            DriverFlags::from_bits_retain(0x80000000),
            0,
            "icc_indicator",
            Uid::ROOT,
            Gid::ROOT,
            Mode::new(0o600).unwrap(),
            None,
            MakeDevFlags::empty(),
        )?;

        Ok(Arc::new(Self {
            icc_configuration,
            icc_indicator,
        }))
    }
}

/// Represents an error when [`IccManager`] fails to initialize.
#[derive(Debug, Error)]
pub enum IccInitError {
    #[error("cannot create icc device")]
    CreateIccFailed(#[from] MakeDevError),
}
