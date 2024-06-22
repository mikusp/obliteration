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
struct Bt {}

impl Bt {
    pub fn new() -> Self {
        Self {}
    }
}

impl DeviceDriver for Bt {
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
            IoCmd::BTSTARTMODE(_) => error!("stubbed sceBtStartMode"),
            _ => todo!(),
        }

        Ok(())
    }
}

pub struct BtManager {
    bt: Arc<CharacterDevice>,
}

impl BtManager {
    pub fn new() -> Result<Arc<Self>, BtInitError> {
        let bt = make_dev(
            Bt::new(),
            DriverFlags::from_bits_retain(0x80000000),
            0,
            "bt",
            Uid::ROOT,
            Gid::ROOT,
            Mode::new(0o666).unwrap(),
            None,
            MakeDevFlags::MAKEDEV_ETERNAL,
        )?;

        Ok(Arc::new(Self { bt }))
    }
}

/// Represents an error when [`BtManager`] fails to initialize.
#[derive(Debug, Error)]
pub enum BtInitError {
    #[error("cannot create bt device")]
    CreateBtFailed(#[from] MakeDevError),
}
