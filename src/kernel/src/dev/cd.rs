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
struct Cd {}

impl Cd {
    pub fn new() -> Self {
        Self {}
    }
}

impl DeviceDriver for Cd {
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
            IoCmd::DEVUNK2(_) => error!("stubbed cd::devunk2"),
            IoCmd::DEVUNK3(_) => error!("stubbed cd::devunk3"),
            _ => todo!(),
        }

        Ok(())
    }
}

pub struct CdManager {
    cd0: Arc<CharacterDevice>,
}

impl CdManager {
    pub fn new() -> Result<Arc<Self>, CdInitError> {
        let cd0 = make_dev(
            Cd::new(),
            DriverFlags::from_bits_retain(0x80000000),
            0,
            "cd0",
            Uid::ROOT,
            Gid::ROOT,
            Mode::new(0o666).unwrap(),
            None,
            MakeDevFlags::MAKEDEV_ETERNAL,
        )?;

        Ok(Arc::new(Self { cd0 }))
    }
}

/// Represents an error when [`CdManager`] fails to initialize.
#[derive(Debug, Error)]
pub enum CdInitError {
    #[error("cannot create cd device")]
    CreateCdFailed(#[from] MakeDevError),
}
