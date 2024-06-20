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
struct NpDrm {}

impl NpDrm {
    pub fn new() -> Self {
        Self {}
    }
}

impl DeviceDriver for NpDrm {
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
            _ => todo!(),
        }

        Ok(())
    }
}

pub struct NpDrmManager {
    npdrm: Arc<CharacterDevice>,
}

impl NpDrmManager {
    pub fn new() -> Result<Arc<Self>, NpDrmInitError> {
        let npdrm = make_dev(
            NpDrm::new(),
            DriverFlags::from_bits_retain(0x80000004),
            0,
            "npdrm",
            Uid::ROOT,
            Gid::ROOT,
            Mode::new(0o666).unwrap(),
            None,
            MakeDevFlags::MAKEDEV_ETERNAL,
        )?;

        Ok(Arc::new(Self { npdrm }))
    }
}

/// Represents an error when [`NpDrmManager`] fails to initialize.
#[derive(Debug, Error)]
pub enum NpDrmInitError {
    #[error("cannot create npdrm device")]
    CreateNpDrmFailed(#[from] MakeDevError),
}
