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
struct Hid {}

impl Hid {
    pub fn new() -> Self {
        Self {}
    }
}

impl DeviceDriver for Hid {
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
            IoCmd::HIDUNK1(_) => warn!("ignoring HIDUNK1"),
            _ => todo!(),
        }

        Ok(())
    }
}

pub struct HidManager {
    hid: Arc<CharacterDevice>,
}

impl HidManager {
    pub fn new() -> Result<Arc<Self>, HidInitError> {
        let hid = make_dev(
            Hid::new(),
            DriverFlags::from_bits_retain(0x80000004),
            0,
            "hid",
            Uid::ROOT,
            Gid::ROOT,
            Mode::new(0o666).unwrap(),
            None,
            MakeDevFlags::MAKEDEV_ETERNAL,
        )?;

        Ok(Arc::new(Self { hid }))
    }
}

/// Represents an error when [`HidManager`] fails to initialize.
#[derive(Debug, Error)]
pub enum HidInitError {
    #[error("cannot create hid device")]
    CreateHidFailed(#[from] MakeDevError),
}
