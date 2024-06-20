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
struct Notification {}

impl Notification {
    pub fn new() -> Self {
        Self {}
    }
}

impl DeviceDriver for Notification {
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

pub struct NotificationManager {
    notification2: Arc<CharacterDevice>,
}

impl NotificationManager {
    pub fn new() -> Result<Arc<Self>, NotificationInitError> {
        let notification2 = make_dev(
            Notification::new(),
            DriverFlags::from_bits_retain(0x80000000),
            0,
            "notification2",
            Uid::ROOT,
            Gid::ROOT,
            Mode::new(0o600).unwrap(),
            None,
            MakeDevFlags::MAKEDEV_ETERNAL,
        )?;

        Ok(Arc::new(Self { notification2 }))
    }
}

/// Represents an error when [`NotificationManager`] fails to initialize.
#[derive(Debug, Error)]
pub enum NotificationInitError {
    #[error("cannot create notification device")]
    CreateNotificationFailed(#[from] MakeDevError),
}
