use crate::{
    errno::Errno,
    error,
    fs::{
        make_dev, CharacterDevice, DeviceDriver, DriverFlags, IoCmd, MakeDevError, MakeDevFlags,
        Mode, OpenFlags,
    },
    info,
    process::VThread,
    ucred::{Gid, Uid},
};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug)]
struct Devctl {}

impl Devctl {
    fn new() -> Self {
        Self {}
    }
}

impl DeviceDriver for Devctl {
    #[allow(unused_variables)] // TODO: remove when implementing
    fn open(
        &self,
        dev: &Arc<CharacterDevice>,
        mode: OpenFlags,
        devtype: i32,
        td: Option<&VThread>,
    ) -> Result<(), Box<dyn Errno>> {
        todo!()
    }

    fn ioctl(
        &self,
        _: &Arc<CharacterDevice>,
        cmd: IoCmd,
        _: Option<&VThread>,
    ) -> Result<(), Box<dyn Errno>> {
        match cmd {
            _ => todo!(),
        }

        Ok(())
    }
}

pub struct DevctlManager {
    devctl: Arc<CharacterDevice>,
}

impl DevctlManager {
    pub fn new() -> Result<Arc<Self>, DevctlInitError> {
        let devctl = make_dev(
            Devctl::new(),
            DriverFlags::from_bits_retain(0x80400000),
            0,
            "devctl",
            Uid::ROOT,
            Gid::ROOT,
            Mode::new(0o600).unwrap(),
            None,
            MakeDevFlags::empty(),
        )?;

        Ok(Arc::new(Self { devctl }))
    }
}

/// Represents an error when [`DevctlManager`] fails to initialize.
#[derive(Debug, Error)]
pub enum DevctlInitError {
    #[error("cannot create devctl device")]
    CreateDevctlFailed(#[from] MakeDevError),
}
