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
struct Geom {}

impl Geom {
    pub fn new() -> Self {
        Self {}
    }
}

impl DeviceDriver for Geom {
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
            IoCmd::GEOMUNK1(_) => warn!("stubbed GEOMUNK1"),
            _ => todo!(),
        }

        Ok(())
    }
}

pub struct GeomManager {
    geom_ctl: Arc<CharacterDevice>,
}

impl GeomManager {
    pub fn new() -> Result<Arc<Self>, GeomInitError> {
        let geom_ctl = make_dev(
            Geom::new(),
            DriverFlags::from_bits_retain(0x80400000),
            0,
            "geom.ctl",
            Uid::ROOT,
            Gid::ROOT,
            Mode::new(0o666).unwrap(),
            None,
            MakeDevFlags::MAKEDEV_ETERNAL,
        )?;

        Ok(Arc::new(Self { geom_ctl }))
    }
}

/// Represents an error when [`GeomManager`] fails to initialize.
#[derive(Debug, Error)]
pub enum GeomInitError {
    #[error("cannot create geom device")]
    CreateGeomFailed(#[from] MakeDevError),
}
