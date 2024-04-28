use crate::budget::BudgetType;
use crate::errno::Errno;
use crate::fs::{
    DefaultFileBackendError, PollEvents, Stat, TruncateLength, VFile, VFileFlags, VFileType,
};
use crate::process::{FileDesc, VThread};
use crate::syscalls::{SysErr, SysIn, SysOut, Syscalls};
use crate::time::TimeSpec;
use crate::{error, info, warn};
use std::convert::Infallible;
use std::ptr;
use std::sync::{Arc, Weak};

pub struct KernelQueueManager {}

impl KernelQueueManager {
    pub fn new(sys: &mut Syscalls) -> Arc<Self> {
        let kq = Arc::new(Self {});

        sys.register(141, &kq, Self::sys_kqueueex);
        sys.register(362, &kq, Self::sys_kqueue);
        sys.register(363, &kq, Self::sys_kevent);

        kq
    }

    fn sys_kqueueex(self: &Arc<Self>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        warn!("sys_kqueueex stubbed");
        self.sys_kqueue(td, i)
    }

    fn sys_kqueue(self: &Arc<Self>, td: &VThread, _: &SysIn) -> Result<SysOut, SysErr> {
        let filedesc = td.proc().files();

        let fd = filedesc.alloc_with_budget::<Infallible>(
            |_| {
                let kq = KernelQueue::new(&filedesc);

                filedesc.insert_kqueue(kq.clone());

                Ok(VFile::new(
                    VFileType::KernelQueue,
                    VFileFlags::READ | VFileFlags::WRITE,
                    None,
                    Box::new(FileBackend(kq)),
                ))
            },
            BudgetType::FdEqueue,
        )?;

        Ok(fd.into())
    }

    fn sys_kevent(self: &Arc<Self>, _td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let kq: usize = i.args[0].into();
        let changelist: *const Kevent = i.args[1].into();
        let nchanges: i32 = i.args[2].try_into().unwrap();
        let eventlist: *mut Kevent = i.args[3].into();
        let nevents: i32 = i.args[4].try_into().unwrap();
        let timeout: *const TimeSpec = i.args[5].into();

        let fd = (kq & 0xffffffff) as u32;
        let obj = (kq >> 0x20) as u32;

        info!(
            "sys_kevent({} ({}), {:#x}, {}, {:#x}, {}, {:#x})",
            fd, obj, changelist as usize, nchanges, eventlist as usize, nevents, timeout as usize
        );

        let changes = unsafe { std::slice::from_raw_parts(changelist, nchanges as _) };

        info!("changes: {:?}", changes);

        if nevents == 0 {
            return Ok(SysOut::ZERO);
        }

        if timeout != ptr::null() {
            warn!("kevent: stubbed elapsed timeout");
            return Ok(SysOut::ZERO);
        }

        todo!()
    }
}

#[derive(Debug)]
pub struct KernelQueue {
    filedesc: Weak<FileDesc>,
}

impl KernelQueue {
    pub fn new(filedesc: &Arc<FileDesc>) -> Arc<Self> {
        Arc::new(KernelQueue {
            filedesc: Arc::downgrade(filedesc),
        })
    }
}

/// Implementation of [`crate::fs::FileBackend`] for kqueue.
#[derive(Debug)]
struct FileBackend(Arc<KernelQueue>);

impl crate::fs::FileBackend for FileBackend {
    fn is_seekable(&self) -> bool {
        todo!()
    }

    #[allow(unused_variables)] // TODO: remove when implementing
    fn poll(&self, file: &VFile, events: PollEvents, td: &VThread) -> PollEvents {
        todo!()
    }

    fn stat(&self, _: &VFile, _: Option<&VThread>) -> Result<Stat, Box<dyn Errno>> {
        let mut stat = Stat::zeroed();

        stat.mode = 0o10000;

        Ok(stat)
    }

    fn truncate(
        &self,
        _: &VFile,
        _: TruncateLength,
        _: Option<&VThread>,
    ) -> Result<(), Box<dyn Errno>> {
        Err(Box::new(DefaultFileBackendError::InvalidValue))
    }
}

#[repr(C)]
#[derive(Debug)]
struct Kevent {
    ident: usize,
    filter: i16,
    flags: u16,
    fflags: u32,
    data: usize,
    udata: usize,
}
