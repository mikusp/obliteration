use crate::errno::{EINVAL, ESRCH, ETIMEDOUT};
use crate::idt::Entry;
use crate::memory::MmapError;
use crate::process::VThread;
use crate::syscalls::{SysErr, SysIn, SysOut, Syscalls};
use crate::{info, warn, VProc};
use bitflags::bitflags;
use bytemuck::Contiguous;
use std::convert::Infallible;
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime};

pub struct OsemManager {
    proc: Arc<VProc>,
}

impl OsemManager {
    pub fn new(sys: &mut Syscalls, proc: &Arc<VProc>) -> Arc<Self> {
        let osem = Arc::new(Self { proc: proc.clone() });

        sys.register(549, &osem, Self::sys_osem_create);
        sys.register(550, &osem, Self::sys_osem_delete);
        sys.register(551, &osem, Self::sys_osem_open);
        sys.register(552, &osem, Self::sys_osem_close);
        sys.register(553, &osem, Self::sys_osem_wait);
        sys.register(555, &osem, Self::sys_osem_post);

        osem
    }

    fn sys_osem_create(self: &Arc<Self>, _: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let name = unsafe { i.args[0].to_str(32) }?.unwrap();
        let flags = {
            let flags = i.args[1].try_into().unwrap();
            let mut flags = OsemFlags::from_bits_retain(flags);

            if flags.bits() & 0xfffffefc != 0 || flags.bits() & 0x3 == 0x3 {
                return Err(SysErr::Raw(EINVAL));
            }

            if flags.bits() & 0x3 == 0 {
                flags |= OsemFlags::QUEUE_FIFO;
            }

            flags
        };

        let init_count = i.args[2].try_into().unwrap();
        let max_count = i.args[3].try_into().unwrap();

        info!(
            "...=sys_osem_create({}, {:?}, {}, {})",
            name, flags, init_count, max_count
        );

        if init_count < 0 {
            return Err(SysErr::Raw(EINVAL));
        }

        if max_count <= 0 || init_count > max_count {
            return Err(SysErr::Raw(EINVAL));
        }

        let mut objects = self.proc.objects_mut();

        // let (entry, id) =
        //     objects.alloc::<_, MmapError>(|_| Ok(Osem::new(flags, init_count, max_count)))?;

        // entry.set_name(Some(name.to_owned()));
        // entry.set_ty(Osem::ENTRY_TYPE);
        let id = objects.alloc_infallible(|_| {
            Entry::new(
                Some(name.to_owned()),
                Osem::new(flags, init_count, max_count),
                Osem::ENTRY_TYPE,
            )
        });

        if flags.intersects(OsemFlags::SEM_SHARED) {
            let mut gnt = self.proc.gnt_mut();

            // gnt.insert(name.to_owned(), entry.data().clone());
        }

        info!(
            "{}=sys_osem_create({}, {:?}, {}, {})",
            id, name, flags, init_count, max_count
        );

        Ok(id.into())
    }

    fn sys_osem_delete(self: &Arc<Self>, _: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let sem_id = i.args[0].into();

        info!("...=sys_osem_delete({})", sem_id);

        let mut objects = self.proc.objects_mut();

        objects
            .delete(sem_id, Some(Osem::ENTRY_TYPE))
            .ok_or(SysErr::Raw(ESRCH))?;

        info!("...=sys_osem_delete({})", sem_id);

        Ok(0.into())
    }

    fn sys_osem_open(self: &Arc<Self>, _: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let sem_name = unsafe { i.args[0].to_str(32) }?.unwrap();

        info!("...=sys_osem_open({})", sem_name);
        return Ok(0.into());

        let gnt = self.proc.gnt_mut();
        let existing = gnt.get(sem_name.into());
        match existing {
            None => Err(SysErr::Raw(ESRCH)),
            Some(entry) => {
                // todo!();
                let osem: &Arc<Osem> = &entry
                    .clone()
                    .downcast()
                    .expect("wrong type of named object");
                let mut objects = self.proc.objects_mut();
                let id = objects.alloc_infallible(|_| {
                    Entry::new(
                        Some(sem_name.into()),
                        Arc::new(osem.clone()),
                        Osem::ENTRY_TYPE,
                    )
                });

                // fd_entry.set_ty(Osem::ENTRY_TYPE);
                // fd_entry.set_name(Some(sem_name.into()));
                // fd_entry.set_data(osem.clone());
                drop(objects);

                Ok(id.into())
            }
        }
    }

    fn sys_osem_close(self: &Arc<Self>, _: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let sem_id: i64 = i.args[0].into();

        info!("0=sys_osem_close({})", sem_id);

        Ok(0.into())
    }

    fn sys_osem_wait(self: &Arc<Self>, _: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let sem_id = i.args[0].into();
        let need_count = i.args[1].try_into().unwrap();
        let timeout: *mut u32 = i.args[2].into();

        let useconds = if timeout.is_null() {
            None
        } else {
            unsafe { Some(*timeout) }
        };

        info!(
            "...=sys_osem_wait({}, {}, {:#x})",
            sem_id, need_count, timeout as usize
        );

        let objects = self.proc.objects();

        let sem: Arc<Osem> = objects
            .get(sem_id, Some(0x120))
            .ok_or(SysErr::Raw(ESRCH))?
            .data()
            .clone()
            .downcast()
            .map_err(|_| SysErr::Raw(ESRCH))?;

        if need_count < 1 || need_count > sem.max_count {
            return Err(SysErr::Raw(EINVAL));
        }

        let timestamp = Instant::now();

        let mut old_value = sem.current_count.load(Ordering::Acquire);
        loop {
            let elapsed_us = timestamp.elapsed().as_micros();
            if useconds.map(|us| elapsed_us > us.into()).is_some_and(|x| x) {
                unsafe {
                    ptr::write(timeout, 0);
                }
                return Err(SysErr::Raw(ETIMEDOUT));
            }

            if old_value < need_count
                || sem
                    .current_count
                    .compare_exchange(
                        old_value,
                        old_value - need_count,
                        Ordering::Acquire,
                        Ordering::Relaxed,
                    )
                    .is_err()
            {
                old_value = sem.current_count.load(Ordering::Acquire);
                continue;
            }

            break;
        }

        if let Some(timeout_us) = useconds {
            unsafe {
                ptr::write(timeout, timeout_us - timestamp.elapsed().as_micros() as u32);
            }
        }

        info!(
            "0=sys_osem_wait({}, {}, {:#x})",
            sem_id, need_count, timeout as usize
        );

        Ok(0.into())
    }

    fn sys_osem_post(self: &Arc<Self>, _: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let sem_id = i.args[0].into();
        let signal_count: i32 = i.args[1].try_into().unwrap();

        info!("...=sys_osem_post({}, {})", sem_id, signal_count);

        let objects = self.proc.objects();

        let sem: Arc<Osem> = objects
            .get(sem_id, Some(0x120))
            .ok_or(SysErr::Raw(ESRCH))?
            .data()
            .clone()
            .downcast()
            .map_err(|_| SysErr::Raw(ESRCH))?;

        let mut old_value = sem.current_count.load(Ordering::Acquire);

        if signal_count < 0 || old_value + (signal_count as u32) > sem.max_count {
            return Err(SysErr::Raw(EINVAL));
        }

        loop {
            if sem
                .current_count
                .compare_exchange(
                    old_value,
                    old_value + (signal_count as u32),
                    Ordering::Acquire,
                    Ordering::Relaxed,
                )
                .is_err()
            {
                old_value = sem.current_count.load(Ordering::Acquire);
                continue;
            }

            break;
        }

        info!("0=sys_osem_post({}, {})", sem_id, signal_count);

        Ok(0.into())
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct OsemFlags: u32 {
        const QUEUE_FIFO = 0x1;
        const QUEUE_THR_PRIO = 0x2;
        const SEM_SHARED = 0x100;
    }
}
struct Osem {
    flags: OsemFlags,
    init_count: u32,
    current_count: AtomicU32,
    max_count: u32,
}

impl Osem {
    const ENTRY_TYPE: u16 = 0x120;
    pub fn new(flags: OsemFlags, init_count: u32, max_count: u32) -> Arc<Self> {
        Arc::new(Self {
            flags,
            init_count,
            current_count: AtomicU32::new(init_count),
            max_count,
        })
    }
}
