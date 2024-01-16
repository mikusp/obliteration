use crate::errno::{EINVAL, ESRCH};
use crate::idt::Entry;
use crate::process::VThread;
use crate::syscalls::{SysErr, SysIn, SysOut, Syscalls};
use crate::{info, VProc};
use bitflags::bitflags;
use gmtx::{Gutex, GutexGroup};
use std::sync::{Arc, Condvar, Mutex, Weak};

pub struct EvfManager {
    proc: Arc<VProc>,
}

impl EvfManager {
    pub fn new(sys: &mut Syscalls, proc: &Arc<VProc>) -> Arc<Self> {
        let evf = Arc::new(Self { proc: proc.clone() });

        sys.register(538, &evf, Self::sys_evf_create);
        sys.register(540, &evf, Self::sys_evf_open);
        sys.register(541, &evf, Self::sys_evf_close);
        sys.register(542, &evf, Self::sys_evf_wait);
        sys.register(543, &evf, Self::sys_evf_try_wait);
        sys.register(544, &evf, Self::sys_evf_set);
        sys.register(545, &evf, Self::sys_evf_clear);
        sys.register(546, &evf, Self::sys_evf_cancel);

        evf
    }

    fn sys_evf_create(self: &Arc<Self>, _: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let name = unsafe { i.args[0].to_str(32) }?.unwrap();
        let attr = {
            let attr = i.args[1].try_into().unwrap();
            let mut attr = EventFlagAttr::from_bits_retain(attr);

            if attr.bits() & 0xfffffecc != 0
                || attr.bits() & 0x3 == 0x3
                || attr.bits() & 0x30 == 0x30
            {
                return Err(SysErr::Raw(EINVAL));
            }

            if attr.bits() & 0x3 == 0 {
                attr |= EventFlagAttr::EVF_FIFO_ORDER;
            }

            if attr.bits() & 0x30 == 0 {
                attr |= EventFlagAttr::EVF_SINGLE_THR;
            }

            attr
        };
        let init_pattern: u64 = i.args[2].into();

        let mut objects = self.proc.objects_mut();

        let id = objects.alloc_infallible(|_| {
            Entry::new(
                Some(name.into()),
                Arc::new(EventFlag::new(attr, init_pattern)),
                EventFlag::ENTRY_TYPE,
            )
        });

        info!(
            "{}=sys_evf_create({}, {:#x}, {:#x})",
            id, name, attr, init_pattern
        );
        // entry.set_name(Some(name.to_owned()));
        // entry.set_ty(EventFlag::ENTRY_TYPE);

        // if attr.intersects(EventFlagAttr::EVF_SHARED) {
        //     self.proc
        //         .gnt_mut()
        //         .insert(name.to_owned(), entry.data().clone());
        // }

        Ok(id.into())
    }

    fn sys_evf_open(self: &Arc<Self>, _: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let flag_name = unsafe { i.args[0].to_str(32)? }.unwrap();
        let flag_name_ptr: usize = i.args[0].into();
        info!("sys_evf_open({})", flag_name);

        if flag_name.is_empty() {
            return Ok(0.into());
            // unsafe {
            //     info!("flag_name_ptr: {:#x}", flag_name_ptr);
            //     info!("flag_ptr: {:#x}", flag_name_ptr - 8);
            //     info!("flag_inited: {}", unsafe {
            //         *((flag_name_ptr + 8) as *const c_short)
            //     });
            //     info!("client_ptr: {:#x}", flag_name_ptr - 8 - 0x28);
            //     info!("*client_ptr: {:#x}", unsafe {
            //         *((flag_name_ptr - 8 - 0x28) as *const c_ulong)
            //     });
            //     info!("client_ipmi_ptr: {:#x}", flag_name_ptr - 0x28);
            //     info!("*client_ipmi_ptr: {:#x}", unsafe {
            //         *((flag_name_ptr - 0x28) as *const c_ulong)
            //     });
            //     info!("{}", getpid());
            //     unsafe { kill(getpid(), SIGSTOP) };
            // }
        }
        let gnt = self.proc.gnt_mut();
        let existing = gnt.get(flag_name.into());
        match existing {
            None => Err(SysErr::Raw(ESRCH)),
            Some(entry) => {
                // todo!();
                let flag: &Arc<EventFlag> = &entry
                    .clone()
                    .downcast()
                    .expect("wrong type of named object");
                let mut objects = self.proc.objects_mut();
                let id = objects.alloc_infallible(|_| {
                    Entry::new(Some(flag_name.into()), flag.clone(), EventFlag::ENTRY_TYPE)
                });

                // fd_entry.set_ty(EventFlag::ENTRY_TYPE);
                // fd_entry.set_name(Some(flag_name.into()));
                // fd_entry.set_data(flag.clone());
                drop(objects);

                Ok(id.into())
            }
        }
    }

    fn sys_evf_close(self: &Arc<Self>, _: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let evf: usize = i.args[0].into();

        info!("sys_evf_close({})", evf);

        return Ok(0.into());
    }

    fn sys_evf_wait(self: &Arc<Self>, _: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let evf: usize = i.args[0].into();
        let pattern: u64 = i.args[1].into();
        let wait_mode: u32 = i.args[2].try_into().unwrap();
        let result_pattern: *const u64 = i.args[3].into();
        let timeout: *const u64 = i.args[4].into();

        info!(
            "sys_evf_wait({}, {:#x}, {:#x}, {:#x}, {:#x})",
            evf, pattern, wait_mode, result_pattern as usize, timeout as usize
        );

        let objects = self.proc.objects();

        match objects.get(evf, Some(EventFlag::ENTRY_TYPE)) {
            None => return Err(SysErr::Raw(ESRCH)),
            Some(entry) => {
                let flag: &Arc<EventFlag> = &entry
                    .data()
                    .clone()
                    .downcast()
                    .expect("wrong type of named object");

                let pair = Arc::new((Mutex::new(false), Condvar::new()));
                let pair2 = Arc::downgrade(&pair);

                let wt = WaitingThread {
                    td: VThread::current().unwrap().clone(),
                    sync: pair2,
                    pattern: pattern,
                    wait_mode: EventFlagWaitMode::from_bits_retain(wait_mode),
                };
                let mut queue = flag.waiting_threads.write();
                queue.push(wt);
                drop(queue);

                let (mtx, cv) = &*pair;

                let mut started = mtx.lock().unwrap();
                drop(objects);
                while !*started {
                    started = cv.wait(started).unwrap();
                }

                todo!();
            }
        }
        return Ok(0.into());
    }

    fn sys_evf_try_wait(self: &Arc<Self>, _: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let evf: usize = i.args[0].into();

        info!("sys_evf_try_wait({})", evf);
        todo!();

        return Ok(0.into());
    }

    fn sys_evf_set(self: &Arc<Self>, _: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let evf = i.args[0].into();
        let pattern: u64 = i.args[1].into();

        info!("sys_evf_set({}, {:#x})", evf, pattern);

        match self
            .proc
            .objects_mut()
            .get(evf, Some(EventFlag::ENTRY_TYPE))
        {
            None => Err(SysErr::Raw(ESRCH)),
            Some(entry) => {
                let flag: &Arc<EventFlag> = &entry
                    .data()
                    .clone()
                    .downcast()
                    .expect("wrong type of named object");

                let mut pat = flag.pattern.write();
                let mut new_val = *pat | pattern;
                // *pat = new_val;

                let mut waiting_threads = flag.waiting_threads.write();

                info!("{} threads waiting on evf {}", waiting_threads.len(), evf);

                waiting_threads.retain(|wt| {
                    let wait_condition_met = match wt.wait_mode {
                        wm if wm.intersects(EventFlagWaitMode::EVF_WAITMODE_AND) => {
                            new_val & wt.pattern == wt.pattern
                        }
                        wm if wm.intersects(EventFlagWaitMode::EVF_WAITMODE_OR) => {
                            new_val & wt.pattern != 0
                        }
                        _ => todo!("wt.wait_mode does not include neither AND nor OR"),
                    };

                    if wait_condition_met {
                        match wt.wait_mode {
                            wm if wm.intersects(EventFlagWaitMode::EVF_WAITMODE_CLEAR_ALL) => {
                                new_val = 0
                            }
                            wm if wm.intersects(EventFlagWaitMode::EVF_WAITMODE_CLEAR_PAT) => {
                                new_val = new_val & !wt.pattern
                            }
                            _ => todo!("wt.wait_mode does not specify CLEAR condition"),
                        }

                        *pat = new_val;
                        if let Some(arc) = wt.sync.upgrade() {
                            let (lock, cvar) = &*arc;
                            let mut started = lock.lock().unwrap();
                            *started = true;
                            // We notify the condvar that the value has changed.
                            info!("waking thread {:?} by evf", wt.td.id());
                            cvar.notify_one();
                        }
                    }

                    !wait_condition_met
                });

                Ok((new_val as usize).into())
            }
        }
    }

    fn sys_evf_clear(self: &Arc<Self>, _: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let evf = i.args[0].into();
        let pattern: u64 = i.args[1].into();

        info!("sys_evf_clear({}, {:#x})", evf, pattern);

        match self
            .proc
            .objects_mut()
            .get(evf, Some(EventFlag::ENTRY_TYPE))
        {
            None => Err(SysErr::Raw(ESRCH)),
            Some(entry) => {
                let flag: &Arc<EventFlag> = &entry
                    .data()
                    .clone()
                    .downcast()
                    .expect("wrong type of named object");

                let mut pat = flag.pattern.write();
                let new_val = pattern & *pat;
                *pat = new_val;

                Ok((new_val as usize).into())
            }
        }
    }

    fn sys_evf_cancel(self: &Arc<Self>, _: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let evf = i.args[0].into();
        let pattern: u64 = i.args[1].into();
        let num_waiting_threads: *mut i32 = i.args[2].into();

        info!(
            "sys_evf_cancel({}, {:#x}, {:#x})",
            evf,
            pattern,
            (num_waiting_threads as usize)
        );

        match self
            .proc
            .objects_mut()
            .get(evf, Some(EventFlag::ENTRY_TYPE))
        {
            None => Err(SysErr::Raw(ESRCH)),
            Some(entry) => {
                let flag: &Arc<EventFlag> = &entry
                    .data()
                    .clone()
                    .downcast()
                    .expect("wrong type of named object");

                let mut pat = flag.pattern.write();
                *pat = pattern;

                //TODO: evict threads

                if !num_waiting_threads.is_null() {
                    todo!("num_waiting_threads is not NULL")
                }

                Ok(0.into())
            }
        }
    }
}

struct EventFlag {
    attr: EventFlagAttr,
    pattern: Gutex<u64>,
    waiting_threads: Gutex<Vec<WaitingThread>>,
}

impl EventFlag {
    const ENTRY_TYPE: u16 = 0x110;
    pub fn new(attr: EventFlagAttr, pattern: u64) -> Arc<Self> {
        let gg = GutexGroup::new();
        Arc::new(Self {
            attr,
            pattern: gg.spawn(pattern),
            waiting_threads: gg.spawn(vec![]),
        })
    }
}

bitflags! {
    #[derive(Clone, Copy)]
    pub struct EventFlagAttr: u32 {
        const EVF_FIFO_ORDER = 0x01;
        const EVF_PRIO_ORDER = 0x02;
        const EVF_SINGLE_THR = 0x10;
        const EVF_MULTI_THR = 0x20;
        const EVF_SHARED = 0x100;
    }
}

bitflags! {
    #[derive(Clone, Copy)]
    pub struct EventFlagWaitMode: u32 {
        const EVF_WAITMODE_AND = 0x01;
        const EVF_WAITMODE_OR = 0x02;
        const EVF_WAITMODE_CLEAR_ALL = 0x10;
        const EVF_WAITMODE_CLEAR_PAT = 0x20;
    }
}

struct WaitingThread {
    td: Arc<VThread>,
    sync: Weak<(Mutex<bool>, Condvar)>,
    pattern: u64,
    wait_mode: EventFlagWaitMode,
}
