pub use self::dmem::*;
pub use self::page::*;
pub use self::stack::*;

use self::dmem::*;
use self::iter::StartFromMut;
use self::storage::Memory;
use self::storage::Storage;
use crate::dev::DmemContainer;
use crate::errno::EAGAIN;
use crate::errno::{Errno, EINVAL, ENOMEM, EOPNOTSUPP};
use crate::error;
use crate::fs::VFile;
use crate::fs::VFileType;
use crate::process::GetFileError;
use crate::process::VThread;
use crate::syscalls::{SysArg, SysErr, SysIn, SysOut, Syscalls};
use crate::{info, warn};
use bitflags::bitflags;
use bitflags::Flags;
use gmtx::Gutex;
use gmtx::GutexGroup;
use macros::Errno;
use std::cmp::max;
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fmt::{Display, Formatter};
use std::io::Error;
use std::num::TryFromIntError;
use std::os::raw::c_void;
use std::ptr::null_mut;
use std::sync::{Arc, RwLock};
use thiserror::Error;

mod dmem;
mod iter;
mod page;
mod stack;
mod storage;

/// Implementation of `vmspace` structure.
#[derive(Debug)]
pub struct Vm {
    allocation_granularity: usize,
    dmem_allocations: RwLock<BTreeMap<PhysAddr, DmemAllocation>>,
    allocations: RwLock<BTreeMap<usize, Memory>>, // Key is DmemAllocation::phys_addr
    mappings: RwLock<BTreeMap<usize, Mapping>>,   // Key is Mapping::addr.
    dmem: Arc<DmemAllocator>,
    stack: AppStack,
}

#[derive(Debug)]
pub enum Addr {
    VirtAddr(usize),
    PhysAddr(PhysAddr),
}

pub struct VmObject {}

impl Vm {
    /// Size of a memory page on PS4.
    pub const VIRTUAL_PAGE_SIZE: usize = 0x4000;

    /// See `vmspace_alloc` on the PS4 for a reference.
    pub fn new(sys: &mut Syscalls) -> Result<Arc<Self>, MemoryManagerError> {
        // Check if page size on the host is supported. We don't need to check allocation
        // granularity because it is always multiply by page size, which is a correct value.
        let (page_size, allocation_granularity) = Self::get_memory_model();

        if page_size > Self::VIRTUAL_PAGE_SIZE {
            // If page size is larger than PS4 we will have a problem with memory protection.
            // Let's say page size on the host is 32K and we have 2 adjacent virtual pages, which is
            // 16K per virtual page. The first virtual page want to use read/write while the second
            // virtual page want to use read-only. This scenario will not be possible because those
            // two virtual pages are on the same page.
            return Err(MemoryManagerError::UnsupportedPageSize);
        }

        let dmem_allocator =
            DmemAllocator::new().map_err(|_| MemoryManagerError::UnsupportedPageSize)?;

        let mut mm = Self {
            allocation_granularity,
            dmem_allocations: RwLock::default(),
            allocations: RwLock::default(),
            mappings: RwLock::default(),
            dmem: dmem_allocator,
            stack: AppStack::new(),
        };

        // Allocate main stack.
        let guard = match mm.mmap(
            0,
            mm.stack.len() + Self::VIRTUAL_PAGE_SIZE,
            mm.stack.prot(),
            "main stack",
            MappingFlags::MAP_ANON | MappingFlags::MAP_PRIVATE,
            -1,
            0,
        ) {
            Ok(v) => v.into_raw(),
            Err(e) => return Err(MemoryManagerError::StackAllocationFailed(e)),
        };

        // Set the guard page to be non-accessible.
        if let Err(e) = mm.mprotect(guard, Self::VIRTUAL_PAGE_SIZE, Protections::empty()) {
            return Err(MemoryManagerError::GuardStackFailed(e));
        }

        mm.stack.set_guard(guard);
        mm.stack
            .set_stack(unsafe { guard.add(Self::VIRTUAL_PAGE_SIZE) });

        // Register syscall handlers.
        let mm = Arc::new(mm);

        sys.register(69, &mm, Self::sys_sbrk);
        sys.register(70, &mm, Self::sys_sstk);
        sys.register(73, &mm, Self::sys_munmap);
        sys.register(74, &mm, Self::sys_mprotect);
        sys.register(203, &mm, Self::sys_mlock);
        sys.register(477, &mm, Self::sys_mmap);
        sys.register(548, &mm, Self::sys_batch_map);
        sys.register(588, &mm, Self::sys_mname);
        sys.register(628, &mm, Self::sys_mmap_dmem);

        Ok(mm)
    }

    pub fn stack(&self) -> &AppStack {
        &self.stack
    }

    pub fn dmem(&self) -> &Arc<DmemAllocator> {
        &self.dmem
    }

    pub fn allocate_dmem(
        &self,
        search_start: usize,
        search_end: usize,
        len: usize,
        align: usize,
    ) -> Result<PhysAddr, SysErr> {
        let mut allocations = self.dmem_allocations.write().unwrap();

        info!(
            "Vm::allocate_dmem({:#x}, {:#x}, {:#x}, {:#x})",
            search_start, search_end, len, align
        );

        if allocations.is_empty() {
            let phys_addr = PhysAddr(search_start);
            let alloc = DmemAllocation { phys_addr, len };

            allocations.insert(phys_addr, alloc);

            Ok(phys_addr)
        } else if allocations.len() == 1 {
            info!("allocate: one allocation");
            let entry = allocations.last_entry().unwrap();
            let allocation = entry.get();

            let mut candidate = search_start
                + (search_start as *const c_void).align_offset(if align == 0 {
                    0x4000
                } else {
                    align
                });

            loop {
                info!(
                    "allocate: candidate {:#x}, len {:#x}, alloc_start {:#x}",
                    candidate, len, allocation.phys_addr.0
                );

                if candidate + len < allocation.phys_addr.0
                    || (candidate >= (allocation.phys_addr.0 + allocation.len)
                        && (candidate + len) < search_end)
                {
                    let phys_addr = PhysAddr(candidate);
                    let alloc = DmemAllocation { phys_addr, len };

                    allocations.insert(phys_addr, alloc);
                    // allocations.sort_by(|a, b| a.phys_addr.partial_cmp(&b.phys_addr).unwrap());

                    return Ok(phys_addr);
                }
                if candidate >= search_end {
                    return Err(SysErr::Raw(ENOMEM));
                }

                candidate = candidate + if align == 0 { 0x4000 } else { align };
            }
            // let candidate = last_allocation.phys_addr.0 + last_allocation.len;
            // let aligned_candidate = candidate
            //     + (candidate as *const c_void).align_offset(if align == 0 {
            //         0x4000
            //     } else {
            //         align
            //     });

            // if aligned_candidate + len < search_end {
            //     let phys_addr = PhysAddr(aligned_candidate);
            //     let alloc = DmemAllocation { phys_addr, len };

            //     allocations.push(alloc);

            //     Ok(phys_addr)
            // } else {
            //     warn!("allocations: {:?}", *allocations);
            //     warn!(
            //         "allocate: aligned_candidate={:#x}, len={:#x}, search_end={:#x}",
            //         aligned_candidate, len, search_end
            //     );
            //     todo!()
            // }
        } else {
            // first try at the beginning of the area
            info!("allocate: trying at the beginning");
            let entry = allocations.first_entry().unwrap();
            let allocation = entry.get();

            let mut candidate = search_start
                + (search_start as *const c_void).align_offset(if align == 0 {
                    0x4000
                } else {
                    align
                });

            loop {
                if candidate + len < allocation.phys_addr.0 {
                    let phys_addr = PhysAddr(candidate);
                    let alloc = DmemAllocation { phys_addr, len };

                    allocations.insert(phys_addr, alloc);
                    // allocations.sort_by(|a, b| a.phys_addr.partial_cmp(&b.phys_addr).unwrap());

                    return Ok(phys_addr);
                }
                if candidate >= allocation.phys_addr.0 {
                    break;
                }

                candidate = candidate + if align == 0 { 0x4000 } else { align };
            }

            // now in between mappings
            let c = allocations.clone();
            let mut iter = c.iter();
            iter.next();
            let mut alloc_clone = allocations.clone();
            let first_entry = alloc_clone.first_entry().unwrap();
            let res = iter.try_fold(first_entry.get(), |i, j_| {
                // let i = &w[0];
                // let j = &w[1];
                let j = j_.1;
                info!("allocate: looking for space between {:?} and {:?}", i, j);
                let start = i.phys_addr.0 + len;
                let candidate = start
                    + (start as *const c_void).align_offset(if align == 0 {
                        0x4000
                    } else {
                        align
                    });

                if candidate < j.phys_addr.0 && (candidate + len) < j.phys_addr.0 {
                    let phys_addr = PhysAddr(candidate);
                    let alloc = DmemAllocation { phys_addr, len };

                    allocations.insert(phys_addr, alloc);
                    // allocations.sort_by(|a, b| a.phys_addr.partial_cmp(&b.phys_addr).unwrap());

                    Err(phys_addr)
                } else {
                    Ok(j)
                }
            });

            if let Err(phys_addr) = res {
                return Ok(phys_addr);
            }

            // no space in between existing mappings, check after all
            let entry = allocations.last_entry().unwrap();
            let last_allocation = entry.get();

            let mut candidate = last_allocation.phys_addr.0
                + (last_allocation.phys_addr.0 as *const c_void).align_offset(if align == 0 {
                    0x4000
                } else {
                    align
                });

            if candidate + len < last_allocation.phys_addr.0 {
                let phys_addr = PhysAddr(candidate);
                let alloc = DmemAllocation { phys_addr, len };

                allocations.insert(phys_addr, alloc);

                return Ok(phys_addr);
            }

            Err(SysErr::Raw(EAGAIN))
        }
    }

    pub fn mmap_dmem(
        &self,
        addr: usize,
        len: usize,
        mem_type: MemoryType,
        prot: Protections,
        phys_addr: PhysAddr,
    ) -> Result<usize, SysErr> {
        info!("Dmem::mmap()");

        /// make sure the area is allocated
        for i in self.dmem_allocations.read().unwrap().values().into_iter() {
            if phys_addr >= i.phys_addr && (phys_addr.0 + len) <= (i.phys_addr.0 + i.len) {
                let addr = self.find_free_area(addr, len)?;

                let virt_addr = self
                    .dmem
                    .native_dmem
                    .map(addr, len, prot, phys_addr)
                    .ok_or(SysErr::Raw(ENOMEM))?;

                let mapping = Mapping {
                    addr: virt_addr as _,
                    len,
                    prot,
                    name: "".to_string(),
                    storage: Arc::new(*i),
                    locked: false,
                    mem_type: Some(mem_type),
                };

                info!("Dmem::mmap(): {:?}", mapping);

                self.mappings.write().unwrap().insert(virt_addr, mapping);

                return Ok(virt_addr);
            }
        }
        error!("mmap_dmem failed, {:#x} is not allocated?", phys_addr.0);

        Err(SysErr::Raw(EAGAIN))
    }

    pub fn get_avail_dmem(
        &self,
        dmem_container: DmemContainer,
        search_start: usize,
        search_end: usize,
        align: usize,
    ) -> Result<(PhysAddr, usize), SysErr> {
        let mut largest_area = (PhysAddr(0), 0);

        let align = max(align, 0x4000);

        let mut allocations = self.dmem_allocations.write().unwrap();

        if allocations.is_empty() {
            return Ok((PhysAddr(0), self.dmem.size));
        }

        let c = allocations.clone();
        let mut iter = c.iter();
        iter.next();
        let mut alloc_clone = allocations.clone();
        let first_entry = alloc_clone.first_entry().unwrap();
        let res = iter.try_fold(first_entry.get(), |i, j_| {
            // let i = &w[0];
            // let j = &w[1];
            let j = j_.1;

            info!("looking for space between {:?} and {:?}", i, j);

            if (i.phys_addr.0 + i.len) < search_start {
                return Ok(j);
            }
            if (i.phys_addr.0 + i.len) > search_end {
                return Err(());
            }

            let candidate = (i.phys_addr.0 + i.len)
                + ((i.phys_addr.0 + i.len) as *const c_void).align_offset(align);

            let size = j.phys_addr.0 - candidate;
            info!("candidate {:#x}, size {:#x}", candidate, size);

            if size > largest_area.1 {
                largest_area = (PhysAddr(candidate), size);
            }
            Ok(j)
        });

        let end_area = {
            allocations.last_entry().and_then(|e| {
                let i = e.get();
                let candidate = (i.phys_addr.0 + i.len)
                    + ((i.phys_addr.0 + i.len) as *const c_void).align_offset(align);

                info!("candidate at the end {:#x}", candidate);

                if search_end > candidate {
                    Some((PhysAddr(candidate), search_end - candidate))
                } else {
                    None
                }
            })
        };

        Ok(end_area
            .and_then(|end| {
                if end.1 > largest_area.1 {
                    Some(end)
                } else {
                    Some(largest_area)
                }
            })
            .unwrap_or(largest_area))
    }

    fn round_page(addr: usize) -> usize {
        (addr + 0x3fff) & !(0x3fff)
    }

    pub fn mmap<N: Into<String>>(
        &self,
        addr: usize,
        len: usize,
        prot: Protections,
        name: N,
        mut flags: MappingFlags,
        fd: i32,
        offset: usize,
    ) -> Result<VPages<'_>, MmapError> {
        let name = name.into();
        info!(
            "mmap({:#x}, {:#x}, {}, {}, {}, {}, {:#x})",
            addr,
            len,
            prot,
            name.clone(),
            flags,
            fd,
            offset
        );

        // Remove unknown protections.
        let prot = prot.intersection(Protections::all());

        // TODO: Check why the PS4 check RBP register.
        if flags.contains(MappingFlags::MAP_SANITIZER) {
            todo!("mmap with flags & 0x200000");
        }

        if len == 0 {
            todo!("mmap with len = 0");
        }

        if flags.intersects(MappingFlags::MAP_VOID | MappingFlags::MAP_ANON) {
            if offset != 0 {
                return Err(MmapError::NonZeroOffset);
            } else if fd != -1 {
                return Err(MmapError::NonNegativeFd);
            }
        } else if flags.contains(MappingFlags::MAP_STACK) {
            todo!("mmap with flags & 0x400");
        }

        flags.remove(MappingFlags::UNK2);
        flags.remove(MappingFlags::UNK3);

        // TODO: Refactor this for readability.
        let td = VThread::current();

        if ((offset & 0x3fff) ^ 0xffffffffffffbfff) < len {
            return Err(MmapError::InvalidOffset);
        }

        if flags.contains(MappingFlags::MAP_FIXED) {
            let pageoff = offset & 0x3fff;
            let adjusted_addr = addr - pageoff;
            let adjusted_len = len + pageoff;
            let rounded_len = Self::round_page(adjusted_len);

            if (adjusted_addr & 0x3fff) != 0 {
                return Err(MmapError::InvalidOffset);
            }
            // TODO: check if addr is within min and max mappings for this proc
            if adjusted_addr + rounded_len < adjusted_addr {
                return Err(MmapError::InvalidOffset);
            }
        } else if addr == 0 {
            if td
                .as_ref()
                .is_some_and(|t| (t.proc().app_info().unk1() & 2) != 0)
            {
                todo!("mmap with addr = 0 and appinfo.unk1 & 2 != 0");
            }
        } else if (addr & 0xfffffffdffffffff) == 0 {
            // TODO: Check what the is value at offset 0x140 on vm_map.
        } else if addr == 0x880000000 {
            todo!("mmap with addr = 0x880000000");
        }

        let mut file_handle = None;
        if flags.contains(MappingFlags::MAP_VOID) {
            flags |= MappingFlags::MAP_ANON;

            if let Some(ref td) = td {
                td.set_fpop(None);
            }
        } else if !flags.contains(MappingFlags::MAP_ANON) {
            if let Some(ref td) = td {
                let file = td
                    .proc()
                    .files()
                    .get(fd)
                    .map_err(|err| MmapError::InvalidFd(err))?;
                td.set_fpop(Some(file.clone()));
                file_handle = Some(file);
            }
        }

        if flags.contains(MappingFlags::MAP_SANITIZER) {
            todo!("mmap with flags & 0x200000 != 0");
        }

        if td.is_some_and(|t| (t.proc().app_info().unk1() & 2) != 0) {
            todo!("mmap with addr = 0 and appinfo.unk1 & 2 != 0");
        }

        // Round len up to virtual page boundary.
        let len = match len % Self::VIRTUAL_PAGE_SIZE {
            0 => len,
            r => len + (Self::VIRTUAL_PAGE_SIZE - r),
        };

        self.map(addr, len, flags, prot, name, file_handle, offset as i64)
    }

    fn mlock(&self, addr: usize, len: usize) -> Result<(), SysErr> {
        self.update(
            addr as _,
            len,
            |i| !i.locked,
            |i| {
                i.storage.lock(i.addr, i.len).unwrap();
                i.locked = true;
            },
        )
        .map_err(|_| SysErr::Raw(EINVAL))
    }

    pub fn munmap(&self, addr: *mut u8, len: usize) -> Result<(), MunmapError> {
        // Check arguments.
        let first = addr as usize;

        if first % Self::VIRTUAL_PAGE_SIZE != 0 {
            return Err(MunmapError::UnalignedAddr);
        } else if len == 0 {
            return Err(MunmapError::ZeroLen);
        }

        // Do unmapping every pages in the range.
        let end = Self::align_virtual_page(unsafe { addr.add(len) });
        let mut adds: Vec<Mapping> = Vec::new();
        let mut removes: Vec<usize> = Vec::new();
        let mut allocs = self.mappings.write().unwrap();

        // FIXME: In theory it is possible to make this more efficient by remove allocation
        // info in-place. Unfortunately Rust does not provides API to achieve what we want.
        for (_, info) in StartFromMut::new(&mut allocs, first) {
            // Check if the current allocation is not in the range.
            if end <= info.addr {
                break;
            }

            // Check if we need to split the first allocation.
            if addr > info.addr {
                let remain = (info.end() as usize) - (addr as usize);

                // Check if we need to split in the middle.
                let decommit = if end < info.end() {
                    adds.push(Mapping {
                        addr: end,
                        len: (info.end() as usize) - (end as usize),
                        prot: info.prot,
                        name: info.name.clone(),
                        storage: info.storage.clone(),
                        locked: false,
                        mem_type: None,
                    });

                    (end as usize) - (addr as usize)
                } else {
                    remain
                };

                // Decommit the memory.
                if let Err(e) = info.storage.decommit(addr, decommit) {
                    panic!("Failed to decommit memory {addr:p}:{decommit}: {e}.");
                }

                info.len -= remain;
            } else if end < info.end() {
                // The current allocation is the last one in the region. What we do here is decommit
                // the head and keep the tail.
                let decommit = (end as usize) - (info.addr as usize);

                if let Err(e) = info.storage.decommit(info.addr, decommit) {
                    panic!(
                        "Failed to decommit memory {:p}:{}: {}.",
                        info.addr, decommit, e
                    );
                }

                // Split the region.
                removes.push(info.addr as usize);

                adds.push(Mapping {
                    addr: end,
                    len: info.len - decommit,
                    prot: info.prot,
                    name: info.name.clone(),
                    storage: info.storage.clone(),
                    locked: false,
                    mem_type: None,
                });
            } else {
                // Unmap the whole allocation.
                if let Err(e) = info.storage.decommit(info.addr, info.len) {
                    panic!(
                        "Failed to decommit memory {:p}:{}: {}.",
                        info.addr, info.len, e
                    );
                }

                removes.push(info.addr as usize);
            }
        }

        // Update allocation set.
        for alloc in adds {
            let addr = alloc.addr;

            if allocs.insert(addr as usize, alloc).is_some() {
                panic!("Address {addr:p} is already allocated.");
            }
        }

        for addr in removes {
            allocs.remove(&addr);
        }

        Ok(())
    }

    pub fn mprotect(
        &self,
        addr: *mut u8,
        len: usize,
        prot: Protections,
    ) -> Result<(), MemoryUpdateError> {
        self.update(
            addr,
            len,
            |i| i.prot != prot,
            |i| {
                i.storage.protect(i.addr, i.len, prot).unwrap();
                i.prot = prot;
            },
        )
    }

    /// See `vm_map_set_name` on the PS4 for a reference.
    pub fn mname(
        &self,
        addr: *mut u8,
        len: usize,
        name: impl AsRef<str>,
    ) -> Result<(), MemoryUpdateError> {
        let name = name.as_ref();
        let sname = CString::new(name);

        self.update(
            addr,
            len,
            |i| i.name != name,
            |i| {
                if let Ok(name) = &sname {
                    let _ = i.set_name(i.addr, i.len, name);
                }

                i.name = name.to_owned();
            },
        )
    }

    fn find_free_area(&self, addr: usize, len: usize) -> Result<usize, MmapError> {
        let mappings = self.mappings.read().unwrap();

        let addr = if addr == 0 { 0x400000 } else { addr };

        if mappings.is_empty() {
            return Ok(addr);
        }

        let mut previous_end = 0x400000; // try minimum mapping
        for i in mappings.range(addr..).into_iter() {
            // info!("find_free_area: trying {:?}", i);
            // if addr > *i.0 || addr < previous_end {
            //     previous_end = (i.1.end() as usize + 0x3fff) & 0xffffffffffffc000;
            //     continue;
            // }

            // assert!(addr >= previous_end, "{:#x}, {:#x}", addr, previous_end);

            if i.0 - previous_end > len && previous_end >= addr {
                // info!(
                //     "found free area at {:#x} starting from {:#x}",
                //     previous_end, addr
                // );
                return Ok(previous_end);
            }

            previous_end = (i.1.end() as usize + 0x3fff) & 0xffffffffffffc000;
        }

        error!(
            "couldn't find area from {:#x} of {:#x} bytes (end of allocated area {:#x})",
            addr, len, previous_end
        );
        Ok(max(addr, previous_end))
    }

    /// See `vm_mmap` on the PS4 for a reference.
    fn map(
        &self,
        addr: usize,
        len: usize,
        mut flags: MappingFlags,
        prot: Protections,
        name: String,
        file_handle: Option<Arc<VFile>>,
        file_offset: i64,
    ) -> Result<VPages<'_>, MmapError> {
        // TODO: Check what is PS4 doing here.
        use std::collections::btree_map::Entry;

        // Do allocation.
        let addr = (addr + 0x3fff) & 0xffffffffffffc000;
        let size = (len + 0x3fff) & 0xffffffffffffc000;

        let addr = if flags.intersects(MappingFlags::MAP_FIXED) {
            addr
        } else {
            self.find_free_area(addr, len)?
        };
        // info!("found addr {:#x}", addr);
        let alloc = match self.alloc(addr, len, prot, name) {
            Ok(v) => v,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::OutOfMemory {
                    return Err(MmapError::NoMem(len));
                } else {
                    // We should not hit other error except for out of memory.
                    panic!("Failed to allocate {len} bytes: {e}.");
                }
            }
        };

        if let Some(ref vfile) = file_handle {
            match &vfile.ty {
                VFileType::Blockpool(bp) => {
                    if file_offset != 0 {
                        return Err(MmapError::InvalidOffset);
                    }

                    if flags.bits() & 0x1f000000 == 0 {
                        flags = flags & MappingFlags::from_bits_retain(0xe0ffffff);
                        flags |= MappingFlags::from_bits_retain(0x15000000)
                    } else if flags.bits() & 0x1f000000 < 0x15000000 {
                        return Err(MmapError::InvalidFlags(1));
                    }

                    if flags.bits() & 3 != 1 || prot.bits() & 0x33 != 0x33 {
                        info!("flags {} vfile {:?} prot {}", flags, vfile.flags(), prot);
                        return Err(MmapError::InvalidFlags(2));
                    }

                    if ((flags.bits() & 0x10 != 0)
                        && (addr & 0x1fffff != 0
                            || (addr < 0xff0000000 && (0x7efffffff < addr + size))))
                        || (len + 0x3fff) & 0xffffffffffe00000 != size
                    {
                        return Err(MmapError::InvalidFlags(3));
                    }

                    // let area = self.pager_allocate(vfile, size, Protections::RW, flags, 0);

                    // todo!()
                }
                VFileType::Device(cdev) => {
                    if cdev.name() == "gc" {
                        // nothing for now
                    } else if cdev.name() == "dmem1" {
                        // nothing
                    } else {
                        todo!("{}", cdev.name())
                    }
                }
                _ => {
                    error!("unhandled {:?}", &vfile.ty);
                    todo!()
                }
            }
        }

        // Store allocation info.
        let mut mappings = self.mappings.write().unwrap();
        let mapping = match mappings.entry(alloc.addr as usize) {
            Entry::Occupied(e) => {
                panic!("Address {:p} is already allocated. {:?}", e.key(), e)
            }
            Entry::Vacant(e) => e.insert(alloc),
        };

        Ok(VPages::new(self, mapping.addr, mapping.len))
    }

    fn update<F, U>(
        &self,
        addr: *mut u8,
        len: usize,
        mut filter: F,
        mut update: U,
    ) -> Result<(), MemoryUpdateError>
    where
        F: FnMut(&Mapping) -> bool,
        U: FnMut(&mut Mapping),
    {
        // Check arguments.
        let first = addr as usize;

        if first % Self::VIRTUAL_PAGE_SIZE != 0 {
            return Err(MemoryUpdateError::UnalignedAddr);
        } else if len == 0 {
            return Err(MemoryUpdateError::ZeroLen);
        }

        // Get allocations within the range.
        let mut valid_addr = false;
        let end = Self::align_virtual_page(unsafe { addr.add(len) });
        let mut prev: *mut u8 = null_mut();
        let mut targets: Vec<&mut Mapping> = Vec::new();
        let mut mappings = self.mappings.write().unwrap();

        for (_, info) in StartFromMut::new(&mut mappings, first) {
            valid_addr = true;

            // Stop if the allocation is out of range.
            if end <= info.addr {
                break;
            }

            // TODO: Check if PS4 requires contiguous allocations.
            if !prev.is_null() && info.addr != prev {
                return Err(MemoryUpdateError::UnmappedAddr(prev as _));
            }

            prev = info.end();

            if filter(info) {
                targets.push(info);
            }
        }

        if !valid_addr {
            return Err(MemoryUpdateError::InvalidAddr);
        }

        // Update allocations within the range.
        let mut adds: Vec<Mapping> = Vec::new();

        for info in targets {
            let storage = &info.storage;

            // Check if we need to split the first allocation.
            if addr > info.addr {
                // Get how many bytes to split.
                let remain = (info.end() as usize) - (addr as usize);
                let len = if end < info.end() {
                    (end as usize) - (addr as usize)
                } else {
                    remain
                };

                // Split the first allocation.
                let mut alloc = Mapping {
                    addr,
                    len,
                    prot: info.prot,
                    name: info.name.clone(),
                    storage: storage.clone(),
                    locked: false,
                    mem_type: None,
                };

                update(&mut alloc);
                adds.push(alloc);

                // Check if the splitting was in the middle.
                if len != remain {
                    adds.push(Mapping {
                        addr: end,
                        len: (info.end() as usize) - (end as usize),
                        prot: info.prot,
                        name: info.name.clone(),
                        storage: storage.clone(),
                        locked: false,
                        mem_type: None,
                    });
                }

                info.len -= remain;
            } else if end < info.end() {
                // The current allocation is the last one in the range. What we do here is we split
                // the allocation and update the head.
                let tail = (info.end() as usize) - (end as usize);

                info.len -= tail;
                adds.push(Mapping {
                    addr: end,
                    len: tail,
                    prot: info.prot,
                    name: info.name.clone(),
                    storage: storage.clone(),
                    locked: false,
                    mem_type: None,
                });

                update(info);
            } else {
                // Update the whole allocation.
                update(info);
            }
        }

        // Add new allocation to the set.
        for alloc in adds {
            let addr = alloc.addr;
            assert!(mappings.insert(addr as usize, alloc).is_none());
        }

        Ok(())
    }

    fn alloc(
        &self,
        addr: usize,
        len: usize,
        prot: Protections,
        name: String,
    ) -> Result<Mapping, std::io::Error> {
        use self::storage::Memory;

        // Determine how to allocate.
        let (addr, len, storage) = if self.allocation_granularity < Self::VIRTUAL_PAGE_SIZE {
            // If allocation granularity is smaller than the virtual page that mean the result of
            // mmap may not aligned correctly. In this case we need to do 2 allocations. The first
            // allocation will be large enough for a second allocation with fixed address.
            // The whole idea is coming from: https://stackoverflow.com/a/31411825/1829232
            let len = len + (Self::VIRTUAL_PAGE_SIZE - self.allocation_granularity);
            let storage = Memory::new(addr, len)?;

            // Do the second allocation.
            let addr = Self::align_virtual_page(storage.ptr());
            let len = len - ((addr as usize) - (storage.ptr() as usize));

            (addr, len, storage)
        } else {
            // If allocation granularity is equal or larger than the virtual page that mean the
            // result of mmap will always aligned correctly.
            let storage = Memory::new(addr, len)?;
            let addr = storage.ptr();

            (addr, len, storage)
        };

        storage.commit(addr, len, prot)?;

        // Set storage name if supported.

        let mapping = Mapping {
            addr,
            len,
            prot,
            name: name.clone(),
            storage: Arc::new(storage),
            locked: false,
            mem_type: None,
        };

        if let Ok(name) = CString::new(name.as_str()) {
            let _ = mapping.set_name(addr, len, &name);
        }

        Ok(mapping)
    }

    fn pager_allocate(
        &self,
        handle: &Arc<VFile>,
        size: usize,
        prot: Protections,
        flags: MappingFlags,
        unk: usize,
    ) -> Option<usize> {
        info!(
            "pager_allocate({:?}, {:#x}, {}, {})",
            handle, size, prot, unk
        );

        let td = &VThread::current();

        match &handle.ty {
            VFileType::Blockpool(bp) => {
                let mut sdk_ver = None;
                if td.is_none()
                    || td
                        .as_ref()
                        .clone()
                        .and_then(|t| t.proc().sdk_ver())
                        .unwrap_or(0)
                        > 0x4ffffff
                {
                    if 0x7fffffffffff < size {
                        return None;
                    }

                    sdk_ver = td.as_ref().unwrap().proc().sdk_ver();
                } else if 0x3fff < (size >> 16) {
                    return None;
                }

                let mut proc = None;
                if sdk_ver.map(|v| v > 0x5ffffff).unwrap_or(false) {
                    proc = Some(td.as_ref().unwrap().proc());
                }

                let unk1 = (size >> 16) * 4 + 0xffff;
                let unk2 = unk1 >> 16;
                let memory: Vec<u8> = Vec::with_capacity((unk2 << 32) >> 30);

                let ret = self.blockpool_flush(handle, unk2 & 0xffffffff, 1, 1, &memory);

                if ret != 0 {
                    return None;
                }

                let unk3 = (unk2 << 32) >> 16;
                let mut ptr: Vec<u8> = Vec::with_capacity(unk3);

                if (unk1 >> 16) > 0 {
                    // todo!()
                }

                drop(memory);
                ptr.fill(0);

                let obj = self.object_allocate(handle, size >> 14);

                if let Some(_o) = obj {
                    let mut rv = 0;
                    if flags.intersects(MappingFlags::MAP_ANON) {
                        todo!()
                    } else {
                        rv = !(flags.intersects(MappingFlags::MAP_PREFAULT_READ)) as u8 * 8 + 8;
                    }

                    todo!()
                } else {
                    return None;
                }
            }
            _ => todo!(),
        }
    }

    fn object_allocate(&self, vfile: &Arc<VFile>, size: usize) -> Option<VmObject> {
        Some(VmObject {})
    }

    fn blockpool_flush(
        &self,
        vfile: &Arc<VFile>,
        blocks: usize,
        b: usize,
        c: usize,
        d: &Vec<u8>,
    ) -> i32 {
        0
    }

    fn sys_sbrk(self: &Arc<Self>, _: &VThread, _: &SysIn) -> Result<SysOut, SysErr> {
        // Return EOPNOTSUPP (Not yet implemented syscall)
        Err(SysErr::Raw(EOPNOTSUPP))
    }

    fn sys_sstk(self: &Arc<Self>, _: &VThread, _: &SysIn) -> Result<SysOut, SysErr> {
        // Return EOPNOTSUPP (Not yet implemented syscall)
        Err(SysErr::Raw(EOPNOTSUPP))
    }

    #[allow(unused_variables)]
    fn sys_munmap(self: &Arc<Self>, _: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let addr: usize = i.args[0].into();
        let len: usize = i.args[1].into();

        self.munmap_internal(addr, len)
    }

    #[allow(unused_variables)]
    fn munmap_internal(self: &Arc<Self>, addr: usize, len: usize) -> Result<SysOut, SysErr> {
        todo!()
    }

    fn sys_mprotect(self: &Arc<Self>, _: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let addr: usize = i.args[0].into();
        let len: usize = i.args[1].into();
        let prot: Protections = i.args[2].try_into().unwrap();

        info!("sys_mprotect({:#x}, {:#x}, {})", addr, len, prot);

        self.mprotect_internal(addr, len, prot)
    }

    fn mprotect_internal(
        self: &Arc<Self>,
        addr: usize,
        len: usize,
        prot: Protections,
    ) -> Result<SysOut, SysErr> {
        let addr = addr + 0x3fff & 0xffffffffffffc000;
        let end = addr & 0x3fff + 0x3fff + len & 0xffffffffffffc000;

        let prot = if prot.intersects(Protections::CPU_WRITE) {
            prot.union(Protections::CPU_READ)
        } else {
            prot
        };

        self.mprotect(addr as _, end - addr, prot)
            .map_err(|_| SysErr::Raw(EINVAL))?;

        Ok(SysOut::ZERO)
    }

    fn sys_mlock(self: &Arc<Self>, _: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let addr: usize = i.args[0].into();
        let len: usize = i.args[1].into();

        info!("sys_mlock({:#x}, {:#x})", addr, len);

        self.mlock_internal(addr, len)
    }

    fn mlock_internal(self: &Arc<Self>, addr: usize, len: usize) -> Result<SysOut, SysErr> {
        let end = addr + len + 0x3fff & 0xffffffffffffc000;

        if addr > end {
            return Err(SysErr::Raw(EINVAL));
        }

        self.mlock(addr, len)?;

        Ok(SysOut::ZERO)
    }

    fn sys_mmap(self: &Arc<Self>, _: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        // Get arguments.
        let addr: usize = i.args[0].into();
        let len: usize = i.args[1].into();
        let prot: Protections = i.args[2].try_into().unwrap();
        let flags: MappingFlags = i.args[3].try_into().unwrap();
        let fd: i32 = i.args[4].try_into().unwrap();
        let pos: usize = i.args[5].into();

        self.mmap_internal(addr, len, prot, flags, fd, pos)
    }

    fn mmap_internal(
        self: &Arc<Self>,
        addr: usize,
        len: usize,
        prot: Protections,
        flags: MappingFlags,
        fd: i32,
        pos: usize,
    ) -> Result<SysOut, SysErr> {
        // Check if the request is a guard for main stack.
        if addr == self.stack.guard() {
            assert_eq!(len, Self::VIRTUAL_PAGE_SIZE);
            assert!(prot.is_empty());
            assert!(flags.intersects(MappingFlags::MAP_ANON));
            assert_eq!(fd, -1);
            assert_eq!(pos, 0);

            info!("Guard page has been requested for main stack.");

            return Ok(self.stack.guard().into());
        }

        // TODO: Make a proper name.
        let pages = self.mmap(addr, len, prot, "", flags, fd, pos)?;

        if addr != 0 && pages.addr() != addr {
            warn!(
                "mmap({:#x}, {:#x}, {}, {}, {}, {}) was success with {:#x} instead of {:#x}.",
                addr,
                len,
                prot,
                flags,
                fd,
                pos,
                pages.addr(),
                addr
            );
        } else {
            info!(
                "{:#x}:{:p} is mapped as {} with {}.",
                pages.addr(),
                pages.end(),
                prot,
                flags,
            );
        }

        Ok(pages.into_raw().into())
    }

    fn sys_batch_map(self: &Arc<Self>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let dmem_fd: i32 = i.args[0].try_into().unwrap();
        let flags: MappingFlags = i.args[1].try_into().unwrap();
        let operations: *const BatchMapArg = i.args[2].into();
        let num_of_ops: i32 = i.args[3].try_into().unwrap();
        let num_of_processed_ops: *mut i32 = i.args[4].into();

        if flags.bits() & 0xe0bffb6f != 0 {
            return Err(SysErr::Raw(EINVAL));
        }

        let slice_size = num_of_ops.try_into().ok().ok_or(SysErr::Raw(EINVAL))?;
        let operations = unsafe { std::slice::from_raw_parts(operations, slice_size) };

        let mut processed = 0;

        let result = operations.iter().try_for_each(|arg| {
            match arg.op.try_into()? {
                BatchMapOp::MapDirect => {
                    if *td.proc().dmem_container() != DmemContainer::One
                    /* || td.proc().unk4 & 2 != 0 */
                    /* || td.proc().sdk_version < 0x2500000 */
                    || flags.intersects(MappingFlags::MAP_STACK)
                    {
                        todo!()
                    }

                    self.mmap_dmem_internal(
                        arg.addr,
                        arg.len,
                        arg.ty.try_into().unwrap(),
                        arg.prot.try_into().unwrap(),
                        flags,
                        arg.offset,
                        td,
                    )?;
                }
                BatchMapOp::MapFlexible => {
                    if arg.addr & 0x3fff != 0 || arg.len & 0x3fff != 0 || arg.prot & 0xc8 != 0 {
                        return Err(SysErr::Raw(EINVAL));
                    }

                    self.mmap_internal(
                        arg.addr,
                        arg.len,
                        arg.prot.try_into().unwrap(),
                        flags.intersection(MappingFlags::MAP_ANON),
                        -1,
                        0,
                    )?;
                }
                BatchMapOp::Protect => {
                    if arg.addr & 0x3fff != 0 || arg.len & 0x3fff != 0 || arg.prot & 0xc8 != 0 {
                        return Err(SysErr::Raw(EINVAL));
                    }

                    self.mprotect_internal(arg.addr, arg.len, arg.prot.try_into().unwrap())?;
                }
                BatchMapOp::TypeProtect => todo!(),
                BatchMapOp::Unmap => {
                    if arg.addr & 0x3fff != 0 || arg.len & 0x3fff != 0 {
                        return Err(SysErr::Raw(EINVAL));
                    }

                    self.munmap_internal(arg.addr, arg.len)?;
                }
                _ => todo!(),
            }

            processed = processed + 1;

            Ok(())
        });

        // TODO: invalidate TLB

        if !num_of_processed_ops.is_null() {
            unsafe {
                *num_of_processed_ops = processed;
            }
        }

        result.map(|_| SysOut::ZERO)
    }

    fn sys_mname(self: &Arc<Self>, _: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let addr: usize = i.args[0].into();
        let len: usize = i.args[1].into();
        let name = unsafe { i.args[2].to_str(32)?.unwrap() };

        info!(
            "Setting name for {:#x}:{:#x} to '{}'.",
            addr,
            addr + len,
            name
        );

        // PS4 does not check if vm_map_set_name is failed.
        let len = ((addr & 0x3fff) + len + 0x3fff) & 0xffffffffffffc000;
        let addr = (addr & 0xffffffffffffc000) as *mut u8;

        if let Err(e) = self.mname(addr, len, name) {
            warn!(e, "mname({addr:p}, {len:#x}, {name}) failed");
        }

        Ok(SysOut::ZERO)
    }

    #[allow(unused_variables)]
    fn sys_mmap_dmem(self: &Arc<Self>, td: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let start_addr: usize = i.args[0].into();
        let len: usize = i.args[1].into();
        let mem_type: MemoryType = i.args[2].try_into().unwrap();
        let prot: Protections = i.args[3].try_into().unwrap();
        let flags: MappingFlags = i.args[4].try_into().unwrap();
        let start_phys_addr: usize = i.args[5].into();

        self.mmap_dmem_internal(start_addr, len, mem_type, prot, flags, start_phys_addr, td)
    }

    #[allow(unused_variables)]
    fn mmap_dmem_internal(
        self: &Arc<Self>,
        mut start_addr: usize,
        len: usize,
        mem_type: MemoryType,
        prot: Protections,
        flags: MappingFlags,
        start_phys_addr: usize,
        td: &VThread,
    ) -> Result<SysOut, SysErr> {
        //todo: check creds
        warn!(
            "sys_mmap_dmem({:#x}, {:#x}, {:?}, {}, {}, {:#x})",
            start_addr, len, mem_type, prot, flags, start_phys_addr
        );

        if *td.proc().dmem_container() != DmemContainer::One {
            return Err(SysErr::Raw(EOPNOTSUPP));
        }

        if start_addr & 0x3fff != 0
            || start_phys_addr & 0x3fff != 0
            || (flags.bits() & 0xe09fff6f | prot.bits() & 0xffffffcc) != 0
            || len < 0x3fff
            || len & 0x3fff != 0
        {
            return Err(SysErr::Raw(EINVAL));
        }

        if flags.intersects(MappingFlags::MAP_SANITIZER) {
            todo!()
        }

        //todo: check rbp as on ps4

        let mut unk = 0;

        if !flags.intersects(MappingFlags::MAP_FIXED) {
            if start_addr == 0 {
                warn!("faking start_addr in sys_mmap_dmem");
                start_addr = 0x500000000;
            } else if start_addr <= 0xff0000000 {
                start_addr = 0xff0000000;
            }
            let unk1 = flags.bits() >> 24 & 0x1f;
            if unk1 > 0xd {
                unk = unk1;
            } else {
                unk = 1;
            }
        } else {
        }

        td.proc()
            .vm()
            .mmap_dmem(start_addr, len, mem_type, prot, PhysAddr(start_phys_addr))
            .map(|x| x.into())
    }

    fn align_virtual_page(ptr: *mut u8) -> *mut u8 {
        match (ptr as usize) % Self::VIRTUAL_PAGE_SIZE {
            0 => ptr,
            v => unsafe { ptr.add(Self::VIRTUAL_PAGE_SIZE - v) },
        }
    }

    #[cfg(unix)]
    fn get_memory_model() -> (usize, usize) {
        let v = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) };

        if v < 0 {
            let e = std::io::Error::last_os_error();
            panic!("Failed to get page size: {e}.");
        }

        (v as usize, v as usize)
    }

    #[cfg(windows)]
    fn get_memory_model() -> (usize, usize) {
        use std::mem::MaybeUninit;
        use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
        let mut i = MaybeUninit::<SYSTEM_INFO>::uninit();

        unsafe { GetSystemInfo(i.as_mut_ptr()) };

        let i = unsafe { i.assume_init() };

        (i.dwPageSize as usize, i.dwAllocationGranularity as usize)
    }
}

unsafe impl Sync for Vm {}

/// Contains information for an allocation of virtual pages.
#[derive(Debug)]
struct Mapping {
    addr: *mut u8,
    len: usize,
    prot: Protections,
    name: String,
    storage: Arc<dyn Storage>,
    locked: bool,
    mem_type: Option<MemoryType>,
}

impl Mapping {
    fn end(&self) -> *mut u8 {
        unsafe { self.addr.add(self.len) }
    }

    #[cfg(target_os = "linux")]
    fn set_name(&self, addr: *mut u8, len: usize, name: &CStr) -> Result<(), Error> {
        use libc::{prctl, PR_SET_VMA, PR_SET_VMA_ANON_NAME};

        if unsafe { prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, addr, len, name.as_ptr()) } < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn set_name(&self, _: *mut u8, _: usize, _: &CStr) -> Result<(), Error> {
        Ok(())
    }
}

unsafe impl Send for Mapping {}

bitflags! {
    /// Flags to tell what access is possible for the virtual page.
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub struct Protections: u32 {
        const CPU_READ = 0x00000001;
        const CPU_WRITE = 0x00000002;
        const CPU_EXEC = 0x00000004;
        const CPU_MASK = Self::CPU_READ.bits() | Self::CPU_WRITE.bits() | Self::CPU_EXEC.bits();
        const GPU_READ = 0x00000010;
        const GPU_WRITE = 0x00000020;
        const GPU_MASK = Self::GPU_READ.bits() | Self::GPU_WRITE.bits();
        const RW = Self::CPU_READ.bits() | Self::CPU_WRITE.bits() | Self::GPU_READ.bits() | Self::GPU_WRITE.bits();
    }
}

impl Protections {
    #[cfg(unix)]
    fn into_host(self) -> std::ffi::c_int {
        use libc::{PROT_EXEC, PROT_NONE, PROT_READ, PROT_WRITE};

        let mut host = PROT_NONE;

        if self.contains(Self::CPU_READ) {
            host |= PROT_READ;
        }

        if self.contains(Self::CPU_WRITE) {
            host |= PROT_WRITE;
        }

        if self.contains(Self::CPU_EXEC) {
            host |= PROT_EXEC;
        }

        host
    }

    #[cfg(windows)]
    fn into_host(self) -> windows_sys::Win32::System::Memory::PAGE_PROTECTION_FLAGS {
        use windows_sys::Win32::System::Memory::{
            PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_NOACCESS, PAGE_READONLY,
            PAGE_READWRITE,
        };

        // We cannot use "match" here because we need "|" to do bitwise OR.
        let cpu = self & Self::CPU_MASK;

        if cpu == Self::CPU_EXEC {
            PAGE_EXECUTE
        } else if cpu == Self::CPU_EXEC | Self::CPU_READ {
            PAGE_EXECUTE_READ
        } else if cpu == Self::CPU_EXEC | Self::CPU_READ | Self::CPU_WRITE {
            PAGE_EXECUTE_READWRITE
        } else if cpu == Self::CPU_READ {
            PAGE_READONLY
        } else if cpu == (Self::CPU_READ | Self::CPU_WRITE) || cpu == Self::CPU_WRITE {
            PAGE_READWRITE
        } else {
            PAGE_NOACCESS
        }
    }
}

impl TryFrom<SysArg> for Protections {
    type Error = TryFromIntError;

    fn try_from(v: SysArg) -> Result<Self, Self::Error> {
        Ok(Self::from_bits_retain(v.get().try_into()?))
    }
}

impl TryFrom<u8> for Protections {
    type Error = TryFromIntError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(Self::from_bits_retain(value as u32))
    }
}

impl Display for Protections {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

bitflags! {
    /// Flags for [`MemoryManager::mmap()`].
    #[repr(transparent)]
    #[derive(Clone, Copy)]
    pub struct MappingFlags: u32 {
        const MAP_SHARED = 0x00000001;
        const MAP_PRIVATE = 0x00000002;
        const MAP_FIXED = 0x00000010;
        const MAP_NO_OVERWRITE = 0x00000080;
        const MAP_VOID = 0x00000100;
        const MAP_STACK = 0x00000400;
        const MAP_DMEM_COMPAT = 0x00000400;
        const MAP_ANON = 0x00001000;
        const MAP_GUARD = 0x00002000;
        const UNK2 = 0x00010000;
        const MAP_NOCORE = 0x00020000;
        const MAP_PREFAULT_READ = 0x00040000;
        const UNK3 = 0x00100000;
        const MAP_SANITIZER = 0x00200000;
        const MAP_NO_COALESCE = 0x00400000;
        const MAP_WRITABLE_WB_GARLIC = 0x00800000;
    }
}

impl TryFrom<SysArg> for MappingFlags {
    type Error = TryFromIntError;

    fn try_from(v: SysArg) -> Result<Self, Self::Error> {
        Ok(Self::from_bits_retain(v.get().try_into()?))
    }
}

impl Display for MappingFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Represents an error when [`MemoryManager`] is failed to initialize.
#[derive(Debug, Error)]
pub enum MemoryManagerError {
    #[error("host system is using an unsupported page size")]
    UnsupportedPageSize,

    #[error("cannot allocate main stack")]
    StackAllocationFailed(#[source] MmapError),

    #[error("cannot setup guard page for main stack")]
    GuardStackFailed(#[source] MemoryUpdateError),
}

/// Represents an error when [`MemoryManager::mmap()`] is failed.
#[derive(Debug, Error, Errno)]
pub enum MmapError {
    #[error("MAP_ANON is specified with non-negative file descriptor")]
    #[errno(EINVAL)]
    NonNegativeFd,

    #[error("MAP_ANON is specified with non-zero offset")]
    #[errno(EINVAL)]
    NonZeroOffset,

    #[error("invalid offset")]
    #[errno(EINVAL)]
    InvalidOffset,

    #[error("invalid flags {0}")]
    #[errno(EINVAL)]
    InvalidFlags(i32),

    #[error("no memory available for {0} bytes")]
    #[errno(ENOMEM)]
    NoMem(usize),

    #[error("file descriptor is invalid")]
    InvalidFd(#[from] GetFileError),
}

/// Errors for [`MemoryManager::munmap()`].
#[derive(Debug, Error, Errno)]
pub enum MunmapError {
    #[error("addr is not aligned")]
    #[errno(EINVAL)]
    UnalignedAddr,

    #[error("len is zero")]
    #[errno(EINVAL)]
    ZeroLen,
}

/// Represents an error when update operations on the memory is failed.
#[derive(Debug, Error)]
pub enum MemoryUpdateError {
    #[error("addr is not aligned")]
    UnalignedAddr,

    #[error("len is zero")]
    ZeroLen,

    #[error("invalid addr")]
    InvalidAddr,

    #[error("address {0:#x} is not mapped")]
    UnmappedAddr(usize),
}

#[repr(C)]
struct BatchMapArg {
    addr: usize,
    offset: usize,
    len: usize,
    prot: u8,
    ty: u8,
    op: i32,
}

#[repr(i32)]
enum BatchMapOp {
    MapDirect = 0,
    Unmap = 1,
    Protect = 2,
    MapFlexible = 3,
    TypeProtect = 4,
}

impl TryFrom<i32> for BatchMapOp {
    type Error = SysErr;

    fn try_from(raw: i32) -> Result<Self, SysErr> {
        match raw {
            0 => Ok(BatchMapOp::MapDirect),
            1 => Ok(BatchMapOp::Unmap),
            2 => Ok(BatchMapOp::Protect),
            3 => Ok(BatchMapOp::MapFlexible),
            4 => Ok(BatchMapOp::TypeProtect),
            _ => Err(SysErr::Raw(EINVAL)),
        }
    }
}

#[repr(i32)]
#[derive(Debug)]
pub enum MemoryType {
    WbOnion = 0,
    WcGarlic = 3,
    WbGarlic = 10,
    Unk(u8),
    Any = -1,
}

impl TryFrom<SysArg> for MemoryType {
    type Error = SysErr;

    fn try_from(value: SysArg) -> Result<Self, Self::Error> {
        // warn!("{:#x}", value.get());
        if value.get() as u32 == !(0u32) {
            Ok(MemoryType::Any)
        } else {
            let val: u8 = value.try_into().unwrap();
            val.try_into()
        }
    }
}

impl TryFrom<u8> for MemoryType {
    type Error = SysErr;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MemoryType::WbOnion),
            3 => Ok(MemoryType::WcGarlic),
            10 => Ok(MemoryType::WbGarlic),
            i if i == !0 => Ok(MemoryType::Any),
            i if i < 10 => Ok(MemoryType::Unk(i)),
            _ => Err(SysErr::Raw(EINVAL)),
        }
    }
}

#[derive(Debug)]
pub struct DmemAllocator {
    native_dmem: DmemInterface,
    size: usize,
}

impl DmemAllocator {
    pub fn new() -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        let gg = GutexGroup::new();
        let interface = DmemInterface::new(0x13C_000_000)?;

        Ok(Arc::new(Self {
            native_dmem: interface,
            size: 0x13C_000_000,
        }))
    }

    // pub fn get_avail(
    //     self: &Arc<Self>,
    //     dmem_container: DmemContainer,
    //     search_start: usize,
    //     search_end: usize,
    //     align: usize,
    // ) -> Result<(PhysAddr, usize), SysErr> {
    //     todo!();

    //     let mut largest_area = (PhysAddr(0), 0);

    //     let align = max(align, 0x4000);

    // let allocations = self.allocations.write();

    // for w in allocations.windows(2) {
    //     let i = &w[0];
    //     let j = &w[1];

    //     info!("looking for space between {:?} and {:?}", i, j);

    //     if (i.phys_addr.0 + i.len) < search_start {
    //         continue;
    //     }
    //     if (i.phys_addr.0 + i.len) > search_end {
    //         break;
    //     }

    //     let candidate = (i.phys_addr.0 + i.len)
    //         + ((i.phys_addr.0 + i.len) as *const c_void).align_offset(align);

    //     let size = j.phys_addr.0 - candidate;
    //     info!("candidate {:#x}, size {:#x}", candidate, size);

    //     if size > largest_area.1 {
    //         largest_area = (PhysAddr(candidate), size);
    //     }
    // }

    // let end_area = {
    //     allocations.last().and_then(|i| {
    //         let candidate = (i.phys_addr.0 + i.len)
    //             + ((i.phys_addr.0 + i.len) as *const c_void).align_offset(align);

    //         info!("candidate at the end {:#x}", candidate);

    //         if search_end > candidate {
    //             Some((PhysAddr(candidate), search_end - candidate))
    //         } else {
    //             None
    //         }
    //     })
    // };

    // Ok(end_area
    //     .and_then(|end| {
    //         if end.1 > largest_area.1 {
    //             Some(end)
    //         } else {
    //             Some(largest_area)
    //         }
    //     })
    //     .unwrap_or(largest_area))
    // }
}
