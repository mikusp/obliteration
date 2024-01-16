use bitflags::bitflags;
use std::{
    ffi::{c_int, c_long, CStr, CString},
    num::NonZeroI32,
    ops::Deref,
    os::raw::c_void,
    sync::Arc,
};

use crate::{
    errno::EINVAL,
    info,
    process::{VProc, VThread},
    syscalls::{SysErr, SysIn, SysOut, Syscalls},
    warn,
};

pub struct IpmiManager {
    proc: Arc<VProc>,
}

impl IpmiManager {
    pub fn new(syscalls: &mut Syscalls, proc: &Arc<VProc>) -> Arc<Self> {
        let ipmi = Arc::new(Self { proc: proc.clone() });
        syscalls.register(622, &ipmi, Self::ipmi_mgr_call);

        ipmi
    }

    fn ipmi_mgr_call(self: &Arc<Self>, _: &VThread, i: &SysIn) -> Result<SysOut, SysErr> {
        let ipmi_command: u32 = i.args[0].try_into().unwrap();
        let kid: u32 = i.args[1].try_into().unwrap();
        let out: usize = i.args[2].into();
        let ipmi_struct: usize = i.args[3].into();
        let probably_size: usize = i.args[4].into();
        let _unk2: u64 = i.args[5].into();

        warn!(
            "ipmi_mgr_call({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x})",
            ipmi_command, kid, out, ipmi_struct as usize, probably_size, _unk2
        );

        match ipmi_command {
            0 => self.ipmi_create_server(out),
            2 => {
                if ipmi_struct == 0 {
                    return Err(SysErr::Raw(EINVAL));
                }
                let args = unsafe { *(ipmi_struct as *const IpmiCreateClientArgs) };
                self.ipmi_create_client(out, args)
            }
            3 => self.ipmi_destroy_client(out),
            0x400 => {
                if ipmi_struct == 0 {
                    return Err(SysErr::Raw(EINVAL));
                }
                let args = unsafe { *(ipmi_struct as *const IpmiConnectArgs) };
                self.ipmi_client_connect(kid, out, args)
            }
            0x320 => {
                if ipmi_struct == 0 {
                    return Err(SysErr::Raw(EINVAL));
                }
                let args = unsafe { *(ipmi_struct as *const IpmiInvokeSyncMethodArgs) };
                self.ipmi_invoke_sync_method(kid, out, args)
            }
            0x310 => self.ipmi_client_disconnect(out),
            0x241 => self.ipmi_invoke_async_method(out),
            0x243 => warn!("stubbed ipmi 0x243"),
            0x491 => self.ipmi_poll_event_flag(out),
            0x252 => self.ipmi_try_get_msg(out, ipmi_struct),
            _ => todo!("ipmi_command {:#x}", ipmi_command),
        }

        Ok(0.into())
    }

    fn ipmi_create_server(self: &Arc<Self>, out: usize) -> () {
        unsafe {
            *(out as *mut c_int) = 0x3afebabe;
        }
    }

    fn ipmi_create_client(self: &Arc<Self>, out: usize, args: IpmiCreateClientArgs) -> () {
        unsafe {
            let config: &IpmiConfig = *args.name.cast();
            let name = CStr::from_ptr(args.name.cast()).to_string_lossy();
            info!(
                "ipmi_create_client config.name: {:#x} ({})",
                args.name as usize, name
            );
            info!(
                "ipmi_create_client({:#x}, {:#x}, {:#x}, {:#x})",
                out, args.client_impl_this, args.name as usize, args.param
            );

            let td = VThread::current().unwrap();
            let proc_name = td.proc().name().to_owned();
            info!("proc_name {:?}", proc_name);
            let thread_name = td.name().to_owned();
            info!("thread_name {:?}", thread_name);
            let tid = td.id();
            info!("tid {:?}", tid);
            let pid = td.proc().id();
            info!("pid {:?}", pid);
            let ipmi_object = IpmiObject::new(
                proc_name,
                thread_name,
                tid,
                pid,
                IpmiType::IPMI_CLIENT,
                -1i16 as u16,
                -1i16 as u16,
                -1i16 as u16,
                0,
                0,
                args.client_impl_this,
                name,
            );
            info!("ipmi_object {:?}", ipmi_object);

            let mut vec = self.proc.ipmi_map_mut();
            vec.push(ipmi_object);

            info!("clientKid = {}", vec.len() - 1);

            *(out as *mut c_int) = (vec.len() - 1) as i32;
        }
    }

    fn ipmi_destroy_client(self: &Arc<Self>, out: usize) -> () {
        unsafe {
            *(out as *mut c_int) = 0;
        }
    }

    fn ipmi_client_connect(self: &Arc<Self>, kid: u32, out: usize, args: IpmiConnectArgs) -> () {
        unsafe {
            *(out as *mut c_int) = 0;
            *(args.status as *mut c_int) = 0;
        }
        info!(
            "ipmi_client_connect({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x})",
            kid, out, args.user_data, args.user_data_len, args.status, args.arg3
        );
    }

    fn ipmi_client_disconnect(self: &Arc<Self>, out: usize) -> () {
        unsafe {
            *(out as *mut c_int) = 0;
        }
    }

    fn ipmi_invoke_sync_method(
        self: &Arc<Self>,
        kid: u32,
        out: usize,
        args: IpmiInvokeSyncMethodArgs,
    ) -> () {
        unsafe {
            *(out as *mut c_int) = 0;
            // let foo: &'static str = "foobar";
            // let ptr = foo.as_ptr() as usize;
            // info!("foobar: {:#x}", ptr);
            // // *(args.out_data as *mut usize) = ;
            // (args.out_data as *mut u8).copy_from("f".as_ptr(), 2);
            *(args.ret as *mut c_int) = 0;
        }
        info!(
            "ipmi_invoke_sync_method({:#x}, {:#x}, {:?})",
            kid, out, args
        );
    }

    fn ipmi_invoke_async_method(self: &Arc<Self>, out: usize) -> () {
        unsafe {
            *(out as *mut c_int) = 0;
        }
    }

    fn ipmi_poll_event_flag(self: &Arc<Self>, out: usize) -> () {
        unsafe {
            *(out as *mut c_int) = 0;
        }
    }

    fn ipmi_try_get_msg(self: &Arc<Self>, out: usize, ipmi_struct: usize) -> () {
        unsafe {
            let unk = *((ipmi_struct + 0) as *const c_int);
            let out_msg = *((ipmi_struct + 8) as *const c_long);
            let out_msg_len = *((ipmi_struct + 16) as *const c_long);
            let size = *((ipmi_struct + 24) as *const c_long);
            info!(
                "ipmi_try_get_msg: {:#x}, {:#x}, {:#x}, {:#x}",
                unk, out_msg, out_msg_len, size
            );
            *(out as *mut c_int) = 0x80020023u32 as i32;
            **((ipmi_struct + 8) as *const *mut c_long) = 1;
            **((ipmi_struct + 16) as *const *mut c_long) = size;

            let unk = *((ipmi_struct + 0) as *const c_int);
            let out_msg = *((ipmi_struct + 8) as *const c_long);
            let out_msg_len = *((ipmi_struct + 16) as *const c_long);
            let size = *((ipmi_struct + 24) as *const c_long);
            info!(
                "ipmi_try_get_msg out: {:#x}, {:#x}, {:#x}, {:#x}",
                unk, out_msg, out_msg_len, size
            );
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IpmiCreateClientArgs {
    client_impl_this: usize,
    name: *const u8,
    param: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IpmiConnectArgs {
    user_data: usize,
    user_data_len: usize,
    status: usize,
    arg3: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IpmiInvokeSyncMethodArgs {
    method: u32,
    in_data_len: u32,
    out_data_len: u32,
    unk: u32,
    in_data: usize,
    out_data: usize,
    ret: usize,
    flags: u32,
}

pub struct IpmiClient {
    client_impl: usize,
    name: String,
}

pub struct IpmiConfig {
    name: *const u8,
}

#[derive(Debug)]
pub struct IpmiObject {
    ty: IpmiType,
    unk1: u16,
    unk2: u16,
    unk3: u16,
    tid: NonZeroI32,
    pid: NonZeroI32,
    unk4: u32,
    unk5: u32,
    impl_this: usize,
    timestamp: u64,
    name: String,
    proc_name: Option<String>,
    thread_name: Option<String>,
}

impl IpmiObject {
    fn new(
        proc_name: Option<String>,
        thread_name: Option<String>,
        tid: NonZeroI32,
        pid: NonZeroI32,
        ty: IpmiType,
        unk1: u16,
        unk2: u16,
        unk3: u16,
        unk4: u32,
        unk5: u32,
        impl_this: usize,
        config: impl Into<String>,
    ) -> IpmiObject {
        let name: String = config.into();

        Self {
            ty,
            unk1,
            unk2,
            unk3,
            tid,
            pid,
            unk4,
            unk5,
            impl_this,
            timestamp: 0,
            name,
            proc_name,
            thread_name,
        }
    }
}

bitflags! {
    #[derive(Debug)]
    pub struct IpmiType: u16 {
        const IPMI_CLIENT = 0x2700;
    }
}
