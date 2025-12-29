use crate::calls::{
    ADIMessage, AllProvisionedAcctStorageDisposeMessage, CoreADIAccount,
    GetAllProvisionedAccountsMessage, GetIDMSRoutingMessage, InitializeMessage,
    IsMachineProvisionedMessage, ProvisioningEndMessage, ProvisioningEraseMessage,
    ProvisioningSessionDestroyMessage, ProvisioningStartMessage, RequestOTPMessage,
    SetIDMSRoutingMessage, StorageDisposeMessage, SynchronizeMessage, TearDownLibraryMessage,
    android, apple,
};
use crate::proxy::{
    ADIAccount, ADIBuffer, ADIPayload, ADIProvisioningSession, ADIProxy, ADIResult, EncryptionType,
};
use bincode::config;
use bincode::serde::{decode_from_slice, encode_to_vec};
use std::ffi::CStr;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::slice;

#[repr(C)]
#[derive(Debug)]
pub struct CoreADIParameters {
    pub payload: *mut u8,
    pub input_size: u32,
    pub output_size: u32,
    pub flags: u32,
}

pub trait CoreADIProxy {
    unsafe fn dispatch(&self, function_code: u32, parameters: *const CoreADIParameters) -> i32;
}

pub trait CoreADIProxyHelper: CoreADIProxy {
    fn dispatch_message<Message: ADIMessage>(
        &self,
        message: Message,
    ) -> ADIResult<Message::ReturnType>;
}

impl<T: CoreADIProxy + ?Sized> CoreADIProxyHelper for T {
    fn dispatch_message<Message: ADIMessage>(
        &self,
        message: Message,
    ) -> ADIResult<Message::ReturnType> {
        let payload = ADIPayload {
            encryption_type: EncryptionType::Clear,
            marker: 1,
            payload: message,
        };

        let config = config::standard()
            .with_fixed_int_encoding()
            .with_big_endian();

        let payload = encode_to_vec(&payload, config).expect("ADI message encoding failed??");
        let mut payload: Box<[u8]> = payload.into_boxed_slice();

        let return_type_length: usize = size_of::<Message::ReturnType>();
        let slice: *mut u8 = payload.as_mut_ptr();
        let mut parameters = CoreADIParameters {
            payload: slice,
            input_size: payload.len() as u32,
            output_size: return_type_length as u32, // HACK
            flags: 0,
        };

        let dispatch_status = unsafe {
            let params: *mut CoreADIParameters = &mut parameters;
            self.dispatch(Message::MAGIC, params)
        };

        if dispatch_status < 0 {
            Err(dispatch_status.into())
        } else {
            Ok(decode_from_slice(&payload[0..return_type_length], config)
                .expect("ADI message decoding failed??")
                .0)
        }
    }
}

impl<T: CoreADIProxyHelper + ?Sized> CoreADIADIProxy for T {
    fn initialize(&self) -> ADIResult<()> {
        let err = self.dispatch_message(InitializeMessage {})?;
        if err < 0 { Err(err.into()) } else { Ok(()) }
    }

    fn is_machine_provisioned(&self, ds_id: i64) -> ADIResult<bool> {
        let err = self.dispatch_message(IsMachineProvisionedMessage { ds_id })?;

        match err {
            0 => Ok(true),
            -45061 => Ok(false),
            err => Err(err.into()),
        }
    }

    fn get_all_provisioned_accounts(&self) -> ADIResult<ADIBuffer<'_, CoreADIAccount>> {
        let mut adi_accounts_ptr = MaybeUninit::uninit();
        let mut adi_accounts_len = MaybeUninit::uninit();
        let err = self.dispatch_message(GetAllProvisionedAccountsMessage {
            account_list_ptr: adi_accounts_ptr.as_mut_ptr(),
            account_list_len: adi_accounts_len.as_mut_ptr(),
        })?;

        if err < 0 {
            Err(err.into())
        } else {
            Ok(ADIBuffer(unsafe {
                slice::from_raw_parts(
                    adi_accounts_ptr.assume_init(),
                    adi_accounts_len.assume_init() as usize,
                )
            }))
        }
    }

    fn start_provisioning(
        &self,
        ds_id: i64,
        spim: &[u8],
    ) -> ADIResult<(&[u8], ADIProvisioningSession<'_>)> {
        let mut cpim_ptr = MaybeUninit::uninit();
        let mut cpim_len = MaybeUninit::uninit();
        let mut session = MaybeUninit::uninit();

        let err = self.dispatch_message(ProvisioningStartMessage {
            ds_id,
            spim_ptr: spim.as_ptr(),
            spim_len: spim.len() as u32,
            cpim_ptr: cpim_ptr.as_mut_ptr(),
            cpim_len: cpim_len.as_mut_ptr(),
            session: session.as_mut_ptr(),
        })?;

        if err < 0 {
            Err(err.into())
        } else {
            let cpim = unsafe {
                slice::from_raw_parts(cpim_ptr.assume_init(), cpim_len.assume_init() as usize)
            };
            let session = ADIProvisioningSession {
                val: unsafe { session.assume_init() },
                proxy: PhantomData,
            };
            Ok((cpim, session))
        }
    }

    fn end_provisioning(
        &self,
        session: ADIProvisioningSession,
        ptm: &[u8],
        tk: &[u8],
    ) -> ADIResult<()> {
        let err = self.dispatch_message(ProvisioningEndMessage {
            session: session.val,
            ptm_ptr: ptm.as_ptr(),
            ptm_length: ptm.len() as u32,
            tk_ptr: tk.as_ptr(),
            tk_length: tk.len() as u32,
        })?;
        std::mem::forget(session);

        if err < 0 { Err(err.into()) } else { Ok(()) }
    }

    fn destroy_provisioning_session(&self, session: ADIProvisioningSession) -> ADIResult<()> {
        let err = self.dispatch_message(ProvisioningSessionDestroyMessage {
            session: session.val,
        })?;
        std::mem::forget(session);

        if err < 0 { Err(err.into()) } else { Ok(()) }
    }

    fn set_idms_routing(&self, ds_id: i64, routing_info: u64) -> ADIResult<()> {
        let err = self.dispatch_message(SetIDMSRoutingMessage {
            ds_id,
            idms_routing: routing_info,
        })?;

        if err < 0 { Err(err.into()) } else { Ok(()) }
    }

    fn get_idms_routing(&self, ds_id: i64) -> ADIResult<u64> {
        let mut routing_info = MaybeUninit::uninit();
        let err = self.dispatch_message(GetIDMSRoutingMessage {
            ds_id,
            idms_routing: routing_info.as_mut_ptr(),
        })?;

        if err < 0 {
            Err(err.into())
        } else {
            Ok(unsafe { routing_info.assume_init() })
        }
    }

    fn synchronize(
        &self,
        ds_id: i64,
        sim: &[u8],
    ) -> ADIResult<(ADIBuffer<'_, u8>, ADIBuffer<'_, u8>)> {
        let mut mid_ptr = MaybeUninit::uninit();
        let mut mid_len = MaybeUninit::uninit();
        let mut srm_ptr = MaybeUninit::uninit();
        let mut srm_len = MaybeUninit::uninit();

        let err = self.dispatch_message(SynchronizeMessage {
            ds_id,
            sim_ptr: sim.as_ptr(),
            sim_len: sim.len() as u32,
            mid_ptr: mid_ptr.as_mut_ptr(),
            mid_len: mid_len.as_mut_ptr(),
            srm_ptr: srm_ptr.as_mut_ptr(),
            srm_len: srm_len.as_mut_ptr(),
        })?;

        if err < 0 {
            Err(err.into())
        } else {
            Ok((
                ADIBuffer(unsafe {
                    slice::from_raw_parts(mid_ptr.assume_init(), mid_len.assume_init() as usize)
                }),
                ADIBuffer(unsafe {
                    slice::from_raw_parts(srm_ptr.assume_init(), srm_len.assume_init() as usize)
                }),
            ))
        }
    }

    fn erase_provisioning(&self, ds_id: i64) -> ADIResult<()> {
        let err = self.dispatch_message(ProvisioningEraseMessage { ds_id })?;

        if err < 0 { Err(err.into()) } else { Ok(()) }
    }

    fn request_otp(&self, ds_id: i64) -> ADIResult<(ADIBuffer<'_, u8>, ADIBuffer<'_, u8>)> {
        let mut mid_ptr = MaybeUninit::uninit();
        let mut mid_len = MaybeUninit::uninit();
        let mut otp_ptr = MaybeUninit::uninit();
        let mut otp_len = MaybeUninit::uninit();

        let err = self.dispatch_message(RequestOTPMessage {
            ds_id,
            mid_ptr: mid_ptr.as_mut_ptr(),
            mid_len: mid_len.as_mut_ptr(),
            otp_ptr: otp_ptr.as_mut_ptr(),
            otp_len: otp_len.as_mut_ptr(),
        })?;

        if err < 0 {
            Err(err.into())
        } else {
            Ok((
                ADIBuffer(unsafe {
                    slice::from_raw_parts(mid_ptr.assume_init(), mid_len.assume_init() as usize)
                }),
                ADIBuffer(unsafe {
                    slice::from_raw_parts(otp_ptr.assume_init(), otp_len.assume_init() as usize)
                }),
            ))
        }
    }

    fn dispose(&self, buffer: ADIBuffer<'_, u8>) -> ADIResult<()> {
        let buf = buffer.0;
        std::mem::forget(buffer);
        let err = self.dispatch_message(StorageDisposeMessage { ptr: buf.as_ptr() })?;
        if err < 0 {
            let err = err.into();
            #[cfg(test)]
            {
                let ptr = buf.as_ptr();
                let len = buf.len();
                log::warn!("Leak of buf {ptr:p} of size {len}: {err:?}");
            }
            Err(err)
        } else {
            Ok(())
        }
    }

    fn dispose_account_storage(&self, buffer: ADIBuffer<'_, CoreADIAccount>) -> ADIResult<()> {
        let buf = buffer.0;
        std::mem::forget(buffer);
        let err = self.dispatch_message(AllProvisionedAcctStorageDisposeMessage {
            ptr: buf.as_ptr(),
            len: buf.len() as u32,
        })?;
        if err < 0 {
            let err = err.into();
            #[cfg(test)]
            {
                let ptr = buf.as_ptr();
                let len = buf.len();
                log::warn!("Leak of buf {ptr:p} of size {len}: {err:?}");
            }
            Err(err)
        } else {
            Ok(())
        }
    }

    fn finalize(&self) -> ADIResult<()> {
        let err = self.dispatch_message(TearDownLibraryMessage {})?;

        if err < 0 { Err(err.into()) } else { Ok(()) }
    }

    fn set_provisioning_path(&self, path: &CStr) -> ADIResult<()> {
        let err = self.dispatch_message(android::SetProvisioningPathMessage {
            provisioning_path: path.as_ptr(),
        })?;

        if err < 0 { Err(err.into()) } else { Ok(()) }
    }

    fn set_android_id(&self, id: &str) -> ADIResult<()> {
        assert_eq!(id.len(), 16, "The identifier must be 16 characters long.");
        let err = self.dispatch_message(android::SetAndroidIDMessage {
            android_id_ptr: id.as_ptr(),
            android_id_len: id.len() as u32,
        })?;

        if err < 0 { Err(err.into()) } else { Ok(()) }
    }

    fn generate_2fa_code(&self, ds_id: i64) -> ADIResult<u32> {
        let mut code = MaybeUninit::uninit();
        let err = self.dispatch_message(apple::Gen2FACodeMessage {
            ds_id,
            code: code.as_mut_ptr(),
        })?;

        if err < 0 {
            Err(err.into())
        } else {
            Ok(unsafe { code.assume_init() })
        }
    }
}

pub trait CoreADIADIProxy {
    fn initialize(&self) -> ADIResult<()>;
    fn is_machine_provisioned(&self, ds_id: i64) -> ADIResult<bool>;
    fn get_all_provisioned_accounts(&self) -> ADIResult<ADIBuffer<'_, CoreADIAccount>>;
    fn start_provisioning(
        &self,
        ds_id: i64,
        spim: &[u8],
    ) -> ADIResult<(&[u8], ADIProvisioningSession<'_>)>;
    fn end_provisioning(
        &self,
        session: ADIProvisioningSession,
        ptm: &[u8],
        tk: &[u8],
    ) -> ADIResult<()>;
    fn destroy_provisioning_session(&self, session: ADIProvisioningSession) -> ADIResult<()>;
    fn set_idms_routing(&self, ds_id: i64, routing_info: u64) -> ADIResult<()>;
    fn get_idms_routing(&self, ds_id: i64) -> ADIResult<u64>;
    fn synchronize(
        &self,
        ds_id: i64,
        sim: &[u8],
    ) -> ADIResult<(ADIBuffer<'_, u8>, ADIBuffer<'_, u8>)>;
    fn erase_provisioning(&self, ds_id: i64) -> ADIResult<()>;
    fn request_otp(&self, ds_id: i64) -> ADIResult<(ADIBuffer<'_, u8>, ADIBuffer<'_, u8>)>;

    fn dispose(&self, buffer: ADIBuffer<'_, u8>) -> ADIResult<()>;
    fn dispose_account_storage(&self, buffer: ADIBuffer<'_, CoreADIAccount>) -> ADIResult<()>;
    fn finalize(&self) -> ADIResult<()>;
    fn set_provisioning_path(&self, path: &CStr) -> ADIResult<()>;
    fn set_android_id(&self, id: &str) -> ADIResult<()>;
    fn generate_2fa_code(&self, ds_id: i64) -> ADIResult<u32>;
}

impl<T: CoreADIADIProxy> ADIProxy for T {
    fn is_machine_provisioned(&self, ds_id: i64) -> ADIResult<bool> {
        <Self as CoreADIADIProxy>::is_machine_provisioned(self, ds_id)
    }

    fn get_all_provisioned_accounts(&self) -> ADIResult<Vec<ADIAccount>> {
        let coreadi_accounts = <Self as CoreADIADIProxy>::get_all_provisioned_accounts(self)?;
        let accounts: Vec<ADIAccount> = unsafe {
            coreadi_accounts.0.iter().map(
                |&CoreADIAccount {
                     ds_id,
                     mid_len,
                     otp_len,
                     mid_ptr,
                     otp_ptr,
                 }| ADIAccount {
                    ds_id,
                    mid: slice::from_raw_parts(mid_ptr, mid_len as usize).to_vec(),
                    otp: slice::from_raw_parts(otp_ptr, otp_len as usize).to_vec(),
                },
            )
        }
        .collect();
        self.dispose_account_storage(coreadi_accounts)?;
        Ok(accounts)
    }

    fn start_provisioning(
        &self,
        ds_id: i64,
        spim: &[u8],
    ) -> ADIResult<(Vec<u8>, ADIProvisioningSession<'_>)> {
        let (cpim, session) = <Self as CoreADIADIProxy>::start_provisioning(self, ds_id, spim)?;
        Ok((cpim.to_vec(), session))
    }

    fn end_provisioning(
        &self,
        session: ADIProvisioningSession,
        ptm: &[u8],
        tk: &[u8],
    ) -> ADIResult<()> {
        <Self as CoreADIADIProxy>::end_provisioning(self, session, ptm, tk)
    }

    fn destroy_provisioning_session(&self, session: ADIProvisioningSession) -> ADIResult<()> {
        <Self as CoreADIADIProxy>::destroy_provisioning_session(self, session)
    }

    fn set_idms_routing(&self, ds_id: i64, routing_info: u64) -> ADIResult<()> {
        <Self as CoreADIADIProxy>::set_idms_routing(self, ds_id, routing_info)
    }

    fn get_idms_routing(&self, ds_id: i64) -> ADIResult<u64> {
        <Self as CoreADIADIProxy>::get_idms_routing(self, ds_id)
    }

    fn synchronize(&self, ds_id: i64, sim: &[u8]) -> ADIResult<(Vec<u8>, Vec<u8>)> {
        let (mid_buf, srm_buf) = <Self as CoreADIADIProxy>::synchronize(self, ds_id, sim)?;
        let (mid, srm) = (mid_buf.0.to_vec(), srm_buf.0.to_vec());
        self.dispose(mid_buf).and_then(|()| self.dispose(srm_buf))?;
        Ok((mid, srm))
    }

    fn erase_provisioning(&self, ds_id: i64) -> ADIResult<()> {
        <Self as CoreADIADIProxy>::erase_provisioning(self, ds_id)
    }

    fn request_otp(&self, ds_id: i64) -> ADIResult<(Vec<u8>, Vec<u8>)> {
        let (mid_buf, otp_buf) = <Self as CoreADIADIProxy>::request_otp(self, ds_id)?;
        let (mid, otp) = (mid_buf.0.to_vec(), otp_buf.0.to_vec());
        self.dispose(mid_buf).and_then(|()| self.dispose(otp_buf))?;
        Ok((mid.into(), otp.into()))
    }

    fn set_provisioning_path(&self, path: &CStr) -> ADIResult<()> {
        <Self as CoreADIADIProxy>::set_provisioning_path(self, path)
    }

    fn set_android_id(&self, id: &str) -> ADIResult<()> {
        <Self as CoreADIADIProxy>::set_android_id(self, id)
    }

    fn generate_2fa_code(&self, ds_id: i64) -> ADIResult<u32> {
        <Self as CoreADIADIProxy>::generate_2fa_code(self, ds_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr::slice_from_raw_parts;

    struct ADITestProxy;

    impl CoreADIProxy for ADITestProxy {
        unsafe fn dispatch(&self, function_code: u32, parameters: *const CoreADIParameters) -> i32 {
            unsafe {
                let parameters = &*parameters;
                println!(
                    "{:08X?}({:?}) - \"{:02X?}\"",
                    function_code,
                    parameters,
                    &*slice_from_raw_parts(parameters.payload, parameters.input_size as usize)
                );
            }
            0
        }
    }

    #[test]
    fn it_works() {
        let proxy = ADITestProxy {};
        proxy.initialize().unwrap();
        proxy.finalize().unwrap();
    }
}
