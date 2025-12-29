extern crate core;

use adi::calls::{
    ADIMessage, GetAllProvisionedAccountsMessage, GetIDMSRoutingMessage,
    IsMachineProvisionedMessage, ProvisioningEndMessage, ProvisioningEraseMessage,
    ProvisioningSessionDestroyMessage, ProvisioningStartMessage, RequestOTPMessage,
    SetIDMSRoutingMessage, SynchronizeMessage,
};
mod xpc;

use crate::xpc::{XpcConnection, XpcData, XpcDictionary};
use adi::calls::android::{SetAndroidIDMessage, SetProvisioningPathMessage};
use adi::calls::apple::Gen2FACodeMessage;
use adi::proxy::{
    ADIAccount, ADIError, ADIProvisioningSession, ADIProxy, ADIResult, EncryptionType,
};
use block::ConcreteBlock;
use std::ffi::CStr;
use std::marker::PhantomData;
use std::mem;
use std::ops::Deref;
use xpc_connection_sys::XPC_CONNECTION_MACH_SERVICE_PRIVILEGED;

pub struct ADIdProxy {
    connection: XpcConnection,
}

impl ADIdProxy {
    pub fn connect() -> Self {
        let connection = XpcConnection::create_mach_service(
            c"com.apple.adid",
            None,
            XPC_CONNECTION_MACH_SERVICE_PRIVILEGED as u64,
        );

        let block = ConcreteBlock::new(move |_event| {}).copy();
        connection.set_event_handler(block);
        connection.resume();

        // proxy.send(0x72096fe6, &[0, 0, 0, 1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE]).await;
        ADIdProxy { connection }
    }

    pub fn send(&self, payload: ADIPayload) -> ADIResult<XpcDictionary> {
        let data = payload.0;

        let payload = XpcData::create(&data);
        let message = XpcDictionary::create_empty();
        message.set_value(c"data", payload.0);

        let message = self
            .connection
            .send_message_with_reply_sync(&message)
            .map_err(|_| ADIError::MachMessageError)?;

        Ok(message)
    }
}

pub fn check_response(data: &[u8]) -> ADIResult<&[u8]> {
    let (adi_code, data) = i32::decode(data);
    if adi_code != 0 {
        Err(adi_code.into())
    } else {
        Ok(data)
    }
}

impl ADIProxy for ADIdProxy {
    fn is_machine_provisioned(&self, ds_id: i64) -> ADIResult<bool> {
        let response =
            self.send(ADIPayload::new(IsMachineProvisionedMessage::MAGIC).push(ds_id))?;
        match check_response(response.get_data(c"data")) {
            Ok(_) => Ok(true),
            Err(ADIError::NotProvisioned) => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn get_all_provisioned_accounts(&self) -> ADIResult<Vec<ADIAccount>> {
        let response = self.send(ADIPayload::new(GetAllProvisionedAccountsMessage::MAGIC))?;
        check_response(response.get_data(c"data"))
            .map(Vec::decode)
            .map(|(a, _)| a)
    }

    fn start_provisioning(
        &self,
        ds_id: i64,
        spim: &[u8],
    ) -> ADIResult<(Vec<u8>, ADIProvisioningSession<'_>)> {
        let response = self.send(
            ADIPayload::new(ProvisioningStartMessage::MAGIC)
                .push(ds_id)
                .push(spim),
        )?;
        check_response(response.get_data(c"data")).map(|data| {
            let (cpim, data) = <Vec<u8>>::decode(data);
            let (session, _) = u32::decode(data);
            (
                cpim,
                ADIProvisioningSession {
                    val: session,
                    proxy: PhantomData,
                },
            )
        })
    }

    fn end_provisioning(
        &self,
        session: ADIProvisioningSession,
        ptm: &[u8],
        tk: &[u8],
    ) -> ADIResult<()> {
        let response = self.send(
            ADIPayload::new(ProvisioningEndMessage::MAGIC)
                .push(session.val)
                .push(ptm)
                .push(tk),
        )?;
        check_response(response.get_data(c"data"))?;
        Ok(())
    }

    fn destroy_provisioning_session(&self, session: ADIProvisioningSession) -> ADIResult<()> {
        let response =
            self.send(ADIPayload::new(ProvisioningSessionDestroyMessage::MAGIC).push(session.val))?;
        check_response(response.get_data(c"data"))?;
        Ok(())
    }

    fn set_idms_routing(&self, ds_id: i64, routing_info: u64) -> ADIResult<()> {
        let response = self.send(
            ADIPayload::new(SetIDMSRoutingMessage::MAGIC)
                .push(ds_id)
                .push(routing_info),
        )?;
        check_response(response.get_data(c"data"))?;
        Ok(())
    }

    fn get_idms_routing(&self, ds_id: i64) -> ADIResult<u64> {
        let response = self.send(ADIPayload::new(GetIDMSRoutingMessage::MAGIC).push(ds_id))?;
        check_response(response.get_data(c"data")).map(|data| {
            let (routing_info, _) = u64::decode(data);
            routing_info
        })
    }

    fn synchronize(&self, ds_id: i64, sim: &[u8]) -> ADIResult<(Vec<u8>, Vec<u8>)> {
        let response = self.send(
            ADIPayload::new(SynchronizeMessage::MAGIC)
                .push(ds_id)
                .push(sim),
        )?;
        check_response(response.get_data(c"data")).map(|data| {
            let (mid, data) = <Vec<u8>>::decode(data);
            let (srm, _) = <Vec<u8>>::decode(data);
            (mid, srm)
        })
    }

    fn erase_provisioning(&self, ds_id: i64) -> ADIResult<()> {
        let response = self.send(ADIPayload::new(ProvisioningEraseMessage::MAGIC).push(ds_id))?;
        check_response(response.get_data(c"data"))?;
        Ok(())
    }

    fn request_otp(&self, ds_id: i64) -> ADIResult<(Vec<u8>, Vec<u8>)> {
        let response = self.send(ADIPayload::new(RequestOTPMessage::MAGIC).push(ds_id))?;
        check_response(response.get_data(c"data")).map(|data| {
            let (mid, data) = <Vec<u8>>::decode(data);
            let (otp, _) = <Vec<u8>>::decode(data);
            (mid, otp)
        })
    }

    fn set_provisioning_path(&self, path: &CStr) -> ADIResult<()> {
        let response = self.send(ADIPayload::new(SetProvisioningPathMessage::MAGIC).push(path))?;
        check_response(response.get_data(c"data"))?;
        Ok(())
    }

    fn set_android_id(&self, id: &str) -> ADIResult<()> {
        let response = self.send(ADIPayload::new(SetAndroidIDMessage::MAGIC).push(id))?;
        check_response(response.get_data(c"data"))?;
        Ok(())
    }

    fn generate_2fa_code(&self, ds_id: i64) -> ADIResult<u32> {
        let response = self.send(ADIPayload::new(Gen2FACodeMessage::MAGIC).push(ds_id))?;
        check_response(response.get_data(c"data")).map(|data| {
            let (code, _) = u32::decode(data);
            code
        })
    }
}

pub trait ADIdEncodable: Sized {
    fn encode(&self) -> impl AsRef<[u8]>;
}

pub trait ADIdDecodable: Sized {
    fn decode(data: &[u8]) -> (Self, &[u8]);
}

pub struct ADIPayload(Vec<u8>);

impl ADIPayload {
    pub fn new(magic: u32) -> Self {
        let mut vec = Vec::with_capacity(12);
        vec.extend_from_slice(&u32::from(EncryptionType::Clear).to_be_bytes());
        vec.extend_from_slice(&magic.to_be_bytes());
        vec.extend_from_slice(&[0, 0, 0, 1]);
        Self(vec)
    }

    pub fn push(mut self, encodable: impl ADIdEncodable) -> Self {
        self.0.extend_from_slice(encodable.encode().as_ref());
        self
    }
}

impl Deref for ADIPayload {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

macro_rules! impl_integer_traits {
    ($t:ty) => {
        impl ADIdEncodable for $t {
            fn encode(&self) -> impl AsRef<[u8]> {
                self.to_be_bytes()
            }
        }

        impl ADIdDecodable for $t {
            fn decode(data: &[u8]) -> (Self, &[u8]) {
                let integer_size = mem::size_of::<Self>();
                let (integer, data) = data.split_at(integer_size);
                (Self::from_be_bytes(integer.try_into().unwrap()), data)
            }
        }
    };
}

impl_integer_traits!(u8);
impl_integer_traits!(u16);
impl_integer_traits!(u32);
impl_integer_traits!(u64);

impl_integer_traits!(i8);
impl_integer_traits!(i16);
impl_integer_traits!(i32);
impl_integer_traits!(i64);

impl<T: ADIdEncodable> ADIdEncodable for &[T] {
    fn encode(&self) -> impl AsRef<[u8]> {
        let count = self.len();
        let mut data: Vec<u8> = (count as u32).to_be_bytes().into();
        if count >= 1 {
            let ([elem], self2) = self.split_at(1) else {
                unreachable!()
            };

            {
                let elem = elem.encode();
                let size = elem.as_ref().len();
                data.reserve(size * count);
                data.extend_from_slice(elem.as_ref());
            }

            for elem in self2 {
                data.extend_from_slice(elem.encode().as_ref());
            }
        }
        data
    }
}

impl<T: ADIdEncodable> ADIdEncodable for Vec<T> {
    fn encode(&self) -> impl AsRef<[u8]> {
        let count = self.len();
        let mut data: Vec<u8> = (count as u32).to_be_bytes().into();
        if count >= 1 {
            let ([elem], self2) = self.split_at(1) else {
                unreachable!()
            };

            {
                let elem = elem.encode();
                let size = elem.as_ref().len();
                data.reserve(size * count);
                data.extend_from_slice(elem.as_ref());
            }

            for elem in self2 {
                data.extend_from_slice(elem.encode().as_ref());
            }
        }
        data
    }
}

impl<T: ADIdDecodable> ADIdDecodable for Vec<T> {
    fn decode(data: &[u8]) -> (Self, &[u8]) {
        let (len, mut data) = data.split_at(mem::size_of::<u32>());
        let length = u32::from_be_bytes(len.try_into().unwrap());
        let mut vec = Vec::with_capacity(length as usize);
        for _ in 0..length {
            let (elem, remaining) = T::decode(data);
            data = remaining;
            vec.push(elem);
        }
        assert_eq!(vec.capacity(), length as usize);
        (vec, data)
    }
}

impl ADIdDecodable for ADIAccount {
    fn decode(data: &[u8]) -> (Self, &[u8]) {
        let (ds_id, data) = i64::decode(data);
        let (mid_len, data) = u32::decode(data);
        let (otp_len, data) = u32::decode(data);
        let (mid, data) = data.split_at(mid_len as usize);
        let (otp, data) = data.split_at(otp_len as usize);
        (
            ADIAccount {
                ds_id,
                mid: mid.to_vec(),
                otp: otp.to_vec(),
            },
            data,
        )
    }
}

impl ADIdEncodable for &CStr {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.to_bytes_with_nul()
    }
}

impl ADIdEncodable for &str {
    fn encode(&self) -> impl AsRef<[u8]> {
        let mut vec = self.len().to_be_bytes().to_vec();
        vec.extend_from_slice(self.as_bytes());
        vec
    }
}
