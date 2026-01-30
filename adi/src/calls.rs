use serde::de::DeserializeOwned;
use serde::{Serialize, Serializer};
use std::slice;

pub trait ADIMessage: Serialize {
    const MAGIC: u32;

    type ReturnType: DeserializeOwned; // = u32;
}

fn serialize_ptr<S: Serializer, T>(ptr: &*const T, serializer: S) -> Result<S::Ok, S::Error> {
    (*ptr as usize).serialize(serializer)
}

fn serialize_ptr_mut<S: Serializer, T>(ptr: &*mut T, serializer: S) -> Result<S::Ok, S::Error> {
    (*ptr as usize).serialize(serializer)
}

#[derive(Serialize, PartialEq)]
#[repr(C)]
pub struct CoreADIAccount {
    pub ds_id: i64,
    pub mid_len: u32,
    pub otp_len: u32,
    #[serde(serialize_with = "serialize_ptr")]
    pub mid_ptr: *const u8,
    #[serde(serialize_with = "serialize_ptr")]
    pub otp_ptr: *const u8,
}

impl std::fmt::Debug for CoreADIAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ADIAccount")
            .field("ds_id", &self.ds_id)
            .field("mid", &self.mid())
            .field("otp", &self.otp())
            .finish()
    }
}

impl CoreADIAccount {
    fn mid(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.mid_ptr, self.mid_len as usize) }
    }

    fn otp(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.otp_ptr, self.otp_len as usize) }
    }
}

#[derive(Serialize, PartialEq, Debug)]
#[repr(C)]
pub struct InitializeMessage {}

#[derive(Serialize, PartialEq, Debug)]
#[repr(C)]
pub struct IsMachineProvisionedMessage {
    pub ds_id: i64,
}

#[derive(Serialize, PartialEq, Debug)]
#[repr(C)]
pub struct GetAllProvisionedAccountsMessage {
    #[serde(serialize_with = "serialize_ptr_mut")]
    pub account_list_ptr: *mut *const CoreADIAccount,
    #[serde(serialize_with = "serialize_ptr_mut")]
    pub account_list_len: *mut u32,
}

#[derive(Serialize, PartialEq, Debug)]
#[repr(C)]
pub struct ProvisioningStartMessage {
    pub ds_id: i64,
    #[serde(serialize_with = "serialize_ptr")]
    pub spim_ptr: *const u8,
    pub spim_len: u32,
    #[serde(serialize_with = "serialize_ptr_mut")]
    pub cpim_ptr: *mut *const u8,
    #[serde(serialize_with = "serialize_ptr_mut")]
    pub cpim_len: *mut u32,
    #[serde(serialize_with = "serialize_ptr_mut")]
    pub session: *mut u32,
}

#[derive(Serialize, PartialEq, Debug)]
#[repr(C)]
pub struct ProvisioningEndMessage {
    pub session: u32,
    #[serde(serialize_with = "serialize_ptr")]
    pub ptm_ptr: *const u8,
    pub ptm_length: u32,
    #[serde(serialize_with = "serialize_ptr")]
    pub tk_ptr: *const u8,
    pub tk_length: u32,
}

#[derive(Serialize, PartialEq, Debug)]
#[repr(C)]
pub struct ProvisioningSessionDestroyMessage {
    pub session: u32,
}

#[derive(Serialize, PartialEq, Debug)]
#[repr(C)]
pub struct SetIDMSRoutingMessage {
    pub ds_id: i64,
    pub idms_routing: u64,
}

#[derive(Serialize, PartialEq, Debug)]
#[repr(C)]
pub struct GetIDMSRoutingMessage {
    pub ds_id: i64,
    #[serde(serialize_with = "serialize_ptr_mut")]
    pub idms_routing: *mut u64,
}

#[derive(Serialize, PartialEq, Debug)]
#[repr(C)]
pub struct SynchronizeMessage {
    pub ds_id: i64,
    #[serde(serialize_with = "serialize_ptr")]
    pub sim_ptr: *const u8,
    pub sim_len: u32,
    #[serde(serialize_with = "serialize_ptr_mut")]
    pub mid_ptr: *mut *const u8,
    #[serde(serialize_with = "serialize_ptr_mut")]
    pub mid_len: *mut u32,
    #[serde(serialize_with = "serialize_ptr_mut")]
    pub srm_ptr: *mut *const u8,
    #[serde(serialize_with = "serialize_ptr_mut")]
    pub srm_len: *mut u32,
}

#[derive(Serialize, PartialEq, Debug)]
#[repr(C)]
pub struct ProvisioningEraseMessage {
    pub ds_id: i64,
}

#[derive(Serialize, PartialEq, Debug)]
#[repr(C)]
pub struct RequestOTPMessage {
    pub ds_id: i64,
    #[serde(serialize_with = "serialize_ptr_mut")]
    pub mid_ptr: *mut *const u8,
    #[serde(serialize_with = "serialize_ptr_mut")]
    pub mid_len: *mut u32,
    #[serde(serialize_with = "serialize_ptr_mut")]
    pub otp_ptr: *mut *const u8,
    #[serde(serialize_with = "serialize_ptr_mut")]
    pub otp_len: *mut u32,
}

#[derive(Serialize, PartialEq, Debug)]
#[repr(C)]
pub struct StorageDisposeMessage {
    #[serde(serialize_with = "serialize_ptr")]
    pub ptr: *const u8,
}

#[derive(Serialize, PartialEq, Debug)]
#[repr(C)]
pub struct AllProvisionedAcctStorageDisposeMessage {
    #[serde(serialize_with = "serialize_ptr")]
    pub ptr: *const CoreADIAccount,
    pub len: u32,
}

#[derive(Serialize, PartialEq, Debug)]
#[repr(C)]
pub struct TearDownLibraryMessage {}

impl ADIMessage for InitializeMessage {
    const MAGIC: u32 = 0x12db31c5;
    type ReturnType = i32;
}

impl ADIMessage for IsMachineProvisionedMessage {
    const MAGIC: u32 = 0xb0eda7af;
    type ReturnType = i32;
}

impl ADIMessage for GetAllProvisionedAccountsMessage {
    const MAGIC: u32 = 0x72096fe6;
    type ReturnType = i32;
}

impl ADIMessage for ProvisioningStartMessage {
    const MAGIC: u32 = 0x716bd86c;
    type ReturnType = i32;
}

impl ADIMessage for ProvisioningEndMessage {
    const MAGIC: u32 = 0x0b2b3196;
    type ReturnType = i32;
}

impl ADIMessage for ProvisioningSessionDestroyMessage {
    const MAGIC: u32 = 0x55a637c0;
    type ReturnType = i32;
}

impl ADIMessage for SetIDMSRoutingMessage {
    const MAGIC: u32 = 0x632b8d6e;
    type ReturnType = i32;
}

impl ADIMessage for GetIDMSRoutingMessage {
    const MAGIC: u32 = 0x85fe63b0;
    type ReturnType = i32;
}

impl ADIMessage for SynchronizeMessage {
    const MAGIC: u32 = 0xa54951ec;
    type ReturnType = i32;
}

impl ADIMessage for ProvisioningEraseMessage {
    const MAGIC: u32 = 0x7715488c;
    type ReturnType = i32;
}

impl ADIMessage for RequestOTPMessage {
    const MAGIC: u32 = 0xcfe0b46a;
    type ReturnType = i32;
}

impl ADIMessage for StorageDisposeMessage {
    const MAGIC: u32 = 0x3e58e7f9;
    type ReturnType = i32;
}

impl ADIMessage for AllProvisionedAcctStorageDisposeMessage {
    const MAGIC: u32 = 0x9679d4b5;
    type ReturnType = i32;
}

impl ADIMessage for TearDownLibraryMessage {
    const MAGIC: u32 = 0x08c0fe9e;
    type ReturnType = i32;
}

/// Contains messages only implemented on Apple platforms
pub mod apple {
    use crate::calls::ADIMessage;
    use crate::calls::serialize_ptr_mut;
    use serde::Serialize;

    #[derive(Serialize, PartialEq, Debug)]
    #[repr(C)]
    pub struct Gen2FACodeMessage {
        pub ds_id: i64,
        #[serde(serialize_with = "serialize_ptr_mut")]
        pub code: *mut u32,
    }

    impl ADIMessage for Gen2FACodeMessage {
        const MAGIC: u32 = 0x385b2ce8;
        type ReturnType = i32;
    }
}

/// Contains messages only implemented on Android platforms
pub mod android {
    use crate::calls::ADIMessage;
    use crate::calls::serialize_ptr;
    use serde::Serialize;

    // Only on Android implementations
    #[derive(Serialize, PartialEq, Debug)]
    #[repr(C)]
    pub struct SetAndroidIDMessage {
        #[serde(serialize_with = "serialize_ptr")]
        pub android_id_ptr: *const u8,
        pub android_id_len: u32,
    }

    // Only on Android implementations
    #[derive(Serialize, PartialEq, Debug)]
    #[repr(C)]
    pub struct SetProvisioningPathMessage {
        #[serde(serialize_with = "serialize_ptr")]
        pub provisioning_path: *const std::ffi::c_char,
    }

    impl ADIMessage for SetAndroidIDMessage {
        const MAGIC: u32 = 0xc774d292;
        type ReturnType = i32;
    }

    impl ADIMessage for SetProvisioningPathMessage {
        const MAGIC: u32 = 0xb23c691e;
        type ReturnType = i32;
    }
}
