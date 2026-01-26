use crate::calls::ADIMessage;
use serde::{Serialize, Serializer};
use std::ffi::CStr;
use std::fmt::{Debug, Display};
use std::marker::PhantomData;
use std::ops::Deref;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum EncryptionType {
    Clear,
    Encrypted,
}

impl From<EncryptionType> for u32 {
    fn from(value: EncryptionType) -> Self {
        match value {
            EncryptionType::Clear => 1,
            EncryptionType::Encrypted => 2,
        }
    }
}

impl Serialize for EncryptionType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encryption_type: u32 = (*self).into();
        encryption_type.serialize(serializer)
    }
}

#[repr(i32)]
#[derive(Debug)]
pub enum ADIError {
    // -45001 - Invalid parameters, have all the library fields been properly initialized?
    InvalidParameters = -45001,
    // -45002 - Invalid parameters.
    InvalidParameters2 = -45002,
    // -45003 - Trust Key is invalid
    InvalidTK = -45003,
    // -45004 - Unknown, but observed in fm23w5mn5o
    // <unknown = -45004>,
    // -45006 - Valid PTM/TK pair, but not matching the inner ADI state.
    PTMTKPairMismatch = -45006,
    // -45012 - Thread error
    ThreadingError = -45012,
    // -45016 - Mach call failed, can't contact adid.
    UnreachableADID = -45016,
    // -45017 - Mach call cannot be sent to adid, have you got the right entitlements?
    MachMessageError = -45017,
    // -45018 - Unknown encryption scheme given to CoreADI.
    InvalidEncryptionScheme = -45018,
    // -45019 - Unimplemented call
    InvalidFunctionCode = -45019,
    // -45020 - Cannot decrypt the input parameter block.
    InvalidParameterBody = -45020,
    // -45025 - Unknown session number.
    InvalidSession = -45025,
    // -45026 - Empty session number.
    EmptySession = -45026,
    // -45031 - Cryptographic block: Invalid input header.
    InvalidEncryptedBlockHeader = -45031,
    // -45032 - Cryptographic block: Invalid input length.
    InvalidEncryptedBlockLength = -45032,
    // -45033 - Cryptographic block: Input has been tampered with.
    InvalidEncryptedBlockContent = -45033,
    // -45034 - Invalid ADI call: input buffer is too small.
    InvalidADICall = -45034,
    // -45036 - Invalid time.
    InvalidTime = -45036,
    // -45046 - Invalid hardware identifiers.
    InvalidHardwareIdentifiers = -45046,
    // -45054 - Filesystem error.
    FilesystemError,
    // -45061 - Device has not been provisioned.
    NotProvisioned = -45061,
    // -45062 - No provisioning data to erase.
    NoProvisioningToErase = -45062,
    // -45063 - Another provisioning session is pending.
    PendingSession = -45063,
    // -45066 - Session has been previously ended.
    TerminatedSession = -45066,
    // -45075 - Cannot load the CoreADI executable.
    LibraryLoadingError = -45075,
    // -45076 - This CoreADI distribution has been phased out in favor of adid. Downgrade CoreADI or switch to adid.
    UnsupportedCoreADI = -45076,
    UnknownError(i32) = -1,
}

impl From<i32> for ADIError {
    fn from(value: i32) -> Self {
        match value {
            -45001 => ADIError::InvalidParameters,
            -45002 => ADIError::InvalidParameters2,
            -45003 => ADIError::InvalidTK,
            -45006 => ADIError::PTMTKPairMismatch,
            -45012 => ADIError::ThreadingError,
            -45016 => ADIError::UnreachableADID,
            -45017 => ADIError::MachMessageError,
            -45018 => ADIError::InvalidEncryptionScheme,
            -45019 => ADIError::InvalidFunctionCode,
            -45020 => ADIError::InvalidParameterBody,
            -45025 => ADIError::InvalidSession,
            -45026 => ADIError::EmptySession,
            -45031 => ADIError::InvalidEncryptedBlockHeader,
            -45032 => ADIError::InvalidEncryptedBlockLength,
            -45033 => ADIError::InvalidEncryptedBlockContent,
            -45034 => ADIError::InvalidADICall,
            -45036 => ADIError::InvalidTime,
            -45046 => ADIError::InvalidHardwareIdentifiers,
            -45054 => ADIError::FilesystemError,
            -45061 => ADIError::NotProvisioned,
            -45062 => ADIError::NoProvisioningToErase,
            -45063 => ADIError::PendingSession,
            -45066 => ADIError::TerminatedSession,
            -45075 => ADIError::LibraryLoadingError,
            -45076 => ADIError::UnsupportedCoreADI,
            _ => ADIError::UnknownError(value),
        }
    }
}

impl Display for ADIError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ADIError::InvalidParameters => write!(
                f,
                "Invalid parameters, have all the library fields been properly initialized? (-45001)"
            ),
            ADIError::InvalidParameters2 => write!(f, "Invalid parameters. (-45002)"),
            ADIError::InvalidTK => write!(f, "Trust Key is invalid (-45003)"),
            ADIError::PTMTKPairMismatch => write!(
                f,
                "Valid PTM/TK pair, but not matching the inner ADI state. (-45006)"
            ),
            ADIError::ThreadingError => write!(f, "Thread error (-45012)"),
            ADIError::UnreachableADID => {
                write!(f, "Mach call failed, can't contact adid. (-45016)")
            }
            ADIError::MachMessageError => write!(
                f,
                "Mach call cannot be sent to adid, have you got the right entitlements? (-45017)"
            ),
            ADIError::InvalidEncryptionScheme => {
                write!(f, "Unknown encryption scheme given to CoreADI. (-45018)")
            }
            ADIError::InvalidFunctionCode => write!(f, "Unimplemented call (-45019)"),
            ADIError::InvalidParameterBody => {
                write!(f, "Cannot decrypt the input parameter block. (-45020)")
            }
            ADIError::InvalidSession => write!(f, "Unknown session number. (-45025)"),
            ADIError::EmptySession => write!(f, "Empty session number. (-45026)"),
            ADIError::InvalidEncryptedBlockHeader => {
                write!(f, "Cryptographic block: Invalid input header. (-45031)")
            }
            ADIError::InvalidEncryptedBlockLength => {
                write!(f, "Cryptographic block: Invalid input length. (-45032)")
            }
            ADIError::InvalidEncryptedBlockContent => write!(
                f,
                "Cryptographic block: Input has been tampered with. (-45033)"
            ),
            ADIError::InvalidADICall => {
                write!(f, "Invalid ADI call: input buffer is too small. (-45034)")
            }
            ADIError::InvalidTime => write!(f, "Invalid time. (-45036)"),
            ADIError::InvalidHardwareIdentifiers => {
                write!(f, "Invalid hardware identifiers. (-45046)")
            }
            ADIError::FilesystemError => write!(f, "Filesystem error. (-45054)"),
            ADIError::NotProvisioned => write!(f, "Device has not been provisioned. (-45061)"),
            ADIError::NoProvisioningToErase => write!(f, "No provisioning data to erase. (-45062)"),
            ADIError::PendingSession => {
                write!(f, "Another provisioning session is pending. (-45063)")
            }
            ADIError::TerminatedSession => write!(f, "Session has been previously ended. (-45066)"),
            ADIError::LibraryLoadingError => {
                write!(f, "Cannot load the CoreADI executable. (-45075)")
            }
            ADIError::UnsupportedCoreADI => write!(
                f,
                "This CoreADI distribution has been phased out in favor of adid. Downgrade CoreADI or switch to adid. (-45076)"
            ),
            ADIError::UnknownError(n) => write!(f, "Unknown error. ({n})"),
        }
    }
}

impl std::error::Error for ADIError {}

pub type ADIResult<T> = Result<T, ADIError>;

#[derive(Serialize, PartialEq, Debug)]
#[repr(C)]
pub struct ADIPayload<Message: ADIMessage> {
    pub encryption_type: EncryptionType,
    pub marker: u32,
    pub payload: Message,
}

pub struct ADIBuffer<'lt, T>(pub Option<&'lt [T]>);

impl<'lt, T> Deref for ADIBuffer<'lt, T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        match self.0 {
            Some(arr) => arr,
            None => &[],
        }
    }
}

pub struct ADIProvisioningSession<'lt> {
    pub val: u32,
    pub proxy: PhantomData<&'lt dyn ADIProxy>,
}

impl<T> Drop for ADIBuffer<'_, T> {
    fn drop(&mut self) {
        // it should never be called :(
        // in D we could have added a static assert here giving a compiling error and preventing misuse.
        panic!("The ADIBuffer {self:p} has not been disposed properly.");
    }
}

impl Drop for ADIProvisioningSession<'_> {
    fn drop(&mut self) {
        // it should never be called :(
        // in D we could have added a static assert here giving a compiling error and preventing misuse.
        panic!(
            "The ADIProvisioningSession {} has not been terminated properly.",
            self.val
        );
    }
}

#[derive(Debug, Clone)]
pub struct ADIAccount {
    pub ds_id: i64,
    pub mid: Vec<u8>,
    pub otp: Vec<u8>,
}

pub trait ADIProxy {
    /// Returns whether ADI stores provisioning data for a given DSID.
    fn is_machine_provisioned(&self, ds_id: i64) -> ADIResult<bool>;
    /// Get a list of every provisioned DSID along with its associated MID and OTP.
    fn get_all_provisioned_accounts(&self) -> ADIResult<Vec<ADIAccount>>;
    /// Starts a provisioning session for the DSID.
    fn start_provisioning(
        &self,
        ds_id: i64,
        spim: &[u8],
    ) -> ADIResult<(Vec<u8>, ADIProvisioningSession<'_>)>;
    /// Ends a provisioning session.
    fn end_provisioning(
        &self,
        session: ADIProvisioningSession,
        ptm: &[u8],
        tk: &[u8],
    ) -> ADIResult<()>;
    /// Cancels a provisioning session.
    fn destroy_provisioning_session(&self, session: ADIProvisioningSession) -> ADIResult<()>;
    fn set_idms_routing(&self, ds_id: i64, routing_info: u64) -> ADIResult<()>;
    fn get_idms_routing(&self, ds_id: i64) -> ADIResult<u64>;
    fn synchronize(&self, ds_id: i64, sim: &[u8]) -> ADIResult<(Vec<u8>, Vec<u8>)>;
    fn erase_provisioning(&self, ds_id: i64) -> ADIResult<()>;
    fn request_otp(&self, ds_id: i64) -> ADIResult<(Vec<u8>, Vec<u8>)>;

    /// Exclusive to Android's CoreADI: set the provisioning path.
    fn set_provisioning_path(&self, path: &CStr) -> ADIResult<()>;
    /// Exclusive to Android's CoreADI: set the hardware identifier used by the library.
    fn set_android_id(&self, id: &str) -> ADIResult<()>;

    /// Exclusive to Apple's ADI implementations: compute a 2FA code.
    fn generate_2fa_code(&self, ds_id: i64) -> ADIResult<u32>;
}
