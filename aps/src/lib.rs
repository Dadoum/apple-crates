//! Device activation and connections to the Apple Push Service.
//!
//! Activation yields a device identity. The courier handshake then yields a
//! push token. Neither operation requires an Apple account or anisette.

mod activation;
mod connection;
mod protocol;
mod windows_signer;

pub use activation::{
    ActivationDevice, ActivationError, ActivationSignature, ActivationSigner, IdentityError,
    PushIdentity, activate,
};
pub use connection::{ConnectError, Notification, PushConnection, PushToken};
pub use protocol::CourierError;
pub use windows_signer::WindowsActivationSigner;

/// DER-encoded Apple root needed by the push configuration HTTPS endpoint.
/// Add it to the HTTP client's trust store before connecting.
pub const APPLE_ROOT_CA: &[u8] = include_bytes!("../certs/AppleRootCA.der");
