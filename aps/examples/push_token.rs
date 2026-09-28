//! cargo run -p aps --example push_token -- STATE.plist
use aps::{ActivationDevice, PushConnection, PushIdentity, PushToken, WindowsActivationSigner};
use plist::Data;
use rsa::{
    RsaPrivateKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use serde::{Deserialize, Serialize};
use std::{fs, io, path::PathBuf, time::Duration};
use thiserror::Error;

#[derive(Debug, Error)]
enum ExampleError {
    #[error("usage: push_token STATE.plist")]
    Usage,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    Plist(#[from] plist::Error),
    #[error(transparent)]
    Key(#[from] rsa::pkcs8::Error),
    #[error(transparent)]
    Identity(#[from] aps::IdentityError),
    #[error(transparent)]
    Activation(#[from] aps::ActivationError<rsa::Error>),
    #[error(transparent)]
    Connect(#[from] aps::ConnectError),
    #[error(transparent)]
    Courier(#[from] aps::CourierError),
}

#[derive(Serialize, Deserialize)]
struct SavedState {
    certificate: Data,
    private_key: Data,
    token: PushToken,
}

#[tokio::main]
async fn main() -> Result<(), ExampleError> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 1 {
        return Err(ExampleError::Usage);
    }
    let state_path = PathBuf::from(&args[0]);
    let client = reqwest::Client::builder()
        .tls_certs_merge([reqwest::Certificate::from_der(aps::APPLE_ROOT_CA)?])
        .timeout(Duration::from_secs(30))
        .build()?;
    let mut connection = match fs::read(&state_path) {
        Ok(bytes) => {
            let state: SavedState = plist::from_bytes(&bytes)?;
            let identity = PushIdentity::new(
                state.certificate.into(),
                RsaPrivateKey::from_pkcs8_der(state.private_key.as_ref())?,
            )?;
            let connection = PushConnection::resume(&client, identity, &state.token).await?;
            println!(
                "Resumed APS; token unchanged: {}",
                connection.push_token() == &state.token
            );
            connection
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let udid = uuid::Uuid::new_v4().to_string().to_uppercase();
            // Values observed in Apple's Windows activation client.
            let device = ActivationDevice {
                device_class: "Windows",
                product_type: "windows1,1",
                product_version: "10.6.4",
                build_version: "10.6.4",
                serial_number: "WindowSerial",
                unique_device_id: &udid,
            };
            let signer = WindowsActivationSigner::new();
            let identity = aps::activate(&client, &device, &signer).await?;
            println!(
                "Activated; device certificate is {} bytes",
                identity.certificate().len()
            );
            PushConnection::connect(&client, identity).await?
        }
        Err(error) => return Err(error.into()),
    };
    connection.set_topics(&["com.apple.idmsauth"]).await?;
    let state = SavedState {
        certificate: connection.identity().certificate().to_vec().into(),
        private_key: connection
            .identity()
            .private_key()
            .to_pkcs8_der()?
            .as_bytes()
            .to_vec()
            .into(),
        token: connection.push_token().clone(),
    };
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    plist::to_writer_xml(options.open(&state_path)?, &state)?;
    println!(
        "Connected; saved identity and {}-byte token to {}",
        connection.push_token().as_bytes().len(),
        state_path.display()
    );
    connection.close().await?;
    Ok(())
}
