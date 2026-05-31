use sapsig::{SapsigConfig, SapsigSigner};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storeservicescore_path = required_env("SAPSIG_STORESERVICESCORE_PATH")?;
    let native_lib_dir = required_env("SAPSIG_NATIVE_LIB_DIR")?;
    let payload = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("SAPSIG_PAYLOAD").ok())
        .ok_or("set SAPSIG_PAYLOAD or pass the payload as the first argument")?;

    let config = SapsigConfig {
        storeservicescore_path: PathBuf::from(storeservicescore_path),
        native_lib_dir: PathBuf::from(native_lib_dir),
    };

    let signer = SapsigSigner::establish(config)?;
    let signature = signer.sign(payload.as_bytes())?;
    println!("{signature}");

    Ok(())
}

fn required_env(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    std::env::var(name).map_err(|_| format!("set {name} to run the sapsig signing example").into())
}
