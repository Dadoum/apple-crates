use sapsig::{SapsigConfig, SapsigSigner};
use std::path::PathBuf;

fn main() {
    let so_path = std::env::var("SAPSIG_TEST_SO_PATH").ok();
    let lib_dir = std::env::var("SAPSIG_TEST_LIB_DIR").ok();

    let (Some(so_path), Some(lib_dir)) = (so_path, lib_dir) else {
        eprintln!(
            "manual smoke skipped: set SAPSIG_TEST_SO_PATH and SAPSIG_TEST_LIB_DIR to run it"
        );
        return;
    };

    let config = SapsigConfig {
        storeservicescore_path: PathBuf::from(so_path),
        native_lib_dir: PathBuf::from(lib_dir),
    };

    let mut signer = SapsigSigner::establish(config).expect("establish should work on main thread");
    let signature = signer
        .sign(b"143441-19,31 t:music312026-02-10T00:00:00.000ZmusicAndroid")
        .expect("sign should work");
    assert!(!signature.is_empty(), "signature should not be empty");

    signer.refresh().expect("refresh should work");
    let refreshed_signature = signer
        .sign(b"143441-19,31 t:music312026-02-10T00:00:00.000ZmusicAndroid")
        .expect("sign after refresh should work");
    assert!(
        !refreshed_signature.is_empty(),
        "refreshed signature should not be empty"
    );
}
