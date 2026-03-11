mod posix_compat;
mod runtime;
mod session;

pub(crate) use runtime::elf_loader;
pub(crate) use runtime::hooks;

use base64::Engine;
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;

fn render_error(error: &anyhow::Error) -> String {
    format!("{error:#}")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SapsigConfig {
    pub storeservicescore_path: PathBuf,
    pub native_lib_dir: PathBuf,
}

impl SapsigConfig {
    fn validate(&self) -> Result<(), SapsigError> {
        if !self.storeservicescore_path.exists() {
            return Err(SapsigError::MissingStoreservicescorePath {
                path: self.storeservicescore_path.clone(),
            });
        }

        if !self.storeservicescore_path.is_file() {
            return Err(SapsigError::InvalidStoreservicescorePath {
                path: self.storeservicescore_path.clone(),
            });
        }

        if !self.native_lib_dir.exists() {
            return Err(SapsigError::MissingNativeLibDir {
                path: self.native_lib_dir.clone(),
            });
        }

        if !self.native_lib_dir.is_dir() {
            return Err(SapsigError::InvalidNativeLibDir {
                path: self.native_lib_dir.clone(),
            });
        }

        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum SapsigError {
    #[error("storeservicescore library not found: {path}")]
    MissingStoreservicescorePath { path: PathBuf },
    #[error("storeservicescore path is not a file: {path}")]
    InvalidStoreservicescorePath { path: PathBuf },
    #[error("native library directory not found: {path}")]
    MissingNativeLibDir { path: PathBuf },
    #[error("native library path is not a directory: {path}")]
    InvalidNativeLibDir { path: PathBuf },
    #[error("host architecture is unsupported; only aarch64 and x86_64 are supported")]
    UnsupportedHostArchitecture,
    #[error("failed to establish sapsig signer: {0}")]
    Establish(String),
    #[error("failed to sign payload: {0}")]
    Sign(String),
    #[error("failed to refresh sapsig signer: {0}")]
    Refresh(String),
}

pub struct SapsigSigner {
    inner: session::SapSession,
}

impl SapsigSigner {
    /// Establish the underlying SAP session.
    ///
    /// This must be called from the main thread on hosts where the native
    /// StoreServicesCore runtime expects main-thread initialization.
    pub fn establish(config: SapsigConfig) -> Result<Self, SapsigError> {
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            let _ = config;
            return Err(SapsigError::UnsupportedHostArchitecture);
        }

        config.validate()?;

        let inner =
            session::SapSession::establish(&config.storeservicescore_path, &config.native_lib_dir)
                .map_err(|error| SapsigError::Establish(render_error(&error)))?;

        Ok(Self { inner })
    }

    pub fn sign(&self, input: &[u8]) -> Result<String, SapsigError> {
        let signature = self
            .inner
            .sign(input)
            .map_err(|error| SapsigError::Sign(render_error(&error)))?;

        Ok(base64::engine::general_purpose::STANDARD.encode(signature))
    }

    pub fn refresh(&mut self) -> Result<(), SapsigError> {
        self.inner
            .refresh()
            .map_err(|error| SapsigError::Refresh(render_error(&error)))
    }

    pub fn age(&self) -> Duration {
        self.inner.age()
    }
}

#[cfg(test)]
mod tests {
    use super::{SapsigConfig, SapsigError};
    use crate::session::{
        build_hwinfo_from_id, encode_sap_setup_request_body, parse_sap_setup_response_body,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn hardware_info_encodes_length_and_bytes() {
        let hwinfo = build_hwinfo_from_id(&[0x01, 0x02, 0x03, 0x04]);

        assert_eq!(&hwinfo[..4], &(4_u32.to_le_bytes()));
        assert_eq!(&hwinfo[4..8], &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn sap_setup_request_body_encodes_base64_payload() {
        let body = encode_sap_setup_request_body(b"abc").expect("request encoding should work");

        assert!(body.contains("<key>sign-sap-setup-buffer</key>"));
        assert!(body.contains("<data>YWJj</data>"));
    }

    #[test]
    fn sap_setup_response_body_decodes_data_payload() {
        let response = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>sign-sap-setup-buffer</key>
    <data>YWJj</data>
</dict>
</plist>"#;

        let decoded =
            parse_sap_setup_response_body(response).expect("response decoding should work");

        assert_eq!(decoded, b"abc");
    }

    #[test]
    fn config_validation_rejects_missing_paths() {
        let config = SapsigConfig {
            storeservicescore_path: PathBuf::from("/definitely/missing/libstoreservicescore.so"),
            native_lib_dir: PathBuf::from("/definitely/missing"),
        };

        let error = config.validate().expect_err("missing config should fail");
        assert!(matches!(
            error,
            SapsigError::MissingStoreservicescorePath { .. }
        ));
    }

    #[test]
    fn config_validation_accepts_existing_file_and_dir() {
        let temp_root = unique_test_dir();
        let native_lib_dir = temp_root.join("libs");
        fs::create_dir_all(&native_lib_dir).expect("dir should be created");

        let storeservicescore_path = native_lib_dir.join("libstoreservicescore.so");
        fs::write(&storeservicescore_path, b"fake").expect("file should be created");

        let config = SapsigConfig {
            storeservicescore_path,
            native_lib_dir,
        };

        config
            .validate()
            .expect("existing file and dir should pass");

        let _ = fs::remove_dir_all(temp_root);
    }

    fn unique_test_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic enough for tests")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("sapsig-test-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).expect("temp dir should be created");
        dir
    }
}
