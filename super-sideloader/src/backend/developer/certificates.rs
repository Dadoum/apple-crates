use crate::backend::paths::app_data_dir;
use crate::backend::{BackendError, BackendResult};
use der::{Decode, Encode, EncodePem};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::{Signature, SigningKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::rand_core::OsRng;
use rsa::RsaPrivateKey;
use sha1::Digest as _;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use x509_cert::builder::{Builder, RequestBuilder};
use x509_cert::name::Name;
use x509_cert::Certificate;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Clone, Debug)]
pub(crate) struct GeneratedCertificateSigningRequest {
    pub(crate) machine_id: String,
    pub(crate) machine_name: String,
    pub(crate) csr_content: String,
    pub(crate) public_key_fingerprint: String,
    pub(crate) private_key_pem: Vec<u8>,
}

pub(crate) struct AppManagedSigningMaterial {
    pub(crate) private_key_pem: Vec<u8>,
    pub(crate) certificate_der: Vec<u8>,
}

pub(crate) fn generate_development_certificate_signing_request(
) -> BackendResult<GeneratedCertificateSigningRequest> {
    let machine_id = Uuid::new_v4().to_string().to_uppercase();
    let machine_name = "Super Sideloader".to_string();
    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).map_err(crypto_error)?;
    let public_key_der = private_key
        .to_public_key()
        .to_public_key_der()
        .map_err(crypto_error)?;
    let public_key_fingerprint = certificate_fingerprint(public_key_der.as_bytes());
    let private_key_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(crypto_error)?
        .as_bytes()
        .to_vec();
    let signer = SigningKey::<sha2_010::Sha256>::new(private_key);
    let subject: Name = format!("CN={machine_name}").parse().map_err(crypto_error)?;
    let csr = RequestBuilder::new(subject, &signer)
        .map_err(crypto_error)?
        .build::<Signature>()
        .map_err(crypto_error)?;
    let csr_content = csr.to_pem(LineEnding::LF).map_err(crypto_error)?;

    Ok(GeneratedCertificateSigningRequest {
        machine_id,
        machine_name,
        csr_content,
        public_key_fingerprint,
        private_key_pem,
    })
}

pub(crate) fn import_app_managed_private_key(
    certificate_id: &str,
    expected_public_key_fingerprint: &str,
    private_key_path: &Path,
) -> BackendResult<()> {
    let private_key_pem = fs::read(private_key_path).map_err(|source| BackendError::Io {
        action: "Read private key",
        path: private_key_path.to_path_buf(),
        source,
    })?;
    let public_key_der = public_key_der_from_private_key(&private_key_pem)?;
    let public_key_fingerprint = certificate_fingerprint(&public_key_der);
    if !public_key_fingerprint.eq_ignore_ascii_case(expected_public_key_fingerprint) {
        return Err(BackendError::Keychain(format!(
            "The selected PEM private key does not match certificate {certificate_id}."
        )));
    }

    save_app_managed_private_key(&public_key_fingerprint, &private_key_pem)
}

pub(crate) fn certificate_fingerprint(contents: &[u8]) -> String {
    sha1::Sha1::digest(contents)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

pub(crate) fn certificate_public_key_fingerprint(certificate_der: &[u8]) -> Option<String> {
    certificate_public_key_der(certificate_der)
        .ok()
        .map(|public_key_der| certificate_fingerprint(&public_key_der))
}

pub(crate) fn app_managed_private_key_fingerprints() -> Vec<String> {
    let Ok(keys_dir) = certificate_keys_dir() else {
        return Vec::new();
    };
    let Ok(entries) = fs::read_dir(keys_dir) else {
        return Vec::new();
    };

    entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            entry
                .path()
                .file_stem()
                .and_then(|stem| stem.to_str())
                .map(str::to_ascii_uppercase)
        })
        .filter(|fingerprint| {
            fingerprint.len() == 40 && fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .collect()
}

pub(crate) fn save_app_managed_certificate(
    fingerprint: &str,
    certificate_der: &[u8],
) -> BackendResult<()> {
    let certificates_dir = signing_certificates_dir()?;
    fs::create_dir_all(&certificates_dir).map_err(|source| BackendError::Io {
        action: "Create signing certificate folder",
        path: certificates_dir.clone(),
        source,
    })?;
    let certificate_path = certificates_dir.join(format!("{}.der", safe_fingerprint(fingerprint)?));
    fs::write(&certificate_path, certificate_der).map_err(|source| BackendError::Io {
        action: "Save signing certificate",
        path: certificate_path,
        source,
    })
}

pub(crate) fn load_app_managed_signing_material(
    certificate_fingerprint: &str,
    public_key_fingerprint: &str,
) -> BackendResult<AppManagedSigningMaterial> {
    let certificate_path = signing_certificates_dir()?.join(format!(
        "{}.der",
        safe_fingerprint(certificate_fingerprint)?
    ));
    let certificate_der = read_signing_resource(
        &certificate_path,
        "Read signing certificate",
        "The selected certificate data is not cached. Refresh Developer Settings, then try signing again.",
    )?;

    let private_key_path =
        certificate_keys_dir()?.join(format!("{}.pem", safe_fingerprint(public_key_fingerprint)?));
    let private_key_pem = read_signing_resource(
        &private_key_path,
        "Read certificate private key",
        "The selected certificate has no Super Sideloader managed private key. Create a certificate or import its matching PEM key in Developer Settings.",
    )?;

    Ok(AppManagedSigningMaterial {
        private_key_pem,
        certificate_der,
    })
}

fn decode_private_key(pem: &[u8]) -> BackendResult<RsaPrivateKey> {
    let pem = std::str::from_utf8(pem).map_err(crypto_error)?;
    // Match the unencrypted RSA formats accepted by the app's CMS signer.
    RsaPrivateKey::from_pkcs8_pem(pem)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
        .map_err(|error| {
            BackendError::Message(format!(
                "Expected an unencrypted RSA private key in PKCS#8 or PKCS#1 PEM format: {error}"
            ))
        })
}

fn public_key_der_from_private_key(private_key_pem: &[u8]) -> BackendResult<Vec<u8>> {
    decode_private_key(private_key_pem)?
        .to_public_key()
        .to_public_key_der()
        .map(|document| document.as_bytes().to_vec())
        .map_err(crypto_error)
}

fn certificate_public_key_der(certificate_der: &[u8]) -> BackendResult<Vec<u8>> {
    Certificate::from_der(certificate_der)
        .map_err(crypto_error)?
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(crypto_error)
}

fn crypto_error(error: impl std::fmt::Display) -> BackendError {
    BackendError::Message(format!("Certificate operation failed: {error}"))
}

pub(crate) fn save_app_managed_private_key(
    fingerprint: &str,
    private_key_pem: &[u8],
) -> BackendResult<()> {
    let keys_dir = certificate_keys_dir()?;
    fs::create_dir_all(&keys_dir).map_err(|source| BackendError::Io {
        action: "Create certificate key folder",
        path: keys_dir.clone(),
        source,
    })?;
    let key_path = keys_dir.join(format!("{}.pem", safe_fingerprint(fingerprint)?));
    fs::write(&key_path, private_key_pem).map_err(|source| BackendError::Io {
        action: "Save certificate private key",
        path: key_path.clone(),
        source,
    })?;
    secure_private_key_file(&key_path)
}

#[cfg(unix)]
fn secure_private_key_file(path: &Path) -> BackendResult<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
        BackendError::Io {
            action: "Secure certificate private key",
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn secure_private_key_file(_: &Path) -> BackendResult<()> {
    Ok(())
}

fn read_signing_resource(
    path: &Path,
    action: &'static str,
    missing_message: &str,
) -> BackendResult<Vec<u8>> {
    fs::read(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            BackendError::Message(missing_message.to_string())
        } else {
            BackendError::Io {
                action,
                path: path.to_path_buf(),
                source,
            }
        }
    })
}

fn safe_fingerprint(fingerprint: &str) -> BackendResult<String> {
    let fingerprint = fingerprint.trim().to_ascii_uppercase();
    if fingerprint.len() == 40 && fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(fingerprint)
    } else {
        Err(BackendError::Cache(
            "Signing certificate cache contains an invalid fingerprint.".to_string(),
        ))
    }
}

fn certificate_keys_dir() -> BackendResult<PathBuf> {
    app_data_dir()
        .map(|path| path.join("certificates").join("keys"))
        .ok_or_else(|| {
            BackendError::Unsupported("The application data folder is not available.".to_string())
        })
}

fn signing_certificates_dir() -> BackendResult<PathBuf> {
    app_data_dir()
        .map(|path| path.join("certificates").join("certificates"))
        .ok_or_else(|| {
            BackendError::Unsupported("The application data folder is not available.".to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::DecodePem;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::DecodePublicKey;
    use rsa::signature::Verifier;
    use rsa::traits::PublicKeyParts;
    use rsa::{pkcs1v15::VerifyingKey, RsaPublicKey};
    use x509_cert::builder::{CertificateBuilder, Profile};
    use x509_cert::request::CertReq;
    use x509_cert::time::Validity;

    #[test]
    fn csr_signature_keys_and_certificate_fingerprints_agree() {
        let generated = generate_development_certificate_signing_request().unwrap();
        let csr = CertReq::from_pem(&generated.csr_content).unwrap();
        assert_eq!(csr.info.subject.to_string(), "CN=Super Sideloader");
        assert_eq!(csr.algorithm.oid.to_string(), "1.2.840.113549.1.1.11");
        let spki = csr.info.public_key.to_der().unwrap();
        let public_key = RsaPublicKey::from_public_key_der(&spki).unwrap();
        assert_eq!(public_key.n().bits(), 2048);
        let verifier = VerifyingKey::<sha2_010::Sha256>::new(public_key);
        let signature = Signature::try_from(csr.signature.as_bytes().unwrap()).unwrap();
        let info = csr.info.to_der().unwrap();
        verifier.verify(&info, &signature).unwrap();
        let mut tampered = info.clone();
        tampered[0] ^= 1;
        assert!(verifier.verify(&tampered, &signature).is_err());
        assert_eq!(
            certificate_fingerprint(&spki),
            generated.public_key_fingerprint
        );
        assert_eq!(
            public_key_der_from_private_key(&generated.private_key_pem).unwrap(),
            spki
        );

        let key = decode_private_key(&generated.private_key_pem).unwrap();
        let pkcs1 = key.to_pkcs1_pem(LineEnding::LF).unwrap();
        assert_eq!(
            public_key_der_from_private_key(pkcs1.as_bytes()).unwrap(),
            spki
        );
        let signer = SigningKey::<sha2_010::Sha256>::new(key);
        let cert = CertificateBuilder::new(
            Profile::Root,
            1u32.into(),
            Validity::from_now(std::time::Duration::from_secs(3600)).unwrap(),
            csr.info.subject,
            csr.info.public_key,
            &signer,
        )
        .unwrap()
        .build::<Signature>()
        .unwrap();
        assert_eq!(
            certificate_public_key_fingerprint(&cert.to_der().unwrap()).unwrap(),
            generated.public_key_fingerprint
        );

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("key.pem");
        fs::write(&path, pkcs1.as_bytes()).unwrap();
        let error =
            import_app_managed_private_key("test-certificate", &"0".repeat(40), &path).unwrap_err();
        assert!(error.to_string().contains("does not match"));
    }

    #[test]
    fn malformed_key_and_certificate_are_rejected() {
        assert!(public_key_der_from_private_key(b"not a PEM key").is_err());
        assert!(public_key_der_from_private_key(&[255, 254]).is_err());
        assert!(certificate_public_key_fingerprint(b"not a certificate").is_none());
    }
}
