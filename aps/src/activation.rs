use plist::{Dictionary, Value};
use reqwest::Client;
use rsa::{
    Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePublicKey, EncodePublicKey},
    rand_core::OsRng,
};
use sha1::{Digest, Sha1};
use thiserror::Error;
use uuid::Uuid;
use x509_cert::{
    Certificate,
    der::{
        Decode, DecodePem, Encode, EncodePem,
        asn1::{Any, BitString},
        pem::LineEnding,
    },
    request::{CertReq, CertReqInfo},
    spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned},
};

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("Invalid RSA private key: {0}")]
    PrivateKey(#[from] rsa::Error),
    #[error("Invalid device certificate: {0}")]
    Certificate(#[from] x509_cert::der::Error),
    #[error("Invalid certificate public key: {0}")]
    PublicKey(#[from] rsa::pkcs8::spki::Error),
    #[error("The certificate does not match the private key")]
    KeyMismatch,
}

#[derive(Debug, Error)]
pub enum ActivationError<E> {
    #[error("Activation request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("Activation plist error: {0}")]
    Plist(#[from] plist::Error),
    #[error("RSA key generation or CSR signing failed: {0}")]
    Rsa(#[from] rsa::Error),
    #[error("Certificate/CSR encoding error: {0}")]
    Der(#[from] x509_cert::der::Error),
    #[error("Public key encoding error: {0}")]
    PublicKey(#[from] rsa::pkcs8::spki::Error),
    #[error("Activation signing failed: {0}")]
    Signing(#[source] E),
    #[error("Invalid activation response")]
    InvalidResponse(Vec<u8>),
    #[error("Invalid activated identity: {0}")]
    Identity(#[from] IdentityError),
}

/// Fields placed in Apple's activation-info plist, excluding the generated CSR
/// and activation nonce. `device_class` also selects the activation endpoint.
pub struct ActivationDevice<'a> {
    pub device_class: &'a str,
    pub product_type: &'a str,
    pub product_version: &'a str,
    pub build_version: &'a str,
    pub serial_number: &'a str,
    pub unique_device_id: &'a str,
}

/// The matching pair sent as FairPlaySignature and FairPlayCertChain.
pub struct ActivationSignature {
    pub signature: Vec<u8>,
    /// Concatenated DER certificates, leaf first.
    pub certificate_chain: Vec<u8>,
}

/// Signs the exact serialized ActivationInfoXML bytes using an activation
/// signing identity. This is separate from the newly generated device key.
pub trait ActivationSigner {
    type Error: std::error::Error + 'static;

    fn sign(&self, activation_info_xml: &[u8]) -> Result<ActivationSignature, Self::Error>;
}

/// The device certificate issued by Apple and its matching private key.
/// Keep both when persisting an identity; a token alone cannot authenticate APS.
#[derive(Clone)]
pub struct PushIdentity {
    certificate: Vec<u8>,
    private_key: RsaPrivateKey,
}

impl PushIdentity {
    /// Imports a DER device certificate and checks that it matches the key.
    pub fn new(certificate: Vec<u8>, private_key: RsaPrivateKey) -> Result<Self, IdentityError> {
        private_key.validate()?;
        let parsed = Certificate::from_der(&certificate)?;
        let public = RsaPublicKey::from_public_key_der(
            &parsed.tbs_certificate.subject_public_key_info.to_der()?,
        )?;
        if public != private_key.to_public_key() {
            return Err(IdentityError::KeyMismatch);
        }
        Ok(Self {
            certificate,
            private_key,
        })
    }

    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    pub fn private_key(&self) -> &RsaPrivateKey {
        &self.private_key
    }
}

pub(crate) fn sign_sha1(key: &RsaPrivateKey, data: &[u8]) -> Result<Vec<u8>, rsa::Error> {
    // SHA-1 DigestInfo (OID 1.3.14.3.2.26), followed by the 20-byte hash.
    let mut digest_info = [0; 35];
    digest_info[..15].copy_from_slice(&[
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
    ]);
    digest_info[15..].copy_from_slice(&Sha1::digest(data));
    key.sign_with_rng(&mut OsRng, Pkcs1v15Sign::new_unprefixed(), &digest_info)
}

/// Generates a device key and CSR, then requests an activation certificate.
/// Use a plain HTTP client; account authentication headers are not needed here.
pub async fn activate<S: ActivationSigner>(
    client: &Client,
    device: &ActivationDevice<'_>,
    signer: &S,
) -> Result<PushIdentity, ActivationError<S::Error>> {
    let private_key = RsaPrivateKey::new(&mut OsRng, 1024)?;
    let info = CertReqInfo {
        version: Default::default(),
        subject: "CN=Client Push Certificate".parse()?,
        public_key: SubjectPublicKeyInfoOwned::from_der(
            private_key.to_public_key().to_public_key_der()?.as_bytes(),
        )?,
        attributes: Default::default(),
    };
    let signature = sign_sha1(&private_key, &info.to_der()?)?;
    let csr = CertReq {
        info,
        algorithm: AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5"),
            parameters: Some(Any::null()),
        },
        signature: BitString::from_bytes(&signature)?,
    }
    .to_pem(LineEnding::LF)?;

    let mut info = Dictionary::new();
    for (name, value) in [
        ("DeviceClass", device.device_class),
        ("ProductType", device.product_type),
        ("ProductVersion", device.product_version),
        ("BuildVersion", device.build_version),
        ("SerialNumber", device.serial_number),
        ("UniqueDeviceID", device.unique_device_id),
        ("ActivationState", "Unactivated"),
    ] {
        info.insert(name.into(), value.into());
    }
    info.insert(
        "ActivationRandomness".into(),
        Uuid::new_v4().to_string().to_uppercase().into(),
    );
    info.insert("DeviceCertRequest".into(), Value::Data(csr.into_bytes()));
    let mut xml = Vec::new();
    plist::to_writer_xml(&mut xml, &info)?;
    let signed = signer.sign(&xml).map_err(ActivationError::Signing)?;
    let envelope = Dictionary::from_iter([
        ("ActivationInfoComplete", Value::Boolean(true)),
        ("ActivationInfoXML", Value::Data(xml)),
        ("FairPlaySignature", Value::Data(signed.signature)),
        ("FairPlayCertChain", Value::Data(signed.certificate_chain)),
    ]);
    let mut body = Vec::new();
    plist::to_writer_xml(&mut body, &envelope)?;
    let response = client
        .post("https://albert.apple.com/WebObjects/ALUnbrick.woa/wa/deviceActivation")
        .query(&[("device", device.device_class)])
        .form(&[("activation-info", String::from_utf8_lossy(&body).as_ref())])
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    // The Windows endpoint wraps the response plist in an HTML Protocol element.
    let text = String::from_utf8_lossy(&response);
    let payload = match text.split_once("<Protocol>") {
        Some((_, rest)) => rest
            .split_once("</Protocol>")
            .map(|(plist, _)| plist)
            .ok_or_else(|| ActivationError::InvalidResponse(response.to_vec()))?,
        None => &text,
    };
    let parsed: Value = plist::from_bytes(payload.as_bytes())
        .map_err(|_| ActivationError::InvalidResponse(response.to_vec()))?;
    let certificate = parsed
        .as_dictionary()
        .and_then(|d| d.get("device-activation"))
        .and_then(Value::as_dictionary)
        .and_then(|d| d.get("activation-record"))
        .and_then(Value::as_dictionary)
        .and_then(|d| d.get("DeviceCertificate"))
        .and_then(Value::as_data)
        .ok_or_else(|| ActivationError::InvalidResponse(response.to_vec()))?;
    let certificate = Certificate::from_pem(certificate)?.to_der()?;
    Ok(PushIdentity::new(certificate, private_key)?)
}
