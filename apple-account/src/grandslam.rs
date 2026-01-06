mod anisette;
mod authenticated_session;
mod post_data;
mod secondary_actions;
mod url_switch;

use crate::bundle_information::BundleInformation;
use crate::device::Device;
use crate::grandslam::AuthOutcome::AnisetteResyncRequired;
use crate::http_session::{
    AnisetteHTTPSession, AppleError, BasicHTTPSession, HTTPSession, HTTPSessionCreationError,
    URLBagError, parse_status,
};
use crate::plist_request::dict_to_body;
use adi::proxy::{ADIError, ADIResult};
use aes::cipher::block_padding;
use aes::cipher::block_padding::Pkcs7;
pub use anisette::*;
pub use authenticated_session::*;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use bytes::Bytes;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
use chrono::{Local, SecondsFormat};
use hmac::{Hmac, KeyInit, Mac};
use log::trace;
use plist::{Dictionary, Value};
use plist_macros::{array, dict};
pub use post_data::*;
use reqwest::{Certificate, Method, RequestBuilder};
use sha2::{Digest, Sha256};
use srp::client::SrpClient;
use srp::groups::G_2048;
use srp::types::SrpAuthError;
use std::fmt::{Display, Formatter};
use thiserror::Error;
pub use url_switch::*;

const ROOT_CA: &[u8] = include_bytes!("grandslam/root-ca.pem");

/// Build an HTTP session for interacting with grandslam endpoints.
/// It will connect to the default production servers, and identifies itself as the application
/// described in `client_bundle_info` running on the device `device`.
///
/// # Arguments
///
/// * `device`: device information sent to Apple
/// * `client_bundle_info`: application information sent to Apple
///
/// returns: Result<HTTPSession, HTTPSessionCreationError>
///
/// # Examples
///
/// ```
/// let device = Device {
///     device_model: "MacBookPro13,2".to_string(),
///     operating_system_information: "macOS;15.6.1;24G90".to_string(),
///     device_uuid: "A8B31C86-359B-4D95-8950-BA5DD8FFC46F".to_string(),
/// };
///
/// let grandslam_http_session = grandslam::http_session(device, XCODE_BUNDLE_INFORMATION).await?;
/// ```
pub async fn http_session(
    device: Device,
    client_bundle_info: BundleInformation<'_>,
) -> Result<HTTPSession<'_>, HTTPSessionCreationError> {
    http_session_with_idms_env(device, client_bundle_info, 0).await
}

pub fn bag_url(idms_env: usize) -> &'static str {
    const URL_FOR_IDMS_ENV: [&str; 4] = [
        "https://gsa.apple.com/grandslam/GsService2/lookup",
        // the other urls seem to be internal Apple servers.
        "https://grandslam-uat.apple.com/grandslam/GsService2/lookup",
        "https://grandslam-it.apple.com/grandslam/GsService2/lookup",
        "https://grandslam-it3.apple.com/grandslam/GsService2/lookup",
    ];

    URL_FOR_IDMS_ENV[idms_env]
}

pub async fn http_session_with_idms_env(
    device: Device,
    client_bundle_info: BundleInformation<'_>,
    idms_env: usize,
) -> Result<HTTPSession<'_>, HTTPSessionCreationError> {
    http_session_with_custom_bag_url(device, client_bundle_info, bag_url(idms_env)).await
}

pub(crate) fn parse_url_bag_response(url_bag_response: Bytes) -> Result<Dictionary, URLBagError> {
    let url_bag_plist = plist::from_bytes::<Dictionary>(&url_bag_response)
        .map_err(|_| URLBagError::Parsing)?
        .get("urls")
        .and_then(Value::as_dictionary)
        .cloned()
        .ok_or(URLBagError::InvalidUrlBag)?;

    Ok(url_bag_plist)
}

pub async fn http_session_with_custom_bag_url<'lt>(
    device: Device,
    client_bundle_info: BundleInformation<'lt>,
    url: &str,
) -> Result<HTTPSession<'lt>, HTTPSessionCreationError> {
    let http_session = BasicHTTPSession::new(
        device,
        client_bundle_info,
        Some(Certificate::from_pem(ROOT_CA).expect("the bundled certificate is not valid??")),
    )?;

    let url_bag_response = http_session
        .request_builder(Method::GET, url)
        .send()
        .await
        .map_err(HTTPSessionCreationError::Reqwest)?
        .error_for_status()
        .map_err(HTTPSessionCreationError::Reqwest)?
        .bytes()
        .await
        .map_err(HTTPSessionCreationError::Reqwest)?;

    let url_bag = parse_url_bag_response(url_bag_response)
        .map_err(|_| HTTPSessionCreationError::InvalidURLBagResponseStructure)?;

    HTTPSession::new(http_session, url_bag)
}

pub struct Token<'lt, 'lt2, 'adi> {
    http_session: &'lt AnisetteHTTPSession<'lt2, 'adi>,
    alt_dsid: String,
    token: String,
}

#[derive(Debug)]
pub enum TokenError {
    Expired,
    ADI(ADIError),
}

impl Display for TokenError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::Expired => {
                write!(f, "The session has expired.")
            }
            TokenError::ADI(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for TokenError {}

impl<'lt, 'lt2, 'adi> Token<'lt, 'lt2, 'adi> {
    pub fn new(
        http_session: &'lt AnisetteHTTPSession<'lt2, 'adi>,
        alt_dsid: String,
        token: String,
    ) -> Result<Self, TokenError> {
        // TODO check the validity of the token.
        Ok(Self {
            http_session,
            alt_dsid,
            token,
        })
    }

    pub fn authenticated_request_builder(
        &self,
        method: Method,
        url: &str,
    ) -> Result<RequestBuilder, TokenError> {
        Ok(self
            .http_session
            .anisette_request_builder(GRANDSLAM_DSID, method, url)
            .map_err(TokenError::ADI)?
            .header("X-Apple-I-Identity-Id", &self.alt_dsid)
            .header("X-Apple-GS-Token", &self.token))
    }
}
#[derive(Debug)]
pub enum AuthOutcome {
    Success(Dictionary),
    SecondaryActionRequired(Option<Dictionary>, String),
    AnisetteResyncRequired(Vec<u8>),
    AnisetteReprovisionRequired,
    UrlSwitchingRequired(String),
}

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Could not log-in to Apple servers: {0}")]
    Apple(#[from] AppleError),
    #[error("Cannot generate device authentication data: {0}")]
    Anisette(#[from] ADIError),
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    // vvv Internal errors vvv
    #[error("Invalid URL bag")]
    InvalidURLBag,
    #[error("Cannot parse server response from step {auth_step}: {error}")]
    Parsing { auth_step: u8, error: plist::Error },
    #[error("Invalid server response structure (censor private data before reporting): {0:?}")]
    Structure(Dictionary),
    #[error("Authentication protocol failure: {0}")]
    SRP(#[from] SrpAuthError),
    #[error("Unknown server protocol: {0}")]
    UnknownProtocol(String),
    #[error("Decryption error: {0}")]
    Decryption(#[from] block_padding::Error),
}

pub type AuthResult = Result<AuthOutcome, AuthError>;

pub fn build_client_provided_data(
    http_session: &AnisetteHTTPSession<'_, '_>,
) -> ADIResult<Dictionary> {
    let adi_proxy = http_session.adi_proxy();
    let device = http_session.device();
    let application_information = http_session.application_information();

    let client_time = Local::now()
        .to_utc()
        .to_rfc3339_opts(SecondsFormat::Secs, true);

    let timezone = iana_time_zone::get_timezone().unwrap_or_else(|_| "UTC".to_string());
    let locale = sys_locale::get_locale()
        .unwrap_or_else(|| String::from("en-US"))
        .replace('-', "_");

    let routing_info = adi_proxy.get_idms_routing(GRANDSLAM_DSID)?;

    let (mid, otp) = {
        let (mid_b, otp_b) = adi_proxy.request_otp(GRANDSLAM_DSID)?;

        let mid = BASE64_STANDARD.encode(mid_b);
        let otp = BASE64_STANDARD.encode(otp_b);

        (mid, otp)
    };

    let client_provided_data = dict! {
        "X-Apple-I-Client-Time": client_time,
        "X-Apple-I-TimeZone": timezone,
        "X-Apple-Locale": locale.clone(),

        "X-Apple-I-MD": otp,
        "X-Apple-I-MD-M": mid,
        "X-Apple-I-MD-RINFO": routing_info.to_string(),

        "X-Mme-Device-Id": device.device_uuid.clone(),

        "bootstrap": true,
        "capp": application_information.bundle_name,
        "ckgen": true,
        "icscrec": true,
        "loc": locale,
        "pbe": false,
        "prkgen": true,
        "svct": "iCloud",
    };

    Ok(client_provided_data)
}

#[repr(u64)]
enum StatusCode {
    Success = 200,
    SecondaryActionRequired = 409,
    AnisetteReprovisionRequired = 433,
    AnisetteResyncRequired = 434,
    UrlSwitchingRequired = 435,
}

impl TryFrom<u64> for StatusCode {
    type Error = ();

    fn try_from(v: u64) -> Result<Self, Self::Error> {
        match v {
            x if x == Self::Success as u64 => Ok(Self::Success),
            x if x == Self::SecondaryActionRequired as u64 => Ok(Self::SecondaryActionRequired),
            x if x == Self::AnisetteReprovisionRequired as u64 => {
                Ok(Self::AnisetteReprovisionRequired)
            }
            x if x == Self::AnisetteResyncRequired as u64 => Ok(Self::AnisetteResyncRequired),
            x if x == Self::UrlSwitchingRequired as u64 => Ok(Self::UrlSwitchingRequired),
            _ => Err(()),
        }
    }
}

pub async fn login(
    http_session: &AnisetteHTTPSession<'_, '_>,
    apple_id: &str,
    password: &str,
) -> AuthResult {
    let gs_service_url = http_session
        .url_bag()
        .get("gsService")
        .and_then(Value::as_string)
        .ok_or(AuthError::InvalidURLBag)?;

    let cpd = build_client_provided_data(http_session)?;

    // TODO: implement s4k, if some day someone needs that.
    let srp_client = SrpClient::<Sha256>::new_with_options(&G_2048, true);
    let a: [u8; 256] = rand::random();
    let a_pub = srp_client.compute_public_ephemeral(&a);

    let request_plist = dict! {
        "Header": dict!{
            "Version": "1.0.1"
        },
        "Request": dict!{
            "A2k": Value::Data(a_pub),
            "cpd": cpd,
            "o": "init",
            "ps": array![
                "s2k",
                "s2k_fo" // most Apple servers seem to not even implement that protocol anymore.
            ],
            "u": apple_id
        }
    };

    let response = http_session
        .anisette_request_builder(GRANDSLAM_DSID, Method::POST, gs_service_url)?
        .body(dict_to_body(request_plist))
        .send()
        .await?
        .bytes()
        .await?;

    let response_plist: Dictionary =
        plist::from_bytes(&response).map_err(|error| AuthError::Parsing {
            auth_step: 0,
            error,
        })?;

    let response_dict = response_plist
        .get("Response")
        .and_then(|response| response.as_dictionary())
        .ok_or(AuthError::Structure(response_plist.clone()))?;

    let status = response_dict
        .get("Status")
        .and_then(|status| status.as_dictionary())
        .ok_or(AuthError::Structure(response_plist.clone()))?;

    parse_status(status).map_err(AuthError::Apple)?;

    let iteration_count = response_dict
        .get("i")
        .and_then(|iteration_count| iteration_count.as_unsigned_integer())
        .ok_or(AuthError::Structure(response_plist.clone()))?;

    let salt = response_dict
        .get("s")
        .and_then(|salt| salt.as_data())
        .ok_or(AuthError::Structure(response_plist.clone()))?;

    let selected_protocol = response_dict
        .get("sp")
        .and_then(|selected_protocol| selected_protocol.as_string())
        .ok_or(AuthError::Structure(response_plist.clone()))?;

    let cookie = response_dict
        .get("c")
        .and_then(|cookie| cookie.as_string())
        .ok_or(AuthError::Structure(response_plist.clone()))?;

    let b = response_dict
        .get("B")
        .and_then(|b| b.as_data())
        .ok_or(AuthError::Structure(response_plist.clone()))?;

    let hashed_password: Vec<u8> = match selected_protocol {
        // SRP with a 2048/4096-bit long A.
        "s2k" | "s4k" => Sha256::digest(password.as_bytes()).to_vec(),
        // SRP with a 2048-bit long A + fo?
        "s2k_fo" => hex::encode(Sha256::digest(password.as_bytes())).into_bytes(),
        _ => {
            return Err(AuthError::UnknownProtocol(selected_protocol.into()));
        }
    };

    let processed_password = {
        let mut buf = [0u8; 32];
        pbkdf2::pbkdf2::<Hmac<Sha256>>(&hashed_password, salt, iteration_count as u32, &mut buf)
            .expect("the length is wrong??");
        buf
    };

    let verifier =
        srp_client.process_reply_rfc5054(&a, apple_id.as_bytes(), &processed_password, salt, b)?;

    let cpd = build_client_provided_data(http_session)?;

    let request_plist = dict! {
        "Header": dict!{
            "Version": "1.0.1"
        },
        "Request": dict!{
            "M1": Value::Data(verifier.proof().to_vec()),
            "c": cookie,
            "cpd": cpd,
            "o": "complete",
            "u": apple_id
        }
    };

    let response = http_session
        .anisette_request_builder(GRANDSLAM_DSID, Method::POST, gs_service_url)?
        .body(dict_to_body(request_plist))
        .send()
        .await?
        .bytes()
        .await?;

    let response_plist: Dictionary =
        plist::from_bytes(&response).map_err(|error| AuthError::Parsing {
            auth_step: 1,
            error,
        })?;

    trace!("Received: {:#?}", response_plist);

    let response_dict = response_plist
        .get("Response")
        .and_then(|response| response.as_dictionary())
        .ok_or(AuthError::Structure(response_plist.clone()))?;

    // println!("Response: {response_dict:?}");

    let status = response_dict
        .get("Status")
        .and_then(|status| status.as_dictionary())
        .ok_or(AuthError::Structure(response_plist.clone()))?;

    parse_status(status)?;

    let status_code: StatusCode = status
        .get("hsc")
        .and_then(|status_code| status_code.as_unsigned_integer())
        .unwrap_or(0)
        .try_into()
        .map_err(|_| AuthError::Structure(response_plist.clone()))?;

    let server_provided_data = response_dict
        .get("spd")
        .and_then(|server_provided_data| server_provided_data.as_data())
        .map::<Result<_, AuthError>, _>(|server_provided_data| {
            let server_reply = response_dict
                .get("M2")
                .and_then(|server_reply| server_reply.as_data())
                .ok_or(AuthError::Structure(response_plist.clone()))?;

            verifier
                .verify_server(server_reply)
                .map_err(AuthError::SRP)?;

            // The session is now verified, let's grab those tokens!
            let session_key = verifier.key();

            // The session key here is of a known length, we know those can't fail.
            let extra_data_key = Hmac::<Sha256>::new_from_slice(session_key)
                .expect("the length is wrong??")
                .chain_update("extra data key:")
                .finalize()
                .into_bytes();

            let extra_data_iv = Hmac::<Sha256>::new_from_slice(session_key)
                .expect("the length is wrong??")
                .chain_update("extra data iv:")
                .finalize()
                .into_bytes();

            let server_provided_data = cbc::Decryptor::<aes::Aes256>::new_from_slices(
                &extra_data_key,
                &extra_data_iv[..16],
            )
            .expect("the lengths are wrong??")
            .decrypt_padded_vec::<Pkcs7>(server_provided_data)
            .map_err(AuthError::Decryption)?;

            let server_provided_data: Dictionary = plist::from_bytes(&server_provided_data)
                .map_err(|error| AuthError::Parsing {
                    auth_step: 3,
                    error,
                })?;

            trace!("Parsed server provided data: {:#?}", server_provided_data);

            Ok(server_provided_data)
        })
        .transpose()?;

    match status_code {
        StatusCode::Success => {
            let server_provided_data =
                server_provided_data.expect("No server data has been provided??");
            Ok(AuthOutcome::Success(server_provided_data))
        }
        StatusCode::SecondaryActionRequired => {
            let action_url = status
                .get("au")
                .and_then(|action_url| action_url.as_string())
                .map(|action_url| action_url.to_string())
                .ok_or(AuthError::Structure(response_plist))?;

            Ok(AuthOutcome::SecondaryActionRequired(
                server_provided_data,
                action_url,
            ))
        }
        StatusCode::AnisetteReprovisionRequired => Ok(AuthOutcome::AnisetteReprovisionRequired),
        StatusCode::AnisetteResyncRequired => {
            let sim = status
                .get("X-Apple-I-MD-DATA")
                .and_then(|sim| sim.as_string())
                .ok_or(AuthError::Structure(response_plist.clone()))?;

            let sim = BASE64_STANDARD
                .decode(sim)
                .map_err(|_| AuthError::Structure(response_plist.clone()))?;

            Ok(AnisetteResyncRequired(sim))
        }
        StatusCode::UrlSwitchingRequired => {
            let url_switching_data = status
                .get("X-Apple-I-Data")
                .and_then(|data| data.as_string());

            match url_switching_data {
                Some(url_switching_data) => Ok(AuthOutcome::UrlSwitchingRequired(
                    url_switching_data.to_string(),
                )),
                None => {
                    panic!("URL Switching has been required but no data has been given for it.")
                }
            }
        }
    }
}
