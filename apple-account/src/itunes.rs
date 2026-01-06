use crate::bundle_information::BundleInformation;
use crate::device::Device;
use crate::http_session::{
    AnisetteHTTPSession, AppleError, BasicHTTPSession, HTTPSession, HTTPSessionCreationError,
    URLBagError,
};
use adi::proxy::ADIError;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use bytes::Bytes;
use plist::{Dictionary, Value};
use plist_macros::dict;
use reqwest::Method;
use thiserror::Error;

pub async fn http_session<'lt>(
    device: Device,
    client_bundle_info: BundleInformation<'lt>,
) -> Result<HTTPSession<'lt>, HTTPSessionCreationError> {
    let http_session = BasicHTTPSession::new(device, client_bundle_info, None)?;

    // https://init.itunes.apple.com/WebObjects/MZInit.woa/wa/initiateSession
    let url_bag_response = http_session
        .request_builder(Method::GET, "https://init.itunes.apple.com/bag.xml")
        .query(&[("ix", "6")])
        .header("Content-Type", "application/x-apple-plist")
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

    println!("url_bag: {:#?}", url_bag);

    HTTPSession::new(http_session, url_bag)
}

pub(crate) fn parse_url_bag_response(url_bag_response: Bytes) -> Result<Dictionary, URLBagError> {
    let url_bag_plist =
        plist::from_bytes::<Dictionary>(&url_bag_response).map_err(|_| URLBagError::Parsing)?;

    Ok(url_bag_plist)
}

pub async fn setup_sap(http_session: &HTTPSession<'_>) -> Result<(), Box<dyn std::error::Error>> {
    // TODO: error type
    let sign_sap_setup_url = http_session
        .url_bag()
        .get("sign-sap-setup")
        .and_then(Value::as_string)
        .ok_or(AuthError::InvalidURLBag)?;

    let sap_certificate_response = http_session
        .request_builder(Method::GET, sign_sap_setup_url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    let sap_certificate_dict: Dictionary =
        plist::from_bytes(&sap_certificate_response).map_err(|_| URLBagError::Parsing)?;

    let sap_certificate = sap_certificate_dict
        .get("sign-sap-setup-buffer")
        .ok_or(URLBagError::Parsing)?
        .as_data()
        .ok_or(URLBagError::Parsing)?;

    todo!()
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Could not log-in to Apple servers: {0}")]
    Apple(#[from] AppleError),
    #[error("Cannot generate device authentication data: {0}")]
    Anisette(#[from] ADIError),
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Cannot find the endpoint in the URL bag.")]
    InvalidURLBag,
    #[error("Cannot parse HTTP response")]
    Parsing,
}

///
///
/// # Arguments
///
/// * `http_session`: The HTTPSession to use for the requests.
/// * `apple_id`: Apple Account identifier
/// * `password`: Apple Account password (can be a PET)
/// * `attempt`: Current attempt count. The first attempt should be numbered 1.
///
/// returns: Result<(), AuthError>
///
/// # Examples
///
/// ```
///
/// ```
pub async fn login(
    http_session: &AnisetteHTTPSession<'_, '_>,
    apple_id: &str,
    password: &str,
    attempt: i32,
) -> Result<(), AuthError> {
    let authenticate_url = http_session
        .url_bag()
        .get("authenticateAccount")
        .and_then(Value::as_string)
        .ok_or(AuthError::InvalidURLBag)?;

    let adi_proxy = http_session.adi_proxy();

    let accounts = adi_proxy
        .get_all_provisioned_accounts()?
        .iter()
        .map(|account| {
            Value::Dictionary(dict! {
                "dsid": account.ds_id,
                "mid": BASE64_STANDARD.encode(&account.mid),
                "otp": BASE64_STANDARD.encode(&account.otp),
            })
        })
        .collect::<Vec<_>>();

    let request_plist = dict! {
        "appleId": apple_id,
        "attempt": attempt,
        "auth-mid-otp": accounts,
        "createSession": true,
        "guid": "A0DE61112331", // TODO
        "machineName": "MacBook", // TODO
        "password": password,
        "passwordSettings": dict! {
            "free": "",
            "paid": ""
        },
        // "kbsync": vec![],
        "uuid": "3E72931A-9BFE-46EB-9EEA-3383CE091615", // TODO
        "why": "signIn",
    };

    let mut request_body = Vec::new();
    plist::to_writer_xml(&mut request_body, &request_plist).unwrap();

    // println!("request_body: {}", String::from_utf8(request_body).unwrap());

    let signature = todo!();

    let response = http_session
        .anisette_request_builder(-2, Method::POST, authenticate_url)?
        .body(request_body)
        .header("Content-Type", "application/x-apple-plist")
        // .header("X-Apple-ActionSignature", signature)
        .send()
        .await
        .and_then(|response| response.error_for_status())?
        .text()
        .await?;

    println!("response: {:?}", response);

    /*
    let response_plist: Dictionary =
        plist::from_bytes(&response).map_err(|err| AuthError::Parsing)?;

    let response_dict = response_plist
        .get("Response")
        .and_then(|response| response.as_dictionary())
        .ok_or(AuthError::Parsing)?;

    println!("{:#?}", response_dict);

    Ok(())
    // */
}
