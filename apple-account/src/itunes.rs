use crate::bundle_information::BundleInformation;
use crate::device::Device;
use crate::http_session::{
    AnisetteHTTPSession, AppleError, BasicHTTPSession, HTTPSession, HTTPSessionCreationError,
    URLBagError,
};
use adi::proxy::ADIError;
use bytes::Bytes;
use plist::{Dictionary, Value};
use plist_macros::dict;
use reqwest::Method;
use std::fmt::{Display, Formatter};

pub async fn http_session<'lt>(
    device: Device,
    client_bundle_info: BundleInformation<'lt>,
) -> Result<HTTPSession<'lt>, HTTPSessionCreationError> {
    let http_session = BasicHTTPSession::new(device, client_bundle_info, None)?;

    let url_bag_response = http_session
        .request_builder(Method::GET, "https://sandbox.itunes.apple.com/bag.xml")
        .query(&[("ix", 6)])
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

pub(crate) fn parse_url_bag_response(url_bag_response: Bytes) -> Result<Dictionary, URLBagError> {
    let url_bag_plist =
        plist::from_bytes::<Dictionary>(&url_bag_response).map_err(|_| URLBagError::Parsing)?;

    Ok(url_bag_plist)
}

#[derive(Debug)]
pub enum AuthError {
    Apple(AppleError),
    Anisette(ADIError),
    Network(reqwest::Error),
    InvalidURLBag,
    Parsing,
}

impl Display for AuthError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            AuthError::Apple(err) => {
                write!(f, "Could not log-in to Apple servers: {err}")
            }
            AuthError::Anisette(err) => {
                write!(f, "Cannot generate device authentication data: {err}")
            }
            AuthError::Network(err) => {
                write!(f, "Network error: {err}")
            }
            AuthError::InvalidURLBag => {
                write!(f, "Cannot find the endpoint in the URL bag.")
            }
            AuthError::Parsing => {
                write!(f, "Cannot parse HTTP response")
            }
        }
    }
}

impl std::error::Error for AuthError {}

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
        .ok_or(AuthError::InvalidURLBag)?
        .replace("sandbox", "p51-buy");

    let adi_proxy = http_session.adi_proxy();

    /*
       "guid": "",
       "kbsync": vec![],
    */

    let request_plist = dict! {
        "appleId": apple_id,
        "attempt": attempt,
        "createSession": true,
        "password": password,
        "passwordSettings": dict! {
            "free": "always",
            "paid": "always"
        },
        "rmp": "0",
        "why": "signIn",
    };

    let mut request_body = Vec::new();
    plist::to_writer_xml(&mut request_body, &request_plist).unwrap();

    /*
    let response = http_session
        .anisette_request_builder(GRANDSLAM_DSID, Method::POST, &authenticate_url)
        .map_err(AuthError::Anisette)?
        .body(request_body)
        .send()
        .await
        .and_then(|response| response.error_for_status())
        .map_err(AuthError::Network)?
        .text()
        .await
        .map_err(AuthError::Network)?;

    println!("response: {:?}", response);

        .bytes()
        .await
        .map_err(AuthError::Network)?;



    let response_plist: Dictionary =
        plist::from_bytes(&response).map_err(|err| AuthError::Parsing)?;

    let response_dict = response_plist
        .get("Response")
        .and_then(|response| response.as_dictionary())
        .ok_or(AuthError::Parsing)?;

    println!("{:#?}", response_dict);
    // */

    Ok(())
}
