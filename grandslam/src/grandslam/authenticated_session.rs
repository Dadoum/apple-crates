use crate::grandslam::{GRANDSLAM_DSID, build_client_provided_data};
use crate::http_session::{AnisetteHTTPSession, AppleError, URLBag, parse_status};
use adi::proxy::{ADIError, ADIResult};
use aes::Aes256;
use aes::cipher::consts::U16;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{AesGcm, KeyInit};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use chrono::{Local, SecondsFormat};
use hmac::{Hmac, Mac};
use log::{trace, warn};
use plist::{Dictionary, Value};
use plist_macros::{array, dict};
use reqwest::header::{HeaderValue, InvalidHeaderValue};
use reqwest::{Method, RequestBuilder};
use serde::Deserialize;
use sha2::Sha256;
use thiserror::Error;

#[derive(Debug, Deserialize, Clone)]
pub struct Token {
    pub duration: u64,
    // #[serde(rename = "cts")]
    // pub start_epoch_millis: u64,
    #[serde(rename = "expiry")]
    pub expiry_epoch_millis: u64,
    pub token: String,
}

impl TryFrom<&Token> for HeaderValue {
    type Error = InvalidHeaderValue;

    fn try_from(token: &Token) -> Result<Self, Self::Error> {
        HeaderValue::from_str(token.token.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct AuthToken {
    pub alt_dsid: String,
    pub idms_token: String,
    pub session_key: Vec<u8>,
    pub cookie: Vec<u8>,
    pub identity_token: String,
}

impl AuthToken {
    fn new(alt_dsid: String, idms_token: String, session_key: Vec<u8>, cookie: Vec<u8>) -> Self {
        let identity_token = BASE64_STANDARD.encode(format!("{alt_dsid}:{idms_token}"));
        AuthToken {
            alt_dsid,
            idms_token,
            session_key,
            cookie,
            identity_token,
        }
    }
}

pub fn parse_tokens_from_server_provided_data(
    server_provided_data: &Dictionary,
) -> Option<(AuthToken, Vec<(String, Token)>)> {
    let alt_dsid = server_provided_data
        .get("adsid")
        .and_then(|alt_dsid| alt_dsid.as_string())
        .map(|alt_dsid| alt_dsid.to_string());

    let idms_token = server_provided_data
        .get("GsIdmsToken")
        .and_then(|idms_token| idms_token.as_string())
        .map(|idms_token| idms_token.to_string());

    let session_key = server_provided_data
        .get("sk")
        .and_then(|session_key| session_key.as_data())
        .map(|session_key| session_key.to_vec());

    let cookie = server_provided_data
        .get("c")
        .and_then(|cookie| cookie.as_data())
        .map(|cookie| cookie.to_vec());

    let tokens = server_provided_data
        .get("t")
        .and_then(|tokens| tokens.as_dictionary())
        .map(|tokens| {
            tokens
                .iter()
                .filter_map(|(key, token)| {
                    plist::from_value(token)
                        .ok()
                        .map(|token| (key.clone(), token))
                })
                .collect()
        });

    match (alt_dsid, idms_token, session_key, cookie) {
        (Some(alt_dsid), Some(idms_token), Some(session_key), Some(cookie)) => Some((
            AuthToken::new(alt_dsid, idms_token, session_key, cookie),
            tokens.unwrap_or_default(),
        )),
        _ => None,
    }
}

#[derive(Debug, Error)]
pub enum AppTokenRequestError {
    #[error("Cannot proceed: {0}")]
    Apple(#[from] AppleError),
    #[error("Cannot generate device authentication data: {0}")]
    Anisette(#[from] ADIError),
    #[error("The provided authentication token is not valid")]
    InvalidAuthToken,
    // vvvv Internal errors vvvv
    #[error("Invalid URL bag")]
    InvalidURLBag,
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Failed to parse the app token request response: {0}")]
    Parsing(#[from] plist::Error),
    #[error("Failed to parse the app token request response")]
    Structure(Dictionary),
    #[error("Invalid token returned by the server")]
    InvalidResponse,
}

pub struct AppTokenIdentifier<'lt>(pub &'lt str);

#[derive(Debug, Error)]
pub enum AuthenticatedRequestError {
    #[error("Server returned: {0}")]
    Apple(#[from] AppleError),
    #[error("Cannot generate Anisette headers: {0}")]
    Anisette(#[from] ADIError),
    #[error("Invalid URL bag")]
    InvalidURLBag,
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Invalid server response")]
    InvalidResponse(plist::Error),
}

pub type AuthenticatedRequestResult<T> = Result<T, AuthenticatedRequestError>;

#[derive(Clone)]
pub struct AuthenticatedHTTPSession<'lt, 'adi> {
    pub http_session: AnisetteHTTPSession<'lt, 'adi>,
    pub auth_token: AuthToken,
    pub hb_token: String,
}

impl<'a, 'b> AuthenticatedHTTPSession<'a, 'b> {
    pub fn new(
        http_session: AnisetteHTTPSession<'a, 'b>,
        auth_token: AuthToken,
        heartbeat_token: Token,
    ) -> Self {
        let hb_token =
            BASE64_STANDARD.encode(format!("{}:{}", auth_token.alt_dsid, heartbeat_token.token));

        Self {
            http_session,
            auth_token,
            hb_token,
        }
    }

    pub fn url_bag(&self) -> &URLBag {
        self.http_session.url_bag()
    }

    pub fn simple_request_builder(&self, method: Method, url: &str) -> RequestBuilder {
        self.http_session.simple_request_builder(method, url)
    }

    pub fn anisette_request_builder(&self, method: Method, url: &str) -> ADIResult<RequestBuilder> {
        self.http_session.anisette_request_builder(method, url)
    }

    pub fn authenticated_request_builder(
        &self,
        method: Method,
        url: &str,
    ) -> ADIResult<RequestBuilder> {
        self.anisette_request_builder(method, url).map(|builder| {
            let client_time = Local::now()
                .to_utc()
                .to_rfc3339_opts(SecondsFormat::Secs, true);

            let timezone = iana_time_zone::get_timezone().unwrap_or_else(|_| "UTC".to_string());
            let locale = sys_locale::get_locale().unwrap_or_else(|| String::from("en-US"));
            let apple_locale = locale.replace('-', "_");

            builder
                .header("Accept-Language", locale)
                .header("X-Apple-I-Identity-Id", self.auth_token.alt_dsid.as_str())
                .header("X-Apple-HB-Token", self.hb_token.as_str())
                .header("X-Apple-Locale", apple_locale)
                .header("X-Apple-I-Client-Time", client_time)
                .header("X-Apple-I-TimeZone", timezone)
        })
    }

    pub async fn get_app_token(
        &self,
        app_token_identifier: AppTokenIdentifier<'_>,
    ) -> Result<Token, AppTokenRequestError> {
        let app_token_identifier = app_token_identifier.0;
        let AuthenticatedHTTPSession {
            http_session,
            auth_token,
            ..
        } = self;

        let gs_service_url = http_session
            .url_bag()
            .get("gsService")
            .and_then(Value::as_string)
            .ok_or(AppTokenRequestError::InvalidURLBag)?;

        let cpd =
            build_client_provided_data(&http_session).map_err(AppTokenRequestError::Anisette)?;

        let checksum = Hmac::<Sha256>::new_from_slice(&auth_token.session_key)
            .map_err(|_| AppTokenRequestError::InvalidAuthToken)?
            .chain_update("apptokens")
            .chain_update(&auth_token.alt_dsid)
            .chain_update(app_token_identifier)
            .finalize()
            .into_bytes()
            .to_vec();

        let request_plist = dict! {
            "Header": dict!{
                "Version": "1.0.1"
            },
            "Request": dict!{
                "u": auth_token.alt_dsid.clone(),
                "app": array![
                    app_token_identifier
                ],
                "c": Value::Data(auth_token.cookie.clone()),
                "t": auth_token.idms_token.clone(),
                "checksum": Value::Data(checksum),
                "cpd": cpd,
                "o": "apptokens",
            }
        };

        let mut request_body = Vec::new();
        plist::to_writer_xml(&mut request_body, &request_plist).expect("Serializing plist failed?");

        let response = http_session
            .anisette_request_builder(Method::POST, gs_service_url)
            .map_err(AppTokenRequestError::Anisette)?
            .body(request_body)
            .send()
            .await
            .map_err(AppTokenRequestError::Network)?
            .error_for_status()?
            .bytes()
            .await
            .map_err(AppTokenRequestError::Network)?;

        let response_plist: Dictionary =
            plist::from_bytes(&response).map_err(AppTokenRequestError::Parsing)?;

        let response_dict = response_plist
            .get("Response")
            .and_then(|response| response.as_dictionary())
            .ok_or_else(|| AppTokenRequestError::Structure(response_plist.clone()))?;

        // println!("Response: {response_dict:?}");

        let status = response_dict
            .get("Status")
            .and_then(|status| status.as_dictionary())
            .ok_or_else(|| AppTokenRequestError::Structure(response_plist.clone()))?;

        parse_status(status)?;

        let encrypted_tokens = response_dict
            .get("et")
            .and_then(|et| et.as_data())
            .ok_or_else(|| AppTokenRequestError::Structure(response_plist.clone()))?;

        let associated_data = &encrypted_tokens[0..3];
        if associated_data != b"XYZ" {
            warn!("Surprised by the associated data provided by Apple: {associated_data:02X?}");
            // return Err(AppTokenRequestError::InvalidResponse);
        }

        let iv = &encrypted_tokens[3..19];
        let encrypted_token = &encrypted_tokens[19..];

        let tokens_data = AesGcm::<Aes256, U16>::new_from_slice(&auth_token.session_key)
            .map_err(|_| AppTokenRequestError::InvalidAuthToken)?
            .decrypt(
                // iv is of fixed size. It shall not fail.
                iv.try_into().expect("Invalid IV size??"),
                Payload {
                    msg: encrypted_token,
                    aad: associated_data,
                },
            )
            .map_err(|_| AppTokenRequestError::InvalidResponse)?;

        let tokens: Dictionary =
            plist::from_bytes(&tokens_data).map_err(AppTokenRequestError::Parsing)?;

        trace!("Decrypted token response: {:#?}", tokens);

        tokens
            .get("t")
            .and_then(|token| token.as_dictionary())
            .and_then(|token| token.get(app_token_identifier))
            .and_then(|token| plist::from_value(token).ok())
            .ok_or(AppTokenRequestError::InvalidResponse)
    }

    pub async fn fetch_user_info(&self) -> AuthenticatedRequestResult<Dictionary> {
        let url = self
            .http_session
            .url_bag()
            .get("fetchUserInfo")
            .and_then(Value::as_string)
            .ok_or(AuthenticatedRequestError::InvalidURLBag)?;

        let response = self
            .authenticated_request_builder(Method::GET, url)?
            .send()
            .await?
            .bytes()
            .await?;

        let dict =
            plist::from_bytes(&response).map_err(AuthenticatedRequestError::InvalidResponse)?;

        parse_status(&dict)?;

        Ok(dict)
    }

    pub async fn validate_code(
        &self,
        validation_code: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // TODO: change that error type.
        let validate_code_url = self
            .url_bag()
            .get("validateCode")
            .and_then(Value::as_string)
            .ok_or(AppTokenRequestError::InvalidURLBag)?;

        let _ = self
            .authenticated_request_builder(Method::POST, validate_code_url)?
            .header("security-code", validation_code);

        todo!()
    }
}
