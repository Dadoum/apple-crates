use super::app::{AppToken, Token, TokenBag};
use crate::grandslam::{ContinuationToken, build_client_provided_data};
use crate::http_session::{AnisetteHTTPSession, AppleError, parse_status};
use adi::proxy::{ADIError, ADIResult};
use aes::Aes256;
use aes::cipher::consts::U16;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{AesGcm, KeyInit};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use hmac::{Hmac, Mac};
use log::{trace, warn};
use plist::{Dictionary, Value};
use plist_macros::{array, dict};
use reqwest::{Method, RequestBuilder};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AltDsid(pub(super) String);

impl AsRef<str> for AltDsid {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdmsToken(String);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionKey(Vec<u8>);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuthCookie(Vec<u8>);

#[derive(Debug, Clone)]
pub struct ServerProvidedData(pub(super) Dictionary);

impl ServerProvidedData {
    pub fn alt_dsid(&self) -> Option<AltDsid> {
        Some(AltDsid(self.0.get("adsid")?.as_string()?.to_owned()))
    }

    pub fn idms_token(&self) -> Option<IdmsToken> {
        Some(IdmsToken(
            self.0.get("GsIdmsToken")?.as_string()?.to_owned(),
        ))
    }

    pub fn session_key(&self) -> Option<SessionKey> {
        Some(SessionKey(self.0.get("sk")?.as_data()?.to_vec()))
    }

    pub fn cookie(&self) -> Option<AuthCookie> {
        Some(AuthCookie(self.0.get("c")?.as_data()?.to_vec()))
    }

    pub fn continuation_token(&self) -> Option<ContinuationToken> {
        Some(ContinuationToken(self.0.get("ck")?.as_string()?.to_owned()))
    }

    pub fn tokens(&self) -> Option<TokenBag> {
        Some(TokenBag(self.0.get("t")?.as_dictionary()?.clone()))
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
    InvalidResponse(Dictionary),
}

#[derive(Debug, Error)]
pub enum ValidateCodeError {
    #[error("The provided code is not valid.")]
    InvalidCode,
    #[error("Could not validate the code: {0}")]
    Apple(#[from] AppleError),
    #[error("Cannot generate device authentication data: {0}")]
    Anisette(#[from] ADIError),
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Invalid URL bag")]
    InvalidURLBag,
    #[error("Unexpected validation HTTP status: {0}")]
    UnexpectedStatus(reqwest::StatusCode),
    #[error("Cannot parse server response: {0}")]
    Parsing(#[from] plist::Error),
    #[error("Invalid validation response: {0:?}")]
    InvalidResponse(Dictionary),
}

#[derive(Clone)]
pub struct AccountHTTPSession<'lt, 'adi> {
    pub http_session: AnisetteHTTPSession<'lt, 'adi>,
    pub alt_dsid: AltDsid,
}

impl<'lt, 'adi> AccountHTTPSession<'lt, 'adi> {
    pub fn new(http_session: AnisetteHTTPSession<'lt, 'adi>, alt_dsid: AltDsid) -> Self {
        Self {
            http_session,
            alt_dsid,
        }
    }

    pub fn simple_request_builder(&self, method: Method, url: &str) -> RequestBuilder {
        self.http_session.simple_request_builder(method, url)
    }

    pub fn anisette_request_builder(&self, method: Method, url: &str) -> ADIResult<RequestBuilder> {
        self.http_session.anisette_request_builder(method, url)
    }

    /// Adds Anisette and the account ID; the endpoint's credential is supplied separately.
    pub fn account_request_builder(&self, method: Method, url: &str) -> ADIResult<RequestBuilder> {
        Ok(self
            .anisette_request_builder(method, url)?
            .header("X-Apple-I-Identity-Id", &self.alt_dsid.0))
    }

    pub async fn get_app_token<T: AppToken>(
        &self,
        idms_token: &IdmsToken,
        session_key: &SessionKey,
        cookie: &AuthCookie,
    ) -> Result<Token<T>, AppTokenRequestError> {
        let app_token_identifier = T::APP_TOKEN_IDENTIFIER;
        let alt_dsid = self.alt_dsid.0.as_str();

        let gs_service_url = self
            .http_session
            .url_bag()
            .get("gsService")
            .and_then(Value::as_string)
            .ok_or(AppTokenRequestError::InvalidURLBag)?;

        let cpd = build_client_provided_data(&self.http_session)
            .map_err(AppTokenRequestError::Anisette)?;

        let checksum = Hmac::<Sha256>::new_from_slice(&session_key.0)
            .map_err(|_| AppTokenRequestError::InvalidAuthToken)?
            .chain_update("apptokens")
            .chain_update(alt_dsid)
            .chain_update(app_token_identifier)
            .finalize()
            .into_bytes()
            .to_vec();

        let request_plist = dict! {
            "Header": dict!{
                "Version": "1.0.1"
            },
            "Request": dict!{
                "u": alt_dsid,
                "app": array![
                    app_token_identifier
                ],
                "c": Value::Data(cookie.0.to_vec()),
                "t": idms_token.0.as_str(),
                "checksum": Value::Data(checksum),
                "cpd": cpd,
                "o": "apptokens",
            }
        };

        let mut request_body = Vec::new();
        plist::to_writer_xml(&mut request_body, &request_plist).expect("Serializing plist failed?");

        let response = self
            .anisette_request_builder(Method::POST, gs_service_url)
            .map_err(AppTokenRequestError::Anisette)?
            .header("Content-Type", "text/x-xml-plist")
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

        if encrypted_tokens.len() < 19 {
            return Err(AppTokenRequestError::InvalidResponse(response_plist));
        }

        let associated_data = &encrypted_tokens[0..3];
        if associated_data != b"XYZ" {
            warn!("Surprised by the associated data provided by Apple: {associated_data:02X?}");
            // return Err(AppTokenRequestError::InvalidResponse);
        }

        let iv = &encrypted_tokens[3..19];
        let encrypted_token = &encrypted_tokens[19..];

        let tokens_data = AesGcm::<Aes256, U16>::new_from_slice(&session_key.0)
            .map_err(|_| AppTokenRequestError::InvalidAuthToken)?
            .decrypt(
                // iv is of fixed size. It shall not fail.
                iv.try_into().expect("Invalid IV size??"),
                Payload {
                    msg: encrypted_token,
                    aad: associated_data,
                },
            )
            .map_err(|_| AppTokenRequestError::InvalidResponse(response_plist.clone()))?;

        let tokens: Dictionary =
            plist::from_bytes(&tokens_data).map_err(AppTokenRequestError::Parsing)?;

        trace!("Decrypted token response: {:#?}", tokens);

        let tokens = ServerProvidedData(tokens);
        tokens
            .tokens()
            .and_then(|tokens| tokens.get())
            .ok_or_else(|| AppTokenRequestError::InvalidResponse(tokens.0))
    }

    pub async fn validate_code(
        &self,
        idms_token: &IdmsToken,
        validation_code: &str,
    ) -> Result<(), ValidateCodeError> {
        let validate_code_url = self
            .http_session
            .url_bag()
            .get("validateCode")
            .and_then(Value::as_string)
            .ok_or(ValidateCodeError::InvalidURLBag)?;

        // AuthKitWin uses POST only when attaching a piggyback verification body.
        let response = self
            .anisette_request_builder(Method::GET, validate_code_url)?
            .header(
                "X-Apple-Identity-Token",
                BASE64_STANDARD.encode(format!("{}:{}", self.alt_dsid.0, idms_token.0)),
            )
            .header("security-code", validation_code)
            .send()
            .await?
            .error_for_status()?;

        if response.status() != reqwest::StatusCode::OK {
            return Err(ValidateCodeError::UnexpectedStatus(response.status()));
        }

        let response_plist: Dictionary = plist::from_bytes(&response.bytes().await?)?;
        let code = response_plist
            .get("ec")
            .and_then(Value::as_signed_integer)
            .ok_or_else(|| ValidateCodeError::InvalidResponse(response_plist.clone()))?;

        match code {
            0 => Ok(()),
            -21669 => Err(ValidateCodeError::InvalidCode),
            code => Err(AppleError {
                code,
                message: response_plist
                    .get("em")
                    .and_then(Value::as_string)
                    .unwrap_or("Unknown validation error")
                    .to_owned(),
            }
            .into()),
        }
    }
}
