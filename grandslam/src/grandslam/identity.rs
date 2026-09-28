use super::account::{AccountHTTPSession, IdmsToken};
use crate::http_session::AppleError;
use adi::proxy::{ADIError, ADIResult};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use plist::{Dictionary, Value};
use reqwest::{Method, RequestBuilder};
use thiserror::Error;

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

/// An account session with an IDMS credential for secondary authentication actions.
#[derive(Clone)]
pub struct IdentityHTTPSession<'lt, 'adi> {
    pub http_session: AccountHTTPSession<'lt, 'adi>,
    pub idms_token: IdmsToken,
}

impl<'lt, 'adi> IdentityHTTPSession<'lt, 'adi> {
    pub fn new(http_session: AccountHTTPSession<'lt, 'adi>, idms_token: IdmsToken) -> Self {
        Self {
            http_session,
            idms_token,
        }
    }

    pub fn simple_request_builder(&self, method: Method, url: &str) -> RequestBuilder {
        self.http_session.simple_request_builder(method, url)
    }

    pub fn anisette_request_builder(&self, method: Method, url: &str) -> ADIResult<RequestBuilder> {
        self.http_session.anisette_request_builder(method, url)
    }

    pub fn account_request_builder(&self, method: Method, url: &str) -> ADIResult<RequestBuilder> {
        self.http_session.account_request_builder(method, url)
    }

    /// Adds Anisette and `X-Apple-Identity-Token` for secondary authentication actions.
    /// The identity header encodes this account's alternate DSID and its IDMS token.
    pub fn identity_request_builder(&self, method: Method, url: &str) -> ADIResult<RequestBuilder> {
        Ok(self.anisette_request_builder(method, url)?.header(
            "X-Apple-Identity-Token",
            BASE64_STANDARD.encode(format!(
                "{}:{}",
                self.http_session.alt_dsid.0, self.idms_token.0
            )),
        ))
    }

    pub async fn validate_code(&self, validation_code: &str) -> Result<(), ValidateCodeError> {
        let validate_code_url = self
            .http_session
            .http_session
            .url_bag()
            .get("validateCode")
            .and_then(Value::as_string)
            .ok_or(ValidateCodeError::InvalidURLBag)?;

        // AuthKitWin uses POST only when attaching a piggyback verification body.
        let response = self
            .identity_request_builder(Method::GET, validate_code_url)?
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
