use super::account::AccountHTTPSession;
use adi::proxy::ADIResult;
use plist::Dictionary;
use reqwest::{Method, RequestBuilder};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Token<T = String> {
    pub duration: u64,
    // #[serde(rename = "cts")]
    // pub start_epoch_millis: u64,
    #[serde(rename = "expiry")]
    pub expiry_epoch_millis: u64,
    pub token: T,
}

pub trait AppToken: From<String> + AsRef<str> {
    const APP_TOKEN_IDENTIFIER: &'static str;
}

#[derive(Debug, Clone)]
pub struct TokenBag(pub(super) Dictionary);

impl TokenBag {
    pub fn get<T: AppToken>(&self) -> Option<Token<T>> {
        let token: Token = plist::from_value(self.0.get(T::APP_TOKEN_IDENTIFIER)?).ok()?;
        Some(Token {
            duration: token.duration,
            expiry_epoch_millis: token.expiry_epoch_millis,
            token: T::from(token.token),
        })
    }
}

#[derive(Clone)]
pub struct AppHTTPSession<'lt, 'adi, T: AppToken> {
    pub http_session: AccountHTTPSession<'lt, 'adi>,
    pub token: Token<T>,
}

impl<'lt, 'adi, T: AppToken> AppHTTPSession<'lt, 'adi, T> {
    pub fn new(http_session: AccountHTTPSession<'lt, 'adi>, token: Token<T>) -> Self {
        Self {
            http_session,
            token,
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

    pub fn app_request_builder(&self, method: Method, url: &str) -> ADIResult<RequestBuilder> {
        Ok(self
            .account_request_builder(method, url)?
            .header("Content-Type", "text/x-xml-plist")
            .header("Accept", "text/x-xml-plist")
            .header("X-Apple-App-Info", T::APP_TOKEN_IDENTIFIER)
            .header("X-Apple-GS-Token", self.token.token.as_ref()))
    }
}
