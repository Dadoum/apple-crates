use super::account::AccountHTTPSession;
use super::app::{AppToken, Token};
use crate::http_session::{AppleError, parse_status};
use crate::plist_request::plist_to_body;
use adi::proxy::{ADIError, ADIResult};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use chrono::{Local, SecondsFormat};
use plist::{Dictionary, Value};
use reqwest::{Method, RequestBuilder};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HeartbeatToken(String);

impl From<String> for HeartbeatToken {
    fn from(token: String) -> Self {
        Self(token)
    }
}

impl AsRef<str> for HeartbeatToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AppToken for HeartbeatToken {
    const APP_TOKEN_IDENTIFIER: &'static str = "com.apple.gs.idms.hb";
}

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

#[derive(Debug, Error)]
pub enum PostDataError {
    #[error("Serialization failure! {0}")]
    Serialization(#[from] plist::Error),
    #[error("Failed to perform HTTP request! {0}")]
    Network(#[from] reqwest::Error),
    #[error("Failed to perform the request! {0}")]
    Anisette(#[from] ADIError),
    #[error("Failed to perform the request! {0}")]
    Apple(#[from] AppleError),
    #[error("Invalid URL bag.")]
    InvalidURLBag,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    ICloud,
    ITunesStore,
    IMessage,
    FaceTime,
    GameCenter,
    Piggybacking,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckInEvent {
    Liveness,
    UpdateDeviceState,
    SignOutAll,
    SignOutService(Service),
}

impl Serialize for CheckInEvent {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(match self {
            Self::Liveness => "liveness",
            Self::UpdateDeviceState => "update-device-state",
            Self::SignOutAll => "signout-all",
            Self::SignOutService(service) => match service {
                Service::ICloud => "signout-icloud",
                Service::ITunesStore => "signout-itunesstore",
                Service::IMessage => "signout-imessage",
                Service::FaceTime => "signout-facetime",
                Service::GameCenter => "signout-gamecenter",
                Service::Piggybacking => "signout-piggybacking",
            },
        })
    }
}

#[derive(Debug, Default, Serialize)]
pub struct DeviceData {
    #[serde(rename = "circleStatus")]
    pub circle_status: Option<bool>,
    #[serde(rename = "dc")]
    pub device_color: Option<String>,
    #[serde(rename = "dn")]
    pub device_name: Option<String>,
    pub event: Option<CheckInEvent>,
    #[serde(rename = "imei")]
    pub imei: Option<String>,
    #[serde(rename = "loc")]
    pub locale: Option<String>,
    #[serde(rename = "pn")]
    pub phone_number: Option<String>,
    #[serde(rename = "ptkn")]
    pub push_token: Option<String>,
    pub services: Option<Vec<String>>,
    #[serde(rename = "sn")]
    pub serial_number: Option<String>,
}

#[derive(Clone)]
pub struct HeartbeatHTTPSession<'lt, 'adi> {
    pub http_session: AccountHTTPSession<'lt, 'adi>,
    pub token: Token<HeartbeatToken>,
}

impl<'lt, 'adi> HeartbeatHTTPSession<'lt, 'adi> {
    pub fn new(http_session: AccountHTTPSession<'lt, 'adi>, token: Token<HeartbeatToken>) -> Self {
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

    pub fn heartbeat_request_builder(
        &self,
        method: Method,
        url: &str,
    ) -> ADIResult<RequestBuilder> {
        self.account_request_builder(method, url).map(|builder| {
            let client_time = Local::now()
                .to_utc()
                .to_rfc3339_opts(SecondsFormat::Secs, true);

            let timezone = iana_time_zone::get_timezone().unwrap_or_else(|_| "UTC".to_string());
            let locale = sys_locale::get_locale().unwrap_or_else(|| String::from("en-US"));
            let apple_locale = locale.replace('-', "_");

            builder
                .header("Accept-Language", locale)
                .header(
                    "X-Apple-HB-Token",
                    BASE64_STANDARD.encode(format!(
                        "{}:{}",
                        self.http_session.alt_dsid.0, self.token.token.0
                    )),
                )
                .header("X-Apple-Locale", apple_locale)
                .header("X-Apple-I-Client-Time", client_time)
                .header("X-Apple-I-TimeZone", timezone)
        })
    }

    pub async fn fetch_user_info(&self) -> AuthenticatedRequestResult<Dictionary> {
        let url = self
            .http_session
            .http_session
            .url_bag()
            .get("fetchUserInfo")
            .and_then(Value::as_string)
            .ok_or(AuthenticatedRequestError::InvalidURLBag)?;

        let response = self
            .heartbeat_request_builder(Method::GET, url)?
            .send()
            .await?
            .bytes()
            .await?;

        let dict =
            plist::from_bytes(&response).map_err(AuthenticatedRequestError::InvalidResponse)?;

        parse_status(&dict)?;

        Ok(dict)
    }

    pub async fn post_data(&self, device_data: DeviceData) -> Result<(), PostDataError> {
        let post_data = plist::to_value(&device_data).map_err(PostDataError::Serialization)?;
        let post_data_url = self
            .http_session
            .http_session
            .url_bag()
            .get("postData")
            .and_then(Value::as_string)
            .ok_or(PostDataError::InvalidURLBag)?;

        let mut request = Dictionary::new();
        request.insert("Request".into(), post_data);

        let response = self
            .heartbeat_request_builder(Method::POST, post_data_url)?
            .header("Content-Type", "text/x-xml-plist")
            .body(plist_to_body(request.into()))
            .send()
            .await?
            .bytes()
            .await?;

        let status: Dictionary =
            plist::from_bytes(&response).map_err(PostDataError::Serialization)?;

        parse_status(&status).map_err(PostDataError::Apple)
    }
}
