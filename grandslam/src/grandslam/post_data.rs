use crate::grandslam::AuthenticatedHTTPSession;
use crate::http_session::{AppleError, parse_status};
use crate::plist_request::plist_to_body;
use adi::proxy::ADIError;
use plist::{Dictionary, Value};
use reqwest::Method;
use serde::Serialize;
use thiserror::Error;

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

#[derive(Debug, Default, Serialize)]
pub struct DeviceData {
    #[serde(rename = "circleStatus")]
    pub circle_status: Option<bool>,
    #[serde(rename = "dc")]
    pub device_color: Option<String>,
    #[serde(rename = "dn")]
    pub device_name: Option<String>,
    #[serde(rename = "event")]
    pub event: Option<String>,
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

impl AuthenticatedHTTPSession<'_, '_> {
    pub async fn post_data(&self, device_data: DeviceData) -> Result<(), PostDataError> {
        let post_data = plist::to_value(&device_data).map_err(PostDataError::Serialization)?;
        let post_data_url = self
            .http_session
            .url_bag()
            .get("postData")
            .and_then(Value::as_string)
            .ok_or(PostDataError::InvalidURLBag)?;

        let mut request = Dictionary::new();
        request.insert("Request".into(), post_data);

        let response = self
            .authenticated_request_builder(Method::POST, post_data_url)?
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
