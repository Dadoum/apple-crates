use crate::grandslam::{Token, TokenError};
use crate::http_session::{AppleError, parse_status};
use plist::{Dictionary, Value};
use reqwest::Method;
use serde::Serialize;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum PostDataError {
    Serialization(plist::Error),
    Reqwest(reqwest::Error),
    Apple(AppleError),
    Token(TokenError),
    URLNotFound,
}

impl Display for PostDataError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            PostDataError::Serialization(err) => write!(f, "Serialization failure! {err}"),
            PostDataError::Reqwest(err) => write!(f, "Failed to perform HTTP request! {err}"),
            PostDataError::Apple(err) => err.fmt(f),
            PostDataError::Token(err) => err.fmt(f),
            PostDataError::URLNotFound => write!(f, "Endpoint not found"),
        }
    }
}

impl std::error::Error for PostDataError {}

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

impl Token<'_, '_, '_> {
    pub async fn post_data(&self, device_data: DeviceData) -> Result<(), PostDataError> {
        let post_data = plist::to_value(&device_data).map_err(PostDataError::Serialization)?;
        let post_data_url = self
            .http_session
            .url_bag()
            .get("postData")
            .and_then(Value::as_string)
            .ok_or(PostDataError::URLNotFound)?;

        let mut request_plist = Dictionary::new();
        request_plist.insert("Request".into(), post_data);

        let mut request_body = Vec::<u8>::new();
        plist::to_writer_xml(&mut request_body, &request_plist)
            .expect("Cannot write request plist??");

        let request = self
            .authenticated_request_builder(Method::POST, post_data_url)
            .map_err(PostDataError::Token)?
            .body(request_body);

        let response = request
            .send()
            .await
            .map_err(PostDataError::Reqwest)?
            .bytes()
            .await
            .map_err(PostDataError::Reqwest)?;

        let status: Dictionary =
            plist::from_bytes(&response).map_err(PostDataError::Serialization)?;

        parse_status(&status).map_err(PostDataError::Apple)
    }
}
