mod developer_actions;

use adi::proxy::{ADIError, ADIResult};
use apple_account::bundle_information::BundleInformation;
use apple_account::grandslam::{
    AppTokenIdentifier, AuthenticatedHTTPSession, GRANDSLAM_DSID, Token,
};
use apple_account::http_session::{AnisetteHTTPSession, HTTPSessionCreationError};
use apple_account::plist_request::plist_to_body;
use plist::{Dictionary, Value};
use plist_macros::{array, dict};
use reqwest::{Method, RequestBuilder};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use thiserror::Error;

/// From Xcode 16.4
pub const XCODE_BUNDLE_INFORMATION: BundleInformation = BundleInformation {
    bundle_name: "Xcode",
    bundle_identifier: "com.apple.dt.Xcode",
    bundle_version: "23792",
};

pub const XCODE_TOKEN_IDENTIFIER: AppTokenIdentifier =
    AppTokenIdentifier("com.apple.gs.xcode.auth");

const CLIENT_ID: &str = "XABBG36SBA";
const PROTOCOL_VERSION: &str = "QH65B2";

pub enum PlatformType {
    IOS,
    TvOS,
    WatchOS,
}

impl From<&PlatformType> for &'static str {
    fn from(value: &PlatformType) -> &'static str {
        match value {
            PlatformType::IOS => "ios",
            PlatformType::TvOS => "tvos",
            PlatformType::WatchOS => "watchos",
        }
    }
}

impl Display for PlatformType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str: &'static str = self.into();
        write!(f, "{}", str)
    }
}

pub trait DeveloperActionBase: Serialize + Sized {
    fn action() -> &'static str;

    fn request(&self) -> Dictionary {
        plist::to_value(self)
            .expect("Serialization should never fail.")
            .into_dictionary()
            .expect("Usage error: every DeveloperAction is a dictionary.")
    }
}

pub trait DeveloperAction: DeveloperActionBase {
    type Result;

    fn parse_response(value: Dictionary) -> Self::Result;
}

#[derive(Debug, Error)]
pub enum XcodeError {
    #[error("Failed to perform the demanded action: {} ({status_code})", user_string.as_ref().or(result_string.as_ref()).unwrap_or(&"(null)".to_string()))]
    DeveloperPortal {
        status_code: u64,
        user_string: Option<String>,
        result_string: Option<String>,
    },

    #[error("Failed to perform the demanded action: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Failed to perform the demanded action: {0}")]
    Anisette(#[from] ADIError),
    #[error("Failed to perform the demanded action: {0}")]
    Parsing(#[from] plist::Error),
}

pub struct XcodeSession<'a, 'b> {
    pub http_session: AuthenticatedHTTPSession<'a, 'b>,
    pub token: Token,
}

impl<'a, 'b> XcodeSession<'a, 'b> {
    pub fn new(http_session: AuthenticatedHTTPSession<'a, 'b>, token: Token) -> Self {
        Self {
            http_session,
            token,
        }
    }

    pub async fn perform_developer_action_base<T: DeveloperActionBase>(
        &self,
        developer_action: T,
    ) -> Result<Dictionary, XcodeError> {
        let locale = sys_locale::get_locale()
            .unwrap_or_else(|| String::from("en-US"))
            .replace('-', "_");

        let url = format!(
            "https://developerservices2.apple.com/services/{PROTOCOL_VERSION}/{}",
            T::action()
        );
        let request_id = uuid::Uuid::new_v4();

        let mut base_request = dict! {
            "clientId": CLIENT_ID,
            "protocolVersion": PROTOCOL_VERSION,
            "requestId": request_id.to_string(),
            "userLocale": array![locale],
        };

        base_request.clone_from(&developer_action.request());

        let response = self
            .http_session
            .authenticated_request_builder(Method::POST, url.as_str())?
            .header("Content-Type", "text/x-xml-plist")
            .header("Accept", "text/x-xml-plist")
            .header("X-Apple-App-Info", XCODE_TOKEN_IDENTIFIER.0)
            .header("X-Apple-GS-Token", &self.token)
            .header("X-Xcode-Version", "16.4 (16F6)")
            .query(&[("clientId", CLIENT_ID)])
            .body(plist_to_body(base_request.into()))
            .send()
            .await?
            .bytes()
            .await?;

        let response: Dictionary = plist::from_bytes(&response)?;
        match response
            .get("statusCode")
            .and_then(Value::as_unsigned_integer)
        {
            None | Some(0) => Ok(response),
            Some(status_code) => Err(XcodeError::DeveloperPortal {
                status_code,
                user_string: response
                    .get("userString")
                    .and_then(Value::as_string)
                    .map(ToString::to_string),
                result_string: response
                    .get("resultString")
                    .and_then(Value::as_string)
                    .map(ToString::to_string),
            }),
        }
    }

    pub async fn perform_developer_action<T: DeveloperAction>(
        &self,
        developer_action: T,
    ) -> Result<T::Result, XcodeError> {
        Ok(T::parse_response(
            self.perform_developer_action_base(developer_action).await?,
        ))
    }
}

#[macro_export]
macro_rules! impl_developer_action_base {
    ($name: ty, $action: literal) => {
        impl DeveloperActionBase for $name {
            fn action() -> &'static str {
                $action
            }
        }
    };
}

#[macro_export]
macro_rules! impl_developer_action {
    ($name: ty, $result: ty) => {
        impl DeveloperAction for $name {
            type Result = Result<$result, plist::Error>;

            fn parse_response(value: Dictionary) -> Result<$result, plist::Error> {
                plist::from_value(&value.into())
            }
        }
    };
}

pub use developer_actions::*;
