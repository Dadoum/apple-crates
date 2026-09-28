use adi::proxy::{ADIError, ADIResult};
use grandslam::bundle_information::BundleInformation;
use grandslam::plist_request::plist_to_body;
use grandslam::{AccountHTTPSession, AppHTTPSession, AppToken, Token};
use plist::{Dictionary, Value};
use plist_macros::{array, dict};
use reqwest::{Method, RequestBuilder};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt::Display;
use thiserror::Error;

/// From Xcode 16.4
pub const XCODE_BUNDLE_INFORMATION: BundleInformation = BundleInformation {
    bundle_name: "Xcode",
    bundle_identifier: "com.apple.dt.Xcode",
    bundle_version: "23792",
};

const CLIENT_ID: &str = "XABBG36SBA";
const PROTOCOL_VERSION: &str = "QH65B2";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlatformType {
    IOS,
    TvOS,
    WatchOS,
}

impl PlatformType {
    pub fn as_str(self) -> &'static str {
        match self {
            PlatformType::IOS => "ios",
            PlatformType::TvOS => "tvos",
            PlatformType::WatchOS => "watchos",
        }
    }
}

impl From<&PlatformType> for &'static str {
    fn from(value: &PlatformType) -> &'static str {
        value.as_str()
    }
}

impl Display for PlatformType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str: &'static str = self.into();
        write!(f, "{}", str)
    }
}

pub trait DeveloperActionBase: Serialize + Sized {
    fn action() -> Cow<'static, str>;

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

pub trait PlatformDeveloperAction<P>: Serialize + Sized {
    type Result;

    fn action() -> Cow<'static, str>;

    fn parse_response(value: Dictionary) -> Self::Result;

    fn request(&self) -> Dictionary {
        plist::to_value(self)
            .expect("Serialization should never fail.")
            .into_dictionary()
            .expect("Usage error: every DeveloperAction is a dictionary.")
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct IOS;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct TvOS;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct WatchOS;

#[derive(Debug, Serialize)]
#[serde(transparent)]
pub struct PlatformRequest<P, T> {
    #[serde(skip)]
    pub platform: P,
    pub request: T,
}

pub type IOSRequest<T> = PlatformRequest<IOS, T>;
pub type TvOSRequest<T> = PlatformRequest<TvOS, T>;
pub type WatchOSRequest<T> = PlatformRequest<WatchOS, T>;

impl<P: Default, T> PlatformRequest<P, T> {
    pub fn new(request: T) -> Self {
        Self {
            platform: P::default(),
            request,
        }
    }
}

impl<T: PlatformDeveloperAction<IOS>> DeveloperActionBase for PlatformRequest<IOS, T> {
    fn action() -> Cow<'static, str> {
        Cow::Owned(format!(
            "ios/{}",
            <T as PlatformDeveloperAction<IOS>>::action()
        ))
    }

    fn request(&self) -> Dictionary {
        <T as PlatformDeveloperAction<IOS>>::request(&self.request)
    }
}

impl<T: PlatformDeveloperAction<IOS>> DeveloperAction for PlatformRequest<IOS, T> {
    type Result = T::Result;

    fn parse_response(value: Dictionary) -> Self::Result {
        T::parse_response(value)
    }
}

impl<T: PlatformDeveloperAction<TvOS>> DeveloperActionBase for PlatformRequest<TvOS, T> {
    fn action() -> Cow<'static, str> {
        Cow::Owned(format!(
            "tvos/{}",
            <T as PlatformDeveloperAction<TvOS>>::action()
        ))
    }

    fn request(&self) -> Dictionary {
        <T as PlatformDeveloperAction<TvOS>>::request(&self.request)
    }
}

impl<T: PlatformDeveloperAction<TvOS>> DeveloperAction for PlatformRequest<TvOS, T> {
    type Result = T::Result;

    fn parse_response(value: Dictionary) -> Self::Result {
        T::parse_response(value)
    }
}

impl<T: PlatformDeveloperAction<WatchOS>> DeveloperActionBase for PlatformRequest<WatchOS, T> {
    fn action() -> Cow<'static, str> {
        Cow::Owned(format!(
            "watchos/{}",
            <T as PlatformDeveloperAction<WatchOS>>::action()
        ))
    }

    fn request(&self) -> Dictionary {
        <T as PlatformDeveloperAction<WatchOS>>::request(&self.request)
    }
}

impl<T: PlatformDeveloperAction<WatchOS>> DeveloperAction for PlatformRequest<WatchOS, T> {
    type Result = T::Result;

    fn parse_response(value: Dictionary) -> Self::Result {
        T::parse_response(value)
    }
}

#[derive(Debug, Error)]
pub enum XcodeError {
    #[error("Failed to perform the demanded action: {} ({status_code})", user_string.as_deref().or(result_string.as_deref()).unwrap_or("(null)"))]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct XcodeToken(String);

impl From<String> for XcodeToken {
    fn from(token: String) -> Self {
        Self(token)
    }
}

impl AsRef<str> for XcodeToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AppToken for XcodeToken {
    const APP_TOKEN_IDENTIFIER: &'static str = "com.apple.gs.xcode.auth";
}

pub struct XcodeSession<'a, 'b> {
    pub http_session: AppHTTPSession<'a, 'b, XcodeToken>,
}

impl<'a, 'b> XcodeSession<'a, 'b> {
    pub fn new(http_session: AccountHTTPSession<'a, 'b>, token: Token<XcodeToken>) -> Self {
        Self {
            http_session: AppHTTPSession::new(http_session, token),
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
        self.http_session.app_request_builder(method, url)
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
        let request_id = uuid::Uuid::new_v4().to_string().to_uppercase();

        let mut base_request = dict! {
            "clientId": CLIENT_ID,
            "protocolVersion": PROTOCOL_VERSION,
            "requestId": request_id,
            "userLocale": array![locale],
        };

        base_request.extend(developer_action.request());

        let response = self
            .app_request_builder(Method::POST, url.as_str())?
            .header("X-Xcode-Version", "16.4 (16F6)")
            .query(&[("clientId", CLIENT_ID)])
            .body(plist_to_body(base_request.into()))
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;

        let response: Dictionary = plist::from_bytes(&response)?;
        match response
            .get("resultCode")
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
        impl $crate::DeveloperActionBase for $name {
            fn action() -> std::borrow::Cow<'static, str> {
                std::borrow::Cow::Borrowed($action)
            }
        }
    };
}

#[macro_export]
macro_rules! impl_developer_action {
    ($name: ty, $action: literal, $result: ty, [$($platform:ty),+ $(,)?]) => {
        $(
            impl $crate::PlatformDeveloperAction<$platform> for $name {
                type Result = Result<$result, plist::Error>;

                fn action() -> std::borrow::Cow<'static, str> {
                    std::borrow::Cow::Borrowed($action)
                }

                fn parse_response(value: plist::Dictionary) -> Result<$result, plist::Error> {
                    plist::from_value(&value.into())
                }
            }
        )+
    };

    ($name: ty, $action: literal, $result: ty) => {
        impl $crate::DeveloperActionBase for $name {
            fn action() -> std::borrow::Cow<'static, str> {
                std::borrow::Cow::Borrowed($action)
            }
        }

        impl $crate::DeveloperAction for $name {
            type Result = Result<$result, plist::Error>;

            fn parse_response(value: plist::Dictionary) -> Result<$result, plist::Error> {
                plist::from_value(&value.into())
            }
        }
    };
}

mod developer_actions;

pub use developer_actions::*;
