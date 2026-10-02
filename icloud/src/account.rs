use adi::proxy::{ADIError, ADIResult};
use grandslam::plist_request::dict_to_body;
use grandslam::{AccountHTTPSession, AppToken};
use plist::{Dictionary, Value};
use plist_macros::dict;
use reqwest::{Method, RequestBuilder};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// GrandSlam's password-equivalent token. Only used to establish iCloud credentials.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PasswordEquivalentToken(String);

impl From<String> for PasswordEquivalentToken {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl AsRef<str> for PasswordEquivalentToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AppToken for PasswordEquivalentToken {
    const APP_TOKEN_IDENTIFIER: &'static str = "com.apple.gs.idms.pet";
}

/// Numeric account ID returned by iCloud, distinct from GrandSlam's alternate ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Dsid(String);

impl AsRef<str> for Dsid {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MmeAuthToken(String);

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CloudKitToken(String);

impl AsRef<str> for MmeAuthToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for CloudKitToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// iCloud's service data. Extract only the credentials needed by each service.
/// Deliberately has no Debug implementation: the dictionary contains credentials.
#[derive(Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct AccountSettings(Dictionary);

impl AccountSettings {
    pub fn dsid(&self) -> Option<Dsid> {
        let value = self.account_info()?.get("dsPrsID")?;
        let dsid = match value {
            Value::String(value)
                if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) =>
            {
                value.clone()
            }
            Value::Integer(value) => value.as_unsigned()?.to_string(),
            _ => return None,
        };
        Some(Dsid(dsid))
    }

    pub fn account_info(&self) -> Option<&Dictionary> {
        self.0.get("appleAccountInfo")?.as_dictionary()
    }

    pub fn mme_token(&self) -> Option<MmeAuthToken> {
        Some(MmeAuthToken(self.token("mmeAuthToken")?.to_owned()))
    }

    pub fn cloudkit_token(&self) -> Option<CloudKitToken> {
        Some(CloudKitToken(self.token("cloudKitToken")?.to_owned()))
    }

    pub fn service(&self, dataclass: &str) -> Option<&Dictionary> {
        // Delegate login returns dataclasses directly; get_account_settings
        // groups them under mobilemeAccountInfo (the AOSKit account bag).
        let services = match self.0.get("mobilemeAccountInfo") {
            Some(value) => value.as_dictionary()?,
            None => &self.0,
        };
        services.get(dataclass)?.as_dictionary()
    }

    fn token(&self, name: &str) -> Option<&str> {
        self.0
            .get("tokens")?
            .as_dictionary()?
            .get(name)?
            .as_string()
            .filter(|value| !value.is_empty())
    }
}

#[derive(Debug, Error)]
pub enum LoginError {
    #[error("Cannot generate device authentication data: {0}")]
    Anisette(#[from] ADIError),
    #[error("iCloud request failed: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Cannot parse the iCloud response: {0}")]
    Parsing(#[from] plist::Error),
    #[error("iCloud rejected authentication (status {0})")]
    Status(i64),
    #[error("iCloud rejected authentication: {0}")]
    Rejected(String),
    #[error("iCloud rejected the MobileMe delegate (status {0})")]
    DelegateStatus(i64),
    #[error("iCloud returned an invalid or missing {0}")]
    InvalidResponse(&'static str),
}

/// Build the native MobileMe delegate request, without starting another password login.
///
/// The caller can add `X-Mme-Nas-Qualify` here when supplying validation data.
/// Whether a particular client/account is accepted without it must be checked live.
/// This request neither registers IDS nor accepts new terms of service.
pub fn login_request_builder(
    session: &AccountHTTPSession<'_, '_>,
    apple_id: &str,
    token: &PasswordEquivalentToken,
    language: &str,
    timezone: &str,
) -> ADIResult<RequestBuilder> {
    let request = dict! {
        "delegates": dict! { "com.apple.mobileme": Dictionary::new() },
        "protocolVersion": "1.0",
        "userInfo": dict! {
            "client-id": session.http_session.device().device_uuid.as_str(),
            "language": language,
            "timezone": timezone,
        },
    };
    Ok(session
        .anisette_request_builder(
            Method::POST,
            "https://setup.icloud.com/setup/signin/v2/login",
        )?
        .header("X-Apple-ADSID", session.alt_dsid.as_ref())
        .header("Content-Type", "text/plist")
        .header("Accept", "application/x-plist")
        .basic_auth(apple_id.trim(), Some(token.as_ref()))
        .body(dict_to_body(request)))
}

/// Finish a request made by `login_request_builder`, checking both status levels.
pub async fn login(request: RequestBuilder) -> Result<AccountSettings, LoginError> {
    let response = request.send().await?.error_for_status()?.bytes().await?;
    parse_login_response(&response)
}

pub fn parse_login_response(response: &[u8]) -> Result<AccountSettings, LoginError> {
    let mut response: Dictionary = plist::from_bytes(response)?;
    if let Some(error) = response.get("localizedError").and_then(Value::as_string) {
        return Err(LoginError::Rejected(error.to_owned()));
    }
    let status = response
        .get("status")
        .and_then(Value::as_signed_integer)
        .ok_or(LoginError::InvalidResponse("status"))?;
    if status != 0 {
        return Err(LoginError::Status(status));
    }
    let mut delegates = response
        .remove("delegates")
        .and_then(Value::into_dictionary)
        .ok_or(LoginError::InvalidResponse("delegates"))?;
    let mut delegate = delegates
        .remove("com.apple.mobileme")
        .and_then(Value::into_dictionary)
        .ok_or(LoginError::InvalidResponse("MobileMe delegate"))?;
    let status = delegate
        .get("status")
        .and_then(Value::as_signed_integer)
        .ok_or(LoginError::InvalidResponse("MobileMe delegate status"))?;
    if status != 0 {
        return Err(LoginError::DelegateStatus(status));
    }
    let settings = delegate
        .remove("service-data")
        .and_then(Value::into_dictionary)
        .ok_or(LoginError::InvalidResponse("MobileMe service data"))?;
    Ok(AccountSettings(settings))
}

#[derive(Debug, Error)]
pub enum AccountSettingsError {
    #[error("Cannot generate device authentication data: {0}")]
    Anisette(#[from] ADIError),
    #[error("Cannot retrieve iCloud account settings: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Cannot parse iCloud account settings: {0}")]
    Parsing(#[from] plist::Error),
    #[error("iCloud account settings contain no numeric account ID")]
    MissingAccountId,
    #[error("iCloud returned settings for a different account")]
    AccountMismatch,
}

pub struct ICloudSession<'lt, 'adi> {
    pub http_session: AccountHTTPSession<'lt, 'adi>,
    pub dsid: Dsid,
    token: MmeAuthToken,
}

impl<'lt, 'adi> ICloudSession<'lt, 'adi> {
    pub fn new(
        http_session: AccountHTTPSession<'lt, 'adi>,
        dsid: Dsid,
        token: MmeAuthToken,
    ) -> Self {
        Self {
            http_session,
            dsid,
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

    pub fn icloud_request_builder(&self, method: Method, url: &str) -> ADIResult<RequestBuilder> {
        Ok(self
            .anisette_request_builder(method, url)?
            .header("X-Apple-ADSID", self.http_session.alt_dsid.as_ref())
            .basic_auth(self.dsid.as_ref(), Some(self.token.as_ref())))
    }

    pub async fn account_settings(&self) -> Result<AccountSettings, AccountSettingsError> {
        let response = self
            .icloud_request_builder(
                Method::POST,
                "https://setup.icloud.com/setup/get_account_settings",
            )?
            .header("X-Aos-Accept-Tos", "false")
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        let settings: AccountSettings = plist::from_bytes(&response)?;
        let dsid = settings
            .dsid()
            .ok_or(AccountSettingsError::MissingAccountId)?;
        if dsid != self.dsid {
            return Err(AccountSettingsError::AccountMismatch);
        }
        Ok(settings)
    }
}
