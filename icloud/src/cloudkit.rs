use crate::account::{CloudKitToken, Dsid, MmeAuthToken};
use adi::proxy::{ADIError, ADIResult};
use grandslam::AccountHTTPSession;
use reqwest::{Method, RequestBuilder};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Database {
    Private,
    Shared,
    Public,
}

impl Database {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Shared => "shared",
            Self::Public => "public",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Container<'a> {
    pub identifier: &'a str,
    pub bundle_id: &'a str,
    pub database: Database,
}

/// The native Drive container; its records still require PCS decryption.
pub const CLOUD_DOCS: Container<'static> = Container {
    identifier: "com.apple.CloudDocs",
    bundle_id: "com.apple.clouddocs",
    database: Database::Private,
};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct UserId(String);

impl AsRef<str> for UserId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Error)]
pub enum ContainerInitError {
    #[error("Cannot generate device authentication data: {0}")]
    Anisette(#[from] ADIError),
    #[error("CloudKit initialization failed: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Cannot parse CloudKit initialization: {0}")]
    Parsing(#[from] serde_json::Error),
    #[error("CloudKit returned an empty user identifier")]
    EmptyUserId,
}

impl Container<'_> {
    /// Resolve the container-scoped user ID using the iCloud setup credential.
    /// This does not create zones, recover keys, or register for push notifications.
    pub async fn initialize(
        &self,
        session: &AccountHTTPSession<'_, '_>,
        dsid: &Dsid,
        token: &MmeAuthToken,
    ) -> Result<UserId, ContainerInitError> {
        #[derive(Deserialize)]
        struct Response {
            #[serde(rename = "cloudKitUserId")]
            user_id: UserId,
        }

        let request = session.anisette_request_builder(
            Method::POST,
            "https://setup.icloud.com/setup/ck/v1/ckAppInit",
        )?;
        let response = self
            .request_headers(request)
            .header("Accept", "application/json")
            .basic_auth(dsid.as_ref(), Some(token.as_ref()))
            .query(&[("container", self.identifier)])
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        let response: Response = serde_json::from_slice(&response)?;
        if response.user_id.0.is_empty() {
            return Err(ContainerInitError::EmptyUserId);
        }
        Ok(response.user_id)
    }

    fn request_headers(&self, request: RequestBuilder) -> RequestBuilder {
        request
            .header("X-CloudKit-BundleId", self.bundle_id)
            .header("X-CloudKit-ContainerId", self.identifier)
            .header("X-CloudKit-DatabaseScope", self.database.as_str())
            .header("X-CloudKit-Environment", "production")
            .header(
                "X-Apple-Request-UUID",
                uuid::Uuid::new_v4().to_string().to_uppercase(),
            )
    }
}

/// A native CloudKit request context. MMe/PET credentials are not retained here.
///
/// Operation bodies use CloudKit's delimited protobuf protocol; this is not the
/// developer-facing CloudKit JSON API. Drive records and transfers are not yet
/// implemented by this crate.
pub struct CloudKitSession<'lt, 'adi, 'container> {
    pub http_session: AccountHTTPSession<'lt, 'adi>,
    pub container: Container<'container>,
    pub user_id: UserId,
    token: CloudKitToken,
}

impl<'lt, 'adi, 'container> CloudKitSession<'lt, 'adi, 'container> {
    pub fn new(
        http_session: AccountHTTPSession<'lt, 'adi>,
        container: Container<'container>,
        user_id: UserId,
        token: CloudKitToken,
    ) -> Self {
        Self {
            http_session,
            container,
            user_id,
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

    pub fn cloudkit_request_builder(&self, method: Method, url: &str) -> ADIResult<RequestBuilder> {
        Ok(self
            .container
            .request_headers(self.anisette_request_builder(method, url)?)
            .header("X-CloudKit-UserId", self.user_id.as_ref())
            .header("X-CloudKit-AuthToken", self.token.as_ref())
            .header("Accept", "application/x-protobuf")
            .header(
                "Content-Type",
                "application/x-protobuf; messageType=RequestOperation; delimited=true",
            ))
    }
}
