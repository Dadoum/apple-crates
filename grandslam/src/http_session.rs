use crate::bundle_information::{AUTH_KIT_BUNDLE_INFORMATION, BundleInformation};
use crate::device::Device;
use adi::proxy::{ADIProxy, ADIResult};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use chrono::{Local, SecondsFormat};
use plist::Dictionary;
use reqwest::header::{HeaderMap, InvalidHeaderValue};
use reqwest::{Certificate, Client, Method, RequestBuilder};
use std::error::Error;
use std::fmt::{Display, Formatter};

const SIMULATED_AUTHENTICATION_FRAMEWORK_INFORMATION: BundleInformation =
    AUTH_KIT_BUNDLE_INFORMATION;

/// Error returned by Apple servers' endpoints
#[derive(Debug)]
pub struct AppleError {
    // description: String,
    pub code: i64,
    pub message: String,
}

impl Display for AppleError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

impl Error for AppleError {}

pub type URLBag = Dictionary;

#[derive(Debug)]
pub enum URLBagError {
    InvalidUrlBag,
    Parsing,
}

impl Display for URLBagError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            URLBagError::InvalidUrlBag => {
                write!(f, "The provided URL bag is invalid")
            }
            URLBagError::Parsing => {
                write!(f, "Unable to parse the provided URL bag")
            }
        }
    }
}

impl Error for URLBagError {}

/// Parse the Status field of an Apple server Response.
/// Returns the AppleError if there is one reported.
pub fn parse_status(status_dict: &Dictionary) -> Result<(), AppleError> {
    match (
        status_dict["ec"].as_signed_integer(),
        // status_dict["ed"].as_string(),
        status_dict["em"].as_string(),
    ) {
        (Some(ec), Some(em)) if ec != 0 => {
            Err(AppleError {
                // description: ed.to_string(),
                code: ec,
                message: em.to_string(),
            })
        }
        _ => Ok(()),
    }
}

/// Abstracts a session with Apple servers.
pub struct BasicHTTPSession<'lt> {
    pub client: Client,
    pub device: Device,
    pub application_info: BundleInformation<'lt>,
}

pub struct HTTPSession<'lt> {
    pub http_session: BasicHTTPSession<'lt>,
    pub url_bag: URLBag,
}

#[derive(Debug)]
pub enum HTTPSessionCreationError {
    InvalidHeader(InvalidHeaderValue),
    Reqwest(reqwest::Error),
    InvalidURLBagResponsePlist(URLBagError),
    InvalidURLBagResponseStructure,
}

impl Display for HTTPSessionCreationError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        // TODO write better errors maybe?
        write!(f, "{self:?}")
    }
}

impl Error for HTTPSessionCreationError {}

impl<'lt> BasicHTTPSession<'lt> {
    pub fn new(
        device: Device,
        client_bundle_info: BundleInformation<'lt>,
        custom_certificate: Option<Certificate>,
    ) -> Result<Self, HTTPSessionCreationError> {
        let client_builder = Client::builder().danger_accept_invalid_certs(true);
        let client_builder = match custom_certificate {
            Some(certificate) => client_builder.add_root_certificate(certificate),
            None => client_builder,
        };

        let headers = {
            let mut headers = HeaderMap::new();
            headers.insert(
                "User-Agent",
                format!(
                    "{}/{}",
                    client_bundle_info.bundle_name, client_bundle_info.bundle_version
                )
                .parse()
                .map_err(HTTPSessionCreationError::InvalidHeader)?,
            );
            headers.insert(
                "X-MMe-Client-Info",
                device
                    .server_friendly_description(
                        &SIMULATED_AUTHENTICATION_FRAMEWORK_INFORMATION,
                        &client_bundle_info,
                    )
                    .parse()
                    .map_err(HTTPSessionCreationError::InvalidHeader)?,
            );
            headers.insert(
                "X-Mme-Device-Id",
                device
                    .device_uuid
                    .parse()
                    .map_err(HTTPSessionCreationError::InvalidHeader)?,
            );
            headers.insert(
                "X-Apple-Client-App-Name",
                client_bundle_info
                    .bundle_name
                    .parse()
                    .map_err(HTTPSessionCreationError::InvalidHeader)?,
            );

            headers
        };

        let client = client_builder
            .default_headers(headers)
            // .connection_verbose(true)
            // .http1_title_case_headers()
            .build()
            .map_err(HTTPSessionCreationError::Reqwest)?;

        Ok(BasicHTTPSession {
            client,
            device,
            application_info: client_bundle_info,
        })
    }

    pub fn device(&self) -> &Device {
        &self.device
    }

    pub fn application_information(&self) -> &BundleInformation<'_> {
        &self.application_info
    }

    pub fn request_builder(&self, method: Method, url: &str) -> RequestBuilder {
        let client_time = Local::now()
            .to_utc()
            .to_rfc3339_opts(SecondsFormat::Secs, true);
        self.client
            .request(method, url)
            .header("X-Apple-I-Client-Time", client_time)
    }
}

impl<'lt> HTTPSession<'lt> {
    pub fn new(
        http_session: BasicHTTPSession<'lt>,
        url_bag: URLBag,
    ) -> Result<Self, HTTPSessionCreationError> {
        Ok(Self {
            http_session,
            url_bag,
        })
    }

    pub fn url_switch(&mut self, url_bag: URLBag) {
        self.url_bag = url_bag;
    }

    pub fn device(&self) -> &Device {
        self.http_session.device()
    }

    pub fn application_information(&self) -> &BundleInformation<'_> {
        self.http_session.application_information()
    }

    pub fn url_bag(&self) -> &URLBag {
        &self.url_bag
    }

    pub fn request_builder(&self, method: Method, url: &str) -> RequestBuilder {
        self.http_session.request_builder(method, url)
    }
}

pub struct AnisetteHTTPSession<'lt, 'adi> {
    pub http_session: HTTPSession<'lt>,
    pub adi_proxy: &'adi dyn ADIProxy,
}

impl<'lt, 'adi> AnisetteHTTPSession<'lt, 'adi> {
    pub fn new(http_session: HTTPSession<'lt>, adi_proxy: &'adi dyn ADIProxy) -> Self {
        Self {
            http_session,
            adi_proxy,
        }
    }

    pub fn url_bag(&self) -> &URLBag {
        self.http_session.url_bag()
    }

    pub fn simple_request_builder(&self, method: Method, url: &str) -> RequestBuilder {
        self.http_session.request_builder(method, url)
    }

    pub fn anisette_request_builder(&self, method: Method, url: &str) -> ADIResult<RequestBuilder> {
        let mut request_builder = self.simple_request_builder(method, url);

        if self.adi_proxy.is_machine_provisioned(-2)? {
            let ds_id = -2;

            let (mid_b, otp_b) = self.adi_proxy.request_otp(ds_id)?;

            let mid = BASE64_STANDARD.encode(mid_b);
            let otp = BASE64_STANDARD.encode(otp_b);

            let rinfo = self.adi_proxy.get_idms_routing(ds_id)?;

            request_builder = request_builder
                .header("X-Apple-I-MD", otp)
                .header("X-Apple-I-MD-M", mid)
                .header("X-Apple-I-MD-RINFO", rinfo);
        }

        if self.adi_proxy.is_machine_provisioned(-1)? {
            let ds_id = -1;

            let (mid_b, otp_b) = self.adi_proxy.request_otp(ds_id)?;

            let mid = BASE64_STANDARD.encode(mid_b);
            let otp = BASE64_STANDARD.encode(otp_b);

            let rinfo = self.adi_proxy.get_idms_routing(ds_id)?;

            request_builder = request_builder
                .header("X-Apple-I-AMD", otp)
                .header("X-Apple-I-AMD-M", mid)
                .header("X-Apple-I-AMD-RINFO", rinfo);
        }

        Ok(request_builder)
    }

    pub fn device(&self) -> &Device {
        self.http_session.device()
    }

    pub fn application_information(&self) -> &BundleInformation<'_> {
        self.http_session.application_information()
    }

    pub fn adi_proxy(&self) -> &dyn ADIProxy {
        self.adi_proxy
    }

    pub fn url_switch(&mut self, url_bag: URLBag) {
        self.http_session.url_switch(url_bag)
    }
}
