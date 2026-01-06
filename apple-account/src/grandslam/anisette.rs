use crate::http_session::{AnisetteHTTPSession, AppleError, parse_status};
use adi::proxy::ADIError;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use plist::{Dictionary, Value};
use plist_macros::dict;
use reqwest::Method;
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum ProvisioningError {
    ADIError(ADIError),
    AppleError(AppleError),
    URLNotFound(String),
    StartProvisioningRequest(reqwest::Error),
    StartProvisioningRequestPlist(plist::Error),
    StartProvisioningRequestStructure(Dictionary),
    FinishProvisioningRequest(reqwest::Error),
    FinishProvisioningRequestPlist(plist::Error),
    FinishProvisioningRequestStructure(Dictionary),
}

impl Display for ProvisioningError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            ProvisioningError::ADIError(err) => write!(
                f,
                "An internal error has been encountered while provisioning the device: {err}"
            ),
            ProvisioningError::StartProvisioningRequest(err) => {
                write!(f, "The first provisioning request errored: {err}")
            }
            ProvisioningError::StartProvisioningRequestPlist(err) => write!(
                f,
                "The first provisioning request could not be parsed: {err}"
            ),
            ProvisioningError::StartProvisioningRequestStructure(plist) => write!(
                f,
                "The first provisioning request could not be parsed: {plist:?}"
            ),
            ProvisioningError::AppleError(err) => write!(f, "Provisioning failed: {err:?}"),
            ProvisioningError::FinishProvisioningRequest(err) => {
                write!(f, "The second provisioning request errored: {err}")
            }
            ProvisioningError::FinishProvisioningRequestPlist(err) => write!(
                f,
                "The second provisioning request could not be parsed: {err}"
            ),
            ProvisioningError::FinishProvisioningRequestStructure(plist) => write!(
                f,
                "The second provisioning request could not be parsed: {plist:?}"
            ),
            ProvisioningError::URLNotFound(url) => {
                write!(f, "Endpoint not found in the URL bag: {url}")
            }
        }
    }
}

impl Error for ProvisioningError {}

pub const GRANDSLAM_DSID: i64 = -2;

pub async fn provision(
    http_session: &AnisetteHTTPSession<'_, '_>,
) -> Result<(), ProvisioningError> {
    let adi_proxy = http_session.adi_proxy();

    let mid_start_provisioning_url = http_session
        .url_bag()
        .get("midStartProvisioning")
        .and_then(Value::as_string)
        .ok_or(ProvisioningError::URLNotFound(
            "midStartProvisioning".into(),
        ))?;

    let start_provisioning_request_builder =
        http_session.simple_request_builder(Method::GET, mid_start_provisioning_url);

    let start_provisioning_response = start_provisioning_request_builder
        .send()
        .await
        .map_err(ProvisioningError::StartProvisioningRequest)?;

    let start_provisioning_plist: Dictionary = plist::from_bytes(
        &start_provisioning_response
            .bytes()
            .await
            .map_err(ProvisioningError::StartProvisioningRequest)?,
    )
    .map_err(ProvisioningError::StartProvisioningRequestPlist)?;

    let spim = start_provisioning_plist
        .get("Response")
        .and_then(|response| response.as_dictionary())
        .and_then(|response| response.get("spim"))
        .and_then(|spim| spim.as_string())
        .ok_or(ProvisioningError::StartProvisioningRequestStructure(
            start_provisioning_plist.clone(),
        ))?;

    let spim = BASE64_STANDARD.decode(spim).map_err(|_| {
        ProvisioningError::StartProvisioningRequestStructure(start_provisioning_plist.clone())
    })?;

    let (cpim, session) = adi_proxy
        .start_provisioning(GRANDSLAM_DSID, &spim)
        .map_err(ProvisioningError::ADIError)?;

    let mid_finish_provisioning_url = http_session
        .url_bag()
        .get("midFinishProvisioning")
        .and_then(Value::as_string)
        .ok_or(ProvisioningError::URLNotFound(
            "midFinishProvisioning".into(),
        ))?;

    // Soon try blocks will come to Rust :,)
    let ptm_tk_result = async {
        let finish_provisioning_request_builder =
            http_session.simple_request_builder(Method::POST, mid_finish_provisioning_url);

        let mut response = Dictionary::new();
        response.insert("cpim".into(), Value::String(BASE64_STANDARD.encode(cpim)));

        let mut finish_provisioning_request_dict = Dictionary::new();
        finish_provisioning_request_dict.insert("Request".into(), Value::Dictionary(response));

        let mut finish_provisioning_request_body = Vec::<u8>::new();
        plist::to_writer_xml(
            &mut finish_provisioning_request_body,
            &finish_provisioning_request_dict,
        )
        .expect("Cannot write response plist??");

        // println!("{}", String::from_utf8(finish_provisioning_request_body.clone()).unwrap());

        let finish_provisioning_response = finish_provisioning_request_builder
            .body(finish_provisioning_request_body)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send()
            .await
            .map_err(ProvisioningError::FinishProvisioningRequest)?;

        let finish_provisioning_plist: Dictionary = plist::from_bytes(
            &finish_provisioning_response
                .bytes()
                .await
                .map_err(ProvisioningError::FinishProvisioningRequest)?,
        )
        .map_err(ProvisioningError::FinishProvisioningRequestPlist)?;

        let finish_provisioning_response_plist = finish_provisioning_plist
            .get("Response")
            .and_then(|response| response.as_dictionary())
            .ok_or(ProvisioningError::FinishProvisioningRequestStructure(
                finish_provisioning_plist.clone(),
            ))?;

        finish_provisioning_response_plist
            .get("Status")
            .and_then(|status| status.as_dictionary())
            .map(|status| parse_status(status).map_err(ProvisioningError::AppleError))
            .transpose()?;

        let ptm = finish_provisioning_response_plist
            .get("ptm")
            .and_then(|ptm| ptm.as_string())
            .ok_or(ProvisioningError::FinishProvisioningRequestStructure(
                finish_provisioning_plist.clone(),
            ))?;
        let ptm = BASE64_STANDARD.decode(ptm).map_err(|_| {
            ProvisioningError::FinishProvisioningRequestStructure(finish_provisioning_plist.clone())
        })?;

        let tk = finish_provisioning_response_plist
            .get("tk")
            .and_then(|tk| tk.as_string())
            .ok_or(ProvisioningError::FinishProvisioningRequestStructure(
                finish_provisioning_plist.clone(),
            ))?;
        let tk = BASE64_STANDARD.decode(tk).map_err(|_| {
            ProvisioningError::FinishProvisioningRequestStructure(finish_provisioning_plist.clone())
        })?;

        let routing_info = finish_provisioning_response_plist
            .get("X-Apple-I-MD-RINFO")
            .and_then(|tk| tk.as_string())
            .ok_or(ProvisioningError::FinishProvisioningRequestStructure(
                finish_provisioning_plist.clone(),
            ))?
            .parse()
            .map_err(|_| {
                ProvisioningError::FinishProvisioningRequestStructure(
                    finish_provisioning_plist.clone(),
                )
            })?;

        Ok((ptm, tk, routing_info))
    }
    .await;

    match ptm_tk_result {
        Ok((ptm, tk, routing_info)) => {
            adi_proxy
                .end_provisioning(session, &ptm, &tk)
                .map_err(ProvisioningError::ADIError)?;

            adi_proxy
                .set_idms_routing(GRANDSLAM_DSID, routing_info)
                .map_err(ProvisioningError::ADIError)
        }
        Err(e) => {
            adi_proxy
                .destroy_provisioning_session(session)
                .map_err(ProvisioningError::ADIError)?;

            Err(e)
        }
    }
}

#[derive(Debug)]
pub enum SyncError {
    ADI(ADIError),
    Apple(AppleError),
    Network(reqwest::Error),
    Parsing(plist::Error),
    ResponseStructure(Dictionary),
    URLNotFound,
}

impl Display for SyncError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Self::ADI(e) => write!(f, "ADI error: {e}"),
            Self::Apple(e) => write!(f, "Apple error: {e}"),
            Self::Network(e) => write!(f, "Network error: {e}"),
            Self::Parsing(e) => write!(f, "Parsing error: {e}"),
            Self::ResponseStructure(dict) => write!(f, "Invalid response: {dict:?}"),
            Self::URLNotFound => write!(f, "URL not found"),
        }
    }
}

impl Error for SyncError {}

pub async fn sync_machine(
    http_session: &AnisetteHTTPSession<'_, '_>,
    sim: &[u8],
) -> Result<(), SyncError> {
    let adi_proxy = http_session.adi_proxy();

    let (mid, srm) = adi_proxy
        .synchronize(GRANDSLAM_DSID, sim)
        .map_err(SyncError::ADI)?;

    let sync_machine_request_plist = dict! {
        "Header": Dictionary::new(),
        "Request": dict!{
            "X-Apple-I-MD-M": BASE64_STANDARD.encode(mid),
            "srm": BASE64_STANDARD.encode(srm)
        }
    };

    let mid_sync_machine_url = http_session
        .url_bag()
        .get("midSyncMachine")
        .and_then(Value::as_string)
        .ok_or(SyncError::URLNotFound)?;

    let sync_machine_request_builder =
        http_session.simple_request_builder(Method::GET, mid_sync_machine_url);

    let mut sync_machine_request_body = Vec::<u8>::new();
    plist::to_writer_xml(&mut sync_machine_request_body, &sync_machine_request_plist)
        .expect("Cannot write response plist??");

    let sync_machine_response = sync_machine_request_builder
        .body(sync_machine_request_body)
        .header("Content-Type", "text/x-xml-plist")
        .send()
        .await
        .map_err(SyncError::Network)?
        .bytes()
        .await
        .map_err(SyncError::Network)?;

    let sync_machine_response_plist: Dictionary =
        plist::from_bytes(&sync_machine_response).map_err(SyncError::Parsing)?;

    sync_machine_response_plist
        .get("Response")
        .and_then(|response| response.as_dictionary())
        .and_then(|response| response.get("Status"))
        .and_then(|response| response.as_dictionary())
        .map(|status| parse_status(status).map_err(SyncError::Apple))
        .ok_or(SyncError::ResponseStructure(
            sync_machine_response_plist.clone(),
        ))?
}
