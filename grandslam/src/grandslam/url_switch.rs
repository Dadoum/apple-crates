use crate::grandslam::parse_url_bag_response;
use crate::http_session::{AppleError, HTTPSession, URLBagError};
use reqwest::Method;
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum URLSwitchingError {
    Reqwest(reqwest::Error),
    AppleError(AppleError),
    URLBag(URLBagError),
}

impl Display for URLSwitchingError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            URLSwitchingError::Reqwest(err) => {
                write!(f, "Failed to connect to server: {err}")
            }
            URLSwitchingError::AppleError(err) => {
                write!(f, "Failed to perform the URL switch: {err}")
            }
            URLSwitchingError::URLBag(err) => {
                write!(f, "Failed to parse the provided URL bag: {err}")
            }
        }
    }
}

impl Error for URLSwitchingError {}

pub async fn url_switch(
    http_session: &mut HTTPSession<'_>,
    url: &str,
    idata: &str,
) -> Result<(), URLSwitchingError> {
    let url_bag_response = http_session
        .request_builder(Method::GET, url)
        .query(&[("idata", idata.to_string())])
        .send()
        .await
        .map_err(URLSwitchingError::Reqwest)?
        .error_for_status()
        .map_err(URLSwitchingError::Reqwest)?
        .bytes()
        .await
        .map_err(URLSwitchingError::Reqwest)?;

    let url_bag = parse_url_bag_response(url_bag_response).map_err(URLSwitchingError::URLBag)?;

    http_session.url_switch(url_bag);

    Ok(())
}
