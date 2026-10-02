//! Apple's public Xcode download catalog. MobileAsset entries need separate
//! resolution before downloading; this module only fetches and parses the index.

use plist::{Dictionary, Value};
use reqwest::{Client, Url};
use serde::{Deserialize, de::DeserializeOwned};
use thiserror::Error;

pub const DOWNLOAD_CATALOG_URL: &str =
    "https://devimages-cdn.apple.com/downloads/xcode/simulators/index2.dvtdownloadableindex";

#[derive(Debug, Clone)]
pub enum DownloadSource {
    Direct(Url),
    /// Resolve using the download identifier and its runtime/component metadata.
    MobileAsset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ContentType {
    Package,
    DiskImage,
    CryptexDiskImage,
    Directory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum Platform {
    #[serde(rename = "com.apple.platform.iphoneos")]
    IOS,
    #[serde(rename = "com.apple.platform.appletvos")]
    TvOS,
    #[serde(rename = "com.apple.platform.watchos")]
    WatchOS,
    #[serde(rename = "com.apple.platform.macosx")]
    MacOS,
    #[serde(rename = "com.apple.platform.xros")]
    VisionOS,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum ComponentKind {
    #[serde(rename = "xcodeDeviceSupport")]
    DeviceSupport,
    #[serde(rename = "metalToolchain")]
    MetalToolchain,
    #[serde(rename = "developerDocumentation")]
    DeveloperDocumentation,
}

#[derive(Debug, Clone)]
pub struct Download {
    pub identifier: String,
    pub name: String,
    /// Advertised file size in bytes.
    pub size: u64,
    pub content_type: ContentType,
    pub source: DownloadSource,
    /// Apple's value, such as `virtual` or `none`. Absence does not imply
    /// anonymous access, and a direct URL may still require authentication.
    pub authentication: Option<String>,
    pub dictionary_version: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostRequirements {
    pub min_host_version: Option<String>,
    pub max_host_version: Option<String>,
    pub min_xcode_version: Option<String>,
    pub max_xcode_version: Option<String>,
    #[serde(default)]
    pub excluded_host_architectures: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SimulatorRuntime {
    pub download: Download,
    pub platform: Platform,
    pub version: String,
    pub build: String,
    /// The catalog's package version, distinct from the simulated OS version.
    pub download_version: String,
    /// Architectures explicitly advertised by Apple, when supplied.
    pub architectures: Option<Vec<String>>,
    pub host_requirements: HostRequirements,
    pub is_internal_content: Option<bool>,
    pub is_user_initiated: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct Component {
    pub download: Download,
    pub kind: ComponentKind,
    pub build: String,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Affinity {
    Available,
    Preferred,
    Unavailable,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SdkSeedMapping {
    pub build_update: String,
    pub platform: Platform,
    pub seed_number: u64,
    pub identifier: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SdkSimulatorMapping {
    pub sdk_build_update: String,
    pub sdk_identifier: String,
    pub simulator_build_update: String,
    /// Normalizes the singular and plural catalog fields. Empty means the
    /// mapping names the simulator by build rather than download identifier.
    pub downloadable_identifiers: Vec<String>,
    pub affinity: Option<Affinity>,
    pub group_tag: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XcodeRelease {
    Build(String),
    Version(String),
}

#[derive(Debug, Clone)]
pub struct XcodeComponentMapping {
    pub xcode: XcodeRelease,
    pub kind: ComponentKind,
    pub build: String,
    /// Some mappings identify the component by kind and build alone.
    pub downloadable_identifier: Option<String>,
    pub affinity: Affinity,
}

#[derive(Debug, Clone)]
pub struct DownloadCatalog {
    pub version: String,
    /// Apple's suggested refresh interval in seconds.
    pub refresh_interval: u64,
    pub simulators: Vec<SimulatorRuntime>,
    pub components: Vec<Component>,
    pub sdk_to_seed_mappings: Vec<SdkSeedMapping>,
    pub sdk_to_simulator_mappings: Vec<SdkSimulatorMapping>,
    pub xcode_to_component_mappings: Vec<XcodeComponentMapping>,
}

#[derive(Debug, Error)]
pub enum CatalogFetchError {
    #[error("Failed to fetch the download catalog: {0}")]
    Reqwest(#[source] reqwest::Error),
    #[error("Failed to parse the download catalog: {0}")]
    Parsing(#[source] CatalogParseError),
}

#[derive(Debug, Error)]
pub enum CatalogParseError {
    #[error("Invalid catalog plist: {0}")]
    Plist(#[source] plist::Error),
    #[error("Missing catalog field: {0}")]
    MissingField(String),
    #[error("Invalid catalog field {path}: {source}")]
    InvalidField {
        path: String,
        #[source]
        source: plist::Error,
    },
    #[error("Invalid catalog structure at {path}: {reason}")]
    Structure { path: String, reason: &'static str },
}

impl DownloadCatalog {
    /// Fetch the public index with the caller's HTTP client. No Xcode session
    /// or Apple account credentials are required.
    pub async fn fetch(client: &Client) -> Result<Self, CatalogFetchError> {
        let bytes = client
            .get(DOWNLOAD_CATALOG_URL)
            .send()
            .await
            .map_err(CatalogFetchError::Reqwest)?
            .error_for_status()
            .map_err(CatalogFetchError::Reqwest)?
            .bytes()
            .await
            .map_err(CatalogFetchError::Reqwest)?;
        Self::from_bytes(&bytes).map_err(CatalogFetchError::Parsing)
    }

    /// Parse an XML or binary plist. Unknown dictionary keys are ignored;
    /// unsupported enum values and malformed entries are reported as errors.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CatalogParseError> {
        let value =
            Value::from_reader(std::io::Cursor::new(bytes)).map_err(CatalogParseError::Plist)?;
        let dict = dictionary(&value, "catalog")?;
        Ok(Self {
            version: field(dict, "catalog", "version")?,
            refresh_interval: field(dict, "catalog", "refreshInterval")?,
            simulators: entries(dict, "downloadables", SimulatorRuntime::parse)?,
            components: entries(dict, "otherDownloadables", Component::parse)?,
            sdk_to_seed_mappings: entries(dict, "sdkToSeedMappings", |value, path| {
                plist::from_value(value).map_err(|source| CatalogParseError::InvalidField {
                    path: path.to_owned(),
                    source,
                })
            })?,
            sdk_to_simulator_mappings: entries(
                dict,
                "sdkToSimulatorMappings",
                SdkSimulatorMapping::parse,
            )?,
            xcode_to_component_mappings: entries(
                dict,
                "xcodeToOtherDownloadablesMappings",
                XcodeComponentMapping::parse,
            )?,
        })
    }
}

impl Download {
    fn parse(
        dict: &Dictionary,
        path: &str,
        size_key: &'static str,
        url_key: &'static str,
    ) -> Result<Self, CatalogParseError> {
        let method: Option<String> = optional_field(dict, path, "downloadMethod")?;
        let url: Option<String> = optional_field(dict, path, url_key)?;
        let source = match (method.as_deref(), url) {
            (None, Some(url)) => {
                let url = Url::parse(&url).map_err(|_| CatalogParseError::Structure {
                    path: format!("{path}.{url_key}"),
                    reason: "expected an absolute HTTP or HTTPS URL",
                })?;
                if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                    return Err(CatalogParseError::Structure {
                        path: format!("{path}.{url_key}"),
                        reason: "expected an absolute HTTP or HTTPS URL",
                    });
                }
                DownloadSource::Direct(url)
            }
            (Some("mobileAsset"), None) => DownloadSource::MobileAsset,
            _ => {
                return Err(CatalogParseError::Structure {
                    path: format!("{path}.downloadMethod"),
                    reason: "expected a direct source URL or downloadMethod = mobileAsset, exclusively",
                });
            }
        };
        Ok(Self {
            identifier: field(dict, path, "identifier")?,
            name: field(dict, path, "name")?,
            size: field(dict, path, size_key)?,
            content_type: field(dict, path, "contentType")?,
            source,
            authentication: optional_field(dict, path, "authentication")?,
            dictionary_version: field(dict, path, "dictionaryVersion")?,
        })
    }
}

impl SimulatorRuntime {
    fn parse(value: &Value, path: &str) -> Result<Self, CatalogParseError> {
        let dict = dictionary(value, path)?;
        if field::<String>(dict, path, "category")? != "simulator" {
            return Err(CatalogParseError::Structure {
                path: format!("{path}.category"),
                reason: "expected simulator",
            });
        }
        let version_path = format!("{path}.simulatorVersion");
        let version = dictionary(
            required_value(dict, path, "simulatorVersion")?,
            &version_path,
        )?;
        Ok(Self {
            download: Download::parse(dict, path, "fileSize", "source")?,
            platform: field(dict, path, "platform")?,
            version: field(version, &version_path, "version")?,
            build: field(version, &version_path, "buildUpdate")?,
            download_version: field(dict, path, "version")?,
            architectures: optional_field(dict, path, "architectures")?,
            host_requirements: optional_field(dict, path, "hostRequirements")?.unwrap_or_default(),
            is_internal_content: optional_field(dict, path, "isInternalContent")?,
            is_user_initiated: optional_field(dict, path, "isUserInitiated")?,
        })
    }
}

impl Component {
    fn parse(value: &Value, path: &str) -> Result<Self, CatalogParseError> {
        let dict = dictionary(value, path)?;
        Ok(Self {
            download: Download::parse(dict, path, "fileSizeBytes", "sourceURL")?,
            kind: field(dict, path, "assetType")?,
            build: field(dict, path, "assetBuildUpdate")?,
            description: field(dict, path, "description")?,
        })
    }
}

impl SdkSimulatorMapping {
    fn parse(value: &Value, path: &str) -> Result<Self, CatalogParseError> {
        let dict = dictionary(value, path)?;
        let identifier: Option<String> = optional_field(dict, path, "downloadableIdentifier")?;
        let identifiers: Option<Vec<String>> =
            optional_field(dict, path, "downloadableIdentifiers")?;
        let downloadable_identifiers = match (identifier, identifiers) {
            (Some(identifier), None) => vec![identifier],
            (None, Some(identifiers)) => identifiers,
            (None, None) => Vec::new(),
            (Some(_), Some(_)) => {
                return Err(CatalogParseError::Structure {
                    path: format!("{path}.downloadableIdentifiers"),
                    reason: "both singular and plural download identifiers are present",
                });
            }
        };
        Ok(Self {
            sdk_build_update: field(dict, path, "sdkBuildUpdate")?,
            sdk_identifier: field(dict, path, "sdkIdentifier")?,
            simulator_build_update: field(dict, path, "simulatorBuildUpdate")?,
            downloadable_identifiers,
            affinity: optional_field(dict, path, "affinity")?,
            group_tag: optional_field(dict, path, "groupTag")?,
        })
    }
}

impl XcodeComponentMapping {
    fn parse(value: &Value, path: &str) -> Result<Self, CatalogParseError> {
        let dict = dictionary(value, path)?;
        let build: Option<String> = optional_field(dict, path, "xcodeBuildUpdate")?;
        let version: Option<String> = optional_field(dict, path, "xcodeVersion")?;
        let xcode = match (build, version) {
            (Some(build), None) => XcodeRelease::Build(build),
            (None, Some(version)) => XcodeRelease::Version(version),
            _ => {
                return Err(CatalogParseError::Structure {
                    path: path.to_owned(),
                    reason: "expected exactly one of xcodeBuildUpdate and xcodeVersion",
                });
            }
        };
        Ok(Self {
            xcode,
            kind: field(dict, path, "assetType")?,
            build: field(dict, path, "assetBuildUpdate")?,
            downloadable_identifier: optional_field(dict, path, "downloadableIdentifier")?,
            affinity: field(dict, path, "affinity")?,
        })
    }
}

fn dictionary<'a>(value: &'a Value, path: &str) -> Result<&'a Dictionary, CatalogParseError> {
    value
        .as_dictionary()
        .ok_or_else(|| CatalogParseError::Structure {
            path: path.to_owned(),
            reason: "expected a dictionary",
        })
}

fn required_value<'a>(
    dict: &'a Dictionary,
    path: &str,
    name: &str,
) -> Result<&'a Value, CatalogParseError> {
    dict.get(name)
        .ok_or_else(|| CatalogParseError::MissingField(format!("{path}.{name}")))
}

fn field<T: DeserializeOwned>(
    dict: &Dictionary,
    path: &str,
    name: &str,
) -> Result<T, CatalogParseError> {
    plist::from_value(required_value(dict, path, name)?).map_err(|source| {
        CatalogParseError::InvalidField {
            path: format!("{path}.{name}"),
            source,
        }
    })
}

fn optional_field<T: DeserializeOwned>(
    dict: &Dictionary,
    path: &str,
    name: &str,
) -> Result<Option<T>, CatalogParseError> {
    dict.get(name).map(|_| field(dict, path, name)).transpose()
}

fn entries<T>(
    dict: &Dictionary,
    name: &str,
    parse: impl Fn(&Value, &str) -> Result<T, CatalogParseError>,
) -> Result<Vec<T>, CatalogParseError> {
    let values = required_value(dict, "catalog", name)?
        .as_array()
        .ok_or_else(|| CatalogParseError::Structure {
            path: name.to_owned(),
            reason: "expected an array",
        })?;
    values
        .iter()
        .enumerate()
        .map(|(index, value)| parse(value, &format!("{name}[{index}]")))
        .collect()
}
