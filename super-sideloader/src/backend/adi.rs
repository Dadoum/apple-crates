use crate::backend::paths::app_data_dir;
use crate::backend::{runtime as backend_runtime, BackendError, BackendResult};
use crate::domain::{
    AdiBackend, AdiBackendAvailability, AdiBackendDetail, AdiBackendKind, AdiProvisioningState,
    AdiRepairAction, MachineIdentity,
};
use adi::core_adi::CoreADIADIProxy;
use adi::ADIProxy;
use async_zip::tokio::read::fs::ZipFileReader;
use futures_lite::io::AsyncReadExt;
use grandslam::bundle_information::{BundleInformation, AKD_BUNDLE_INFORMATION};
use grandslam::device::Device;
use grandslam::http_session::AnisetteHTTPSession;
use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::AsyncWriteExt as _;

const ANDROID_COREADI_APK_URL: &str =
    "https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk";
const ANDROID_COREADI_APK_FILE: &str = "applemusic.apk";
const ANDROID_COREADI_LIBRARY_FILE: &str = "libCoreADI.so";
const GRANDSLAM_DSID: i64 = -2;
const XCODE_BUNDLE_INFORMATION: BundleInformation<'static> = BundleInformation {
    bundle_name: "Xcode",
    bundle_identifier: "com.apple.dt.Xcode",
    bundle_version: "23792",
};

#[derive(Clone, Copy, Debug)]
pub(crate) struct AndroidCoreAdiInstallProgress {
    pub(crate) downloaded_bytes: u64,
    pub(crate) total_bytes: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum AndroidCoreAdiInstallEvent {
    Downloading(AndroidCoreAdiInstallProgress),
    Installing,
}

pub(crate) fn available_adi_backends(
    android_adi_identifier: &str,
    probe_provisioning: bool,
) -> Vec<AdiBackend> {
    let mut backends: Vec<_> = vec![
        system_adi_backend(),
        windows_coreadi_backend(),
        android_coreadi_backend(android_adi_identifier),
    ]
    .into_iter()
    .filter(|backend| backend.availability.is_available())
    .collect();

    for backend in &mut backends {
        backend.provisioning_state = if backend.availability.is_ready() && probe_provisioning {
            adi_provisioning_state(backend.kind, android_adi_identifier)
        } else {
            backend.provisioning_state.clone()
        };
    }

    backends
}

pub(crate) fn selected_adi_proxy(
    kind: AdiBackendKind,
    android_adi_identifier: &str,
) -> BackendResult<Box<dyn ADIProxy>> {
    match kind {
        AdiBackendKind::SystemAdid => system_adi_proxy(),
        AdiBackendKind::WindowsCoreAdi => windows_coreadi_proxy(),
        AdiBackendKind::AndroidCoreAdi => android_coreadi_proxy(android_adi_identifier),
    }
}

#[allow(dead_code)]
pub(crate) fn erase_adi_provisioning(
    kind: AdiBackendKind,
    android_adi_identifier: &str,
) -> BackendResult<()> {
    selected_adi_proxy(kind, android_adi_identifier)?
        .erase_provisioning(GRANDSLAM_DSID)
        .map_err(|error| BackendError::Adi(format!("Failed to erase ADI provisioning: {error}")))
}

pub(crate) async fn provision_adi(
    kind: AdiBackendKind,
    machine_identity: &MachineIdentity,
    android_adi_identifier: &str,
) -> BackendResult<()> {
    let machine_identity = machine_identity.clone();
    let android_adi_identifier = android_adi_identifier.to_string();
    backend_runtime::run("ADI provisioning", move || async move {
        provision_adi_async(kind, machine_identity, android_adi_identifier).await
    })
    .await?
}

async fn provision_adi_async(
    kind: AdiBackendKind,
    machine_identity: MachineIdentity,
    android_adi_identifier: String,
) -> BackendResult<()> {
    let proxy = selected_adi_proxy(kind, &android_adi_identifier)?;
    let http_session = grandslam::http_session(
        grandslam_device(&machine_identity, kind),
        AKD_BUNDLE_INFORMATION,
    )
    .await
    .map_err(|error| {
        BackendError::Network(format!(
            "Failed to create ADI provisioning session: {error}"
        ))
    })?;
    let anisette_session = AnisetteHTTPSession::new(http_session, proxy.as_ref());

    grandslam::provision(&anisette_session)
        .await
        .map_err(|error| BackendError::Adi(format!("Failed to provision ADI: {error}")))
}

pub(crate) fn grandslam_device(machine_identity: &MachineIdentity, kind: AdiBackendKind) -> Device {
    #[cfg(target_os = "windows")]
    if kind == AdiBackendKind::WindowsCoreAdi {
        let identity = crate::backend::system_identity::windows_machine_identity();
        return Device {
            device_model: identity.machine_name,
            operating_system_information: format!("{}; {}", identity.os_name, identity.os_version),
            device_uuid: identity.machine_id,
        };
    }
    #[cfg(not(target_os = "windows"))]
    let _ = kind;
    Device {
        device_model: machine_identity.machine_name.to_string(),
        operating_system_information: format!(
            "{};{}",
            machine_identity.os_name, machine_identity.os_version
        ),
        device_uuid: machine_identity.machine_id.to_string(),
    }
}

fn adi_provisioning_state(
    kind: AdiBackendKind,
    android_adi_identifier: &str,
) -> AdiProvisioningState {
    match selected_adi_proxy(kind, android_adi_identifier) {
        Ok(proxy) => match proxy.is_machine_provisioned(GRANDSLAM_DSID) {
            Ok(true) => AdiProvisioningState::Provisioned,
            Ok(false) => AdiProvisioningState::NotProvisioned,
            Err(error) => AdiProvisioningState::Error(error.to_string()),
        },
        Err(error) => AdiProvisioningState::Error(error.user_message()),
    }
}

#[cfg(target_os = "macos")]
fn system_adi_proxy() -> BackendResult<Box<dyn ADIProxy>> {
    Ok(Box::new(adid_proxy::ADIdProxy::connect()))
}

#[cfg(not(target_os = "macos"))]
fn system_adi_proxy() -> BackendResult<Box<dyn ADIProxy>> {
    Err(BackendError::Unsupported(
        "System ADI is only available on macOS.".to_string(),
    ))
}

#[cfg(target_os = "windows")]
fn windows_coreadi_proxy() -> BackendResult<Box<dyn ADIProxy>> {
    let library_path = find_windows_coreadi_library().ok_or_else(|| {
        BackendError::Adi(
            "A compatible CoreADI library was not found in the installed iTunes or iCloud folders."
                .into(),
        )
    })?;
    let proxy =
        library_coreadi::windows::WindowsCoreADIProxy::open(&library_path).map_err(|error| {
            BackendError::Adi(format!(
                "Failed to load {}: {error}",
                library_path.display()
            ))
        })?;
    Ok(Box::new(proxy))
}

#[cfg(not(target_os = "windows"))]
fn windows_coreadi_proxy() -> BackendResult<Box<dyn ADIProxy>> {
    Err(BackendError::Unsupported(
        "iTunes or iCloud CoreADI is only available on Windows.".to_string(),
    ))
}

fn android_coreadi_proxy(android_adi_identifier: &str) -> BackendResult<Box<dyn ADIProxy>> {
    let library_path = android_coreadi_library_path().ok_or_else(|| {
        BackendError::Unsupported("The application data folder is not available.".to_string())
    })?;
    let library_data = fs::read(&library_path).map_err(|error| BackendError::Io {
        action: "Read Apple Music CoreADI",
        path: library_path.clone(),
        source: error,
    })?;

    let proxy =
        android_coreadi::AndroidCoreADIProxy::load_library(library_data).map_err(|error| {
            BackendError::Adi(format!("Failed to load Apple Music CoreADI: {error}"))
        })?;
    CoreADIADIProxy::initialize(&proxy).map_err(|error| {
        BackendError::Adi(format!(
            "Apple Music CoreADI initialization failed: {error}"
        ))
    })?;

    let provisioning_path = android_coreadi_provisioning_path().ok_or_else(|| {
        BackendError::Unsupported("The application data folder is not available.".to_string())
    })?;
    fs::create_dir_all(&provisioning_path).map_err(|error| BackendError::Io {
        action: "Create CoreADI provisioning folder",
        path: provisioning_path.clone(),
        source: error,
    })?;
    let provisioning_path = c_string_from_path(&provisioning_path)?;
    CoreADIADIProxy::set_provisioning_path(&proxy, &provisioning_path).map_err(|error| {
        BackendError::Adi(format!(
            "Failed to configure CoreADI provisioning path: {error}"
        ))
    })?;

    if android_adi_identifier.len() != 16 {
        return Err(BackendError::Adi(format!(
            "Apple Music CoreADI ADI identifier must be 16 characters long, got {}.",
            android_adi_identifier.len()
        )));
    }
    CoreADIADIProxy::set_android_id(&proxy, android_adi_identifier).map_err(|error| {
        BackendError::Adi(format!(
            "Failed to configure CoreADI ADI identifier: {error}"
        ))
    })?;

    Ok(Box::new(proxy))
}

fn system_adi_backend() -> AdiBackend {
    #[cfg(target_os = "macos")]
    let availability = AdiBackendAvailability::Ready;

    #[cfg(not(target_os = "macos"))]
    let availability = AdiBackendAvailability::Unavailable;

    AdiBackend {
        kind: AdiBackendKind::SystemAdid,
        name: "System ADI".into(),
        detail: "Use the platform ADI provider.".into(),
        availability,
        details: vec![AdiBackendDetail {
            label: "Identity storage".into(),
            value: "System managed".into(),
        }],
        provisioning_state: AdiProvisioningState::Unknown,
        editable_identity: false,
        repair_action: None,
    }
}

fn windows_coreadi_backend() -> AdiBackend {
    let library_path = find_windows_coreadi_library();
    let availability = if cfg!(target_os = "windows") {
        if library_path.is_some() {
            AdiBackendAvailability::Ready
        } else {
            AdiBackendAvailability::NeedsSetup
        }
    } else {
        AdiBackendAvailability::Unavailable
    };

    AdiBackend {
        kind: AdiBackendKind::WindowsCoreAdi,
        name: "iTunes / iCloud CoreADI".into(),
        detail: "Load Apple's Windows ADI library.".into(),
        availability,
        details: vec![
            AdiBackendDetail {
                label: "Library path".into(),
                value: library_path
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "Not found".to_string()),
            },
            AdiBackendDetail {
                label: "Identity storage".into(),
                value: "Apple managed".into(),
            },
            #[cfg(target_os = "windows")]
            AdiBackendDetail {
                label: "Device identifier".into(),
                value: library_coreadi::windows::device_identifier(),
            },
        ],
        provisioning_state: AdiProvisioningState::Unknown,
        editable_identity: false,
        repair_action: (availability == AdiBackendAvailability::NeedsSetup)
            .then_some(AdiRepairAction::LocateLibrary),
    }
}

fn android_coreadi_backend(android_adi_identifier: &str) -> AdiBackend {
    let Some(abi) = android_coreadi_abi() else {
        return AdiBackend {
            kind: AdiBackendKind::AndroidCoreAdi,
            name: "Apple Music CoreADI".into(),
            detail: "Use Android's portable CoreADI library.".into(),
            availability: AdiBackendAvailability::Unavailable,
            details: vec![AdiBackendDetail {
                label: "Architecture".into(),
                value: "Unsupported".into(),
            }],
            provisioning_state: AdiProvisioningState::NotAvailable,
            editable_identity: false,
            repair_action: None,
        };
    };

    let library_path = android_coreadi_library_path();
    let availability = if library_path
        .as_ref()
        .is_some_and(|path| installed_library_exists(path))
    {
        AdiBackendAvailability::Ready
    } else {
        AdiBackendAvailability::NeedsSetup
    };
    let library_path_label = library_path
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "Not available".to_string());
    let provisioning_path_label = android_coreadi_provisioning_path()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "Not available".to_string());

    AdiBackend {
        kind: AdiBackendKind::AndroidCoreAdi,
        name: "Apple Music CoreADI".into(),
        detail: "Use Android's portable CoreADI library.".into(),
        availability,
        details: vec![
            AdiBackendDetail {
                label: "Library path".into(),
                value: library_path_label,
            },
            AdiBackendDetail {
                label: "APK ABI".into(),
                value: abi.into(),
            },
            AdiBackendDetail {
                label: "ADI identifier".into(),
                value: android_adi_identifier.to_string(),
            },
            AdiBackendDetail {
                label: "Provisioning path".into(),
                value: provisioning_path_label,
            },
        ],
        provisioning_state: if availability.is_ready() {
            AdiProvisioningState::Unknown
        } else {
            AdiProvisioningState::NotAvailable
        },
        editable_identity: true,
        repair_action: (availability == AdiBackendAvailability::NeedsSetup)
            .then_some(AdiRepairAction::InstallCoreAdi),
    }
}

pub(crate) fn android_coreadi_library_path() -> Option<PathBuf> {
    app_data_dir()
        .zip(android_coreadi_abi())
        .map(|(path, abi)| path.join(abi).join(ANDROID_COREADI_LIBRARY_FILE))
}

fn android_coreadi_apk_path() -> Option<PathBuf> {
    app_data_dir().map(|path| path.join(ANDROID_COREADI_APK_FILE))
}

fn android_coreadi_provisioning_path() -> Option<PathBuf> {
    app_data_dir().map(|path| path.join("coreadi"))
}

pub(crate) async fn download_android_coreadi_apk(
    mut progress: impl FnMut(AndroidCoreAdiInstallProgress),
) -> BackendResult<PathBuf> {
    let _ = android_coreadi_abi().ok_or_else(|| {
        BackendError::Unsupported(format!(
            "Apple Music CoreADI is not available for this CPU architecture ({})",
            std::env::consts::ARCH
        ))
    })?;
    let destination = android_coreadi_apk_path().ok_or_else(|| {
        BackendError::Unsupported("The application data folder is not available.".to_string())
    })?;
    if let Some(parent) = destination.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|error| BackendError::Io {
                action: "Create Apple Music APK folder",
                path: parent.to_path_buf(),
                source: error,
            })?;
    }

    let mut response = reqwest::Client::new()
        .get(ANDROID_COREADI_APK_URL)
        .send()
        .await
        .and_then(|response| response.error_for_status())
        .map_err(|error| {
            BackendError::Network(format!("Failed to download Apple Music APK: {error}"))
        })?;
    let total_bytes = response.content_length();
    let partial_destination = partial_file_path(&destination);
    let mut file = File::create(&partial_destination)
        .await
        .map_err(|error| BackendError::Io {
            action: "Create Apple Music APK",
            path: partial_destination.clone(),
            source: error,
        })?;
    let mut downloaded_bytes = 0;
    progress(AndroidCoreAdiInstallProgress {
        downloaded_bytes,
        total_bytes,
    });

    while let Some(chunk) = response.chunk().await.map_err(|error| {
        BackendError::Network(format!("Failed to download Apple Music APK: {error}"))
    })? {
        file.write_all(&chunk)
            .await
            .map_err(|error| BackendError::Io {
                action: "Save Apple Music APK",
                path: partial_destination.clone(),
                source: error,
            })?;
        downloaded_bytes += chunk.len() as u64;
        progress(AndroidCoreAdiInstallProgress {
            downloaded_bytes,
            total_bytes,
        });
    }

    file.flush().await.map_err(|error| BackendError::Io {
        action: "Flush Apple Music APK",
        path: partial_destination.clone(),
        source: error,
    })?;
    drop(file);

    if downloaded_bytes == 0 {
        let _ = tokio::fs::remove_file(&partial_destination).await;
        return Err(BackendError::Adi(
            "Downloaded Apple Music APK is empty.".to_string(),
        ));
    }

    publish_partial_file(
        &partial_destination,
        &destination,
        "Publish Apple Music APK",
    )
    .await?;

    Ok(destination)
}

fn installed_library_exists(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|metadata| metadata.is_file() && metadata.len() > 0)
}

fn partial_file_path(destination: &Path) -> PathBuf {
    let file_name = destination
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    destination.with_file_name(format!("{file_name}.part"))
}

async fn publish_partial_file(
    partial: &Path,
    destination: &Path,
    action: &'static str,
) -> BackendResult<()> {
    match tokio::fs::remove_file(destination).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(BackendError::Io {
                action,
                path: destination.to_path_buf(),
                source,
            });
        }
    }

    tokio::fs::rename(partial, destination)
        .await
        .map_err(|source| BackendError::Io {
            action,
            path: destination.to_path_buf(),
            source,
        })
}

pub(crate) async fn download_and_install_android_coreadi(
    mut progress: impl FnMut(AndroidCoreAdiInstallEvent) + Send + 'static,
) -> BackendResult<PathBuf> {
    backend_runtime::run_send_with("CoreADI install", move || async move {
        let apk_path = Box::pin(download_android_coreadi_apk(|download| {
            progress(AndroidCoreAdiInstallEvent::Downloading(download));
        }))
        .await?;
        progress(AndroidCoreAdiInstallEvent::Installing);
        Box::pin(install_android_coreadi_from_apk_async(apk_path)).await
    })
    .await?
}

#[allow(dead_code)]
pub(crate) async fn install_android_coreadi_from_apk(apk_path: PathBuf) -> BackendResult<PathBuf> {
    backend_runtime::run_send_with("CoreADI APK reader", move || {
        Box::pin(install_android_coreadi_from_apk_async(apk_path))
    })
    .await?
}

async fn install_android_coreadi_from_apk_async(apk_path: PathBuf) -> BackendResult<PathBuf> {
    let entry_name = android_coreadi_apk_entry().ok_or_else(|| {
        BackendError::Unsupported(format!(
            "Apple Music CoreADI is not available for this CPU architecture ({})",
            std::env::consts::ARCH
        ))
    })?;
    let reader = ZipFileReader::new(&apk_path).await.map_err(|error| {
        BackendError::Zip(format!(
            "Failed to read APK archive at {}: {error}",
            apk_path.display()
        ))
    })?;
    let entry_index = reader
        .file()
        .entries()
        .iter()
        .position(|entry| {
            entry
                .filename()
                .as_str()
                .is_ok_and(|filename| filename == entry_name)
        })
        .ok_or_else(|| BackendError::Zip(format!("APK does not contain {entry_name}.")))?;

    let mut entry_reader = reader
        .reader_without_entry(entry_index)
        .await
        .map_err(|error| BackendError::Zip(format!("Failed to read CoreADI from APK: {error}")))?;

    let destination = android_coreadi_library_path().ok_or_else(|| {
        BackendError::Unsupported("The application data folder is not available.".to_string())
    })?;
    if let Some(parent) = destination.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|error| BackendError::Io {
                action: "Create CoreADI folder",
                path: parent.to_path_buf(),
                source: error,
            })?;
    }
    let partial_destination = partial_file_path(&destination);
    let mut destination_file =
        File::create(&partial_destination)
            .await
            .map_err(|error| BackendError::Io {
                action: "Create CoreADI destination",
                path: partial_destination.clone(),
                source: error,
            })?;
    let mut written_bytes = 0u64;
    // Keep the extraction buffer out of the async state machine on the caller stack.
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = entry_reader.read(&mut buffer).await.map_err(|error| {
            BackendError::Zip(format!("Failed to extract CoreADI from APK: {error}"))
        })?;
        if read == 0 {
            break;
        }

        destination_file
            .write_all(&buffer[..read])
            .await
            .map_err(|error| BackendError::Io {
                action: "Store CoreADI",
                path: partial_destination.clone(),
                source: error,
            })?;
        written_bytes += read as u64;
    }

    destination_file
        .flush()
        .await
        .map_err(|error| BackendError::Io {
            action: "Flush CoreADI",
            path: partial_destination.clone(),
            source: error,
        })?;
    drop(destination_file);

    if written_bytes == 0 {
        let _ = tokio::fs::remove_file(&partial_destination).await;
        return Err(BackendError::Zip(
            "APK contains an empty CoreADI library.".to_string(),
        ));
    }

    publish_partial_file(&partial_destination, &destination, "Publish CoreADI").await?;

    Ok(destination)
}

#[cfg(target_arch = "aarch64")]
fn android_coreadi_abi() -> Option<&'static str> {
    Some("arm64-v8a")
}

#[cfg(target_arch = "arm")]
fn android_coreadi_abi() -> Option<&'static str> {
    Some("armeabi-v7a")
}

#[cfg(target_arch = "x86")]
fn android_coreadi_abi() -> Option<&'static str> {
    Some("x86")
}

#[cfg(target_arch = "x86_64")]
fn android_coreadi_abi() -> Option<&'static str> {
    Some("x86_64")
}

#[cfg(not(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "x86",
    target_arch = "x86_64"
)))]
fn android_coreadi_abi() -> Option<&'static str> {
    None
}

fn android_coreadi_apk_entry() -> Option<String> {
    android_coreadi_abi().map(|abi| format!("lib/{abi}/{ANDROID_COREADI_LIBRARY_FILE}"))
}

fn c_string_from_path(path: &Path) -> BackendResult<CString> {
    CString::new(path.to_string_lossy().into_owned())
        .map_err(|_| BackendError::Adi(format!("Path contains a null byte: {}", path.display())))
}

fn find_windows_coreadi_library() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        library_coreadi::windows::find_library()
    }
    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_future_does_not_embed_the_extraction_buffer() {
        let future = download_and_install_android_coreadi(|_| {});
        assert!(std::mem::size_of_val(&future) < 16 * 1024);
    }

    #[test]
    fn available_backends_return_domain_backends_and_filter_unavailable() {
        let backends = available_adi_backends("0123456789abcdef", false);

        assert!(backends
            .iter()
            .all(|backend| backend.availability != AdiBackendAvailability::Unavailable));
        if android_coreadi_abi().is_some() {
            assert!(backends
                .iter()
                .any(|backend| backend.kind == AdiBackendKind::AndroidCoreAdi));
        }
    }

    #[test]
    fn installed_library_requires_a_nonempty_regular_file() {
        let temp = tempfile::tempdir().expect("temporary directory should be created");
        let library = temp.path().join(ANDROID_COREADI_LIBRARY_FILE);

        assert!(!installed_library_exists(&library));
        fs::write(&library, []).expect("empty library should be created");
        assert!(!installed_library_exists(&library));
        fs::write(&library, [1]).expect("nonempty library should be created");
        assert!(installed_library_exists(&library));
        assert!(!installed_library_exists(temp.path()));
    }

    #[test]
    fn partial_file_is_stored_next_to_its_destination() {
        assert_eq!(
            partial_file_path(Path::new("/data/x86_64/libCoreADI.so")),
            PathBuf::from("/data/x86_64/libCoreADI.so.part")
        );
    }
}
