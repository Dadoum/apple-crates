use crate::backend::adi::{grandslam_device, selected_adi_proxy};
use crate::backend::developer::cache::{
    delete_account_cache as delete_cached_account, merge_team_resources, new_account_id,
    refresh_account_seed, save_account_cache, CachedAppId, CachedAppIdCapability,
    CachedDeveloperTeam, CachedDevelopmentCertificate, DeveloperAccountCache, CACHE_VERSION,
};
use crate::backend::developer::certificates::{
    app_managed_private_key_fingerprints, certificate_fingerprint,
    certificate_public_key_fingerprint, generate_development_certificate_signing_request,
    import_app_managed_private_key, save_app_managed_certificate, save_app_managed_private_key,
    GeneratedCertificateSigningRequest,
};
use crate::backend::developer::client::{with_developer_session, DeveloperSessionConfig};
use crate::backend::developer::keychain::{
    cache_keychain_session, delete_keychain_session, load_keychain_session, save_keychain_session,
    token_is_near_expiry, DeveloperAccountKeychainSession,
};
use crate::backend::runtime as backend_runtime;
use crate::backend::{BackendError, BackendResult};
use crate::domain::{AdiBackendKind, DeveloperAccount, DeveloperDevice, MachineIdentity};
use chrono::{DateTime, Local};
use grandslam::http_session::AnisetteHTTPSession;
use grandslam::{AuthOutcome, AuthenticatedHTTPSession, Token};
use plist::{Dictionary, Value};
use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};
use grandslam::bundle_information::AKD_BUNDLE_INFORMATION;
use xcode::{
    AddAppIdAction, AddDeviceAction, AppIdFeature, DeleteAppIdAction, DeleteDeviceAction,
    DeveloperTeam, DownloadTeamProvisioningProfileAction, IOSRequest,
    ListAllDevelopmentCertsAction, ListAppIdsAction, ListDevicesAction, ListTeamsAction,
    RevokeDevelopmentCertAction, SubmitDevelopmentCsrAction, UpdateAppIdAction,
    ViewDeveloperAction, XcodeSession, XCODE_BUNDLE_INFORMATION, XCODE_TOKEN_IDENTIFIER,
};

const HEARTBEAT_TOKEN_IDENTIFIER: &str = "com.apple.gs.idms.hb";

#[derive(Clone, Debug)]
pub(crate) struct DeveloperLoginRequest {
    pub(crate) email: String,
    pub(crate) password: String,
    pub(crate) remember_account: bool,
    pub(crate) adi_backend: AdiBackendKind,
    pub(crate) machine_identity: MachineIdentity,
    pub(crate) android_adi_identifier: String,
}

#[derive(Clone, Debug)]
pub(crate) struct DeveloperAccountRefreshRequest {
    pub(crate) account_id: String,
    pub(crate) email: String,
    pub(crate) adi_backend: AdiBackendKind,
    pub(crate) machine_identity: MachineIdentity,
    pub(crate) android_adi_identifier: String,
}

#[derive(Clone, Debug)]
pub(crate) struct DeveloperAppIdDeleteRequest {
    pub(crate) account_id: String,
    pub(crate) email: String,
    pub(crate) team_id: String,
    pub(crate) app_id_id: String,
    pub(crate) adi_backend: AdiBackendKind,
    pub(crate) machine_identity: MachineIdentity,
    pub(crate) android_adi_identifier: String,
}

#[derive(Clone, Debug)]
pub(crate) struct DeveloperAppIdAddRequest {
    pub(crate) account_id: String,
    pub(crate) email: String,
    pub(crate) team_id: String,
    pub(crate) identifier: String,
    pub(crate) name: String,
    pub(crate) adi_backend: AdiBackendKind,
    pub(crate) machine_identity: MachineIdentity,
    pub(crate) android_adi_identifier: String,
}

#[derive(Clone, Debug)]
pub(crate) struct DeveloperAppIdCapabilityUpdate {
    pub(crate) key: String,
    pub(crate) enabled: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct DeveloperAppIdUpdateRequest {
    pub(crate) account_id: String,
    pub(crate) email: String,
    pub(crate) team_id: String,
    pub(crate) app_id_id: String,
    pub(crate) name: Option<String>,
    pub(crate) capabilities: Vec<DeveloperAppIdCapabilityUpdate>,
    pub(crate) adi_backend: AdiBackendKind,
    pub(crate) machine_identity: MachineIdentity,
    pub(crate) android_adi_identifier: String,
}

#[derive(Clone, Debug)]
pub(crate) struct DeveloperCertificateRevokeRequest {
    pub(crate) account_id: String,
    pub(crate) email: String,
    pub(crate) team_id: String,
    pub(crate) serial_number: String,
    pub(crate) adi_backend: AdiBackendKind,
    pub(crate) machine_identity: MachineIdentity,
    pub(crate) android_adi_identifier: String,
}

#[derive(Clone, Debug)]
pub(crate) struct DeveloperCertificateCreateRequest {
    pub(crate) account_id: String,
    pub(crate) email: String,
    pub(crate) team_id: String,
    pub(crate) adi_backend: AdiBackendKind,
    pub(crate) machine_identity: MachineIdentity,
    pub(crate) android_adi_identifier: String,
}

#[derive(Clone, Debug)]
pub(crate) struct DeveloperCertificatePrivateKeyImportRequest {
    pub(crate) account_id: String,
    pub(crate) email: String,
    pub(crate) team_id: String,
    pub(crate) certificate_id: String,
    pub(crate) public_key_fingerprint: String,
    pub(crate) adi_backend: AdiBackendKind,
    pub(crate) machine_identity: MachineIdentity,
    pub(crate) android_adi_identifier: String,
}

#[derive(Clone, Debug)]
pub(crate) struct DeveloperProvisioningProfileDownloadRequest {
    pub(crate) account_id: String,
    pub(crate) email: String,
    pub(crate) team_id: String,
    pub(crate) app_id_id: String,
    pub(crate) adi_backend: AdiBackendKind,
    pub(crate) machine_identity: MachineIdentity,
    pub(crate) android_adi_identifier: String,
}

#[derive(Clone, Debug)]
pub(crate) struct DeveloperDeviceListRequest {
    pub(crate) account_id: String,
    pub(crate) email: String,
    pub(crate) team_id: String,
    pub(crate) adi_backend: AdiBackendKind,
    pub(crate) machine_identity: MachineIdentity,
    pub(crate) android_adi_identifier: String,
}

#[derive(Clone, Debug)]
pub(crate) struct DeveloperDeviceAddRequest {
    pub(crate) account_id: String,
    pub(crate) email: String,
    pub(crate) team_id: String,
    pub(crate) name: String,
    pub(crate) udid: String,
    pub(crate) adi_backend: AdiBackendKind,
    pub(crate) machine_identity: MachineIdentity,
    pub(crate) android_adi_identifier: String,
}

#[derive(Clone, Debug)]
pub(crate) struct DeveloperDeviceDeleteRequest {
    pub(crate) account_id: String,
    pub(crate) email: String,
    pub(crate) team_id: String,
    pub(crate) device_id: String,
    pub(crate) adi_backend: AdiBackendKind,
    pub(crate) machine_identity: MachineIdentity,
    pub(crate) android_adi_identifier: String,
}

#[derive(Clone, Debug)]
pub(crate) struct DownloadedProvisioningProfile {
    pub(crate) name: String,
    pub(crate) bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) enum DeveloperLoginOutcome {
    SignedIn(DeveloperAccount),
    RequiresSecondaryAction { detail: String },
}

pub(crate) fn delete_account_cache(account_id: &str) -> BackendResult<()> {
    delete_cached_account(account_id)
}

pub(crate) async fn refresh_developer_account(
    request: DeveloperAccountRefreshRequest,
) -> BackendResult<DeveloperAccount> {
    let account = refresh_account_seed(&request.account_id, &request.email);
    let session = validated_keychain_session(&account)?;

    backend_runtime::run("account refresh", move || async move {
        let result = with_developer_session(
            session_config(
                request.adi_backend,
                request.machine_identity,
                request.android_adi_identifier,
            ),
            session,
            |xcode_session| {
                Box::pin(async move {
                    refresh_full_account(account.id.clone(), account.email.clone(), xcode_session)
                        .await
                })
            },
        )
        .await?;

        let mut account_cache = result.value;
        touch_account_cache(
            &mut account_cache,
            result.keychain_session.expires_at_millis(),
        );
        save_keychain_session(&account_cache.id, &result.keychain_session)?;
        save_account_cache(&account_cache)?;
        Ok(DeveloperAccount::from(account_cache))
    })
    .await?
}

pub(crate) async fn delete_developer_app_id(
    request: DeveloperAppIdDeleteRequest,
) -> BackendResult<DeveloperAccount> {
    mutate_team_resources(
        &request.account_id,
        &request.email,
        request.adi_backend,
        request.machine_identity,
        request.android_adi_identifier,
        request.team_id.clone(),
        DeveloperTeamOperation::DeleteAppId {
            app_id_id: request.app_id_id,
        },
    )
    .await
}

pub(crate) async fn add_developer_app_id(
    request: DeveloperAppIdAddRequest,
) -> BackendResult<DeveloperAccount> {
    mutate_team_resources(
        &request.account_id,
        &request.email,
        request.adi_backend,
        request.machine_identity,
        request.android_adi_identifier,
        request.team_id.clone(),
        DeveloperTeamOperation::AddAppId {
            identifier: request.identifier,
            name: request.name,
        },
    )
    .await
}

pub(crate) async fn update_developer_app_id(
    request: DeveloperAppIdUpdateRequest,
) -> BackendResult<DeveloperAccount> {
    mutate_team_resources(
        &request.account_id,
        &request.email,
        request.adi_backend,
        request.machine_identity,
        request.android_adi_identifier,
        request.team_id.clone(),
        DeveloperTeamOperation::UpdateAppId {
            app_id_id: request.app_id_id,
            name: request.name,
            capabilities: request.capabilities,
        },
    )
    .await
}

pub(crate) async fn revoke_developer_certificate(
    request: DeveloperCertificateRevokeRequest,
) -> BackendResult<DeveloperAccount> {
    mutate_team_resources(
        &request.account_id,
        &request.email,
        request.adi_backend,
        request.machine_identity,
        request.android_adi_identifier,
        request.team_id.clone(),
        DeveloperTeamOperation::RevokeCertificate {
            serial_number: request.serial_number,
        },
    )
    .await
}

pub(crate) async fn create_developer_certificate(
    request: DeveloperCertificateCreateRequest,
) -> BackendResult<DeveloperAccount> {
    let signing_request = generate_development_certificate_signing_request()?;
    mutate_team_resources(
        &request.account_id,
        &request.email,
        request.adi_backend,
        request.machine_identity,
        request.android_adi_identifier,
        request.team_id.clone(),
        DeveloperTeamOperation::CreateCertificate { signing_request },
    )
    .await
}

pub(crate) async fn import_developer_certificate_private_key(
    request: DeveloperCertificatePrivateKeyImportRequest,
    private_key_path: PathBuf,
) -> BackendResult<DeveloperAccount> {
    import_app_managed_private_key(
        &request.certificate_id,
        &request.public_key_fingerprint,
        &private_key_path,
    )?;

    refresh_cached_team_only(
        &request.account_id,
        &request.email,
        request.adi_backend,
        request.machine_identity,
        request.android_adi_identifier,
        request.team_id,
    )
    .await
}

pub(crate) async fn download_developer_provisioning_profile(
    request: DeveloperProvisioningProfileDownloadRequest,
) -> BackendResult<DownloadedProvisioningProfile> {
    let account = refresh_account_seed(&request.account_id, &request.email);
    let session = validated_keychain_session(&account)?;

    backend_runtime::run("profile download", move || async move {
        let account_id = account.id.clone();
        let result = with_developer_session(
            session_config(
                request.adi_backend,
                request.machine_identity,
                request.android_adi_identifier,
            ),
            session,
            |xcode_session| {
                Box::pin(async move {
                    let profile = xcode_session
                        .perform_developer_action(IOSRequest::new(
                            DownloadTeamProvisioningProfileAction {
                                app_id_id: request.app_id_id,
                                team_id: request.team_id.into(),
                            },
                        ))
                        .await
                        .map_err(|error| {
                            BackendError::Network(format!(
                                "Failed to download provisioning profile: {error}"
                            ))
                        })?
                        .map_err(|error| {
                            BackendError::AppleAuth(format!(
                                "Failed to parse provisioning profile response: {error}"
                            ))
                        })?
                        .provisioning_profile;

                    Ok(DownloadedProvisioningProfile {
                        name: profile.name,
                        bytes: profile.encoded_profile,
                    })
                })
            },
        )
        .await?;

        save_keychain_session(&account_id, &result.keychain_session)?;
        Ok(result.value)
    })
    .await?
}

pub(crate) async fn list_developer_devices(
    request: DeveloperDeviceListRequest,
) -> BackendResult<Vec<DeveloperDevice>> {
    let account = refresh_account_seed(&request.account_id, &request.email);
    let session = validated_keychain_session(&account)?;

    backend_runtime::run("developer device list", move || async move {
        let account_id = account.id.clone();
        let result = with_developer_session(
            session_config(
                request.adi_backend,
                request.machine_identity,
                request.android_adi_identifier,
            ),
            session,
            |xcode_session| {
                Box::pin(
                    async move { fetch_developer_devices(xcode_session, &request.team_id).await },
                )
            },
        )
        .await?;

        save_keychain_session(&account_id, &result.keychain_session)?;
        Ok(result.value)
    })
    .await?
}

pub(crate) async fn add_developer_device(
    request: DeveloperDeviceAddRequest,
) -> BackendResult<Vec<DeveloperDevice>> {
    mutate_developer_devices(
        request.account_id,
        request.email,
        request.adi_backend,
        request.machine_identity,
        request.android_adi_identifier,
        request.team_id,
        DeveloperDeviceOperation::Add {
            name: request.name,
            udid: request.udid,
        },
    )
    .await
}

pub(crate) async fn delete_developer_device(
    request: DeveloperDeviceDeleteRequest,
) -> BackendResult<Vec<DeveloperDevice>> {
    mutate_developer_devices(
        request.account_id,
        request.email,
        request.adi_backend,
        request.machine_identity,
        request.android_adi_identifier,
        request.team_id,
        DeveloperDeviceOperation::Delete {
            device_id: request.device_id,
        },
    )
    .await
}

pub(crate) async fn login_developer_account(
    request: DeveloperLoginRequest,
) -> BackendResult<DeveloperLoginOutcome> {
    if request.email.trim().is_empty() {
        return Err(BackendError::AppleAuth(
            "Enter the Apple Account email.".to_string(),
        ));
    }
    if request.password.is_empty() {
        return Err(BackendError::AppleAuth(
            "Enter the account password.".to_string(),
        ));
    }

    backend_runtime::run("login", move || login_developer_account_async(request)).await?
}

pub(crate) fn developer_secondary_action_not_supported() -> String {
    "Apple requested an additional authentication action and did not return enough reusable tokens to continue. Completing secondary actions is not implemented yet, so finish the action outside Super Sideloader if Apple shows one, then try signing in again.".to_string()
}

enum DeveloperTeamOperation {
    AddAppId {
        identifier: String,
        name: String,
    },
    DeleteAppId {
        app_id_id: String,
    },
    UpdateAppId {
        app_id_id: String,
        name: Option<String>,
        capabilities: Vec<DeveloperAppIdCapabilityUpdate>,
    },
    RevokeCertificate {
        serial_number: String,
    },
    CreateCertificate {
        signing_request: GeneratedCertificateSigningRequest,
    },
}

enum DeveloperDeviceOperation {
    Add { name: String, udid: String },
    Delete { device_id: String },
}

async fn mutate_team_resources(
    account_id: &str,
    email: &str,
    adi_backend: AdiBackendKind,
    machine_identity: MachineIdentity,
    android_adi_identifier: String,
    team_id: String,
    operation: DeveloperTeamOperation,
) -> BackendResult<DeveloperAccount> {
    let account = refresh_account_seed(account_id, email);
    let session = validated_keychain_session(&account)?;

    backend_runtime::run("developer team update", move || async move {
        let account_for_refresh = account.clone();
        let team_id_for_refresh = team_id.clone();
        let result = with_developer_session(
            session_config(adi_backend, machine_identity, android_adi_identifier),
            session,
            |xcode_session| {
                Box::pin(async move {
                    let created_certificate_id =
                        perform_team_operation(xcode_session, &team_id_for_refresh, operation)
                            .await?;
                    let mut refreshed_team = refresh_team_resources(
                        &account_for_refresh,
                        &team_id_for_refresh,
                        xcode_session,
                    )
                    .await?;
                    if let Some(certificate_id) = created_certificate_id {
                        for _ in 0..4 {
                            if team_has_certificate_id(&refreshed_team, &certificate_id) {
                                break;
                            }
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            refreshed_team = refresh_team_resources(
                                &account_for_refresh,
                                &team_id_for_refresh,
                                xcode_session,
                            )
                            .await?;
                        }
                        if !team_has_certificate_id(&refreshed_team, &certificate_id) {
                            return Err(BackendError::AppleAuth(format!(
                                "Apple accepted the CSR as certificate {certificate_id}, but the certificate was not returned by the developer portal yet. Try Refresh in a moment."
                            )));
                        }
                    }
                    Ok(refreshed_team)
                })
            },
        )
        .await?;

        let mut account = account;
        merge_team_resources(&mut account, result.value);
        touch_account_cache(&mut account, result.keychain_session.expires_at_millis());
        save_keychain_session(&account.id, &result.keychain_session)?;
        save_account_cache(&account)?;
        Ok(DeveloperAccount::from(account))
    })
    .await?
}

async fn perform_team_operation(
    xcode_session: &XcodeSession<'_, '_>,
    team_id: &str,
    operation: DeveloperTeamOperation,
) -> BackendResult<Option<String>> {
    match operation {
        DeveloperTeamOperation::AddAppId { identifier, name } => {
            xcode_session
                .perform_developer_action(IOSRequest::new(AddAppIdAction {
                    identifier,
                    name,
                    team_id: team_id.into(),
                }))
                .await
                .map_err(|error| BackendError::Network(format!("Failed to add App ID: {error}")))?
                .map_err(|error| {
                    BackendError::AppleAuth(format!(
                        "Failed to parse App ID creation response: {error}"
                    ))
                })?;
            Ok(None)
        }
        DeveloperTeamOperation::DeleteAppId { app_id_id } => {
            xcode_session
                .perform_developer_action(IOSRequest::new(DeleteAppIdAction {
                    app_id_id,
                    team_id: team_id.into(),
                }))
                .await
                .map_err(|error| {
                    BackendError::Network(format!("Failed to delete App ID: {error}"))
                })?
                .map_err(|error| {
                    BackendError::AppleAuth(format!(
                        "Failed to parse App ID deletion response: {error}"
                    ))
                })?;
            Ok(None)
        }
        DeveloperTeamOperation::UpdateAppId {
            app_id_id,
            name,
            capabilities,
        } => {
            xcode_session
                .perform_developer_action(IOSRequest::new(UpdateAppIdAction {
                    app_id_id,
                    team_id: team_id.into(),
                    name,
                    features: app_id_update_features(&capabilities),
                }))
                .await
                .map_err(|error| {
                    BackendError::Network(format!("Failed to update App ID: {error}"))
                })?
                .map_err(|error| {
                    BackendError::AppleAuth(format!(
                        "Failed to parse App ID update response: {error}"
                    ))
                })?;
            Ok(None)
        }
        DeveloperTeamOperation::RevokeCertificate { serial_number } => {
            xcode_session
                .perform_developer_action(IOSRequest::new(RevokeDevelopmentCertAction {
                    team_id: team_id.into(),
                    serial_number,
                }))
                .await
                .map_err(|error| {
                    BackendError::Network(format!("Failed to revoke certificate: {error}"))
                })?
                .map_err(|error| {
                    BackendError::AppleAuth(format!(
                        "Failed to parse certificate revocation response: {error}"
                    ))
                })?;
            Ok(None)
        }
        DeveloperTeamOperation::CreateCertificate { signing_request } => {
            let response = xcode_session
                .perform_developer_action(IOSRequest::new(SubmitDevelopmentCsrAction {
                    team_id: team_id.into(),
                    machine_id: signing_request.machine_id,
                    machine_name: signing_request.machine_name,
                    csr_content: signing_request.csr_content,
                }))
                .await
                .map_err(|error| {
                    BackendError::Network(format!(
                        "Failed to submit development certificate CSR: {error}"
                    ))
                })?
                .map_err(|error| {
                    BackendError::AppleAuth(format!(
                        "Failed to parse development certificate CSR response: {error}"
                    ))
                })?;
            let certificate_id = response.cert_request.cert_request_id;
            if certificate_id.trim().is_empty() {
                return Err(BackendError::AppleAuth(
                    "Apple accepted the CSR but did not return a certificate identifier."
                        .to_string(),
                ));
            }
            save_app_managed_private_key(
                &signing_request.public_key_fingerprint,
                &signing_request.private_key_pem,
            )?;
            Ok(Some(certificate_id))
        }
    }
}

async fn mutate_developer_devices(
    account_id: String,
    email: String,
    adi_backend: AdiBackendKind,
    machine_identity: MachineIdentity,
    android_adi_identifier: String,
    team_id: String,
    operation: DeveloperDeviceOperation,
) -> BackendResult<Vec<DeveloperDevice>> {
    let account = refresh_account_seed(&account_id, &email);
    let session = validated_keychain_session(&account)?;

    backend_runtime::run("developer device update", move || async move {
        let account_id = account.id.clone();
        let result = with_developer_session(
            session_config(adi_backend, machine_identity, android_adi_identifier),
            session,
            |xcode_session| {
                Box::pin(async move {
                    perform_device_operation(xcode_session, &team_id, operation).await?;
                    fetch_developer_devices(xcode_session, &team_id).await
                })
            },
        )
        .await?;

        save_keychain_session(&account_id, &result.keychain_session)?;
        Ok(result.value)
    })
    .await?
}

async fn perform_device_operation(
    xcode_session: &XcodeSession<'_, '_>,
    team_id: &str,
    operation: DeveloperDeviceOperation,
) -> BackendResult<()> {
    match operation {
        DeveloperDeviceOperation::Add { name, udid } => {
            if name.trim().is_empty() {
                return Err(BackendError::Message(
                    "Enter a device name before registering it.".to_string(),
                ));
            }
            if udid.trim().is_empty() {
                return Err(BackendError::Message(
                    "Enter a device UDID before registering it.".to_string(),
                ));
            }
            xcode_session
                .perform_developer_action(IOSRequest::new(AddDeviceAction {
                    team_id: team_id.into(),
                    name,
                    device_number: udid,
                }))
                .await
                .map_err(|error| {
                    BackendError::Network(format!("Failed to register device: {error}"))
                })?
                .map_err(|error| {
                    BackendError::AppleAuth(format!(
                        "Failed to parse device registration response: {error}"
                    ))
                })?;
        }
        DeveloperDeviceOperation::Delete { device_id } => {
            xcode_session
                .perform_developer_action(IOSRequest::new(DeleteDeviceAction {
                    team_id: team_id.into(),
                    device_id,
                }))
                .await
                .map_err(|error| {
                    BackendError::Network(format!("Failed to remove device: {error}"))
                })?
                .map_err(|error| {
                    BackendError::AppleAuth(format!(
                        "Failed to parse device removal response: {error}"
                    ))
                })?;
        }
    }
    Ok(())
}

async fn fetch_developer_devices(
    xcode_session: &XcodeSession<'_, '_>,
    team_id: &str,
) -> BackendResult<Vec<DeveloperDevice>> {
    let mut devices = xcode_session
        .perform_developer_action(IOSRequest::new(ListDevicesAction {
            team_id: team_id.into(),
        }))
        .await
        .map_err(|error| {
            BackendError::Network(format!("Failed to fetch registered devices: {error}"))
        })?
        .map_err(|error| {
            BackendError::AppleAuth(format!(
                "Failed to parse registered devices response: {error}"
            ))
        })?
        .devices
        .into_iter()
        .map(|device| DeveloperDevice {
            id: device.device_id,
            name: device.name,
            udid: device.device_number,
        })
        .collect::<Vec<_>>();
    sort_developer_devices(&mut devices);
    Ok(devices)
}

fn sort_developer_devices(devices: &mut [DeveloperDevice]) {
    devices.sort_by(|left, right| {
        left.name
            .to_ascii_lowercase()
            .cmp(&right.name.to_ascii_lowercase())
            .then_with(|| left.udid.cmp(&right.udid))
    });
}

async fn refresh_cached_team_only(
    account_id: &str,
    email: &str,
    adi_backend: AdiBackendKind,
    machine_identity: MachineIdentity,
    android_adi_identifier: String,
    team_id: String,
) -> BackendResult<DeveloperAccount> {
    let account = refresh_account_seed(account_id, email);
    let session = validated_keychain_session(&account)?;

    backend_runtime::run("developer team refresh", move || async move {
        let account_for_refresh = account.clone();
        let team_id_for_refresh = team_id.clone();
        let result = with_developer_session(
            session_config(adi_backend, machine_identity, android_adi_identifier),
            session,
            |xcode_session| {
                Box::pin(async move {
                    refresh_team_resources(
                        &account_for_refresh,
                        &team_id_for_refresh,
                        xcode_session,
                    )
                    .await
                })
            },
        )
        .await?;

        let mut account = account;
        merge_team_resources(&mut account, result.value);
        touch_account_cache(&mut account, result.keychain_session.expires_at_millis());
        save_keychain_session(&account.id, &result.keychain_session)?;
        save_account_cache(&account)?;
        Ok(DeveloperAccount::from(account))
    })
    .await?
}

fn validated_keychain_session(
    account: &DeveloperAccountCache,
) -> BackendResult<DeveloperAccountKeychainSession> {
    let session = match load_keychain_session(&account.id)? {
        Some(session) => session,
        None => {
            return Err(BackendError::Keychain(
                "The saved account cache has no matching session in the system keychain."
                    .to_string(),
            ));
        }
    };

    if account
        .token_expires_at_epoch_millis
        .is_some_and(token_is_near_expiry)
        || token_is_near_expiry(session.expires_at_millis())
    {
        if let Err(error) = delete_cached_account(&account.id) {
            log::warn!("{error}");
        }
        return Err(BackendError::AppleAuth(
            "The saved Apple Account session is expired.".to_string(),
        ));
    }

    Ok(session)
}

async fn login_developer_account_async(
    request: DeveloperLoginRequest,
) -> BackendResult<DeveloperLoginOutcome> {
    let account_id = new_account_id();
    let proxy = selected_adi_proxy(request.adi_backend, &request.android_adi_identifier)?;
    let http_session = grandslam::http_session(
        grandslam_device(&request.machine_identity, request.adi_backend),
        AKD_BUNDLE_INFORMATION,
    )
    .await
    .map_err(|error| {
        BackendError::Network(format!("Failed to create Apple login session: {error}"))
    })?;
    let anisette_session = AnisetteHTTPSession::new(http_session, proxy.as_ref());

    let auth_outcome = grandslam::login(
        &anisette_session,
        request.email.trim(),
        request.password.as_str(),
    )
    .await
    .map_err(|error| BackendError::AppleAuth(format!("Apple login failed: {error}")))?;

    let secondary_action_url;
    let server_provided_data = match auth_outcome {
        AuthOutcome::Success(server_provided_data) => {
            secondary_action_url = None;
            server_provided_data
        }
        AuthOutcome::SecondaryActionRequired(Some(server_provided_data), action_url) => {
            secondary_action_url = Some(action_url);
            server_provided_data
        }
        AuthOutcome::SecondaryActionRequired(None, action_url) => {
            return Ok(DeveloperLoginOutcome::RequiresSecondaryAction {
                detail: format!(
                    "Apple requested an additional authentication action at {action_url}. {}",
                    developer_secondary_action_not_supported()
                ),
            });
        }
        AuthOutcome::AnisetteReprovisionRequired => {
            return Err(BackendError::AppleAuth("ADI provisioning is missing or expired. Provision the selected ADI backend in Settings, then try again.".to_string()));
        }
        AuthOutcome::AnisetteResyncRequired(_) => {
            return Err(BackendError::AppleAuth(
                "ADI resync is required before this account can sign in.".to_string(),
            ));
        }
        AuthOutcome::UrlSwitchingRequired(url) => {
            return Err(BackendError::Unsupported(format!(
                "Apple requested a sign-in URL switch that is not supported yet: {url}"
            )));
        }
    };

    let Some((auth_token, tokens)) =
        grandslam::parse_tokens_from_server_provided_data(&server_provided_data)
    else {
        if let Some(action_url) = secondary_action_url {
            return Ok(DeveloperLoginOutcome::RequiresSecondaryAction {
                detail: format!(
                    "Apple requested an additional authentication action at {action_url}. {}",
                    developer_secondary_action_not_supported()
                ),
            });
        }
        return Err(BackendError::AppleAuth(
            "Apple login succeeded but no reusable account tokens were returned.".to_string(),
        ));
    };
    let heartbeat_token = match heartbeat_token(&tokens) {
        Ok(token) => token,
        Err(error) if secondary_action_url.is_some() => {
            let action_url = secondary_action_url.as_deref().unwrap_or_default();
            return Ok(DeveloperLoginOutcome::RequiresSecondaryAction {
                detail: format!(
                    "Apple requested an additional authentication action at {action_url}. {error}"
                ),
            });
        }
        Err(error) => return Err(error),
    };
    let authenticated_session = AuthenticatedHTTPSession::new(
        anisette_session,
        auth_token.clone(),
        heartbeat_token.clone(),
    );
    let xcode_token = match authenticated_session
        .get_app_token(XCODE_TOKEN_IDENTIFIER)
        .await
    {
        Ok(token) => token,
        Err(error) if secondary_action_url.is_some() => {
            let action_url = secondary_action_url.as_deref().unwrap_or_default();
            return Ok(DeveloperLoginOutcome::RequiresSecondaryAction {
                detail: format!(
                    "Apple requested an additional authentication action at {action_url}. The login tokens were returned, but the Xcode token could not be requested yet: {error}"
                ),
            });
        }
        Err(error) => {
            return Err(BackendError::AppleAuth(format!(
                "Failed to request the Xcode app token: {error}"
            )));
        }
    };

    let keychain_session =
        DeveloperAccountKeychainSession::new(auth_token, heartbeat_token, xcode_token.clone());
    let xcode_session = XcodeSession::new(authenticated_session, xcode_token);
    let mut account_cache =
        refresh_full_account(account_id, request.email.trim().to_string(), &xcode_session).await?;
    touch_account_cache(&mut account_cache, keychain_session.expires_at_millis());

    if request.remember_account {
        save_keychain_session(&account_cache.id, &keychain_session)?;
        if let Err(error) = save_account_cache(&account_cache) {
            if let Err(delete_error) = delete_keychain_session(&account_cache.id) {
                log::warn!("{delete_error}");
            }
            return Err(error);
        }
    } else {
        cache_keychain_session(&account_cache.id, &keychain_session)?;
    }

    Ok(DeveloperLoginOutcome::SignedIn(account_cache.into()))
}

async fn refresh_full_account(
    account_id: String,
    email: String,
    xcode_session: &XcodeSession<'_, '_>,
) -> BackendResult<DeveloperAccountCache> {
    let developer_view = xcode_session
        .perform_developer_action(ViewDeveloperAction {})
        .await
        .map_err(|error| {
            BackendError::Network(format!(
                "Failed to fetch developer account details: {error}"
            ))
        })?
        .map_err(|error| {
            BackendError::AppleAuth(format!(
                "Failed to parse developer account details: {error}"
            ))
        })?;

    let profile_name = developer_profile_name(&developer_view.developer).unwrap_or(email.clone());
    let developer_teams = xcode_session
        .perform_developer_action(ListTeamsAction {})
        .await
        .map_err(|error| {
            BackendError::Network(format!("Failed to fetch developer teams: {error}"))
        })?
        .map_err(|error| {
            BackendError::AppleAuth(format!("Failed to parse developer teams: {error}"))
        })?
        .teams;
    if developer_teams.is_empty() {
        return Err(BackendError::AppleAuth(
            "Apple returned no developer teams for this account.".to_string(),
        ));
    }

    let mut account = DeveloperAccountCache {
        version: CACHE_VERSION,
        id: account_id,
        email,
        profile_name: Some(profile_name),
        token_expires_at: None,
        token_expires_at_epoch_millis: None,
        last_refreshed_at: Some(format_now()),
        teams: Vec::with_capacity(developer_teams.len()),
    };
    for team in developer_teams {
        account
            .teams
            .push(fetch_team_resources(developer_team_seed(team), xcode_session).await?);
    }
    Ok(account)
}

async fn refresh_team_resources(
    account: &DeveloperAccountCache,
    team_id: &str,
    xcode_session: &XcodeSession<'_, '_>,
) -> BackendResult<CachedDeveloperTeam> {
    let seed = account
        .teams
        .iter()
        .find(|team| team.id == team_id)
        .cloned()
        .unwrap_or_else(|| CachedDeveloperTeam {
            id: team_id.to_string(),
            name: team_id.to_string(),
            role: "Developer".to_string(),
            app_id_available_quantity: None,
            app_id_max_quantity: None,
            app_ids: Vec::new(),
            certificates: Vec::new(),
        });
    fetch_team_resources(seed, xcode_session).await
}

async fn fetch_team_resources(
    team: CachedDeveloperTeam,
    xcode_session: &XcodeSession<'_, '_>,
) -> BackendResult<CachedDeveloperTeam> {
    let app_managed_key_fingerprints = app_managed_private_key_fingerprints();
    let certificates = xcode_session
        .perform_developer_action(IOSRequest::new(ListAllDevelopmentCertsAction {
            team_id: team.id.clone().into(),
        }))
        .await
        .map_err(|error| {
            BackendError::Network(format!(
                "Failed to fetch development certificates for team {}: {error}",
                team.id
            ))
        })?
        .map_err(|error| {
            BackendError::AppleAuth(format!(
                "Failed to parse development certificates for team {}: {error}",
                team.id
            ))
        })?
        .certificates
        .into_iter()
        .map(|certificate| -> BackendResult<_> {
            let fingerprint = certificate_fingerprint(&certificate.cert_content);
            let public_key_fingerprint =
                certificate_public_key_fingerprint(&certificate.cert_content);
            save_app_managed_certificate(&fingerprint, &certificate.cert_content)?;
            Ok(CachedDevelopmentCertificate {
                id: certificate.certificate_id,
                name: certificate.name,
                serial_number: certificate.serial_number,
                machine_name: certificate.machine_name,
                private_key_available: public_key_fingerprint.as_ref().is_some_and(|fingerprint| {
                    app_managed_key_fingerprints
                        .iter()
                        .any(|candidate| candidate == fingerprint)
                }),
                certificate_fingerprint: Some(fingerprint),
                public_key_fingerprint,
            })
        })
        .collect::<BackendResult<Vec<_>>>()?;

    let app_id_response = xcode_session
        .perform_developer_action(IOSRequest::new(ListAppIdsAction {
            team_id: team.id.clone().into(),
        }))
        .await
        .map_err(|error| {
            BackendError::Network(format!(
                "Failed to fetch App IDs for team {}: {error}",
                team.id
            ))
        })?
        .map_err(|error| {
            BackendError::AppleAuth(format!(
                "Failed to parse App IDs for team {}: {error}",
                team.id
            ))
        })?;
    let app_ids = app_id_response
        .app_ids
        .into_iter()
        .map(|app_id| {
            let identifier = app_id.identifier;
            CachedAppId {
                id: identifier.clone(),
                developer_id: app_id.app_id_id,
                name: app_id.name,
                kind: if identifier.ends_with(".*") {
                    "Wildcard App ID".to_string()
                } else {
                    "Explicit App ID".to_string()
                },
                capabilities: cached_app_id_capabilities(&app_id.features),
            }
        })
        .collect();

    Ok(CachedDeveloperTeam {
        app_id_available_quantity: known_quantity(app_id_response.available_quantity),
        app_id_max_quantity: known_quantity(app_id_response.max_quantity),
        app_ids,
        certificates,
        ..team
    })
}

fn developer_team_seed(team: DeveloperTeam) -> CachedDeveloperTeam {
    let role = developer_team_type(&team);
    CachedDeveloperTeam {
        id: team.team_id.as_ref().to_string(),
        name: team.name,
        role,
        app_id_available_quantity: None,
        app_id_max_quantity: None,
        app_ids: Vec::new(),
        certificates: Vec::new(),
    }
}

fn touch_account_cache(account: &mut DeveloperAccountCache, token_expires_at_epoch_millis: u64) {
    account.token_expires_at = Some(format_epoch_millis(token_expires_at_epoch_millis));
    account.token_expires_at_epoch_millis = Some(token_expires_at_epoch_millis);
    account.last_refreshed_at = Some(format_now());
}

fn team_has_certificate_id(team: &CachedDeveloperTeam, certificate_id: &str) -> bool {
    team.certificates
        .iter()
        .any(|certificate| certificate.id == certificate_id)
}

struct AppIdCapabilityDefinition {
    feature: AppIdFeature,
    label: &'static str,
    detail: &'static str,
}

const APP_ID_CAPABILITIES: &[AppIdCapabilityDefinition] = &[
    AppIdCapabilityDefinition {
        feature: AppIdFeature::Push,
        label: "Push Notifications",
        detail: "Allow APNs registration and push notification entitlements.",
    },
    AppIdCapabilityDefinition {
        feature: AppIdFeature::ICloud,
        label: "iCloud",
        detail: "Enable iCloud containers and related entitlements.",
    },
    AppIdCapabilityDefinition {
        feature: AppIdFeature::InAppPurchase,
        label: "In-App Purchase",
        detail: "Enable StoreKit in-app purchase support.",
    },
    AppIdCapabilityDefinition {
        feature: AppIdFeature::GameCenter,
        label: "Game Center",
        detail: "Enable Game Center services.",
    },
    AppIdCapabilityDefinition {
        feature: AppIdFeature::Passbook,
        label: "Wallet",
        detail: "Enable Wallet passes.",
    },
    AppIdCapabilityDefinition {
        feature: AppIdFeature::InterAppAudio,
        label: "Inter-App Audio",
        detail: "Enable Inter-App Audio registration.",
    },
    AppIdCapabilityDefinition {
        feature: AppIdFeature::VpnConfiguration,
        label: "VPN Configuration",
        detail: "Enable VPN configuration capabilities.",
    },
    AppIdCapabilityDefinition {
        feature: AppIdFeature::DataProtection,
        label: "Data Protection",
        detail: "Enable Data Protection entitlements.",
    },
    AppIdCapabilityDefinition {
        feature: AppIdFeature::AssociatedDomains,
        label: "Associated Domains",
        detail: "Enable associated domains such as universal links.",
    },
    AppIdCapabilityDefinition {
        feature: AppIdFeature::AppGroup,
        label: "App Groups",
        detail: "Enable app group container sharing.",
    },
    AppIdCapabilityDefinition {
        feature: AppIdFeature::HealthKit,
        label: "HealthKit",
        detail: "Enable HealthKit access.",
    },
    AppIdCapabilityDefinition {
        feature: AppIdFeature::HomeKit,
        label: "HomeKit",
        detail: "Enable HomeKit access.",
    },
    AppIdCapabilityDefinition {
        feature: AppIdFeature::WirelessAccessory,
        label: "Wireless Accessory Configuration",
        detail: "Enable wireless accessory configuration.",
    },
    AppIdCapabilityDefinition {
        feature: AppIdFeature::CloudKitVersion,
        label: "CloudKit",
        detail: "Enable CloudKit versioned services.",
    },
];

fn cached_app_id_capabilities(features: &Dictionary) -> Vec<CachedAppIdCapability> {
    APP_ID_CAPABILITIES
        .iter()
        .map(|definition| {
            let key = definition.feature.as_str();
            CachedAppIdCapability {
                key: key.to_string(),
                label: definition.label.to_string(),
                detail: definition.detail.to_string(),
                enabled: features
                    .get(key)
                    .and_then(Value::as_boolean)
                    .unwrap_or(false),
            }
        })
        .collect()
}

fn app_id_update_features(capabilities: &[DeveloperAppIdCapabilityUpdate]) -> Dictionary {
    let mut features = Dictionary::new();
    for capability in capabilities {
        features.insert(capability.key.clone(), Value::Boolean(capability.enabled));
    }
    features
}

fn developer_profile_name(developer: &xcode::Developer) -> Option<String> {
    let name = format!(
        "{} {}",
        developer.first_name.trim(),
        developer.last_name.trim()
    )
    .trim()
    .to_string();
    if !name.is_empty() {
        return Some(name);
    }

    let ds_name = format!(
        "{} {}",
        developer.ds_first_name.trim(),
        developer.ds_last_name.trim()
    )
    .trim()
    .to_string();
    if ds_name.is_empty() {
        None
    } else {
        Some(ds_name)
    }
}

fn developer_team_type(team: &DeveloperTeam) -> String {
    team.team_type
        .as_deref()
        .map(str::trim)
        .filter(|team_type| !team_type.is_empty())
        .unwrap_or("Developer")
        .to_string()
}

fn heartbeat_token(tokens: &[(String, Token)]) -> BackendResult<Token> {
    tokens
        .iter()
        .find(|(key, _)| key == HEARTBEAT_TOKEN_IDENTIFIER)
        .or_else(|| tokens.iter().find(|(key, _)| key.contains(".hb")))
        .map(|(_, token)| token.clone())
        .ok_or_else(|| {
            let identifiers = tokens
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            if identifiers.is_empty() {
                BackendError::AppleAuth("Apple login did not return a heartbeat token.".to_string())
            } else {
                BackendError::AppleAuth(format!(
                    "Apple login did not return the expected heartbeat token. Returned tokens: {identifiers}"
                ))
            }
        })
}

fn format_now() -> String {
    Local::now().format("%Y-%m-%d %H:%M").to_string()
}

fn format_epoch_millis(epoch_millis: u64) -> String {
    if epoch_millis == 0 {
        return "unknown".to_string();
    }
    DateTime::<Local>::from(UNIX_EPOCH + std::time::Duration::from_millis(epoch_millis))
        .format("%Y-%m-%d %H:%M")
        .to_string()
}

fn known_quantity(quantity: u64) -> Option<u64> {
    (quantity != u64::MAX).then_some(quantity)
}

fn session_config(
    adi_backend: AdiBackendKind,
    machine_identity: MachineIdentity,
    android_adi_identifier: String,
) -> DeveloperSessionConfig {
    DeveloperSessionConfig {
        adi_backend,
        machine_identity,
        android_adi_identifier,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_id_update_features_contains_requested_flags_only() {
        let features = app_id_update_features(&[
            DeveloperAppIdCapabilityUpdate {
                key: "push".into(),
                enabled: true,
            },
            DeveloperAppIdCapabilityUpdate {
                key: "icloud".into(),
                enabled: false,
            },
        ]);

        assert_eq!(features.get("push").and_then(Value::as_boolean), Some(true));
        assert_eq!(
            features.get("icloud").and_then(Value::as_boolean),
            Some(false)
        );
    }

    #[test]
    fn developer_team_seed_keeps_team_type() {
        let team = DeveloperTeam {
            team_id: "TEAM".into(),
            name: "Team".into(),
            team_type: Some("Individual".into()),
        };

        let seed = developer_team_seed(team);

        assert_eq!(seed.id, "TEAM");
        assert_eq!(seed.role, "Individual");
    }

    #[test]
    fn developer_devices_are_sorted_by_name_then_udid() {
        let mut devices = vec![
            DeveloperDevice {
                id: "3".into(),
                name: "iPhone".into(),
                udid: "B".into(),
            },
            DeveloperDevice {
                id: "1".into(),
                name: "iPad".into(),
                udid: "Z".into(),
            },
            DeveloperDevice {
                id: "2".into(),
                name: "iphone".into(),
                udid: "A".into(),
            },
        ];

        sort_developer_devices(&mut devices);

        assert_eq!(
            devices
                .into_iter()
                .map(|device| device.id)
                .collect::<Vec<_>>(),
            vec!["1", "2", "3"]
        );
    }
}
