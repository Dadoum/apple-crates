use crate::backend::adi::{grandslam_device, selected_adi_proxy};
use crate::backend::developer::keychain::{token_is_near_expiry, DeveloperAccountKeychainSession};
use crate::backend::{BackendError, BackendResult};
use crate::domain::{AdiBackendKind, MachineIdentity};
use grandslam::http_session::AnisetteHTTPSession;
use grandslam::AccountHTTPSession;
use std::future::Future;
use std::pin::Pin;
use xcode::{XcodeSession, XCODE_BUNDLE_INFORMATION};

#[derive(Clone, Debug)]
pub(crate) struct DeveloperSessionConfig {
    pub(crate) adi_backend: AdiBackendKind,
    pub(crate) machine_identity: MachineIdentity,
    pub(crate) android_adi_identifier: String,
}

pub(crate) struct DeveloperApiSessionResult<T> {
    pub(crate) value: T,
    pub(crate) keychain_session: DeveloperAccountKeychainSession,
}

pub(crate) async fn with_developer_session<T, F>(
    config: DeveloperSessionConfig,
    session: DeveloperAccountKeychainSession,
    action: F,
) -> BackendResult<DeveloperApiSessionResult<T>>
where
    F: for<'session> FnOnce(
        &'session XcodeSession<'session, 'session>,
    ) -> Pin<Box<dyn Future<Output = BackendResult<T>> + 'session>>,
{
    let proxy = selected_adi_proxy(config.adi_backend, &config.android_adi_identifier)?;
    let http_session = grandslam::http_session(
        grandslam_device(&config.machine_identity, config.adi_backend),
        XCODE_BUNDLE_INFORMATION,
    )
    .await
    .map_err(|error| {
        BackendError::Network(format!("Failed to create Apple developer session: {error}"))
    })?;
    let anisette_session = AnisetteHTTPSession::new(http_session, proxy.as_ref());
    let account_session =
        AccountHTTPSession::new(anisette_session, session.auth_token.alt_dsid.clone());
    let xcode_token = if token_is_near_expiry(session.xcode_token.expiry_epoch_millis) {
        account_session
            .get_app_token(
                &session.auth_token.idms_token,
                &session.auth_token.session_key,
                &session.auth_token.cookie,
            )
            .await
            .map_err(|error| {
                BackendError::AppleAuth(format!("Failed to refresh the Xcode app token: {error}"))
            })?
    } else {
        session.xcode_token.clone()
    };
    let xcode_session = XcodeSession::new(account_session, xcode_token.clone());
    let keychain_session = DeveloperAccountKeychainSession::new(
        session.auth_token,
        session.heartbeat_token,
        xcode_token,
    );
    let value = action(&xcode_session).await?;

    Ok(DeveloperApiSessionResult {
        value,
        keychain_session,
    })
}
