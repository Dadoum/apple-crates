use adi::proxy::ADIProxy;
use android_coreadi::AndroidCoreADIProxy;
use apple_account::bundle_information::APPLE_TV_BUNDLE_INFORMATION;
use apple_account::device::Device;
use apple_account::grandslam::{AuthOutcome, AuthenticatedHTTPSession};
use apple_account::http_session::AnisetteHTTPSession;
use apple_account::{grandslam, itunes};
use std::{env, fs};
use xcode::{ViewDeveloperAction, XcodeSession, XCODE_BUNDLE_INFORMATION, XCODE_TOKEN_IDENTIFIER};

async fn grandslam_test(
    proxy: &dyn ADIProxy,
    apple_id: &str,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // proxy.set_android_id("0123456789012345")?;
    // proxy.set_provisioning_path(c"./adi_files")?;

    let device = Device {
        device_model: "MacBookPro13,2".to_string(),
        operating_system_information: "macOS;15.6.1;24G90".to_string(),
        device_uuid: "A8B31C86-359B-4D95-8950-BA5DD8FFC46F".to_string(),
    };

    // println!("{:#02X?}", proxy.get_all_provisioned_accounts());

    let http_session = AnisetteHTTPSession::new(
        grandslam::http_session(device, XCODE_BUNDLE_INFORMATION).await?,
        proxy,
    );

    if !proxy.is_machine_provisioned(grandslam::GRANDSLAM_DSID)? {
        grandslam::provision(&http_session).await?;
    }

    // Here we should fetch_auth_mode first to know if we should log-in with a password.
    let auth_outcome = grandslam::login(&http_session, apple_id, password).await?;

    match &auth_outcome {
        AuthOutcome::Success(server_provided_data)
        | AuthOutcome::SecondaryActionRequired(Some(server_provided_data), _) => {
            match grandslam::parse_tokens_from_server_provided_data(server_provided_data) {
                Some((auth_token, tokens)) => {
                    let (_, hb_token) = tokens
                        .iter()
                        .find(|(name, _)| name == "com.apple.gs.idms.hb")
                        .unwrap();

                    let http_session =
                        AuthenticatedHTTPSession::new(http_session, auth_token, hb_token.clone());

                    let xcode_token = http_session.get_app_token(XCODE_TOKEN_IDENTIFIER).await?;

                    let session = XcodeSession::new(http_session, xcode_token);
                    let developer = session
                        .perform_developer_action(ViewDeveloperAction {})
                        .await??;
                    println!("{:?}", developer);
                }
                None => {
                    let AuthOutcome::SecondaryActionRequired(_, _secondary_action) = auth_outcome
                    else {
                        panic!("Apple did not return tokens even though it didn't require any action from us??");
                    };
                    todo!()
                }
            }
        }
        AuthOutcome::SecondaryActionRequired(_, _)
        | AuthOutcome::AnisetteResyncRequired(_)
        | AuthOutcome::AnisetteReprovisionRequired
        | AuthOutcome::UrlSwitchingRequired(_) => todo!(),
    }

    Ok(())
}

async fn itunes_test(
    proxy: &dyn ADIProxy,
    apple_id: &str,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let device = Device {
        device_model: "MacBookPro13,2".to_string(),
        operating_system_information: "macOS;15.6.1;24G90".to_string(),
        device_uuid: "A8B31C86-359B-4D95-8950-BA5DD8FFC46F".to_string(),
    };

    let http_session = AnisetteHTTPSession::new(
        grandslam::http_session(device, APPLE_TV_BUNDLE_INFORMATION).await?,
        proxy,
    );

    if !proxy.is_machine_provisioned(grandslam::GRANDSLAM_DSID)? {
        grandslam::provision(&http_session).await?;
    }

    // Here we should fetch_auth_mode first to know if we should log in with a password.
    let auth_outcome = grandslam::login(&http_session, apple_id, password).await?;

    match &auth_outcome {
        AuthOutcome::Success(server_provided_data)
        | AuthOutcome::SecondaryActionRequired(Some(server_provided_data), _) => {
            match grandslam::parse_tokens_from_server_provided_data(server_provided_data) {
                Some((_, tokens)) => {
                    let Some((_, pet)) = tokens
                        .iter()
                        .find(|(name, _)| name == "com.apple.gs.idms.pet")
                    else {
                        todo!()
                    };

                    let device = http_session.http_session.http_session.device;
                    let http_session = AnisetteHTTPSession::new(
                        itunes::http_session(device, APPLE_TV_BUNDLE_INFORMATION).await?,
                        proxy,
                    );
                    itunes::login(&http_session, apple_id, pet.token.as_str(), 1).await?;
                }
                None => {
                    let AuthOutcome::SecondaryActionRequired(_, _secondary_action) = auth_outcome
                    else {
                        panic!("Apple did not return tokens even though it didn't require any action from us??");
                    };
                    todo!()
                }
            }
        }
        AuthOutcome::SecondaryActionRequired(_, _)
        | AuthOutcome::AnisetteResyncRequired(_)
        | AuthOutcome::AnisetteReprovisionRequired
        | AuthOutcome::UrlSwitchingRequired(_) => todo!(),
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let apple_id = env::var("APPLE_ID")?;
    let password = env::var("APPLE_PASSWORD")?;

    // Just re-use system Anisette if available
    #[cfg(target_os = "macos")]
    // on Intel Macs, we could also use a CoreADI.framework taken from an old iTunes version.
    let proxy = adid_proxy::ADIdProxy::connect();

    #[cfg(target_os = "windows")]
    let library = dlopen2::symbor::Library::open("C:\\Program Files\\iTunes\\CoreADI64.dll")?;
    #[cfg(target_os = "windows")]
    let proxy = library_coreadi::LibraryCoreADIProxy::new(&library)?;

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let proxy = {
        let core_adi_data = fs::read("nodistrib/lib/x86_64/libCoreADI.so")?;
        let proxy = AndroidCoreADIProxy::load_library(core_adi_data)?;

        proxy.set_android_id("0123456789012345")?;
        proxy.set_provisioning_path(c"./adi_files")?;

        proxy
    };

    println!("{:#?}", proxy.get_all_provisioned_accounts());

    grandslam_test(&proxy, &apple_id, &password).await?;
    // itunes_test(&proxy, &apple_id, &password).await?;

    Ok(())
}
