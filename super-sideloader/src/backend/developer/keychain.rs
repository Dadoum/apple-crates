#[cfg(target_os = "windows")]
#[path = "windows_session_store.rs"]
mod windows_session_store;

use crate::backend::{BackendError, BackendResult};
use grandslam::{AuthToken, Token};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const KEYCHAIN_SESSION_VERSION: u32 = 1;
const KEYRING_SERVICE: &str = "com.Dadoum.Super-Sideloader";
const TOKEN_EXPIRY_GRACE_MILLIS: u64 = 5 * 60 * 1000;

type KeychainResult<T> = Result<T, String>;
type SessionCache = HashMap<String, CachedKeychainLookup>;
type SessionCacheGuard = MutexGuard<'static, SessionCache>;

static SESSION_CACHE: OnceLock<Mutex<SessionCache>> = OnceLock::new();

#[derive(Clone, Debug)]
struct CachedKeychainSession {
    encoded_contents: String,
    session: DeveloperAccountKeychainSession,
}

#[derive(Clone, Debug)]
enum CachedKeychainLookup {
    Session(CachedKeychainSession),
    Missing,
    Failed(String),
}

impl CachedKeychainLookup {
    fn result(&self) -> BackendResult<Option<DeveloperAccountKeychainSession>> {
        match self {
            Self::Session(cached) => Ok(Some(cached.session.clone())),
            Self::Missing => Ok(None),
            Self::Failed(error) => Err(BackendError::Keychain(error.clone())),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct DeveloperAccountKeychainSession {
    pub(crate) version: u32,
    pub(crate) auth_token: AuthToken,
    pub(crate) heartbeat_token: Token,
    pub(crate) xcode_token: Token,
}

impl DeveloperAccountKeychainSession {
    pub(crate) fn new(auth_token: AuthToken, heartbeat_token: Token, xcode_token: Token) -> Self {
        Self {
            version: KEYCHAIN_SESSION_VERSION,
            auth_token,
            heartbeat_token,
            xcode_token,
        }
    }

    pub(crate) fn expires_at_millis(&self) -> u64 {
        self.heartbeat_token.expiry_epoch_millis
    }
}

pub(crate) fn save_keychain_session(
    account_id: &str,
    session: &DeveloperAccountKeychainSession,
) -> BackendResult<()> {
    let contents = encode_keychain_session(session).map_err(BackendError::Keychain)?;
    let mut cache = lock_session_cache()?;
    if matches!(
        cache.get(account_id),
        Some(CachedKeychainLookup::Session(cached))
            if cached.encoded_contents == contents
    ) {
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    windows_session_store::save(account_id, &contents).map_err(BackendError::Keychain)?;
    #[cfg(not(target_os = "windows"))]
    keyring_entry(account_id)
        .map_err(BackendError::Keychain)?
        .set_password(&contents)
        .map_err(|error| {
            BackendError::Keychain(format!(
                "Failed to save account session to the system keychain: {error}"
            ))
        })?;
    cache_keychain_session_locked(&mut cache, account_id, session.clone(), contents);
    Ok(())
}

pub(crate) fn load_keychain_session(
    account_id: &str,
) -> BackendResult<Option<DeveloperAccountKeychainSession>> {
    #[cfg(target_os = "windows")]
    {
        load_keychain_session_once(account_id, || windows_session_store::load(account_id))
    }
    #[cfg(not(target_os = "windows"))]
    load_keychain_session_once(account_id, || {
        let entry = keyring_entry(account_id)?;
        match entry.get_password() {
            Ok(contents) => Ok(Some(contents)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(format!(
                "Failed to read account session from the system keychain: {error}"
            )),
        }
    })
}

fn load_keychain_session_once(
    account_id: &str,
    read: impl FnOnce() -> KeychainResult<Option<String>>,
) -> BackendResult<Option<DeveloperAccountKeychainSession>> {
    let mut cache = lock_session_cache()?;
    if let Some(cached) = cache.get(account_id) {
        return cached.result();
    }

    let lookup = match read() {
        Ok(Some(contents)) => match decode_keychain_session(&contents) {
            Ok(session) => CachedKeychainLookup::Session(session),
            Err(error) => CachedKeychainLookup::Failed(error),
        },
        Ok(None) => CachedKeychainLookup::Missing,
        Err(error) => CachedKeychainLookup::Failed(error),
    };
    let result = lookup.result();
    cache.insert(account_id.to_string(), lookup);
    result
}

pub(crate) fn cache_keychain_session(
    account_id: &str,
    session: &DeveloperAccountKeychainSession,
) -> BackendResult<()> {
    let contents = encode_keychain_session(session).map_err(BackendError::Keychain)?;
    let mut cache = lock_session_cache()?;
    cache_keychain_session_locked(&mut cache, account_id, session.clone(), contents);
    Ok(())
}

pub(crate) fn delete_keychain_session(account_id: &str) -> BackendResult<()> {
    let mut cache = lock_session_cache()?;
    cache.remove(account_id);

    #[cfg(target_os = "windows")]
    {
        windows_session_store::delete(account_id).map_err(BackendError::Keychain)
    }
    #[cfg(not(target_os = "windows"))]
    match keyring_entry(account_id)
        .map_err(BackendError::Keychain)?
        .delete_credential()
    {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(BackendError::Keychain(format!(
            "Failed to remove account session from the system keychain: {error}"
        ))),
    }
}

#[allow(dead_code)]
pub(crate) fn keyring_service() -> &'static str {
    KEYRING_SERVICE
}

#[allow(dead_code)]
pub(crate) fn keyring_account_name(account_id: &str) -> String {
    format!("account-session:{account_id}")
}

pub(crate) fn token_is_near_expiry(expiry_epoch_millis: u64) -> bool {
    if expiry_epoch_millis == 0 {
        return false;
    }
    current_epoch_millis().saturating_add(TOKEN_EXPIRY_GRACE_MILLIS) >= expiry_epoch_millis
}

pub(crate) fn current_epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn keyring_entry(account_id: &str) -> KeychainResult<keyring::Entry> {
    keyring::Entry::new(keyring_service(), &keyring_account_name(account_id))
        .map_err(|error| format!("Failed to access the system keychain: {error}"))
}

fn encode_keychain_session(session: &DeveloperAccountKeychainSession) -> KeychainResult<String> {
    toml::to_string(session)
        .map_err(|error| format!("Failed to encode account keychain payload: {error}"))
}

fn decode_keychain_session(contents: &str) -> KeychainResult<CachedKeychainSession> {
    let mut session: DeveloperAccountKeychainSession = toml::from_str(contents)
        .map_err(|error| format!("Failed to decode account keychain payload: {error}"))?;
    session.version = KEYCHAIN_SESSION_VERSION;
    let encoded_contents = encode_keychain_session(&session)?;
    Ok(CachedKeychainSession {
        encoded_contents,
        session,
    })
}

fn session_cache() -> &'static Mutex<SessionCache> {
    SESSION_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_session_cache() -> BackendResult<SessionCacheGuard> {
    session_cache().lock().map_err(|_| {
        BackendError::Keychain("Failed to lock account keychain session cache.".to_string())
    })
}

fn cache_keychain_session_locked(
    cache: &mut SessionCache,
    account_id: &str,
    session: DeveloperAccountKeychainSession,
    encoded_contents: String,
) {
    cache.insert(
        account_id.to_string(),
        CachedKeychainLookup::Session(CachedKeychainSession {
            encoded_contents,
            session,
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    fn test_account_id(label: &str) -> String {
        format!("{label}-{}-{}", std::process::id(), current_epoch_millis())
    }

    fn test_session() -> DeveloperAccountKeychainSession {
        DeveloperAccountKeychainSession::new(
            AuthToken {
                alt_dsid: "alt-dsid".to_string(),
                idms_token: "idms-token".to_string(),
                session_key: vec![1, 2, 3],
                cookie: vec![4, 5, 6],
                identity_token: "identity-token".to_string(),
            },
            Token {
                duration: 3600,
                expiry_epoch_millis: current_epoch_millis() + 3_600_000,
                token: "heartbeat-token".to_string(),
            },
            Token {
                duration: 3600,
                expiry_epoch_millis: current_epoch_millis() + 3_600_000,
                token: "xcode-token".to_string(),
            },
        )
    }

    #[test]
    fn zero_expiry_is_treated_as_unknown_not_expired() {
        assert!(!token_is_near_expiry(0));
    }

    #[test]
    fn near_expiry_is_detected() {
        assert!(token_is_near_expiry(current_epoch_millis() + 1));
    }

    #[test]
    fn concurrent_successful_lookups_read_the_keychain_once() {
        let account_id = Arc::new(test_account_id("concurrent-session"));
        let contents = Arc::new(encode_keychain_session(&test_session()).unwrap());
        let reads = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(2));

        let handles = (0..2)
            .map(|_| {
                let account_id = Arc::clone(&account_id);
                let contents = Arc::clone(&contents);
                let reads = Arc::clone(&reads);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    load_keychain_session_once(&account_id, || {
                        reads.fetch_add(1, Ordering::SeqCst);
                        thread::sleep(Duration::from_millis(25));
                        Ok(Some(contents.as_ref().clone()))
                    })
                    .unwrap()
                    .unwrap()
                })
            })
            .collect::<Vec<_>>();

        for handle in handles {
            assert_eq!(handle.join().unwrap().auth_token.idms_token, "idms-token");
        }
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn missing_keychain_session_is_memoized() {
        let account_id = test_account_id("missing-session");
        let reads = Cell::new(0);

        for _ in 0..2 {
            let loaded = load_keychain_session_once(&account_id, || {
                reads.set(reads.get() + 1);
                Ok(None)
            })
            .unwrap();
            assert!(loaded.is_none());
        }

        assert_eq!(reads.get(), 1);
    }

    #[test]
    fn malformed_keychain_session_is_memoized() {
        let account_id = test_account_id("malformed-session");
        let reads = Cell::new(0);

        for _ in 0..2 {
            let error = load_keychain_session_once(&account_id, || {
                reads.set(reads.get() + 1);
                Ok(Some("not valid TOML".to_string()))
            })
            .unwrap_err();
            assert!(error
                .user_message()
                .contains("decode account keychain payload"));
        }

        assert_eq!(reads.get(), 1);
    }

    #[test]
    fn failed_keychain_lookup_is_memoized_and_can_be_replaced() {
        let account_id = test_account_id("failed-session");
        let reads = Cell::new(0);

        for _ in 0..2 {
            let error = load_keychain_session_once(&account_id, || {
                reads.set(reads.get() + 1);
                Err("Keychain access was denied.".to_string())
            })
            .unwrap_err();
            assert!(error.user_message().contains("access was denied"));
        }
        assert_eq!(reads.get(), 1);

        let session = test_session();
        cache_keychain_session(&account_id, &session).unwrap();
        let loaded = load_keychain_session(&account_id).unwrap().unwrap();
        assert_eq!(loaded.auth_token.idms_token, session.auth_token.idms_token);
    }
}
