//! Large sessions stay in Credential Manager, split into bounded binary entries.
//! A generation-specific index is committed last so failed writes preserve the
//! previous session.
use super::{keyring_entry, KeychainResult};

const PREFIX: &str = "super-sideloader-chunks-v1:";
const CHUNK_BYTES: usize = 2400; // Below Windows' 2560-byte credential blob limit.
const MAX_CHUNKS: usize = 4096;

struct Index {
    generation: uuid::Uuid,
    count: usize,
}

impl Index {
    fn parse(value: &str) -> KeychainResult<Self> {
        let invalid = || "Invalid account session chunk index".to_string();
        let value = value.strip_prefix(PREFIX).ok_or_else(invalid)?;
        let (generation, count) = value.split_once(':').ok_or_else(invalid)?;
        let generation = uuid::Uuid::parse_str(generation).map_err(|_| invalid())?;
        let count = count.parse::<usize>().map_err(|_| invalid())?;
        if count == 0 || count > MAX_CHUNKS {
            return Err(invalid());
        }
        Ok(Self { generation, count })
    }

    fn encode(&self) -> String {
        format!("{PREFIX}{}:{}", self.generation, self.count)
    }
    fn chunk(&self, account: &str, number: usize) -> KeychainResult<keyring::Entry> {
        keyring_entry(&format!("{account}:chunks:{}:{number}", self.generation))
    }
    fn remove(&self, account: &str) -> KeychainResult<()> {
        let mut failure = None;
        for number in 0..self.count {
            if let Err(error) = self
                .chunk(account, number)
                .and_then(|entry| remove_entry(&entry))
            {
                failure = Some(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

fn read_index(account: &str) -> KeychainResult<Option<String>> {
    match keyring_entry(account)?.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(format!("Failed to read account session: {error}")),
    }
}

fn remove_entry(entry: &keyring::Entry) -> KeychainResult<()> {
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(format!("Failed to remove account session entry: {error}")),
    }
}

pub(super) fn load(account: &str) -> KeychainResult<Option<String>> {
    let Some(value) = read_index(account)? else {
        return Ok(None);
    };
    let index = Index::parse(&value)?;
    let mut bytes = Vec::new();
    for number in 0..index.count {
        let chunk = index
            .chunk(account, number)?
            .get_secret()
            .map_err(|error| format!("Failed to read account session chunk {number}: {error}"))?;
        if chunk.is_empty() || chunk.len() > CHUNK_BYTES {
            return Err("Invalid account session chunk size".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| "Invalid account session encoding".into())
}

pub(super) fn save(account: &str, contents: &str) -> KeychainResult<()> {
    save_with_commit(account, contents, |entry, index| {
        entry
            .set_password(index)
            .map_err(|error| format!("Failed to commit account session: {error}"))
    })
}

fn save_with_commit(
    account: &str,
    contents: &str,
    commit: impl FnOnce(&keyring::Entry, &str) -> KeychainResult<()>,
) -> KeychainResult<()> {
    let count = contents.len().div_ceil(CHUNK_BYTES);
    if count == 0 || count > MAX_CHUNKS {
        return Err("Account session size is invalid".into());
    }
    let old = read_index(account)?
        .map(|value| Index::parse(&value))
        .transpose()?;
    let index = Index {
        generation: uuid::Uuid::new_v4(),
        count,
    };
    let result = (|| {
        for (number, chunk) in contents.as_bytes().chunks(CHUNK_BYTES).enumerate() {
            index
                .chunk(account, number)?
                .set_secret(chunk)
                .map_err(|error| {
                    format!("Failed to save account session chunk {number}: {error}")
                })?;
        }
        commit(&keyring_entry(account)?, &index.encode())
    })();
    if result.is_err() {
        if let Err(error) = index.remove(account) {
            log::warn!("Failed to clean up incomplete session: {error}");
        }
        return result;
    }
    if let Some(old) = old {
        if let Err(error) = old.remove(account) {
            log::warn!("Failed to clean up old session: {error}");
        }
    }
    Ok(())
}

pub(super) fn delete(account: &str) -> KeychainResult<()> {
    let index = read_index(account)?
        .map(|value| Index::parse(&value))
        .transpose()?;
    remove_entry(&keyring_entry(account)?)?;
    if let Some(index) = index {
        index.remove(account)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_indexes() {
        assert!(Index::parse("version = 1").is_err());
        for suffix in [
            "invalid:1",
            "00000000-0000-0000-0000-000000000000:0",
            "00000000-0000-0000-0000-000000000000:4097",
        ] {
            assert!(Index::parse(&format!("{PREFIX}{suffix}")).is_err());
        }
    }

    #[test]
    #[ignore = "writes synthetic entries to the native Windows Credential Manager"]
    fn native_large_session_round_trip_update_failure_and_delete() {
        let account = format!("storage-test-{}", uuid::Uuid::new_v4());
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = delete(&self.0);
            }
        }
        let _cleanup = Cleanup(account.clone());
        assert!(load(&account).unwrap().is_none());
        let contents = "synthetic-token-😀-é\n".repeat(2000);
        save(&account, &contents).unwrap();
        assert_eq!(load(&account).unwrap().unwrap(), contents);
        let old = Index::parse(&read_index(&account).unwrap().unwrap()).unwrap();
        let mut failed_index = None;
        let failed = save_with_commit(&account, &contents, |_, value| {
            failed_index = Some(Index::parse(value).unwrap());
            Err("Simulated commit failure".into())
        });
        assert!(failed.is_err());
        assert_eq!(load(&account).unwrap().unwrap(), contents);
        let failed_index = failed_index.unwrap();
        for i in 0..failed_index.count {
            assert!(matches!(
                failed_index.chunk(&account, i).unwrap().get_secret(),
                Err(keyring::Error::NoEntry)
            ));
        }
        save(&account, "replacement").unwrap();
        assert_eq!(load(&account).unwrap().unwrap(), "replacement");
        for i in 0..old.count {
            assert!(matches!(
                old.chunk(&account, i).unwrap().get_secret(),
                Err(keyring::Error::NoEntry)
            ));
        }
        delete(&account).unwrap();
        assert!(load(&account).unwrap().is_none());
    }
}
