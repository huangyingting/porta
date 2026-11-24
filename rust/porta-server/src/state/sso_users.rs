//! Accounts provisioned by user single sign-on. Each identity-provider
//! subject maps to one client account and that account's token, sealed by
//! the portal with a key derived from `PORTA_ADMIN_TOKEN`, so a user who
//! signs in again sees their setup without a new token. The file alone does
//! not reveal tokens.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use thiserror::Error;
use time::OffsetDateTime;

const STORE_VERSION: u32 = 1;
pub const MAX_SSO_USERS: usize = 100_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SsoUser {
    /// The identity provider's stable `sub` claim.
    pub subject: String,
    /// The verified email at the latest sign-in.
    pub email: String,
    pub client_id: String,
    pub sealed_token: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Error)]
pub enum SsoUserError {
    #[error("{0}")]
    Invalid(String),
    #[error("SSO user store I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("decode SSO user store: {0}")]
    Decode(#[from] serde_json::Error),
}

#[derive(Default, Deserialize, Serialize)]
struct StoreFile {
    version: u32,
    users: Vec<SsoUser>,
}

pub struct SsoUsers {
    path: PathBuf,
    users: Mutex<Vec<SsoUser>>,
}

impl SsoUsers {
    /// Opens the store at `path`, creating an empty one if it is missing.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, SsoUserError> {
        let path = path.into();
        let users = match std::fs::read(&path) {
            Ok(data) => {
                let file: StoreFile = serde_json::from_slice(&data)?;
                if file.version != STORE_VERSION {
                    return Err(SsoUserError::Invalid(format!(
                        "unsupported SSO user store version {}",
                        file.version
                    )));
                }
                file.users
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            path,
            users: Mutex::new(users),
        })
    }

    pub fn get(&self, subject: &str) -> Option<SsoUser> {
        self.users
            .lock()
            .iter()
            .find(|user| user.subject == subject)
            .cloned()
    }

    /// Adds `user`, replacing any record with the same subject.
    pub fn put(&self, user: SsoUser) -> Result<(), SsoUserError> {
        let mut users = self.users.lock();
        let mut candidate = users.clone();
        match candidate
            .iter()
            .position(|existing| existing.subject == user.subject)
        {
            Some(index) => candidate[index] = user,
            None if candidate.len() >= MAX_SSO_USERS => {
                return Err(SsoUserError::Invalid(
                    "too many single sign-on users".to_owned(),
                ))
            }
            None => candidate.push(user),
        }
        persist(&self.path, &candidate)?;
        *users = candidate;
        Ok(())
    }
}

fn persist(path: &Path, users: &[SsoUser]) -> Result<(), SsoUserError> {
    let data = serde_json::to_vec_pretty(&StoreFile {
        version: STORE_VERSION,
        users: users.to_vec(),
    })?;
    let temporary = path.with_extension("json.new");
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&data)?;
        file.sync_all()?;
    }
    std::fs::rename(&temporary, path)?;
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// The lowercase domain of an email address.
pub fn email_domain(email: &str) -> Option<String> {
    let (local, domain) = email.trim().rsplit_once('@')?;
    let domain = domain.to_ascii_lowercase();
    (!local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.'))
    .then_some(domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(subject: &str, client: &str) -> SsoUser {
        SsoUser {
            subject: subject.to_owned(),
            email: format!("{subject}@example.com"),
            client_id: client.to_owned(),
            sealed_token: "sealed".to_owned(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn users_persist_privately_and_are_replaced_by_subject() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sso-users.json");
        let store = SsoUsers::open(&path).unwrap();
        assert!(store.get("alice").is_none());
        store.put(user("alice", "0001")).unwrap();
        store.put(user("bob", "0002")).unwrap();
        store.put(user("alice", "0003")).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let reopened = SsoUsers::open(&path).unwrap();
        assert_eq!(reopened.get("alice").unwrap().client_id, "0003");
        assert_eq!(reopened.get("bob").unwrap().client_id, "0002");
    }

    #[test]
    fn email_domains_are_lowercase_and_well_formed() {
        assert_eq!(
            email_domain("Ann@Example.COM").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            email_domain("a@b@corp.example").as_deref(),
            Some("corp.example")
        );
        for invalid in [
            "",
            "ann",
            "@example.com",
            "ann@",
            "ann@localhost",
            "ann@.example",
            "ann@example.",
        ] {
            assert_eq!(email_domain(invalid), None, "{invalid}");
        }
    }

    use std::os::unix::fs::PermissionsExt as _;
}
