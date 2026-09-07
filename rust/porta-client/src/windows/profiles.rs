use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::windows::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use chrono::{SecondsFormat, Utc};
use p256::elliptic_curve::rand_core::{OsRng, RngCore as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use windows_sys::Win32::Storage::FileSystem::{
    MoveFileExW, ReplaceFileW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};
use zeroize::Zeroizing;

use crate::tunnel::Transport;

use super::dpapi;

const MAX_STORE_SIZE: u64 = 1024 * 1024;
const STATE_VERSION: u8 = 2;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub server_url: String,
    #[serde(with = "transport_serde")]
    pub transport: Transport,
    #[serde(default)]
    pub ca_path: String,
    #[serde(default)]
    pub thumbprint: String,
    pub reconnect: bool,
    #[serde(with = "duration_nanos")]
    pub reconnect_max_delay: Duration,
    pub created_at: String,
    pub updated_at: String,
}

impl Profile {
    pub fn new(
        name: impl Into<String>,
        server_url: impl Into<String>,
        transport: Transport,
    ) -> Self {
        Self {
            id: String::new(),
            name: name.into(),
            server_url: server_url.into(),
            transport,
            ca_path: String::new(),
            thumbprint: String::new(),
            reconnect: true,
            reconnect_max_delay: Duration::from_secs(30),
            created_at: String::new(),
            updated_at: String::new(),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
struct Record {
    #[serde(flatten)]
    profile: Profile,
    protected_token: String,
}

#[derive(Clone, Deserialize, Serialize)]
struct State {
    version: u8,
    #[serde(default)]
    profiles: Vec<Record>,
}

pub struct Store {
    path: PathBuf,
    state: Mutex<State>,
}

#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("profile store path is required")]
    MissingPath,
    #[error("read profile store: {0}")]
    Read(#[source] std::io::Error),
    #[error("profile store exceeds maximum size")]
    TooLarge,
    #[error("decode profile store: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("unsupported profile store version {0}")]
    UnsupportedVersion(u8),
    #[error("profile {index}: {message}")]
    InvalidRecord { index: usize, message: String },
    #[error("{0}")]
    Invalid(String),
    #[error("profile not found")]
    NotFound,
    #[error("profile token is corrupt")]
    CorruptToken,
    #[error("protect profile token: {0}")]
    Protect(#[source] std::io::Error),
    #[error("unprotect profile token: {0}")]
    Unprotect(#[source] std::io::Error),
    #[error("profile store lock is poisoned")]
    Poisoned,
    #[error("persist profile store: {0}")]
    Persist(#[source] std::io::Error),
}

impl Store {
    pub fn open(path: PathBuf) -> Result<Self, ProfileError> {
        if path.as_os_str().is_empty() {
            return Err(ProfileError::MissingPath);
        }
        let state = match fs::read(&path) {
            Ok(data) => {
                if data.len() as u64 > MAX_STORE_SIZE {
                    return Err(ProfileError::TooLarge);
                }
                let state: State = serde_json::from_slice(&data)?;
                if state.version != STATE_VERSION {
                    return Err(ProfileError::UnsupportedVersion(state.version));
                }
                for (index, record) in state.profiles.iter().enumerate() {
                    validate(&record.profile).map_err(|error| ProfileError::InvalidRecord {
                        index: index + 1,
                        message: error.to_string(),
                    })?;
                }
                state
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => State {
                version: STATE_VERSION,
                profiles: Vec::new(),
            },
            Err(error) => return Err(ProfileError::Read(error)),
        };
        Ok(Self {
            path,
            state: Mutex::new(state),
        })
    }

    pub fn list(&self) -> Result<Vec<Profile>, ProfileError> {
        let state = self.state.lock().map_err(|_| ProfileError::Poisoned)?;
        let mut profiles = state
            .profiles
            .iter()
            .map(|record| record.profile.clone())
            .collect::<Vec<_>>();
        profiles.sort_by_cached_key(|profile| profile.name.to_lowercase());
        Ok(profiles)
    }

    pub fn save(&self, mut profile: Profile, token: &str) -> Result<Profile, ProfileError> {
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);
        if profile.id.is_empty() {
            profile.id = random_id();
            profile.created_at = now.clone();
        }
        profile.updated_at = now;
        if profile.reconnect_max_delay.is_zero() {
            profile.reconnect_max_delay = Duration::from_secs(30);
        }
        profile.name = profile.name.trim().to_owned();
        profile.server_url = profile.server_url.trim().to_owned();
        validate(&profile)?;

        let mut state = self.state.lock().map_err(|_| ProfileError::Poisoned)?;
        let index = state
            .profiles
            .iter()
            .position(|record| record.profile.id == profile.id);
        let mut protected_token = String::new();
        if let Some(index) = index {
            protected_token = state.profiles[index].protected_token.clone();
            profile.created_at = state.profiles[index].profile.created_at.clone();
        }
        if !token.is_empty() {
            let protected = Zeroizing::new(
                dpapi::protect(token.as_bytes(), false, "Porta client profile")
                    .map_err(ProfileError::Protect)?,
            );
            protected_token = STANDARD_NO_PAD.encode(&protected);
        }
        if protected_token.is_empty() {
            return Err(ProfileError::Invalid(
                "profile token is required".to_owned(),
            ));
        }

        let previous = state.clone();
        let record = Record {
            profile: profile.clone(),
            protected_token,
        };
        if let Some(index) = index {
            state.profiles[index] = record;
        } else {
            state.profiles.push(record);
        }
        if let Err(error) = persist(&self.path, &state) {
            *state = previous;
            return Err(ProfileError::Persist(error));
        }
        Ok(profile)
    }

    pub fn token(&self, id: &str) -> Result<String, ProfileError> {
        let state = self.state.lock().map_err(|_| ProfileError::Poisoned)?;
        let record = state
            .profiles
            .iter()
            .find(|record| record.profile.id == id)
            .ok_or(ProfileError::NotFound)?;
        let protected = Zeroizing::new(
            STANDARD_NO_PAD
                .decode(&record.protected_token)
                .map_err(|_| ProfileError::CorruptToken)?,
        );
        let plain = Zeroizing::new(dpapi::unprotect(&protected).map_err(ProfileError::Unprotect)?);
        String::from_utf8(plain.to_vec()).map_err(|_| ProfileError::CorruptToken)
    }

    pub fn delete(&self, id: &str) -> Result<(), ProfileError> {
        let mut state = self.state.lock().map_err(|_| ProfileError::Poisoned)?;
        let index = state
            .profiles
            .iter()
            .position(|record| record.profile.id == id)
            .ok_or(ProfileError::NotFound)?;
        let previous = state.clone();
        state.profiles.remove(index);
        if let Err(error) = persist(&self.path, &state) {
            *state = previous;
            return Err(ProfileError::Persist(error));
        }
        Ok(())
    }
}

fn validate(profile: &Profile) -> Result<(), ProfileError> {
    if profile.id.is_empty() || profile.id.len() > 64 {
        return Err(ProfileError::Invalid("profile ID is invalid".to_owned()));
    }
    if profile.name.is_empty() || profile.name.chars().count() > 80 {
        return Err(ProfileError::Invalid(
            "profile name must contain 1 to 80 characters".to_owned(),
        ));
    }
    if profile.server_url.is_empty() {
        return Err(ProfileError::Invalid("server URL is required".to_owned()));
    }
    Ok(())
}

fn random_id() -> String {
    let mut bytes = [0_u8; 12];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn persist(path: &Path, state: &State) -> std::io::Result<()> {
    let mut data = serde_json::to_vec_pretty(state)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    data.push(b'\n');
    let directory = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "profile store has no parent directory",
        )
    })?;
    fs::create_dir_all(directory)?;
    let mut random = [0_u8; 8];
    OsRng.fill_bytes(&mut random);
    let pending = directory.join(format!(".profiles-{}.tmp", hex::encode(random)));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pending)?;
        file.write_all(&data)?;
        file.sync_all()?;
        drop(file);
        replace_file(&pending, path)
    })();
    let _ = fs::remove_file(&pending);
    result
}

fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    let source = wide(source);
    let destination_wide = wide(destination);
    let success = unsafe {
        if destination.exists() {
            ReplaceFileW(
                destination_wide.as_ptr(),
                source.as_ptr(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                std::ptr::null(),
            )
        } else {
            MoveFileExW(
                source.as_ptr(),
                destination_wide.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        }
    };
    if success == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

mod transport_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::tunnel::Transport;

    pub fn serialize<S>(value: &Transport, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match value {
            Transport::Auto => "auto",
            Transport::Http2 => "h2",
            Transport::Http3 => "h3",
        })
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Transport, D::Error>
    where
        D: Deserializer<'de>,
    {
        match String::deserialize(deserializer)?.as_str() {
            "auto" => Ok(Transport::Auto),
            "h2" => Ok(Transport::Http2),
            "h3" => Ok(Transport::Http3),
            value => Err(serde::de::Error::custom(format!(
                "unsupported transport {value}"
            ))),
        }
    }
}

mod duration_nanos {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let nanos = u64::try_from(value.as_nanos()).map_err(serde::ser::Error::custom)?;
        serializer.serialize_u64(nanos)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Duration::from_nanos(u64::deserialize(deserializer)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_store_preserves_schema_and_protected_tokens() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profiles.json");
        let store = Store::open(path.clone()).unwrap();
        let saved = store
            .save(
                Profile::new("Office", "https://porta.example:8443", Transport::Http3),
                "secret-token",
            )
            .unwrap();
        assert_eq!(store.token(&saved.id).unwrap(), "secret-token");

        let data = fs::read_to_string(&path).unwrap();
        assert!(data.ends_with('\n'));
        assert!(data.contains("\"version\": 2"));
        assert!(data.contains("\"reconnect_max_delay\": 30000000000"));
        assert!(!data.contains("secret-token"));

        let reopened = Store::open(path).unwrap();
        assert_eq!(reopened.token(&saved.id).unwrap(), "secret-token");
        assert_eq!(reopened.list().unwrap()[0].transport, Transport::Http3);
    }

    #[test]
    fn updates_keep_existing_tokens_and_sort_profiles() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path().join("profiles.json")).unwrap();
        let zulu = store
            .save(
                Profile::new("Zulu", "https://zulu.example", Transport::Auto),
                "zulu-token",
            )
            .unwrap();
        store
            .save(
                Profile::new("alpha", "https://alpha.example", Transport::Http2),
                "alpha-token",
            )
            .unwrap();
        let mut updated = zulu.clone();
        updated.name = "Beta".to_owned();
        let updated = store.save(updated, "").unwrap();
        assert_eq!(store.token(&updated.id).unwrap(), "zulu-token");
        assert_eq!(
            store
                .list()
                .unwrap()
                .into_iter()
                .map(|profile| profile.name)
                .collect::<Vec<_>>(),
            vec!["alpha".to_owned(), "Beta".to_owned()]
        );
        store.delete(&updated.id).unwrap();
        assert!(matches!(
            store.token(&updated.id),
            Err(ProfileError::NotFound)
        ));
    }
}
