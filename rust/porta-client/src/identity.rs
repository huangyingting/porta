use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use porta_wire::device_auth::Proof;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::device::{self, DeviceProofError};

const STATE_VERSION: u8 = 1;
const MAX_IDENTITY_SIZE: u64 = 1024 * 1024;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error(
        "machine name must contain an ASCII letter or digit; rename this machine in OS settings"
    )]
    InvalidName,
    #[error("decode device identity: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("unsupported device identity version {0}")]
    UnsupportedVersion(u8),
    #[error("device identity key is corrupt")]
    CorruptKey,
    #[error("device identity path is required")]
    MissingPath,
    #[error("locate user config directory")]
    MissingConfigDirectory,
    #[error("user config directory is not absolute")]
    RelativeConfigDirectory,
    #[error("read machine name: {0}")]
    Hostname(#[source] std::io::Error),
    #[error("prepare device identity storage: {0}")]
    Prepare(#[source] std::io::Error),
    #[error("lock device identity: {0}")]
    Lock(#[source] std::io::Error),
    #[error("read device identity: {0}")]
    Read(#[source] std::io::Error),
    #[error("persist device identity: {0}")]
    Persist(#[source] std::io::Error),
    #[error(
        "device identity file must be a private, singly linked regular file owned by the current user"
    )]
    InsecureFile,
    #[error(
        "device identity directory must be a non-symlink directory owned by the current user and not writable by other users"
    )]
    InsecureDirectory,
    #[error("create device proof: {0}")]
    Proof(#[from] DeviceProofError),
}

#[derive(Deserialize, Serialize)]
struct StoredIdentity {
    version: u8,
    private_key: String,
}

pub struct Identity {
    pub id: String,
    pub name: String,
    signing_key: SigningKey,
}

impl Identity {
    pub fn load_or_create(path: &Path, name: &str) -> Result<Self, IdentityError> {
        if path.as_os_str().is_empty() {
            return Err(IdentityError::MissingPath);
        }
        let name = normalize_name(name)?;
        prepare_storage(path)?;
        let lock = open_private(&lock_path(path), true).map_err(IdentityError::Lock)?;
        lock_exclusive(&lock).map_err(IdentityError::Lock)?;
        let signing_key = match read_private(path) {
            Ok(encoded) => decode(&encoded)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let key = SigningKey::random(&mut OsRng);
                persist(path, &key)?;
                key
            }
            Err(error) => return Err(IdentityError::Read(error)),
        };
        Self::from_signing_key(signing_key, name)
    }

    pub fn from_signing_key(
        signing_key: SigningKey,
        name: impl Into<String>,
    ) -> Result<Self, IdentityError> {
        let name = normalize_name(&name.into())?;
        let encoded_public_key = signing_key
            .verifying_key()
            .to_public_key_der()
            .map_err(|_| IdentityError::CorruptKey)?;
        let id = porta_wire::device_auth::device_id_from_encoded(encoded_public_key.as_bytes())
            .map_err(|_| IdentityError::CorruptKey)?;
        Ok(Self {
            id,
            name,
            signing_key,
        })
    }

    pub fn proof(&self, token: &str, method: &str, path: &str) -> Result<Proof, IdentityError> {
        Ok(device::create_proof(
            &self.signing_key,
            &self.name,
            token,
            method,
            path,
            SystemTime::now(),
        )?)
    }
}

#[cfg(all(target_os = "linux", not(target_os = "android")))]
pub fn current() -> Result<Identity, IdentityError> {
    let path = identity_path()?;
    let name = hostname().map_err(IdentityError::Hostname)?;
    Identity::load_or_create(&path, &name)
}

#[cfg(all(target_os = "linux", not(target_os = "android")))]
pub fn identity_path() -> Result<PathBuf, IdentityError> {
    if unsafe { libc::geteuid() } == 0 {
        return Ok(PathBuf::from("/var/lib/porta/client-identity.json"));
    }
    let directory = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .ok_or(IdentityError::MissingConfigDirectory)?;
    if !directory.is_absolute() {
        return Err(IdentityError::RelativeConfigDirectory);
    }
    Ok(directory.join("porta/client-identity.json"))
}

pub fn normalize_name(value: &str) -> Result<String, IdentityError> {
    let mut normalized = String::with_capacity(value.len().min(64));
    let mut invalid = false;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
            normalized.push(character);
            invalid = false;
        } else if !invalid {
            normalized.push('-');
            invalid = true;
        }
    }
    let normalized = normalized.trim_matches(['-', '.', '_']);
    if normalized.is_empty() {
        return Err(IdentityError::InvalidName);
    }
    Ok(normalized[..normalized.len().min(64)].to_owned())
}

pub fn encode(signing_key: &SigningKey) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
    let encoded = signing_key
        .to_pkcs8_der()
        .map_err(|_| IdentityError::CorruptKey)?;
    let stored = StoredIdentity {
        version: STATE_VERSION,
        private_key: STANDARD_NO_PAD.encode(encoded.as_bytes()),
    };
    let mut output = serde_json::to_vec_pretty(&stored)?;
    output.push(b'\n');
    Ok(Zeroizing::new(output))
}

pub fn decode(encoded: &[u8]) -> Result<SigningKey, IdentityError> {
    let stored: StoredIdentity = serde_json::from_slice(encoded)?;
    if stored.version != STATE_VERSION {
        return Err(IdentityError::UnsupportedVersion(stored.version));
    }
    let private_key = Zeroizing::new(
        STANDARD_NO_PAD
            .decode(stored.private_key)
            .map_err(|_| IdentityError::CorruptKey)?,
    );
    SigningKey::from_pkcs8_der(&private_key).map_err(|_| IdentityError::CorruptKey)
}

fn lock_path(path: &Path) -> PathBuf {
    let mut value = OsString::from(path.as_os_str());
    value.push(".lock");
    PathBuf::from(value)
}

fn prepare_storage(path: &Path) -> Result<(), IdentityError> {
    let directory = path.parent().ok_or(IdentityError::MissingPath)?;
    fs::create_dir_all(directory).map_err(IdentityError::Prepare)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let metadata = fs::symlink_metadata(directory).map_err(IdentityError::Prepare)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(IdentityError::InsecureDirectory);
        }
    }
    Ok(())
}

fn open_private(path: &Path, create: bool) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(create).create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    validate_private(&file)?;
    Ok(file)
}

fn read_private(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut file = open_private(path, false)?;
    let mut encoded = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_IDENTITY_SIZE + 1)
        .read_to_end(&mut encoded)?;
    if encoded.len() as u64 > MAX_IDENTITY_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "device identity file exceeds maximum size",
        ));
    }
    Ok(encoded)
}

fn validate_private(_file: &File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let metadata = _file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                IdentityError::InsecureFile,
            ));
        }
    }
    Ok(())
}

fn lock_exclusive(_file: &File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;

        if unsafe { libc::flock(_file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn persist(path: &Path, signing_key: &SigningKey) -> Result<(), IdentityError> {
    let encoded = encode(signing_key)?;
    let directory = path.parent().ok_or(IdentityError::MissingPath)?;
    let mut random = [0_u8; 8];
    rand::rng().fill_bytes(&mut random);
    let pending = directory.join(format!(".device-identity-{}.tmp", hex::encode(random)));
    let result = (|| -> std::io::Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;

            options
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let mut file = options.open(&pending)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&pending, path)?;
        File::open(directory)?.sync_all()
    })();
    let _ = fs::remove_file(&pending);
    result.map_err(IdentityError::Persist)
}

#[cfg(all(target_os = "linux", not(target_os = "android")))]
fn hostname() -> std::io::Result<String> {
    let mut buffer = [0_u8; 256];
    if unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let length = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    String::from_utf8(buffer[..length].to_vec())
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readable_machine_names_match_the_go_client() {
        for (name, expected) in [
            ("DESKTOP-123", "DESKTOP-123"),
            ("workstation.example", "workstation.example"),
            ("My Tablet", "My-Tablet"),
            ("  .._John's / Tablet_..  ", "John-s-Tablet"),
            ("Lab_PC-01", "Lab_PC-01"),
            ("123", "123"),
            ("Pad 📱", "Pad"),
            ("平板-01", "01"),
            ("tablet\r\nInjected: header", "tablet-Injected-header"),
        ] {
            let normalized = normalize_name(name).unwrap();
            assert_eq!(normalized, expected);
            assert_eq!(normalize_name(&normalized).unwrap(), normalized);
        }
        assert_eq!(normalize_name(&"a".repeat(80)).unwrap(), "a".repeat(64));
        for name in ["", " \r\n ", ".._--", "平板", "\0"] {
            assert!(normalize_name(name).is_err(), "{name:?}");
        }
    }

    #[test]
    fn identity_state_round_trips_without_changing_the_key() {
        let key = SigningKey::random(&mut OsRng);
        let encoded = encode(&key).unwrap();
        assert!(encoded.ends_with(b"\n"));
        let decoded = decode(&encoded).unwrap();
        assert_eq!(
            key.verifying_key().to_public_key_der().unwrap(),
            decoded.verifying_key().to_public_key_der().unwrap()
        );
    }

    #[test]
    fn identity_state_rejects_versions_and_corrupt_keys() {
        assert!(matches!(
            decode(br#"{"version":2,"private_key":"AA"}"#),
            Err(IdentityError::UnsupportedVersion(2))
        ));
        assert!(matches!(
            decode(br#"{"version":1,"private_key":"AA"}"#),
            Err(IdentityError::CorruptKey)
        ));
    }

    #[test]
    fn persistent_identity_reuses_key_and_never_replaces_corruption() {
        let directory = tempfile::tempdir().unwrap();
        let private = directory.path().join("private");
        fs::create_dir(&private).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = private.join("client-identity.json");
        let first = Identity::load_or_create(&path, "Office PC").unwrap();
        let second = Identity::load_or_create(&path, "Renamed PC").unwrap();
        assert_eq!(first.id, second.id);
        assert_eq!(first.name, "Office-PC");
        assert_eq!(second.name, "Renamed-PC");

        fs::write(&path, b"not json").unwrap();
        assert!(matches!(
            Identity::load_or_create(&path, "Office PC"),
            Err(IdentityError::Decode(_))
        ));
    }
}
