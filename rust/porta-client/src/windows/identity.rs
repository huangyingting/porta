use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use fs2::FileExt as _;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::SystemInformation::{ComputerNameDnsHostname, GetComputerNameExW};
use zeroize::Zeroizing;

use crate::identity::{Identity, IdentityError};

use super::dpapi;
use super::paths;

const MAX_IDENTITY_SIZE: u64 = 1024 * 1024;
const STATE_VERSION: u8 = 1;

#[derive(Deserialize, Serialize)]
struct StoredIdentity {
    version: u8,
    private_key: String,
}

pub fn current() -> Result<Identity, IdentityError> {
    let path = identity_path()?;
    let name = hostname().map_err(IdentityError::Hostname)?;
    load_or_create(&path, &name)
}

pub fn identity_path() -> Result<PathBuf, IdentityError> {
    Ok(paths::program_data()
        .map_err(IdentityError::Prepare)?
        .join("Porta")
        .join("client-identity.json"))
}

fn load_or_create(path: &Path, name: &str) -> Result<Identity, IdentityError> {
    let directory = path.parent().ok_or(IdentityError::MissingPath)?;
    let _directory = prepare_directory(directory)?;

    let lock_path = path.with_file_name("client-identity.lock");
    let lock = open_private(&lock_path, true).map_err(IdentityError::Lock)?;
    lock.lock_exclusive().map_err(IdentityError::Lock)?;

    let signing_key = match read_private(path) {
        Ok(encoded) => decode(&encoded)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let key = SigningKey::random(&mut OsRng);
            persist(path, &key)?;
            key
        }
        Err(error) => return Err(IdentityError::Read(error)),
    };
    Identity::from_signing_key(signing_key, name)
}

fn prepare_directory(path: &Path) -> Result<File, IdentityError> {
    paths::prepare_admin_directory(path).map_err(IdentityError::Prepare)
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

fn open_private(path: &Path, create: bool) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(create);
    if create {
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    } else {
        options.share_mode(FILE_SHARE_READ);
    }
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let (file, created) = if create {
        match options.create_new(true).open(path) {
            Ok(file) => (file, true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                options.create_new(false);
                (options.open(path)?, false)
            }
            Err(error) => return Err(error),
        }
    } else {
        (options.open(path)?, false)
    };
    if created {
        paths::secure_new_admin_file(path, &file)?;
    } else {
        paths::adopt_admin_file(path, &file)?;
    }
    Ok(file)
}

fn persist(path: &Path, signing_key: &SigningKey) -> Result<(), IdentityError> {
    let encoded = signing_key
        .to_pkcs8_der()
        .map_err(|_| IdentityError::CorruptKey)?;
    let protected = Zeroizing::new(
        dpapi::protect(encoded.as_bytes(), true, "Porta device identity")
            .map_err(IdentityError::Persist)?,
    );
    let stored = StoredIdentity {
        version: STATE_VERSION,
        private_key: STANDARD_NO_PAD.encode(&protected),
    };
    let mut contents = Zeroizing::new(serde_json::to_vec_pretty(&stored)?);
    contents.push(b'\n');

    let directory = path.parent().ok_or(IdentityError::MissingPath)?;
    let mut random = [0_u8; 8];
    rand::rng().fill_bytes(&mut random);
    let pending = directory.join(format!(".client-identity-{}.tmp", hex::encode(random)));
    let result = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&pending)?;
        paths::secure_new_admin_file(&pending, &file)?;
        file.write_all(&contents)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&pending, path)?;
        drop(open_private(path, false)?);
        Ok(())
    })();
    let _ = fs::remove_file(&pending);
    result.map_err(IdentityError::Persist)
}

fn decode(encoded: &[u8]) -> Result<SigningKey, IdentityError> {
    let stored: StoredIdentity = serde_json::from_slice(encoded)?;
    if stored.version != STATE_VERSION {
        return Err(IdentityError::UnsupportedVersion(stored.version));
    }
    let encrypted = Zeroizing::new(
        STANDARD_NO_PAD
            .decode(stored.private_key)
            .map_err(|_| IdentityError::CorruptKey)?,
    );
    let private_key = Zeroizing::new(dpapi::unprotect(&encrypted).map_err(IdentityError::Read)?);
    SigningKey::from_pkcs8_der(&private_key).map_err(|_| IdentityError::CorruptKey)
}

fn hostname() -> std::io::Result<String> {
    let mut length = 0_u32;
    unsafe { GetComputerNameExW(ComputerNameDnsHostname, std::ptr::null_mut(), &mut length) };
    if length == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut buffer = vec![0_u16; length as usize];
    if unsafe { GetComputerNameExW(ComputerNameDnsHostname, buffer.as_mut_ptr(), &mut length) } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    buffer.truncate(length as usize);
    String::from_utf16(&buffer)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}
