use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};

use super::paths;

const RING_CAPACITY: u32 = 4 * 1024 * 1024;
const MAX_LIBRARY_SIZE: u64 = 8 * 1024 * 1024;
const WINTUN_SHA256: &str = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";

#[derive(Debug, Error)]
pub enum TunError {
    #[error("TUN interface name is required")]
    MissingName,
    #[error("locate Porta executable: {0}")]
    Executable(#[source] std::io::Error),
    #[error("wintun.dll path is not absolute")]
    RelativeLibrary,
    #[error("verify Wintun library {path}: {source}")]
    Verify {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("Wintun library {path} does not match the pinned official release")]
    Integrity { path: PathBuf },
    #[error("load Wintun library {path}: {source}")]
    Load {
        path: PathBuf,
        #[source]
        source: wintun::Error,
    },
    #[error("open or create Wintun adapter {name}: {source}")]
    Adapter {
        name: String,
        #[source]
        source: wintun::Error,
    },
    #[error("start Wintun packet session: {0}")]
    Session(#[source] wintun::Error),
    #[error("read Wintun packet: {0}")]
    Read(#[source] wintun::Error),
    #[error("packet length {0} exceeds Wintun capacity")]
    PacketTooLarge(usize),
    #[error("write Wintun packet: {0}")]
    Write(#[source] wintun::Error),
    #[error("stop Wintun packet session: {0}")]
    Shutdown(#[source] wintun::Error),
}

#[derive(Clone)]
pub struct Tun {
    name: String,
    session: Arc<wintun::Session>,
}

impl Tun {
    pub fn open(name: &str, library: Option<&Path>) -> Result<Self, TunError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(TunError::MissingName);
        }
        let library = match library {
            Some(path) => path.to_owned(),
            None => std::env::current_exe()
                .map_err(TunError::Executable)?
                .parent()
                .ok_or_else(|| {
                    TunError::Executable(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "executable has no parent directory",
                    ))
                })?
                .join("wintun.dll"),
        };
        if !library.is_absolute() {
            return Err(TunError::RelativeLibrary);
        }
        let verified_library = verify_library(&library)?;
        let wintun =
            unsafe { wintun::load_from_path(&library) }.map_err(|source| TunError::Load {
                path: library.clone(),
                source,
            })?;
        drop(verified_library);
        let adapter = match wintun::Adapter::open(&wintun, name) {
            Ok(adapter) => adapter,
            Err(_) => wintun::Adapter::create(&wintun, name, "Porta", None).map_err(|source| {
                TunError::Adapter {
                    name: name.to_owned(),
                    source,
                }
            })?,
        };
        let actual_name = adapter.get_name().map_err(|source| TunError::Adapter {
            name: name.to_owned(),
            source,
        })?;
        let session = Arc::new(
            adapter
                .start_session(RING_CAPACITY)
                .map_err(TunError::Session)?,
        );
        Ok(Self {
            name: actual_name,
            session,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn read_packet(&self) -> Result<Vec<u8>, TunError> {
        let packet = self.session.receive_blocking().map_err(TunError::Read)?;
        Ok(packet.bytes().to_vec())
    }

    pub fn write_packet(&self, bytes: &[u8]) -> Result<(), TunError> {
        let length =
            u16::try_from(bytes.len()).map_err(|_| TunError::PacketTooLarge(bytes.len()))?;
        let mut packet = self
            .session
            .allocate_send_packet(length)
            .map_err(TunError::Write)?;
        packet.bytes_mut().copy_from_slice(bytes);
        self.session.send_packet(packet);
        Ok(())
    }

    pub fn shutdown(&self) -> Result<(), TunError> {
        self.session.shutdown().map_err(TunError::Shutdown)
    }
}

fn verify_library(path: &Path) -> Result<File, TunError> {
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|source| TunError::Verify {
            path: path.to_owned(),
            source,
        })?;
    paths::validate_single_link_file(&file).map_err(|source| TunError::Verify {
        path: path.to_owned(),
        source,
    })?;
    let length = file
        .metadata()
        .map_err(|source| TunError::Verify {
            path: path.to_owned(),
            source,
        })?
        .len();
    if length == 0 || length > MAX_LIBRARY_SIZE {
        return Err(TunError::Integrity {
            path: path.to_owned(),
        });
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|source| TunError::Verify {
            path: path.to_owned(),
            source,
        })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    if hex::encode(digest.finalize()) != WINTUN_SHA256 {
        return Err(TunError::Integrity {
            path: path.to_owned(),
        });
    }
    Ok(file)
}
