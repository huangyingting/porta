use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek};
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_BUFFER_OVERFLOW, ERROR_FILE_EXISTS,
};
use windows_sys::Win32::Storage::FileSystem::{
    MoveFileExW, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    MOVEFILE_WRITE_THROUGH,
};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteOutcome {
    Delivered,
    Dropped,
}

impl WriteOutcome {
    pub fn delivered_bytes(self, length: usize) -> u64 {
        match self {
            Self::Delivered => length as u64,
            Self::Dropped => 0,
        }
    }
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
        let staged = stage_library(verify_library(&library)?)?;
        let wintun =
            unsafe { wintun::load_from_path(&staged.path) }.map_err(|source| TunError::Load {
                path: staged.path.clone(),
                source,
            })?;
        drop(staged);
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

    pub fn write_packet(&self, bytes: &[u8]) -> Result<WriteOutcome, TunError> {
        let length =
            u16::try_from(bytes.len()).map_err(|_| TunError::PacketTooLarge(bytes.len()))?;
        let Some(mut packet) = allocation_outcome(self.session.allocate_send_packet(length))?
        else {
            return Ok(WriteOutcome::Dropped);
        };
        packet.bytes_mut().copy_from_slice(bytes);
        self.session.send_packet(packet);
        Ok(WriteOutcome::Delivered)
    }

    pub fn shutdown(&self) -> Result<(), TunError> {
        self.session.shutdown().map_err(TunError::Shutdown)
    }
}

fn allocation_outcome<T>(result: Result<T, wintun::Error>) -> Result<Option<T>, TunError> {
    match result {
        Ok(packet) => Ok(Some(packet)),
        Err(wintun::Error::Io(error))
            if error.raw_os_error() == Some(ERROR_BUFFER_OVERFLOW as i32) =>
        {
            Ok(None)
        }
        Err(error) => Err(TunError::Write(error)),
    }
}

fn verify_library(path: &Path) -> Result<File, TunError> {
    let mut file = open_library(path).map_err(|source| TunError::Verify {
        path: path.to_owned(),
        source,
    })?;
    paths::validate_single_link_file(&file).map_err(|source| TunError::Verify {
        path: path.to_owned(),
        source,
    })?;
    verify_hash(&mut file, path, WINTUN_SHA256)?;
    Ok(file)
}

fn open_library(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

struct StagedLibrary {
    path: PathBuf,
    _file: File,
    _directories: [File; 2],
}

fn stage_library(mut source: File) -> Result<StagedLibrary, TunError> {
    let root = paths::program_data()
        .map_err(|source| TunError::Verify {
            path: PathBuf::from("ProgramData"),
            source,
        })?
        .join("Porta");
    let directory = root.join("wintun");
    let path = directory.join(format!("wintun-{WINTUN_SHA256}.dll"));
    let io_error = |source| TunError::Verify {
        path: path.to_owned(),
        source,
    };
    // Keep both ancestors pinned until LoadLibrary has opened the staged DLL.
    let directories = [
        paths::prepare_admin_directory(&root).map_err(io_error)?,
        paths::prepare_admin_directory(&directory).map_err(io_error)?,
    ];
    for directory in &directories {
        paths::validate_admin_directory(directory).map_err(io_error)?;
    }
    let file = match open_library(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let pending = directory.join(format!(
                ".wintun-{}-{:032x}.pending",
                std::process::id(),
                rand::random::<u128>()
            ));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&pending)
                .map_err(io_error)?;
            let result = finish_staging(&mut source, file, &pending, &path);
            let cleanup = fs::remove_file(&pending);
            result?;
            if let Err(error) = cleanup {
                if error.kind() != std::io::ErrorKind::NotFound {
                    return Err(io_error(error));
                }
            }
            open_library(&path).map_err(io_error)?
        }
        Err(error) => return Err(io_error(error)),
    };
    paths::validate_admin_file(&file).map_err(io_error)?;
    let mut file = file;
    verify_hash(&mut file, &path, WINTUN_SHA256)?;
    Ok(StagedLibrary {
        path,
        _file: file,
        _directories: directories,
    })
}

fn finish_staging(
    source: &mut File,
    mut file: File,
    pending: &Path,
    destination: &Path,
) -> Result<(), TunError> {
    let io_error = |source| TunError::Verify {
        path: pending.to_owned(),
        source,
    };
    paths::secure_new_admin_file(pending, &file).map_err(io_error)?;
    copy_source_handle(source, &mut file).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    paths::validate_admin_file(&file).map_err(io_error)?;
    verify_hash(&mut file, pending, WINTUN_SHA256)?;
    drop(file);
    publish_library(pending, destination).map_err(io_error)
}

fn publish_library(pending: &Path, destination: &Path) -> std::io::Result<()> {
    // Publish without replacing a concurrent winner or an existing corrupt file.
    let pending = pending
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    if unsafe {
        MoveFileExW(
            pending.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        let error = std::io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(code) if code == ERROR_ALREADY_EXISTS as i32 || code == ERROR_FILE_EXISTS as i32
        ) {
            return Err(error);
        }
    }
    Ok(())
}

fn copy_source_handle(source: &mut File, destination: &mut File) -> std::io::Result<u64> {
    source.rewind()?;
    std::io::copy(source, destination)
}

fn verify_hash(file: &mut File, path: &Path, expected: &str) -> Result<(), TunError> {
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
    file.rewind().map_err(|source| TunError::Verify {
        path: path.to_owned(),
        source,
    })?;
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
    if hex::encode(digest.finalize()) != expected {
        return Err(TunError::Integrity {
            path: path.to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_HANDLE_EOF, ERROR_INVALID_DATA, ERROR_NO_SYSTEM_RESOURCES,
    };

    #[test]
    fn only_ring_exhaustion_is_a_nonterminal_allocation_drop() {
        assert_eq!(allocation_outcome(Ok(42)).unwrap(), Some(42));
        assert!(allocation_outcome::<()>(Err(wintun::Error::Io(
            std::io::Error::from_raw_os_error(ERROR_BUFFER_OVERFLOW as i32)
        )))
        .unwrap()
        .is_none());
        for code in [
            ERROR_ACCESS_DENIED,
            ERROR_HANDLE_EOF,
            ERROR_INVALID_DATA,
            ERROR_NO_SYSTEM_RESOURCES,
        ] {
            assert!(matches!(
                allocation_outcome::<()>(Err(wintun::Error::Io(
                    std::io::Error::from_raw_os_error(code as i32)
                ))),
                Err(TunError::Write(wintun::Error::Io(error))) if error.raw_os_error() == Some(code as i32)
            ));
        }
        for error in [
            wintun::Error::ShuttingDown,
            wintun::Error::String("ERROR_BUFFER_OVERFLOW".to_owned()),
            wintun::Error::Io(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
        ] {
            assert!(matches!(
                allocation_outcome::<()>(Err(error)),
                Err(TunError::Write(_))
            ));
        }
        assert_eq!(WriteOutcome::Delivered.delivered_bytes(1500), 1500);
        assert_eq!(WriteOutcome::Dropped.delivered_bytes(1500), 0);
    }

    #[test]
    fn staging_copies_the_retained_handle_from_the_start_and_rechecks_hash() {
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let source_path = directory.path().join("custom.dll");
        let destination_path = directory.path().join("staged.dll");
        let bytes = b"verified source bytes";
        fs::write(&source_path, bytes).unwrap();
        let mut source = open_library(&source_path).unwrap();
        let expected = hex::encode(Sha256::digest(bytes));
        verify_hash(&mut source, &source_path, &expected).unwrap();
        assert_eq!(source.stream_position().unwrap(), bytes.len() as u64);
        assert!(OpenOptions::new().write(true).open(&source_path).is_err());
        assert!(fs::remove_file(&source_path).is_err());
        let mut destination = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&destination_path)
            .unwrap();
        assert_eq!(
            copy_source_handle(&mut source, &mut destination).unwrap(),
            bytes.len() as u64
        );
        verify_hash(&mut destination, &destination_path, &expected).unwrap();
        destination.rewind().unwrap();
        destination.write_all(b"corrupt").unwrap();
        assert!(matches!(
            verify_hash(&mut destination, &destination_path, &expected),
            Err(TunError::Integrity { .. })
        ));
    }

    #[test]
    fn concurrent_staging_never_overwrites_the_published_library() {
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let destination = directory.path().join("staged.dll");
        let first = directory.path().join("first.pending");
        let second = directory.path().join("second.pending");
        fs::write(&first, b"first").unwrap();
        fs::write(&second, b"second").unwrap();
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            for pending in [&first, &second] {
                let destination = &destination;
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    publish_library(pending, destination).unwrap();
                });
            }
        });
        let published = fs::read(&destination).unwrap();
        assert!(published == b"first" || published == b"second");
        assert_ne!(first.exists(), second.exists());
        let loser = if first.exists() { &first } else { &second };
        publish_library(loser, &destination).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), published);
        assert!(loser.exists());
    }

    #[test]
    fn staged_libraries_must_have_admin_acls_and_no_additional_links() {
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let path = directory.path().join("staged.dll");
        fs::write(&path, b"untrusted").unwrap();
        let file = open_library(&path).unwrap();
        assert_eq!(
            paths::validate_admin_file(&file).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        drop(file);
        fs::hard_link(&path, directory.path().join("alias.dll")).unwrap();
        let file = open_library(&path).unwrap();
        assert!(paths::validate_admin_file(&file)
            .unwrap_err()
            .to_string()
            .contains("singly linked"));
    }
}
