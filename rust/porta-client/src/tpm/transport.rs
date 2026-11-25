//! How commands reach a TPM: the Windows TPM Base Services, a Linux TPM
//! resource manager device, or the TCP data channel of a TPM simulator
//! (`swtpm socket --server type=tcp`), used by tests.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Mutex;
use std::time::Duration;

/// Sends one marshalled command and returns the marshalled response.
pub trait Transport: Send + Sync {
    fn transmit(&self, command: &[u8]) -> io::Result<Vec<u8>>;
}

/// The largest TPM response Porta reads.
pub const MAX_RESPONSE: usize = 8192;

/// Reads one response: its 10-byte header carries the total size.
fn read_response(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut response = vec![0_u8; 10];
    reader.read_exact(&mut response)?;
    let size = u32::from_be_bytes(response[2..6].try_into().unwrap()) as usize;
    if !(10..=MAX_RESPONSE).contains(&size) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the TPM response has an invalid size",
        ));
    }
    response.resize(size, 0);
    reader.read_exact(&mut response[10..])?;
    Ok(response)
}

/// A TPM simulator's TCP data channel.
pub struct Socket {
    address: SocketAddr,
    stream: Mutex<Option<TcpStream>>,
}

impl Socket {
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            stream: Mutex::new(None),
        }
    }
}

impl Transport for Socket {
    fn transmit(&self, command: &[u8]) -> io::Result<Vec<u8>> {
        let mut stream = self
            .stream
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if stream.is_none() {
            let connected = TcpStream::connect_timeout(&self.address, Duration::from_secs(5))?;
            connected.set_read_timeout(Some(Duration::from_secs(30)))?;
            *stream = Some(connected);
        }
        let result = (|| {
            let connection = stream.as_mut().expect("connected above");
            connection.write_all(command)?;
            read_response(connection)
        })();
        if result.is_err() {
            *stream = None;
        }
        result
    }
}

/// A Linux TPM resource manager, `/dev/tpmrm0`, which isolates each open
/// file's transient objects and sessions.
#[cfg(target_os = "linux")]
pub struct Device {
    file: Mutex<std::fs::File>,
}

#[cfg(target_os = "linux")]
impl Device {
    pub fn open(path: &std::path::Path) -> io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

#[cfg(target_os = "linux")]
impl Transport for Device {
    fn transmit(&self, command: &[u8]) -> io::Result<Vec<u8>> {
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        file.write_all(command)?;
        // The device returns each response in one read.
        let mut response = vec![0_u8; MAX_RESPONSE];
        let length = file.read(&mut response)?;
        response.truncate(length);
        if length < 10 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the TPM response is truncated",
            ));
        }
        Ok(response)
    }
}

/// The Windows TPM Base Services, which virtualizes transient handles per
/// context.
#[cfg(windows)]
pub struct Tbs {
    context: *mut core::ffi::c_void,
    lock: Mutex<()>,
}

// SAFETY: the context handle may be used from any thread; `lock`
// serializes submissions.
#[cfg(windows)]
unsafe impl Send for Tbs {}
#[cfg(windows)]
unsafe impl Sync for Tbs {}

#[cfg(windows)]
impl Tbs {
    pub fn open() -> io::Result<Self> {
        use windows_sys::Win32::System::TpmBaseServices::{
            Tbsi_Context_Create, TBS_CONTEXT_PARAMS, TBS_CONTEXT_PARAMS2, TBS_CONTEXT_PARAMS2_0,
            TBS_CONTEXT_VERSION_TWO,
        };
        /// `includeTpm20` in TBS_CONTEXT_PARAMS2.
        const INCLUDE_TPM20: u32 = 1 << 2;
        let parameters = TBS_CONTEXT_PARAMS2 {
            version: TBS_CONTEXT_VERSION_TWO,
            Anonymous: TBS_CONTEXT_PARAMS2_0 {
                asUINT32: INCLUDE_TPM20,
            },
        };
        let mut context = std::ptr::null_mut();
        // SAFETY: the parameters and output pointer are valid for the call.
        let result = unsafe {
            Tbsi_Context_Create(
                std::ptr::from_ref(&parameters).cast::<TBS_CONTEXT_PARAMS>(),
                &mut context,
            )
        };
        if result != 0 {
            return Err(io::Error::other(format!(
                "no TPM 2.0 is available (TBS error {result:#x})"
            )));
        }
        Ok(Self {
            context,
            lock: Mutex::new(()),
        })
    }
}

#[cfg(windows)]
impl Transport for Tbs {
    fn transmit(&self, command: &[u8]) -> io::Result<Vec<u8>> {
        use windows_sys::Win32::System::TpmBaseServices::{
            Tbsip_Submit_Command, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL,
        };
        let _guard = self
            .lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut response = vec![0_u8; MAX_RESPONSE];
        let mut length = response.len() as u32;
        // SAFETY: the buffers are valid for their stated lengths.
        let result = unsafe {
            Tbsip_Submit_Command(
                self.context,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                command.as_ptr(),
                command.len() as u32,
                response.as_mut_ptr(),
                &mut length,
            )
        };
        if result != 0 {
            return Err(io::Error::other(format!(
                "the TPM command failed (TBS error {result:#x})"
            )));
        }
        response.truncate(length as usize);
        Ok(response)
    }
}

#[cfg(windows)]
impl Drop for Tbs {
    fn drop(&mut self) {
        // SAFETY: the context came from Tbsi_Context_Create.
        unsafe {
            windows_sys::Win32::System::TpmBaseServices::Tbsip_Context_Close(self.context);
        }
    }
}
