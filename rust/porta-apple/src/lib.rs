//! C interface to the Porta tunnel for the macOS and iOS apps.
//!
//! The apps' packet tunnel extension (`NEPacketTunnelProvider`) calls these
//! functions through `include/porta.h`: it creates a device identity, either
//! a key file or an external signer such as a Secure Enclave key, connects a
//! session, applies the session's addresses and routes to the tunnel's
//! network settings, and moves packets between `NEPacketTunnelFlow` and
//! [`porta_send`] / [`porta_receive`]. Sockets the extension opens are kept
//! out of its own tunnel by the system, so no socket protection is needed.
//!
//! Every function is safe to call from any thread. Errors are written as
//! NUL-terminated UTF-8 into the caller's buffer; account denials start with
//! `account-denied:CODE:` so the app can explain them.

use std::ffi::{c_char, c_void, CStr};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use porta_client::identity::Identity;
use porta_client::tls;
use porta_client::tunnel::{ClientConfig, ClientError, Connection, ProofProvider, Transport};
use porta_wire::device_auth::{device_id_from_encoded, signature_payload, Proof, NONCE_SIZE};
use rand::Rng as _;
use serde_json::json;
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;
use url::Url;

pub const PORTA_OK: i32 = 0;
/// The tunnel failed in a way that reconnecting may fix.
pub const PORTA_RETRYABLE: i32 = -1;
/// Reconnecting with the same settings will fail again.
pub const PORTA_PERMANENT: i32 = -2;
/// The gateway refused the account or device; see the error text.
pub const PORTA_DENIED: i32 = -3;

pub const PORTA_TRANSPORT_AUTO: u32 = 0;
pub const PORTA_TRANSPORT_HTTP2: u32 = 2;
pub const PORTA_TRANSPORT_HTTP3: u32 = 3;

const MAX_SIGNATURE: usize = 128;

/// Signs `message` with the device's P-256 key (ECDSA over SHA-256) and
/// writes the DER signature. Returns zero on success.
pub type PortaSignCallback = Option<
    unsafe extern "C" fn(
        context: *mut c_void,
        message: *const u8,
        message_length: usize,
        signature: *mut u8,
        signature_capacity: usize,
        signature_length: *mut usize,
    ) -> i32,
>;

/// What a session connects to; optional strings may be null.
#[repr(C)]
pub struct PortaConfig {
    /// Gateway origin, such as `https://vpn.example.com:8443`.
    pub server: *const c_char,
    pub token: *const c_char,
    /// Numeric gateway address to dial instead of resolving `server`.
    pub remote_address: *const c_char,
    /// PEM CA certificate for a privately signed gateway.
    pub ca_path: *const c_char,
    /// SHA-256 thumbprint the gateway certificate must match.
    pub thumbprint: *const c_char,
    /// One of the `PORTA_TRANSPORT_` values.
    pub transport: u32,
    /// Connection deadline; zero means 15 seconds.
    pub timeout_ms: u32,
}

/// A device key and name that prove the device to the gateway.
pub struct PortaIdentity {
    inner: Arc<IdentityKind>,
    device_id: std::ffi::CString,
}

impl PortaIdentity {
    fn new(inner: IdentityKind) -> *mut Self {
        let device_id = match &inner {
            IdentityKind::File(identity) => identity.id.clone(),
            IdentityKind::External(signer) => signer.device_id.clone(),
        };
        Box::into_raw(Box::new(Self {
            inner: Arc::new(inner),
            device_id: std::ffi::CString::new(device_id).unwrap_or_default(),
        }))
    }
}

enum IdentityKind {
    File(Identity),
    External(ExternalSigner),
}

struct ExternalSigner {
    device_id: String,
    name: String,
    public_key: String,
    sign: unsafe extern "C" fn(*mut c_void, *const u8, usize, *mut u8, usize, *mut usize) -> i32,
    context: usize,
}

/// A connected tunnel.
pub struct PortaSession {
    connection: Arc<Connection>,
    cancellation: CancellationToken,
}

fn runtime() -> Result<&'static Runtime, String> {
    static RUNTIME: OnceLock<Result<Runtime, String>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("porta")
                .build()
                .map_err(|error| format!("start the tunnel runtime: {error}"))
        })
        .as_ref()
        .map_err(Clone::clone)
}

/// Copies `message` into the caller's error buffer, truncating at a
/// character boundary and always NUL-terminating.
unsafe fn write_error(buffer: *mut c_char, capacity: usize, message: &str) {
    if buffer.is_null() || capacity == 0 {
        return;
    }
    let mut length = message.len().min(capacity - 1);
    while !message.is_char_boundary(length) {
        length -= 1;
    }
    std::ptr::copy_nonoverlapping(message.as_ptr(), buffer.cast::<u8>(), length);
    *buffer.add(length) = 0;
}

unsafe fn optional_string(value: *const c_char, field: &str) -> Result<Option<String>, String> {
    if value.is_null() {
        return Ok(None);
    }
    let value = CStr::from_ptr(value)
        .to_str()
        .map_err(|_| format!("{field} is not UTF-8"))?
        .trim();
    Ok((!value.is_empty()).then(|| value.to_owned()))
}

unsafe fn required_string(value: *const c_char, field: &str) -> Result<String, String> {
    optional_string(value, field)?.ok_or_else(|| format!("{field} is required"))
}

fn classify(error: &ClientError) -> (i32, String) {
    match error.denial() {
        Some(denial) => (
            PORTA_DENIED,
            format!("account-denied:{}: {}", denial.code(), denial.message()),
        ),
        None if error.is_permanent() => (PORTA_PERMANENT, error.to_string()),
        None => (PORTA_RETRYABLE, error.to_string()),
    }
}

/// An identity bound to the account token its proofs cover; sessions keep
/// it after the app frees the identity.
struct BoundIdentity {
    identity: Arc<IdentityKind>,
    token: String,
}

impl ProofProvider for BoundIdentity {
    fn proof(&self, method: &str, path: &str) -> Result<Proof, ClientError> {
        match &*self.identity {
            IdentityKind::File(identity) => identity
                .proof(&self.token, method, path)
                .map_err(|error| ClientError::permanent(error.to_string())),
            IdentityKind::External(signer) => signer.proof(&self.token, method, path),
        }
    }
}

impl ExternalSigner {
    fn proof(&self, token: &str, method: &str, path: &str) -> Result<Proof, ClientError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ClientError::permanent("the system clock is before 1970"))?
            .as_secs()
            .to_string();
        let mut nonce = [0_u8; NONCE_SIZE];
        rand::rng().fill_bytes(&mut nonce);
        let mut proof = Proof {
            device_id: self.device_id.clone(),
            name: self.name.clone(),
            public_key: self.public_key.clone(),
            timestamp,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            signature: String::new(),
        };
        let message = signature_payload(&proof, token, method, path);
        let mut signature = [0_u8; MAX_SIGNATURE];
        let mut length = 0_usize;
        // SAFETY: the callback receives valid buffers of the stated sizes and
        // the context the app registered with the identity.
        let status = unsafe {
            (self.sign)(
                self.context as *mut c_void,
                message.as_ptr(),
                message.len(),
                signature.as_mut_ptr(),
                signature.len(),
                &mut length,
            )
        };
        if status != 0 || length == 0 || length > signature.len() {
            return Err(ClientError::permanent("the device key could not sign"));
        }
        proof.signature = URL_SAFE_NO_PAD.encode(&signature[..length]);
        Ok(proof)
    }
}

/// The library version, a static string.
#[unsafe(no_mangle)]
pub extern "C" fn porta_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// Loads the device key from `path`, creating it on first use. Returns null
/// and writes `error` on failure.
///
/// # Safety
///
/// `path` and `device_name` must be NUL-terminated strings; `error` must
/// point to `error_capacity` writable bytes or be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn porta_identity_file(
    path: *const c_char,
    device_name: *const c_char,
    error: *mut c_char,
    error_capacity: usize,
) -> *mut PortaIdentity {
    let result = (|| {
        let path = required_string(path, "identity path")?;
        let name = required_string(device_name, "device name")?;
        Identity::load_or_create(Path::new(&path), &name).map_err(|error| error.to_string())
    })();
    match result {
        Ok(identity) => PortaIdentity::new(IdentityKind::File(identity)),
        Err(message) => {
            write_error(error, error_capacity, &message);
            std::ptr::null_mut()
        }
    }
}

/// An identity whose key the app keeps, for example in the Secure Enclave:
/// `public_key` is its DER SubjectPublicKeyInfo and `sign` signs proofs.
/// `context` is passed back to `sign` and must outlive the identity and its
/// sessions.
///
/// # Safety
///
/// `public_key` must point to `public_key_length` readable bytes, the
/// strings must be NUL-terminated, and `sign` must be safe to call from any
/// thread with `context`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn porta_identity_external(
    public_key: *const u8,
    public_key_length: usize,
    device_name: *const c_char,
    sign: PortaSignCallback,
    context: *mut c_void,
    error: *mut c_char,
    error_capacity: usize,
) -> *mut PortaIdentity {
    let result = (|| {
        let sign = sign.ok_or_else(|| "a signing callback is required".to_owned())?;
        if public_key.is_null() || public_key_length == 0 || public_key_length > 1024 {
            return Err("a public key is required".to_owned());
        }
        let key = std::slice::from_raw_parts(public_key, public_key_length);
        let device_id = device_id_from_encoded(key).map_err(|error| error.to_string())?;
        let name =
            porta_client::identity::normalize_name(&required_string(device_name, "device name")?)
                .map_err(|error| error.to_string())?;
        Ok(ExternalSigner {
            device_id,
            name,
            public_key: URL_SAFE_NO_PAD.encode(key),
            sign,
            context: context as usize,
        })
    })();
    match result {
        Ok(signer) => PortaIdentity::new(IdentityKind::External(signer)),
        Err(message) => {
            write_error(error, error_capacity, &message);
            std::ptr::null_mut()
        }
    }
}

/// The device ID (`d-...`) of an identity, valid until the identity is freed.
///
/// # Safety
///
/// `identity` must come from a `porta_identity_` function and not be freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn porta_identity_device_id(identity: *const PortaIdentity) -> *const c_char {
    identity
        .as_ref()
        .map_or(std::ptr::null(), |identity| identity.device_id.as_ptr())
}

/// Frees an identity. Sessions connected with it keep working.
///
/// # Safety
///
/// `identity` must come from a `porta_identity_` function or be null, and
/// must not be used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn porta_identity_free(identity: *mut PortaIdentity) {
    if !identity.is_null() {
        drop(Box::from_raw(identity));
    }
}

/// Connects a tunnel. Returns null and writes `error` on failure; `status`,
/// if not null, receives `PORTA_OK` or the failure class.
///
/// # Safety
///
/// `config` and `identity` must be valid; strings in `config` must be
/// NUL-terminated or null; `error` must point to `error_capacity` writable
/// bytes or be null; `status` must be writable or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn porta_connect(
    config: *const PortaConfig,
    identity: *const PortaIdentity,
    status: *mut i32,
    error: *mut c_char,
    error_capacity: usize,
) -> *mut PortaSession {
    let result = connect(config, identity);
    let (code, session) = match result {
        Ok(session) => (PORTA_OK, Box::into_raw(Box::new(session))),
        Err((code, message)) => {
            write_error(error, error_capacity, &message);
            (code, std::ptr::null_mut())
        }
    };
    if !status.is_null() {
        *status = code;
    }
    session
}

unsafe fn connect(
    config: *const PortaConfig,
    identity: *const PortaIdentity,
) -> Result<PortaSession, (i32, String)> {
    let permanent = |message: String| (PORTA_PERMANENT, message);
    let config = config
        .as_ref()
        .ok_or_else(|| permanent("configuration is required".to_owned()))?;
    let identity = identity
        .as_ref()
        .ok_or_else(|| permanent("identity is required".to_owned()))?;
    let server = required_string(config.server, "server").map_err(permanent)?;
    let token = required_string(config.token, "token").map_err(permanent)?;
    let ca_path = optional_string(config.ca_path, "CA path").map_err(permanent)?;
    let thumbprint = optional_string(config.thumbprint, "thumbprint").map_err(permanent)?;
    let transport = match config.transport {
        PORTA_TRANSPORT_AUTO => Transport::Auto,
        PORTA_TRANSPORT_HTTP2 => Transport::Http2,
        PORTA_TRANSPORT_HTTP3 => Transport::Http3,
        _ => return Err(permanent("unknown transport".to_owned())),
    };
    let dial_address =
        match optional_string(config.remote_address, "remote address").map_err(permanent)? {
            // The gateway's resolved IP, or a relay's `IP[:PORT]`.
            Some(address) => {
                let port = Url::parse(&server)
                    .ok()
                    .and_then(|url| url.port_or_known_default())
                    .ok_or_else(|| permanent("server must be an HTTPS origin".to_owned()))?;
                Some(
                    porta_client::tunnel::parse_dial_address(&address, port)
                        .map_err(|error| permanent(format!("invalid remote address: {error}")))?,
                )
            }
            None => None,
        };
    let tls = tls::config(
        ca_path.as_deref().map(Path::new),
        thumbprint.as_deref(),
        false,
    )
    .map_err(|error| permanent(error.to_string()))?;
    let cancellation = CancellationToken::new();
    let client = ClientConfig {
        url: server,
        token: token.clone(),
        transport,
        tls,
        timeout: Duration::from_millis(if config.timeout_ms == 0 {
            15_000
        } else {
            u64::from(config.timeout_ms)
        }),
        dial_address,
        proof: Arc::new(BoundIdentity {
            identity: identity.inner.clone(),
            token,
        }),
        socket_protector: None,
        cancellation: cancellation.clone(),
    };
    let runtime = runtime().map_err(permanent)?;
    let connection = runtime
        .block_on(porta_client::tunnel::connect(client))
        .map_err(|error| classify(&error))?;
    Ok(PortaSession {
        connection: Arc::new(connection),
        cancellation,
    })
}

/// Writes the session's network settings as JSON (addresses, DNS, MTU,
/// routes, transport and account limits) and returns the length the JSON
/// needs, without the NUL; call again with a larger buffer if it is not
/// smaller than `capacity`. Returns -1 for a null session.
///
/// # Safety
///
/// `session` must come from [`porta_connect`] and not be closed; `buffer`
/// must point to `capacity` writable bytes or be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn porta_session_info(
    session: *const PortaSession,
    buffer: *mut c_char,
    capacity: usize,
) -> i64 {
    let Some(session) = session.as_ref() else {
        return -1;
    };
    let connection = &session.connection;
    let lease = connection.lease;
    let account = connection.account();
    let info = json!({
        "address": lease.address.to_string(),
        "gateway": lease.gateway.map(|gateway| gateway.to_string()),
        "address6": lease.ipv6().map(|address| address.to_string()),
        "dns": lease.dns.map(|dns| dns.to_string()),
        "mtu": lease.mtu,
        "transport": match connection.transport {
            Transport::Http3 => "h3",
            Transport::Http2 => "h2",
            Transport::Auto => "auto",
        },
        "routes": connection.routing.routes.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "routes6": if lease.ipv6().is_some() {
            connection.routing.routes6.iter().map(ToString::to_string).collect::<Vec<_>>()
        } else {
            Vec::new()
        },
        "dnsDomains": connection.routing.dns_domains,
        "fullTunnel": connection.routing.is_full_tunnel(),
        "account": {
            "expiresAt": account.expires_at,
            "quotaBytes": account.quota_bytes,
            "quotaUsedBytes": account.quota_used_bytes,
            "rateLimitKbps": account.rate_limit_kbps,
        },
    })
    .to_string();
    if !buffer.is_null() && capacity > info.len() {
        std::ptr::copy_nonoverlapping(info.as_ptr(), buffer.cast::<u8>(), info.len());
        *buffer.add(info.len()) = 0;
    }
    info.len() as i64
}

/// Sends one IP packet from the device into the tunnel. Returns `PORTA_OK`
/// or a failure class; packets the tunnel does not carry, such as those
/// from foreign sources, are failures the app may ignore.
///
/// # Safety
///
/// `session` must come from [`porta_connect`] and not be closed; `packet`
/// must point to `length` readable bytes; `error` must point to
/// `error_capacity` writable bytes or be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn porta_send(
    session: *const PortaSession,
    packet: *const u8,
    length: usize,
    error: *mut c_char,
    error_capacity: usize,
) -> i32 {
    let Some(session) = session.as_ref() else {
        write_error(error, error_capacity, "session is closed");
        return PORTA_PERMANENT;
    };
    if packet.is_null() || length == 0 {
        write_error(error, error_capacity, "packet is empty");
        return PORTA_PERMANENT;
    }
    let packet = std::slice::from_raw_parts(packet, length);
    let Ok(runtime) = runtime() else {
        return PORTA_PERMANENT;
    };
    match runtime.block_on(session.connection.send(packet)) {
        Ok(()) => PORTA_OK,
        Err(failure) => {
            let (code, message) = classify(&failure);
            write_error(error, error_capacity, &message);
            code
        }
    }
}

/// Waits up to `timeout_ms` for an IP packet for the device and copies it
/// into `buffer`. Returns its length, 0 on timeout, or a negative failure
/// class once the session has ended.
///
/// # Safety
///
/// `session` must come from [`porta_connect`] and not be closed; `buffer`
/// must point to `capacity` writable bytes; `error` must point to
/// `error_capacity` writable bytes or be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn porta_receive(
    session: *const PortaSession,
    buffer: *mut u8,
    capacity: usize,
    timeout_ms: u32,
    error: *mut c_char,
    error_capacity: usize,
) -> i64 {
    let Some(session) = session.as_ref() else {
        write_error(error, error_capacity, "session is closed");
        return i64::from(PORTA_PERMANENT);
    };
    let Ok(runtime) = runtime() else {
        return i64::from(PORTA_PERMANENT);
    };
    let connection = session.connection.clone();
    let cancellation = session.cancellation.clone();
    let result = runtime.block_on(async move {
        tokio::select! {
            _ = cancellation.cancelled() => Some(Err(ClientError::Closed)),
            packet = tokio::time::timeout(Duration::from_millis(u64::from(timeout_ms)), connection.receive()) => packet.ok(),
        }
    });
    match result {
        None => 0,
        Some(Ok(packet)) if packet.len() <= capacity && !buffer.is_null() => {
            std::ptr::copy_nonoverlapping(packet.as_ptr(), buffer, packet.len());
            packet.len() as i64
        }
        Some(Ok(packet)) => {
            write_error(
                error,
                error_capacity,
                &format!("packet of {} bytes exceeds the buffer", packet.len()),
            );
            i64::from(PORTA_RETRYABLE)
        }
        Some(Err(failure)) => {
            let (code, message) = classify(&failure);
            write_error(error, error_capacity, &message);
            i64::from(code)
        }
    }
}

/// Ends the tunnel: pending and later [`porta_receive`] calls return a
/// failure. The session must still be freed with [`porta_close`].
///
/// # Safety
///
/// `session` must come from [`porta_connect`] and not be closed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn porta_cancel(session: *const PortaSession) {
    if let Some(session) = session.as_ref() {
        session.cancellation.cancel();
    }
}

/// Closes the tunnel and frees the session. No other call on the session
/// may run concurrently; use [`porta_cancel`] first to end blocked calls.
///
/// # Safety
///
/// `session` must come from [`porta_connect`] or be null, and must not be
/// used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn porta_close(session: *mut PortaSession) {
    if session.is_null() {
        return;
    }
    let session = Box::from_raw(session);
    session.cancellation.cancel();
    if let Ok(runtime) = runtime() {
        runtime.block_on(session.connection.close());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::pkcs8::EncodePublicKey as _;

    unsafe extern "C" fn sign(
        context: *mut c_void,
        message: *const u8,
        message_length: usize,
        signature: *mut u8,
        signature_capacity: usize,
        signature_length: *mut usize,
    ) -> i32 {
        let key = &*(context as *const SigningKey);
        let message = std::slice::from_raw_parts(message, message_length);
        let signed: Signature = key.sign(message);
        let der = signed.to_der();
        if der.as_bytes().len() > signature_capacity {
            return 1;
        }
        std::ptr::copy_nonoverlapping(der.as_bytes().as_ptr(), signature, der.as_bytes().len());
        *signature_length = der.as_bytes().len();
        0
    }

    #[test]
    fn external_signers_produce_proofs_the_gateway_accepts() {
        let key = Box::new(<SigningKey as p256::elliptic_curve::Generate>::generate());
        let public_key = key.verifying_key().to_public_key_der().unwrap();
        let mut error = [0 as c_char; 256];
        let identity = unsafe {
            porta_identity_external(
                public_key.as_bytes().as_ptr(),
                public_key.as_bytes().len(),
                c"Test iPhone".as_ptr(),
                Some(sign),
                (&*key as *const SigningKey).cast_mut().cast(),
                error.as_mut_ptr(),
                error.len(),
            )
        };
        assert!(!identity.is_null());
        let device_id = unsafe { CStr::from_ptr(porta_identity_device_id(identity)) }
            .to_str()
            .unwrap()
            .to_owned();
        assert!(device_id.starts_with("d-"));
        let bound = BoundIdentity {
            identity: unsafe { (*identity).inner.clone() },
            token: "token-0123456789abcdef".to_owned(),
        };
        unsafe { porta_identity_free(identity) };
        let proof = bound
            .proof("CONNECT", "/.well-known/masque/ip/*/*/")
            .unwrap();
        assert_eq!(proof.device_id, device_id);
        assert_eq!(proof.name, "Test-iPhone");
        porta_wire::device_auth::verify(
            &proof,
            "token-0123456789abcdef",
            "CONNECT",
            "/.well-known/masque/ip/*/*/",
            time::OffsetDateTime::now_utc(),
        )
        .unwrap();
    }

    #[test]
    fn invalid_input_is_reported_without_crashing() {
        let mut error = [0 as c_char; 64];
        let identity = unsafe {
            porta_identity_external(
                std::ptr::null(),
                0,
                c"Phone".as_ptr(),
                Some(sign),
                std::ptr::null_mut(),
                error.as_mut_ptr(),
                error.len(),
            )
        };
        assert!(identity.is_null());
        let message = unsafe { CStr::from_ptr(error.as_ptr()) }.to_str().unwrap();
        assert_eq!(message, "a public key is required");

        let mut status = 0;
        let session = unsafe {
            porta_connect(
                std::ptr::null(),
                std::ptr::null(),
                &mut status,
                error.as_mut_ptr(),
                error.len(),
            )
        };
        assert!(session.is_null());
        assert_eq!(status, PORTA_PERMANENT);
        assert_eq!(
            unsafe { porta_session_info(std::ptr::null(), std::ptr::null_mut(), 0) },
            -1
        );
        assert_eq!(
            unsafe { CStr::from_ptr(porta_version()) }.to_str().unwrap(),
            env!("CARGO_PKG_VERSION")
        );
        // Long messages are truncated at a character boundary.
        let mut small = [0 as c_char; 4];
        unsafe { write_error(small.as_mut_ptr(), small.len(), "éé") };
        assert_eq!(
            unsafe { CStr::from_ptr(small.as_ptr()) }.to_str().unwrap(),
            "é"
        );
    }
}
