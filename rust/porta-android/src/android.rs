use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use base64::Engine;
use jni::objects::{Global, JByteArray, JClass, JObject, JString, Reference};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring, JNI_FALSE, JNI_TRUE};
use jni::{jni_sig, jni_str, Env, EnvUnowned, JValue, JavaVM};
use porta_client::tls;
use porta_client::tunnel::{
    ClientConfig, ClientError, Connection, DeliveryMode, ProofProvider, SocketProtector, Transport,
};
use porta_wire::device_auth::{device_id_from_encoded, signature_payload, Proof};
use serde::Deserialize;
use tokio::runtime::{Builder, Runtime};
use tokio_util::sync::CancellationToken;
use url::Url;

const MAX_PACKET_SIZE: usize = 65_535;

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static RUNTIME: OnceLock<Result<Runtime, String>> = OnceLock::new();
static HANDLES: OnceLock<Handles> = OnceLock::new();

#[derive(Debug, thiserror::Error)]
enum BridgeError {
    #[error(transparent)]
    Jni(#[from] jni::errors::Error),
    #[error("{0}")]
    Message(String),
}

impl From<ClientError> for BridgeError {
    fn from(error: ClientError) -> Self {
        Self::Message(error.to_string())
    }
}

impl From<tls::TlsConfigError> for BridgeError {
    fn from(error: tls::TlsConfigError) -> Self {
        Self::Message(error.to_string())
    }
}

struct Handles {
    next: AtomicI64,
    dialers: Mutex<HashMap<i64, Arc<DialerHandle>>>,
    sessions: Mutex<HashMap<i64, Arc<SessionHandle>>>,
}

impl Handles {
    fn new() -> Self {
        Self {
            next: AtomicI64::new(1),
            dialers: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn next_id(&self) -> Result<i64, BridgeError> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        if id <= 0 {
            return Err(BridgeError::Message(
                "native handle space exhausted".to_string(),
            ));
        }
        Ok(id)
    }
}

struct DialerHandle {
    cancellation: CancellationToken,
}

struct SessionHandle {
    connection: Arc<Connection>,
}

struct AndroidSocketProtector {
    vm: Arc<JavaVM>,
    protector: Global<JObject<'static>>,
}

struct AndroidProofProvider {
    vm: Arc<JavaVM>,
    provider: Global<JObject<'static>>,
    device_id: Mutex<Option<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JavaProof {
    public_key: String,
    timestamp: String,
    nonce: String,
    signature: String,
    device_name: String,
}

impl ProofProvider for AndroidProofProvider {
    fn proof(&self, method: &str, path: &str) -> Result<Proof, ClientError> {
        let encoded = self
            .vm
            .attach_current_thread(|env| -> jni::errors::Result<String> {
                let method = JString::from_str(env, method)?;
                let path = JString::from_str(env, path)?;
                let result = env.call_method(
                    &self.provider,
                    jni_str!("proof"),
                    jni_sig!((method: java.lang.String, path: java.lang.String) -> java.lang.String),
                    &[JValue::Object(&method), JValue::Object(&path)],
                )?;
                let result = result.l()?;
                if result.is_null() {
                    return Err(jni::errors::Error::NullPtr(
                        "Android proof callback returned null",
                    ));
                }
                env.cast_local::<JString>(result)?.try_to_string(env)
            })
            .map_err(|error| {
                ClientError::permanent(format!("Android proof callback failed: {error}"))
            })?;
        let value: JavaProof = serde_json::from_str(&encoded)
            .map_err(|error| ClientError::permanent(format!("invalid Android proof: {error}")))?;
        let public_key_der = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value.public_key.as_bytes())
            .map_err(|error| ClientError::permanent(format!("invalid public key: {error}")))?;
        let device_id = device_id_from_encoded(&public_key_der)
            .map_err(|error| ClientError::permanent(error.to_string()))?;
        let mut expected = self
            .device_id
            .lock()
            .map_err(|_| ClientError::permanent("Android proof state is unavailable"))?;
        if let Some(expected) = expected.as_ref() {
            if expected != &device_id {
                return Err(ClientError::permanent(
                    "Android proof key changed during connection",
                ));
            }
        } else {
            *expected = Some(device_id.clone());
        }
        Ok(Proof {
            device_id,
            name: value.device_name,
            public_key: value.public_key,
            timestamp: value.timestamp,
            nonce: value.nonce,
            signature: value.signature,
        })
    }
}

impl SocketProtector for AndroidSocketProtector {
    fn prepare(&self, descriptor: i64) -> Result<(), ClientError> {
        let descriptor = i32::try_from(descriptor)
            .map_err(|_| ClientError::permanent("socket descriptor is out of range"))?;
        let message = self
            .vm
            .attach_current_thread(|env| -> jni::errors::Result<Option<String>> {
                let result = env.call_method(
                    &self.protector,
                    jni_str!("prepare"),
                    jni_sig!((fd: int) -> java.lang.String),
                    &[JValue::Int(descriptor)],
                )?;
                let object = result.l()?;
                if object.is_null() {
                    return Ok(None);
                }
                let message = env.cast_local::<JString>(object)?;
                Ok(Some(message.try_to_string(env)?))
            })
            .map_err(|error| {
                ClientError::permanent(format!(
                    "Android socket protection callback failed: {error}"
                ))
            })?;
        let Some(message) = message else {
            return Ok(());
        };
        if message.is_empty() {
            Ok(())
        } else {
            Err(classify_callback_error(&message))
        }
    }
}

fn classify_callback_error(message: &str) -> ClientError {
    if message.starts_with("transport unavailable:") {
        ClientError::unavailable(message.trim_start_matches("transport unavailable:").trim())
    } else if message.starts_with("retryable:") {
        ClientError::retryable(message.trim_start_matches("retryable:").trim())
    } else {
        ClientError::permanent(message)
    }
}

fn runtime() -> Result<&'static Runtime, BridgeError> {
    match RUNTIME.get_or_init(|| {
        Builder::new_multi_thread()
            .enable_all()
            .thread_name("porta-android")
            .build()
            .map_err(|error| format!("could not start the native runtime: {error}"))
    }) {
        Ok(runtime) => Ok(runtime),
        Err(error) => Err(BridgeError::Message(error.clone())),
    }
}

fn handles() -> &'static Handles {
    HANDLES.get_or_init(Handles::new)
}

fn lock<T>(mutex: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>, BridgeError> {
    mutex
        .lock()
        .map_err(|_| BridgeError::Message("native handle state is unavailable".to_string()))
}

fn read_string(env: &Env<'_>, value: &JString<'_>, field: &str) -> Result<String, BridgeError> {
    let value = value.try_to_string(env)?;
    if value.is_empty() {
        Err(BridgeError::Message(format!("{field} is required")))
    } else {
        Ok(value)
    }
}

fn parse_server(server: &str) -> Result<(String, u16), BridgeError> {
    let url = Url::parse(server)
        .map_err(|error| BridgeError::Message(format!("invalid server URL: {error}")))?;
    if url.scheme() != "https" {
        return Err(BridgeError::Message(
            "server URL must use https".to_string(),
        ));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(BridgeError::Message(
            "server URL must not contain credentials, a query, or a fragment".to_string(),
        ));
    }
    if url.path() != "/" && !url.path().is_empty() {
        return Err(BridgeError::Message(
            "server URL must not contain a path".to_string(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| BridgeError::Message("server URL has no host".to_string()))?
        .to_string();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| BridgeError::Message("server URL has no port".to_string()))?;
    Ok((host, port))
}

fn parse_remote(remote_ip: &str, port: u16) -> Result<SocketAddr, BridgeError> {
    let ip = remote_ip
        .parse::<IpAddr>()
        .map_err(|error| BridgeError::Message(format!("invalid remote IP address: {error}")))?;
    if ip.is_unspecified() || ip.is_multicast() {
        return Err(BridgeError::Message(
            "remote IP address must be unicast".to_string(),
        ));
    }
    Ok(SocketAddr::new(ip, port))
}

fn get_dialer(id: jlong) -> Result<Arc<DialerHandle>, BridgeError> {
    lock(&handles().dialers)?
        .get(&id)
        .cloned()
        .ok_or_else(|| BridgeError::Message("tunnel dialer is closed".to_string()))
}

fn get_session(id: jlong) -> Result<Arc<SessionHandle>, BridgeError> {
    lock(&handles().sessions)?
        .get(&id)
        .cloned()
        .ok_or_else(|| BridgeError::Message("tunnel is closed".to_string()))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_portamobile_Portamobile_nativeInitialize(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
    context: JObject<'_>,
) -> jboolean {
    env.with_env(|env| -> Result<jboolean, BridgeError> {
        rustls_platform_verifier::android::init_with_env(env, context)?;
        runtime()?;
        INITIALIZED.store(true, Ordering::Release);
        Ok(JNI_TRUE)
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_portamobile_Portamobile_nativeVersion(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
) -> jstring {
    env.with_env(|env| -> Result<jstring, BridgeError> {
        Ok(JString::from_str(env, env!("CARGO_PKG_VERSION"))?.into_raw())
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_portamobile_Portamobile_nativeDeviceIDFromPublicKey(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
    public_key: JByteArray<'_>,
) -> jstring {
    env.with_env(|env| -> Result<jstring, BridgeError> {
        let public_key = env.convert_byte_array(public_key)?;
        let device_id = device_id_from_encoded(&public_key)
            .map_err(|error| BridgeError::Message(error.to_string()))?;
        Ok(JString::from_str(env, device_id)?.into_raw())
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_portamobile_Portamobile_nativeDeviceProofMessage(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
    token: JString<'_>,
    method: JString<'_>,
    path: JString<'_>,
    device_id: JString<'_>,
    device_name: JString<'_>,
    timestamp: JString<'_>,
    nonce: JString<'_>,
) -> jbyteArray {
    env.with_env(|env| -> Result<jbyteArray, BridgeError> {
        let method = read_string(env, &method, "method")?;
        let path = read_string(env, &path, "path")?;
        let token = read_string(env, &token, "token")?;
        let proof = Proof {
            device_id: read_string(env, &device_id, "device ID")?,
            name: read_string(env, &device_name, "device name")?,
            public_key: String::new(),
            timestamp: read_string(env, &timestamp, "timestamp")?,
            nonce: read_string(env, &nonce, "nonce")?,
            signature: String::new(),
        };
        let payload = signature_payload(&proof, &token, &method, &path);
        Ok(env.byte_array_from_slice(&payload)?.into_raw())
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_portamobile_Portamobile_nativeNewDialer(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
) -> jlong {
    env.with_env(|_env| -> Result<jlong, BridgeError> {
        let handles = handles();
        let id = handles.next_id()?;
        lock(&handles.dialers)?.insert(
            id,
            Arc::new(DialerHandle {
                cancellation: CancellationToken::new(),
            }),
        );
        Ok(id)
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_portamobile_Portamobile_nativeCloseDialer(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
    id: jlong,
) {
    env.with_env(|_env| -> Result<(), BridgeError> {
        if let Some(dialer) = lock(&handles().dialers)?.remove(&id) {
            dialer.cancellation.cancel();
        }
        Ok(())
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_portamobile_Portamobile_nativeDial(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
    dialer_id: jlong,
    server: JString<'_>,
    token: JString<'_>,
    remote_ip: JString<'_>,
    proof_provider: JObject<'_>,
    protector: JObject<'_>,
) -> jlong {
    env.with_env(|env| -> Result<jlong, BridgeError> {
        if !INITIALIZED.load(Ordering::Acquire) {
            return Err(BridgeError::Message(
                "native Android TLS is not initialized".to_string(),
            ));
        }
        let dialer = get_dialer(dialer_id)?;
        let server = read_string(env, &server, "server")?;
        let token = read_string(env, &token, "token")?;
        let remote_ip = read_string(env, &remote_ip, "remote IP address")?;
        let (_server_name, port) = parse_server(&server)?;
        let remote = parse_remote(&remote_ip, port)?;
        let vm = Arc::new(env.get_java_vm()?);
        let proof_provider: Arc<dyn ProofProvider> = Arc::new(AndroidProofProvider {
            vm: Arc::clone(&vm),
            provider: env.new_global_ref(proof_provider)?,
            device_id: Mutex::new(None),
        });
        let socket_protector = Arc::new(AndroidSocketProtector {
            vm,
            protector: env.new_global_ref(protector)?,
        });
        let config = ClientConfig {
            url: server,
            token,
            transport: Transport::Auto,
            tls: tls::platform_config()?,
            timeout: Duration::from_secs(15),
            dial_address: Some(remote),
            proof: proof_provider,
            socket_protector: Some(socket_protector),
            cancellation: dialer.cancellation.clone(),
        };
        let connection = runtime()?.block_on(porta_client::tunnel::connect(config))?;
        let handles = handles();
        let id = handles.next_id()?;
        lock(&handles.sessions)?.insert(
            id,
            Arc::new(SessionHandle {
                connection: Arc::new(connection),
            }),
        );
        Ok(id)
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_portamobile_Portamobile_nativeSessionTransport(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
    id: jlong,
) -> jstring {
    env.with_env(|env| -> Result<jstring, BridgeError> {
        let transport = match get_session(id)?.connection.transport {
            Transport::Http3 => "h3",
            Transport::Http2 => "h2",
            Transport::Auto => {
                return Err(BridgeError::Message(
                    "native tunnel has no selected transport".to_string(),
                ));
            }
        };
        Ok(JString::from_str(env, transport)?.into_raw())
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_portamobile_Portamobile_nativeSessionSend(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
    id: jlong,
    packet: JByteArray<'_>,
) {
    env.with_env(|env| -> Result<(), BridgeError> {
        let packet = env.convert_byte_array(packet)?;
        if packet.is_empty() || packet.len() > MAX_PACKET_SIZE {
            return Err(BridgeError::Message(format!(
                "invalid tunnel packet length {}",
                packet.len()
            )));
        }
        let session = get_session(id)?;
        runtime()?.block_on(session.connection.send(&packet))?;
        Ok(())
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_portamobile_Portamobile_nativeSessionReceive(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
    id: jlong,
) -> jbyteArray {
    env.with_env(|env| -> Result<jbyteArray, BridgeError> {
        let session = get_session(id)?;
        let packet = runtime()?.block_on(session.connection.receive())?;
        Ok(env.byte_array_from_slice(&packet)?.into_raw())
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_portamobile_Portamobile_nativeSessionAddress(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
    id: jlong,
) -> jstring {
    env.with_env(|env| -> Result<jstring, BridgeError> {
        let session = get_session(id)?;
        Ok(JString::from_str(env, session.connection.lease.address.addr().to_string())?.into_raw())
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_portamobile_Portamobile_nativeSessionPrefixLength(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
    id: jlong,
) -> jint {
    env.with_env(|_env| -> Result<jint, BridgeError> {
        Ok(get_session(id)?
            .connection
            .lease
            .address
            .prefix_len()
            .into())
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_portamobile_Portamobile_nativeSessionMTU(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
    id: jlong,
) -> jint {
    env.with_env(|_env| -> Result<jint, BridgeError> {
        Ok(get_session(id)?.connection.lease.mtu.into())
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_portamobile_Portamobile_nativeSessionDNS(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
    id: jlong,
) -> jstring {
    env.with_env(|env| -> Result<jstring, BridgeError> {
        let session = get_session(id)?;
        let dns = session
            .connection
            .lease
            .dns
            .map_or_else(String::new, |address| address.to_string());
        Ok(JString::from_str(env, dns)?.into_raw())
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_portamobile_Portamobile_nativeSessionAutomaticMTU(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
    id: jlong,
) -> jboolean {
    env.with_env(|_env| -> Result<jboolean, BridgeError> {
        Ok(if get_session(id)?.connection.mtu_automatic {
            JNI_TRUE
        } else {
            JNI_FALSE
        })
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_portamobile_Portamobile_nativeSessionMaximumMTU(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
    id: jlong,
) -> jint {
    env.with_env(|_env| -> Result<jint, BridgeError> {
        Ok(get_session(id)?
            .connection
            .mtu_ceiling
            .unwrap_or_default()
            .into())
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_portamobile_Portamobile_nativeSessionPacketDeliveryMode(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
    id: jlong,
) -> jstring {
    env.with_env(|env| -> Result<jstring, BridgeError> {
        let mode = match get_session(id)?.connection.delivery_mode {
            DeliveryMode::Datagram => "datagram",
            DeliveryMode::Capsule => "capsule",
            DeliveryMode::Framed => "framed",
            DeliveryMode::Unknown => "unknown",
        };
        Ok(JString::from_str(env, mode)?.into_raw())
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_portamobile_Portamobile_nativeCloseSession(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
    id: jlong,
) {
    env.with_env(|_env| -> Result<(), BridgeError> {
        if let Some(session) = lock(&handles().sessions)?.remove(&id) {
            runtime()?.block_on(session.connection.close());
        }
        Ok(())
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}
