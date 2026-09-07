use crate::state::sessions::{LiveSessions, SessionGuard};
use crate::state::usage;
use crate::wire::device_auth;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use parking_lot::Mutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub const REGISTRY_VERSION: u32 = 2;
pub const MAX_DEVICE_NONCES: usize = 2048;
pub const FORWARD_PROXY_DEVICE_ID: &str = "forward-proxy";
const FORWARD_PROXY_DEVICE_NAME: &str = "Forward proxy";
const LAST_SEEN_INTERVAL: Duration = Duration::from_secs(60);
const DEFAULT_METADATA_DEBOUNCE: Duration = Duration::from_secs(1);

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("client token is invalid")]
    Unauthorized,
    #[error("client is disabled")]
    Disabled,
    #[error("client device limit reached")]
    DeviceLimit,
    #[error("device sessions are being disconnected")]
    Draining,
    #[error("client registry is closed")]
    Closed,
    #[error("client or device not found")]
    NotFound,
    #[error("{0}")]
    InvalidInput(String),
    #[error("unsupported client registry version {0}")]
    UnsupportedVersion(u32),
    #[error("decode client registry: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("client registry I/O: {0}")]
    Io(#[from] io::Error),
    #[error("device proof is invalid")]
    InvalidDeviceProof,
    #[error("client registry durability sync failed: {0}")]
    Durability(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientRecord {
    pub id: String,
    pub name: String,
    pub token_hash: String,
    pub max_devices: usize,
    pub enabled: bool,
    #[serde(with = "rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<DeviceRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceRecord {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub public_key: String,
    #[serde(with = "rfc3339")]
    pub first_seen: OffsetDateTime,
    #[serde(with = "rfc3339")]
    pub last_seen: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegistryFile {
    pub version: u32,
    pub clients: Vec<ClientRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ClientSummary {
    pub id: String,
    pub name: String,
    pub max_devices: usize,
    pub enabled: bool,
    #[serde(with = "rfc3339")]
    pub created_at: OffsetDateTime,
    pub device_count: usize,
    pub active_sessions: usize,
    pub connections_total: u64,
    pub bytes_uploaded: u64,
    pub bytes_downloaded: u64,
    pub packets_uploaded: u64,
    pub packets_downloaded: u64,
    #[serde(skip_serializing_if = "Option::is_none", with = "optional_rfc3339")]
    pub last_connected: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none", with = "optional_rfc3339")]
    pub last_disconnected: Option<OffsetDateTime>,
    pub devices: Vec<DeviceSummary>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeviceSummary {
    pub id: String,
    pub name: String,
    #[serde(with = "rfc3339")]
    pub first_seen: OffsetDateTime,
    #[serde(with = "rfc3339")]
    pub last_seen: OffsetDateTime,
    pub active_sessions: usize,
    pub connections_total: u64,
    pub bytes_uploaded: u64,
    pub bytes_downloaded: u64,
    pub packets_uploaded: u64,
    pub packets_downloaded: u64,
    #[serde(skip_serializing_if = "Option::is_none", with = "optional_rfc3339")]
    pub last_connected: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none", with = "optional_rfc3339")]
    pub last_disconnected: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub transport: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub assigned_address: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub target: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortalIdentity {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientIdentity {
    pub account_id: String,
    pub lease_id: String,
}

pub struct AuthenticatedSession {
    pub identity: ClientIdentity,
    pub device_id: String,
    pub cancellation: CancellationToken,
    pub guard: SessionGuard,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct DeviceKey {
    account_id: String,
    device_id: String,
}

impl DeviceKey {
    fn new(account_id: impl Into<String>, device_id: impl Into<String>) -> Self {
        Self {
            account_id: account_id.into(),
            device_id: device_id.into(),
        }
    }
}

struct NonceWindow {
    values: HashMap<String, OffsetDateTime>,
    next_expiry: Option<OffsetDateTime>,
}

#[derive(Default)]
struct RegistryState {
    clients: Vec<ClientRecord>,
    token_index: HashMap<[u8; 32], usize>,
    nonces: HashMap<DeviceKey, NonceWindow>,
    retiring_devices: HashMap<DeviceKey, usize>,
    retiring_accounts: HashMap<String, usize>,
    account_disconnect: HashMap<String, u64>,
    device_disconnect: HashMap<DeviceKey, u64>,
    next_persist_sequence: u64,
    metadata_dirty: bool,
    metadata_version: u64,
}

struct PersistenceState {
    persisted_sequence: u64,
    durability_error: Option<String>,
}

struct RegistryInner {
    path: PathBuf,
    state: Mutex<RegistryState>,
    mutations: AsyncMutex<()>,
    persistence: AsyncMutex<PersistenceState>,
    sessions: LiveSessions,
    disconnect_epoch: AtomicU64,
    authentication_epochs: Mutex<HashMap<u64, usize>>,
    closed: AtomicBool,
    metadata_debounce: Mutex<Duration>,
    metadata_stop: CancellationToken,
    metadata_worker: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Clone)]
pub struct ClientRegistry {
    inner: Arc<RegistryInner>,
}

pub(crate) struct DeviceRetirement {
    _drain: DrainGuard,
}

struct AuthenticationAttempt {
    inner: Arc<RegistryInner>,
    epoch: u64,
}

enum DrainTarget {
    Account(String),
    Device(DeviceKey),
}

struct DrainGuard {
    inner: Arc<RegistryInner>,
    target: DrainTarget,
}

impl Drop for DrainGuard {
    fn drop(&mut self) {
        finish_drain(&self.inner, &self.target);
    }
}

impl Drop for AuthenticationAttempt {
    fn drop(&mut self) {
        let mut state = self.inner.state.lock();
        let mut epochs = self.inner.authentication_epochs.lock();
        if let Some(count) = epochs.get_mut(&self.epoch) {
            *count -= 1;
            if *count == 0 {
                epochs.remove(&self.epoch);
            }
        }
        prune_disconnects(
            &mut state,
            &epochs,
            self.inner.disconnect_epoch.load(Ordering::Acquire),
        );
    }
}

impl ClientRegistry {
    pub async fn open(
        path: impl Into<PathBuf>,
        bootstrap_token: impl AsRef<str>,
    ) -> Result<Self, RegistryError> {
        let path = path.into();
        if path.as_os_str().is_empty() {
            return Err(RegistryError::InvalidInput(
                "client registry path is required".into(),
            ));
        }

        let bootstrap_token = bootstrap_token.as_ref();
        let clients = match tokio::fs::read(&path).await {
            Ok(data) => {
                let file: RegistryFile = serde_json::from_slice(&data)?;
                if file.version != REGISTRY_VERSION {
                    return Err(RegistryError::UnsupportedVersion(file.version));
                }
                for (index, client) in file.clients.iter().enumerate() {
                    validate_stored_client(client).map_err(|error| {
                        RegistryError::InvalidInput(format!(
                            "client registry entry {}: {error}",
                            index + 1
                        ))
                    })?;
                }
                file.clients
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if bootstrap_token.trim().is_empty() {
                    return Err(RegistryError::InvalidInput(
                        "client registry does not exist and no bootstrap token was provided".into(),
                    ));
                }
                vec![ClientRecord {
                    id: random_hex(8),
                    name: "Default client".into(),
                    token_hash: hash_token(bootstrap_token),
                    max_devices: 5,
                    enabled: true,
                    created_at: OffsetDateTime::now_utc(),
                    devices: Vec::new(),
                }]
            }
            Err(error) => return Err(error.into()),
        };

        let mut state = RegistryState {
            clients,
            ..RegistryState::default()
        };
        rebuild_token_index(&mut state);
        let registry = Self {
            inner: Arc::new(RegistryInner {
                path,
                state: Mutex::new(state),
                mutations: AsyncMutex::new(()),
                persistence: AsyncMutex::new(PersistenceState {
                    persisted_sequence: 0,
                    durability_error: None,
                }),
                sessions: LiveSessions::new(),
                disconnect_epoch: AtomicU64::new(0),
                authentication_epochs: Mutex::new(HashMap::new()),
                closed: AtomicBool::new(false),
                metadata_debounce: Mutex::new(DEFAULT_METADATA_DEBOUNCE),
                metadata_stop: CancellationToken::new(),
                metadata_worker: Mutex::new(None),
            }),
        };

        if !tokio::fs::try_exists(&registry.inner.path).await? {
            let _mutation = registry.inner.mutations.lock().await;
            registry.persist_current().await?;
        }
        Ok(registry)
    }

    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    pub fn list(&self) -> Vec<ClientSummary> {
        self.list_with_optional_usage(None)
    }

    pub fn list_with_usage(&self, snapshot: &usage::Snapshot) -> Vec<ClientSummary> {
        self.list_with_optional_usage(Some(snapshot))
    }

    fn list_with_optional_usage(&self, snapshot: Option<&usage::Snapshot>) -> Vec<ClientSummary> {
        let state = self.inner.state.lock();
        let mut summaries = state
            .clients
            .iter()
            .map(|client| summarize_client(client, &self.inner.sessions, snapshot))
            .collect::<Vec<_>>();
        summaries.sort_by_cached_key(|client| client.name.to_ascii_lowercase());
        summaries
    }

    pub fn authenticate_portal(&self, token: &str) -> Result<PortalIdentity, RegistryError> {
        let state = self.inner.state.lock();
        let client = client_for_token(&state, token)?;
        Ok(PortalIdentity {
            id: client.id.clone(),
            name: client.name.clone(),
        })
    }

    pub fn portal_client_active(&self, client_id: &str, token_hash: &str) -> bool {
        self.inner
            .state
            .lock()
            .clients
            .iter()
            .find(|client| client.id == client_id)
            .is_some_and(|client| {
                client.enabled
                    && client.token_hash.len() == token_hash.len()
                    && bool::from(client.token_hash.as_bytes().ct_eq(token_hash.as_bytes()))
            })
    }

    pub async fn create(
        &self,
        name: impl AsRef<str>,
        max_devices: usize,
    ) -> Result<(ClientSummary, String), RegistryError> {
        self.ensure_open()?;
        let name = validate_client_input(name.as_ref(), max_devices)?;
        let token = random_token();
        let client = ClientRecord {
            id: random_hex(8),
            name,
            token_hash: hash_token(&token),
            max_devices,
            enabled: true,
            created_at: OffsetDateTime::now_utc(),
            devices: Vec::new(),
        };
        let _mutation = self.inner.mutations.lock().await;
        self.ensure_open()?;
        let candidate = {
            let state = self.inner.state.lock();
            let mut clients = state.clients.clone();
            clients.push(client.clone());
            clients
        };
        self.persist_clients(&candidate).await?;
        let mut state = self.inner.state.lock();
        state.clients.push(client.clone());
        rebuild_token_index(&mut state);
        drop(state);
        Ok((summarize_client(&client, &self.inner.sessions, None), token))
    }

    pub async fn update(
        &self,
        id: &str,
        name: impl AsRef<str>,
        max_devices: usize,
        enabled: bool,
    ) -> Result<ClientSummary, RegistryError> {
        self.ensure_open()?;
        let name = validate_client_input(name.as_ref(), max_devices)?;
        let _mutation = self.inner.mutations.lock().await;
        self.ensure_open()?;
        let candidate = {
            let state = self.inner.state.lock();
            let client = state
                .clients
                .iter()
                .find(|client| client.id == id)
                .ok_or(RegistryError::NotFound)?;
            if max_devices < client.devices.len() {
                return Err(RegistryError::InvalidInput(format!(
                    "device limit cannot be below the {} enrolled devices",
                    client.devices.len()
                )));
            }
            let mut clients = state.clients.clone();
            let client = clients
                .iter_mut()
                .find(|client| client.id == id)
                .expect("candidate contains the selected client");
            client.name = name;
            client.max_devices = max_devices;
            client.enabled = enabled;
            clients
        };
        self.persist_clients(&candidate).await?;
        {
            let mut state = self.inner.state.lock();
            let persisted = candidate
                .iter()
                .find(|client| client.id == id)
                .expect("candidate contains the selected client");
            let client = find_client_mut(&mut state, id)?;
            client.name.clone_from(&persisted.name);
            client.max_devices = persisted.max_devices;
            client.enabled = persisted.enabled;
        }

        if !enabled {
            let _drain = self.begin_account_drain(id);
            self.inner.sessions.cancel_account(id).await;
        }
        let state = self.inner.state.lock();
        let client = state
            .clients
            .iter()
            .find(|client| client.id == id)
            .ok_or(RegistryError::NotFound)?;
        Ok(summarize_client(client, &self.inner.sessions, None))
    }

    pub async fn rotate_token(&self, id: &str) -> Result<String, RegistryError> {
        self.ensure_open()?;
        let token = random_token();
        let new_hash = hash_token(&token);
        let _mutation = self.inner.mutations.lock().await;
        self.ensure_open()?;
        let candidate = {
            let state = self.inner.state.lock();
            if !state.clients.iter().any(|client| client.id == id) {
                return Err(RegistryError::NotFound);
            }
            let mut clients = state.clients.clone();
            clients
                .iter_mut()
                .find(|client| client.id == id)
                .expect("candidate contains the selected client")
                .token_hash
                .clone_from(&new_hash);
            clients
        };
        self.persist_clients(&candidate).await?;
        {
            let mut state = self.inner.state.lock();
            find_client_mut(&mut state, id)?
                .token_hash
                .clone_from(&new_hash);
            rebuild_token_index(&mut state);
        }
        {
            let mut state = self.inner.state.lock();
            state.nonces.retain(|key, _| key.account_id != id);
        }
        let _drain = self.begin_account_drain(id);
        self.inner.sessions.cancel_account(id).await;
        Ok(token)
    }

    pub async fn delete(&self, id: &str) -> Result<(), RegistryError> {
        self.ensure_open()?;
        let _mutation = self.inner.mutations.lock().await;
        self.ensure_open()?;
        let (index, candidate) = {
            let state = self.inner.state.lock();
            let index = state
                .clients
                .iter()
                .position(|client| client.id == id)
                .ok_or(RegistryError::NotFound)?;
            let mut clients = state.clients.clone();
            clients.remove(index);
            (index, clients)
        };
        self.persist_clients(&candidate).await?;
        {
            let mut state = self.inner.state.lock();
            if state
                .clients
                .get(index)
                .is_none_or(|client| client.id != id)
            {
                return Err(RegistryError::NotFound);
            }
            state.clients.remove(index);
            rebuild_token_index(&mut state);
        }
        {
            let mut state = self.inner.state.lock();
            state.nonces.retain(|key, _| key.account_id != id);
        }
        let _drain = self.begin_account_drain(id);
        self.inner.sessions.cancel_account(id).await;
        Ok(())
    }

    pub async fn forget_device(
        &self,
        account_id: &str,
        device_id: &str,
    ) -> Result<(), RegistryError> {
        let _retirement = self.retire_device(account_id, device_id).await?;
        Ok(())
    }

    pub(crate) async fn retire_device(
        &self,
        account_id: &str,
        device_id: &str,
    ) -> Result<DeviceRetirement, RegistryError> {
        self.ensure_open()?;
        let _mutation = self.inner.mutations.lock().await;
        self.ensure_open()?;
        let (index, candidate) = {
            let state = self.inner.state.lock();
            let client = state
                .clients
                .iter()
                .find(|client| client.id == account_id)
                .ok_or(RegistryError::NotFound)?;
            let index = client
                .devices
                .iter()
                .position(|device| device.id == device_id)
                .ok_or(RegistryError::NotFound)?;
            let mut clients = state.clients.clone();
            clients
                .iter_mut()
                .find(|client| client.id == account_id)
                .expect("candidate contains selected client")
                .devices
                .remove(index);
            (index, clients)
        };
        self.persist_clients(&candidate).await?;
        {
            let mut state = self.inner.state.lock();
            let client = find_client_mut(&mut state, account_id)?;
            if client
                .devices
                .get(index)
                .is_none_or(|device| device.id != device_id)
            {
                return Err(RegistryError::NotFound);
            }
            client.devices.remove(index);
        }
        let key = DeviceKey::new(account_id, device_id);
        self.inner.state.lock().nonces.remove(&key);
        let drain = self.begin_device_drain(&key);
        self.inner
            .sessions
            .cancel_device(account_id, device_id)
            .await;
        Ok(DeviceRetirement { _drain: drain })
    }

    pub async fn delete_device(
        &self,
        account_id: &str,
        device_id: &str,
    ) -> Result<(), RegistryError> {
        self.forget_device(account_id, device_id).await
    }

    pub async fn disconnect(
        &self,
        account_id: &str,
        device_id: Option<&str>,
    ) -> Result<usize, RegistryError> {
        self.ensure_open()?;
        let _mutation = self.inner.mutations.lock().await;
        self.ensure_open()?;
        {
            let state = self.inner.state.lock();
            let client = state
                .clients
                .iter()
                .find(|client| client.id == account_id)
                .ok_or(RegistryError::NotFound)?;
            if let Some(device_id) = device_id {
                if !client.devices.iter().any(|device| device.id == device_id) {
                    return Err(RegistryError::NotFound);
                }
            }
        }
        match device_id {
            Some(device_id) => {
                let key = DeviceKey::new(account_id, device_id);
                let _drain = self.begin_device_drain(&key);
                let count = self
                    .inner
                    .sessions
                    .cancel_device(account_id, device_id)
                    .await;
                Ok(count)
            }
            None => {
                let _drain = self.begin_account_drain(account_id);
                let count = self.inner.sessions.cancel_account(account_id).await;
                Ok(count)
            }
        }
    }

    pub async fn authenticate_device_session(
        &self,
        token: &str,
        proof: &device_auth::Proof,
        method: &str,
        path: &str,
    ) -> Result<AuthenticatedSession, RegistryError> {
        self.ensure_open()?;
        let attempt = self.begin_authentication();
        let attempt_epoch = attempt.epoch;
        {
            let state = self.inner.state.lock();
            client_for_token(&state, token)?;
        }

        let verified = device_auth::verify(proof, token, method, path, OffsetDateTime::now_utc())
            .map_err(|_| RegistryError::Unauthorized)?;
        let canonical_key = URL_SAFE_NO_PAD.encode(&verified.encoded_public_key);
        let now = OffsetDateTime::now_utc();
        {
            let mut state = self.inner.state.lock();
            self.ensure_open()?;
            let client_index = client_index_for_token(&state, token)?;
            let account_id = state.clients[client_index].id.clone();
            let key = DeviceKey::new(&account_id, &proof.device_id);
            if authentication_blocked(&state, &account_id, &key, attempt_epoch) {
                return Err(RegistryError::Draining);
            }
            if nonce_seen(&mut state, &key, &proof.nonce, verified.signed_at, now) {
                return Err(RegistryError::Unauthorized);
            }
            if let Some(device) = state.clients[client_index]
                .devices
                .iter()
                .find(|device| device.id == proof.device_id)
            {
                if device.public_key != canonical_key {
                    return Err(RegistryError::Unauthorized);
                }
                if device.name == proof.name
                    && !elapsed_at_least(device.last_seen, now, LAST_SEEN_INTERVAL)
                {
                    remember_nonce(&mut state, key, proof.nonce.clone(), verified.signed_at);
                    let identity = registry_identity(&account_id, &proof.device_id);
                    let registration = self.inner.sessions.register(&account_id, &proof.device_id);
                    let (cancellation, guard) = registration.into_parts();
                    return Ok(AuthenticatedSession {
                        identity,
                        device_id: proof.device_id.clone(),
                        cancellation,
                        guard,
                    });
                }
            }
        }

        let _mutation = self.inner.mutations.lock().await;
        self.ensure_open()?;
        let (account_id, candidate, existing_index, is_new) = {
            let mut state = self.inner.state.lock();
            let client_index = client_index_for_token(&state, token)?;
            let account_id = state.clients[client_index].id.clone();
            let key = DeviceKey::new(&account_id, &proof.device_id);
            if authentication_blocked(&state, &account_id, &key, attempt_epoch) {
                return Err(RegistryError::Draining);
            }
            if nonce_seen(&mut state, &key, &proof.nonce, verified.signed_at, now) {
                return Err(RegistryError::Unauthorized);
            }

            if let Some(device_index) = state.clients[client_index]
                .devices
                .iter()
                .position(|device| device.id == proof.device_id)
            {
                let device = &state.clients[client_index].devices[device_index];
                if device.public_key != canonical_key {
                    return Err(RegistryError::Unauthorized);
                }
                let needs_persist = device.name != proof.name
                    || elapsed_at_least(device.last_seen, now, LAST_SEEN_INTERVAL);
                if !needs_persist {
                    remember_nonce(&mut state, key, proof.nonce.clone(), verified.signed_at);
                    let identity = registry_identity(&account_id, &proof.device_id);
                    let registration = self.inner.sessions.register(&account_id, &proof.device_id);
                    let (cancellation, guard) = registration.into_parts();
                    return Ok(AuthenticatedSession {
                        identity,
                        device_id: proof.device_id.clone(),
                        cancellation,
                        guard,
                    });
                }
                let mut clients = state.clients.clone();
                let device = &mut clients[client_index].devices[device_index];
                device.name.clone_from(&proof.name);
                device.last_seen = now;
                (account_id, clients, Some(device_index), false)
            } else {
                if state.clients[client_index].devices.len()
                    >= state.clients[client_index].max_devices
                {
                    return Err(RegistryError::DeviceLimit);
                }
                let mut clients = state.clients.clone();
                clients[client_index].devices.push(DeviceRecord {
                    id: proof.device_id.clone(),
                    name: proof.name.clone(),
                    public_key: canonical_key.clone(),
                    first_seen: now,
                    last_seen: now,
                });
                (account_id, clients, None, true)
            }
        };

        self.persist_clients(&candidate).await?;
        {
            let mut state = self.inner.state.lock();
            let client = state
                .clients
                .iter_mut()
                .find(|client| client.id == account_id)
                .ok_or(RegistryError::Unauthorized)?;
            if is_new {
                if client.devices.len() >= client.max_devices {
                    return Err(RegistryError::DeviceLimit);
                }
                client.devices.push(
                    candidate
                        .iter()
                        .find(|client| client.id == account_id)
                        .and_then(|client| client.devices.last())
                        .cloned()
                        .ok_or(RegistryError::InvalidDeviceProof)?,
                );
            } else if let Some(device_index) = existing_index {
                let persisted = candidate
                    .iter()
                    .find(|client| client.id == account_id)
                    .and_then(|client| client.devices.get(device_index))
                    .cloned()
                    .ok_or(RegistryError::InvalidDeviceProof)?;
                let current = client
                    .devices
                    .iter_mut()
                    .find(|device| device.id == proof.device_id)
                    .ok_or(RegistryError::Unauthorized)?;
                current.name = persisted.name;
                current.last_seen = persisted.last_seen;
            }
            let key = DeviceKey::new(&account_id, &proof.device_id);
            remember_nonce(&mut state, key, proof.nonce.clone(), verified.signed_at);
            let identity = registry_identity(&account_id, &proof.device_id);
            let registration = self.inner.sessions.register(&account_id, &proof.device_id);
            let (cancellation, guard) = registration.into_parts();
            Ok(AuthenticatedSession {
                identity,
                device_id: proof.device_id.clone(),
                cancellation,
                guard,
            })
        }
    }

    pub async fn authenticate_proxy_session(
        &self,
        token: &str,
    ) -> Result<AuthenticatedSession, RegistryError> {
        self.ensure_open()?;
        let attempt = self.begin_authentication();
        let attempt_epoch = attempt.epoch;
        let now = OffsetDateTime::now_utc();
        let mut start_metadata_worker = false;
        {
            let mut state = self.inner.state.lock();
            self.ensure_open()?;
            let client_index = client_index_for_token(&state, token)?;
            let account_id = state.clients[client_index].id.clone();
            let key = DeviceKey::new(&account_id, FORWARD_PROXY_DEVICE_ID);
            if authentication_blocked(&state, &account_id, &key, attempt_epoch) {
                return Err(RegistryError::Draining);
            }
            if let Some(device) = state.clients[client_index]
                .devices
                .iter_mut()
                .find(|device| device.id == FORWARD_PROXY_DEVICE_ID)
            {
                if elapsed_at_least(device.last_seen, now, LAST_SEEN_INTERVAL) {
                    device.last_seen = now;
                    state.metadata_dirty = true;
                    state.metadata_version = state.metadata_version.wrapping_add(1);
                    start_metadata_worker = true;
                }
                let identity = registry_identity(&account_id, FORWARD_PROXY_DEVICE_ID);
                let registration = self
                    .inner
                    .sessions
                    .register(&account_id, FORWARD_PROXY_DEVICE_ID);
                let (cancellation, guard) = registration.into_parts();
                drop(state);
                if start_metadata_worker {
                    self.start_metadata_worker();
                }
                return Ok(AuthenticatedSession {
                    identity,
                    device_id: FORWARD_PROXY_DEVICE_ID.into(),
                    cancellation,
                    guard,
                });
            }
        }

        let _mutation = self.inner.mutations.lock().await;
        self.ensure_open()?;
        let (account_id, candidate) = {
            let state = self.inner.state.lock();
            let client_index = client_index_for_token(&state, token)?;
            let account_id = state.clients[client_index].id.clone();
            let key = DeviceKey::new(&account_id, FORWARD_PROXY_DEVICE_ID);
            if authentication_blocked(&state, &account_id, &key, attempt_epoch) {
                return Err(RegistryError::Draining);
            }
            if let Some(device) = state.clients[client_index]
                .devices
                .iter()
                .find(|device| device.id == FORWARD_PROXY_DEVICE_ID)
            {
                let identity = registry_identity(&account_id, FORWARD_PROXY_DEVICE_ID);
                let registration = self
                    .inner
                    .sessions
                    .register(&account_id, FORWARD_PROXY_DEVICE_ID);
                let (cancellation, guard) = registration.into_parts();
                let _ = device;
                return Ok(AuthenticatedSession {
                    identity,
                    device_id: FORWARD_PROXY_DEVICE_ID.into(),
                    cancellation,
                    guard,
                });
            }
            if state.clients[client_index].devices.len() >= state.clients[client_index].max_devices
            {
                return Err(RegistryError::DeviceLimit);
            }
            let mut clients = state.clients.clone();
            clients[client_index].devices.push(DeviceRecord {
                id: FORWARD_PROXY_DEVICE_ID.into(),
                name: FORWARD_PROXY_DEVICE_NAME.into(),
                public_key: String::new(),
                first_seen: now,
                last_seen: now,
            });
            (account_id, clients)
        };
        self.persist_clients(&candidate).await?;
        {
            let mut state = self.inner.state.lock();
            let client = state
                .clients
                .iter_mut()
                .find(|client| client.id == account_id)
                .ok_or(RegistryError::Unauthorized)?;
            if !client
                .devices
                .iter()
                .any(|device| device.id == FORWARD_PROXY_DEVICE_ID)
            {
                client.devices.push(
                    candidate
                        .iter()
                        .find(|client| client.id == account_id)
                        .and_then(|client| client.devices.last())
                        .cloned()
                        .ok_or(RegistryError::Unauthorized)?,
                );
            }
            let identity = registry_identity(&account_id, FORWARD_PROXY_DEVICE_ID);
            let registration = self
                .inner
                .sessions
                .register(&account_id, FORWARD_PROXY_DEVICE_ID);
            let (cancellation, guard) = registration.into_parts();
            Ok(AuthenticatedSession {
                identity,
                device_id: FORWARD_PROXY_DEVICE_ID.into(),
                cancellation,
                guard,
            })
        }
    }

    pub async fn close(&self) -> Result<(), RegistryError> {
        let mutation = self.inner.mutations.lock().await;
        let already_closed = {
            let _state = self.inner.state.lock();
            self.inner.closed.swap(true, Ordering::AcqRel)
        };
        drop(mutation);
        if already_closed {
            self.flush_metadata().await?;
            return self.retry_durability_sync().await;
        }
        self.inner.metadata_stop.cancel();
        let worker = self.inner.metadata_worker.lock().take();
        if let Some(worker) = worker {
            let _ = worker.await;
        }
        self.flush_metadata().await?;
        self.retry_durability_sync().await
    }

    fn ensure_open(&self) -> Result<(), RegistryError> {
        if self.inner.closed.load(Ordering::Acquire) {
            Err(RegistryError::Closed)
        } else {
            Ok(())
        }
    }

    fn begin_authentication(&self) -> AuthenticationAttempt {
        let mut epochs = self.inner.authentication_epochs.lock();
        let epoch = self.inner.disconnect_epoch.load(Ordering::Acquire);
        *epochs.entry(epoch).or_default() += 1;
        AuthenticationAttempt {
            inner: self.inner.clone(),
            epoch,
        }
    }

    fn begin_account_drain(&self, account_id: &str) -> DrainGuard {
        let mut state = self.inner.state.lock();
        let epoch = self.inner.disconnect_epoch.fetch_add(1, Ordering::AcqRel) + 1;
        state.account_disconnect.insert(account_id.into(), epoch);
        *state
            .retiring_accounts
            .entry(account_id.to_owned())
            .or_default() += 1;
        DrainGuard {
            inner: self.inner.clone(),
            target: DrainTarget::Account(account_id.to_owned()),
        }
    }

    fn begin_device_drain(&self, key: &DeviceKey) -> DrainGuard {
        let mut state = self.inner.state.lock();
        let epoch = self.inner.disconnect_epoch.fetch_add(1, Ordering::AcqRel) + 1;
        state.device_disconnect.insert(key.clone(), epoch);
        *state.retiring_devices.entry(key.clone()).or_default() += 1;
        DrainGuard {
            inner: self.inner.clone(),
            target: DrainTarget::Device(key.clone()),
        }
    }

    fn start_metadata_worker(&self) {
        let mut worker = self.inner.metadata_worker.lock();
        if worker.as_ref().is_some_and(|worker| !worker.is_finished()) {
            return;
        }
        let registry = self.clone();
        *worker = Some(tokio::spawn(async move {
            loop {
                let delay = *registry.inner.metadata_debounce.lock();
                tokio::select! {
                    _ = registry.inner.metadata_stop.cancelled() => {
                        let _ = registry.flush_metadata().await;
                        return;
                    }
                    _ = tokio::time::sleep(delay) => {}
                }
                match registry.flush_metadata().await {
                    Ok(()) => {
                        if !registry.inner.state.lock().metadata_dirty {
                            return;
                        }
                    }
                    Err(error) => {
                        tracing::error!(%error, "persist client registry metadata");
                    }
                }
            }
        }));
    }

    async fn flush_metadata(&self) -> Result<(), RegistryError> {
        let _mutation = self.inner.mutations.lock().await;
        let (version, clients) = {
            let state = self.inner.state.lock();
            if !state.metadata_dirty {
                return Ok(());
            }
            (state.metadata_version, state.clients.clone())
        };
        self.persist_clients(&clients).await?;
        let mut state = self.inner.state.lock();
        if state.metadata_version == version {
            state.metadata_dirty = false;
        }
        Ok(())
    }

    async fn persist_current(&self) -> Result<(), RegistryError> {
        let clients = self.inner.state.lock().clients.clone();
        self.persist_clients(&clients).await
    }

    async fn persist_clients(&self, clients: &[ClientRecord]) -> Result<(), RegistryError> {
        let sequence = {
            let mut state = self.inner.state.lock();
            state.next_persist_sequence = state.next_persist_sequence.wrapping_add(1);
            state.next_persist_sequence
        };
        let mut data = serde_json::to_vec_pretty(&RegistryFile {
            version: REGISTRY_VERSION,
            clients: clients.to_vec(),
        })?;
        data.push(b'\n');

        let inner = self.inner.clone();
        tokio::spawn(async move {
            let mut persistence = inner.persistence.lock().await;
            if sequence <= persistence.persisted_sequence {
                return Ok(());
            }
            let path = inner.path.clone();
            let outcome = tokio::task::spawn_blocking(move || atomic_write_registry(&path, &data))
                .await
                .map_err(|error| io::Error::other(error.to_string()))??;
            persistence.persisted_sequence = sequence;
            persistence.durability_error = outcome;
            Ok(())
        })
        .await
        .map_err(|error| io::Error::other(error.to_string()))?
    }

    async fn retry_durability_sync(&self) -> Result<(), RegistryError> {
        let mut persistence = self.inner.persistence.lock().await;
        let Some(previous) = persistence.durability_error.clone() else {
            return Ok(());
        };
        let directory = self
            .inner
            .path
            .parent()
            .filter(|directory| !directory.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let result = tokio::task::spawn_blocking(move || {
            let directory = std::fs::File::open(directory)?;
            directory.sync_all()
        })
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
        match result {
            Ok(()) => {
                persistence.durability_error = None;
                Ok(())
            }
            Err(error) => Err(RegistryError::Durability(format!(
                "{previous}; retry: {error}"
            ))),
        }
    }

    #[cfg(test)]
    fn set_metadata_debounce(&self, duration: Duration) {
        *self.inner.metadata_debounce.lock() = duration;
    }
}

fn client_index_for_token(state: &RegistryState, token: &str) -> Result<usize, RegistryError> {
    let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    let index = state.token_index.get(&digest).copied();
    let mut indexed_digest = [0_u8; 32];
    if let Some(client) = index.and_then(|index| state.clients.get(index)) {
        let _ = hex::decode_to_slice(&client.token_hash, &mut indexed_digest);
    }
    let matches = bool::from(indexed_digest.ct_eq(&digest));
    let index = index
        .filter(|_| matches)
        .ok_or(RegistryError::Unauthorized)?;
    if !state.clients[index].enabled {
        return Err(RegistryError::Disabled);
    }
    Ok(index)
}

fn client_for_token<'a>(
    state: &'a RegistryState,
    token: &str,
) -> Result<&'a ClientRecord, RegistryError> {
    client_index_for_token(state, token).map(|index| &state.clients[index])
}

fn find_client_mut<'a>(
    state: &'a mut RegistryState,
    id: &str,
) -> Result<&'a mut ClientRecord, RegistryError> {
    state
        .clients
        .iter_mut()
        .find(|client| client.id == id)
        .ok_or(RegistryError::NotFound)
}

fn rebuild_token_index(state: &mut RegistryState) {
    state.token_index.clear();
    state.token_index.reserve(state.clients.len());
    for (index, client) in state.clients.iter().enumerate() {
        let Ok(decoded) = hex::decode(&client.token_hash) else {
            continue;
        };
        let Ok(digest) = <[u8; 32]>::try_from(decoded) else {
            continue;
        };
        state.token_index.entry(digest).or_insert(index);
    }
}

fn authentication_blocked(
    state: &RegistryState,
    account_id: &str,
    key: &DeviceKey,
    attempt_epoch: u64,
) -> bool {
    state
        .retiring_accounts
        .get(account_id)
        .is_some_and(|count| *count > 0)
        || state
            .retiring_devices
            .get(key)
            .is_some_and(|count| *count > 0)
        || state
            .account_disconnect
            .get(account_id)
            .is_some_and(|epoch| *epoch > attempt_epoch)
        || state
            .device_disconnect
            .get(key)
            .is_some_and(|epoch| *epoch > attempt_epoch)
}

fn prune_disconnects(
    state: &mut RegistryState,
    authentication_epochs: &HashMap<u64, usize>,
    current_epoch: u64,
) {
    let oldest = authentication_epochs
        .keys()
        .copied()
        .min()
        .unwrap_or(current_epoch);
    state.account_disconnect.retain(|_, epoch| *epoch > oldest);
    state.device_disconnect.retain(|_, epoch| *epoch > oldest);
}

fn nonce_seen(
    state: &mut RegistryState,
    key: &DeviceKey,
    nonce: &str,
    signed_at: OffsetDateTime,
    now: OffsetDateTime,
) -> bool {
    let max_clock_skew =
        time::Duration::try_from(device_auth::MAX_CLOCK_SKEW).unwrap_or(time::Duration::MAX);
    if signed_at + max_clock_skew < now {
        return true;
    }
    let Some(window) = state.nonces.get_mut(key) else {
        return false;
    };
    if window.next_expiry.is_none_or(|expiry| expiry <= now) {
        window.values.retain(|_, expiry| *expiry > now);
        window.next_expiry = window.values.values().copied().min();
        if window.values.is_empty() {
            state.nonces.remove(key);
            return false;
        }
    }
    window.values.contains_key(nonce) || window.values.len() >= MAX_DEVICE_NONCES
}

fn remember_nonce(
    state: &mut RegistryState,
    key: DeviceKey,
    nonce: String,
    signed_at: OffsetDateTime,
) {
    let max_clock_skew =
        time::Duration::try_from(device_auth::MAX_CLOCK_SKEW).unwrap_or(time::Duration::MAX);
    let expiry = signed_at + max_clock_skew;
    let window = state.nonces.entry(key).or_insert_with(|| NonceWindow {
        values: HashMap::new(),
        next_expiry: None,
    });
    window.values.insert(nonce, expiry);
    window.next_expiry = Some(
        window
            .next_expiry
            .map_or(expiry, |current| current.min(expiry)),
    );
}

fn finish_drain(inner: &RegistryInner, target: &DrainTarget) {
    let mut state = inner.state.lock();
    let epoch = inner.disconnect_epoch.fetch_add(1, Ordering::AcqRel) + 1;
    match target {
        DrainTarget::Account(account_id) => {
            state.account_disconnect.insert(account_id.clone(), epoch);
            decrement(&mut state.retiring_accounts, account_id);
        }
        DrainTarget::Device(key) => {
            state.device_disconnect.insert(key.clone(), epoch);
            decrement(&mut state.retiring_devices, key);
        }
    }
    let epochs = inner.authentication_epochs.lock();
    prune_disconnects(&mut state, &epochs, epoch);
}

fn decrement<K, Q>(counts: &mut HashMap<K, usize>, key: &Q)
where
    K: Eq + std::hash::Hash + std::borrow::Borrow<Q>,
    Q: Eq + std::hash::Hash + ?Sized,
{
    if let Some(count) = counts.get_mut(key) {
        *count -= 1;
        if *count == 0 {
            counts.remove(key);
        }
    }
}

fn validate_stored_client(client: &ClientRecord) -> Result<(), RegistryError> {
    if client.id.len() != 16 || !client.id.bytes().all(|value| value.is_ascii_hexdigit()) {
        return Err(RegistryError::InvalidInput("invalid client ID".into()));
    }
    validate_client_input(&client.name, client.max_devices)?;
    if client.token_hash.len() != 64
        || !client
            .token_hash
            .bytes()
            .all(|value| value.is_ascii_hexdigit())
    {
        return Err(RegistryError::InvalidInput("invalid token hash".into()));
    }
    let mut seen = std::collections::HashSet::with_capacity(client.devices.len());
    for device in &client.devices {
        if !(device.id == FORWARD_PROXY_DEVICE_ID || device_auth::is_valid_device_id(&device.id))
            || !seen.insert(&device.id)
        {
            return Err(RegistryError::InvalidInput(format!(
                "invalid or duplicate device ID {:?}",
                device.id
            )));
        }
        if device.id == FORWARD_PROXY_DEVICE_ID {
            if !device.public_key.is_empty() || device.name != FORWARD_PROXY_DEVICE_NAME {
                return Err(RegistryError::InvalidInput(
                    "invalid forward proxy device".into(),
                ));
            }
            continue;
        }
        if !device_auth::is_valid_device_name(&device.name) {
            return Err(RegistryError::InvalidInput(format!(
                "invalid device name {:?}",
                device.name
            )));
        }
        let encoded = URL_SAFE_NO_PAD.decode(&device.public_key).map_err(|_| {
            RegistryError::InvalidInput(format!("invalid public key for device {:?}", device.id))
        })?;
        if encoded.is_empty() || URL_SAFE_NO_PAD.encode(&encoded) != device.public_key {
            return Err(RegistryError::InvalidInput(format!(
                "non-canonical public key for device {:?}",
                device.id
            )));
        }
        let derived_id = device_auth::device_id_from_encoded(&encoded).map_err(|_| {
            RegistryError::InvalidInput(format!("invalid public key for device {:?}", device.id))
        })?;
        if derived_id != device.id {
            return Err(RegistryError::InvalidInput(format!(
                "public key does not match device ID {:?}",
                device.id
            )));
        }
    }
    if client.devices.len() > client.max_devices {
        return Err(RegistryError::InvalidInput(
            "enrolled devices exceed device limit".into(),
        ));
    }
    Ok(())
}

fn validate_client_input(name: &str, max_devices: usize) -> Result<String, RegistryError> {
    let name = name.trim();
    if name.is_empty() || name.len() > 80 {
        return Err(RegistryError::InvalidInput(
            "client name must contain 1 to 80 characters".into(),
        ));
    }
    if !(1..=100).contains(&max_devices) {
        return Err(RegistryError::InvalidInput(
            "device limit must be between 1 and 100".into(),
        ));
    }
    Ok(name.into())
}

fn summarize_client(
    client: &ClientRecord,
    sessions: &LiveSessions,
    snapshot: Option<&usage::Snapshot>,
) -> ClientSummary {
    let mut devices = client.devices.clone();
    devices.sort_by_key(|device| std::cmp::Reverse(device.last_seen));
    let client_usage = snapshot
        .and_then(|snapshot| snapshot.clients.get(&client.id))
        .cloned()
        .unwrap_or_default();
    ClientSummary {
        id: client.id.clone(),
        name: client.name.clone(),
        max_devices: client.max_devices,
        enabled: client.enabled,
        created_at: client.created_at,
        device_count: devices.len(),
        active_sessions: snapshot.map_or_else(
            || sessions.active_count(&client.id, None),
            |_| client_usage.active_sessions,
        ),
        connections_total: client_usage.connections_total,
        bytes_uploaded: client_usage.bytes_uploaded,
        bytes_downloaded: client_usage.bytes_downloaded,
        packets_uploaded: client_usage.packets_uploaded,
        packets_downloaded: client_usage.packets_downloaded,
        last_connected: client_usage.last_connected,
        last_disconnected: client_usage.last_disconnected,
        devices: devices
            .into_iter()
            .map(|device| {
                let device_usage = snapshot
                    .map(|snapshot| usage::device(snapshot, &client.id, &device.id))
                    .unwrap_or_default();
                DeviceSummary {
                    active_sessions: snapshot.map_or_else(
                        || sessions.active_count(&client.id, Some(&device.id)),
                        |_| device_usage.active_sessions,
                    ),
                    id: device.id,
                    name: device.name,
                    first_seen: device.first_seen,
                    last_seen: device.last_seen,
                    connections_total: device_usage.connections_total,
                    bytes_uploaded: device_usage.bytes_uploaded,
                    bytes_downloaded: device_usage.bytes_downloaded,
                    packets_uploaded: device_usage.packets_uploaded,
                    packets_downloaded: device_usage.packets_downloaded,
                    last_connected: device_usage.last_connected,
                    last_disconnected: device_usage.last_disconnected,
                    transport: device_usage.transport,
                    assigned_address: device_usage.assigned_address,
                    target: device_usage.target,
                }
            })
            .collect(),
    }
}

fn registry_identity(account_id: &str, device_id: &str) -> ClientIdentity {
    let mut digest = Sha256::new();
    digest.update(account_id.as_bytes());
    digest.update(b"\0");
    digest.update(device_id.as_bytes());
    let digest = digest.finalize();
    ClientIdentity {
        account_id: account_id.into(),
        lease_id: format!("device-{}", hex::encode(&digest[..16])),
    }
}

fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn random_token() -> String {
    let mut value = [0_u8; 32];
    rand::rng().fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

fn random_hex(size: usize) -> String {
    let mut value = vec![0_u8; size];
    rand::rng().fill_bytes(&mut value);
    hex::encode(value)
}

fn elapsed_at_least(then: OffsetDateTime, now: OffsetDateTime, duration: Duration) -> bool {
    now - then >= time::Duration::try_from(duration).unwrap_or(time::Duration::MAX)
}

fn atomic_write_registry(path: &Path, data: &[u8]) -> io::Result<Option<String>> {
    let directory = path
        .parent()
        .filter(|directory| !directory.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o700).create(directory)?;
    let temporary = directory.join(format!(".clients-{}", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)?;
        match std::fs::File::open(directory).and_then(|directory| directory.sync_all()) {
            Ok(()) => Ok(None),
            Err(error) => Ok(Some(error.to_string())),
        }
    })();
    let _ = std::fs::remove_file(temporary);
    result
}

mod rfc3339 {
    use serde::{Deserialize, Deserializer, Serializer};
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    pub fn serialize<S>(value: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.format(&Rfc3339).map_err(serde::ser::Error::custom)?)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        OffsetDateTime::parse(&value, &Rfc3339).map_err(serde::de::Error::custom)
    }
}

mod optional_rfc3339 {
    use serde::Serializer;
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    pub fn serialize<S>(value: &Option<OffsetDateTime>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) => serializer
                .serialize_some(&value.format(&Rfc3339).map_err(serde::ser::Error::custom)?),
            None => serializer.serialize_none(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::pkcs8::EncodePublicKey;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicBool, Ordering};

    const BOOTSTRAP_TOKEN: &str = "bootstrap-token-0123456789";

    fn test_device(name: &str, at: OffsetDateTime) -> DeviceRecord {
        let key = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let encoded = key
            .public_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        DeviceRecord {
            id: device_auth::device_id_from_encoded(&encoded).unwrap(),
            name: name.into(),
            public_key: URL_SAFE_NO_PAD.encode(encoded),
            first_seen: at,
            last_seen: at,
        }
    }

    fn signed_proof(
        key: &SigningKey,
        name: &str,
        token: &str,
        nonce_byte: u8,
    ) -> device_auth::Proof {
        let public_key = key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        let mut proof = device_auth::Proof {
            device_id: device_auth::device_id_from_encoded(&public_key).unwrap(),
            name: name.into(),
            public_key: URL_SAFE_NO_PAD.encode(public_key),
            timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
            nonce: URL_SAFE_NO_PAD.encode([nonce_byte; 16]),
            signature: String::new(),
        };
        let digest = Sha256::digest(device_auth::signature_payload(
            &proof,
            token,
            "POST",
            "/v1/tunnel",
        ));
        let signature: Signature = key.sign_prehash(&digest).unwrap();
        proof.signature = URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes());
        proof
    }

    async fn cancelled_enrollment_keeps_disk_and_memory_consistent(native: bool) {
        use crate::integration::{NativeAuthenticator, RegistryProxyAuthorizer};
        use crate::ops::abuse::AbuseGuard;
        use crate::ops::metrics::Metrics;
        use crate::proxy::service::Authorizer;
        use crate::transport::session::{AuthenticationRequest, Authenticator, DeviceProof};

        let directory = tempfile::tempdir_in(".").unwrap();
        let path = directory.path().join("clients.json");
        let registry = Arc::new(ClientRegistry::open(&path, BOOTSTRAP_TOKEN).await.unwrap());
        let persistence = registry.inner.persistence.lock().await;
        let sequence = persistence.persisted_sequence;
        let authenticating = if native {
            let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
            let proof = signed_proof(&key, "phone", BOOTSTRAP_TOKEN, 1);
            let authenticator = NativeAuthenticator::new(
                registry.clone(),
                Arc::new(AbuseGuard::default_with_metrics(Arc::new(
                    Metrics::default(),
                ))),
            );
            tokio::spawn(async move {
                let session = authenticator
                    .authenticate(AuthenticationRequest {
                        bearer_token: BOOTSTRAP_TOKEN.into(),
                        proof: DeviceProof {
                            device_id: proof.device_id,
                            name: proof.name,
                            public_key: proof.public_key,
                            timestamp: proof.timestamp,
                            nonce: proof.nonce,
                            signature: proof.signature,
                        },
                        method: http::Method::POST,
                        path: "/v1/tunnel".into(),
                        peer: "127.0.0.1:1234".parse().unwrap(),
                    })
                    .await
                    .unwrap();
                session.cleanup.close();
            })
        } else {
            let authorizer = RegistryProxyAuthorizer::new(registry.clone());
            tokio::spawn(async move {
                let _session = authorizer
                    .authorize(
                        BOOTSTRAP_TOKEN,
                        FORWARD_PROXY_DEVICE_ID,
                        CancellationToken::new(),
                    )
                    .await
                    .unwrap();
            })
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            while registry.inner.state.lock().next_persist_sequence == sequence {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("authentication reached its persistence await");
        authenticating.abort();
        assert!(authenticating.await.unwrap_err().is_cancelled());
        drop(persistence);
        tokio::time::timeout(Duration::from_secs(2), async {
            while registry.inner.persistence.lock().await.persisted_sequence == sequence {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached persistence completed");
        let mutation = registry.inner.mutations.lock().await;
        let disk: RegistryFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(disk.clients[0].devices.len(), 1);
        assert_eq!(registry.inner.state.lock().clients, disk.clients);
        assert_eq!(registry.list()[0].active_sessions, 0);
        drop(mutation);
        registry.close().await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_native_enrollment_is_consistent() {
        cancelled_enrollment_keeps_disk_and_memory_consistent(true).await;
    }

    #[tokio::test]
    async fn cancelled_proxy_enrollment_is_consistent() {
        cancelled_enrollment_keeps_disk_and_memory_consistent(false).await;
    }

    #[tokio::test]
    async fn opens_go_compatible_version_two_registry_and_preserves_field_names() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("clients.json");
        let fixture = r#"{
          "version": 2,
          "clients": [
            {
              "id": "0011223344556677",
              "name": "Engineering",
              "token_hash": "ce366961bbfd002bfc5fe38316af1b933e7bcf2e92c3ef6f3ca0a29779252f20",
              "max_devices": 3,
              "enabled": true,
              "created_at": "2026-09-06T20:21:16.123456789Z",
              "devices": [
                {
                  "id": "forward-proxy",
                  "name": "Forward proxy",
                  "first_seen": "2026-09-06T20:22:00Z",
                  "last_seen": "2026-09-06T20:23:00Z"
                }
              ]
            }
          ]
        }
        "#;
        tokio::fs::write(&path, fixture).await.unwrap();
        let registry = ClientRegistry::open(&path, "").await.unwrap();
        let listed = registry.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].devices[0].id, FORWARD_PROXY_DEVICE_ID);

        let (_, token) = registry.create("Second", 2).await.unwrap();
        assert!(!token.is_empty());
        registry.close().await.unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
        assert_eq!(value["version"], 2);
        assert!(value["clients"][0].get("token_hash").is_some());
        assert!(value["clients"][0].get("max_devices").is_some());
        assert!(value["clients"][0].get("created_at").is_some());
        assert!(value["clients"][0].get("token").is_none());
        assert!(!String::from_utf8_lossy(&tokio::fs::read(&path).await.unwrap()).contains(&token));
    }

    #[tokio::test]
    async fn bootstrap_requires_a_token_and_persists_only_its_sha256_hash() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("nested").join("clients.json");
        assert!(matches!(
            ClientRegistry::open(&path, "").await,
            Err(RegistryError::InvalidInput(_))
        ));
        let registry = ClientRegistry::open(&path, BOOTSTRAP_TOKEN).await.unwrap();
        let bytes = tokio::fs::read(&path).await.unwrap();
        let file: RegistryFile = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(file.version, REGISTRY_VERSION);
        assert_eq!(file.clients.len(), 1);
        assert_eq!(file.clients[0].token_hash, hash_token(BOOTSTRAP_TOKEN));
        assert!(!String::from_utf8_lossy(&bytes).contains(BOOTSTRAP_TOKEN));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        registry.close().await.unwrap();
    }

    #[test]
    fn hash_index_is_constant_time_lookup_and_preserves_first_duplicate() {
        let token = "duplicate-token-0123456789";
        let at = OffsetDateTime::now_utc();
        let mut state = RegistryState {
            clients: (0..10_000)
                .map(|index| ClientRecord {
                    id: format!("{index:016x}"),
                    name: "Benchmark".into(),
                    token_hash: hash_token(&format!("token-{index}-0123456789")),
                    max_devices: 1,
                    enabled: true,
                    created_at: at,
                    devices: Vec::new(),
                })
                .collect(),
            ..RegistryState::default()
        };
        let last_token = "token-9999-0123456789";
        rebuild_token_index(&mut state);
        assert_eq!(
            client_for_token(&state, last_token).unwrap().id,
            "000000000000270f"
        );

        state.clients = vec![
            ClientRecord {
                id: "0011223344556677".into(),
                name: "First".into(),
                token_hash: hash_token(token),
                max_devices: 1,
                enabled: false,
                created_at: at,
                devices: Vec::new(),
            },
            ClientRecord {
                id: "8899aabbccddeeff".into(),
                name: "Second".into(),
                token_hash: hash_token(token),
                max_devices: 1,
                enabled: true,
                created_at: at,
                devices: Vec::new(),
            },
        ];
        rebuild_token_index(&mut state);
        assert!(matches!(
            client_for_token(&state, token),
            Err(RegistryError::Disabled)
        ));
    }

    #[tokio::test]
    async fn persistent_enrollments_count_until_forgotten() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("clients.json");
        let at = OffsetDateTime::now_utc();
        let file = RegistryFile {
            version: REGISTRY_VERSION,
            clients: vec![ClientRecord {
                id: "0011223344556677".into(),
                name: "Test".into(),
                token_hash: hash_token(BOOTSTRAP_TOKEN),
                max_devices: 2,
                enabled: true,
                created_at: at,
                devices: vec![test_device("phone", at), test_device("tablet", at)],
            }],
        };
        tokio::fs::write(&path, serde_json::to_vec(&file).unwrap())
            .await
            .unwrap();
        let registry = ClientRegistry::open(&path, "").await.unwrap();
        assert!(matches!(
            registry.update("0011223344556677", "Test", 1, true).await,
            Err(RegistryError::InvalidInput(_))
        ));
        let forgotten = registry.list()[0].devices[0].id.clone();
        registry
            .forget_device("0011223344556677", &forgotten)
            .await
            .unwrap();
        registry
            .update("0011223344556677", "Renamed", 1, true)
            .await
            .unwrap();
        assert_eq!(registry.list()[0].device_count, 1);
        registry.close().await.unwrap();
    }

    #[tokio::test]
    async fn device_retirement_fences_reenrollment_until_cleanup_finishes() {
        let directory = tempfile::tempdir().unwrap();
        let registry = ClientRegistry::open(directory.path().join("clients.json"), BOOTSTRAP_TOKEN)
            .await
            .unwrap();
        let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let first = signed_proof(&key, "phone", BOOTSTRAP_TOKEN, 1);
        let session = registry
            .authenticate_device_session(BOOTSTRAP_TOKEN, &first, "POST", "/v1/tunnel")
            .await
            .unwrap();
        let account_id = session.identity.account_id.clone();
        let device_id = session.device_id.clone();
        drop(session);

        let retirement = registry
            .retire_device(&account_id, &device_id)
            .await
            .unwrap();
        let replacement = signed_proof(&key, "phone", BOOTSTRAP_TOKEN, 2);
        assert!(matches!(
            registry
                .authenticate_device_session(BOOTSTRAP_TOKEN, &replacement, "POST", "/v1/tunnel")
                .await,
            Err(RegistryError::Draining)
        ));

        drop(retirement);
        registry
            .authenticate_device_session(BOOTSTRAP_TOKEN, &replacement, "POST", "/v1/tunnel")
            .await
            .unwrap();
        registry.close().await.unwrap();
    }

    #[tokio::test]
    async fn device_proofs_enroll_by_key_reject_replay_and_allow_mutable_names() {
        let directory = tempfile::tempdir().unwrap();
        let registry = ClientRegistry::open(directory.path().join("clients.json"), BOOTSTRAP_TOKEN)
            .await
            .unwrap();
        let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let first = signed_proof(&key, "Office-PC", BOOTSTRAP_TOKEN, 1);
        let session = registry
            .authenticate_device_session(BOOTSTRAP_TOKEN, &first, "POST", "/v1/tunnel")
            .await
            .unwrap();
        drop(session);
        assert!(matches!(
            registry
                .authenticate_device_session(BOOTSTRAP_TOKEN, &first, "POST", "/v1/tunnel")
                .await,
            Err(RegistryError::Unauthorized)
        ));

        let renamed = signed_proof(&key, "Renamed-PC", BOOTSTRAP_TOKEN, 2);
        let session = registry
            .authenticate_device_session(BOOTSTRAP_TOKEN, &renamed, "POST", "/v1/tunnel")
            .await
            .unwrap();
        drop(session);
        let client = &registry.list()[0];
        assert_eq!(client.device_count, 1);
        assert_eq!(client.devices[0].name, "Renamed-PC");
        let account_id = client.id.clone();
        registry
            .update(&account_id, "Default client", 1, true)
            .await
            .unwrap();
        let second_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let second = signed_proof(&second_key, "tablet", BOOTSTRAP_TOKEN, 3);
        assert!(matches!(
            registry
                .authenticate_device_session(BOOTSTRAP_TOKEN, &second, "POST", "/v1/tunnel")
                .await,
            Err(RegistryError::DeviceLimit)
        ));
        registry.close().await.unwrap();
    }

    #[tokio::test]
    async fn every_revocation_cancels_and_drains_affected_sessions() {
        for action in ["disable", "delete", "rotate", "forget"] {
            let directory = tempfile::tempdir().unwrap();
            let registry =
                ClientRegistry::open(directory.path().join("clients.json"), BOOTSTRAP_TOKEN)
                    .await
                    .unwrap();
            let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
            let proof = signed_proof(&key, "phone", BOOTSTRAP_TOKEN, 1);
            let session = registry
                .authenticate_device_session(BOOTSTRAP_TOKEN, &proof, "POST", "/v1/tunnel")
                .await
                .unwrap();
            let cancellation = session.cancellation.clone();
            let account_id = session.identity.account_id.clone();
            let device_id = session.device_id.clone();
            let mutation = {
                let registry = registry.clone();
                tokio::spawn(async move {
                    match action {
                        "disable" => registry
                            .update(&account_id, "test", 5, false)
                            .await
                            .map(|_| ()),
                        "delete" => registry.delete(&account_id).await,
                        "rotate" => registry.rotate_token(&account_id).await.map(|_| ()),
                        "forget" => registry.forget_device(&account_id, &device_id).await,
                        _ => unreachable!(),
                    }
                })
            };
            cancellation.cancelled().await;
            assert!(!mutation.is_finished(), "{action} did not wait for drain");
            drop(session);
            mutation.await.unwrap().unwrap();
            registry.close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn failed_durable_mutation_does_not_change_memory_or_cancel_sessions() {
        let directory = tempfile::tempdir().unwrap();
        let registry_directory = directory.path().join("registry");
        let path = registry_directory.join("clients.json");
        let registry = ClientRegistry::open(&path, BOOTSTRAP_TOKEN).await.unwrap();
        let session = registry
            .authenticate_proxy_session(BOOTSTRAP_TOKEN)
            .await
            .unwrap();
        let cancellation = session.cancellation.clone();
        let account_id = session.identity.account_id.clone();

        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&registry_directory).unwrap();
        std::fs::write(&registry_directory, b"not a directory").unwrap();
        assert!(registry
            .update(&account_id, "Changed", 5, false)
            .await
            .is_err());
        assert!(!cancellation.is_cancelled());
        assert_eq!(
            registry.authenticate_portal(BOOTSTRAP_TOKEN).unwrap().name,
            "Default client"
        );
        drop(session);
        registry.close().await.unwrap();
    }

    #[test]
    fn replay_windows_are_bounded_expiring_and_scoped_per_device() {
        let now = OffsetDateTime::now_utc();
        let key = DeviceKey::new("account", "device");
        let other = DeviceKey::new("other", "device");
        let mut state = RegistryState::default();
        let expiry = now + time::Duration::minutes(1);
        state.nonces.insert(
            key.clone(),
            NonceWindow {
                values: (0..MAX_DEVICE_NONCES)
                    .map(|index| (format!("nonce-{index}"), expiry))
                    .collect(),
                next_expiry: Some(expiry),
            },
        );
        state.nonces.insert(
            other.clone(),
            NonceWindow {
                values: HashMap::from([("expired".into(), now - time::Duration::SECOND)]),
                next_expiry: Some(now - time::Duration::SECOND),
            },
        );
        assert!(nonce_seen(&mut state, &key, "fresh", now, now));
        assert_eq!(state.nonces[&other].values.len(), 1);

        state.nonces.insert(
            key.clone(),
            NonceWindow {
                values: HashMap::from([("expired".into(), now - time::Duration::SECOND)]),
                next_expiry: Some(now - time::Duration::SECOND),
            },
        );
        assert!(!nonce_seen(&mut state, &key, "fresh", now, now));
        assert!(!state.nonces.contains_key(&key));
    }

    #[tokio::test]
    async fn disconnect_epoch_fences_attempts_started_before_drain_completion() {
        let directory = tempfile::tempdir().unwrap();
        let registry = ClientRegistry::open(directory.path().join("clients.json"), BOOTSTRAP_TOKEN)
            .await
            .unwrap();
        let account_id = registry.list()[0].id.clone();
        let registration = registry.inner.sessions.register(&account_id, "device");
        let cancellation = registration.cancellation.clone();
        let (_, guard) = registration.into_parts();
        let attempt = registry.begin_authentication();
        let attempt_epoch = attempt.epoch;
        let disconnecting = {
            let registry = registry.clone();
            let account_id = account_id.clone();
            tokio::spawn(async move { registry.disconnect(&account_id, None).await })
        };
        cancellation.cancelled().await;
        assert!(!disconnecting.is_finished());
        drop(guard);
        assert_eq!(disconnecting.await.unwrap().unwrap(), 1);

        {
            let state = registry.inner.state.lock();
            let key = DeviceKey::new(&account_id, "device");
            assert!(authentication_blocked(
                &state,
                &account_id,
                &key,
                attempt_epoch
            ));
            let post_completion = registry.inner.disconnect_epoch.load(Ordering::Acquire);
            assert!(!authentication_blocked(
                &state,
                &account_id,
                &key,
                post_completion
            ));
        }

        drop(attempt);
        registry.close().await.unwrap();
    }

    #[tokio::test]
    async fn cancelling_disconnect_clears_the_retiring_account() {
        let directory = tempfile::tempdir().unwrap();
        let registry = ClientRegistry::open(directory.path().join("clients.json"), BOOTSTRAP_TOKEN)
            .await
            .unwrap();
        let client = registry.list().remove(0);
        let registration = registry.inner.sessions.register(&client.id, "device");
        let cancellation = registration.cancellation.clone();
        let disconnect = tokio::spawn({
            let registry = registry.clone();
            let client_id = client.id.clone();
            async move { registry.disconnect(&client_id, None).await }
        });
        tokio::time::timeout(Duration::from_secs(1), cancellation.cancelled())
            .await
            .unwrap();
        assert_eq!(
            registry
                .inner
                .state
                .lock()
                .retiring_accounts
                .get(&client.id),
            Some(&1)
        );
        disconnect.abort();
        let _ = disconnect.await;
        assert!(!registry
            .inner
            .state
            .lock()
            .retiring_accounts
            .contains_key(&client.id));
        drop(registration);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rotation_keeps_hash_index_consistent_during_concurrent_authentication() {
        let directory = tempfile::tempdir().unwrap();
        let registry = ClientRegistry::open(directory.path().join("clients.json"), BOOTSTRAP_TOKEN)
            .await
            .unwrap();
        let account_id = registry.list()[0].id.clone();
        let running = Arc::new(AtomicBool::new(true));
        let current = Arc::new(Mutex::new(BOOTSTRAP_TOKEN.to_owned()));
        let mut workers = Vec::new();
        for _ in 0..16 {
            let registry = registry.clone();
            let running = running.clone();
            let current = current.clone();
            workers.push(tokio::spawn(async move {
                while running.load(Ordering::Relaxed) {
                    let token = current.lock().clone();
                    match registry.authenticate_portal(&token) {
                        Ok(_) | Err(RegistryError::Unauthorized) => {}
                        Err(error) => panic!("unexpected authentication error: {error}"),
                    }
                    tokio::task::yield_now().await;
                }
            }));
        }
        for _ in 0..20 {
            let token = registry.rotate_token(&account_id).await.unwrap();
            *current.lock() = token;
        }
        running.store(false, Ordering::Relaxed);
        for worker in workers {
            worker.await.unwrap();
        }
        let token = current.lock().clone();
        assert_eq!(registry.authenticate_portal(&token).unwrap().id, account_id);
        {
            let state = registry.inner.state.lock();
            assert_eq!(state.token_index.len(), 1);
        }
        registry.close().await.unwrap();
    }

    #[tokio::test]
    async fn proxy_metadata_writes_coalesce_and_close_flushes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("clients.json");
        let registry = ClientRegistry::open(&path, BOOTSTRAP_TOKEN).await.unwrap();
        let session = registry
            .authenticate_proxy_session(BOOTSTRAP_TOKEN)
            .await
            .unwrap();
        assert_eq!(session.device_id, FORWARD_PROXY_DEVICE_ID);
        assert!(session.identity.lease_id.starts_with("device-"));
        drop(session);
        {
            let mut state = registry.inner.state.lock();
            let device = &mut state.clients[0].devices[0];
            device.last_seen = OffsetDateTime::now_utc() - time::Duration::minutes(2);
        }
        registry.set_metadata_debounce(Duration::from_secs(3600));
        for _ in 0..8 {
            let session = registry
                .authenticate_proxy_session(BOOTSTRAP_TOKEN)
                .await
                .unwrap();
            drop(session);
        }
        let expected = registry.list()[0].devices[0].last_seen;
        registry.close().await.unwrap();
        let reopened = ClientRegistry::open(&path, "").await.unwrap();
        assert_eq!(reopened.list()[0].devices[0].last_seen, expected);
        reopened.close().await.unwrap();
    }
}
