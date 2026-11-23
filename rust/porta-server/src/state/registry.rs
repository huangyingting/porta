use crate::state::sessions::{LiveSessions, SessionGuard};
use crate::state::usage;
use crate::wire::device_auth;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ipnet::{IpNet, Ipv4Net};
use parking_lot::Mutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
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
/// The logical device of an account's standard CONNECT-IP clients.
pub const STANDARD_DEVICE_ID: &str = "standard-masque";
const STANDARD_DEVICE_NAME: &str = "Standard MASQUE clients";
const LAST_SEEN_INTERVAL: Duration = Duration::from_secs(60);
const DEFAULT_METADATA_DEBOUNCE: Duration = Duration::from_secs(1);

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("client token is invalid")]
    Unauthorized,
    #[error("standard CONNECT-IP clients are not allowed for this account")]
    StandardClientsDisabled,
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
    #[error("client account has expired")]
    Expired,
    #[error("client account has used its monthly data quota")]
    QuotaExceeded,
    #[error("device is waiting for administrator approval")]
    DevicePending,
    #[error("device enrollment is closed for this account")]
    EnrollmentClosed,
    #[error("device enrollment was denied")]
    DeviceDenied,
    #[error("this gateway mirrors its accounts from a primary gateway; change them there")]
    ReadOnly,
    #[error("new devices enroll on the primary gateway first")]
    EnrollOnPrimary,
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
    #[serde(default, flatten)]
    pub limits: AccountLimits,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage_period: Option<UsagePeriod>,
    #[serde(default, skip_serializing_if = "EnrollmentPolicy::is_open")]
    pub enrollment: EnrollmentPolicy,
    /// New devices enroll directly until this instant, whatever the policy.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_rfc3339"
    )]
    pub enrollment_open_until: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "AccessPolicy::is_default")]
    pub access: AccessPolicy,
    /// Standard CONNECT-IP clients may connect with the token alone, without
    /// a Porta device key.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub standard_clients: bool,
}

/// Network access rules for an account's tunnels. The default reaches every
/// destination and belongs to no client-to-client group.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccessPolicy {
    /// Destinations the account may reach; empty allows every destination.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<IpNet>,
    /// Destinations the account may never reach; takes precedence over `allow`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<IpNet>,
    /// Accounts in the same group reach each other's devices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Named exit for the account's traffic; unset uses the gateway default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<String>,
}

impl AccessPolicy {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// Prefixes per allow or deny list.
pub const MAX_ACCESS_PREFIXES: usize = 64;
/// Subnets one device may route for other clients.
pub const MAX_DEVICE_SUBNETS: usize = 16;

/// How an account accepts device keys it has not seen before.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EnrollmentPolicy {
    /// New devices enroll on first connection, up to the device limit.
    #[default]
    Open,
    /// New devices wait for an administrator to approve them.
    Approval,
    /// New devices are refused.
    Closed,
}

impl EnrollmentPolicy {
    fn is_open(&self) -> bool {
        *self == Self::Open
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Approval => "approval",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceStatus {
    #[default]
    Approved,
    Pending,
    Denied,
}

impl DeviceStatus {
    fn is_approved(&self) -> bool {
        *self == Self::Approved
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Pending => "pending",
            Self::Denied => "denied",
        }
    }
}

/// Pending and denied devices kept per account; further unknown devices are
/// refused so that a leaked token cannot flood the registry.
pub const MAX_UNAPPROVED_DEVICES: usize = 16;
/// Longest temporary enrollment window an administrator can open.
pub const MAX_ENROLLMENT_WINDOW: Duration = Duration::from_secs(7 * 24 * 60 * 60);

fn approved_devices(client: &ClientRecord) -> usize {
    client
        .devices
        .iter()
        .filter(|device| device.status.is_approved())
        .count()
}

fn unapproved_devices(client: &ClientRecord) -> usize {
    client.devices.len() - approved_devices(client)
}

/// Whether a new device enrolls directly, waits for approval, or is refused.
fn enrollment_decision(
    client: &ClientRecord,
    now: OffsetDateTime,
) -> Result<DeviceStatus, RegistryError> {
    let window_open = client
        .enrollment_open_until
        .is_some_and(|until| until > now);
    match client.enrollment {
        _ if window_open => Ok(DeviceStatus::Approved),
        EnrollmentPolicy::Open => Ok(DeviceStatus::Approved),
        EnrollmentPolicy::Approval if unapproved_devices(client) < MAX_UNAPPROVED_DEVICES => {
            Ok(DeviceStatus::Pending)
        }
        EnrollmentPolicy::Approval | EnrollmentPolicy::Closed => {
            Err(RegistryError::EnrollmentClosed)
        }
    }
}

fn device_access(status: DeviceStatus) -> Result<(), RegistryError> {
    match status {
        DeviceStatus::Approved => Ok(()),
        DeviceStatus::Pending => Err(RegistryError::DevicePending),
        DeviceStatus::Denied => Err(RegistryError::DeviceDenied),
    }
}

/// Optional account restrictions; absent values mean unrestricted.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccountLimits {
    /// Access ends at this instant, including active sessions.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_rfc3339"
    )]
    pub expires_at: Option<OffsetDateTime>,
    /// Uploaded plus downloaded IP bytes allowed per UTC calendar month.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monthly_quota_bytes: Option<u64>,
    /// Per-direction throughput shared by all of the account's sessions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_kbps: Option<u32>,
}

impl AccountLimits {
    pub fn expired_at(&self, now: OffsetDateTime) -> bool {
        self.expires_at.is_some_and(|expires_at| expires_at <= now)
    }
}

/// Quota accounting period: monthly usage is the account's lifetime traffic
/// minus `baseline_bytes`, its lifetime traffic when the period began.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UsagePeriod {
    pub month: String,
    pub baseline_bytes: u64,
}

/// Limits and accounting state the policy enforcer evaluates per account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountPolicy {
    pub id: String,
    pub limits: AccountLimits,
    pub usage_period: Option<UsagePeriod>,
    pub active_sessions: usize,
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
    #[serde(default, skip_serializing_if = "DeviceStatus::is_approved")]
    pub status: DeviceStatus,
    /// Networks behind this device that the gateway routes to it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subnets: Vec<Ipv4Net>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutedSubnet {
    pub account_id: String,
    pub device_id: String,
    pub subnet: Ipv4Net,
}

/// The network rules that apply to one device's tunnel.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeviceNetwork {
    pub access: AccessPolicy,
    pub subnets: Vec<Ipv4Net>,
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
    #[serde(flatten)]
    pub limits: AccountLimits,
    pub enrollment: &'static str,
    #[serde(skip_serializing_if = "Option::is_none", with = "optional_rfc3339")]
    pub enrollment_open_until: Option<OffsetDateTime>,
    /// Devices waiting for approval.
    pub pending_devices: usize,
    /// Traffic counted against the monthly quota in the current period.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_used_bytes: Option<u64>,
    /// `active`, `disabled`, `expired`, or `quota_exceeded`.
    pub status: &'static str,
    pub access: AccessPolicy,
    /// Standard CONNECT-IP clients may connect with the token alone.
    pub standard_clients: bool,
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
    /// `approved`, `pending`, or `denied`.
    pub status: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub transport: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub assigned_address: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub target: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subnets: Vec<Ipv4Net>,
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
    quota_blocked: HashSet<String>,
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
    /// Accounts are mirrored from a primary gateway and read-only here.
    replica: AtomicBool,
}

/// Sessions a replica sync ended because their access was revoked.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReplicaSync {
    pub clients: usize,
    pub ended_accounts: usize,
    pub ended_devices: usize,
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
                    limits: AccountLimits::default(),
                    usage_period: None,
                    enrollment: EnrollmentPolicy::Open,
                    enrollment_open_until: None,
                    access: AccessPolicy::default(),
                    standard_clients: false,
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
                replica: AtomicBool::new(false),
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

    /// Opens a registry that mirrors a primary gateway's accounts. Until the
    /// first sync it serves the last mirrored copy, or no accounts.
    pub async fn open_replica(path: impl Into<PathBuf>) -> Result<Self, RegistryError> {
        let path = path.into();
        if !tokio::fs::try_exists(&path).await? {
            let mut data = serde_json::to_vec_pretty(&RegistryFile {
                version: REGISTRY_VERSION,
                clients: Vec::new(),
            })?;
            data.push(b'\n');
            if let Some(parent) = path.parent() {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)?;
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            file.write_all(&data)?;
            file.sync_all()?;
        }
        let registry = Self::open(path, "").await?;
        registry.inner.replica.store(true, Ordering::Release);
        Ok(registry)
    }

    pub fn is_replica(&self) -> bool {
        self.inner.replica.load(Ordering::Acquire)
    }

    fn ensure_writable(&self) -> Result<(), RegistryError> {
        if self.is_replica() {
            Err(RegistryError::ReadOnly)
        } else {
            Ok(())
        }
    }

    /// Every account, as the primary serves it to replicas.
    pub fn export(&self) -> RegistryFile {
        RegistryFile {
            version: REGISTRY_VERSION,
            clients: self.inner.state.lock().clients.clone(),
        }
    }

    /// Replaces a replica's accounts with the primary's. Each gateway keeps
    /// its own quota period, and sessions whose account, token or device was
    /// revoked end.
    pub async fn replace_from_primary(
        &self,
        file: RegistryFile,
    ) -> Result<ReplicaSync, RegistryError> {
        if file.version != REGISTRY_VERSION {
            return Err(RegistryError::UnsupportedVersion(file.version));
        }
        for (index, client) in file.clients.iter().enumerate() {
            validate_stored_client(client).map_err(|error| {
                RegistryError::InvalidInput(format!(
                    "primary registry entry {}: {error}",
                    index + 1
                ))
            })?;
        }
        self.ensure_open()?;
        let _mutation = self.inner.mutations.lock().await;
        self.ensure_open()?;
        let (candidate, previous) = {
            let state = self.inner.state.lock();
            let previous = state.clients.clone();
            let mut candidate = file.clients;
            for client in &mut candidate {
                client.usage_period = previous
                    .iter()
                    .find(|local| local.id == client.id)
                    .and_then(|local| local.usage_period.clone());
            }
            (candidate, previous)
        };
        if candidate == previous {
            return Ok(ReplicaSync {
                clients: candidate.len(),
                ..ReplicaSync::default()
            });
        }
        self.persist_clients(&candidate).await?;
        {
            let mut state = self.inner.state.lock();
            state.clients.clone_from(&candidate);
            rebuild_token_index(&mut state);
        }
        let mut sync = ReplicaSync {
            clients: candidate.len(),
            ..ReplicaSync::default()
        };
        for old in &previous {
            let current = candidate.iter().find(|client| client.id == old.id);
            let account_revoked =
                current.is_none_or(|client| !client.enabled || client.token_hash != old.token_hash);
            if account_revoked {
                let _drain = self.begin_account_drain(&old.id);
                if self.inner.sessions.cancel_account(&old.id).await > 0 {
                    sync.ended_accounts += 1;
                }
                continue;
            }
            let current = current.expect("account is present");
            for device in &old.devices {
                let still_approved = current.devices.iter().any(|candidate| {
                    candidate.id == device.id && candidate.status == DeviceStatus::Approved
                });
                if !still_approved {
                    let key = DeviceKey::new(&old.id, &device.id);
                    let _drain = self.begin_device_drain(&key);
                    if self.inner.sessions.cancel_device(&old.id, &device.id).await > 0 {
                        sync.ended_devices += 1;
                    }
                }
            }
        }
        Ok(sync)
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
            .map(|client| {
                summarize_client(
                    client,
                    &self.inner.sessions,
                    snapshot,
                    state.quota_blocked.contains(&client.id),
                )
            })
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
        let now = OffsetDateTime::now_utc();
        let state = self.inner.state.lock();
        state
            .clients
            .iter()
            .find(|client| client.id == client_id)
            .is_some_and(|client| {
                client.enabled
                    && !client.limits.expired_at(now)
                    && !state.quota_blocked.contains(&client.id)
                    && client.token_hash.len() == token_hash.len()
                    && bool::from(client.token_hash.as_bytes().ct_eq(token_hash.as_bytes()))
            })
    }

    pub async fn create(
        &self,
        name: impl AsRef<str>,
        max_devices: usize,
    ) -> Result<(ClientSummary, String), RegistryError> {
        self.ensure_writable()?;
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
            limits: AccountLimits::default(),
            usage_period: None,
            enrollment: EnrollmentPolicy::Open,
            enrollment_open_until: None,
            access: AccessPolicy::default(),
            standard_clients: false,
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
        Ok((
            summarize_client(&client, &self.inner.sessions, None, false),
            token,
        ))
    }

    pub async fn update(
        &self,
        id: &str,
        name: impl AsRef<str>,
        max_devices: usize,
        enabled: bool,
    ) -> Result<ClientSummary, RegistryError> {
        self.ensure_writable()?;
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
            if max_devices < approved_devices(client) {
                return Err(RegistryError::InvalidInput(format!(
                    "device limit cannot be below the {} enrolled devices",
                    approved_devices(client)
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
        Ok(summarize_client(
            client,
            &self.inner.sessions,
            None,
            state.quota_blocked.contains(id),
        ))
    }

    /// Replaces an account's limits. Expiry takes effect immediately; quota
    /// and throughput limits are applied by the account policy enforcer.
    pub async fn set_limits(
        &self,
        id: &str,
        limits: AccountLimits,
    ) -> Result<ClientSummary, RegistryError> {
        self.ensure_writable()?;
        self.ensure_open()?;
        validate_limits(&limits)?;
        let _mutation = self.inner.mutations.lock().await;
        self.ensure_open()?;
        let candidate = {
            let state = self.inner.state.lock();
            let mut clients = state.clients.clone();
            let client = clients
                .iter_mut()
                .find(|client| client.id == id)
                .ok_or(RegistryError::NotFound)?;
            if limits.monthly_quota_bytes.is_none() {
                client.usage_period = None;
            }
            client.limits = limits;
            clients
        };
        self.persist_clients(&candidate).await?;
        let expired = {
            let mut state = self.inner.state.lock();
            let persisted = candidate
                .iter()
                .find(|client| client.id == id)
                .expect("candidate contains the selected client")
                .clone();
            if persisted.limits.monthly_quota_bytes.is_none() {
                state.quota_blocked.remove(id);
            }
            let client = find_client_mut(&mut state, id)?;
            client.limits = persisted.limits;
            client.usage_period = persisted.usage_period;
            client.limits.expired_at(OffsetDateTime::now_utc())
        };
        if expired {
            self.end_sessions(id).await;
        }
        let state = self.inner.state.lock();
        let client = state
            .clients
            .iter()
            .find(|client| client.id == id)
            .ok_or(RegistryError::NotFound)?;
        Ok(summarize_client(
            client,
            &self.inner.sessions,
            None,
            state.quota_blocked.contains(id),
        ))
    }

    /// Sets how the account accepts new devices. `window` additionally lets
    /// new devices enroll directly until it elapses.
    pub async fn set_enrollment(
        &self,
        id: &str,
        policy: EnrollmentPolicy,
        window: Option<Duration>,
    ) -> Result<ClientSummary, RegistryError> {
        if window.is_some_and(|window| window.is_zero() || window > MAX_ENROLLMENT_WINDOW) {
            return Err(RegistryError::InvalidInput(
                "enrollment window must be between one minute and seven days".into(),
            ));
        }
        let until = window.map(|window| OffsetDateTime::now_utc() + window);
        self.mutate_client(id, |client| {
            client.enrollment = policy;
            client.enrollment_open_until = until;
            Ok(())
        })
        .await
    }

    /// Lets standard CONNECT-IP clients connect with the account's token
    /// alone, or stops them and ends their sessions.
    pub async fn set_standard_clients(
        &self,
        id: &str,
        allowed: bool,
    ) -> Result<ClientSummary, RegistryError> {
        let summary = self
            .mutate_client(id, |client| {
                client.standard_clients = allowed;
                Ok(())
            })
            .await?;
        if !allowed {
            self.inner
                .sessions
                .cancel_device(id, STANDARD_DEVICE_ID)
                .await;
        }
        Ok(summary)
    }

    /// Lets a pending or denied device connect, within the device limit.
    pub async fn approve_device(
        &self,
        id: &str,
        device_id: &str,
    ) -> Result<ClientSummary, RegistryError> {
        self.mutate_client(id, |client| {
            if approved_devices(client) >= client.max_devices {
                return Err(RegistryError::InvalidInput(
                    "the device limit is reached; raise it or forget a device first".into(),
                ));
            }
            let device = client
                .devices
                .iter_mut()
                .find(|device| device.id == device_id)
                .ok_or(RegistryError::NotFound)?;
            device.status = DeviceStatus::Approved;
            Ok(())
        })
        .await
    }

    /// Refuses a device until an administrator approves or forgets it, and
    /// ends any of its sessions.
    pub async fn deny_device(
        &self,
        id: &str,
        device_id: &str,
    ) -> Result<ClientSummary, RegistryError> {
        let summary = self
            .mutate_client(id, |client| {
                let device = client
                    .devices
                    .iter_mut()
                    .find(|device| device.id == device_id && !is_logical_device(&device.id))
                    .ok_or(RegistryError::NotFound)?;
                device.status = DeviceStatus::Denied;
                Ok(())
            })
            .await?;
        let key = DeviceKey::new(id, device_id);
        let _drain = self.begin_device_drain(&key);
        self.inner.sessions.cancel_device(id, device_id).await;
        Ok(summary)
    }

    /// Persists a change to one client record, then applies the same
    /// idempotent change to the live record so that concurrent in-memory
    /// metadata updates are kept.
    async fn mutate_client(
        &self,
        id: &str,
        change: impl Fn(&mut ClientRecord) -> Result<(), RegistryError>,
    ) -> Result<ClientSummary, RegistryError> {
        self.mutate_clients(id, |clients| {
            let client = clients
                .iter_mut()
                .find(|client| client.id == id)
                .ok_or(RegistryError::NotFound)?;
            change(client)
        })
        .await
    }

    /// Like `mutate_client`, for changes to `id` that are validated against
    /// every client record.
    async fn mutate_clients(
        &self,
        id: &str,
        change: impl Fn(&mut [ClientRecord]) -> Result<(), RegistryError>,
    ) -> Result<ClientSummary, RegistryError> {
        self.ensure_writable()?;
        self.ensure_open()?;
        let _mutation = self.inner.mutations.lock().await;
        self.ensure_open()?;
        let candidate = {
            let state = self.inner.state.lock();
            let mut clients = state.clients.clone();
            change(&mut clients)?;
            clients
        };
        self.persist_clients(&candidate).await?;
        let mut state = self.inner.state.lock();
        let blocked = state.quota_blocked.contains(id);
        if change(&mut state.clients).is_err() {
            // Memory changed since the snapshot; keep it consistent with disk.
            if let Some(persisted) = candidate.into_iter().find(|client| client.id == id) {
                *find_client_mut(&mut state, id)? = persisted;
            }
        }
        let client = find_client_mut(&mut state, id)?;
        let summary = summarize_client(client, &self.inner.sessions, None, blocked);
        drop(state);
        Ok(summary)
    }

    /// Replaces an account's network access policy and reconnects its
    /// sessions so that the new rules apply. `exits` lists the exit names the
    /// gateway offers.
    pub async fn set_access(
        &self,
        id: &str,
        access: AccessPolicy,
        exits: &[String],
    ) -> Result<ClientSummary, RegistryError> {
        let access = validate_access(access, exits)?;
        let summary = self
            .mutate_client(id, |client| {
                client.access = access.clone();
                Ok(())
            })
            .await?;
        self.end_sessions(id).await;
        Ok(summary)
    }

    /// Assigns the networks behind a device ("subnet router") and reconnects
    /// it. Subnets may not overlap another device's subnets or `reserved`,
    /// such as the client pool.
    pub async fn set_device_subnets(
        &self,
        id: &str,
        device_id: &str,
        subnets: Vec<Ipv4Net>,
        reserved: &[Ipv4Net],
    ) -> Result<ClientSummary, RegistryError> {
        let subnets = validate_subnets(subnets, reserved)?;
        let summary = self
            .mutate_clients(id, |clients| {
                for client in clients.iter() {
                    for device in &client.devices {
                        if client.id == id && device.id == device_id {
                            continue;
                        }
                        if let Some(conflict) = device.subnets.iter().find(|existing| {
                            subnets
                                .iter()
                                .any(|subnet| prefixes_overlap(subnet, existing))
                        }) {
                            return Err(RegistryError::InvalidInput(format!(
                                "{conflict} is already routed to device {} of {}",
                                device.name, client.name
                            )));
                        }
                    }
                }
                let device = clients
                    .iter_mut()
                    .find(|client| client.id == id)
                    .ok_or(RegistryError::NotFound)?
                    .devices
                    .iter_mut()
                    .find(|device| device.id == device_id && !is_logical_device(&device.id))
                    .ok_or(RegistryError::NotFound)?;
                device.subnets.clone_from(&subnets);
                Ok(())
            })
            .await?;
        let key = DeviceKey::new(id, device_id);
        let _drain = self.begin_device_drain(&key);
        self.inner.sessions.cancel_device(id, device_id).await;
        Ok(summary)
    }

    /// DNS names of every device relative to the resolver zone,
    /// `device.account`, by account and device ID.
    pub fn dns_names(&self) -> HashMap<(String, String), String> {
        dns_labels(&self.inner.state.lock().clients)
    }

    /// Every subnet routed to a device, with its owner.
    pub fn routed_subnets(&self) -> Vec<RoutedSubnet> {
        let state = self.inner.state.lock();
        state
            .clients
            .iter()
            .flat_map(|client| {
                client.devices.iter().flat_map(move |device| {
                    device.subnets.iter().map(move |subnet| RoutedSubnet {
                        account_id: client.id.clone(),
                        device_id: device.id.clone(),
                        subnet: *subnet,
                    })
                })
            })
            .collect()
    }

    /// The access policy and routed subnets of one device's tunnel.
    pub fn device_network(&self, id: &str, device_id: &str) -> DeviceNetwork {
        let state = self.inner.state.lock();
        let Some(client) = state.clients.iter().find(|client| client.id == id) else {
            return DeviceNetwork::default();
        };
        DeviceNetwork {
            access: client.access.clone(),
            subnets: client
                .devices
                .iter()
                .find(|device| device.id == device_id)
                .map(|device| device.subnets.clone())
                .unwrap_or_default(),
        }
    }

    /// Starts a new quota period whose usage is measured from `baseline_bytes`.
    pub async fn set_usage_period(
        &self,
        id: &str,
        period: UsagePeriod,
    ) -> Result<(), RegistryError> {
        self.ensure_open()?;
        let _mutation = self.inner.mutations.lock().await;
        self.ensure_open()?;
        let candidate = {
            let state = self.inner.state.lock();
            let mut clients = state.clients.clone();
            clients
                .iter_mut()
                .find(|client| client.id == id)
                .ok_or(RegistryError::NotFound)?
                .usage_period = Some(period.clone());
            clients
        };
        self.persist_clients(&candidate).await?;
        let mut state = self.inner.state.lock();
        find_client_mut(&mut state, id)?.usage_period = Some(period);
        Ok(())
    }

    pub fn account_policy(&self, id: &str) -> Option<AccountPolicy> {
        let state = self.inner.state.lock();
        state
            .clients
            .iter()
            .find(|client| client.id == id)
            .map(|client| AccountPolicy {
                id: client.id.clone(),
                limits: client.limits.clone(),
                usage_period: client.usage_period.clone(),
                active_sessions: self.inner.sessions.active_count(&client.id, None),
            })
    }

    pub fn account_policies(&self) -> Vec<AccountPolicy> {
        let state = self.inner.state.lock();
        state
            .clients
            .iter()
            .map(|client| AccountPolicy {
                id: client.id.clone(),
                limits: client.limits.clone(),
                usage_period: client.usage_period.clone(),
                active_sessions: self.inner.sessions.active_count(&client.id, None),
            })
            .collect()
    }

    /// Marks an account as over (or back under) its quota. Newly blocked
    /// accounts lose their active sessions. Returns whether the state changed.
    pub async fn set_quota_blocked(&self, id: &str, blocked: bool) -> bool {
        let changed = {
            let mut state = self.inner.state.lock();
            if blocked {
                state.quota_blocked.insert(id.to_owned())
            } else {
                state.quota_blocked.remove(id)
            }
        };
        if changed && blocked {
            self.end_sessions(id).await;
        }
        changed
    }

    /// Ends every VPN and proxy session of an account that must stop now.
    pub async fn end_sessions(&self, id: &str) -> usize {
        let _drain = self.begin_account_drain(id);
        self.inner.sessions.cancel_account(id).await
    }

    pub async fn rotate_token(&self, id: &str) -> Result<String, RegistryError> {
        self.ensure_writable()?;
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
        self.ensure_writable()?;
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
        self.ensure_writable()?;
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
                device_access(device.status)?;
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
                device_access(device.status)?;
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
                if self.is_replica() {
                    return Err(RegistryError::EnrollOnPrimary);
                }
                let client = &state.clients[client_index];
                let status = enrollment_decision(client, now)?;
                if status.is_approved() && approved_devices(client) >= client.max_devices {
                    return Err(RegistryError::DeviceLimit);
                }
                let mut clients = state.clients.clone();
                clients[client_index].devices.push(DeviceRecord {
                    id: proof.device_id.clone(),
                    name: proof.name.clone(),
                    public_key: canonical_key.clone(),
                    first_seen: now,
                    last_seen: now,
                    status,
                    subnets: Vec::new(),
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
                let enrolled = candidate
                    .iter()
                    .find(|client| client.id == account_id)
                    .and_then(|client| client.devices.last())
                    .cloned()
                    .ok_or(RegistryError::InvalidDeviceProof)?;
                if enrolled.status.is_approved() && approved_devices(client) >= client.max_devices {
                    return Err(RegistryError::DeviceLimit);
                }
                let status = enrolled.status;
                client.devices.push(enrolled);
                if !status.is_approved() {
                    // The pending enrollment is recorded; the device can
                    // connect once an administrator approves it.
                    let key = DeviceKey::new(&account_id, &proof.device_id);
                    remember_nonce(&mut state, key, proof.nonce.clone(), verified.signed_at);
                    return Err(RegistryError::DevicePending);
                }
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
        self.authenticate_logical_device(
            token,
            FORWARD_PROXY_DEVICE_ID,
            FORWARD_PROXY_DEVICE_NAME,
            |_| Ok(()),
        )
        .await
    }

    /// Authenticates a standard CONNECT-IP client by its token alone, for
    /// accounts that allow it. Such clients have no device key, so all of an
    /// account's standard clients share one logical device and its lease.
    pub async fn authenticate_standard_session(
        &self,
        token: &str,
    ) -> Result<AuthenticatedSession, RegistryError> {
        self.authenticate_logical_device(
            token,
            STANDARD_DEVICE_ID,
            STANDARD_DEVICE_NAME,
            |client| {
                if client.standard_clients {
                    Ok(())
                } else {
                    Err(RegistryError::StandardClientsDisabled)
                }
            },
        )
        .await
    }

    /// A session for a device the gateway records on the account's behalf,
    /// created on first use within the device limit.
    async fn authenticate_logical_device(
        &self,
        token: &str,
        device_id: &str,
        device_name: &str,
        permitted: impl Fn(&ClientRecord) -> Result<(), RegistryError>,
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
            permitted(&state.clients[client_index])?;
            let account_id = state.clients[client_index].id.clone();
            let key = DeviceKey::new(&account_id, device_id);
            if authentication_blocked(&state, &account_id, &key, attempt_epoch) {
                return Err(RegistryError::Draining);
            }
            if let Some(device) = state.clients[client_index]
                .devices
                .iter_mut()
                .find(|device| device.id == device_id)
            {
                if elapsed_at_least(device.last_seen, now, LAST_SEEN_INTERVAL) {
                    device.last_seen = now;
                    state.metadata_dirty = true;
                    state.metadata_version = state.metadata_version.wrapping_add(1);
                    start_metadata_worker = true;
                }
                let identity = registry_identity(&account_id, device_id);
                let registration = self.inner.sessions.register(&account_id, device_id);
                let (cancellation, guard) = registration.into_parts();
                drop(state);
                if start_metadata_worker {
                    self.start_metadata_worker();
                }
                return Ok(AuthenticatedSession {
                    identity,
                    device_id: device_id.into(),
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
            permitted(&state.clients[client_index])?;
            let account_id = state.clients[client_index].id.clone();
            let key = DeviceKey::new(&account_id, device_id);
            if authentication_blocked(&state, &account_id, &key, attempt_epoch) {
                return Err(RegistryError::Draining);
            }
            if let Some(device) = state.clients[client_index]
                .devices
                .iter()
                .find(|device| device.id == device_id)
            {
                let identity = registry_identity(&account_id, device_id);
                let registration = self.inner.sessions.register(&account_id, device_id);
                let (cancellation, guard) = registration.into_parts();
                let _ = device;
                return Ok(AuthenticatedSession {
                    identity,
                    device_id: device_id.into(),
                    cancellation,
                    guard,
                });
            }
            if approved_devices(&state.clients[client_index])
                >= state.clients[client_index].max_devices
            {
                return Err(RegistryError::DeviceLimit);
            }
            let mut clients = state.clients.clone();
            clients[client_index].devices.push(DeviceRecord {
                id: device_id.into(),
                name: device_name.into(),
                public_key: String::new(),
                first_seen: now,
                last_seen: now,
                status: DeviceStatus::Approved,
                subnets: Vec::new(),
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
            if !client.devices.iter().any(|device| device.id == device_id) {
                client.devices.push(
                    candidate
                        .iter()
                        .find(|client| client.id == account_id)
                        .and_then(|client| client.devices.last())
                        .cloned()
                        .ok_or(RegistryError::Unauthorized)?,
                );
            }
            let identity = registry_identity(&account_id, device_id);
            let registration = self.inner.sessions.register(&account_id, device_id);
            let (cancellation, guard) = registration.into_parts();
            Ok(AuthenticatedSession {
                identity,
                device_id: device_id.into(),
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
                        if registry.retire_metadata_worker_if_clean() {
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

    fn retire_metadata_worker_if_clean(&self) -> bool {
        let mut worker = self.inner.metadata_worker.lock();
        if self.inner.state.lock().metadata_dirty {
            return false;
        }
        // Producers must see no cached worker once it has decided to stop.
        worker.take();
        true
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
    let client = &state.clients[index];
    if !client.enabled {
        return Err(RegistryError::Disabled);
    }
    if client.limits.expired_at(OffsetDateTime::now_utc()) {
        return Err(RegistryError::Expired);
    }
    if state.quota_blocked.contains(&client.id) {
        return Err(RegistryError::QuotaExceeded);
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
        let logical = match device.id.as_str() {
            FORWARD_PROXY_DEVICE_ID => Some(FORWARD_PROXY_DEVICE_NAME),
            STANDARD_DEVICE_ID => Some(STANDARD_DEVICE_NAME),
            _ => None,
        };
        if !(logical.is_some() || device_auth::is_valid_device_id(&device.id))
            || !seen.insert(&device.id)
        {
            return Err(RegistryError::InvalidInput(format!(
                "invalid or duplicate device ID {:?}",
                device.id
            )));
        }
        if let Some(name) = logical {
            if !device.public_key.is_empty() || device.name != name {
                return Err(RegistryError::InvalidInput(format!(
                    "invalid logical device {:?}",
                    device.id
                )));
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
    if approved_devices(client) > client.max_devices
        || unapproved_devices(client) > MAX_UNAPPROVED_DEVICES
    {
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
    quota_blocked: bool,
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
        device_count: approved_devices(client),
        enrollment: client.enrollment.as_str(),
        enrollment_open_until: client
            .enrollment_open_until
            .filter(|until| *until > OffsetDateTime::now_utc()),
        pending_devices: client
            .devices
            .iter()
            .filter(|device| device.status == DeviceStatus::Pending)
            .count(),
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
                    status: device.status.as_str(),
                    subnets: device.subnets,
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
        quota_used_bytes: client.limits.monthly_quota_bytes.and_then(|_| {
            let period = client.usage_period.as_ref()?;
            snapshot.map(|_| {
                (client_usage.bytes_uploaded + client_usage.bytes_downloaded)
                    .saturating_sub(period.baseline_bytes)
            })
        }),
        status: if !client.enabled {
            "disabled"
        } else if client.limits.expired_at(OffsetDateTime::now_utc()) {
            "expired"
        } else if quota_blocked {
            "quota_exceeded"
        } else {
            "active"
        },
        limits: client.limits.clone(),
        access: client.access.clone(),
        standard_clients: client.standard_clients,
    }
}

/// Smallest accepted throughput limit; lower values cannot carry one
/// full-size packet per second in each direction.
pub const MIN_RATE_LIMIT_KBPS: u32 = 64;

/// A DNS label for a display name: lower-case letters, digits and single
/// hyphens.
fn dns_label(name: &str, fallback: &str) -> String {
    let mut label = String::new();
    for character in name.chars() {
        if character.is_ascii_alphanumeric() {
            label.push(character.to_ascii_lowercase());
        } else if !label.is_empty() && !label.ends_with('-') {
            label.push('-');
        }
        if label.len() >= 40 {
            break;
        }
    }
    let label = label.trim_end_matches('-');
    if label.is_empty() {
        fallback.to_owned()
    } else {
        label.to_owned()
    }
}

/// Unique `device.account` names. Duplicate labels get a short suffix
/// derived from the immutable ID, older accounts keeping the plain label.
fn dns_labels(clients: &[ClientRecord]) -> HashMap<(String, String), String> {
    let mut ordered = clients.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| (left.created_at, &left.id).cmp(&(right.created_at, &right.id)));
    let mut used = HashSet::new();
    let mut names = HashMap::new();
    for client in ordered {
        let mut account = dns_label(&client.name, "client");
        if !used.insert(account.clone()) {
            account = format!("{account}-{}", &client.id[..4.min(client.id.len())]);
            used.insert(account.clone());
        }
        let devices = client
            .devices
            .iter()
            .filter(|device| device.id != FORWARD_PROXY_DEVICE_ID)
            .collect::<Vec<_>>();
        for device in &devices {
            let base = dns_label(&device.name, "device");
            let duplicate = devices
                .iter()
                .filter(|other| dns_label(&other.name, "device") == base)
                .count()
                > 1;
            let label = if duplicate {
                format!(
                    "{base}-{}",
                    &hex::encode(Sha256::digest(device.id.as_bytes()))[..4]
                )
            } else {
                base
            };
            names.insert(
                (client.id.clone(), device.id.clone()),
                format!("{label}.{account}"),
            );
        }
    }
    names
}

fn prefixes_overlap(left: &Ipv4Net, right: &Ipv4Net) -> bool {
    left.contains(&right.network()) || right.contains(&left.network())
}

fn normalize_prefixes<T: Ord + Copy + Truncate>(prefixes: Vec<T>) -> Vec<T> {
    let mut prefixes = prefixes
        .into_iter()
        .map(|prefix| prefix.trunc())
        .collect::<Vec<_>>();
    prefixes.sort();
    prefixes.dedup();
    prefixes
}

/// Prefixes whose host bits can be cleared.
trait Truncate {
    fn trunc(&self) -> Self;
}

impl Truncate for Ipv4Net {
    fn trunc(&self) -> Self {
        Ipv4Net::trunc(self)
    }
}

impl Truncate for IpNet {
    fn trunc(&self) -> Self {
        IpNet::trunc(self)
    }
}

fn validate_access(access: AccessPolicy, exits: &[String]) -> Result<AccessPolicy, RegistryError> {
    if access.allow.len() > MAX_ACCESS_PREFIXES || access.deny.len() > MAX_ACCESS_PREFIXES {
        return Err(RegistryError::InvalidInput(format!(
            "allow and deny lists hold at most {MAX_ACCESS_PREFIXES} prefixes each"
        )));
    }
    let group = access
        .group
        .map(|group| group.trim().to_ascii_lowercase())
        .filter(|group| !group.is_empty());
    if let Some(group) = &group {
        if group.len() > 32
            || !group
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(RegistryError::InvalidInput(
                "group names use at most 32 letters, digits, '-' or '_'".into(),
            ));
        }
    }
    let exit = access.exit.filter(|exit| !exit.is_empty());
    if let Some(exit) = &exit {
        if !exits.iter().any(|known| known == exit) {
            return Err(RegistryError::InvalidInput(format!(
                "unknown exit {exit:?}; this gateway offers: {}",
                exits.join(", ")
            )));
        }
    }
    Ok(AccessPolicy {
        allow: normalize_prefixes(access.allow),
        deny: normalize_prefixes(access.deny),
        group,
        exit,
    })
}

fn validate_subnets(
    subnets: Vec<Ipv4Net>,
    reserved: &[Ipv4Net],
) -> Result<Vec<Ipv4Net>, RegistryError> {
    let subnets = normalize_prefixes(subnets);
    if subnets.len() > MAX_DEVICE_SUBNETS {
        return Err(RegistryError::InvalidInput(format!(
            "a device routes at most {MAX_DEVICE_SUBNETS} subnets"
        )));
    }
    for subnet in &subnets {
        let address = subnet.network();
        if subnet.prefix_len() < 8
            || address.is_loopback()
            || address.is_link_local()
            || address.is_multicast()
            || address.is_broadcast()
            || address.is_unspecified()
        {
            return Err(RegistryError::InvalidInput(format!(
                "{subnet} cannot be routed to a device; use a unicast prefix of /8 or longer"
            )));
        }
        if let Some(conflict) = reserved
            .iter()
            .find(|reserved| prefixes_overlap(subnet, reserved))
        {
            return Err(RegistryError::InvalidInput(format!(
                "{subnet} overlaps the gateway network {conflict}"
            )));
        }
    }
    if subnets
        .windows(2)
        .any(|pair| prefixes_overlap(&pair[0], &pair[1]))
    {
        return Err(RegistryError::InvalidInput(
            "a device's subnets may not overlap each other".into(),
        ));
    }
    Ok(subnets)
}

fn validate_limits(limits: &AccountLimits) -> Result<(), RegistryError> {
    if limits.monthly_quota_bytes == Some(0) {
        return Err(RegistryError::InvalidInput(
            "monthly quota must be positive; disable the client to block all traffic".into(),
        ));
    }
    if limits
        .rate_limit_kbps
        .is_some_and(|rate| rate < MIN_RATE_LIMIT_KBPS)
    {
        return Err(RegistryError::InvalidInput(format!(
            "throughput limit must be at least {MIN_RATE_LIMIT_KBPS} kbit/s"
        )));
    }
    Ok(())
}

/// Devices the gateway records on an account's behalf, without a key.
fn is_logical_device(device_id: &str) -> bool {
    matches!(device_id, FORWARD_PROXY_DEVICE_ID | STANDARD_DEVICE_ID)
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
    use serde::{Deserialize, Deserializer, Serializer};
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<OffsetDateTime>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|value| OffsetDateTime::parse(&value, &Rfc3339).map_err(serde::de::Error::custom))
            .transpose()
    }

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
            status: DeviceStatus::Approved,
            subnets: Vec::new(),
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
                        standard: false,
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
                    limits: AccountLimits::default(),
                    usage_period: None,
                    enrollment: EnrollmentPolicy::Open,
                    enrollment_open_until: None,
                    access: AccessPolicy::default(),
                    standard_clients: false,
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
                limits: AccountLimits::default(),
                usage_period: None,
                enrollment: EnrollmentPolicy::Open,
                enrollment_open_until: None,
                access: AccessPolicy::default(),
                standard_clients: false,
            },
            ClientRecord {
                id: "8899aabbccddeeff".into(),
                name: "Second".into(),
                token_hash: hash_token(token),
                max_devices: 1,
                enabled: true,
                created_at: at,
                devices: Vec::new(),
                limits: AccountLimits::default(),
                usage_period: None,
                enrollment: EnrollmentPolicy::Open,
                enrollment_open_until: None,
                access: AccessPolicy::default(),
                standard_clients: false,
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
                limits: AccountLimits::default(),
                usage_period: None,
                enrollment: EnrollmentPolicy::Open,
                enrollment_open_until: None,
                access: AccessPolicy::default(),
                standard_clients: false,
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
    async fn account_limits_persist_and_expiry_rejects_and_ends_sessions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("clients.json");
        let registry = ClientRegistry::open(&path, BOOTSTRAP_TOKEN).await.unwrap();
        let id = registry.list()[0].id.clone();
        assert!(matches!(
            registry
                .set_limits(
                    &id,
                    AccountLimits {
                        monthly_quota_bytes: Some(0),
                        ..AccountLimits::default()
                    }
                )
                .await,
            Err(RegistryError::InvalidInput(_))
        ));
        assert!(matches!(
            registry
                .set_limits(
                    &id,
                    AccountLimits {
                        rate_limit_kbps: Some(MIN_RATE_LIMIT_KBPS - 1),
                        ..AccountLimits::default()
                    }
                )
                .await,
            Err(RegistryError::InvalidInput(_))
        ));

        let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let session = registry
            .authenticate_device_session(
                BOOTSTRAP_TOKEN,
                &signed_proof(&key, "Laptop", BOOTSTRAP_TOKEN, 1),
                "POST",
                "/v1/tunnel",
            )
            .await
            .unwrap();
        let limits = AccountLimits {
            expires_at: Some(OffsetDateTime::now_utc() - time::Duration::seconds(1)),
            monthly_quota_bytes: Some(10 << 30),
            rate_limit_kbps: Some(20_000),
        };
        // Like a transport, release the session once it is cancelled.
        let ended = tokio::spawn(async move {
            let session = session;
            session.cancellation.cancelled().await;
            drop(session);
        });
        let summary = registry.set_limits(&id, limits.clone()).await.unwrap();
        assert_eq!(summary.status, "expired");
        assert_eq!(summary.limits, limits);
        // Setting a past expiry ends the account's live sessions.
        tokio::time::timeout(Duration::from_secs(1), ended)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            registry
                .authenticate_device_session(
                    BOOTSTRAP_TOKEN,
                    &signed_proof(&key, "Laptop", BOOTSTRAP_TOKEN, 2),
                    "POST",
                    "/v1/tunnel",
                )
                .await,
            Err(RegistryError::Expired)
        ));
        assert!(matches!(
            registry.authenticate_portal(BOOTSTRAP_TOKEN),
            Err(RegistryError::Expired)
        ));
        assert!(matches!(
            registry.authenticate_proxy_session(BOOTSTRAP_TOKEN).await,
            Err(RegistryError::Expired)
        ));
        registry.close().await.unwrap();

        let reopened = ClientRegistry::open(&path, BOOTSTRAP_TOKEN).await.unwrap();
        assert_eq!(reopened.list()[0].limits, limits);
        let mut renewed = limits;
        renewed.expires_at = Some(OffsetDateTime::now_utc() + time::Duration::days(30));
        assert_eq!(
            reopened.set_limits(&id, renewed).await.unwrap().status,
            "active"
        );
        assert!(reopened.authenticate_portal(BOOTSTRAP_TOKEN).is_ok());
        reopened.close().await.unwrap();
    }

    #[tokio::test]
    async fn quota_blocking_rejects_and_clearing_the_quota_restores_access() {
        let directory = tempfile::tempdir().unwrap();
        let registry = ClientRegistry::open(directory.path().join("clients.json"), BOOTSTRAP_TOKEN)
            .await
            .unwrap();
        let id = registry.list()[0].id.clone();
        registry
            .set_limits(
                &id,
                AccountLimits {
                    monthly_quota_bytes: Some(1 << 20),
                    ..AccountLimits::default()
                },
            )
            .await
            .unwrap();
        let session = registry
            .authenticate_proxy_session(BOOTSTRAP_TOKEN)
            .await
            .unwrap();
        let ended = tokio::spawn(async move {
            let session = session;
            session.cancellation.cancelled().await;
            drop(session);
        });
        assert!(registry.set_quota_blocked(&id, true).await);
        assert!(!registry.set_quota_blocked(&id, true).await);
        tokio::time::timeout(Duration::from_secs(1), ended)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            registry.authenticate_proxy_session(BOOTSTRAP_TOKEN).await,
            Err(RegistryError::QuotaExceeded)
        ));
        assert_eq!(registry.list()[0].status, "quota_exceeded");
        registry
            .set_limits(&id, AccountLimits::default())
            .await
            .unwrap();
        assert!(registry
            .authenticate_proxy_session(BOOTSTRAP_TOKEN)
            .await
            .is_ok());
        assert_eq!(registry.account_policies()[0].usage_period, None);
        registry.close().await.unwrap();
    }

    #[test]
    fn registries_without_limits_still_load_and_omit_them_when_saved() {
        let json = r#"{"id":"0011223344556677","name":"Old","token_hash":"00","max_devices":5,"enabled":true,"created_at":"2026-01-01T00:00:00Z"}"#;
        let client: ClientRecord = serde_json::from_str(json).unwrap();
        assert_eq!(client.limits, AccountLimits::default());
        assert_eq!(client.usage_period, None);
        let encoded = serde_json::to_string(&client).unwrap();
        assert!(!encoded.contains("expires_at"));
        assert!(!encoded.contains("usage_period"));
    }

    async fn enroll(
        registry: &ClientRegistry,
        key: &SigningKey,
        nonce: u8,
    ) -> Result<AuthenticatedSession, RegistryError> {
        registry
            .authenticate_device_session(
                BOOTSTRAP_TOKEN,
                &signed_proof(key, "Phone", BOOTSTRAP_TOKEN, nonce),
                "POST",
                "/v1/tunnel",
            )
            .await
    }

    #[tokio::test]
    async fn replicas_mirror_the_primary_read_only_and_end_revoked_sessions() {
        let directory = tempfile::tempdir().unwrap();
        let primary = ClientRegistry::open(directory.path().join("primary.json"), BOOTSTRAP_TOKEN)
            .await
            .unwrap();
        let account = primary.list()[0].id.clone();
        let laptop = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let laptop_id = enroll(&primary, &laptop, 1).await.unwrap().device_id;

        let path = directory.path().join("replica").join("clients.json");
        let replica = ClientRegistry::open_replica(&path).await.unwrap();
        assert!(replica.is_replica() && replica.list().is_empty());
        let sync = replica
            .replace_from_primary(primary.export())
            .await
            .unwrap();
        assert_eq!(sync.clients, 1);

        // Known devices connect; new devices and changes go to the primary.
        let session = enroll(&replica, &laptop, 2).await.unwrap();
        let cancelled = session.cancellation.clone();
        // Like a transport, end the session once it is cancelled.
        let held = tokio::spawn(async move {
            session.cancellation.cancelled().await;
            drop(session);
        });
        let phone = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        assert!(matches!(
            enroll(&replica, &phone, 3).await,
            Err(RegistryError::EnrollOnPrimary)
        ));
        assert!(matches!(
            replica.create("Other", 1).await,
            Err(RegistryError::ReadOnly)
        ));
        assert!(matches!(
            replica
                .set_access(&account, AccessPolicy::default(), &[])
                .await,
            Err(RegistryError::ReadOnly)
        ));

        // Each gateway keeps its own quota period.
        let period = UsagePeriod {
            month: "2026-11".into(),
            baseline_bytes: 42,
        };
        replica
            .set_usage_period(&account, period.clone())
            .await
            .unwrap();

        // Revoking the device on the primary ends its replica session.
        primary.deny_device(&account, &laptop_id).await.unwrap();
        let sync = replica
            .replace_from_primary(primary.export())
            .await
            .unwrap();
        assert_eq!(sync.ended_devices, 1);
        assert!(cancelled.is_cancelled());
        held.await.unwrap();
        assert!(matches!(
            enroll(&replica, &laptop, 4).await,
            Err(RegistryError::DeviceDenied)
        ));
        assert_eq!(
            replica.account_policy(&account).unwrap().usage_period,
            Some(period)
        );

        // The mirrored copy survives a restart without the primary.
        replica.close().await.unwrap();
        let replica = ClientRegistry::open_replica(&path).await.unwrap();
        assert_eq!(replica.list()[0].id, account);
        replica.close().await.unwrap();
        primary.close().await.unwrap();
    }

    #[test]
    fn dns_labels_are_sanitized_and_unique() {
        assert_eq!(
            dns_label("Alice's MacBook Pro", "device"),
            "alice-s-macbook-pro"
        );
        assert_eq!(dns_label("  ***  ", "device"), "device");
        let at = OffsetDateTime::now_utc();
        let client = |id: &str, name: &str, created_at, devices: Vec<DeviceRecord>| ClientRecord {
            id: id.into(),
            name: name.into(),
            token_hash: String::new(),
            max_devices: 5,
            enabled: true,
            created_at,
            devices,
            limits: AccountLimits::default(),
            usage_period: None,
            enrollment: EnrollmentPolicy::Open,
            enrollment_open_until: None,
            access: AccessPolicy::default(),
            standard_clients: false,
        };
        let mut phone = test_device("Phone", at);
        phone.id = "d-phone".into();
        let mut second_phone = test_device("phone", at);
        second_phone.id = "d-other-phone".into();
        let clients = vec![
            client(
                "bbbb000000000000",
                "Team",
                at + Duration::from_secs(60),
                vec![test_device("Laptop", at)],
            ),
            client("aaaa000000000000", "Team", at, vec![phone, second_phone]),
        ];
        let names = dns_labels(&clients);
        let name =
            |account: &str, device: &str| names[&(account.to_owned(), device.to_owned())].clone();
        // The older account keeps the plain label; duplicate devices get suffixes.
        assert!(name("bbbb000000000000", &clients[0].devices[0].id).ends_with(".team-bbbb"));
        let first = name("aaaa000000000000", "d-phone");
        let second = name("aaaa000000000000", "d-other-phone");
        assert!(
            first.starts_with("phone-") && first.ends_with(".team"),
            "{first}"
        );
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn standard_clients_need_the_account_setting_and_share_one_device() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("clients.json");
        let registry = ClientRegistry::open(&path, BOOTSTRAP_TOKEN).await.unwrap();
        let id = registry.list()[0].id.clone();
        assert!(matches!(
            registry
                .authenticate_standard_session(BOOTSTRAP_TOKEN)
                .await,
            Err(RegistryError::StandardClientsDisabled)
        ));
        assert!(matches!(
            registry
                .authenticate_standard_session("wrong-token-0123456789")
                .await,
            Err(RegistryError::Unauthorized)
        ));
        let summary = registry.set_standard_clients(&id, true).await.unwrap();
        assert!(summary.standard_clients);
        let first = registry
            .authenticate_standard_session(BOOTSTRAP_TOKEN)
            .await
            .unwrap();
        let second = registry
            .authenticate_standard_session(BOOTSTRAP_TOKEN)
            .await
            .unwrap();
        assert_eq!(first.device_id, STANDARD_DEVICE_ID);
        assert_eq!(first.identity.lease_id, second.identity.lease_id);
        let devices = &registry.list()[0].devices;
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].name, STANDARD_DEVICE_NAME);
        drop(second);

        // Turning the setting off ends standard sessions and is persisted.
        let ended = tokio::spawn(async move {
            let session = first;
            session.cancellation.cancelled().await;
        });
        registry.set_standard_clients(&id, false).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), ended)
            .await
            .unwrap()
            .unwrap();
        registry.close().await.unwrap();
        let reopened = ClientRegistry::open(&path, BOOTSTRAP_TOKEN).await.unwrap();
        assert!(!reopened.list()[0].standard_clients);
        assert!(matches!(
            reopened
                .authenticate_standard_session(BOOTSTRAP_TOKEN)
                .await,
            Err(RegistryError::StandardClientsDisabled)
        ));
    }

    #[tokio::test]
    async fn access_policies_and_device_subnets_are_validated_and_persisted() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("clients.json");
        let registry = ClientRegistry::open(&path, BOOTSTRAP_TOKEN).await.unwrap();
        let id = registry.list()[0].id.clone();
        let mut devices = Vec::new();
        for nonce in [1, 2] {
            let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
            devices.push(enroll(&registry, &key, nonce).await.unwrap().device_id);
        }
        let pool: Ipv4Net = "10.66.0.0/24".parse().unwrap();
        let exits = vec!["local".to_owned()];
        let net = |value: &str| -> Ipv4Net { value.parse().unwrap() };
        let prefix = |value: &str| -> IpNet { value.parse().unwrap() };

        let summary = registry
            .set_access(
                &id,
                AccessPolicy {
                    allow: vec![
                        prefix("10.30.0.9/24"),
                        prefix("10.30.0.0/24"),
                        prefix("2001:db8::1/64"),
                    ],
                    deny: Vec::new(),
                    group: Some(" Team ".into()),
                    exit: Some("local".into()),
                },
                &exits,
            )
            .await
            .unwrap();
        assert_eq!(
            summary.access.allow,
            vec![prefix("10.30.0.0/24"), prefix("2001:db8::/64")]
        );
        assert_eq!(summary.access.group.as_deref(), Some("team"));
        for invalid in [
            AccessPolicy {
                group: Some("bad group".into()),
                ..AccessPolicy::default()
            },
            AccessPolicy {
                exit: Some("elsewhere".into()),
                ..AccessPolicy::default()
            },
            AccessPolicy {
                deny: vec![prefix("10.0.0.0/8"); MAX_ACCESS_PREFIXES + 1],
                ..AccessPolicy::default()
            },
        ] {
            assert!(matches!(
                registry.set_access(&id, invalid, &exits).await,
                Err(RegistryError::InvalidInput(_))
            ));
        }

        registry
            .set_device_subnets(&id, &devices[0], vec![net("10.30.0.0/24")], &[pool])
            .await
            .unwrap();
        for (subnets, reason) in [
            (vec![net("10.30.0.128/25")], "already routed"),
            (vec![net("10.66.0.0/16")], "gateway network"),
            (vec![net("127.0.0.0/8")], "unicast"),
            (vec![net("10.0.0.0/4")], "unicast"),
        ] {
            match registry
                .set_device_subnets(&id, &devices[1], subnets, &[pool])
                .await
            {
                Err(RegistryError::InvalidInput(message)) => {
                    assert!(message.contains(reason), "{message}")
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        registry
            .set_device_subnets(&id, &devices[1], vec![net("10.31.0.0/24")], &[pool])
            .await
            .unwrap();
        assert_eq!(
            registry.device_network(&id, &devices[0]).subnets,
            vec![net("10.30.0.0/24")]
        );
        assert_eq!(registry.routed_subnets().len(), 2);

        // Both survive a restart, and replacing a device's own subnets works.
        registry.close().await.unwrap();
        let registry = ClientRegistry::open(&path, BOOTSTRAP_TOKEN).await.unwrap();
        let network = registry.device_network(&id, &devices[0]);
        assert_eq!(network.access.group.as_deref(), Some("team"));
        assert_eq!(network.subnets, vec![net("10.30.0.0/24")]);
        registry
            .set_device_subnets(&id, &devices[0], vec![net("10.30.0.0/23")], &[pool])
            .await
            .unwrap();
        registry
            .set_device_subnets(&id, &devices[0], Vec::new(), &[pool])
            .await
            .unwrap();
        assert_eq!(registry.routed_subnets().len(), 1);
        registry.close().await.unwrap();
    }

    #[tokio::test]
    async fn approval_policy_holds_new_devices_until_reviewed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("clients.json");
        let registry = ClientRegistry::open(&path, BOOTSTRAP_TOKEN).await.unwrap();
        let id = registry.list()[0].id.clone();
        let existing = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        drop(enroll(&registry, &existing, 1).await.unwrap());
        registry
            .set_enrollment(&id, EnrollmentPolicy::Approval, None)
            .await
            .unwrap();

        // Enrolled devices keep working; a new one waits for approval.
        drop(enroll(&registry, &existing, 2).await.unwrap());
        let newcomer = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        assert!(matches!(
            enroll(&registry, &newcomer, 3).await,
            Err(RegistryError::DevicePending)
        ));
        assert!(matches!(
            enroll(&registry, &newcomer, 4).await,
            Err(RegistryError::DevicePending)
        ));
        let summary = &registry.list()[0];
        assert_eq!(summary.enrollment, "approval");
        assert_eq!(summary.pending_devices, 1);
        assert_eq!(summary.device_count, 1);
        let pending = summary
            .devices
            .iter()
            .find(|device| device.status == "pending")
            .unwrap()
            .id
            .clone();

        // Pending state survives a restart.
        registry.close().await.unwrap();
        let registry = ClientRegistry::open(&path, BOOTSTRAP_TOKEN).await.unwrap();
        assert!(matches!(
            enroll(&registry, &newcomer, 5).await,
            Err(RegistryError::DevicePending)
        ));
        registry.approve_device(&id, &pending).await.unwrap();
        drop(enroll(&registry, &newcomer, 6).await.unwrap());
        assert_eq!(registry.list()[0].device_count, 2);

        registry.deny_device(&id, &pending).await.unwrap();
        assert!(matches!(
            enroll(&registry, &newcomer, 7).await,
            Err(RegistryError::DeviceDenied)
        ));
        assert_eq!(registry.list()[0].device_count, 1);
        registry.close().await.unwrap();
    }

    #[tokio::test]
    async fn closed_enrollment_refuses_new_devices_outside_a_window() {
        let directory = tempfile::tempdir().unwrap();
        let registry = ClientRegistry::open(directory.path().join("clients.json"), BOOTSTRAP_TOKEN)
            .await
            .unwrap();
        let id = registry.list()[0].id.clone();
        registry
            .set_enrollment(&id, EnrollmentPolicy::Closed, None)
            .await
            .unwrap();
        let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        assert!(matches!(
            enroll(&registry, &key, 1).await,
            Err(RegistryError::EnrollmentClosed)
        ));
        assert_eq!(registry.list()[0].devices.len(), 0);
        assert!(matches!(
            registry
                .set_enrollment(&id, EnrollmentPolicy::Closed, Some(Duration::ZERO))
                .await,
            Err(RegistryError::InvalidInput(_))
        ));
        let summary = registry
            .set_enrollment(
                &id,
                EnrollmentPolicy::Closed,
                Some(Duration::from_secs(900)),
            )
            .await
            .unwrap();
        assert!(summary.enrollment_open_until.is_some());
        drop(enroll(&registry, &key, 2).await.unwrap());
        assert_eq!(registry.list()[0].device_count, 1);
        registry.close().await.unwrap();
    }

    #[tokio::test]
    async fn unapproved_devices_are_bounded_and_excluded_from_the_limit() {
        let directory = tempfile::tempdir().unwrap();
        let registry = ClientRegistry::open(directory.path().join("clients.json"), BOOTSTRAP_TOKEN)
            .await
            .unwrap();
        let id = registry.list()[0].id.clone();
        registry
            .set_enrollment(&id, EnrollmentPolicy::Approval, None)
            .await
            .unwrap();
        for nonce in 0..MAX_UNAPPROVED_DEVICES {
            let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
            assert!(matches!(
                enroll(&registry, &key, nonce as u8).await,
                Err(RegistryError::DevicePending)
            ));
        }
        let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        assert!(matches!(
            enroll(&registry, &key, 200).await,
            Err(RegistryError::EnrollmentClosed)
        ));
        // Pending devices do not count toward the device limit.
        registry
            .update(&id, "Default client", 1, true)
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
    async fn metadata_updates_restart_after_a_worker_decides_to_retire() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("clients.json");
        let registry = ClientRegistry::open(&path, BOOTSTRAP_TOKEN).await.unwrap();
        drop(
            registry
                .authenticate_proxy_session(BOOTSTRAP_TOKEN)
                .await
                .unwrap(),
        );
        registry.set_metadata_debounce(Duration::from_millis(1));

        let (retired, retirement) = tokio::sync::oneshot::channel();
        let (resume, resumed) = tokio::sync::oneshot::channel();
        let retiring_registry = registry.clone();
        *registry.inner.metadata_worker.lock() = Some(tokio::spawn(async move {
            assert!(retiring_registry.retire_metadata_worker_if_clean());
            retired.send(()).unwrap();
            resumed.await.unwrap();
        }));
        retirement.await.unwrap();
        {
            let mut state = registry.inner.state.lock();
            state.clients[0].devices[0].last_seen =
                OffsetDateTime::now_utc() - time::Duration::minutes(2);
        }
        drop(
            registry
                .authenticate_proxy_session(BOOTSTRAP_TOKEN)
                .await
                .unwrap(),
        );
        let expected = registry.list()[0].devices[0].last_seen;
        let completed = tokio::time::timeout(Duration::from_secs(1), async {
            while registry.inner.state.lock().metadata_dirty {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await;
        let disk: RegistryFile = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        resume.send(()).unwrap();
        registry.close().await.unwrap();
        assert!(
            completed.is_ok(),
            "metadata was stranded behind a retiring worker"
        );
        assert_eq!(disk.clients[0].devices[0].last_seen, expected);
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
