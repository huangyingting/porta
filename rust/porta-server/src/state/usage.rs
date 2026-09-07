use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::future::pending;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

const STATE_VERSION: u32 = 1;
const DEFAULT_PERSISTENCE_DELAY: Duration = Duration::from_millis(100);
const SESSION_CLOSED: u64 = 1 << 63;
const SESSION_WRITERS_MASK: u64 = SESSION_CLOSED - 1;
static TEMP_FILE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Error)]
pub enum UsageError {
    #[error("{context}: {source}")]
    Io {
        context: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("{context}: {source}")]
    Json {
        context: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("{0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, UsageError>;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default)]
pub struct DeviceSnapshot {
    pub account_id: String,
    pub device_id: String,
    pub active_sessions: usize,
    pub connections_total: u64,
    pub bytes_uploaded: u64,
    pub bytes_downloaded: u64,
    pub packets_uploaded: u64,
    pub packets_downloaded: u64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_rfc3339"
    )]
    pub last_connected: Option<OffsetDateTime>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_rfc3339"
    )]
    pub last_disconnected: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub transport: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub assigned_address: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientSnapshot {
    pub active_sessions: usize,
    pub connections_total: u64,
    pub bytes_uploaded: u64,
    pub bytes_downloaded: u64,
    pub packets_uploaded: u64,
    pub packets_downloaded: u64,
    pub last_connected: Option<OffsetDateTime>,
    pub last_disconnected: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub clients: HashMap<String, ClientSnapshot>,
    pub devices: HashMap<String, DeviceSnapshot>,
}

#[derive(Clone, Debug)]
pub struct Store {
    inner: Arc<StoreInner>,
}

#[derive(Debug)]
struct StoreInner {
    path: Option<PathBuf>,
    data: RwLock<StoreData>,
    persist: Mutex<()>,
    next_id: AtomicU64,
    change_version: AtomicU64,
    persisted_version: AtomicU64,
    persist_requested: Notify,
    persistence_delay_ns: AtomicU64,
}

#[derive(Debug, Default)]
struct StoreData {
    devices: HashMap<String, DeviceSnapshot>,
    sessions: HashMap<String, ActiveSession>,
}

#[derive(Debug)]
struct ActiveSession {
    id: u64,
    account_id: String,
    device_id: String,
    transport: String,
    assigned_address: String,
    target: String,
    connected_at: OffsetDateTime,
    members: HashMap<u64, Arc<SessionCounters>>,
    completed: CounterSnapshot,
}

#[derive(Debug)]
pub struct Session {
    store: Arc<StoreInner>,
    key: String,
    state_id: u64,
    member_id: u64,
    counters: Arc<SessionCounters>,
    closed: AtomicBool,
}

#[derive(Debug, Default)]
struct SessionCounters {
    lifecycle: AtomicU64,
    generation: AtomicU64,
    uploaded: AtomicU64,
    downloaded: AtomicU64,
    packets_up: AtomicU64,
    packets_down: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default)]
struct CounterSnapshot {
    uploaded: u64,
    downloaded: u64,
    packets_up: u64,
    packets_down: u64,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct PersistentState {
    version: u32,
    devices: Vec<DeviceSnapshot>,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let path = match path.to_str() {
            Some(path) => {
                let path = path.trim();
                (!path.is_empty()).then(|| PathBuf::from(path))
            }
            None => Some(path.to_owned()),
        };
        let store = Self {
            inner: Arc::new(StoreInner {
                path,
                data: RwLock::new(StoreData::default()),
                persist: Mutex::new(()),
                next_id: AtomicU64::new(0),
                change_version: AtomicU64::new(0),
                persisted_version: AtomicU64::new(0),
                persist_requested: Notify::new(),
                persistence_delay_ns: AtomicU64::new(DEFAULT_PERSISTENCE_DELAY.as_nanos() as u64),
            }),
        };
        store.load()?;
        Ok(store)
    }

    pub fn in_memory() -> Self {
        Self::open("").expect("an in-memory usage store cannot fail to open")
    }

    fn load(&self) -> Result<()> {
        let Some(path) = &self.inner.path else {
            return Ok(());
        };
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(source) => {
                return Err(UsageError::Io {
                    context: "read usage state",
                    source,
                });
            }
        };
        let mut state: PersistentState =
            serde_json::from_slice(&bytes).map_err(|source| UsageError::Json {
                context: "decode usage state",
                source,
            })?;
        if state.version != STATE_VERSION {
            return Err(UsageError::Invalid(format!(
                "unsupported usage state version {}",
                state.version
            )));
        }
        let mut data = self
            .inner
            .data
            .write()
            .unwrap_or_else(|error| error.into_inner());
        for device in &mut state.devices {
            if device.account_id.is_empty() || device.device_id.is_empty() {
                return Err(UsageError::Invalid(
                    "usage state contains an invalid device".to_owned(),
                ));
            }
            device.active_sessions = 0;
            data.devices.insert(
                device_key(&device.account_id, &device.device_id),
                device.clone(),
            );
        }
        Ok(())
    }

    pub fn begin(
        &self,
        session_key: impl Into<String>,
        account_id: impl Into<String>,
        device_id: impl Into<String>,
        transport: impl Into<String>,
        assigned_address: impl Into<String>,
        target: impl Into<String>,
    ) -> Session {
        let mut session_key = session_key.into();
        let account_id = account_id.into();
        let device_id = device_id.into();
        let transport = transport.into();
        let assigned_address = assigned_address.into();
        let target = target.into();
        let mut data = self
            .inner
            .data
            .write()
            .unwrap_or_else(|error| error.into_inner());
        if session_key.is_empty() {
            loop {
                session_key = format!(
                    "session-{}",
                    self.inner.next_id.fetch_add(1, Ordering::Relaxed) + 1
                );
                if !data.sessions.contains_key(&session_key) {
                    break;
                }
            }
        }
        let state_id = if let Some(state) = data.sessions.get_mut(&session_key) {
            if !transport.is_empty() {
                state.transport = transport;
            }
            if !assigned_address.is_empty() {
                state.assigned_address = assigned_address;
            }
            if !target.is_empty() {
                state.target = target;
            }
            state.id
        } else {
            let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed) + 1;
            data.sessions.insert(
                session_key.clone(),
                ActiveSession {
                    id,
                    account_id,
                    device_id,
                    transport,
                    assigned_address,
                    target,
                    connected_at: OffsetDateTime::now_utc(),
                    members: HashMap::new(),
                    completed: CounterSnapshot::default(),
                },
            );
            id
        };
        let member_id = self.inner.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let counters = Arc::new(SessionCounters::default());
        data.sessions
            .get_mut(&session_key)
            .expect("active session was just inserted")
            .members
            .insert(member_id, counters.clone());
        Session {
            store: self.inner.clone(),
            key: session_key,
            state_id,
            member_id,
            counters,
            closed: AtomicBool::new(false),
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        let data = self
            .inner
            .data
            .read()
            .unwrap_or_else(|error| error.into_inner());
        let mut result = Snapshot {
            clients: HashMap::new(),
            devices: data.devices.clone(),
        };
        for session in data.sessions.values() {
            let key = device_key(&session.account_id, &session.device_id);
            let device = result.devices.entry(key).or_default();
            device.account_id.clone_from(&session.account_id);
            device.device_id.clone_from(&session.device_id);
            device.active_sessions += 1;
            device.connections_total += 1;
            add_counters(device, session.counters());
            set_connection_metadata(device, session);
        }
        for device in result.devices.values() {
            add_client_usage(&mut result.clients, device);
        }
        result
    }

    pub fn device(&self, account_id: &str, device_id: &str) -> DeviceSnapshot {
        device(&self.snapshot(), account_id, device_id)
    }

    pub fn delete_client(&self, account_id: &str) -> Result<()> {
        {
            let mut data = self
                .inner
                .data
                .write()
                .unwrap_or_else(|error| error.into_inner());
            data.devices
                .retain(|_, device| device.account_id != account_id);
            data.sessions.retain(|_, session| {
                if session.account_id == account_id {
                    session.stop_members();
                    false
                } else {
                    true
                }
            });
        }
        self.request_persistence();
        self.flush()
    }

    pub fn delete_device(&self, account_id: &str, device_id: &str) -> Result<()> {
        {
            let mut data = self
                .inner
                .data
                .write()
                .unwrap_or_else(|error| error.into_inner());
            data.devices.remove(&device_key(account_id, device_id));
            data.sessions.retain(|_, session| {
                if session.account_id == account_id && session.device_id == device_id {
                    session.stop_members();
                    false
                } else {
                    true
                }
            });
        }
        self.request_persistence();
        self.flush()
    }

    pub fn flush(&self) -> Result<()> {
        self.flush_inner(true)
    }

    pub fn checkpoint(&self) -> Result<()> {
        self.flush_inner(true)
    }

    fn flush_inner(&self, force: bool) -> Result<()> {
        if self.inner.path.is_none() {
            return Ok(());
        }
        let _persist = self
            .inner
            .persist
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let version = self.inner.change_version.load(Ordering::Acquire);
        if !force && version <= self.inner.persisted_version.load(Ordering::Acquire) {
            return Ok(());
        }
        self.persist()?;
        self.inner
            .persisted_version
            .fetch_max(version, Ordering::AcqRel);
        Ok(())
    }

    fn persist(&self) -> Result<()> {
        let Some(path) = &self.inner.path else {
            return Ok(());
        };
        let data = self
            .inner
            .data
            .read()
            .unwrap_or_else(|error| error.into_inner());
        let mut checkpoint = data.devices.clone();
        for session in data.sessions.values() {
            let key = device_key(&session.account_id, &session.device_id);
            let device = checkpoint.entry(key).or_default();
            device.account_id.clone_from(&session.account_id);
            device.device_id.clone_from(&session.device_id);
            device.connections_total += 1;
            add_counters(device, session.counters());
            set_connection_metadata(device, session);
        }
        drop(data);
        let mut devices: Vec<_> = checkpoint.into_values().collect();
        devices.sort_by(|left, right| {
            (&left.account_id, &left.device_id).cmp(&(&right.account_id, &right.device_id))
        });
        let mut encoded = serde_json::to_vec_pretty(&PersistentState {
            version: STATE_VERSION,
            devices,
        })
        .map_err(|source| UsageError::Json {
            context: "encode usage state",
            source,
        })?;
        encoded.push(b'\n');
        write_state_atomically(path, &encoded)
    }

    pub async fn run(
        &self,
        cancellation: CancellationToken,
        checkpoint_interval: Duration,
    ) -> Result<()> {
        if self.inner.path.is_none() {
            return Ok(());
        }
        let checkpoint_interval = if checkpoint_interval.is_zero() {
            Duration::from_secs(30)
        } else {
            checkpoint_interval
        };
        let mut ticker = tokio::time::interval(checkpoint_interval);
        ticker.tick().await;
        let mut persistence_deadline: Option<tokio::time::Instant> = None;
        loop {
            let debounce_deadline = persistence_deadline;
            tokio::select! {
                _ = cancellation.cancelled() => {
                    return self.flush_background(self.has_active_sessions()).await;
                }
                _ = self.inner.persist_requested.notified() => {
                    persistence_deadline = Some(
                        tokio::time::Instant::now() + self.persistence_delay()
                    );
                }
                _ = async {
                    match debounce_deadline {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => pending::<()>().await,
                    }
                } => {
                    persistence_deadline = None;
                    if let Err(error) = self.flush_background(false).await {
                        tracing::error!(%error, "persist usage state");
                        persistence_deadline = Some(
                            tokio::time::Instant::now() + self.persistence_delay()
                        );
                    }
                }
                _ = ticker.tick() => {
                    if let Err(error) = self.flush_background(true).await {
                        tracing::error!(%error, "persist usage state checkpoint");
                    }
                }
            }
        }
    }

    fn has_active_sessions(&self) -> bool {
        !self
            .inner
            .data
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .sessions
            .is_empty()
    }

    async fn flush_background(&self, force: bool) -> Result<()> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.flush_inner(force))
            .await
            .map_err(|error| {
                UsageError::Invalid(format!("usage persistence task failed: {error}"))
            })?
    }

    fn persistence_delay(&self) -> Duration {
        Duration::from_nanos(self.inner.persistence_delay_ns.load(Ordering::Relaxed))
    }

    #[cfg(test)]
    fn set_persistence_delay(&self, delay: Duration) {
        self.inner
            .persistence_delay_ns
            .store(delay.as_nanos() as u64, Ordering::Relaxed);
    }

    fn request_persistence(&self) {
        if self.inner.path.is_none() {
            return;
        }
        self.inner.change_version.fetch_add(1, Ordering::AcqRel);
        self.inner.persist_requested.notify_one();
    }
}

impl Default for Store {
    fn default() -> Self {
        Self::in_memory()
    }
}

impl Session {
    pub fn add_uploaded(&self, bytes: u64, packets: u64) {
        if !self.counters.begin_update() {
            return;
        }
        self.counters.uploaded.fetch_add(bytes, Ordering::Relaxed);
        self.counters
            .packets_up
            .fetch_add(packets, Ordering::Relaxed);
        self.counters.end_update();
    }

    pub fn add_downloaded(&self, bytes: u64, packets: u64) {
        if !self.counters.begin_update() {
            return;
        }
        self.counters.downloaded.fetch_add(bytes, Ordering::Relaxed);
        self.counters
            .packets_down
            .fetch_add(packets, Ordering::Relaxed);
        self.counters.end_update();
    }

    pub fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let counters = self.counters.stop_and_snapshot();
        finish_session(
            &self.store,
            &self.key,
            self.state_id,
            self.member_id,
            counters,
        );
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.close();
    }
}

impl SessionCounters {
    fn begin_update(&self) -> bool {
        loop {
            let state = self.lifecycle.load(Ordering::Acquire);
            if state & SESSION_CLOSED != 0 || state & SESSION_WRITERS_MASK == SESSION_WRITERS_MASK {
                return false;
            }
            if self
                .lifecycle
                .compare_exchange_weak(state, state + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }

    fn end_update(&self) {
        self.generation.fetch_add(1, Ordering::Release);
        self.lifecycle.fetch_sub(1, Ordering::Release);
    }

    fn snapshot(&self) -> CounterSnapshot {
        loop {
            let generation = self.generation.load(Ordering::Acquire);
            if self.lifecycle.load(Ordering::Acquire) & SESSION_WRITERS_MASK != 0 {
                std::thread::yield_now();
                continue;
            }
            let counters = CounterSnapshot {
                uploaded: self.uploaded.load(Ordering::Relaxed),
                downloaded: self.downloaded.load(Ordering::Relaxed),
                packets_up: self.packets_up.load(Ordering::Relaxed),
                packets_down: self.packets_down.load(Ordering::Relaxed),
            };
            if self.lifecycle.load(Ordering::Acquire) & SESSION_WRITERS_MASK == 0
                && self.generation.load(Ordering::Acquire) == generation
            {
                return counters;
            }
        }
    }

    fn stop_and_snapshot(&self) -> CounterSnapshot {
        loop {
            let state = self.lifecycle.load(Ordering::Acquire);
            if state & SESSION_CLOSED != 0
                || self
                    .lifecycle
                    .compare_exchange_weak(
                        state,
                        state | SESSION_CLOSED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
            {
                break;
            }
        }
        while self.lifecycle.load(Ordering::Acquire) & SESSION_WRITERS_MASK != 0 {
            std::thread::yield_now();
        }
        self.snapshot()
    }
}

impl ActiveSession {
    fn counters(&self) -> CounterSnapshot {
        let mut counters = self.completed;
        for member in self.members.values() {
            counters += member.snapshot();
        }
        counters
    }

    fn stop_members(&self) {
        for member in self.members.values() {
            member.stop_and_snapshot();
        }
    }
}

impl std::ops::AddAssign for CounterSnapshot {
    fn add_assign(&mut self, other: Self) {
        self.uploaded += other.uploaded;
        self.downloaded += other.downloaded;
        self.packets_up += other.packets_up;
        self.packets_down += other.packets_down;
    }
}

fn finish_session(
    store: &Arc<StoreInner>,
    key: &str,
    state_id: u64,
    member_id: u64,
    counters: CounterSnapshot,
) {
    let mut data = store
        .data
        .write()
        .unwrap_or_else(|error| error.into_inner());
    let Some(state) = data.sessions.get_mut(key) else {
        return;
    };
    if state.id != state_id || state.members.remove(&member_id).is_none() {
        return;
    }
    state.completed += counters;
    if !state.members.is_empty() {
        return;
    }
    let state = data.sessions.remove(key).expect("active session exists");
    let now = OffsetDateTime::now_utc();
    let key = device_key(&state.account_id, &state.device_id);
    let device = data.devices.entry(key).or_default();
    device.account_id.clone_from(&state.account_id);
    device.device_id.clone_from(&state.device_id);
    device.connections_total += 1;
    add_counters(device, state.completed);
    set_connection_metadata(device, &state);
    device.last_disconnected = Some(now);
    drop(data);
    if store.path.is_some() {
        store.change_version.fetch_add(1, Ordering::AcqRel);
        store.persist_requested.notify_one();
    }
}

fn add_counters(device: &mut DeviceSnapshot, counters: CounterSnapshot) {
    device.bytes_uploaded += counters.uploaded;
    device.bytes_downloaded += counters.downloaded;
    device.packets_uploaded += counters.packets_up;
    device.packets_downloaded += counters.packets_down;
}

fn set_connection_metadata(device: &mut DeviceSnapshot, session: &ActiveSession) {
    if device
        .last_connected
        .is_some_and(|connected| session.connected_at < connected)
    {
        return;
    }
    device.last_connected = Some(session.connected_at);
    device.transport.clone_from(&session.transport);
    device
        .assigned_address
        .clone_from(&session.assigned_address);
    device.target.clone_from(&session.target);
}

fn add_client_usage(clients: &mut HashMap<String, ClientSnapshot>, device: &DeviceSnapshot) {
    let client = clients.entry(device.account_id.clone()).or_default();
    client.active_sessions += device.active_sessions;
    client.connections_total += device.connections_total;
    client.bytes_uploaded += device.bytes_uploaded;
    client.bytes_downloaded += device.bytes_downloaded;
    client.packets_uploaded += device.packets_uploaded;
    client.packets_downloaded += device.packets_downloaded;
    client.last_connected = latest_time(client.last_connected, device.last_connected);
    client.last_disconnected = latest_time(client.last_disconnected, device.last_disconnected);
}

fn latest_time(
    current: Option<OffsetDateTime>,
    candidate: Option<OffsetDateTime>,
) -> Option<OffsetDateTime> {
    match (current, candidate) {
        (None, candidate) => candidate,
        (current, None) => current,
        (Some(current), Some(candidate)) => Some(current.max(candidate)),
    }
}

pub fn device(snapshot: &Snapshot, account_id: &str, device_id: &str) -> DeviceSnapshot {
    snapshot
        .devices
        .get(&device_key(account_id, device_id))
        .cloned()
        .unwrap_or_default()
}

pub fn open(path: impl AsRef<Path>) -> Result<Store> {
    Store::open(path)
}

fn device_key(account_id: &str, device_id: &str) -> String {
    let mut key = String::with_capacity(account_id.len() + device_id.len() + 1);
    key.push_str(account_id);
    key.push('\0');
    key.push_str(device_id);
    key
}

fn state_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn write_state_atomically(path: &Path, data: &[u8]) -> Result<()> {
    let directory = state_directory(path);
    create_state_directory(directory).map_err(|source| UsageError::Io {
        context: "create usage state directory",
        source,
    })?;
    let (temporary_path, mut temporary) =
        create_temporary(directory, ".usage-").map_err(|source| UsageError::Io {
            context: "create usage state temporary file",
            source,
        })?;
    let result = (|| {
        temporary.write_all(data).map_err(|source| UsageError::Io {
            context: "write usage state temporary file",
            source,
        })?;
        temporary.sync_all().map_err(|source| UsageError::Io {
            context: "sync usage state temporary file",
            source,
        })?;
        drop(temporary);
        fs::rename(&temporary_path, path).map_err(|source| UsageError::Io {
            context: "replace usage state",
            source,
        })?;
        sync_directory(directory).map_err(|source| UsageError::Io {
            context: "sync usage state directory",
            source,
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }

    fn create_state_directory(directory: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;

            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(directory)
        }
        #[cfg(not(unix))]
        {
            fs::create_dir_all(directory)
        }
    }
    result
}

fn create_temporary(directory: &Path, prefix: &str) -> io::Result<(PathBuf, File)> {
    for _ in 0..128 {
        let id = TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!("{prefix}{}-{id}", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create a unique temporary state file",
    ))
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> io::Result<()> {
    Ok(())
}

mod optional_rfc3339 {
    use super::*;

    pub fn serialize<S>(
        value: &Option<OffsetDateTime>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) => serializer
                .serialize_some(&value.format(&Rfc3339).map_err(serde::ser::Error::custom)?),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> std::result::Result<Option<OffsetDateTime>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<String>::deserialize(deserializer)?;
        value
            .map(|value| OffsetDateTime::parse(&value, &Rfc3339).map_err(serde::de::Error::custom))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::thread;
    use tempfile::tempdir;

    fn usage(snapshot: &Snapshot, account: &str, device_id: &str) -> DeviceSnapshot {
        device(snapshot, account, device_id)
    }

    #[test]
    fn reads_and_round_trips_go_compatible_json() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("usage.json");
        fs::write(
            &path,
            br#"{
  "version": 1,
  "devices": [
    {
      "account_id": "account",
      "device_id": "phone",
      "active_sessions": 7,
      "connections_total": 4,
      "bytes_uploaded": 10,
      "bytes_downloaded": 20,
      "packets_uploaded": 1,
      "packets_downloaded": 2,
      "last_connected": "2024-01-02T03:04:05.123456789Z",
      "last_disconnected": "2024-01-02T04:05:06Z",
      "transport": "masque-h3-datagram",
      "assigned_address": "10.66.0.2"
    }
  ]
}
"#,
        )
        .unwrap();
        let store = Store::open(&path).unwrap();
        let loaded = usage(&store.snapshot(), "account", "phone");
        assert_eq!(loaded.active_sessions, 0);
        assert_eq!(loaded.bytes_downloaded, 20);
        assert_eq!(loaded.last_connected.unwrap().nanosecond(), 123_456_789);
        store.flush().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(value["version"], 1);
        assert_eq!(value["devices"][0]["account_id"], "account");
        assert_eq!(
            value["devices"][0]["last_connected"],
            "2024-01-02T03:04:05.123456789Z"
        );
        assert!(value["devices"][0].get("target").is_none());
    }

    #[test]
    fn collapses_multi_lane_sessions_and_persists_totals() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("usage.json");
        let store = Store::open(&path).unwrap();
        let first = store.begin(
            "vpn:account:phone:session",
            "account",
            "phone",
            "HTTP/2.0",
            "10.66.0.2",
            "",
        );
        let second = store.begin(
            "vpn:account:phone:session",
            "account",
            "phone",
            "HTTP/2.0",
            "10.66.0.2",
            "",
        );
        first.add_uploaded(120, 2);
        second.add_downloaded(340, 3);
        let live = usage(&store.snapshot(), "account", "phone");
        assert_eq!(live.active_sessions, 1);
        assert_eq!(live.connections_total, 1);
        assert_eq!(live.bytes_uploaded, 120);
        assert_eq!(live.bytes_downloaded, 340);
        first.close();
        assert_eq!(
            usage(&store.snapshot(), "account", "phone").active_sessions,
            1
        );
        second.close();
        store.flush().unwrap();

        let reopened = Store::open(&path).unwrap();
        let persisted = usage(&reopened.snapshot(), "account", "phone");
        assert_eq!(persisted.active_sessions, 0);
        assert_eq!(persisted.connections_total, 1);
        assert_eq!(persisted.packets_uploaded, 2);
        assert_eq!(persisted.packets_downloaded, 3);
        assert!(persisted.last_connected.is_some());
        assert!(persisted.last_disconnected.is_some());
    }

    #[test]
    fn checkpoint_includes_active_traffic_as_completed_on_restart() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("usage.json");
        let store = Store::open(&path).unwrap();
        let session = store.begin("", "account", "phone", "HTTP/2.0", "10.66.0.2", "");
        session.add_uploaded(4096, 8);
        store.checkpoint().unwrap();
        let reopened = Store::open(&path).unwrap();
        let device = usage(&reopened.snapshot(), "account", "phone");
        assert_eq!(device.active_sessions, 0);
        assert_eq!(device.connections_total, 1);
        assert_eq!(device.bytes_uploaded, 4096);
        assert_eq!(device.packets_uploaded, 8);
    }

    #[test]
    fn concurrent_accounting_and_snapshots_keep_pairs_consistent() {
        let store = Store::in_memory();
        let session = Arc::new(store.begin("", "account", "phone", "", "", ""));
        let writers = 8_usize;
        let updates = 2_000_u64;
        let start = Arc::new(Barrier::new(writers + 1));
        let mut threads = Vec::new();
        for _ in 0..writers {
            let session = session.clone();
            let start = start.clone();
            threads.push(thread::spawn(move || {
                start.wait();
                for _ in 0..updates {
                    session.add_uploaded(2, 1);
                    session.add_downloaded(3, 1);
                }
            }));
        }
        start.wait();
        while threads.iter().any(|thread| !thread.is_finished()) {
            let current = usage(&store.snapshot(), "account", "phone");
            assert_eq!(current.bytes_uploaded, current.packets_uploaded * 2);
            assert_eq!(current.bytes_downloaded, current.packets_downloaded * 3);
        }
        for thread in threads {
            thread.join().unwrap();
        }
        session.close();
        let final_usage = usage(&store.snapshot(), "account", "phone");
        assert_eq!(final_usage.bytes_uploaded, writers as u64 * updates * 2);
        assert_eq!(final_usage.bytes_downloaded, writers as u64 * updates * 3);
        assert_eq!(final_usage.packets_uploaded, writers as u64 * updates);
        assert_eq!(final_usage.packets_downloaded, writers as u64 * updates);
    }

    #[test]
    fn concurrent_lanes_survive_snapshots_and_checkpoints() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("usage.json");
        let store = Store::open(&path).unwrap();
        let lanes = 6_usize;
        let updates = 1_000_u64;
        let start = Arc::new(Barrier::new(lanes + 1));
        let mut threads = Vec::new();
        for _ in 0..lanes {
            let session = store.begin("multi-lane", "account", "phone", "", "", "");
            let start = start.clone();
            threads.push(thread::spawn(move || {
                start.wait();
                for _ in 0..updates {
                    session.add_uploaded(2, 1);
                    session.add_downloaded(3, 1);
                }
            }));
        }
        start.wait();
        while threads.iter().any(|thread| !thread.is_finished()) {
            let current = usage(&store.snapshot(), "account", "phone");
            assert_eq!(current.bytes_uploaded, current.packets_uploaded * 2);
            assert_eq!(current.bytes_downloaded, current.packets_downloaded * 3);
            store.checkpoint().unwrap();
        }
        for thread in threads {
            thread.join().unwrap();
        }
        store.flush().unwrap();
        let reopened = Store::open(&path).unwrap();
        let persisted = usage(&reopened.snapshot(), "account", "phone");
        assert_eq!(persisted.active_sessions, 0);
        assert_eq!(persisted.connections_total, 1);
        assert_eq!(persisted.bytes_uploaded, lanes as u64 * updates * 2);
        assert_eq!(persisted.bytes_downloaded, lanes as u64 * updates * 3);
        assert_eq!(persisted.packets_uploaded, lanes as u64 * updates);
        assert_eq!(persisted.packets_downloaded, lanes as u64 * updates);
    }

    #[test]
    fn deleting_a_device_detaches_old_sessions_from_replacements() {
        let store = Store::in_memory();
        let old = store.begin("shared-key", "account", "phone", "", "", "");
        store.delete_device("account", "phone").unwrap();
        let replacement = store.begin("shared-key", "account", "phone", "", "", "");
        old.close();
        old.add_uploaded(100, 1);
        replacement.add_uploaded(7, 1);
        let current = usage(&store.snapshot(), "account", "phone");
        assert_eq!(current.active_sessions, 1);
        assert_eq!(current.bytes_uploaded, 7);
    }

    #[test]
    fn latest_connection_controls_transport_address_and_target() {
        let store = Store::in_memory();
        let older = store.begin("older", "account", "phone", "old", "", "old:443");
        thread::sleep(Duration::from_millis(1));
        let newer = store.begin("newer", "account", "phone", "new", "10.66.0.2", "new:443");
        let current = usage(&store.snapshot(), "account", "phone");
        assert_eq!(current.transport, "new");
        assert_eq!(current.assigned_address, "10.66.0.2");
        assert_eq!(current.target, "new:443");
        newer.close();
        older.close();
        let completed = usage(&store.snapshot(), "account", "phone");
        assert_eq!(completed.transport, "new");
        assert_eq!(completed.target, "new:443");
    }

    #[tokio::test]
    async fn run_debounces_dirty_sessions_and_flushes_on_shutdown() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("usage.json");
        let store = Store::open(&path).unwrap();
        store.set_persistence_delay(Duration::from_millis(5));
        for amount in 1..=25 {
            let session = store.begin("", "account", "phone", "https-connect", "", "");
            session.add_uploaded(amount, 1);
            session.close();
        }
        let cancellation = CancellationToken::new();
        let runner = {
            let store = store.clone();
            let cancellation = cancellation.clone();
            tokio::spawn(async move { store.run(cancellation, Duration::from_secs(60)).await })
        };
        tokio::time::sleep(Duration::from_millis(30)).await;
        cancellation.cancel();
        runner.await.unwrap().unwrap();
        let reopened = Store::open(&path).unwrap();
        let persisted = usage(&reopened.snapshot(), "account", "phone");
        assert_eq!(persisted.connections_total, 25);
        assert_eq!(persisted.bytes_uploaded, 25 * 26 / 2);
        assert_eq!(persisted.packets_uploaded, 25);
    }
}
