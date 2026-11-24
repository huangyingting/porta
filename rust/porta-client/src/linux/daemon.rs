//! Background service behind the Linux desktop app.
//!
//! `porta-client --daemon` runs as root under systemd and owns networking,
//! the profile store (root-only, with tokens) and at most one tunnel. The
//! unprivileged desktop app talks to it over a Unix socket that only root
//! and the members of the control group may open. Each request is one JSON
//! line, such as `{"command":"connect","id":"..."}`, and each response is
//! one JSON line holding either `snapshot`, the same state the Windows app
//! shows, or `error`.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio_util::sync::CancellationToken;
use url::Url;
use zeroize::Zeroizing;

use super::client::{self, Event, RunError, State};
use crate::tunnel::{AccountStatus, Routing, Transport};

const STORE_VERSION: u8 = 1;
const MAX_STORE_SIZE: u64 = 1024 * 1024;
const MAX_REQUEST: usize = 64 * 1024;
const MAX_PROFILES: usize = 64;
const MAX_ACTIVITY_LINES: usize = 200;
const MAX_CLIENTS: usize = 16;

pub struct DaemonConfig {
    pub control_socket: PathBuf,
    pub profiles: PathBuf,
    pub network_state: PathBuf,
    pub identity_path: Option<PathBuf>,
    pub interface_name: String,
    /// Group whose members may use the control socket; root only without it.
    pub group: Option<String>,
    /// Trust for privately signed gateways, applied to every profile.
    pub ca_path: Option<PathBuf>,
    pub thumbprint: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredProfile {
    id: String,
    name: String,
    server_url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    backup_servers: Vec<String>,
    transport: String,
    token: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct StoreFile {
    version: u8,
    #[serde(default)]
    selected: String,
    #[serde(default)]
    profiles: Vec<StoredProfile>,
}

/// A profile as the desktop app edits it; an empty token keeps the saved one.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileInput {
    #[serde(default)]
    id: String,
    name: String,
    server_url: String,
    #[serde(default)]
    backup_servers: Vec<String>,
    #[serde(default)]
    transport: String,
    #[serde(default)]
    token: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum Request {
    Snapshot,
    SelectProfile { id: String },
    SaveProfile { input: ProfileInput },
    DeleteProfile { id: String },
    Connect { id: String },
    Disconnect,
    RestoreNetwork,
    ClearActivity,
}

#[derive(Debug, Serialize)]
struct Response {
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot: Option<Snapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct SnapshotProfile {
    id: String,
    name: String,
    server_url: String,
    backup_servers: Vec<String>,
    transport: String,
    selected: bool,
    active: bool,
    status: String,
}

/// The desktop app's view, field for field the Windows app's snapshot.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    platform: &'static str,
    version: String,
    profiles: Vec<SnapshotProfile>,
    selected_profile_id: String,
    active_profile_id: String,
    status: String,
    detail: String,
    tone: String,
    running: bool,
    connected: bool,
    restoring: bool,
    disconnecting: bool,
    recovery_available: bool,
    startup_blocked: bool,
    address: String,
    transport: String,
    mtu: u16,
    connected_at: String,
    bytes_uploaded: u64,
    bytes_downloaded: u64,
    upload_rate: u64,
    download_rate: u64,
    account_expires_at: i64,
    quota_bytes: u64,
    quota_used_bytes: Option<u64>,
    rate_limit_kbps: u32,
    account_denial: String,
    split_routes: Vec<String>,
    split_dns_domains: Vec<String>,
    direct_peers: Vec<String>,
    activity: Vec<String>,
}

#[derive(Default)]
struct Status {
    active_id: String,
    cancellation: Option<CancellationToken>,
    running: bool,
    connected: bool,
    disconnecting: bool,
    restoring: bool,
    recovery: bool,
    status: String,
    detail: String,
    tone: String,
    address: String,
    transport: String,
    mtu: u16,
    connected_at: String,
    bytes_uploaded: u64,
    bytes_downloaded: u64,
    upload_rate: u64,
    download_rate: u64,
    last_sample: Option<(Instant, u64, u64)>,
    account: AccountStatus,
    account_denial: String,
    routing: Routing,
    direct_peers: Vec<crate::tunnel::DirectPeer>,
    activity: Vec<String>,
}

struct Daemon {
    config: DaemonConfig,
    store: Mutex<StoreFile>,
    status: Mutex<Status>,
}

/// Serves the control socket until cancelled, then ends any tunnel.
pub async fn run(config: DaemonConfig, cancellation: &CancellationToken) -> Result<(), RunError> {
    let store = load_store(&config.profiles)?;
    let recovery = network_recovery(&config.network_state);
    let listener = bind_control_socket(&config.control_socket, config.group.as_deref())?;
    let daemon = Arc::new(Daemon {
        config,
        store: Mutex::new(store),
        status: Mutex::new(Status {
            status: "Disconnected".to_owned(),
            detail: "Choose a profile to connect securely.".to_owned(),
            tone: "offline".to_owned(),
            recovery,
            ..Status::default()
        }),
    });
    daemon.log("Porta service started");
    let clients = Arc::new(tokio::sync::Semaphore::new(MAX_CLIENTS));
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                let Ok(permit) = clients.clone().try_acquire_owned() else { continue };
                let daemon = daemon.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    daemon.serve(stream).await;
                });
            }
        }
    }
    let session = daemon.lock_status().cancellation.clone();
    if let Some(session) = session {
        session.cancel();
        for _ in 0..200 {
            if !daemon.lock_status().running {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    let _ = fs::remove_file(&daemon.config.control_socket);
    Ok(())
}

impl Daemon {
    /// Answers one request per connection.
    async fn serve(self: Arc<Self>, stream: UnixStream) {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader.take(MAX_REQUEST as u64));
        let mut line = String::new();
        {
            match tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await {
                Ok(Ok(length)) if length > 0 => {}
                _ => return,
            }
            let response = match serde_json::from_str::<Request>(line.trim()) {
                Ok(request) => match self.handle(request) {
                    Ok(snapshot) => Response {
                        snapshot: Some(snapshot),
                        error: None,
                    },
                    Err(error) => Response {
                        snapshot: None,
                        error: Some(error),
                    },
                },
                Err(error) => Response {
                    snapshot: None,
                    error: Some(format!("invalid request: {error}")),
                },
            };
            let mut encoded = serde_json::to_vec(&response).unwrap_or_default();
            encoded.push(b'\n');
            // A client that stops reading must not hold its slot forever.
            let _ = tokio::time::timeout(Duration::from_secs(10), writer.write_all(&encoded)).await;
        }
    }

    fn handle(self: &Arc<Self>, request: Request) -> Result<Snapshot, String> {
        match request {
            Request::Snapshot => {}
            Request::SelectProfile { id } => self.select_profile(&id)?,
            Request::SaveProfile { input } => self.save_profile(input)?,
            Request::DeleteProfile { id } => self.delete_profile(&id)?,
            Request::Connect { id } => self.connect(&id)?,
            Request::Disconnect => self.disconnect(),
            Request::RestoreNetwork => self.restore_network()?,
            Request::ClearActivity => self.lock_status().activity.clear(),
        }
        Ok(self.snapshot())
    }

    fn lock_status(&self) -> std::sync::MutexGuard<'_, Status> {
        self.status
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn lock_store(&self) -> std::sync::MutexGuard<'_, StoreFile> {
        self.store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn log(&self, message: &str) {
        add_activity(&mut self.lock_status().activity, message);
    }

    fn snapshot(&self) -> Snapshot {
        let store = self.lock_store();
        let status = self.lock_status();
        let mut profiles = store
            .profiles
            .iter()
            .map(|profile| SnapshotProfile {
                id: profile.id.clone(),
                name: profile.name.clone(),
                server_url: profile.server_url.clone(),
                backup_servers: profile.backup_servers.clone(),
                transport: profile.transport.clone(),
                selected: profile.id == store.selected,
                active: profile.id == status.active_id && status.running,
                status: if profile.id == status.active_id {
                    status.status.clone()
                } else if profile.id == store.selected {
                    "Selected profile".to_owned()
                } else {
                    "Ready".to_owned()
                },
            })
            .collect::<Vec<_>>();
        profiles.sort_by_cached_key(|profile| profile.name.to_lowercase());
        Snapshot {
            platform: "linux",
            version: crate::VERSION.trim().to_owned(),
            profiles,
            selected_profile_id: store.selected.clone(),
            active_profile_id: status.active_id.clone(),
            status: status.status.clone(),
            detail: status.detail.clone(),
            tone: status.tone.clone(),
            running: status.running,
            connected: status.connected,
            restoring: status.restoring,
            disconnecting: status.disconnecting,
            recovery_available: status.recovery,
            startup_blocked: false,
            address: status.address.clone(),
            transport: status.transport.clone(),
            mtu: status.mtu,
            connected_at: status.connected_at.clone(),
            bytes_uploaded: status.bytes_uploaded,
            bytes_downloaded: status.bytes_downloaded,
            upload_rate: status.upload_rate,
            download_rate: status.download_rate,
            account_expires_at: status.account.expires_at.unwrap_or_default(),
            quota_bytes: status.account.quota_bytes.unwrap_or_default(),
            quota_used_bytes: status.account.quota_used_bytes,
            rate_limit_kbps: status.account.rate_limit_kbps.unwrap_or_default(),
            account_denial: status.account_denial.clone(),
            split_routes: status
                .routing
                .routes
                .iter()
                .map(ToString::to_string)
                .chain(status.routing.routes6.iter().map(ToString::to_string))
                .collect(),
            split_dns_domains: status.routing.dns_domains.clone(),
            direct_peers: status
                .direct_peers
                .iter()
                .map(ToString::to_string)
                .collect(),
            activity: status.activity.clone(),
        }
    }

    fn select_profile(&self, id: &str) -> Result<(), String> {
        let mut store = self.lock_store();
        if !store.profiles.iter().any(|profile| profile.id == id) {
            return Err("profile not found".to_owned());
        }
        let status = self.lock_status();
        if status.running && id != status.active_id {
            return Err("disconnect the active profile before selecting another one".to_owned());
        }
        drop(status);
        store.selected = id.to_owned();
        persist_store(&self.config.profiles, &store).map_err(|error| error.to_string())
    }

    fn save_profile(&self, input: ProfileInput) -> Result<(), String> {
        {
            let status = self.lock_status();
            if status.running || status.restoring {
                return Err("profiles cannot be changed while Porta is busy".to_owned());
            }
        }
        let name = input.name.trim().to_owned();
        if name.is_empty() || name.chars().count() > 80 {
            return Err("profile name must contain 1 to 80 characters".to_owned());
        }
        let server_url = input.server_url.trim().to_owned();
        parse_origin(&server_url)?;
        let backup_servers = input
            .backup_servers
            .iter()
            .map(|server| server.trim())
            .filter(|server| !server.is_empty())
            .map(|server| parse_origin(server).map(|_| server.to_owned()))
            .collect::<Result<Vec<_>, _>>()?;
        if backup_servers.len() > 7 {
            return Err("a profile lists at most 7 backup gateways".to_owned());
        }
        let transport = match input.transport.trim() {
            "" | "auto" => "auto",
            "h3" => "h3",
            "h2" => "h2",
            _ => return Err("transport must be auto, h2, or h3".to_owned()),
        }
        .to_owned();
        let token = Zeroizing::new(input.token.trim().to_owned());
        if !token.is_empty()
            && (token.len() > 512 || !token.bytes().all(|byte| byte.is_ascii_graphic()))
        {
            return Err("token contains unsupported characters".to_owned());
        }
        let mut store = self.lock_store();
        let id = input.id.trim();
        let index = store.profiles.iter().position(|profile| profile.id == id);
        if !id.is_empty() && index.is_none() {
            return Err("profile not found".to_owned());
        }
        let previous_token = index.map(|index| store.profiles[index].token.clone());
        let token = if token.is_empty() {
            previous_token.ok_or_else(|| "token is required for a new profile".to_owned())?
        } else {
            token.to_string()
        };
        if index.is_none() && store.profiles.len() >= MAX_PROFILES {
            return Err(format!("at most {MAX_PROFILES} profiles are supported"));
        }
        let profile = StoredProfile {
            id: if id.is_empty() {
                random_id()
            } else {
                id.to_owned()
            },
            name,
            server_url,
            backup_servers,
            transport,
            token,
        };
        let previous = match index {
            Some(index) => Some(std::mem::replace(
                &mut store.profiles[index],
                profile.clone(),
            )),
            None => {
                store.profiles.push(profile.clone());
                None
            }
        };
        let previous_selected = std::mem::replace(&mut store.selected, profile.id.clone());
        if let Err(error) = persist_store(&self.config.profiles, &store) {
            match (index, previous) {
                (Some(index), Some(previous)) => store.profiles[index] = previous,
                _ => {
                    store.profiles.pop();
                }
            }
            store.selected = previous_selected;
            return Err(error.to_string());
        }
        drop(store);
        self.log(&format!("Saved profile {}", profile.name));
        Ok(())
    }

    fn delete_profile(&self, id: &str) -> Result<(), String> {
        {
            let status = self.lock_status();
            if (status.running || status.restoring) && status.active_id == id {
                return Err("disconnect the profile before deleting it".to_owned());
            }
        }
        let mut store = self.lock_store();
        let index = store
            .profiles
            .iter()
            .position(|profile| profile.id == id)
            .ok_or_else(|| "profile not found".to_owned())?;
        let removed = store.profiles.remove(index);
        let previous_selected = store.selected.clone();
        if store.selected == id {
            store.selected = store
                .profiles
                .first()
                .map(|profile| profile.id.clone())
                .unwrap_or_default();
        }
        if let Err(error) = persist_store(&self.config.profiles, &store) {
            store.profiles.insert(index, removed);
            store.selected = previous_selected;
            return Err(error.to_string());
        }
        drop(store);
        self.log(&format!("Deleted profile {}", removed.name));
        Ok(())
    }

    fn connect(self: &Arc<Self>, id: &str) -> Result<(), String> {
        let profile = {
            let mut store = self.lock_store();
            let id = if id.trim().is_empty() {
                store.selected.clone()
            } else {
                id.trim().to_owned()
            };
            let profile = store
                .profiles
                .iter()
                .find(|profile| profile.id == id)
                .cloned()
                .ok_or_else(|| "choose a profile first".to_owned())?;
            if store.selected != profile.id {
                store.selected = profile.id.clone();
                let _ = persist_store(&self.config.profiles, &store);
            }
            profile
        };
        let cancellation = CancellationToken::new();
        {
            let mut status = self.lock_status();
            if status.running || status.restoring {
                return Err("Porta is already connecting or restoring the network".to_owned());
            }
            status.active_id = profile.id.clone();
            status.cancellation = Some(cancellation.clone());
            status.running = true;
            status.connected = false;
            status.disconnecting = false;
            status.account_denial.clear();
            status.status = "Connecting".to_owned();
            status.detail = "Establishing a secure tunnel...".to_owned();
            status.tone = "warning".to_owned();
            reset_connection(&mut status);
            add_activity(
                &mut status.activity,
                &format!("Connecting {} to {}", profile.name, profile.server_url),
            );
        }
        let daemon = Arc::clone(self);
        tokio::spawn(async move { daemon.run_connection(profile, cancellation).await });
        Ok(())
    }

    async fn run_connection(
        self: Arc<Self>,
        profile: StoredProfile,
        cancellation: CancellationToken,
    ) {
        let observer = {
            let daemon = Arc::clone(&self);
            move |event: Event| daemon.handle_event(event)
        };
        let result = client::run(
            client::Config {
                server_urls: std::iter::once(profile.server_url.clone())
                    .chain(profile.backup_servers.iter().cloned())
                    .collect(),
                token: profile.token.clone(),
                transport: match profile.transport.as_str() {
                    "h3" => Transport::Http3,
                    "h2" => Transport::Http2,
                    _ => Transport::Auto,
                },
                interface_name: self.config.interface_name.clone(),
                identity_path: self.config.identity_path.clone(),
                ca_path: self.config.ca_path.clone(),
                thumbprint: self.config.thumbprint.clone(),
                insecure: false,
                reconnect: true,
                reconnect_max_delay: Duration::from_secs(30),
                manual_network: false,
                network_state: self.config.network_state.clone(),
                subnet_router: false,
            },
            &cancellation,
            observer,
        )
        .await;
        let recovery = network_recovery(&self.config.network_state);
        let mut status = self.lock_status();
        status.running = false;
        status.connected = false;
        status.disconnecting = false;
        status.cancellation = None;
        status.active_id.clear();
        status.recovery = recovery;
        reset_connection(&mut status);
        match result {
            Ok(()) | Err(RunError::Cancelled) => {
                status.status = "Disconnected".to_owned();
                status.detail = "Choose a profile to reconnect securely.".to_owned();
                status.tone = "offline".to_owned();
                add_activity(&mut status.activity, "Disconnected");
            }
            Err(error) => {
                status.status = "Connection error".to_owned();
                status.detail = error.to_string();
                status.account_denial = match &error {
                    RunError::Tunnel(error) => error
                        .denial()
                        .map(|denial| denial.code().to_owned())
                        .unwrap_or_default(),
                    _ => String::new(),
                };
                status.tone = "danger".to_owned();
                let line = format!("Connection error: {error}");
                add_activity(&mut status.activity, &line);
            }
        }
    }

    fn handle_event(&self, event: Event) {
        let mut status = self.lock_status();
        match event.state {
            State::Connected => {
                let transport = match event.transport {
                    Transport::Http3 => "h3",
                    Transport::Http2 => "h2",
                    Transport::Auto => "auto",
                };
                if !status.connected {
                    add_activity(&mut status.activity, &format!("Connected over {transport}"));
                }
                status.connected = true;
                status.status = "Connected".to_owned();
                if let Some(lease) = event.lease {
                    status.detail = match event.transport {
                        Transport::Http3 => {
                            format!("HTTP/3 MASQUE - fast and resilient - MTU {}", lease.mtu)
                        }
                        Transport::Http2 => {
                            format!("4-lane HTTP/2 fallback - encrypted - MTU {}", lease.mtu)
                        }
                        Transport::Auto => format!("Encrypted tunnel active - MTU {}", lease.mtu),
                    };
                    status.address = match lease.ipv6() {
                        Some(ipv6) => format!("{} · {}", lease.address.addr(), ipv6.addr()),
                        None => lease.address.to_string(),
                    };
                    status.mtu = lease.mtu;
                }
                status.tone = "connected".to_owned();
                status.transport = transport.to_owned();
                status.account = event.account;
                status.routing = event.routing;
                if status.direct_peers != event.direct_peers {
                    add_activity(
                        &mut status.activity,
                        &crate::tunnel::direct_summary(&event.direct_peers),
                    );
                    status.direct_peers = event.direct_peers;
                }
                status.connected_at = event.connected_at.map(rfc3339).unwrap_or_default();
                update_rates(&mut status, event.bytes_uploaded, event.bytes_downloaded);
            }
            State::Connecting | State::Configuring | State::Reconnecting => {
                if status.disconnecting {
                    return;
                }
                status.connected = false;
                status.status = match event.state {
                    State::Configuring => "Configuring network",
                    State::Reconnecting => "Reconnecting",
                    _ => "Connecting",
                }
                .to_owned();
                status.detail = event.message.clone();
                status.tone = "warning".to_owned();
                add_activity(&mut status.activity, &event.message);
            }
            State::Disconnected | State::Error => {
                add_activity(&mut status.activity, &event.message);
            }
        }
    }

    fn disconnect(&self) {
        let mut status = self.lock_status();
        let Some(cancellation) = status.cancellation.clone() else {
            return;
        };
        status.disconnecting = true;
        status.status = "Disconnecting".to_owned();
        status.detail = "Restoring normal network access...".to_owned();
        status.tone = "warning".to_owned();
        drop(status);
        cancellation.cancel();
    }

    fn restore_network(self: &Arc<Self>) -> Result<(), String> {
        {
            let mut status = self.lock_status();
            if status.running || status.restoring {
                return Err("disconnect before restoring the network".to_owned());
            }
            status.restoring = true;
            status.status = "Restoring network".to_owned();
            status.detail = "Removing retained leak protection...".to_owned();
            status.tone = "warning".to_owned();
        }
        let daemon = Arc::clone(self);
        tokio::spawn(async move {
            let result = client::cleanup_network(
                daemon.config.network_state.clone(),
                &CancellationToken::new(),
            )
            .await;
            let recovery = network_recovery(&daemon.config.network_state);
            let mut status = daemon.lock_status();
            status.restoring = false;
            status.recovery = recovery;
            match result {
                Ok(()) => {
                    status.status = "Disconnected".to_owned();
                    status.detail = "Normal network access is restored.".to_owned();
                    status.tone = "offline".to_owned();
                    add_activity(&mut status.activity, "Restored normal network access");
                }
                Err(error) => {
                    status.status = "Restore failed".to_owned();
                    status.detail = error.to_string();
                    status.tone = "danger".to_owned();
                    let line = format!("Network restore failed: {error}");
                    add_activity(&mut status.activity, &line);
                }
            }
        });
        Ok(())
    }
}

fn reset_connection(status: &mut Status) {
    status.address.clear();
    status.transport.clear();
    status.mtu = 0;
    status.connected_at.clear();
    status.bytes_uploaded = 0;
    status.bytes_downloaded = 0;
    status.upload_rate = 0;
    status.download_rate = 0;
    status.last_sample = None;
    status.account = AccountStatus::default();
    status.routing = Routing::default();
    status.direct_peers.clear();
}

fn update_rates(status: &mut Status, uploaded: u64, downloaded: u64) {
    let now = Instant::now();
    if let Some((previous, last_uploaded, last_downloaded)) = status.last_sample {
        let elapsed = now.duration_since(previous).as_secs_f64();
        if elapsed > 0.0 {
            status.upload_rate = (uploaded.saturating_sub(last_uploaded) as f64 / elapsed) as u64;
            status.download_rate =
                (downloaded.saturating_sub(last_downloaded) as f64 / elapsed) as u64;
        }
    }
    status.last_sample = Some((now, uploaded, downloaded));
    status.bytes_uploaded = uploaded;
    status.bytes_downloaded = downloaded;
}

fn add_activity(activity: &mut Vec<String>, message: &str) {
    let message = message
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    let message = message.trim();
    if message.is_empty() {
        return;
    }
    activity.push(format!("{}  {message}", local_clock()));
    if activity.len() > MAX_ACTIVITY_LINES {
        activity.drain(..activity.len() - MAX_ACTIVITY_LINES);
    }
}

/// The local wall-clock time as `HH:MM:SS`.
fn local_clock() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs()) as libc::time_t;
    // SAFETY: localtime_r writes only into the provided zeroed struct.
    let mut parts: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&seconds, &mut parts) }.is_null() {
        return "--:--:--".to_owned();
    }
    format!(
        "{:02}:{:02}:{:02}",
        parts.tm_hour, parts.tm_min, parts.tm_sec
    )
}

/// An RFC 3339 UTC timestamp.
fn rfc3339(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let days = (seconds / 86_400) as i64;
    let remainder = seconds % 86_400;
    // Civil date from days since the epoch (Howard Hinnant's algorithm).
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        remainder / 3600,
        remainder % 3600 / 60,
        remainder % 60
    )
}

fn parse_origin(value: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|error| format!("invalid server URL: {error}"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("server URL must be an HTTPS origin".to_owned());
    }
    Ok(url)
}

fn random_id() -> String {
    let mut bytes = [0_u8; 12];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Whether a retained fail-closed guard can be restored.
fn network_recovery(path: &Path) -> bool {
    path.exists()
}

fn load_store(path: &Path) -> Result<StoreFile, RunError> {
    let invalid =
        |message: String| RunError::Invalid(format!("profile store {}: {message}", path.display()));
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(StoreFile {
                version: STORE_VERSION,
                ..StoreFile::default()
            })
        }
        Err(error) => return Err(invalid(error.to_string())),
    };
    let metadata = file
        .metadata()
        .map_err(|error| invalid(error.to_string()))?;
    if metadata.len() > MAX_STORE_SIZE {
        return Err(invalid("is too large".to_owned()));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(invalid("must not be readable by other users".to_owned()));
    }
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .map_err(|error| invalid(error.to_string()))?;
    let store: StoreFile =
        serde_json::from_slice(&data).map_err(|error| invalid(error.to_string()))?;
    if store.version != STORE_VERSION {
        return Err(invalid(format!(
            "has unsupported version {}",
            store.version
        )));
    }
    Ok(store)
}

fn persist_store(path: &Path, store: &StoreFile) -> std::io::Result<()> {
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(directory)?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    let mut data = serde_json::to_vec_pretty(store).map_err(std::io::Error::other)?;
    data.push(b'\n');
    let pending = directory.join(format!(".profiles-{}.tmp", random_id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&pending)?;
        file.write_all(&data)?;
        file.sync_all()?;
        fs::rename(&pending, path)?;
        File::open(directory)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&pending);
    }
    result
}

/// Binds the control socket: owner root, and the control group's members
/// may connect when a group is configured.
fn bind_control_socket(path: &Path, group: Option<&str>) -> Result<UnixListener, RunError> {
    let invalid = |message: String| {
        RunError::Invalid(format!("control socket {}: {message}", path.display()))
    };
    if let Some(directory) = path.parent() {
        fs::create_dir_all(directory).map_err(|error| invalid(error.to_string()))?;
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if std::os::unix::fs::FileTypeExt::is_socket(&metadata.file_type()) => {
            fs::remove_file(path).map_err(|error| invalid(error.to_string()))?;
        }
        Ok(_) => return Err(invalid("exists and is not a socket".to_owned())),
        Err(_) => {}
    }
    let gid = match group {
        Some(group) => {
            Some(group_id(group).ok_or_else(|| invalid(format!("group {group} does not exist")))?)
        }
        None => None,
    };
    let listener = UnixListener::bind(path).map_err(|error| invalid(error.to_string()))?;
    if let Some(gid) = gid {
        std::os::unix::fs::chown(path, Some(0), Some(gid))
            .map_err(|error| invalid(error.to_string()))?;
    }
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if gid.is_some() { 0o660 } else { 0o600 }),
    )
    .map_err(|error| invalid(error.to_string()))?;
    Ok(listener)
}

/// The numeric ID of a group from /etc/group.
fn group_id(name: &str) -> Option<u32> {
    let groups = fs::read_to_string("/etc/group").ok()?;
    groups.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == name).then_some(())?;
        fields.nth(1)?.parse().ok()
    })
}

/// Sends one request to a daemon and returns its snapshot, for the desktop
/// app and tests.
pub async fn request(
    socket: &Path,
    request: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let stream = UnixStream::connect(socket).await.map_err(|error| {
        format!(
            "cannot reach the Porta service at {}: {error}",
            socket.display()
        )
    })?;
    let (reader, mut writer) = stream.into_split();
    let mut line = serde_json::to_vec(request).map_err(|error| error.to_string())?;
    line.push(b'\n');
    writer
        .write_all(&line)
        .await
        .map_err(|error| error.to_string())?;
    let mut reader = BufReader::new(reader);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .await
        .map_err(|error| error.to_string())?;
    let mut response: HashMap<String, serde_json::Value> = serde_json::from_str(&response)
        .map_err(|error| format!("invalid service response: {error}"))?;
    if let Some(error) = response.remove("error") {
        return Err(error.as_str().unwrap_or("Porta service error").to_owned());
    }
    response
        .remove("snapshot")
        .ok_or_else(|| "Porta service response has no snapshot".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn timestamps_are_rfc3339_utc() {
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        assert_eq!(
            rfc3339(UNIX_EPOCH + Duration::from_secs(1_795_000_000)),
            "2026-11-18T11:06:40Z"
        );
        assert_eq!(
            rfc3339(UNIX_EPOCH + Duration::from_secs(951_782_400)),
            "2000-02-29T00:00:00Z"
        );
    }

    #[tokio::test]
    async fn profiles_are_managed_over_the_control_socket() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("control.sock");
        let profiles = directory.path().join("state/profiles.json");
        let cancellation = CancellationToken::new();
        let daemon = tokio::spawn({
            let config = DaemonConfig {
                control_socket: socket.clone(),
                profiles: profiles.clone(),
                network_state: directory.path().join("network.json"),
                identity_path: None,
                interface_name: "porta0".to_owned(),
                group: None,
                ca_path: None,
                thumbprint: None,
            };
            let cancellation = cancellation.clone();
            async move { run(config, &cancellation).await }
        });
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let snapshot = request(&socket, &json!({"command": "snapshot"}))
            .await
            .unwrap();
        assert_eq!(snapshot["platform"], "linux");
        assert_eq!(snapshot["status"], "Disconnected");
        assert!(snapshot["profiles"].as_array().unwrap().is_empty());

        let error = request(
            &socket,
            &json!({"command": "save_profile", "input": {"name": "Home", "serverUrl": "https://vpn.example.com"}}),
        )
        .await
        .unwrap_err();
        assert_eq!(error, "token is required for a new profile");
        let snapshot = request(
            &socket,
            &json!({"command": "save_profile", "input": {
                "name": "Home", "serverUrl": "https://vpn.example.com",
                "backupServers": ["https://backup.example.com", " "], "transport": "h3",
                "token": "token-0123456789abcdef"}}),
        )
        .await
        .unwrap();
        let profile = &snapshot["profiles"][0];
        assert_eq!(profile["name"], "Home");
        assert_eq!(
            profile["backupServers"],
            json!(["https://backup.example.com"])
        );
        assert_eq!(profile["selected"], true);
        assert!(profile.get("token").is_none());
        let id = profile["id"].as_str().unwrap().to_owned();
        assert_eq!(
            fs::metadata(&profiles).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(fs::read_to_string(&profiles)
            .unwrap()
            .contains("token-0123456789abcdef"));

        // Editing without a token keeps it; invalid input is refused.
        request(
            &socket,
            &json!({"command": "save_profile", "input": {"id": id, "name": "Work",
                "serverUrl": "https://vpn.example.com"}}),
        )
        .await
        .unwrap();
        assert!(fs::read_to_string(&profiles)
            .unwrap()
            .contains("token-0123456789abcdef"));
        for input in [
            json!({"name": "x", "serverUrl": "http://vpn.example.com", "token": "t"}),
            json!({"name": "", "serverUrl": "https://vpn.example.com", "token": "t"}),
            json!({"name": "x", "serverUrl": "https://vpn.example.com", "transport": "udp", "token": "t"}),
        ] {
            assert!(
                request(&socket, &json!({"command": "save_profile", "input": input}))
                    .await
                    .is_err()
            );
        }
        assert!(request(&socket, &json!({"command": "unknown"}))
            .await
            .is_err());

        let snapshot = request(&socket, &json!({"command": "delete_profile", "id": id}))
            .await
            .unwrap();
        assert!(snapshot["profiles"].as_array().unwrap().is_empty());
        assert!(snapshot["activity"]
            .as_array()
            .unwrap()
            .iter()
            .any(|line| line.as_str().unwrap().ends_with("Deleted profile Work")));
        cancellation.cancel();
        daemon.await.unwrap().unwrap();
        assert!(!socket.exists());
    }
}
