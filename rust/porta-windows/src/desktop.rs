use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::windows::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{Local, SecondsFormat, Utc};
use porta_client::tls;
use porta_client::tunnel::Transport;
use porta_client::windows::client::{self, Event};
use porta_client::windows::network::NetworkManager;
use porta_client::windows::paths;
use porta_client::windows::profiles::{Profile, Store};
use serde::{Deserialize, Serialize};
use tauri::menu::MenuBuilder;
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter as _, Manager as _, State, WindowEvent};
use tokio_util::sync::CancellationToken;
use url::Url;
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

const MAX_ACTIVITY_LINES: usize = 200;
const NETWORK_ACTION_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileInput {
    id: String,
    name: String,
    server_url: String,
    transport: String,
    token: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopProfile {
    id: String,
    name: String,
    server_url: String,
    transport: String,
    selected: bool,
    active: bool,
    status: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopSnapshot {
    version: String,
    profiles: Vec<DesktopProfile>,
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
    activity: Vec<String>,
}

struct DesktopState {
    selected_id: String,
    active_id: String,
    cancellation: Option<CancellationToken>,
    running: bool,
    connected: bool,
    disconnecting: bool,
    restoring: bool,
    quitting: bool,
    recovery: bool,
    startup_blocked: bool,
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
    last_sample_at: Option<Instant>,
    last_uploaded: u64,
    last_downloaded: u64,
    activity: Vec<String>,
}

struct Controller {
    store: Store,
    network_state: PathBuf,
    log_path: PathBuf,
    startup_error: Option<String>,
    state: Mutex<DesktopState>,
    log_lock: Mutex<()>,
}

impl Controller {
    fn new(
        store: Store,
        network_state: PathBuf,
        log_path: PathBuf,
        startup_error: Option<String>,
    ) -> Result<Self, String> {
        let profiles = store.list().map_err(|error| error.to_string())?;
        let selected_id = profiles
            .first()
            .map_or(String::new(), |profile| profile.id.clone());
        let recovery = if startup_error.is_none() {
            NetworkManager::open(network_state.clone())
                .map_err(|error| error.to_string())?
                .needs_cleanup()
        } else {
            false
        };
        let (status, detail, tone) = if let Some(error) = startup_error.as_ref() {
            (
                "Action required".to_owned(),
                error.clone(),
                "danger".to_owned(),
            )
        } else if recovery {
            (
                "Network recovery available".to_owned(),
                "Reconnect to resume, or restore normal connectivity.".to_owned(),
                "warning".to_owned(),
            )
        } else if profiles.is_empty() {
            (
                "Disconnected".to_owned(),
                "Add a profile to connect securely.".to_owned(),
                "offline".to_owned(),
            )
        } else {
            (
                "Ready".to_owned(),
                "Choose a profile to connect securely.".to_owned(),
                "offline".to_owned(),
            )
        };
        let mut activity = load_activity(&log_path);
        if recovery {
            push_activity(
                &mut activity,
                "Retained network protection is ready for recovery.",
            );
        }
        if let Some(error) = startup_error.as_deref() {
            push_activity(&mut activity, &format!("Startup blocked: {error}"));
        }
        let startup_blocked = startup_error.is_some();
        Ok(Self {
            store,
            network_state,
            log_path,
            startup_error,
            state: Mutex::new(DesktopState {
                selected_id,
                active_id: String::new(),
                cancellation: None,
                running: false,
                connected: false,
                disconnecting: false,
                restoring: false,
                quitting: false,
                recovery,
                startup_blocked,
                status,
                detail,
                tone,
                address: String::new(),
                transport: String::new(),
                mtu: 0,
                connected_at: String::new(),
                bytes_uploaded: 0,
                bytes_downloaded: 0,
                upload_rate: 0,
                download_rate: 0,
                last_sample_at: None,
                last_uploaded: 0,
                last_downloaded: 0,
                activity,
            }),
            log_lock: Mutex::new(()),
        })
    }

    fn snapshot(&self) -> Result<DesktopSnapshot, String> {
        let profiles = self.store.list().map_err(|error| error.to_string())?;
        let state = self
            .state
            .lock()
            .map_err(|_| "desktop state lock is poisoned".to_owned())?;
        Ok(snapshot_from(&state, profiles))
    }

    fn ensure_operational(&self) -> Result<(), String> {
        match self.startup_error.as_ref() {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }

    fn publish(&self, app: &AppHandle) {
        let Ok(snapshot) = self.snapshot() else {
            return;
        };
        let _ = app.emit("porta:snapshot", snapshot.clone());
        if let Some(tray) = app.tray_by_id("porta") {
            let _ = tray.set_tooltip(Some(format!("Porta - {}", snapshot.status)));
        }
    }

    fn select_profile(&self, app: &AppHandle, id: &str) -> Result<DesktopSnapshot, String> {
        self.ensure_operational()?;
        let profile = self.profile(id)?;
        {
            let mut state = self.lock_state()?;
            if state.running && id != state.active_id {
                return Err("disconnect the active profile before selecting another one".to_owned());
            }
            state.selected_id = id.to_owned();
            if !state.running && !state.restoring {
                state.status = "Ready".to_owned();
                state.detail = format!("{} - {}", profile.name, profile.server_url);
                state.tone = "offline".to_owned();
            }
        }
        self.publish(app);
        self.snapshot()
    }

    fn save_profile(
        &self,
        app: &AppHandle,
        input: ProfileInput,
    ) -> Result<DesktopSnapshot, String> {
        self.ensure_operational()?;
        {
            let state = self.lock_state()?;
            if state.running || state.restoring {
                return Err("profiles cannot be changed while Porta is busy".to_owned());
            }
        }
        let name = input.name.trim();
        let server_url = input.server_url.trim();
        parse_origin(server_url)?;
        let transport = parse_transport(input.transport.trim())?;
        let mut profile = if input.id.trim().is_empty() {
            Profile::new(name, server_url, transport)
        } else {
            let mut profile = self.profile(input.id.trim())?;
            profile.name = name.to_owned();
            profile.server_url = server_url.to_owned();
            profile.transport = transport;
            profile
        };
        profile.id = input.id.trim().to_owned();
        let saved = self
            .store
            .save(profile, input.token.trim())
            .map_err(|error| error.to_string())?;
        let line;
        {
            let mut state = self.lock_state()?;
            state.selected_id = saved.id.clone();
            state.status = "Ready".to_owned();
            state.detail = format!("{} - {}", saved.name, saved.server_url);
            state.tone = "offline".to_owned();
            line = add_activity(&mut state, &format!("Saved profile {}", saved.name));
        }
        self.write_activity(line);
        self.publish(app);
        self.snapshot()
    }

    fn delete_profile(&self, app: &AppHandle, id: &str) -> Result<DesktopSnapshot, String> {
        self.ensure_operational()?;
        {
            let state = self.lock_state()?;
            if state.running || state.restoring {
                return Err("profiles cannot be deleted while Porta is busy".to_owned());
            }
        }
        let profile = self.profile(id)?;
        self.store.delete(id).map_err(|error| error.to_string())?;
        let profiles = self.store.list().map_err(|error| error.to_string())?;
        let line;
        {
            let mut state = self.lock_state()?;
            state.selected_id = profiles
                .first()
                .map_or(String::new(), |profile| profile.id.clone());
            if let Some(first) = profiles.first() {
                state.status = "Ready".to_owned();
                state.detail = format!("{} - {}", first.name, first.server_url);
            } else {
                state.status = "Disconnected".to_owned();
                state.detail = "Add a profile to connect securely.".to_owned();
            }
            state.tone = "offline".to_owned();
            line = add_activity(&mut state, &format!("Deleted profile {}", profile.name));
        }
        self.write_activity(line);
        self.publish(app);
        self.snapshot()
    }

    fn connect(self: &Arc<Self>, app: &AppHandle, id: &str) -> Result<(), String> {
        self.ensure_operational()?;
        let selected = if id.trim().is_empty() {
            self.lock_state()?.selected_id.clone()
        } else {
            id.trim().to_owned()
        };
        let profile = self.profile(&selected)?;
        let token = self
            .store
            .token(&profile.id)
            .map_err(|error| error.to_string())?;
        let cancellation = CancellationToken::new();
        let line;
        {
            let mut state = self.lock_state()?;
            if state.running || state.restoring {
                return Err("Porta is already connecting or restoring the network".to_owned());
            }
            state.selected_id = profile.id.clone();
            state.active_id = profile.id.clone();
            state.cancellation = Some(cancellation.clone());
            state.running = true;
            state.connected = false;
            state.disconnecting = false;
            state.status = "Connecting".to_owned();
            state.detail = "Establishing a secure tunnel...".to_owned();
            state.tone = "warning".to_owned();
            reset_connection(&mut state);
            line = add_activity(
                &mut state,
                &format!("Connecting {} to {}", profile.name, profile.server_url),
            );
        }
        self.write_activity(line);
        self.publish(app);

        let controller = Arc::clone(self);
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            controller
                .run_connection(app, profile, token, cancellation)
                .await;
        });
        Ok(())
    }

    fn disconnect(&self, app: &AppHandle) -> Result<(), String> {
        self.ensure_operational()?;
        let cancellation = {
            let mut state = self.lock_state()?;
            if state.restoring {
                return Err("network restoration is already in progress".to_owned());
            }
            let Some(cancellation) = state.cancellation.clone() else {
                return Ok(());
            };
            state.disconnecting = true;
            state.status = "Disconnecting".to_owned();
            state.detail = "Restoring normal network access...".to_owned();
            state.tone = "warning".to_owned();
            cancellation
        };
        self.publish(app);
        cancellation.cancel();
        Ok(())
    }

    fn toggle(self: &Arc<Self>, app: &AppHandle) -> Result<(), String> {
        let (running, selected) = {
            let state = self.lock_state()?;
            (state.running, state.selected_id.clone())
        };
        if running {
            self.disconnect(app)
        } else {
            self.connect(app, &selected)
        }
    }

    async fn run_connection(
        self: Arc<Self>,
        app: AppHandle,
        profile: Profile,
        token: String,
        cancellation: CancellationToken,
    ) {
        let result = async {
            let server = parse_origin(&profile.server_url)?;
            let ca_path = (!profile.ca_path.is_empty()).then(|| Path::new(&profile.ca_path));
            let thumbprint =
                (!profile.thumbprint.is_empty()).then_some(profile.thumbprint.as_str());
            let tls = tls::config(ca_path, thumbprint, false).map_err(|error| error.to_string())?;
            let observer_controller = Arc::clone(&self);
            let observer_app = app.clone();
            match client::run(
                client::Config {
                    server,
                    token,
                    tls,
                    transport: profile.transport,
                    interface_name: "Porta".to_owned(),
                    network_state_path: self.network_state.clone(),
                    wintun_path: None,
                    manual_network: false,
                    reconnect: profile.reconnect,
                    connect_timeout: Duration::from_secs(15),
                    reconnect_max_delay: profile.reconnect_max_delay,
                },
                cancellation,
                Arc::new(move |event| {
                    observer_controller.handle_connection_event(&observer_app, event);
                }),
            )
            .await
            {
                Ok(()) | Err(client::RunError::Cancelled) => Ok(()),
                Err(error) => Err(error.to_string()),
            }
        }
        .await;

        let recovery = network_recovery(&self.network_state).unwrap_or(true);
        let line;
        let should_exit;
        {
            let mut state = match self.lock_state() {
                Ok(state) => state,
                Err(_) => return,
            };
            state.running = false;
            state.connected = false;
            state.disconnecting = false;
            state.cancellation = None;
            state.active_id.clear();
            state.recovery = recovery;
            reset_connection(&mut state);
            should_exit = state.quitting && result.is_ok() && !recovery;
            if let Err(error) = result {
                state.quitting = false;
                state.status = "Connection error".to_owned();
                state.detail = error.clone();
                state.tone = "danger".to_owned();
                line = add_activity(&mut state, &format!("Connection error: {error}"));
            } else {
                state.status = "Disconnected".to_owned();
                state.detail = "Choose a profile to reconnect securely.".to_owned();
                state.tone = "offline".to_owned();
                line = add_activity(&mut state, "Disconnected");
            }
        }
        self.write_activity(line);
        self.publish(&app);
        if should_exit {
            app.exit(0);
        } else if self.lock_state().is_ok_and(|state| state.quitting) {
            if let Ok(mut state) = self.lock_state() {
                state.quitting = false;
            }
            show_window(&app);
        }
    }

    fn handle_connection_event(&self, app: &AppHandle, event: Event) {
        let activity;
        {
            let mut state = match self.lock_state() {
                Ok(state) => state,
                Err(_) => return,
            };
            activity = match event {
                Event::RecoveringNetwork => {
                    state.status = "Recovering network".to_owned();
                    state.detail = "Resuming retained fail-closed protection...".to_owned();
                    state.tone = "warning".to_owned();
                    add_activity(&mut state, "Recovering retained network protection")
                }
                Event::Connecting {
                    attempt,
                    remote_address,
                } => {
                    state.status = "Connecting".to_owned();
                    state.detail = format!("Secure endpoint {remote_address}");
                    state.tone = "warning".to_owned();
                    add_activity(&mut state, &format!("Connection attempt {attempt}"))
                }
                Event::ConfiguringNetwork => {
                    state.status = "Configuring network".to_owned();
                    state.detail = "Applying private routes, DNS, and tunnel MTU...".to_owned();
                    state.tone = "warning".to_owned();
                    add_activity(&mut state, "Configuring fail-closed network")
                }
                Event::Connected(info) => {
                    state.status = "Connected".to_owned();
                    state.detail = match info.transport {
                        Transport::Http3 => format!(
                            "HTTP/3 MASQUE - fast and resilient - MTU {}",
                            info.lease.mtu
                        ),
                        Transport::Http2 => format!(
                            "4-lane HTTP/2 fallback - encrypted - MTU {}",
                            info.lease.mtu
                        ),
                        Transport::Auto => {
                            format!("Encrypted tunnel active - MTU {}", info.lease.mtu)
                        }
                    };
                    state.tone = "connected".to_owned();
                    state.connected = true;
                    state.address = info.lease.address.to_string();
                    state.transport = transport_name(info.transport).to_owned();
                    state.mtu = info.lease.mtu;
                    state.connected_at = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);
                    add_activity(
                        &mut state,
                        &format!(
                            "Connected over {} to {}",
                            transport_name(info.transport),
                            info.remote_address
                        ),
                    )
                }
                Event::Progress {
                    uploaded_bytes,
                    downloaded_bytes,
                } => {
                    update_rates(&mut state, uploaded_bytes, downloaded_bytes);
                    None
                }
                Event::Reconnecting { reason, delay } => {
                    state.status = "Reconnecting".to_owned();
                    state.detail = "The network changed; restoring the secure tunnel...".to_owned();
                    state.tone = "warning".to_owned();
                    state.connected = false;
                    add_activity(
                        &mut state,
                        &format!(
                            "Reconnecting in {}: {reason}",
                            humantime::format_duration(delay)
                        ),
                    )
                }
                Event::Stopping => {
                    state.status = "Disconnecting".to_owned();
                    state.detail = "Restoring normal network access...".to_owned();
                    state.tone = "warning".to_owned();
                    add_activity(&mut state, "Stopping tunnel")
                }
            };
        }
        if let Some(line) = activity {
            self.write_activity(Some(line));
        }
        self.publish(app);
    }

    fn restore_network(self: &Arc<Self>, app: &AppHandle, exit_after: bool) -> Result<(), String> {
        self.ensure_operational()?;
        {
            let mut state = self.lock_state()?;
            if state.running {
                return Err("disconnect before restoring retained network state".to_owned());
            }
            if state.restoring {
                return Err("network restoration is already in progress".to_owned());
            }
            state.restoring = true;
            state.status = "Restoring network".to_owned();
            state.detail = "Removing retained routes and leak protection...".to_owned();
            state.tone = "warning".to_owned();
        }
        self.publish(app);
        let controller = Arc::clone(self);
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            let result = async {
                let mut network = NetworkManager::open(controller.network_state.clone())
                    .map_err(|error| error.to_string())?;
                tokio::time::timeout(NETWORK_ACTION_TIMEOUT, network.down())
                    .await
                    .map_err(|_| "network restoration timed out".to_owned())?
                    .map_err(|error| error.to_string())
            }
            .await;
            let recovery = network_recovery(&controller.network_state).unwrap_or(true);
            let line;
            let should_exit;
            {
                let mut state = match controller.lock_state() {
                    Ok(state) => state,
                    Err(_) => return,
                };
                state.restoring = false;
                state.recovery = recovery;
                should_exit = exit_after && state.quitting && result.is_ok() && !recovery;
                match result {
                    Ok(()) if !recovery => {
                        state.status = "Disconnected".to_owned();
                        state.detail = "Normal network access has been restored.".to_owned();
                        state.tone = "offline".to_owned();
                        line = add_activity(
                            &mut state,
                            "Restored network and removed retained protection.",
                        );
                    }
                    Ok(()) => {
                        state.quitting = false;
                        state.status = "Network recovery failed".to_owned();
                        state.detail = "Network recovery remains pending.".to_owned();
                        state.tone = "danger".to_owned();
                        line = add_activity(&mut state, "Network recovery remains pending.");
                    }
                    Err(error) => {
                        state.quitting = false;
                        state.status = "Network recovery failed".to_owned();
                        state.detail = error.clone();
                        state.tone = "danger".to_owned();
                        line =
                            add_activity(&mut state, &format!("Network recovery failed: {error}"));
                    }
                }
            }
            controller.write_activity(line);
            controller.publish(&app);
            if should_exit {
                app.exit(0);
            } else if exit_after {
                show_window(&app);
            }
        });
        Ok(())
    }

    fn quit(self: &Arc<Self>, app: &AppHandle) {
        let action = {
            let mut state = match self.lock_state() {
                Ok(state) => state,
                Err(_) => return,
            };
            if state.quitting {
                return;
            }
            state.quitting = true;
            if state.running {
                state.disconnecting = true;
                state.status = "Disconnecting".to_owned();
                state.detail = "Restoring normal network access before exit...".to_owned();
                state.tone = "warning".to_owned();
                state
                    .cancellation
                    .clone()
                    .map_or(QuitAction::None, QuitAction::Cancel)
            } else if state.recovery {
                QuitAction::Restore
            } else {
                QuitAction::Exit
            }
        };
        self.publish(app);
        match action {
            QuitAction::Cancel(cancellation) => cancellation.cancel(),
            QuitAction::Restore => {
                if self.restore_network(app, true).is_err() {
                    if let Ok(mut state) = self.lock_state() {
                        state.quitting = false;
                    }
                    show_window(app);
                }
            }
            QuitAction::Exit => app.exit(0),
            QuitAction::None => {}
        }
    }

    fn clear_activity(&self, app: &AppHandle) -> Result<(), String> {
        let _log = self
            .log_lock
            .lock()
            .map_err(|_| "activity log lock is poisoned".to_owned())?;
        let rotated = self.log_path.with_extension("log.1");
        for path in [&self.log_path, &rotated] {
            if let Err(error) = fs::remove_file(path) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    return Err(error.to_string());
                }
            }
        }
        self.lock_state()?.activity.clear();
        self.publish(app);
        Ok(())
    }

    fn save_activity_log(&self) -> Result<String, String> {
        let activity = self.lock_state()?.activity.clone();
        if activity.is_empty() {
            return Ok(String::new());
        }
        let directory = self
            .log_path
            .parent()
            .ok_or_else(|| "activity log directory is unavailable".to_owned())?
            .join("exports");
        fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        let path = directory.join(format!(
            "porta-activity-{}.log",
            Local::now().format("%Y%m%d-%H%M%S-%3f")
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| error.to_string())?;
        for line in activity {
            writeln!(file, "{line}").map_err(|error| error.to_string())?;
        }
        file.sync_all().map_err(|error| error.to_string())?;
        Ok(path.display().to_string())
    }

    fn open_log_folder(&self) -> Result<String, String> {
        let directory = self
            .log_path
            .parent()
            .ok_or_else(|| "activity log directory is unavailable".to_owned())?;
        fs::create_dir_all(directory).map_err(|error| error.to_string())?;
        open_folder(directory)?;
        Ok(directory.display().to_string())
    }

    fn profile(&self, id: &str) -> Result<Profile, String> {
        self.store
            .list()
            .map_err(|error| error.to_string())?
            .into_iter()
            .find(|profile| profile.id == id)
            .ok_or_else(|| "profile not found".to_owned())
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, DesktopState>, String> {
        self.state
            .lock()
            .map_err(|_| "desktop state lock is poisoned".to_owned())
    }

    fn write_activity(&self, line: Option<String>) {
        let Some(line) = line else {
            return;
        };
        let Ok(_guard) = self.log_lock.lock() else {
            return;
        };
        let Some(directory) = self.log_path.parent() else {
            return;
        };
        if fs::create_dir_all(directory).is_err() {
            return;
        }
        if fs::metadata(&self.log_path).is_ok_and(|metadata| metadata.len() >= 1 << 20) {
            let rotated = self.log_path.with_extension("log.1");
            let _ = fs::remove_file(&rotated);
            let _ = fs::rename(&self.log_path, rotated);
        }
        let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
        else {
            return;
        };
        let _ = writeln!(
            file,
            "{} {line}",
            Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
        );
    }
}

enum QuitAction {
    Cancel(CancellationToken),
    Restore,
    Exit,
    None,
}

#[tauri::command]
fn snapshot(controller: State<'_, Arc<Controller>>) -> Result<DesktopSnapshot, String> {
    controller.snapshot()
}

#[tauri::command]
fn select_profile(
    app: AppHandle,
    controller: State<'_, Arc<Controller>>,
    id: String,
) -> Result<DesktopSnapshot, String> {
    controller.select_profile(&app, &id)
}

#[tauri::command]
fn save_profile(
    app: AppHandle,
    controller: State<'_, Arc<Controller>>,
    input: ProfileInput,
) -> Result<DesktopSnapshot, String> {
    controller.save_profile(&app, input)
}

#[tauri::command]
fn delete_profile(
    app: AppHandle,
    controller: State<'_, Arc<Controller>>,
    id: String,
) -> Result<DesktopSnapshot, String> {
    controller.delete_profile(&app, &id)
}

#[tauri::command]
fn connect(
    app: AppHandle,
    controller: State<'_, Arc<Controller>>,
    id: String,
) -> Result<(), String> {
    controller.inner().connect(&app, &id)
}

#[tauri::command]
fn disconnect(app: AppHandle, controller: State<'_, Arc<Controller>>) -> Result<(), String> {
    controller.disconnect(&app)
}

#[tauri::command]
fn restore_network(app: AppHandle, controller: State<'_, Arc<Controller>>) -> Result<(), String> {
    controller.inner().restore_network(&app, false)
}

#[tauri::command]
fn clear_activity(app: AppHandle, controller: State<'_, Arc<Controller>>) -> Result<(), String> {
    controller.clear_activity(&app)
}

#[tauri::command]
fn save_activity_log(controller: State<'_, Arc<Controller>>) -> Result<String, String> {
    controller.save_activity_log()
}

#[tauri::command]
fn open_log_folder(controller: State<'_, Arc<Controller>>) -> Result<String, String> {
    controller.open_log_folder()
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() == 1 && matches!(arguments[0].as_str(), "--version" | "-version") {
        println!("{}", porta_client::VERSION.trim());
        return Ok(());
    }
    let data_directory = paths::roaming_app_data()?.join("Porta");
    let (network_state, startup_error) = match paths::network_state_path() {
        Ok(path) => (path, None),
        Err(error) => (
            paths::current_network_state_path()?,
            Some(error.to_string()),
        ),
    };
    if arguments == ["--cleanup-network"] {
        if let Some(error) = startup_error.as_deref() {
            return Err(error.to_owned().into());
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let mut network = NetworkManager::open(network_state)?;
            network.down().await
        })?;
        return Ok(());
    }
    if !arguments.is_empty() {
        return Err("unsupported arguments; use --version or --cleanup-network".into());
    }
    fs::create_dir_all(&data_directory)?;
    let store = Store::open(data_directory.join("profiles.json"))?;
    let controller = Arc::new(Controller::new(
        store,
        network_state,
        data_directory.join("porta.log"),
        startup_error,
    )?);

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            show_window(app);
        }))
        .manage(controller)
        .invoke_handler(tauri::generate_handler![
            snapshot,
            select_profile,
            save_profile,
            delete_profile,
            connect,
            disconnect,
            restore_network,
            clear_activity,
            save_activity_log,
            open_log_folder
        ])
        .setup(|app| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_title(&format!("Porta {}", porta_client::VERSION.trim()));
            }
            let menu = MenuBuilder::new(app)
                .text("open", "Open Porta")
                .text("connect", "Connect or disconnect")
                .text("activity", "Activity")
                .text("restore", "Restore network")
                .separator()
                .text("quit", "Quit Porta")
                .build()?;
            let icon = app
                .default_window_icon()
                .cloned()
                .ok_or_else(|| std::io::Error::other("Porta window icon is unavailable"))?;
            TrayIconBuilder::with_id("porta")
                .icon(icon)
                .tooltip("Porta - Disconnected")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| {
                    let controller = app.state::<Arc<Controller>>().inner().clone();
                    match event.id().as_ref() {
                        "open" => show_window(app),
                        "connect" => {
                            if let Err(error) = controller.toggle(app) {
                                controller.record_error(app, "Connection action failed", &error);
                            }
                        }
                        "activity" => {
                            show_window(app);
                            let _ = app.emit("porta:view", "activity");
                        }
                        "restore" => {
                            if let Err(error) = controller.restore_network(app, false) {
                                controller.record_error(app, "Network recovery failed", &error);
                            }
                        }
                        "quit" => controller.quit(app),
                        _ => {}
                    }
                })
                .on_tray_icon_event(|tray, event| match event {
                    TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    }
                    | TrayIconEvent::DoubleClick {
                        button: MouseButton::Left,
                        ..
                    } => show_window(tray.app_handle()),
                    _ => {}
                })
                .build(app)?;
            let controller = app.state::<Arc<Controller>>();
            controller.publish(app.handle());
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())?;
    Ok(())
}

impl Controller {
    fn record_error(&self, app: &AppHandle, action: &str, error: &str) {
        let line = if let Ok(mut state) = self.lock_state() {
            state.status = action.to_owned();
            state.detail = error.to_owned();
            state.tone = "danger".to_owned();
            add_activity(&mut state, &format!("{action}: {error}"))
        } else {
            None
        };
        self.write_activity(line);
        self.publish(app);
    }
}

fn snapshot_from(state: &DesktopState, profiles: Vec<Profile>) -> DesktopSnapshot {
    let profiles = profiles
        .into_iter()
        .map(|profile| {
            let status = if profile.id == state.active_id {
                state.status.clone()
            } else if profile.id == state.selected_id {
                "Selected profile".to_owned()
            } else if profile.reconnect {
                "Auto reconnect enabled".to_owned()
            } else {
                "Ready".to_owned()
            };
            DesktopProfile {
                selected: profile.id == state.selected_id,
                active: profile.id == state.active_id && state.running,
                id: profile.id,
                name: profile.name,
                server_url: profile.server_url,
                transport: transport_name(profile.transport).to_owned(),
                status,
            }
        })
        .collect();
    DesktopSnapshot {
        version: porta_client::VERSION.trim().to_owned(),
        profiles,
        selected_profile_id: state.selected_id.clone(),
        active_profile_id: state.active_id.clone(),
        status: state.status.clone(),
        detail: state.detail.clone(),
        tone: state.tone.clone(),
        running: state.running,
        connected: state.connected,
        restoring: state.restoring,
        disconnecting: state.disconnecting,
        recovery_available: state.recovery,
        startup_blocked: state.startup_blocked,
        address: state.address.clone(),
        transport: state.transport.clone(),
        mtu: state.mtu,
        connected_at: state.connected_at.clone(),
        bytes_uploaded: state.bytes_uploaded,
        bytes_downloaded: state.bytes_downloaded,
        upload_rate: state.upload_rate,
        download_rate: state.download_rate,
        activity: state.activity.clone(),
    }
}

fn parse_transport(value: &str) -> Result<Transport, String> {
    match value {
        "" | "auto" => Ok(Transport::Auto),
        "h2" => Ok(Transport::Http2),
        "h3" => Ok(Transport::Http3),
        _ => Err("transport must be auto, h2, or h3".to_owned()),
    }
}

fn transport_name(value: Transport) -> &'static str {
    match value {
        Transport::Auto => "auto",
        Transport::Http2 => "h2",
        Transport::Http3 => "h3",
    }
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

fn reset_connection(state: &mut DesktopState) {
    state.address.clear();
    state.transport.clear();
    state.mtu = 0;
    state.connected_at.clear();
    state.bytes_uploaded = 0;
    state.bytes_downloaded = 0;
    state.upload_rate = 0;
    state.download_rate = 0;
    state.last_sample_at = None;
    state.last_uploaded = 0;
    state.last_downloaded = 0;
}

fn update_rates(state: &mut DesktopState, uploaded: u64, downloaded: u64) {
    let now = Instant::now();
    if let Some(previous) = state.last_sample_at {
        let elapsed = now.duration_since(previous).as_secs_f64();
        if elapsed > 0.0 {
            if uploaded >= state.last_uploaded {
                state.upload_rate = ((uploaded - state.last_uploaded) as f64 / elapsed) as u64;
            }
            if downloaded >= state.last_downloaded {
                state.download_rate =
                    ((downloaded - state.last_downloaded) as f64 / elapsed) as u64;
            }
        }
    }
    state.last_sample_at = Some(now);
    state.last_uploaded = uploaded;
    state.last_downloaded = downloaded;
    state.bytes_uploaded = uploaded;
    state.bytes_downloaded = downloaded;
}

fn add_activity(state: &mut DesktopState, message: &str) -> Option<String> {
    let message = message.trim();
    if message.is_empty() {
        return None;
    }
    let line = format!("{}  {message}", Local::now().format("%H:%M:%S"));
    state.activity.push(line.clone());
    if state.activity.len() > MAX_ACTIVITY_LINES {
        state
            .activity
            .drain(..state.activity.len() - MAX_ACTIVITY_LINES);
    }
    Some(line)
}

fn push_activity(activity: &mut Vec<String>, message: &str) {
    let line = format!("{}  {}", Local::now().format("%H:%M:%S"), message.trim());
    activity.push(line);
    if activity.len() > MAX_ACTIVITY_LINES {
        activity.drain(..activity.len() - MAX_ACTIVITY_LINES);
    }
}

fn load_activity(path: &Path) -> Vec<String> {
    let Ok(contents) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut lines = contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if lines.len() > MAX_ACTIVITY_LINES {
        lines.drain(..lines.len() - MAX_ACTIVITY_LINES);
    }
    lines
}

fn network_recovery(path: &Path) -> Result<bool, String> {
    NetworkManager::open(path.to_owned())
        .map(|network| network.needs_cleanup())
        .map_err(|error| error.to_string())
}

fn show_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn open_folder(path: &Path) -> Result<(), String> {
    let operation = wide("open");
    let path = wide_os(path);
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            path.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    if result as isize <= 32 {
        return Err(format!(
            "open activity log directory failed ({})",
            result as isize
        ));
    }
    Ok(())
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_os(value: &Path) -> Vec<u16> {
    value
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
