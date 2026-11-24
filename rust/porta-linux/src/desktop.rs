//! The Linux desktop window and tray. The root `porta-client --daemon`
//! service owns profiles and the tunnel, so closing or quitting the app
//! leaves the connection to the service.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tauri::menu::MenuBuilder;
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter as _, Manager as _, State, WindowEvent};

use crate::control;

const POLL_INTERVAL: Duration = Duration::from_secs(1);

struct Desktop {
    socket: PathBuf,
    last: Mutex<Option<Value>>,
}

impl Desktop {
    fn call(&self, app: &AppHandle, request: Value) -> Result<Value, String> {
        let snapshot = control::request(&self.socket, &request)?;
        self.publish(app, snapshot.clone());
        Ok(snapshot)
    }

    fn current(&self) -> Value {
        control::request(&self.socket, &json!({"command": "snapshot"}))
            .unwrap_or_else(|error| control::unavailable_snapshot(&error))
    }

    /// Sends a changed snapshot to the window, and traffic every time.
    fn publish(&self, app: &AppHandle, snapshot: Value) {
        let traffic = json!({
            "bytesUploaded": snapshot["bytesUploaded"],
            "bytesDownloaded": snapshot["bytesDownloaded"],
            "uploadRate": snapshot["uploadRate"],
            "downloadRate": snapshot["downloadRate"],
        });
        let changed = {
            let mut last = self
                .last
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let changed = last
                .as_ref()
                .is_none_or(|previous| without_traffic(previous) != without_traffic(&snapshot));
            *last = Some(snapshot.clone());
            changed
        };
        if changed {
            if let Some(tray) = app.tray_by_id("porta") {
                let status = snapshot["status"].as_str().unwrap_or("Disconnected");
                let _ = tray.set_tooltip(Some(format!("Porta - {status}")));
            }
            let _ = app.emit("porta:snapshot", snapshot);
        }
        let _ = app.emit("porta:traffic", traffic);
    }
}

fn without_traffic(snapshot: &Value) -> Value {
    let mut snapshot = snapshot.clone();
    if let Some(object) = snapshot.as_object_mut() {
        for key in [
            "bytesUploaded",
            "bytesDownloaded",
            "uploadRate",
            "downloadRate",
        ] {
            object.remove(key);
        }
    }
    snapshot
}

#[tauri::command(async)]
fn snapshot(desktop: State<'_, Arc<Desktop>>) -> Value {
    desktop.current()
}

#[tauri::command(async)]
fn select_profile(
    app: AppHandle,
    desktop: State<'_, Arc<Desktop>>,
    id: String,
) -> Result<Value, String> {
    desktop.call(&app, json!({"command": "select_profile", "id": id}))
}

#[tauri::command(async)]
fn save_profile(
    app: AppHandle,
    desktop: State<'_, Arc<Desktop>>,
    input: Value,
) -> Result<Value, String> {
    desktop.call(&app, json!({"command": "save_profile", "input": input}))
}

#[tauri::command(async)]
fn delete_profile(
    app: AppHandle,
    desktop: State<'_, Arc<Desktop>>,
    id: String,
) -> Result<Value, String> {
    desktop.call(&app, json!({"command": "delete_profile", "id": id}))
}

#[tauri::command(async)]
fn connect(app: AppHandle, desktop: State<'_, Arc<Desktop>>, id: String) -> Result<(), String> {
    desktop
        .call(&app, json!({"command": "connect", "id": id}))
        .map(|_| ())
}

#[tauri::command(async)]
fn disconnect(app: AppHandle, desktop: State<'_, Arc<Desktop>>) -> Result<(), String> {
    desktop
        .call(&app, json!({"command": "disconnect"}))
        .map(|_| ())
}

#[tauri::command(async)]
fn restore_network(app: AppHandle, desktop: State<'_, Arc<Desktop>>) -> Result<(), String> {
    desktop
        .call(&app, json!({"command": "restore_network"}))
        .map(|_| ())
}

#[tauri::command(async)]
fn sign_in_network(app: AppHandle, desktop: State<'_, Arc<Desktop>>) -> Result<(), String> {
    desktop
        .call(&app, json!({"command": "sign_in_network"}))
        .map(|_| ())
}

#[tauri::command(async)]
fn clear_activity(app: AppHandle, desktop: State<'_, Arc<Desktop>>) -> Result<(), String> {
    desktop
        .call(&app, json!({"command": "clear_activity"}))
        .map(|_| ())
}

#[tauri::command(async)]
fn save_activity_log(desktop: State<'_, Arc<Desktop>>) -> Result<String, String> {
    let directory = std::env::var_os("XDG_DOWNLOAD_DIR")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .ok_or_else(|| "cannot find a folder for the activity log".to_owned())?;
    control::save_activity(&directory, &desktop.current()).map(|path| path.display().to_string())
}

fn show_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn toggle(app: &AppHandle, desktop: &Desktop) {
    let snapshot = desktop.current();
    let request = if snapshot["running"].as_bool().unwrap_or(false) {
        json!({"command": "disconnect"})
    } else {
        json!({"command": "connect", "id": ""})
    };
    if let Err(error) = desktop.call(app, request) {
        show_window(app);
        let _ = app.emit("porta:error", error);
    }
}

/// Whether a tray library is installed: without one the tray cannot be
/// created, and the window then quits on close instead of hiding.
fn tray_available() -> bool {
    ["libayatana-appindicator3.so.1", "libappindicator3.so.1"]
        .iter()
        .any(|name| {
            let name = std::ffi::CString::new(*name).expect("library name has no NUL");
            // SAFETY: dlopen with a valid C string; the handle is released.
            let handle = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_LAZY) };
            if handle.is_null() {
                return false;
            }
            unsafe { libc::dlclose(handle) };
            true
        })
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let desktop = Arc::new(Desktop {
        socket: control::socket_path(),
        last: Mutex::new(None),
    });
    tauri::Builder::default()
        .manage(desktop.clone())
        .invoke_handler(tauri::generate_handler![
            snapshot,
            select_profile,
            save_profile,
            delete_profile,
            connect,
            disconnect,
            restore_network,
            sign_in_network,
            clear_activity,
            save_activity_log
        ])
        .setup(move |app| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_title(&format!("Porta {}", env!("CARGO_PKG_VERSION")));
            }
            let menu = MenuBuilder::new(app)
                .text("open", "Open Porta")
                .text("connect", "Connect / Disconnect")
                .separator()
                .text("quit", "Quit (the connection stays up)")
                .build()?;
            // Desktops without a status-notifier host have no tray; the
            // window still works.
            let tray = tray_available()
                .then(|| app.default_window_icon().cloned())
                .flatten()
                .map(|icon| {
                    TrayIconBuilder::with_id("porta")
                        .icon(icon)
                        .tooltip("Porta")
                        .menu(&menu)
                        .show_menu_on_left_click(false)
                        .on_menu_event(|app, event| {
                            let desktop = app.state::<Arc<Desktop>>().inner().clone();
                            match event.id().as_ref() {
                                "open" => show_window(app),
                                "connect" => toggle(app, &desktop),
                                "quit" => app.exit(0),
                                _ => {}
                            }
                        })
                        .on_tray_icon_event(|tray, event| {
                            if let TrayIconEvent::Click {
                                button: MouseButton::Left,
                                button_state: MouseButtonState::Up,
                                ..
                            } = event
                            {
                                show_window(tray.app_handle());
                            }
                        })
                        .build(app)
                });
            let has_tray = matches!(tray, Some(Ok(_)));
            if let Some(Err(error)) = tray {
                eprintln!("porta-desktop: no tray icon: {error}");
            }
            if let Some(window) = app.get_webview_window("main") {
                let hidden = window.clone();
                window.on_window_event(move |event| {
                    if let WindowEvent::CloseRequested { api, .. } = event {
                        if has_tray {
                            api.prevent_close();
                            let _ = hidden.hide();
                        }
                    }
                });
            }
            let handle = app.handle().clone();
            let poller = desktop.clone();
            std::thread::spawn(move || loop {
                poller.publish(&handle, poller.current());
                std::thread::sleep(POLL_INTERVAL);
            });
            Ok(())
        })
        .run(tauri::generate_context!())?;
    Ok(())
}
