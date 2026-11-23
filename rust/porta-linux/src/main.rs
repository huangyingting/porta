//! Porta for the Linux desktop: a window and tray icon in front of the
//! `porta-client --daemon` service, which runs as root and owns networking.

mod control;
#[cfg(all(target_os = "linux", feature = "gui"))]
mod desktop;

#[cfg(all(target_os = "linux", feature = "gui"))]
fn main() {
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if let Err(error) = desktop::run() {
        eprintln!("porta-desktop: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(all(target_os = "linux", feature = "gui")))]
fn main() {
    // Without the window, report what the service is doing.
    let socket = control::socket_path();
    match control::request(&socket, &serde_json::json!({"command": "snapshot"})) {
        Ok(snapshot) => println!(
            "{}: {}",
            snapshot["status"].as_str().unwrap_or("unknown"),
            snapshot["detail"].as_str().unwrap_or_default()
        ),
        Err(error) => {
            eprintln!(
                "porta-desktop: {error} (this build has no window; build with --features gui)"
            );
            std::process::exit(1);
        }
    }
}
