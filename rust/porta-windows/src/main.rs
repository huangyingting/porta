#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

#[cfg(target_os = "windows")]
mod desktop;

#[cfg(target_os = "windows")]
fn main() {
    if let Err(error) = desktop::run() {
        eprintln!("porta: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "windows"))]
fn main() {
    println!("Porta desktop is available on Windows.");
}
