#[cfg(all(target_os = "linux", not(target_os = "android")))]
use std::path::PathBuf;
#[cfg(all(target_os = "linux", not(target_os = "android")))]
use std::process::Command;
#[cfg(all(target_os = "linux", not(target_os = "android")))]
use std::process::Stdio;

#[cfg(all(target_os = "linux", not(target_os = "android")))]
use ipnet::Ipv4Net;
#[cfg(all(target_os = "linux", not(target_os = "android")))]
use porta_client::linux::network::NetworkManager;
#[cfg(all(target_os = "linux", not(target_os = "android")))]
use porta_client::linux::tun::Tun;
#[cfg(all(target_os = "linux", not(target_os = "android")))]
use porta_client::tunnel::Lease;

#[cfg(all(target_os = "linux", not(target_os = "android")))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state_path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("network state path is required")?;
    let endpoint = "198.51.100.10:443".parse()?;
    let lease = Lease {
        address: "10.66.0.2/24".parse::<Ipv4Net>()?,
        gateway: Some("10.66.0.1".parse()?),
        dns: Some("1.1.1.1".parse()?),
        mtu: 1280,
    };

    let device = Tun::open("porta0", lease.mtu)?;
    let mut network = NetworkManager::open(&state_path)?;
    network.prepare(endpoint).await?;

    let state: serde_json::Value = serde_json::from_slice(&std::fs::read(&state_path)?)?;
    let table = state
        .get("table")
        .and_then(serde_json::Value::as_str)
        .ok_or("network journal has no nftables table")?;
    require_success(Command::new("nft").args(["list", "table", "inet", table]))?;

    network
        .up(device.name(), endpoint, lease)
        .await
        .map_err(|error| format!("configure native network: {error}"))?;
    require_success(Command::new("ip").args(["route", "show", "0.0.0.0/1"]))?;
    require_success(Command::new("ip").args(["route", "show", "128.0.0.0/1"]))?;
    require_success(Command::new("ip").args(["address", "show", "dev", device.name()]))?;

    network.down().await?;
    if state_path.exists() {
        return Err("network journal remains after cleanup".into());
    }
    if Command::new("nft")
        .args(["list", "table", "inet", table])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success()
    {
        return Err("nftables guard remains after cleanup".into());
    }
    drop(device);
    Ok(())
}

#[cfg(all(target_os = "linux", not(target_os = "android")))]
fn require_success(command: &mut Command) -> Result<(), Box<dyn std::error::Error>> {
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("command exited with {status}").into())
    }
}

#[cfg(not(all(target_os = "linux", not(target_os = "android"))))]
fn main() {}
