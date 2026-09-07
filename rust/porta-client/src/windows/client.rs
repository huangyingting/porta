use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::ClientConfig as RustlsClientConfig;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::identity::IdentityError;
use crate::tunnel::{self, ClientError, Connection, DeliveryMode, Lease, Transport};

use super::identity;
use super::network::{NetworkError, NetworkManager};
use super::tun::{Tun, TunError};

const PACKET_QUEUE: usize = 1024;
const STABLE_CONNECTION: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct Config {
    pub server: Url,
    pub token: String,
    pub tls: Arc<RustlsClientConfig>,
    pub transport: Transport,
    pub interface_name: String,
    pub network_state_path: PathBuf,
    pub wintun_path: Option<PathBuf>,
    pub manual_network: bool,
    pub reconnect: bool,
    pub connect_timeout: Duration,
    pub reconnect_max_delay: Duration,
}

#[derive(Clone, Debug)]
pub struct ConnectionInfo {
    pub transport: Transport,
    pub delivery_mode: DeliveryMode,
    pub remote_address: SocketAddr,
    pub lease: Lease,
    pub connected_at: Instant,
}

#[derive(Clone, Debug)]
pub enum Event {
    RecoveringNetwork,
    Connecting {
        attempt: u64,
        remote_address: SocketAddr,
    },
    ConfiguringNetwork,
    Connected(ConnectionInfo),
    Progress {
        uploaded_bytes: u64,
        downloaded_bytes: u64,
    },
    Reconnecting {
        reason: String,
        delay: Duration,
    },
    Stopping,
}

pub trait Observer: Send + Sync {
    fn event(&self, event: Event);
}

impl<F> Observer for F
where
    F: Fn(Event) + Send + Sync,
{
    fn event(&self, event: Event) {
        self(event);
    }
}

#[derive(Debug, Error)]
pub enum RunError {
    #[error("{0}")]
    Invalid(String),
    #[error("resolve gateway endpoint: {0}")]
    Resolve(#[source] ClientError),
    #[error("device identity: {0}")]
    Identity(#[from] IdentityError),
    #[error("open Windows network manager: {0}")]
    Network(#[from] NetworkError),
    #[error("open Windows tunnel: {0}")]
    Tun(#[from] TunError),
    #[error("tunnel: {0}")]
    Runtime(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("tunnel failed while the fail-closed network guard remains active at {state_path}: {source}")]
    GuardRetained {
        state_path: PathBuf,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("tunnel stopped")]
    Cancelled,
}

pub async fn run(
    config: Config,
    cancellation: CancellationToken,
    observer: Arc<dyn Observer>,
) -> Result<(), RunError> {
    let identity = Arc::new(identity::current()?);
    let proof_token = config.token.clone();
    let proof_identity = Arc::clone(&identity);
    let proof = Arc::new(move |method: &str, path: &str| {
        proof_identity
            .proof(&proof_token, method, path)
            .map_err(ClientError::permanent)
    });

    let mut network = if config.manual_network {
        None
    } else {
        Some(NetworkManager::open(config.network_state_path.clone())?)
    };
    let mut network_active = network.as_ref().is_some_and(NetworkManager::needs_cleanup);
    let endpoints = if let Some(manager) = network.as_ref() {
        let saved = manager.recovery_endpoints()?;
        if saved.is_empty() {
            if network_active {
                return Err(retained(
                    &config.network_state_path,
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "network protection is active but its recovery journal has no gateway endpoint",
                    ),
                ));
            }
            resolve_endpoints(&config.server, &cancellation)
                .await
                .map_err(RunError::Resolve)?
        } else {
            observer.event(Event::RecoveringNetwork);
            restored_endpoints(&config.server, saved)?
        }
    } else {
        resolve_endpoints(&config.server, &cancellation)
            .await
            .map_err(RunError::Resolve)?
    };

    let mut attempt = 0_u64;
    let mut failures = 0_u32;
    let mut endpoint_index = 0_usize;
    let mut tun = None;
    let mut reader = None;
    let (packet_tx, mut packet_rx) = mpsc::channel(PACKET_QUEUE);
    let (device_error_tx, mut device_error_rx) = mpsc::channel(1);

    loop {
        if cancellation.is_cancelled() {
            return stop(
                &config,
                &mut network,
                tun.as_ref(),
                reader.take(),
                &observer,
            )
            .await;
        }

        attempt += 1;
        let remote_address = endpoints[endpoint_index % endpoints.len()];
        endpoint_index += 1;
        observer.event(Event::Connecting {
            attempt,
            remote_address,
        });

        if let Some(manager) = network.as_mut().filter(|_| network_active) {
            if let Err(source) = manager
                .prepare(&config.interface_name, &remote_address)
                .await
            {
                return Err(fail_after_device(
                    &config,
                    &network,
                    tun.as_ref(),
                    &mut reader,
                    source,
                )
                .await);
            }
        }

        let connected = tunnel::connect(tunnel::ClientConfig {
            url: config.server.to_string(),
            token: config.token.clone(),
            transport: config.transport,
            tls: Arc::clone(&config.tls),
            timeout: config.connect_timeout,
            dial_address: Some(remote_address),
            proof: proof.clone(),
            socket_protector: None,
            cancellation: cancellation.child_token(),
        })
        .await;
        let connection = match connected {
            Ok(connection) => Arc::new(connection),
            Err(_error) if cancellation.is_cancelled() => {
                return stop(
                    &config,
                    &mut network,
                    tun.as_ref(),
                    reader.take(),
                    &observer,
                )
                .await;
            }
            Err(error) if error.is_retryable() && config.reconnect => {
                let delay = reconnect_delay(failures, config.reconnect_max_delay);
                failures = failures.saturating_add(1);
                observer.event(Event::Reconnecting {
                    reason: error.to_string(),
                    delay,
                });
                if wait_or_cancel(delay, &cancellation).await {
                    continue;
                }
                return stop(
                    &config,
                    &mut network,
                    tun.as_ref(),
                    reader.take(),
                    &observer,
                )
                .await;
            }
            Err(error) => {
                return Err(
                    fail_after_device(&config, &network, tun.as_ref(), &mut reader, error).await,
                );
            }
        };

        if let Some(manager) = network.as_mut().filter(|_| !network_active) {
            if let Err(source) = manager
                .prepare(&config.interface_name, &connection.remote_address)
                .await
            {
                connection.close().await;
                return Err(retained_if_needed(&config, &network, source));
            }
            network_active = true;
        }

        if tun.is_none() {
            let opened = match Tun::open(&config.interface_name, config.wintun_path.as_deref()) {
                Ok(tun) => tun,
                Err(error) => return Err(retained_if_needed(&config, &network, error)),
            };
            let reader_tun = opened.clone();
            let reader_packets = packet_tx.clone();
            let reader_errors = device_error_tx.clone();
            reader = Some(tokio::task::spawn_blocking(move || loop {
                match reader_tun.read_packet() {
                    Ok(packet) => {
                        let _ = reader_packets.try_send(packet);
                    }
                    Err(TunError::Read(wintun::Error::ShuttingDown)) => break,
                    Err(error) => {
                        let _ = reader_errors.try_send(error);
                        break;
                    }
                }
            }));
            tun = Some(opened);
        }
        let device = tun.as_ref().expect("TUN initialized after successful dial");

        if let Some(manager) = network.as_mut() {
            observer.event(Event::ConfiguringNetwork);
            let result = manager
                .up(device.name(), &connection.remote_address, connection.lease)
                .await;
            if let Err(source) = result {
                connection.close().await;
                return Err(fail_after_device(
                    &config,
                    &network,
                    tun.as_ref(),
                    &mut reader,
                    source,
                )
                .await);
            }
        }
        while packet_rx.try_recv().is_ok() {}

        observer.event(Event::Connected(ConnectionInfo {
            transport: connection.transport,
            delivery_mode: connection.delivery_mode,
            remote_address: connection.remote_address,
            lease: connection.lease,
            connected_at: Instant::now(),
        }));

        let session_started = Instant::now();
        let session = run_session(
            Arc::clone(&connection),
            device,
            &mut packet_rx,
            &mut device_error_rx,
            &cancellation,
            &observer,
        )
        .await;
        connection.close().await;
        match session {
            SessionEnd::Cancelled => {
                return stop(
                    &config,
                    &mut network,
                    tun.as_ref(),
                    reader.take(),
                    &observer,
                )
                .await;
            }
            SessionEnd::Retry(error) => {
                if !config.reconnect {
                    return Err(fail_after_device(
                        &config,
                        &network,
                        tun.as_ref(),
                        &mut reader,
                        std::io::Error::new(std::io::ErrorKind::ConnectionAborted, error),
                    )
                    .await);
                }
                if session_started.elapsed() >= STABLE_CONNECTION {
                    failures = 0;
                }
                let delay = reconnect_delay(failures, config.reconnect_max_delay);
                failures = failures.saturating_add(1);
                observer.event(Event::Reconnecting {
                    reason: error,
                    delay,
                });
                if !wait_or_cancel(delay, &cancellation).await {
                    return stop(
                        &config,
                        &mut network,
                        tun.as_ref(),
                        reader.take(),
                        &observer,
                    )
                    .await;
                }
            }
            SessionEnd::Terminal(error) => {
                return Err(
                    fail_after_device(&config, &network, tun.as_ref(), &mut reader, error).await,
                );
            }
        }
    }
}

enum SessionEnd {
    Cancelled,
    Retry(String),
    Terminal(Box<dyn std::error::Error + Send + Sync>),
}

async fn run_session(
    connection: Arc<Connection>,
    tun: &Tun,
    packets: &mut mpsc::Receiver<Vec<u8>>,
    device_errors: &mut mpsc::Receiver<TunError>,
    cancellation: &CancellationToken,
    observer: &Arc<dyn Observer>,
) -> SessionEnd {
    let mut uploaded_bytes = 0_u64;
    let mut downloaded_bytes = 0_u64;
    let mut progress = tokio::time::interval(Duration::from_secs(1));
    progress.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    progress.tick().await;

    loop {
        tokio::select! {
            _ = cancellation.cancelled() => return SessionEnd::Cancelled,
            Some(error) = device_errors.recv() => {
                return SessionEnd::Terminal(Box::new(error));
            }
            packet = packets.recv() => {
                let Some(packet) = packet else {
                    return SessionEnd::Terminal(Box::new(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "Wintun packet reader stopped",
                    )));
                };
                match connection.send(&packet).await {
                    Ok(()) => uploaded_bytes = uploaded_bytes.saturating_add(packet.len() as u64),
                    Err(error) if error.is_retryable() => return SessionEnd::Retry(error.to_string()),
                    Err(error) => return SessionEnd::Terminal(Box::new(error)),
                }
            }
            packet = connection.receive() => {
                match packet {
                    Ok(packet) => {
                        if let Err(error) = tun.write_packet(&packet) {
                            return SessionEnd::Terminal(Box::new(error));
                        }
                        downloaded_bytes = downloaded_bytes.saturating_add(packet.len() as u64);
                    }
                    Err(error) if error.is_retryable() => return SessionEnd::Retry(error.to_string()),
                    Err(error) => return SessionEnd::Terminal(Box::new(error)),
                }
            }
            _ = progress.tick() => observer.event(Event::Progress {
                uploaded_bytes,
                downloaded_bytes,
            }),
        }
    }
}

async fn wait_or_cancel(delay: Duration, cancellation: &CancellationToken) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(delay) => true,
        _ = cancellation.cancelled() => false,
    }
}

async fn stop(
    config: &Config,
    network: &mut Option<NetworkManager>,
    tun: Option<&Tun>,
    reader: Option<tokio::task::JoinHandle<()>>,
    observer: &Arc<dyn Observer>,
) -> Result<(), RunError> {
    observer.event(Event::Stopping);
    let mut reader = reader;
    let device_result = stop_device(tun, &mut reader).await;
    if let Some(manager) = network.as_mut() {
        manager
            .down()
            .await
            .map_err(|source| retained(&config.network_state_path, source))?;
    }
    if let Err(error) = device_result {
        return Err(RunError::Runtime(error));
    }
    Err(RunError::Cancelled)
}

async fn fail_after_device(
    config: &Config,
    network: &Option<NetworkManager>,
    tun: Option<&Tun>,
    reader: &mut Option<tokio::task::JoinHandle<()>>,
    source: impl Into<Box<dyn std::error::Error + Send + Sync>>,
) -> RunError {
    let source = source.into().to_string();
    let detail = match stop_device(tun, reader).await {
        Ok(()) => source,
        Err(cleanup) => format!("{source}; stopping the local tunnel also failed: {cleanup}"),
    };
    retained_if_needed(config, network, std::io::Error::other(detail))
}

async fn stop_device(
    tun: Option<&Tun>,
    reader: &mut Option<tokio::task::JoinHandle<()>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(tun) = tun {
        tun.shutdown()?;
    }
    if let Some(reader) = reader.take() {
        reader.await?;
    }
    Ok(())
}

fn retained(
    state_path: &std::path::Path,
    source: impl std::error::Error + Send + Sync + 'static,
) -> RunError {
    RunError::GuardRetained {
        state_path: state_path.to_owned(),
        source: Box::new(source),
    }
}

fn retained_if_needed(
    config: &Config,
    network: &Option<NetworkManager>,
    source: impl std::error::Error + Send + Sync + 'static,
) -> RunError {
    if network.as_ref().is_some_and(NetworkManager::needs_cleanup) {
        retained(&config.network_state_path, source)
    } else {
        RunError::Runtime(Box::new(source))
    }
}

async fn resolve_endpoints(
    endpoint: &Url,
    cancellation: &CancellationToken,
) -> Result<Vec<SocketAddr>, ClientError> {
    let host = endpoint
        .host_str()
        .ok_or_else(|| ClientError::permanent("gateway URL has no hostname"))?
        .trim_matches(['[', ']']);
    if host.contains('%') {
        return Err(ClientError::permanent(
            "automatic networking does not support scoped gateway addresses",
        ));
    }
    let port = endpoint
        .port_or_known_default()
        .ok_or_else(|| ClientError::permanent("gateway URL has no port"))?;
    let mut addresses = if let Ok(address) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(normalize_ip(address), port)]
    } else {
        tokio::select! {
            _ = cancellation.cancelled() => return Err(ClientError::Closed),
            result = tokio::net::lookup_host((host, port)) => result
                .map_err(ClientError::unavailable)?
                .map(|address| SocketAddr::new(normalize_ip(address.ip()), address.port()))
                .collect(),
        }
    };
    addresses.retain(|address| usable_endpoint(address.ip()));
    addresses.sort_by_key(|address| if address.is_ipv4() { 0 } else { 1 });
    let mut seen = HashSet::new();
    addresses.retain(|address| seen.insert(*address));
    if addresses.is_empty() {
        return Err(ClientError::permanent(
            "gateway has no supported unscoped unicast IP endpoint",
        ));
    }
    Ok(addresses)
}

fn restored_endpoints(endpoint: &Url, saved: Vec<SocketAddr>) -> Result<Vec<SocketAddr>, RunError> {
    let host = endpoint
        .host_str()
        .ok_or_else(|| RunError::Invalid("gateway URL has no hostname".to_owned()))?
        .trim_matches(['[', ']']);
    let port = endpoint
        .port_or_known_default()
        .ok_or_else(|| RunError::Invalid("gateway URL has no port".to_owned()))?;
    if let Ok(address) = host.parse::<IpAddr>() {
        let address = normalize_ip(address);
        if !usable_endpoint(address) {
            return Err(RunError::Invalid(
                "automatic networking requires an unscoped unicast gateway endpoint".to_owned(),
            ));
        }
        return Ok(vec![SocketAddr::new(address, port)]);
    }
    let mut seen = HashSet::new();
    let endpoints = saved
        .into_iter()
        .filter(|address| {
            address.port() == port && usable_endpoint(address.ip()) && seen.insert(*address)
        })
        .collect::<Vec<_>>();
    if endpoints.is_empty() {
        return Err(RunError::Invalid(
            "network protection is active but no cached endpoint matches this gateway port"
                .to_owned(),
        ));
    }
    Ok(endpoints)
}

fn normalize_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        address => address,
    }
}

fn usable_endpoint(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_link_local()
                && !address.is_multicast()
                && address != Ipv4Addr::BROADCAST
        }

        IpAddr::V6(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_unicast_link_local()
                && address != Ipv6Addr::LOCALHOST
        }
    }
}

pub fn reconnect_delay(failures: u32, maximum: Duration) -> Duration {
    let maximum = maximum.max(Duration::from_secs(1));
    Duration::from_secs(1_u64 << failures.min(5)).min(maximum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_backoff_is_bounded() {
        assert_eq!(
            reconnect_delay(0, Duration::from_secs(30)),
            Duration::from_secs(1)
        );
        assert_eq!(
            reconnect_delay(4, Duration::from_secs(30)),
            Duration::from_secs(16)
        );
        assert_eq!(
            reconnect_delay(9, Duration::from_secs(30)),
            Duration::from_secs(30)
        );
        assert_eq!(reconnect_delay(9, Duration::ZERO), Duration::from_secs(1));
    }

    #[test]
    fn endpoint_filter_rejects_local_and_scoped_addresses() {
        for address in [
            "0.0.0.0",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "::",
            "::1",
            "fe80::1",
            "ff02::1",
        ] {
            assert!(!usable_endpoint(address.parse().unwrap()), "{address}");
        }
        for address in ["192.0.2.1", "2001:db8::1"] {
            assert!(usable_endpoint(address.parse().unwrap()), "{address}");
        }
    }
}
