use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{interval_at, timeout, Instant as TokioInstant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::identity::{self, IdentityError};
use crate::tls::{self, TlsConfigError};
use crate::tunnel::{self, ClientConfig, ClientError, Connection, DeliveryMode, Lease, Transport};

use super::network::{NetworkError, NetworkManager};
use super::tun::Tun;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(20);
const STABLE_CONNECTION: Duration = Duration::from_secs(30);
const PACKET_QUEUE: usize = 256;

#[derive(Clone, Debug)]
pub struct Config {
    pub server_url: String,
    pub token: String,
    pub transport: Transport,
    pub interface_name: String,
    pub ca_path: Option<PathBuf>,
    pub thumbprint: Option<String>,
    pub insecure: bool,
    pub reconnect: bool,
    pub reconnect_max_delay: Duration,
    pub manual_network: bool,
    pub network_state: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Connecting,
    Configuring,
    Connected,
    Reconnecting,
    Disconnected,
    Error,
}

#[derive(Clone, Debug)]
pub struct Event {
    pub state: State,
    pub message: String,
    pub lease: Option<Lease>,
    pub transport: Transport,
    pub delivery_mode: DeliveryMode,
    pub connected_at: Option<SystemTime>,
    pub bytes_uploaded: u64,
    pub bytes_downloaded: u64,
    pub packets_uploaded: u64,
    pub packets_downloaded: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("{0}")]
    Invalid(String),
    #[error("resolve device identity: {0}")]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Tls(#[from] TlsConfigError),
    #[error("{0}")]
    Tunnel(#[from] ClientError),
    #[error("automatic networking: {0}")]
    Network(#[from] NetworkError),
    #[error("TUN device: {0}")]
    Device(#[from] io::Error),
    #[error("client task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
    #[error("operation cancelled")]
    Cancelled,
    #[error(
        "{0}; automatic cleanup was not attempted: use --cleanup-network for network recovery"
    )]
    GuardRetained(String),
    #[error("restore network: {0}")]
    Cleanup(NetworkError),
    #[error("restore network: deadline exceeded")]
    CleanupTimeout,
}

#[derive(Default)]
struct Counters {
    bytes_uploaded: AtomicU64,
    bytes_downloaded: AtomicU64,
    packets_uploaded: AtomicU64,
    packets_downloaded: AtomicU64,
}

impl Counters {
    fn event(
        &self,
        state: State,
        message: impl Into<String>,
        lease: Option<Lease>,
        transport: Transport,
        delivery_mode: DeliveryMode,
        connected_at: Option<SystemTime>,
    ) -> Event {
        Event {
            state,
            message: message.into(),
            lease,
            transport,
            delivery_mode,
            connected_at,
            bytes_uploaded: self.bytes_uploaded.load(Ordering::Relaxed),
            bytes_downloaded: self.bytes_downloaded.load(Ordering::Relaxed),
            packets_uploaded: self.packets_uploaded.load(Ordering::Relaxed),
            packets_downloaded: self.packets_downloaded.load(Ordering::Relaxed),
        }
    }
}

struct DeviceReader {
    cancellation: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl DeviceReader {
    fn start(
        device: Tun,
        outbound: mpsc::Sender<Vec<u8>>,
        errors: mpsc::Sender<io::Error>,
        parent: &CancellationToken,
    ) -> Self {
        let cancellation = parent.child_token();
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            loop {
                let packet = tokio::select! {
                    _ = task_cancellation.cancelled() => return,
                    result = device.read_packet() => match result {
                        Ok(packet) => packet,
                        Err(error) => {
                            if !task_cancellation.is_cancelled() {
                                let _ = errors.send(error).await;
                            }
                            return;
                        }
                    },
                };
                if porta_wire::ip::parse_ipv4(&packet).is_err() {
                    continue;
                }
                tokio::select! {
                    _ = task_cancellation.cancelled() => return,
                    result = outbound.send(packet) => {
                        if result.is_err() {
                            return;
                        }
                    }
                }
            }
        });
        Self {
            cancellation,
            task: Some(task),
        }
    }

    async fn stop(&mut self) -> Result<(), RunError> {
        self.cancellation.cancel();
        if let Some(task) = self.task.take() {
            task.await?;
        }
        Ok(())
    }
}

struct Runtime {
    network: Option<NetworkManager>,
    network_started: bool,
    device: Option<Tun>,
    reader: Option<DeviceReader>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
    outbound_rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    device_error_tx: mpsc::Sender<io::Error>,
    device_error_rx: mpsc::Receiver<io::Error>,
    lease: Option<Lease>,
    transport: Transport,
    delivery_mode: DeliveryMode,
    connected_at: Option<SystemTime>,
    counters: Arc<Counters>,
}

impl Runtime {
    fn new(network: Option<NetworkManager>, transport: Transport) -> Self {
        let (outbound_tx, outbound_rx) = mpsc::channel(PACKET_QUEUE);
        let (device_error_tx, device_error_rx) = mpsc::channel(1);
        Self {
            network,
            network_started: false,
            device: None,
            reader: None,
            outbound_tx,
            outbound_rx: Arc::new(Mutex::new(outbound_rx)),
            device_error_tx,
            device_error_rx,
            lease: None,
            transport,
            delivery_mode: DeliveryMode::Unknown,
            connected_at: None,
            counters: Arc::new(Counters::default()),
        }
    }

    async fn replace_device(&mut self, name: &str, lease: Lease) -> Result<(), RunError> {
        self.stop_reader().await?;
        self.device.take();
        {
            let mut outbound = self.outbound_rx.lock().await;
            while outbound.try_recv().is_ok() {}
        }
        while self.device_error_rx.try_recv().is_ok() {}
        self.device = Some(Tun::open(name, lease.mtu)?);
        Ok(())
    }

    fn ensure_reader(&mut self, cancellation: &CancellationToken) {
        if self.reader.is_none() {
            self.reader = Some(DeviceReader::start(
                self.device
                    .as_ref()
                    .expect("device exists before reader starts")
                    .clone(),
                self.outbound_tx.clone(),
                self.device_error_tx.clone(),
                cancellation,
            ));
        }
    }

    async fn stop_reader(&mut self) -> Result<(), RunError> {
        if let Some(mut reader) = self.reader.take() {
            reader.stop().await?;
        }
        Ok(())
    }

    fn event(&self, state: State, message: impl Into<String>) -> Event {
        self.counters.event(
            state,
            message,
            self.lease,
            self.transport,
            self.delivery_mode,
            self.connected_at,
        )
    }
}

pub async fn cleanup_network(
    state_path: PathBuf,
    cancellation: &CancellationToken,
) -> Result<(), RunError> {
    let mut network = NetworkManager::open(state_path)?;
    tokio::select! {
        _ = cancellation.cancelled() => Err(RunError::Cancelled),
        result = timeout(CLEANUP_TIMEOUT, network.down()) => match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(RunError::Cleanup(error)),
            Err(_) => Err(RunError::CleanupTimeout),
        }
    }
}

pub async fn run(
    config: Config,
    cancellation: &CancellationToken,
    mut observer: impl FnMut(Event),
) -> Result<(), RunError> {
    validate_config(&config)?;
    let endpoint = parse_origin(&config.server_url)?;
    let tls = tls::config(
        config.ca_path.as_deref(),
        config.thumbprint.as_deref(),
        config.insecure,
    )?;
    let identity = Arc::new(identity::current()?);
    observer(Event {
        state: State::Connecting,
        message: format!("Device: {} ({})", identity.name, identity.id),
        lease: None,
        transport: config.transport,
        delivery_mode: DeliveryMode::Unknown,
        connected_at: None,
        bytes_uploaded: 0,
        bytes_downloaded: 0,
        packets_uploaded: 0,
        packets_downloaded: 0,
    });
    observer(Event {
        state: State::Connecting,
        message: "Connecting".to_owned(),
        lease: None,
        transport: config.transport,
        delivery_mode: DeliveryMode::Unknown,
        connected_at: None,
        bytes_uploaded: 0,
        bytes_downloaded: 0,
        packets_uploaded: 0,
        packets_downloaded: 0,
    });

    let network = if config.manual_network {
        None
    } else {
        Some(NetworkManager::open(config.network_state.clone())?)
    };
    let mut runtime = Runtime::new(network, config.transport);
    let mut endpoints = if let Some(network) = runtime.network.as_ref() {
        let recovered = network.recovery_endpoints()?;
        if recovered.is_empty() {
            Vec::new()
        } else {
            runtime.network_started = true;
            restored_endpoints(&endpoint, recovered)?
        }
    } else {
        Vec::new()
    };

    let token = Arc::new(config.token.clone());
    let proof_identity = identity.clone();
    let proof_token = token.clone();
    let base_tunnel_config = ClientConfig {
        url: config.server_url.clone(),
        token: config.token.clone(),
        transport: config.transport,
        tls,
        timeout: CONNECT_TIMEOUT,
        dial_address: None,
        proof: Arc::new(move |method: &str, path: &str| {
            proof_identity
                .proof(&proof_token, method, path)
                .map_err(ClientError::permanent)
        }),
        socket_protector: None,
        cancellation: cancellation.clone(),
    };

    let result = run_loop(
        &config,
        &endpoint,
        &base_tunnel_config,
        &mut runtime,
        &mut endpoints,
        cancellation,
        &mut observer,
    )
    .await;

    let reader_result = runtime.stop_reader().await;
    let cancelled = matches!(result, Err(RunError::Cancelled)) || cancellation.is_cancelled();
    let cleanup_result = if cancelled && runtime.network_started {
        match runtime.network.as_mut() {
            Some(network) => match timeout(CLEANUP_TIMEOUT, network.down()).await {
                Ok(Ok(())) => {
                    runtime.network_started = false;
                    Ok(())
                }
                Ok(Err(error)) => Err(RunError::Cleanup(error)),
                Err(_) => Err(RunError::CleanupTimeout),
            },
            None => Ok(()),
        }
    } else {
        Ok(())
    };
    runtime.device.take();

    if let Err(error) = cleanup_result {
        observer(runtime.event(State::Error, error.to_string()));
        return Err(error);
    }
    if let Err(error) = reader_result {
        observer(runtime.event(State::Error, error.to_string()));
        return Err(error);
    }
    if cancelled {
        observer(runtime.event(State::Disconnected, "Disconnected"));
        return Err(RunError::Cancelled);
    }
    match result {
        Err(RunError::Cancelled) => {
            observer(runtime.event(State::Disconnected, "Disconnected"));
            Err(RunError::Cancelled)
        }
        Err(error) if runtime.network_started => {
            observer(runtime.event(State::Error, error.to_string()));
            Err(RunError::GuardRetained(error.to_string()))
        }
        Err(error) => {
            observer(runtime.event(State::Error, error.to_string()));
            Err(error)
        }
        Ok(()) => {
            observer(runtime.event(State::Disconnected, "Disconnected"));
            Ok(())
        }
    }
}

async fn run_loop(
    config: &Config,
    endpoint: &Url,
    base_tunnel_config: &ClientConfig,
    runtime: &mut Runtime,
    endpoints: &mut Vec<SocketAddr>,
    cancellation: &CancellationToken,
    observer: &mut impl FnMut(Event),
) -> Result<(), RunError> {
    let mut failures = 0_u32;
    let mut retry_error: Option<ClientError> = None;
    loop {
        if cancellation.is_cancelled() {
            return Err(RunError::Cancelled);
        }
        if let Some(error) = retry_error.take() {
            if !config.reconnect || !error.is_retryable() {
                return Err(RunError::Tunnel(error));
            }
            let delay = reconnect_delay(failures, config.reconnect_max_delay);
            failures = failures.saturating_add(1);
            observer(runtime.event(State::Reconnecting, format!("Reconnecting in {delay:?}")));
            tokio::select! {
                _ = cancellation.cancelled() => return Err(RunError::Cancelled),
                error = runtime.device_error_rx.recv(), if runtime.reader.is_some() => {
                    return Err(RunError::Device(error.unwrap_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))));
                }
                _ = tokio::time::sleep(delay) => {}
            }
        }

        let dial_address = if runtime.network.is_some() {
            if endpoints.is_empty() {
                match resolve_endpoints(endpoint, cancellation).await {
                    Ok(resolved) => *endpoints = resolved,
                    Err(error) => {
                        retry_error = Some(error);
                        continue;
                    }
                }
            }
            Some(endpoints[failures as usize % endpoints.len()])
        } else {
            None
        };

        if runtime.network_started {
            runtime
                .network
                .as_mut()
                .expect("network-started state has a manager")
                .prepare(dial_address.expect("automatic networking pins an endpoint"))
                .await?;
        }

        let mut tunnel_config = base_tunnel_config.clone();
        tunnel_config.dial_address = dial_address;
        let connection = tokio::select! {
            _ = cancellation.cancelled() => return Err(RunError::Cancelled),
            result = tunnel::connect(tunnel_config) => match result {
                Ok(connection) => connection,
                Err(error) => {
                    retry_error = Some(error);
                    continue;
                }
            }
        };

        if cancellation.is_cancelled() {
            connection.close().await;
            return Err(RunError::Cancelled);
        }
        if let Some(network) = runtime
            .network
            .as_mut()
            .filter(|_| !runtime.network_started)
        {
            runtime.network_started = true;
            if let Err(error) = network.prepare(connection.remote_address).await {
                connection.close().await;
                return Err(RunError::Network(error));
            }
        }

        let replace_device = runtime.lease.is_none_or(|lease| {
            lease.address != connection.lease.address || lease.mtu != connection.lease.mtu
        });
        if replace_device {
            if let Err(error) = runtime
                .replace_device(&config.interface_name, connection.lease)
                .await
            {
                connection.close().await;
                return Err(error);
            }
        }
        runtime.transport = connection.transport;
        runtime.delivery_mode = connection.delivery_mode;
        if let Some(network) = runtime.network.as_mut() {
            observer(runtime.counters.event(
                State::Configuring,
                "Configuring network",
                Some(connection.lease),
                connection.transport,
                connection.delivery_mode,
                runtime.connected_at,
            ));
            if let Err(error) = network
                .up(
                    runtime
                        .device
                        .as_ref()
                        .expect("device exists before network configuration")
                        .name(),
                    connection.remote_address,
                    connection.lease,
                )
                .await
            {
                connection.close().await;
                return Err(RunError::Network(error));
            }
        }
        runtime.lease = Some(connection.lease);
        runtime.ensure_reader(cancellation);
        runtime.connected_at.get_or_insert_with(SystemTime::now);
        observer(runtime.event(State::Connected, "Connected"));

        let started = Instant::now();
        let error = run_connection(connection, runtime, cancellation, observer).await;
        if started.elapsed() >= STABLE_CONNECTION {
            failures = 0;
        }
        match error {
            RunError::Tunnel(error) => retry_error = Some(error),
            error => return Err(error),
        }
    }
}

async fn run_connection(
    connection: Connection,
    runtime: &mut Runtime,
    cancellation: &CancellationToken,
    observer: &mut impl FnMut(Event),
) -> RunError {
    enum PumpError {
        Tunnel(ClientError),
        Device(io::Error),
    }

    let connection = Arc::new(connection);
    let pumps = cancellation.child_token();
    let (errors_tx, mut errors_rx) = mpsc::channel::<PumpError>(2);

    let upload_connection = connection.clone();
    let upload_cancellation = pumps.clone();
    let upload_errors = errors_tx.clone();
    let outbound = runtime.outbound_rx.clone();
    let upload_counters = runtime.counters.clone();
    let upload = tokio::spawn(async move {
        loop {
            let packet = tokio::select! {
                _ = upload_cancellation.cancelled() => return,
                packet = async {
                    let mut receiver = outbound.lock().await;
                    receiver.recv().await
                } => match packet {
                    Some(packet) => packet,
                    None => return,
                }
            };
            let result = tokio::select! {
                _ = upload_cancellation.cancelled() => return,
                result = upload_connection.send(&packet) => result,
            };
            if let Err(error) = result {
                let _ = upload_errors.send(PumpError::Tunnel(error)).await;
                return;
            }
            upload_counters
                .bytes_uploaded
                .fetch_add(packet.len() as u64, Ordering::Relaxed);
            upload_counters
                .packets_uploaded
                .fetch_add(1, Ordering::Relaxed);
        }
    });

    let download_connection = connection.clone();
    let download_cancellation = pumps.clone();
    let download_errors = errors_tx;
    let device = runtime
        .device
        .as_ref()
        .expect("connected session has a TUN")
        .clone();
    let download_counters = runtime.counters.clone();
    let download = tokio::spawn(async move {
        loop {
            let packet = tokio::select! {
                _ = download_cancellation.cancelled() => return,
                result = download_connection.receive() => match result {
                    Ok(packet) => packet,
                    Err(error) => {
                        let _ = download_errors.send(PumpError::Tunnel(error)).await;
                        return;
                    }
                }
            };
            let result = tokio::select! {
                _ = download_cancellation.cancelled() => return,
                result = device.write_packet(&packet) => result,
            };
            if let Err(error) = result {
                let _ = download_errors.send(PumpError::Device(error)).await;
                return;
            }
            download_counters
                .bytes_downloaded
                .fetch_add(packet.len() as u64, Ordering::Relaxed);
            download_counters
                .packets_downloaded
                .fetch_add(1, Ordering::Relaxed);
        }
    });

    let mut progress = interval_at(
        TokioInstant::now() + Duration::from_secs(1),
        Duration::from_secs(1),
    );
    progress.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let result = loop {
        tokio::select! {
            _ = cancellation.cancelled() => break RunError::Cancelled,
            error = runtime.device_error_rx.recv() => {
                break RunError::Device(error.unwrap_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof)));
            }
            error = errors_rx.recv() => {
                break match error {
                    Some(PumpError::Tunnel(error)) => RunError::Tunnel(error),
                    Some(PumpError::Device(error)) => RunError::Device(error),
                    None => RunError::Tunnel(ClientError::Closed),
                };
            }
            _ = progress.tick() => observer(runtime.event(State::Connected, "Connected")),
        }
    };
    pumps.cancel();
    connection.close().await;
    for task in [upload, download] {
        if let Err(error) = task.await {
            return RunError::Task(error);
        }
    }
    result
}

fn validate_config(config: &Config) -> Result<(), RunError> {
    if config.server_url.trim().is_empty() || config.token.is_empty() {
        return Err(RunError::Invalid(
            "server URL and token are required".to_owned(),
        ));
    }
    if config.interface_name.is_empty() {
        return Err(RunError::Invalid(
            "TUN interface name is required".to_owned(),
        ));
    }
    Ok(())
}

fn parse_origin(value: &str) -> Result<Url, RunError> {
    let url = Url::parse(value)
        .map_err(|error| RunError::Invalid(format!("invalid server URL: {error}")))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(RunError::Invalid(
            "server URL must be an HTTPS origin".to_owned(),
        ));
    }
    Ok(url)
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
    fn validates_origins_and_reconnect_bounds() {
        assert!(parse_origin("https://vpn.example.com:8443").is_ok());
        for invalid in [
            "http://vpn.example.com",
            "https://user@vpn.example.com",
            "https://vpn.example.com/path",
            "https://vpn.example.com/?query",
        ] {
            assert!(parse_origin(invalid).is_err(), "{invalid}");
        }
        assert_eq!(reconnect_delay(0, Duration::ZERO), Duration::from_secs(1));
        assert_eq!(
            reconnect_delay(100, Duration::from_secs(5)),
            Duration::from_secs(5)
        );
    }

    #[tokio::test]
    async fn numeric_and_recovered_endpoints_are_strict() {
        let cancellation = CancellationToken::new();
        let ipv4 = parse_origin("https://192.0.2.1").unwrap();
        assert_eq!(
            resolve_endpoints(&ipv4, &cancellation).await.unwrap(),
            ["192.0.2.1:443".parse().unwrap()]
        );
        let ipv6 = parse_origin("https://[2001:db8::1]:8443").unwrap();
        assert_eq!(
            resolve_endpoints(&ipv6, &cancellation).await.unwrap(),
            ["[2001:db8::1]:8443".parse().unwrap()]
        );
        let named = parse_origin("https://vpn.example.com:443").unwrap();
        assert_eq!(
            restored_endpoints(
                &named,
                vec![
                    "198.51.100.10:443".parse().unwrap(),
                    "198.51.100.10:8443".parse().unwrap(),
                ],
            )
            .unwrap(),
            ["198.51.100.10:443".parse().unwrap()]
        );
        assert!(restored_endpoints(&named, vec!["127.0.0.1:443".parse().unwrap()]).is_err());
    }
}
