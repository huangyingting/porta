//! Cascade relay: carry this gateway's client traffic through another Porta
//! gateway instead of exiting locally.
//!
//! The gateway joins the next hop as an ordinary native device and owns a
//! second TUN interface for that tunnel. The kernel policy-routes packets that
//! arrive from local clients to the upstream interface and masquerades them to
//! a fixed local relay address (see `scripts/server-up.sh`). This process
//! exchanges that address with the current upstream lease while moving packets
//! between the interface and the tunnel. The lease is never a local address,
//! so every hop can keep the default client pool, and hops chain
//! (A -> B -> C) without nested encapsulation.

use crate::data::tun::NativeTun;
use crate::ops::metrics::Metrics;
use anyhow::{Context, Result};
use parking_lot::Mutex;
use porta_client::identity::Identity;
use porta_client::tunnel::{self, ClientConfig, ClientError, Connection, Lease, Transport};
use porta_wire::nat::{translate, Direction};
use std::io;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const STABLE_CONNECTION: Duration = Duration::from_secs(30);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(30);
/// Interface MTU used until the first upstream lease is known.
const INITIAL_MTU: usize = 1280;

#[derive(Clone)]
pub struct UpstreamConfig {
    pub url: String,
    pub token: Zeroizing<String>,
    pub transport: Transport,
    pub interface: String,
    /// Fixed address of the upstream interface; client traffic is
    /// masqueraded to it before translation to the upstream lease.
    pub local_address: Ipv4Addr,
    pub identity_path: PathBuf,
    pub ca_path: Option<PathBuf>,
    pub thumbprint: Option<String>,
}

/// Connection state shared with readiness and logging.
#[derive(Default)]
pub struct UpstreamStatus {
    inner: Mutex<StatusInner>,
}

#[derive(Default)]
struct StatusInner {
    connected: Option<(Lease, Transport)>,
    error: Option<String>,
}

impl UpstreamStatus {
    pub fn check(&self) -> Result<(), String> {
        let inner = self.inner.lock();
        if inner.connected.is_some() {
            return Ok(());
        }
        Err(match &inner.error {
            Some(error) => format!("next-hop tunnel is down: {error}"),
            None => "next-hop tunnel is connecting".to_owned(),
        })
    }

    pub fn lease(&self) -> Option<Lease> {
        self.inner.lock().connected.map(|(lease, _)| lease)
    }

    /// Current next-hop state for operators.
    pub fn snapshot(&self) -> UpstreamSnapshot {
        let inner = self.inner.lock();
        UpstreamSnapshot {
            connected: inner.connected.is_some(),
            address: inner
                .connected
                .map(|(lease, _)| lease.address.addr().to_string()),
            transport: inner.connected.map(|(_, transport)| match transport {
                Transport::Http3 => "h3",
                Transport::Http2 => "h2",
                Transport::Auto => "auto",
            }),
            error: inner.error.clone(),
        }
    }

    fn connected(&self, lease: Lease, transport: Transport) {
        let mut inner = self.inner.lock();
        inner.connected = Some((lease, transport));
        inner.error = None;
    }

    fn failed(&self, error: impl Into<String>) {
        let mut inner = self.inner.lock();
        inner.connected = None;
        inner.error = Some(error.into());
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UpstreamSnapshot {
    pub connected: bool,
    pub address: Option<String>,
    pub transport: Option<&'static str>,
    pub error: Option<String>,
}

pub struct Upstream {
    config: UpstreamConfig,
    device: Arc<NativeTun>,
    identity: Arc<Identity>,
    tls: Arc<rustls::ClientConfig>,
    status: Arc<UpstreamStatus>,
    metrics: Arc<Metrics>,
}

impl Upstream {
    /// Validates credentials and opens the upstream interface. Call this
    /// before the network helper runs: it installs routes through the device.
    pub fn open(config: UpstreamConfig, metrics: Arc<Metrics>) -> Result<Self> {
        let tls = porta_client::tls::config(
            config.ca_path.as_deref(),
            config.thumbprint.as_deref(),
            false,
        )
        .context("configure next-hop TLS verification")?;
        let identity = porta_client::identity::current_at(Some(&config.identity_path))
            .context("load next-hop device identity")?;
        let device = NativeTun::open(&config.interface, INITIAL_MTU)
            .with_context(|| format!("open upstream TUN {}", config.interface))?;
        device
            .set_ipv4_address(config.local_address)
            .with_context(|| format!("address upstream TUN {}", config.interface))?;
        device
            .set_up()
            .with_context(|| format!("bring up upstream TUN {}", config.interface))?;
        tracing::info!(
            upstream = %config.url,
            interface = device.name(),
            device_id = %identity.id,
            device_name = %identity.name,
            "cascade relay enabled; enroll this device on the next-hop gateway if it is new"
        );
        Ok(Self {
            config,
            device: Arc::new(device),
            identity: Arc::new(identity),
            tls,
            status: Arc::new(UpstreamStatus::default()),
            metrics,
        })
    }

    pub fn status(&self) -> Arc<UpstreamStatus> {
        self.status.clone()
    }

    pub fn interface(&self) -> &str {
        self.device.name()
    }

    pub fn url(&self) -> &str {
        &self.config.url
    }

    /// Maintains the next-hop tunnel until cancelled, reconnecting with
    /// bounded exponential backoff. Traffic is dropped while disconnected;
    /// kernel policy routing keeps it from leaving through another interface.
    pub async fn run(&self, cancellation: CancellationToken) -> Result<()> {
        let mut failures = 0_u32;
        let mut configured_mtu = None;
        loop {
            let result = tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Ok(()),
                result = tunnel::connect(self.client_config(&cancellation)) => result,
            };
            let connection = match result {
                Ok(connection) => connection,
                Err(error) => {
                    let delay = reconnect_delay(failures, &error);
                    failures = failures.saturating_add(1);
                    tracing::warn!(
                        upstream = %self.config.url,
                        error = %error,
                        retry_in = %humantime::format_duration(delay),
                        "next-hop tunnel connection failed"
                    );
                    self.status.failed(error.to_string());
                    if !sleep_or_cancel(delay, &cancellation).await {
                        return Ok(());
                    }
                    continue;
                }
            };
            if let Err(error) = self.configure_mtu(connection.lease.mtu, configured_mtu) {
                connection.close().await;
                let delay = MAX_RECONNECT_DELAY;
                tracing::error!(
                    interface = self.device.name(),
                    error = %format!("{error:#}"),
                    retry_in = %humantime::format_duration(delay),
                    "could not configure the upstream interface"
                );
                self.status.failed(format!("{error:#}"));
                if !sleep_or_cancel(delay, &cancellation).await {
                    return Ok(());
                }
                continue;
            }
            configured_mtu = Some(connection.lease.mtu);
            tracing::info!(
                upstream = %self.config.url,
                address = %connection.lease.address,
                mtu = connection.lease.mtu,
                transport = ?connection.transport,
                delivery = ?connection.delivery_mode,
                "next-hop tunnel connected"
            );
            self.status
                .connected(connection.lease, connection.transport);
            self.metrics.upstream_state(true);
            let started = Instant::now();
            let reason = self.relay(connection, &cancellation).await;
            self.metrics.upstream_state(false);
            if cancellation.is_cancelled() {
                return Ok(());
            }
            self.status.failed(reason.clone());
            if started.elapsed() >= STABLE_CONNECTION {
                failures = 0;
            }
            let delay = reconnect_delay(failures, &ClientError::Closed);
            failures = failures.saturating_add(1);
            tracing::warn!(
                upstream = %self.config.url,
                reason = %reason,
                retry_in = %humantime::format_duration(delay),
                "next-hop tunnel interrupted"
            );
            if !sleep_or_cancel(delay, &cancellation).await {
                return Ok(());
            }
        }
    }

    fn client_config(&self, cancellation: &CancellationToken) -> ClientConfig {
        let identity = self.identity.clone();
        let token = self.config.token.clone();
        ClientConfig {
            url: self.config.url.clone(),
            token: self.config.token.to_string(),
            transport: self.config.transport,
            tls: self.tls.clone(),
            timeout: CONNECT_TIMEOUT,
            dial_address: None,
            proof: Arc::new(move |method: &str, path: &str| {
                identity
                    .proof(&token, method, path)
                    .map_err(ClientError::permanent)
            }),
            socket_protector: None,
            cancellation: cancellation.child_token(),
        }
    }

    fn configure_mtu(&self, mtu: u16, previous: Option<u16>) -> Result<()> {
        if previous != Some(mtu) {
            self.device.set_mtu(usize::from(mtu))?;
        }
        Ok(())
    }

    async fn relay(&self, connection: Connection, cancellation: &CancellationToken) -> String {
        let connection = Arc::new(connection);
        let lease = connection.lease;
        let local = self.config.local_address;
        let pumps = cancellation.child_token();

        let upload = tokio::spawn({
            let connection = connection.clone();
            let device = self.device.clone();
            let metrics = self.metrics.clone();
            let pumps = pumps.clone();
            async move {
                let mut warned = false;
                loop {
                    let mut packet = tokio::select! {
                        biased;
                        _ = pumps.cancelled() => return None,
                        result = device.read_packet() => match result {
                            Ok(packet) => packet,
                            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                                metrics.upstream_dropped();
                                continue;
                            }
                            Err(error) => return Some(format!("read upstream TUN: {error}")),
                        },
                    };
                    match relayable(&packet, local, lease.mtu) {
                        Relayable::Yes => {}
                        Relayable::ForeignSource(source) => {
                            metrics.upstream_dropped();
                            if !warned {
                                warned = true;
                                tracing::warn!(
                                    source = %source,
                                    relay_address = %local,
                                    "dropping upstream packet that was not masqueraded; check the Porta NAT rules"
                                );
                            }
                            continue;
                        }
                        Relayable::Invalid => {
                            metrics.upstream_dropped();
                            continue;
                        }
                    }
                    if translate(
                        &mut packet,
                        Direction::Outbound,
                        local,
                        lease.address.addr(),
                    )
                    .is_err()
                    {
                        metrics.upstream_dropped();
                        continue;
                    }
                    let result = tokio::select! {
                        biased;
                        _ = pumps.cancelled() => return None,
                        result = connection.send(&packet) => result,
                    };
                    if let Err(error) = result {
                        return Some(error.to_string());
                    }
                    metrics.upstream_sent();
                }
            }
        });

        let download = tokio::spawn({
            let connection = connection.clone();
            let device = self.device.clone();
            let metrics = self.metrics.clone();
            let pumps = pumps.clone();
            async move {
                loop {
                    let mut packet = tokio::select! {
                        biased;
                        _ = pumps.cancelled() => return None,
                        result = connection.receive() => match result {
                            Ok(packet) => Vec::from(packet),
                            Err(error) => return Some(error.to_string()),
                        },
                    };
                    if translate(&mut packet, Direction::Inbound, lease.address.addr(), local)
                        .is_err()
                    {
                        metrics.upstream_dropped();
                        continue;
                    }
                    let result = tokio::select! {
                        biased;
                        _ = pumps.cancelled() => return None,
                        result = device.write_packet(&packet) => result,
                    };
                    match result {
                        Ok(()) => metrics.upstream_received(),
                        Err(error) if error.kind() == io::ErrorKind::InvalidInput => {
                            metrics.upstream_dropped();
                        }
                        Err(error) => return Some(format!("write upstream TUN: {error}")),
                    }
                }
            }
        });

        let upload_abort = upload.abort_handle();
        let download_abort = download.abort_handle();
        let reason = tokio::select! {
            _ = cancellation.cancelled() => None,
            result = upload => result.unwrap_or_else(|error| Some(error.to_string())),
            result = download => result.unwrap_or_else(|error| Some(error.to_string())),
        };
        pumps.cancel();
        connection.close().await;
        upload_abort.abort();
        download_abort.abort();
        reason.unwrap_or_else(|| "gateway shutting down".to_owned())
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Relayable {
    Yes,
    ForeignSource(Ipv4Addr),
    Invalid,
}

fn relayable(packet: &[u8], local: Ipv4Addr, mtu: u16) -> Relayable {
    if packet.len() > usize::from(mtu) {
        return Relayable::Invalid;
    }
    match porta_wire::ip::parse_ipv4(packet) {
        Ok(info) if info.source == local => Relayable::Yes,
        Ok(info) => Relayable::ForeignSource(info.source),
        Err(_) => Relayable::Invalid,
    }
}

fn reconnect_delay(failures: u32, error: &ClientError) -> Duration {
    if !error.is_retryable() {
        // Authentication or protocol rejection needs operator action; retry
        // slowly so a fixed token or enrollment recovers without a restart.
        return MAX_RECONNECT_DELAY;
    }
    Duration::from_secs(1_u64 << failures.min(5)).min(MAX_RECONNECT_DELAY)
}

async fn sleep_or_cancel(delay: Duration, cancellation: &CancellationToken) -> bool {
    tokio::select! {
        _ = cancellation.cancelled() => false,
        _ = tokio::time::sleep(delay) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease() -> Lease {
        Lease {
            address: "10.77.0.5/32".parse().unwrap(),
            gateway: Some(Ipv4Addr::new(10, 77, 0, 1)),
            dns: None,
            mtu: 1280,
            address6: None,
        }
    }

    fn packet(source: [u8; 4], length: usize) -> Vec<u8> {
        let mut packet = vec![0_u8; length];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        packet
    }

    #[test]
    fn relays_only_masqueraded_packets_within_the_lease_mtu() {
        let local = Ipv4Addr::new(169, 254, 66, 1);
        assert_eq!(
            relayable(&packet([169, 254, 66, 1], 60), local, 1280),
            Relayable::Yes
        );
        assert_eq!(
            relayable(&packet([10, 66, 0, 2], 60), local, 1280),
            Relayable::ForeignSource(Ipv4Addr::new(10, 66, 0, 2))
        );
        assert_eq!(
            relayable(&packet([169, 254, 66, 1], 1281), local, 1280),
            Relayable::Invalid
        );
        assert_eq!(relayable(&[0x45, 0, 0], local, 1280), Relayable::Invalid);
    }

    #[test]
    fn rejected_credentials_retry_slowly_and_transient_failures_back_off() {
        assert_eq!(
            reconnect_delay(0, &ClientError::retryable("reset")),
            Duration::from_secs(1)
        );
        assert_eq!(
            reconnect_delay(3, &ClientError::unavailable("udp blocked")),
            Duration::from_secs(8)
        );
        assert_eq!(
            reconnect_delay(40, &ClientError::Closed),
            MAX_RECONNECT_DELAY
        );
        assert_eq!(
            reconnect_delay(0, &ClientError::permanent("401 Unauthorized")),
            MAX_RECONNECT_DELAY
        );
    }

    #[test]
    fn status_reports_the_last_failure_until_connected() {
        let status = UpstreamStatus::default();
        assert_eq!(status.check().unwrap_err(), "next-hop tunnel is connecting");
        status.failed("401 Unauthorized");
        assert!(status.check().unwrap_err().contains("401 Unauthorized"));
        status.connected(lease(), Transport::Http3);
        assert!(status.check().is_ok());
        assert_eq!(status.lease(), Some(lease()));
        status.failed("tunnel is closed");
        assert!(status.check().is_err());
        assert_eq!(status.lease(), None);
    }
}
