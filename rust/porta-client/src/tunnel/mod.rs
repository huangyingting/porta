mod error;
mod h2;
mod h2_queue;
mod h3;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ipnet::Ipv4Net;
use porta_wire::device_auth::Proof;
use rustls::ClientConfig as RustlsClientConfig;
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

pub use error::ClientError;

pub const TUNNEL_PATH: &str = "/v1/tunnel";
pub const MASQUE_PATH: &str = "/.well-known/masque/ip/%2A/%2A/";
pub const MASQUE_AUTH_PATH: &str = "/.well-known/masque/ip/*/*/";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Transport {
    #[default]
    Auto,
    Http2,
    Http3,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DeliveryMode {
    #[default]
    Unknown,
    Framed,
    Capsule,
    Datagram,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lease {
    pub address: Ipv4Net,
    pub gateway: Option<Ipv4Addr>,
    pub dns: Option<Ipv4Addr>,
    pub mtu: u16,
}

pub trait ProofProvider: Send + Sync {
    fn proof(&self, method: &str, path: &str) -> Result<Proof, ClientError>;
}

impl<F> ProofProvider for F
where
    F: Fn(&str, &str) -> Result<Proof, ClientError> + Send + Sync,
{
    fn proof(&self, method: &str, path: &str) -> Result<Proof, ClientError> {
        self(method, path)
    }
}

pub trait SocketProtector: Send + Sync {
    fn prepare(&self, descriptor: i64) -> Result<(), ClientError>;
}

#[derive(Clone)]
pub struct ClientConfig {
    pub url: String,
    pub token: String,
    pub transport: Transport,
    pub tls: Arc<RustlsClientConfig>,
    pub timeout: Duration,
    pub dial_address: Option<SocketAddr>,
    pub proof: Arc<dyn ProofProvider>,
    pub socket_protector: Option<Arc<dyn SocketProtector>>,
    pub cancellation: CancellationToken,
}

pub struct Connection {
    pub lease: Lease,
    pub remote_address: SocketAddr,
    pub transport: Transport,
    pub delivery_mode: DeliveryMode,
    pub mtu_automatic: bool,
    pub mtu_ceiling: Option<u16>,
    inner: Arc<ConnectionInner>,
}

struct ConnectionInner {
    outbound: mpsc::Sender<Outbound>,
    inbound: Mutex<mpsc::Receiver<Inbound>>,
    cancellation: CancellationToken,
    tasks: TaskTracker,
    closed: AtomicBool,
}

enum Outbound {
    Packet {
        packet: Bytes,
        result: tokio::sync::oneshot::Sender<Result<(), ClientError>>,
    },
    Datagram {
        payload: Bytes,
        result: tokio::sync::oneshot::Sender<Result<(), ClientError>>,
    },
    Capsule {
        capsule_type: u64,
        value: Bytes,
        result: tokio::sync::oneshot::Sender<Result<(), ClientError>>,
    },
}

enum Inbound {
    Packet(Bytes),
    MtuProbe(porta_wire::masque::MtuProbe),
    MtuSelected(Bytes),
    Address(Ipv4Net),
    Failure(ClientError),
}

impl Connection {
    pub async fn send(&self, packet: &[u8]) -> Result<(), ClientError> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(ClientError::Closed);
        }
        if packet.len() > usize::from(self.lease.mtu) {
            return Err(ClientError::permanent(format!(
                "packet length {} exceeds tunnel MTU {}",
                packet.len(),
                self.lease.mtu
            )));
        }
        let info = porta_wire::ip::parse_ipv4(packet)
            .map_err(|error| ClientError::permanent(error.to_string()))?;
        if info.source != self.lease.address.addr() {
            return Err(ClientError::permanent(format!(
                "packet source {} does not match lease {}",
                info.source, self.lease.address
            )));
        }
        send_outbound(&self.inner.outbound, |result| Outbound::Packet {
            packet: Bytes::copy_from_slice(packet),
            result,
        })
        .await
    }

    pub async fn receive(&self) -> Result<Bytes, ClientError> {
        let mut inbound = self.inner.inbound.lock().await;
        loop {
            match inbound.recv().await {
                Some(Inbound::Packet(packet)) => {
                    if packet.len() > usize::from(self.lease.mtu) {
                        continue;
                    }
                    let Ok(info) = porta_wire::ip::parse_ipv4(&packet) else {
                        continue;
                    };
                    if info.destination == self.lease.address.addr() {
                        return Ok(packet);
                    }
                }
                Some(Inbound::Failure(error)) => return Err(error),
                Some(_) => {}
                None => return Err(ClientError::Closed),
            }
        }
    }

    pub async fn close(&self) {
        if !self.inner.closed.swap(true, Ordering::AcqRel) {
            self.inner.cancellation.cancel();
            self.inner.tasks.close();
            self.inner.tasks.wait().await;
        }
    }
}

impl Drop for ConnectionInner {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

pub async fn connect(config: ClientConfig) -> Result<Connection, ClientError> {
    if config.url.is_empty() || config.token.is_empty() {
        return Err(ClientError::permanent("gateway URL and token are required"));
    }
    if let Some(address) = config.dial_address {
        if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
            return Err(ClientError::permanent(
                "dial address must be a numeric unicast IP and port",
            ));
        }
    }
    let mut config = config;
    if config.timeout.is_zero() {
        config.timeout = Duration::from_secs(15);
    }
    match config.transport {
        Transport::Http3 => h3::connect(config).await,
        Transport::Auto => match h3::connect(config.clone()).await {
            Ok(connection) => Ok(connection),
            Err(error) if error.is_transport_unavailable() => h2::connect(config).await,
            Err(error) => Err(error),
        },
        Transport::Http2 => h2::connect(config).await,
    }
}

async fn send_outbound(
    sender: &mpsc::Sender<Outbound>,
    build: impl FnOnce(tokio::sync::oneshot::Sender<Result<(), ClientError>>) -> Outbound,
) -> Result<(), ClientError> {
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    sender
        .send(build(result_tx))
        .await
        .map_err(|_| ClientError::Closed)?;
    result_rx.await.map_err(|_| ClientError::Closed)?
}

fn valid_unicast(address: Ipv4Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_multicast()
        && address != Ipv4Addr::BROADCAST
}
