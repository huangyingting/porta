mod error;
mod h2;
mod h2_queue;
mod h3;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use bytes::Bytes;
use ipnet::Ipv4Net;
use porta_wire::device_auth::Proof;
use rustls::ClientConfig as RustlsClientConfig;
use tokio::sync::{mpsc, Mutex, Notify};
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
    failure: Arc<FailureSignal>,
    cancellation: CancellationToken,
    tasks: TaskTracker,
    closed: AtomicBool,
}

#[derive(Default)]
struct FailureSignal {
    failed: AtomicBool,
    error: StdMutex<Option<ClientError>>,
    changed: Notify,
}

impl FailureSignal {
    fn set(&self, error: ClientError) -> bool {
        let mut current = self.error.lock().expect("tunnel failure lock poisoned");
        if current.is_some() {
            return false;
        }
        *current = Some(error);
        self.failed.store(true, Ordering::Release);
        drop(current);
        self.changed.notify_waiters();
        true
    }

    fn current(&self) -> Option<ClientError> {
        if !self.failed.load(Ordering::Acquire) {
            return None;
        }
        self.error
            .lock()
            .expect("tunnel failure lock poisoned")
            .clone()
    }

    async fn next(&self, inbound: &mut mpsc::Receiver<Inbound>) -> Result<Inbound, ClientError> {
        loop {
            let changed = self.changed.notified();
            if let Some(error) = self.current() {
                return Err(error);
            }
            tokio::select! {
                biased;
                _ = changed => {}
                value = inbound.recv() => return value.ok_or(ClientError::Closed),
            }
        }
    }
}

enum Outbound {
    Packet {
        packet: Bytes,
        result: tokio::sync::oneshot::Sender<Result<(), ClientError>>,
    },
    Datagram {
        payload: Bytes,
        result: tokio::sync::oneshot::Sender<Result<DatagramSend, ClientError>>,
    },
    Capsule {
        capsule_type: u64,
        value: Bytes,
        result: tokio::sync::oneshot::Sender<Result<(), ClientError>>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DatagramSend {
    Sent,
    TooLarge,
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
        if let Some(error) = self.inner.failure.current() {
            return Err(error);
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
        send_outbound(&self.inner.outbound, &self.inner.failure, |result| {
            Outbound::Packet {
                packet: Bytes::copy_from_slice(packet),
                result,
            }
        })
        .await
    }

    pub async fn receive(&self) -> Result<Bytes, ClientError> {
        let mut inbound = self.inner.inbound.lock().await;
        loop {
            match self.inner.failure.next(&mut inbound).await? {
                Inbound::Packet(packet) => {
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
                Inbound::Failure(error) => return Err(error),
                _ => {}
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

async fn send_outbound<T>(
    sender: &mpsc::Sender<Outbound>,
    failure: &FailureSignal,
    build: impl FnOnce(tokio::sync::oneshot::Sender<Result<T, ClientError>>) -> Outbound,
) -> Result<T, ClientError> {
    if let Some(error) = failure.current() {
        return Err(error);
    }
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    if sender.send(build(result_tx)).await.is_err() {
        return Err(failure.current().unwrap_or(ClientError::Closed));
    }
    match result_rx.await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(error)) => Err(failure.current().unwrap_or(error)),
        Err(_) => Err(failure.current().unwrap_or(ClientError::Closed)),
    }
}

fn valid_unicast(address: Ipv4Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_multicast()
        && address != Ipv4Addr::BROADCAST
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pending_send_returns_the_stored_terminal_failure() {
        let failure = Arc::new(FailureSignal::default());
        let (outbound, mut requests) = mpsc::channel(1);
        let pending_failure = failure.clone();
        let pending = tokio::spawn(async move {
            send_outbound(&outbound, &pending_failure, |result| Outbound::Packet {
                packet: Bytes::new(),
                result,
            })
            .await
        });
        let Outbound::Packet { result, .. } =
            requests.recv().await.expect("pending outbound request")
        else {
            panic!("unexpected outbound request");
        };

        assert!(failure.set(ClientError::permanent("invalid tunnel response")));
        result
            .send(Err(ClientError::retryable("connection cancelled")))
            .expect("pending request receiver");
        assert!(matches!(
            pending.await.unwrap(),
            Err(ClientError::Permanent(message)) if message == "invalid tunnel response"
        ));
    }
}
