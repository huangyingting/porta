mod error;
mod h2;
mod h2_queue;
mod h3;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use bytes::Bytes;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use porta_wire::device_auth::Proof;
use rustls::ClientConfig as RustlsClientConfig;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

pub use error::{AccountDenial, ClientError};

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
    /// The device's IPv6 /128 on a dual-stack gateway.
    pub address6: Option<Ipv6Net>,
}

impl Lease {
    /// The IPv6 address the device configures: only when the tunnel MTU
    /// meets the IPv6 minimum, below which operating systems disable IPv6
    /// on the interface. Without it, clients keep IPv6 off the tunnel and
    /// guarded.
    pub fn ipv6(&self) -> Option<Ipv6Net> {
        self.address6
            .filter(|_| usize::from(self.mtu) >= porta_wire::ip::IPV6_MIN_MTU)
    }

    /// Whether `address` is one of the lease's own addresses.
    pub fn owns(&self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(address) => address == self.address.addr(),
            IpAddr::V6(address) => self.ipv6().is_some_and(|ipv6| ipv6.addr() == address),
        }
    }
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

/// Account limits reported by the gateway when the tunnel was established.
/// Usage is a snapshot taken at connection time.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AccountStatus {
    /// Unix time in seconds at which the account expires.
    pub expires_at: Option<i64>,
    pub quota_bytes: Option<u64>,
    pub quota_used_bytes: Option<u64>,
    pub rate_limit_kbps: Option<u32>,
}

impl AccountStatus {
    pub fn is_limited(&self) -> bool {
        self.expires_at.is_some() || self.quota_bytes.is_some() || self.rate_limit_kbps.is_some()
    }
}

pub const HEADER_ACCOUNT_EXPIRES: &str = "x-porta-account-expires";
pub const HEADER_QUOTA_BYTES: &str = "x-porta-quota-bytes";
pub const HEADER_QUOTA_USED_BYTES: &str = "x-porta-quota-used-bytes";
pub const HEADER_RATE_LIMIT_KBPS: &str = "x-porta-rate-limit-kbps";

/// Reads optional account headers; malformed values are ignored because
/// they are informational and never affect tunnel behavior.
pub fn parse_account_status(headers: &http::HeaderMap) -> AccountStatus {
    fn value<T: std::str::FromStr>(headers: &http::HeaderMap, name: &str) -> Option<T> {
        headers.get(name)?.to_str().ok()?.trim().parse().ok()
    }
    AccountStatus {
        expires_at: value(headers, HEADER_ACCOUNT_EXPIRES),
        quota_bytes: value(headers, HEADER_QUOTA_BYTES),
        quota_used_bytes: value(headers, HEADER_QUOTA_USED_BYTES),
        rate_limit_kbps: value(headers, HEADER_RATE_LIMIT_KBPS),
    }
}

/// Destinations the gateway routes through the tunnel and the DNS domains it
/// resolves. No routes means a full tunnel.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Routing {
    pub routes: Vec<Ipv4Net>,
    /// IPv6 split-tunnel prefixes; they apply only with an IPv6 lease.
    pub routes6: Vec<Ipv6Net>,
    pub dns_domains: Vec<String>,
    /// Networks behind this device that the gateway routes to it, when the
    /// device is a subnet router.
    pub subnets: Vec<Ipv4Net>,
}

impl Routing {
    pub fn is_full_tunnel(&self) -> bool {
        self.routes.is_empty()
    }

    /// Whether `address` lies in a network this device routes for others.
    pub fn serves(&self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(address) => self.subnets.iter().any(|subnet| subnet.contains(&address)),
            IpAddr::V6(_) => false,
        }
    }

    /// Whether `address` is sent through the tunnel.
    pub fn routes_address(&self, address: Ipv4Addr) -> bool {
        self.is_full_tunnel() || self.routes.iter().any(|route| route.contains(&address))
    }
}

pub const HEADER_ROUTES: &str = "x-porta-routes";
pub const HEADER_SUBNETS: &str = "x-porta-subnets";
const MAX_SUBNETS: usize = 16;
pub const HEADER_DNS_DOMAINS: &str = "x-porta-dns-domains";
const MAX_ROUTES: usize = 64;
const MAX_DNS_DOMAINS: usize = 16;

/// Reads split-tunnel routes. A malformed advertisement fails the tunnel
/// rather than silently becoming a full tunnel or dropping routes.
pub fn parse_routing(headers: &http::HeaderMap) -> Result<Routing, ClientError> {
    let text = |name: &str| -> Result<Option<String>, ClientError> {
        headers
            .get(name)
            .map(|value| {
                value
                    .to_str()
                    .map(str::to_owned)
                    .map_err(|_| ClientError::permanent(format!("gateway sent an invalid {name}")))
            })
            .transpose()
    };
    let prefixes = |name: &str| -> Result<Vec<IpNet>, ClientError> {
        let mut prefixes = Vec::new();
        if let Some(value) = text(name)? {
            for item in value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
            {
                let prefix = item
                    .parse::<IpNet>()
                    .ok()
                    .filter(|prefix| prefix.prefix_len() > 0 && *prefix == prefix.trunc())
                    .ok_or_else(|| {
                        ClientError::permanent(format!("gateway sent an invalid route {item:?}"))
                    })?;
                prefixes.push(prefix);
            }
        }
        Ok(prefixes)
    };
    let mut routes = Vec::new();
    let mut routes6 = Vec::new();
    for route in prefixes(HEADER_ROUTES)? {
        match route {
            IpNet::V4(route) => routes.push(route),
            IpNet::V6(route) => routes6.push(route),
        }
    }
    let subnets = prefixes(HEADER_SUBNETS)?
        .into_iter()
        .map(|subnet| match subnet {
            IpNet::V4(subnet) => Ok(subnet),
            IpNet::V6(subnet) => Err(ClientError::permanent(format!(
                "gateway sent an IPv6 subnet {subnet}; subnet routing is IPv4"
            ))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if subnets.len() > MAX_SUBNETS {
        return Err(ClientError::permanent("gateway sent too many subnets"));
    }
    let mut dns_domains = Vec::new();
    if let Some(value) = text(HEADER_DNS_DOMAINS)? {
        for item in value
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
        {
            let valid = item.len() <= 253
                && item.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && label
                            .bytes()
                            .all(|value| value.is_ascii_alphanumeric() || value == b'-')
                });
            if !valid {
                return Err(ClientError::permanent(format!(
                    "gateway sent an invalid DNS domain {item:?}"
                )));
            }
            dns_domains.push(item.to_ascii_lowercase());
        }
    }
    if routes.len() + routes6.len() > MAX_ROUTES || dns_domains.len() > MAX_DNS_DOMAINS {
        return Err(ClientError::permanent(
            "gateway sent too many routes or DNS domains",
        ));
    }
    if routes.is_empty() && !dns_domains.is_empty() {
        return Err(ClientError::permanent(
            "gateway sent DNS domains without split routes",
        ));
    }
    if routes.is_empty() && !routes6.is_empty() {
        return Err(ClientError::permanent(
            "gateway sent IPv6 routes without IPv4 split routes",
        ));
    }
    Ok(Routing {
        routes,
        routes6,
        dns_domains,
        subnets,
    })
}

pub struct Connection {
    pub lease: Lease,
    /// Routes and DNS domains advertised when the tunnel was established.
    pub routing: Routing,
    /// Latest gateway-reported limits; HTTP/2 lanes that reconnect within a
    /// connection update it. Read with [`Connection::account`].
    account: Arc<StdMutex<AccountStatus>>,
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

struct CancellationGuard {
    cancellation: Option<CancellationToken>,
}

impl CancellationGuard {
    fn new(cancellation: CancellationToken) -> Self {
        Self {
            cancellation: Some(cancellation),
        }
    }

    fn disarm(&mut self) {
        self.cancellation = None;
    }
}

impl Drop for CancellationGuard {
    fn drop(&mut self) {
        if let Some(cancellation) = self.cancellation.take() {
            cancellation.cancel();
        }
    }
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

/// The addresses an ADDRESS_ASSIGN capsule gives the client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Assignment {
    ipv4: Ipv4Net,
    ipv6: Option<Ipv6Net>,
}

enum Inbound {
    Packet(Bytes),
    MtuProbe(porta_wire::masque::MtuProbe),
    MtuSelected(Bytes),
    Address(Assignment),
    Failure(ClientError),
}

impl Connection {
    /// Account limits most recently reported by the gateway.
    pub fn account(&self) -> AccountStatus {
        *self.account.lock().expect("tunnel account lock poisoned")
    }

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
        let info = porta_wire::ip::parse_ip(packet)
            .map_err(|error| ClientError::permanent(error.to_string()))?;
        if !self.lease.owns(info.source) && !self.routing.serves(info.source) {
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
                    let Ok(info) = porta_wire::ip::parse_ip(&packet) else {
                        continue;
                    };
                    if self.lease.owns(info.destination) || self.routing.serves(info.destination) {
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
        }
        self.inner.tasks.wait().await;
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

/// Response header explaining why a gateway refused valid credentials.
pub const REASON_HEADER: &str = "x-porta-reason";

/// Returns the account denial a refused tunnel request reports, so users
/// learn why access ended rather than only an HTTP status.
fn account_denial(status: http::StatusCode, reason: Option<&str>) -> Option<ClientError> {
    (status == http::StatusCode::FORBIDDEN)
        .then(|| reason.and_then(AccountDenial::from_reason))
        .flatten()
        .map(ClientError::Denied)
}

fn valid_unicast6(address: std::net::Ipv6Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_multicast()
        && !address.is_unicast_link_local()
        && address.to_ipv4_mapped().is_none()
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
    async fn repeated_close_waits_for_workers_even_if_the_first_close_was_cancelled() {
        for abort_first in [false, true] {
            let cancellation = CancellationToken::new();
            let tasks = TaskTracker::new();
            let finish = Arc::new(Notify::new());
            let worker_finish = finish.clone();
            tasks.spawn(async move { worker_finish.notified().await });
            let (outbound, _) = mpsc::channel(1);
            let (_, inbound) = mpsc::channel(1);
            let connection = Arc::new(Connection {
                account: Default::default(),
                routing: Routing::default(),
                lease: Lease {
                    address: "10.66.0.2/32".parse().unwrap(),
                    gateway: None,
                    dns: None,
                    mtu: 1100,
                    address6: None,
                },
                remote_address: "127.0.0.1:443".parse().unwrap(),
                transport: Transport::Http3,
                delivery_mode: DeliveryMode::Capsule,
                mtu_automatic: false,
                mtu_ceiling: None,
                inner: Arc::new(ConnectionInner {
                    outbound,
                    inbound: Mutex::new(inbound),
                    failure: Arc::new(FailureSignal::default()),
                    cancellation: cancellation.clone(),
                    tasks: tasks.clone(),
                    closed: AtomicBool::new(false),
                }),
            });
            let first_connection = connection.clone();
            let first = tokio::spawn(async move { first_connection.close().await });
            cancellation.cancelled().await;
            if abort_first {
                first.abort();
            }
            let closing = connection.close();
            tokio::pin!(closing);
            assert!(
                tokio::time::timeout(Duration::from_millis(30), &mut closing)
                    .await
                    .is_err(),
                "close returned before the transport worker exited"
            );
            finish.notify_one();
            tokio::time::timeout(Duration::from_secs(1), closing)
                .await
                .unwrap();
            if abort_first {
                assert!(first.await.unwrap_err().is_cancelled());
            } else {
                first.await.unwrap();
            }
            assert!(tasks.is_empty());
            connection.close().await;
        }
    }

    #[test]
    fn setup_cancellation_guard_cancels_only_while_armed() {
        let cancelled = CancellationToken::new();
        {
            let _guard = CancellationGuard::new(cancelled.clone());
        }
        assert!(cancelled.is_cancelled());

        let retained = CancellationToken::new();
        {
            let mut guard = CancellationGuard::new(retained.clone());
            guard.disarm();
        }
        assert!(!retained.is_cancelled());
    }

    #[test]
    fn account_denials_are_structured_permanent_errors() {
        let forbidden = http::StatusCode::FORBIDDEN;
        let expired = account_denial(forbidden, Some("account-expired")).unwrap();
        assert_eq!(expired.denial(), Some(AccountDenial::Expired));
        assert!(expired.is_permanent() && !expired.is_retryable());
        assert!(expired.to_string().contains("expired"));
        assert_eq!(
            account_denial(forbidden, Some("quota-exceeded"))
                .unwrap()
                .denial(),
            Some(AccountDenial::QuotaExceeded)
        );
        for (code, denial) in [
            ("device-pending", AccountDenial::DevicePending),
            ("enrollment-closed", AccountDenial::EnrollmentClosed),
            ("device-denied", AccountDenial::DeviceDenied),
        ] {
            let error = account_denial(forbidden, Some(code)).unwrap();
            assert_eq!(error.denial(), Some(denial));
            assert_eq!(denial.code(), code);
            assert!(error.is_permanent());
        }
        assert!(account_denial(forbidden, Some("<script>")).is_none());
        assert!(account_denial(http::StatusCode::UNAUTHORIZED, Some("account-expired")).is_none());
    }

    #[test]
    fn split_routing_headers_are_strict() {
        let mut headers = http::HeaderMap::new();
        let full = parse_routing(&headers).unwrap();
        assert!(full.is_full_tunnel());
        assert!(full.routes_address(Ipv4Addr::new(8, 8, 8, 8)));
        headers.insert(HEADER_ROUTES, "10.0.0.0/8, 192.168.5.0/24".parse().unwrap());
        headers.insert(HEADER_DNS_DOMAINS, "Corp.Example,internal".parse().unwrap());
        let split = parse_routing(&headers).unwrap();
        assert_eq!(split.routes.len(), 2);
        assert_eq!(split.dns_domains, vec!["corp.example", "internal"]);
        assert!(split.routes_address(Ipv4Addr::new(10, 1, 2, 3)));
        assert!(!split.routes_address(Ipv4Addr::new(8, 8, 8, 8)));
        for invalid in ["10.0.0.1/8", "0.0.0.0/0", "not-a-route"] {
            headers.insert(HEADER_ROUTES, invalid.parse().unwrap());
            assert!(parse_routing(&headers).is_err(), "{invalid}");
        }
        headers.remove(HEADER_ROUTES);
        assert!(parse_routing(&headers).is_err());

        let mut headers = http::HeaderMap::new();
        headers.insert(HEADER_SUBNETS, "10.30.0.0/24".parse().unwrap());
        let router = parse_routing(&headers).unwrap();
        assert!(router.is_full_tunnel());
        assert!(router.serves(IpAddr::V4(Ipv4Addr::new(10, 30, 0, 5))));
        assert!(!router.serves(IpAddr::V4(Ipv4Addr::new(10, 31, 0, 5))));
        headers.insert(HEADER_SUBNETS, "10.30.0.1/24".parse().unwrap());
        assert!(parse_routing(&headers).is_err());
        headers.insert(HEADER_SUBNETS, "fd00::/64".parse().unwrap());
        assert!(parse_routing(&headers).is_err());

        let mut headers = http::HeaderMap::new();
        headers.insert(
            HEADER_ROUTES,
            "10.0.0.0/8,2001:db8::/32,fd66::/64".parse().unwrap(),
        );
        let dual = parse_routing(&headers).unwrap();
        assert_eq!(dual.routes.len(), 1);
        assert_eq!(dual.routes6.len(), 2);
        headers.insert(HEADER_ROUTES, "2001:db8::/32".parse().unwrap());
        assert!(parse_routing(&headers).is_err());
        headers.insert(HEADER_ROUTES, "10.0.0.0/8,::/0".parse().unwrap());
        assert!(parse_routing(&headers).is_err());
    }

    #[test]
    fn ipv6_leases_need_the_ipv6_minimum_mtu() {
        let mut lease = Lease {
            address: "10.66.0.2/32".parse().unwrap(),
            gateway: None,
            dns: None,
            mtu: 1400,
            address6: Some("fd66::2/128".parse().unwrap()),
        };
        assert_eq!(lease.ipv6(), lease.address6);
        assert!(lease.owns("fd66::2".parse().unwrap()));
        assert!(lease.owns("10.66.0.2".parse().unwrap()));
        assert!(!lease.owns("fd66::3".parse().unwrap()));
        lease.mtu = 1200;
        assert_eq!(lease.ipv6(), None);
        assert!(!lease.owns("fd66::2".parse().unwrap()));
    }

    #[test]
    fn account_status_headers_are_optional_and_tolerant() {
        let mut headers = http::HeaderMap::new();
        assert_eq!(parse_account_status(&headers), AccountStatus::default());
        assert!(!AccountStatus::default().is_limited());
        headers.insert(HEADER_ACCOUNT_EXPIRES, "1900000000".parse().unwrap());
        headers.insert(HEADER_QUOTA_BYTES, "2147483648".parse().unwrap());
        headers.insert(HEADER_QUOTA_USED_BYTES, "not-a-number".parse().unwrap());
        headers.insert(HEADER_RATE_LIMIT_KBPS, "5000".parse().unwrap());
        let status = parse_account_status(&headers);
        assert_eq!(status.expires_at, Some(1_900_000_000));
        assert_eq!(status.quota_bytes, Some(2_147_483_648));
        assert_eq!(status.quota_used_bytes, None);
        assert_eq!(status.rate_limit_kbps, Some(5000));
        assert!(status.is_limited());
    }

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
