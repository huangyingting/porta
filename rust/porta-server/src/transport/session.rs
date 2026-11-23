use bytes::Bytes;
use futures_util::future::BoxFuture;
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::wire::ip::{classify_packet, FlowKey, PacketClass};
pub use porta_wire::mtu::MtuError;

pub const TUNNEL_PATH: &str = "/v1/tunnel";
pub const MASQUE_PATH: &str = "/.well-known/masque/ip/%2A/%2A/";
pub const MASQUE_AUTH_PATH: &str = "/.well-known/masque/ip/*/*/";
pub const PROTOCOL_VERSION: &str = "2";
pub const HEADER_VERSION: &str = "X-Porta-Version";
pub const HEADER_MIN_VERSION: &str = "X-Porta-Min-Version";
pub const HEADER_MAX_VERSION: &str = "X-Porta-Max-Version";
pub const CONTENT_TYPE: &str = "application/x-porta-packets";
pub const HEADER_LANE_SESSION: &str = "X-Porta-Lane-Session";
pub const HEADER_LANE: &str = "X-Porta-Lane";
pub const HEADER_LANES: &str = "X-Porta-Lanes";
pub const MIN_LANES: u8 = 2;
pub const MAX_LANES: u8 = 4;
pub const PACKET_BATCH: usize = 16;
pub const BATCH_BYTES: usize = 16 << 10;
static NEXT_TUNNEL_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeviceProof {
    pub device_id: String,
    pub name: String,
    pub public_key: String,
    pub timestamp: String,
    pub nonce: String,
    pub signature: String,
}

impl DeviceProof {
    pub fn from_headers(headers: &http::HeaderMap) -> Self {
        let value = |name: &'static str| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned()
        };
        Self {
            device_id: value("X-Porta-Client-ID"),
            name: value("X-Porta-Device-Name"),
            public_key: value("X-Porta-Device-Key"),
            timestamp: value("X-Porta-Device-Time"),
            nonce: value("X-Porta-Device-Nonce"),
            signature: value("X-Porta-Device-Signature"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientIdentity {
    pub account_id: String,
    pub lease_id: String,
}

#[derive(Clone, Debug)]
pub struct AuthenticationRequest {
    pub bearer_token: String,
    pub proof: DeviceProof,
    pub method: http::Method,
    pub path: String,
    pub peer: std::net::SocketAddr,
}

pub trait Cleanup: Send + Sync {
    fn close(&self);
}

#[derive(Default)]
pub struct NoopCleanup;

impl Cleanup for NoopCleanup {
    fn close(&self) {}
}

pub trait Cancellation: Send + Sync {
    fn token(&self) -> CancellationToken;
    fn cancel(&self);
}

pub struct TokenCancellation {
    token: CancellationToken,
}

impl TokenCancellation {
    pub fn new(token: CancellationToken) -> Self {
        Self { token }
    }
}

impl Cancellation for TokenCancellation {
    fn token(&self) -> CancellationToken {
        self.token.clone()
    }

    fn cancel(&self) {
        self.token.cancel();
    }
}

pub struct Authenticated {
    pub identity: ClientIdentity,
    pub cancellation: Arc<dyn Cancellation>,
    pub cleanup: Arc<dyn Cleanup>,
    pub account: AccountStatus,
    pub network: NetworkPolicy,
}

/// Network rules for one device's tunnel, enforced by the packet router.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NetworkPolicy {
    /// Destinations the device may reach; empty allows every destination.
    pub allow: Vec<ipnet::IpNet>,
    /// Destinations the device may never reach; takes precedence over `allow`.
    pub deny: Vec<ipnet::IpNet>,
    /// Devices of accounts in the same group reach each other.
    pub group: Option<String>,
    /// Named exit for the device's traffic; unset uses the gateway default.
    pub exit: Option<String>,
    /// Networks behind this device that it routes for other clients.
    pub subnets: Vec<ipnet::Ipv4Net>,
    /// Subnets behind other devices, added to split-tunnel routes.
    pub published: Vec<ipnet::Ipv4Net>,
}

impl NetworkPolicy {
    /// Whether the allow and deny lists let the device exchange packets
    /// with `address`.
    pub fn permits(&self, address: IpAddr) -> bool {
        !self.deny.iter().any(|prefix| prefix.contains(&address))
            && (self.allow.is_empty() || self.allow.iter().any(|prefix| prefix.contains(&address)))
    }

    /// Whether `address` lies in a network behind this device.
    pub fn routes_subnet(&self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(address) => self.subnets.iter().any(|subnet| subnet.contains(&address)),
            IpAddr::V6(_) => false,
        }
    }
}

/// Account limits reported to the client when a tunnel is established.
/// Usage is a snapshot; enforcement does not depend on the client.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AccountStatus {
    /// Unix time in seconds.
    pub expires_at: Option<i64>,
    pub quota_bytes: Option<u64>,
    pub quota_used_bytes: Option<u64>,
    pub rate_limit_kbps: Option<u32>,
}

pub const HEADER_ACCOUNT_EXPIRES: &str = "x-porta-account-expires";
pub const HEADER_QUOTA_BYTES: &str = "x-porta-quota-bytes";
pub const HEADER_QUOTA_USED_BYTES: &str = "x-porta-quota-used-bytes";
pub const HEADER_RATE_LIMIT_KBPS: &str = "x-porta-rate-limit-kbps";

pub fn set_account_headers(headers: &mut http::HeaderMap, account: &AccountStatus) {
    let values = [
        (
            HEADER_ACCOUNT_EXPIRES,
            account.expires_at.map(|value| value.to_string()),
        ),
        (
            HEADER_QUOTA_BYTES,
            account.quota_bytes.map(|value| value.to_string()),
        ),
        (
            HEADER_QUOTA_USED_BYTES,
            account
                .quota_bytes
                .and(account.quota_used_bytes)
                .map(|value| value.to_string()),
        ),
        (
            HEADER_RATE_LIMIT_KBPS,
            account.rate_limit_kbps.map(|value| value.to_string()),
        ),
    ];
    for (name, value) in values {
        if let Some(value) = value.and_then(|value| http::HeaderValue::from_str(&value).ok()) {
            headers.insert(name, value);
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AuthenticationError {
    #[error("authentication failed")]
    Unauthorized,
    /// Valid credentials whose account may not connect now; the reason is
    /// reported to the client.
    #[error("account access denied: {0}")]
    Forbidden(DenialReason),
    #[error("too many authentication attempts")]
    RateLimited { retry_after_seconds: u64 },
    /// This gateway cannot admit the client now; another gateway may.
    #[error("{0}")]
    Unavailable(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenialReason {
    AccountExpired,
    QuotaExceeded,
    DevicePending,
    EnrollmentClosed,
    DeviceDenied,
}

impl DenialReason {
    /// Value of the `X-Porta-Reason` response header.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccountExpired => "account-expired",
            Self::QuotaExceeded => "quota-exceeded",
            Self::DevicePending => "device-pending",
            Self::EnrollmentClosed => "enrollment-closed",
            Self::DeviceDenied => "device-denied",
        }
    }
}

impl std::fmt::Display for DenialReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

pub const REASON_HEADER: &str = "x-porta-reason";

pub trait Authenticator: Send + Sync {
    fn authenticate(
        &self,
        request: AuthenticationRequest,
    ) -> BoxFuture<'static, Result<Authenticated, AuthenticationError>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseMode {
    Exclusive,
    LaneGroup,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseRequest {
    pub lease_id: String,
    pub group_id: Option<String>,
    pub mode: LeaseMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lease {
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Ipv4Addr,
    pub opaque_id: u64,
    /// The device's IPv6 address on a dual-stack gateway.
    pub ipv6: Option<Ipv6Lease>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv6Lease {
    pub address: Ipv6Addr,
    pub prefix_len: u8,
    pub gateway: Ipv6Addr,
}

impl Lease {
    pub fn prefix(&self) -> String {
        format!("{}/{}", self.address, self.prefix_len)
    }

    /// Whether `address` is one of this lease's own addresses.
    pub fn owns(&self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(address) => address == self.address,
            IpAddr::V6(address) => self.ipv6.is_some_and(|lease| lease.address == address),
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum LeaseError {
    #[error("no tunnel addresses available")]
    Exhausted,
    #[error("lease allocation failed")]
    Internal,
}

pub trait LeaseAllocator: Send + Sync {
    fn acquire(&self, request: LeaseRequest) -> BoxFuture<'static, Result<Lease, LeaseError>>;
    fn release(&self, lease: &Lease);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteKind {
    Http2Lane {
        session_id: String,
        lane: u8,
        lanes: u8,
        backend_connection: String,
    },
    ConnectIp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteRequest {
    pub lease: Lease,
    pub kind: RouteKind,
    pub parent: CancellationToken,
    /// Account whose throughput limit applies to the route.
    pub account_id: String,
    pub device_id: String,
    pub network: NetworkPolicy,
}

pub trait PacketSource: Send + Sync {
    fn next_packet(&self) -> BoxFuture<'_, Option<Bytes>>;
    fn try_packet(&self) -> Option<Bytes>;
    fn queued_bytes(&self) -> usize;
}

pub struct RouteSession {
    pub downlink: Arc<dyn PacketSource>,
    pub cancellation: CancellationToken,
    pub collapsed_backend: bool,
    pub cleanup: Arc<dyn Cleanup>,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RouteError {
    #[error("invalid tunnel lane group")]
    Conflict,
    #[error("packet router unavailable")]
    Unavailable,
}

pub trait PacketRouter: Send + Sync {
    fn register(
        &self,
        request: RouteRequest,
    ) -> BoxFuture<'static, Result<RouteSession, RouteError>>;

    fn inject_from_client(
        &self,
        cancellation: CancellationToken,
        lease: Ipv4Addr,
        packet: Bytes,
    ) -> BoxFuture<'static, Result<(), RouteError>>;

    fn inject_validated(
        &self,
        cancellation: CancellationToken,
        packet: Bytes,
    ) -> BoxFuture<'static, Result<(), RouteError>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsageMetadata {
    pub account_id: String,
    pub device_id: String,
    pub transport: String,
    pub address: Ipv4Addr,
    pub address6: Option<Ipv6Addr>,
    pub session_id: String,
}

pub trait UsageSession: Send + Sync {
    fn uploaded(&self, bytes: u64, packets: u64);
    fn downloaded(&self, bytes: u64, packets: u64);
    fn close(&self);
}

pub trait Usage: Send + Sync {
    fn begin(&self, metadata: UsageMetadata) -> Arc<dyn UsageSession>;
}

#[derive(Default)]
pub struct NoopUsage;

impl Usage for NoopUsage {
    fn begin(&self, _metadata: UsageMetadata) -> Arc<dyn UsageSession> {
        Arc::new(NoopUsageSession)
    }
}

struct NoopUsageSession;

impl UsageSession for NoopUsageSession {
    fn uploaded(&self, _bytes: u64, _packets: u64) {}
    fn downloaded(&self, _bytes: u64, _packets: u64) {}
    fn close(&self) {}
}

struct CountedUsage {
    inner: Arc<dyn UsageSession>,
    uploaded_bytes: AtomicU64,
    uploaded_packets: AtomicU64,
    downloaded_bytes: AtomicU64,
    downloaded_packets: AtomicU64,
}

impl CountedUsage {
    fn new(inner: Arc<dyn UsageSession>) -> Self {
        Self {
            inner,
            uploaded_bytes: AtomicU64::new(0),
            uploaded_packets: AtomicU64::new(0),
            downloaded_bytes: AtomicU64::new(0),
            downloaded_packets: AtomicU64::new(0),
        }
    }
}

impl UsageSession for CountedUsage {
    fn uploaded(&self, bytes: u64, packets: u64) {
        self.uploaded_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.uploaded_packets.fetch_add(packets, Ordering::Relaxed);
        self.inner.uploaded(bytes, packets);
    }

    fn downloaded(&self, bytes: u64, packets: u64) {
        self.downloaded_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.downloaded_packets
            .fetch_add(packets, Ordering::Relaxed);
        self.inner.downloaded(bytes, packets);
    }

    fn close(&self) {
        self.inner.close();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueDrop {
    Closed,
    Full,
    Tail,
    Oldest,
    Expired,
}

pub trait Metrics: Send + Sync {
    fn authentication_failed(&self) {}
    fn connected(&self) {}
    fn disconnected(&self) {}
    fn received_from_client(&self) {}
    fn sent_to_client(&self) {}
    fn dropped_from_client(&self) {}
    fn datagram_oversize(&self) {}
    fn datagram_mtu_reduced(&self) {}
    fn collapsed_lane_group(&self) {}
    fn queue_drop(&self, _lane: i8, _reason: QueueDrop) {}
    fn queue_bytes(&self, _lane: i8, _delta: isize) {}
    fn invalid_tun_packet(&self) {}
    fn mtu_fragmented(&self) {}
    fn mtu_icmp_sent(&self) {}
    fn mtu_icmp_suppressed(&self) {}
    fn mtu_icmp_rate_limited(&self) {}
}

#[derive(Default)]
pub struct NoopMetrics;

impl Metrics for NoopMetrics {}

#[derive(Clone)]
pub struct Services {
    pub authenticator: Arc<dyn Authenticator>,
    pub leases: Arc<dyn LeaseAllocator>,
    pub router: Arc<dyn PacketRouter>,
    pub usage: Arc<dyn Usage>,
    pub metrics: Arc<dyn Metrics>,
    /// Destinations clients route through the tunnel by default.
    pub routing: TunnelRouting,
    /// Ends every tunnel when the gateway stops, so that shutdown and
    /// in-place restarts need not wait for clients to disconnect.
    pub shutdown: CancellationToken,
}

/// Which destinations a client sends through the tunnel, and which DNS
/// names it resolves through the tunnel's DNS server.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TunnelRouting {
    /// Empty means a full tunnel.
    pub routes: Vec<ipnet::IpNet>,
    /// With split routes: domains resolved by the tunnel DNS server.
    pub dns_domains: Vec<String>,
    /// Networks behind this client that the gateway routes to it.
    pub subnets: Vec<ipnet::Ipv4Net>,
    /// The client has an IPv6 address: IPv6 routes apply, and a full
    /// tunnel carries IPv6 as well.
    pub ipv6: bool,
}

pub const HEADER_ROUTES: &str = "x-porta-routes";
/// The client's IPv6 address on HTTP/2; HTTP/3 assigns it in a capsule.
pub const HEADER_ADDRESS6: &str = "x-porta-address6";
pub const HEADER_DNS_DOMAINS: &str = "x-porta-dns-domains";
pub const HEADER_SUBNETS: &str = "x-porta-subnets";

impl TunnelRouting {
    pub fn is_full_tunnel(&self) -> bool {
        self.routes.is_empty()
    }

    /// Routes as RFC 9484 ROUTE_ADVERTISEMENT ranges; IPv6 ranges only
    /// with an IPv6 address.
    pub fn advertisement(&self) -> Vec<crate::wire::masque::Route> {
        let ipv6 = self.ipv6;
        let mut routes = if self.routes.is_empty() {
            let mut routes = vec![crate::wire::masque::Route {
                start: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                end: IpAddr::V4(Ipv4Addr::BROADCAST),
                protocol: 0,
            }];
            if ipv6 {
                routes.push(crate::wire::masque::Route {
                    start: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    end: IpAddr::V6(Ipv6Addr::from(u128::MAX)),
                    protocol: 0,
                });
            }
            routes
        } else {
            self.routes
                .iter()
                .filter(|route| ipv6 || matches!(route, ipnet::IpNet::V4(_)))
                .map(|route| crate::wire::masque::Route {
                    start: route.network(),
                    end: route.broadcast(),
                    protocol: 0,
                })
                .collect::<Vec<_>>()
        };
        // IPv4 ranges precede IPv6 ranges, each in address order.
        routes.sort_by_key(|route| (route.start.is_ipv6(), route.start));
        routes
    }

    pub fn set_headers(&self, headers: &mut http::HeaderMap) {
        if !self.routes.is_empty() {
            let routes = self
                .routes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            if let Ok(value) = http::HeaderValue::from_str(&routes) {
                headers.insert(HEADER_ROUTES, value);
            }
        }
        if !self.dns_domains.is_empty() {
            if let Ok(value) = http::HeaderValue::from_str(&self.dns_domains.join(",")) {
                headers.insert(HEADER_DNS_DOMAINS, value);
            }
        }
        if !self.subnets.is_empty() {
            let subnets = self
                .subnets
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            if let Ok(value) = http::HeaderValue::from_str(&subnets) {
                headers.insert(HEADER_SUBNETS, value);
            }
        }
    }

    /// The routing one device receives: its own subnets, and in a split
    /// tunnel also the subnets other devices publish. IPv6 routes, and in a
    /// split tunnel the IPv6 client pool, apply only with an IPv6 address.
    pub fn for_device(&self, network: &NetworkPolicy, ipv6: Option<ipnet::Ipv6Net>) -> Self {
        let mut routing = self.clone();
        routing.subnets.clone_from(&network.subnets);
        routing.ipv6 = ipv6.is_some();
        match ipv6 {
            None => routing
                .routes
                .retain(|route| matches!(route, ipnet::IpNet::V4(_))),
            Some(pool) => {
                let pool = ipnet::IpNet::V6(pool.trunc());
                if !routing.is_full_tunnel() && !routing.routes.contains(&pool) {
                    routing.routes.push(pool);
                }
            }
        }
        if !routing.is_full_tunnel() {
            for subnet in &network.published {
                let subnet = ipnet::IpNet::V4(*subnet);
                if !routing.routes.contains(&subnet) {
                    routing.routes.push(subnet);
                }
            }
        }
        routing
    }
}

pub struct OpenSessionRequest {
    pub authentication: AuthenticationRequest,
    pub group_id: Option<String>,
    pub route: RouteKind,
    pub transport: String,
}

#[derive(Debug, Error)]
pub enum OpenSessionError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("account access denied: {0}")]
    Forbidden(DenialReason),
    #[error("too many authentication attempts")]
    RateLimited { retry_after_seconds: u64 },
    #[error("{0}")]
    Unavailable(&'static str),
    #[error(transparent)]
    Lease(#[from] LeaseError),
    #[error(transparent)]
    Route(#[from] RouteError),
}

impl Services {
    pub async fn open(
        self: &Arc<Self>,
        request: OpenSessionRequest,
    ) -> Result<Session, OpenSessionError> {
        let peer = request.authentication.peer;
        let proof = request.authentication.proof.clone();
        let transport = request.transport.clone();
        let session_id = request.group_id.clone().unwrap_or_default();
        let authenticated = match self
            .authenticator
            .authenticate(request.authentication)
            .await
        {
            Ok(authenticated) => authenticated,
            Err(AuthenticationError::Unauthorized) => {
                self.metrics.authentication_failed();
                return Err(OpenSessionError::Unauthorized);
            }
            Err(AuthenticationError::Forbidden(reason)) => {
                return Err(OpenSessionError::Forbidden(reason));
            }
            Err(AuthenticationError::RateLimited {
                retry_after_seconds,
            }) => {
                return Err(OpenSessionError::RateLimited {
                    retry_after_seconds,
                });
            }
            Err(AuthenticationError::Unavailable(message)) => {
                return Err(OpenSessionError::Unavailable(message));
            }
        };
        let lease_request = LeaseRequest {
            lease_id: authenticated.identity.lease_id.clone(),
            group_id: request.group_id.clone(),
            mode: if request.group_id.is_some() {
                LeaseMode::LaneGroup
            } else {
                LeaseMode::Exclusive
            },
        };
        let mut lease = match self.leases.acquire(lease_request).await {
            Ok(lease) => lease,
            Err(error) => {
                authenticated.cancellation.cancel();
                authenticated.cleanup.close();
                return Err(error.into());
            }
        };
        // Named exits carry IPv4 only; their devices get no IPv6 address so
        // that IPv6 never leaves through the default exit instead.
        if authenticated.network.exit.is_some() {
            lease.ipv6 = None;
        }
        let route = match self
            .router
            .register(RouteRequest {
                lease: lease.clone(),
                kind: request.route,
                parent: authenticated.cancellation.token(),
                account_id: authenticated.identity.account_id.clone(),
                device_id: proof.device_id.clone(),
                network: authenticated.network.clone(),
            })
            .await
        {
            Ok(route) => route,
            Err(error) => {
                self.leases.release(&lease);
                authenticated.cancellation.cancel();
                authenticated.cleanup.close();
                return Err(error.into());
            }
        };
        let usage = Arc::new(CountedUsage::new(self.usage.begin(UsageMetadata {
            account_id: authenticated.identity.account_id.clone(),
            device_id: proof.device_id.clone(),
            transport: transport.clone(),
            address: lease.address,
            address6: lease.ipv6.map(|ipv6| ipv6.address),
            session_id: session_id.clone(),
        })));
        let tunnel_id = NEXT_TUNNEL_ID.fetch_add(1, Ordering::Relaxed);
        let shutdown = self.shutdown.clone();
        let ended = route.cancellation.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = shutdown.cancelled() => ended.cancel(),
                _ = ended.cancelled() => {}
            }
        });
        self.metrics.connected();
        tracing::info!(
            tunnel_id,
            account_id = %authenticated.identity.account_id,
            device_id = %proof.device_id,
            device_name = %proof.name,
            address = %lease.address,
            ipv6 = %lease.ipv6.map(|ipv6| ipv6.address.to_string()).unwrap_or_default(),
            transport,
            peer = %peer,
            session_id,
            "tunnel connected"
        );
        let routing = self.routing.for_device(
            &authenticated.network,
            lease.ipv6.map(|ipv6| {
                ipnet::Ipv6Net::new(ipv6.address, ipv6.prefix_len)
                    .expect("validated IPv6 lease prefix")
            }),
        );
        Ok(Session {
            services: self.clone(),
            identity: authenticated.identity,
            proof,
            lease,
            peer,
            transport,
            session_id,
            tunnel_id,
            opened_at: Instant::now(),
            downlink: route.downlink,
            cancellation: route.cancellation,
            collapsed_backend: route.collapsed_backend,
            auth_cancellation: authenticated.cancellation,
            auth_cleanup: authenticated.cleanup,
            route_cleanup: route.cleanup,
            usage: usage.clone(),
            counted_usage: usage,
            account: authenticated.account,
            routing,
            closed: AtomicBool::new(false),
        })
    }
}

pub struct Session {
    services: Arc<Services>,
    pub identity: ClientIdentity,
    pub proof: DeviceProof,
    pub lease: Lease,
    peer: std::net::SocketAddr,
    transport: String,
    session_id: String,
    pub(crate) tunnel_id: u64,
    opened_at: Instant,
    pub downlink: Arc<dyn PacketSource>,
    pub cancellation: CancellationToken,
    pub collapsed_backend: bool,
    auth_cancellation: Arc<dyn Cancellation>,
    auth_cleanup: Arc<dyn Cleanup>,
    route_cleanup: Arc<dyn Cleanup>,
    pub usage: Arc<dyn UsageSession>,
    counted_usage: Arc<CountedUsage>,
    pub account: AccountStatus,
    pub routing: TunnelRouting,
    closed: AtomicBool,
}

impl Session {
    /// Whether the client may send packets from `source`: its lease or, on a
    /// subnet router, a network behind it.
    pub fn may_send_from(&self, source: IpAddr) -> bool {
        self.lease.owns(source)
            || match source {
                IpAddr::V4(source) => self
                    .routing
                    .subnets
                    .iter()
                    .any(|subnet| subnet.contains(&source)),
                IpAddr::V6(_) => false,
            }
    }

    pub fn close(&self) {
        self.close_with_reason(if self.cancellation.is_cancelled() {
            "cancelled"
        } else {
            "unspecified"
        });
    }

    pub(crate) fn close_with_reason(&self, reason: &'static str) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.cancellation.cancel();
        self.auth_cancellation.cancel();
        self.route_cleanup.close();
        self.services.leases.release(&self.lease);
        self.usage.close();
        self.auth_cleanup.close();
        self.services.metrics.disconnected();
        tracing::info!(
            tunnel_id = self.tunnel_id,
            account_id = %self.identity.account_id,
            device_id = %self.proof.device_id,
            address = %self.lease.address,
            transport = %self.transport,
            peer = %self.peer,
            session_id = %self.session_id,
            duration_ms = u64::try_from(self.opened_at.elapsed().as_millis()).unwrap_or(u64::MAX),
            reason,
            uploaded_ip_bytes = self.counted_usage.uploaded_bytes.load(Ordering::Relaxed),
            uploaded_ip_packets = self.counted_usage.uploaded_packets.load(Ordering::Relaxed),
            // Usage accounting can precede the transport write; these are not delivery counters.
            downlink_accounted_ip_bytes = self.counted_usage.downloaded_bytes.load(Ordering::Relaxed),
            downlink_accounted_ip_packets = self.counted_usage.downloaded_packets.load(Ordering::Relaxed),
            "tunnel disconnected"
        );
    }

    pub fn services(&self) -> &Arc<Services> {
        &self.services
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.close();
    }
}

pub fn bearer_token(headers: &http::HeaderMap) -> Result<String, AuthenticationError> {
    let value = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(AuthenticationError::Unauthorized)?;
    const PREFIX: &str = "Bearer ";
    if value.len() < PREFIX.len() || !value[..PREFIX.len()].eq_ignore_ascii_case(PREFIX) {
        return Err(AuthenticationError::Unauthorized);
    }
    let token = &value[PREFIX.len()..];
    if !(16..=512).contains(&token.len()) {
        return Err(AuthenticationError::Unauthorized);
    }
    Ok(token.to_owned())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaneConfig {
    pub session_id: String,
    pub index: u8,
    pub count: u8,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum LaneConfigError {
    #[error("invalid tunnel lane session")]
    Session,
    #[error("invalid tunnel lane index")]
    Index,
    #[error("invalid tunnel lane count")]
    Count,
}

pub fn parse_lane_config(headers: &http::HeaderMap) -> Result<LaneConfig, LaneConfigError> {
    let text = |name| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .unwrap_or_default()
    };
    let session_id = text(HEADER_LANE_SESSION);
    if !(16..=64).contains(&session_id.len())
        || !session_id
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'_' | b'-'))
    {
        return Err(LaneConfigError::Session);
    }
    let index = text(HEADER_LANE)
        .parse::<u8>()
        .map_err(|_| LaneConfigError::Index)?;
    let count = text(HEADER_LANES)
        .parse::<u8>()
        .map_err(|_| LaneConfigError::Count)?;
    if !(MIN_LANES..=MAX_LANES).contains(&count) || index >= count {
        return Err(LaneConfigError::Count);
    }
    Ok(LaneConfig {
        session_id: session_id.to_owned(),
        index,
        count,
    })
}

#[derive(Clone, Copy, Debug)]
pub struct QueueConfig {
    pub max_packets: usize,
    pub max_bytes: usize,
    pub tcp_max_age: Option<Duration>,
    pub datagram_max_age: Option<Duration>,
    pub control_max_age: Option<Duration>,
    pub drop_oldest: bool,
}

impl QueueConfig {
    pub const HTTP2: Self = Self {
        max_packets: 96,
        max_bytes: 128 << 10,
        tcp_max_age: Some(Duration::from_millis(500)),
        datagram_max_age: Some(Duration::from_millis(150)),
        control_max_age: Some(Duration::from_millis(250)),
        drop_oldest: false,
    };

    pub const MASQUE: Self = Self {
        max_packets: 256,
        max_bytes: 256 * 9000,
        tcp_max_age: None,
        datagram_max_age: None,
        control_max_age: None,
        drop_oldest: true,
    };
}

struct QueuedPacket {
    data: Bytes,
    class: PacketClass,
    enqueued: Instant,
}

struct QueueState {
    packets: VecDeque<QueuedPacket>,
    bytes: usize,
    closed: bool,
}

pub struct PacketQueue {
    config: QueueConfig,
    lane: i8,
    metrics: Arc<dyn Metrics>,
    state: Mutex<QueueState>,
    ready: Notify,
}

impl PacketQueue {
    pub fn new(config: QueueConfig, lane: i8, metrics: Arc<dyn Metrics>) -> Arc<Self> {
        Arc::new(Self {
            config,
            lane,
            metrics,
            state: Mutex::new(QueueState {
                packets: VecDeque::with_capacity(config.max_packets),
                bytes: 0,
                closed: false,
            }),
            ready: Notify::new(),
        })
    }

    pub fn enqueue(&self, packet: Bytes) -> bool {
        let class = classify_packet(&packet).class;
        let now = Instant::now();
        let mut state = self.state.lock();
        if state.closed {
            self.metrics.queue_drop(self.lane, QueueDrop::Closed);
            return false;
        }
        self.drop_expired(&mut state, now);
        while state.packets.len() >= self.config.max_packets
            || state.bytes.saturating_add(packet.len()) > self.config.max_bytes
        {
            let victim = if self.config.drop_oldest {
                (!state.packets.is_empty()).then_some(0)
            } else {
                state
                    .packets
                    .iter()
                    .position(|queued| queued.class == PacketClass::Datagram)
                    .or_else(|| {
                        (class == PacketClass::Control).then(|| {
                            state
                                .packets
                                .iter()
                                .position(|queued| queued.class == PacketClass::Control)
                                .unwrap_or(usize::MAX)
                        })
                    })
                    .filter(|index| *index != usize::MAX)
            };
            let Some(victim) = victim else {
                self.metrics.queue_drop(
                    self.lane,
                    if class == PacketClass::Tcp {
                        QueueDrop::Tail
                    } else {
                        QueueDrop::Full
                    },
                );
                return false;
            };
            let removed = state.packets.remove(victim).expect("queue victim exists");
            state.bytes -= removed.data.len();
            self.metrics
                .queue_bytes(self.lane, -(removed.data.len() as isize));
            self.metrics.queue_drop(self.lane, QueueDrop::Oldest);
        }
        let wake = state.packets.is_empty();
        state.bytes += packet.len();
        self.metrics.queue_bytes(self.lane, packet.len() as isize);
        state.packets.push_back(QueuedPacket {
            data: packet,
            class,
            enqueued: now,
        });
        drop(state);
        if wake {
            self.ready.notify_one();
        }
        true
    }

    pub fn close(&self) {
        let mut state = self.state.lock();
        if state.closed {
            return;
        }
        state.closed = true;
        if state.bytes != 0 {
            self.metrics.queue_bytes(self.lane, -(state.bytes as isize));
        }
        state.bytes = 0;
        state.packets.clear();
        drop(state);
        self.ready.notify_waiters();
    }

    fn pop(&self) -> Option<Bytes> {
        let mut state = self.state.lock();
        self.drop_expired(&mut state, Instant::now());
        let packet = state.packets.pop_front()?;
        state.bytes -= packet.data.len();
        self.metrics
            .queue_bytes(self.lane, -(packet.data.len() as isize));
        Some(packet.data)
    }

    fn drop_expired(&self, state: &mut QueueState, now: Instant) {
        let mut index = 0;
        while index < state.packets.len() {
            let max_age = match state.packets[index].class {
                PacketClass::Tcp => self.config.tcp_max_age,
                PacketClass::Control => self.config.control_max_age,
                PacketClass::Datagram => self.config.datagram_max_age,
            };
            if max_age
                .is_some_and(|max_age| now.duration_since(state.packets[index].enqueued) >= max_age)
            {
                let removed = state.packets.remove(index).expect("queue item exists");
                state.bytes -= removed.data.len();
                self.metrics
                    .queue_bytes(self.lane, -(removed.data.len() as isize));
                self.metrics.queue_drop(self.lane, QueueDrop::Expired);
            } else {
                index += 1;
            }
        }
    }
}

impl PacketSource for PacketQueue {
    fn next_packet(&self) -> BoxFuture<'_, Option<Bytes>> {
        Box::pin(async move {
            loop {
                let notified = self.ready.notified();
                if let Some(packet) = self.pop() {
                    return Some(packet);
                }
                if self.state.lock().closed {
                    return None;
                }
                notified.await;
            }
        })
    }

    fn try_packet(&self) -> Option<Bytes> {
        self.pop()
    }

    fn queued_bytes(&self) -> usize {
        self.state.lock().bytes
    }
}

struct LaneEntry {
    generation: u64,
    queue: Arc<PacketQueue>,
    cancellation: CancellationToken,
    backend: String,
}

struct FlowLane {
    lane: u8,
    last_seen: Instant,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FlowId {
    source: [u8; 16],
    destination: [u8; 16],
    source_port: u16,
    destination_port: u16,
    fragment_id: u16,
    protocol: u8,
    fragmented: bool,
    family: u8,
}

impl From<FlowKey> for FlowId {
    fn from(flow: FlowKey) -> Self {
        Self {
            source: flow.source,
            destination: flow.destination,
            source_port: flow.source_port,
            destination_port: flow.destination_port,
            fragment_id: flow.fragment_id,
            protocol: flow.protocol,
            fragmented: flow.fragmented,
            family: flow.family,
        }
    }
}

struct LaneGroup {
    id: String,
    lane_count: u8,
    lanes: HashMap<u8, LaneEntry>,
    flows: HashMap<FlowId, FlowLane>,
    collapse_reported: bool,
}

struct LaneTableState {
    groups: HashMap<Ipv4Addr, LaneGroup>,
}

struct LaneTableInner {
    state: Mutex<LaneTableState>,
    generation: AtomicU64,
    metrics: Arc<dyn Metrics>,
}

#[derive(Clone)]
pub struct LaneTable {
    inner: Arc<LaneTableInner>,
}

pub struct LaneBinding {
    pub downlink: Arc<PacketQueue>,
    pub cancellation: CancellationToken,
    pub collapsed_backend: bool,
    pub cleanup: Arc<dyn Cleanup>,
}

impl LaneTable {
    pub fn new(metrics: Arc<dyn Metrics>) -> Self {
        Self {
            inner: Arc::new(LaneTableInner {
                state: Mutex::new(LaneTableState {
                    groups: HashMap::new(),
                }),
                generation: AtomicU64::new(0),
                metrics,
            }),
        }
    }

    pub fn register(
        &self,
        address: Ipv4Addr,
        session_id: &str,
        lane: u8,
        lanes: u8,
        backend: String,
        parent: &CancellationToken,
    ) -> Result<LaneBinding, RouteError> {
        if session_id.is_empty() || !(MIN_LANES..=MAX_LANES).contains(&lanes) || lane >= lanes {
            return Err(RouteError::Conflict);
        }
        let generation = self.inner.generation.fetch_add(1, Ordering::Relaxed) + 1;
        let cancellation = parent.child_token();
        let queue = PacketQueue::new(QueueConfig::HTTP2, lane as i8, self.inner.metrics.clone());
        let mut replaced_group = Vec::new();
        let mut replaced_lane = None;
        let mut state = self.inner.state.lock();
        let replace_group = state
            .groups
            .get(&address)
            .is_some_and(|group| group.id != session_id);
        if replace_group {
            if let Some(group) = state.groups.remove(&address) {
                replaced_group.extend(
                    group
                        .lanes
                        .into_values()
                        .map(|entry| (entry.cancellation, entry.queue)),
                );
            }
        }
        let group = state.groups.entry(address).or_insert_with(|| LaneGroup {
            id: session_id.to_owned(),
            lane_count: lanes,
            lanes: HashMap::with_capacity(lanes as usize),
            flows: HashMap::new(),
            collapse_reported: false,
        });
        if group.lane_count != lanes {
            cancellation.cancel();
            queue.close();
            return Err(RouteError::Conflict);
        }
        if let Some(previous) = group.lanes.insert(
            lane,
            LaneEntry {
                generation,
                queue: queue.clone(),
                cancellation: cancellation.clone(),
                backend,
            },
        ) {
            replaced_lane = Some((previous.cancellation, previous.queue));
        }
        let collapsed = collapsed(group);
        if collapsed && !group.collapse_reported {
            group.collapse_reported = true;
            self.inner.metrics.collapsed_lane_group();
        }
        drop(state);
        for (token, queue) in replaced_group {
            token.cancel();
            queue.close();
        }
        if let Some((token, queue)) = replaced_lane {
            token.cancel();
            queue.close();
        }
        Ok(LaneBinding {
            downlink: queue,
            cancellation,
            collapsed_backend: collapsed,
            cleanup: Arc::new(LaneCleanup {
                table: self.clone(),
                address,
                lane,
                generation,
                closed: AtomicBool::new(false),
            }),
        })
    }

    pub fn dispatch(&self, address: Ipv4Addr, packet: Bytes) -> bool {
        let metadata = classify_packet(&packet);
        let queue = {
            let mut state = self.inner.state.lock();
            let Some(group) = state.groups.get_mut(&address) else {
                return false;
            };
            let mut preferred = 0;
            if metadata.class != PacketClass::Control {
                preferred = select_data_lane(group, metadata.flow, metadata.hash);
            }
            group
                .lanes
                .get(&preferred)
                .or_else(|| (0..group.lane_count).find_map(|lane| group.lanes.get(&lane)))
                .map(|entry| entry.queue.clone())
        };
        queue.is_some_and(|queue| queue.enqueue(packet))
    }

    fn remove(&self, address: Ipv4Addr, lane: u8, generation: u64) {
        let removed = {
            let mut state = self.inner.state.lock();
            let Some(group) = state.groups.get_mut(&address) else {
                return;
            };
            let matches = group
                .lanes
                .get(&lane)
                .is_some_and(|entry| entry.generation == generation);
            let removed = matches.then(|| group.lanes.remove(&lane)).flatten();
            if group.lanes.is_empty() {
                state.groups.remove(&address);
            }
            removed
        };
        if let Some(entry) = removed {
            entry.cancellation.cancel();
            entry.queue.close();
        }
    }
}

struct LaneCleanup {
    table: LaneTable,
    address: Ipv4Addr,
    lane: u8,
    generation: u64,
    closed: AtomicBool,
}

impl Cleanup for LaneCleanup {
    fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.table.remove(self.address, self.lane, self.generation);
        }
    }
}

fn collapsed(group: &LaneGroup) -> bool {
    if group.lanes.len() < 2 {
        return false;
    }
    let mut backends = Vec::with_capacity(group.lanes.len());
    for entry in group.lanes.values() {
        if !entry.backend.is_empty() && !backends.contains(&entry.backend) {
            backends.push(entry.backend.clone());
        }
    }
    !backends.is_empty() && backends.len() < group.lanes.len()
}

fn select_data_lane(group: &mut LaneGroup, flow: FlowKey, hash: u32) -> u8 {
    let flow = FlowId::from(flow);
    let now = Instant::now();
    if let Some(existing) = group.flows.get_mut(&flow) {
        if group.lanes.contains_key(&existing.lane) {
            existing.last_seen = now;
            return existing.lane;
        }
    }
    group.flows.remove(&flow);
    if group.flows.len() >= 4096 {
        group.flows.retain(|_, assignment| {
            now.duration_since(assignment.last_seen) < Duration::from_secs(120)
        });
        if group.flows.len() >= 4096 {
            if let Some(oldest) = group
                .flows
                .iter()
                .min_by_key(|(_, assignment)| assignment.last_seen)
                .map(|(flow, _)| *flow)
            {
                group.flows.remove(&oldest);
            }
        }
    }
    let candidate_count = (1..group.lane_count)
        .filter(|lane| group.lanes.contains_key(lane))
        .count();
    let selected = if candidate_count == 0 {
        0
    } else {
        let start = hash as usize % candidate_count;
        let mut selected = 0;
        let mut selected_bytes = usize::MAX;
        for offset in 0..candidate_count {
            let wanted = (start + offset) % candidate_count;
            let lane = (1..group.lane_count)
                .filter(|lane| group.lanes.contains_key(lane))
                .nth(wanted)
                .expect("candidate lane exists");
            let bytes = group.lanes[&lane].queue.queued_bytes();
            if bytes < selected_bytes {
                selected = lane;
                selected_bytes = bytes;
            }
        }
        selected
    };
    group.flows.insert(
        flow,
        FlowLane {
            lane: selected,
            last_seen: now,
        },
    );
    selected
}

/// Splits an oversized IPv4 packet for `mtu`. IPv6 packets are never
/// fragmented on the way; oversized ones need a Packet Too Big message.
pub fn fragment_ipv4(packet: &Bytes, mtu: usize) -> Result<Vec<Bytes>, MtuError> {
    if crate::wire::ip::ip_version(packet) == Some(6) {
        return if packet.len() <= mtu {
            Ok(vec![packet.clone()])
        } else {
            Err(MtuError::FragmentationNeeded)
        };
    }
    porta_wire::mtu::fragment_ipv4(packet, mtu)
        .map(|fragments| fragments.into_iter().map(Bytes::from).collect())
}

/// The ICMP or ICMPv6 error that tells the sender of an oversized packet to
/// use `mtu`. IPv6 senders cannot go below 1280 bytes, so smaller limits
/// suppress the message; callers carry such packets another way.
pub fn icmp_fragmentation_needed(
    packet: &Bytes,
    lease: &Lease,
    mtu: usize,
    identification: u16,
) -> Result<Bytes, MtuError> {
    if crate::wire::ip::ip_version(packet) == Some(6) {
        let lease = lease.ipv6.ok_or(MtuError::InvalidPacket)?;
        if mtu < crate::wire::ip::IPV6_MIN_MTU {
            return Err(MtuError::IcmpSuppressed);
        }
        return porta_wire::mtu::icmpv6_packet_too_big(packet, lease.gateway, mtu).map(Bytes::from);
    }
    porta_wire::mtu::icmp_fragmentation_needed(
        packet,
        porta_wire::mtu::IcmpContext {
            gateway: lease.gateway,
            address: lease.address,
            prefix_len: lease.prefix_len,
        },
        mtu,
        identification,
    )
    .map(Bytes::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::ip::{internet_checksum, parse_ipv4, set_ipv4_header_checksum};
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn usage_counters_forward_accounting_without_changing_calls() {
        #[derive(Default)]
        struct RecordingUsage {
            uploads: Mutex<Vec<(u64, u64)>>,
            downloads: Mutex<Vec<(u64, u64)>>,
            closes: AtomicUsize,
        }
        impl UsageSession for RecordingUsage {
            fn uploaded(&self, bytes: u64, packets: u64) {
                self.uploads.lock().push((bytes, packets));
            }
            fn downloaded(&self, bytes: u64, packets: u64) {
                self.downloads.lock().push((bytes, packets));
            }
            fn close(&self) {
                self.closes.fetch_add(1, Ordering::Relaxed);
            }
        }
        let inner = Arc::new(RecordingUsage::default());
        let usage = CountedUsage::new(inner.clone());
        assert_eq!(usage.uploaded_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(usage.downloaded_bytes.load(Ordering::Relaxed), 0);
        usage.uploaded(1200, 1);
        usage.uploaded(2400, 2);
        usage.downloaded(100, 1);
        usage.close();
        assert_eq!(usage.uploaded_bytes.load(Ordering::Relaxed), 3600);
        assert_eq!(usage.uploaded_packets.load(Ordering::Relaxed), 3);
        assert_eq!(usage.downloaded_bytes.load(Ordering::Relaxed), 100);
        assert_eq!(usage.downloaded_packets.load(Ordering::Relaxed), 1);
        assert_eq!(*inner.uploads.lock(), [(1200, 1), (2400, 2)]);
        assert_eq!(*inner.downloads.lock(), [(100, 1)]);
        assert_eq!(inner.closes.load(Ordering::Relaxed), 1);
    }

    #[derive(Default)]
    struct TestMetrics {
        collapsed: AtomicUsize,
        oldest: AtomicUsize,
    }

    impl Metrics for TestMetrics {
        fn collapsed_lane_group(&self) {
            self.collapsed.fetch_add(1, Ordering::Relaxed);
        }

        fn queue_drop(&self, _lane: i8, reason: QueueDrop) {
            if reason == QueueDrop::Oldest {
                self.oldest.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn packet(source: [u8; 4], destination: [u8; 4], length: usize) -> Bytes {
        let mut packet = vec![0; length];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[20..24].copy_from_slice(&[0x9c, 0x40, 0x01, 0xbb]);
        set_ipv4_header_checksum(&mut packet).unwrap();
        Bytes::from(packet)
    }

    #[test]
    fn extracts_all_device_proof_headers() {
        let mut headers = http::HeaderMap::new();
        for (name, value) in [
            ("X-Porta-Client-ID", "d-client"),
            ("X-Porta-Device-Name", "phone"),
            ("X-Porta-Device-Key", "key"),
            ("X-Porta-Device-Time", "123"),
            ("X-Porta-Device-Nonce", "nonce"),
            ("X-Porta-Device-Signature", "signature"),
        ] {
            headers.insert(name, value.parse().unwrap());
        }
        assert_eq!(
            DeviceProof::from_headers(&headers),
            DeviceProof {
                device_id: "d-client".into(),
                name: "phone".into(),
                public_key: "key".into(),
                timestamp: "123".into(),
                nonce: "nonce".into(),
                signature: "signature".into(),
            }
        );
    }

    #[test]
    fn protocol_and_lane_vectors_match_gateway_validation() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            format!("{} {}", "Bearer", "0123456789abcdef")
                .parse()
                .unwrap(),
        );
        assert_eq!(bearer_token(&headers).unwrap(), "0123456789abcdef");
        headers.insert(HEADER_LANE_SESSION, "session-1234567890".parse().unwrap());
        headers.insert(HEADER_LANE, "2".parse().unwrap());
        headers.insert(HEADER_LANES, "4".parse().unwrap());
        assert_eq!(
            parse_lane_config(&headers).unwrap(),
            LaneConfig {
                session_id: "session-1234567890".into(),
                index: 2,
                count: 4,
            }
        );
        headers.insert(HEADER_LANE, "4".parse().unwrap());
        assert_eq!(parse_lane_config(&headers), Err(LaneConfigError::Count));
    }

    #[tokio::test]
    async fn queue_preserves_tcp_prefix_and_replaces_datagrams() {
        let metrics = Arc::new(TestMetrics::default());
        let queue = PacketQueue::new(
            QueueConfig {
                max_packets: 1,
                max_bytes: 4096,
                ..QueueConfig::HTTP2
            },
            0,
            metrics.clone(),
        );
        let mut datagram = packet([8, 8, 8, 8], [10, 66, 0, 2], 300).to_vec();
        datagram[9] = 17;
        assert!(queue.enqueue(Bytes::from(datagram)));
        let mut tcp = packet([8, 8, 8, 8], [10, 66, 0, 2], 80).to_vec();
        tcp[9] = 6;
        tcp[32] = 5 << 4;
        tcp[33] = 0x18;
        assert!(queue.enqueue(Bytes::from(tcp.clone())));
        assert_eq!(queue.next_packet().await.unwrap(), Bytes::from(tcp));
        assert_eq!(metrics.oldest.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn lane_replacement_preserves_siblings_and_detects_collapse() {
        let metrics = Arc::new(TestMetrics::default());
        let table = LaneTable::new(metrics.clone());
        let parent = CancellationToken::new();
        let first = table
            .register(
                "10.66.0.2".parse().unwrap(),
                "session-12345678",
                0,
                4,
                "proxy:443".into(),
                &parent,
            )
            .unwrap();
        let second = table
            .register(
                "10.66.0.2".parse().unwrap(),
                "session-12345678",
                1,
                4,
                "proxy:443".into(),
                &parent,
            )
            .unwrap();
        assert!(second.collapsed_backend);
        let replacement = table
            .register(
                "10.66.0.2".parse().unwrap(),
                "session-12345678",
                0,
                4,
                "proxy:444".into(),
                &parent,
            )
            .unwrap();
        assert!(first.cancellation.is_cancelled());
        assert!(!second.cancellation.is_cancelled());
        replacement.cleanup.close();
        assert!(!second.cancellation.is_cancelled());
        assert_eq!(metrics.collapsed.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn fragments_and_generates_icmp_without_mutating_input() {
        let original = packet([8, 8, 8, 8], [10, 66, 0, 2], 1300);
        let fragments = fragment_ipv4(&original, 1100).unwrap();
        assert_eq!(fragments.len(), 2);
        assert!(fragments.iter().all(|fragment| fragment.len() <= 1100));
        assert_eq!(internet_checksum(&fragments[0][..20]), 0);

        let mut df = original.to_vec();
        df[6] = 0x40;
        set_ipv4_header_checksum(&mut df).unwrap();
        let df = Bytes::from(df);
        assert!(matches!(
            fragment_ipv4(&df, 1100),
            Err(MtuError::FragmentationNeeded)
        ));
        let lease = Lease {
            address: "10.66.0.2".parse().unwrap(),
            prefix_len: 24,
            gateway: "10.66.0.1".parse().unwrap(),
            opaque_id: 1,
            ipv6: None,
        };
        let reply = icmp_fragmentation_needed(&df, &lease, 1100, 7).unwrap();
        assert_eq!(parse_ipv4(&reply).unwrap().source, lease.gateway);
        assert_eq!(&reply[20..22], &[3, 4]);
        assert_eq!(u16::from_be_bytes([reply[26], reply[27]]), 1100);
        assert_eq!(internet_checksum(&reply[20..]), 0);
    }

    #[test]
    fn ipv6_routing_and_packet_too_big_follow_the_lease() {
        let policy = NetworkPolicy {
            published: vec!["10.30.0.0/24".parse().unwrap()],
            ..NetworkPolicy::default()
        };
        let split = TunnelRouting {
            routes: vec![
                "10.20.0.0/16".parse().unwrap(),
                "2001:db8::/32".parse().unwrap(),
            ],
            ..TunnelRouting::default()
        };
        let ipv4_only = split.for_device(&policy, None);
        assert_eq!(
            ipv4_only.routes,
            vec![
                "10.20.0.0/16".parse::<ipnet::IpNet>().unwrap(),
                "10.30.0.0/24".parse().unwrap()
            ]
        );
        assert!(ipv4_only
            .advertisement()
            .iter()
            .all(|route| route.start.is_ipv4()));
        let dual = split.for_device(&policy, Some("fd66::2/64".parse().unwrap()));
        assert!(dual.routes.contains(&"fd66::/64".parse().unwrap()));
        let advertised = dual.advertisement();
        assert_eq!(advertised.len(), 4);
        assert!(advertised[..2].iter().all(|route| route.start.is_ipv4()));
        assert!(advertised[2..].iter().all(|route| route.start.is_ipv6()));
        let full =
            TunnelRouting::default().for_device(&policy, Some("fd66::2/64".parse().unwrap()));
        assert_eq!(full.advertisement().len(), 2);
        assert!(full.routes.is_empty());

        let mut lease = Lease {
            address: "10.66.0.2".parse().unwrap(),
            prefix_len: 24,
            gateway: "10.66.0.1".parse().unwrap(),
            opaque_id: 1,
            ipv6: Some(Ipv6Lease {
                address: "fd66::2".parse().unwrap(),
                prefix_len: 64,
                gateway: "fd66::1".parse().unwrap(),
            }),
        };
        assert!(lease.owns("fd66::2".parse().unwrap()));
        assert!(!lease.owns("fd66::3".parse().unwrap()));
        let mut packet = vec![0; 1400];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&1360_u16.to_be_bytes());
        packet[6] = 17;
        packet[8..24].copy_from_slice(&"2001:db8::80".parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(&"fd66::2".parse::<Ipv6Addr>().unwrap().octets());
        let packet = Bytes::from(packet);
        assert_eq!(
            fragment_ipv4(&packet, 1300),
            Err(MtuError::FragmentationNeeded)
        );
        assert_eq!(fragment_ipv4(&packet, 1400).unwrap(), vec![packet.clone()]);
        let reply = icmp_fragmentation_needed(&packet, &lease, 1300, 1).unwrap();
        assert_eq!(reply[40], 2);
        assert_eq!(
            &reply[8..24],
            &"fd66::1".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(
            icmp_fragmentation_needed(&packet, &lease, 1200, 1),
            Err(MtuError::IcmpSuppressed)
        );
        lease.ipv6 = None;
        assert_eq!(
            icmp_fragmentation_needed(&packet, &lease, 1300, 1),
            Err(MtuError::InvalidPacket)
        );
    }

    #[test]
    fn mtu_wrappers_match_shared_packets_and_errors() {
        let original = packet([8, 8, 8, 8], [10, 66, 0, 2], 1300);
        for mtu in [68, 1100, 1300] {
            let expected = porta_wire::mtu::fragment_ipv4(&original, mtu).unwrap();
            let actual = fragment_ipv4(&original, mtu).unwrap();
            assert_eq!(
                actual.iter().map(Bytes::as_ref).collect::<Vec<_>>(),
                expected.iter().map(Vec::as_slice).collect::<Vec<_>>()
            );
        }
        assert_eq!(fragment_ipv4(&original, 67), Err(MtuError::InvalidMtu));
        let mut df = original.to_vec();
        df[6] = 0x40;
        set_ipv4_header_checksum(&mut df).unwrap();
        let df = Bytes::from(df);
        let mut lease = Lease {
            address: "10.66.0.2".parse().unwrap(),
            prefix_len: 24,
            gateway: "10.66.0.1".parse().unwrap(),
            opaque_id: 1,
            ipv6: None,
        };
        let expected = porta_wire::mtu::icmp_fragmentation_needed(
            &df,
            porta_wire::mtu::IcmpContext {
                address: lease.address,
                gateway: lease.gateway,
                prefix_len: lease.prefix_len,
            },
            1100,
            7,
        )
        .unwrap();
        assert_eq!(
            icmp_fragmentation_needed(&df, &lease, 1100, 7)
                .unwrap()
                .as_ref(),
            expected
        );
        assert_eq!(
            icmp_fragmentation_needed(&original, &lease, 1100, 7),
            Err(MtuError::IcmpSuppressed)
        );
        lease.prefix_len = 33;
        assert_eq!(
            icmp_fragmentation_needed(&df, &lease, 1100, 7),
            Err(MtuError::InvalidPacket)
        );
    }
}
