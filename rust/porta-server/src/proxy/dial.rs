use futures_util::future::BoxFuture;
use parking_lot::Mutex;
use socket2::{SockRef, TcpKeepalive};
use std::borrow::Cow;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::task::JoinSet;

pub const DESTINATION_TIMEOUT: Duration = Duration::from_secs(10);
pub const DNS_CACHE_TTL: Duration = Duration::from_secs(30);
pub const DNS_CACHE_ENTRIES: usize = 256;
pub const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

pub type BoxIo = Box<dyn AsyncStream>;

pub trait Resolver: Send + Sync + 'static {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>>;
}

pub trait Dialer: Send + Sync + 'static {
    fn dial(&self, address: SocketAddr) -> BoxFuture<'_, io::Result<BoxIo>>;
}

#[derive(Debug, Error)]
pub enum DialError {
    #[error("invalid destination authority")]
    InvalidAuthority,
    #[error("invalid destination port")]
    InvalidPort,
    #[error("proxy destination denied: {0}")]
    Denied(String),
    #[error("destination has no addresses")]
    NoAddresses,
    #[error("proxy destination timed out")]
    Timeout,
    #[error("proxy destination unavailable: {0}")]
    Unavailable(#[source] io::Error),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Destination {
    host: Box<str>,
    port: u16,
}

impl Destination {
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

#[derive(Default)]
pub struct TokioResolver;

impl Resolver for TokioResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
        Box::pin(async move {
            if let Ok(address) = host.parse::<IpAddr>() {
                return Ok(vec![unmap(address)]);
            }
            let addresses = tokio::net::lookup_host((host, 0)).await?;
            Ok(addresses.map(|address| unmap(address.ip())).collect())
        })
    }
}

#[derive(Default)]
pub struct TokioDialer;

impl Dialer for TokioDialer {
    fn dial(&self, address: SocketAddr) -> BoxFuture<'_, io::Result<BoxIo>> {
        Box::pin(async move {
            let stream = TcpStream::connect(address).await?;
            stream.set_nodelay(true)?;
            SockRef::from(&stream).set_tcp_keepalive(
                &TcpKeepalive::new()
                    .with_time(Duration::from_secs(30))
                    .with_interval(Duration::from_secs(30)),
            )?;
            Ok(Box::new(stream) as BoxIo)
        })
    }
}

#[derive(Clone)]
pub struct PublicConnector {
    resolver: Arc<dyn Resolver>,
    dialer: Arc<dyn Dialer>,
    cache: Arc<AddressCache>,
    timeout: Duration,
    stagger: Duration,
}

impl Default for PublicConnector {
    fn default() -> Self {
        Self::new(Arc::new(TokioResolver), Arc::new(TokioDialer))
    }
}

impl PublicConnector {
    pub fn new(resolver: Arc<dyn Resolver>, dialer: Arc<dyn Dialer>) -> Self {
        Self {
            resolver,
            dialer,
            cache: Arc::new(AddressCache::new(DNS_CACHE_ENTRIES, DNS_CACHE_TTL)),
            timeout: DESTINATION_TIMEOUT,
            stagger: HAPPY_EYEBALLS_DELAY,
        }
    }

    pub fn with_options(
        resolver: Arc<dyn Resolver>,
        dialer: Arc<dyn Dialer>,
        cache_entries: usize,
        cache_ttl: Duration,
        timeout: Duration,
        stagger: Duration,
    ) -> Self {
        Self {
            resolver,
            dialer,
            cache: Arc::new(AddressCache::new(cache_entries, cache_ttl)),
            timeout,
            stagger,
        }
    }

    pub async fn connect(&self, authority: &str) -> Result<BoxIo, DialError> {
        let destination = parse_destination(authority)?;
        self.connect_destination(&destination).await
    }

    pub async fn connect_destination(&self, destination: &Destination) -> Result<BoxIo, DialError> {
        let operation = async {
            let addresses = if let Some(addresses) = self.cache.get(destination.host()) {
                addresses
            } else {
                let resolved = self
                    .resolver
                    .resolve(destination.host())
                    .await
                    .map_err(DialError::Unavailable)?;
                if resolved.is_empty() {
                    return Err(DialError::NoAddresses);
                }
                let mut validated = Vec::with_capacity(resolved.len());
                for address in resolved {
                    let address = unmap(address);
                    if !public_address(address) {
                        return Err(DialError::Denied(address.to_string()));
                    }
                    validated.push(address);
                }
                let validated: Arc<[IpAddr]> = validated.into();
                self.cache.put(destination.host(), Arc::clone(&validated));
                validated
            };
            happy_eyeballs(
                Arc::clone(&self.dialer),
                destination.port(),
                addresses,
                self.stagger,
            )
            .await
        };
        match tokio::time::timeout(self.timeout, operation).await {
            Ok(result) => result,
            Err(_) => Err(DialError::Timeout),
        }
    }
}

struct CachedAddresses {
    addresses: Arc<[IpAddr]>,
    expires: Instant,
}

pub struct AddressCache {
    entries: Mutex<HashMap<Box<str>, CachedAddresses>>,
    max_entries: usize,
    ttl: Duration,
}

impl AddressCache {
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::with_capacity(max_entries)),
            max_entries,
            ttl: ttl.min(DNS_CACHE_TTL),
        }
    }

    pub fn get(&self, host: &str) -> Option<Arc<[IpAddr]>> {
        self.get_at(host, Instant::now())
    }

    pub fn put(&self, host: &str, addresses: Arc<[IpAddr]>) {
        self.put_at(host, addresses, Instant::now());
    }

    fn get_at(&self, host: &str, now: Instant) -> Option<Arc<[IpAddr]>> {
        if self.max_entries == 0 || self.ttl.is_zero() {
            return None;
        }
        let key = normalize_cache_host(host);
        let mut entries = self.entries.lock();
        let entry = entries.get(key.as_ref())?;
        if now >= entry.expires {
            entries.remove(key.as_ref());
            return None;
        }
        Some(Arc::clone(&entry.addresses))
    }

    fn put_at(&self, host: &str, addresses: Arc<[IpAddr]>, now: Instant) {
        if self.max_entries == 0 || self.ttl.is_zero() || addresses.is_empty() {
            return;
        }
        let key = normalize_cache_host(host);
        let mut entries = self.entries.lock();
        entries.retain(|_, entry| now < entry.expires);
        if !entries.contains_key(key.as_ref()) && entries.len() >= self.max_entries {
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires)
                .map(|(host, _)| host.clone())
            {
                entries.remove(oldest.as_ref());
            }
        }
        entries.insert(
            key.into_owned().into_boxed_str(),
            CachedAddresses {
                addresses,
                expires: now + self.ttl,
            },
        );
    }
}

fn normalize_cache_host(host: &str) -> Cow<'_, str> {
    let trimmed = host.trim().trim_end_matches('.');
    if trimmed.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(trimmed.to_ascii_lowercase())
    } else {
        Cow::Borrowed(trimmed)
    }
}

pub fn parse_destination(authority: &str) -> Result<Destination, DialError> {
    if authority.is_empty()
        || authority != authority.trim()
        || authority
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        || authority.bytes().any(|byte| b"/?#@".contains(&byte))
    {
        return Err(DialError::InvalidAuthority);
    }
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, port) = bracketed
            .split_once("]:")
            .ok_or(DialError::InvalidAuthority)?;
        if host.is_empty()
            || port.is_empty()
            || port.contains(':')
            || host.contains('%')
            || host.parse::<Ipv6Addr>().is_err()
        {
            return Err(DialError::InvalidAuthority);
        }
        (host, port)
    } else {
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or(DialError::InvalidAuthority)?;
        if host.is_empty() || host.contains(':') || !valid_host(host) {
            return Err(DialError::InvalidAuthority);
        }
        (host, port)
    };
    let parsed_port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(DialError::InvalidPort)?;
    if port != "443" || parsed_port != 443 {
        return Err(DialError::Denied(format!("port {port}")));
    }
    Ok(Destination {
        host: host.into(),
        port: parsed_port,
    })
}

fn valid_host(host: &str) -> bool {
    if host.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return false;
    }
    host.split('.').all(|label| {
        let bytes = label.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 63
            && bytes[0].is_ascii_alphanumeric()
            && bytes[bytes.len() - 1].is_ascii_alphanumeric()
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    })
}

async fn happy_eyeballs(
    dialer: Arc<dyn Dialer>,
    port: u16,
    addresses: Arc<[IpAddr]>,
    stagger: Duration,
) -> Result<BoxIo, DialError> {
    let ordered = interleave_address_families(&addresses);
    if ordered.is_empty() {
        return Err(DialError::NoAddresses);
    }
    let mut attempts = JoinSet::new();
    let mut next = 0;
    start_attempt(&mut attempts, Arc::clone(&dialer), ordered[next], port);
    next += 1;
    if stagger.is_zero() {
        while next < ordered.len() {
            start_attempt(&mut attempts, Arc::clone(&dialer), ordered[next], port);
            next += 1;
        }
    }
    let mut timer = Box::pin(tokio::time::sleep(stagger));
    let mut last_error = None;
    loop {
        if attempts.is_empty() {
            return Err(last_error.map(DialError::Unavailable).unwrap_or_else(|| {
                DialError::Unavailable(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "destination has no reachable addresses",
                ))
            }));
        }
        tokio::select! {
            result = attempts.join_next() => {
                let result = result.expect("attempt set was not empty");
                match result {
                    Ok(Ok(connection)) => {
                        attempts.abort_all();
                        return Ok(connection);
                    }
                    Ok(Err(error)) => last_error = Some(error),
                    Err(error) if error.is_cancelled() => {}
                    Err(error) => {
                        last_error = Some(io::Error::other(format!("dial task failed: {error}")));
                    }
                }
                if next < ordered.len() {
                    start_attempt(&mut attempts, Arc::clone(&dialer), ordered[next], port);
                    next += 1;
                    timer.as_mut().reset(tokio::time::Instant::now() + stagger);
                }
            }
            _ = &mut timer, if !stagger.is_zero() && next < ordered.len() => {
                start_attempt(&mut attempts, Arc::clone(&dialer), ordered[next], port);
                next += 1;
                timer.as_mut().reset(tokio::time::Instant::now() + stagger);
            }
        }
    }
}

fn start_attempt(
    attempts: &mut JoinSet<io::Result<BoxIo>>,
    dialer: Arc<dyn Dialer>,
    address: IpAddr,
    port: u16,
) {
    attempts.spawn(async move { dialer.dial(SocketAddr::new(address, port)).await });
}

pub fn interleave_address_families(addresses: &[IpAddr]) -> Vec<IpAddr> {
    if addresses.len() < 2 {
        return addresses.to_vec();
    }
    let first_is_ipv6 = addresses[0].is_ipv6();
    let mut ipv4 = Vec::with_capacity(addresses.len());
    let mut ipv6 = Vec::with_capacity(addresses.len());
    for address in addresses {
        if address.is_ipv6() {
            ipv6.push(*address);
        } else {
            ipv4.push(*address);
        }
    }
    let (first, second) = if first_is_ipv6 {
        (ipv6, ipv4)
    } else {
        (ipv4, ipv6)
    };
    let mut result = Vec::with_capacity(addresses.len());
    for index in 0..first.len().max(second.len()) {
        if let Some(address) = first.get(index) {
            result.push(*address);
        }
        if let Some(address) = second.get(index) {
            result.push(*address);
        }
    }
    result
}

pub fn public_address(address: IpAddr) -> bool {
    match unmap(address) {
        IpAddr::V4(address) => {
            if address.is_unspecified()
                || address.is_loopback()
                || address.is_private()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_broadcast()
            {
                return false;
            }
            let value = u32::from(address);
            !DENIED_V4
                .iter()
                .any(|(network, bits)| prefix_v4(value, *network, *bits))
        }
        IpAddr::V6(address) => {
            if address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || prefix_v6(u128::from(address), 0xfc00u128 << 112, 7)
                || prefix_v6(u128::from(address), 0xfe80u128 << 112, 10)
            {
                return false;
            }
            let value = u128::from(address);
            !DENIED_V6
                .iter()
                .any(|(network, bits)| prefix_v6(value, *network, *bits))
        }
    }
}

const DENIED_V4: &[(u32, u8)] = &[
    (0x0000_0000, 8),
    (0x6440_0000, 10),
    (0xa9fe_0000, 16),
    (0xc000_0000, 24),
    (0xc000_0200, 24),
    (0xc01f_c400, 24),
    (0xc034_c100, 24),
    (0xc058_6300, 24),
    (0xc0af_3000, 24),
    (0xc612_0000, 15),
    (0xc633_6400, 24),
    (0xcb00_7100, 24),
    (0xf000_0000, 4),
];

const DENIED_V6: &[(u128, u8)] = &[
    (0x0064_ff9b_0000_0000_0000_0000_0000_0000, 96),
    (0x0064_ff9b_0001_0000_0000_0000_0000_0000, 48),
    (0x0100_0000_0000_0000_0000_0000_0000_0000, 64),
    (0x2001_0000_0000_0000_0000_0000_0000_0000, 23),
    (0x2001_0db8_0000_0000_0000_0000_0000_0000, 32),
    (0x2002_0000_0000_0000_0000_0000_0000_0000, 16),
    (0x3fff_0000_0000_0000_0000_0000_0000_0000, 20),
    (0x5f00_0000_0000_0000_0000_0000_0000_0000, 16),
    (0xfec0_0000_0000_0000_0000_0000_0000_0000, 10),
];

fn prefix_v4(address: u32, network: u32, bits: u8) -> bool {
    let mask = u32::MAX << (32 - bits);
    address & mask == network & mask
}

fn prefix_v6(address: u128, network: u128, bits: u8) -> bool {
    let mask = u128::MAX << (128 - bits);
    address & mask == network & mask
}

fn unmap(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use tokio::io::DuplexStream;
    use tokio::io::ReadBuf;
    use tokio::sync::{mpsc, Barrier, Mutex as AsyncMutex};

    struct FakeResolver {
        addresses: Vec<IpAddr>,
        calls: AtomicUsize,
    }

    impl Resolver for FakeResolver {
        fn resolve<'a>(&'a self, _host: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let addresses = self.addresses.clone();
            Box::pin(async move { Ok(addresses) })
        }
    }

    struct FakeDialer {
        calls: mpsc::UnboundedSender<SocketAddr>,
        success: IpAddr,
        peers: AsyncMutex<Vec<DuplexStream>>,
    }

    impl Dialer for FakeDialer {
        fn dial(&self, address: SocketAddr) -> BoxFuture<'_, io::Result<BoxIo>> {
            Box::pin(async move {
                let _ = self.calls.send(address);
                if address.ip() == self.success {
                    let (client, peer) = tokio::io::duplex(64);
                    self.peers.lock().await.push(peer);
                    Ok(Box::new(client) as BoxIo)
                } else {
                    futures_util::future::pending().await
                }
            })
        }
    }

    struct FailingThenSuccessfulDialer {
        first: IpAddr,
        second_started: Arc<tokio::sync::Notify>,
        peers: AsyncMutex<Vec<DuplexStream>>,
    }

    impl Dialer for FailingThenSuccessfulDialer {
        fn dial(&self, address: SocketAddr) -> BoxFuture<'_, io::Result<BoxIo>> {
            Box::pin(async move {
                if address.ip() == self.first {
                    return Err(io::Error::new(io::ErrorKind::NotConnected, "unreachable"));
                }
                self.second_started.notify_one();
                let (client, peer) = tokio::io::duplex(64);
                self.peers.lock().await.push(peer);
                Ok(Box::new(client) as BoxIo)
            })
        }
    }

    struct ConcurrentSuccessDialer {
        barrier: Barrier,
        drops: Arc<AtomicUsize>,
        peers: AsyncMutex<Vec<DuplexStream>>,
    }

    impl Dialer for ConcurrentSuccessDialer {
        fn dial(&self, _address: SocketAddr) -> BoxFuture<'_, io::Result<BoxIo>> {
            Box::pin(async move {
                let (client, peer) = tokio::io::duplex(64);
                self.peers.lock().await.push(peer);
                let stream = DropTrackedStream {
                    inner: client,
                    drops: Arc::clone(&self.drops),
                };
                self.barrier.wait().await;
                Ok(Box::new(stream) as BoxIo)
            })
        }
    }

    struct DropTrackedStream {
        inner: DuplexStream,
        drops: Arc<AtomicUsize>,
    }

    impl AsyncRead for DropTrackedStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(context, buffer)
        }
    }

    impl AsyncWrite for DropTrackedStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(context, bytes)
        }

        fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(context)
        }
    }

    impl Drop for DropTrackedStream {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn destination_parser_is_strict_and_allows_only_443() {
        assert_eq!(
            parse_destination("example.com:443").unwrap(),
            Destination {
                host: "example.com".into(),
                port: 443
            }
        );
        assert_eq!(
            parse_destination("[2001:4860:4860::8888]:443")
                .unwrap()
                .host(),
            "2001:4860:4860::8888"
        );
        for invalid in [
            "",
            "example.com",
            "example.com:0443",
            "example.com:443 ",
            "user@example.com:443",
            "https://example.com:443",
            "2001:4860:4860::8888:443",
            "[fe80::1%eth0]:443",
            "bad_label.example:443",
        ] {
            assert!(parse_destination(invalid).is_err(), "{invalid}");
        }
        assert!(matches!(
            parse_destination("example.com:80"),
            Err(DialError::Denied(_))
        ));
    }

    #[test]
    fn rejects_every_non_public_category() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "192.31.196.1",
            "192.52.193.1",
            "192.88.99.1",
            "192.175.48.1",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "::1",
            "64:ff9b::1",
            "64:ff9b:1::1",
            "100::1",
            "2001::1",
            "2001:2::1",
            "2001:10::1",
            "fc00::1",
            "fe80::1",
            "fec0::1",
            "2001:db8::1",
            "2002::1",
            "3fff::1",
            "5f00::1",
            "ff02::1",
        ] {
            assert!(
                !public_address(address.parse().unwrap()),
                "{address} was accepted"
            );
        }
        assert!(public_address("1.1.1.1".parse().unwrap()));
        assert!(public_address("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn cache_expires_caps_ttl_and_returns_shared_answers() {
        let cache = AddressCache::new(2, Duration::from_secs(60));
        let now = Instant::now();
        let addresses: Arc<[IpAddr]> = vec!["1.1.1.1".parse().unwrap()].into();
        cache.put_at("Example.COM.", Arc::clone(&addresses), now);
        let first = cache
            .get_at("example.com", now + Duration::from_secs(29))
            .unwrap();
        assert!(Arc::ptr_eq(&first, &addresses));
        assert!(cache
            .get_at("example.com", now + Duration::from_secs(30))
            .is_none());
    }

    #[test]
    fn families_are_interleaved_starting_with_preferred_family() {
        let addresses = [
            "2001:4860:4860::8888".parse().unwrap(),
            "2001:4860:4860::8844".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
        ];
        assert_eq!(
            interleave_address_families(&addresses),
            vec![addresses[0], addresses[2], addresses[1], addresses[3]]
        );
    }

    #[tokio::test]
    async fn starts_alternate_family_after_stagger() {
        let (calls, mut called) = mpsc::unbounded_channel();
        let success = "1.1.1.1".parse().unwrap();
        let dialer = Arc::new(FakeDialer {
            calls,
            success,
            peers: AsyncMutex::new(Vec::new()),
        });
        let addresses: Arc<[IpAddr]> = vec![
            "2001:4860:4860::8888".parse().unwrap(),
            "2001:4860:4860::8844".parse().unwrap(),
            success,
        ]
        .into();
        let connection = tokio::time::timeout(
            Duration::from_millis(100),
            happy_eyeballs(dialer, 443, addresses, Duration::from_millis(5)),
        )
        .await
        .unwrap()
        .unwrap();
        drop(connection);
        assert_eq!(
            called.recv().await.unwrap().ip(),
            "2001:4860:4860::8888".parse::<IpAddr>().unwrap()
        );
        assert_eq!(called.recv().await.unwrap().ip(), success);
    }

    #[tokio::test]
    async fn immediate_failure_accelerates_next_attempt() {
        let first = "2001:4860:4860::8888".parse().unwrap();
        let second = "1.1.1.1".parse().unwrap();
        let second_started = Arc::new(tokio::sync::Notify::new());
        let addresses: Arc<[IpAddr]> = vec![first, second].into();
        let connection = tokio::time::timeout(
            Duration::from_millis(100),
            happy_eyeballs(
                Arc::new(FailingThenSuccessfulDialer {
                    first,
                    second_started: Arc::clone(&second_started),
                    peers: AsyncMutex::new(Vec::new()),
                }),
                443,
                addresses,
                Duration::from_secs(1),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        drop(connection);
        tokio::time::timeout(Duration::from_millis(20), second_started.notified())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn concurrent_late_success_is_closed() {
        let drops = Arc::new(AtomicUsize::new(0));
        let addresses: Arc<[IpAddr]> = vec![
            "2001:4860:4860::8888".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
        ]
        .into();
        let winner = happy_eyeballs(
            Arc::new(ConcurrentSuccessDialer {
                barrier: Barrier::new(2),
                drops: Arc::clone(&drops),
                peers: AsyncMutex::new(Vec::new()),
            }),
            443,
            addresses,
            Duration::ZERO,
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while drops.load(Ordering::Relaxed) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        drop(winner);
        assert_eq!(drops.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn caches_only_complete_validated_answer_sets() {
        let resolver = Arc::new(FakeResolver {
            addresses: vec!["1.1.1.1".parse().unwrap()],
            calls: AtomicUsize::new(0),
        });
        let (calls, _called) = mpsc::unbounded_channel();
        let dialer = Arc::new(FakeDialer {
            calls,
            success: "1.1.1.1".parse().unwrap(),
            peers: AsyncMutex::new(Vec::new()),
        });
        let connector = PublicConnector::with_options(
            resolver.clone(),
            dialer,
            4,
            DNS_CACHE_TTL,
            Duration::from_secs(1),
            Duration::ZERO,
        );
        drop(connector.connect("example.com:443").await.unwrap());
        drop(connector.connect("example.com:443").await.unwrap());
        assert_eq!(resolver.calls.load(Ordering::Relaxed), 1);

        let denied_resolver = Arc::new(FakeResolver {
            addresses: vec!["1.1.1.1".parse().unwrap(), "127.0.0.1".parse().unwrap()],
            calls: AtomicUsize::new(0),
        });
        let (calls, _called) = mpsc::unbounded_channel();
        let denied = PublicConnector::with_options(
            denied_resolver.clone(),
            Arc::new(FakeDialer {
                calls,
                success: "1.1.1.1".parse().unwrap(),
                peers: AsyncMutex::new(Vec::new()),
            }),
            4,
            DNS_CACHE_TTL,
            Duration::from_secs(1),
            Duration::ZERO,
        );
        assert!(matches!(
            denied.connect("mixed.example:443").await,
            Err(DialError::Denied(_))
        ));
        assert!(denied.cache.get("mixed.example").is_none());
    }
}
