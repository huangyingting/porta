//! Built-in resolver on the gateway's tunnel address.
//!
//! Clients that run with `--dns-resolver` resolve device names under
//! [`ZONE`] (`laptop.alice.porta.internal`), and their reverse lookups,
//! from the live sessions they may reach; names they may not reach do not
//! exist for them. Other names are refused when a blocklist lists them or
//! their parent domain, and otherwise forwarded unchanged to the upstream
//! resolvers. Only live clients and the gateway host may query it.

use anyhow::{Context, Result};
use parking_lot::RwLock;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

/// Zone of device names.
pub const ZONE: &str = "porta.internal";
const TTL: u32 = 30;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONCURRENT_QUERIES: usize = 512;
const MAX_TCP_QUERIES: usize = 32;
const BLOCKLIST_CHECK_INTERVAL: Duration = Duration::from_secs(60);

const TYPE_A: u16 = 1;
const TYPE_PTR: u16 = 12;
const TYPE_AAAA: u16 = 28;
const TYPE_ANY: u16 = 255;
const RCODE_FORMERR: u8 = 1;
const RCODE_SERVFAIL: u8 = 2;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_NOTIMP: u8 = 4;

/// Live devices the resolver names, and who may see them.
pub trait Directory: Send + Sync {
    /// Whether `address` is a live client that may use the resolver.
    fn is_client(&self, address: Ipv4Addr) -> bool;
    /// The addresses of the device `name` (relative to [`ZONE`]) when
    /// `querier` may reach it.
    fn resolve(&self, querier: Ipv4Addr, name: &str) -> Option<DeviceAddresses>;
    /// The name (relative to [`ZONE`]) of the device at `address` when
    /// `querier` may reach it.
    fn reverse(&self, querier: Ipv4Addr, address: IpAddr) -> Option<String>;
}

/// A live device's addresses: IPv6 only on a dual-stack gateway.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceAddresses {
    pub ipv4: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
}

pub struct ResolverConfig {
    /// The gateway's tunnel address, which clients use as their DNS server.
    pub listen: Ipv4Addr,
    pub upstreams: Vec<SocketAddr>,
    /// Resolvers for particular domains and their subdomains.
    pub forwards: Vec<(String, SocketAddr)>,
    pub blocklist: Option<PathBuf>,
}

pub struct Listeners {
    udp: UdpSocket,
    tcp: TcpListener,
}

pub struct Resolver {
    config: ResolverConfig,
    directory: Arc<dyn Directory>,
    metrics: Arc<crate::ops::metrics::Metrics>,
    blocklist: RwLock<Blocklist>,
    queries: Arc<Semaphore>,
}

#[derive(Default)]
struct Blocklist {
    domains: HashSet<String>,
    modified: Option<SystemTime>,
}

/// What a query asks for.
struct Question {
    id: u16,
    recursion_desired: bool,
    name: String,
    kind: u16,
    /// End of the question section in the query.
    end: usize,
}

impl Resolver {
    pub fn new(
        config: ResolverConfig,
        directory: Arc<dyn Directory>,
        metrics: Arc<crate::ops::metrics::Metrics>,
    ) -> Result<Arc<Self>> {
        let resolver = Arc::new(Self {
            config,
            directory,
            metrics,
            blocklist: RwLock::new(Blocklist::default()),
            queries: Arc::new(Semaphore::new(MAX_CONCURRENT_QUERIES)),
        });
        resolver.reload_blocklist()?;
        Ok(resolver)
    }

    /// Binds UDP and TCP port 53 of the gateway address, which works before
    /// `server-up.sh` assigns that address.
    pub fn bind(&self) -> Result<Listeners> {
        let address = SocketAddr::from((self.config.listen, 53));
        let listeners = Listeners {
            udp: bind_udp(address)?,
            tcp: bind_tcp(address)?,
        };
        tracing::info!(%address, upstreams = ?self.config.upstreams, "built-in DNS resolver listening");
        Ok(listeners)
    }

    /// Serves queries until cancelled.
    pub async fn run(
        self: Arc<Self>,
        listeners: Listeners,
        cancellation: CancellationToken,
    ) -> Result<()> {
        let udp = Arc::new(listeners.udp);
        let tcp = listeners.tcp;
        let mut buffer = vec![0_u8; 4096];
        let mut blocklist_check = tokio::time::interval(BLOCKLIST_CHECK_INTERVAL);
        loop {
            tokio::select! {
                _ = cancellation.cancelled() => return Ok(()),
                _ = blocklist_check.tick() => {
                    if let Err(error) = self.reload_blocklist() {
                        tracing::warn!(%error, "could not reload the DNS blocklist");
                    }
                }
                received = udp.recv_from(&mut buffer) => {
                    let Ok((length, peer)) = received else { continue };
                    let Some(querier) = self.querier(peer) else { continue };
                    // Queries beyond the limit are dropped; clients retry.
                    let Ok(permit) = self.queries.clone().try_acquire_owned() else { continue };
                    let query = buffer[..length].to_vec();
                    let resolver = self.clone();
                    let udp = udp.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Some(reply) = resolver.answer(querier, &query, false).await {
                            let _ = udp.send_to(&reply, peer).await;
                        }
                    });
                }
                accepted = tcp.accept() => {
                    let Ok((stream, peer)) = accepted else { continue };
                    let Some(querier) = self.querier(peer) else { continue };
                    let resolver = self.clone();
                    let cancellation = cancellation.clone();
                    tokio::spawn(async move {
                        tokio::select! {
                            _ = cancellation.cancelled() => {}
                            _ = resolver.serve_tcp(querier, stream) => {}
                        }
                    });
                }
            }
        }
    }

    /// The client address of a permitted querier.
    fn querier(&self, peer: SocketAddr) -> Option<Ipv4Addr> {
        let IpAddr::V4(address) = peer.ip() else {
            return None;
        };
        (address == self.config.listen || self.directory.is_client(address)).then_some(address)
    }

    async fn serve_tcp(&self, querier: Ipv4Addr, mut stream: TcpStream) {
        for _ in 0..MAX_TCP_QUERIES {
            let mut length = [0_u8; 2];
            let read = tokio::time::timeout(TCP_IDLE_TIMEOUT, stream.read_exact(&mut length)).await;
            if !matches!(read, Ok(Ok(_))) {
                return;
            }
            let mut query = vec![0_u8; usize::from(u16::from_be_bytes(length))];
            if !matches!(
                tokio::time::timeout(TCP_IDLE_TIMEOUT, stream.read_exact(&mut query)).await,
                Ok(Ok(_))
            ) {
                return;
            }
            let Some(reply) = self.answer(querier, &query, true).await else {
                return;
            };
            let Ok(length) = u16::try_from(reply.len()) else {
                return;
            };
            if stream.write_all(&length.to_be_bytes()).await.is_err()
                || stream.write_all(&reply).await.is_err()
            {
                return;
            }
        }
    }

    /// The reply to `query` from `querier`, or nothing for responses and
    /// messages too short to answer.
    pub async fn answer(&self, querier: Ipv4Addr, query: &[u8], tcp: bool) -> Option<Vec<u8>> {
        let (response, outcome) = self.respond(querier, query, tcp).await?;
        self.metrics.dns_answer(outcome);
        Some(response)
    }

    /// The reply to `query` and how it was answered, for metrics.
    async fn respond(
        &self,
        querier: Ipv4Addr,
        query: &[u8],
        tcp: bool,
    ) -> Option<(Vec<u8>, &'static str)> {
        if query.len() < 12 || query[2] & 0x80 != 0 {
            return None;
        }
        let opcode = (query[2] >> 3) & 0x0f;
        let question = match parse_question(query) {
            Some(question) if opcode == 0 => question,
            Some(question) => {
                return Some((reply(query, &question, RCODE_NOTIMP, false, &[]), "invalid"))
            }
            None => {
                let id = u16::from_be_bytes([query[0], query[1]]);
                return Some((
                    header_only(id, query[2] & 0x01 != 0, RCODE_FORMERR),
                    "invalid",
                ));
            }
        };
        if let Some(relative) = zone_relative(&question.name) {
            let address = match relative {
                Some(name) => self.directory.resolve(querier, name),
                None => None,
            };
            return Some((
                match (address, question.kind) {
                    (Some(address), TYPE_A | TYPE_AAAA | TYPE_ANY) => {
                        let mut records = Vec::new();
                        if question.kind != TYPE_AAAA {
                            records.push(record(TYPE_A, &address.ipv4.octets()));
                        }
                        if let Some(ipv6) = address.ipv6.filter(|_| question.kind != TYPE_A) {
                            records.push(record(TYPE_AAAA, &ipv6.octets()));
                        }
                        reply(query, &question, 0, true, &records)
                    }
                    // The name exists but has no record of the requested type.
                    (Some(_), _) => reply(query, &question, 0, true, &[]),
                    (None, _) if relative.is_none() => reply(query, &question, 0, true, &[]),
                    (None, _) => reply(query, &question, RCODE_NXDOMAIN, true, &[]),
                },
                "local",
            ));
        }
        if let Some(address) = reverse_address(&question.name) {
            if question.kind == TYPE_PTR || question.kind == TYPE_ANY {
                if let Some(name) = self.directory.reverse(querier, address) {
                    let target = encode_name(&format!("{name}.{ZONE}"));
                    return Some((
                        reply(query, &question, 0, true, &[record(TYPE_PTR, &target)]),
                        "local",
                    ));
                }
            }
        }
        if self.blocked(&question.name) {
            return Some((
                reply(query, &question, RCODE_NXDOMAIN, false, &[]),
                "blocked",
            ));
        }
        Some(match self.forward(query, &question.name, tcp).await {
            Some(response) => (response, "forwarded"),
            None => (
                reply(query, &question, RCODE_SERVFAIL, false, &[]),
                "failed",
            ),
        })
    }

    fn blocked(&self, name: &str) -> bool {
        let blocklist = self.blocklist.read();
        if blocklist.domains.is_empty() {
            return false;
        }
        let mut suffix = name;
        loop {
            if blocklist.domains.contains(suffix) {
                return true;
            }
            match suffix.split_once('.') {
                Some((_, parent)) => suffix = parent,
                None => return false,
            }
        }
    }

    /// Forwards over UDP, and for a TCP client over TCP too when the UDP
    /// answer is truncated.
    async fn forward(&self, query: &[u8], name: &str, tcp: bool) -> Option<Vec<u8>> {
        let id = [query[0], query[1]];
        let valid = |response: &Vec<u8>| response.len() >= 12 && response[..2] == id;
        // The most specific conditional forward wins over the upstreams.
        let conditional = self
            .config
            .forwards
            .iter()
            .filter(|(domain, _)| {
                name == domain
                    || name
                        .strip_suffix(domain.as_str())
                        .is_some_and(|prefix| prefix.ends_with('.'))
            })
            .max_by_key(|(domain, _)| domain.len())
            .map(|(_, upstream)| vec![*upstream]);
        for upstream in conditional.as_ref().unwrap_or(&self.config.upstreams) {
            let response =
                match tokio::time::timeout(UPSTREAM_TIMEOUT, forward_udp(*upstream, query)).await {
                    Ok(Ok(response)) if valid(&response) => response,
                    Ok(Err(error)) => {
                        tracing::debug!(%error, %upstream, "DNS upstream failed");
                        continue;
                    }
                    _ => continue,
                };
            let truncated = response[2] & 0x02 != 0;
            if tcp && truncated {
                if let Ok(Ok(full)) =
                    tokio::time::timeout(UPSTREAM_TIMEOUT, forward_tcp(*upstream, query)).await
                {
                    if valid(&full) {
                        return Some(full);
                    }
                }
            }
            return Some(response);
        }
        None
    }

    fn reload_blocklist(&self) -> Result<()> {
        let Some(path) = &self.config.blocklist else {
            return Ok(());
        };
        let modified = std::fs::metadata(path)
            .and_then(|metadata| metadata.modified())
            .with_context(|| format!("read DNS blocklist {}", path.display()))?;
        if self.blocklist.read().modified == Some(modified) {
            return Ok(());
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read DNS blocklist {}", path.display()))?;
        let domains = parse_blocklist(&text);
        tracing::info!(domains = domains.len(), path = %path.display(), "loaded DNS blocklist");
        *self.blocklist.write() = Blocklist {
            domains,
            modified: Some(modified),
        };
        Ok(())
    }
}

/// Domains of a blocklist in plain or hosts-file format.
fn parse_blocklist(text: &str) -> HashSet<String> {
    text.lines()
        .map(|line| line.split('#').next().unwrap_or_default())
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let first = fields.next()?;
            // hosts files: "0.0.0.0 ads.example"
            let domain = match fields.next() {
                Some(second) if first.parse::<IpAddr>().is_ok() => second,
                _ => first,
            };
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            (!domain.is_empty()
                && domain != "localhost"
                && domain
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_')))
            .then_some(domain)
        })
        .collect()
}

/// For a name in [`ZONE`]: `Some(None)` for the zone apex, `Some(Some(relative))`
/// for a name below it.
fn zone_relative(name: &str) -> Option<Option<&str>> {
    if name == ZONE {
        return Some(None);
    }
    name.strip_suffix(ZONE)
        .and_then(|prefix| prefix.strip_suffix('.'))
        .filter(|relative| !relative.is_empty())
        .map(Some)
}

/// The address of an `in-addr.arpa` or `ip6.arpa` name.
fn reverse_address(name: &str) -> Option<IpAddr> {
    if let Some(nibbles) = name.strip_suffix(".ip6.arpa") {
        let nibbles = nibbles
            .split('.')
            .map(|nibble| match nibble.as_bytes() {
                [digit] => (*digit as char).to_digit(16),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()?;
        if nibbles.len() != 32 {
            return None;
        }
        let value = nibbles
            .iter()
            .rev()
            .fold(0_u128, |value, nibble| (value << 4) | u128::from(*nibble));
        return Some(IpAddr::V6(Ipv6Addr::from(value)));
    }
    reverse_ipv4(name).map(IpAddr::V4)
}

fn reverse_ipv4(name: &str) -> Option<Ipv4Addr> {
    let octets = name.strip_suffix(".in-addr.arpa")?;
    let mut parts = octets
        .split('.')
        .map(|part| part.parse::<u8>().ok())
        .collect::<Option<Vec<_>>>()?;
    if parts.len() != 4 {
        return None;
    }
    parts.reverse();
    Some(Ipv4Addr::new(parts[0], parts[1], parts[2], parts[3]))
}

fn parse_question(query: &[u8]) -> Option<Question> {
    if u16::from_be_bytes([query[4], query[5]]) != 1 {
        return None;
    }
    let mut offset = 12;
    let mut labels = Vec::new();
    loop {
        let length = usize::from(*query.get(offset)?);
        offset += 1;
        if length == 0 {
            break;
        }
        // Queries carry uncompressed names of at most 63-byte labels.
        if length > 63 || labels.len() >= 127 {
            return None;
        }
        let label = query.get(offset..offset + length)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        offset += length;
    }
    let kind = u16::from_be_bytes([*query.get(offset)?, *query.get(offset + 1)?]);
    query.get(offset + 3)?;
    Some(Question {
        id: u16::from_be_bytes([query[0], query[1]]),
        recursion_desired: query[2] & 0x01 != 0,
        name: labels.join("."),
        kind,
        end: offset + 4,
    })
}

fn header_only(id: u16, recursion_desired: bool, rcode: u8) -> Vec<u8> {
    let mut reply = Vec::with_capacity(12);
    reply.extend_from_slice(&id.to_be_bytes());
    reply.push(0x80 | u8::from(recursion_desired));
    reply.push(0x80 | rcode);
    reply.extend_from_slice(&[0; 8]);
    reply
}

/// A reply that repeats the question, with `answers` already encoded.
fn reply(
    query: &[u8],
    question: &Question,
    rcode: u8,
    authoritative: bool,
    answers: &[Vec<u8>],
) -> Vec<u8> {
    let mut reply = header_only(question.id, question.recursion_desired, rcode);
    if authoritative {
        reply[2] |= 0x04;
    }
    reply[4..6].copy_from_slice(&1_u16.to_be_bytes());
    reply[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
    reply.extend_from_slice(&query[12..question.end]);
    for answer in answers {
        reply.extend_from_slice(answer);
    }
    reply
}

/// A resource record for the question's name.
fn record(kind: u16, data: &[u8]) -> Vec<u8> {
    let mut record = vec![0xc0, 0x0c];
    record.extend_from_slice(&kind.to_be_bytes());
    record.extend_from_slice(&1_u16.to_be_bytes());
    record.extend_from_slice(&TTL.to_be_bytes());
    record.extend_from_slice(&(data.len() as u16).to_be_bytes());
    record.extend_from_slice(data);
    record
}

fn encode_name(name: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    for label in name.split('.').filter(|label| !label.is_empty()) {
        encoded.push(label.len() as u8);
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0);
    encoded
}

async fn forward_udp(upstream: SocketAddr, query: &[u8]) -> std::io::Result<Vec<u8>> {
    let local: SocketAddr = if upstream.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0_u16; 8], 0))
    };
    let socket = UdpSocket::bind(local).await?;
    socket.connect(upstream).await?;
    socket.send(query).await?;
    let mut buffer = vec![0_u8; 4096];
    let length = socket.recv(&mut buffer).await?;
    buffer.truncate(length);
    Ok(buffer)
}

async fn forward_tcp(upstream: SocketAddr, query: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(upstream).await?;
    let length =
        u16::try_from(query.len()).map_err(|_| std::io::Error::other("DNS query too long"))?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(query).await?;
    let mut length = [0_u8; 2];
    stream.read_exact(&mut length).await?;
    let mut response = vec![0_u8; usize::from(u16::from_be_bytes(length))];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

/// Allows binding the gateway address before it is assigned.
#[cfg(not(target_os = "linux"))]
fn set_freebind(_socket: &socket2::Socket) -> std::io::Result<()> {
    Ok(())
}

/// Allows binding the gateway address before it is assigned.
#[cfg(target_os = "linux")]
fn set_freebind(socket: &socket2::Socket) -> std::io::Result<()> {
    let enabled: libc::c_int = 1;
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_FREEBIND,
            (&enabled as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn bind_udp(address: SocketAddr) -> Result<UdpSocket> {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    set_freebind(&socket)?;
    socket.set_nonblocking(true)?;
    socket
        .bind(&address.into())
        .with_context(|| format!("bind DNS resolver to UDP {address}"))?;
    Ok(UdpSocket::from_std(socket.into())?)
}

fn bind_tcp(address: SocketAddr) -> Result<TcpListener> {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
    set_freebind(&socket)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket
        .bind(&address.into())
        .with_context(|| format!("bind DNS resolver to TCP {address}"))?;
    socket.listen(128)?;
    Ok(TcpListener::from_std(socket.into())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeDirectory;

    impl Directory for FakeDirectory {
        fn is_client(&self, address: Ipv4Addr) -> bool {
            address == Ipv4Addr::new(10, 66, 0, 2)
        }

        fn resolve(&self, querier: Ipv4Addr, name: &str) -> Option<DeviceAddresses> {
            let ipv6 = || Some("fd66::3".parse().unwrap());
            match name {
                "laptop.alice" if self.is_client(querier) => Some(DeviceAddresses {
                    ipv4: Ipv4Addr::new(10, 66, 0, 3),
                    ipv6: None,
                }),
                "desktop.alice" if self.is_client(querier) => Some(DeviceAddresses {
                    ipv4: Ipv4Addr::new(10, 66, 0, 3),
                    ipv6: ipv6(),
                }),
                _ => None,
            }
        }

        fn reverse(&self, _querier: Ipv4Addr, address: IpAddr) -> Option<String> {
            (address == IpAddr::V4(Ipv4Addr::new(10, 66, 0, 3))
                || address == IpAddr::V6("fd66::3".parse().unwrap()))
            .then(|| "laptop.alice".to_owned())
        }
    }

    fn query(name: &str, kind: u16) -> Vec<u8> {
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        query.extend_from_slice(&encode_name(name));
        query.extend_from_slice(&kind.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        query
    }

    fn rcode(reply: &[u8]) -> u8 {
        reply[3] & 0x0f
    }

    fn answers(reply: &[u8]) -> u16 {
        u16::from_be_bytes([reply[6], reply[7]])
    }

    async fn resolver(upstreams: Vec<SocketAddr>, blocklist: Option<PathBuf>) -> Arc<Resolver> {
        Resolver::new(
            ResolverConfig {
                listen: Ipv4Addr::new(10, 66, 0, 1),
                upstreams,
                forwards: Vec::new(),
                blocklist,
            },
            Arc::new(FakeDirectory),
            Arc::default(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn device_names_resolve_only_for_permitted_queriers() {
        let resolver = resolver(Vec::new(), None).await;
        let client = Ipv4Addr::new(10, 66, 0, 2);
        let reply = resolver
            .answer(client, &query("Laptop.Alice.porta.internal", TYPE_A), false)
            .await
            .unwrap();
        assert_eq!(&reply[..2], &[0x12, 0x34]);
        assert_eq!(reply[2] & 0x84, 0x84, "authoritative response");
        assert_eq!((rcode(&reply), answers(&reply)), (0, 1));
        assert_eq!(&reply[reply.len() - 4..], &[10, 66, 0, 3]);

        // Other record types exist without data; unknown names do not.
        let aaaa = resolver
            .answer(client, &query("laptop.alice.porta.internal", 28), false)
            .await
            .unwrap();
        assert_eq!((rcode(&aaaa), answers(&aaaa)), (0, 0));
        let missing = resolver
            .answer(client, &query("phone.alice.porta.internal", TYPE_A), false)
            .await
            .unwrap();
        assert_eq!(rcode(&missing), RCODE_NXDOMAIN);
        let stranger = resolver
            .answer(
                Ipv4Addr::new(10, 66, 0, 9),
                &query("laptop.alice.porta.internal", TYPE_A),
                false,
            )
            .await
            .unwrap();
        assert_eq!(rcode(&stranger), RCODE_NXDOMAIN);

        let reverse = resolver
            .answer(client, &query("3.0.66.10.in-addr.arpa", TYPE_PTR), false)
            .await
            .unwrap();
        assert_eq!(answers(&reverse), 1);
        assert!(reverse.ends_with(&encode_name("laptop.alice.porta.internal")));

        // Dual-stack devices also have AAAA records and ip6.arpa names.
        let aaaa = resolver
            .answer(
                client,
                &query("desktop.alice.porta.internal", TYPE_AAAA),
                false,
            )
            .await
            .unwrap();
        assert_eq!((rcode(&aaaa), answers(&aaaa)), (0, 1));
        assert_eq!(
            &aaaa[aaaa.len() - 16..],
            &"fd66::3".parse::<Ipv6Addr>().unwrap().octets()
        );
        let any = resolver
            .answer(
                client,
                &query("desktop.alice.porta.internal", TYPE_ANY),
                false,
            )
            .await
            .unwrap();
        assert_eq!(answers(&any), 2);
        let only_a = resolver
            .answer(
                client,
                &query("desktop.alice.porta.internal", TYPE_A),
                false,
            )
            .await
            .unwrap();
        assert_eq!(answers(&only_a), 1);
        let nibbles = "3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.6.d.f.ip6.arpa";
        let reverse6 = resolver
            .answer(client, &query(nibbles, TYPE_PTR), false)
            .await
            .unwrap();
        assert_eq!(answers(&reverse6), 1);

        // Malformed and response messages.
        assert!(resolver.answer(client, &[0; 4], false).await.is_none());
        let mut response = query("example.com", TYPE_A);
        response[2] |= 0x80;
        assert!(resolver.answer(client, &response, false).await.is_none());
        let mut two = query("example.com", TYPE_A);
        two[5] = 2;
        assert_eq!(
            rcode(&resolver.answer(client, &two, false).await.unwrap()),
            RCODE_FORMERR
        );
    }

    #[tokio::test]
    async fn blocklists_refuse_domains_and_subdomains_and_others_are_forwarded() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0_u8; 512];
            loop {
                let (length, peer) = upstream.recv_from(&mut buffer).await.unwrap();
                let mut reply = buffer[..length].to_vec();
                reply[2] |= 0x80;
                reply[7] = 1;
                reply.extend_from_slice(&record(TYPE_A, &[192, 0, 2, 10]));
                upstream.send_to(&reply, peer).await.unwrap();
            }
        });
        let directory = tempfile::tempdir().unwrap();
        let blocklist = directory.path().join("blocklist.txt");
        std::fs::write(&blocklist, "# ads\n0.0.0.0 ads.example\ntracker.example.\n").unwrap();
        let resolver = resolver(
            vec![SocketAddr::from(([127, 0, 0, 1], 9)), upstream_address],
            Some(blocklist),
        )
        .await;
        // Conditional forwarding sends a zone's queries to its own resolver.
        let conditional = Resolver::new(
            ResolverConfig {
                listen: Ipv4Addr::new(10, 66, 0, 1),
                upstreams: vec![SocketAddr::from(([127, 0, 0, 1], 9))],
                forwards: vec![("corp.example".to_owned(), upstream_address)],
                blocklist: None,
            },
            Arc::new(FakeDirectory),
            Arc::default(),
        )
        .unwrap();
        let client = Ipv4Addr::new(10, 66, 0, 2);
        let internal = conditional
            .answer(client, &query("db.corp.example", TYPE_A), false)
            .await
            .unwrap();
        assert_eq!(answers(&internal), 1);
        let elsewhere = conditional
            .answer(client, &query("notcorp.example", TYPE_A), false)
            .await
            .unwrap();
        assert_eq!(rcode(&elsewhere), RCODE_SERVFAIL);
        let client = Ipv4Addr::new(10, 66, 0, 2);
        for blocked in ["ads.example", "x.y.tracker.example"] {
            let reply = resolver
                .answer(client, &query(blocked, TYPE_A), false)
                .await
                .unwrap();
            assert_eq!(rcode(&reply), RCODE_NXDOMAIN, "{blocked}");
        }
        // The first upstream refuses; the second answers.
        let forwarded = resolver
            .answer(client, &query("www.example", TYPE_A), false)
            .await
            .unwrap();
        assert_eq!((rcode(&forwarded), answers(&forwarded)), (0, 1));
        assert!(forwarded.ends_with(&[192, 0, 2, 10]));
    }

    #[test]
    fn helpers_parse_names_zones_and_reverse_addresses() {
        assert_eq!(zone_relative("porta.internal"), Some(None));
        assert_eq!(zone_relative("a.b.porta.internal"), Some(Some("a.b")));
        assert_eq!(zone_relative("evilporta.internal"), None);
        assert_eq!(
            reverse_ipv4("4.3.2.1.in-addr.arpa"),
            Some(Ipv4Addr::new(1, 2, 3, 4))
        );
        assert_eq!(reverse_address("3.2.1.in-addr.arpa"), None);
        assert_eq!(reverse_address("1.0.ip6.arpa"), None);
        assert_eq!(reverse_address("x.ip6.arpa"), None);
        let domains =
            parse_blocklist("127.0.0.1 localhost\nbad_domain.example\n::1 v6.example # comment\n");
        assert!(domains.contains("bad_domain.example") && domains.contains("v6.example"));
        assert!(!domains.contains("localhost"));
    }
}
