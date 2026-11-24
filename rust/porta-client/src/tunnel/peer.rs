//! Direct paths to other devices; see [`porta_wire::peer`] for the
//! protocol. The gateway connection's socket also carries the device's
//! QUIC connections to its peers, so the public address the gateway sees
//! for it is the one peers reach. Of each pair, the device with the lower
//! tunnel address connects; the other sends connection attempts of its own
//! only to open its NAT for the first, and accepts. Packets fall back to
//! the gateway whenever no direct path is up or a packet does not fit.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bytes::Bytes;
use porta_wire::peer::{Fingerprint, Peer, PEER_ALPN, PEER_SERVER_NAME};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::Endpoint;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as RustlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use super::{ClientError, Inbound, Lease, Routing};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// How long a silent direct path lasts before packets return to the
/// gateway; keep-alives make silence mean the path broke.
const IDLE_TIMEOUT: Duration = Duration::from_secs(8);
const KEEP_ALIVE: Duration = Duration::from_secs(2);

/// A device reached directly rather than through the gateway.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectPeer {
    pub address: Ipv4Addr,
    /// Where the path goes: the peer's public UDP address.
    pub endpoint: SocketAddr,
}

impl std::fmt::Display for DirectPeer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} via {}", self.address, self.endpoint)
    }
}

/// A log line for a change in the tunnel's direct paths.
pub fn direct_summary(peers: &[DirectPeer]) -> String {
    if peers.is_empty() {
        return "direct paths: none; peers are reached through the gateway".to_owned();
    }
    let peers = peers.iter().map(ToString::to_string).collect::<Vec<_>>();
    format!("direct paths: {}", peers.join(", "))
}

/// The certificate this device presents to its peers, new for each tunnel.
struct Identity {
    certificate: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    fingerprint: Fingerprint,
}

impl Identity {
    fn generate() -> Result<Self, ClientError> {
        let generated = rcgen::generate_simple_self_signed(vec![PEER_SERVER_NAME.to_owned()])
            .map_err(|error| ClientError::permanent(format!("create peer certificate: {error}")))?;
        let certificate = generated.cert.der().clone();
        Ok(Self {
            fingerprint: Sha256::digest(certificate.as_ref()).into(),
            key: PrivateKeyDer::Pkcs8(generated.signing_key.serialize_der().into()),
            certificate,
        })
    }
}

/// The tunnel's direct paths.
pub(super) struct Peers {
    /// Live paths by the peer's tunnel addresses.
    links: RwLock<HashMap<IpAddr, quinn::Connection>>,
    /// Devices the gateway listed, by tunnel address, with the token that
    /// ends their path.
    known: RwLock<HashMap<Ipv4Addr, (Peer, CancellationToken)>>,
    updates: watch::Sender<Vec<Peer>>,
    status: watch::Sender<Vec<DirectPeer>>,
    lease: Lease,
    routing: Routing,
    provider: Arc<CryptoProvider>,
    identity: Identity,
    inbound: mpsc::Sender<Inbound>,
}

impl Peers {
    /// Starts accepting and making direct paths on `endpoint`, and returns
    /// the fingerprint to offer the gateway.
    pub(super) fn start(
        endpoint: Endpoint,
        lease: Lease,
        routing: Routing,
        inbound: mpsc::Sender<Inbound>,
        tasks: &TaskTracker,
        cancellation: CancellationToken,
    ) -> Result<(Arc<Self>, Fingerprint), ClientError> {
        let identity = Identity::generate()?;
        let fingerprint = identity.fingerprint;
        let peers = Arc::new(Self {
            links: RwLock::default(),
            known: RwLock::default(),
            updates: watch::channel(Vec::new()).0,
            status: watch::channel(Vec::new()).0,
            lease,
            routing,
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            identity,
            inbound,
        });
        // Every incoming connection is accepted with a configuration
        // pinned to the peer expected at its address.
        endpoint.set_server_config(Some(peers.server_config(None)?));
        let updates = peers.updates.subscribe();
        tasks.spawn(
            peers
                .clone()
                .manage(endpoint, updates, tasks.clone(), cancellation),
        );
        Ok((peers, fingerprint))
    }

    /// Replaces the gateway's list of peers.
    pub(super) fn update(&self, peers: Vec<Peer>) {
        self.updates.send_replace(peers);
    }

    /// Sends `packet` directly when a path to `destination` is up and the
    /// packet fits it.
    pub(super) fn send(&self, destination: IpAddr, packet: &[u8]) -> bool {
        let links = self.links.read().expect("peer links lock poisoned");
        let Some(link) = links.get(&destination) else {
            return false;
        };
        link.max_datagram_size()
            .is_some_and(|maximum| packet.len() <= maximum)
            && link.send_datagram(Bytes::copy_from_slice(packet)).is_ok()
    }

    pub(super) fn status(&self) -> watch::Receiver<Vec<DirectPeer>> {
        self.status.subscribe()
    }

    async fn manage(
        self: Arc<Self>,
        endpoint: Endpoint,
        mut updates: watch::Receiver<Vec<Peer>>,
        tasks: TaskTracker,
        cancellation: CancellationToken,
    ) {
        let family_v6 = endpoint.local_addr().is_ok_and(|address| address.is_ipv6());
        loop {
            tokio::select! {
                _ = cancellation.cancelled() => break,
                changed = updates.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    let listed = updates.borrow_and_update().clone();
                    self.reconcile(listed, family_v6, &endpoint, &tasks, &cancellation);
                }
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else { break };
                    self.clone().admit(incoming, &tasks);
                }
            }
        }
        for (_, token) in self
            .known
            .write()
            .expect("peer list lock poisoned")
            .values()
        {
            token.cancel();
        }
    }

    /// Follows a new peer list: paths to devices no longer listed, or
    /// listed differently, end; new devices get a path.
    fn reconcile(
        self: &Arc<Self>,
        listed: Vec<Peer>,
        family_v6: bool,
        endpoint: &Endpoint,
        tasks: &TaskTracker,
        cancellation: &CancellationToken,
    ) {
        let wanted = listed
            .into_iter()
            .filter(|peer| reachable(&self.lease, &self.routing, peer, family_v6))
            .map(|peer| (peer.address, peer))
            .collect::<HashMap<_, _>>();
        let mut known = self.known.write().expect("peer list lock poisoned");
        known.retain(|address, (peer, token)| {
            let keep = wanted.get(address) == Some(peer);
            if !keep {
                token.cancel();
            }
            keep
        });
        for (address, peer) in wanted {
            if known.contains_key(&address) {
                continue;
            }
            let token = cancellation.child_token();
            known.insert(address, (peer, token.clone()));
            tasks.spawn(self.clone().connect(endpoint.clone(), peer, token));
        }
    }

    fn dials(&self, peer: &Peer) -> bool {
        self.lease.address.addr() < peer.address
    }

    /// Keeps a path to `peer` up until `token` ends: connecting to it, or
    /// opening this side's NAT for its connections.
    async fn connect(self: Arc<Self>, endpoint: Endpoint, peer: Peer, token: CancellationToken) {
        let mut backoff = Duration::from_secs(1);
        while !token.is_cancelled() {
            if !self.dials(&peer) {
                if let Some(link) = self.link(&peer) {
                    tokio::select! {
                        _ = token.cancelled() => break,
                        _ = link.closed() => backoff = Duration::from_secs(1),
                    }
                    continue;
                }
            }
            let attempt = self.client_config(peer.fingerprint).and_then(|config| {
                endpoint
                    .connect_with(config, peer.endpoint, PEER_SERVER_NAME)
                    .map_err(ClientError::unavailable)
            });
            match attempt {
                Ok(connecting) if self.dials(&peer) => {
                    // The handshake completes for this side before the peer
                    // has checked this side's certificate; the peer confirms
                    // by opening a stream.
                    let connected = tokio::select! {
                        _ = token.cancelled() => break,
                        result = tokio::time::timeout(CONNECT_TIMEOUT, async {
                            let link = connecting.await.ok()?;
                            link.accept_uni().await.ok()?;
                            Some(link)
                        }) => result,
                    };
                    if let Ok(Some(link)) = connected {
                        self.carry(peer, link, &token).await;
                        backoff = Duration::from_secs(1);
                        continue;
                    }
                }
                // The peer ignores this attempt; it only lets the peer's
                // own attempts through this side's NAT.
                Ok(connecting) => {
                    tokio::select! {
                        _ = token.cancelled() => break,
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                    }
                    drop(connecting);
                    if self.link(&peer).is_some() {
                        continue;
                    }
                }
                Err(_) => {}
            }
            tokio::select! {
                _ = token.cancelled() => break,
                _ = tokio::time::sleep(backoff) => {}
            }
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }

    /// Accepts a connection only from the address the gateway listed for a
    /// peer that connects to this device, pinned to that peer's certificate.
    fn admit(self: Arc<Self>, incoming: quinn::Incoming, tasks: &TaskTracker) {
        let remote = canonical(incoming.remote_address());
        let expected = self
            .known
            .read()
            .expect("peer list lock poisoned")
            .values()
            .find(|(peer, _)| peer.endpoint == remote && !self.dials(peer))
            .cloned();
        let Some((peer, token)) = expected else {
            incoming.ignore();
            return;
        };
        let Ok(config) = self.server_config(Some(peer.fingerprint)) else {
            incoming.ignore();
            return;
        };
        let Ok(connecting) = incoming.accept_with(Arc::new(config)) else {
            return;
        };
        tasks.spawn(async move {
            let connected = tokio::select! {
                _ = token.cancelled() => return,
                result = tokio::time::timeout(CONNECT_TIMEOUT, async {
                    let link = connecting.await.ok()?;
                    link.open_uni().await.ok()?.finish().ok()?;
                    Some(link)
                }) => result,
            };
            if let Ok(Some(link)) = connected {
                self.carry(peer, link, &token).await;
            }
        });
    }

    /// Carries packets from `link` until it or `token` ends.
    async fn carry(&self, peer: Peer, link: quinn::Connection, token: &CancellationToken) {
        self.attach(&peer, &link);
        loop {
            let datagram = tokio::select! {
                _ = token.cancelled() => {
                    link.close(0_u32.into(), b"peer removed");
                    break;
                }
                datagram = link.read_datagram() => datagram,
            };
            let Ok(packet) = datagram else { break };
            if self.accepts(&peer, &packet)
                && self.inbound.send(Inbound::Packet(packet)).await.is_err()
            {
                break;
            }
        }
        self.detach(&peer, &link);
    }

    /// Whether a packet from `peer` is its own, addressed to this device.
    fn accepts(&self, peer: &Peer, packet: &[u8]) -> bool {
        if packet.len() > usize::from(self.lease.mtu) {
            return false;
        }
        porta_wire::ip::parse_ip(packet).is_ok_and(|info| {
            (info.source == IpAddr::V4(peer.address)
                || peer
                    .address6
                    .is_some_and(|address| info.source == IpAddr::V6(address)))
                && self.lease.owns(info.destination)
        })
    }

    fn link(&self, peer: &Peer) -> Option<quinn::Connection> {
        self.links
            .read()
            .expect("peer links lock poisoned")
            .get(&IpAddr::V4(peer.address))
            .cloned()
    }

    fn attach(&self, peer: &Peer, link: &quinn::Connection) {
        let mut links = self.links.write().expect("peer links lock poisoned");
        links.insert(IpAddr::V4(peer.address), link.clone());
        if let Some(address) = peer.address6.filter(|_| self.lease.ipv6().is_some()) {
            links.insert(IpAddr::V6(address), link.clone());
        }
        self.publish(&links);
    }

    fn detach(&self, peer: &Peer, link: &quinn::Connection) {
        let mut links = self.links.write().expect("peer links lock poisoned");
        links.retain(|address, current| {
            let address = match address {
                IpAddr::V4(address) => *address == peer.address,
                IpAddr::V6(address) => Some(*address) == peer.address6,
            };
            !(address && current.stable_id() == link.stable_id())
        });
        self.publish(&links);
    }

    fn publish(&self, links: &HashMap<IpAddr, quinn::Connection>) {
        let mut direct = links
            .iter()
            .filter_map(|(address, link)| match address {
                IpAddr::V4(address) => Some(DirectPeer {
                    address: *address,
                    endpoint: canonical(link.remote_address()),
                }),
                IpAddr::V6(_) => None,
            })
            .collect::<Vec<_>>();
        direct.sort_by_key(|peer| peer.address);
        self.status.send_if_modified(|current| {
            let changed = *current != direct;
            if changed {
                *current = direct;
            }
            changed
        });
    }

    fn client_config(&self, fingerprint: Fingerprint) -> Result<quinn::ClientConfig, ClientError> {
        let mut tls = rustls::ClientConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(ClientError::permanent)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Pinned {
                provider: self.provider.clone(),
                fingerprint: Some(fingerprint),
            }))
            .with_client_auth_cert(
                vec![self.identity.certificate.clone()],
                self.identity.key.clone_key(),
            )
            .map_err(ClientError::permanent)?;
        tls.alpn_protocols = vec![PEER_ALPN.to_vec()];
        let crypto = QuicClientConfig::try_from(tls).map_err(ClientError::permanent)?;
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        config.transport_config(transport());
        Ok(config)
    }

    /// Without a fingerprint, the configuration accepts no peer.
    fn server_config(
        &self,
        fingerprint: Option<Fingerprint>,
    ) -> Result<quinn::ServerConfig, ClientError> {
        let mut tls = rustls::ServerConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(ClientError::permanent)?
            .with_client_cert_verifier(Arc::new(Pinned {
                provider: self.provider.clone(),
                fingerprint,
            }))
            .with_single_cert(
                vec![self.identity.certificate.clone()],
                self.identity.key.clone_key(),
            )
            .map_err(ClientError::permanent)?;
        tls.alpn_protocols = vec![PEER_ALPN.to_vec()];
        let crypto = QuicServerConfig::try_from(tls).map_err(ClientError::permanent)?;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        config.transport_config(transport());
        Ok(config)
    }
}

/// Whether a direct path to `peer` could work: its address is of the
/// socket's family and outside the tunnel, which would otherwise carry the
/// path through the gateway.
fn reachable(lease: &Lease, routing: &Routing, peer: &Peer, family_v6: bool) -> bool {
    if peer.address == lease.address.addr() || peer.endpoint.is_ipv6() != family_v6 {
        return false;
    }
    match peer.endpoint.ip() {
        IpAddr::V4(address) => !routing.routes_address(address),
        IpAddr::V6(address) => {
            lease.ipv6().is_none()
                || !(routing.is_full_tunnel()
                    || routing.routes6.iter().any(|route| route.contains(&address)))
        }
    }
}

fn transport() -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        IDLE_TIMEOUT
            .try_into()
            .expect("the peer idle timeout is a valid QUIC timeout"),
    ));
    transport.keep_alive_interval(Some(KEEP_ALIVE));
    transport.max_concurrent_bidi_streams(0_u8.into());
    // One stream confirms the handshake to the connecting side.
    transport.max_concurrent_uni_streams(1_u8.into());
    transport.datagram_receive_buffer_size(Some(1 << 20));
    transport.datagram_send_buffer_size(1 << 20);
    Arc::new(transport)
}

fn canonical(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip().to_canonical(), address.port())
}

/// Accepts exactly the certificate the gateway vouched for.
#[derive(Debug)]
struct Pinned {
    provider: Arc<CryptoProvider>,
    fingerprint: Option<Fingerprint>,
}

impl Pinned {
    fn check(&self, certificate: &CertificateDer<'_>) -> Result<(), RustlsError> {
        let actual: Fingerprint = Sha256::digest(certificate.as_ref()).into();
        match self.fingerprint {
            Some(expected) if bool::from(actual.ct_eq(&expected)) => Ok(()),
            _ => Err(RustlsError::General(
                "peer certificate does not match the gateway's".to_owned(),
            )),
        }
    }
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        self.check(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _certificate: &CertificateDer<'_>,
        _signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Err(RustlsError::PeerIncompatible(
            rustls::PeerIncompatible::Tls13RequiredForQuic,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl ClientCertVerifier for Pinned {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        self.check(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        ServerCertVerifier::verify_tls12_signature(self, message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        ServerCertVerifier::verify_tls13_signature(self, message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ServerCertVerifier::supported_verify_schemes(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Device {
        peers: Arc<Peers>,
        fingerprint: Fingerprint,
        endpoint: SocketAddr,
        inbound: mpsc::Receiver<Inbound>,
        _tasks: TaskTracker,
        cancellation: CancellationToken,
    }

    impl Drop for Device {
        fn drop(&mut self) {
            self.cancellation.cancel();
        }
    }

    fn device(address: &str) -> Device {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let endpoint = Endpoint::new(
            Default::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        let local = endpoint.local_addr().unwrap();
        let (inbound_tx, inbound) = mpsc::channel(16);
        let tasks = TaskTracker::new();
        let cancellation = CancellationToken::new();
        let (peers, fingerprint) = Peers::start(
            endpoint,
            Lease {
                address: format!("{address}/32").parse().unwrap(),
                gateway: None,
                dns: None,
                mtu: 1280,
                address6: None,
            },
            Routing {
                routes: vec!["10.66.0.0/24".parse().unwrap()],
                ..Routing::default()
            },
            inbound_tx,
            &tasks,
            cancellation.clone(),
        )
        .unwrap();
        Device {
            peers,
            fingerprint,
            endpoint: local,
            inbound,
            _tasks: tasks,
            cancellation,
        }
    }

    fn listing(device: &Device, address: &str) -> Peer {
        Peer {
            address: address.parse().unwrap(),
            address6: None,
            endpoint: device.endpoint,
            fingerprint: device.fingerprint,
        }
    }

    fn packet(source: &str, destination: &str) -> Vec<u8> {
        let mut packet = vec![0_u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 253;
        packet[12..16].copy_from_slice(&source.parse::<Ipv4Addr>().unwrap().octets());
        packet[16..20].copy_from_slice(&destination.parse::<Ipv4Addr>().unwrap().octets());
        porta_wire::ip::set_ipv4_header_checksum(&mut packet).unwrap();
        packet
    }

    async fn direct(device: &Device) -> Vec<DirectPeer> {
        let mut status = device.peers.status();
        let peers = tokio::time::timeout(
            Duration::from_secs(10),
            status.wait_for(|peers| !peers.is_empty()),
        )
        .await
        .expect("direct path came up")
        .unwrap()
        .clone();
        peers
    }

    async fn next_packet(device: &mut Device) -> Option<Bytes> {
        match tokio::time::timeout(Duration::from_millis(500), device.inbound.recv()).await {
            Ok(Some(Inbound::Packet(packet))) => Some(packet),
            _ => None,
        }
    }

    #[tokio::test]
    async fn listed_devices_connect_and_exchange_only_their_own_packets() {
        let mut low = device("10.66.0.2");
        let mut high = device("10.66.0.3");
        low.peers.update(vec![listing(&high, "10.66.0.3")]);
        high.peers.update(vec![listing(&low, "10.66.0.2")]);
        assert_eq!(
            direct(&low).await,
            vec![DirectPeer {
                address: "10.66.0.3".parse().unwrap(),
                endpoint: high.endpoint,
            }]
        );
        direct(&high).await;

        let forward = packet("10.66.0.2", "10.66.0.3");
        assert!(low.peers.send("10.66.0.3".parse().unwrap(), &forward));
        assert_eq!(next_packet(&mut high).await.unwrap(), forward);
        let back = packet("10.66.0.3", "10.66.0.2");
        assert!(high.peers.send("10.66.0.2".parse().unwrap(), &back));
        assert_eq!(next_packet(&mut low).await.unwrap(), back);

        // A peer cannot send as another device or to another device.
        for spoofed in [
            packet("10.66.0.9", "10.66.0.3"),
            packet("10.66.0.2", "10.66.0.9"),
        ] {
            assert!(low.peers.send("10.66.0.3".parse().unwrap(), &spoofed));
        }
        assert!(next_packet(&mut high).await.is_none());
        // Unlisted destinations and oversized packets use the gateway.
        assert!(!low.peers.send("10.66.0.4".parse().unwrap(), &forward));
        assert!(!low
            .peers
            .send("10.66.0.3".parse().unwrap(), &vec![0x45; 4000]));

        // Delisting ends the path on both sides.
        low.peers.update(Vec::new());
        let mut status = high.peers.status();
        tokio::time::timeout(
            Duration::from_secs(10),
            status.wait_for(|peers| peers.is_empty()),
        )
        .await
        .expect("path ended")
        .unwrap();
        assert!(!low.peers.send("10.66.0.3".parse().unwrap(), &forward));
    }

    #[tokio::test]
    async fn a_device_without_the_listed_certificate_is_refused() {
        let low = device("10.66.0.2");
        let high = device("10.66.0.3");
        let impostor = Peer {
            fingerprint: [0; 32],
            ..listing(&low, "10.66.0.2")
        };
        low.peers.update(vec![listing(&high, "10.66.0.3")]);
        high.peers.update(vec![impostor]);
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(low.peers.status().borrow().is_empty());
        assert!(high.peers.status().borrow().is_empty());
    }

    #[test]
    fn tunneled_endpoints_and_other_families_are_not_direct() {
        let routing = Routing {
            routes: vec!["10.0.0.0/8".parse().unwrap()],
            ..Routing::default()
        };
        let lease = Lease {
            address: "10.66.0.2/32".parse().unwrap(),
            gateway: None,
            dns: None,
            mtu: 1280,
            address6: None,
        };
        let check = |endpoint: &str, family_v6| {
            let peer = Peer {
                address: "10.66.0.3".parse().unwrap(),
                address6: None,
                endpoint: endpoint.parse().unwrap(),
                fingerprint: [1; 32],
            };
            reachable(&lease, &routing, &peer, family_v6)
        };
        assert!(check("198.51.100.7:4000", false));
        assert!(!check("10.1.2.3:4000", false));
        assert!(!check("198.51.100.7:4000", true));
        assert!(check("[2001:db8::7]:4000", true));
    }
}
