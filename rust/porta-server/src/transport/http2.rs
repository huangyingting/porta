use anyhow::Result;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures_util::future::BoxFuture;
use http::{HeaderMap, Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::http_handler::EffectiveClientAddress;
use crate::server::{plain_response, BoxError, Handler, RequestLifetime, ResponseBody};
use crate::transport::http3::{
    address_response, append_ip_capsule, decode_ip_bytes, inject_packet, take_capsule,
};
use crate::transport::session::{
    bearer_token, fragment_ipv4, icmp_fragmentation_needed, parse_lane_config,
    AuthenticationRequest, DeviceProof, LaneConfig, LeaseError, MtuError, OpenSessionError,
    OpenSessionRequest, RouteError, RouteKind, Services, Session, BATCH_BYTES, CONTENT_TYPE,
    HEADER_LANE, HEADER_LANES, HEADER_LANE_SESSION, HEADER_MAX_VERSION, HEADER_MIN_VERSION,
    HEADER_VERSION, MASQUE_AUTH_PATH, MASQUE_PATH, PACKET_BATCH, PROTOCOL_VERSION, TUNNEL_PATH,
};
use crate::wire::ip::parse_ipv4;
use crate::wire::masque::{
    decode_address_assign, decode_route_advertisement, CAPSULE_ADDRESS_ASSIGN,
    CAPSULE_ADDRESS_REQUEST, CAPSULE_DATAGRAM, CAPSULE_ROUTE_ADVERTISEMENT, MAX_CAPSULE_SIZE,
};

const CAPSULE_PROTOCOL: &str = "capsule-protocol";
static ICMP_IDENTIFICATION: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
pub struct Http2Config {
    pub mtu: u16,
    pub dns: Option<std::net::Ipv4Addr>,
    pub keepalive_interval: Duration,
    pub response_queue_chunks: usize,
}

impl Default for Http2Config {
    fn default() -> Self {
        Self {
            mtu: 1400,
            dns: None,
            keepalive_interval: Duration::from_secs(20),
            response_queue_chunks: 32,
        }
    }
}

pub struct Http2Handler {
    services: Arc<Services>,
    config: Http2Config,
}

impl Http2Handler {
    pub fn new(services: Arc<Services>, config: Http2Config) -> Result<Self> {
        if !(576..=9000).contains(&config.mtu) {
            anyhow::bail!("MTU {} is outside 576..9000", config.mtu);
        }
        if config.keepalive_interval.is_zero() {
            anyhow::bail!("HTTP/2 keepalive interval must be positive");
        }
        if config.response_queue_chunks == 0 {
            anyhow::bail!("HTTP/2 response queue must be non-empty");
        }
        Ok(Self { services, config })
    }

    async fn handle(
        self: Arc<Self>,
        request: Request<Incoming>,
        peer: SocketAddr,
    ) -> Result<Response<ResponseBody>> {
        if request.uri().path().eq_ignore_ascii_case(MASQUE_PATH) {
            return self.handle_masque(request, peer).await;
        }
        if request.uri().path() != TUNNEL_PATH {
            return Ok(plain_response(StatusCode::NOT_FOUND, "not found\n"));
        }
        if request.method() != http::Method::POST {
            let mut response =
                plain_response(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed\n");
            response
                .headers_mut()
                .insert(http::header::ALLOW, http::HeaderValue::from_static("POST"));
            return Ok(response);
        }
        if request.version() < Version::HTTP_2 {
            return Ok(plain_response(
                StatusCode::HTTP_VERSION_NOT_SUPPORTED,
                "Porta requires HTTP/2 or HTTP/3\n",
            ));
        }
        if !protocol_version_supported(request.headers()) {
            return Ok(version_error_response());
        }
        if media_type(request.headers()) != Some(CONTENT_TYPE) {
            return Ok(plain_response(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported content type\n",
            ));
        }
        let lanes = match parse_lane_config(request.headers()) {
            Ok(lanes) => lanes,
            Err(error) => {
                return Ok(plain_response(
                    StatusCode::BAD_REQUEST,
                    match error {
                        crate::transport::session::LaneConfigError::Session => {
                            "invalid tunnel lane session\n"
                        }
                        crate::transport::session::LaneConfigError::Index => {
                            "invalid tunnel lane index\n"
                        }
                        crate::transport::session::LaneConfigError::Count => {
                            "invalid tunnel lane count\n"
                        }
                    },
                ))
            }
        };
        let token = match bearer_token(request.headers()) {
            Ok(token) => token,
            Err(_) => {
                self.services.metrics.authentication_failed();
                return Ok(unauthorized_response());
            }
        };
        let authentication = AuthenticationRequest {
            bearer_token: token,
            proof: DeviceProof::from_headers(request.headers()),
            method: request.method().clone(),
            path: request.uri().path().to_owned(),
            peer: request
                .extensions()
                .get::<EffectiveClientAddress>()
                .map_or(peer, |address| SocketAddr::new(address.0, peer.port())),
        };
        let session = match self
            .services
            .open(OpenSessionRequest {
                authentication,
                group_id: Some(lanes.session_id.clone()),
                route: RouteKind::Http2Lane {
                    session_id: lanes.session_id.clone(),
                    lane: lanes.index,
                    lanes: lanes.count,
                    backend_connection: peer.to_string(),
                },
                transport: format!("{:?}", request.version()),
            })
            .await
        {
            Ok(session) => session,
            Err(error) => return Ok(open_error_response(error)),
        };
        if session.collapsed_backend {
            tracing::warn!(
                address = %session.lease.address,
                session = %lanes.session_id,
                "HTTP/2 fallback lanes share a backend TCP connection; reverse-proxy multiplexing restores head-of-line blocking"
            );
        }

        let (sender, receiver) = mpsc::channel(self.config.response_queue_chunks);
        sender
            .try_send(Bytes::from_static(&[0, 0]))
            .expect("new response queue has room for initial frame");
        let cancellation = session.cancellation.clone();
        let body = ChannelBody {
            receiver,
            cancellation,
        }
        .boxed();
        let response = success_response(&session, &lanes, self.config.mtu, self.config.dns, body);
        let config = self.config.clone();
        tokio::spawn(async move {
            if let Err(error) = run_tunnel(request.into_body(), session, sender, config).await {
                tracing::debug!(%peer, %error, "HTTP/2 tunnel stopped");
            }
        });
        Ok(response)
    }

    async fn handle_masque(
        self: Arc<Self>,
        mut request: Request<Incoming>,
        peer: SocketAddr,
    ) -> Result<Response<ResponseBody>> {
        if request.version() != Version::HTTP_2 {
            return Ok(plain_response(
                StatusCode::HTTP_VERSION_NOT_SUPPORTED,
                "CONNECT-IP requires HTTP/2\n",
            ));
        }
        if request.method() != http::Method::CONNECT
            || request
                .extensions()
                .get::<hyper::ext::Protocol>()
                .map(hyper::ext::Protocol::as_str)
                != Some("connect-ip")
        {
            return Ok(plain_response(
                StatusCode::BAD_REQUEST,
                "invalid CONNECT-IP request\n",
            ));
        }
        if request
            .headers()
            .get(CAPSULE_PROTOCOL)
            .and_then(|value| value.to_str().ok())
            != Some("?1")
        {
            return Ok(plain_response(
                StatusCode::BAD_REQUEST,
                "Capsule-Protocol is required\n",
            ));
        }
        if !protocol_version_supported(request.headers()) {
            return Ok(version_error_response());
        }
        let token = match bearer_token(request.headers()) {
            Ok(token) => token,
            Err(_) => {
                self.services.metrics.authentication_failed();
                return Ok(unauthorized_response());
            }
        };
        let authentication = AuthenticationRequest {
            bearer_token: token,
            proof: DeviceProof::from_headers(request.headers()),
            method: request.method().clone(),
            path: MASQUE_AUTH_PATH.to_owned(),
            peer: request
                .extensions()
                .get::<EffectiveClientAddress>()
                .map_or(peer, |address| SocketAddr::new(address.0, peer.port())),
        };
        let session = match self
            .services
            .open(OpenSessionRequest {
                authentication,
                group_id: None,
                route: RouteKind::ConnectIp,
                transport: "masque-h2-capsule".to_owned(),
            })
            .await
        {
            Ok(session) => session,
            Err(error) => return Ok(open_error_response(error)),
        };

        let upgrade = hyper::upgrade::on(&mut request);
        let lifetime = request.extensions_mut().remove::<RequestLifetime>();
        let response = masque_success_response(
            self.config.mtu,
            self.config.dns,
            Full::new(Bytes::new())
                .map_err(|never| -> BoxError { match never {} })
                .boxed(),
        );
        let mtu = self.config.mtu;
        tokio::spawn(async move {
            let _lifetime = lifetime;
            match upgrade.await {
                Ok(stream) => {
                    if let Err(error) = run_masque_tunnel(TokioIo::new(stream), session, mtu).await
                    {
                        tracing::debug!(%peer, %error, "HTTP/2 CONNECT-IP tunnel stopped");
                    }
                }
                Err(error) => {
                    tracing::debug!(%peer, %error, "HTTP/2 CONNECT-IP upgrade failed");
                }
            }
        });
        Ok(response)
    }
}

impl Handler for Http2Handler {
    fn call(
        self: Arc<Self>,
        request: Request<Incoming>,
        peer: SocketAddr,
    ) -> BoxFuture<'static, Result<Response<ResponseBody>>> {
        Box::pin(async move { self.handle(request, peer).await })
    }
}

fn protocol_version_supported(headers: &HeaderMap) -> bool {
    headers
        .get(HEADER_VERSION)
        .and_then(|value| value.to_str().ok())
        == Some(PROTOCOL_VERSION)
}

fn media_type(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
}

fn set_version_headers(headers: &mut HeaderMap) {
    headers.insert(HEADER_VERSION, PROTOCOL_VERSION.parse().unwrap());
    headers.insert(HEADER_MIN_VERSION, PROTOCOL_VERSION.parse().unwrap());
    headers.insert(HEADER_MAX_VERSION, PROTOCOL_VERSION.parse().unwrap());
}

fn version_error_response() -> Response<ResponseBody> {
    let mut response = plain_response(
        StatusCode::UPGRADE_REQUIRED,
        "unsupported Porta protocol version\n",
    );
    set_version_headers(response.headers_mut());
    response
}

fn unauthorized_response() -> Response<ResponseBody> {
    let mut response = plain_response(StatusCode::UNAUTHORIZED, "unauthorized\n");
    response
        .headers_mut()
        .insert(http::header::WWW_AUTHENTICATE, porta_authenticate_header());
    response
}

fn porta_authenticate_header() -> http::HeaderValue {
    http::HeaderValue::from_str(&["Bearer", " realm=\"porta\""].concat())
        .expect("static authentication challenge is valid")
}

fn open_error_response(error: OpenSessionError) -> Response<ResponseBody> {
    match error {
        OpenSessionError::Unauthorized => unauthorized_response(),
        OpenSessionError::RateLimited {
            retry_after_seconds,
        } => {
            let mut response = plain_response(
                StatusCode::TOO_MANY_REQUESTS,
                "too many authentication attempts\n",
            );
            response.headers_mut().insert(
                http::header::RETRY_AFTER,
                retry_after_seconds.to_string().parse().unwrap(),
            );
            response
        }
        OpenSessionError::Lease(LeaseError::Exhausted | LeaseError::Internal) => plain_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "no tunnel addresses available\n",
        ),
        OpenSessionError::Route(RouteError::Conflict) => {
            plain_response(StatusCode::CONFLICT, "invalid tunnel lane group\n")
        }
        OpenSessionError::Route(RouteError::Unavailable) => plain_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "packet router unavailable\n",
        ),
    }
}

fn success_response(
    session: &Session,
    lanes: &LaneConfig,
    mtu: u16,
    dns: Option<std::net::Ipv4Addr>,
    body: ResponseBody,
) -> Response<ResponseBody> {
    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static(CONTENT_TYPE),
    );
    headers.insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    headers.insert(
        "X-Content-Type-Options",
        http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        "Referrer-Policy",
        http::HeaderValue::from_static("no-referrer"),
    );
    set_version_headers(headers);
    headers.insert("X-Porta-Address", session.lease.prefix().parse().unwrap());
    headers.insert(
        "X-Porta-Gateway",
        session.lease.gateway.to_string().parse().unwrap(),
    );
    headers.insert("X-Porta-MTU", mtu.to_string().parse().unwrap());
    headers.insert(HEADER_LANE_SESSION, lanes.session_id.parse().unwrap());
    headers.insert(HEADER_LANE, lanes.index.to_string().parse().unwrap());
    headers.insert(HEADER_LANES, lanes.count.to_string().parse().unwrap());
    if let Some(dns) = dns {
        headers.insert("X-Porta-DNS", dns.to_string().parse().unwrap());
    }
    response
}

fn masque_success_response(
    mtu: u16,
    dns: Option<std::net::Ipv4Addr>,
    body: ResponseBody,
) -> Response<ResponseBody> {
    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(CAPSULE_PROTOCOL, http::HeaderValue::from_static("?1"));
    headers.insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    headers.insert(
        "X-Content-Type-Options",
        http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        "Referrer-Policy",
        http::HeaderValue::from_static("no-referrer"),
    );
    set_version_headers(headers);
    headers.insert("X-Porta-MTU", mtu.to_string().parse().unwrap());
    if let Some(dns) = dns {
        headers.insert("X-Porta-DNS", dns.to_string().parse().unwrap());
    }
    response
}

async fn run_masque_tunnel<I>(io: I, session: Session, mtu: u16) -> Result<()>
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(io);
    let mut input = BytesMut::with_capacity(usize::from(mtu) * 2);
    let mut read_buffer = vec![0_u8; usize::from(mtu) * 2 + 256];
    let mut assigned = false;
    let mut downlink_ready = false;
    let mut icmp_after = Instant::now();
    loop {
        tokio::select! {
            biased;
            _ = session.cancellation.cancelled() => return Ok(()),
            size = reader.read(&mut read_buffer) => {
                let size = size?;
                if size == 0 {
                    return Ok(());
                }
                input.extend_from_slice(&read_buffer[..size]);
                while let Some((capsule_type, value)) = take_capsule(&mut input)? {
                    match capsule_type {
                        CAPSULE_ADDRESS_REQUEST => {
                            let (response, now_assigned) =
                                address_response(&session.lease, assigned, &value)?;
                            assigned = now_assigned;
                            downlink_ready = downlink_ready || now_assigned;
                            write_masque_output(&mut writer, &response, &session).await?;
                        }
                        CAPSULE_DATAGRAM => {
                            if !assigned {
                                session.services().metrics.dropped_from_client();
                            } else if let Ok(packet) = decode_ip_bytes(value) {
                                inject_packet(&session, packet, mtu).await?;
                            } else {
                                session.services().metrics.dropped_from_client();
                            }
                        }
                        CAPSULE_ADDRESS_ASSIGN => {
                            decode_address_assign(&value).map_err(anyhow::Error::new)?;
                        }
                        CAPSULE_ROUTE_ADVERTISEMENT => {
                            decode_route_advertisement(&value).map_err(anyhow::Error::new)?;
                        }
                        _ => {}
                    }
                }
                if input.len() > MAX_CAPSULE_SIZE + 16 {
                    anyhow::bail!("CONNECT-IP capsule buffer exceeded its limit");
                }
            }
            packet = session.downlink.next_packet(), if downlink_ready => {
                let packet = packet.ok_or_else(|| anyhow::anyhow!("packet router closed"))?;
                send_masque_downlink(&session, packet, mtu, &mut writer, &mut icmp_after).await?;
            }
        }
    }
}

async fn send_masque_downlink<W>(
    session: &Session,
    packet: Bytes,
    mtu: u16,
    output: &mut W,
    icmp_after: &mut Instant,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if packet.len() > usize::from(mtu) {
        match fragment_ipv4(&packet, usize::from(mtu)) {
            Ok(fragments) => {
                session.services().metrics.mtu_fragmented();
                let mut control = BytesMut::with_capacity(packet.len() + fragments.len() * 16);
                for fragment in fragments {
                    append_ip_capsule(&mut control, &fragment)?;
                    session.services().metrics.sent_to_client();
                    session.usage.downloaded(fragment.len() as u64, 1);
                }
                write_masque_output(output, &control, session).await?;
                return Ok(());
            }
            Err(MtuError::FragmentationNeeded) => {
                let now = Instant::now();
                if now < *icmp_after {
                    session.services().metrics.mtu_icmp_rate_limited();
                    return Ok(());
                }
                match icmp_fragmentation_needed(
                    &packet,
                    &session.lease,
                    usize::from(mtu),
                    ICMP_IDENTIFICATION.fetch_add(1, Ordering::Relaxed) as u16,
                ) {
                    Ok(reply) => {
                        session
                            .services()
                            .router
                            .inject_validated(session.cancellation.clone(), reply)
                            .await
                            .map_err(anyhow::Error::new)?;
                        *icmp_after = now + Duration::from_millis(100);
                        session.services().metrics.mtu_icmp_sent();
                    }
                    Err(MtuError::IcmpSuppressed) => {
                        session.services().metrics.mtu_icmp_suppressed();
                    }
                    Err(_) => session.services().metrics.invalid_tun_packet(),
                }
                return Ok(());
            }
            Err(_) => {
                session.services().metrics.invalid_tun_packet();
                return Ok(());
            }
        }
    }

    let mut control = BytesMut::with_capacity(packet.len() + 16);
    append_ip_capsule(&mut control, &packet)?;
    session.services().metrics.sent_to_client();
    session.usage.downloaded(packet.len() as u64, 1);
    let mut count = 1;
    let mut bytes = packet.len();
    while count < PACKET_BATCH && bytes < BATCH_BYTES {
        let Some(packet) = session.downlink.try_packet() else {
            break;
        };
        append_ip_capsule(&mut control, &packet)?;
        count += 1;
        bytes += packet.len();
        session.services().metrics.sent_to_client();
        session.usage.downloaded(packet.len() as u64, 1);
    }
    write_masque_output(output, &control, session).await?;
    Ok(())
}

async fn write_masque_output<W>(output: &mut W, data: &[u8], session: &Session) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    tokio::select! {
        result = output.write_all(data) => result?,
        _ = session.cancellation.cancelled() => return Ok(()),
    }
    tokio::select! {
        result = output.flush() => result?,
        _ = session.cancellation.cancelled() => {}
    }
    Ok(())
}

async fn run_tunnel<B>(
    mut body: B,
    session: Session,
    output: mpsc::Sender<Bytes>,
    config: Http2Config,
) -> Result<()>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let mut input = BytesMut::with_capacity(usize::from(config.mtu) * 2);
    let mut keepalive = tokio::time::interval(config.keepalive_interval);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    keepalive.tick().await;
    loop {
        tokio::select! {
            biased;
            _ = session.cancellation.cancelled() => return Ok(()),
            frame = body.frame() => {
                let Some(frame) = frame else {
                    return Ok(());
                };
                let frame = frame.map_err(anyhow::Error::new)?;
                let Ok(data) = frame.into_data() else {
                    continue;
                };
                input.extend_from_slice(&data);
                consume_uploads(&mut input, &session, config.mtu).await?;
            }
            packet = session.downlink.next_packet() => {
                let Some(packet) = packet else {
                    return Ok(());
                };
                let batch = frame_downlink_batch(packet, &session);
                if !send_output(&output, batch, &session).await {
                    return Ok(());
                }
            }
            _ = keepalive.tick() => {
                if !send_output(&output, Bytes::from_static(&[0, 0]), &session).await {
                    return Ok(());
                }
            }
        }
    }
}

async fn send_output(output: &mpsc::Sender<Bytes>, data: Bytes, session: &Session) -> bool {
    tokio::select! {
        result = output.send(data) => result.is_ok(),
        _ = session.cancellation.cancelled() => false,
    }
}

async fn consume_uploads(input: &mut BytesMut, session: &Session, mtu: u16) -> Result<()> {
    loop {
        if input.len() < 2 {
            return Ok(());
        }
        let size = usize::from(u16::from_be_bytes([input[0], input[1]]));
        if input.len() < size + 2 {
            return Ok(());
        }
        input.advance(2);
        if size == 0 {
            continue;
        }
        let packet = input.split_to(size).freeze();
        if size > usize::from(mtu) {
            session.services().metrics.dropped_from_client();
            continue;
        }
        let Ok(info) = parse_ipv4(&packet) else {
            session.services().metrics.dropped_from_client();
            continue;
        };
        if info.source != session.lease.address {
            session.services().metrics.dropped_from_client();
            continue;
        }
        session
            .services()
            .router
            .inject_from_client(
                session.cancellation.clone(),
                session.lease.address,
                packet.clone(),
            )
            .await
            .map_err(anyhow::Error::new)?;
        session.services().metrics.received_from_client();
        session.usage.uploaded(packet.len() as u64, 1);
    }
}

fn frame_downlink_batch(first: Bytes, session: &Session) -> Bytes {
    let mut output = BytesMut::with_capacity((first.len() + 2).min(BATCH_BYTES));
    let mut packet = first;
    let mut count = 0;
    let mut packet_bytes = 0;
    loop {
        output.put_u16(packet.len() as u16);
        output.extend_from_slice(&packet);
        packet_bytes += packet.len();
        count += 1;
        session.services().metrics.sent_to_client();
        session.usage.downloaded(packet.len() as u64, 1);
        if count >= PACKET_BATCH || packet_bytes >= BATCH_BYTES {
            break;
        }
        let Some(next) = session.downlink.try_packet() else {
            break;
        };
        packet = next;
    }
    output.freeze()
}

struct ChannelBody {
    receiver: mpsc::Receiver<Bytes>,
    cancellation: tokio_util::sync::CancellationToken,
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.receiver
            .poll_recv(context)
            .map(|item| item.map(|data| Ok(Frame::data(data))))
    }

    fn is_end_stream(&self) -> bool {
        self.receiver.is_closed() && self.receiver.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

impl Drop for ChannelBody {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::session::{
        Authenticated, AuthenticationError, Authenticator, ClientIdentity, Lease, LeaseAllocator,
        LeaseRequest, NoopCleanup, NoopMetrics, NoopUsage, PacketQueue, PacketRouter, PacketSource,
        QueueConfig, RouteRequest, RouteSession, TokenCancellation,
    };
    use crate::wire::masque::{encode_address_request, Address, Encoder};
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use ipnet::Ipv4Net;
    use std::sync::Mutex;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_util::sync::CancellationToken;

    #[test]
    fn exact_protocol_status_and_headers() {
        let response = version_error_response();
        assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);
        assert_eq!(response.headers()[HEADER_VERSION], "2");
        assert_eq!(response.headers()[HEADER_MIN_VERSION], "2");
        assert_eq!(response.headers()[HEADER_MAX_VERSION], "2");
        assert_eq!(
            media_type(
                &[(
                    http::header::CONTENT_TYPE,
                    "application/x-porta-packets; charset=binary"
                        .parse()
                        .unwrap()
                )]
                .into_iter()
                .collect()
            ),
            Some(CONTENT_TYPE)
        );
    }

    struct FakeAuthenticator;

    impl Authenticator for FakeAuthenticator {
        fn authenticate(
            &self,
            request: AuthenticationRequest,
        ) -> BoxFuture<'static, Result<Authenticated, AuthenticationError>> {
            Box::pin(async move {
                assert_eq!(request.proof.device_id, "d-test");
                let token = CancellationToken::new();
                Ok(Authenticated {
                    identity: ClientIdentity {
                        account_id: "account".into(),
                        lease_id: "lease".into(),
                    },
                    cancellation: Arc::new(TokenCancellation::new(token)),
                    cleanup: Arc::new(NoopCleanup),
                })
            })
        }
    }

    struct CancellableAuthenticator {
        cancellation: CancellationToken,
    }

    impl Authenticator for CancellableAuthenticator {
        fn authenticate(
            &self,
            _request: AuthenticationRequest,
        ) -> BoxFuture<'static, Result<Authenticated, AuthenticationError>> {
            let cancellation = self.cancellation.clone();
            Box::pin(async move {
                Ok(Authenticated {
                    identity: ClientIdentity {
                        account_id: "account".into(),
                        lease_id: "lease".into(),
                    },
                    cancellation: Arc::new(TokenCancellation::new(cancellation)),
                    cleanup: Arc::new(NoopCleanup),
                })
            })
        }
    }

    struct FakeLeases;

    impl LeaseAllocator for FakeLeases {
        fn acquire(&self, _request: LeaseRequest) -> BoxFuture<'static, Result<Lease, LeaseError>> {
            Box::pin(async {
                Ok(Lease {
                    address: "10.66.0.2".parse().unwrap(),
                    prefix_len: 24,
                    gateway: "10.66.0.1".parse().unwrap(),
                    opaque_id: 1,
                })
            })
        }

        fn release(&self, _lease: &Lease) {}
    }

    struct FakeRouter {
        uploads: Arc<Mutex<Vec<Bytes>>>,
        downlink: Arc<PacketQueue>,
    }

    impl PacketRouter for FakeRouter {
        fn register(
            &self,
            request: RouteRequest,
        ) -> BoxFuture<'static, Result<RouteSession, RouteError>> {
            let downlink = self.downlink.clone();
            Box::pin(async move {
                Ok(RouteSession {
                    downlink,
                    cancellation: request.parent.child_token(),
                    collapsed_backend: false,
                    cleanup: Arc::new(NoopCleanup),
                })
            })
        }

        fn inject_from_client(
            &self,
            _cancellation: CancellationToken,
            _lease: std::net::Ipv4Addr,
            packet: Bytes,
        ) -> BoxFuture<'static, Result<(), RouteError>> {
            let uploads = self.uploads.clone();
            let downlink = self.downlink.clone();
            Box::pin(async move {
                uploads.lock().unwrap().push(packet.clone());
                downlink.enqueue(packet);
                Ok(())
            })
        }

        fn inject_validated(
            &self,
            _cancellation: CancellationToken,
            packet: Bytes,
        ) -> BoxFuture<'static, Result<(), RouteError>> {
            self.inject_from_client(
                CancellationToken::new(),
                "10.66.0.2".parse().unwrap(),
                packet,
            )
        }
    }

    #[tokio::test]
    async fn fake_router_validates_source_and_batches_downlink() {
        let uploads = Arc::new(Mutex::new(Vec::new()));
        let downlink = PacketQueue::new(QueueConfig::HTTP2, 0, Arc::new(NoopMetrics));
        let services = Arc::new(Services {
            authenticator: Arc::new(FakeAuthenticator),
            leases: Arc::new(FakeLeases),
            router: Arc::new(FakeRouter {
                uploads: uploads.clone(),
                downlink: downlink.clone(),
            }),
            usage: Arc::new(NoopUsage),
            metrics: Arc::new(NoopMetrics),
        });
        let session = services
            .open(OpenSessionRequest {
                authentication: AuthenticationRequest {
                    bearer_token: "0123456789abcdef".into(),
                    proof: DeviceProof {
                        device_id: "d-test".into(),
                        ..DeviceProof::default()
                    },
                    method: http::Method::POST,
                    path: TUNNEL_PATH.into(),
                    peer: "127.0.0.1:1234".parse().unwrap(),
                },
                group_id: Some("session-12345678".into()),
                route: RouteKind::Http2Lane {
                    session_id: "session-12345678".into(),
                    lane: 0,
                    lanes: 2,
                    backend_connection: "peer".into(),
                },
                transport: "HTTP/2".into(),
            })
            .await
            .unwrap();
        let mut packet = vec![0; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 66, 0, 2]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        let mut framed = BytesMut::new();
        framed.put_u16(packet.len() as u16);
        framed.extend_from_slice(&packet);
        consume_uploads(&mut framed, &session, 1400).await.unwrap();
        assert_eq!(uploads.lock().unwrap().len(), 1);
        let echoed = downlink.try_packet().unwrap();
        let batch = frame_downlink_batch(echoed, &session);
        assert_eq!(&batch[..2], &28_u16.to_be_bytes());
        assert_eq!(&batch[2..], &packet);

        packet[12] = 192;
        let mut spoofed = BytesMut::new();
        spoofed.put_u16(packet.len() as u16);
        spoofed.extend_from_slice(&packet);
        consume_uploads(&mut spoofed, &session, 1400).await.unwrap();
        assert_eq!(uploads.lock().unwrap().len(), 1);

        let (sender, mut receiver) = mpsc::channel(1);
        sender.send(Bytes::from_static(b"full")).await.unwrap();
        let cancellation = session.cancellation.clone();
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            cancellation.cancel();
        });
        assert!(!send_output(&sender, Bytes::from_static(b"blocked"), &session).await);
        assert_eq!(receiver.recv().await.unwrap(), Bytes::from_static(b"full"));
    }

    #[tokio::test]
    async fn masque_capsules_assign_address_and_carry_packets() {
        let uploads = Arc::new(Mutex::new(Vec::new()));
        let downlink = PacketQueue::new(QueueConfig::HTTP2, 0, Arc::new(NoopMetrics));
        let services = Arc::new(Services {
            authenticator: Arc::new(FakeAuthenticator),
            leases: Arc::new(FakeLeases),
            router: Arc::new(FakeRouter {
                uploads: uploads.clone(),
                downlink,
            }),
            usage: Arc::new(NoopUsage),
            metrics: Arc::new(NoopMetrics),
        });
        let session = services
            .open(OpenSessionRequest {
                authentication: AuthenticationRequest {
                    bearer_token: "0123456789abcdef".into(),
                    proof: DeviceProof {
                        device_id: "d-test".into(),
                        ..DeviceProof::default()
                    },
                    method: http::Method::CONNECT,
                    path: MASQUE_AUTH_PATH.into(),
                    peer: "127.0.0.1:1234".parse().unwrap(),
                },
                group_id: None,
                route: RouteKind::ConnectIp,
                transport: "masque-h2-capsule".into(),
            })
            .await
            .unwrap();
        let cancellation = session.cancellation.clone();

        let request = encode_address_request(&[Address {
            request_id: 1,
            prefix: "0.0.0.0/32".parse::<Ipv4Net>().unwrap().into(),
        }])
        .unwrap();
        let mut packet = vec![0; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 66, 0, 2]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        let mut encoder = Encoder::new(Vec::new());
        encoder.write(0xdead, &[0; 8192]).unwrap();
        encoder.write(CAPSULE_DATAGRAM, &[0, 0x45]).unwrap();
        encoder.write(CAPSULE_ADDRESS_REQUEST, &request).unwrap();
        encoder.write(CAPSULE_DATAGRAM, &[1, 0x45]).unwrap();
        let mut datagram = Vec::with_capacity(packet.len() + 1);
        datagram.push(0);
        datagram.extend_from_slice(&packet);
        encoder.write(CAPSULE_DATAGRAM, &datagram).unwrap();
        let (mut client, server) = tokio::io::duplex(8192);
        let tunnel = tokio::spawn(run_masque_tunnel(server, session, 1400));
        client.write_all(&encoder.into_inner()).await.unwrap();

        let mut received = BytesMut::new();
        while received
            .windows(packet.len())
            .all(|window| window != packet.as_slice())
        {
            let mut buffer = [0_u8; 2048];
            let size = tokio::time::timeout(Duration::from_secs(1), client.read(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert_ne!(size, 0);
            received.extend_from_slice(&buffer[..size]);
        }
        assert_eq!(
            take_capsule(&mut received).unwrap().unwrap().0,
            CAPSULE_ADDRESS_ASSIGN
        );
        assert_eq!(
            take_capsule(&mut received).unwrap().unwrap().0,
            CAPSULE_ROUTE_ADVERTISEMENT
        );
        let (capsule_type, value) = take_capsule(&mut received).unwrap().unwrap();
        assert_eq!(capsule_type, CAPSULE_DATAGRAM);
        assert_eq!(&decode_ip_bytes(value).unwrap()[..], &packet);
        assert_eq!(&uploads.lock().unwrap()[0][..], &packet);

        cancellation.cancel();
        tunnel.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn hyper_extended_connect_ip_is_full_duplex() {
        let uploads = Arc::new(Mutex::new(Vec::new()));
        let downlink = PacketQueue::new(QueueConfig::HTTP2, 0, Arc::new(NoopMetrics));
        let services = Arc::new(Services {
            authenticator: Arc::new(FakeAuthenticator),
            leases: Arc::new(FakeLeases),
            router: Arc::new(FakeRouter { uploads, downlink }),
            usage: Arc::new(NoopUsage),
            metrics: Arc::new(NoopMetrics),
        });
        let handler = Arc::new(
            Http2Handler::new(
                services,
                Http2Config {
                    mtu: 1400,
                    dns: None,
                    keepalive_interval: Duration::from_secs(30),
                    response_queue_chunks: 4,
                },
            )
            .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            let service = service_fn(move |request| handler.clone().call(request, peer));
            hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .enable_connect_protocol()
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        });

        let stream = TcpStream::connect(address).await.unwrap();
        let (mut sender, connection) =
            hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .handshake(TokioIo::new(stream))
                .await
                .unwrap();
        let client = tokio::spawn(async move {
            connection.await.unwrap();
        });
        tokio::time::sleep(Duration::from_millis(10)).await;

        let address_request = encode_address_request(&[Address {
            request_id: 1,
            prefix: "0.0.0.0/32".parse::<Ipv4Net>().unwrap().into(),
        }])
        .unwrap();
        let mut packet = vec![0; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 66, 0, 2]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        let mut encoder = Encoder::new(Vec::new());
        encoder
            .write(CAPSULE_ADDRESS_REQUEST, &address_request)
            .unwrap();
        let mut datagram = vec![0];
        datagram.extend_from_slice(&packet);
        encoder.write(CAPSULE_DATAGRAM, &datagram).unwrap();
        let capsules = encoder.into_inner();
        let mut request = Request::new(Full::new(Bytes::new()));
        *request.method_mut() = http::Method::CONNECT;
        *request.version_mut() = Version::HTTP_2;
        *request.uri_mut() = format!("http://localhost{MASQUE_PATH}").parse().unwrap();
        request
            .extensions_mut()
            .insert(hyper::ext::Protocol::from_static("connect-ip"));
        request
            .headers_mut()
            .insert(CAPSULE_PROTOCOL, http::HeaderValue::from_static("?1"));
        request.headers_mut().insert(
            HEADER_VERSION,
            http::HeaderValue::from_static(PROTOCOL_VERSION),
        );
        request.headers_mut().insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer 0123456789abcdef"),
        );
        request.headers_mut().insert(
            "X-Porta-Client-ID",
            http::HeaderValue::from_static("d-test"),
        );

        let mut response =
            tokio::time::timeout(Duration::from_secs(1), sender.send_request(request))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CAPSULE_PROTOCOL], "?1");
        let tunnel =
            tokio::time::timeout(Duration::from_secs(1), hyper::upgrade::on(&mut response))
                .await
                .unwrap()
                .unwrap();
        let mut tunnel = TokioIo::new(tunnel);
        tunnel.write_all(&capsules).await.unwrap();

        let mut received = BytesMut::new();
        while received
            .windows(packet.len())
            .all(|window| window != packet.as_slice())
        {
            let mut buffer = [0_u8; 2048];
            let size = tokio::time::timeout(Duration::from_secs(1), tunnel.read(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert_ne!(size, 0);
            received.extend_from_slice(&buffer[..size]);
        }
        assert_eq!(
            take_capsule(&mut received).unwrap().unwrap().0,
            CAPSULE_ADDRESS_ASSIGN
        );
        assert_eq!(
            take_capsule(&mut received).unwrap().unwrap().0,
            CAPSULE_ROUTE_ADVERTISEMENT
        );
        let (capsule_type, value) = take_capsule(&mut received).unwrap().unwrap();
        assert_eq!(capsule_type, CAPSULE_DATAGRAM);
        assert_eq!(&decode_ip_bytes(value).unwrap()[..], &packet);

        drop(tunnel);
        drop(response);
        drop(sender);
        tokio::time::timeout(Duration::from_secs(1), client)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap();
    }

    async fn assert_cancelling_blocked_connect_ip_releases_stream(include_echo: bool) {
        let authentication_cancellation = CancellationToken::new();
        let downlink = PacketQueue::new(QueueConfig::HTTP2, 0, Arc::new(NoopMetrics));
        let services = Arc::new(Services {
            authenticator: Arc::new(CancellableAuthenticator {
                cancellation: authentication_cancellation.clone(),
            }),
            leases: Arc::new(FakeLeases),
            router: Arc::new(FakeRouter {
                uploads: Arc::new(Mutex::new(Vec::new())),
                downlink,
            }),
            usage: Arc::new(NoopUsage),
            metrics: Arc::new(NoopMetrics),
        });
        let handler = Arc::new(
            Http2Handler::new(
                services,
                Http2Config {
                    mtu: 1400,
                    dns: None,
                    keepalive_interval: Duration::from_secs(30),
                    response_queue_chunks: 4,
                },
            )
            .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            let service = service_fn(move |request| handler.clone().call(request, peer));
            hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .enable_connect_protocol()
                .max_concurrent_streams(1)
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        });

        let stream = TcpStream::connect(address).await.unwrap();
        let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
        builder.initial_stream_window_size(1);
        let (mut sender, connection) = builder.handshake(TokioIo::new(stream)).await.unwrap();
        let client = tokio::spawn(async move {
            connection.await.unwrap();
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        let address_request = encode_address_request(&[Address {
            request_id: 1,
            prefix: "0.0.0.0/32".parse::<Ipv4Net>().unwrap().into(),
        }])
        .unwrap();
        let mut encoder = Encoder::new(Vec::new());
        encoder
            .write(CAPSULE_ADDRESS_REQUEST, &address_request)
            .unwrap();
        if include_echo {
            let mut packet = vec![0; 28];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
            packet[9] = 17;
            packet[12..16].copy_from_slice(&[10, 66, 0, 2]);
            packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
            let mut datagram = vec![0];
            datagram.extend_from_slice(&packet);
            encoder.write(CAPSULE_DATAGRAM, &datagram).unwrap();
        }

        let mut request = Request::new(Full::new(Bytes::new()));
        *request.method_mut() = http::Method::CONNECT;
        *request.version_mut() = Version::HTTP_2;
        *request.uri_mut() = format!("http://localhost{MASQUE_PATH}").parse().unwrap();
        request
            .extensions_mut()
            .insert(hyper::ext::Protocol::from_static("connect-ip"));
        request
            .headers_mut()
            .insert(CAPSULE_PROTOCOL, http::HeaderValue::from_static("?1"));
        request.headers_mut().insert(
            HEADER_VERSION,
            http::HeaderValue::from_static(PROTOCOL_VERSION),
        );
        request.headers_mut().insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer 0123456789abcdef"),
        );
        let mut response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let tunnel = hyper::upgrade::on(&mut response).await.unwrap();
        let mut tunnel = TokioIo::new(tunnel);
        tunnel.write_all(&encoder.into_inner()).await.unwrap();

        tokio::time::sleep(Duration::from_millis(20)).await;
        authentication_cancellation.cancel();
        let follow_up = Request::builder()
            .uri("http://localhost/not-found")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let follow_up =
            tokio::time::timeout(Duration::from_secs(1), sender.send_request(follow_up))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(follow_up.status(), StatusCode::NOT_FOUND);

        drop(follow_up);
        drop(tunnel);
        drop(response);
        drop(sender);
        tokio::time::timeout(Duration::from_secs(1), client)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn cancelling_flow_control_blocked_connect_ip_releases_the_stream() {
        assert_cancelling_blocked_connect_ip_releases_stream(false).await;
        assert_cancelling_blocked_connect_ip_releases_stream(true).await;
    }

    #[tokio::test]
    async fn graceful_upgraded_shutdown_drains_flow_controlled_data() {
        const PAYLOAD: &[u8] = b"accepted response data";

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let service = service_fn(|mut request| async move {
                let upgrade = hyper::upgrade::on(&mut request);
                tokio::spawn(async move {
                    let stream = upgrade.await.unwrap();
                    let mut stream = TokioIo::new(stream);
                    stream.write_all(PAYLOAD).await.unwrap();
                    stream.shutdown().await.unwrap();
                });
                Ok::<_, std::convert::Infallible>(Response::<ResponseBody>::new(
                    Full::new(Bytes::new())
                        .map_err(|never| match never {})
                        .boxed(),
                ))
            });
            hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .enable_connect_protocol()
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        });

        let stream = TcpStream::connect(address).await.unwrap();
        let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
        builder.initial_stream_window_size(1);
        let (mut sender, connection) = builder.handshake(TokioIo::new(stream)).await.unwrap();
        let client = tokio::spawn(async move {
            connection.await.unwrap();
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        let mut request = Request::new(Full::new(Bytes::new()));
        *request.method_mut() = http::Method::CONNECT;
        *request.version_mut() = Version::HTTP_2;
        *request.uri_mut() = "http://localhost/tunnel".parse().unwrap();
        request
            .extensions_mut()
            .insert(hyper::ext::Protocol::from_static("connect-ip"));
        let mut response = sender.send_request(request).await.unwrap();
        let stream = hyper::upgrade::on(&mut response).await.unwrap();
        let mut stream = TokioIo::new(stream);
        tokio::time::sleep(Duration::from_millis(20)).await;
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, PAYLOAD);

        drop(stream);
        drop(response);
        drop(sender);
        tokio::time::timeout(Duration::from_secs(1), client)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn dropping_a_pending_graceful_shutdown_aborts_the_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let service = service_fn(|mut request| async move {
                if request.method() != http::Method::CONNECT {
                    let mut response = Response::<ResponseBody>::new(
                        Full::new(Bytes::new())
                            .map_err(|never| -> BoxError { match never {} })
                            .boxed(),
                    );
                    *response.status_mut() = StatusCode::NO_CONTENT;
                    return Ok::<_, std::convert::Infallible>(response);
                }
                let upgrade = hyper::upgrade::on(&mut request);
                tokio::spawn(async move {
                    let stream = upgrade.await.unwrap();
                    let mut stream = TokioIo::new(stream);
                    stream.write_all(&[1; 4096]).await.unwrap();
                    stream.flush().await.unwrap();
                    stream.write_all(&[2; 4096]).await.unwrap();
                    let mut shutdown = Box::pin(stream.shutdown());
                    tokio::select! {
                        result = &mut shutdown => panic!("shutdown unexpectedly completed: {result:?}"),
                        _ = tokio::time::sleep(Duration::from_millis(20)) => {}
                    }
                    drop(shutdown);
                    drop(stream);
                });
                Ok::<_, std::convert::Infallible>(Response::<ResponseBody>::new(
                    Full::new(Bytes::new())
                        .map_err(|never| -> BoxError { match never {} })
                        .boxed(),
                ))
            });
            hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .enable_connect_protocol()
                .max_concurrent_streams(1)
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        });

        let stream = TcpStream::connect(address).await.unwrap();
        let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
        builder.initial_stream_window_size(1);
        let (mut sender, connection) = builder.handshake(TokioIo::new(stream)).await.unwrap();
        let client = tokio::spawn(async move {
            connection.await.unwrap();
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        let mut request = Request::new(Full::new(Bytes::new()));
        *request.method_mut() = http::Method::CONNECT;
        *request.version_mut() = Version::HTTP_2;
        *request.uri_mut() = "http://localhost/tunnel".parse().unwrap();
        request
            .extensions_mut()
            .insert(hyper::ext::Protocol::from_static("connect-ip"));
        let mut response = sender.send_request(request).await.unwrap();
        let tunnel = hyper::upgrade::on(&mut response).await.unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;

        let follow_up = Request::builder()
            .uri("http://localhost/after-cancel")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let follow_up =
            tokio::time::timeout(Duration::from_secs(1), sender.send_request(follow_up))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(follow_up.status(), StatusCode::NO_CONTENT);

        drop(follow_up);
        drop(tunnel);
        drop(response);
        drop(sender);
        tokio::time::timeout(Duration::from_secs(1), client)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap();
    }
}
