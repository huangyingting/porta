use std::collections::VecDeque;
use std::future::{poll_fn, Future};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(unix)]
use std::os::fd::AsRawFd as _;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket as _;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use h3::ext::Protocol;
use h3::ConnectionState;
use h3_datagram::datagram_handler::{HandleDatagramsExt, SendDatagramError};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use ipnet::{IpNet, Ipv4Net};
use porta_wire::frame;
use porta_wire::masque::{
    self, Address, MasqueError, MtuProbe, CAPSULE_ADDRESS_ASSIGN, CAPSULE_ADDRESS_REQUEST,
    CAPSULE_DATAGRAM, CAPSULE_MTU_SELECT, CAPSULE_MTU_SELECTED, CAPSULE_ROUTE_ADVERTISEMENT,
    MAX_CAPSULE_SIZE, MAX_DISCOVERED_MTU, MTU_DISCOVERY_HEADER, SAFE_MTU,
};
use porta_wire::mtu::{
    fragment_ipv4, icmp_fragmentation_needed, ip_datagram_capacity, DatagramMtu, FeedbackPolicy,
    IcmpContext, MtuError,
};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig as QuinnClientConfig, Endpoint};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{timeout, timeout_at, Instant};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use url::Url;

use super::{
    send_outbound, valid_unicast, CancellationGuard, ClientConfig, ClientError, Connection,
    ConnectionInner, DatagramSend, DeliveryMode, FailureSignal, Inbound, Lease, Outbound,
    Transport, MASQUE_AUTH_PATH, MASQUE_PATH,
};

const CAPSULE_PROTOCOL_HEADER: &str = "capsule-protocol";
const MTU_BUDGET: Duration = Duration::from_millis(750);
const MTU_ATTEMPT: Duration = Duration::from_millis(150);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const DATAGRAM_RACE_RETRIES: usize = 2;
const REQUEST_ID: u64 = 1;

pub(super) async fn connect(config: ClientConfig) -> Result<Connection, ClientError> {
    let deadline = Instant::now() + config.timeout;
    let parsed = parse_origin(&config.url)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| ClientError::permanent("gateway URL has no hostname"))?
        .trim_matches(['[', ']'])
        .to_owned();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| ClientError::permanent("gateway URL has no port"))?;
    let addresses = if let Some(address) = config.dial_address {
        vec![address]
    } else {
        tokio::select! {
            _ = config.cancellation.cancelled() => return Err(ClientError::Closed),
            result = timeout_at(deadline, tokio::net::lookup_host((host.as_str(), port))) => {
                result
                    .map_err(|_| ClientError::unavailable("HTTP/3 establishment timed out"))?
                    .map_err(ClientError::unavailable)?
                    .collect::<Vec<_>>()
            }
        }
    };
    if addresses.is_empty() {
        return Err(ClientError::unavailable(
            "gateway hostname resolved to no addresses",
        ));
    }

    let mut last_error = None;
    for remote_address in addresses {
        match connect_address(&config, &parsed, &host, remote_address, deadline).await {
            Ok(connection) => return Ok(connection),
            Err(error) if error.is_transport_unavailable() => last_error = Some(error),
            Err(error) => return Err(error),
        }
    }
    Err(last_error.unwrap_or_else(|| ClientError::unavailable("could not reach gateway")))
}

async fn connect_address(
    config: &ClientConfig,
    parsed: &Url,
    host: &str,
    remote_address: SocketAddr,
    deadline: Instant,
) -> Result<Connection, ClientError> {
    let cancellation = config.cancellation.child_token();
    let mut setup_guard = CancellationGuard::new(cancellation.clone());
    let bind_address = match remote_address {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = std::net::UdpSocket::bind(bind_address).map_err(ClientError::unavailable)?;
    socket
        .set_nonblocking(true)
        .map_err(ClientError::unavailable)?;
    if let Some(protector) = &config.socket_protector {
        protector.prepare(socket_descriptor(&socket))?;
    }
    let mut endpoint = Endpoint::new(
        Default::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(ClientError::unavailable)?;
    let mut tls = (*config.tls).clone();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = QuicClientConfig::try_from(tls)
        .map_err(|error| ClientError::permanent(format!("configure QUIC TLS: {error}")))?;
    let mut quinn_config = QuinnClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        Duration::from_secs(60)
            .try_into()
            .expect("60 seconds is a valid QUIC timeout"),
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(20)));
    transport.datagram_receive_buffer_size(Some(1 << 20));
    transport.datagram_send_buffer_size(1 << 20);
    quinn_config.transport_config(Arc::new(transport));
    endpoint.set_default_client_config(quinn_config);

    let connecting = endpoint
        .connect(remote_address, host)
        .map_err(ClientError::unavailable)?;
    let quic = tokio::select! {
        _ = cancellation.cancelled() => return Err(ClientError::Closed),
        result = timeout_at(deadline, connecting) => {
            result
                .map_err(|_| ClientError::unavailable("HTTP/3 establishment timed out"))?
                .map_err(classify_quic_connection)?
        }
    };
    let tasks = TaskTracker::new();
    let (inbound_tx, mut inbound_rx) = mpsc::channel(256);
    let (outbound_tx, outbound_rx) = mpsc::channel(256);
    let (writer_lease_tx, writer_lease_rx) = oneshot::channel();
    let failure = Arc::new(FailureSignal::default());

    let h3_connection = h3_quinn::Connection::new(quic.clone());
    let mut builder = h3::client::builder();
    builder
        .enable_extended_connect(true)
        .enable_datagram(true)
        .max_field_section_size(16 << 10);
    let (mut driver, mut requests) = tokio::select! {
        _ = cancellation.cancelled() => return Err(ClientError::Closed),
        result = timeout_at(deadline, builder.build::<_, _, Bytes>(h3_connection)) => {
            result
                .map_err(|_| ClientError::unavailable("HTTP/3 establishment timed out"))?
                .map_err(ClientError::unavailable)?
        }
    };

    let mut stream = tokio::select! {
        _ = cancellation.cancelled() => return Err(ClientError::Closed),
        error = poll_fn(|context| driver.poll_close(context)) => {
            return Err(ClientError::unavailable(format!(
                "HTTP/3 connection stopped before request: {error}"
            )));
        }
        result = timeout_at(deadline, async {
            wait_for_peer_settings(&requests, &cancellation, config.timeout).await?;
            if !requests.settings().enable_extended_connect() {
                return Err(ClientError::unavailable(
                    "gateway did not enable HTTP/3 Extended CONNECT",
                ));
            }
            let mut request = Request::builder()
                .method(Method::CONNECT)
                .uri(masque_url(parsed)?.as_str())
                .body(())
                .map_err(ClientError::permanent)?;
            request.extensions_mut().insert(Protocol::CONNECT_IP);
            apply_headers(&mut request, config)?;
            requests.send_request(request).await.map_err(ClientError::unavailable)
        }) => {
            result
                .map_err(|_| ClientError::unavailable("HTTP/3 establishment timed out"))??
        }
    };
    let stream_id = stream.id();
    let datagram_sender = driver.get_datagram_sender(stream_id);
    let datagram_reader = driver.get_datagram_reader();

    let driver_cancellation = cancellation.clone();
    let driver_inbound = inbound_tx.clone();
    let driver_failure = failure.clone();
    tasks.spawn(async move {
        let error = poll_fn(|context| driver.poll_close(context)).await;
        if !driver_cancellation.is_cancelled() {
            report_failure(
                &driver_inbound,
                &driver_failure,
                &driver_cancellation,
                ClientError::retryable(format!("HTTP/3 connection stopped: {error}")),
            );
        }
    });

    let mut transport_ready = false;
    let established = tokio::select! {
        _ = cancellation.cancelled() => {
            Err(failure.current().unwrap_or(ClientError::Closed))
        }
        result = timeout_at(deadline, async {
            let datagrams = requests.settings().enable_datagram();

            let response = timeout(config.timeout, stream.recv_response())
                .await
                .map_err(|_| ClientError::unavailable("HTTP/3 response timed out"))?
                .map_err(ClientError::unavailable)?;
            validate_response(&response)?;
            transport_ready = true;
            let request_cancellation = cancellation.clone();
            tasks.spawn(async move {
                request_cancellation.cancelled().await;
                drop(requests);
            });
            let (send_stream, receive_stream) = stream.split();

            let writer_cancellation = cancellation.clone();
            let writer_inbound = inbound_tx.clone();
            let writer_failure = failure.clone();
            tasks.spawn(run_writer(
                outbound_rx,
                H3Writer {
                    stream: send_stream,
                    datagrams: datagram_sender,
                    quic: quic.clone(),
                    stream_id: stream_id.into_inner(),
                },
                writer_lease_rx,
                datagrams,
                WriterSignals {
                    cancellation: writer_cancellation,
                    inbound: writer_inbound,
                    failures: writer_failure,
                    write_timeout: config.timeout.min(WRITE_TIMEOUT),
                },
            ));
            let reader_cancellation = cancellation.clone();
            let reader_inbound = inbound_tx.clone();
            let reader_failure = failure.clone();
            tasks.spawn(run_reader(
                receive_stream,
                datagram_reader,
                stream_id,
                reader_cancellation,
                reader_inbound,
                reader_failure,
            ));

            let mut lease = response_lease(response.headers())?;
            let (automatic, ceiling) = configure_mtu(
                config,
                response.headers(),
                datagrams,
                &outbound_tx,
                &mut inbound_rx,
                &failure,
                &mut lease,
            )
            .await?;
            let address_request = masque::encode_address_request(&[Address {
                request_id: REQUEST_ID,
                prefix: IpNet::V4(
                    Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 32)
                        .expect("the IPv4 unspecified /32 is valid"),
                ),
            }])
            .map_err(ClientError::permanent)?;
            send_capsule(
                &outbound_tx,
                &failure,
                CAPSULE_ADDRESS_REQUEST,
                Bytes::from(address_request),
            )
            .await?;
            lease.address = wait_for_address(config.timeout, &mut inbound_rx, &failure).await?;
            if lease.gateway == Some(lease.address.addr()) {
                return Err(ClientError::permanent("gateway returned the leased address as gateway"));
            }
            writer_lease_tx.send(lease).map_err(|_| {
                failure.current().unwrap_or(ClientError::Closed)
            })?;
            Ok((lease, automatic, ceiling, datagrams))
        }) => {
            result.unwrap_or_else(|_| {
                Err(if transport_ready {
                    ClientError::retryable("HTTP/3 tunnel configuration timed out")
                } else {
                    ClientError::unavailable("HTTP/3 establishment timed out")
                })
            })
        }
    };
    let (lease, automatic, ceiling, datagrams) = match established {
        Ok(established) => established,
        Err(error) => {
            cancellation.cancel();
            quic.close(0_u32.into(), b"client setup failed");
            tasks.close();
            let _ = timeout(Duration::from_secs(1), tasks.wait()).await;
            endpoint.close(0_u32.into(), b"client setup failed");
            let _ = timeout(Duration::from_secs(1), endpoint.wait_idle()).await;
            return Err(error);
        }
    };

    let close_cancellation = cancellation.clone();
    tasks.spawn(async move {
        close_cancellation.cancelled().await;
        quic.close(0_u32.into(), b"client closed");
        endpoint.wait_idle().await;
    });

    setup_guard.disarm();
    Ok(Connection {
        lease,
        remote_address,
        transport: Transport::Http3,
        delivery_mode: if datagrams {
            DeliveryMode::Datagram
        } else {
            DeliveryMode::Capsule
        },
        mtu_automatic: automatic,
        mtu_ceiling: ceiling,
        inner: Arc::new(ConnectionInner {
            outbound: outbound_tx,
            inbound: tokio::sync::Mutex::new(inbound_rx),
            failure,
            cancellation,
            tasks,
            closed: std::sync::atomic::AtomicBool::new(false),
        }),
    })
}

#[cfg(unix)]
fn socket_descriptor(socket: &std::net::UdpSocket) -> i64 {
    i64::from(socket.as_raw_fd())
}

#[cfg(windows)]
fn socket_descriptor(socket: &std::net::UdpSocket) -> i64 {
    socket.as_raw_socket() as i64
}

async fn wait_for_peer_settings(
    state: &(impl ConnectionState + ?Sized),
    cancellation: &CancellationToken,
    duration: Duration,
) -> Result<(), ClientError> {
    timeout(duration, async {
        while !state.settings_received() {
            tokio::select! {
                _ = cancellation.cancelled() => {
                    return Err(ClientError::Closed);
                }
                _ = tokio::time::sleep(Duration::from_millis(1)) => {}
            }
        }
        Ok(())
    })
    .await
    .map_err(|_| ClientError::unavailable("wait for HTTP/3 peer SETTINGS timed out"))?
}

fn parse_origin(value: &str) -> Result<Url, ClientError> {
    let url = Url::parse(value).map_err(|error| ClientError::permanent(error.to_string()))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ClientError::permanent(
            "gateway URL must be an HTTPS origin",
        ));
    }
    Ok(url)
}

fn masque_url(origin: &Url) -> Result<Url, ClientError> {
    origin
        .join(MASQUE_PATH)
        .map_err(|error| ClientError::permanent(error.to_string()))
}

fn apply_headers(request: &mut Request<()>, config: &ClientConfig) -> Result<(), ClientError> {
    let proof = config
        .proof
        .proof(Method::CONNECT.as_str(), MASQUE_AUTH_PATH)?;
    let headers = request.headers_mut();
    headers.insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", config.token))
            .map_err(|_| ClientError::permanent("token is not a valid HTTP header value"))?,
    );
    headers.insert(
        HeaderName::from_static(CAPSULE_PROTOCOL_HEADER),
        HeaderValue::from_static("?1"),
    );
    headers.insert(
        HeaderName::from_static("x-porta-mtu-discovery"),
        HeaderValue::from_static("1"),
    );
    headers.insert(
        HeaderName::from_static("x-porta-version"),
        HeaderValue::from_static(frame::VERSION),
    );
    for (name, value) in [
        ("x-porta-client-id", proof.device_id),
        ("x-porta-device-name", proof.name),
        ("x-porta-device-key", proof.public_key),
        ("x-porta-device-time", proof.timestamp),
        ("x-porta-device-nonce", proof.nonce),
        ("x-porta-device-signature", proof.signature),
    ] {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_str(&value)
                .map_err(|_| ClientError::permanent("device proof contains an invalid header"))?,
        );
    }
    Ok(())
}

fn validate_response(response: &http::Response<()>) -> Result<(), ClientError> {
    if !response.status().is_success() {
        let status = response.status();
        let versions = (
            header(response.headers(), frame::HEADER_MIN_VERSION),
            header(response.headers(), frame::HEADER_MAX_VERSION),
        );
        let detail = format!("gateway returned HTTP {status}");
        return match status {
            StatusCode::NOT_FOUND
            | StatusCode::METHOD_NOT_ALLOWED
            | StatusCode::MISDIRECTED_REQUEST
            | StatusCode::NOT_IMPLEMENTED
            | StatusCode::HTTP_VERSION_NOT_SUPPORTED => Err(ClientError::unavailable(detail)),
            StatusCode::UPGRADE_REQUIRED if versions == (None, None) => {
                Err(ClientError::unavailable(detail))
            }
            StatusCode::REQUEST_TIMEOUT
            | StatusCode::TOO_EARLY
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT => Err(ClientError::retryable(detail)),
            _ => Err(ClientError::permanent(detail)),
        };
    }
    if header(response.headers(), CAPSULE_PROTOCOL_HEADER) != Some("?1") {
        return Err(ClientError::permanent(
            "gateway response did not enable the Capsule Protocol",
        ));
    }
    if header(response.headers(), frame::HEADER_VERSION) != Some(frame::VERSION) {
        return Err(ClientError::permanent(format!(
            "gateway selected Porta protocol {:?}, client requires {:?}",
            header(response.headers(), frame::HEADER_VERSION),
            frame::VERSION
        )));
    }
    response_lease(response.headers()).map(|_| ())
}

fn response_lease(headers: &HeaderMap) -> Result<Lease, ClientError> {
    let gateway = match headers.get("x-porta-gateway") {
        Some(value) => Some(
            value
                .to_str()
                .ok()
                .and_then(|value| value.parse::<Ipv4Addr>().ok())
                .filter(|address| {
                    valid_unicast(*address) && address.octets()[0] != 0 && address.octets()[0] < 224
                })
                .ok_or_else(|| {
                    ClientError::permanent("gateway returned an invalid IPv4 tunnel gateway")
                })?,
        ),
        None => None,
    };
    let mtu = match header(headers, "x-porta-mtu") {
        Some(value) => value
            .parse::<u16>()
            .ok()
            .filter(|value| (576..=9000).contains(value))
            .ok_or_else(|| ClientError::permanent("gateway returned an invalid tunnel MTU"))?,
        None => 1280,
    };
    let dns = match header(headers, "x-porta-dns") {
        Some(value) => {
            let address = value.parse::<Ipv4Addr>().map_err(|_| {
                ClientError::permanent("gateway returned an invalid IPv4 DNS address")
            })?;
            if !valid_unicast(address) {
                return Err(ClientError::permanent(
                    "gateway returned an invalid IPv4 DNS address",
                ));
            }
            Some(address)
        }
        None => None,
    };
    Ok(Lease {
        address: Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 32)
            .expect("the IPv4 unspecified /32 is valid"),
        gateway,
        dns,
        mtu,
    })
}

async fn configure_mtu(
    config: &ClientConfig,
    headers: &HeaderMap,
    datagrams: bool,
    outbound: &mpsc::Sender<Outbound>,
    inbound: &mut mpsc::Receiver<Inbound>,
    failure: &FailureSignal,
    lease: &mut Lease,
) -> Result<(bool, Option<u16>), ClientError> {
    let Some(offer) = header(headers, MTU_DISCOVERY_HEADER) else {
        return Ok((false, None));
    };
    let token = masque::parse_mtu_token(offer)
        .map_err(|_| ClientError::permanent("invalid MTU discovery message"))?;
    if !datagrams || lease.mtu <= SAFE_MTU || lease.mtu > 9000 {
        return Err(ClientError::permanent(
            "invalid MTU discovery message: unsupported gateway MTU offer",
        ));
    }
    let maximum = lease.mtu.min(MAX_DISCOVERED_MTU);
    let selected = discover_mtu(token, maximum, outbound, inbound, failure).await?;
    send_capsule(
        outbound,
        failure,
        CAPSULE_MTU_SELECT,
        Bytes::copy_from_slice(&masque::encode_mtu_selection(token, selected)),
    )
    .await?;
    let selected_by_gateway = timeout(config.timeout, async {
        loop {
            match failure.next(inbound).await? {
                Inbound::MtuSelected(value) => {
                    return decode_selected_mtu(&value, token, maximum);
                }
                Inbound::Failure(error) => return Err(error),
                _ => {}
            }
        }
    })
    .await
    .map_err(|_| ClientError::retryable("wait for MTU selection timed out"))??;
    if selected_by_gateway != selected {
        return Err(ClientError::permanent(format!(
            "gateway selected MTU {selected_by_gateway} instead of {selected}"
        )));
    }
    lease.mtu = selected;
    Ok((true, Some(maximum)))
}

async fn discover_mtu(
    token: masque::MtuToken,
    maximum: u16,
    outbound: &mpsc::Sender<Outbound>,
    inbound: &mut mpsc::Receiver<Inbound>,
    failure: &FailureSignal,
) -> Result<u16, ClientError> {
    let deadline = Instant::now() + MTU_BUDGET;
    let mut sizes = vec![SAFE_MTU];
    for size in [1152, 1200, 1280, 1360, 1400] {
        if size < maximum {
            sizes.push(size);
        }
    }
    if sizes.last().copied() != Some(maximum) {
        sizes.push(maximum);
    }
    let mut best = SAFE_MTU;
    let mut sequence = 0_u16;
    for size in sizes {
        let mut confirmed = false;
        for _ in 0..2 {
            if Instant::now() >= deadline {
                return Ok(best);
            }
            sequence = sequence.saturating_add(1);
            let probe = MtuProbe {
                token,
                sequence,
                size,
            };
            let payload = masque::encode_mtu_probe(probe)
                .map_err(|_| ClientError::permanent("invalid MTU discovery message"))?;
            if send_datagram(outbound, failure, Bytes::from(payload)).await?
                == DatagramSend::TooLarge
            {
                return Ok(best);
            }
            let attempt = (Instant::now() + MTU_ATTEMPT).min(deadline);
            let echoed = timeout_at(attempt, async {
                loop {
                    match failure.next(inbound).await? {
                        Inbound::MtuProbe(value) if value == probe => return Ok(true),
                        Inbound::Failure(error) => return Err(error),
                        _ => {}
                    }
                }
            })
            .await;
            if let Ok(result) = echoed {
                if result? {
                    confirmed = true;
                    break;
                }
            }
        }
        if !confirmed {
            return Ok(best);
        }
        best = size;
    }
    Ok(best)
}

fn decode_selected_mtu(
    value: &[u8],
    token: masque::MtuToken,
    maximum: u16,
) -> Result<u16, ClientError> {
    let selected = masque::decode_mtu_selection(value, token)
        .map_err(|_| ClientError::permanent("invalid MTU discovery message"))?;
    if !(SAFE_MTU..=maximum).contains(&selected) {
        return Err(ClientError::permanent("invalid MTU discovery message"));
    }
    Ok(selected)
}

async fn wait_for_address(
    duration: Duration,
    inbound: &mut mpsc::Receiver<Inbound>,
    failure: &FailureSignal,
) -> Result<Ipv4Net, ClientError> {
    timeout(duration, async {
        loop {
            match failure.next(inbound).await? {
                Inbound::Address(address) => return Ok(address),
                Inbound::Failure(error) => return Err(error),
                _ => {}
            }
        }
    })
    .await
    .map_err(|_| ClientError::retryable("wait for ADDRESS_ASSIGN timed out"))?
}

async fn send_datagram(
    outbound: &mpsc::Sender<Outbound>,
    failure: &FailureSignal,
    payload: Bytes,
) -> Result<DatagramSend, ClientError> {
    send_outbound(outbound, failure, |result| Outbound::Datagram {
        payload,
        result,
    })
    .await
}

async fn send_capsule(
    outbound: &mpsc::Sender<Outbound>,
    failure: &FailureSignal,
    capsule_type: u64,
    value: Bytes,
) -> Result<(), ClientError> {
    send_outbound(outbound, failure, |result| Outbound::Capsule {
        capsule_type,
        value,
        result,
    })
    .await
}

struct WriterSignals {
    cancellation: CancellationToken,
    inbound: mpsc::Sender<Inbound>,
    failures: Arc<FailureSignal>,
    write_timeout: Duration,
}

enum DatagramError {
    TooLarge,
    NotAvailable,
    Connection(ClientError),
}

trait WriterTransport: Send {
    fn ip_capacity(&self) -> Option<usize>;
    fn rtt(&self) -> Duration;
    fn send_datagram(&mut self, payload: Bytes) -> Result<(), DatagramError>;
    fn send_capsule(
        &mut self,
        capsule_type: u64,
        value: Bytes,
    ) -> impl Future<Output = Result<(), ClientError>> + Send;
    fn stop(&mut self);
}

struct H3Writer<S, B: Buf, H: h3_datagram::quic_traits::SendDatagram<B>> {
    stream: h3::client::RequestStream<S, B>,
    datagrams: h3_datagram::datagram_handler::DatagramSender<H, B>,
    quic: quinn::Connection,
    stream_id: u64,
}

impl<S, B, H> WriterTransport for H3Writer<S, B, H>
where
    S: h3::quic::SendStream<B> + Send + 'static,
    B: Buf + From<Bytes> + Send + 'static,
    H: h3_datagram::quic_traits::SendDatagram<B> + Send + 'static,
{
    fn ip_capacity(&self) -> Option<usize> {
        ip_datagram_capacity(self.quic.max_datagram_size(), self.stream_id)
    }

    fn rtt(&self) -> Duration {
        self.quic.rtt()
    }

    fn send_datagram(&mut self, payload: Bytes) -> Result<(), DatagramError> {
        self.datagrams
            .send_datagram(payload.into())
            .map_err(|error| match datagram_error_kind(&error) {
                DatagramErrorKind::TooLarge => DatagramError::TooLarge,
                DatagramErrorKind::NotAvailable => DatagramError::NotAvailable,
                DatagramErrorKind::Connection => {
                    DatagramError::Connection(ClientError::retryable(error))
                }
            })
    }

    async fn send_capsule(&mut self, capsule_type: u64, value: Bytes) -> Result<(), ClientError> {
        send_capsule_data(&mut self.stream, capsule_type, &value).await
    }

    fn stop(&mut self) {
        self.stream.stop_stream(h3::error::Code::H3_NO_ERROR);
    }
}

#[derive(Default)]
struct MtuDiagnostics {
    reductions: u64,
    feedback: u64,
    suppressed: u64,
    rate_limited: u64,
    compatibility: u64,
    reasons: u8,
}

impl MtuDiagnostics {
    fn compatibility(&mut self, reason: u8, message: &'static str) {
        self.compatibility = self.compatibility.saturating_add(1);
        if self.reasons & reason == 0 {
            self.reasons |= reason;
            eprintln!("porta-client: INFO HTTP/3 bounded capsule compatibility: {message}");
        }
    }

    fn suppressed(&mut self, rate_limited: bool) {
        let (count, reason) = if rate_limited {
            (&mut self.rate_limited, "rate limited")
        } else {
            (&mut self.suppressed, "suppressed by IPv4 ICMP rules")
        };
        if *count == 0 {
            eprintln!("porta-client: INFO HTTP/3 PMTU feedback {reason}");
        }
        *count = count.saturating_add(1);
    }
}

impl Drop for MtuDiagnostics {
    fn drop(&mut self) {
        if self.reductions != 0
            || self.feedback != 0
            || self.suppressed != 0
            || self.rate_limited != 0
            || self.compatibility != 0
        {
            eprintln!(
                "porta-client: INFO HTTP/3 PMTU summary reductions={} feedback={} suppressed={} rate_limited={} compatibility={}",
                self.reductions, self.feedback, self.suppressed, self.rate_limited, self.compatibility,
            );
        }
    }
}

struct PacketWriter {
    lease: Lease,
    mtu: DatagramMtu,
    feedback: FeedbackPolicy,
    identification: u16,
    use_datagrams: bool,
    diagnostics: MtuDiagnostics,
}

impl PacketWriter {
    fn new(lease: Lease, use_datagrams: bool) -> Self {
        Self {
            lease,
            mtu: DatagramMtu::new(lease.mtu),
            feedback: FeedbackPolicy::default(),
            identification: 0,
            use_datagrams,
            diagnostics: MtuDiagnostics::default(),
        }
    }

    fn refresh(&mut self, transport: &impl WriterTransport) -> Result<(), ClientError> {
        if !self.use_datagrams {
            return Ok(());
        }
        let Some(capacity) = transport.ip_capacity() else {
            self.use_datagrams = false;
            self.diagnostics
                .compatibility(1, "QUIC datagrams unavailable");
            return Ok(());
        };
        let previous = self.mtu.limit();
        if self.mtu.update(capacity).map_err(|error| {
            ClientError::retryable(format!(
                "invalid live HTTP/3 IP capacity {capacity}: {error}"
            ))
        })? {
            self.diagnostics.reductions += 1;
            if self.diagnostics.reductions <= 8 {
                eprintln!(
                    "porta-client: INFO HTTP/3 outbound IP MTU reduced {previous}->{} (interface ceiling {})",
                    self.mtu.limit(), self.lease.mtu,
                );
            }
        }
        Ok(())
    }

    async fn oversized_df(
        &mut self,
        transport: &mut impl WriterTransport,
        packet: Bytes,
        signals: &WriterSignals,
    ) -> Result<(), ClientError> {
        let Some(gateway) = self.lease.gateway else {
            self.diagnostics
                .compatibility(2, "peer omitted authenticated gateway for PMTU feedback");
            return send_ip_capsule(transport, &packet).await;
        };
        let feedback = match icmp_fragmentation_needed(
            &packet,
            IcmpContext {
                gateway,
                address: self.lease.address.addr(),
                prefix_len: self.lease.address.prefix_len(),
            },
            self.mtu.limit(),
            self.identification,
        ) {
            Ok(feedback) => feedback,
            Err(MtuError::IcmpSuppressed) => {
                self.diagnostics.suppressed(false);
                return Ok(());
            }
            Err(error) => {
                return Err(ClientError::retryable(format!(
                    "create PMTU feedback: {error}"
                )))
            }
        };
        if feedback.len() > usize::from(self.lease.mtu)
            || porta_wire::ip::parse_ipv4(&feedback)
                .map_err(ClientError::retryable)?
                .destination
                != self.lease.address.addr()
        {
            return Err(ClientError::retryable(
                "PMTU feedback violates tunnel receive limits",
            ));
        }
        let decision = self.feedback.on_oversized(
            &packet,
            self.mtu.limit(),
            usize::from(self.lease.mtu),
            std::time::Instant::now(),
            transport.rtt(),
        );
        if decision.send_icmp {
            deliver_inbound(
                &signals.inbound,
                &signals.cancellation,
                Inbound::Packet(Bytes::from(feedback)),
            )
            .await?;
            self.identification = self.identification.wrapping_add(1);
            self.diagnostics.feedback = self.diagnostics.feedback.saturating_add(1);
        } else if !decision.use_capsule {
            self.diagnostics.suppressed(true);
        }
        if decision.use_capsule {
            self.diagnostics
                .compatibility(4, "DF flow did not adapt to PMTU feedback");
            send_ip_capsule(transport, &packet).await?;
        }
        Ok(())
    }

    async fn send(
        &mut self,
        transport: &mut impl WriterTransport,
        packet: Bytes,
        signals: &WriterSignals,
    ) -> Result<(), ClientError> {
        let mut initial = Some(packet);
        let mut pending = VecDeque::new();
        let mut races = 0;
        while let Some(packet) = initial.take().or_else(|| pending.pop_front()) {
            self.refresh(transport)?;
            if !self.use_datagrams {
                send_ip_capsule(transport, &packet).await?;
                continue;
            }
            if packet.len() > self.mtu.limit() {
                match fragment_ipv4(&packet, self.mtu.limit()) {
                    Ok(fragments) => {
                        for fragment in fragments.into_iter().rev() {
                            pending.push_front(Bytes::from(fragment));
                        }
                    }
                    Err(MtuError::FragmentationNeeded) => {
                        self.oversized_df(transport, packet, signals).await?;
                    }
                    Err(error) => {
                        return Err(ClientError::retryable(format!(
                            "fragment outgoing IPv4: {error}"
                        )))
                    }
                }
                continue;
            }
            match transport.send_datagram(Bytes::from(masque::encode_ip_packet(&packet))) {
                Ok(()) => {}
                Err(DatagramError::TooLarge) => {
                    // Only this unsent fragment is retried; successfully sent prefixes are never replayed.
                    self.refresh(transport)?;
                    if races < DATAGRAM_RACE_RETRIES {
                        races += 1;
                        pending.push_front(packet);
                    } else if packet.len() > self.mtu.limit()
                        && u16::from_be_bytes([packet[6], packet[7]]) & 0x4000 != 0
                        && self.use_datagrams
                    {
                        self.oversized_df(transport, packet, signals).await?;
                    } else {
                        self.diagnostics
                            .compatibility(8, "QUIC capacity raced repeated datagram sends");
                        send_ip_capsule(transport, &packet).await?;
                    }
                }
                Err(DatagramError::NotAvailable) => {
                    self.use_datagrams = false;
                    self.diagnostics
                        .compatibility(1, "QUIC datagrams unavailable");
                    send_ip_capsule(transport, &packet).await?;
                }
                Err(DatagramError::Connection(error)) => return Err(error),
            }
        }
        Ok(())
    }
}

async fn send_ip_capsule(
    transport: &mut impl WriterTransport,
    packet: &[u8],
) -> Result<(), ClientError> {
    transport
        .send_capsule(
            CAPSULE_DATAGRAM,
            Bytes::from(masque::encode_ip_packet(packet)),
        )
        .await
}

async fn bounded_write<T>(
    signals: &WriterSignals,
    write: impl Future<Output = Result<T, ClientError>>,
) -> Result<T, ClientError> {
    tokio::select! {
        biased;
        _ = signals.cancellation.cancelled() => Err(ClientError::Closed),
        result = timeout(signals.write_timeout, write) => {
            result.map_err(|_| ClientError::retryable("HTTP/3 tunnel write timed out"))?
        }
    }
}

async fn run_writer(
    mut outbound: mpsc::Receiver<Outbound>,
    mut transport: impl WriterTransport,
    mut lease: oneshot::Receiver<Lease>,
    use_datagrams: bool,
    signals: WriterSignals,
) {
    let mut packets = None;
    loop {
        let outbound = tokio::select! {
            biased;
            _ = signals.cancellation.cancelled() => break,
            value = outbound.recv() => match value {
                Some(value) => value,
                None => break,
            },
        };
        let failure = match outbound {
            Outbound::Packet { packet, result } => {
                let sent = bounded_write(&signals, async {
                    if packets.is_none() {
                        // Startup probes and control writes must finish before sampling the live IP limit.
                        let lease = (&mut lease).await.map_err(|_| ClientError::Closed)?;
                        packets = Some(PacketWriter::new(lease, use_datagrams));
                    }
                    packets
                        .as_mut()
                        .expect("writer lease initialized")
                        .send(&mut transport, packet, &signals)
                        .await
                })
                .await;
                let failed = sent.as_ref().err().cloned();
                let _ = result.send(sent);
                failed
            }
            Outbound::Datagram { payload, result } => {
                let sent = match transport.send_datagram(payload) {
                    Ok(()) => Ok(DatagramSend::Sent),
                    Err(DatagramError::TooLarge) => Ok(DatagramSend::TooLarge),
                    Err(DatagramError::NotAvailable) => {
                        Err(ClientError::retryable("Datagrams are not available"))
                    }
                    Err(DatagramError::Connection(error)) => Err(error),
                };
                let failed = sent.as_ref().err().cloned();
                let _ = result.send(sent);
                failed
            }
            Outbound::Capsule {
                capsule_type,
                value,
                result,
            } => {
                let sent =
                    bounded_write(&signals, transport.send_capsule(capsule_type, value)).await;
                let failed = sent.as_ref().err().cloned();
                let _ = result.send(sent);
                failed
            }
        };
        if let Some(error) = failure {
            report_failure(
                &signals.inbound,
                &signals.failures,
                &signals.cancellation,
                error,
            );
            break;
        }
    }
    transport.stop();
}

async fn send_capsule_data<S, B>(
    stream: &mut h3::client::RequestStream<S, B>,
    capsule_type: u64,
    value: &[u8],
) -> Result<(), ClientError>
where
    S: h3::quic::SendStream<B>,
    B: Buf + From<Bytes>,
{
    let mut encoded = Vec::with_capacity(value.len() + 16);
    masque::Encoder::new(&mut encoded)
        .write(capsule_type, value)
        .map_err(ClientError::retryable)?;
    stream
        .send_data(Bytes::from(encoded).into())
        .await
        .map_err(ClientError::retryable)
}

async fn run_reader<S, B, H>(
    mut stream: h3::client::RequestStream<S, B>,
    mut datagrams: h3_datagram::datagram_handler::DatagramReader<H>,
    stream_id: h3::quic::StreamId,
    cancellation: CancellationToken,
    inbound: mpsc::Sender<Inbound>,
    failure: Arc<FailureSignal>,
) where
    S: h3::quic::RecvStream + Send + 'static,
    B: Buf + Send + 'static,
    H: h3_datagram::quic_traits::RecvDatagram + Send + 'static,
    H::Buffer: Send + 'static,
{
    let mut capsules = BytesMut::new();
    'reader: loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            data = stream.recv_data() => {
                match data {
                    Ok(Some(mut data)) => {
                        capsules.extend_from_slice(&data.copy_to_bytes(data.remaining()));
                        loop {
                            match take_capsule(&mut capsules) {
                                Ok(Some((capsule_type, value))) => {
                                    if let Err(error) = handle_capsule(
                                        capsule_type,
                                        value,
                                        &inbound,
                                        &cancellation,
                                    ).await {
                                        report_failure(&inbound, &failure, &cancellation, error);
                                        break 'reader;
                                    }
                                }
                                Ok(None) => break,
                                Err(error) => {
                                    report_failure(&inbound, &failure, &cancellation, error);
                                    break 'reader;
                                }
                            }
                        }
                    }
                    Ok(None) => {
                        let error = if !capsules.is_empty() {
                            ClientError::permanent(
                                "truncated MASQUE capsule stream",
                            )
                        } else {
                            ClientError::retryable(
                                "HTTP/3 response stream ended",
                            )
                        };
                        report_failure(&inbound, &failure, &cancellation, error);
                        break;
                    }
                    Err(error) => {
                        report_failure(
                            &inbound,
                            &failure,
                            &cancellation,
                            ClientError::retryable(error),
                        );
                        break;
                    }
                }
            }
            datagram = datagrams.read_datagram() => {
                match datagram {
                    Ok(datagram) if datagram.stream_id() == stream_id => {
                        let mut payload = datagram.into_payload();
                        let payload = payload.copy_to_bytes(payload.remaining());
                        if masque::is_mtu_probe(&payload) {
                            if let Ok(probe) = masque::decode_mtu_probe(&payload) {
                                if deliver_inbound(
                                    &inbound,
                                    &cancellation,
                                    Inbound::MtuProbe(probe),
                                ).await.is_err() {
                                    break 'reader;
                                }
                            }
                            continue;
                        }
                        match masque::decode_ip_packet(&payload) {
                            Ok(packet) => {
                                if deliver_inbound(
                                    &inbound,
                                    &cancellation,
                                    Inbound::Packet(Bytes::copy_from_slice(packet)),
                                ).await.is_err() {
                                    break 'reader;
                                }
                            }
                            Err(MasqueError::UnknownContext(_)) => {}
                            Err(error) => {
                                report_failure(
                                    &inbound,
                                    &failure,
                                    &cancellation,
                                    ClientError::permanent(error),
                                );
                                break 'reader;
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(error) => {
                        report_failure(
                            &inbound,
                            &failure,
                            &cancellation,
                            ClientError::retryable(error),
                        );
                        break;
                    }
                }
            }
        }
    }
    stream.stop_sending(h3::error::Code::H3_NO_ERROR);
}

fn take_capsule(buffer: &mut BytesMut) -> Result<Option<(u64, Bytes)>, ClientError> {
    let (capsule_type, type_length) = match masque::parse_varint(buffer) {
        Ok(value) => value,
        Err(MasqueError::TruncatedVarInt) => return Ok(None),
        Err(error) => return Err(ClientError::permanent(error)),
    };
    let (length, length_length) = match masque::parse_varint(&buffer[type_length..]) {
        Ok(value) => value,
        Err(MasqueError::TruncatedVarInt) => return Ok(None),
        Err(error) => return Err(ClientError::permanent(error)),
    };
    let length = usize::try_from(length)
        .map_err(|_| ClientError::permanent("MASQUE capsule length is too large"))?;
    if length > MAX_CAPSULE_SIZE {
        return Err(ClientError::permanent(
            "MASQUE capsule exceeds maximum size",
        ));
    }
    let header_length = type_length + length_length;
    let total = header_length
        .checked_add(length)
        .ok_or_else(|| ClientError::permanent("MASQUE capsule length overflow"))?;
    if buffer.len() < total {
        return Ok(None);
    }
    buffer.advance(header_length);
    Ok(Some((capsule_type, buffer.split_to(length).freeze())))
}

async fn handle_capsule(
    capsule_type: u64,
    value: Bytes,
    inbound: &mpsc::Sender<Inbound>,
    cancellation: &CancellationToken,
) -> Result<(), ClientError> {
    match capsule_type {
        CAPSULE_MTU_SELECTED => {
            deliver_inbound(inbound, cancellation, Inbound::MtuSelected(value)).await?;
        }
        CAPSULE_ADDRESS_ASSIGN => {
            for address in masque::decode_address_assign(&value).map_err(ClientError::permanent)? {
                if address.request_id != REQUEST_ID {
                    continue;
                }
                let IpNet::V4(prefix) = address.prefix else {
                    return Err(ClientError::permanent(
                        "gateway returned an invalid IPv4 /32 lease",
                    ));
                };
                if prefix.prefix_len() != 32 || !valid_unicast(prefix.addr()) {
                    return Err(ClientError::permanent(format!(
                        "gateway returned an invalid IPv4 /32 lease: {prefix}"
                    )));
                }
                deliver_inbound(inbound, cancellation, Inbound::Address(prefix)).await?;
            }
        }
        CAPSULE_ROUTE_ADVERTISEMENT => {
            masque::decode_route_advertisement(&value).map_err(ClientError::permanent)?;
        }
        CAPSULE_DATAGRAM => match masque::decode_ip_packet(&value) {
            Ok(packet) => {
                deliver_inbound(
                    inbound,
                    cancellation,
                    Inbound::Packet(Bytes::copy_from_slice(packet)),
                )
                .await?;
            }
            Err(MasqueError::UnknownContext(_)) => {}
            Err(error) => return Err(ClientError::permanent(error)),
        },
        _ => {}
    }
    Ok(())
}

async fn deliver_inbound(
    inbound: &mpsc::Sender<Inbound>,
    cancellation: &CancellationToken,
    value: Inbound,
) -> Result<(), ClientError> {
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(ClientError::Closed),
        result = inbound.send(value) => result.map_err(|_| ClientError::Closed),
    }
}

fn report_failure(
    inbound: &mpsc::Sender<Inbound>,
    failure: &FailureSignal,
    cancellation: &CancellationToken,
    error: ClientError,
) {
    if failure.set(error.clone()) {
        let _ = inbound.try_send(Inbound::Failure(error));
    }
    cancellation.cancel();
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn classify_quic_connection(error: quinn::ConnectionError) -> ClientError {
    match &error {
        quinn::ConnectionError::TransportError(transport)
            if (0x100..=0x1ff).contains(&u64::from(transport.code)) =>
        {
            ClientError::permanent(format!("QUIC TLS handshake failed: {error}"))
        }
        quinn::ConnectionError::ApplicationClosed(_) => ClientError::permanent(error),
        _ => ClientError::unavailable(error),
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DatagramErrorKind {
    TooLarge,
    NotAvailable,
    Connection,
}

fn datagram_error_kind(error: &SendDatagramError) -> DatagramErrorKind {
    match error.to_string().as_str() {
        "Datagram is too large" => DatagramErrorKind::TooLarge,
        "Datagrams are not available" => DatagramErrorKind::NotAvailable,
        _ => DatagramErrorKind::Connection,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MockWriterState {
        capacity: Option<usize>,
        capacity_reads: usize,
        attempts: usize,
        reductions: VecDeque<(usize, usize)>,
        rejections: usize,
        unavailable: bool,
        packets: Vec<Bytes>,
        capsules: Vec<(u64, Bytes)>,
        blocked: bool,
        write_error: bool,
        stopped: bool,
    }

    struct MockWriter(Arc<Mutex<MockWriterState>>);

    impl WriterTransport for MockWriter {
        fn ip_capacity(&self) -> Option<usize> {
            let mut state = self.0.lock().unwrap();
            state.capacity_reads += 1;
            state.capacity
        }

        fn rtt(&self) -> Duration {
            Duration::from_millis(10)
        }

        fn send_datagram(&mut self, payload: Bytes) -> Result<(), DatagramError> {
            let mut state = self.0.lock().unwrap();
            state.attempts += 1;
            if state.reductions.front().map(|value| value.0) == Some(state.attempts) {
                state.capacity = Some(state.reductions.pop_front().unwrap().1);
            }
            if state.unavailable {
                return Err(DatagramError::NotAvailable);
            }
            if state.rejections > 0 {
                state.rejections -= 1;
                return Err(DatagramError::TooLarge);
            }
            if state
                .capacity
                .is_some_and(|limit| payload.len() > limit + 1)
            {
                return Err(DatagramError::TooLarge);
            }
            state.packets.push(payload);
            Ok(())
        }

        async fn send_capsule(
            &mut self,
            capsule_type: u64,
            value: Bytes,
        ) -> Result<(), ClientError> {
            let (blocked, error) = {
                let mut state = self.0.lock().unwrap();
                state.capsules.push((capsule_type, value));
                (state.blocked, state.write_error)
            };
            if error {
                return Err(ClientError::retryable("test stream write failed"));
            }
            if blocked {
                std::future::pending::<()>().await;
            }
            Ok(())
        }

        fn stop(&mut self) {
            self.0.lock().unwrap().stopped = true;
        }
    }

    fn writer_harness(
        datagrams: bool,
        gateway: bool,
        capacity: Option<usize>,
        write_timeout: Duration,
    ) -> (
        Connection,
        Arc<Mutex<MockWriterState>>,
        mpsc::Sender<Inbound>,
        oneshot::Sender<Lease>,
    ) {
        let cancellation = CancellationToken::new();
        let failures = Arc::new(FailureSignal::default());
        let tasks = TaskTracker::new();
        let (outbound, requests) = mpsc::channel(2);
        let (inbound, received) = mpsc::channel(8);
        let (lease_tx, lease_rx) = oneshot::channel();
        let state = Arc::new(Mutex::new(MockWriterState {
            capacity,
            capacity_reads: 0,
            attempts: 0,
            reductions: VecDeque::new(),
            rejections: 0,
            unavailable: false,
            packets: Vec::new(),
            capsules: Vec::new(),
            blocked: false,
            write_error: false,
            stopped: false,
        }));
        tasks.spawn(run_writer(
            requests,
            MockWriter(state.clone()),
            lease_rx,
            datagrams,
            WriterSignals {
                cancellation: cancellation.clone(),
                inbound: inbound.clone(),
                failures: failures.clone(),
                write_timeout,
            },
        ));
        (
            Connection {
                lease: Lease {
                    address: "10.66.0.2/32".parse().unwrap(),
                    gateway: gateway.then_some(Ipv4Addr::new(10, 66, 0, 1)),
                    dns: None,
                    mtu: 1400,
                },
                remote_address: "192.0.2.1:443".parse().unwrap(),
                transport: Transport::Http3,
                delivery_mode: if datagrams {
                    DeliveryMode::Datagram
                } else {
                    DeliveryMode::Capsule
                },
                mtu_automatic: true,
                mtu_ceiling: Some(1400),
                inner: Arc::new(ConnectionInner {
                    outbound,
                    inbound: tokio::sync::Mutex::new(received),
                    failure: failures,
                    cancellation,
                    tasks,
                    closed: std::sync::atomic::AtomicBool::new(false),
                }),
            },
            state,
            inbound,
            lease_tx,
        )
    }

    fn ipv4_packet(length: usize, df: bool) -> Vec<u8> {
        let mut packet = vec![0x5a; length];
        packet[..20].fill(0);
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&42_u16.to_be_bytes());
        packet[6] = if df { 0x40 } else { 0 };
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 66, 0, 2]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 1]);
        packet[20..24].copy_from_slice(&[0x12, 0x34, 0x01, 0xbb]);
        packet[24..26].copy_from_slice(&((length - 20) as u16).to_be_bytes());
        packet[26..28].fill(0);
        let checksum = internet_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn internet_checksum(data: &[u8]) -> u16 {
        let mut sum = 0_u32;
        for chunk in data.chunks(2) {
            sum += u32::from(u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn tcp_packet(length: usize) -> Vec<u8> {
        let mut packet = ipv4_packet(length, true);
        packet[9] = 6;
        packet[24..40].fill(0);
        packet[32] = 0x50;
        packet[33] = 0x10;
        packet[10..12].fill(0);
        let checksum = internet_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn assert_feedback(feedback: &[u8], original: &[u8], mtu: u16) {
        let info = porta_wire::ip::parse_ipv4(feedback).unwrap();
        assert_eq!(info.source, Ipv4Addr::new(10, 66, 0, 1));
        assert_eq!(info.destination, Ipv4Addr::new(10, 66, 0, 2));
        assert_eq!(feedback[9], 1);
        assert_eq!(&feedback[20..22], &[3, 4]);
        assert_eq!(&feedback[26..28], &mtu.to_be_bytes());
        assert_eq!(internet_checksum(&feedback[..20]), 0);
        assert_eq!(internet_checksum(&feedback[20..]), 0);
        assert_eq!(&feedback[28..], &original[..feedback.len() - 28]);
        assert!(feedback.len() <= 1400);
    }

    #[tokio::test]
    async fn writer_applies_live_mtu_without_changing_interface_or_receive_ceiling() {
        let (connection, state, inbound, ready) =
            writer_harness(true, true, Some(1400), WRITE_TIMEOUT);
        ready.send(connection.lease).unwrap();
        let original = ipv4_packet(1400, false);
        connection.send(&original).await.unwrap();
        state.lock().unwrap().capacity = Some(1160);
        connection.send(&ipv4_packet(40, true)).await.unwrap();
        connection.send(&original).await.unwrap();
        let df = ipv4_packet(1400, true);
        connection.send(&df).await.unwrap();
        assert_feedback(&connection.receive().await.unwrap(), &df, 1160);
        state.lock().unwrap().capacity = Some(1400);
        connection.send(&original).await.unwrap();
        {
            let state = state.lock().unwrap();
            assert!(state.capsules.is_empty());
            let packets: Vec<_> = state
                .packets
                .iter()
                .map(|value| masque::decode_ip_packet(value).unwrap())
                .collect();
            assert_eq!(packets[0], original);
            assert_eq!(packets[1].len(), 40);
            for fragments in [&packets[2..4], &packets[4..6]] {
                assert_eq!(
                    fragments
                        .iter()
                        .map(|packet| packet.len())
                        .collect::<Vec<_>>(),
                    vec![1156, 264]
                );
                assert_eq!(internet_checksum(&fragments[0][..20]), 0);
                assert_eq!(internet_checksum(&fragments[1][..20]), 0);
                assert_eq!(
                    u16::from_be_bytes([fragments[0][6], fragments[0][7]]),
                    0x2000
                );
                assert_eq!(u16::from_be_bytes([fragments[1][6], fragments[1][7]]), 142);
                assert_eq!(
                    [&fragments[0][20..], &fragments[1][20..]].concat(),
                    original[20..]
                );
            }
        }
        assert_eq!(connection.lease.mtu, 1400);
        let mut reply = original.clone();
        reply[12..16].copy_from_slice(&[198, 51, 100, 1]);
        reply[16..20].copy_from_slice(&[10, 66, 0, 2]);
        handle_capsule(
            CAPSULE_DATAGRAM,
            Bytes::from(masque::encode_ip_packet(&reply)),
            &inbound,
            &connection.inner.cancellation,
        )
        .await
        .unwrap();
        assert_eq!(connection.receive().await.unwrap(), reply);
        assert!(connection.send(&ipv4_packet(1401, false)).await.is_err());
        let mut spoofed = ipv4_packet(100, false);
        spoofed[12] = 11;
        assert!(connection.send(&spoofed).await.is_err());
        connection.close().await;
    }

    #[tokio::test]
    async fn writer_races_refragment_only_the_unsent_fragment() {
        let (connection, state, _, ready) = writer_harness(true, true, Some(1160), WRITE_TIMEOUT);
        ready.send(connection.lease).unwrap();
        state.lock().unwrap().reductions.push_back((2, 200));
        let original = ipv4_packet(1400, false);
        connection.send(&original).await.unwrap();
        {
            let state = state.lock().unwrap();
            assert!(state.capsules.is_empty());
            let packets: Vec<_> = state
                .packets
                .iter()
                .map(|value| masque::decode_ip_packet(value).unwrap())
                .collect();
            assert_eq!(
                packets.iter().map(|value| value.len()).collect::<Vec<_>>(),
                vec![1156, 196, 88]
            );
            assert_eq!(
                packets
                    .iter()
                    .flat_map(|packet| packet[20..].iter().copied())
                    .collect::<Vec<_>>(),
                original[20..]
            );
            for (packet, offset) in packets.iter().zip([0, 142, 164]) {
                assert_eq!(u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff, offset);
                assert_eq!(internet_checksum(&packet[..20]), 0);
            }
        }
        connection.close().await;
    }

    #[tokio::test]
    async fn writer_race_on_df_sends_feedback_and_persistent_races_are_bounded() {
        let (connection, state, _, ready) = writer_harness(true, true, Some(1400), WRITE_TIMEOUT);
        ready.send(connection.lease).unwrap();
        state.lock().unwrap().reductions.push_back((1, 1160));
        let packet = ipv4_packet(1400, true);
        connection.send(&packet).await.unwrap();
        assert_feedback(&connection.receive().await.unwrap(), &packet, 1160);
        assert_eq!(state.lock().unwrap().attempts, 1);
        assert!(state.lock().unwrap().capsules.is_empty());

        state.lock().unwrap().rejections = usize::MAX;
        connection.send(&ipv4_packet(100, false)).await.unwrap();
        assert_eq!(
            state.lock().unwrap().attempts,
            1 + DATAGRAM_RACE_RETRIES + 1
        );
        assert_eq!(state.lock().unwrap().capsules.len(), 1);
        connection.close().await;
    }

    #[tokio::test]
    async fn writer_waits_for_probe_completion_before_sampling_capacity() {
        let (connection, state, _, ready) = writer_harness(true, true, Some(1160), WRITE_TIMEOUT);
        send_datagram(
            &connection.inner.outbound,
            &connection.inner.failure,
            Bytes::from(
                masque::encode_mtu_probe(MtuProbe {
                    token: [1; 16],
                    sequence: 1,
                    size: SAFE_MTU,
                })
                .unwrap(),
            ),
        )
        .await
        .unwrap();
        send_capsule(
            &connection.inner.outbound,
            &connection.inner.failure,
            CAPSULE_ADDRESS_REQUEST,
            Bytes::new(),
        )
        .await
        .unwrap();
        assert_eq!(state.lock().unwrap().capacity_reads, 0);
        state.lock().unwrap().capacity = Some(1400);
        ready.send(connection.lease).unwrap();
        connection.send(&ipv4_packet(1400, true)).await.unwrap();
        assert_eq!(state.lock().unwrap().packets.len(), 2);
        assert_eq!(state.lock().unwrap().capsules.len(), 1);
        connection.close().await;
    }

    #[tokio::test]
    async fn final_lease_ceiling_survives_duplicate_mtu_control_after_live_reduction() {
        let (mut connection, state, inbound, ready) =
            writer_harness(true, true, Some(1400), WRITE_TIMEOUT);
        let token = [3; 16];
        let selection = Bytes::copy_from_slice(&masque::encode_mtu_selection(token, 1100));
        send_capsule(
            &connection.inner.outbound,
            &connection.inner.failure,
            CAPSULE_MTU_SELECT,
            selection.clone(),
        )
        .await
        .unwrap();
        assert_eq!(state.lock().unwrap().capacity_reads, 0);
        connection.lease.mtu = 1100;
        ready.send(connection.lease).unwrap();
        let packet = ipv4_packet(1100, true);
        connection.send(&packet).await.unwrap();
        assert_eq!(state.lock().unwrap().packets.len(), 1);
        assert!(connection.send(&ipv4_packet(1101, true)).await.is_err());

        state.lock().unwrap().capacity = Some(1000);
        connection.send(&packet).await.unwrap();
        assert_feedback(&connection.receive().await.unwrap(), &packet, 1000);
        state.lock().unwrap().capacity = Some(1400);
        send_capsule(
            &connection.inner.outbound,
            &connection.inner.failure,
            CAPSULE_MTU_SELECT,
            selection.clone(),
        )
        .await
        .unwrap();
        handle_capsule(
            CAPSULE_MTU_SELECTED,
            selection,
            &inbound,
            &connection.inner.cancellation,
        )
        .await
        .unwrap();
        connection.send(&ipv4_packet(1100, false)).await.unwrap();
        {
            let state = state.lock().unwrap();
            let lengths: Vec<_> = state
                .packets
                .iter()
                .map(|packet| masque::decode_ip_packet(packet).unwrap().len())
                .collect();
            assert_eq!(lengths, vec![1100, 996, 124]);
            assert_eq!(state.capsules.len(), 2);
            assert!(state
                .capsules
                .iter()
                .all(|(kind, _)| *kind == CAPSULE_MTU_SELECT));
        }
        assert_eq!(connection.lease.mtu, 1100);
        assert_eq!(connection.mtu_ceiling, Some(1400));
        connection.close().await;
    }

    #[tokio::test]
    async fn initial_selection_is_not_counted_as_a_live_mtu_reduction() {
        let (mut connection, state, _, _ready) =
            writer_harness(true, true, Some(1400), WRITE_TIMEOUT);
        connection.lease.mtu = 1100;
        let transport = MockWriter(state.clone());
        let mut packets = PacketWriter::new(connection.lease, true);
        packets.refresh(&transport).unwrap();
        assert_eq!(packets.mtu.limit(), 1100);
        assert_eq!(packets.diagnostics.reductions, 0);
        state.lock().unwrap().capacity = Some(1000);
        packets.refresh(&transport).unwrap();
        assert_eq!(packets.mtu.limit(), 1000);
        assert_eq!(packets.diagnostics.reductions, 1);
        state.lock().unwrap().capacity = Some(1400);
        packets.refresh(&transport).unwrap();
        assert_eq!(packets.mtu.limit(), 1000);
        assert_eq!(packets.diagnostics.reductions, 1);
        connection.close().await;
    }

    #[tokio::test]
    async fn writer_supports_capsule_only_unavailable_and_missing_gateway_peers() {
        for (datagrams, gateway, capacity, unavailable) in [
            (false, true, Some(1160), false),
            (true, true, None, false),
            (true, true, Some(1160), true),
            (true, false, Some(1160), false),
        ] {
            let (connection, state, _, ready) =
                writer_harness(datagrams, gateway, capacity, WRITE_TIMEOUT);
            ready.send(connection.lease).unwrap();
            state.lock().unwrap().unavailable = unavailable;
            connection.send(&ipv4_packet(100, true)).await.unwrap();
            let packet = ipv4_packet(1400, true);
            connection.send(&packet).await.unwrap();
            {
                let state = state.lock().unwrap();
                assert_eq!(state.capsules.len(), if !gateway { 1 } else { 2 });
                assert_eq!(
                    masque::decode_ip_packet(&state.capsules.last().unwrap().1).unwrap(),
                    packet
                );
                if !datagrams {
                    assert_eq!(state.capacity_reads, 0);
                    assert_eq!(state.attempts, 0);
                }
            }
            connection.close().await;
        }
    }

    #[tokio::test]
    async fn writer_rejects_invalid_live_capacity_instead_of_disabling_datagrams() {
        for capacity in [0, 67] {
            let (connection, state, _, ready) =
                writer_harness(true, true, Some(capacity), WRITE_TIMEOUT);
            ready.send(connection.lease).unwrap();
            assert!(matches!(
                connection.send(&ipv4_packet(100, false)).await,
                Err(ClientError::Retryable(message))
                    if message == format!("invalid live HTTP/3 IP capacity {capacity}: invalid MTU")
            ));
            assert!(state.lock().unwrap().packets.is_empty());
            assert!(state.lock().unwrap().capsules.is_empty());
            assert!(matches!(
                connection.receive().await,
                Err(ClientError::Retryable(_))
            ));
            connection.close().await;
        }
    }

    #[tokio::test]
    async fn writer_ignored_feedback_has_grace_and_resets_after_further_reduction() {
        let (connection, state, _, ready) = writer_harness(true, true, Some(1160), WRITE_TIMEOUT);
        ready.send(connection.lease).unwrap();
        let packet = tcp_packet(1400);
        for _ in 0..3 {
            connection.send(&packet).await.unwrap();
            assert_feedback(&connection.receive().await.unwrap(), &packet, 1160);
            connection.send(&tcp_packet(40)).await.unwrap();
            tokio::time::sleep(Duration::from_millis(110)).await;
        }
        assert!(state.lock().unwrap().capsules.is_empty());
        tokio::time::sleep(Duration::from_secs(2)).await;
        connection.send(&packet).await.unwrap();
        assert_eq!(state.lock().unwrap().capsules.len(), 1);
        // Drain any simultaneous feedback before asserting the new, lower feedback MTU.
        while timeout(Duration::from_millis(10), connection.receive())
            .await
            .is_ok()
        {}
        state.lock().unwrap().capacity = Some(1100);
        connection.send(&packet).await.unwrap();
        assert_feedback(&connection.receive().await.unwrap(), &packet, 1100);
        assert_eq!(state.lock().unwrap().capsules.len(), 1);
        connection.close().await;
    }

    #[tokio::test]
    async fn writer_feedback_suppression_is_counted_without_invalid_icmp_or_capsules() {
        let (connection, state, _, ready) = writer_harness(true, true, Some(1160), WRITE_TIMEOUT);
        ready.send(connection.lease).unwrap();
        let packet = ipv4_packet(1400, true);
        connection.send(&packet).await.unwrap();
        connection.receive().await.unwrap();
        connection.send(&packet).await.unwrap();
        let mut suppressed = packet.clone();
        suppressed[16..20].copy_from_slice(&[224, 0, 0, 1]);
        suppressed[10..12].fill(0);
        let checksum = internet_checksum(&suppressed[..20]);
        suppressed[10..12].copy_from_slice(&checksum.to_be_bytes());
        connection.send(&suppressed).await.unwrap();
        assert!(timeout(Duration::from_millis(20), connection.receive())
            .await
            .is_err());
        assert!(state.lock().unwrap().capsules.is_empty());
        connection.close().await;
    }

    #[tokio::test]
    async fn writer_blocked_capsules_allow_receive_and_finish_on_deadline_or_cancellation() {
        for cancel in [false, true] {
            let (connection, state, inbound, ready) =
                writer_harness(false, true, Some(1160), Duration::from_millis(150));
            ready.send(connection.lease).unwrap();
            state.lock().unwrap().blocked = true;
            let connection = Arc::new(connection);
            let sending_connection = connection.clone();
            let sending =
                tokio::spawn(
                    async move { sending_connection.send(&ipv4_packet(1400, true)).await },
                );
            timeout(Duration::from_secs(1), async {
                while state.lock().unwrap().capsules.is_empty() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let mut reply = ipv4_packet(100, true);
            reply[16..20].copy_from_slice(&[10, 66, 0, 2]);
            handle_capsule(
                CAPSULE_DATAGRAM,
                Bytes::from(masque::encode_ip_packet(&reply)),
                &inbound,
                &connection.inner.cancellation,
            )
            .await
            .unwrap();
            assert_eq!(
                timeout(Duration::from_millis(50), connection.receive())
                    .await
                    .unwrap()
                    .unwrap(),
                reply
            );
            if cancel {
                timeout(Duration::from_millis(50), connection.close())
                    .await
                    .unwrap();
                assert!(matches!(sending.await.unwrap(), Err(ClientError::Closed)));
            } else {
                assert!(matches!(
                    timeout(Duration::from_secs(1), sending).await.unwrap().unwrap(),
                    Err(ClientError::Retryable(message)) if message == "HTTP/3 tunnel write timed out"
                ));
                assert!(matches!(
                    connection.receive().await,
                    Err(ClientError::Retryable(_))
                ));
                connection.close().await;
            }
            assert!(state.lock().unwrap().stopped);
        }
    }

    #[tokio::test]
    async fn writer_reliable_failure_is_not_acknowledged_as_success() {
        let (connection, state, _, ready) = writer_harness(false, false, None, WRITE_TIMEOUT);
        ready.send(connection.lease).unwrap();
        state.lock().unwrap().write_error = true;
        assert!(
            matches!(connection.send(&ipv4_packet(100, false)).await, Err(ClientError::Retryable(message)) if message == "test stream write failed")
        );
        assert!(
            matches!(connection.receive().await, Err(ClientError::Retryable(message)) if message == "test stream write failed")
        );
        connection.close().await;
    }

    #[tokio::test]
    async fn writer_deadline_releases_saturated_outbound_backpressure() {
        let (connection, state, _, ready) =
            writer_harness(false, false, None, Duration::from_millis(150));
        ready.send(connection.lease).unwrap();
        state.lock().unwrap().blocked = true;
        let connection = Arc::new(connection);
        let mut sends = Vec::new();
        for _ in 0..8 {
            let connection = connection.clone();
            sends.push(tokio::spawn(async move {
                connection.send(&ipv4_packet(1400, true)).await
            }));
        }
        timeout(Duration::from_millis(100), async {
            while connection.inner.outbound.capacity() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(connection.inner.outbound.max_capacity(), 2);
        timeout(Duration::from_secs(1), async {
            for send in sends {
                assert!(matches!(
                    send.await.unwrap(),
                    Err(ClientError::Retryable(message)) if message == "HTTP/3 tunnel write timed out"
                ));
            }
        })
        .await
        .unwrap();
        assert_eq!(state.lock().unwrap().capsules.len(), 1);
        connection.close().await;
    }

    fn response(status: StatusCode, headers: &[(&str, &str)]) -> http::Response<()> {
        let mut response = http::Response::builder().status(status).body(()).unwrap();
        for (name, value) in headers {
            response.headers_mut().insert(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        response
    }

    fn current_response(status: StatusCode) -> http::Response<()> {
        response(
            status,
            &[
                (CAPSULE_PROTOCOL_HEADER, "?1"),
                (frame::HEADER_VERSION, frame::VERSION),
                ("x-porta-mtu", "1400"),
                ("x-porta-dns", "10.0.0.53"),
            ],
        )
    }

    #[test]
    fn validates_origins_without_accepting_embedded_request_components() {
        for valid in ["https://vpn.example", "https://vpn.example:8443/"] {
            assert!(parse_origin(valid).is_ok(), "{valid}");
        }
        assert_eq!(
            masque_url(&parse_origin("https://vpn.example").unwrap())
                .unwrap()
                .path(),
            MASQUE_PATH
        );
        for invalid in [
            "http://vpn.example",
            "https://user@vpn.example",
            "https://vpn.example/path",
            "https://vpn.example/?query",
            "https://vpn.example/#fragment",
        ] {
            assert!(parse_origin(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn capsule_parser_handles_fragmented_and_batched_input() {
        let mut first = Vec::new();
        masque::Encoder::new(&mut first)
            .write(CAPSULE_DATAGRAM, &[0, 1, 2, 3])
            .unwrap();
        let mut second = Vec::new();
        masque::Encoder::new(&mut second)
            .write(CAPSULE_ROUTE_ADVERTISEMENT, &[4, 5])
            .unwrap();
        let mut buffer = BytesMut::from(&first[..2]);
        assert!(take_capsule(&mut buffer).unwrap().is_none());
        buffer.extend_from_slice(&first[2..]);
        buffer.extend_from_slice(&second);
        assert_eq!(
            take_capsule(&mut buffer).unwrap().unwrap(),
            (CAPSULE_DATAGRAM, Bytes::from_static(&[0, 1, 2, 3]))
        );
        assert_eq!(
            take_capsule(&mut buffer).unwrap().unwrap(),
            (CAPSULE_ROUTE_ADVERTISEMENT, Bytes::from_static(&[4, 5]))
        );
        assert!(buffer.is_empty());
    }

    #[test]
    fn capsule_parser_rejects_oversized_values_before_buffering_them() {
        let mut encoded = masque::encode_varint(CAPSULE_DATAGRAM).unwrap();
        encoded.extend(masque::encode_varint((MAX_CAPSULE_SIZE + 1) as u64).unwrap());
        let error = take_capsule(&mut BytesMut::from(encoded.as_slice())).unwrap_err();
        assert!(matches!(error, ClientError::Permanent(_)));
    }

    #[test]
    fn response_statuses_only_allow_safe_automatic_fallbacks() {
        for status in [
            StatusCode::NOT_FOUND,
            StatusCode::METHOD_NOT_ALLOWED,
            StatusCode::MISDIRECTED_REQUEST,
            StatusCode::NOT_IMPLEMENTED,
            StatusCode::HTTP_VERSION_NOT_SUPPORTED,
        ] {
            assert!(validate_response(&response(status, &[]))
                .unwrap_err()
                .is_transport_unavailable());
        }
        assert!(
            validate_response(&response(StatusCode::UPGRADE_REQUIRED, &[]))
                .unwrap_err()
                .is_transport_unavailable()
        );

        let version_mismatch = response(
            StatusCode::UPGRADE_REQUIRED,
            &[(frame::HEADER_MIN_VERSION, frame::VERSION)],
        );
        assert!(matches!(
            validate_response(&version_mismatch),
            Err(ClientError::Permanent(_))
        ));

        for status in [
            StatusCode::REQUEST_TIMEOUT,
            StatusCode::TOO_EARLY,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            assert!(validate_response(&response(status, &[]))
                .unwrap_err()
                .is_retryable());
        }
        assert!(matches!(
            validate_response(&response(StatusCode::UNAUTHORIZED, &[])),
            Err(ClientError::Permanent(_))
        ));
    }

    #[test]
    fn response_requires_protocol_headers_and_valid_lease_metadata() {
        assert!(validate_response(&current_response(StatusCode::OK)).is_ok());

        let mut missing_capsule = current_response(StatusCode::OK);
        missing_capsule
            .headers_mut()
            .remove(CAPSULE_PROTOCOL_HEADER);
        assert!(validate_response(&missing_capsule).is_err());

        let mut wrong_version = current_response(StatusCode::OK);
        wrong_version.headers_mut().insert(
            HeaderName::from_bytes(frame::HEADER_VERSION.as_bytes()).unwrap(),
            HeaderValue::from_static("999"),
        );
        assert!(validate_response(&wrong_version).is_err());

        for (name, value) in [
            ("x-porta-mtu", "575"),
            ("x-porta-mtu", "9001"),
            ("x-porta-mtu", "not-a-number"),
            ("x-porta-dns", "0.0.0.0"),
            ("x-porta-dns", "224.0.0.1"),
            ("x-porta-dns", "not-an-address"),
            ("x-porta-gateway", "not-an-address"),
            ("x-porta-gateway", "0.0.0.1"),
            ("x-porta-gateway", "127.0.0.1"),
            ("x-porta-gateway", "169.254.1.1"),
            ("x-porta-gateway", "224.0.0.1"),
            ("x-porta-gateway", "240.0.0.1"),
        ] {
            let mut invalid = current_response(StatusCode::OK);
            invalid.headers_mut().insert(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
            assert!(validate_response(&invalid).is_err(), "{name}={value}");
        }
        let mut with_gateway = current_response(StatusCode::OK);
        with_gateway.headers_mut().insert(
            HeaderName::from_static("x-porta-gateway"),
            HeaderValue::from_static("10.66.0.1"),
        );
        assert_eq!(
            response_lease(with_gateway.headers()).unwrap().gateway,
            Some(Ipv4Addr::new(10, 66, 0, 1))
        );
        assert_eq!(
            response_lease(current_response(StatusCode::OK).headers())
                .unwrap()
                .gateway,
            None
        );
    }

    #[test]
    fn mtu_selection_binds_token_and_offered_range() {
        let token = [7; 16];
        let selected = masque::encode_mtu_selection(token, 1360);
        assert_eq!(decode_selected_mtu(&selected, token, 1400).unwrap(), 1360);

        let mut wrong = token;
        wrong[0] ^= 1;
        assert!(decode_selected_mtu(&selected, wrong, 1400).is_err());
        assert!(decode_selected_mtu(
            &masque::encode_mtu_selection(token, SAFE_MTU - 1),
            token,
            1400
        )
        .is_err());
        assert!(
            decode_selected_mtu(&masque::encode_mtu_selection(token, 1401), token, 1400).is_err()
        );
    }

    #[tokio::test]
    async fn address_assignment_requires_requested_ipv4_unicast_host_route() {
        let (inbound, mut received) = mpsc::channel(1);
        let cancellation = CancellationToken::new();
        let valid = masque::encode_address_assign(&[Address {
            request_id: REQUEST_ID,
            prefix: IpNet::V4(Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 2), 32).unwrap()),
        }])
        .unwrap();
        handle_capsule(
            CAPSULE_ADDRESS_ASSIGN,
            Bytes::from(valid),
            &inbound,
            &cancellation,
        )
        .await
        .unwrap();
        assert!(matches!(
            received.recv().await,
            Some(Inbound::Address(address)) if address == "10.0.0.2/32".parse().unwrap()
        ));

        let invalid = masque::encode_address_assign(&[Address {
            request_id: REQUEST_ID,
            prefix: IpNet::V4(Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 24).unwrap()),
        }])
        .unwrap();
        assert!(matches!(
            handle_capsule(
                CAPSULE_ADDRESS_ASSIGN,
                Bytes::from(invalid),
                &inbound,
                &cancellation,
            )
            .await,
            Err(ClientError::Permanent(_))
        ));
    }

    #[tokio::test]
    async fn mtu_discovery_stops_at_the_local_quic_datagram_limit() {
        let token = [9; 16];
        let (outbound, mut requests) = mpsc::channel(8);
        let (inbound, mut responses) = mpsc::channel(8);
        let failure = FailureSignal::default();
        let writer = tokio::spawn(async move {
            let mut rejected = 0;
            while let Some(request) = requests.recv().await {
                let Outbound::Datagram { payload, result } = request else {
                    panic!("MTU discovery emitted a non-datagram request");
                };
                let probe = masque::decode_mtu_probe(&payload).unwrap();
                if probe.size > 1280 {
                    rejected += 1;
                    let _ = result.send(Ok(DatagramSend::TooLarge));
                } else {
                    let _ = result.send(Ok(DatagramSend::Sent));
                    inbound.send(Inbound::MtuProbe(probe)).await.unwrap();
                }
            }
            rejected
        });

        assert_eq!(
            discover_mtu(token, 1400, &outbound, &mut responses, &failure)
                .await
                .unwrap(),
            1280
        );
        let probe = MtuProbe {
            token,
            sequence: 99,
            size: SAFE_MTU,
        };
        assert_eq!(
            send_datagram(
                &outbound,
                &failure,
                Bytes::from(masque::encode_mtu_probe(probe).unwrap()),
            )
            .await
            .unwrap(),
            DatagramSend::Sent
        );
        drop(outbound);
        assert_eq!(writer.await.unwrap(), 1);
    }

    #[tokio::test]
    async fn close_completes_with_a_saturated_inbound_queue() {
        let cancellation = CancellationToken::new();
        let tasks = TaskTracker::new();
        let failure = Arc::new(FailureSignal::default());
        let (inbound, receiver) = mpsc::channel(1);
        inbound
            .send(Inbound::MtuSelected(Bytes::new()))
            .await
            .unwrap();
        let blocked_inbound = inbound.clone();
        let blocked_cancellation = cancellation.clone();
        tasks.spawn(async move {
            let _ = deliver_inbound(
                &blocked_inbound,
                &blocked_cancellation,
                Inbound::MtuSelected(Bytes::new()),
            )
            .await;
        });
        tokio::task::yield_now().await;

        let (outbound, _requests) = mpsc::channel(1);
        let connection = Connection {
            lease: Lease {
                address: "10.0.0.2/32".parse().unwrap(),
                gateway: None,
                dns: None,
                mtu: SAFE_MTU,
            },
            remote_address: "192.0.2.1:443".parse().unwrap(),
            transport: Transport::Http3,
            delivery_mode: DeliveryMode::Datagram,
            mtu_automatic: true,
            mtu_ceiling: Some(1400),
            inner: Arc::new(ConnectionInner {
                outbound,
                inbound: tokio::sync::Mutex::new(receiver),
                failure,
                cancellation,
                tasks,
                closed: std::sync::atomic::AtomicBool::new(false),
            }),
        };

        timeout(Duration::from_secs(1), connection.close())
            .await
            .expect("HTTP/3 shutdown blocked behind a full inbound queue");
    }

    #[tokio::test]
    async fn terminal_failure_survives_a_saturated_inbound_queue() {
        let cancellation = CancellationToken::new();
        let failure = FailureSignal::default();
        let (inbound, mut receiver) = mpsc::channel(1);
        inbound
            .send(Inbound::MtuSelected(Bytes::new()))
            .await
            .unwrap();

        report_failure(
            &inbound,
            &failure,
            &cancellation,
            ClientError::permanent("malformed HTTP/3 capsule"),
        );

        assert!(matches!(
            failure.next(&mut receiver).await,
            Err(ClientError::Permanent(message)) if message == "malformed HTTP/3 capsule"
        ));
        assert!(cancellation.is_cancelled());
    }
}
