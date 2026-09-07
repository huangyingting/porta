use std::future::poll_fn;
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
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig as QuinnClientConfig, Endpoint};
use tokio::sync::mpsc;
use tokio::time::{timeout, timeout_at, Instant};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use url::Url;

use super::{
    send_outbound, valid_unicast, ClientConfig, ClientError, Connection, ConnectionInner,
    DatagramSend, DeliveryMode, FailureSignal, Inbound, Lease, Outbound, Transport,
    MASQUE_AUTH_PATH, MASQUE_PATH,
};

const CAPSULE_PROTOCOL_HEADER: &str = "capsule-protocol";
const MTU_BUDGET: Duration = Duration::from_millis(750);
const MTU_ATTEMPT: Duration = Duration::from_millis(150);
const REQUEST_ID: u64 = 1;

pub(super) async fn connect(config: ClientConfig) -> Result<Connection, ClientError> {
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
        tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(ClientError::unavailable)?
            .collect::<Vec<_>>()
    };
    if addresses.is_empty() {
        return Err(ClientError::unavailable(
            "gateway hostname resolved to no addresses",
        ));
    }

    let mut last_error = None;
    for remote_address in addresses {
        match connect_address(&config, &parsed, &host, remote_address).await {
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
) -> Result<Connection, ClientError> {
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
    let quic = timeout(config.timeout, connecting)
        .await
        .map_err(|_| ClientError::unavailable("QUIC handshake timed out"))?
        .map_err(classify_quic_connection)?;
    let cancellation = config.cancellation.child_token();
    let tasks = TaskTracker::new();
    let (inbound_tx, mut inbound_rx) = mpsc::channel(256);
    let (outbound_tx, outbound_rx) = mpsc::channel(256);
    let failure = Arc::new(FailureSignal::default());

    let h3_connection = h3_quinn::Connection::new(quic.clone());
    let (mut driver, mut requests) = h3::client::builder()
        .enable_extended_connect(true)
        .enable_datagram(true)
        .max_field_section_size(16 << 10)
        .build::<_, _, Bytes>(h3_connection)
        .await
        .map_err(ClientError::unavailable)?;

    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(masque_url(parsed)?.as_str())
        .body(())
        .map_err(ClientError::permanent)?;
    request.extensions_mut().insert(Protocol::CONNECT_IP);
    apply_headers(&mut request, config)?;
    let mut stream = requests
        .send_request(request)
        .await
        .map_err(ClientError::unavailable)?;
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

    let established = async {
        wait_for_peer_settings(&requests, &cancellation, config.timeout).await?;
        if !requests.settings().enable_extended_connect() {
            return Err(ClientError::unavailable(
                "gateway did not enable HTTP/3 Extended CONNECT",
            ));
        }
        let datagrams = requests.settings().enable_datagram();

        let response = timeout(config.timeout, stream.recv_response())
            .await
            .map_err(|_| ClientError::unavailable("HTTP/3 response timed out"))?
            .map_err(ClientError::unavailable)?;
        validate_response(&response)?;
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
            send_stream,
            datagram_sender,
            datagrams,
            writer_cancellation,
            writer_inbound,
            writer_failure,
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
                Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 32).expect("the IPv4 unspecified /32 is valid"),
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
        Ok((lease, automatic, ceiling, datagrams))
    }
    .await;
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
                    return Err(ClientError::unavailable(
                        "HTTP/3 connection stopped before peer SETTINGS",
                    ));
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
        gateway: None,
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

async fn run_writer<S, B, H>(
    mut outbound: mpsc::Receiver<Outbound>,
    mut stream: h3::client::RequestStream<S, B>,
    mut datagrams: h3_datagram::datagram_handler::DatagramSender<H, B>,
    mut use_datagrams: bool,
    cancellation: CancellationToken,
    inbound: mpsc::Sender<Inbound>,
    failures: Arc<FailureSignal>,
) where
    S: h3::quic::SendStream<B> + Send + 'static,
    B: Buf + From<Bytes> + Send + 'static,
    H: h3_datagram::quic_traits::SendDatagram<B> + Send + 'static,
{
    loop {
        let outbound = tokio::select! {
            _ = cancellation.cancelled() => break,
            value = outbound.recv() => match value {
                Some(value) => value,
                None => break,
            },
        };
        let failure = match outbound {
            Outbound::Packet { packet, result } => {
                let sent = if use_datagrams {
                    match datagrams
                        .send_datagram(Bytes::from(masque::encode_ip_packet(&packet)).into())
                    {
                        Ok(()) => Ok(()),
                        Err(error)
                            if datagram_error_kind(&error) == DatagramErrorKind::TooLarge =>
                        {
                            send_capsule_data(
                                &mut stream,
                                CAPSULE_DATAGRAM,
                                &masque::encode_ip_packet(&packet),
                            )
                            .await
                        }
                        Err(error)
                            if datagram_error_kind(&error) == DatagramErrorKind::NotAvailable =>
                        {
                            use_datagrams = false;
                            send_capsule_data(
                                &mut stream,
                                CAPSULE_DATAGRAM,
                                &masque::encode_ip_packet(&packet),
                            )
                            .await
                        }
                        Err(error) => Err(ClientError::retryable(error)),
                    }
                } else {
                    send_capsule_data(
                        &mut stream,
                        CAPSULE_DATAGRAM,
                        &masque::encode_ip_packet(&packet),
                    )
                    .await
                };
                let failed = sent.as_ref().err().cloned();
                let _ = result.send(sent);
                failed
            }
            Outbound::Datagram { payload, result } => {
                let sent = match datagrams.send_datagram(payload.into()) {
                    Ok(()) => Ok(DatagramSend::Sent),
                    Err(error) if datagram_error_kind(&error) == DatagramErrorKind::TooLarge => {
                        Ok(DatagramSend::TooLarge)
                    }
                    Err(error) => Err(ClientError::retryable(error)),
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
                let sent = send_capsule_data(&mut stream, capsule_type, &value).await;
                let failed = sent.as_ref().err().cloned();
                let _ = result.send(sent);
                failed
            }
        };
        if let Some(error) = failure {
            report_failure(&inbound, &failures, &cancellation, error);
            break;
        }
    }
    stream.stop_stream(h3::error::Code::H3_NO_ERROR);
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
        ] {
            let mut invalid = current_response(StatusCode::OK);
            invalid.headers_mut().insert(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
            assert!(validate_response(&invalid).is_err(), "{name}={value}");
        }
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
