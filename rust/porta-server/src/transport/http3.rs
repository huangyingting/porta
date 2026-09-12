use anyhow::Result;
use bytes::{Buf, Bytes, BytesMut};
use h3::ext::Protocol;
use h3::ConnectionState;
use h3_datagram::datagram_handler::{HandleDatagramsExt, SendDatagramError};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, BufReader};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::Instrument;

use crate::ops::admission::{AdmissionPermit, ConnectionAdmission, RetryController};
use crate::transport::session::{
    bearer_token, fragment_ipv4, icmp_fragmentation_needed, AuthenticationRequest, DeviceProof,
    Lease, LeaseError, MtuError, OpenSessionError, OpenSessionRequest, RouteError, RouteKind,
    Services, Session, BATCH_BYTES, HEADER_MAX_VERSION, HEADER_MIN_VERSION, HEADER_VERSION,
    MASQUE_AUTH_PATH, MASQUE_PATH, PACKET_BATCH, PROTOCOL_VERSION,
};
use crate::web::landing::LandingSite;
use crate::web::portal::Portal;
use crate::web::session::{normalized_headers, RequestContext, Response as WebResponse};
use crate::wire::ip::parse_ipv4;
use crate::wire::masque::{
    decode_address_assign, decode_address_request, decode_mtu_probe, decode_mtu_selection,
    decode_route_advertisement, encode_address_assign, encode_mtu_selection,
    encode_route_advertisement, parse_varint, Address, MasqueError, MtuProbe, MtuToken, Route,
    CAPSULE_ADDRESS_ASSIGN, CAPSULE_ADDRESS_REQUEST, CAPSULE_DATAGRAM, CAPSULE_MTU_SELECT,
    CAPSULE_MTU_SELECTED, CAPSULE_ROUTE_ADVERTISEMENT, MAX_CAPSULE_SIZE, MAX_DISCOVERED_MTU,
    MTU_DISCOVERY_HEADER, SAFE_MTU,
};

const CAPSULE_PROTOCOL: &str = "Capsule-Protocol";
const MAX_WEB_BODY: usize = 16 << 10;
const MAX_MTU_PROBES: usize = 16;
static ICMP_IDENTIFICATION: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
pub struct Http3Config {
    pub mtu: u16,
    pub dns: Option<Ipv4Addr>,
    pub auto_mtu: bool,
    pub enable_datagrams: bool,
    pub max_field_section_size: u64,
}

fn set_security_headers(headers: &mut http::HeaderMap) {
    headers.insert(
        "X-Content-Type-Options",
        http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        "Referrer-Policy",
        http::HeaderValue::from_static("no-referrer"),
    );
}

impl Default for Http3Config {
    fn default() -> Self {
        Self {
            mtu: 1400,
            dns: None,
            auto_mtu: true,
            enable_datagrams: true,
            max_field_section_size: 16 << 10,
        }
    }
}

pub struct Http3Server {
    services: Arc<Services>,
    portal: Arc<Portal>,
    landing: Arc<LandingSite>,
    config: Http3Config,
}

impl Http3Server {
    pub fn new(
        services: Arc<Services>,
        portal: Arc<Portal>,
        landing: Arc<LandingSite>,
        config: Http3Config,
    ) -> Result<Self> {
        if !(576..=9000).contains(&config.mtu) {
            anyhow::bail!("MTU {} is outside 576..9000", config.mtu);
        }
        Ok(Self {
            services,
            portal,
            landing,
            config,
        })
    }
}

pub async fn serve_quinn(
    endpoint: quinn::Endpoint,
    server: Arc<Http3Server>,
    admission: Arc<ConnectionAdmission>,
    retry: Arc<RetryController>,
    shutdown: CancellationToken,
) -> Result<()> {
    let connections = TaskTracker::new();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                endpoint.close(0_u32.into(), b"server shutting down");
                connections.close();
                endpoint.wait_idle().await;
                connections.wait().await;
                return Ok(());
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    connections.close();
                    connections.wait().await;
                    return Ok(());
                };
                let peer = incoming.remote_address();
                if retry.should_retry(peer) && incoming.may_retry() {
                    if incoming.retry().is_ok() {
                        continue;
                    }
                    continue;
                }
                let Ok(permit) = admission.admit_quic(peer, false) else {
                    continue;
                };
                let server = server.clone();
                connections.spawn(async move {
                    if let Err(error) = serve_connection(incoming, server, permit).await {
                        tracing::debug!(%error, "HTTP/3 connection stopped");
                    }
                });
            }
        }
    }
}

async fn serve_connection(
    incoming: quinn::Incoming,
    server: Arc<Http3Server>,
    mut permit: AdmissionPermit,
) -> Result<()> {
    let connection = incoming.await?;
    let peer = connection.remote_address();
    if permit.mark_verified(peer).is_err() {
        connection.close(0_u32.into(), b"connection limit reached");
        return Ok(());
    }
    let quic = h3_quinn::Connection::new(connection.clone());
    let mut builder = h3::server::builder();
    builder
        .enable_extended_connect(true)
        .enable_datagram(server.config.enable_datagrams)
        .max_field_section_size(server.config.max_field_section_size);
    let mut h3 = builder.build::<_, Bytes>(quic).await?;
    let requests = TaskTracker::new();
    let tunnel_active = Arc::new(AtomicBool::new(false));
    let (resolved_tx, mut resolved_rx) = mpsc::unbounded_channel();
    loop {
        tokio::select! {
            accepted = h3.accept() => {
                match accepted {
                    Ok(Some(resolver)) => {
                        let resolved_tx = resolved_tx.clone();
                        requests.spawn(async move {
                            let _ = resolved_tx.send(resolver.resolve_request().await);
                        });
                    }
                    Ok(None) => {
                        requests.close();
                        requests.wait().await;
                        return Ok(());
                    }
                    Err(error) => {
                        drop(h3);
                        requests.close();
                        requests.wait().await;
                        return Err(error.into());
                    }
                }
            }
            resolved = resolved_rx.recv() => {
                let Some(resolved) = resolved else {
                    requests.close();
                    requests.wait().await;
                    return Ok(());
                };
                let (request, stream) = match resolved {
                    Ok(resolved) => resolved,
                    Err(error @ h3::error::StreamError::ConnectionError(_)) => {
                        drop(h3);
                        requests.close();
                        requests.wait().await;
                        return Err(error.into());
                    }
                    Err(h3::error::StreamError::RemoteClosing) => {
                        continue;
                    }
                    Err(error) => {
                        tracing::debug!(%error, "HTTP/3 request stream rejected");
                        continue;
                    }
                };
                if request.method() == http::Method::CONNECT
                    && request.uri().path().eq_ignore_ascii_case(MASQUE_PATH)
                {
                    if tunnel_active.swap(true, Ordering::AcqRel) {
                        requests.spawn(async move {
                            let mut stream = stream;
                            if let Err(error) = send_error(
                                &mut stream,
                                http::StatusCode::CONFLICT,
                                "one CONNECT-IP tunnel is allowed per HTTP/3 connection\n",
                                false,
                            )
                            .await
                            {
                                tracing::debug!(%error, "HTTP/3 duplicate tunnel rejection stopped");
                            }
                        });
                        continue;
                    }
                    let stream_id = stream.id();
                    let datagram_sender = h3.get_datagram_sender(stream_id);
                    let datagram_reader = h3.get_datagram_reader();
                    let tunnel_slot = TunnelSlot(tunnel_active.clone());
                    let tunnel_server = server.clone();
                    let tunnel_connection = connection.clone();
                    requests.spawn(async move {
                        let _tunnel_slot = tunnel_slot;
                        if let Err(error) = serve_tunnel(
                            request,
                            stream,
                            datagram_sender,
                            datagram_reader,
                            peer,
                            tunnel_server,
                            tunnel_connection,
                        )
                        .await
                        {
                            tracing::debug!(%error, "HTTP/3 tunnel stopped");
                        }
                    });
                    continue;
                }
                let server = server.clone();
                requests.spawn(async move {
                    if let Err(error) = serve_web_request(request, stream, peer, server).await {
                        tracing::debug!(%error, "HTTP/3 web request stopped");
                    }
                });
            }
        }
    }
}

struct TunnelSlot(Arc<AtomicBool>);

impl Drop for TunnelSlot {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

async fn serve_web_request<S, B>(
    request: http::Request<()>,
    mut stream: h3::server::RequestStream<S, B>,
    peer: SocketAddr,
    server: Arc<Http3Server>,
) -> Result<()>
where
    S: h3::quic::BidiStream<B> + Send + 'static,
    B: Buf + From<Bytes> + Send + 'static,
{
    if request.method() == http::Method::CONNECT {
        return send_error(
            &mut stream,
            http::StatusCode::NOT_IMPLEMENTED,
            "HTTP/3 forward proxy is not supported\n",
            false,
        )
        .await;
    }
    let context = match collect_web_request(request, &mut stream, peer.ip()).await {
        Ok(context) => context,
        Err((status, message)) => {
            return send_error(&mut stream, status, message, false).await;
        }
    };
    let response = if let Some(response) = server.portal.handle(&context).await {
        response
    } else if let Some(response) = server.landing.handle(&context) {
        response
    } else {
        WebResponse::not_found()
    };
    send_web_response(&mut stream, response).await
}

async fn collect_web_request<S, B>(
    request: http::Request<()>,
    stream: &mut h3::server::RequestStream<S, B>,
    peer: IpAddr,
) -> std::result::Result<RequestContext, (http::StatusCode, &'static str)>
where
    S: h3::quic::BidiStream<B>,
    B: Buf + From<Bytes>,
{
    let mut body = BytesMut::new();
    while let Some(mut chunk) = stream
        .recv_data()
        .await
        .map_err(|_| (http::StatusCode::BAD_REQUEST, "invalid request body\n"))?
    {
        if body.len().saturating_add(chunk.remaining()) > MAX_WEB_BODY {
            return Err((
                http::StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large\n",
            ));
        }
        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    Ok(web_request_context(&request, body.freeze(), peer))
}

fn web_request_context(request: &http::Request<()>, body: Bytes, peer: IpAddr) -> RequestContext {
    let host = request
        .uri()
        .authority()
        .map(http::uri::Authority::as_str)
        .or_else(|| {
            request
                .headers()
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok())
        })
        .unwrap_or_default()
        .to_owned();
    RequestContext {
        method: request.method().as_str().to_owned(),
        path: request.uri().path().to_owned(),
        query: request.uri().query().unwrap_or_default().to_owned(),
        host,
        headers: normalized_headers(request.headers()),
        body: body.to_vec(),
        peer_ip: Some(peer),
        client_ip: Some(peer),
    }
}

async fn send_web_response<S, B>(
    stream: &mut h3::server::RequestStream<S, B>,
    response: WebResponse,
) -> Result<()>
where
    S: h3::quic::BidiStream<B>,
    B: Buf + From<Bytes>,
{
    let mut h3_response = http::Response::new(());
    *h3_response.status_mut() = http::StatusCode::from_u16(response.status)?;
    for (name, value) in &response.headers {
        h3_response.headers_mut().insert(
            http::HeaderName::try_from(name)?,
            http::HeaderValue::try_from(value)?,
        );
    }
    stream.send_response(h3_response).await?;
    if !response.body.is_empty() {
        stream.send_data(Bytes::from(response.body).into()).await?;
    }
    if let Some(file) = response.file {
        let mut remaining = file.length;
        let mut reader = BufReader::new(tokio::fs::File::from_std(file.file));
        let mut buffer = vec![0_u8; 16 << 10];
        while remaining > 0 {
            let limit = usize::try_from(remaining.min(buffer.len() as u64))
                .expect("bounded read length fits usize");
            let read = reader.read(&mut buffer[..limit]).await?;
            if read == 0 {
                anyhow::bail!("download file ended before declared content length");
            }
            stream
                .send_data(Bytes::copy_from_slice(&buffer[..read]).into())
                .await?;
            remaining -= read as u64;
        }
    }
    stream.finish().await?;
    Ok(())
}

async fn serve_tunnel<S, B, SendHandler, RecvHandler>(
    request: http::Request<()>,
    mut stream: h3::server::RequestStream<S, B>,
    datagram_sender: h3_datagram::datagram_handler::DatagramSender<SendHandler, B>,
    datagram_reader: h3_datagram::datagram_handler::DatagramReader<RecvHandler>,
    peer: SocketAddr,
    server: Arc<Http3Server>,
    connection: quinn::Connection,
) -> Result<()>
where
    S: h3::quic::BidiStream<B> + Send + 'static,
    B: Buf + From<Bytes> + Send + 'static,
    SendHandler: h3_datagram::quic_traits::SendDatagram<B> + Send,
    RecvHandler: h3_datagram::quic_traits::RecvDatagram + Send + 'static,
    RecvHandler::Buffer: Send + 'static,
{
    if !request.uri().path().eq_ignore_ascii_case(MASQUE_PATH) {
        send_error(
            &mut stream,
            http::StatusCode::NOT_FOUND,
            "not found\n",
            false,
        )
        .await?;
        return Ok(());
    }
    if request.method() != http::Method::CONNECT {
        send_method_not_allowed(&mut stream).await?;
        return Ok(());
    }
    if !is_connect_ip(&request) {
        send_error(
            &mut stream,
            http::StatusCode::BAD_REQUEST,
            "CONNECT-IP requires HTTP Extended CONNECT\n",
            false,
        )
        .await?;
        return Ok(());
    }
    if request
        .headers()
        .get(CAPSULE_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        != Some("?1")
    {
        send_error(
            &mut stream,
            http::StatusCode::BAD_REQUEST,
            "Capsule-Protocol: ?1 is required\n",
            false,
        )
        .await?;
        return Ok(());
    }
    if request
        .headers()
        .get(HEADER_VERSION)
        .and_then(|value| value.to_str().ok())
        != Some(PROTOCOL_VERSION)
    {
        send_error(
            &mut stream,
            http::StatusCode::UPGRADE_REQUIRED,
            "unsupported Porta protocol version\n",
            true,
        )
        .await?;
        return Ok(());
    }
    let peer_datagrams = if server.config.enable_datagrams {
        if tokio::time::timeout(Duration::from_secs(2), async {
            while !stream.settings_received() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .is_err()
        {
            send_error(
                &mut stream,
                http::StatusCode::REQUEST_TIMEOUT,
                "peer HTTP/3 SETTINGS were not received\n",
                false,
            )
            .await?;
            return Ok(());
        }
        stream.settings().enable_datagram()
    } else {
        false
    };
    let token = match bearer_token(request.headers()) {
        Ok(token) => token,
        Err(_) => {
            server.services.metrics.authentication_failed();
            send_unauthorized(&mut stream).await?;
            return Ok(());
        }
    };
    let use_datagrams = server.config.enable_datagrams && peer_datagrams;
    let mtu = if server.config.auto_mtu
        && server.config.mtu > SAFE_MTU
        && use_datagrams
        && request
            .headers()
            .get(MTU_DISCOVERY_HEADER)
            .and_then(|value| value.to_str().ok())
            == Some("1")
    {
        Some(MtuResponder::new(server.config.mtu))
    } else {
        None
    };
    let session = match server
        .services
        .open(OpenSessionRequest {
            authentication: AuthenticationRequest {
                bearer_token: token,
                proof: DeviceProof::from_headers(request.headers()),
                method: request.method().clone(),
                path: MASQUE_AUTH_PATH.to_owned(),
                peer,
            },
            group_id: None,
            route: RouteKind::ConnectIp,
            transport: if use_datagrams {
                "masque-h3-datagram".into()
            } else {
                "masque-h3-capsule".into()
            },
        })
        .await
    {
        Ok(session) => session,
        Err(error) => {
            send_open_error(&mut stream, error).await?;
            return Ok(());
        }
    };
    let span = tracing::info_span!(
        "http3_tunnel",
        tunnel_id = session.tunnel_id,
        account_id = %session.identity.account_id,
        device_id = %session.proof.device_id,
        address = %session.lease.address,
        peer = %peer,
        stream_id = stream.id().into_inner(),
    );
    async {
        let mut diagnostics = Http3Diagnostics::new(
            connection,
            stream.id().into_inner(),
            use_datagrams,
            server.config.mtu,
        );
        let result = run_tunnel(
            stream,
            datagram_sender,
            datagram_reader,
            &session,
            &server,
            mtu,
            &mut diagnostics,
        )
        .await;
        let termination = tunnel_termination(
            &result,
            session.cancellation.is_cancelled(),
            diagnostics.connection.close_reason().as_ref(),
        );
        diagnostics.finish(termination, &session);
        session.close_with_reason(termination.reason);
        result.map(|_| ())
    }
    .instrument(span)
    .await
}

async fn run_tunnel<S, B, SendHandler, RecvHandler>(
    mut stream: h3::server::RequestStream<S, B>,
    mut datagram_sender: h3_datagram::datagram_handler::DatagramSender<SendHandler, B>,
    mut datagram_reader: h3_datagram::datagram_handler::DatagramReader<RecvHandler>,
    session: &Session,
    server: &Http3Server,
    mut mtu: Option<MtuResponder>,
    diagnostics: &mut Http3Diagnostics,
) -> Result<&'static str>
where
    S: h3::quic::BidiStream<B> + Send + 'static,
    B: Buf + From<Bytes> + Send + 'static,
    SendHandler: h3_datagram::quic_traits::SendDatagram<B> + Send,
    RecvHandler: h3_datagram::quic_traits::RecvDatagram + Send + 'static,
    RecvHandler::Buffer: Send + 'static,
{
    let response = success_response(&server.config, mtu.as_ref());
    let response_sent = tokio::select! {
        biased;
        _ = session.cancellation.cancelled() => false,
        result = stream.send_response(response) => {
            result?;
            true
        }
    };
    if !response_sent {
        stream.stop_stream(h3::error::Code::H3_NO_ERROR);
        stream.stop_sending(h3::error::Code::H3_NO_ERROR);
        return Ok("cancelled");
    }
    let stream_id = stream.id();
    let (mut send_stream, mut receive_stream) = stream.split();
    let datagram_cancellation = CancellationToken::new();
    let datagram_stop = datagram_cancellation.clone();
    let (datagram_tx, mut datagram_rx) =
        mpsc::channel::<std::result::Result<Bytes, h3::error::StreamError>>(32);
    let datagram_task = diagnostics.datagrams_enabled.then(|| {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = datagram_stop.cancelled() => return,
                    datagram = datagram_reader.read_datagram() => {
                        let payload = match datagram {
                            Ok(datagram) if datagram.stream_id() == stream_id => {
                                let mut payload = datagram.into_payload();
                                Ok(payload.copy_to_bytes(payload.remaining()))
                            }
                            Ok(_) => continue,
                            Err(error) => Err(error),
                        };
                        let failed = payload.is_err();
                        let sent = tokio::select! {
                            _ = datagram_stop.cancelled() => return,
                            sent = datagram_tx.send(payload) => sent,
                        };
                        if sent.is_err() || failed {
                            return;
                        }
                    }
                }
            }
        })
    });
    let mut capsules = BytesMut::with_capacity(256);
    let assigned = AtomicBool::new(false);
    let mut downlink_ready = false;
    let mut icmp_after = Instant::now();

    let mut result: Result<&'static str> = async {
        'tunnel: loop {
            tokio::select! {
            biased;
            _ = session.cancellation.cancelled() => break Ok("cancelled"),
            incoming = receive_stream.recv_data() => {
                let Some(mut incoming) = incoming? else {
                    break Ok("client_eof");
                };
                capsules.extend_from_slice(&incoming.copy_to_bytes(incoming.remaining()));
                while let Some((capsule_type, value)) = take_capsule(&mut capsules)? {
                    match capsule_type {
                        CAPSULE_MTU_SELECT => {
                            let responder = mtu.as_mut().ok_or(MasqueError::InvalidMtuMessage)?;
                            let first_selection = !responder.committed;
                            let selected = responder.commit(&value)?;
                            diagnostics.selected_mtu = responder.selected;
                            let mut control = BytesMut::with_capacity(selected.len() + 16);
                            append_capsule(&mut control, CAPSULE_MTU_SELECTED, &selected)?;
                            send_h3_data(
                                &mut send_stream,
                                control.freeze().into(),
                                &session.cancellation,
                            )
                            .await?;
                            if first_selection {
                                tracing::info!(
                                    account_id = %session.identity.account_id,
                                    device_id = %session.proof.device_id,
                                    address = %session.lease.address,
                                    mtu = responder.selected,
                                    ceiling = server.config.mtu,
                                    "tunnel MTU selected"
                                );
                            }
                        }
                        CAPSULE_ADDRESS_REQUEST => {
                            if mtu.as_ref().is_some_and(|responder| !responder.committed) {
                                break 'tunnel Err(MasqueError::InvalidMtuMessage.into());
                            }
                            let previous = assigned.load(Ordering::Acquire);
                            let (control, becomes_assigned) =
                                address_response(&session.lease, previous, &value)?;
                            if becomes_assigned {
                                assigned.store(true, Ordering::Release);
                            }
                            if let Err(error) = send_h3_data(
                                &mut send_stream,
                                control.into(),
                                &session.cancellation,
                            )
                            .await
                            {
                                assigned.store(previous, Ordering::Release);
                                break 'tunnel Err(error);
                            }
                            if assigned.load(Ordering::Acquire) {
                                downlink_ready = true;
                            }
                        }
                        CAPSULE_DATAGRAM => {
                            if assigned.load(Ordering::Acquire) {
                                if let Ok(packet) = decode_ip_bytes(value) {
                                    inject_packet(session, packet, selected_mtu(&mtu, server.config.mtu)).await?;
                                } else {
                                    session.services().metrics.dropped_from_client();
                                }
                            } else {
                                session.services().metrics.dropped_from_client();
                            }
                        }
                        CAPSULE_ADDRESS_ASSIGN => {
                            decode_address_assign(&value)?;
                        }
                        CAPSULE_ROUTE_ADVERTISEMENT => {
                            decode_route_advertisement(&value)?;
                        }
                        _ => {}
                    }
                }
            }
            datagram = datagram_rx.recv(), if diagnostics.datagrams_enabled => {
                let Some(datagram) = datagram else {
                    diagnostics.disable_datagrams("reader_ended");
                    continue;
                };
                let value = datagram?;
                if let Some(responder) = mtu.as_mut() {
                    if responder.is_probe(&value) {
                        match responder.accept_probe(&value) {
                            Ok(true) => match datagram_sender.send_datagram(value.clone().into()) {
                                        Ok(()) => responder.probe_echoed(&value)?,
                                        Err(error) => match datagram_error_kind(&error) {
                                            DatagramErrorKind::TooLarge => {}
                                            DatagramErrorKind::NotAvailable => {
                                                diagnostics.disable_datagrams("not_available");
                                            }
                                            DatagramErrorKind::Connection => break Err(error.into()),
                                        },
                                    },
                            Ok(false) => {}
                            Err(_) => session.services().metrics.dropped_from_client(),
                        }
                        continue;
                    }
                }
                if !assigned.load(Ordering::Acquire) {
                    session.services().metrics.dropped_from_client();
                    continue;
                }
                match decode_ip_bytes(value) {
                    Ok(packet) => {
                        inject_packet(session, packet, selected_mtu(&mtu, server.config.mtu)).await?;
                    }
                    Err(_) => session.services().metrics.dropped_from_client(),
                }
            }
            packet = session.downlink.next_packet(), if downlink_ready => {
                let Some(packet) = packet else {
                    break Ok("downlink_closed");
                };
                send_downlink(
                    session,
                    packet,
                    selected_mtu(&mtu, server.config.mtu),
                    &mut datagram_sender,
                    &mut send_stream,
                    &mut icmp_after,
                    diagnostics,
                ).await?;
            }
            }
        }
    }
    .await;
    datagram_cancellation.cancel();
    if let Some(datagram_task) = datagram_task {
        if let Err(error) = datagram_task.await {
            diagnostics.datagram_reader_failed = true;
            if result.is_ok() {
                result = Err(error.into());
            }
        }
    }
    receive_stream.stop_sending(h3::error::Code::H3_NO_ERROR);
    if result.is_ok() && !session.cancellation.is_cancelled() {
        let finished = tokio::select! {
            biased;
            _ = session.cancellation.cancelled() => false,
            finished = send_stream.finish() => {
                if let Err(error) = finished {
                    result = Err(error.into());
                }
                true
            },
        };
        if !finished {
            result = Ok("cancelled");
            send_stream.stop_stream(h3::error::Code::H3_NO_ERROR);
        }
    } else {
        send_stream.stop_stream(h3::error::Code::H3_NO_ERROR);
    }
    result
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TunnelTermination {
    reason: &'static str,
    unexpected: bool,
    code: Option<u64>,
}

impl TunnelTermination {
    fn normal(reason: &'static str) -> Self {
        Self {
            reason,
            unexpected: false,
            code: None,
        }
    }

    fn failure(reason: &'static str, code: Option<u64>) -> Self {
        Self {
            reason,
            unexpected: true,
            code,
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("session cancelled")]
struct SessionCancelled;

fn tunnel_termination(
    result: &Result<&'static str>,
    cancelled: bool,
    quic_close: Option<&quinn::ConnectionError>,
) -> TunnelTermination {
    use h3::error::{Code, StreamError};
    let error = match result {
        Ok(reason) => return TunnelTermination::normal(reason),
        Err(error) => error,
    };
    if error.is::<SessionCancelled>() || (cancelled && error.is::<RouteError>()) {
        return TunnelTermination::normal("cancelled");
    }
    if let Some(error) = error.downcast_ref::<StreamError>() {
        if error.is_h3_no_error() {
            return TunnelTermination::normal("h3_no_error");
        }
        match error {
            StreamError::RemoteClosing => return TunnelTermination::normal("peer_closing"),
            StreamError::RemoteTerminate {
                code: Code::H3_REQUEST_CANCELLED,
                ..
            } => {
                return TunnelTermination::normal("client_cancelled");
            }
            StreamError::RemoteTerminate { code, .. } | StreamError::StreamError { code, .. } => {
                return TunnelTermination::failure("h3_stream_error", Some(code.value()));
            }
            StreamError::HeaderTooBig { .. } => {
                return TunnelTermination::failure("h3_headers_too_large", None);
            }
            StreamError::ConnectionError(error) => {
                return h3_connection_termination(error, quic_close);
            }
            _ => {}
        }
    }
    if let Some(error) = error.downcast_ref::<h3::error::ConnectionError>() {
        return h3_connection_termination(error, quic_close);
    }
    if error.is::<MasqueError>() {
        return TunnelTermination::failure("capsule_protocol_error", None);
    }
    if error.is::<RouteError>() {
        return TunnelTermination::failure("router_error", None);
    }
    if error.is::<tokio::task::JoinError>() {
        return TunnelTermination::failure("datagram_reader_failed", None);
    }
    quic_close
        .map(quic_termination)
        .unwrap_or_else(|| TunnelTermination::failure("tunnel_error", None))
}

fn h3_connection_termination(
    error: &h3::error::ConnectionError,
    quic_close: Option<&quinn::ConnectionError>,
) -> TunnelTermination {
    use h3::error::{ConnectionError, LocalError};
    if error.is_h3_no_error() {
        return TunnelTermination::normal("h3_no_error");
    }
    match error {
        ConnectionError::Timeout => TunnelTermination::failure("quic_timeout", None),
        ConnectionError::Local {
            error: LocalError::Application { code, .. },
            ..
        } => TunnelTermination::failure("h3_connection_error", Some(code.value())),
        ConnectionError::Remote(h3::quic::ConnectionErrorIncoming::ApplicationClose {
            error_code,
        }) => {
            if *error_code == 0 {
                TunnelTermination::normal("peer_closed")
            } else {
                TunnelTermination::failure("peer_application_error", Some(*error_code))
            }
        }
        _ => quic_close
            .map(quic_termination)
            .unwrap_or_else(|| TunnelTermination::failure("h3_connection_error", None)),
    }
}

fn quic_termination(error: &quinn::ConnectionError) -> TunnelTermination {
    use quinn::ConnectionError;
    match error {
        ConnectionError::LocallyClosed => TunnelTermination::normal("local_close"),
        ConnectionError::ApplicationClosed(close)
            if close.error_code.into_inner() == 0
                || close.error_code.into_inner() == h3::error::Code::H3_NO_ERROR.value() =>
        {
            TunnelTermination::normal("peer_closed")
        }
        ConnectionError::ConnectionClosed(close) if u64::from(close.error_code) == 0 => {
            TunnelTermination::normal("peer_closed")
        }
        ConnectionError::ApplicationClosed(close) => TunnelTermination::failure(
            "peer_application_error",
            Some(close.error_code.into_inner()),
        ),
        ConnectionError::TransportError(error) => {
            TunnelTermination::failure("quic_transport_error", Some(u64::from(error.code)))
        }
        ConnectionError::ConnectionClosed(close) => {
            TunnelTermination::failure("quic_transport_error", Some(u64::from(close.error_code)))
        }
        ConnectionError::TimedOut => TunnelTermination::failure("quic_timeout", None),
        ConnectionError::Reset => TunnelTermination::failure("quic_reset", None),
        _ => TunnelTermination::failure("quic_connection_error", None),
    }
}

#[derive(Default)]
struct Http3SendCounters {
    // DATAGRAM enqueue can be evicted; capsule submissions can still block or fail.
    datagram_queued_packets: u64,
    datagram_queued_ip_bytes: u64,
    capsule_submitted_packets: u64,
    capsule_submitted_ip_bytes: u64,
    oversize_fallback_packets: u64,
    oversize_fallback_ip_bytes: u64,
    max_oversize_ip_bytes: usize,
    unavailable_fallback_packets: u64,
}

impl Http3SendCounters {
    fn datagram_queued(&mut self, ip_bytes: usize) {
        self.datagram_queued_packets += 1;
        self.datagram_queued_ip_bytes += ip_bytes as u64;
    }

    fn capsule_submitted(&mut self, ip_bytes: usize, packets: u64) {
        self.capsule_submitted_packets += packets;
        self.capsule_submitted_ip_bytes += ip_bytes as u64;
    }

    fn fallback(&mut self, kind: DatagramErrorKind, ip_bytes: usize) -> bool {
        match kind {
            DatagramErrorKind::TooLarge => {
                self.oversize_fallback_packets += 1;
                self.oversize_fallback_ip_bytes += ip_bytes as u64;
                self.max_oversize_ip_bytes = self.max_oversize_ip_bytes.max(ip_bytes);
                self.oversize_fallback_packets == 1
            }
            DatagramErrorKind::NotAvailable => {
                self.unavailable_fallback_packets += 1;
                self.unavailable_fallback_packets == 1
            }
            DatagramErrorKind::Connection => false,
        }
    }
}

struct Http3Diagnostics {
    connection: quinn::Connection,
    stream_id: u64,
    selected_mtu: u16,
    datagrams_enabled: bool,
    datagrams_disabled_reason: &'static str,
    datagram_reader_failed: bool,
    min_oversize_ip_capacity: Option<usize>,
    sends: Http3SendCounters,
}

impl Http3Diagnostics {
    fn new(connection: quinn::Connection, stream_id: u64, datagrams: bool, mtu: u16) -> Self {
        let stats = connection.stats();
        tracing::info!(
            datagrams_enabled = datagrams,
            configured_mtu = mtu,
            quic_datagram_capacity = ?connection.max_datagram_size(),
            ip_datagram_capacity = ?ip_datagram_capacity(connection.max_datagram_size(), stream_id),
            quic_path_mtu = stats.path.current_mtu,
            quic_rtt_ms = stats.path.rtt.as_millis() as u64,
            quic_path_sent_packets = stats.path.sent_packets,
            quic_path_lost_packets = stats.path.lost_packets,
            quic_path_congestion_events = stats.path.congestion_events,
            quic_path_black_holes = stats.path.black_holes_detected,
            "HTTP/3 tunnel transport started"
        );
        Self {
            connection,
            stream_id,
            selected_mtu: mtu,
            datagrams_enabled: datagrams,
            datagrams_disabled_reason: if datagrams { "none" } else { "not_negotiated" },
            datagram_reader_failed: false,
            min_oversize_ip_capacity: None,
            sends: Http3SendCounters::default(),
        }
    }

    fn fallback(&mut self, kind: DatagramErrorKind, ip_bytes: usize) {
        let capacity = self.connection.max_datagram_size();
        let ip_capacity = ip_datagram_capacity(capacity, self.stream_id);
        if kind == DatagramErrorKind::TooLarge {
            if let Some(capacity) = ip_capacity {
                self.min_oversize_ip_capacity = Some(
                    self.min_oversize_ip_capacity
                        .map_or(capacity, |previous| previous.min(capacity)),
                );
            }
        }
        if self.sends.fallback(kind, ip_bytes) {
            tracing::info!(
                reason = if kind == DatagramErrorKind::TooLarge { "too_large" } else { "not_available" },
                ip_bytes,
                quic_datagram_capacity = ?capacity,
                ip_datagram_capacity = ?ip_capacity,
                "HTTP/3 downlink capsule fallback started"
            );
        }
    }

    fn disable_datagrams(&mut self, reason: &'static str) {
        if self.datagrams_enabled {
            self.datagrams_enabled = false;
            self.datagrams_disabled_reason = reason;
            tracing::info!(reason, "HTTP/3 tunnel switched to capsules");
        }
    }

    fn finish(&self, termination: TunnelTermination, session: &Session) {
        let stats = self.connection.stats();
        if termination.unexpected || self.datagram_reader_failed {
            tracing::warn!(
                tunnel_id = session.tunnel_id,
                account_id = %session.identity.account_id,
                device_id = %session.proof.device_id,
                reason = termination.reason,
                error_code = ?termination.code,
                datagram_reader_failed = self.datagram_reader_failed,
                "authenticated HTTP/3 tunnel stopped unexpectedly"
            );
        }
        tracing::info!(
            reason = termination.reason,
            error_code = ?termination.code,
            selected_mtu = self.selected_mtu,
            datagrams_enabled = self.datagrams_enabled,
            datagrams_disabled_reason = self.datagrams_disabled_reason,
            quic_datagram_capacity = ?self.connection.max_datagram_size(),
            ip_datagram_capacity = ?ip_datagram_capacity(self.connection.max_datagram_size(), self.stream_id),
            quic_path_mtu = stats.path.current_mtu,
            quic_rtt_ms = stats.path.rtt.as_millis() as u64,
            quic_path_sent_packets = stats.path.sent_packets,
            quic_path_lost_packets = stats.path.lost_packets,
            quic_path_congestion_events = stats.path.congestion_events,
            quic_path_black_holes = stats.path.black_holes_detected,
            datagram_queued_packets = self.sends.datagram_queued_packets,
            datagram_queued_ip_bytes = self.sends.datagram_queued_ip_bytes,
            capsule_submitted_packets = self.sends.capsule_submitted_packets,
            capsule_submitted_ip_bytes = self.sends.capsule_submitted_ip_bytes,
            oversize_fallback_packets = self.sends.oversize_fallback_packets,
            oversize_fallback_ip_bytes = self.sends.oversize_fallback_ip_bytes,
            max_oversize_ip_bytes = self.sends.max_oversize_ip_bytes,
            min_oversize_ip_capacity = ?self.min_oversize_ip_capacity,
            unavailable_fallback_packets = self.sends.unavailable_fallback_packets,
            "HTTP/3 tunnel transport summary"
        );
    }
}

fn ip_datagram_capacity(quic_capacity: Option<usize>, stream_id: u64) -> Option<usize> {
    // QUIC's payload limit includes the HTTP/3 quarter stream ID and CONNECT-IP context ID.
    let stream_id_bytes = match stream_id / 4 {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    };
    quic_capacity.map(|capacity| capacity.saturating_sub(stream_id_bytes + 1))
}

fn is_connect_ip(request: &http::Request<()>) -> bool {
    request.method() == http::Method::CONNECT
        && request.uri().path().eq_ignore_ascii_case(MASQUE_PATH)
        && request.extensions().get::<Protocol>() == Some(&Protocol::CONNECT_IP)
}

fn success_response(config: &Http3Config, mtu: Option<&MtuResponder>) -> http::Response<()> {
    let mut response = http::Response::new(());
    *response.status_mut() = http::StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(CAPSULE_PROTOCOL, http::HeaderValue::from_static("?1"));
    headers.insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    set_security_headers(headers);
    set_version_headers(headers);
    headers.insert("X-Porta-MTU", config.mtu.to_string().parse().unwrap());
    if let Some(dns) = config.dns {
        headers.insert("X-Porta-DNS", dns.to_string().parse().unwrap());
    }
    if let Some(mtu) = mtu {
        headers.insert(MTU_DISCOVERY_HEADER, mtu.offer().parse().unwrap());
    }
    response
}

async fn send_error<S, B>(
    stream: &mut h3::server::RequestStream<S, B>,
    status: http::StatusCode,
    message: &'static str,
    versions: bool,
) -> Result<()>
where
    S: h3::quic::BidiStream<B>,
    B: Buf + From<Bytes>,
{
    let mut response = http::Response::new(());
    *response.status_mut() = status;
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    set_security_headers(response.headers_mut());
    if versions {
        set_version_headers(response.headers_mut());
    }
    stream.send_response(response).await?;
    stream
        .send_data(Bytes::from_static(message.as_bytes()).into())
        .await?;
    stream.finish().await?;
    Ok(())
}

async fn send_unauthorized<S, B>(stream: &mut h3::server::RequestStream<S, B>) -> Result<()>
where
    S: h3::quic::BidiStream<B>,
    B: Buf + From<Bytes>,
{
    let mut response = http::Response::new(());
    *response.status_mut() = http::StatusCode::UNAUTHORIZED;
    response
        .headers_mut()
        .insert(http::header::WWW_AUTHENTICATE, porta_authenticate_header());
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    set_security_headers(response.headers_mut());
    stream.send_response(response).await?;
    stream
        .send_data(Bytes::from_static(b"unauthorized\n").into())
        .await?;
    stream.finish().await?;
    Ok(())
}

fn porta_authenticate_header() -> http::HeaderValue {
    http::HeaderValue::from_str(&["Bearer", " realm=\"porta\""].concat())
        .expect("static authentication challenge is valid")
}

async fn send_method_not_allowed<S, B>(stream: &mut h3::server::RequestStream<S, B>) -> Result<()>
where
    S: h3::quic::BidiStream<B>,
    B: Buf + From<Bytes>,
{
    let mut response = http::Response::new(());
    *response.status_mut() = http::StatusCode::METHOD_NOT_ALLOWED;
    response.headers_mut().insert(
        http::header::ALLOW,
        http::HeaderValue::from_static("CONNECT"),
    );
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    set_security_headers(response.headers_mut());
    stream.send_response(response).await?;
    stream
        .send_data(Bytes::from_static(b"Method Not Allowed\n").into())
        .await?;
    stream.finish().await?;
    Ok(())
}

async fn send_open_error<S, B>(
    stream: &mut h3::server::RequestStream<S, B>,
    error: OpenSessionError,
) -> Result<()>
where
    S: h3::quic::BidiStream<B>,
    B: Buf + From<Bytes>,
{
    match error {
        OpenSessionError::Unauthorized => send_unauthorized(stream).await,
        OpenSessionError::RateLimited {
            retry_after_seconds,
        } => {
            let mut response = http::Response::new(());
            *response.status_mut() = http::StatusCode::TOO_MANY_REQUESTS;
            response.headers_mut().insert(
                http::header::RETRY_AFTER,
                retry_after_seconds.to_string().parse().unwrap(),
            );
            response.headers_mut().insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            response.headers_mut().insert(
                http::header::CACHE_CONTROL,
                http::HeaderValue::from_static("no-store"),
            );
            set_security_headers(response.headers_mut());
            stream.send_response(response).await?;
            stream
                .send_data(Bytes::from_static(b"too many authentication attempts\n").into())
                .await?;
            stream.finish().await?;
            Ok(())
        }
        OpenSessionError::Lease(LeaseError::Exhausted | LeaseError::Internal) => {
            send_error(
                stream,
                http::StatusCode::SERVICE_UNAVAILABLE,
                "no tunnel addresses available\n",
                false,
            )
            .await
        }
        OpenSessionError::Route(RouteError::Conflict) => {
            send_error(
                stream,
                http::StatusCode::CONFLICT,
                "tunnel lease superseded\n",
                false,
            )
            .await
        }
        OpenSessionError::Route(RouteError::Unavailable) => {
            send_error(
                stream,
                http::StatusCode::SERVICE_UNAVAILABLE,
                "packet router unavailable\n",
                false,
            )
            .await
        }
    }
}

fn set_version_headers(headers: &mut http::HeaderMap) {
    headers.insert(
        HEADER_VERSION,
        http::HeaderValue::from_static(PROTOCOL_VERSION),
    );
    headers.insert(
        HEADER_MIN_VERSION,
        http::HeaderValue::from_static(PROTOCOL_VERSION),
    );
    headers.insert(
        HEADER_MAX_VERSION,
        http::HeaderValue::from_static(PROTOCOL_VERSION),
    );
}

pub(crate) fn address_response(
    lease: &Lease,
    assigned: bool,
    value: &[u8],
) -> Result<(Bytes, bool)> {
    let requests = decode_address_request(value)?;
    let mut responses = Vec::with_capacity(requests.len() + 1);
    let mut requested_ipv4 = false;
    for request in requests {
        let prefix = match request.prefix {
            IpNet::V4(_) if !requested_ipv4 => {
                requested_ipv4 = true;
                IpNet::V4(Ipv4Net::new(lease.address, 32).expect("IPv4 /32 is valid"))
            }
            IpNet::V4(_) => {
                IpNet::V4(Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 32).expect("IPv4 /32 is valid"))
            }
            IpNet::V6(_) => {
                IpNet::V6(Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 128).expect("IPv6 /128 is valid"))
            }
        };
        responses.push(Address {
            request_id: request.request_id,
            prefix,
        });
    }
    if assigned && !requested_ipv4 {
        responses.push(Address {
            request_id: 0,
            prefix: IpNet::V4(Ipv4Net::new(lease.address, 32).expect("IPv4 /32 is valid")),
        });
    }
    let assignment = encode_address_assign(&responses)?;
    let mut control = BytesMut::with_capacity(assignment.len() + 32);
    append_capsule(&mut control, CAPSULE_ADDRESS_ASSIGN, &assignment)?;
    let becomes_assigned = assigned || requested_ipv4;
    if becomes_assigned {
        let routes = encode_route_advertisement(&[Route {
            start: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            end: IpAddr::V4(Ipv4Addr::BROADCAST),
            protocol: 0,
        }])?;
        append_capsule(&mut control, CAPSULE_ROUTE_ADVERTISEMENT, &routes)?;
    }
    Ok((control.freeze(), becomes_assigned))
}

pub(crate) async fn inject_packet(session: &Session, packet: Bytes, mtu: u16) -> Result<()> {
    if packet.len() > usize::from(mtu) {
        session.services().metrics.dropped_from_client();
        return Ok(());
    }
    let Ok(info) = parse_ipv4(&packet) else {
        session.services().metrics.dropped_from_client();
        return Ok(());
    };
    if info.source != session.lease.address {
        session.services().metrics.dropped_from_client();
        return Ok(());
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
    Ok(())
}

async fn send_downlink<S, B, SendHandler>(
    session: &Session,
    packet: Bytes,
    mtu: u16,
    datagram_sender: &mut h3_datagram::datagram_handler::DatagramSender<SendHandler, B>,
    send_stream: &mut h3::server::RequestStream<S, B>,
    icmp_after: &mut Instant,
    diagnostics: &mut Http3Diagnostics,
) -> Result<()>
where
    S: h3::quic::SendStream<B>,
    B: Buf + From<Bytes>,
    SendHandler: h3_datagram::quic_traits::SendDatagram<B>,
{
    if packet.len() > usize::from(mtu) {
        match fragment_ipv4(&packet, usize::from(mtu)) {
            Ok(fragments) => {
                session.services().metrics.mtu_fragmented();
                for fragment in fragments {
                    send_one(session, fragment, datagram_sender, send_stream, diagnostics).await?;
                }
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
    if !diagnostics.datagrams_enabled {
        let mut control = BytesMut::with_capacity(packet.len() + 16);
        append_ip_capsule(&mut control, &packet)?;
        let mut count = 1;
        let mut bytes = packet.len();
        session.services().metrics.sent_to_client();
        session.usage.downloaded(packet.len() as u64, 1);
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
        diagnostics.sends.capsule_submitted(bytes, count as u64);
        send_h3_data(send_stream, control.freeze().into(), &session.cancellation).await?;
        return Ok(());
    }
    send_one(session, packet, datagram_sender, send_stream, diagnostics).await
}

async fn send_one<S, B, SendHandler>(
    session: &Session,
    packet: Bytes,
    datagram_sender: &mut h3_datagram::datagram_handler::DatagramSender<SendHandler, B>,
    send_stream: &mut h3::server::RequestStream<S, B>,
    diagnostics: &mut Http3Diagnostics,
) -> Result<()>
where
    S: h3::quic::SendStream<B>,
    B: Buf + From<Bytes>,
    SendHandler: h3_datagram::quic_traits::SendDatagram<B>,
{
    let mut value = BytesMut::with_capacity(packet.len() + 1);
    value.extend_from_slice(&[0]);
    value.extend_from_slice(&packet);
    match datagram_sender.send_datagram(value.freeze().into()) {
        Ok(()) => diagnostics.sends.datagram_queued(packet.len()),
        Err(error) => match datagram_error_kind(&error) {
            DatagramErrorKind::TooLarge => {
                session.services().metrics.datagram_oversize();
                diagnostics.fallback(DatagramErrorKind::TooLarge, packet.len());
                let mut control = BytesMut::with_capacity(packet.len() + 16);
                append_ip_capsule(&mut control, &packet)?;
                diagnostics.sends.capsule_submitted(packet.len(), 1);
                send_h3_data(send_stream, control.freeze().into(), &session.cancellation).await?;
            }
            DatagramErrorKind::NotAvailable => {
                diagnostics.fallback(DatagramErrorKind::NotAvailable, packet.len());
                diagnostics.disable_datagrams("not_available");
                let mut control = BytesMut::with_capacity(packet.len() + 16);
                append_ip_capsule(&mut control, &packet)?;
                diagnostics.sends.capsule_submitted(packet.len(), 1);
                send_h3_data(send_stream, control.freeze().into(), &session.cancellation).await?;
            }
            DatagramErrorKind::Connection => return Err(error.into()),
        },
    }
    session.services().metrics.sent_to_client();
    session.usage.downloaded(packet.len() as u64, 1);
    Ok(())
}

async fn send_h3_data<S, B>(
    stream: &mut h3::server::RequestStream<S, B>,
    data: B,
    cancellation: &CancellationToken,
) -> Result<()>
where
    S: h3::quic::SendStream<B>,
    B: Buf,
{
    tokio::select! {
        result = stream.send_data(data) => {
            result?;
            Ok(())
        }
        _ = cancellation.cancelled() => {
            Err(SessionCancelled.into())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

pub(crate) fn append_ip_capsule(output: &mut BytesMut, packet: &[u8]) -> Result<()> {
    append_varint(output, CAPSULE_DATAGRAM)?;
    append_varint(output, (packet.len() + 1) as u64)?;
    output.extend_from_slice(&[0]);
    output.extend_from_slice(packet);
    Ok(())
}

pub(crate) fn decode_ip_bytes(value: Bytes) -> std::result::Result<Bytes, MasqueError> {
    let (context_id, consumed) = parse_varint(&value)?;
    if context_id != 0 {
        return Err(MasqueError::UnknownContext(context_id));
    }
    if consumed == value.len() {
        return Err(MasqueError::EmptyIpDatagram);
    }
    Ok(value.slice(consumed..))
}

fn append_capsule(output: &mut BytesMut, capsule_type: u64, value: &[u8]) -> Result<()> {
    if value.len() > MAX_CAPSULE_SIZE {
        return Err(MasqueError::CapsuleTooLarge.into());
    }
    append_varint(output, capsule_type)?;
    append_varint(output, value.len() as u64)?;
    output.extend_from_slice(value);
    Ok(())
}

fn append_varint(output: &mut BytesMut, value: u64) -> Result<()> {
    match value {
        0..=63 => output.extend_from_slice(&[value as u8]),
        64..=16_383 => output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        16_384..=1_073_741_823 => {
            output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes())
        }
        1_073_741_824..=0x3fff_ffff_ffff_ffff => {
            output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes())
        }
        _ => return Err(MasqueError::VarIntTooLarge.into()),
    }
    Ok(())
}

pub(crate) fn take_capsule(buffer: &mut BytesMut) -> Result<Option<(u64, Bytes)>> {
    let (capsule_type, type_length) = match parse_varint(buffer) {
        Ok(value) => value,
        Err(MasqueError::TruncatedVarInt) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let (length, length_length) = match parse_varint(&buffer[type_length..]) {
        Ok(value) => value,
        Err(MasqueError::TruncatedVarInt) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if length > MAX_CAPSULE_SIZE as u64 {
        return Err(MasqueError::CapsuleTooLarge.into());
    }
    let header = type_length + length_length;
    let length = length as usize;
    if buffer.len() < header + length {
        return Ok(None);
    }
    buffer.advance(header);
    Ok(Some((capsule_type, buffer.split_to(length).freeze())))
}

fn selected_mtu(responder: &Option<MtuResponder>, configured: u16) -> u16 {
    responder
        .as_ref()
        .map(|responder| responder.selected)
        .unwrap_or(configured)
}

struct MtuResponder {
    token: MtuToken,
    maximum: u16,
    selected: u16,
    offered: Instant,
    probes: usize,
    proven: [bool; (MAX_DISCOVERED_MTU - SAFE_MTU + 1) as usize],
    committed: bool,
}

impl MtuResponder {
    fn new(maximum: u16) -> Self {
        Self {
            token: rand::random(),
            maximum: maximum.min(MAX_DISCOVERED_MTU),
            selected: maximum,
            offered: Instant::now(),
            probes: 0,
            proven: [false; (MAX_DISCOVERED_MTU - SAFE_MTU + 1) as usize],
            committed: false,
        }
    }

    fn offer(&self) -> String {
        hex::encode(self.token)
    }

    fn is_probe(&self, value: &[u8]) -> bool {
        value.first() == Some(&1)
    }

    fn accept_probe(&mut self, value: &[u8]) -> Result<bool> {
        let probe = decode_mtu_probe(value)?;
        if self.committed
            || self.offered.elapsed() > Duration::from_secs(3)
            || self.probes >= MAX_MTU_PROBES
            || probe.token != self.token
            || probe.size > self.maximum
        {
            return Err(MasqueError::InvalidMtuMessage.into());
        }
        self.probes += 1;
        Ok(true)
    }

    fn probe_echoed(&mut self, value: &[u8]) -> Result<()> {
        let MtuProbe { size, .. } = decode_mtu_probe(value)?;
        self.proven[usize::from(size - SAFE_MTU)] = true;
        Ok(())
    }

    fn commit(&mut self, value: &[u8]) -> Result<[u8; 18]> {
        let selected = decode_mtu_selection(value, self.token)?;
        if selected < SAFE_MTU
            || selected > self.maximum
            || (selected > SAFE_MTU && !self.proven[usize::from(selected - SAFE_MTU)])
            || (self.committed && selected != self.selected)
        {
            return Err(MasqueError::InvalidMtuMessage.into());
        }
        self.selected = selected;
        self.committed = true;
        Ok(encode_mtu_selection(self.token, selected))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::session::{
        Authenticated, AuthenticationError, Authenticator, ClientIdentity, LeaseAllocator,
        LeaseRequest, NoopCleanup, NoopMetrics, NoopUsage, PacketQueue, PacketRouter, QueueConfig,
        RouteRequest, RouteSession, TokenCancellation,
    };
    use futures_util::future::BoxFuture;
    use std::sync::Mutex;

    #[test]
    fn tunnel_termination_distinguishes_normal_closes_from_failures() {
        use h3::error::{Code, ConnectionError, StreamError};
        for (error, reason, unexpected) in [
            (
                StreamError::RemoteTerminate {
                    code: Code::H3_NO_ERROR,
                },
                "h3_no_error",
                false,
            ),
            (
                StreamError::RemoteTerminate {
                    code: Code::H3_REQUEST_CANCELLED,
                },
                "client_cancelled",
                false,
            ),
            (StreamError::RemoteClosing, "peer_closing", false),
            (
                StreamError::RemoteTerminate {
                    code: Code::H3_MESSAGE_ERROR,
                },
                "h3_stream_error",
                true,
            ),
            (
                StreamError::ConnectionError(ConnectionError::Timeout),
                "quic_timeout",
                true,
            ),
        ] {
            let result = Err(anyhow::Error::new(error).context("stream operation"));
            let termination = tunnel_termination(&result, false, None);
            assert_eq!(termination.reason, reason);
            assert_eq!(termination.unexpected, unexpected);
        }
        let result = Err(SessionCancelled.into());
        assert_eq!(
            tunnel_termination(&result, false, None),
            TunnelTermination::normal("cancelled")
        );
        let result = Err(RouteError::Unavailable.into());
        assert_eq!(
            tunnel_termination(&result, true, None),
            TunnelTermination::normal("cancelled")
        );
        assert_eq!(
            tunnel_termination(&result, false, None).reason,
            "router_error"
        );
        let result = Err(MasqueError::InvalidMtuMessage.into());
        let termination =
            tunnel_termination(&result, true, Some(&quinn::ConnectionError::LocallyClosed));
        assert_eq!(termination.reason, "capsule_protocol_error");
        assert!(termination.unexpected);
        for reason in ["client_eof", "cancelled", "downlink_closed"] {
            assert_eq!(
                tunnel_termination(&Ok(reason), false, None),
                TunnelTermination::normal(reason)
            );
        }
    }

    #[test]
    fn quic_termination_uses_codes_not_peer_reason_text() {
        for (code, unexpected) in [(0_u32, false), (0x100, false), (0x102, true)] {
            let close = quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                error_code: code.into(),
                reason: Bytes::from_static(b"untrusted peer close reason"),
            });
            let termination = tunnel_termination(
                &Err(anyhow::anyhow!("datagram send failed")),
                false,
                Some(&close),
            );
            assert_eq!(termination.unexpected, unexpected);
            assert!(!format!("{termination:?}").contains("untrusted"));
            if unexpected {
                assert_eq!(termination.code, Some(u64::from(code)));
            }
        }
        assert_eq!(
            quic_termination(&quinn::ConnectionError::Reset).reason,
            "quic_reset"
        );
        assert_eq!(
            quic_termination(&quinn::ConnectionError::TimedOut).reason,
            "quic_timeout"
        );
        assert!(!quic_termination(&quinn::ConnectionError::LocallyClosed).unexpected);
    }

    #[test]
    fn capsule_fallback_counters_bound_first_event_and_count_submissions() {
        let mut sends = Http3SendCounters::default();
        sends.datagram_queued(100);
        assert!(sends.fallback(DatagramErrorKind::TooLarge, 1300));
        sends.capsule_submitted(1300, 1);
        for _ in 0..10_000 {
            assert!(!sends.fallback(DatagramErrorKind::TooLarge, 1400));
        }
        assert!(sends.fallback(DatagramErrorKind::NotAvailable, 800));
        assert!(!sends.fallback(DatagramErrorKind::NotAvailable, 800));
        assert!(!sends.fallback(DatagramErrorKind::Connection, 800));
        sends.capsule_submitted(900, 3);
        assert_eq!(sends.datagram_queued_packets, 1);
        assert_eq!(sends.datagram_queued_ip_bytes, 100);
        assert_eq!(sends.capsule_submitted_packets, 4);
        assert_eq!(sends.capsule_submitted_ip_bytes, 2200);
        assert_eq!(sends.oversize_fallback_packets, 10_001);
        assert_eq!(sends.oversize_fallback_ip_bytes, 14_001_300);
        assert_eq!(sends.max_oversize_ip_bytes, 1400);
        assert_eq!(sends.unavailable_fallback_packets, 2);
    }

    #[test]
    fn ip_datagram_capacity_accounts_for_both_context_headers() {
        assert_eq!(ip_datagram_capacity(None, 0), None);
        assert_eq!(ip_datagram_capacity(Some(1), 0), Some(0));
        for stream_id in [0, 252, 256, 65_532, 65_536, 4_294_967_292, 4_294_967_296] {
            let overhead = crate::wire::masque::encode_varint(stream_id / 4)
                .unwrap()
                .len()
                + 1;
            assert_eq!(
                ip_datagram_capacity(Some(1400), stream_id),
                Some(1400 - overhead)
            );
        }
    }

    #[derive(Clone, Default)]
    struct LogCapture(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for LogCapture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn lease() -> Lease {
        Lease {
            address: "10.66.0.2".parse().unwrap(),
            prefix_len: 24,
            gateway: "10.66.0.1".parse().unwrap(),
            opaque_id: 1,
        }
    }

    #[test]
    fn accepts_only_canonical_percent_encoded_connect_ip_path() {
        let mut valid = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("/.well-known/masque/ip/%2a/%2A/")
            .body(())
            .unwrap();
        valid.extensions_mut().insert(Protocol::CONNECT_IP);
        assert!(is_connect_ip(&valid));

        let mut decoded = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("/.well-known/masque/ip/*/*/")
            .body(())
            .unwrap();
        decoded.extensions_mut().insert(Protocol::CONNECT_IP);
        assert!(!is_connect_ip(&decoded));
    }

    #[test]
    fn web_requests_preserve_http3_authority_and_body() {
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://porta.example/portal/login?next=%2Fportal")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(())
            .unwrap();
        let peer = "192.0.2.10".parse().unwrap();
        let context = web_request_context(&request, Bytes::from_static(b"token=value"), peer);
        assert_eq!(context.host, "porta.example");
        assert_eq!(context.path, "/portal/login");
        assert_eq!(context.query, "next=%2Fportal");
        assert_eq!(context.body, b"token=value");
        assert_eq!(context.peer_ip, Some(peer));
        assert_eq!(context.client_ip, Some(peer));
    }

    #[test]
    fn address_assignment_precedes_route_and_uses_context_zero() {
        let request = crate::wire::masque::encode_address_request(&[Address {
            request_id: 7,
            prefix: IpNet::V4(Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 32).unwrap()),
        }])
        .unwrap();
        let (control, assigned) = address_response(&lease(), false, &request).unwrap();
        assert!(assigned);
        let mut buffered = BytesMut::from(control.as_ref());
        let (first, assignment) = take_capsule(&mut buffered).unwrap().unwrap();
        assert_eq!(first, CAPSULE_ADDRESS_ASSIGN);
        let assigned = decode_address_assign(&assignment).unwrap();
        assert_eq!(assigned[0].request_id, 7);
        assert_eq!(assigned[0].prefix.addr(), IpAddr::V4(lease().address));
        let (second, route) = take_capsule(&mut buffered).unwrap().unwrap();
        assert_eq!(second, CAPSULE_ROUTE_ADVERTISEMENT);
        assert_eq!(
            decode_route_advertisement(&route).unwrap()[0].end,
            IpAddr::V4(Ipv4Addr::BROADCAST)
        );

        let mut datagram = BytesMut::new();
        append_ip_capsule(&mut datagram, &[0x45; 20]).unwrap();
        let (kind, value) = take_capsule(&mut datagram).unwrap().unwrap();
        assert_eq!(kind, CAPSULE_DATAGRAM);
        assert_eq!(value[0], 0);
    }

    #[test]
    fn mtu_selection_requires_an_echoed_candidate() {
        let mut responder = MtuResponder::new(1400);
        let token = responder.token;
        assert!(responder
            .commit(&encode_mtu_selection(token, 1200))
            .is_err());
        let probe = crate::wire::masque::encode_mtu_probe(MtuProbe {
            token,
            sequence: 1,
            size: 1200,
        })
        .unwrap();
        assert!(responder.accept_probe(&probe).unwrap());
        responder.probe_echoed(&probe).unwrap();
        assert_eq!(
            responder
                .commit(&encode_mtu_selection(token, 1200))
                .unwrap(),
            encode_mtu_selection(token, 1200)
        );
    }

    struct FakeAuthenticator;

    impl Authenticator for FakeAuthenticator {
        fn authenticate(
            &self,
            _request: AuthenticationRequest,
        ) -> BoxFuture<'static, Result<Authenticated, AuthenticationError>> {
            Box::pin(async {
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

    struct FakeLeases;

    impl LeaseAllocator for FakeLeases {
        fn acquire(&self, _request: LeaseRequest) -> BoxFuture<'static, Result<Lease, LeaseError>> {
            Box::pin(async { Ok(lease()) })
        }
        fn release(&self, _lease: &Lease) {}
    }

    struct FakeRouter {
        packets: Arc<Mutex<Vec<Bytes>>>,
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
            _lease: Ipv4Addr,
            packet: Bytes,
        ) -> BoxFuture<'static, Result<(), RouteError>> {
            let packets = self.packets.clone();
            Box::pin(async move {
                packets.lock().unwrap().push(packet);
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
    async fn fake_router_accepts_only_assigned_source_and_close_logs_accounting_once() {
        let logs = LogCapture::default();
        let writer = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::INFO)
            .with_writer(move || writer.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let packets = Arc::new(Mutex::new(Vec::new()));
        let services = Arc::new(Services {
            authenticator: Arc::new(FakeAuthenticator),
            leases: Arc::new(FakeLeases),
            router: Arc::new(FakeRouter {
                packets: packets.clone(),
                downlink: PacketQueue::new(QueueConfig::MASQUE, -1, Arc::new(NoopMetrics)),
            }),
            usage: Arc::new(NoopUsage),
            metrics: Arc::new(NoopMetrics),
        });
        let session = services
            .open(OpenSessionRequest {
                authentication: AuthenticationRequest {
                    bearer_token: "0123456789abcdef".into(),
                    proof: DeviceProof::default(),
                    method: http::Method::CONNECT,
                    path: MASQUE_PATH.into(),
                    peer: "127.0.0.1:1234".parse().unwrap(),
                },
                group_id: None,
                route: RouteKind::ConnectIp,
                transport: "masque-h3-datagram".into(),
            })
            .await
            .unwrap();
        let mut packet = vec![0; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
        packet[12..16].copy_from_slice(&[10, 66, 0, 2]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        inject_packet(&session, Bytes::from(packet.clone()), 1400)
            .await
            .unwrap();
        packet[12] = 192;
        inject_packet(&session, Bytes::from(packet), 1400)
            .await
            .unwrap();
        assert_eq!(packets.lock().unwrap().len(), 1);
        session.usage.downloaded(1000, 2);
        session.close_with_reason("client_eof");
        session.close();
        drop(session);
        let output = logs.0.lock().unwrap();
        let events: Vec<serde_json::Value> = std::str::from_utf8(&output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let closes: Vec<_> = events
            .iter()
            .filter(|event| event["fields"]["message"] == "tunnel disconnected")
            .collect();
        assert_eq!(closes.len(), 1);
        let fields = &closes[0]["fields"];
        assert_eq!(fields["reason"], "client_eof");
        assert_eq!(fields["uploaded_ip_bytes"], 20);
        assert_eq!(fields["uploaded_ip_packets"], 1);
        assert_eq!(fields["downlink_accounted_ip_bytes"], 1000);
        assert_eq!(fields["downlink_accounted_ip_packets"], 2);
        assert_eq!(fields["account_id"], "account");
        let opened = events
            .iter()
            .find(|event| event["fields"]["message"] == "tunnel connected")
            .unwrap();
        assert_eq!(opened["fields"]["tunnel_id"], fields["tunnel_id"]);
    }
}
