use std::collections::HashMap;
use std::future::poll_fn;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Version};
use ipnet::Ipv4Net;
use porta_wire::frame;
use porta_wire::ip::{FlowKey, PacketClass, PacketMetadata};
use rand::RngCore as _;
use rustls::pki_types::ServerName;
#[cfg(unix)]
use std::os::fd::AsRawFd as _;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket as _;
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::{mpsc, Notify};
use tokio::time::{sleep, timeout, Instant};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tokio_util::task::{AbortOnDropHandle, TaskTracker};
use url::Url;

use super::h2_queue::{EnqueueError, UploadQueue};
use super::{
    valid_unicast, CancellationGuard, ClientConfig, ClientError, Connection, ConnectionInner,
    DeliveryMode, FailureSignal, Inbound, Lease, Outbound, Transport, TUNNEL_PATH,
};

const LANE_COUNT: usize = 4;
const UPLOAD_BATCH_PACKETS: usize = 16;
const UPLOAD_BATCH_BYTES: usize = 16 << 10;
const DOWNSTREAM_PACKETS: usize = 64;
const CONTROL_BURST: usize = 4;
const FLOW_LIMIT: usize = 4096;
const NO_FLOW_INDEX: u16 = u16::MAX;
const _: () = assert!(FLOW_LIMIT < NO_FLOW_INDEX as usize);
const RETRY_INITIAL: Duration = Duration::from_millis(100);
const RETRY_MAXIMUM: Duration = Duration::from_secs(2);

#[derive(Clone, Copy)]
struct FlowEntry {
    flow: FlowKey,
    previous: u16,
    next: u16,
    lane: u8,
}

struct FlowTable {
    assignments: HashMap<FlowKey, u16>,
    entries: Vec<FlowEntry>,
    free: Vec<u16>,
    oldest: u16,
    newest: u16,
}

impl Default for FlowTable {
    fn default() -> Self {
        Self {
            assignments: HashMap::new(),
            entries: Vec::new(),
            free: Vec::new(),
            oldest: NO_FLOW_INDEX,
            newest: NO_FLOW_INDEX,
        }
    }
}

impl FlowTable {
    fn assignment(&self, flow: &FlowKey) -> Option<(u16, usize)> {
        let index = *self.assignments.get(flow)?;
        Some((index, usize::from(self.entries[usize::from(index)].lane)))
    }

    fn assign(&mut self, flow: FlowKey, lane: usize) {
        if let Some(index) = self.assignments.get(&flow).copied() {
            self.entries[usize::from(index)].lane = lane as u8;
            self.touch(index);
            return;
        }
        if self.assignments.len() >= FLOW_LIMIT {
            self.evict_oldest();
        }
        let entry = FlowEntry {
            flow,
            previous: NO_FLOW_INDEX,
            next: NO_FLOW_INDEX,
            lane: lane as u8,
        };
        let index = if let Some(index) = self.free.pop() {
            self.entries[usize::from(index)] = entry;
            index
        } else {
            let index = u16::try_from(self.entries.len()).expect("flow table index fits in u16");
            self.entries.push(entry);
            index
        };
        self.assignments.insert(flow, index);
        self.link_newest(index);
    }

    fn remove(&mut self, flow: &FlowKey) {
        if let Some(index) = self.assignments.remove(flow) {
            self.unlink(index);
            self.free.push(index);
        }
    }

    fn touch(&mut self, index: u16) {
        if index != self.newest {
            self.unlink(index);
            self.link_newest(index);
        }
    }

    fn evict_oldest(&mut self) {
        debug_assert_ne!(self.oldest, NO_FLOW_INDEX);
        let index = self.oldest;
        let flow = self.entries[usize::from(index)].flow;
        let removed = self.assignments.remove(&flow);
        debug_assert_eq!(removed, Some(index));
        self.unlink(index);
        self.free.push(index);
    }

    fn unlink(&mut self, index: u16) {
        let entry = self.entries[usize::from(index)];
        if entry.previous == NO_FLOW_INDEX {
            self.oldest = entry.next;
        } else {
            self.entries[usize::from(entry.previous)].next = entry.next;
        }
        if entry.next == NO_FLOW_INDEX {
            self.newest = entry.previous;
        } else {
            self.entries[usize::from(entry.next)].previous = entry.previous;
        }
    }

    fn link_newest(&mut self, index: u16) {
        let previous = self.newest;
        let entry = &mut self.entries[usize::from(index)];
        entry.previous = previous;
        entry.next = NO_FLOW_INDEX;
        if previous == NO_FLOW_INDEX {
            self.oldest = index;
        } else {
            self.entries[usize::from(previous)].next = index;
        }
        self.newest = index;
    }
}

struct Lane {
    index: usize,
    upload: Arc<UploadQueue>,
    downstream: mpsc::Sender<Bytes>,
    active: AtomicBool,
    remote_address: Mutex<Option<SocketAddr>>,
}

struct Group {
    config: ClientConfig,
    endpoint: Url,
    session: String,
    lanes: [Arc<Lane>; LANE_COUNT],
    lease: Mutex<Option<Lease>>,
    flows: Mutex<FlowTable>,
    established: AtomicBool,
    failure: Arc<FailureSignal>,
    cancellation: CancellationToken,
    state_changed: Notify,
    download_ready: Notify,
    inbound: mpsc::Sender<Inbound>,
}

struct LaneConnection {
    sender: ::h2::SendStream<Bytes>,
    receiver: ::h2::RecvStream,
    driver: AbortOnDropHandle<Result<(), ::h2::Error>>,
    remote_address: SocketAddr,
    lease: Lease,
}

pub(super) async fn connect(config: ClientConfig) -> Result<Connection, ClientError> {
    let origin = parse_origin(&config.url)?;
    let endpoint = origin
        .join(TUNNEL_PATH)
        .map_err(|error| ClientError::permanent(error.to_string()))?;
    let session = new_session_id()?;
    let cancellation = config.cancellation.child_token();
    let mut setup_guard = CancellationGuard::new(cancellation.clone());
    let tasks = TaskTracker::new();
    let (inbound_tx, inbound_rx) = mpsc::channel(256);
    let (outbound_tx, outbound_rx) = mpsc::channel(256);
    let failure = Arc::new(FailureSignal::default());

    let mut receivers = Vec::with_capacity(LANE_COUNT);
    let lanes = std::array::from_fn(|index| {
        let (downstream, receiver) = mpsc::channel(DOWNSTREAM_PACKETS);
        receivers.push(receiver);
        let upload = Arc::new(UploadQueue::new());
        upload.deactivate_and_clear();
        Arc::new(Lane {
            index,
            upload,
            downstream,
            active: AtomicBool::new(false),
            remote_address: Mutex::new(None),
        })
    });
    let group = Arc::new(Group {
        config,
        endpoint,
        session,
        lanes,
        lease: Mutex::new(None),
        flows: Mutex::new(FlowTable::default()),
        established: AtomicBool::new(false),
        failure: failure.clone(),
        cancellation: cancellation.clone(),
        state_changed: Notify::new(),
        download_ready: Notify::new(),
        inbound: inbound_tx,
    });

    for lane in &group.lanes {
        tasks.spawn(run_lane(group.clone(), lane.clone()));
    }
    if let Err(error) = wait_for_startup(&group).await {
        shutdown_failed_setup(&group, &tasks).await;
        return Err(error);
    }
    group.established.store(true, Ordering::Release);

    let lease = group
        .lease
        .lock()
        .expect("HTTP/2 lease lock poisoned")
        .expect("required lane capacity established a lease");
    let remote_address = group.lanes[0]
        .remote_address
        .lock()
        .expect("HTTP/2 lane address lock poisoned")
        .expect("control lane has a remote address");

    tasks.spawn(dispatch_outbound(group.clone(), outbound_rx));
    tasks.spawn(merge_downstream(group.clone(), receivers));
    tasks.spawn(monitor_capacity(group));

    setup_guard.disarm();
    Ok(Connection {
        lease,
        remote_address,
        transport: Transport::Http2,
        delivery_mode: DeliveryMode::Framed,
        mtu_automatic: false,
        mtu_ceiling: None,
        inner: Arc::new(ConnectionInner {
            outbound: outbound_tx,
            inbound: tokio::sync::Mutex::new(inbound_rx),
            failure,
            cancellation,
            tasks,
            closed: AtomicBool::new(false),
        }),
    })
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

fn new_session_id() -> Result<String, ClientError> {
    let mut random = [0_u8; 18];
    rand::rng().fill_bytes(&mut random);
    let session = URL_SAFE_NO_PAD.encode(random);
    if session.len() < 16 {
        return Err(ClientError::permanent(
            "generated HTTP/2 lane session is too short",
        ));
    }
    Ok(session)
}

async fn wait_for_startup(group: &Group) -> Result<(), ClientError> {
    timeout(group.config.timeout, async {
        loop {
            if group.required_capacity() {
                return Ok(());
            }
            if let Some(error) = group.failure() {
                return Err(error);
            }
            let changed = group.state_changed.notified();
            if group.required_capacity() {
                return Ok(());
            }
            tokio::select! {
                _ = group.cancellation.cancelled() => {
                    return Err(group.failure().unwrap_or(ClientError::Closed));
                }
                _ = changed => {}
            }
        }
    })
    .await
    .map_err(|_| ClientError::unavailable("establish HTTP/2 lane capacity timed out"))?
}

async fn shutdown_failed_setup(group: &Group, tasks: &TaskTracker) {
    group.cancellation.cancel();
    for lane in &group.lanes {
        lane.upload.close();
    }
    tasks.close();
    let _ = timeout(Duration::from_secs(1), tasks.wait()).await;
}

async fn run_lane(group: Arc<Group>, lane: Arc<Lane>) {
    let mut backoff = RETRY_INITIAL;
    loop {
        if group.cancellation.is_cancelled() {
            return;
        }
        let connection = tokio::select! {
            _ = group.cancellation.cancelled() => return,
            result = timeout(group.config.timeout, establish_lane(&group, lane.index)) => {
                match result {
                    Ok(result) => result,
                    Err(_) => Err(ClientError::unavailable(format!(
                        "open HTTP/2 lane {} timed out",
                        lane.index
                    ))),
                }
            }
        };
        let connection = match connection {
            Ok(connection) => connection,
            Err(error) => {
                if matches!(error, ClientError::Permanent(_)) {
                    group.fail(error);
                    return;
                }
                if !wait_retry(&group.cancellation, backoff).await {
                    return;
                }
                backoff = (backoff * 2).min(RETRY_MAXIMUM);
                continue;
            }
        };
        let lease = connection.lease;
        if let Err(error) = group.accept_lease(lease) {
            close_lane(connection).await;
            group.fail(error);
            return;
        }

        backoff = RETRY_INITIAL;
        group.activate(&lane, connection.remote_address);
        let error = run_connected_lane(&group, &lane, connection).await;
        group.deactivate(&lane);
        if group.cancellation.is_cancelled() {
            return;
        }
        if matches!(error, ClientError::Permanent(_)) {
            group.fail(error);
            return;
        }
        if !wait_retry(&group.cancellation, backoff).await {
            return;
        }
        backoff = (backoff * 2).min(RETRY_MAXIMUM);
    }
}

async fn establish_lane(group: &Group, index: usize) -> Result<LaneConnection, ClientError> {
    let host = group
        .endpoint
        .host_str()
        .ok_or_else(|| ClientError::permanent("gateway URL has no hostname"))?
        .trim_matches(['[', ']']);
    let port = group
        .endpoint
        .port_or_known_default()
        .ok_or_else(|| ClientError::permanent("gateway URL has no port"))?;
    let (tcp, remote_address) = dial_tcp(
        host,
        port,
        group.config.dial_address,
        group.config.socket_protector.as_ref(),
        &group.cancellation,
    )
    .await?;
    tcp.set_nodelay(true).map_err(ClientError::unavailable)?;

    let mut tls = (*group.config.tls).clone();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|_| ClientError::permanent("gateway hostname is invalid for TLS"))?;
    let stream = TlsConnector::from(Arc::new(tls))
        .connect(server_name, tcp)
        .await
        .map_err(classify_tls_error)?;
    if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
        return Err(ClientError::unavailable("gateway did not negotiate HTTP/2"));
    }

    let (requests, connection) = ::h2::client::handshake(stream)
        .await
        .map_err(classify_h2_startup)?;
    let driver = AbortOnDropHandle::new(tokio::spawn(connection));
    let established = async {
        let mut requests = requests.ready().await.map_err(classify_h2_startup)?;
        let request = lane_request(group, index)?;
        let (response, mut sender) = requests
            .send_request(request, false)
            .map_err(classify_h2_startup)?;
        send_h2_data(
            &mut sender,
            Bytes::from_static(&[0, 0]),
            &group.cancellation,
        )
        .await?;
        let response = response.await.map_err(classify_h2_startup)?;
        validate_response(&response, &group.session, index)?;
        let lease = lease_from_headers(response.headers())?;
        Ok((sender, response.into_body(), lease))
    }
    .await;
    let (sender, receiver, lease) = match established {
        Ok(established) => established,
        Err(error) => {
            driver.abort();
            let _ = driver.await;
            return Err(error);
        }
    };

    Ok(LaneConnection {
        sender,
        receiver,
        driver,
        remote_address,
        lease,
    })
}

fn lane_request(group: &Group, index: usize) -> Result<Request<()>, ClientError> {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(group.endpoint.as_str())
        .header(http::header::CONTENT_TYPE, frame::CONTENT_TYPE)
        .header(
            http::header::AUTHORIZATION,
            format!("Bearer {}", group.config.token),
        )
        .header(frame::HEADER_VERSION, frame::VERSION)
        .header("X-Porta-Lane-Session", &group.session)
        .header("X-Porta-Lane", index)
        .header("X-Porta-Lanes", LANE_COUNT)
        .body(())
        .map_err(ClientError::permanent)?;
    let proof = group
        .config
        .proof
        .proof(Method::POST.as_str(), TUNNEL_PATH)?;
    for (name, value) in [
        ("x-porta-client-id", proof.device_id),
        ("x-porta-device-name", proof.name),
        ("x-porta-device-key", proof.public_key),
        ("x-porta-device-time", proof.timestamp),
        ("x-porta-device-nonce", proof.nonce),
        ("x-porta-device-signature", proof.signature),
    ] {
        request.headers_mut().insert(
            HeaderName::from_static(name),
            HeaderValue::from_str(&value)
                .map_err(|_| ClientError::permanent("device proof contains an invalid header"))?,
        );
    }
    Ok(request)
}

async fn dial_tcp(
    host: &str,
    port: u16,
    pinned: Option<SocketAddr>,
    protector: Option<&Arc<dyn super::SocketProtector>>,
    cancellation: &CancellationToken,
) -> Result<(TcpStream, SocketAddr), ClientError> {
    let addresses = if let Some(address) = pinned {
        vec![address]
    } else {
        tokio::net::lookup_host((host, port))
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
    for address in addresses {
        let socket = match address {
            SocketAddr::V4(_) => TcpSocket::new_v4(),
            SocketAddr::V6(_) => TcpSocket::new_v6(),
        }
        .map_err(ClientError::unavailable)?;
        if let Some(protector) = protector {
            protector.prepare(tcp_socket_descriptor(&socket))?;
        }
        let connected = tokio::select! {
            _ = cancellation.cancelled() => return Err(ClientError::Closed),
            result = socket.connect(address) => result,
        };
        match connected {
            Ok(stream) => return Ok((stream, address)),
            Err(error) => last_error = Some(error),
        }

        #[cfg(unix)]
        fn tcp_socket_descriptor(socket: &TcpSocket) -> i64 {
            i64::from(socket.as_raw_fd())
        }

        #[cfg(windows)]
        fn tcp_socket_descriptor(socket: &TcpSocket) -> i64 {
            socket.as_raw_socket() as i64
        }
    }
    Err(ClientError::unavailable(
        last_error.expect("at least one TCP address was attempted"),
    ))
}

fn classify_tls_error(error: std::io::Error) -> ClientError {
    if error
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<rustls::Error>())
        .is_some()
    {
        ClientError::permanent(format!("TLS handshake failed: {error}"))
    } else {
        ClientError::unavailable(error)
    }
}

fn classify_h2_startup(error: ::h2::Error) -> ClientError {
    if matches!(error.reason(), Some(::h2::Reason::NO_ERROR)) {
        ClientError::retryable(error)
    } else if error.is_io() || matches!(error.reason(), Some(::h2::Reason::REFUSED_STREAM)) {
        ClientError::unavailable(error)
    } else {
        ClientError::permanent(error)
    }
}

fn validate_response(
    response: &http::Response<::h2::RecvStream>,
    session: &str,
    lane: usize,
) -> Result<(), ClientError> {
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
    if response.version() != Version::HTTP_2 {
        return Err(ClientError::permanent("gateway did not negotiate HTTP/2"));
    }
    if header(response.headers(), frame::HEADER_VERSION) != Some(frame::VERSION) {
        return Err(ClientError::permanent(format!(
            "gateway selected Porta protocol {:?}, client requires {:?}",
            header(response.headers(), frame::HEADER_VERSION),
            frame::VERSION
        )));
    }
    let content_type = header(response.headers(), "content-type")
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if content_type != Some(frame::CONTENT_TYPE) {
        return Err(ClientError::permanent(
            "gateway returned an invalid tunnel content type",
        ));
    }
    let lane = lane.to_string();
    let lane_count = LANE_COUNT.to_string();
    if header(response.headers(), "x-porta-lane-session") != Some(session)
        || header(response.headers(), "x-porta-lane") != Some(lane.as_str())
        || header(response.headers(), "x-porta-lanes") != Some(lane_count.as_str())
    {
        return Err(ClientError::permanent(
            "gateway rejected HTTP/2 lane negotiation",
        ));
    }
    Ok(())
}

fn lease_from_headers(headers: &HeaderMap) -> Result<Lease, ClientError> {
    let address = header(headers, "x-porta-address")
        .ok_or_else(|| ClientError::permanent("gateway returned no IPv4 tunnel address"))?
        .parse::<Ipv4Net>()
        .map_err(|_| ClientError::permanent("gateway returned an invalid IPv4 tunnel address"))?;
    if !valid_unicast(address.addr()) || !(16..=32).contains(&address.prefix_len()) {
        return Err(ClientError::permanent(
            "gateway returned an invalid IPv4 tunnel address",
        ));
    }
    let gateway = header(headers, "x-porta-gateway")
        .ok_or_else(|| ClientError::permanent("gateway returned no IPv4 tunnel gateway"))?
        .parse::<Ipv4Addr>()
        .map_err(|_| ClientError::permanent("gateway returned an invalid IPv4 tunnel gateway"))?;
    if !valid_unicast(gateway) || gateway == address.addr() || !address.contains(&gateway) {
        return Err(ClientError::permanent(
            "gateway returned an invalid IPv4 tunnel gateway",
        ));
    }
    let mtu = header(headers, "x-porta-mtu")
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| (576..=9000).contains(value))
        .ok_or_else(|| ClientError::permanent("gateway returned an invalid tunnel MTU"))?;
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
        address,
        gateway: Some(gateway),
        dns,
        mtu,
    })
}

async fn run_connected_lane(group: &Group, lane: &Lane, connection: LaneConnection) -> ClientError {
    let LaneConnection {
        mut sender,
        mut receiver,
        driver,
        ..
    } = connection;
    let error = {
        let upload = upload_lane(group, lane, &mut sender);
        let download = download_lane(group, lane, &mut receiver);
        tokio::pin!(upload);
        tokio::pin!(download);
        tokio::select! {
            _ = group.cancellation.cancelled() => ClientError::Closed,
            result = &mut upload => result.unwrap_err_or_closed(),
            result = &mut download => result.unwrap_err_or_closed(),
        }
    };
    sender.send_reset(::h2::Reason::CANCEL);
    driver.abort();
    let _ = driver.await;
    error
}

trait ResultExt {
    fn unwrap_err_or_closed(self) -> ClientError;
}

impl ResultExt for Result<(), ClientError> {
    fn unwrap_err_or_closed(self) -> ClientError {
        match self {
            Ok(()) => ClientError::Closed,
            Err(error) => error,
        }
    }
}

async fn close_lane(mut connection: LaneConnection) {
    connection.sender.send_reset(::h2::Reason::CANCEL);
    connection.driver.abort();
    let _ = connection.driver.await;
}

async fn upload_lane(
    group: &Group,
    lane: &Lane,
    sender: &mut ::h2::SendStream<Bytes>,
) -> Result<(), ClientError> {
    loop {
        let Some(batch) = lane
            .upload
            .take_batch(
                &group.cancellation,
                UPLOAD_BATCH_PACKETS,
                UPLOAD_BATCH_BYTES,
            )
            .await
        else {
            return Err(ClientError::Closed);
        };
        let mut framed =
            Vec::with_capacity(batch.iter().map(|packet| packet.len() + 2).sum::<usize>());
        for packet in batch {
            let size = u16::try_from(packet.len())
                .map_err(|_| ClientError::permanent("packet exceeds HTTP/2 frame size"))?;
            framed.extend_from_slice(&size.to_be_bytes());
            framed.extend_from_slice(&packet);
        }
        send_h2_data(sender, Bytes::from(framed), &group.cancellation).await?;
    }
}

async fn send_h2_data(
    sender: &mut ::h2::SendStream<Bytes>,
    mut data: Bytes,
    cancellation: &CancellationToken,
) -> Result<(), ClientError> {
    while data.has_remaining() {
        sender.reserve_capacity(data.remaining());
        let capacity = tokio::select! {
            _ = cancellation.cancelled() => return Err(ClientError::Closed),
            result = poll_fn(|context| sender.poll_capacity(context)) => result,
        };
        let capacity = capacity
            .ok_or_else(|| ClientError::retryable("HTTP/2 upload stream closed"))?
            .map_err(ClientError::retryable)?;
        let length = capacity.min(data.remaining());
        sender
            .send_data(data.split_to(length), false)
            .map_err(ClientError::retryable)?;
    }
    Ok(())
}

async fn download_lane(
    group: &Group,
    lane: &Lane,
    receiver: &mut ::h2::RecvStream,
) -> Result<(), ClientError> {
    let lease = group
        .lease
        .lock()
        .expect("HTTP/2 lease lock poisoned")
        .expect("active HTTP/2 lane has a lease");
    let mut framed = BytesMut::new();
    loop {
        let data = tokio::select! {
            _ = group.cancellation.cancelled() => return Err(ClientError::Closed),
            data = receiver.data() => data,
        };
        let Some(data) = data else {
            return Err(ClientError::retryable(if framed.is_empty() {
                "HTTP/2 response stream ended"
            } else {
                "truncated HTTP/2 packet frame"
            }));
        };
        let data = data.map_err(ClientError::retryable)?;
        let length = data.len();
        framed.extend_from_slice(&data);
        receiver
            .flow_control()
            .release_capacity(length)
            .map_err(ClientError::retryable)?;
        while framed.len() >= 2 {
            let packet_length = usize::from(u16::from_be_bytes([framed[0], framed[1]]));
            if framed.len() < packet_length + 2 {
                break;
            }
            framed.advance(2);
            let packet = framed.split_to(packet_length).freeze();
            if packet.is_empty() || packet.len() > usize::from(lease.mtu) {
                continue;
            }
            let Ok(info) = porta_wire::ip::parse_ipv4(&packet) else {
                continue;
            };
            if info.destination != lease.address.addr() {
                continue;
            }
            tokio::select! {
                _ = group.cancellation.cancelled() => return Err(ClientError::Closed),
                result = lane.downstream.send(packet) => {
                    result.map_err(|_| ClientError::Closed)?;
                    group.download_ready.notify_one();
                }
            }
        }
    }
}

async fn dispatch_outbound(group: Arc<Group>, mut outbound: mpsc::Receiver<Outbound>) {
    loop {
        let outbound = tokio::select! {
            _ = group.cancellation.cancelled() => return,
            outbound = outbound.recv() => match outbound {
                Some(outbound) => outbound,
                None => return,
            }
        };
        match outbound {
            Outbound::Packet { packet, result } => {
                let _ = result.send(group.route(packet));
            }
            Outbound::Datagram { result, .. } => {
                let _ = result.send(Err(ClientError::permanent(
                    "invalid outbound operation for HTTP/2",
                )));
            }
            Outbound::Capsule { result, .. } => {
                let _ = result.send(Err(ClientError::permanent(
                    "invalid outbound operation for HTTP/2",
                )));
            }
        }
    }
}

async fn merge_downstream(group: Arc<Group>, mut receivers: Vec<mpsc::Receiver<Bytes>>) {
    let mut control_budget = CONTROL_BURST;
    let mut next_data_lane = 1;
    loop {
        if let Some(packet) =
            take_downstream(&mut receivers, &mut control_budget, &mut next_data_lane)
        {
            tokio::select! {
                _ = group.cancellation.cancelled() => return,
                result = group.inbound.send(Inbound::Packet(packet)) => {
                    if result.is_err() {
                        return;
                    }
                }
            }
            continue;
        }
        let ready = group.download_ready.notified();
        if let Some(packet) =
            take_downstream(&mut receivers, &mut control_budget, &mut next_data_lane)
        {
            tokio::select! {
                _ = group.cancellation.cancelled() => return,
                result = group.inbound.send(Inbound::Packet(packet)) => {
                    if result.is_err() {
                        return;
                    }
                }
            }
            continue;
        }
        tokio::select! {
            _ = group.cancellation.cancelled() => return,
            _ = ready => {}
        }
    }
}

fn take_downstream(
    receivers: &mut [mpsc::Receiver<Bytes>],
    control_budget: &mut usize,
    next_data_lane: &mut usize,
) -> Option<Bytes> {
    if *control_budget > 0 {
        if let Ok(packet) = receivers[0].try_recv() {
            *control_budget -= 1;
            return Some(packet);
        }
    }
    for offset in 0..LANE_COUNT - 1 {
        let index = 1 + (*next_data_lane - 1 + offset) % (LANE_COUNT - 1);
        if let Ok(packet) = receivers[index].try_recv() {
            *next_data_lane = 1 + index % (LANE_COUNT - 1);
            *control_budget = CONTROL_BURST;
            return Some(packet);
        }
    }
    if let Ok(packet) = receivers[0].try_recv() {
        *control_budget = control_budget.saturating_sub(1);
        return Some(packet);
    }
    None
}

async fn monitor_capacity(group: Arc<Group>) {
    loop {
        if group.cancellation.is_cancelled() {
            return;
        }
        if group.required_capacity() {
            let changed = group.state_changed.notified();
            if group.required_capacity() {
                tokio::select! {
                    _ = group.cancellation.cancelled() => return,
                    _ = changed => {}
                }
            }
            continue;
        }
        let recovered = timeout(group.config.timeout, async {
            loop {
                if group.required_capacity() {
                    return;
                }
                let changed = group.state_changed.notified();
                if group.required_capacity() {
                    return;
                }
                tokio::select! {
                    _ = group.cancellation.cancelled() => return,
                    _ = changed => {}
                }
            }
        })
        .await;
        if recovered.is_err() && !group.required_capacity() {
            group.fail(ClientError::retryable(
                "HTTP/2 required lane capacity unavailable: deadline exceeded",
            ));
            return;
        }
    }
}

impl Group {
    fn route(&self, packet: Bytes) -> Result<(), ClientError> {
        if let Some(error) = self.failure() {
            return Err(error);
        }
        if self.cancellation.is_cancelled() {
            return Err(ClientError::Closed);
        }
        let metadata = porta_wire::ip::classify_ipv4(&packet);
        let lane = if metadata.class == PacketClass::Control {
            self.control_lane()
        } else {
            self.data_lane(metadata, Instant::now()).or_else(|| {
                self.lanes[0]
                    .active
                    .load(Ordering::Acquire)
                    .then(|| self.lanes[0].clone())
            })
        };
        let Some(lane) = lane else {
            return Err(ClientError::retryable(
                "HTTP/2 upload capacity is unavailable",
            ));
        };
        let packet = match lane.upload.enqueue(packet, metadata, Instant::now()) {
            Ok(()) => return Ok(()),
            Err(EnqueueError::Full(_)) if metadata.class != PacketClass::Control => {
                // A healthy queue already owns this flow's prefix. Tail-drop
                // instead of moving later packets onto a faster lane.
                return Ok(());
            }
            Err(EnqueueError::Full(packet) | EnqueueError::Unavailable(packet)) => packet,
        };
        if metadata.class != PacketClass::Control {
            self.flows
                .lock()
                .expect("HTTP/2 flow lock poisoned")
                .remove(&metadata.flow);
        }
        let fallback = if metadata.class == PacketClass::Control {
            self.control_lane()
        } else {
            self.data_lane(metadata, Instant::now())
                .or_else(|| self.control_lane())
        };
        if let Some(fallback) = fallback.filter(|fallback| fallback.index != lane.index) {
            if fallback
                .upload
                .enqueue(packet, metadata, Instant::now())
                .is_ok()
            {
                return Ok(());
            }
        }
        // Bounded queue rejection is packet-level congestion, not a failed tunnel.
        Ok(())
    }

    fn control_lane(&self) -> Option<Arc<Lane>> {
        if self.lanes[0].active.load(Ordering::Acquire) {
            return Some(self.lanes[0].clone());
        }
        let now = Instant::now();
        self.lanes[1..]
            .iter()
            .filter(|lane| lane.active.load(Ordering::Acquire))
            .min_by_key(|lane| lane.upload.queued_bytes_at(now))
            .cloned()
    }

    fn data_lane(&self, metadata: PacketMetadata, now: Instant) -> Option<Arc<Lane>> {
        let mut flows = self.flows.lock().expect("HTTP/2 flow lock poisoned");
        if let Some((index, lane)) = flows.assignment(&metadata.flow) {
            if lane > 0 && lane < LANE_COUNT && self.lanes[lane].active.load(Ordering::Acquire) {
                flows.touch(index);
                return Some(self.lanes[lane].clone());
            }
            flows.remove(&metadata.flow);
        }
        let candidates = self.lanes[1..]
            .iter()
            .filter(|lane| lane.active.load(Ordering::Acquire))
            .cloned()
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return None;
        }
        let start = metadata.hash as usize % candidates.len();
        let mut selected = candidates[start].clone();
        let mut selected_bytes = selected.upload.queued_bytes_at(now);
        for offset in 1..candidates.len() {
            let candidate = &candidates[(start + offset) % candidates.len()];
            let queued = candidate.upload.queued_bytes_at(now);
            if queued < selected_bytes {
                selected = candidate.clone();
                selected_bytes = queued;
            }
        }
        flows.assign(metadata.flow, selected.index);
        Some(selected)
    }

    fn accept_lease(&self, lease: Lease) -> Result<(), ClientError> {
        let mut current = self.lease.lock().expect("HTTP/2 lease lock poisoned");
        match *current {
            None => {
                *current = Some(lease);
                Ok(())
            }
            Some(existing) if existing == lease => Ok(()),
            Some(_) if self.established.load(Ordering::Acquire) && !self.has_active_lane() => Err(
                ClientError::retryable("HTTP/2 lease changed after a full lane outage"),
            ),
            Some(_) => Err(ClientError::permanent(
                "HTTP/2 lanes returned different tunnel leases",
            )),
        }
    }

    fn activate(&self, lane: &Lane, remote_address: SocketAddr) {
        *lane
            .remote_address
            .lock()
            .expect("HTTP/2 lane address lock poisoned") = Some(remote_address);
        lane.upload.activate();
        lane.active.store(true, Ordering::Release);
        self.state_changed.notify_waiters();
    }

    fn deactivate(&self, lane: &Lane) {
        lane.active.store(false, Ordering::Release);
        lane.upload.deactivate_and_clear();
        self.state_changed.notify_waiters();
    }

    fn required_capacity(&self) -> bool {
        self.lanes[0].active.load(Ordering::Acquire)
            && self.lanes[1..]
                .iter()
                .any(|lane| lane.active.load(Ordering::Acquire))
    }

    fn has_active_lane(&self) -> bool {
        self.lanes
            .iter()
            .any(|lane| lane.active.load(Ordering::Acquire))
    }

    fn fail(&self, error: ClientError) {
        if !self.failure.set(error.clone()) {
            return;
        }
        let _ = self.inbound.try_send(Inbound::Failure(error));
        self.cancellation.cancel();
        self.state_changed.notify_waiters();
        self.download_ready.notify_waiters();
    }

    fn failure(&self) -> Option<ClientError> {
        self.failure.current()
    }
}

async fn wait_retry(cancellation: &CancellationToken, duration: Duration) -> bool {
    tokio::select! {
        _ = cancellation.cancelled() => false,
        _ = sleep(duration) => true,
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_group_with_full_upload_queues() -> (Arc<Group>, Vec<mpsc::Receiver<Bytes>>) {
        let mut receivers = Vec::with_capacity(LANE_COUNT);
        let lanes = std::array::from_fn(|index| {
            let (downstream, receiver) = mpsc::channel(1);
            receivers.push(receiver);
            Arc::new(Lane {
                index,
                upload: Arc::new(UploadQueue::with_limits(1, 64)),
                downstream,
                active: AtomicBool::new(true),
                remote_address: Mutex::new(None),
            })
        });
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let (inbound, _received) = mpsc::channel(1);
        (
            Arc::new(Group {
                config: ClientConfig {
                    url: "https://porta.test".to_owned(),
                    token: "test".to_owned(),
                    transport: Transport::Http2,
                    tls: Arc::new(tls),
                    timeout: Duration::from_secs(1),
                    dial_address: None,
                    proof: Arc::new(|_: &str, _: &str| {
                        unreachable!("queue routing test does not authenticate")
                    }),
                    socket_protector: None,
                    cancellation: CancellationToken::new(),
                },
                endpoint: Url::parse("https://porta.test/v1/tunnel").unwrap(),
                session: "test".to_owned(),
                lanes,
                lease: Mutex::new(None),
                flows: Mutex::new(FlowTable::default()),
                established: AtomicBool::new(true),
                failure: Arc::new(FailureSignal::default()),
                cancellation: CancellationToken::new(),
                state_changed: Notify::new(),
                download_ready: Notify::new(),
                inbound,
            }),
            receivers,
        )
    }

    fn tcp_packet(destination_port: u16) -> Bytes {
        let mut packet = vec![0_u8; 60];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&60_u16.to_be_bytes());
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 10]);
        packet[20..22].copy_from_slice(&40_000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = 0x02;
        Bytes::from(packet)
    }

    fn lease_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("x-porta-address", "10.66.0.2/29"),
            ("x-porta-gateway", "10.66.0.1"),
            ("x-porta-dns", "1.1.1.1"),
            ("x-porta-mtu", "1300"),
        ] {
            headers.insert(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
        }
        headers
    }

    #[test]
    fn validates_http2_lease_headers() {
        let lease = lease_from_headers(&lease_headers()).unwrap();
        assert_eq!(lease.address, "10.66.0.2/29".parse().unwrap());
        assert_eq!(lease.gateway, Some(Ipv4Addr::new(10, 66, 0, 1)));
        assert_eq!(lease.dns, Some(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(lease.mtu, 1300);

        for (name, value) in [
            ("x-porta-address", "127.0.0.1/32"),
            ("x-porta-address", "10.66.0.2/8"),
            ("x-porta-gateway", "10.66.1.1"),
            ("x-porta-dns", "169.254.1.1"),
            ("x-porta-mtu", "575"),
        ] {
            let mut headers = lease_headers();
            headers.insert(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
            assert!(matches!(
                lease_from_headers(&headers),
                Err(ClientError::Permanent(_))
            ));
        }
    }

    #[test]
    fn graceful_goaway_is_retryable() {
        assert!(matches!(
            classify_h2_startup(::h2::Error::from(::h2::Reason::NO_ERROR)),
            ClientError::Retryable(_)
        ));
        assert!(matches!(
            classify_h2_startup(::h2::Error::from(::h2::Reason::REFUSED_STREAM)),
            ClientError::TransportUnavailable(_)
        ));
        assert!(matches!(
            classify_h2_startup(::h2::Error::from(::h2::Reason::PROTOCOL_ERROR)),
            ClientError::Permanent(_)
        ));
    }

    #[test]
    fn downstream_merge_prioritizes_control_without_starving_data() {
        let mut receivers = Vec::new();
        let mut senders = Vec::new();
        for _ in 0..LANE_COUNT {
            let (sender, receiver) = mpsc::channel(8);
            senders.push(sender);
            receivers.push(receiver);
        }
        for marker in 1..=5 {
            senders[0].try_send(Bytes::from(vec![marker])).unwrap();
        }
        senders[1].try_send(Bytes::from_static(&[99])).unwrap();
        let mut budget = CONTROL_BURST;
        let mut next = 1;
        for marker in 1..=4 {
            assert_eq!(
                take_downstream(&mut receivers, &mut budget, &mut next)
                    .unwrap()
                    .as_ref(),
                &[marker]
            );
        }
        assert_eq!(
            take_downstream(&mut receivers, &mut budget, &mut next)
                .unwrap()
                .as_ref(),
            &[99]
        );
    }

    #[test]
    fn flow_table_evicts_the_least_recent_assignment_in_constant_time() {
        fn flow(index: u32) -> FlowKey {
            FlowKey {
                source: index.to_be_bytes(),
                destination_port: index as u16,
                protocol: 17,
                ..FlowKey::default()
            }
        }

        let mut table = FlowTable::default();
        for index in 0..FLOW_LIMIT as u32 {
            table.assign(flow(index), 1 + index as usize % (LANE_COUNT - 1));
        }
        let (first, _) = table.assignment(&flow(0)).unwrap();
        table.touch(first);
        table.assign(flow(FLOW_LIMIT as u32), 2);

        assert_eq!(table.assignments.len(), FLOW_LIMIT);
        assert!(table.assignment(&flow(0)).is_some());
        assert!(table.assignment(&flow(1)).is_none());
        assert_eq!(table.assignment(&flow(FLOW_LIMIT as u32)).unwrap().1, 2);
    }

    #[test]
    fn saturated_upload_queues_drop_a_packet_without_failing_the_tunnel() {
        let (group, _receivers) = test_group_with_full_upload_queues();
        let queued = tcp_packet(443);
        let metadata = porta_wire::ip::classify_ipv4(&queued);
        assert_eq!(metadata.class, PacketClass::Tcp);
        for lane in &group.lanes {
            assert!(lane
                .upload
                .enqueue(queued.clone(), metadata, Instant::now())
                .is_ok());
        }

        assert!(group.route(tcp_packet(8443)).is_ok());
        assert!(!group.cancellation.is_cancelled());
        assert!(group.failure().is_none());
    }

    #[test]
    fn saturated_healthy_lane_preserves_tcp_flow_affinity() {
        let (group, _receivers) = test_group_with_full_upload_queues();
        let packet = tcp_packet(443);
        let metadata = porta_wire::ip::classify_ipv4(&packet);
        group
            .flows
            .lock()
            .expect("HTTP/2 flow lock poisoned")
            .assign(metadata.flow, 1);
        assert!(group.lanes[1]
            .upload
            .enqueue(packet.clone(), metadata, Instant::now())
            .is_ok());

        assert!(group.route(packet).is_ok());
        assert_eq!(
            group
                .flows
                .lock()
                .expect("HTTP/2 flow lock poisoned")
                .assignment(&metadata.flow)
                .expect("flow assignment remains")
                .1,
            1
        );
        for lane in [&group.lanes[0], &group.lanes[2], &group.lanes[3]] {
            assert_eq!(lane.upload.queued_bytes_at(Instant::now()), 0);
        }
    }
}
