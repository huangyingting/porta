use crate::proxy::dial::{BoxIo, Destination, DialError, PublicConnector};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use futures_util::future::BoxFuture;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use std::error::Error;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

pub const DEVICE_ID: &str = "forward-proxy";
pub const DEFAULT_MAX_CONNECTIONS: usize = 128;
pub const COPY_BUFFER_SIZE: usize = 64 << 10;
pub const RESPONSE_BUFFER_SIZE: usize = 128 << 10;
pub const RESPONSE_FLUSH_INTERVAL: Duration = Duration::from_millis(2);
pub const TUNNEL_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

pub type BoxError = Box<dyn Error + Send + Sync>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    pub account_id: Box<str>,
    pub device_id: Box<str>,
}

pub struct AuthorizedSession {
    identity: Identity,
    cancellation: CancellationToken,
    release: Option<Box<dyn FnOnce() + Send>>,
}

impl AuthorizedSession {
    pub fn new(
        identity: Identity,
        cancellation: CancellationToken,
        release: impl FnOnce() + Send + 'static,
    ) -> Self {
        Self {
            identity,
            cancellation,
            release: Some(Box::new(release)),
        }
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }
}

impl Drop for AuthorizedSession {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            release();
        }
    }
}

pub trait Authorizer: Send + Sync + 'static {
    fn authorize<'a>(
        &'a self,
        token: &'a str,
        device_id: &'a str,
        parent_cancellation: CancellationToken,
    ) -> BoxFuture<'a, Result<AuthorizedSession, BoxError>>;
}

pub trait Connector: Send + Sync + 'static {
    fn connect<'a>(
        &'a self,
        destination: &'a Destination,
    ) -> BoxFuture<'a, Result<BoxIo, DialError>>;
}

impl Connector for PublicConnector {
    fn connect<'a>(
        &'a self,
        destination: &'a Destination,
    ) -> BoxFuture<'a, Result<BoxIo, DialError>> {
        Box::pin(async move { self.connect_destination(destination).await })
    }
}

pub trait UsageSession: Send + Sync + 'static {
    fn add_uploaded(&self, bytes: u64);
    fn add_downloaded(&self, bytes: u64);
}

pub trait UsageHooks: Send + Sync + 'static {
    fn begin(&self, identity: &Identity, kind: &'static str, target: &str)
        -> Box<dyn UsageSession>;
}

#[derive(Default)]
pub struct NoopUsage;

struct NoopUsageSession;

impl UsageHooks for NoopUsage {
    fn begin(
        &self,
        _identity: &Identity,
        _kind: &'static str,
        _target: &str,
    ) -> Box<dyn UsageSession> {
        Box::new(NoopUsageSession)
    }
}

impl UsageSession for NoopUsageSession {
    fn add_uploaded(&self, _bytes: u64) {}
    fn add_downloaded(&self, _bytes: u64) {}
}

pub trait AuthenticationLimiter: Send + Sync + 'static {
    fn reserve(&self, client: IpAddr) -> Option<Box<dyn AuthenticationReservation + '_>>;
}

pub trait AuthenticationReservation: Send {
    fn refund(self: Box<Self>);
}

pub trait FallthroughHook: Send + Sync + 'static {
    fn on_fallthrough(&self, reason: FallthroughReason);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FallthroughReason {
    OriginRequest,
    TargetsProxy,
    Camouflage,
}

pub struct ProxyRequest<'a> {
    pub method: &'a Method,
    pub authority: Option<&'a str>,
    pub uri_is_absolute: bool,
    pub extended_protocol: Option<&'a str>,
    pub tls_server_name: Option<&'a str>,
    pub headers: &'a HeaderMap,
    pub client_ip: IpAddr,
    pub cancellation: CancellationToken,
}

pub enum ProxyAction {
    Fallthrough(FallthroughReason),
    Respond(ProxyResponse),
    Connect(ConnectPlan),
}

#[derive(Debug)]
pub struct ProxyResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: &'static str,
}

pub struct ConnectPlan {
    destination: Destination,
    target: Box<str>,
    session: AuthorizedSession,
    request_cancellation: CancellationToken,
    _permit: OwnedSemaphorePermit,
}

impl ConnectPlan {
    pub fn destination(&self) -> &Destination {
        &self.destination
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn identity(&self) -> &Identity {
        self.session.identity()
    }
}

pub struct EstablishedTunnel {
    upstream: BoxIo,
    session: AuthorizedSession,
    request_cancellation: CancellationToken,
    usage: Box<dyn UsageSession>,
    _permit: OwnedSemaphorePermit,
}

pub struct ForwardProxy {
    authorizer: Arc<dyn Authorizer>,
    connector: Arc<dyn Connector>,
    usage: Arc<dyn UsageHooks>,
    limiter: Option<Arc<dyn AuthenticationLimiter>>,
    fallthrough: Option<Arc<dyn FallthroughHook>>,
    camouflage: bool,
    slots: Arc<Semaphore>,
}

impl ForwardProxy {
    pub fn new(authorizer: Arc<dyn Authorizer>) -> Self {
        Self::with_components(
            authorizer,
            Arc::new(PublicConnector::default()),
            Arc::new(NoopUsage),
            DEFAULT_MAX_CONNECTIONS,
        )
    }

    pub fn with_components(
        authorizer: Arc<dyn Authorizer>,
        connector: Arc<dyn Connector>,
        usage: Arc<dyn UsageHooks>,
        max_connections: usize,
    ) -> Self {
        let max_connections = if max_connections == 0 {
            DEFAULT_MAX_CONNECTIONS
        } else {
            max_connections
        };
        Self {
            authorizer,
            connector,
            usage,
            limiter: None,
            fallthrough: None,
            camouflage: false,
            slots: Arc::new(Semaphore::new(max_connections)),
        }
    }

    pub fn set_camouflage(&mut self, camouflage: bool) {
        self.camouflage = camouflage;
    }

    pub fn set_authentication_limiter(&mut self, limiter: Option<Arc<dyn AuthenticationLimiter>>) {
        self.limiter = limiter;
    }

    pub fn set_fallthrough_hook(&mut self, hook: Option<Arc<dyn FallthroughHook>>) {
        self.fallthrough = hook;
    }

    pub async fn prepare(&self, request: ProxyRequest<'_>) -> ProxyAction {
        if *request.method != Method::CONNECT && !request.uri_is_absolute {
            return self.fallthrough(FallthroughReason::OriginRequest);
        }
        if request_targets_proxy(&request) {
            return self.fallthrough(FallthroughReason::TargetsProxy);
        }
        if request.extended_protocol.is_some() {
            return ProxyAction::Respond(response(
                StatusCode::FORBIDDEN,
                "HTTPS CONNECT is required\n",
            ));
        }

        let reservation = if let Some(limiter) = &self.limiter {
            let Some(reservation) = limiter.reserve(request.client_ip) else {
                let mut response = response(
                    StatusCode::TOO_MANY_REQUESTS,
                    "too many proxy authentication attempts\n",
                );
                response
                    .headers
                    .insert(http::header::RETRY_AFTER, HeaderValue::from_static("5"));
                return ProxyAction::Respond(response);
            };
            Some(reservation)
        } else {
            None
        };

        let Some(token) = proxy_token(request.headers) else {
            return if self.camouflage && *request.method != Method::CONNECT {
                self.fallthrough(FallthroughReason::Camouflage)
            } else {
                ProxyAction::Respond(authentication_required())
            };
        };
        let session = match self
            .authorizer
            .authorize(&token, DEVICE_ID, request.cancellation.clone())
            .await
        {
            Ok(session) => session,
            Err(_) => {
                return if self.camouflage && *request.method != Method::CONNECT {
                    self.fallthrough(FallthroughReason::Camouflage)
                } else {
                    ProxyAction::Respond(authentication_required())
                };
            }
        };
        if let Some(reservation) = reservation {
            reservation.refund();
        }
        if *request.method != Method::CONNECT {
            return ProxyAction::Respond(response(
                StatusCode::FORBIDDEN,
                "HTTPS CONNECT is required\n",
            ));
        }

        let Some(target) = request.authority else {
            return ProxyAction::Respond(response(
                StatusCode::BAD_REQUEST,
                "invalid proxy target\n",
            ));
        };
        let destination = match crate::proxy::dial::parse_destination(target) {
            Ok(destination) => destination,
            Err(DialError::Denied(_)) => {
                return ProxyAction::Respond(response(
                    StatusCode::FORBIDDEN,
                    "proxy destination denied\n",
                ));
            }
            Err(_) => {
                return ProxyAction::Respond(response(
                    StatusCode::BAD_REQUEST,
                    "invalid proxy target\n",
                ));
            }
        };
        let permit = match Arc::clone(&self.slots).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                return ProxyAction::Respond(response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "proxy capacity reached\n",
                ));
            }
        };
        ProxyAction::Connect(ConnectPlan {
            destination,
            target: target.into(),
            session,
            request_cancellation: request.cancellation,
            _permit: permit,
        })
    }

    pub async fn establish(&self, plan: ConnectPlan) -> Result<EstablishedTunnel, ProxyResponse> {
        let cancellation = plan.session.cancellation();
        let upstream = tokio::select! {
            _ = plan.request_cancellation.cancelled() => return Err(response(
                StatusCode::BAD_GATEWAY,
                "proxy destination unavailable\n",
            )),
            _ = cancellation.cancelled() => return Err(response(
                StatusCode::BAD_GATEWAY,
                "proxy destination unavailable\n",
            )),
            result = self.connector.connect(&plan.destination) => {
                result.map_err(dial_response)?
            }
        };
        let usage = self
            .usage
            .begin(plan.session.identity(), "https-connect", &plan.target);
        Ok(EstablishedTunnel {
            upstream,
            session: plan.session,
            request_cancellation: plan.request_cancellation,
            usage,
            _permit: plan._permit,
        })
    }

    pub async fn relay<C>(&self, tunnel: EstablishedTunnel, client: C) -> io::Result<()>
    where
        C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (reader, writer) = tokio::io::split(client);
        relay_tunnel(tunnel, reader, writer).await
    }

    pub async fn relay_split<R, W>(
        &self,
        tunnel: EstablishedTunnel,
        reader: R,
        writer: W,
    ) -> io::Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        relay_tunnel(tunnel, reader, writer).await
    }

    fn fallthrough(&self, reason: FallthroughReason) -> ProxyAction {
        if let Some(hook) = &self.fallthrough {
            hook.on_fallthrough(reason);
        }
        ProxyAction::Fallthrough(reason)
    }
}

pub fn proxy_token(headers: &HeaderMap) -> Option<Zeroizing<String>> {
    let header = headers.get(http::header::PROXY_AUTHORIZATION)?.as_bytes();
    const PREFIX: &[u8] = b"Basic ";
    if header.len() <= PREFIX.len() || !header[..PREFIX.len()].eq_ignore_ascii_case(PREFIX) {
        return None;
    }
    let encoded = trim_ascii(&header[PREFIX.len()..]);
    let decoded = Zeroizing::new(STANDARD.decode(encoded).ok()?);
    let separator = decoded.iter().position(|byte| *byte == b':')?;
    let token = &decoded[separator + 1..];
    if !(16..=512).contains(&token.len()) {
        return None;
    }
    match String::from_utf8(token.to_vec()) {
        Ok(token) => Some(Zeroizing::new(token)),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            None
        }
    }
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

pub fn strip_sensitive_headers(headers: &mut HeaderMap) {
    for name in [
        "proxy-authorization",
        "proxy-authenticate",
        "proxy-connection",
        "authorization",
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-forwarded-port",
        "x-real-ip",
        "x-client-ip",
        "true-client-ip",
        "cf-connecting-ip",
    ] {
        headers.remove(name);
    }
}

fn request_targets_proxy(request: &ProxyRequest<'_>) -> bool {
    let Some(server_name) = request.tls_server_name else {
        return false;
    };
    let Some(target) = request.authority else {
        return false;
    };
    let target_host = authority_host(target).unwrap_or(target);
    target_host
        .trim_end_matches('.')
        .eq_ignore_ascii_case(server_name.trim_end_matches('.'))
}

fn authority_host(authority: &str) -> Option<&str> {
    if let Some(bracketed) = authority.strip_prefix('[') {
        return bracketed.split_once(']').map(|(host, _)| host);
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.parse::<u16>().is_ok() => Some(host),
        _ if !authority.contains(':') => Some(authority),
        _ => None,
    }
}

fn authentication_required() -> ProxyResponse {
    let mut response = response(
        StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        "proxy authentication required\n",
    );
    response.headers.insert(
        http::header::PROXY_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"Porta\""),
    );
    response
}

fn response(status: StatusCode, body: &'static str) -> ProxyResponse {
    ProxyResponse {
        status,
        headers: HeaderMap::new(),
        body,
    }
}

fn dial_response(error: DialError) -> ProxyResponse {
    match error {
        DialError::Denied(_) => response(StatusCode::FORBIDDEN, "proxy destination denied\n"),
        DialError::Timeout => {
            response(StatusCode::GATEWAY_TIMEOUT, "proxy destination timed out\n")
        }
        _ => response(StatusCode::BAD_GATEWAY, "proxy destination unavailable\n"),
    }
}

async fn relay_tunnel<R, W>(
    tunnel: EstablishedTunnel,
    client_reader: R,
    client_writer: W,
) -> io::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let EstablishedTunnel {
        upstream,
        session,
        request_cancellation,
        usage,
        _permit,
    } = tunnel;
    let session_cancellation = session.cancellation();
    let activity = Activity::new();
    let (upstream_reader, upstream_writer) = tokio::io::split(upstream);
    let transfers = async {
        tokio::try_join!(
            copy_upload(client_reader, upstream_writer, usage.as_ref(), &activity,),
            copy_download(upstream_reader, client_writer, usage.as_ref(), &activity,),
        )?;
        Ok(())
    };
    let result = tokio::select! {
        _ = request_cancellation.cancelled() => Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "proxy request cancelled",
        )),
        _ = session_cancellation.cancelled() => Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "proxy session cancelled",
        )),
        _ = activity.wait_until_idle(TUNNEL_IDLE_TIMEOUT) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "proxy tunnel idle timeout",
        )),
        result = transfers => result,
    };
    drop(usage);
    drop(_permit);
    drop(session);
    result
}

async fn copy_upload<R, W>(
    mut reader: R,
    mut writer: W,
    usage: &dyn UsageSession,
    activity: &Activity,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; COPY_BUFFER_SIZE];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        activity.record();
        write_metered(&mut writer, &buffer[..read], |written| {
            usage.add_uploaded(written);
            activity.record();
        })
        .await?;
    }
}

async fn copy_download<R, W>(
    mut reader: R,
    mut writer: W,
    usage: &dyn UsageSession,
    activity: &Activity,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut read_buffer = vec![0_u8; COPY_BUFFER_SIZE];
    let mut pending = Vec::with_capacity(RESPONSE_BUFFER_SIZE);
    let mut deadline = None;
    loop {
        let read = if let Some(flush_at) = deadline {
            tokio::select! {
                read = reader.read(&mut read_buffer) => Some(read?),
                _ = tokio::time::sleep_until(flush_at) => None,
            }
        } else {
            Some(reader.read(&mut read_buffer).await?)
        };
        let Some(read) = read else {
            flush_pending(&mut writer, &mut pending).await?;
            deadline = None;
            continue;
        };
        if read == 0 {
            flush_pending(&mut writer, &mut pending).await?;
            writer.shutdown().await?;
            return Ok(());
        }
        activity.record();
        usage.add_downloaded(read as u64);
        let mut consumed = 0;
        while consumed < read {
            if pending.is_empty() {
                deadline = Some(tokio::time::Instant::now() + RESPONSE_FLUSH_INTERVAL);
            }
            let take = (RESPONSE_BUFFER_SIZE - pending.len()).min(read - consumed);
            pending.extend_from_slice(&read_buffer[consumed..consumed + take]);
            consumed += take;
            if pending.len() == RESPONSE_BUFFER_SIZE {
                flush_pending(&mut writer, &mut pending).await?;
                activity.record();
                deadline = None;
            }
        }
    }
}

struct Activity {
    started: Instant,
    last_millis: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            last_millis: AtomicU64::new(0),
        }
    }

    fn record(&self) {
        self.last_millis.store(
            self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            Ordering::Relaxed,
        );
    }

    async fn wait_until_idle(&self, timeout: Duration) {
        let interval = (timeout / 4).min(Duration::from_secs(30));
        loop {
            tokio::time::sleep(interval).await;
            let elapsed = self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
            let last = self.last_millis.load(Ordering::Relaxed);
            if elapsed.saturating_sub(last) >= timeout.as_millis() as u64 {
                return;
            }
        }
    }
}

async fn flush_pending<W>(writer: &mut W, pending: &mut Vec<u8>) -> io::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    if !pending.is_empty() {
        writer.write_all(pending).await?;
        pending.clear();
    }
    writer.flush().await
}

async fn write_metered<W, F>(writer: &mut W, mut bytes: &[u8], mut record: F) -> io::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
    F: FnMut(u64),
{
    while !bytes.is_empty() {
        let written = writer.write(bytes).await?;
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "failed to write tunnel stream",
            ));
        }
        record(written as u64);
        bytes = &bytes[written..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::dial::parse_destination;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Mutex as StdMutex;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::sync::{Barrier, Mutex};

    const TOKEN: &str = "proxy-token-0123456789";

    struct FakeAuthorizer {
        calls: AtomicUsize,
        cancellation: CancellationToken,
        releases: Arc<AtomicUsize>,
    }

    impl Authorizer for FakeAuthorizer {
        fn authorize<'a>(
            &'a self,
            token: &'a str,
            device_id: &'a str,
            _parent_cancellation: CancellationToken,
        ) -> BoxFuture<'a, Result<AuthorizedSession, BoxError>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let valid = token == TOKEN && device_id == DEVICE_ID;
            let cancellation = self.cancellation.clone();
            let releases = Arc::clone(&self.releases);
            Box::pin(async move {
                if !valid {
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied").into());
                }
                Ok(AuthorizedSession::new(
                    Identity {
                        account_id: "account".into(),
                        device_id: DEVICE_ID.into(),
                    },
                    cancellation,
                    move || {
                        releases.fetch_add(1, Ordering::Relaxed);
                    },
                ))
            })
        }
    }

    struct FakeConnector {
        stream: Mutex<Option<DuplexStream>>,
    }

    impl Connector for FakeConnector {
        fn connect<'a>(
            &'a self,
            _destination: &'a Destination,
        ) -> BoxFuture<'a, Result<BoxIo, DialError>> {
            Box::pin(async move {
                Ok(Box::new(self.stream.lock().await.take().expect("one connection")) as BoxIo)
            })
        }
    }

    struct PendingConnector {
        started: Arc<tokio::sync::Notify>,
    }

    impl Connector for PendingConnector {
        fn connect<'a>(
            &'a self,
            _destination: &'a Destination,
        ) -> BoxFuture<'a, Result<BoxIo, DialError>> {
            Box::pin(async move {
                self.started.notify_one();
                futures_util::future::pending().await
            })
        }
    }

    struct OneAttemptLimiter {
        reservations: AtomicUsize,
        refunds: AtomicUsize,
    }

    struct OneAttemptReservation<'a>(&'a AtomicUsize);

    impl AuthenticationReservation for OneAttemptReservation<'_> {
        fn refund(self: Box<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl AuthenticationLimiter for OneAttemptLimiter {
        fn reserve(&self, _client: IpAddr) -> Option<Box<dyn AuthenticationReservation + '_>> {
            (self.reservations.fetch_add(1, Ordering::Relaxed) == 0).then(|| {
                Box::new(OneAttemptReservation(&self.refunds))
                    as Box<dyn AuthenticationReservation + '_>
            })
        }
    }

    struct ConcurrentAuthorizer {
        barrier: Barrier,
    }

    impl Authorizer for ConcurrentAuthorizer {
        fn authorize<'a>(
            &'a self,
            token: &'a str,
            device_id: &'a str,
            _parent_cancellation: CancellationToken,
        ) -> BoxFuture<'a, Result<AuthorizedSession, BoxError>> {
            Box::pin(async move {
                self.barrier.wait().await;
                if token != TOKEN || device_id != DEVICE_ID {
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied").into());
                }
                Ok(AuthorizedSession::new(
                    Identity {
                        account_id: "account".into(),
                        device_id: DEVICE_ID.into(),
                    },
                    CancellationToken::new(),
                    || {},
                ))
            })
        }
    }

    struct TaggedLimiter {
        refunds: StdMutex<Vec<IpAddr>>,
    }

    struct TaggedReservation<'a> {
        client: IpAddr,
        refunds: &'a StdMutex<Vec<IpAddr>>,
    }

    impl AuthenticationReservation for TaggedReservation<'_> {
        fn refund(self: Box<Self>) {
            self.refunds
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(self.client);
        }
    }

    impl AuthenticationLimiter for TaggedLimiter {
        fn reserve(&self, client: IpAddr) -> Option<Box<dyn AuthenticationReservation + '_>> {
            Some(Box::new(TaggedReservation {
                client,
                refunds: &self.refunds,
            }))
        }
    }

    #[derive(Default)]
    struct Counters {
        uploaded: AtomicU64,
        downloaded: AtomicU64,
        closed: AtomicUsize,
    }

    struct FakeUsage(Arc<Counters>);

    struct FakeUsageSession(Arc<Counters>);

    impl UsageHooks for FakeUsage {
        fn begin(
            &self,
            _identity: &Identity,
            _kind: &'static str,
            _target: &str,
        ) -> Box<dyn UsageSession> {
            Box::new(FakeUsageSession(Arc::clone(&self.0)))
        }
    }

    impl UsageSession for FakeUsageSession {
        fn add_uploaded(&self, bytes: u64) {
            self.0.uploaded.fetch_add(bytes, Ordering::Relaxed);
        }

        fn add_downloaded(&self, bytes: u64) {
            self.0.downloaded.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    impl Drop for FakeUsageSession {
        fn drop(&mut self) {
            self.0.closed.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn authorization(username: &str, token: &str) -> HeaderValue {
        HeaderValue::from_str(&format!(
            "Basic {}",
            STANDARD.encode(format!("{username}:{token}"))
        ))
        .unwrap()
    }

    fn connect_request<'a>(method: &'a Method, headers: &'a HeaderMap) -> ProxyRequest<'a> {
        ProxyRequest {
            method,
            authority: Some("example.com:443"),
            uri_is_absolute: true,
            extended_protocol: None,
            tls_server_name: Some("proxy.example"),
            headers,
            client_ip: "192.0.2.31".parse().unwrap(),
            cancellation: CancellationToken::new(),
        }
    }

    fn proxy_with(
        connector: Arc<dyn Connector>,
        usage: Arc<dyn UsageHooks>,
    ) -> (ForwardProxy, Arc<FakeAuthorizer>, Arc<AtomicUsize>) {
        let releases = Arc::new(AtomicUsize::new(0));
        let authorizer = Arc::new(FakeAuthorizer {
            calls: AtomicUsize::new(0),
            cancellation: CancellationToken::new(),
            releases: Arc::clone(&releases),
        });
        (
            ForwardProxy::with_components(authorizer.clone(), connector, usage, 2),
            authorizer,
            releases,
        )
    }

    #[test]
    fn basic_password_is_token_and_username_is_ignored() {
        for username in ["", "phone", "anything is accepted", "invalid/device/name"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                http::header::PROXY_AUTHORIZATION,
                authorization(username, TOKEN),
            );
            assert_eq!(
                proxy_token(&headers).as_deref().map(String::as_str),
                Some(TOKEN)
            );
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::PROXY_AUTHORIZATION,
            authorization("ignored", ""),
        );
        assert!(proxy_token(&headers).is_none());
    }

    #[tokio::test]
    async fn only_standard_connect_is_challenged_or_accepted() {
        let (stream, _peer) = duplex(64);
        let (proxy, authorizer, _releases) = proxy_with(
            Arc::new(FakeConnector {
                stream: Mutex::new(Some(stream)),
            }),
            Arc::new(NoopUsage),
        );
        let empty = HeaderMap::new();
        match proxy
            .prepare(connect_request(&Method::CONNECT, &empty))
            .await
        {
            ProxyAction::Respond(response) => {
                assert_eq!(response.status, StatusCode::PROXY_AUTHENTICATION_REQUIRED);
                assert_eq!(
                    response.headers[http::header::PROXY_AUTHENTICATE],
                    "Basic realm=\"Porta\""
                );
            }
            _ => panic!("CONNECT was not challenged"),
        }
        match proxy.prepare(connect_request(&Method::GET, &empty)).await {
            ProxyAction::Respond(response) => {
                assert_eq!(response.status, StatusCode::PROXY_AUTHENTICATION_REQUIRED);
            }
            _ => panic!("ordinary proxy method was not challenged"),
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::PROXY_AUTHORIZATION,
            authorization("ignored", TOKEN),
        );
        match proxy.prepare(connect_request(&Method::GET, &headers)).await {
            ProxyAction::Respond(response) => {
                assert_eq!(response.status, StatusCode::FORBIDDEN);
                assert!(!response
                    .headers
                    .contains_key(http::header::PROXY_AUTHENTICATE));
            }
            _ => panic!("authenticated ordinary proxy method was not rejected"),
        }
        let mut extended = connect_request(&Method::CONNECT, &empty);
        extended.extended_protocol = Some("connect-ip");
        assert!(matches!(
            proxy.prepare(extended).await,
            ProxyAction::Respond(ProxyResponse {
                status: StatusCode::FORBIDDEN,
                ..
            })
        ));
        assert_eq!(authorizer.calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn camouflage_and_proxy_target_requests_fall_through() {
        let (stream, _peer) = duplex(64);
        let (mut proxy, _, _) = proxy_with(
            Arc::new(FakeConnector {
                stream: Mutex::new(Some(stream)),
            }),
            Arc::new(NoopUsage),
        );
        proxy.set_camouflage(true);
        let headers = HeaderMap::new();
        assert!(matches!(
            proxy.prepare(connect_request(&Method::GET, &headers)).await,
            ProxyAction::Fallthrough(FallthroughReason::Camouflage)
        ));
        let mut authenticated = HeaderMap::new();
        authenticated.insert(
            http::header::PROXY_AUTHORIZATION,
            authorization("ignored", TOKEN),
        );
        assert!(matches!(
            proxy
                .prepare(connect_request(&Method::GET, &authenticated))
                .await,
            ProxyAction::Respond(ProxyResponse {
                status: StatusCode::FORBIDDEN,
                ..
            })
        ));
        let mut self_target = connect_request(&Method::CONNECT, &headers);
        self_target.authority = Some("proxy.example:443");
        assert!(matches!(
            proxy.prepare(self_target).await,
            ProxyAction::Fallthrough(FallthroughReason::TargetsProxy)
        ));
    }

    #[tokio::test]
    async fn rejects_non_443_and_malformed_targets_after_authentication() {
        let (stream, _peer) = duplex(64);
        let (proxy, _, releases) = proxy_with(
            Arc::new(FakeConnector {
                stream: Mutex::new(Some(stream)),
            }),
            Arc::new(NoopUsage),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::PROXY_AUTHORIZATION,
            authorization("ignored", TOKEN),
        );
        let mut request = connect_request(&Method::CONNECT, &headers);
        request.authority = Some("example.com:80");
        assert!(matches!(
            proxy.prepare(request).await,
            ProxyAction::Respond(ProxyResponse {
                status: StatusCode::FORBIDDEN,
                ..
            })
        ));
        assert_eq!(releases.load(Ordering::Relaxed), 1);

        let mut request = connect_request(&Method::CONNECT, &headers);
        request.authority = Some("https://example.com:443");
        assert!(matches!(
            proxy.prepare(request).await,
            ProxyAction::Respond(ProxyResponse {
                status: StatusCode::BAD_REQUEST,
                ..
            })
        ));
        assert_eq!(releases.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn authentication_failures_can_be_rate_limited() {
        let (stream, _peer) = duplex(64);
        let (mut proxy, authorizer, _releases) = proxy_with(
            Arc::new(FakeConnector {
                stream: Mutex::new(Some(stream)),
            }),
            Arc::new(NoopUsage),
        );
        let limiter = Arc::new(OneAttemptLimiter {
            reservations: AtomicUsize::new(0),
            refunds: AtomicUsize::new(0),
        });
        proxy.set_authentication_limiter(Some(limiter.clone()));
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::PROXY_AUTHORIZATION,
            authorization("ignored", "invalid-token-0123456789"),
        );
        assert!(matches!(
            proxy
                .prepare(connect_request(&Method::CONNECT, &headers))
                .await,
            ProxyAction::Respond(ProxyResponse {
                status: StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                ..
            })
        ));
        match proxy
            .prepare(connect_request(&Method::CONNECT, &headers))
            .await
        {
            ProxyAction::Respond(response) => {
                assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
                assert_eq!(response.headers[http::header::RETRY_AFTER], "5");
            }
            _ => panic!("second authentication failure was not limited"),
        }
        assert_eq!(authorizer.calls.load(Ordering::Relaxed), 1);
        assert_eq!(limiter.refunds.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn concurrent_authentication_refunds_only_the_successful_reservation() {
        let (stream, _peer) = duplex(64);
        let limiter = Arc::new(TaggedLimiter {
            refunds: StdMutex::new(Vec::new()),
        });
        let mut proxy = ForwardProxy::with_components(
            Arc::new(ConcurrentAuthorizer {
                barrier: Barrier::new(2),
            }),
            Arc::new(FakeConnector {
                stream: Mutex::new(Some(stream)),
            }),
            Arc::new(NoopUsage),
            2,
        );
        proxy.set_camouflage(true);
        proxy.set_authentication_limiter(Some(limiter.clone()));

        let mut valid_headers = HeaderMap::new();
        valid_headers.insert(
            http::header::PROXY_AUTHORIZATION,
            authorization("valid", TOKEN),
        );
        let mut invalid_headers = HeaderMap::new();
        invalid_headers.insert(
            http::header::PROXY_AUTHORIZATION,
            authorization("invalid", "invalid-token-0123456789"),
        );
        let valid_client = "192.0.2.31".parse().unwrap();
        let invalid_client = "192.0.2.32".parse().unwrap();
        let mut valid = connect_request(&Method::GET, &valid_headers);
        valid.client_ip = valid_client;
        let mut invalid = connect_request(&Method::GET, &invalid_headers);
        invalid.client_ip = invalid_client;

        let (valid_action, invalid_action) =
            tokio::join!(proxy.prepare(valid), proxy.prepare(invalid));
        assert!(matches!(
            valid_action,
            ProxyAction::Respond(ProxyResponse {
                status: StatusCode::FORBIDDEN,
                ..
            })
        ));
        assert!(matches!(
            invalid_action,
            ProxyAction::Fallthrough(FallthroughReason::Camouflage)
        ));
        assert_eq!(
            *limiter
                .refunds
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
            vec![valid_client]
        );
    }

    #[tokio::test]
    async fn capacity_permit_is_released_with_connect_plan() {
        let releases = Arc::new(AtomicUsize::new(0));
        let authorizer = Arc::new(FakeAuthorizer {
            calls: AtomicUsize::new(0),
            cancellation: CancellationToken::new(),
            releases: Arc::clone(&releases),
        });
        let (stream, _peer) = duplex(64);
        let proxy = ForwardProxy::with_components(
            authorizer,
            Arc::new(FakeConnector {
                stream: Mutex::new(Some(stream)),
            }),
            Arc::new(NoopUsage),
            1,
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::PROXY_AUTHORIZATION,
            authorization("ignored", TOKEN),
        );
        let first = match proxy
            .prepare(connect_request(&Method::CONNECT, &headers))
            .await
        {
            ProxyAction::Connect(plan) => plan,
            _ => panic!("first CONNECT was rejected"),
        };
        assert!(matches!(
            proxy
                .prepare(connect_request(&Method::CONNECT, &headers))
                .await,
            ProxyAction::Respond(ProxyResponse {
                status: StatusCode::SERVICE_UNAVAILABLE,
                ..
            })
        ));
        drop(first);
        assert!(matches!(
            proxy
                .prepare(connect_request(&Method::CONNECT, &headers))
                .await,
            ProxyAction::Connect(_)
        ));
    }

    #[test]
    fn sensitive_credentials_and_identity_headers_are_removed() {
        let mut headers = HeaderMap::new();
        for name in [
            "proxy-authorization",
            "authorization",
            "forwarded",
            "x-forwarded-for",
            "x-real-ip",
            "cf-connecting-ip",
        ] {
            headers.insert(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_static("secret"),
            );
        }
        headers.insert("accept", HeaderValue::from_static("*/*"));
        strip_sensitive_headers(&mut headers);
        assert_eq!(headers.len(), 1);
        assert!(headers.contains_key("accept"));
    }

    #[tokio::test]
    async fn duplex_relay_is_bidirectional_metered_and_releases_session() {
        let (upstream, mut upstream_peer) = duplex(1 << 20);
        let counters = Arc::new(Counters::default());
        let (proxy, _, releases) = proxy_with(
            Arc::new(FakeConnector {
                stream: Mutex::new(Some(upstream)),
            }),
            Arc::new(FakeUsage(Arc::clone(&counters))),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::PROXY_AUTHORIZATION,
            authorization("laptop", TOKEN),
        );
        let plan = match proxy
            .prepare(connect_request(&Method::CONNECT, &headers))
            .await
        {
            ProxyAction::Connect(plan) => plan,
            _ => panic!("authenticated CONNECT was rejected"),
        };
        assert_eq!(
            plan.destination(),
            &parse_destination("example.com:443").unwrap()
        );
        let tunnel = proxy.establish(plan).await.unwrap();
        let (client, mut client_peer) = duplex(1 << 20);
        let relay = tokio::spawn(async move { proxy.relay(tunnel, client).await });

        client_peer.write_all(b"upload").await.unwrap();
        let mut upload = [0; 6];
        upstream_peer.read_exact(&mut upload).await.unwrap();
        assert_eq!(&upload, b"upload");

        upstream_peer.write_all(b"download").await.unwrap();
        let mut download = [0; 8];
        client_peer.read_exact(&mut download).await.unwrap();
        assert_eq!(&download, b"download");

        client_peer.shutdown().await.unwrap();
        upstream_peer.shutdown().await.unwrap();
        relay.await.unwrap().unwrap();
        assert_eq!(counters.uploaded.load(Ordering::Relaxed), 6);
        assert_eq!(counters.downloaded.load(Ordering::Relaxed), 8);
        assert_eq!(counters.closed.load(Ordering::Relaxed), 1);
        assert_eq!(releases.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn relay_preserves_reverse_half_close() {
        let (upstream, mut upstream_peer) = duplex(1 << 20);
        let (proxy, _, _) = proxy_with(
            Arc::new(FakeConnector {
                stream: Mutex::new(Some(upstream)),
            }),
            Arc::new(NoopUsage),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::PROXY_AUTHORIZATION,
            authorization("tablet", TOKEN),
        );
        let plan = match proxy
            .prepare(connect_request(&Method::CONNECT, &headers))
            .await
        {
            ProxyAction::Connect(plan) => plan,
            _ => panic!("authenticated CONNECT was rejected"),
        };
        let tunnel = proxy.establish(plan).await.unwrap();
        let (client, mut client_peer) = duplex(1 << 20);
        let relay = tokio::spawn(async move { proxy.relay(tunnel, client).await });

        upstream_peer.write_all(b"response").await.unwrap();
        upstream_peer.shutdown().await.unwrap();
        let mut response = [0; 8];
        client_peer.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
        assert_eq!(client_peer.read(&mut [0; 1]).await.unwrap(), 0);

        client_peer
            .write_all(b"request-after-half-close")
            .await
            .unwrap();
        client_peer.shutdown().await.unwrap();
        let mut request = Vec::new();
        upstream_peer.read_to_end(&mut request).await.unwrap();
        assert_eq!(&request, b"request-after-half-close");
        relay.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn response_writes_flush_on_timer_and_final_eof() {
        let (mut source, source_reader) = duplex(1 << 20);
        let (destination, mut destination_reader) = duplex(1 << 20);
        let counters = FakeUsageSession(Arc::new(Counters::default()));
        let copy = tokio::spawn(async move {
            let (reader, _) = tokio::io::split(source_reader);
            let (_, writer) = tokio::io::split(destination);
            copy_download(reader, writer, &counters, &Activity::new()).await
        });

        source.write_all(b"interactive").await.unwrap();
        let mut interactive = [0; 11];
        tokio::time::timeout(
            Duration::from_millis(100),
            destination_reader.read_exact(&mut interactive),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&interactive, b"interactive");

        source.write_all(b"final").await.unwrap();
        source.shutdown().await.unwrap();
        let mut final_bytes = [0; 5];
        destination_reader
            .read_exact(&mut final_bytes)
            .await
            .unwrap();
        assert_eq!(&final_bytes, b"final");
        copy.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn cancellation_interrupts_live_tunnel_and_releases_once() {
        let (upstream, _upstream_peer) = duplex(64);
        let (proxy, authorizer, releases) = proxy_with(
            Arc::new(FakeConnector {
                stream: Mutex::new(Some(upstream)),
            }),
            Arc::new(NoopUsage),
        );
        let cancellation = authorizer.cancellation.clone();
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::PROXY_AUTHORIZATION,
            authorization("phone", TOKEN),
        );
        let plan = match proxy
            .prepare(connect_request(&Method::CONNECT, &headers))
            .await
        {
            ProxyAction::Connect(plan) => plan,
            _ => panic!("authenticated CONNECT was rejected"),
        };
        let tunnel = proxy.establish(plan).await.unwrap();
        let (client, _client_peer) = duplex(64);
        let relay = tokio::spawn(async move { proxy.relay(tunnel, client).await });
        cancellation.cancel();
        assert_eq!(
            relay.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(releases.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn request_cancellation_interrupts_pending_dial_and_releases_once() {
        let started = Arc::new(tokio::sync::Notify::new());
        let (proxy, _, releases) = proxy_with(
            Arc::new(PendingConnector {
                started: Arc::clone(&started),
            }),
            Arc::new(NoopUsage),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::PROXY_AUTHORIZATION,
            authorization("phone", TOKEN),
        );
        let cancellation = CancellationToken::new();
        let mut request = connect_request(&Method::CONNECT, &headers);
        request.cancellation = cancellation.clone();
        let plan = match proxy.prepare(request).await {
            ProxyAction::Connect(plan) => plan,
            _ => panic!("authenticated CONNECT was rejected"),
        };
        let proxy = Arc::new(proxy);
        let establishing = tokio::spawn({
            let proxy = Arc::clone(&proxy);
            async move { proxy.establish(plan).await }
        });
        started.notified().await;
        cancellation.cancel();
        match establishing.await.unwrap() {
            Err(response) => assert_eq!(response.status, StatusCode::BAD_GATEWAY),
            Ok(_) => panic!("cancelled dial established a tunnel"),
        }
        assert_eq!(releases.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn idle_tracker_is_refreshed_by_activity() {
        let activity = Activity::new();
        tokio::time::sleep(Duration::from_millis(2)).await;
        activity.record();
        assert!(activity.last_millis.load(Ordering::Relaxed) > 0);
        tokio::time::timeout(
            Duration::from_millis(30),
            activity.wait_until_idle(Duration::from_millis(10)),
        )
        .await
        .unwrap();
    }
}
