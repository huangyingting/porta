use crate::ops::admission::ConnectionAdmission;
use crate::ops::shutdown::{Drain, RequestGuard};
use anyhow::Result;
use bytes::Bytes;
use futures_util::future::BoxFuture;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use socket2::{Domain, Protocol, SockAddr, SockRef, Socket, TcpKeepalive, Type};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;
use tokio_util::task::TaskTracker;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type ResponseBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;

#[derive(Clone, Debug, Default)]
pub struct ConnectionMetadata {
    pub tls_server_name: Option<Arc<str>>,
}

pub trait Handler: Send + Sync + 'static {
    fn call(
        self: Arc<Self>,
        request: Request<Incoming>,
        peer: SocketAddr,
    ) -> BoxFuture<'static, Result<Response<ResponseBody>>>;
}

pub struct ServeOptions {
    pub admission: Option<Arc<ConnectionAdmission>>,
    pub drain: Drain,
    pub connections: TaskTracker,
    pub initial_timeout: std::time::Duration,
    pub idle_timeout: std::time::Duration,
}

pub fn bind_tcp_listener(address: SocketAddr) -> Result<TcpListener> {
    let dual_stack = address.is_ipv6() && address.ip().is_unspecified();
    let domain = if address.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    if dual_stack {
        socket.set_only_v6(false)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&SockAddr::from(address))?;
    socket.listen(1024)?;
    Ok(TcpListener::from_std(socket.into())?)
}

pub fn bind_udp_socket(address: SocketAddr) -> Result<std::net::UdpSocket> {
    let dual_stack = address.is_ipv6() && address.ip().is_unspecified();
    let domain = if address.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    if dual_stack {
        socket.set_only_v6(false)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&SockAddr::from(address))?;
    Ok(socket.into())
}

pub async fn serve_tcp(
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    handler: Arc<dyn Handler>,
    options: ServeOptions,
) -> Result<()> {
    let ServeOptions {
        admission,
        drain,
        connections,
        initial_timeout,
        idle_timeout,
    } = options;
    let cancellation = drain.cancellation();
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => return Ok(()),
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok((stream, peer)) => (stream, normalize_peer(peer)),
                    Err(error) => {
                        tracing::warn!(%error, "public TCP accept failed");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let permit = if let Some(admission) = &admission {
                    let Ok(permit) = admission.admit_tcp(peer) else {
                        continue;
                    };
                    Some(permit)
                } else {
                    None
                };
                stream.set_nodelay(true)?;
                SockRef::from(&stream).set_tcp_keepalive(
                    &TcpKeepalive::new()
                        .with_time(std::time::Duration::from_secs(60))
                        .with_interval(std::time::Duration::from_secs(20)),
                )?;
                let tls = tls.clone();
                let handler = handler.clone();
                let drain = drain.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    let result = if let Some(acceptor) = tls {
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            acceptor.accept(stream),
                        )
                        .await
                        {
                            Ok(Ok(stream)) => {
                                let metadata = ConnectionMetadata {
                                    tls_server_name: stream
                                        .get_ref()
                                        .1
                                        .server_name()
                                        .map(Arc::<str>::from),
                                };
                                serve_connection(
                                    stream,
                                    handler,
                                    drain,
                                    peer,
                                    metadata,
                                    initial_timeout,
                                    idle_timeout,
                                )
                                .await
                            }
                            Ok(Err(error)) => Err(error.into()),
                            Err(_) => Err(anyhow::anyhow!("TLS handshake timed out")),
                        }
                    } else {
                        serve_connection(
                            stream,
                            handler,
                            drain,
                            peer,
                            ConnectionMetadata::default(),
                            initial_timeout,
                            idle_timeout,
                        )
                        .await
                    };
                    if let Err(error) = result {
                        tracing::debug!(%peer, %error, "public TCP connection closed with error");
                    }
                });
            }
        }
    }
}

fn normalize_peer(peer: SocketAddr) -> SocketAddr {
    match peer {
        SocketAddr::V6(address) => address
            .ip()
            .to_ipv4_mapped()
            .map(|ip| SocketAddr::new(ip.into(), address.port()))
            .unwrap_or(peer),
        _ => peer,
    }
}

async fn serve_connection<I>(
    stream: I,
    handler: Arc<dyn Handler>,
    drain: Drain,
    peer: SocketAddr,
    metadata: ConnectionMetadata,
    initial_timeout: std::time::Duration,
    idle_timeout: std::time::Duration,
) -> Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (first_request_tx, first_request_rx) = oneshot::channel();
    let first_request_tx = Arc::new(parking_lot::Mutex::new(Some(first_request_tx)));
    let first_request_seen = Arc::new(AtomicBool::new(false));
    let activity = Arc::new(ConnectionActivity::default());
    let idle_activity = activity.clone();
    let connection_shutdown = drain.cancellation();
    let initial_shutdown = connection_shutdown.clone();
    let service = service_fn(move |mut request| {
        let handler = handler.clone();
        let drain = drain.clone();
        let activity = activity.clone();
        let metadata = metadata.clone();
        let first_request_seen = first_request_seen.clone();
        let first_request_tx = first_request_tx.clone();
        async move {
            request.extensions_mut().insert(metadata);
            let activity = activity.begin();
            if !first_request_seen.swap(true, Ordering::Relaxed) {
                if let Some(sender) = first_request_tx.lock().take() {
                    let _ = sender.send(());
                }
            }
            let Some(request_guard) = drain.begin_request() else {
                return Ok::<_, Infallible>(track_response(
                    plain_response(StatusCode::SERVICE_UNAVAILABLE, "server shutting down\n"),
                    RequestLifetime::new(None, activity),
                ));
            };
            let lifetime = RequestLifetime::new(Some(request_guard), activity);
            request.extensions_mut().insert(lifetime.clone());
            let response = match handler.call(request, peer).await {
                Ok(response) => response,
                Err(error) => {
                    tracing::error!(%peer, %error, "request failed");
                    plain_response(StatusCode::INTERNAL_SERVER_ERROR, "internal server error\n")
                }
            };
            Ok::<_, Infallible>(track_response(response, lifetime))
        }
    });
    let mut builder = Builder::new(TokioExecutor::new());
    builder.http1().max_buf_size(16 << 10);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(128)
        .max_frame_size(64 << 10)
        .max_header_list_size(16 << 10)
        .initial_stream_window_size(1 << 20)
        .initial_connection_window_size(1 << 20)
        .keep_alive_interval(Some(std::time::Duration::from_secs(30)))
        .keep_alive_timeout(std::time::Duration::from_secs(10))
        .max_send_buf_size(1 << 20)
        .enable_connect_protocol();
    let connection = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
    tokio::pin!(connection);
    let first_request = tokio::select! {
        result = &mut connection => {
            result.map_err(|error| anyhow::anyhow!("{error}"))?;
            false
        }
        first_request = tokio::time::timeout(
            initial_timeout,
            first_request_rx,
        ) => {
            match first_request {
                Ok(Ok(())) => true,
                Ok(Err(_)) => {
                    connection
                        .as_mut()
                        .await
                        .map_err(|error| anyhow::anyhow!("{error}"))?;
                    false
                }
                Err(_) => anyhow::bail!("HTTP request header timed out"),
            }
        }
        _ = initial_shutdown.cancelled() => {
            connection.as_mut().graceful_shutdown();
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                connection.as_mut(),
            )
            .await;
            false
        }
    };
    if first_request {
        tokio::select! {
            result = &mut connection => {
                result.map_err(|error| anyhow::anyhow!("{error}"))?;
            }
            _ = idle_activity.wait_until_idle_for(idle_timeout) => {
                anyhow::bail!("HTTP connection idle timed out");
            }
            _ = connection_shutdown.cancelled() => {
                connection.as_mut().graceful_shutdown();
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    connection.as_mut(),
                )
                .await;
            }
        }
    }
    Ok(())
}

#[derive(Default)]
struct ConnectionActivity {
    active: AtomicUsize,
    generation: AtomicU64,
    changed: Notify,
}

impl ConnectionActivity {
    fn begin(self: &Arc<Self>) -> ConnectionRequest {
        self.active.fetch_add(1, Ordering::AcqRel);
        self.touch();
        ConnectionRequest {
            activity: self.clone(),
        }
    }

    fn touch(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.changed.notify_one();
    }

    async fn wait_until_idle_for(&self, timeout: std::time::Duration) {
        loop {
            let observed = self.generation.load(Ordering::Acquire);
            if self.active.load(Ordering::Acquire) != 0 {
                self.changed.notified().await;
                continue;
            }
            tokio::select! {
                _ = tokio::time::sleep(timeout) => {
                    if self.active.load(Ordering::Acquire) == 0
                        && self.generation.load(Ordering::Acquire) == observed
                    {
                        return;
                    }
                }
                _ = self.changed.notified() => {}
            }
        }
    }
}

struct ConnectionRequest {
    activity: Arc<ConnectionActivity>,
}

#[derive(Clone)]
pub(crate) struct RequestLifetime {
    _inner: Arc<RequestLifetimeInner>,
}

struct RequestLifetimeInner {
    _request: Option<RequestGuard>,
    _activity: ConnectionRequest,
}

impl RequestLifetime {
    fn new(request: Option<RequestGuard>, activity: ConnectionRequest) -> Self {
        Self {
            _inner: Arc::new(RequestLifetimeInner {
                _request: request,
                _activity: activity,
            }),
        }
    }
}

fn track_response(
    response: Response<ResponseBody>,
    lifetime: RequestLifetime,
) -> Response<ResponseBody> {
    response.map(|body| {
        TrackedBody {
            body,
            lifetime: Some(lifetime),
        }
        .boxed()
    })
}

struct TrackedBody {
    body: ResponseBody,
    lifetime: Option<RequestLifetime>,
}

impl Body for TrackedBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let result = Pin::new(&mut self.body).poll_frame(context);
        if matches!(result, Poll::Ready(None)) {
            self.lifetime.take();
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

impl Drop for ConnectionRequest {
    fn drop(&mut self) {
        let previous = self.activity.active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "connection activity underflow");
        self.activity.touch();
    }
}

pub fn plain_response(status: StatusCode, body: &'static str) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(http::header::CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .header("referrer-policy", "no-referrer")
        .body(
            Full::new(Bytes::from_static(body.as_bytes()))
                .map_err(|never| match never {})
                .boxed(),
        )
        .expect("static HTTP response is valid")
}

pub fn bytes_response(
    status: StatusCode,
    content_type: &'static str,
    body: Bytes,
) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, content_type)
        .header(http::header::CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .header("referrer-policy", "no-referrer")
        .body(Full::new(body).map_err(|never| match never {}).boxed())
        .expect("static HTTP response is valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_response_sets_no_store() {
        let response = plain_response(StatusCode::OK, "ok\n");
        assert_eq!(response.headers()[http::header::CACHE_CONTROL], "no-store");
    }

    #[tokio::test]
    async fn explicit_ipv4_wildcards_remain_ipv4() {
        let tcp = bind_tcp_listener("0.0.0.0:0".parse().unwrap()).unwrap();
        assert!(tcp.local_addr().unwrap().is_ipv4());
        let udp = bind_udp_socket("0.0.0.0:0".parse().unwrap()).unwrap();
        assert!(udp.local_addr().unwrap().is_ipv4());
    }

    #[tokio::test]
    async fn idle_timeout_pauses_while_a_request_is_active() {
        let activity = Arc::new(ConnectionActivity::default());
        let request = activity.begin();
        let waiting = tokio::spawn({
            let activity = activity.clone();
            async move {
                activity
                    .wait_until_idle_for(std::time::Duration::from_millis(20))
                    .await;
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        assert!(!waiting.is_finished());
        drop(request);
        tokio::time::timeout(std::time::Duration::from_millis(100), waiting)
            .await
            .expect("idle timeout completes after the request")
            .expect("idle timeout task succeeds");
    }

    #[test]
    fn detached_tunnel_lifetime_keeps_request_and_connection_active() {
        let drain = Drain::new();
        let activity = Arc::new(ConnectionActivity::default());
        let lifetime = RequestLifetime::new(drain.begin_request(), activity.begin());
        let tunnel_lifetime = lifetime.clone();
        let response = track_response(plain_response(StatusCode::OK, ""), lifetime);
        drop(response);
        assert_eq!(drain.active(), 1);
        assert_eq!(activity.active.load(Ordering::Acquire), 1);
        drop(tunnel_lifetime);
        assert_eq!(drain.active(), 0);
        assert_eq!(activity.active.load(Ordering::Acquire), 0);
    }
}
