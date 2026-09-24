use crate::proxy::service::{ForwardProxy, ProxyAction, ProxyRequest, ProxyResponse};
use crate::server::{
    plain_response, BoxError, ConnectionMetadata, Handler, RequestLifetime, ResponseBody,
};
use crate::transport::session::{MASQUE_PATH, TUNNEL_PATH};
use crate::web::admin::AdminService;
use crate::web::landing::LandingSite;
use crate::web::portal::Portal;
use crate::web::session::{normalized_headers, RequestContext, Response as WebResponse};
use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use futures_util::{future::BoxFuture, TryStreamExt};
use http::{Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Body, Frame, Incoming};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio_util::io::ReaderStream;
use tokio_util::sync::CancellationToken;

const MAX_WEB_BODY: usize = 16 << 10;

#[derive(Clone, Copy)]
pub struct EffectiveClientAddress(pub IpAddr);

pub struct PublicHttpHandler {
    proxy: Option<Arc<ForwardProxy>>,
    portal: Arc<Portal>,
    landing: Arc<LandingSite>,
    transport: Arc<dyn Handler>,
    trust_proxy_headers: bool,
    shutdown: CancellationToken,
}

impl PublicHttpHandler {
    pub fn new(
        proxy: Option<Arc<ForwardProxy>>,
        portal: Arc<Portal>,
        landing: Arc<LandingSite>,
        transport: Arc<dyn Handler>,
        trust_proxy_headers: bool,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            proxy,
            portal,
            landing,
            transport,
            trust_proxy_headers,
            shutdown,
        }
    }

    async fn handle(
        self: Arc<Self>,
        mut request: Request<Incoming>,
        peer: SocketAddr,
    ) -> Result<Response<ResponseBody>> {
        let client_ip = client_address(peer.ip(), request.headers(), self.trust_proxy_headers);
        if request.method() == http::Method::CONNECT
            && request.uri().path().eq_ignore_ascii_case(MASQUE_PATH)
        {
            request
                .extensions_mut()
                .insert(EffectiveClientAddress(client_ip));
            return self.transport.clone().call(request, peer).await;
        }
        if let Some(proxy) = &self.proxy {
            let protocol = request
                .extensions()
                .get::<hyper::ext::Protocol>()
                .map(hyper::ext::Protocol::as_str);
            let server_name = request
                .extensions()
                .get::<ConnectionMetadata>()
                .and_then(|metadata| metadata.tls_server_name.as_deref());
            let action = proxy
                .prepare(ProxyRequest {
                    method: request.method(),
                    authority: request.uri().authority().map(http::uri::Authority::as_str),
                    uri_is_absolute: is_http1_absolute_form(&request),
                    extended_protocol: protocol,
                    tls_server_name: server_name,
                    headers: request.headers(),
                    client_ip,
                    cancellation: self.shutdown.child_token(),
                })
                .await;
            match action {
                ProxyAction::Fallthrough(_) => {}
                ProxyAction::Respond(response) => return Ok(proxy_response(response)),
                ProxyAction::Connect(plan) => {
                    let tunnel = match proxy.establish(plan).await {
                        Ok(tunnel) => tunnel,
                        Err(response) => return Ok(proxy_response(response)),
                    };
                    return Ok(start_proxy(proxy.clone(), &mut request, tunnel));
                }
            }
        }

        if request.uri().path() == TUNNEL_PATH {
            let context = request_context(&request, peer.ip(), client_ip, Bytes::new());
            if let Some(response) = self.portal.handle(&context).await {
                return web_response(response).await;
            }
            if let Some(response) = self.landing.handle(&context) {
                return web_response(response).await;
            }
            request
                .extensions_mut()
                .insert(EffectiveClientAddress(client_ip));
            return self.transport.clone().call(request, peer).await;
        }

        let context = match collect_request(request, peer.ip(), client_ip).await {
            Ok(context) => context,
            Err(response) => return Ok(*response),
        };
        if let Some(response) = self.portal.handle(&context).await {
            return web_response(response).await;
        }
        if let Some(response) = self.landing.handle(&context) {
            return web_response(response).await;
        }
        Ok(plain_response(StatusCode::NOT_FOUND, "not found\n"))
    }
}

impl Handler for PublicHttpHandler {
    fn call(
        self: Arc<Self>,
        request: Request<Incoming>,
        peer: SocketAddr,
    ) -> BoxFuture<'static, Result<Response<ResponseBody>>> {
        Box::pin(async move { self.handle(request, peer).await })
    }
}

pub struct AdminHttpHandler {
    admin: Arc<AdminService>,
    operations: Arc<dyn Handler>,
}

impl AdminHttpHandler {
    pub fn new(admin: Arc<AdminService>, operations: Arc<dyn Handler>) -> Self {
        Self { admin, operations }
    }

    async fn handle(
        &self,
        request: Request<Incoming>,
        peer: SocketAddr,
    ) -> Result<Response<ResponseBody>> {
        if matches!(request.uri().path(), "/healthz" | "/readyz" | "/metrics") {
            return self.operations.clone().call(request, peer).await;
        }
        let context = match collect_request(request, peer.ip(), peer.ip()).await {
            Ok(context) => context,
            Err(response) => return Ok(*response),
        };
        web_response(
            self.admin
                .handle(&context, false)
                .await
                .unwrap_or_else(WebResponse::not_found),
        )
        .await
    }
}

impl Handler for AdminHttpHandler {
    fn call(
        self: Arc<Self>,
        request: Request<Incoming>,
        peer: SocketAddr,
    ) -> BoxFuture<'static, Result<Response<ResponseBody>>> {
        Box::pin(async move { self.handle(request, peer).await })
    }
}

fn start_proxy(
    proxy: Arc<ForwardProxy>,
    request: &mut Request<Incoming>,
    tunnel: crate::proxy::service::EstablishedTunnel,
) -> Response<ResponseBody> {
    let upgrade = hyper::upgrade::on(&mut *request);
    let lifetime = request.extensions_mut().remove::<RequestLifetime>();
    tokio::spawn(async move {
        let _lifetime = lifetime;
        match upgrade.await {
            Ok(stream) => {
                if let Err(error) = proxy.relay(tunnel, TokioIo::new(stream)).await {
                    tracing::debug!(%error, "HTTP proxy relay stopped");
                }
            }
            Err(error) => tracing::debug!(%error, "HTTP proxy upgrade failed"),
        }
    });
    successful_connect_response(empty_body())
}

fn successful_connect_response(body: ResponseBody) -> Response<ResponseBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .header("referrer-policy", "no-referrer")
        .body(body)
        .expect("CONNECT response is valid")
}

fn proxy_response(response: ProxyResponse) -> Response<ResponseBody> {
    let mut output = plain_response(response.status, response.body);
    output.headers_mut().extend(response.headers);
    output
}

async fn collect_request(
    request: Request<Incoming>,
    peer_ip: IpAddr,
    client_ip: IpAddr,
) -> std::result::Result<RequestContext, Box<Response<ResponseBody>>> {
    if request
        .body()
        .size_hint()
        .upper()
        .is_some_and(|size| size > MAX_WEB_BODY as u64)
    {
        return Err(Box::new(plain_response(
            StatusCode::BAD_REQUEST,
            "invalid request body\n",
        )));
    }
    let mut context = request_context(&request, peer_ip, client_ip, Bytes::new());
    let mut body = request.into_body();
    let mut collected = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| {
            Box::new(plain_response(
                StatusCode::BAD_REQUEST,
                "invalid request body\n",
            ))
        })?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if collected.len().saturating_add(data.len()) > MAX_WEB_BODY {
            return Err(Box::new(plain_response(
                StatusCode::BAD_REQUEST,
                "invalid request body\n",
            )));
        }
        collected.extend_from_slice(&data);
    }
    context.body = collected.to_vec();
    Ok(context)
}

fn request_context(
    request: &Request<Incoming>,
    peer_ip: IpAddr,
    client_ip: IpAddr,
    body: Bytes,
) -> RequestContext {
    let target = request
        .uri()
        .path_and_query()
        .map(http::uri::PathAndQuery::as_str)
        .unwrap_or_else(|| request.uri().path());
    let mut context = RequestContext::new(request.method().as_str(), target)
        .with_host(request_host(request))
        .with_body(body.to_vec());
    context.headers = normalized_headers(request.headers());
    context.peer_ip = Some(peer_ip);
    context.client_ip = Some(client_ip);
    context
}

fn client_address(peer: IpAddr, headers: &http::HeaderMap, trust_proxy_headers: bool) -> IpAddr {
    let peer = normalize_address(peer);
    if !trust_proxy_headers || !peer.is_loopback() {
        return peer;
    }
    if let Some(forwarded) = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
    {
        for value in forwarded.split(',').rev() {
            if let Ok(address) = value.trim().parse::<IpAddr>() {
                return normalize_address(address);
            }
        }
    }
    headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<IpAddr>().ok())
        .map(normalize_address)
        .unwrap_or(peer)
}

fn normalize_address(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

async fn web_response(response: WebResponse) -> Result<Response<ResponseBody>> {
    let status = StatusCode::from_u16(response.status).context("invalid web response status")?;
    let mut output = Response::builder().status(status);
    for (name, value) in response.headers {
        output = output.header(name, value);
    }
    let body = if let Some(file) = response.file {
        let stream = ReaderStream::new(tokio::io::AsyncReadExt::take(
            tokio::fs::File::from_std(file.file),
            file.length,
        ))
        .map_ok(Frame::data)
        .map_err(|error| -> BoxError { Box::new(error) });
        StreamBody::new(stream).boxed()
    } else {
        full_body(Bytes::from(response.body))
    };
    Ok(output.body(body)?)
}

fn request_host<B>(request: &Request<B>) -> &str {
    request
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
}

fn is_http1_absolute_form<B>(request: &Request<B>) -> bool {
    request.version() <= Version::HTTP_11 && request.uri().scheme().is_some()
}

fn empty_body() -> ResponseBody {
    full_body(Bytes::new())
}

fn full_body(body: Bytes) -> ResponseBody {
    Full::new(body)
        .map_err(|never: Infallible| match never {})
        .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn admin_request(handler: Arc<AdminHttpHandler>, request: String) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut client, server) = tokio::io::duplex(64 << 10);
        let connection = tokio::spawn(async move {
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(server),
                    hyper::service::service_fn(move |request| {
                        handler
                            .clone()
                            .call(request, "127.0.0.1:1234".parse().unwrap())
                    }),
                )
                .await
                .unwrap();
        });
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read_to_end(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        connection.await.unwrap();
        String::from_utf8(response).unwrap()
    }

    #[tokio::test]
    async fn admin_routes_operations_methods() {
        use crate::app::OperationsHandler;
        use crate::integration::WebRegistryAdapter;
        use crate::ops::metrics::Metrics;
        use crate::ops::readiness::Readiness;
        use crate::state::{registry::ClientRegistry, usage::Store};
        use std::time::Duration;

        let directory = tempfile::tempdir_in(".").unwrap();
        let registry = Arc::new(
            ClientRegistry::open(
                directory.path().join("clients.json"),
                "test-bootstrap-token",
            )
            .await
            .unwrap(),
        );
        for metrics_token in ["", "test-metrics-token"] {
            let handler = Arc::new(AdminHttpHandler::new(
                Arc::new(AdminService::new(
                    WebRegistryAdapter::new(registry.clone(), Arc::new(Store::in_memory())),
                    b"test-admin-token".to_vec(),
                )),
                Arc::new(OperationsHandler::new(
                    Readiness::new(Vec::new(), Duration::from_secs(1)),
                    Arc::new(Metrics::default()),
                    metrics_token.as_bytes().to_vec(),
                    None,
                )),
            ));
            for (path, status) in [("/healthz", 200), ("/readyz", 503), ("/metrics", 200)] {
                for method in ["GET", "HEAD", "POST"] {
                    let response = admin_request(
                        handler.clone(),
                        format!(
                            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer test-metrics-token\r\nContent-Length: 0\r\n\r\n"
                        ),
                    )
                    .await;
                    let expected = if path == "/metrics" && metrics_token.is_empty() {
                        404
                    } else if method == "POST" {
                        405
                    } else {
                        status
                    };
                    assert!(
                        response.starts_with(&format!("HTTP/1.1 {expected} ")),
                        "{method} {path}: {response}"
                    );
                    if expected == 405 {
                        assert!(response.contains("\r\nallow: GET, HEAD\r\n"));
                    }
                    if method == "HEAD" {
                        assert!(response.ends_with("\r\n\r\n"));
                    }
                }
            }
            if !metrics_token.is_empty() {
                let response = admin_request(
                    handler,
                    "HEAD /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".into(),
                )
                .await;
                assert!(response.starts_with("HTTP/1.1 401 "));
            }
        }
        registry.close().await.unwrap();
    }

    #[test]
    fn forwarded_addresses_are_trusted_only_from_loopback() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.1, 203.0.113.2".parse().unwrap(),
        );
        assert_eq!(
            client_address("127.0.0.1".parse().unwrap(), &headers, true),
            "203.0.113.2".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            client_address("192.0.2.10".parse().unwrap(), &headers, true),
            "192.0.2.10".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            client_address("127.0.0.1".parse().unwrap(), &headers, false),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn http2_authority_is_used_as_the_public_host() {
        let request = Request::builder()
            .version(Version::HTTP_2)
            .uri("https://porta.example/portal")
            .body(())
            .unwrap();
        assert_eq!(request_host(&request), "porta.example");
    }

    #[test]
    fn ordinary_http2_requests_are_not_absolute_form_proxy_requests() {
        let request = Request::builder()
            .version(Version::HTTP_2)
            .uri("https://porta.example/portal")
            .body(())
            .unwrap();
        assert!(!is_http1_absolute_form(&request));

        let request = Request::builder()
            .version(Version::HTTP_11)
            .uri("https://example.com/")
            .body(())
            .unwrap();
        assert!(is_http1_absolute_form(&request));
    }
}
