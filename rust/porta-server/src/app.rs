use crate::ops::metrics::Metrics;
use crate::ops::readiness::Readiness;
use crate::server::{bytes_response, plain_response, Handler, ResponseBody};
use anyhow::Result;
use bytes::Bytes;
use futures_util::future::BoxFuture;
use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use std::net::SocketAddr;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub struct OperationsHandler {
    readiness: Readiness,
    metrics: Arc<Metrics>,
    metrics_token: Zeroizing<Vec<u8>>,
    next: Option<Arc<dyn Handler>>,
}

impl OperationsHandler {
    pub fn new(
        readiness: Readiness,
        metrics: Arc<Metrics>,
        metrics_token: impl Into<Vec<u8>>,
        next: Option<Arc<dyn Handler>>,
    ) -> Self {
        Self {
            readiness,
            metrics,
            metrics_token: Zeroizing::new(metrics_token.into()),
            next,
        }
    }

    async fn handle(
        &self,
        request: Request<Incoming>,
        peer: SocketAddr,
    ) -> Result<Response<ResponseBody>> {
        match (request.method().as_str(), request.uri().path()) {
            ("GET" | "HEAD", "/healthz") => Ok(request_bytes_response(
                request.method(),
                StatusCode::OK,
                "application/json",
                Bytes::from_static(b"{\"status\":\"ok\"}\n"),
            )),
            ("GET" | "HEAD", "/readyz") => {
                let report = self.readiness.check().await;
                let status = if report.status == "ready" {
                    StatusCode::OK
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                };
                let mut body = serde_json::to_vec(&report)?;
                body.push(b'\n');
                Ok(request_bytes_response(
                    request.method(),
                    status,
                    "application/json",
                    Bytes::from(body),
                ))
            }
            ("GET" | "HEAD", "/metrics") if !self.metrics_token.is_empty() => {
                if !authorized(request.headers(), &self.metrics_token) {
                    let mut response = plain_response(StatusCode::UNAUTHORIZED, "unauthorized\n");
                    response.headers_mut().insert(
                        http::header::WWW_AUTHENTICATE,
                        http::HeaderValue::from_static("Bearer realm=\"porta-metrics\""),
                    );
                    return Ok(response);
                }
                Ok(request_bytes_response(
                    request.method(),
                    StatusCode::OK,
                    "text/plain; version=0.0.4",
                    Bytes::from(self.metrics.render_prometheus()),
                ))
            }

            (method, path @ ("/healthz" | "/readyz" | "/metrics"))
                if method != "GET"
                    && method != "HEAD"
                    && (path != "/metrics" || !self.metrics_token.is_empty()) =>
            {
                let mut response =
                    plain_response(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed\n");
                response.headers_mut().insert(
                    http::header::ALLOW,
                    http::HeaderValue::from_static("GET, HEAD"),
                );
                Ok(response)
            }
            _ => {
                if let Some(next) = &self.next {
                    next.clone().call(request, peer).await
                } else {
                    Ok(plain_response(StatusCode::NOT_FOUND, "not found\n"))
                }
            }
        }
    }
}

fn request_bytes_response(
    method: &http::Method,
    status: StatusCode,
    content_type: &'static str,
    body: Bytes,
) -> Response<ResponseBody> {
    let content_length = body.len();
    let mut response = bytes_response(
        status,
        content_type,
        if method == http::Method::HEAD {
            Bytes::new()
        } else {
            body
        },
    );
    response.headers_mut().insert(
        http::header::CONTENT_LENGTH,
        content_length
            .to_string()
            .parse()
            .expect("response content length is valid"),
    );
    response
}

impl Handler for OperationsHandler {
    fn call(
        self: Arc<Self>,
        request: Request<Incoming>,
        peer: SocketAddr,
    ) -> BoxFuture<'static, Result<Response<ResponseBody>>> {
        Box::pin(async move { self.handle(request, peer).await })
    }
}

fn authorized(headers: &http::HeaderMap, token: &[u8]) -> bool {
    let Some(value) = headers
        .get(http::header::AUTHORIZATION)
        .map(http::HeaderValue::as_bytes)
    else {
        return false;
    };
    const PREFIX: &[u8] = b"Bearer ";
    if value.len() < PREFIX.len() || !value[..PREFIX.len()].eq_ignore_ascii_case(PREFIX) {
        return false;
    }
    let provided = &value[PREFIX.len()..];
    provided.len() == token.len() && bool::from(provided.ct_eq(token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_comparison_requires_exact_value() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            "Bearer 1234567890abcdef".parse().unwrap(),
        );
        assert!(authorized(&headers, b"1234567890abcdef"));
        assert!(!authorized(&headers, b"1234567890abcdee"));
        headers.insert(
            http::header::AUTHORIZATION,
            "BEARER 1234567890abcdef".parse().unwrap(),
        );
        assert!(authorized(&headers, b"1234567890abcdef"));
    }
}
