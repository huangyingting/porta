//! Signing in to captive networks.
//!
//! Hotel and airport networks hold every connection until the user signs in
//! on a web page, which leak protection blocks. Clients detect this when the
//! gateway's TLS handshake fails while protection is active, and offer a
//! short pause: protection is lifted, the user signs in, and the tunnel
//! comes back once the gateway answers with its own certificate again, or
//! when the pause ends.

use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig as RustlsClientConfig;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// How long protection stays lifted for network sign-in.
pub const SIGN_IN_PAUSE: Duration = Duration::from_secs(5 * 60);
const PROBE_INTERVAL: Duration = Duration::from_secs(5);
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Waits out a sign-in pause of `pause`, returning early once any of
/// `gateways` passes [`crate::tunnel::probe`]. Returns `false` when
/// cancelled, so the caller must not reconnect.
pub async fn wait_for_sign_in(
    gateways: &[String],
    tls: &Arc<RustlsClientConfig>,
    pause: Duration,
    cancellation: &CancellationToken,
) -> bool {
    wait(gateways, tls, pause, PROBE_INTERVAL, cancellation).await
}

async fn wait(
    gateways: &[String],
    tls: &Arc<RustlsClientConfig>,
    pause: Duration,
    interval: Duration,
    cancellation: &CancellationToken,
) -> bool {
    let deadline = Instant::now() + pause;
    loop {
        // Give the user time to sign in before the first check.
        let next = (Instant::now() + interval).min(deadline);
        tokio::select! {
            _ = cancellation.cancelled() => return false,
            _ = tokio::time::sleep_until(next) => {}
        }
        if Instant::now() >= deadline {
            return true;
        }
        for gateway in gateways {
            let timeout = PROBE_TIMEOUT.min(deadline.saturating_duration_since(Instant::now()));
            if crate::tunnel::probe(gateway, tls, timeout, cancellation)
                .await
                .is_ok()
            {
                return !cancellation.is_cancelled();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::net::TcpListener;

    fn certificate(name: &str) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec![name.to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        (
            certificate.der().clone(),
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
    }

    fn trusting(certificate: &CertificateDer<'static>) -> Arc<RustlsClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate.clone()).unwrap();
        Arc::new(
            RustlsClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }

    /// A TLS server for `localhost` presenting `certificate`.
    async fn serve(certificate: (CertificateDer<'static>, PrivateKeyDer<'static>)) -> String {
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.0], certificate.1)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _ = acceptor.accept(stream).await;
                });
            }
        });
        format!("https://localhost:{port}")
    }

    #[tokio::test]
    async fn probes_accept_only_the_gateway_certificate() {
        let gateway = certificate("localhost");
        let trusted = trusting(&gateway.0);
        let url = serve(gateway).await;
        let cancellation = CancellationToken::new();
        crate::tunnel::probe(&url, &trusted, PROBE_TIMEOUT, &cancellation)
            .await
            .unwrap();

        // A captive network answering for the gateway has another certificate.
        let portal = serve(certificate("localhost")).await;
        let error = crate::tunnel::probe(&portal, &trusted, PROBE_TIMEOUT, &cancellation)
            .await
            .unwrap_err();
        assert!(error.is_intercepted(), "{error}");
        assert!(error.to_string().contains("sign in"), "{error}");
    }

    #[tokio::test]
    async fn sign_in_ends_when_the_gateway_answers_or_the_pause_ends() {
        let gateway = certificate("localhost");
        let trusted = trusting(&gateway.0);
        let url = serve(gateway).await;
        let portal = serve(certificate("localhost")).await;
        let cancellation = CancellationToken::new();
        let interval = Duration::from_millis(20);

        let started = Instant::now();
        let gateways = [portal.clone(), url];
        assert!(
            wait(
                &gateways,
                &trusted,
                Duration::from_secs(30),
                interval,
                &cancellation
            )
            .await
        );
        assert!(started.elapsed() < Duration::from_secs(10));

        let started = Instant::now();
        let pause = Duration::from_millis(200);
        assert!(
            wait(
                std::slice::from_ref(&portal),
                &trusted,
                pause,
                interval,
                &cancellation
            )
            .await
        );
        assert!(started.elapsed() >= pause);

        cancellation.cancel();
        assert!(
            !wait(
                &[portal],
                &trusted,
                Duration::from_secs(30),
                interval,
                &cancellation
            )
            .await
        );
    }
}
