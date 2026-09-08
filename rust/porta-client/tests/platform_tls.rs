use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;
use porta_client::identity::Identity;
use porta_client::tls::platform_config;
use porta_client::tunnel::{
    connect, ClientConfig, ClientError, Transport, MASQUE_AUTH_PATH, TUNNEL_PATH,
};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::ServerName;
use tokio::net::{lookup_host, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

#[tokio::test]
#[ignore = "requires PORTA_TLS_TEST_URL pointing to a public HTTPS/HTTP3 gateway"]
async fn public_gateway_uses_platform_trust_over_tcp_and_quic() {
    let address = std::env::var("PORTA_TLS_TEST_URL").expect("set PORTA_TLS_TEST_URL");
    let server = url::Url::parse(&address).unwrap();
    assert_eq!(server.scheme(), "https");
    assert!(server.username().is_empty() && server.password().is_none());
    let host = server.host_str().expect("gateway URL has a hostname");
    let port = server.port_or_known_default().unwrap();
    let limit = Duration::from_secs(20);
    let remote = timeout(limit, lookup_host((host, port)))
        .await
        .unwrap()
        .unwrap()
        .next()
        .expect("gateway hostname resolves");
    let base = platform_config().unwrap();
    let mut tcp_config = (*base).clone();
    tcp_config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(tcp_config));
    let stream = timeout(limit, TcpStream::connect(remote))
        .await
        .unwrap()
        .unwrap();
    let tls = timeout(
        limit,
        connector.connect(ServerName::try_from(host.to_owned()).unwrap(), stream),
    )
    .await
    .expect("TCP TLS handshake completed")
    .expect("platform trust accepts the gateway certificate");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    drop(tls);

    let stream = timeout(limit, TcpStream::connect(remote))
        .await
        .unwrap()
        .unwrap();
    let mismatch = timeout(
        limit,
        connector.connect(
            ServerName::try_from("porta-certificate-mismatch.invalid").unwrap(),
            stream,
        ),
    )
    .await
    .expect("hostname-mismatch verification completed");
    assert!(mismatch.is_err(), "hostname verification remains enforced");

    let local = if remote.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    let mut endpoint = quinn::Endpoint::client(local).unwrap();
    let mut quic_config = (*base).clone();
    quic_config.alpn_protocols = vec![b"h3".to_vec()];
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(quic_config).unwrap(),
    )));
    let connection = timeout(limit, endpoint.connect(remote, host).unwrap())
        .await
        .expect("QUIC TLS handshake completed")
        .expect("platform trust accepts the gateway certificate over QUIC");
    connection.close(0_u32.into(), b"certificate probe complete");
    timeout(limit, endpoint.wait_idle()).await.unwrap();

    let identity = Arc::new(
        Identity::from_signing_key(SigningKey::random(&mut OsRng), "CI live transport probe")
            .unwrap(),
    );
    for transport in [Transport::Http2, Transport::Http3] {
        let identity = Arc::clone(&identity);
        let token = "ci-live-probe-invalid-account".to_owned();
        let proof_token = token.clone();
        let result = timeout(
            limit,
            connect(ClientConfig {
                url: address.clone(),
                token,
                transport,
                tls: Arc::clone(&base),
                timeout: limit,
                dial_address: Some(remote),
                proof: Arc::new(move |method: &str, path: &str| {
                    assert!(matches!(
                        (transport, method, path),
                        (Transport::Http2, "POST", TUNNEL_PATH)
                            | (Transport::Http3, "CONNECT", MASQUE_AUTH_PATH)
                    ));
                    identity
                        .proof(&proof_token, method, path)
                        .map_err(ClientError::permanent)
                }),
                socket_protector: None,
                cancellation: CancellationToken::new(),
            }),
        )
        .await
        .expect("live authentication probe completed");
        let error = match result {
            Ok(connection) => {
                connection.close().await;
                panic!("invalid account token unexpectedly established a tunnel");
            }
            Err(error) => error,
        };
        assert!(
            matches!(&error, ClientError::Permanent(detail) if detail.contains("HTTP 401")),
            "{transport:?} did not reach the gateway authentication response: {error}"
        );
    }

    println!(
        "{}: platform TLS and rejected-authentication probes succeeded over HTTP/2 and HTTP/3",
        std::env::consts::OS
    );
}
