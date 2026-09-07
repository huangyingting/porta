use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use porta_client::tunnel::{self, ClientConfig, ClientError, DeliveryMode, Transport};
use porta_wire::{device_auth::Proof, frame, masque};
use quinn::crypto::rustls::QuicServerConfig;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::PrivatePkcs8KeyDer;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

fn test_pair() -> (quinn::Endpoint, ClientConfig, Arc<AtomicUsize>) {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate = cert.der().clone();
    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.clone()],
            PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )
        .unwrap();
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let server = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls).unwrap())),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .unwrap();
    let address = server.local_addr().unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).unwrap();
    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let proof_calls = Arc::new(AtomicUsize::new(0));
    let calls = proof_calls.clone();
    let config = ClientConfig {
        url: format!("https://localhost:{}", address.port()),
        token: "test-account-token".to_owned(),
        transport: Transport::Http3,
        tls: Arc::new(tls),
        timeout: Duration::from_secs(3),
        dial_address: Some(address),
        proof: Arc::new(move |method: &str, path: &str| {
            assert_eq!(method, "CONNECT");
            assert_eq!(path, tunnel::MASQUE_AUTH_PATH);
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(Proof {
                device_id: "d-AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                name: "rust-test".to_owned(),
                public_key: "AA".to_owned(),
                timestamp: "1800000000".to_owned(),
                nonce: "AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                signature: "AA".to_owned(),
            })
        }),
        socket_protector: None,
        cancellation: CancellationToken::new(),
    };
    (server, config, proof_calls)
}

fn tunnel_response() -> http::Response<()> {
    http::Response::builder()
        .status(200)
        .header("capsule-protocol", "?1")
        .header(frame::HEADER_VERSION, frame::VERSION)
        .header("x-porta-mtu", "1100")
        .header("x-porta-dns", "1.1.1.1")
        .body(())
        .unwrap()
}

#[tokio::test]
async fn extended_connect_waits_for_peer_settings() {
    let (endpoint, config, proof_calls) = test_pair();
    let client = tokio::spawn(tunnel::connect(config));
    let remote = timeout(Duration::from_secs(2), async {
        endpoint.accept().await.unwrap().await.unwrap()
    })
    .await
    .unwrap();

    assert!(
        timeout(Duration::from_millis(100), remote.accept_bi())
            .await
            .is_err(),
        "client sent Extended CONNECT before receiving server SETTINGS"
    );
    assert_eq!(proof_calls.load(Ordering::Relaxed), 0);

    let mut server = h3::server::builder()
        .enable_extended_connect(true)
        .build::<_, Bytes>(h3_quinn::Connection::new(remote.clone()))
        .await
        .unwrap();
    let resolver = timeout(Duration::from_secs(2), server.accept())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let (request, mut stream) = resolver.resolve_request().await.unwrap();
    assert_eq!(request.method(), http::Method::CONNECT);
    assert_eq!(
        request.extensions().get::<h3::ext::Protocol>(),
        Some(&h3::ext::Protocol::CONNECT_IP)
    );
    stream.send_response(tunnel_response()).await.unwrap();
    timeout(Duration::from_secs(2), stream.recv_data())
        .await
        .unwrap()
        .unwrap()
        .expect("client requested its tunnel address");
    let address = masque::encode_address_assign(&[masque::Address {
        request_id: 1,
        prefix: "10.66.0.2/32".parse().unwrap(),
    }])
    .unwrap();
    let mut capsule = Vec::new();
    masque::Encoder::new(&mut capsule)
        .write(masque::CAPSULE_ADDRESS_ASSIGN, &address)
        .unwrap();
    stream.send_data(Bytes::from(capsule)).await.unwrap();

    let connection = timeout(Duration::from_secs(2), client)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(connection.delivery_mode, DeliveryMode::Capsule);
    assert_eq!(connection.lease.address, "10.66.0.2/32".parse().unwrap());
    assert_eq!(proof_calls.load(Ordering::Relaxed), 1);
    timeout(Duration::from_secs(2), connection.close())
        .await
        .unwrap();
    endpoint.close(0_u32.into(), b"test complete");
    endpoint.wait_idle().await;
}

#[tokio::test]
async fn unsupported_extended_connect_does_not_send_a_request() {
    let (endpoint, config, proof_calls) = test_pair();
    let mut client = tokio::spawn(tunnel::connect(config));
    let remote = timeout(Duration::from_secs(2), async {
        endpoint.accept().await.unwrap().await.unwrap()
    })
    .await
    .unwrap();
    let mut server = h3::server::builder()
        .build::<_, Bytes>(h3_quinn::Connection::new(remote))
        .await
        .unwrap();

    timeout(Duration::from_secs(2), async {
        tokio::select! {
            result = &mut client => {
                assert!(matches!(result.unwrap(), Err(ClientError::TransportUnavailable(_))));
            }
            accepted = server.accept() => {
                assert!(!matches!(accepted, Ok(Some(_))),
                    "client sent Extended CONNECT to a server that did not enable it");
                assert!(matches!(client.await.unwrap(), Err(ClientError::TransportUnavailable(_))));
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(proof_calls.load(Ordering::Relaxed), 0);
    endpoint.close(0_u32.into(), b"test complete");
    endpoint.wait_idle().await;
}

#[tokio::test]
async fn pending_peer_settings_remain_cancellable_and_deadline_bounded() {
    for cancel in [false, true] {
        let (endpoint, mut config, proof_calls) = test_pair();
        config.timeout = Duration::from_secs(1);
        let cancellation = config.cancellation.clone();
        let client = tokio::spawn(tunnel::connect(config));
        let remote = timeout(Duration::from_secs(2), async {
            endpoint.accept().await.unwrap().await.unwrap()
        })
        .await
        .unwrap();
        if cancel {
            cancellation.cancel();
        }
        let result = timeout(Duration::from_secs(2), client)
            .await
            .unwrap()
            .unwrap();
        if cancel {
            assert!(matches!(result, Err(ClientError::Closed)));
        } else {
            assert!(matches!(result, Err(ClientError::TransportUnavailable(_))));
        }
        assert_eq!(proof_calls.load(Ordering::Relaxed), 0);
        timeout(Duration::from_secs(2), remote.closed())
            .await
            .expect("failed setup retained the QUIC connection");
        endpoint.close(0_u32.into(), b"test complete");
        endpoint.wait_idle().await;
    }
}

#[tokio::test]
async fn dropping_setup_before_peer_settings_closes_the_connection() {
    let (endpoint, config, proof_calls) = test_pair();
    let client = tokio::spawn(tunnel::connect(config));
    let remote = timeout(Duration::from_secs(2), async {
        endpoint.accept().await.unwrap().await.unwrap()
    })
    .await
    .unwrap();
    client.abort();
    assert!(matches!(client.await, Err(error) if error.is_cancelled()));
    assert_eq!(proof_calls.load(Ordering::Relaxed), 0);
    timeout(Duration::from_secs(2), remote.closed())
        .await
        .expect("dropped setup retained the QUIC connection");
    endpoint.close(0_u32.into(), b"test complete");
    endpoint.wait_idle().await;
}

#[tokio::test]
async fn address_assignment_timeout_does_not_allow_transport_fallback() {
    let (endpoint, mut config, _proof_calls) = test_pair();
    config.timeout = Duration::from_secs(1);
    let client = tokio::spawn(tunnel::connect(config));
    let remote = timeout(Duration::from_secs(2), async {
        endpoint.accept().await.unwrap().await.unwrap()
    })
    .await
    .unwrap();
    let mut server = h3::server::builder()
        .enable_extended_connect(true)
        .build::<_, Bytes>(h3_quinn::Connection::new(remote))
        .await
        .unwrap();
    let resolver = timeout(Duration::from_secs(2), server.accept())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let (_, mut stream) = resolver.resolve_request().await.unwrap();
    stream.send_response(tunnel_response()).await.unwrap();
    timeout(Duration::from_secs(2), stream.recv_data())
        .await
        .unwrap()
        .unwrap()
        .expect("client requested its tunnel address");

    let error = match timeout(Duration::from_secs(3), client)
        .await
        .unwrap()
        .unwrap()
    {
        Err(error) => error,
        Ok(connection) => {
            connection.close().await;
            panic!("connection succeeded without an address assignment")
        }
    };
    assert!(matches!(error, ClientError::Retryable(_)), "{error}");
    endpoint.close(0_u32.into(), b"test complete");
    endpoint.wait_idle().await;
}
