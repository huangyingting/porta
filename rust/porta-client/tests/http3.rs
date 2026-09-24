use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use h3_datagram::datagram_handler::HandleDatagramsExt;
use porta_client::tunnel::{self, ClientConfig, ClientError, DeliveryMode, Transport};
use porta_wire::{device_auth::Proof, frame, masque};
use quinn::crypto::rustls::QuicServerConfig;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::PrivatePkcs8KeyDer;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

fn test_pair() -> (quinn::Endpoint, ClientConfig, Arc<AtomicUsize>) {
    test_pair_with_limits(None, None)
}

fn test_pair_with_limits(
    max_udp_payload: Option<u16>,
    stream_receive_window: Option<u32>,
) -> (quinn::Endpoint, ClientConfig, Arc<AtomicUsize>) {
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
    let mut endpoint_config = quinn::EndpointConfig::default();
    if let Some(limit) = max_udp_payload {
        endpoint_config.max_udp_payload_size(limit).unwrap();
    }
    let socket = std::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    socket.set_nonblocking(true).unwrap();
    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls).unwrap()));
    if let Some(window) = stream_receive_window {
        let mut transport = quinn::TransportConfig::default();
        transport.stream_receive_window(window.into());
        server_config.transport_config(Arc::new(transport));
    }
    let server = quinn::Endpoint::new(
        endpoint_config,
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
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

fn ipv4_packet(length: usize, df: bool) -> Vec<u8> {
    let mut packet = vec![0x5a; length];
    packet[..20].fill(0);
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&42_u16.to_be_bytes());
    packet[6] = if df { 0x40 } else { 0 };
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[10, 66, 0, 2]);
    packet[16..20].copy_from_slice(&[198, 51, 100, 1]);
    packet[20..24].copy_from_slice(&[0x12, 0x34, 0x01, 0xbb]);
    packet[24..26].copy_from_slice(&((length - 20) as u16).to_be_bytes());
    packet[26..28].fill(0);
    porta_wire::ip::set_ipv4_header_checksum(&mut packet).unwrap();
    packet
}

#[tokio::test]
async fn live_quic_capacity_fragments_and_delivers_icmp_before_bounded_df_compatibility() {
    let (endpoint, config, _) = test_pair_with_limits(Some(1200), None);
    let client = tokio::spawn(tunnel::connect(config));
    let remote = timeout(Duration::from_secs(2), async {
        endpoint.accept().await.unwrap().await.unwrap()
    })
    .await
    .unwrap();
    let mut server = h3::server::builder()
        .enable_extended_connect(true)
        .enable_datagram(true)
        .build::<_, Bytes>(h3_quinn::Connection::new(remote))
        .await
        .unwrap();
    let resolver = timeout(Duration::from_secs(2), server.accept())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let (_, mut stream) = resolver.resolve_request().await.unwrap();
    let stream_id = stream.id();
    let mut outgoing = server.get_datagram_sender(stream_id);
    let mut incoming = server.get_datagram_reader();
    let driver = tokio::spawn(async move { while matches!(server.accept().await, Ok(Some(_))) {} });
    let response = http::Response::builder()
        .status(200)
        .header("capsule-protocol", "?1")
        .header(frame::HEADER_VERSION, frame::VERSION)
        .header("x-porta-mtu", "1400")
        .header("x-porta-gateway", "10.66.0.1")
        .body(())
        .unwrap();
    stream.send_response(response).await.unwrap();
    timeout(Duration::from_secs(2), stream.recv_data())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let assignment = masque::encode_address_assign(&[masque::Address {
        request_id: 1,
        prefix: "10.66.0.2/32".parse().unwrap(),
    }])
    .unwrap();
    let mut capsule = Vec::new();
    masque::Encoder::new(&mut capsule)
        .write(masque::CAPSULE_ADDRESS_ASSIGN, &assignment)
        .unwrap();
    stream.send_data(Bytes::from(capsule)).await.unwrap();
    let connection = timeout(Duration::from_secs(2), client)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(connection.lease.mtu, 1400);
    assert_eq!(connection.lease.gateway, Some(Ipv4Addr::new(10, 66, 0, 1)));
    assert_eq!(connection.delivery_mode, DeliveryMode::Datagram);

    let original = ipv4_packet(1400, false);
    connection.send(&original).await.unwrap();
    let mut fragments = Vec::new();
    timeout(Duration::from_secs(2), async {
        let mut received = 0;
        while received < original.len() - 20 {
            let datagram = incoming.read_datagram().await.unwrap();
            assert_eq!(datagram.stream_id(), stream_id);
            let mut payload = datagram.into_payload();
            let payload = payload.copy_to_bytes(payload.remaining());
            let packet = masque::decode_ip_packet(&payload).unwrap().to_vec();
            assert!(packet.len() < 1200);
            assert_eq!(porta_wire::ip::internet_checksum(&packet[..20]), 0);
            received += packet.len() - 20;
            fragments.push(packet);
        }
    })
    .await
    .unwrap();
    fragments.sort_by_key(|packet| u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff);
    assert_eq!(fragments.len(), 2);
    assert_eq!(
        fragments
            .iter()
            .flat_map(|packet| packet[20..].iter().copied())
            .collect::<Vec<_>>(),
        original[20..]
    );

    let df = ipv4_packet(1400, true);
    connection.send(&df).await.unwrap();
    let feedback = timeout(Duration::from_secs(2), connection.receive())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&feedback[12..16], &[10, 66, 0, 1]);
    assert_eq!(&feedback[16..20], &[10, 66, 0, 2]);
    assert_eq!(&feedback[20..22], &[3, 4]);
    assert!((1100..1200).contains(&u16::from_be_bytes([feedback[26], feedback[27]])));
    assert_eq!(&feedback[28..], &df[..28]);
    assert_eq!(porta_wire::ip::internet_checksum(&feedback[..20]), 0);
    assert_eq!(porta_wire::ip::internet_checksum(&feedback[20..]), 0);
    assert!(
        timeout(Duration::from_millis(50), stream.recv_data())
            .await
            .is_err(),
        "ordinary PMTU handling unexpectedly used reliable capsules"
    );

    let mut reply = ipv4_packet(100, true);
    reply[12..16].copy_from_slice(&[198, 51, 100, 1]);
    reply[16..20].copy_from_slice(&[10, 66, 0, 2]);
    porta_wire::ip::set_ipv4_header_checksum(&mut reply).unwrap();
    outgoing
        .send_datagram(Bytes::from(masque::encode_ip_packet(&reply)))
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), connection.receive())
            .await
            .unwrap()
            .unwrap(),
        reply
    );

    for _ in 0..2 {
        tokio::time::sleep(Duration::from_millis(110)).await;
        connection.send(&df).await.unwrap();
        let repeated_feedback = timeout(Duration::from_secs(2), connection.receive())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&repeated_feedback[20..22], &[3, 4]);
        assert_eq!(&repeated_feedback[28..], &df[..28]);
        connection.send(&ipv4_packet(40, true)).await.unwrap();
    }
    assert!(
        timeout(Duration::from_millis(50), stream.recv_data())
            .await
            .is_err(),
        "DF compatibility started before its feedback grace"
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    connection.send(&df).await.unwrap();
    let mut expected = Vec::new();
    masque::Encoder::new(&mut expected)
        .write(masque::CAPSULE_DATAGRAM, &masque::encode_ip_packet(&df))
        .unwrap();
    let mut received = Vec::new();
    timeout(Duration::from_secs(2), async {
        while received.len() < expected.len() {
            let mut data = stream.recv_data().await.unwrap().unwrap();
            received.extend_from_slice(&data.copy_to_bytes(data.remaining()));
        }
    })
    .await
    .unwrap();
    assert_eq!(
        received, expected,
        "ignored feedback did not select the explicit capsule exception"
    );
    timeout(Duration::from_secs(2), connection.close())
        .await
        .unwrap();
    endpoint.close(0_u32.into(), b"test complete");
    timeout(Duration::from_secs(2), driver)
        .await
        .unwrap()
        .unwrap();
    endpoint.wait_idle().await;
}

#[tokio::test]
async fn blocked_real_quic_writer_preserves_receive_and_surfaces_deadline_or_cancellation() {
    for cancel in [false, true] {
        let (endpoint, config, _) = test_pair_with_limits(None, Some(4096));
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
        let driver =
            tokio::spawn(async move { while matches!(server.accept().await, Ok(Some(_))) {} });
        stream.send_response(tunnel_response()).await.unwrap();
        timeout(Duration::from_secs(2), stream.recv_data())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let assignment = masque::encode_address_assign(&[masque::Address {
            request_id: 1,
            prefix: "10.66.0.2/32".parse().unwrap(),
        }])
        .unwrap();
        let mut capsule = Vec::new();
        masque::Encoder::new(&mut capsule)
            .write(masque::CAPSULE_ADDRESS_ASSIGN, &assignment)
            .unwrap();
        stream.send_data(Bytes::from(capsule)).await.unwrap();
        let connection = timeout(Duration::from_secs(2), client)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(connection.delivery_mode, DeliveryMode::Capsule);
        let packet = ipv4_packet(1100, true);
        let mut completed = 0;
        // Stop reading the upload stream, exhausting real QUIC stream flow control.
        let mut blocked = loop {
            let mut sending = Box::pin(connection.send(&packet));
            match timeout(Duration::from_millis(100), &mut sending).await {
                Ok(result) => {
                    result.unwrap();
                    completed += 1;
                    assert!(
                        completed < 32,
                        "QUIC stream receive window did not block the writer"
                    );
                }
                Err(_) => break sending,
            }
        };
        let mut reply = ipv4_packet(100, true);
        reply[12..16].copy_from_slice(&[198, 51, 100, 1]);
        reply[16..20].copy_from_slice(&[10, 66, 0, 2]);
        porta_wire::ip::set_ipv4_header_checksum(&mut reply).unwrap();
        let mut capsule = Vec::new();
        masque::Encoder::new(&mut capsule)
            .write(masque::CAPSULE_DATAGRAM, &masque::encode_ip_packet(&reply))
            .unwrap();
        stream.send_data(Bytes::from(capsule)).await.unwrap();
        assert_eq!(
            timeout(Duration::from_millis(500), connection.receive())
                .await
                .unwrap()
                .unwrap(),
            reply,
            "the separate reader stopped while the reliable writer was flow controlled"
        );
        if cancel {
            timeout(Duration::from_secs(1), connection.close())
                .await
                .unwrap();
            assert!(matches!(blocked.await, Err(ClientError::Closed)));
        } else {
            assert!(matches!(
                timeout(Duration::from_secs(4), &mut blocked).await.unwrap(),
                Err(ClientError::Retryable(message)) if message == "HTTP/3 tunnel write timed out"
            ));
            assert!(matches!(
                connection.receive().await,
                Err(ClientError::Retryable(_))
            ));
            timeout(Duration::from_secs(1), connection.close())
                .await
                .unwrap();
        }
        endpoint.close(0_u32.into(), b"test complete");
        timeout(Duration::from_secs(2), driver)
            .await
            .unwrap()
            .unwrap();
        endpoint.wait_idle().await;
    }
}
