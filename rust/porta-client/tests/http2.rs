use std::future::poll_fn;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use porta_client::tunnel::{
    self, ClientConfig, ClientError, DeliveryMode, ProofProvider, SocketProtector, Transport,
    TUNNEL_PATH,
};
use porta_wire::device_auth::Proof;
use porta_wire::frame;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::PrivatePkcs8KeyDer;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

struct TestServer {
    address: SocketAddr,
    certificate: rustls::pki_types::CertificateDer<'static>,
    lanes: mpsc::Receiver<usize>,
    cancellation: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

struct RecordingProtector {
    calls: AtomicUsize,
    error: Option<ClientError>,
}

impl SocketProtector for RecordingProtector {
    fn prepare(&self, descriptor: i64) -> Result<(), ClientError> {
        assert!(descriptor >= 0);
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.error.clone().map_or(Ok(()), Err)
    }
}

impl TestServer {
    async fn start() -> Self {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let certificate = cert.der().clone();
        let private_key = PrivatePkcs8KeyDer::from(signing_key.serialize_der());
        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], private_key.into())
            .unwrap();
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let (lanes_tx, lanes) = mpsc::channel(16);
        let cancellation = CancellationToken::new();
        let run_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = run_cancellation.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else {
                            break;
                        };
                        let acceptor = acceptor.clone();
                        let lanes = lanes_tx.clone();
                        connections.spawn(async move {
                            let Ok(stream) = acceptor.accept(stream).await else {
                                return;
                            };
                            serve_connection(stream, lanes).await;
                        });
                    }

                }
            }
            connections.shutdown().await;
        });
        Self {
            address,
            certificate,
            lanes,
            cancellation,
            task,
        }
    }

    fn client_config(&self, transport: Transport, timeout: Duration) -> ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.certificate.clone()).unwrap();
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let proof_calls = Arc::new(AtomicUsize::new(0));
        let proof: Arc<dyn ProofProvider> = Arc::new(move |method: &str, path: &str| {
            assert_eq!(method, "POST");
            assert_eq!(path, TUNNEL_PATH);
            let call = proof_calls.fetch_add(1, Ordering::Relaxed);
            Ok(Proof {
                device_id: "d-AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                name: "rust-test".to_owned(),
                public_key: "AA".to_owned(),
                timestamp: "1800000000".to_owned(),
                nonce: format!("proof-{call}"),
                signature: "AA".to_owned(),
            })
        });
        ClientConfig {
            url: format!("https://localhost:{}", self.address.port()),
            token: "0123456789abcdef0123456789abcdef".to_owned(),
            transport,
            tls: Arc::new(tls),
            timeout,
            dial_address: Some(self.address),
            proof,
            socket_protector: None,
            cancellation: CancellationToken::new(),
        }
    }

    async fn wait_for_lanes(&mut self) {
        let mut seen = [false; 4];
        while !seen.into_iter().all(|ready| ready) {
            let lane = tokio::time::timeout(Duration::from_secs(2), self.lanes.recv())
                .await
                .unwrap()
                .unwrap();
            seen[lane] = true;
        }
    }

    async fn close(self) {
        self.cancellation.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(1), self.task).await;
    }
}

async fn serve_connection(stream: TlsStream<TcpStream>, lanes: mpsc::Sender<usize>) {
    let Ok(mut connection) = ::h2::server::handshake(stream).await else {
        return;
    };
    while let Some(accepted) = connection.accept().await {
        let Ok((request, respond)) = accepted else {
            return;
        };
        tokio::spawn(serve_tunnel(request, respond, lanes.clone()));
    }
}

async fn serve_tunnel(
    request: http::Request<::h2::RecvStream>,
    mut respond: ::h2::server::SendResponse<Bytes>,
    lanes: mpsc::Sender<usize>,
) {
    let lane = request
        .headers()
        .get("x-porta-lane")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap();
    let session = request
        .headers()
        .get("x-porta-lane-session")
        .unwrap()
        .clone();
    let response = http::Response::builder()
        .status(http::StatusCode::OK)
        .header(http::header::CONTENT_TYPE, frame::CONTENT_TYPE)
        .header(frame::HEADER_VERSION, frame::VERSION)
        .header("x-porta-address", "10.66.0.2/29")
        .header("x-porta-gateway", "10.66.0.1")
        .header("x-porta-dns", "1.1.1.1")
        .header("x-porta-mtu", "1300")
        .header("x-porta-lane-session", session)
        .header("x-porta-lane", lane)
        .header("x-porta-lanes", 4)
        .body(())
        .unwrap();
    let Ok(mut sender) = respond.send_response(response, false) else {
        return;
    };
    if send_data(&mut sender, Bytes::from_static(&[0, 0]))
        .await
        .is_err()
    {
        return;
    }
    let _ = lanes.send(lane).await;

    let mut receiver = request.into_body();
    let mut framed = BytesMut::new();
    while let Some(data) = receiver.data().await {
        let Ok(data) = data else {
            return;
        };
        let length = data.len();
        framed.extend_from_slice(&data);
        if receiver.flow_control().release_capacity(length).is_err() {
            return;
        }
        while framed.len() >= 2 {
            let size = usize::from(u16::from_be_bytes([framed[0], framed[1]]));
            if framed.len() < size + 2 {
                break;
            }
            framed.advance(2);
            let mut packet = framed.split_to(size).freeze();
            if packet.is_empty() {
                continue;
            }
            let mut reply = packet.to_vec();
            reply.copy_within(12..16, 16);
            reply[12..16].copy_from_slice(&packet[16..20]);
            packet = Bytes::from(reply);
            let mut response = Vec::with_capacity(packet.len() + 2);
            response.extend_from_slice(&(packet.len() as u16).to_be_bytes());
            response.extend_from_slice(&packet);
            if send_data(&mut sender, Bytes::from(response)).await.is_err() {
                return;
            }
        }
    }
}

async fn send_data(
    sender: &mut ::h2::SendStream<Bytes>,
    mut data: Bytes,
) -> Result<(), ::h2::Error> {
    while data.has_remaining() {
        sender.reserve_capacity(data.remaining());
        let capacity = poll_fn(|context| sender.poll_capacity(context))
            .await
            .ok_or_else(|| ::h2::Error::from(::h2::Reason::CANCEL))??;
        let length = capacity.min(data.remaining());
        sender.send_data(data.split_to(length), false)?;
    }
    Ok(())
}

fn packet() -> Vec<u8> {
    vec![
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 66, 0, 2, 1, 1, 1, 1,
    ]
}

#[tokio::test]
async fn four_lane_http2_round_trip() {
    let mut server = TestServer::start().await;
    let connection =
        tunnel::connect(server.client_config(Transport::Http2, Duration::from_secs(2)))
            .await
            .unwrap();
    assert_eq!(connection.transport, Transport::Http2);
    assert_eq!(connection.delivery_mode, DeliveryMode::Framed);
    server.wait_for_lanes().await;

    connection.send(&packet()).await.unwrap();
    let received = tokio::time::timeout(Duration::from_secs(2), connection.receive())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received[12..16], &[1, 1, 1, 1]);
    assert_eq!(&received[16..20], &[10, 66, 0, 2]);
    connection.close().await;
    server.close().await;
}

#[tokio::test]
async fn automatic_transport_falls_back_to_http2() {
    let server = TestServer::start().await;
    let connection =
        tunnel::connect(server.client_config(Transport::Auto, Duration::from_millis(300)))
            .await
            .unwrap();
    assert_eq!(connection.transport, Transport::Http2);
    connection.close().await;
    server.close().await;
}

#[tokio::test]
async fn socket_protector_runs_before_each_http2_lane_connects() {
    let mut server = TestServer::start().await;
    let protector = Arc::new(RecordingProtector {
        calls: AtomicUsize::new(0),
        error: None,
    });
    let mut config = server.client_config(Transport::Http2, Duration::from_secs(2));
    config.socket_protector = Some(protector.clone());
    let connection = tunnel::connect(config).await.unwrap();
    server.wait_for_lanes().await;
    assert_eq!(protector.calls.load(Ordering::Relaxed), 4);
    connection.close().await;
    server.close().await;
}

#[tokio::test]
async fn socket_protector_errors_keep_their_transport_classification() {
    let server = TestServer::start().await;
    let protector = Arc::new(RecordingProtector {
        calls: AtomicUsize::new(0),
        error: Some(ClientError::unavailable("socket binding failed")),
    });
    let mut config = server.client_config(Transport::Http2, Duration::from_millis(300));
    config.socket_protector = Some(protector.clone());
    let error = match tunnel::connect(config).await {
        Ok(connection) => {
            connection.close().await;
            panic!("socket protection failure unexpectedly connected")
        }
        Err(error) => error,
    };
    assert!(error.is_transport_unavailable(), "{error}");
    assert!(protector.calls.load(Ordering::Relaxed) >= 1);
    server.close().await;
}
