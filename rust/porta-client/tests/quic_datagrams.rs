use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::PrivatePkcs8KeyDer;
use tokio::time::timeout;

#[tokio::test(flavor = "current_thread")]
async fn saturated_datagram_queues_recover_in_both_directions() {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )
        .unwrap();
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_send_buffer_size(4096);
    let transport = Arc::new(transport);
    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls).unwrap()));
    server_config.transport_config(Arc::clone(&transport));
    let server =
        quinn::Endpoint::server(server_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let mut client_tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_tls).unwrap()));
    client_config.transport_config(transport);
    let mut client = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    client.set_default_client_config(client_config);
    let (client_connection, server_connection) = timeout(Duration::from_secs(5), async {
        tokio::join!(
            client
                .connect(server.local_addr().unwrap(), "localhost")
                .unwrap(),
            async { server.accept().await.unwrap().await }
        )
    })
    .await
    .expect("loopback QUIC handshake completed");
    let client_connection = client_connection.unwrap();
    let server_connection = server_connection.unwrap();

    for (sender, receiver, marker) in [
        (&client_connection, &server_connection, 1_u8),
        (&server_connection, &client_connection, 2_u8),
    ] {
        let mut latest = Bytes::new();
        // Do not yield until eviction has repeatedly exercised the queue accounting.
        for sequence in 0..16_384_u32 {
            let mut payload = vec![marker; 1000];
            payload[..4].copy_from_slice(&sequence.to_be_bytes());
            latest = Bytes::from(payload);
            sender.send_datagram(latest.clone()).unwrap();
        }
        timeout(Duration::from_secs(5), async {
            while receiver.read_datagram().await.unwrap() != latest {}
        })
        .await
        .expect("the latest datagram survives sustained queue eviction");

        let acknowledgement = Bytes::from(vec![marker; 8]);
        receiver.send_datagram(acknowledgement.clone()).unwrap();
        timeout(Duration::from_secs(5), async {
            while sender.read_datagram().await.unwrap() != acknowledgement {}
        })
        .await
        .expect("the connection remains usable after the queue drains");
    }

    client_connection.close(0_u32.into(), b"queue regression complete");
    timeout(Duration::from_secs(5), async {
        tokio::join!(client.wait_idle(), server.wait_idle());
    })
    .await
    .expect("loopback endpoints shut down");
}
