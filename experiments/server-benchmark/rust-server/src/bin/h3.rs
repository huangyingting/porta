use bytes::{Buf, Bytes, BytesMut};
use h3::ext::Protocol;
use h3_datagram::datagram_handler::HandleDatagramsExt;
use http::{Request, Response, StatusCode};
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;

const TOKEN: &str = "benchmark-token-1234567890";
const MTU: usize = 1400;
const CAPSULE_DATAGRAM: u64 = 0;
const CAPSULE_ADDRESS_ASSIGN: u64 = 1;
const CAPSULE_ADDRESS_REQUEST: u64 = 2;
const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 3;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut listen = "127.0.0.1:18443".to_string();
    let mut certificate = None;
    let mut private_key = None;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--listen" => listen = required_argument(&mut arguments, "--listen")?,
            "--cert" => certificate = Some(required_argument(&mut arguments, "--cert")?),
            "--key" => private_key = Some(required_argument(&mut arguments, "--key")?),
            _ => return Err(format!("unknown argument {argument}").into()),
        }
    }
    let certificate = certificate.ok_or("--cert is required")?;
    let private_key = private_key.ok_or("--key is required")?;
    let address: SocketAddr = listen.parse()?;

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            load_certificates(&certificate)?,
            load_private_key(&private_key)?,
        )?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = QuicServerConfig::try_from(tls)?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let transport = Arc::get_mut(&mut server.transport).ok_or("shared QUIC transport config")?;
    transport
        .max_concurrent_bidi_streams(1024u32.into())
        .datagram_receive_buffer_size(Some(4 << 20))
        .datagram_send_buffer_size(4 << 20);
    let endpoint = quinn::Endpoint::server(server, address)?;
    println!("LISTEN https://{}", endpoint.local_addr()?);

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            if let Err(error) = serve_connection(incoming).await {
                eprintln!("connection error: {error}");
            }
        });
    }
    Ok(())
}

fn required_argument(
    arguments: &mut impl Iterator<Item = String>,
    name: &str,
) -> Result<String, Box<dyn Error>> {
    arguments
        .next()
        .ok_or_else(|| format!("{name} requires a value").into())
}

fn load_certificates(path: &str) -> Result<Vec<CertificateDer<'static>>, Box<dyn Error>> {
    let mut reader = BufReader::new(File::open(path)?);
    let certificates = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        return Err("certificate file is empty".into());
    }
    Ok(certificates)
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, Box<dyn Error>> {
    let mut reader = BufReader::new(File::open(path)?);
    rustls_pemfile::private_key(&mut reader)?.ok_or_else(|| "private key file is empty".into())
}

async fn serve_connection(incoming: quinn::Incoming) -> Result<(), Box<dyn Error + Send + Sync>> {
    let connection = incoming.await?;
    let quic = h3_quinn::Connection::new(connection);
    let mut builder = h3::server::builder();
    builder
        .enable_extended_connect(true)
        .enable_datagram(true)
        .max_field_section_size(16 << 10);
    let mut h3 = builder.build::<_, Bytes>(quic).await?;
    let resolver = h3.accept().await?.ok_or("HTTP/3 connection closed")?;
    let (request, stream) = resolver.resolve_request().await?;
    let stream_id = stream.id();
    let sender = h3.get_datagram_sender(stream_id);
    let reader = h3.get_datagram_reader();
    serve_tunnel(request, stream, sender, reader).await
}

async fn serve_tunnel<S, B, SendHandler, RecvHandler>(
    request: Request<()>,
    mut stream: h3::server::RequestStream<S, B>,
    mut datagram_sender: h3_datagram::datagram_handler::DatagramSender<SendHandler, B>,
    mut datagram_reader: h3_datagram::datagram_handler::DatagramReader<RecvHandler>,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    S: h3::quic::BidiStream<B> + Send + 'static,
    B: Buf + From<Bytes> + Send + 'static,
    SendHandler: h3_datagram::quic_traits::SendDatagram<B> + Send,
    RecvHandler: h3_datagram::quic_traits::RecvDatagram + Send,
{
    if !valid_request(&request) {
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(())?,
            )
            .await?;
        stream.finish().await?;
        return Ok(());
    }
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("capsule-protocol", "?1")
        .header("cache-control", "no-store")
        .header("x-porta-version", "2")
        .header("x-porta-min-version", "2")
        .header("x-porta-max-version", "2")
        .header("x-porta-dns", "1.1.1.1")
        .header("x-porta-mtu", "1400")
        .body(())?;
    stream.send_response(response).await?;

    let mut buffered = BytesMut::with_capacity(256);
    loop {
        let mut data = stream
            .recv_data()
            .await?
            .ok_or("request ended before ADDRESS_REQUEST")?;
        buffered.extend_from_slice(&data.copy_to_bytes(data.remaining()));
        if let Some((capsule_type, value)) = take_capsule(&mut buffered)? {
            if capsule_type != CAPSULE_ADDRESS_REQUEST {
                return Err("expected ADDRESS_REQUEST".into());
            }
            let (request_id, request_id_length) =
                decode_varint(&value).ok_or("invalid ADDRESS_REQUEST ID")?;
            if value.len() != request_id_length + 6
                || value[request_id_length] != 4
                || value[request_id_length + 5] > 32
            {
                return Err("invalid IPv4 ADDRESS_REQUEST".into());
            }
            let mut assignment = BytesMut::with_capacity(14);
            append_varint(&mut assignment, request_id);
            assignment.extend_from_slice(&[4, 10, 66, 0, 2, 32]);
            let mut control = BytesMut::with_capacity(32);
            append_capsule(&mut control, CAPSULE_ADDRESS_ASSIGN, &assignment);
            append_capsule(
                &mut control,
                CAPSULE_ROUTE_ADVERTISEMENT,
                &[4, 0, 0, 0, 0, 255, 255, 255, 255, 0],
            );
            stream.send_data(control.freeze().into()).await?;
            break;
        }
    }

    let stream_id = stream.id();
    let (send_stream, receive_stream) = stream.split();
    tokio::try_join!(
        serve_capsules(send_stream, receive_stream, buffered),
        serve_datagrams(stream_id, &mut datagram_sender, &mut datagram_reader)
    )?;
    Ok(())
}

async fn serve_capsules<S, R, B>(
    mut send_stream: h3::server::RequestStream<S, B>,
    mut receive_stream: h3::server::RequestStream<R, B>,
    mut buffered: BytesMut,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    S: h3::quic::SendStream<B>,
    R: h3::quic::RecvStream,
    B: Buf + From<Bytes>,
{
    loop {
        while let Some((capsule_type, value)) = take_capsule(&mut buffered)? {
            if capsule_type != CAPSULE_DATAGRAM {
                continue;
            }
            let Some(response) = direct_h3_response(&value) else {
                continue;
            };
            let mut capsule = BytesMut::with_capacity(response.len() + 9);
            append_capsule(&mut capsule, CAPSULE_DATAGRAM, &response);
            send_stream.send_data(capsule.freeze().into()).await?;
        }
        let mut data = receive_stream
            .recv_data()
            .await?
            .ok_or("request capsule stream closed")?;
        buffered.extend_from_slice(&data.copy_to_bytes(data.remaining()));
    }
}

async fn serve_datagrams<B, SendHandler, RecvHandler>(
    stream_id: h3::quic::StreamId,
    datagram_sender: &mut h3_datagram::datagram_handler::DatagramSender<SendHandler, B>,
    datagram_reader: &mut h3_datagram::datagram_handler::DatagramReader<RecvHandler>,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    B: Buf + From<Bytes>,
    SendHandler: h3_datagram::quic_traits::SendDatagram<B>,
    RecvHandler: h3_datagram::quic_traits::RecvDatagram,
{
    loop {
        let datagram = datagram_reader.read_datagram().await?;
        if datagram.stream_id() != stream_id {
            continue;
        }
        let mut payload = datagram.into_payload();
        let bytes = payload.copy_to_bytes(payload.remaining());
        let Some(response) = direct_h3_response(&bytes) else {
            continue;
        };
        datagram_sender.send_datagram(response.into())?;
    }
}

fn direct_h3_response(value: &[u8]) -> Option<Bytes> {
    let (context_id, context_length) = decode_varint(value)?;
    let packet = value.get(context_length..)?;
    if context_id != 0 || !valid_ipv4(packet) {
        return None;
    }
    let mut response = BytesMut::with_capacity(packet.len() + 1);
    append_varint(&mut response, 0);
    response.extend_from_slice(packet);
    swap_ipv4_endpoints(&mut response[1..]);
    Some(response.freeze())
}

fn valid_request(request: &Request<()>) -> bool {
    let path = request.uri().path();
    if request.method() != http::Method::CONNECT
        || (path != "/.well-known/masque/ip/*/*/"
            && !path.eq_ignore_ascii_case("/.well-known/masque/ip/%2a/%2a/"))
        || request.extensions().get::<Protocol>() != Some(&Protocol::CONNECT_IP)
    {
        return false;
    }
    let header = |name: &'static str| {
        request
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
    };
    header("capsule-protocol") == Some("?1")
        && header("x-porta-version") == Some("2")
        && header("authorization").and_then(|value| value.strip_prefix("Bearer ")) == Some(TOKEN)
}

fn take_capsule(
    buffer: &mut BytesMut,
) -> Result<Option<(u64, Bytes)>, Box<dyn Error + Send + Sync>> {
    let Some((capsule_type, type_bytes)) = decode_varint(buffer) else {
        return Ok(None);
    };
    let Some((length, length_bytes)) = decode_varint(&buffer[type_bytes..]) else {
        return Ok(None);
    };
    let header = type_bytes + length_bytes;
    let length = usize::try_from(length)?;
    if length > 1 << 20 {
        return Err("capsule exceeds maximum size".into());
    }
    if buffer.len() < header + length {
        return Ok(None);
    }
    buffer.advance(header);
    Ok(Some((capsule_type, buffer.split_to(length).freeze())))
}

fn decode_varint(value: &[u8]) -> Option<(u64, usize)> {
    let first = *value.first()?;
    let length = 1usize << (first >> 6);
    if value.len() < length {
        return None;
    }
    let mut result = u64::from(first & 0x3f);
    for byte in &value[1..length] {
        result = result << 8 | u64::from(*byte);
    }
    Some((result, length))
}

fn append_capsule(output: &mut BytesMut, capsule_type: u64, value: &[u8]) {
    append_varint(output, capsule_type);
    append_varint(output, value.len() as u64);
    output.extend_from_slice(value);
}

fn append_varint(output: &mut BytesMut, value: u64) {
    match value {
        0..=63 => output.extend_from_slice(&[value as u8]),
        64..=16383 => {
            let encoded = (value as u16) | 0x4000;
            output.extend_from_slice(&encoded.to_be_bytes());
        }
        16384..=1073741823 => {
            let encoded = (value as u32) | 0x80000000;
            output.extend_from_slice(&encoded.to_be_bytes());
        }
        1073741824..=4611686018427387903 => {
            let encoded = value | 0xc000000000000000;
            output.extend_from_slice(&encoded.to_be_bytes());
        }
        _ => unreachable!("QUIC varints are limited to 62 bits"),
    }
}

fn valid_ipv4(packet: &[u8]) -> bool {
    if packet.len() < 20 || packet.len() > MTU || packet[0] >> 4 != 4 {
        return false;
    }
    let header_length = usize::from(packet[0] & 0x0f) * 4;
    let total_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    header_length >= 20
        && header_length <= packet.len()
        && total_length == packet.len()
        && packet[12..16] == [10, 66, 0, 2]
}

fn swap_ipv4_endpoints(packet: &mut [u8]) {
    for index in 0..4 {
        packet.swap(12 + index, 16 + index);
    }
    packet[10] = 0;
    packet[11] = 0;
    let header_length = usize::from(packet[0] & 0x0f) * 4;
    let checksum = ipv4_checksum(&packet[..header_length]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in header.chunks(2) {
        sum += if chunk.len() == 2 {
            u32::from(u16::from_be_bytes([chunk[0], chunk[1]]))
        } else {
            u32::from(chunk[0]) << 8
        };
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_varint_round_trips() {
        for value in [0, 63, 64, 16383, 16384, 1073741823, 1073741824] {
            let mut encoded = BytesMut::new();
            append_varint(&mut encoded, value);
            assert_eq!(decode_varint(&encoded), Some((value, encoded.len())));
        }
    }

    #[test]
    fn capsule_decoder_waits_for_complete_value() {
        let mut encoded = BytesMut::new();
        append_capsule(
            &mut encoded,
            CAPSULE_ADDRESS_REQUEST,
            &[1, 4, 0, 0, 0, 0, 32],
        );
        let suffix = encoded.split_off(encoded.len() - 1);
        assert!(take_capsule(&mut encoded).unwrap().is_none());
        encoded.extend_from_slice(&suffix);
        let (capsule_type, value) = take_capsule(&mut encoded).unwrap().unwrap();
        assert_eq!(capsule_type, CAPSULE_ADDRESS_REQUEST);
        assert_eq!(&value[..], &[1, 4, 0, 0, 0, 0, 32]);
        assert!(encoded.is_empty());
    }

    #[test]
    fn validates_encoded_connect_ip_path() {
        let mut request = Request::builder()
            .method(http::Method::CONNECT)
            .uri("/.well-known/masque/ip/%2a/%2A/")
            .header("capsule-protocol", "?1")
            .header("x-porta-version", "2")
            .header("authorization", format!("Bearer {TOKEN}"))
            .body(())
            .unwrap();
        request.extensions_mut().insert(Protocol::CONNECT_IP);
        assert!(valid_request(&request));
    }

    #[test]
    fn swaps_ipv4_addresses_and_updates_checksum() {
        let mut packet = test_packet();

        swap_ipv4_endpoints(&mut packet);

        assert_eq!(&packet[12..16], &[1, 1, 1, 1]);
        assert_eq!(&packet[16..20], &[10, 66, 0, 2]);
        assert_eq!(ipv4_checksum(&packet[..20]), 0);
    }

    #[test]
    fn accepts_non_minimal_zero_context_id() {
        let mut value = Vec::from([0x40, 0]);
        value.extend_from_slice(&test_packet());
        let response = direct_h3_response(&value).unwrap();
        assert_eq!(response[0], 0);
        assert_eq!(&response[13..17], &[1, 1, 1, 1]);
        assert_eq!(&response[17..21], &[10, 66, 0, 2]);
    }

    fn test_packet() -> [u8; 36] {
        let mut packet = [0u8; 36];
        let packet_length = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&packet_length.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 66, 0, 2]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        let checksum = ipv4_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }
}
