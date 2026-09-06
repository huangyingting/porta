use bytes::{Buf, Bytes, BytesMut};
use h2::server::SendResponse;
use http::{Request, Response, StatusCode};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::env;
use std::error::Error;
use std::fs::File;
use std::future::poll_fn;
use std::io::BufReader;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

const TOKEN: &str = "benchmark-token-1234567890";
const MTU: usize = 1400;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut listen = "127.0.0.1:18444".to_string();
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

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            load_certificates(&certificate)?,
            load_private_key(&private_key)?,
        )?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(&listen).await?;
    println!("LISTEN https://{}", listener.local_addr()?);

    loop {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_connection(acceptor, stream).await {
                eprintln!("connection error: {error}");
            }
        });
    }
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

async fn serve_connection(
    acceptor: TlsAcceptor,
    stream: TcpStream,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let tls = acceptor.accept(stream).await?;
    let mut builder = h2::server::Builder::new();
    builder
        .initial_window_size(1 << 20)
        .initial_connection_window_size(4 << 20)
        .max_concurrent_streams(1024)
        .max_frame_size(64 << 10);
    let mut connection = builder.handshake(tls).await?;
    while let Some(request) = connection.accept().await {
        let (request, respond) = request?;
        tokio::spawn(async move {
            if let Err(error) = serve_tunnel(request, respond).await {
                eprintln!("stream error: {error}");
            }
        });
    }
    Ok(())
}

async fn serve_tunnel(
    request: Request<h2::RecvStream>,
    mut respond: SendResponse<Bytes>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if !valid_request(&request) {
        let response = Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(())?;
        respond.send_response(response, true)?;
        return Ok(());
    }
    let session = request
        .headers()
        .get("x-porta-lane-session")
        .and_then(|value| value.to_str().ok())
        .unwrap()
        .to_string();
    let lane = request
        .headers()
        .get("x-porta-lane")
        .and_then(|value| value.to_str().ok())
        .unwrap()
        .to_string();

    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/x-porta-packets")
        .header("cache-control", "no-store")
        .header("x-porta-version", "2")
        .header("x-porta-min-version", "2")
        .header("x-porta-max-version", "2")
        .header("x-porta-address", "10.66.0.2/16")
        .header("x-porta-gateway", "10.66.0.1")
        .header("x-porta-dns", "1.1.1.1")
        .header("x-porta-mtu", "1400")
        .header("x-porta-lane-session", session)
        .header("x-porta-lane", lane)
        .header("x-porta-lanes", "4")
        .body(())?;
    let mut send = respond.send_response(response, false)?;
    send_bytes(&mut send, Bytes::from_static(&[0, 0])).await?;

    let mut body = request.into_body();
    let mut buffered = BytesMut::with_capacity(MTU * 2);
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        body.flow_control().release_capacity(chunk.len())?;
        buffered.extend_from_slice(&chunk);
        loop {
            if buffered.len() < 2 {
                break;
            }
            let size = u16::from_be_bytes([buffered[0], buffered[1]]) as usize;
            if size > MTU {
                return Err("packet exceeds benchmark MTU".into());
            }
            if buffered.len() < size + 2 {
                break;
            }
            buffered.advance(2);
            if size == 0 {
                continue;
            }
            let packet = buffered.split_to(size);
            if !valid_ipv4(&packet) {
                continue;
            }
            let mut framed = BytesMut::with_capacity(size + 2);
            framed.extend_from_slice(&(size as u16).to_be_bytes());
            framed.extend_from_slice(&packet);
            swap_ipv4_endpoints(&mut framed[2..]);
            send_bytes(&mut send, framed.freeze()).await?;
        }
    }
    send.send_data(Bytes::new(), true)?;
    Ok(())
}

fn valid_request(request: &Request<h2::RecvStream>) -> bool {
    if request.method() != http::Method::POST || request.uri().path() != "/v1/tunnel" {
        return false;
    }
    let header = |name: &'static str| {
        request
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
    };
    let lane = header("x-porta-lane").and_then(|value| value.parse::<usize>().ok());
    header("content-type") == Some("application/x-porta-packets")
        && header("x-porta-version") == Some("2")
        && header("authorization").and_then(|value| value.strip_prefix("Bearer ")) == Some(TOKEN)
        && header("x-porta-lanes") == Some("4")
        && lane.is_some_and(|value| value < 4)
        && header("x-porta-lane-session").is_some_and(|value| value.len() >= 16)
}

fn valid_ipv4(packet: &[u8]) -> bool {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
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

async fn send_bytes(
    send: &mut h2::SendStream<Bytes>,
    bytes: Bytes,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    send.reserve_capacity(bytes.len());
    while send.capacity() < bytes.len() {
        match poll_fn(|context| send.poll_capacity(context)).await {
            Some(Ok(_)) => {}
            Some(Err(error)) => return Err(error.into()),
            None => return Err("response stream closed".into()),
        }
    }
    send.send_data(bytes, false)?;
    Ok(())
}

#[allow(dead_code)]
fn _assert_tls_stream_send(_: TlsStream<TcpStream>) {}
