use std::cmp::Ordering;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use thiserror::Error;

pub const CAPSULE_DATAGRAM: u64 = 0x00;
pub const CAPSULE_ADDRESS_ASSIGN: u64 = 0x01;
pub const CAPSULE_ADDRESS_REQUEST: u64 = 0x02;
pub const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 0x03;
pub const MAX_CAPSULE_SIZE: usize = 1 << 20;

pub const MTU_DISCOVERY_HEADER: &str = "X-Porta-MTU-Discovery";
pub const CAPSULE_MTU_SELECT: u64 = 0xff7000;
pub const CAPSULE_MTU_SELECTED: u64 = 0xff7001;
pub const SAFE_MTU: u16 = 1100;
pub const MAX_DISCOVERED_MTU: u16 = 1400;
pub const MTU_PROBE_CONTEXT: u64 = 1;
pub const MTU_TOKEN_SIZE: usize = 16;

const MAX_QUIC_VARINT: u64 = (1_u64 << 62) - 1;

#[derive(Debug, Error)]
pub enum MasqueError {
    #[error("MASQUE capsule exceeds maximum size")]
    CapsuleTooLarge,
    #[error("QUIC variable-length integer exceeds 62 bits")]
    VarIntTooLarge,
    #[error("truncated QUIC variable-length integer")]
    TruncatedVarInt,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("read capsule length: {0}")]
    ReadCapsuleLength(#[source] io::Error),
    #[error("read capsule value: {0}")]
    ReadCapsuleValue(#[source] io::Error),
    #[error("unknown MASQUE context ID: {0}")]
    UnknownContext(u64),
    #[error("MASQUE IP datagram has an empty payload")]
    EmptyIpDatagram,
    #[error("malformed MASQUE address entry")]
    MalformedAddress,
    #[error("malformed MASQUE address entry: {0}")]
    MalformedAddressDetail(String),
    #[error("ADDRESS_REQUEST requires at least one address")]
    EmptyAddressRequest,
    #[error("ADDRESS_REQUEST IDs must be non-zero")]
    ZeroAddressRequestId,
    #[error("ADDRESS_REQUEST contained no addresses")]
    DecodedEmptyAddressRequest,
    #[error("ADDRESS_REQUEST contained request ID zero")]
    DecodedZeroAddressRequestId,
    #[error("malformed MASQUE route")]
    MalformedRoute,
    #[error("malformed MASQUE route: {0}")]
    MalformedRouteDetail(String),
    #[error("MASQUE routes must be ordered and non-overlapping")]
    RoutesNotOrdered,
    #[error("MASQUE routes are unordered or overlapping")]
    DecodedRoutesNotOrdered,
    #[error("invalid MTU discovery message")]
    InvalidMtuMessage,
}

pub type Result<T> = std::result::Result<T, MasqueError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capsule<T = Vec<u8>> {
    pub capsule_type: u64,
    pub value: T,
}

pub struct Encoder<W> {
    writer: W,
    header: [u8; 16],
}

impl<W: Write> Encoder<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            header: [0; 16],
        }
    }

    pub fn write(&mut self, capsule_type: u64, value: &[u8]) -> Result<()> {
        if value.len() > MAX_CAPSULE_SIZE {
            return Err(MasqueError::CapsuleTooLarge);
        }
        let mut offset = 0;
        offset += encode_varint_into(capsule_type, &mut self.header[offset..])?;
        offset += encode_varint_into(value.len() as u64, &mut self.header[offset..])?;
        self.writer.write_all(&self.header[..offset])?;
        self.writer.write_all(value)?;
        Ok(())
    }

    pub fn write_ip_packet(&mut self, packet: &[u8]) -> Result<()> {
        if packet.len() >= MAX_CAPSULE_SIZE {
            return Err(MasqueError::CapsuleTooLarge);
        }
        let mut offset = 0;
        offset += encode_varint_into(CAPSULE_DATAGRAM, &mut self.header[offset..])?;
        offset += encode_varint_into((packet.len() + 1) as u64, &mut self.header[offset..])?;
        self.header[offset] = 0;
        offset += 1;
        self.writer.write_all(&self.header[..offset])?;
        self.writer.write_all(packet)?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }

    pub fn get_ref(&self) -> &W {
        &self.writer
    }

    pub fn get_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    pub fn into_inner(self) -> W {
        self.writer
    }
}

pub struct Decoder<R> {
    reader: R,
}

impl<R: Read> Decoder<R> {
    pub fn new(reader: R) -> Self {
        Self { reader }
    }

    pub fn read(&mut self) -> Result<Capsule> {
        let mut value = Vec::new();
        let capsule = self.read_into(&mut value)?;
        Ok(Capsule {
            capsule_type: capsule.capsule_type,
            value,
        })
    }

    pub fn read_into<'a>(&mut self, buffer: &'a mut Vec<u8>) -> Result<Capsule<&'a [u8]>> {
        let capsule_type = read_varint(&mut self.reader)?;
        let length = read_varint(&mut self.reader).map_err(map_capsule_length_read_error)?;
        if length > MAX_CAPSULE_SIZE as u64 {
            return Err(MasqueError::CapsuleTooLarge);
        }
        buffer.resize(length as usize, 0);
        self.reader
            .read_exact(buffer)
            .map_err(MasqueError::ReadCapsuleValue)?;
        Ok(Capsule {
            capsule_type,
            value: buffer,
        })
    }

    pub fn get_ref(&self) -> &R {
        &self.reader
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    pub fn into_inner(self) -> R {
        self.reader
    }
}

fn map_capsule_length_read_error(error: MasqueError) -> MasqueError {
    match error {
        MasqueError::Io(error) => MasqueError::ReadCapsuleLength(error),
        other => other,
    }
}

pub fn encode_varint(value: u64) -> Result<Vec<u8>> {
    let mut encoded = [0; 8];
    let length = encode_varint_into(value, &mut encoded)?;
    Ok(encoded[..length].to_vec())
}

fn encode_varint_into(value: u64, output: &mut [u8]) -> Result<usize> {
    let length = match value {
        0..=63 => {
            output[0] = value as u8;
            return Ok(1);
        }
        64..=16_383 => 2_usize,
        16_384..=1_073_741_823 => 4_usize,
        1_073_741_824..=MAX_QUIC_VARINT => 8_usize,
        _ => return Err(MasqueError::VarIntTooLarge),
    };
    match length {
        2 => output[..2].copy_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        4 => output[..4].copy_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes()),
        8 => output[..8].copy_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes()),
        _ => unreachable!(),
    }
    Ok(length)
}

pub fn parse_varint(input: &[u8]) -> Result<(u64, usize)> {
    let Some(first) = input.first().copied() else {
        return Err(MasqueError::TruncatedVarInt);
    };
    let length = 1_usize << (first >> 6);
    if input.len() < length {
        return Err(MasqueError::TruncatedVarInt);
    }
    let mut encoded = [0_u8; 8];
    encoded[8 - length..].copy_from_slice(&input[..length]);
    encoded[8 - length] &= 0x3f;
    Ok((u64::from_be_bytes(encoded), length))
}

fn read_varint(reader: &mut impl Read) -> Result<u64> {
    let mut encoded = [0_u8; 8];
    reader.read_exact(&mut encoded[..1])?;
    let length = 1_usize << (encoded[0] >> 6);
    reader.read_exact(&mut encoded[1..length])?;
    encoded[0] &= 0x3f;
    let mut aligned = [0_u8; 8];
    aligned[8 - length..].copy_from_slice(&encoded[..length]);
    Ok(u64::from_be_bytes(aligned))
}

pub fn encode_ip_packet(packet: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(packet.len() + 1);
    value.push(0);
    value.extend_from_slice(packet);
    value
}

pub fn decode_ip_packet(value: &[u8]) -> Result<&[u8]> {
    let (context_id, consumed) = parse_varint(value)?;
    if context_id != 0 {
        return Err(MasqueError::UnknownContext(context_id));
    }
    if value.len() == consumed {
        return Err(MasqueError::EmptyIpDatagram);
    }
    Ok(&value[consumed..])
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Address {
    pub request_id: u64,
    pub prefix: IpNet,
}

pub fn encode_address_request(addresses: &[Address]) -> Result<Vec<u8>> {
    if addresses.is_empty() {
        return Err(MasqueError::EmptyAddressRequest);
    }
    if addresses.iter().any(|address| address.request_id == 0) {
        return Err(MasqueError::ZeroAddressRequestId);
    }
    encode_addresses(addresses)
}

pub fn decode_address_request(value: &[u8]) -> Result<Vec<Address>> {
    let addresses = decode_addresses(value)?;
    if addresses.is_empty() {
        return Err(MasqueError::DecodedEmptyAddressRequest);
    }
    if addresses.iter().any(|address| address.request_id == 0) {
        return Err(MasqueError::DecodedZeroAddressRequestId);
    }
    Ok(addresses)
}

pub fn encode_address_assign(addresses: &[Address]) -> Result<Vec<u8>> {
    encode_addresses(addresses)
}

pub fn decode_address_assign(value: &[u8]) -> Result<Vec<Address>> {
    decode_addresses(value)
}

fn encode_addresses(addresses: &[Address]) -> Result<Vec<u8>> {
    let mut value = Vec::new();
    for address in addresses {
        let mut request_id = [0; 8];
        let length = encode_varint_into(address.request_id, &mut request_id)?;
        value.extend_from_slice(&request_id[..length]);
        match address.prefix {
            IpNet::V4(prefix) => {
                if prefix.addr() != prefix.network() {
                    return Err(MasqueError::MalformedAddressDetail(
                        "prefix address is not masked".into(),
                    ));
                }
                value.push(4);
                value.extend_from_slice(&prefix.addr().octets());
                value.push(prefix.prefix_len());
            }
            IpNet::V6(prefix) => {
                if prefix.addr() != prefix.network() {
                    return Err(MasqueError::MalformedAddressDetail(
                        "prefix address is not masked".into(),
                    ));
                }
                value.push(6);
                value.extend_from_slice(&prefix.addr().octets());
                value.push(prefix.prefix_len());
            }
        }
    }
    Ok(value)
}

fn decode_addresses(mut value: &[u8]) -> Result<Vec<Address>> {
    let mut addresses = Vec::new();
    while !value.is_empty() {
        let (request_id, consumed) = parse_varint(value)
            .map_err(|error| MasqueError::MalformedAddressDetail(format!("request ID: {error}")))?;
        value = &value[consumed..];
        let (&version, rest) = value.split_first().ok_or(MasqueError::MalformedAddress)?;
        value = rest;
        let (address, prefix_bits, consumed) = match version {
            4 if value.len() >= 5 => {
                let address = Ipv4Addr::new(value[0], value[1], value[2], value[3]);
                (IpAddr::V4(address), value[4], 5)
            }
            6 if value.len() >= 17 => {
                let mut bytes = [0; 16];
                bytes.copy_from_slice(&value[..16]);
                (IpAddr::V6(Ipv6Addr::from(bytes)), value[16], 17)
            }
            4 | 6 => return Err(MasqueError::MalformedAddress),
            _ => {
                return Err(MasqueError::MalformedAddressDetail(format!(
                    "invalid IP version {version}"
                )))
            }
        };
        value = &value[consumed..];
        let prefix = match address {
            IpAddr::V4(address) => {
                if prefix_bits > 32 {
                    return Err(MasqueError::MalformedAddressDetail(format!(
                        "invalid prefix length {prefix_bits}"
                    )));
                }
                let prefix = Ipv4Net::new(address, prefix_bits)
                    .map_err(|_| MasqueError::MalformedAddress)?;
                if prefix.addr() != prefix.network() {
                    return Err(MasqueError::MalformedAddressDetail(
                        "prefix address is not masked".into(),
                    ));
                }
                IpNet::V4(prefix)
            }
            IpAddr::V6(address) => {
                if prefix_bits > 128 {
                    return Err(MasqueError::MalformedAddressDetail(format!(
                        "invalid prefix length {prefix_bits}"
                    )));
                }
                let prefix = Ipv6Net::new(address, prefix_bits)
                    .map_err(|_| MasqueError::MalformedAddress)?;
                if prefix.addr() != prefix.network() {
                    return Err(MasqueError::MalformedAddressDetail(
                        "prefix address is not masked".into(),
                    ));
                }
                IpNet::V6(prefix)
            }
        };
        addresses.push(Address { request_id, prefix });
    }
    Ok(addresses)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Route {
    pub start: IpAddr,
    pub end: IpAddr,
    pub protocol: u8,
}

pub fn encode_route_advertisement(routes: &[Route]) -> Result<Vec<u8>> {
    let mut value = Vec::new();
    for (index, route) in routes.iter().copied().enumerate() {
        if !same_address_family(route.start, route.end) || route.start > route.end {
            return Err(MasqueError::MalformedRoute);
        }
        if index > 0 && compare_routes(routes[index - 1], route) != Ordering::Less {
            return Err(MasqueError::RoutesNotOrdered);
        }
        match (route.start, route.end) {
            (IpAddr::V4(start), IpAddr::V4(end)) => {
                value.push(4);
                value.extend_from_slice(&start.octets());
                value.extend_from_slice(&end.octets());
            }
            (IpAddr::V6(start), IpAddr::V6(end)) => {
                value.push(6);
                value.extend_from_slice(&start.octets());
                value.extend_from_slice(&end.octets());
            }
            _ => return Err(MasqueError::MalformedRoute),
        }
        value.push(route.protocol);
    }
    Ok(value)
}

pub fn decode_route_advertisement(mut value: &[u8]) -> Result<Vec<Route>> {
    let mut routes = Vec::new();
    while !value.is_empty() {
        let version = value[0];
        value = &value[1..];
        let address_length = match version {
            4 => 4,
            6 => 16,
            _ => {
                return Err(MasqueError::MalformedRouteDetail(format!(
                    "invalid IP version {version}"
                )))
            }
        };
        if value.len() < address_length * 2 + 1 {
            return Err(MasqueError::MalformedRoute);
        }
        let (start, end) = if version == 4 {
            (
                IpAddr::V4(Ipv4Addr::new(value[0], value[1], value[2], value[3])),
                IpAddr::V4(Ipv4Addr::new(value[4], value[5], value[6], value[7])),
            )
        } else {
            let mut start = [0; 16];
            let mut end = [0; 16];
            start.copy_from_slice(&value[..16]);
            end.copy_from_slice(&value[16..32]);
            (
                IpAddr::V6(Ipv6Addr::from(start)),
                IpAddr::V6(Ipv6Addr::from(end)),
            )
        };
        let route = Route {
            start,
            end,
            protocol: value[address_length * 2],
        };
        value = &value[address_length * 2 + 1..];
        if route.start > route.end {
            return Err(MasqueError::MalformedRoute);
        }
        if routes
            .last()
            .is_some_and(|previous| compare_routes(*previous, route) != Ordering::Less)
        {
            return Err(MasqueError::DecodedRoutesNotOrdered);
        }
        routes.push(route);
    }
    Ok(routes)
}

fn same_address_family(first: IpAddr, second: IpAddr) -> bool {
    matches!(
        (first, second),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

fn compare_routes(first: Route, second: Route) -> Ordering {
    match (first.start, second.start) {
        (IpAddr::V4(_), IpAddr::V6(_)) => return Ordering::Less,
        (IpAddr::V6(_), IpAddr::V4(_)) => return Ordering::Greater,
        _ => {}
    }
    match first.protocol.cmp(&second.protocol) {
        Ordering::Equal => {}
        ordering => return ordering,
    }
    if first.end < second.start {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

pub type MtuToken = [u8; MTU_TOKEN_SIZE];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtuProbe {
    pub token: MtuToken,
    pub sequence: u16,
    pub size: u16,
}

pub fn parse_mtu_token(value: &str) -> Result<MtuToken> {
    let mut token = [0; MTU_TOKEN_SIZE];
    if value.len() != MTU_TOKEN_SIZE * 2 || hex::decode_to_slice(value, &mut token).is_err() {
        return Err(MasqueError::InvalidMtuMessage);
    }
    Ok(token)
}

pub fn encode_mtu_probe(probe: MtuProbe) -> Result<Vec<u8>> {
    if !(SAFE_MTU..=MAX_DISCOVERED_MTU).contains(&probe.size) || probe.sequence == 0 {
        return Err(MasqueError::InvalidMtuMessage);
    }
    let mut data = vec![0; usize::from(probe.size) + 1];
    data[0] = MTU_PROBE_CONTEXT as u8;
    data[1..17].copy_from_slice(&probe.token);
    data[17..19].copy_from_slice(&probe.sequence.to_be_bytes());
    data[19..21].copy_from_slice(&probe.size.to_be_bytes());
    Ok(data)
}

pub fn is_mtu_probe(data: &[u8]) -> bool {
    data.first() == Some(&(MTU_PROBE_CONTEXT as u8))
}

pub fn decode_mtu_probe(data: &[u8]) -> Result<MtuProbe> {
    if !is_mtu_probe(data)
        || data.len() < usize::from(SAFE_MTU) + 1
        || data.len() > usize::from(MAX_DISCOVERED_MTU) + 1
    {
        return Err(MasqueError::InvalidMtuMessage);
    }
    let mut token = [0; MTU_TOKEN_SIZE];
    token.copy_from_slice(&data[1..17]);
    let probe = MtuProbe {
        token,
        sequence: u16::from_be_bytes([data[17], data[18]]),
        size: u16::from_be_bytes([data[19], data[20]]),
    };
    if probe.sequence == 0
        || usize::from(probe.size) != data.len() - 1
        || data[21..].iter().any(|&value| value != 0)
    {
        return Err(MasqueError::InvalidMtuMessage);
    }
    Ok(probe)
}

pub fn encode_mtu_selection(token: MtuToken, mtu: u16) -> [u8; 18] {
    let mut data = [0; 18];
    data[..16].copy_from_slice(&token);
    data[16..].copy_from_slice(&mtu.to_be_bytes());
    data
}

pub fn decode_mtu_selection(data: &[u8], token: MtuToken) -> Result<u16> {
    if data.len() != 18 || data[..16] != token {
        return Err(MasqueError::InvalidMtuMessage);
    }
    Ok(u16::from_be_bytes([data[16], data[17]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, ErrorKind};

    #[test]
    fn quic_varint_golden_vectors_and_non_minimal_values() {
        for (value, encoded) in [
            (0, vec![0x00]),
            (63, vec![0x3f]),
            (64, vec![0x40, 0x40]),
            (16_383, vec![0x7f, 0xff]),
            (16_384, vec![0x80, 0x00, 0x40, 0x00]),
            (
                MAX_QUIC_VARINT,
                vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ] {
            assert_eq!(encode_varint(value).unwrap(), encoded);
            assert_eq!(parse_varint(&encoded).unwrap(), (value, encoded.len()));
        }
        assert_eq!(parse_varint(&[0x40, 0x00]).unwrap(), (0, 2));
        assert_eq!(parse_varint(&[0x80, 0, 0, 0]).unwrap(), (0, 4));
        assert_eq!(parse_varint(&[0xc0, 0, 0, 0, 0, 0, 0, 0]).unwrap(), (0, 8));
        assert!(matches!(
            encode_varint(1_u64 << 62),
            Err(MasqueError::VarIntTooLarge)
        ));
        assert!(matches!(
            parse_varint(&[0x40]),
            Err(MasqueError::TruncatedVarInt)
        ));
    }

    #[test]
    fn capsule_round_trip_reuses_buffer_and_matches_go_bytes() {
        let mut encoder = Encoder::new(Vec::new());
        encoder.write(CAPSULE_DATAGRAM, &[0, 1, 2, 3]).unwrap();
        let encoded = encoder.into_inner();
        assert_eq!(encoded, [0, 4, 0, 1, 2, 3]);

        let mut decoder = Decoder::new(Cursor::new(encoded));
        let mut buffer = Vec::with_capacity(16);
        let original = buffer.as_ptr();
        let capsule = decoder.read_into(&mut buffer).unwrap();
        assert_eq!(capsule.capsule_type, CAPSULE_DATAGRAM);
        assert_eq!(capsule.value, [0, 1, 2, 3]);
        assert_eq!(capsule.value.as_ptr(), original);
    }

    #[test]
    fn capsule_decoder_accepts_non_minimal_type_and_length() {
        let encoded = [0x40, 0x00, 0x80, 0, 0, 1, 0xaa];
        let capsule = Decoder::new(Cursor::new(encoded)).read().unwrap();
        assert_eq!(capsule.capsule_type, 0);
        assert_eq!(capsule.value, [0xaa]);
    }

    #[test]
    fn capsule_size_and_truncation_errors_are_bounded() {
        let mut encoder = Encoder::new(Vec::new());
        assert!(matches!(
            encoder.write(0, &vec![0; MAX_CAPSULE_SIZE + 1]),
            Err(MasqueError::CapsuleTooLarge)
        ));
        assert!(matches!(
            encoder.write_ip_packet(&vec![0; MAX_CAPSULE_SIZE]),
            Err(MasqueError::CapsuleTooLarge)
        ));

        let oversized = [0, 0x80, 0x10, 0, 1];
        assert!(matches!(
            Decoder::new(Cursor::new(oversized)).read(),
            Err(MasqueError::CapsuleTooLarge)
        ));

        let error = Decoder::new(Cursor::new([0, 2, 1])).read().unwrap_err();
        assert!(matches!(
            error,
            MasqueError::ReadCapsuleValue(ref source)
                if source.kind() == ErrorKind::UnexpectedEof
        ));
    }

    #[test]
    fn ip_datagram_context_zero_and_non_minimal_contexts() {
        let packet = [0x45, 0, 0, 20];
        assert_eq!(encode_ip_packet(&packet), [0, 0x45, 0, 0, 20]);
        assert_eq!(decode_ip_packet(&[0, 0x45, 0, 0, 20]).unwrap(), packet);
        assert_eq!(
            decode_ip_packet(&[0x40, 0, 0x45, 0, 0, 20]).unwrap(),
            packet
        );
        assert!(matches!(
            decode_ip_packet(&[1, 0x45]),
            Err(MasqueError::UnknownContext(1))
        ));
        assert!(matches!(
            decode_ip_packet(&[0]),
            Err(MasqueError::EmptyIpDatagram)
        ));
    }

    #[test]
    fn rfc9484_address_request_matches_go_golden_bytes() {
        let addresses = [Address {
            request_id: 1,
            prefix: "0.0.0.0/32".parse().unwrap(),
        }];
        let value = encode_address_request(&addresses).unwrap();
        assert_eq!(value, [0x01, 0x04, 0, 0, 0, 0, 0x20]);
        let mut encoder = Encoder::new(Vec::new());
        encoder.write(CAPSULE_ADDRESS_REQUEST, &value).unwrap();
        assert_eq!(
            encoder.into_inner(),
            [0x02, 0x07, 0x01, 0x04, 0, 0, 0, 0, 0x20]
        );
        assert_eq!(decode_address_request(&value).unwrap(), addresses);
    }

    #[test]
    fn address_codecs_cover_ipv6_nonminimal_ids_and_errors() {
        let value = [
            0x40, 0x01, 0x06, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x40,
        ];
        let decoded = decode_address_request(&value).unwrap();
        assert_eq!(decoded[0].request_id, 1);
        assert_eq!(decoded[0].prefix, "2001:db8::/64".parse().unwrap());
        assert!(matches!(
            encode_address_request(&[]),
            Err(MasqueError::EmptyAddressRequest)
        ));
        assert!(matches!(
            decode_address_request(&[0, 4, 0, 0, 0, 0, 32]),
            Err(MasqueError::DecodedZeroAddressRequestId)
        ));
        assert!(matches!(
            decode_address_assign(&[1, 4, 10, 0, 0, 1, 24]),
            Err(MasqueError::MalformedAddressDetail(_))
        ));
        assert!(matches!(
            decode_address_assign(&[1, 5]),
            Err(MasqueError::MalformedAddressDetail(_))
        ));
        assert!(matches!(
            decode_address_assign(&[1, 4, 0, 0, 0, 0, 33]),
            Err(MasqueError::MalformedAddressDetail(_))
        ));
        let unmasked = [Address {
            request_id: 1,
            prefix: IpNet::V4(Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 1), 24).unwrap()),
        }];
        assert!(matches!(
            encode_address_assign(&unmasked),
            Err(MasqueError::MalformedAddressDetail(_))
        ));
    }

    #[test]
    fn address_assign_matches_rfc9484_entry_encoding() {
        let addresses = [Address {
            request_id: 1,
            prefix: "10.66.0.2/32".parse().unwrap(),
        }];
        let value = encode_address_assign(&addresses).unwrap();
        assert_eq!(value, [1, 4, 10, 66, 0, 2, 32]);
        assert_eq!(decode_address_assign(&value).unwrap(), addresses);
    }

    #[test]
    fn route_advertisement_matches_go_golden_bytes() {
        let routes = [Route {
            start: "0.0.0.0".parse().unwrap(),
            end: "255.255.255.255".parse().unwrap(),
            protocol: 0,
        }];
        let value = encode_route_advertisement(&routes).unwrap();
        assert_eq!(value, [4, 0, 0, 0, 0, 255, 255, 255, 255, 0]);
        assert_eq!(decode_route_advertisement(&value).unwrap(), routes);
    }

    #[test]
    fn route_codecs_reject_reversed_overlapping_and_malformed_routes() {
        let reversed = [Route {
            start: "10.0.0.2".parse().unwrap(),
            end: "10.0.0.1".parse().unwrap(),
            protocol: 0,
        }];
        assert!(matches!(
            encode_route_advertisement(&reversed),
            Err(MasqueError::MalformedRoute)
        ));
        let overlapping = [
            Route {
                start: "10.0.0.0".parse().unwrap(),
                end: "10.0.0.10".parse().unwrap(),
                protocol: 17,
            },
            Route {
                start: "10.0.0.10".parse().unwrap(),
                end: "10.0.0.20".parse().unwrap(),
                protocol: 17,
            },
        ];
        assert!(matches!(
            encode_route_advertisement(&overlapping),
            Err(MasqueError::RoutesNotOrdered)
        ));
        assert!(matches!(
            decode_route_advertisement(&[5]),
            Err(MasqueError::MalformedRouteDetail(_))
        ));
        assert!(matches!(
            decode_route_advertisement(&[4, 0]),
            Err(MasqueError::MalformedRoute)
        ));
    }

    #[test]
    fn ipv6_route_advertisement_has_the_expected_wire_width() {
        let routes = [Route {
            start: "2001:db8::".parse().unwrap(),
            end: "2001:db8::ffff".parse().unwrap(),
            protocol: 17,
        }];
        let value = encode_route_advertisement(&routes).unwrap();
        assert_eq!(value.len(), 34);
        assert_eq!(value[0], 6);
        assert_eq!(value[33], 17);
        assert_eq!(decode_route_advertisement(&value).unwrap(), routes);
    }

    #[test]
    fn mtu_probe_matches_go_shape_and_rejects_mutations() {
        let probe = MtuProbe {
            token: [1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            sequence: 7,
            size: 1280,
        };
        let data = encode_mtu_probe(probe).unwrap();
        assert_eq!(data.len(), encode_ip_packet(&vec![0; 1280]).len());
        assert_eq!(
            &data[..21],
            &[1, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 5, 0]
        );
        assert_eq!(decode_mtu_probe(&data).unwrap(), probe);

        let mut malformed = data.clone();
        malformed[18] = 0;
        assert!(matches!(
            decode_mtu_probe(&malformed),
            Err(MasqueError::InvalidMtuMessage)
        ));
        let mut malformed = data.clone();
        malformed[20] += 1;
        assert!(matches!(
            decode_mtu_probe(&malformed),
            Err(MasqueError::InvalidMtuMessage)
        ));
        let mut malformed = data.clone();
        *malformed.last_mut().unwrap() = 1;
        assert!(matches!(
            decode_mtu_probe(&malformed),
            Err(MasqueError::InvalidMtuMessage)
        ));
        assert!(matches!(
            encode_mtu_probe(MtuProbe {
                size: 1099,
                ..probe
            }),
            Err(MasqueError::InvalidMtuMessage)
        ));
    }

    #[test]
    fn mtu_token_and_selection_golden_vectors() {
        let token = parse_mtu_token("000102030405060708090a0b0c0d0e0f").unwrap();
        assert_eq!(
            token,
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
        assert!(matches!(
            parse_mtu_token("xyz"),
            Err(MasqueError::InvalidMtuMessage)
        ));
        let selection = encode_mtu_selection(token, 1400);
        assert_eq!(
            selection,
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 5, 120]
        );
        assert_eq!(&selection[16..], &[0x05, 0x78]);
        assert_eq!(decode_mtu_selection(&selection, token).unwrap(), 1400);
        let mut wrong = token;
        wrong[0] = 1;
        assert!(matches!(
            decode_mtu_selection(&selection, wrong),
            Err(MasqueError::InvalidMtuMessage)
        ));
    }

    #[test]
    fn specialized_ip_capsule_matches_generic_encoding() {
        for size in [1, 20, 63, 1100, 9000] {
            let packet = vec![0x45; size];
            let mut generic = Encoder::new(Vec::new());
            generic
                .write(CAPSULE_DATAGRAM, &encode_ip_packet(&packet))
                .unwrap();
            let mut specialized = Encoder::new(Vec::new());
            specialized.write_ip_packet(&packet).unwrap();
            assert_eq!(generic.into_inner(), specialized.into_inner());
        }
    }
}
