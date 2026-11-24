//! IPv4 and IPv6 validation, classification, and checksum helpers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use thiserror::Error;

pub const IPV6_HEADER_LENGTH: usize = 40;
/// The smallest MTU every IPv6 link supports (RFC 8200).
pub const IPV6_MIN_MTU: usize = 1280;
const PROTOCOL_ICMPV6: u8 = 58;
const PROTOCOL_FRAGMENT: u8 = 44;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Info {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub total_length: usize,
    pub header_length: usize,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum Ipv4Error {
    #[error("only IPv4 packets are supported")]
    NotIpv4,
    #[error("IPv4 packet is shorter than its header")]
    ShortHeader,
    #[error("invalid IPv4 total length: header={declared} packet={actual}")]
    InvalidLength { declared: usize, actual: usize },
}

/// Addresses of a validated IPv4 or IPv6 packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpInfo {
    pub source: IpAddr,
    pub destination: IpAddr,
}

impl IpInfo {
    pub fn is_ipv6(&self) -> bool {
        self.source.is_ipv6()
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum IpError {
    #[error("only IPv4 and IPv6 packets are supported")]
    Unsupported,
    #[error("IP packet is shorter than its header")]
    ShortHeader,
    #[error("invalid IP packet length: header={declared} packet={actual}")]
    InvalidLength { declared: usize, actual: usize },
}

impl From<Ipv4Error> for IpError {
    fn from(error: Ipv4Error) -> Self {
        match error {
            Ipv4Error::NotIpv4 => Self::Unsupported,
            Ipv4Error::ShortHeader => Self::ShortHeader,
            Ipv4Error::InvalidLength { declared, actual } => {
                Self::InvalidLength { declared, actual }
            }
        }
    }
}

/// The IP version of `packet`, if it is 4 or 6.
pub fn ip_version(packet: &[u8]) -> Option<u8> {
    packet
        .first()
        .map(|first| first >> 4)
        .filter(|version| matches!(version, 4 | 6))
}

/// Validates the fixed header and length of an IPv4 or IPv6 packet.
pub fn parse_ip(packet: &[u8]) -> Result<IpInfo, IpError> {
    match packet.first().map(|first| first >> 4) {
        None => Err(IpError::ShortHeader),
        Some(4) => {
            let info = parse_ipv4(packet)?;
            Ok(IpInfo {
                source: IpAddr::V4(info.source),
                destination: IpAddr::V4(info.destination),
            })
        }
        Some(6) => {
            let (source, destination) = parse_ipv6(packet)?;
            Ok(IpInfo {
                source: IpAddr::V6(source),
                destination: IpAddr::V6(destination),
            })
        }
        Some(_) => Err(IpError::Unsupported),
    }
}

/// Validates an IPv6 header and payload length; jumbograms are rejected.
pub fn parse_ipv6(packet: &[u8]) -> Result<(Ipv6Addr, Ipv6Addr), IpError> {
    if packet.len() < IPV6_HEADER_LENGTH {
        return Err(IpError::ShortHeader);
    }
    if packet[0] >> 4 != 6 {
        return Err(IpError::Unsupported);
    }
    let payload_length = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if payload_length + IPV6_HEADER_LENGTH != packet.len() {
        return Err(IpError::InvalidLength {
            declared: payload_length + IPV6_HEADER_LENGTH,
            actual: packet.len(),
        });
    }
    Ok((ipv6_at(packet, 8), ipv6_at(packet, 24)))
}

fn ipv6_at(packet: &[u8], offset: usize) -> Ipv6Addr {
    let mut octets = [0; 16];
    octets.copy_from_slice(&packet[offset..offset + 16]);
    Ipv6Addr::from(octets)
}

pub fn parse_ipv4(packet: &[u8]) -> Result<Ipv4Info, Ipv4Error> {
    if packet.len() < 20 {
        return Err(Ipv4Error::ShortHeader);
    }
    if packet[0] >> 4 != 4 {
        return Err(Ipv4Error::NotIpv4);
    }
    let header_length = usize::from(packet[0] & 0x0f) * 4;
    if header_length < 20 || header_length > packet.len() {
        return Err(Ipv4Error::ShortHeader);
    }
    let total_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_length < header_length || total_length != packet.len() {
        return Err(Ipv4Error::InvalidLength {
            declared: total_length,
            actual: packet.len(),
        });
    }

    Ok(Ipv4Info {
        source: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        destination: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        total_length,
        header_length,
    })
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum PacketClass {
    Tcp,
    #[default]
    Datagram,
    Control,
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct FlowKey {
    /// IPv4 addresses use the first four bytes.
    pub source: [u8; 16],
    pub destination: [u8; 16],
    pub source_port: u16,
    pub destination_port: u16,
    pub fragment_id: u16,
    pub protocol: u8,
    pub fragmented: bool,
    /// 6 for IPv6 flows; IPv4 flows leave it 0.
    pub family: u8,
}

impl FlowKey {
    fn address_length(&self) -> usize {
        if self.family == 6 {
            16
        } else {
            4
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct PacketMetadata {
    pub class: PacketClass,
    pub flow: FlowKey,
    pub hash: u32,
}

/// Classifies an IPv4 or IPv6 packet for queueing and lane selection.
pub fn classify_packet(packet: &[u8]) -> PacketMetadata {
    match packet.first().map(|first| first >> 4) {
        Some(6) => classify_ipv6(packet),
        _ => classify_ipv4(packet),
    }
}

fn classify_ipv4(packet: &[u8]) -> PacketMetadata {
    let mut metadata = PacketMetadata::default();
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return metadata;
    }
    let header_length = usize::from(packet[0] & 0x0f) * 4;
    if header_length < 20 || header_length > packet.len() {
        return metadata;
    }

    metadata.flow.source[..4].copy_from_slice(&packet[12..16]);
    metadata.flow.destination[..4].copy_from_slice(&packet[16..20]);
    metadata.flow.protocol = packet[9];
    let flags_and_offset = u16::from_be_bytes([packet[6], packet[7]]);
    metadata.flow.fragmented = flags_and_offset & 0x3fff != 0;
    if metadata.flow.fragmented {
        metadata.flow.fragment_id = u16::from_be_bytes([packet[4], packet[5]]);
    }
    classify_transport(packet, header_length, 1, metadata)
}

fn classify_ipv6(packet: &[u8]) -> PacketMetadata {
    let mut metadata = PacketMetadata::default();
    if packet.len() < IPV6_HEADER_LENGTH {
        return metadata;
    }
    metadata.flow.family = 6;
    metadata.flow.source.copy_from_slice(&packet[8..24]);
    metadata.flow.destination.copy_from_slice(&packet[24..40]);
    let mut next = packet[6];
    let mut offset = IPV6_HEADER_LENGTH;
    // A few extension headers precede most transport headers; longer
    // chains are classified as plain datagrams.
    for _ in 0..4 {
        match next {
            0 | 43 | 60 if packet.len() >= offset + 8 => {
                next = packet[offset];
                offset += (usize::from(packet[offset + 1]) + 1) * 8;
            }
            PROTOCOL_FRAGMENT if packet.len() >= offset + 8 => {
                let identification = u32::from_be_bytes([
                    packet[offset + 4],
                    packet[offset + 5],
                    packet[offset + 6],
                    packet[offset + 7],
                ]);
                metadata.flow.fragmented = true;
                metadata.flow.fragment_id = (identification ^ (identification >> 16)) as u16;
                next = packet[offset];
                offset += 8;
                break;
            }
            _ => break,
        }
    }
    metadata.flow.protocol = next;
    if offset > packet.len() {
        metadata.hash = hash_flow(metadata.flow);
        return metadata;
    }
    classify_transport(packet, offset, PROTOCOL_ICMPV6, metadata)
}

/// Fills in ports and the queueing class from the transport header at
/// `header_length`; `icmp` is the protocol number of the family's ICMP.
fn classify_transport(
    packet: &[u8],
    header_length: usize,
    icmp: u8,
    mut metadata: PacketMetadata,
) -> PacketMetadata {
    let has_ports = !metadata.flow.fragmented
        && matches!(metadata.flow.protocol, 6 | 17)
        && packet.len() >= header_length + 4;
    if has_ports {
        metadata.flow.source_port =
            u16::from_be_bytes([packet[header_length], packet[header_length + 1]]);
        metadata.flow.destination_port =
            u16::from_be_bytes([packet[header_length + 2], packet[header_length + 3]]);
    }

    metadata.class = match metadata.flow.protocol {
        protocol if protocol == icmp => PacketClass::Control,
        6 => {
            if has_ports
                && (metadata.flow.source_port == 53 || metadata.flow.destination_port == 53)
                || has_ports && tcp_ack_only(packet, header_length)
            {
                PacketClass::Control
            } else {
                PacketClass::Tcp
            }
        }
        17 if has_ports
            && (metadata.flow.source_port == 53
                || metadata.flow.destination_port == 53
                || packet.len() <= 256) =>
        {
            PacketClass::Control
        }
        _ => PacketClass::Datagram,
    };
    metadata.hash = hash_flow(metadata.flow);
    metadata
}

fn tcp_ack_only(packet: &[u8], ip_header_length: usize) -> bool {
    if packet.len() < ip_header_length + 20 {
        return false;
    }
    let tcp_header_length = usize::from(packet[ip_header_length + 12] >> 4) * 4;
    if tcp_header_length < 20 || packet.len() < ip_header_length + tcp_header_length {
        return false;
    }
    let flags = packet[ip_header_length + 13];
    const FIN: u8 = 0x01;
    const SYN: u8 = 0x02;
    const RST: u8 = 0x04;
    const ACK: u8 = 0x10;
    flags & ACK != 0
        && flags & (FIN | SYN | RST) == 0
        && packet.len() == ip_header_length + tcp_header_length
}

pub fn hash_flow(flow: FlowKey) -> u32 {
    let mut hash = 2_166_136_261_u32;
    let length = flow.address_length();
    for value in flow.source[..length]
        .iter()
        .copied()
        .chain(flow.destination[..length].iter().copied())
        .chain(flow.source_port.to_be_bytes())
        .chain(flow.destination_port.to_be_bytes())
        .chain(flow.fragment_id.to_be_bytes())
        .chain([flow.protocol, u8::from(flow.fragmented)])
    {
        hash ^= u32::from(value);
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}

pub fn internet_checksum(data: &[u8]) -> u16 {
    let (chunks, remainder) = data.as_chunks::<2>();
    let mut sum = chunks.iter().fold(0_u64, |sum, word| {
        sum + u64::from(u16::from_be_bytes([word[0], word[1]]))
    });
    if let Some(&last) = remainder.first() {
        sum += u64::from(last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn ipv4_header_checksum(packet: &[u8]) -> Result<u16, Ipv4Error> {
    let header_length = ipv4_header_length(packet)?;
    Ok(internet_checksum(&packet[..header_length]))
}

pub fn set_ipv4_header_checksum(packet: &mut [u8]) -> Result<(), Ipv4Error> {
    let header_length = ipv4_header_length(packet)?;
    packet[10] = 0;
    packet[11] = 0;
    let checksum = internet_checksum(&packet[..header_length]).to_be_bytes();
    packet[10..12].copy_from_slice(&checksum);
    Ok(())
}

fn ipv4_header_length(packet: &[u8]) -> Result<usize, Ipv4Error> {
    if packet.len() < 20 {
        return Err(Ipv4Error::ShortHeader);
    }
    if packet[0] >> 4 != 4 {
        return Err(Ipv4Error::NotIpv4);
    }
    let header_length = usize::from(packet[0] & 0x0f) * 4;
    if header_length < 20 || header_length > packet.len() {
        return Err(Ipv4Error::ShortHeader);
    }
    Ok(header_length)
}

/// Decrements the IPv4 TTL or IPv6 hop limit as a router forwarding the
/// packet does, keeping the IPv4 header checksum valid. Returns false, and
/// leaves the packet unchanged, once the limit is exhausted or when the
/// packet is malformed.
pub fn decrement_hop_limit(packet: &mut [u8]) -> bool {
    if parse_ip(packet).is_err() {
        return false;
    }
    match ip_version(packet) {
        Some(4) if packet[8] > 1 => {
            packet[8] -= 1;
            set_ipv4_header_checksum(packet).is_ok()
        }
        Some(6) if packet[7] > 1 => {
            packet[7] -= 1;
            true
        }
        _ => false,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn malformed_packets_keep_their_hop_limit() {
        // Found by fuzzing: a header whose total length exceeds the packet.
        let mut packet = [
            0x46, 0x26, 0xa9, 0xbc, 0xbc, 0xbc, 0x26, 0x26, 0x26, 0x26, 0x26, 0x26, 0x26, 0x26,
            0x26, 0x26, 0x26, 0x26, 0x26, 0x26, 0x26, 0x26, 0x26, 0x40,
        ];
        let original = packet;
        assert!(!decrement_hop_limit(&mut packet));
        assert_eq!(packet, original);
    }

    fn ipv4_packet(source: [u8; 4], destination: [u8; 4], payload_len: usize) -> Vec<u8> {
        let mut packet = vec![0; 20 + payload_len];
        packet[0] = 0x45;
        let length = packet.len() as u16;
        packet[2..4].copy_from_slice(&length.to_be_bytes());
        packet[8] = 64;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    #[test]
    fn parses_the_go_ipv4_vector() {
        let packet = ipv4_packet([10, 66, 0, 2], [1, 1, 1, 1], 0);
        let info = parse_ipv4(&packet).unwrap();
        assert_eq!(info.source, Ipv4Addr::new(10, 66, 0, 2));
        assert_eq!(info.destination, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(info.total_length, 20);
        assert_eq!(info.header_length, 20);
    }

    #[test]
    fn rejects_malformed_ipv4_lengths_and_versions() {
        assert_eq!(parse_ipv4(&[0; 19]), Err(Ipv4Error::ShortHeader));

        let mut packet = ipv4_packet([0; 4], [0; 4], 0);
        packet[0] = 0x65;
        assert_eq!(parse_ipv4(&packet), Err(Ipv4Error::NotIpv4));

        packet[0] = 0x44;
        assert_eq!(parse_ipv4(&packet), Err(Ipv4Error::ShortHeader));

        packet[0] = 0x4f;
        assert_eq!(parse_ipv4(&packet), Err(Ipv4Error::ShortHeader));

        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&19_u16.to_be_bytes());
        assert_eq!(
            parse_ipv4(&packet),
            Err(Ipv4Error::InvalidLength {
                declared: 19,
                actual: 20
            })
        );

        packet[2..4].copy_from_slice(&21_u16.to_be_bytes());
        let error = parse_ipv4(&packet).unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid IPv4 total length: header=21 packet=20"
        );
    }

    #[test]
    fn classification_matches_go_control_and_flow_rules() {
        let mut udp = ipv4_packet([10, 0, 0, 1], [1, 1, 1, 1], 8);
        udp[9] = 17;
        udp[20..24].copy_from_slice(&[0x30, 0x39, 0, 53]);
        let dns = classify_packet(&udp);
        assert_eq!(dns.class, PacketClass::Control);
        assert_eq!(dns.flow.source_port, 12_345);
        assert_eq!(dns.flow.destination_port, 53);
        assert_eq!(dns.hash, 0x4b5b_0ddd);

        udp.resize(300, 0);
        let length = udp.len() as u16;
        udp[2..4].copy_from_slice(&length.to_be_bytes());
        udp[22..24].copy_from_slice(&443_u16.to_be_bytes());
        assert_eq!(classify_packet(&udp).class, PacketClass::Datagram);

        let mut tcp = ipv4_packet([10, 0, 0, 1], [1, 1, 1, 1], 20);
        tcp[9] = 6;
        tcp[20..24].copy_from_slice(&[0x30, 0x39, 0x01, 0xbb]);
        tcp[32] = 5 << 4;
        tcp[33] = 0x10;
        assert_eq!(classify_packet(&tcp).class, PacketClass::Control);
        tcp.push(1);
        assert_eq!(classify_packet(&tcp).class, PacketClass::Tcp);

        let mut icmp = ipv4_packet([10, 0, 0, 1], [1, 1, 1, 1], 8);
        icmp[9] = 1;
        assert_eq!(classify_packet(&icmp).class, PacketClass::Control);
    }

    #[test]
    fn fragments_do_not_parse_ports_and_hash_by_fragment_id() {
        let mut packet = ipv4_packet([10, 0, 0, 1], [1, 1, 1, 1], 8);
        packet[4..6].copy_from_slice(&0x1234_u16.to_be_bytes());
        packet[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
        packet[9] = 17;
        packet[20..24].copy_from_slice(&[0, 53, 0, 53]);
        let metadata = classify_packet(&packet);
        assert!(metadata.flow.fragmented);
        assert_eq!(metadata.flow.fragment_id, 0x1234);
        assert_eq!(metadata.flow.source_port, 0);
        assert_eq!(metadata.class, PacketClass::Datagram);
    }

    #[test]
    fn checksum_matches_go_golden_vectors() {
        assert_eq!(internet_checksum(&[]), 0xffff);
        assert_eq!(internet_checksum(&[0]), 0xffff);
        assert_eq!(internet_checksum(&[1]), 0xfeff);
        assert_eq!(internet_checksum(&[1, 2, 3]), 0xfbfd);
        assert_eq!(internet_checksum(&[0xff; 65_535]), 0x00ff);

        let mut packet = ipv4_packet([10, 66, 0, 2], [1, 1, 1, 1], 0);
        set_ipv4_header_checksum(&mut packet).unwrap();
        assert_eq!(&packet[10..12], &[0x6e, 0xa5]);
        assert_eq!(ipv4_header_checksum(&packet).unwrap(), 0);
    }

    #[test]
    fn checksum_helpers_reject_short_or_non_ipv4_headers() {
        assert_eq!(
            set_ipv4_header_checksum(&mut [0; 19]),
            Err(Ipv4Error::ShortHeader)
        );
        let mut packet = [0; 20];
        packet[0] = 0x65;
        assert_eq!(
            set_ipv4_header_checksum(&mut packet),
            Err(Ipv4Error::NotIpv4)
        );
    }

    pub(crate) fn ipv6_packet(
        source: Ipv6Addr,
        destination: Ipv6Addr,
        next_header: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut packet = vec![0; IPV6_HEADER_LENGTH + payload.len()];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        packet[6] = next_header;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet[IPV6_HEADER_LENGTH..].copy_from_slice(payload);
        packet
    }

    #[test]
    fn parses_ipv6_and_rejects_bad_lengths() {
        let source: Ipv6Addr = "fd66::2".parse().unwrap();
        let destination: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let packet = ipv6_packet(source, destination, 17, &[0; 8]);
        assert_eq!(
            parse_ip(&packet).unwrap(),
            IpInfo {
                source: IpAddr::V6(source),
                destination: IpAddr::V6(destination),
            }
        );
        assert!(parse_ip(&packet).unwrap().is_ipv6());
        assert_eq!(parse_ip(&packet[..39]), Err(IpError::ShortHeader));
        assert!(matches!(
            parse_ip(&packet[..47]),
            Err(IpError::InvalidLength { .. })
        ));
        assert_eq!(parse_ip(&[0x50; 40]), Err(IpError::Unsupported));
        assert_eq!(parse_ip(&[]), Err(IpError::ShortHeader));
        let ipv4 = ipv4_packet([10, 66, 0, 2], [1, 1, 1, 1], 0);
        assert_eq!(
            parse_ip(&ipv4).unwrap().destination,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))
        );
        assert_eq!(ip_version(&packet), Some(6));
        assert_eq!(ip_version(&ipv4), Some(4));
        assert_eq!(ip_version(&[0x50]), None);
    }

    #[test]
    fn classifies_ipv6_transports_extension_headers_and_fragments() {
        let source: Ipv6Addr = "fd66::2".parse().unwrap();
        let destination: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut udp = [0_u8; 8];
        udp[..4].copy_from_slice(&[0x30, 0x39, 0, 53]);
        let dns = classify_packet(&ipv6_packet(source, destination, 17, &udp));
        assert_eq!(dns.class, PacketClass::Control);
        assert_eq!(dns.flow.family, 6);
        assert_eq!(dns.flow.destination_port, 53);
        assert_eq!(&dns.flow.source, &source.octets());

        let icmp = classify_packet(&ipv6_packet(source, destination, 58, &[128, 0, 0, 0]));
        assert_eq!(icmp.class, PacketClass::Control);

        let mut tcp = vec![0_u8; 21];
        tcp[..4].copy_from_slice(&[0x30, 0x39, 0x01, 0xbb]);
        tcp[12] = 5 << 4;
        tcp[13] = 0x18;
        let data = classify_packet(&ipv6_packet(source, destination, 6, &tcp));
        assert_eq!(data.class, PacketClass::Tcp);
        assert_eq!(data.flow.destination_port, 443);

        // A hop-by-hop header in front of TCP.
        let mut extended = vec![6, 0, 0, 0, 0, 0, 0, 0];
        extended.extend_from_slice(&tcp);
        let behind = classify_packet(&ipv6_packet(source, destination, 0, &extended));
        assert_eq!(behind.flow.protocol, 6);
        assert_eq!(behind.flow.destination_port, 443);
        assert_eq!(behind.hash, data.hash);

        // Fragments hash by identification, not ports.
        let mut fragment = vec![17, 0, 0, 1, 0x12, 0x34, 0x56, 0x78];
        fragment.extend_from_slice(&udp);
        let first = classify_packet(&ipv6_packet(source, destination, 44, &fragment));
        assert!(first.flow.fragmented);
        assert_eq!(first.flow.source_port, 0);
        fragment[2..4].copy_from_slice(&[0, 0x80]);
        fragment[8] ^= 0xff;
        let later = classify_packet(&ipv6_packet(source, destination, 44, &fragment));
        assert_eq!(first.hash, later.hash);
        assert_ne!(first.hash, dns.hash);
    }

    #[test]
    fn hop_limits_decrement_for_both_families() {
        let mut ipv4 = ipv4_packet([10, 66, 0, 2], [10, 66, 0, 3], 0);
        set_ipv4_header_checksum(&mut ipv4).unwrap();
        assert!(decrement_hop_limit(&mut ipv4));
        assert_eq!(ipv4[8], 63);
        assert_eq!(ipv4_header_checksum(&ipv4).unwrap(), 0);
        ipv4[8] = 1;
        assert!(!decrement_hop_limit(&mut ipv4));

        let mut ipv6 = ipv6_packet(
            "fd66::2".parse().unwrap(),
            "fd66::3".parse().unwrap(),
            59,
            &[],
        );
        assert!(decrement_hop_limit(&mut ipv6));
        assert_eq!(ipv6[7], 63);
        ipv6[7] = 1;
        assert!(!decrement_hop_limit(&mut ipv6));
        assert!(!decrement_hop_limit(&mut [0x50; 40]));
    }
}
