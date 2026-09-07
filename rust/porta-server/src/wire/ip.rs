use std::net::Ipv4Addr;

use thiserror::Error;

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
    pub source: [u8; 4],
    pub destination: [u8; 4],
    pub source_port: u16,
    pub destination_port: u16,
    pub fragment_id: u16,
    pub protocol: u8,
    pub fragmented: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct PacketMetadata {
    pub class: PacketClass,
    pub flow: FlowKey,
    pub hash: u32,
}

pub fn classify_ipv4(packet: &[u8]) -> PacketMetadata {
    let mut metadata = PacketMetadata::default();
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return metadata;
    }
    let header_length = usize::from(packet[0] & 0x0f) * 4;
    if header_length < 20 || header_length > packet.len() {
        return metadata;
    }

    metadata.flow.source.copy_from_slice(&packet[12..16]);
    metadata.flow.destination.copy_from_slice(&packet[16..20]);
    metadata.flow.protocol = packet[9];
    let flags_and_offset = u16::from_be_bytes([packet[6], packet[7]]);
    metadata.flow.fragmented = flags_and_offset & 0x3fff != 0;
    if metadata.flow.fragmented {
        metadata.flow.fragment_id = u16::from_be_bytes([packet[4], packet[5]]);
    }

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
        1 => PacketClass::Control,
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
    for value in flow
        .source
        .into_iter()
        .chain(flow.destination)
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let dns = classify_ipv4(&udp);
        assert_eq!(dns.class, PacketClass::Control);
        assert_eq!(dns.flow.source_port, 12_345);
        assert_eq!(dns.flow.destination_port, 53);
        assert_eq!(dns.hash, 0x4b5b_0ddd);

        udp.resize(300, 0);
        let length = udp.len() as u16;
        udp[2..4].copy_from_slice(&length.to_be_bytes());
        udp[22..24].copy_from_slice(&443_u16.to_be_bytes());
        assert_eq!(classify_ipv4(&udp).class, PacketClass::Datagram);

        let mut tcp = ipv4_packet([10, 0, 0, 1], [1, 1, 1, 1], 20);
        tcp[9] = 6;
        tcp[20..24].copy_from_slice(&[0x30, 0x39, 0x01, 0xbb]);
        tcp[32] = 5 << 4;
        tcp[33] = 0x10;
        assert_eq!(classify_ipv4(&tcp).class, PacketClass::Control);
        tcp.push(1);
        assert_eq!(classify_ipv4(&tcp).class, PacketClass::Tcp);

        let mut icmp = ipv4_packet([10, 0, 0, 1], [1, 1, 1, 1], 8);
        icmp[9] = 1;
        assert_eq!(classify_ipv4(&icmp).class, PacketClass::Control);
    }

    #[test]
    fn fragments_do_not_parse_ports_and_hash_by_fragment_id() {
        let mut packet = ipv4_packet([10, 0, 0, 1], [1, 1, 1, 1], 8);
        packet[4..6].copy_from_slice(&0x1234_u16.to_be_bytes());
        packet[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
        packet[9] = 17;
        packet[20..24].copy_from_slice(&[0, 53, 0, 53]);
        let metadata = classify_ipv4(&packet);
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
}
