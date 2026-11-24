//! Stateless one-to-one IPv4 address translation.
//!
//! A cascade relay masquerades its clients to one fixed local address and
//! exchanges that address with its upstream lease here. The lease therefore
//! never becomes a local address, so adjacent gateways may use overlapping
//! client pools.

use std::net::Ipv4Addr;

use crate::ip::{parse_ipv4, set_ipv4_header_checksum};

const PROTOCOL_ICMP: u8 = 1;
const PROTOCOL_TCP: u8 = 6;
const PROTOCOL_UDP: u8 = 17;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// Rewrite the source of an outgoing packet; an ICMP error's quoted
    /// packet was addressed to that source, so its destination is rewritten.
    Outbound,
    /// Rewrite the destination of an incoming packet; an ICMP error's quoted
    /// packet came from that destination, so its source is rewritten.
    Inbound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TranslateError {
    #[error("invalid IPv4 packet")]
    Invalid,
    #[error("packet address does not match the translated address")]
    AddressMismatch,
}

/// Replaces `from` with `to` in the field selected by `direction` and keeps
/// IPv4, TCP, UDP and ICMP checksums valid.
pub fn translate(
    packet: &mut [u8],
    direction: Direction,
    from: Ipv4Addr,
    to: Ipv4Addr,
) -> Result<(), TranslateError> {
    let info = parse_ipv4(packet).map_err(|_| TranslateError::Invalid)?;
    let outer = match direction {
        Direction::Outbound => 12,
        Direction::Inbound => 16,
    };
    if packet[outer..outer + 4] != from.octets() {
        return Err(TranslateError::AddressMismatch);
    }
    let header_length = info.header_length;
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    let first_fragment = fragment & 0x1fff == 0;
    let unfragmented = first_fragment && fragment & 0x2000 == 0;
    let protocol = packet[9];
    packet[outer..outer + 4].copy_from_slice(&to.octets());
    set_ipv4_header_checksum(packet).map_err(|_| TranslateError::Invalid)?;
    if !first_fragment {
        return Ok(());
    }
    let transport = &mut packet[header_length..];
    match protocol {
        PROTOCOL_TCP => adjust_checksum_at(transport, 16, from, to, false),
        PROTOCOL_UDP => adjust_checksum_at(transport, 6, from, to, true),
        PROTOCOL_ICMP if unfragmented => translate_icmp_error(transport, direction, from, to),
        _ => {}
    }
    Ok(())
}

fn translate_icmp_error(icmp: &mut [u8], direction: Direction, from: Ipv4Addr, to: Ipv4Addr) {
    // Destination unreachable, source quench, redirect, time exceeded and
    // parameter problem quote the offending packet after an 8-byte header.
    if icmp.len() < 8 + 20 || !matches!(icmp[0], 3 | 4 | 5 | 11 | 12) {
        return;
    }
    let quoted = &mut icmp[8..];
    let header_length = usize::from(quoted[0] & 0x0f) * 4;
    if quoted[0] >> 4 != 4 || header_length < 20 || header_length > quoted.len() {
        return;
    }
    let field = match direction {
        Direction::Outbound => 16,
        Direction::Inbound => 12,
    };
    if quoted[field..field + 4] != from.octets() {
        return;
    }
    quoted[field..field + 4].copy_from_slice(&to.octets());
    quoted[10..12].fill(0);
    let checksum = crate::ip::internet_checksum(&quoted[..header_length]);
    quoted[10..12].copy_from_slice(&checksum.to_be_bytes());
    if u16::from_be_bytes([quoted[6], quoted[7]]) & 0x1fff == 0 {
        let protocol = quoted[9];
        let transport = &mut quoted[header_length..];
        match protocol {
            PROTOCOL_TCP => adjust_checksum_at(transport, 16, from, to, false),
            PROTOCOL_UDP => adjust_checksum_at(transport, 6, from, to, true),
            _ => {}
        }
    }
    icmp[2..4].fill(0);
    let checksum = crate::ip::internet_checksum(icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
}

/// Incrementally updates a transport checksum covering a pseudo-header
/// address (RFC 1624). Truncated headers, as in quoted ICMP payloads, are
/// left unchanged.
fn adjust_checksum_at(
    transport: &mut [u8],
    offset: usize,
    from: Ipv4Addr,
    to: Ipv4Addr,
    zero_means_absent: bool,
) {
    let Some(field) = transport.get_mut(offset..offset + 2) else {
        return;
    };
    let checksum = u16::from_be_bytes([field[0], field[1]]);
    if zero_means_absent && checksum == 0 {
        return;
    }
    let mut sum = u32::from(!checksum);
    for (old, new) in from.octets().chunks(2).zip(to.octets().chunks(2)) {
        sum += u32::from(!u16::from_be_bytes([old[0], old[1]]));
        sum += u32::from(u16::from_be_bytes([new[0], new[1]]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let mut updated = !(sum as u16);
    if zero_means_absent && updated == 0 {
        updated = 0xffff;
    }
    field.copy_from_slice(&updated.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip::internet_checksum;

    const LOCAL: Ipv4Addr = Ipv4Addr::new(169, 254, 66, 1);
    const LEASE: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 2);
    const REMOTE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);

    fn transport_checksum(packet: &[u8]) -> u16 {
        let header_length = usize::from(packet[0] & 0x0f) * 4;
        let transport = &packet[header_length..];
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&packet[12..20]);
        pseudo.extend_from_slice(&[0, packet[9]]);
        pseudo.extend_from_slice(&(transport.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(transport);
        internet_checksum(&pseudo)
    }

    fn packet(protocol: u8, source: Ipv4Addr, destination: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet.extend_from_slice(payload);
        let length = packet.len() as u16;
        packet[2..4].copy_from_slice(&length.to_be_bytes());
        set_ipv4_header_checksum(&mut packet).unwrap();
        let offset = match protocol {
            PROTOCOL_TCP => Some(20 + 16),
            PROTOCOL_UDP => Some(20 + 6),
            _ => None,
        };
        if let Some(offset) = offset {
            let checksum = transport_checksum(&packet);
            packet[offset..offset + 2].copy_from_slice(&checksum.to_be_bytes());
        }
        packet
    }

    fn assert_valid(packet: &[u8]) {
        assert_eq!(internet_checksum(&packet[..20]), 0, "IPv4 header checksum");
        match packet[9] {
            PROTOCOL_TCP | PROTOCOL_UDP => {
                assert_eq!(transport_checksum(packet), 0, "transport checksum")
            }
            PROTOCOL_ICMP => assert_eq!(internet_checksum(&packet[20..]), 0, "ICMP checksum"),
            _ => {}
        }
    }

    #[test]
    fn translates_tcp_and_udp_in_both_directions_with_valid_checksums() {
        for protocol in [PROTOCOL_TCP, PROTOCOL_UDP] {
            let payload = [
                0x9c, 0x40, 0x01, 0xbb, 0, 0, 0, 0, 0x50, 0x02, 0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                2, 3,
            ];
            let mut outbound = packet(protocol, LOCAL, REMOTE, &payload);
            translate(&mut outbound, Direction::Outbound, LOCAL, LEASE).unwrap();
            assert_eq!(&outbound[12..16], &LEASE.octets());
            assert_valid(&outbound);

            let mut inbound = packet(protocol, REMOTE, LEASE, &payload);
            translate(&mut inbound, Direction::Inbound, LEASE, LOCAL).unwrap();
            assert_eq!(&inbound[16..20], &LOCAL.octets());
            assert_valid(&inbound);
        }
    }

    #[test]
    fn preserves_absent_udp_checksums_and_non_first_fragments() {
        let mut udp = packet(
            PROTOCOL_UDP,
            LOCAL,
            REMOTE,
            &[0, 53, 0, 53, 0, 12, 0, 0, 1, 2, 3, 4],
        );
        udp[26..28].fill(0);
        translate(&mut udp, Direction::Outbound, LOCAL, LEASE).unwrap();
        assert_eq!(&udp[26..28], &[0, 0]);

        let mut fragment = packet(PROTOCOL_TCP, LOCAL, REMOTE, &[0xaa; 24]);
        fragment[6..8].copy_from_slice(&0x0003_u16.to_be_bytes());
        set_ipv4_header_checksum(&mut fragment).unwrap();
        let payload = fragment[20..].to_vec();
        translate(&mut fragment, Direction::Outbound, LOCAL, LEASE).unwrap();
        assert_eq!(fragment[20..], payload);
        assert_eq!(internet_checksum(&fragment[..20]), 0);
    }

    #[test]
    fn rewrites_the_packet_quoted_by_icmp_errors() {
        let original = packet(
            PROTOCOL_UDP,
            LEASE,
            REMOTE,
            &[0x9c, 0x40, 0, 53, 0, 12, 0, 0, 1, 2, 3, 4],
        );
        let mut icmp = vec![3, 4, 0, 0, 0, 0, 0x05, 0x00];
        icmp.extend_from_slice(&original[..28]);
        let checksum = internet_checksum(&icmp);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
        let mut error = packet(PROTOCOL_ICMP, Ipv4Addr::new(10, 66, 0, 1), LEASE, &icmp);

        translate(&mut error, Direction::Inbound, LEASE, LOCAL).unwrap();
        assert_eq!(&error[16..20], &LOCAL.octets());
        let quoted = &error[28..];
        assert_eq!(&quoted[12..16], &LOCAL.octets());
        assert_eq!(
            internet_checksum(&quoted[..20]),
            0,
            "quoted header checksum"
        );
        assert_valid(&error);

        // A client's own ICMP error about an inbound packet quotes it with
        // the translated destination.
        let inbound = packet(
            PROTOCOL_UDP,
            REMOTE,
            LOCAL,
            &[0, 53, 0x9c, 0x40, 0, 12, 0, 0, 1, 2, 3, 4],
        );
        let mut icmp = vec![3, 3, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&inbound[..28]);
        let checksum = internet_checksum(&icmp);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
        let mut error = packet(PROTOCOL_ICMP, LOCAL, REMOTE, &icmp);
        translate(&mut error, Direction::Outbound, LOCAL, LEASE).unwrap();
        assert_eq!(&error[12..16], &LEASE.octets());
        assert_eq!(&error[28 + 16..28 + 20], &LEASE.octets());
        assert_valid(&error);
    }

    #[test]
    fn rejects_foreign_addresses_and_malformed_packets() {
        let mut foreign = packet(PROTOCOL_TCP, REMOTE, LEASE, &[0; 20]);
        assert_eq!(
            translate(&mut foreign, Direction::Outbound, LOCAL, LEASE),
            Err(TranslateError::AddressMismatch)
        );
        assert_eq!(
            translate(&mut [0x45, 0, 0], Direction::Inbound, LEASE, LOCAL),
            Err(TranslateError::Invalid)
        );
    }
}
