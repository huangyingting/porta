//! IP packets from a tunnel: parsing, flow classification, hop-limit
//! updates, fragmentation, ICMP errors and NAT never panic, and what they
//! produce parses again.
#![no_main]

use std::net::{Ipv4Addr, Ipv6Addr};

use libfuzzer_sys::fuzz_target;
use porta_wire::ip;
use porta_wire::mtu::{self, IcmpContext};
use porta_wire::nat::{self, Direction};

fuzz_target!(|data: &[u8]| {
    let Some((&selector, packet)) = data.split_first() else {
        return;
    };
    let _ = ip::ip_version(packet);
    let parsed = ip::parse_ip(packet);
    let _ = ip::parse_ipv6(packet);
    let _ = ip::classify_packet(packet);
    let _ = ip::internet_checksum(packet);

    let mut copy = packet.to_vec();
    if ip::decrement_hop_limit(&mut copy) {
        assert!(ip::parse_ip(&copy).is_ok());
    }

    if let Ok(info) = ip::parse_ipv4(packet) {
        let _ = info;
        let fragment_mtu = 68 + usize::from(selector) * 8;
        if let Ok(fragments) = mtu::fragment_ipv4(packet, fragment_mtu) {
            for fragment in fragments {
                assert!(fragment.len() <= fragment_mtu);
                assert!(ip::parse_ipv4(&fragment).is_ok());
            }
        }
        let context = IcmpContext {
            gateway: Ipv4Addr::new(10, 66, 0, 1),
            address: Ipv4Addr::new(10, 66, 0, 2),
            prefix_len: 24,
        };
        if let Ok(error) = mtu::icmp_fragmentation_needed(packet, context, 576, 7) {
            assert!(ip::parse_ipv4(&error).is_ok());
        }
        let mut translated = packet.to_vec();
        let direction = if selector & 1 == 0 {
            Direction::Outbound
        } else {
            Direction::Inbound
        };
        let from = match direction {
            Direction::Outbound => Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16]).unwrap()),
            Direction::Inbound => Ipv4Addr::from(<[u8; 4]>::try_from(&packet[16..20]).unwrap()),
        };
        if nat::translate(&mut translated, direction, from, Ipv4Addr::new(100, 64, 0, 9)).is_ok() {
            assert!(ip::parse_ipv4(&translated).is_ok());
        }
    }
    if parsed.is_ok() {
        if let Ok(error) = mtu::icmpv6_packet_too_big(packet, Ipv6Addr::LOCALHOST, 1280) {
            assert!(error.len() <= 1280);
            assert!(ip::parse_ip(&error).is_ok());
        }
    }
});
