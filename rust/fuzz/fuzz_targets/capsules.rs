//! A MASQUE capsule stream as a gateway or client receives it: every
//! capsule a peer can send is decoded, and whatever decodes re-encodes to
//! the same value.
#![no_main]

use libfuzzer_sys::fuzz_target;
use porta_wire::masque::{self, Decoder};
use porta_wire::peer;

fuzz_target!(|data: &[u8]| {
    let mut decoder = Decoder::new(data);
    while let Ok(capsule) = decoder.read() {
        let value = capsule.value.as_slice();
        match capsule.capsule_type {
            masque::CAPSULE_DATAGRAM => {
                if let Ok(packet) = masque::decode_ip_packet(value) {
                    let encoded = masque::encode_ip_packet(packet);
                    assert_eq!(masque::decode_ip_packet(&encoded).unwrap(), packet);
                }
            }
            masque::CAPSULE_ADDRESS_REQUEST => {
                if let Ok(addresses) = masque::decode_address_request(value) {
                    let encoded = masque::encode_address_request(&addresses).unwrap();
                    assert_eq!(masque::decode_address_request(&encoded).unwrap(), addresses);
                }
            }
            masque::CAPSULE_ADDRESS_ASSIGN => {
                if let Ok(addresses) = masque::decode_address_assign(value) {
                    let encoded = masque::encode_address_assign(&addresses).unwrap();
                    assert_eq!(masque::decode_address_assign(&encoded).unwrap(), addresses);
                }
            }
            masque::CAPSULE_ROUTE_ADVERTISEMENT => {
                if let Ok(routes) = masque::decode_route_advertisement(value) {
                    let encoded = masque::encode_route_advertisement(&routes).unwrap();
                    assert_eq!(encoded, value);
                }
            }
            masque::CAPSULE_MTU_SELECT | masque::CAPSULE_MTU_SELECTED => {
                let _ = masque::decode_mtu_selection(value, [0; masque::MTU_TOKEN_SIZE]);
            }
            peer::CAPSULE_PEER_OFFER => {
                let _ = peer::decode_offer(value);
            }
            peer::CAPSULE_PEERS => {
                let _ = peer::decode_peers(value);
            }
            _ => {}
        }
    }
    if masque::is_mtu_probe(data) {
        if let Ok(probe) = masque::decode_mtu_probe(data) {
            assert_eq!(masque::encode_mtu_probe(probe).unwrap(), data);
        }
    }
    // QUIC allows non-minimal varints; encoding is minimal.
    if let Ok((value, length)) = masque::parse_varint(data) {
        let encoded = masque::encode_varint(value).unwrap();
        assert!(encoded.len() <= length);
        assert_eq!(masque::parse_varint(&encoded).unwrap(), (value, encoded.len()));
    }
});
