//! Peer offers and peer lists: whatever decodes re-encodes identically.
#![no_main]

use libfuzzer_sys::fuzz_target;
use porta_wire::peer;

fuzz_target!(|data: &[u8]| {
    if let Ok(peers) = peer::decode_peers(data) {
        assert_eq!(peer::encode_peers(&peers).unwrap(), data);
    }
    if let Ok(fingerprint) = peer::decode_offer(data) {
        assert_eq!(peer::encode_offer(&fingerprint), data);
    }
});
