//! The HTTP/2 transport's length-prefixed packet stream.
#![no_main]

use libfuzzer_sys::fuzz_target;
use porta_wire::frame::{Decoder, Encoder};

fuzz_target!(|data: &[u8]| {
    let mut decoder = Decoder::new(data);
    let mut packets = Vec::new();
    while let Ok(packet) = decoder.read_packet() {
        packets.push(packet);
    }
    let mut encoder = Encoder::new(Vec::new());
    for packet in &packets {
        encoder.write_packet(packet).unwrap();
    }
    let encoded = encoder.into_inner();
    let mut again = Decoder::new(encoded.as_slice());
    for packet in &packets {
        assert_eq!(&again.read_packet().unwrap(), packet);
    }
});
