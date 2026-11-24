//! Device proof headers from an unauthenticated client: parsing and
//! verification reject garbage without panicking.
#![no_main]

use http::{HeaderMap, HeaderName, HeaderValue};
use libfuzzer_sys::fuzz_target;
use porta_wire::device_auth::{self, *};

const HEADERS: [&str; 6] = [
    HEADER_CLIENT_ID,
    HEADER_NAME,
    HEADER_PUBLIC_KEY,
    HEADER_TIMESTAMP,
    HEADER_NONCE,
    HEADER_SIGNATURE,
];

fuzz_target!(|data: &[u8]| {
    let mut headers = HeaderMap::new();
    for (name, value) in HEADERS.iter().zip(data.split(|byte| *byte == b'\n')) {
        if let Ok(value) = HeaderValue::from_bytes(value) {
            headers.append(HeaderName::from_static_lowercase(name), value);
        }
    }
    if let Ok(proof) = device_auth::from_headers(&headers) {
        let now = time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let _ = device_auth::verify(&proof, "token", "CONNECT", "/.well-known/masque/ip/*/*/", now);
        let _ = device_auth::signature_payload(&proof, "token", "CONNECT", "/");
    }
    let _ = device_auth::parse_public_key_spki(data);
    let _ = device_auth::device_id_from_encoded(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = device_auth::parse_nonce(text);
        let _ = device_auth::is_valid_device_id(text);
        let _ = device_auth::is_valid_device_name(text);
    }
});

trait StaticLowercase {
    fn from_static_lowercase(name: &str) -> HeaderName;
}

impl StaticLowercase for HeaderName {
    fn from_static_lowercase(name: &str) -> HeaderName {
        HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes()).unwrap()
    }
}
