//! Device proof parsing, canonicalization, and verification.

use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use http::HeaderMap;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;

pub const HEADER_CLIENT_ID: &str = "X-Porta-Client-ID";
pub const HEADER_PUBLIC_KEY: &str = "X-Porta-Device-Key";
pub const HEADER_NAME: &str = "X-Porta-Device-Name";
pub const HEADER_TIMESTAMP: &str = "X-Porta-Device-Time";
pub const HEADER_NONCE: &str = "X-Porta-Device-Nonce";
pub const HEADER_SIGNATURE: &str = "X-Porta-Device-Signature";
pub const MAX_CLOCK_SKEW_SECONDS: i64 = 5 * 60;
pub const MAX_CLOCK_SKEW: std::time::Duration =
    std::time::Duration::from_secs(MAX_CLOCK_SKEW_SECONDS as u64);
pub const NONCE_SIZE: usize = 16;

const DOMAIN: &str = "porta/device-auth/v1";
const MAX_PUBLIC_KEY_SIZE: usize = 512;
const MAX_SIGNATURE_SIZE: usize = 128;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Proof {
    pub device_id: String,
    pub name: String,
    pub public_key: String,
    pub timestamp: String,
    pub nonce: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedProof {
    pub encoded_public_key: Vec<u8>,
    pub signed_at: OffsetDateTime,
    pub nonce: [u8; NONCE_SIZE],
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum DeviceAuthError {
    #[error("device proof header is invalid")]
    InvalidHeader,
    #[error("device ID is invalid")]
    InvalidDeviceId,
    #[error("device name is invalid")]
    InvalidDeviceName,
    #[error("device public key is invalid")]
    InvalidPublicKey,
    #[error("device public key must use ECDSA P-256")]
    PublicKeyNotP256,
    #[error("device ID does not match its public key")]
    DeviceIdMismatch,
    #[error("device proof timestamp is invalid")]
    InvalidTimestamp,
    #[error("device proof timestamp is outside the allowed window")]
    TimestampOutsideWindow,
    #[error("device proof nonce is invalid")]
    InvalidNonce,
    #[error("device proof signature is invalid")]
    InvalidSignature,
    #[error("system time is before the Unix epoch")]
    InvalidSystemTime,
}

impl Proof {
    pub fn from_headers(headers: &HeaderMap) -> Result<Self, DeviceAuthError> {
        Ok(Self {
            device_id: header_value(headers, HEADER_CLIENT_ID)?,
            name: header_value(headers, HEADER_NAME)?,
            public_key: header_value(headers, HEADER_PUBLIC_KEY)?,
            timestamp: header_value(headers, HEADER_TIMESTAMP)?,
            nonce: header_value(headers, HEADER_NONCE)?,
            signature: header_value(headers, HEADER_SIGNATURE)?,
        })
    }

    pub fn verify(
        &self,
        token: &str,
        method: &str,
        path: &str,
        now_unix_seconds: i64,
    ) -> Result<VerifiedProof, DeviceAuthError> {
        if !is_valid_device_id(&self.device_id) {
            return Err(DeviceAuthError::InvalidDeviceId);
        }
        if !is_valid_device_name(&self.name) {
            return Err(DeviceAuthError::InvalidDeviceName);
        }

        let encoded_public_key = decode_bounded_base64(
            &self.public_key,
            MAX_PUBLIC_KEY_SIZE,
            DeviceAuthError::InvalidPublicKey,
        )?;
        let public_key = parse_p256_public_key(&encoded_public_key)?;
        let derived_id = device_id(&public_key).map_err(|_| DeviceAuthError::InvalidPublicKey)?;
        if derived_id != self.device_id {
            return Err(DeviceAuthError::DeviceIdMismatch);
        }

        let signed_at = self
            .timestamp
            .parse::<i64>()
            .map_err(|_| DeviceAuthError::InvalidTimestamp)?;
        if signed_at < now_unix_seconds.saturating_sub(MAX_CLOCK_SKEW_SECONDS)
            || signed_at > now_unix_seconds.saturating_add(MAX_CLOCK_SKEW_SECONDS)
        {
            return Err(DeviceAuthError::TimestampOutsideWindow);
        }
        let signed_at_time = OffsetDateTime::from_unix_timestamp(signed_at)
            .map_err(|_| DeviceAuthError::InvalidTimestamp)?;

        let nonce = parse_nonce(&self.nonce)?;
        let signature_bytes = decode_bounded_base64(
            &self.signature,
            MAX_SIGNATURE_SIZE,
            DeviceAuthError::InvalidSignature,
        )?;
        let signature =
            Signature::from_der(&signature_bytes).map_err(|_| DeviceAuthError::InvalidSignature)?;
        let digest = Sha256::digest(signature_payload(self, token, method, path));
        VerifyingKey::from(public_key)
            .verify_prehash(&digest, &signature)
            .map_err(|_| DeviceAuthError::InvalidSignature)?;

        Ok(VerifiedProof {
            encoded_public_key,
            signed_at: signed_at_time,
            nonce,
        })
    }

    pub fn verify_at_system_time(
        &self,
        token: &str,
        method: &str,
        path: &str,
        now: SystemTime,
    ) -> Result<VerifiedProof, DeviceAuthError> {
        let seconds = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DeviceAuthError::InvalidSystemTime)?
            .as_secs();
        let seconds = i64::try_from(seconds).map_err(|_| DeviceAuthError::InvalidSystemTime)?;
        self.verify(token, method, path, seconds)
    }
}

pub fn verify(
    proof: &Proof,
    token: &str,
    method: &str,
    path: &str,
    now: OffsetDateTime,
) -> Result<VerifiedProof, DeviceAuthError> {
    proof.verify(token, method, path, now.unix_timestamp())
}

pub fn from_headers(headers: &HeaderMap) -> Result<Proof, DeviceAuthError> {
    Proof::from_headers(headers)
}

pub fn parse_public_key_spki(encoded: &[u8]) -> Result<VerifyingKey, DeviceAuthError> {
    if encoded.is_empty() || encoded.len() > MAX_PUBLIC_KEY_SIZE {
        return Err(DeviceAuthError::InvalidPublicKey);
    }
    let public_key = parse_p256_public_key(encoded)?;
    Ok(VerifyingKey::from(public_key))
}

pub fn device_id_from_encoded(encoded: &[u8]) -> Result<String, DeviceAuthError> {
    let public_key = parse_p256_public_key(encoded)?;
    device_id(&public_key)
}

pub fn device_id(public_key: &p256::PublicKey) -> Result<String, DeviceAuthError> {
    let encoded = public_key
        .to_public_key_der()
        .map_err(|_| DeviceAuthError::InvalidPublicKey)?;
    let digest = Sha256::digest(encoded.as_bytes());
    Ok(format!("d-{}", URL_SAFE_NO_PAD.encode(&digest[..16])))
}

pub fn parse_nonce(encoded: &str) -> Result<[u8; NONCE_SIZE], DeviceAuthError> {
    if encoded.len() != 22 {
        return Err(DeviceAuthError::InvalidNonce);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| DeviceAuthError::InvalidNonce)?;
    decoded
        .try_into()
        .map_err(|_| DeviceAuthError::InvalidNonce)
}

pub fn token_binding(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

pub fn signature_payload(proof: &Proof, token: &str, method: &str, path: &str) -> Vec<u8> {
    let token_hash = token_binding(token);
    let method = method.to_uppercase();
    let capacity = DOMAIN.len()
        + method.len()
        + path.len()
        + proof.device_id.len()
        + proof.name.len()
        + proof.timestamp.len()
        + proof.nonce.len()
        + token_hash.len()
        + 7;
    let mut canonical = String::with_capacity(capacity);
    write!(
        canonical,
        "{DOMAIN}\n{method}\n{path}\n{}\n{}\n{}\n{}\n{token_hash}",
        proof.device_id, proof.name, proof.timestamp, proof.nonce
    )
    .expect("writing to a String cannot fail");
    canonical.into_bytes()
}

fn header_value(headers: &HeaderMap, name: &'static str) -> Result<String, DeviceAuthError> {
    headers.get(name).map_or(Ok(String::new()), |value| {
        value
            .to_str()
            .map(str::to_owned)
            .map_err(|_| DeviceAuthError::InvalidHeader)
    })
}

pub fn is_valid_device_id(value: &str) -> bool {
    value.len() == 24
        && value.starts_with("d-")
        && value.as_bytes()[2..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub fn is_valid_device_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn decode_bounded_base64(
    encoded: &str,
    maximum_decoded_size: usize,
    error: DeviceAuthError,
) -> Result<Vec<u8>, DeviceAuthError> {
    let maximum_encoded_size = maximum_decoded_size.div_ceil(3) * 4;
    if encoded.is_empty() || encoded.len() > maximum_encoded_size {
        return Err(error);
    }
    let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| error)?;
    if decoded.is_empty() || decoded.len() > maximum_decoded_size {
        return Err(error);
    }
    Ok(decoded)
}

fn parse_p256_public_key(encoded: &[u8]) -> Result<p256::PublicKey, DeviceAuthError> {
    match p256::PublicKey::from_public_key_der(encoded) {
        Ok(key) => Ok(key),
        Err(_) if spki_declares_non_p256(encoded) => Err(DeviceAuthError::PublicKeyNotP256),
        Err(_) => Err(DeviceAuthError::InvalidPublicKey),
    }
}

fn spki_declares_non_p256(encoded: &[u8]) -> bool {
    const EC_PUBLIC_KEY_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    const P256_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

    let Some((outer, remainder)) = read_der_value(encoded, 0x30) else {
        return false;
    };
    if !remainder.is_empty() {
        return false;
    }
    let Some((algorithm, _public_key)) = read_der_value(outer, 0x30) else {
        return false;
    };
    let Some((algorithm_oid, parameters)) = read_der_value(algorithm, 0x06) else {
        return false;
    };
    if algorithm_oid != EC_PUBLIC_KEY_OID {
        return true;
    }
    let Some((curve_oid, remainder)) = read_der_value(parameters, 0x06) else {
        return false;
    };
    remainder.is_empty() && curve_oid != P256_OID
}

fn read_der_value(input: &[u8], expected_tag: u8) -> Option<(&[u8], &[u8])> {
    if input.first().copied()? != expected_tag {
        return None;
    }
    let first_length = *input.get(1)?;
    let (length, header_length) = if first_length & 0x80 == 0 {
        (usize::from(first_length), 2)
    } else {
        let length_bytes = usize::from(first_length & 0x7f);
        if length_bytes == 0 || length_bytes > std::mem::size_of::<usize>() {
            return None;
        }
        let bytes = input.get(2..2 + length_bytes)?;
        if bytes.first() == Some(&0) {
            return None;
        }
        let length = bytes.iter().try_fold(0_usize, |value, byte| {
            value.checked_mul(256)?.checked_add(usize::from(*byte))
        })?;
        if length < 128 {
            return None;
        }
        (length, 2 + length_bytes)
    };
    let end = header_length.checked_add(length)?;
    Some((input.get(header_length..end)?, input.get(end..)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use http::HeaderValue;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::ecdsa::{Signature, SigningKey};

    const SPKI_HEX: &str = "3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
    const SPKI_BASE64: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li_hp_m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q";
    const DEVICE_ID: &str = "d-XNJS-wzokyQ2-vjM0QQJgQ";
    const NONCE: &str = "AAECAwQFBgcICQoLDA0ODw";

    fn signing_key() -> SigningKey {
        let mut scalar = [0_u8; 32];
        scalar[31] = 1;
        SigningKey::from_bytes((&scalar).into()).unwrap()
    }

    fn nonce_bytes() -> [u8; 16] {
        std::array::from_fn(|index| index as u8)
    }

    fn unsigned_proof() -> Proof {
        Proof {
            device_id: DEVICE_ID.into(),
            name: "Office-PC".into(),
            public_key: SPKI_BASE64.into(),
            timestamp: "1800000000".into(),
            nonce: NONCE.into(),
            signature: String::new(),
        }
    }

    fn signed_proof() -> Proof {
        let mut proof = unsigned_proof();
        let digest = Sha256::digest(signature_payload(
            &proof,
            "account-token",
            "CONNECT",
            "/tunnel",
        ));
        let signature: Signature = signing_key().sign_prehash(&digest).unwrap();
        proof.signature = URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes());
        proof
    }

    #[test]
    fn parses_p256_spki_and_derives_go_fingerprint() {
        let encoded = hex::decode(SPKI_HEX).unwrap();
        let key = parse_public_key_spki(&encoded).unwrap();
        assert_eq!(
            key.to_encoded_point(false).as_bytes(),
            signing_key()
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
        );
        assert_eq!(device_id_from_encoded(&encoded).unwrap(), DEVICE_ID);
        assert_eq!(URL_SAFE_NO_PAD.encode(encoded), SPKI_BASE64);
    }

    #[test]
    fn distinguishes_valid_non_p256_spki_from_malformed_der() {
        let mut ed25519 = hex::decode("302a300506032b6570032100").unwrap();
        ed25519.extend_from_slice(&[7; 32]);
        assert_eq!(
            parse_public_key_spki(&ed25519),
            Err(DeviceAuthError::PublicKeyNotP256)
        );
        assert_eq!(
            parse_public_key_spki(&[0x30, 0x01, 0]),
            Err(DeviceAuthError::InvalidPublicKey)
        );
    }

    #[test]
    fn canonical_payload_and_token_binding_match_go_vectors() {
        assert_eq!(
            token_binding("account-token"),
            "wpyd2jYFD0jdqJE_kt95wwSQ6CwaD_abtnGP0VZZrZI"
        );
        let expected = concat!(
            "porta/device-auth/v1\n",
            "CONNECT\n",
            "/tunnel\n",
            "d-XNJS-wzokyQ2-vjM0QQJgQ\n",
            "Office-PC\n",
            "1800000000\n",
            "AAECAwQFBgcICQoLDA0ODw\n",
            "wpyd2jYFD0jdqJE_kt95wwSQ6CwaD_abtnGP0VZZrZI"
        );
        assert_eq!(
            signature_payload(&unsigned_proof(), "account-token", "connect", "/tunnel"),
            expected.as_bytes()
        );
    }

    #[test]
    fn verifies_a_complete_proof_and_inclusive_time_window() {
        let proof = signed_proof();
        let verified = proof
            .verify("account-token", "CONNECT", "/tunnel", 1_800_000_000)
            .unwrap();
        assert_eq!(verified.encoded_public_key, hex::decode(SPKI_HEX).unwrap());
        assert_eq!(verified.signed_at.unix_timestamp(), 1_800_000_000);
        assert_eq!(verified.nonce, nonce_bytes());
        assert!(proof
            .verify(
                "account-token",
                "CONNECT",
                "/tunnel",
                1_800_000_000 + MAX_CLOCK_SKEW_SECONDS
            )
            .is_ok());
        assert!(proof
            .verify(
                "account-token",
                "CONNECT",
                "/tunnel",
                1_800_000_000 - MAX_CLOCK_SKEW_SECONDS
            )
            .is_ok());
    }

    #[test]
    fn parses_proof_headers_like_go_from_request() {
        let proof = signed_proof();
        let mut headers = HeaderMap::new();
        headers.insert(HEADER_CLIENT_ID, proof.device_id.parse().unwrap());
        headers.insert(HEADER_NAME, proof.name.parse().unwrap());
        headers.insert(HEADER_PUBLIC_KEY, proof.public_key.parse().unwrap());
        headers.insert(HEADER_TIMESTAMP, proof.timestamp.parse().unwrap());
        headers.insert(HEADER_NONCE, proof.nonce.parse().unwrap());
        headers.insert(HEADER_SIGNATURE, proof.signature.parse().unwrap());
        assert_eq!(Proof::from_headers(&headers).unwrap(), proof);

        let mut invalid = HeaderMap::new();
        invalid.insert(
            HEADER_NAME,
            HeaderValue::from_bytes(&[0xff]).expect("opaque header value"),
        );
        assert_eq!(
            Proof::from_headers(&invalid),
            Err(DeviceAuthError::InvalidHeader)
        );
    }

    #[test]
    fn signature_binds_every_security_field() {
        let proof = signed_proof();
        let cases = [
            (proof.clone(), "other-token", "CONNECT", "/tunnel"),
            (proof.clone(), "account-token", "POST", "/tunnel"),
            (proof.clone(), "account-token", "CONNECT", "/other"),
            (
                Proof {
                    name: "Home-PC".into(),
                    ..proof.clone()
                },
                "account-token",
                "CONNECT",
                "/tunnel",
            ),
            (
                Proof {
                    timestamp: "1800000001".into(),
                    ..proof.clone()
                },
                "account-token",
                "CONNECT",
                "/tunnel",
            ),
            (
                Proof {
                    nonce: URL_SAFE_NO_PAD.encode([0_u8; 16]),
                    ..proof.clone()
                },
                "account-token",
                "CONNECT",
                "/tunnel",
            ),
        ];
        for (proof, token, method, path) in cases {
            assert!(proof.verify(token, method, path, 1_800_000_000).is_err());
        }
    }

    #[test]
    fn rejects_stale_and_malformed_proofs() {
        let proof = signed_proof();
        assert_eq!(
            proof
                .verify(
                    "account-token",
                    "CONNECT",
                    "/tunnel",
                    1_800_000_000 + MAX_CLOCK_SKEW_SECONDS + 1
                )
                .unwrap_err(),
            DeviceAuthError::TimestampOutsideWindow
        );
        assert_eq!(
            proof
                .verify(
                    "account-token",
                    "CONNECT",
                    "/tunnel",
                    1_800_000_000 - MAX_CLOCK_SKEW_SECONDS - 1
                )
                .unwrap_err(),
            DeviceAuthError::TimestampOutsideWindow
        );

        let malformed = [
            Proof {
                device_id: "d-AAAAAAAAAAAAAAAAAAAAAA".into(),
                ..proof.clone()
            },
            Proof {
                name: "invalid name".into(),
                ..proof.clone()
            },
            Proof {
                public_key: "bad".into(),
                ..proof.clone()
            },
            Proof {
                timestamp: "not-a-time".into(),
                ..proof.clone()
            },
            Proof {
                nonce: "bad".into(),
                ..proof.clone()
            },
            Proof {
                signature: "bad".into(),
                ..proof
            },
        ];
        for proof in malformed {
            assert!(proof
                .verify("account-token", "CONNECT", "/tunnel", 1_800_000_000)
                .is_err());
        }

        let mut scalar = [0_u8; 32];
        scalar[31] = 2;
        let other = SigningKey::from_bytes((&scalar).into()).unwrap();
        let other_spki = p256::PublicKey::from(other.verifying_key())
            .to_public_key_der()
            .unwrap();
        let wrong_key = Proof {
            public_key: URL_SAFE_NO_PAD.encode(other_spki.as_bytes()),
            ..signed_proof()
        };
        assert_eq!(
            wrong_key
                .verify("account-token", "CONNECT", "/tunnel", 1_800_000_000)
                .unwrap_err(),
            DeviceAuthError::DeviceIdMismatch
        );
    }

    #[test]
    fn nonce_validation_requires_raw_url_base64_and_exact_length() {
        assert_eq!(parse_nonce(NONCE).unwrap(), nonce_bytes());
        for invalid in [
            "",
            "AAECAwQFBgcICQoLDA0ODw==",
            "AAECAwQFBgcICQoLDA0OD+",
            "AAECAwQFBgcICQoLDA0O",
        ] {
            assert_eq!(parse_nonce(invalid), Err(DeviceAuthError::InvalidNonce));
        }
    }

    #[test]
    fn identifier_and_name_shapes_match_go_patterns() {
        assert!(is_valid_device_id(DEVICE_ID));
        assert!(!is_valid_device_id("forward-proxy"));
        assert!(!is_valid_device_id("d-AAAAAAAAAAAAAAAAAAAAA="));
        assert!(is_valid_device_name("A"));
        assert!(is_valid_device_name(&format!("A{}", "_".repeat(63))));
        assert!(!is_valid_device_name(""));
        assert!(!is_valid_device_name("-starts-with-punctuation"));
        assert!(!is_valid_device_name(&format!("A{}", "_".repeat(64))));
    }
}
