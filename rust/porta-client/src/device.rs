use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use p256::pkcs8::EncodePublicKey;
use porta_wire::device_auth::{self, Proof};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DeviceProofError {
    #[error("device public key is invalid")]
    PublicKey,
    #[error("system time is before the Unix epoch")]
    InvalidSystemTime,
    #[error("device proof signature failed")]
    Signature,
}

pub fn create_proof(
    signing_key: &SigningKey,
    name: &str,
    token: &str,
    method: &str,
    path: &str,
    now: SystemTime,
) -> Result<Proof, DeviceProofError> {
    let timestamp = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| DeviceProofError::InvalidSystemTime)?
        .as_secs()
        .to_string();
    let encoded_public_key = signing_key
        .verifying_key()
        .to_public_key_der()
        .map_err(|_| DeviceProofError::PublicKey)?;
    let device_id = device_auth::device_id_from_encoded(encoded_public_key.as_bytes())
        .map_err(|_| DeviceProofError::PublicKey)?;
    let mut nonce = [0_u8; device_auth::NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    let mut proof = Proof {
        device_id,
        name: name.to_owned(),
        public_key: URL_SAFE_NO_PAD.encode(encoded_public_key.as_bytes()),
        timestamp,
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        signature: String::new(),
    };
    let digest = Sha256::digest(device_auth::signature_payload(&proof, token, method, path));
    let signature: Signature = signing_key
        .sign_prehash(&digest)
        .map_err(|_| DeviceProofError::Signature)?;
    proof.signature = URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes());
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::rand_core::OsRng;
    use std::time::Duration;

    #[test]
    fn generated_proof_round_trips_through_shared_verifier() {
        let key = SigningKey::random(&mut OsRng);
        let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let proof = create_proof(
            &key,
            "Office-PC",
            "account-token",
            "CONNECT",
            "/.well-known/masque/ip/*/*/",
            now,
        )
        .unwrap();
        let verified = proof
            .verify(
                "account-token",
                "CONNECT",
                "/.well-known/masque/ip/*/*/",
                1_800_000_000,
            )
            .unwrap();
        assert_eq!(
            proof.device_id,
            device_auth::device_id_from_encoded(&verified.encoded_public_key).unwrap()
        );
    }

    #[test]
    fn proof_binds_token_method_and_path() {
        let key = SigningKey::random(&mut OsRng);
        let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let proof = create_proof(
            &key,
            "Office-PC",
            "account-token",
            "POST",
            "/v1/tunnel",
            now,
        )
        .unwrap();
        assert!(proof
            .verify("other-token", "POST", "/v1/tunnel", 1_800_000_000)
            .is_err());
        assert!(proof
            .verify("account-token", "CONNECT", "/v1/tunnel", 1_800_000_000)
            .is_err());
        assert!(proof
            .verify("account-token", "POST", "/other", 1_800_000_000)
            .is_err());
    }
}
