//! Requests by which a device proves to its gateway that its key lives in
//! secure hardware. Both are signed like a tunnel request, with the account
//! token and a device proof for the request's path.
//!
//! - Android sends its Keystore attestation certificate chain, which Google's
//!   attestation roots sign and which binds the device key.
//! - A TPM first sends its endorsement key, that key's certificate and the
//!   device key's public area to [`ATTESTATION_CHALLENGE_PATH`]. The gateway
//!   encrypts a secret to the endorsement key so that only a TPM holding
//!   the device key can recover it (TPM2_ActivateCredential), and the device
//!   returns the secret to [`ATTESTATION_PATH`].

use serde::{Deserialize, Serialize};

pub const ATTESTATION_PATH: &str = "/v1/device/attestation";
pub const ATTESTATION_CHALLENGE_PATH: &str = "/v1/device/attestation/challenge";

/// The challenge Android device keys are generated with. Freshness is not
/// needed: the evidence attests the key itself, whose possession every
/// request proves.
pub const ANDROID_ATTESTATION_CHALLENGE: &[u8] = b"porta-device-key-attestation-v1";

/// Upper bounds the gateway enforces on evidence.
pub const MAX_CERTIFICATES: usize = 8;
pub const MAX_CERTIFICATE_SIZE: usize = 8 << 10;

/// Body of a `POST` to [`ATTESTATION_PATH`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "platform", rename_all = "snake_case", deny_unknown_fields)]
pub enum AttestationRequest {
    /// The attestation certificate chain, leaf first, each certificate
    /// base64url-encoded DER.
    Android { certificates: Vec<String> },
    /// The answer to a [`TpmChallenge`].
    Tpm { challenge: String, secret: String },
}

/// Body of a `POST` to [`ATTESTATION_CHALLENGE_PATH`]; every field is
/// base64url without padding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TpmChallengeRequest {
    /// The endorsement key's `TPMT_PUBLIC`.
    pub endorsement_key: String,
    /// The endorsement key certificate, then any intermediates, as DER.
    pub endorsement_certificates: Vec<String>,
    /// The device key's `TPMT_PUBLIC`.
    pub device_key: String,
}

/// What the gateway answers a [`TpmChallengeRequest`] with.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TpmChallenge {
    /// Identifies the pending challenge in the answer.
    pub challenge: String,
    /// `TPM2B_ID_OBJECT` and `TPM2B_ENCRYPTED_SECRET` for
    /// TPM2_ActivateCredential, base64url without padding.
    pub credential_blob: String,
    pub encrypted_secret: String,
}

/// What the gateway records for a verified device key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestationResult {
    /// `android` or `tpm`.
    pub platform: String,
    /// `strongbox`, `tee` or `tpm`.
    pub level: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub vendor: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_tagged_by_platform_and_strict() {
        let android = AttestationRequest::Android {
            certificates: vec!["AQID".into()],
        };
        let encoded = serde_json::to_string(&android).unwrap();
        assert_eq!(encoded, r#"{"platform":"android","certificates":["AQID"]}"#);
        assert_eq!(
            serde_json::from_str::<AttestationRequest>(&encoded).unwrap(),
            android
        );
        assert!(serde_json::from_str::<AttestationRequest>(
            r#"{"platform":"android","certificates":[],"extra":1}"#
        )
        .is_err());
        assert!(serde_json::from_str::<AttestationRequest>(r#"{"platform":"ios"}"#).is_err());
        let tpm: AttestationRequest =
            serde_json::from_str(r#"{"platform":"tpm","challenge":"c","secret":"s"}"#).unwrap();
        assert_eq!(
            tpm,
            AttestationRequest::Tpm {
                challenge: "c".into(),
                secret: "s".into()
            }
        );
    }
}
