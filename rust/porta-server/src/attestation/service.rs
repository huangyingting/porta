//! The gateway endpoints devices prove their key at, signed like a tunnel
//! request with the account token and a device proof for the path.

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use porta_wire::attestation::{
    AttestationRequest, AttestationResult, TpmChallengeRequest, ATTESTATION_CHALLENGE_PATH,
    ATTESTATION_PATH, MAX_CERTIFICATES, MAX_CERTIFICATE_SIZE,
};
use porta_wire::device_auth::{self, Proof};
use time::OffsetDateTime;

use super::android::AndroidVerifier;
use super::tpm::TpmVerifier;
use super::AttestationError;
use crate::state::registry::{ClientRegistry, HardwareAttestation, RegistryError};
use crate::web::session::{RequestContext, Response};

pub struct AttestationService {
    registry: Arc<ClientRegistry>,
    android: Arc<AndroidVerifier>,
    tpm: Option<Arc<TpmVerifier>>,
}

impl AttestationService {
    pub fn new(registry: Arc<ClientRegistry>, android: Arc<AndroidVerifier>) -> Self {
        Self {
            registry,
            android,
            tpm: None,
        }
    }

    /// Verifies TPM keys against these vendor CAs.
    pub fn with_tpm(mut self, tpm: Arc<TpmVerifier>) -> Self {
        self.tpm = Some(tpm);
        self
    }

    /// Answers requests to the attestation endpoints, and nothing else.
    pub async fn handle(&self, request: &RequestContext) -> Option<Response> {
        if request.path != ATTESTATION_PATH && request.path != ATTESTATION_CHALLENGE_PATH {
            return None;
        }
        if request.method != "POST" {
            let mut response = error(405, "use POST");
            response.set_header("Allow", "POST");
            return Some(response);
        }
        Some(self.respond(request).await)
    }

    async fn respond(&self, request: &RequestContext) -> Response {
        let token = request
            .header("authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .unwrap_or_default();
        let Some(proof) = proof(request) else {
            return error(401, "the request has no device proof");
        };
        let (account, device, key) = match self
            .registry
            .authenticate_attestation(token, &proof, "POST", &request.path)
            .await
        {
            Ok(identity) => identity,
            Err(RegistryError::DeviceDenied) => {
                let mut response = error(403, "the administrator has not allowed this device");
                response.set_header("X-Porta-Reason", "device-denied");
                return response;
            }
            Err(RegistryError::Unauthorized | RegistryError::Disabled) => {
                return error(401, "the token or device proof is not valid")
            }
            Err(error_value) => {
                tracing::warn!(error = %error_value, "device attestation could not authenticate");
                return error(503, "the gateway cannot verify devices right now");
            }
        };
        if request.path == ATTESTATION_CHALLENGE_PATH {
            let Some(tpm) = &self.tpm else {
                return error(404, "this gateway does not verify TPM keys");
            };
            let Ok(body) = serde_json::from_slice::<TpmChallengeRequest>(&request.body) else {
                return error(400, "the TPM challenge request is malformed");
            };
            return match tpm.challenge(&account, &device, &key, &body, OffsetDateTime::now_utc()) {
                Ok(challenge) => {
                    Response::json(200, serde_json::to_vec(&challenge).unwrap_or_default())
                }
                Err(reason) => {
                    tracing::info!(account_id = %account, device_id = %device, %reason, "TPM verification refused");
                    error(422, &reason.to_string())
                }
            };
        }
        let body = match serde_json::from_slice::<AttestationRequest>(&request.body) {
            Ok(body) => body,
            Err(_) => return error(400, "the attestation request is malformed"),
        };
        let result = match body {
            AttestationRequest::Android { certificates } => decode_certificates(&certificates)
                .and_then(|chain| self.android.verify(&chain, &key, OffsetDateTime::now_utc())),
            AttestationRequest::Tpm { challenge, secret } => match &self.tpm {
                Some(tpm) => tpm.answer(&account, &device, &challenge, &secret),
                None => return error(404, "this gateway does not verify TPM keys"),
            },
        };
        match result {
            Ok(result) => self.record(&account, &device, result).await,
            Err(reason) => {
                tracing::info!(account_id = %account, device_id = %device, %reason, "device attestation refused");
                error(422, &reason.to_string())
            }
        }
    }

    async fn record(&self, account: &str, device: &str, result: AttestationResult) -> Response {
        let hardware = HardwareAttestation {
            platform: result.platform.clone(),
            level: result.level.clone(),
            vendor: result.vendor.clone(),
            verified_at: OffsetDateTime::now_utc(),
        };
        match self
            .registry
            .record_hardware(account, device, hardware)
            .await
        {
            Ok(()) => {
                tracing::info!(
                    account_id = %account,
                    device_id = %device,
                    platform = %result.platform,
                    level = %result.level,
                    "device key verified in secure hardware"
                );
                Response::json(200, serde_json::to_vec(&result).unwrap_or_default())
            }
            Err(RegistryError::ReadOnly) => error(
                503,
                "verify the device on the primary gateway, which records it",
            ),
            Err(error_value) => {
                tracing::warn!(error = %error_value, "device attestation could not be recorded");
                error(503, "the gateway could not record the verification")
            }
        }
    }
}

fn proof(request: &RequestContext) -> Option<Proof> {
    let field = |name: &str| request.header(name).map(str::to_owned);
    Some(Proof {
        device_id: field(device_auth::HEADER_CLIENT_ID)?,
        name: field(device_auth::HEADER_NAME)?,
        public_key: field(device_auth::HEADER_PUBLIC_KEY)?,
        timestamp: field(device_auth::HEADER_TIMESTAMP)?,
        nonce: field(device_auth::HEADER_NONCE)?,
        signature: field(device_auth::HEADER_SIGNATURE)?,
    })
}

fn decode_certificates(encoded: &[String]) -> Result<Vec<Vec<u8>>, AttestationError> {
    if encoded.is_empty() || encoded.len() > MAX_CERTIFICATES {
        return Err(AttestationError::invalid(
            "the certificate chain has too few or too many certificates",
        ));
    }
    encoded
        .iter()
        .map(|certificate| {
            if certificate.len() > MAX_CERTIFICATE_SIZE * 4 / 3 + 4 {
                return Err(AttestationError::invalid("a certificate is too large"));
            }
            URL_SAFE_NO_PAD
                .decode(certificate)
                .map_err(|_| AttestationError::invalid("a certificate is not base64url"))
        })
        .collect()
}

fn error(status: u16, message: &str) -> Response {
    Response::json(
        status,
        serde_json::to_vec(&serde_json::json!({ "error": message })).unwrap_or_default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::android::test_support::{synthetic_for, PORTA_STRONGBOX};
    use crate::state::registry::RegistryError;
    use p256::ecdsa::signature::hazmat::PrehashSigner as _;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::elliptic_curve::Generate as _;
    use p256::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _};
    use sha2::{Digest as _, Sha256};

    const TOKEN: &str = "attestation-test-token-0123456789";

    fn signed(key: &SigningKey, path: &str, nonce: u8, body: Vec<u8>) -> RequestContext {
        let public_key = key.verifying_key().to_public_key_der().unwrap();
        let mut proof = Proof {
            device_id: device_auth::device_id_from_encoded(public_key.as_bytes()).unwrap(),
            name: "Phone".into(),
            public_key: URL_SAFE_NO_PAD.encode(public_key.as_bytes()),
            timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
            nonce: URL_SAFE_NO_PAD.encode([nonce; 16]),
            signature: String::new(),
        };
        let digest = Sha256::digest(device_auth::signature_payload(&proof, TOKEN, "POST", path));
        let signature: Signature = key.sign_prehash(&digest).unwrap();
        proof.signature = URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes());
        let mut request = RequestContext::new("POST", path).with_body(body);
        for (name, value) in [
            ("authorization", format!("Bearer {TOKEN}")),
            (device_auth::HEADER_CLIENT_ID, proof.device_id),
            (device_auth::HEADER_NAME, proof.name),
            (device_auth::HEADER_PUBLIC_KEY, proof.public_key),
            (device_auth::HEADER_TIMESTAMP, proof.timestamp),
            (device_auth::HEADER_NONCE, proof.nonce),
            (device_auth::HEADER_SIGNATURE, proof.signature),
        ] {
            request.headers.insert(name.to_ascii_lowercase(), value);
        }
        request
    }

    async fn tunnel(
        registry: &ClientRegistry,
        key: &SigningKey,
        nonce: u8,
    ) -> Result<(), RegistryError> {
        let request = signed(key, "/v1/tunnel", nonce, Vec::new());
        let proof = proof(&request).unwrap();
        registry
            .authenticate_device_session(TOKEN, &proof, "POST", "/v1/tunnel")
            .await
            .map(drop)
    }

    #[tokio::test]
    async fn a_verified_android_key_lets_its_device_connect() {
        let directory = tempfile::tempdir().unwrap();
        let registry = Arc::new(
            ClientRegistry::open(directory.path().join("clients.json"), TOKEN)
                .await
                .unwrap(),
        );
        let account = registry.list()[0].id.clone();
        registry.set_require_hardware(&account, true).await.unwrap();

        let device = SigningKey::generate();
        let pair = rcgen::KeyPair::try_from(device.to_pkcs8_der().unwrap().as_bytes()).unwrap();
        let (chain, _, root) = synthetic_for(&PORTA_STRONGBOX, &pair);
        let service = AttestationService::new(
            registry.clone(),
            Arc::new(AndroidVerifier::with_policy(
                vec![root],
                vec![crate::attestation::android::PACKAGE.to_owned()],
                porta_wire::attestation::ANDROID_ATTESTATION_CHALLENGE.to_vec(),
            )),
        );
        let body = |chain: &[Vec<u8>]| {
            serde_json::to_vec(&AttestationRequest::Android {
                certificates: chain
                    .iter()
                    .map(|der| URL_SAFE_NO_PAD.encode(der))
                    .collect(),
            })
            .unwrap()
        };

        // Enrolled on its first attempt, the device must prove its key.
        assert!(matches!(
            tunnel(&registry, &device, 1).await,
            Err(RegistryError::HardwareRequired)
        ));
        assert!(service
            .handle(&RequestContext::new("GET", ATTESTATION_PATH))
            .await
            .is_some());
        assert!(service
            .handle(&RequestContext::new("POST", "/v1/tunnel"))
            .await
            .is_none());
        let unsigned = RequestContext::new("POST", ATTESTATION_PATH).with_body(body(&chain));
        assert_eq!(service.handle(&unsigned).await.unwrap().status, 401);
        let malformed = signed(&device, ATTESTATION_PATH, 2, b"{}".to_vec());
        assert_eq!(service.handle(&malformed).await.unwrap().status, 400);
        let partial = signed(&device, ATTESTATION_PATH, 3, body(&chain[..1]));
        assert_eq!(service.handle(&partial).await.unwrap().status, 422);
        // Someone else's evidence does not describe this key.
        let other = SigningKey::generate();
        assert!(tunnel(&registry, &other, 4).await.is_err());
        let borrowed = signed(&other, ATTESTATION_PATH, 5, body(&chain));
        assert_eq!(service.handle(&borrowed).await.unwrap().status, 422);
        assert!(tunnel(&registry, &device, 6).await.is_err());

        let accepted = signed(&device, ATTESTATION_PATH, 7, body(&chain));
        let response = service.handle(&accepted).await.unwrap();
        assert_eq!(response.status, 200);
        let result: AttestationResult = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(result.level, "strongbox");
        tunnel(&registry, &device, 8).await.unwrap();
        // A replayed request is refused.
        assert_eq!(service.handle(&accepted).await.unwrap().status, 401);
        assert!(matches!(
            tunnel(&registry, &other, 9).await,
            Err(RegistryError::HardwareRequired)
        ));
    }
}
