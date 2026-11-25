//! Verifies that a device key lives in a TPM, by credential activation.
//!
//! The device sends its TPM's endorsement key (EK), the EK certificate, and
//! its key's public area. The gateway checks the certificate chain up to a
//! TPM vendor's root, then encrypts a random secret to the EK with
//! TPM2_MakeCredential, bound to the device key's name. A TPM recovers the
//! secret (TPM2_ActivateCredential) only if it holds that EK and has that
//! exact key loaded; the name covers the key's attributes, which say it was
//! generated in the TPM and cannot leave it.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use aws_lc_rs::cipher::{EncryptingKey, EncryptionContext, UnboundCipherKey, AES_128};
use aws_lc_rs::hmac;
use aws_lc_rs::iv::FixedLength;
use aws_lc_rs::rand::SecureRandom as _;
use aws_lc_rs::rsa::{OaepPublicEncryptingKey, PublicEncryptingKey, OAEP_SHA256_MGF1SHA256};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use parking_lot::Mutex;
use porta_wire::attestation::{AttestationResult, TpmChallenge, TpmChallengeRequest};
use porta_wire::tpm::{
    self, attributes, Parameters, Public, Symmetric, Unique, ALG_RSA, ALG_SHA256,
};
use subtle::ConstantTimeEq as _;
use time::OffsetDateTime;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::public_key::PublicKey;
use zeroize::Zeroizing;

use super::x509;
use super::AttestationError;

const CHALLENGE_LIFETIME: Duration = Duration::from_secs(300);
const MAX_PENDING: usize = 4096;
const MAX_CHAIN: usize = 6;
/// tcg-at-tpmManufacturer in an EK certificate's subject alternative name.
const TPM_MANUFACTURER: &str = "2.23.133.2.1";

struct Pending {
    account: String,
    device: String,
    secret: Zeroizing<Vec<u8>>,
    vendor: String,
    created: Instant,
}

pub struct TpmVerifier {
    anchors: Vec<Vec<u8>>,
    intermediates: Vec<Vec<u8>>,
    pending: Mutex<HashMap<String, Pending>>,
}

impl TpmVerifier {
    /// Trusts the TPM vendor CAs in `directory`, such as the contents of
    /// Microsoft's TrustedTpm.cab: self-signed certificates are roots, the
    /// rest intermediates. Certificates may be DER or PEM.
    pub fn from_directory(directory: &Path) -> std::io::Result<Self> {
        let mut certificates = Vec::new();
        let mut pending = vec![directory.to_owned()];
        while let Some(path) = pending.pop() {
            for entry in std::fs::read_dir(&path)? {
                let entry = entry?;
                let kind = entry.file_type()?;
                if kind.is_dir() {
                    pending.push(entry.path());
                } else if kind.is_file() && entry.metadata()?.len() <= 1 << 20 {
                    let data = std::fs::read(entry.path())?;
                    // PEM files may carry a text dump before the block.
                    if data.windows(10).any(|window| window == b"-----BEGIN") {
                        certificates.extend(
                            x509_parser::pem::Pem::iter_from_buffer(&data)
                                .filter_map(Result::ok)
                                .map(|pem| pem.contents),
                        );
                    } else {
                        certificates.push(data);
                    }
                }
            }
        }
        Ok(Self::from_certificates(certificates))
    }

    /// Sorts DER `certificates` into roots and intermediates.
    pub fn from_certificates(certificates: Vec<Vec<u8>>) -> Self {
        let mut anchors = Vec::new();
        let mut intermediates = Vec::new();
        for der in certificates {
            let Ok(certificate) = x509::parse(&der) else {
                continue;
            };
            if certificate.subject() == certificate.issuer()
                && x509::signed_by(&certificate, certificate.public_key())
            {
                anchors.push(certificate.public_key().raw.to_vec());
            } else if x509::is_ca(&certificate) {
                intermediates.push(der);
            }
        }
        Self {
            anchors,
            intermediates,
            pending: Mutex::new(HashMap::new()),
        }
    }

    pub fn root_count(&self) -> usize {
        self.anchors.len()
    }

    /// Checks the endorsement evidence and returns a challenge that only
    /// the TPM holding `device_key` can answer.
    pub fn challenge(
        &self,
        account: &str,
        device: &str,
        device_key: &[u8],
        request: &TpmChallengeRequest,
        now: OffsetDateTime,
    ) -> Result<TpmChallenge, AttestationError> {
        let decode = |value: &str, limit: usize| {
            if value.len() > limit * 4 / 3 + 4 {
                return Err(AttestationError::invalid("the TPM evidence is too large"));
            }
            URL_SAFE_NO_PAD
                .decode(value)
                .map_err(|_| AttestationError::invalid("the TPM evidence is not base64url"))
        };
        let endorsement_area = decode(&request.endorsement_key, 1024)?;
        let device_area = decode(&request.device_key, 1024)?;
        if request.endorsement_certificates.is_empty()
            || request.endorsement_certificates.len() > MAX_CHAIN
        {
            return Err(AttestationError::invalid(
                "the endorsement key certificate is missing",
            ));
        }
        let certificates = request
            .endorsement_certificates
            .iter()
            .map(|certificate| decode(certificate, 8 << 10))
            .collect::<Result<Vec<_>, _>>()?;

        let endorsement = Public::decode(&endorsement_area)
            .map_err(|_| AttestationError::invalid("the endorsement key is malformed"))?;
        let modulus = endorsement_modulus(&endorsement)?;
        let device_public = Public::decode(&device_area)
            .map_err(|_| AttestationError::invalid("the device key is malformed"))?;
        let required = attributes::FIXED_TPM
            | attributes::FIXED_PARENT
            | attributes::SENSITIVE_DATA_ORIGIN
            | attributes::SIGN;
        if device_public.name_alg != ALG_SHA256 || device_public.attributes & required != required {
            return Err(AttestationError::untrusted(
                "the device key was not generated in the TPM or could leave it",
            ));
        }
        if device_public.p256_spki().as_deref() != Some(device_key) {
            return Err(AttestationError::invalid(
                "the TPM key is not this device's key",
            ));
        }

        let leaf = x509::parse(&certificates[0])?;
        let certified = match leaf.public_key().parsed() {
            Ok(PublicKey::RSA(key)) => strip_zeros(key.modulus),
            _ => {
                return Err(AttestationError::invalid(
                    "the endorsement key certificate is not for an RSA key",
                ))
            }
        };
        if certified != strip_zeros(modulus) {
            return Err(AttestationError::invalid(
                "the endorsement key certificate is for another key",
            ));
        }
        let extra = certificates[1..]
            .iter()
            .map(|der| x509::parse(der))
            .collect::<Result<Vec<_>, _>>()?;
        let known = self
            .intermediates
            .iter()
            .filter_map(|der| x509::parse(der).ok())
            .collect::<Vec<_>>();
        let chain = self.build_chain(leaf, &extra, &known);
        x509::verify_chain(&chain, &self.anchors, now)?;
        let vendor = manufacturer(&chain[0]);
        let ek_spki = chain[0].public_key().raw.to_vec();

        let mut secret = Zeroizing::new(vec![0_u8; 32]);
        random(&mut secret)?;
        let (credential_blob, encrypted_secret) =
            make_credential(&ek_spki, &tpm::name(&device_area), &secret)?;
        let mut id = [0_u8; 16];
        random(&mut id)?;
        let id = URL_SAFE_NO_PAD.encode(id);
        {
            let mut pending = self.pending.lock();
            pending.retain(|_, entry| entry.created.elapsed() < CHALLENGE_LIFETIME);
            if pending.len() >= MAX_PENDING {
                return Err(AttestationError::untrusted(
                    "too many TPM verifications are in progress; try again shortly",
                ));
            }
            pending.insert(
                id.clone(),
                Pending {
                    account: account.to_owned(),
                    device: device.to_owned(),
                    secret,
                    vendor,
                    created: Instant::now(),
                },
            );
        }
        Ok(TpmChallenge {
            challenge: id,
            credential_blob: URL_SAFE_NO_PAD.encode(credential_blob),
            encrypted_secret: URL_SAFE_NO_PAD.encode(encrypted_secret),
        })
    }

    /// Checks the secret the device recovered for `challenge`.
    pub fn answer(
        &self,
        account: &str,
        device: &str,
        challenge: &str,
        secret: &str,
    ) -> Result<AttestationResult, AttestationError> {
        let pending = self
            .pending
            .lock()
            .remove(challenge)
            .filter(|entry| entry.created.elapsed() < CHALLENGE_LIFETIME)
            .ok_or_else(|| {
                AttestationError::invalid("the TPM challenge expired or was already answered")
            })?;
        let secret = URL_SAFE_NO_PAD
            .decode(secret)
            .map_err(|_| AttestationError::invalid("the TPM answer is not base64url"))?;
        if pending.account != account
            || pending.device != device
            || !bool::from(secret.ct_eq(&pending.secret))
        {
            return Err(AttestationError::untrusted(
                "the TPM could not prove that it holds the device key",
            ));
        }
        Ok(AttestationResult {
            platform: "tpm".to_owned(),
            level: "tpm".to_owned(),
            vendor: pending.vendor,
        })
    }

    fn build_chain<'a>(
        &self,
        leaf: X509Certificate<'a>,
        extra: &[X509Certificate<'a>],
        known: &[X509Certificate<'a>],
    ) -> Vec<X509Certificate<'a>> {
        let mut chain = vec![leaf];
        while chain.len() < MAX_CHAIN {
            let current = chain.last().expect("the chain starts with the leaf");
            let anchored = self.anchors.iter().any(|anchor| {
                x509_parser::x509::SubjectPublicKeyInfo::from_der(anchor)
                    .is_ok_and(|(_, key)| x509::signed_by(current, &key))
            });
            if anchored {
                break;
            }
            let Some(issuer) = extra
                .iter()
                .chain(known)
                .find(|candidate| {
                    // Names may differ in encoding; the signature decides.
                    candidate.subject().to_string() == current.issuer().to_string()
                        && x509::signed_by(current, candidate.public_key())
                })
                .cloned()
            else {
                break;
            };
            chain.push(issuer);
        }
        chain
    }
}

use x509_parser::prelude::FromDer as _;

/// The modulus of an RSA 2048 endorsement key that MakeCredential can use.
fn endorsement_modulus(public: &Public) -> Result<&[u8], AttestationError> {
    let required = attributes::FIXED_TPM
        | attributes::FIXED_PARENT
        | attributes::SENSITIVE_DATA_ORIGIN
        | attributes::RESTRICTED
        | attributes::DECRYPT;
    let (
        Parameters::Rsa {
            symmetric,
            key_bits: 2048,
            ..
        },
        Unique::Rsa(modulus),
    ) = (&public.parameters, &public.unique)
    else {
        return Err(AttestationError::invalid(
            "the endorsement key is not an RSA 2048 key",
        ));
    };
    if public.kind != ALG_RSA
        || public.name_alg != ALG_SHA256
        || public.attributes & required != required
        || *symmetric != Symmetric::AES_128_CFB
        || modulus.len() != 256
    {
        return Err(AttestationError::invalid(
            "the endorsement key is not a TCG endorsement key",
        ));
    }
    Ok(modulus)
}

fn strip_zeros(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len());
    &value[start..]
}

fn random(output: &mut [u8]) -> Result<(), AttestationError> {
    aws_lc_rs::rand::SystemRandom::new()
        .fill(output)
        .map_err(|_| AttestationError::invalid("the gateway could not create a challenge"))
}

/// The TPM manufacturer an EK certificate names, such as `IFX` or `INTC`.
fn manufacturer(certificate: &X509Certificate<'_>) -> String {
    let Ok(Some(names)) = certificate.subject_alternative_name() else {
        return String::new();
    };
    for name in &names.value.general_names {
        let GeneralName::DirectoryName(directory) = name else {
            continue;
        };
        for attribute in directory.iter_attributes() {
            if attribute.attr_type().to_id_string() != TPM_MANUFACTURER {
                continue;
            }
            let Ok(value) = attribute.as_str() else {
                continue;
            };
            let id = value.strip_prefix("id:").unwrap_or(value);
            return match hex::decode(id) {
                Ok(bytes)
                    if bytes
                        .iter()
                        .all(|byte| byte.is_ascii_alphanumeric() || *byte == 0) =>
                {
                    match String::from_utf8_lossy(&bytes).trim_end_matches('\0') {
                        "IFX" => "Infineon".to_owned(),
                        "STM" => "STMicroelectronics".to_owned(),
                        "NTC" => "Nuvoton".to_owned(),
                        "INTC" => "Intel".to_owned(),
                        "AMD" => "AMD".to_owned(),
                        "MSFT" => "Microsoft".to_owned(),
                        "NTZ" => "Nationz".to_owned(),
                        "ATML" => "Atmel".to_owned(),
                        "QCOM" => "Qualcomm".to_owned(),
                        other if !other.is_empty() => other.to_owned(),
                        _ => format!("id:{id}"),
                    }
                }
                _ => format!("id:{id}"),
            };
        }
    }
    String::new()
}

/// TPM2_MakeCredential (TPM 2.0 Part 1, 24.6) for an RSA endorsement key
/// with a SHA-256 name algorithm and AES-128-CFB symmetric definition.
/// Returns the `TPM2B_ID_OBJECT` and `TPM2B_ENCRYPTED_SECRET`.
fn make_credential(
    endorsement_spki: &[u8],
    object_name: &[u8],
    credential: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), AttestationError> {
    let failed = || AttestationError::invalid("the gateway could not encrypt the challenge");
    let mut seed = Zeroizing::new(vec![0_u8; 32]);
    random(&mut seed)?;
    let key = PublicEncryptingKey::from_der(endorsement_spki).map_err(|_| failed())?;
    let key = OaepPublicEncryptingKey::new(key).map_err(|_| failed())?;
    let mut encrypted_seed = vec![0_u8; key.ciphertext_size()];
    let encrypted_seed = key
        .encrypt(
            &OAEP_SHA256_MGF1SHA256,
            &seed,
            &mut encrypted_seed,
            Some(b"IDENTITY\0"),
        )
        .map_err(|_| failed())?
        .to_vec();

    let symmetric_key = kdfa(&seed, b"STORAGE", object_name, &[], 128);
    let mut identity = (credential.len() as u16).to_be_bytes().to_vec();
    identity.extend(credential);
    let cipher = EncryptingKey::cfb128(
        UnboundCipherKey::new(&AES_128, &symmetric_key).map_err(|_| failed())?,
    )
    .map_err(|_| failed())?;
    cipher
        .less_safe_encrypt(
            &mut identity,
            EncryptionContext::Iv128(FixedLength::from([0_u8; 16])),
        )
        .map_err(|_| failed())?;

    let integrity_key = kdfa(&seed, b"INTEGRITY", &[], &[], 256);
    let mut message = identity.clone();
    message.extend(object_name);
    let outer = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &integrity_key), &message);
    let mut id_object = (outer.as_ref().len() as u16).to_be_bytes().to_vec();
    id_object.extend(outer.as_ref());
    id_object.extend(&identity);

    let mut credential_blob = (id_object.len() as u16).to_be_bytes().to_vec();
    credential_blob.extend(id_object);
    let mut encrypted_secret = (encrypted_seed.len() as u16).to_be_bytes().to_vec();
    encrypted_secret.extend(encrypted_seed);
    Ok((credential_blob, encrypted_secret))
}

/// KDFa with HMAC-SHA256 (TPM 2.0 Part 1, 11.4.10.2).
fn kdfa(key: &[u8], label: &[u8], context_u: &[u8], context_v: &[u8], bits: u32) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let length = bits.div_ceil(8) as usize;
    let mut output = Vec::with_capacity(length + 32);
    let mut counter = 1_u32;
    while output.len() < length {
        let mut block = counter.to_be_bytes().to_vec();
        block.extend(label);
        block.push(0);
        block.extend(context_u);
        block.extend(context_v);
        block.extend(bits.to_be_bytes());
        output.extend(hmac::sign(&key, &block).as_ref());
        counter += 1;
    }
    output.truncate(length);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdfa_matches_its_definition() {
        // One block: HMAC(key, 1 || "STORAGE\0" || context || 128).
        let key = [7_u8; 32];
        let derived = kdfa(&key, b"STORAGE", b"name", &[], 128);
        let mut block = 1_u32.to_be_bytes().to_vec();
        block.extend(b"STORAGE\0name");
        block.extend(128_u32.to_be_bytes());
        let expected = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &key), &block);
        assert_eq!(derived, &expected.as_ref()[..16]);
        assert_eq!(kdfa(&key, b"INTEGRITY", &[], &[], 512).len(), 64);
    }

    /// Loads Microsoft's TPM vendor list as `porta-tpm-cas` installs it, when
    /// `PORTA_TPM_VENDOR_CAS` names that directory.
    #[test]
    fn the_tpm_vendor_list_loads_with_its_roots() {
        let Some(directory) = std::env::var_os("PORTA_TPM_VENDOR_CAS") else {
            return;
        };
        let verifier = TpmVerifier::from_directory(Path::new(&directory)).unwrap();
        assert!(
            verifier.root_count() >= 20,
            "{} roots",
            verifier.root_count()
        );
        assert!(verifier.intermediates.len() >= 100);
    }

    /// The full exchange against a TPM simulator. Run it with a provisioned
    /// swtpm: `PORTA_TPM_TCP=127.0.0.1:2321 PORTA_TPM_CA=/path/to/localca
    /// cargo test -p porta-server-rust tpm -- --ignored`.
    #[tokio::test]
    #[ignore = "needs a TPM simulator; see scripts/test-tpm-attestation.sh"]
    async fn a_simulated_tpm_proves_its_device_key() {
        use porta_client::tpm::{Tpm, TpmError};
        let ca = std::env::var("PORTA_TPM_CA").expect("PORTA_TPM_CA names the CA directory");
        let verifier = TpmVerifier::from_directory(Path::new(&ca)).unwrap();
        assert!(verifier.root_count() >= 1);

        let tpm = Tpm::open().unwrap();
        let key = std::sync::Arc::new(tpm.create_device_key().unwrap());
        // Proofs signed in the TPM verify with the device key.
        let digest = [9_u8; 32];
        let signature = key.sign(&digest).unwrap();
        {
            use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
            use p256::pkcs8::DecodePublicKey as _;
            let verifying = p256::ecdsa::VerifyingKey::from_public_key_der(key.spki()).unwrap();
            let signature = p256::ecdsa::Signature::from_der(&signature).unwrap();
            verifying.verify_prehash(&digest, &signature).unwrap();
        }
        // The saved key reloads.
        let reloaded = porta_client::tpm::DeviceKey::from_parts(
            tpm.clone(),
            key.parent(),
            key.private_blob().to_vec(),
            key.public_area().to_vec(),
        )
        .unwrap();
        reloaded.sign(&digest).unwrap();

        let endorsement = tpm.endorsement().unwrap();
        let request = TpmChallengeRequest {
            endorsement_key: URL_SAFE_NO_PAD.encode(&endorsement.public),
            endorsement_certificates: vec![URL_SAFE_NO_PAD.encode(&endorsement.certificate)],
            device_key: URL_SAFE_NO_PAD.encode(key.public_area()),
        };
        let now = OffsetDateTime::now_utc();
        let decode = |value: &str| URL_SAFE_NO_PAD.decode(value).unwrap();
        let challenge = verifier
            .challenge("account", "device", key.spki(), &request, now)
            .unwrap();
        let secret = key
            .activate_credential(
                &decode(&challenge.credential_blob),
                &decode(&challenge.encrypted_secret),
            )
            .unwrap();
        let result = verifier
            .answer(
                "account",
                "device",
                &challenge.challenge,
                &URL_SAFE_NO_PAD.encode(&secret),
            )
            .unwrap();
        assert_eq!(
            (result.platform.as_str(), result.level.as_str()),
            ("tpm", "tpm")
        );
        // A challenge is answered once, by the device it was issued to.
        assert!(verifier
            .answer(
                "account",
                "device",
                &challenge.challenge,
                &URL_SAFE_NO_PAD.encode(&secret)
            )
            .is_err());
        let challenge = verifier
            .challenge("account", "device", key.spki(), &request, now)
            .unwrap();
        assert!(verifier
            .answer(
                "account",
                "other",
                &challenge.challenge,
                &URL_SAFE_NO_PAD.encode(&secret)
            )
            .is_err());

        // Another key, even in the same TPM, cannot answer for this one.
        let other = tpm.create_device_key().unwrap();
        let challenge = verifier
            .challenge("account", "device", key.spki(), &request, now)
            .unwrap();
        assert!(matches!(
            other.activate_credential(
                &decode(&challenge.credential_blob),
                &decode(&challenge.encrypted_secret),
            ),
            Err(TpmError::Code(_))
        ));
        // The evidence must name this device's key, and a trusted vendor.
        assert!(verifier
            .challenge("account", "device", other.spki(), &request, now)
            .is_err());
        let strangers = TpmVerifier::from_certificates(Vec::new());
        assert!(strangers
            .challenge("account", "device", key.spki(), &request, now)
            .is_err());
    }
}
