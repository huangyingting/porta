//! Verifies Android Keystore key attestation: a certificate chain from the
//! device key up to Google's attestation roots, whose leaf describes the key
//! in an extension. A key counts as hardware-backed when both the
//! attestation and the key live in the TEE or StrongBox, the key was
//! generated there (not imported), and it belongs to the Porta app.

use std::collections::HashSet;
use std::sync::Arc;

use parking_lot::RwLock;
use time::OffsetDateTime;

use super::der::{self, Tlv, CONTEXT, OCTET_STRING, SEQUENCE, SET, UNIVERSAL};
use super::x509;
use super::AttestationError;
use porta_wire::attestation::AttestationResult;

/// Google's hardware attestation roots, as published at
/// <https://android.googleapis.com/attestation/root>.
const GOOGLE_ROOTS: &str = include_str!("../../assets/android-attestation-roots.pem");
/// The Android Keystore key description extension.
const KEY_DESCRIPTION: &str = "1.3.6.1.4.1.11129.2.1.17";
/// Google's list of revoked attestation certificates.
pub const STATUS_URL: &str = "https://android.googleapis.com/attestation/status";
/// The Porta Android app.
pub const PACKAGE: &str = "dev.porta.android";

const TRUSTED_ENVIRONMENT: u64 = 1;
const STRONGBOX: u64 = 2;
const TAG_ORIGIN: u32 = 702;
const TAG_APPLICATION_ID: u32 = 709;
const TAG_BRAND: u32 = 710;
const ORIGIN_GENERATED: u64 = 0;

pub struct AndroidVerifier {
    anchors: Vec<Vec<u8>>,
    packages: Vec<String>,
    challenge: Vec<u8>,
    /// Serial numbers (lowercase hex) of revoked attestation certificates.
    revoked: Arc<RwLock<HashSet<String>>>,
}

impl AndroidVerifier {
    pub fn new() -> Self {
        Self::with_policy(
            x509::anchors_from_pem(GOOGLE_ROOTS),
            vec![PACKAGE.to_owned()],
            porta_wire::attestation::ANDROID_ATTESTATION_CHALLENGE.to_vec(),
        )
    }

    pub fn with_policy(anchors: Vec<Vec<u8>>, packages: Vec<String>, challenge: Vec<u8>) -> Self {
        Self {
            anchors,
            packages,
            challenge,
            revoked: Arc::default(),
        }
    }

    pub fn set_revoked(&self, revoked: HashSet<String>) {
        *self.revoked.write() = revoked;
    }

    /// Replaces the revocation list with Google's current one. The previous
    /// list stays in use when the fetch fails.
    pub async fn refresh_revocations(&self, http: &reqwest::Client) -> Result<usize, String> {
        #[derive(serde::Deserialize)]
        struct Status {
            entries: std::collections::HashMap<String, serde_json::Value>,
        }
        let response = http
            .get(STATUS_URL)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|error| error.to_string())?;
        let body = response.bytes().await.map_err(|error| error.to_string())?;
        if body.len() > 16 << 20 {
            return Err("the attestation status list is too large".to_owned());
        }
        let status: Status = serde_json::from_slice(&body).map_err(|error| error.to_string())?;
        let revoked = status
            .entries
            .into_keys()
            .map(|serial| serial.trim_start_matches('0').to_ascii_lowercase())
            .collect::<HashSet<_>>();
        let count = revoked.len();
        self.set_revoked(revoked);
        Ok(count)
    }

    /// Verifies `chain` (DER, leaf first) for the device key `device_key`
    /// (DER `SubjectPublicKeyInfo`).
    pub fn verify(
        &self,
        chain: &[Vec<u8>],
        device_key: &[u8],
        now: OffsetDateTime,
    ) -> Result<AttestationResult, AttestationError> {
        if chain.len() < 2 {
            return Err(AttestationError::invalid(
                "the key has no attestation certificate chain",
            ));
        }
        let certificates = chain
            .iter()
            .map(|der| x509::parse(der))
            .collect::<Result<Vec<_>, _>>()?;
        let leaf = &certificates[0];
        if leaf.public_key().raw != device_key {
            return Err(AttestationError::invalid(
                "the attestation certificate is for another key",
            ));
        }
        x509::verify_chain(&certificates, &self.anchors, now)?;
        {
            let revoked = self.revoked.read();
            if certificates
                .iter()
                .any(|certificate| revoked.contains(&x509::serial_hex(certificate)))
            {
                return Err(AttestationError::untrusted(
                    "an attestation certificate has been revoked",
                ));
            }
        }
        let extension = leaf
            .extensions()
            .iter()
            .find(|extension| extension.oid.to_id_string() == KEY_DESCRIPTION)
            .ok_or_else(|| {
                AttestationError::invalid("the leaf certificate has no key description")
            })?;
        let description = KeyDescription::parse(extension.value)
            .ok_or_else(|| AttestationError::invalid("the key description is malformed"))?;
        if description.attestation_level != description.key_level
            || !matches!(description.key_level, TRUSTED_ENVIRONMENT | STRONGBOX)
        {
            return Err(AttestationError::untrusted(
                "the key is not protected by the device's secure hardware",
            ));
        }
        if description.challenge != self.challenge {
            return Err(AttestationError::invalid(
                "the attestation challenge is not Porta's",
            ));
        }
        if description.origin != Some(ORIGIN_GENERATED) {
            return Err(AttestationError::untrusted(
                "the key was not generated in secure hardware",
            ));
        }
        if !self.packages.is_empty()
            && !description
                .packages
                .iter()
                .any(|package| self.packages.contains(package))
        {
            return Err(AttestationError::untrusted(
                "the key does not belong to the Porta app",
            ));
        }
        Ok(AttestationResult {
            platform: "android".to_owned(),
            level: if description.key_level == STRONGBOX {
                "strongbox"
            } else {
                "tee"
            }
            .to_owned(),
            vendor: description.brand.unwrap_or_default(),
        })
    }
}

impl Default for AndroidVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default)]
struct KeyDescription {
    attestation_level: u64,
    key_level: u64,
    challenge: Vec<u8>,
    /// From the hardware-enforced list.
    origin: Option<u64>,
    packages: Vec<String>,
    brand: Option<String>,
}

impl KeyDescription {
    fn parse(extension: &[u8]) -> Option<Self> {
        let (sequence, rest) = der::read(extension)?;
        if !rest.is_empty() || !sequence.is(UNIVERSAL, SEQUENCE) {
            return None;
        }
        let fields = sequence.children()?;
        if fields.len() < 8 || !fields[4].is(UNIVERSAL, OCTET_STRING) {
            return None;
        }
        let software = authorizations(&fields[6])?;
        let hardware = authorizations(&fields[7])?;
        let mut description = Self {
            attestation_level: fields[1].small_unsigned()?,
            key_level: fields[3].small_unsigned()?,
            challenge: fields[4].value.to_vec(),
            ..Self::default()
        };
        for (tag, value) in &hardware {
            match *tag {
                TAG_ORIGIN => description.origin = Some(value.small_unsigned()?),
                TAG_BRAND if value.is(UNIVERSAL, OCTET_STRING) => {
                    description.brand = std::str::from_utf8(value.value)
                        .ok()
                        .map(|brand| brand.chars().take(64).collect());
                }
                _ => {}
            }
        }
        // The application identity is usually software-enforced.
        for (tag, value) in software.iter().chain(&hardware) {
            if *tag == TAG_APPLICATION_ID && value.is(UNIVERSAL, OCTET_STRING) {
                description
                    .packages
                    .extend(application_packages(value.value)?);
            }
        }
        Some(description)
    }
}

/// The `[tag] EXPLICIT value` entries of an AuthorizationList.
fn authorizations<'a>(list: &Tlv<'a>) -> Option<Vec<(u32, Tlv<'a>)>> {
    if !list.is(UNIVERSAL, SEQUENCE) {
        return None;
    }
    list.children()?
        .into_iter()
        .map(|entry| {
            if entry.class != CONTEXT || !entry.constructed {
                return None;
            }
            let (value, rest) = der::read(entry.value)?;
            rest.is_empty().then_some((entry.tag, value))
        })
        .collect()
}

/// Package names in an AttestationApplicationId.
fn application_packages(encoded: &[u8]) -> Option<Vec<String>> {
    let (sequence, _) = der::read(encoded)?;
    let fields = sequence.children()?;
    let infos = fields.first().filter(|infos| infos.is(UNIVERSAL, SET))?;
    infos
        .children()?
        .iter()
        .map(|info| {
            let parts = info.children()?;
            let name = parts
                .first()
                .filter(|name| name.is(UNIVERSAL, OCTET_STRING))?;
            String::from_utf8(name.value.to_vec()).ok()
        })
        .collect()
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::{TAG_APPLICATION_ID, TAG_ORIGIN};
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, IsCa, Issuer, KeyPair,
        PublicKeyData as _, PKCS_ECDSA_P256_SHA256,
    };

    fn tlv(tag: &[u8], content: &[u8]) -> Vec<u8> {
        let mut out = tag.to_vec();
        match content.len() {
            length @ 0..=0x7F => out.push(length as u8),
            length @ 0x80..=0xFF => out.extend([0x81, length as u8]),
            length => out.extend([0x82, (length >> 8) as u8, length as u8]),
        }
        out.extend(content);
        out
    }

    /// `[tag] EXPLICIT` in the high-tag-number form Android uses.
    fn explicit(tag: u32, content: &[u8]) -> Vec<u8> {
        if tag < 31 {
            return tlv(&[0xA0 | tag as u8], content);
        }
        let mut identifier = vec![0xBF];
        let mut groups = vec![(tag & 0x7F) as u8];
        let mut rest = tag >> 7;
        while rest > 0 {
            groups.push(0x80 | (rest & 0x7F) as u8);
            rest >>= 7;
        }
        identifier.extend(groups.iter().rev());
        tlv(&identifier, content)
    }

    pub(crate) struct Key {
        pub level: u8,
        pub origin: u8,
        pub package: &'static str,
        pub challenge: &'static [u8],
    }

    fn key_description(key: &Key) -> Vec<u8> {
        let integer = |value: u8| tlv(&[0x02], &[value]);
        let enumerated = |value: u8| tlv(&[0x0A], &[value]);
        let application = tlv(
            &[0x30],
            &[
                tlv(
                    &[0x31],
                    &tlv(
                        &[0x30],
                        &[tlv(&[0x04], key.package.as_bytes()), integer(1)].concat(),
                    ),
                ),
                tlv(&[0x31], &tlv(&[0x04], &[0xAB; 32])),
            ]
            .concat(),
        );
        let software = tlv(
            &[0x30],
            &explicit(TAG_APPLICATION_ID, &tlv(&[0x04], &application)),
        );
        let hardware = tlv(
            &[0x30],
            &[
                explicit(1, &tlv(&[0x31], &integer(2))),
                explicit(2, &integer(3)),
                explicit(TAG_ORIGIN, &integer(key.origin)),
            ]
            .concat(),
        );
        tlv(
            &[0x30],
            &[
                integer(100),
                enumerated(key.level),
                integer(100),
                enumerated(key.level),
                tlv(&[0x04], key.challenge),
                tlv(&[0x04], &[]),
                software,
                hardware,
            ]
            .concat(),
        )
    }

    /// A root, an intermediate and a certificate for `device` describing
    /// `key`: the chain, the device key and the root key, as DER.
    pub(crate) fn synthetic_for(key: &Key, device: &KeyPair) -> (Vec<Vec<u8>>, Vec<u8>, Vec<u8>) {
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut root = CertificateParams::new(Vec::<String>::new()).unwrap();
        root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let intermediate_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut intermediate = CertificateParams::new(Vec::<String>::new()).unwrap();
        intermediate.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let intermediate_certificate = intermediate
            .signed_by(&intermediate_key, &Issuer::from_params(&root, &root_key))
            .unwrap();
        let mut leaf = CertificateParams::new(Vec::<String>::new()).unwrap();
        leaf.custom_extensions = vec![CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
            key_description(key),
        )];
        let leaf_certificate = leaf
            .signed_by(
                device,
                &Issuer::from_params(&intermediate, &intermediate_key),
            )
            .unwrap();
        (
            vec![
                leaf_certificate.der().to_vec(),
                intermediate_certificate.der().to_vec(),
            ],
            device.subject_public_key_info(),
            root_key.subject_public_key_info(),
        )
    }

    pub(crate) const PORTA_STRONGBOX: Key = Key {
        level: 2,
        origin: 0,
        package: super::PACKAGE,
        challenge: porta_wire::attestation::ANDROID_ATTESTATION_CHALLENGE,
    };
}

#[cfg(test)]
mod tests {
    use super::test_support::{synthetic_for, Key, PORTA_STRONGBOX};
    use super::*;
    use rcgen::{KeyPair, PublicKeyData as _, PKCS_ECDSA_P256_SHA256};

    /// A real production chain: an EC key in a TEE, under Google's RSA root.
    fn real_chain() -> Vec<Vec<u8>> {
        (0..4)
            .map(|index| {
                std::fs::read(format!(
                    "{}/tests/fixtures/android-attestation/ec-tee/cert{index}.der",
                    env!("CARGO_MANIFEST_DIR")
                ))
                .unwrap()
            })
            .collect()
    }

    fn description(chain: &[Vec<u8>]) -> KeyDescription {
        let leaf = x509::parse(&chain[0]).unwrap();
        let extension = leaf
            .extensions()
            .iter()
            .find(|extension| extension.oid.to_id_string() == KEY_DESCRIPTION)
            .unwrap();
        KeyDescription::parse(extension.value).unwrap()
    }

    /// A time when the real chain's intermediates are valid.
    fn when() -> OffsetDateTime {
        time::macros::datetime!(2026-11-24 00:00 UTC)
    }

    fn device_key(chain: &[Vec<u8>]) -> Vec<u8> {
        x509::parse(&chain[0]).unwrap().public_key().raw.to_vec()
    }

    #[test]
    fn a_real_device_chain_verifies_under_googles_roots() {
        let chain = real_chain();
        let parsed = description(&chain);
        assert_eq!(parsed.origin, Some(ORIGIN_GENERATED));
        assert!(!parsed.packages.is_empty());
        let verifier = AndroidVerifier::with_policy(
            x509::anchors_from_pem(GOOGLE_ROOTS),
            parsed.packages.clone(),
            parsed.challenge.clone(),
        );
        let result = verifier
            .verify(&chain, &device_key(&chain), when())
            .unwrap();
        assert_eq!(
            (result.platform.as_str(), result.level.as_str()),
            ("android", "tee")
        );
        // Without its copy of the root, the chain still anchors at the key.
        verifier
            .verify(&chain[..3], &device_key(&chain), when())
            .unwrap();

        // The evidence must describe this key, under Google's roots, now.
        let stranger = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        assert!(verifier
            .verify(&chain, &stranger.subject_public_key_info(), when())
            .is_err());
        let later = time::macros::datetime!(2030-01-01 00:00 UTC);
        assert!(verifier.verify(&chain, &device_key(&chain), later).is_err());
        let shuffled = vec![chain[0].clone(), chain[2].clone(), chain[1].clone()];
        assert!(verifier
            .verify(&shuffled, &device_key(&chain), when())
            .is_err());
        let elsewhere = AndroidVerifier::with_policy(
            vec![stranger.subject_public_key_info()],
            parsed.packages.clone(),
            parsed.challenge.clone(),
        );
        assert!(elsewhere
            .verify(&chain[..3], &device_key(&chain), when())
            .is_err());
        // Porta's own app and challenge are required by default.
        assert!(AndroidVerifier::new()
            .verify(&chain, &device_key(&chain), when())
            .is_err());

        let intermediate = x509::serial_hex(&x509::parse(&chain[1]).unwrap());
        verifier.set_revoked(HashSet::from([intermediate]));
        assert!(verifier
            .verify(&chain, &device_key(&chain), when())
            .is_err());
    }

    fn check(key: &Key) -> Result<AttestationResult, AttestationError> {
        let device = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let (chain, device, root) = synthetic_for(key, &device);
        AndroidVerifier::with_policy(
            vec![root],
            vec![PACKAGE.to_owned()],
            porta_wire::attestation::ANDROID_ATTESTATION_CHALLENGE.to_vec(),
        )
        .verify(&chain, &device, OffsetDateTime::now_utc())
    }

    #[test]
    fn only_generated_hardware_keys_of_the_porta_app_count() {
        let result = check(&PORTA_STRONGBOX).unwrap();
        assert_eq!(result.level, "strongbox");
        assert_eq!(
            check(&Key {
                level: 1,
                ..PORTA_STRONGBOX
            })
            .unwrap()
            .level,
            "tee"
        );
        for (key, why) in [
            (
                Key {
                    level: 0,
                    ..PORTA_STRONGBOX
                },
                "a software key",
            ),
            (
                Key {
                    origin: 2,
                    ..PORTA_STRONGBOX
                },
                "an imported key",
            ),
            (
                Key {
                    package: "com.example.other",
                    ..PORTA_STRONGBOX
                },
                "another app's key",
            ),
            (
                Key {
                    challenge: b"replayed",
                    ..PORTA_STRONGBOX
                },
                "another challenge",
            ),
        ] {
            assert!(check(&key).is_err(), "{why} was accepted");
        }
    }

    #[test]
    fn both_published_google_roots_are_trusted() {
        assert_eq!(x509::anchors_from_pem(GOOGLE_ROOTS).len(), 2);
    }
}
