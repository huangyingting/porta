//! Certificate chain checks shared by the Android and TPM verifiers. The
//! chains are not TLS chains (no names, no extended key usage), so they are
//! verified directly: each certificate's signature against the next one's
//! key, ending at a configured trust anchor.

use aws_lc_rs::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use time::OffsetDateTime;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer as _;
use x509_parser::x509::SubjectPublicKeyInfo;

use super::AttestationError;

pub fn parse(der: &[u8]) -> Result<X509Certificate<'_>, AttestationError> {
    match X509Certificate::from_der(der) {
        Ok(([], certificate)) => Ok(certificate),
        _ => Err(AttestationError::invalid("a certificate is not valid DER")),
    }
}

/// Whether `certificate` carries a valid signature by `issuer`.
pub fn signed_by(certificate: &X509Certificate<'_>, issuer: &SubjectPublicKeyInfo<'_>) -> bool {
    let Some(algorithm) = algorithm(
        &certificate.signature_algorithm.algorithm.to_id_string(),
        issuer,
    ) else {
        return false;
    };
    UnparsedPublicKey::new(algorithm, issuer.subject_public_key.data.as_ref())
        .verify(
            certificate.tbs_certificate.as_ref(),
            certificate.signature_value.data.as_ref(),
        )
        .is_ok()
}

fn algorithm(
    signature: &str,
    issuer: &SubjectPublicKeyInfo<'_>,
) -> Option<&'static dyn VerificationAlgorithm> {
    let curve = issuer
        .algorithm
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.as_oid().ok())
        .map(|oid| oid.to_id_string());
    let key = issuer.algorithm.algorithm.to_id_string();
    Some(match (key.as_str(), curve.as_deref(), signature) {
        ("1.2.840.10045.2.1", Some("1.2.840.10045.3.1.7"), "1.2.840.10045.4.3.2") => {
            &signature::ECDSA_P256_SHA256_ASN1
        }
        ("1.2.840.10045.2.1", Some("1.2.840.10045.3.1.7"), "1.2.840.10045.4.3.3") => {
            &signature::ECDSA_P256_SHA384_ASN1
        }
        ("1.2.840.10045.2.1", Some("1.3.132.0.34"), "1.2.840.10045.4.3.2") => {
            &signature::ECDSA_P384_SHA256_ASN1
        }
        ("1.2.840.10045.2.1", Some("1.3.132.0.34"), "1.2.840.10045.4.3.3") => {
            &signature::ECDSA_P384_SHA384_ASN1
        }
        ("1.2.840.113549.1.1.1", _, "1.2.840.113549.1.1.11") => {
            &signature::RSA_PKCS1_2048_8192_SHA256
        }
        ("1.2.840.113549.1.1.1", _, "1.2.840.113549.1.1.12") => {
            &signature::RSA_PKCS1_2048_8192_SHA384
        }
        ("1.2.840.113549.1.1.1", _, "1.2.840.113549.1.1.13") => {
            &signature::RSA_PKCS1_2048_8192_SHA512
        }
        _ => return None,
    })
}

pub fn valid_at(certificate: &X509Certificate<'_>, now: OffsetDateTime) -> bool {
    let validity = certificate.validity();
    validity.not_before.to_datetime() <= now && now <= validity.not_after.to_datetime()
}

/// The serial number as lowercase hex without leading zeros, as Google's
/// attestation status list writes it.
pub fn serial_hex(certificate: &X509Certificate<'_>) -> String {
    let encoded = hex::encode(certificate.raw_serial());
    let trimmed = encoded.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// Whether a certificate may sign others: a CA in basic constraints.
pub fn is_ca(certificate: &X509Certificate<'_>) -> bool {
    matches!(certificate.basic_constraints(), Ok(Some(constraints)) if constraints.value.ca)
}

/// Checks that `chain` (leaf first) links up to one of `anchors`, given as
/// DER `SubjectPublicKeyInfo`, and that every certificate after the leaf
/// is a valid CA at `now`. The chain may end with the anchor's own
/// certificate, whose dates are not checked: the key is what is trusted.
pub fn verify_chain(
    chain: &[X509Certificate<'_>],
    anchors: &[Vec<u8>],
    now: OffsetDateTime,
) -> Result<(), AttestationError> {
    let Some(last) = chain.last() else {
        return Err(AttestationError::invalid("the certificate chain is empty"));
    };
    for pair in chain.windows(2) {
        // The signature binds each link; names may differ in encoding.
        let (certificate, issuer) = (&pair[0], &pair[1]);
        if !signed_by(certificate, issuer.public_key()) {
            return Err(AttestationError::invalid(
                "a certificate is not signed by the next one in the chain",
            ));
        }
    }
    let anchored_by_last = anchors
        .iter()
        .any(|anchor| anchor.as_slice() == last.public_key().raw);
    let issuers = if anchored_by_last {
        &chain[1..chain.len() - 1]
    } else {
        let anchor_signed = anchors.iter().any(|anchor| {
            SubjectPublicKeyInfo::from_der(anchor)
                .ok()
                .is_some_and(|(_, key)| signed_by(last, &key))
        });
        if !anchor_signed {
            return Err(AttestationError::untrusted(
                "the certificate chain does not end at a trusted root",
            ));
        }
        &chain[1..]
    };
    for issuer in issuers {
        if !is_ca(issuer) {
            return Err(AttestationError::invalid(
                "an issuing certificate is not a certificate authority",
            ));
        }
        if !valid_at(issuer, now) {
            return Err(AttestationError::invalid(
                "an issuing certificate is expired or not yet valid",
            ));
        }
    }
    Ok(())
}

/// The DER `SubjectPublicKeyInfo` of each PEM certificate in `pem`.
pub fn anchors_from_pem(pem: &str) -> Vec<Vec<u8>> {
    x509_parser::pem::Pem::iter_from_buffer(pem.as_bytes())
        .filter_map(Result::ok)
        .filter_map(|pem| {
            parse(&pem.contents)
                .ok()
                .map(|certificate| certificate.public_key().raw.to_vec())
        })
        .collect()
}
