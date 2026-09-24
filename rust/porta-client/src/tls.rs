use std::fmt;
use std::fs;
use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use rustls_platform_verifier::Verifier;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TlsConfigError {
    #[error("--insecure and --thumbprint cannot be used together")]
    InsecureWithThumbprint,
    #[error(
        "thumbprint must be a 64-digit SHA-256 value (separators and a sha256: prefix are optional)"
    )]
    InvalidThumbprint,
    #[error("read CA file: {0}")]
    ReadCa(#[source] std::io::Error),
    #[error("CA file contains no certificates")]
    EmptyCa,
    #[error("parse CA certificate: {0}")]
    ParseCa(#[source] std::io::Error),
    #[error("configure certificate verification: {0}")]
    Configure(#[from] RustlsError),
    #[error("configure certificate roots: {0}")]
    ConfigureRoots(#[from] rustls::client::VerifierBuilderError),
}

pub fn platform_config() -> Result<Arc<ClientConfig>, TlsConfigError> {
    config(None, None, false)
}

pub fn config(
    ca_path: Option<&Path>,
    thumbprint: Option<&str>,
    insecure: bool,
) -> Result<Arc<ClientConfig>, TlsConfigError> {
    let thumbprint = parse_thumbprint(thumbprint.unwrap_or_default())?;
    if insecure && thumbprint.is_some() {
        return Err(TlsConfigError::InsecureWithThumbprint);
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier: Arc<dyn ServerCertVerifier> = if insecure {
        Arc::new(CertificateVerifier::new(provider.clone(), None, None))
    } else {
        let platform: Arc<dyn ServerCertVerifier> = platform_verifier(ca_path, provider.clone())?;
        if let Some(thumbprint) = thumbprint {
            Arc::new(CertificateVerifier::new(
                provider.clone(),
                Some(platform),
                Some(thumbprint),
            ))
        } else {
            platform
        }
    };
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

fn platform_verifier(
    ca_path: Option<&Path>,
    provider: Arc<CryptoProvider>,
) -> Result<Arc<dyn ServerCertVerifier>, TlsConfigError> {
    let Some(path) = ca_path else {
        return Ok(Arc::new(Verifier::new(provider)?));
    };
    let data = fs::read(path).map_err(TlsConfigError::ReadCa)?;
    let certificates = rustls_pemfile::certs(&mut Cursor::new(data))
        .collect::<Result<Vec<_>, _>>()
        .map_err(TlsConfigError::ParseCa)?;
    if certificates.is_empty() {
        return Err(TlsConfigError::EmptyCa);
    }
    platform_verifier_with_extra_roots(certificates, provider)
}

#[cfg(not(target_os = "android"))]
fn platform_verifier_with_extra_roots(
    certificates: Vec<CertificateDer<'static>>,
    provider: Arc<CryptoProvider>,
) -> Result<Arc<dyn ServerCertVerifier>, TlsConfigError> {
    Ok(Arc::new(Verifier::new_with_extra_roots(
        certificates,
        provider,
    )?))
}

#[cfg(target_os = "android")]
fn platform_verifier_with_extra_roots(
    certificates: Vec<CertificateDer<'static>>,
    provider: Arc<CryptoProvider>,
) -> Result<Arc<dyn ServerCertVerifier>, TlsConfigError> {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate)?;
    }
    Ok(
        rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()?,
    )
}

pub fn parse_thumbprint(value: &str) -> Result<Option<[u8; 32]>, TlsConfigError> {
    if value.is_empty() {
        return Ok(None);
    }
    let mut normalized = value.trim();
    if normalized
        .get(.."sha256:".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("sha256:"))
    {
        normalized = &normalized["sha256:".len()..];
    }
    let normalized = normalized.replace([':', '-'], "");
    let mut thumbprint = [0_u8; 32];
    if normalized.len() != thumbprint.len() * 2
        || hex::decode_to_slice(normalized, &mut thumbprint).is_err()
    {
        return Err(TlsConfigError::InvalidThumbprint);
    }
    Ok(Some(thumbprint))
}

struct CertificateVerifier {
    provider: Arc<CryptoProvider>,
    inner: Option<Arc<dyn ServerCertVerifier>>,
    thumbprint: Option<[u8; 32]>,
}

impl CertificateVerifier {
    fn new(
        provider: Arc<CryptoProvider>,
        inner: Option<Arc<dyn ServerCertVerifier>>,
        thumbprint: Option<[u8; 32]>,
    ) -> Self {
        Self {
            provider,
            inner,
            thumbprint,
        }
    }
}

impl fmt::Debug for CertificateVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertificateVerifier")
            .field("platform_verification", &self.inner.is_some())
            .field("thumbprint", &self.thumbprint.is_some())
            .finish()
    }
}

impl ServerCertVerifier for CertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if let Some(inner) = &self.inner {
            inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;
        }
        if let Some(expected) = self.thumbprint {
            let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
            if !bool::from(actual.ct_eq(&expected)) {
                return Err(RustlsError::General(format!(
                    "gateway certificate SHA-256 thumbprint mismatch: got {}",
                    hex::encode(actual)
                )));
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        if let Some(inner) = &self.inner {
            inner.verify_tls12_signature(message, certificate, signature)
        } else {
            rustls::crypto::verify_tls12_signature(
                message,
                certificate,
                signature,
                &self.provider.signature_verification_algorithms,
            )
        }
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        if let Some(inner) = &self.inner {
            inner.verify_tls13_signature(message, certificate, signature)
        } else {
            rustls::crypto::verify_tls13_signature(
                message,
                certificate,
                signature,
                &self.provider.signature_verification_algorithms,
            )
        }
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.as_ref().map_or_else(
            || {
                self.provider
                    .signature_verification_algorithms
                    .supported_schemes()
            },
            |inner| inner.supported_verify_schemes(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_compatible_thumbprint_forms() {
        let expected = [0xab; 32];
        let plain = "ab".repeat(32);
        assert_eq!(parse_thumbprint(&plain).unwrap(), Some(expected));
        let separated = plain
            .as_bytes()
            .chunks(2)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(
            parse_thumbprint(&format!("SHA256:{separated}")).unwrap(),
            Some(expected)
        );
        assert!(parse_thumbprint("bad").is_err());
        assert_eq!(parse_thumbprint("").unwrap(), None);
    }
}
