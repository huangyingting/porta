use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use rand::Rng as _;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair,
    KeyUsagePurpose, SerialNumber, PKCS_ED25519,
};
use thiserror::Error;
use time::OffsetDateTime;

const DEFAULT_VALIDITY: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const COMMON_NAME: &str = "Porta development gateway";

#[derive(Debug, Error)]
pub enum GenerateError {
    #[error("distinct certificate and key paths are required")]
    InvalidPaths,
    #[error("at least one DNS name or IP address is required")]
    MissingHosts,
    #[error("host list contained no usable names")]
    EmptyHosts,
    #[error("certificate validity is outside the supported time range")]
    InvalidValidity,
    #[error("generate private key: {0}")]
    GenerateKey(#[source] rcgen::Error),
    #[error("configure certificate: {0}")]
    Configure(#[source] rcgen::Error),
    #[error("create certificate: {0}")]
    CreateCertificate(#[source] rcgen::Error),
    #[error("create {path}: {source}")]
    Create {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("write {path}: {source}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("close {path}: {source}")]
    Close {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

pub struct Options {
    pub hosts: Vec<String>,
    pub valid_for: Duration,
}

pub fn generate(
    certificate_path: &Path,
    key_path: &Path,
    mut options: Options,
) -> Result<(), GenerateError> {
    if certificate_path.as_os_str().is_empty()
        || key_path.as_os_str().is_empty()
        || certificate_path == key_path
    {
        return Err(GenerateError::InvalidPaths);
    }
    if options.hosts.is_empty() {
        return Err(GenerateError::MissingHosts);
    }
    options.hosts = options
        .hosts
        .into_iter()
        .map(|host| host.trim().to_owned())
        .filter(|host| !host.is_empty())
        .collect();
    if options.hosts.is_empty() {
        return Err(GenerateError::EmptyHosts);
    }
    if options.valid_for.is_zero() {
        options.valid_for = DEFAULT_VALIDITY;
    }

    let now = OffsetDateTime::now_utc();
    let valid_for =
        time::Duration::try_from(options.valid_for).map_err(|_| GenerateError::InvalidValidity)?;
    let not_before = now
        .checked_sub(time::Duration::minutes(5))
        .ok_or(GenerateError::InvalidValidity)?;
    let not_after = now
        .checked_add(valid_for)
        .ok_or(GenerateError::InvalidValidity)?;

    let mut params = CertificateParams::new(options.hosts).map_err(GenerateError::Configure)?;
    params.not_before = not_before;
    params.not_after = not_after;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, COMMON_NAME);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let mut serial = [0_u8; 16];
    rand::rng().fill(&mut serial);
    serial[0] &= 0x7f;
    params.serial_number = Some(SerialNumber::from_slice(&serial));

    let key = KeyPair::generate_for(&PKCS_ED25519).map_err(GenerateError::GenerateKey)?;
    let certificate = params
        .self_signed(&key)
        .map_err(GenerateError::CreateCertificate)?;
    let certificate_pem = certificate.pem();
    let key_pem = key.serialize_pem();

    write_exclusive(certificate_path, 0o644, certificate_pem.as_bytes())?;
    if let Err(error) = write_exclusive(key_path, 0o600, key_pem.as_bytes()) {
        let _ = fs::remove_file(certificate_path);
        return Err(error);
    }
    Ok(())
}

fn write_exclusive(path: &Path, mode: u32, contents: &[u8]) -> Result<(), GenerateError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options.open(path).map_err(|source| GenerateError::Create {
        path: path.display().to_string(),
        source,
    })?;
    if let Err(source) = file.write_all(contents) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(GenerateError::Write {
            path: path.display().to_string(),
            source,
        });
    }
    close(file, path)
}

fn close(file: File, path: &Path) -> Result<(), GenerateError> {
    if let Err(source) = file.sync_all() {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(GenerateError::Close {
            path: path.display().to_string(),
            source,
        });
    }
    drop(file);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_self_signed_ed25519_certificate_and_private_key() {
        let directory = tempfile::tempdir().unwrap();
        let certificate_path = directory.path().join("server.crt");
        let key_path = directory.path().join("server.key");
        generate(
            &certificate_path,
            &key_path,
            Options {
                hosts: vec!["localhost".to_owned(), "127.0.0.1".to_owned()],
                valid_for: Duration::from_secs(3600),
            },
        )
        .unwrap();

        let certificate_pem = fs::read(&certificate_path).unwrap();
        let (_, pem) = x509_parser::pem::parse_x509_pem(&certificate_pem).unwrap();
        let certificate = pem.parse_x509().unwrap();
        assert_eq!(
            certificate
                .subject()
                .iter_common_name()
                .next()
                .unwrap()
                .as_str(),
            Ok(COMMON_NAME)
        );
        let alternatives = &certificate
            .subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names;
        assert!(alternatives.iter().any(|name| matches!(
            name,
            x509_parser::extensions::GeneralName::DNSName("localhost")
        )));
        assert!(alternatives.iter().any(|name| matches!(
            name,
            x509_parser::extensions::GeneralName::IPAddress(address)
                if *address == [127, 0, 0, 1]
        )));
        certificate.verify_signature(None).unwrap();

        let key = fs::read_to_string(&key_path).unwrap();
        assert!(key.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(key_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn never_clobbers_existing_outputs_or_leaves_an_orphaned_certificate() {
        for existing in ["server.crt", "server.key"] {
            let directory = tempfile::tempdir().unwrap();
            let certificate_path = directory.path().join("server.crt");
            let key_path = directory.path().join("server.key");
            fs::write(directory.path().join(existing), b"original").unwrap();
            assert!(generate(
                &certificate_path,
                &key_path,
                Options {
                    hosts: vec!["localhost".to_owned()],
                    valid_for: Duration::from_secs(3600),
                },
            )
            .is_err());
            assert_eq!(
                fs::read(directory.path().join(existing)).unwrap(),
                b"original"
            );
            if existing == "server.key" {
                assert!(!certificate_path.exists());
            }
        }
    }
}
