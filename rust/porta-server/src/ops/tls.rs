use anyhow::{bail, Context, Result};
use arc_swap::ArcSwap;
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::version::TLS13;
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

/// When the certificate the gateway serves expires, for monitoring.
#[derive(Debug, Default)]
pub struct CertificateExpiry {
    /// Unix seconds; zero until a certificate is known.
    not_after: AtomicI64,
    /// The certificate last recorded, to parse each one only once.
    recorded: AtomicUsize,
}

impl CertificateExpiry {
    pub fn not_after(&self) -> Option<i64> {
        Some(self.not_after.load(Ordering::Relaxed)).filter(|seconds| *seconds != 0)
    }

    /// Records the leaf certificate of `key` if it is not the last one seen.
    pub fn record(&self, key: &Arc<CertifiedKey>) {
        let identity = Arc::as_ptr(key) as usize;
        if self.recorded.swap(identity, Ordering::Relaxed) == identity {
            return;
        }
        if let Some(not_after) = key.end_entity_cert().ok().and_then(certificate_not_after) {
            self.not_after.store(not_after, Ordering::Relaxed);
        }
    }

    /// Reports expiry through `metrics` on every scrape.
    pub fn export(self: &Arc<Self>, metrics: &crate::ops::metrics::Metrics) {
        let expiry = self.clone();
        metrics.register(Box::new(move |output| {
            if let Some(not_after) = expiry.not_after() {
                crate::ops::metrics::metric(
                    output,
                    "porta_tls_certificate_expiry_timestamp_seconds",
                    "gauge",
                    "When the TLS certificate the gateway serves expires, in Unix seconds.",
                    not_after,
                );
            }
        }));
    }
}

/// The Unix time at which `certificate` stops being valid.
pub fn certificate_not_after(certificate: &CertificateDer<'_>) -> Option<i64> {
    let (_, parsed) = x509_parser::parse_x509_certificate(certificate.as_ref()).ok()?;
    Some(parsed.validity().not_after.timestamp())
}

/// Records the expiry of every certificate another resolver serves.
#[derive(Debug)]
pub struct ExpiryRecordingResolver {
    pub inner: Arc<dyn ResolvesServerCert>,
    pub expiry: Arc<CertificateExpiry>,
}

impl ResolvesServerCert for ExpiryRecordingResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // TLS-ALPN-01 challenge certificates are not the gateway's.
        let challenge = client_hello
            .alpn()
            .is_some_and(|mut protocols| protocols.any(|protocol| protocol == b"acme-tls/1"));
        let key = self.inner.resolve(client_hello)?;
        if !challenge {
            self.expiry.record(&key);
        }
        Some(key)
    }
}

pub struct StaticCertificateResolver {
    certificate_path: PathBuf,
    private_key_path: PathBuf,
    expiry: Arc<CertificateExpiry>,
    current: ArcSwap<CertifiedKey>,
    digest: Mutex<[u8; 32]>,
    stamps: Mutex<FileStamps>,
}

impl fmt::Debug for StaticCertificateResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StaticCertificateResolver")
            .field("certificate_path", &self.certificate_path)
            .field("private_key_path", &self.private_key_path)
            .finish_non_exhaustive()
    }
}

impl StaticCertificateResolver {
    pub fn open(
        certificate_path: impl Into<PathBuf>,
        private_key_path: impl Into<PathBuf>,
    ) -> Result<Arc<Self>> {
        let certificate_path = certificate_path.into();
        let private_key_path = private_key_path.into();
        let loaded = load_key_pair(&certificate_path, &private_key_path)?;
        let stamps = file_stamps(&certificate_path, &private_key_path)?;
        let expiry = Arc::new(CertificateExpiry::default());
        expiry.record(&loaded.key);
        Ok(Arc::new(Self {
            certificate_path,
            private_key_path,
            expiry,
            current: ArcSwap::from(loaded.key),
            digest: Mutex::new(loaded.digest),
            stamps: Mutex::new(stamps),
        }))
    }

    pub fn expiry(&self) -> Arc<CertificateExpiry> {
        self.expiry.clone()
    }

    pub fn server_config(self: &Arc<Self>, alpn_protocols: Vec<Vec<u8>>) -> rustls::ServerConfig {
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(self.clone());
        config.alpn_protocols = alpn_protocols;
        config
    }

    pub fn quinn_server_config(self: &Arc<Self>) -> Result<quinn::ServerConfig> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&TLS13])
            .context("configure HTTP/3 TLS version")?
            .with_no_client_auth()
            .with_cert_resolver(self.clone());
        config.alpn_protocols = vec![b"h3".to_vec()];
        let crypto =
            QuicServerConfig::try_from(config).context("build Quinn rustls configuration")?;
        Ok(quinn::ServerConfig::with_crypto(Arc::new(crypto)))
    }

    pub fn spawn_reload(
        self: &Arc<Self>,
        interval: Duration,
        shutdown: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        let resolver = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = ticker.tick() => {
                        if let Err(error) = resolver.reload_if_changed() {
                            tracing::warn!(%error, "reload TLS certificate failed; keeping previous certificate");
                        }
                    }
                }
            }
        })
    }

    fn reload_if_changed(&self) -> Result<bool> {
        let stamps = file_stamps(&self.certificate_path, &self.private_key_path)?;
        if *self.stamps.lock().expect("TLS reload stamp mutex poisoned") == stamps {
            return Ok(false);
        }
        let loaded = load_key_pair(&self.certificate_path, &self.private_key_path)?;
        let mut digest = self
            .digest
            .lock()
            .expect("TLS reload digest mutex poisoned");
        if *digest == loaded.digest {
            *self.stamps.lock().expect("TLS reload stamp mutex poisoned") = stamps;
            return Ok(false);
        }
        self.expiry.record(&loaded.key);
        self.current.store(loaded.key);
        *digest = loaded.digest;
        *self.stamps.lock().expect("TLS reload stamp mutex poisoned") = stamps;
        tracing::info!("TLS certificate reloaded");
        Ok(true)
    }
}

impl ResolvesServerCert for StaticCertificateResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.load_full())
    }
}

struct LoadedKeyPair {
    key: Arc<CertifiedKey>,
    digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileStamp {
    length: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileStamps {
    certificate: FileStamp,
    private_key: FileStamp,
}

fn file_stamps(certificate_path: &Path, private_key_path: &Path) -> Result<FileStamps> {
    Ok(FileStamps {
        certificate: file_stamp(certificate_path)?,
        private_key: file_stamp(private_key_path)?,
    })
}

fn file_stamp(path: &Path) -> Result<FileStamp> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("stat TLS file {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        Ok(FileStamp {
            length: metadata.len(),
            modified: metadata.modified().ok(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(FileStamp {
            length: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }
}

fn load_key_pair(certificate_path: &Path, private_key_path: &Path) -> Result<LoadedKeyPair> {
    let certificate_bytes = std::fs::read(certificate_path)
        .with_context(|| format!("read TLS certificate {}", certificate_path.display()))?;
    let private_key_bytes = Zeroizing::new(
        std::fs::read(private_key_path)
            .with_context(|| format!("read TLS private key {}", private_key_path.display()))?,
    );
    let certificates = CertificateDer::pem_slice_iter(&certificate_bytes)
        .collect::<std::result::Result<Vec<CertificateDer<'static>>, _>>()
        .context("parse TLS certificate")?;
    if certificates.is_empty() {
        bail!("TLS certificate file is empty");
    }
    let private_key = private_key_from_pem(&private_key_bytes)
        .context("parse TLS private key")?
        .context("TLS private key file is empty")?;
    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&private_key)
        .context("TLS private key is unsupported")?;
    let key = Arc::new(CertifiedKey::new(certificates, signing_key));
    key.keys_match()
        .context("TLS private key does not match certificate")?;
    let mut hasher = Sha256::new();
    hasher.update(&certificate_bytes);
    hasher.update([0]);
    hasher.update(private_key_bytes.as_slice());
    let digest = hasher.finalize().into();
    Ok(LoadedKeyPair { key, digest })
}

/// The first private key in `pem`, or `None` when it holds none.
pub(crate) fn private_key_from_pem(
    pem: &[u8],
) -> std::result::Result<Option<PrivateKeyDer<'static>>, rustls::pki_types::pem::Error> {
    match PrivateKeyDer::from_pem_slice(pem) {
        Ok(key) => Ok(Some(key)),
        Err(rustls::pki_types::pem::Error::NoItemsFound) => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{generate_simple_self_signed, CertifiedKey as GeneratedKey};

    fn generate(name: &str) -> (String, String) {
        let GeneratedKey { cert, signing_key } =
            generate_simple_self_signed(vec![name.to_owned()]).unwrap();
        (cert.pem(), signing_key.serialize_pem())
    }

    /// Replaces a file the way certificate tooling does, with a rename, so the
    /// change is visible even when the length and modification time match.
    fn replace(path: &Path, contents: impl AsRef<[u8]>) {
        let staged = path.with_extension("new");
        std::fs::write(&staged, contents).unwrap();
        std::fs::rename(&staged, path).unwrap();
    }

    #[test]
    fn records_the_served_certificate_expiry_once_per_certificate() {
        let mut params = rcgen::CertificateParams::new(vec!["vpn.example".to_owned()]).unwrap();
        params.not_after = rcgen::date_time_ymd(2031, 5, 17);
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        assert_eq!(
            certificate_not_after(certificate.der()),
            Some(time::macros::datetime!(2031-05-17 0:00 UTC).unix_timestamp())
        );

        let directory = tempfile::tempdir().unwrap();
        let (cert_path, key_path) = (
            directory.path().join("c.pem"),
            directory.path().join("k.pem"),
        );
        std::fs::write(&cert_path, certificate.pem()).unwrap();
        std::fs::write(&key_path, key.serialize_pem()).unwrap();
        let resolver = StaticCertificateResolver::open(&cert_path, &key_path).unwrap();
        let expiry = resolver.expiry();
        assert_eq!(expiry.not_after(), certificate_not_after(certificate.der()));

        let metrics = crate::ops::metrics::Metrics::default();
        expiry.export(&metrics);
        assert!(metrics.render_prometheus().contains(&format!(
            "porta_tls_certificate_expiry_timestamp_seconds {}",
            expiry.not_after().unwrap()
        )));
        assert!(CertificateExpiry::default().not_after().is_none());
        assert!(certificate_not_after(&CertificateDer::from(vec![0_u8; 8])).is_none());
    }

    #[test]
    fn rejects_a_private_key_for_another_certificate() {
        let directory = tempfile::tempdir().unwrap();
        let certificate_path = directory.path().join("server.crt");
        let private_key_path = directory.path().join("server.key");
        let (certificate, _) = generate("first.example");
        let (_, private_key) = generate("second.example");
        std::fs::write(&certificate_path, certificate).unwrap();
        std::fs::write(&private_key_path, private_key).unwrap();

        let error = StaticCertificateResolver::open(certificate_path, private_key_path)
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not match"));
    }

    #[test]
    fn reloads_valid_replacements_and_keeps_the_last_valid_key() {
        let directory = tempfile::tempdir().unwrap();
        let certificate_path = directory.path().join("server.crt");
        let private_key_path = directory.path().join("server.key");
        let (certificate, private_key) = generate("first.example");
        std::fs::write(&certificate_path, certificate).unwrap();
        std::fs::write(&private_key_path, private_key).unwrap();
        let resolver =
            StaticCertificateResolver::open(&certificate_path, &private_key_path).unwrap();
        resolver.quinn_server_config().unwrap();
        let first = resolver.current.load().cert[0].as_ref().to_vec();
        assert!(!resolver.reload_if_changed().unwrap());

        let (certificate, private_key) = generate("second.example");
        replace(&certificate_path, certificate);
        replace(&private_key_path, private_key);
        assert!(resolver.reload_if_changed().unwrap());
        let second = resolver.current.load().cert[0].as_ref().to_vec();
        assert_ne!(first, second);

        replace(&certificate_path, "invalid certificate");
        assert!(resolver.reload_if_changed().is_err());
        assert_eq!(resolver.current.load().cert[0].as_ref(), second);
    }
}
