use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use futures_util::StreamExt;
use http::{header, Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use p256::pkcs8::EncodePrivateKey;
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::version::{TLS12, TLS13};
use rustls::ServerConfig;
use rustls_acme::caches::DirCache;
use rustls_acme::{AcmeConfig, ResolvesServerCertAcme, UseChallenge};
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";
const LETS_ENCRYPT_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";

#[derive(Clone, Debug)]
pub struct AutomaticCertificateConfig {
    pub domain: String,
    pub email: String,
    pub cache_directory: PathBuf,
    pub http_listen: String,
}

pub struct AutomaticCertificateManager {
    domain: String,
    resolver: Arc<ResolvesServerCertAcme>,
    tcp_config: Arc<ServerConfig>,
    quinn_config: quinn::ServerConfig,
    cancellation: CancellationToken,
    state_task: Option<JoinHandle<()>>,
    http_task: Option<JoinHandle<Result<()>>>,
}

impl AutomaticCertificateManager {
    pub async fn start(
        config: AutomaticCertificateConfig,
        shutdown: CancellationToken,
    ) -> Result<Self> {
        let domain = normalize_and_validate_domain(&config.domain)?;
        validate_cache_directory(&config.cache_directory)?;
        tokio::fs::create_dir_all(&config.cache_directory)
            .await
            .with_context(|| {
                format!(
                    "create ACME cache directory {}",
                    config.cache_directory.display()
                )
            })?;
        secure_cache_directory(&config.cache_directory)?;
        let cached_fallback =
            match import_go_cached_certificate(&config.cache_directory, &domain).await {
                Ok(certificate) => certificate,
                Err(error) => {
                    tracing::warn!(%error, "import Go ACME certificate cache failed");
                    None
                }
            };

        let http_listener = if config.http_listen.is_empty() {
            None
        } else {
            let address =
                parse_listen_address(&config.http_listen).context("parse --acme-http-listen")?;
            Some(
                TcpListener::bind(address)
                    .await
                    .with_context(|| format!("listen for ACME HTTP-01 on {address}"))?,
            )
        };
        let challenge = if http_listener.is_some() {
            UseChallenge::Http01
        } else {
            UseChallenge::TlsAlpn01
        };
        let mut acme = AcmeConfig::new([domain.as_str()])
            .cache(DirCache::new(config.cache_directory))
            .directory_lets_encrypt(true)
            .challenge_type(challenge);
        let email = config.email.trim();
        if !email.is_empty() {
            acme = acme.contact_push(format!("mailto:{email}"));
        }

        let mut state = acme.state();
        let resolver = state.resolver();
        let server_resolver: Arc<dyn ResolvesServerCert> = match cached_fallback {
            Some(fallback) => Arc::new(CachedCertificateResolver {
                primary: resolver.clone(),
                fallback,
                domain: domain.clone(),
            }),
            None => resolver.clone(),
        };

        let mut tcp_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        if http_listener.is_none() {
            tcp_protocols.push(ACME_TLS_ALPN.to_vec());
        }
        let tcp_config = Arc::new(server_config(
            server_resolver.clone(),
            tcp_protocols,
            &[&TLS13, &TLS12],
        )?);
        let h3_config = server_config(server_resolver, vec![b"h3".to_vec()], &[&TLS13])?;
        let quic_crypto =
            QuicServerConfig::try_from(h3_config).context("build Quinn rustls configuration")?;
        let quinn_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));

        let cancellation = shutdown.child_token();
        let state_cancellation = cancellation.clone();
        let state_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = state_cancellation.cancelled() => return,
                    event = state.next() => {
                        let Some(event) = event else {
                            tracing::warn!("ACME certificate manager stopped");
                            return;
                        };
                        match event {
                            Ok(event) => tracing::info!(?event, "ACME certificate manager event"),
                            Err(error) => tracing::warn!(%error, "ACME certificate manager event failed"),
                        }
                    }
                }
            }
        });
        let http_task = http_listener.map(|listener| {
            let cancellation = cancellation.clone();
            let resolver = resolver.clone();
            let domain = domain.clone();
            tokio::spawn(
                async move { serve_http01(listener, resolver, domain, cancellation).await },
            )
        });

        Ok(Self {
            domain,
            resolver,
            tcp_config,
            quinn_config,
            cancellation,
            state_task: Some(state_task),
            http_task,
        })
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn allows_domain(&self, candidate: &str) -> bool {
        normalize_domain(candidate) == self.domain
    }

    pub fn resolver(&self) -> Arc<dyn ResolvesServerCert> {
        self.resolver.clone()
    }

    pub fn tcp_server_config(&self) -> Arc<ServerConfig> {
        self.tcp_config.clone()
    }

    pub fn quinn_server_config(&self) -> quinn::ServerConfig {
        self.quinn_config.clone()
    }

    pub async fn shutdown(mut self) -> Result<()> {
        self.cancellation.cancel();
        if let Some(mut task) = self.state_task.take() {
            match tokio::time::timeout(Duration::from_secs(10), &mut task).await {
                Ok(result) => result.context("join ACME certificate manager")?,
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    bail!("ACME certificate manager did not shut down");
                }
            }
        }
        if let Some(mut task) = self.http_task.take() {
            match tokio::time::timeout(Duration::from_secs(10), &mut task).await {
                Ok(result) => result.context("join ACME HTTP-01 server")??,
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    bail!("ACME HTTP-01 server did not shut down");
                }
            }
        }
        Ok(())
    }
}

impl Drop for AutomaticCertificateManager {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(task) = self.state_task.take() {
            task.abort();
        }
        if let Some(task) = self.http_task.take() {
            task.abort();
        }
    }
}

#[derive(Debug)]
struct CachedCertificateResolver {
    primary: Arc<ResolvesServerCertAcme>,
    fallback: Arc<CertifiedKey>,
    domain: String,
}

struct PreparedCachedCertificate {
    fallback: Arc<CertifiedKey>,
    acme_pem: Option<Zeroizing<Vec<u8>>>,
}

impl ResolvesServerCert for CachedCertificateResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let fallback_allowed = client_hello
            .server_name()
            .is_some_and(|name| normalize_domain(name) == self.domain);
        self.primary
            .resolve(client_hello)
            .or_else(|| fallback_allowed.then(|| self.fallback.clone()))
    }
}

async fn import_go_cached_certificate(
    directory: &Path,
    domain: &str,
) -> Result<Option<Arc<CertifiedKey>>> {
    let target = directory.join(rustls_acme_certificate_name(domain));
    if tokio::fs::try_exists(&target).await? {
        let cached = Zeroizing::new(tokio::fs::read(&target).await?);
        return prepare_cached_certificate(cached).map(|prepared| Some(prepared.fallback));
    }
    let mut last_error = None;
    for name in [domain.to_owned(), format!("{domain}+rsa")] {
        match tokio::fs::read(directory.join(name)).await {
            Ok(value) => {
                let cached = Zeroizing::new(value);
                match prepare_cached_certificate(cached) {
                    Ok(prepared) => {
                        if let Some(normalized) = prepared.acme_pem {
                            install_cached_certificate(target.clone(), normalized).await?;
                        }
                        return Ok(Some(prepared.fallback));
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    match last_error {
        Some(error) => Err(error),
        None => Ok(None),
    }
}

async fn install_cached_certificate(target: PathBuf, cached: Zeroizing<Vec<u8>>) -> Result<()> {
    tokio::task::spawn_blocking(move || -> Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        if target.exists() {
            return Ok(());
        }
        let temporary = target.with_extension(format!("import-{}", std::process::id()));
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .with_context(|| format!("create {}", temporary.display()))?;
        file.write_all(&cached)
            .with_context(|| format!("write {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("sync {}", temporary.display()))?;
        std::fs::rename(&temporary, &target)
            .with_context(|| format!("install {}", target.display()))?;
        Ok(())
    })
    .await
    .context("join ACME cache import")??;
    Ok(())
}

fn prepare_cached_certificate(cached: Zeroizing<Vec<u8>>) -> Result<PreparedCachedCertificate> {
    let certificates = rustls_pemfile::certs(&mut std::io::Cursor::new(cached.as_slice()))
        .collect::<std::result::Result<Vec<CertificateDer<'static>>, _>>()
        .context("parse cached ACME certificate")?;
    if certificates.is_empty() {
        bail!("cached ACME certificate is empty");
    }
    let private_key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut std::io::Cursor::new(cached.as_slice()))
            .context("parse cached ACME private key")?
            .context("cached ACME private key is empty")?;
    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&private_key)
        .context("cached ACME private key is unsupported")?;
    let certificate = Arc::new(CertifiedKey::new(certificates.clone(), signing_key));
    certificate
        .keys_match()
        .context("cached ACME private key does not match certificate")?;
    let normalized =
        match private_key {
            PrivateKeyDer::Pkcs8(key)
                if rustls::crypto::aws_lc_rs::sign::any_ecdsa_type(&PrivateKeyDer::Pkcs8(
                    key.clone_key(),
                ))
                .is_ok() =>
            {
                Some(cached)
            }
            PrivateKeyDer::Sec1(key) => {
                let key = p256::SecretKey::from_sec1_der(key.secret_sec1_der())
                    .context("parse Go ACME ECDSA private key")?;
                let key = key
                    .to_pkcs8_der()
                    .context("convert Go ACME ECDSA private key to PKCS#8")?;
                let mut blocks = Vec::with_capacity(certificates.len() + 1);
                blocks.push(pem::Pem::new("PRIVATE KEY", key.as_bytes().to_vec()));
                blocks.extend(certificates.iter().map(|certificate| {
                    pem::Pem::new("CERTIFICATE", certificate.as_ref().to_vec())
                }));
                let encoded = Zeroizing::new(pem::encode_many(&blocks));
                Some(Zeroizing::new(encoded.as_bytes().to_vec()))
            }
            _ => None,
        };
    Ok(PreparedCachedCertificate {
        fallback: certificate,
        acme_pem: normalized,
    })
}

fn rustls_acme_certificate_name(domain: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(domain.as_bytes());
    digest.update([0]);
    digest.update(LETS_ENCRYPT_DIRECTORY.as_bytes());
    format!("cached_cert_{}", URL_SAFE_NO_PAD.encode(digest.finalize()))
}

fn server_config(
    resolver: Arc<dyn ResolvesServerCert>,
    protocols: Vec<Vec<u8>>,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<ServerConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .context("configure TLS protocol versions")?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = protocols;
    Ok(config)
}

async fn serve_http01(
    listener: TcpListener,
    resolver: Arc<ResolvesServerCertAcme>,
    domain: String,
    cancellation: CancellationToken,
) -> Result<()> {
    let mut connections = tokio::task::JoinSet::new();
    let permits = Arc::new(Semaphore::new(256));
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(connection) => connection,
                    Err(error) => {
                        tracing::warn!(%error, "ACME HTTP-01 accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    tracing::warn!(%peer, "ACME HTTP-01 connection limit reached");
                    drop(stream);
                    continue;
                };
                let resolver = resolver.clone();
                let domain = domain.clone();
                let cancellation = cancellation.child_token();
                connections.spawn(async move {
                    let _permit = permit;
                    if let Err(error) =
                        serve_http01_connection(stream, resolver, domain, cancellation).await
                    {
                        tracing::debug!(%peer, %error, "ACME HTTP-01 connection closed with error");
                    }
                });
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    tracing::debug!(%error, "ACME HTTP-01 connection task failed");
                }
            }
        }
    }
    if tokio::time::timeout(Duration::from_secs(2), async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    Ok(())
}

async fn serve_http01_connection(
    stream: TcpStream,
    resolver: Arc<ResolvesServerCertAcme>,
    domain: String,
    cancellation: CancellationToken,
) -> Result<()> {
    let service = service_fn(move |request| {
        let resolver = resolver.clone();
        let domain = domain.clone();
        async move { Ok::<_, Infallible>(http01_response(request, resolver.as_ref(), &domain)) }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder.keep_alive(false).max_buf_size(16 << 10);
    let connection = builder.serve_connection(TokioIo::new(stream), service);
    tokio::pin!(connection);
    tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(10), &mut connection) => {
            match result {
                Ok(result) => result.context("serve ACME HTTP-01 connection")?,
                Err(_) => bail!("ACME HTTP-01 connection timed out"),
            }
        },
        _ = cancellation.cancelled() => {
            connection.as_mut().graceful_shutdown();
            let _ = tokio::time::timeout(Duration::from_secs(1), &mut connection).await;
        }
    }
    Ok(())
}

fn http01_response(
    request: Request<Incoming>,
    resolver: &ResolvesServerCertAcme,
    domain: &str,
) -> Response<Full<Bytes>> {
    const PREFIX: &str = "/.well-known/acme-challenge/";
    if let Some(token) = request.uri().path().strip_prefix(PREFIX) {
        if !host_allowed(request.headers().get(header::HOST), domain) {
            return text_response(StatusCode::FORBIDDEN, "acme host policy rejected request\n");
        }
        if token.is_empty() || token.contains('/') {
            return text_response(StatusCode::NOT_FOUND, "acme challenge token not found\n");
        }
        return match resolver.get_http_01_key_auth(token) {
            Some(key_authorization) => Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(Full::new(Bytes::from(key_authorization)))
                .expect("static ACME response is valid"),
            None => text_response(StatusCode::NOT_FOUND, "acme challenge token not found\n"),
        };
    }
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return text_response(StatusCode::BAD_REQUEST, "Use HTTPS\n");
    }
    let Some(host) = redirect_host(request.headers().get(header::HOST)) else {
        return text_response(StatusCode::BAD_REQUEST, "missing Host header\n");
    };
    let location = format!("https://{host}{}", request.uri());
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        .body(Full::new(Bytes::new()))
        .expect("static redirect response is valid")
}

fn text_response(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .expect("static ACME response is valid")
}

fn host_allowed(value: Option<&http::HeaderValue>, domain: &str) -> bool {
    host_without_port(value).is_some_and(|host| normalize_domain(host) == domain)
}

fn host_without_port(value: Option<&http::HeaderValue>) -> Option<&str> {
    let value = value?.to_str().ok()?;
    if let Ok(address) = value.parse::<SocketAddr>() {
        return match address.ip() {
            IpAddr::V4(_) | IpAddr::V6(_) => None,
        };
    }
    value
        .rsplit_once(':')
        .filter(|(_, port)| port.parse::<u16>().is_ok())
        .map_or(Some(value), |(host, _)| Some(host))
}

fn redirect_host(value: Option<&http::HeaderValue>) -> Option<String> {
    let value = value?.to_str().ok()?;
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Some(SocketAddr::new(address.ip(), 443).to_string());
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if port.parse::<u16>().is_ok() {
            return Some(format!("{host}:443"));
        }
    }
    Some(value.to_string())
}

fn parse_listen_address(value: &str) -> Result<SocketAddr> {
    if let Some(port) = value.strip_prefix(':') {
        return Ok(SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            port.parse()?,
        ));
    }
    Ok(value.parse()?)
}

pub fn normalize_domain(domain: &str) -> String {
    let domain = domain.trim();
    domain
        .strip_suffix('.')
        .unwrap_or(domain)
        .to_ascii_lowercase()
}

pub fn normalize_and_validate_domain(domain: &str) -> Result<String> {
    let domain = normalize_domain(domain);
    if !valid_dns_name(&domain) {
        bail!(
            "--acme-domain is required and must be a fully qualified DNS name without a scheme or port"
        );
    }
    Ok(domain)
}

fn valid_dns_name(domain: &str) -> bool {
    if domain.is_empty()
        || domain.len() > 253
        || !domain.contains('.')
        || domain.parse::<IpAddr>().is_ok()
    {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .bytes()
                .all(|value| value.is_ascii_alphanumeric() || value == b'-')
    })
}

fn validate_cache_directory(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        bail!("--acme-cache must not be empty when --acme-domain is set");
    }
    Ok(())
}

fn secure_cache_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("secure ACME cache directory {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_one_configured_fqdn() {
        assert_eq!(
            normalize_and_validate_domain(" VPN.Example.COM. ").unwrap(),
            "vpn.example.com"
        );
    }

    #[test]
    fn rejects_invalid_acme_options_like_go_server() {
        for domain in [
            "",
            "localhost",
            "https://vpn.example.com",
            "192.0.2.1",
            "vpn..example.com",
            "-vpn.example.com",
            "vpn-.example.com",
            "vpn_test.example.com",
            "vpn.example.com..",
        ] {
            assert!(normalize_and_validate_domain(domain).is_err(), "{domain}");
        }
        let long_label = format!("{}.example.com", "a".repeat(64));
        assert!(normalize_and_validate_domain(&long_label).is_err());
        assert!(validate_cache_directory(Path::new("")).is_err());
    }

    #[test]
    fn configured_domain_policy_is_exact_after_normalization() {
        let configured = normalize_and_validate_domain("VPN.Example.COM.").unwrap();
        assert_eq!(normalize_domain("vpn.example.com"), configured);
        assert_ne!(normalize_domain("other.example.com"), configured);
    }

    #[test]
    fn parses_go_style_http_listen_address() {
        assert_eq!(
            parse_listen_address(":80").unwrap(),
            SocketAddr::from(([0, 0, 0, 0], 80))
        );
    }

    #[tokio::test]
    async fn imports_the_existing_go_certificate_cache() {
        use p256::pkcs8::DecodePrivateKey;
        use rcgen::{generate_simple_self_signed, CertifiedKey as GeneratedKey};

        let directory = tempfile::tempdir().unwrap();
        let GeneratedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["vpn.example.com".to_owned()]).unwrap();
        let secret = p256::SecretKey::from_pkcs8_der(&signing_key.serialize_der()).unwrap();
        let cached = format!(
            "{}{}",
            pem::encode(&pem::Pem::new(
                "EC PRIVATE KEY",
                secret.to_sec1_der().unwrap().as_slice().to_vec()
            )),
            cert.pem()
        );
        tokio::fs::write(directory.path().join("vpn.example.com"), &cached)
            .await
            .unwrap();
        assert!(
            import_go_cached_certificate(directory.path(), "vpn.example.com")
                .await
                .unwrap()
                .is_some()
        );
        let imported = tokio::fs::read(
            directory
                .path()
                .join(rustls_acme_certificate_name("vpn.example.com")),
        )
        .await
        .unwrap();
        let blocks = pem::parse_many(imported).unwrap();
        assert_eq!(blocks[0].tag(), "PRIVATE KEY");
        assert!(
            rustls::crypto::aws_lc_rs::sign::any_ecdsa_type(&PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(blocks[0].contents().to_vec())
            ))
            .is_ok()
        );
        assert!(
            import_go_cached_certificate(directory.path(), "vpn.example.com")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn serves_rsa_go_cache_as_fallback_without_poisoning_acme_cache() {
        use rcgen::{CertificateParams, KeyPair, PKCS_RSA_SHA256};

        let directory = tempfile::tempdir().unwrap();
        let key = KeyPair::generate_for(&PKCS_RSA_SHA256).unwrap();
        let certificate = CertificateParams::new(vec!["vpn.example.com".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let cached = format!("{}{}", key.serialize_pem(), certificate.pem());
        tokio::fs::write(directory.path().join("vpn.example.com+rsa"), cached)
            .await
            .unwrap();
        assert!(
            import_go_cached_certificate(directory.path(), "vpn.example.com")
                .await
                .unwrap()
                .is_some()
        );
        assert!(!tokio::fs::try_exists(
            directory
                .path()
                .join(rustls_acme_certificate_name("vpn.example.com"))
        )
        .await
        .unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn secures_cache_directory() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        secure_cache_directory(directory.path()).unwrap();
        assert_eq!(
            std::fs::metadata(directory.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}
