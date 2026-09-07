use anyhow::{bail, Context, Result};
use clap::{ArgAction, Parser};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Parser)]
#[command(name = "porta-server", disable_version_flag = true)]
pub struct Config {
    #[arg(long, default_value = ":8443")]
    pub listen: String,
    #[arg(long)]
    pub acme_domain: Option<String>,
    #[arg(long, default_value = "")]
    pub acme_email: String,
    #[arg(long, default_value = "acme-cache")]
    pub acme_cache: PathBuf,
    #[arg(long, default_value = ":80")]
    pub acme_http_listen: String,
    #[arg(long, num_args = 0..=1, default_missing_value = "", value_parser = parse_path)]
    pub tls_cert: Option<PathBuf>,
    #[arg(long, num_args = 0..=1, default_missing_value = "", value_parser = parse_path)]
    pub tls_key: Option<PathBuf>,
    #[arg(long, action = ArgAction::SetTrue)]
    pub behind_proxy: bool,
    #[arg(long, action = ArgAction::SetTrue)]
    pub trust_proxy_headers: bool,
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    pub landing_page: bool,
    #[arg(long, num_args = 0..=1, default_missing_value = "", value_parser = parse_path)]
    pub landing_template_dir: Option<PathBuf>,
    #[arg(long, action = ArgAction::SetTrue)]
    pub disable_forward_proxy: bool,
    #[arg(long, num_args = 0..=1, default_missing_value = "", value_parser = parse_path)]
    pub client_downloads: Option<PathBuf>,
    #[arg(long, default_value = "127.0.0.1:9090")]
    pub admin_listen: Option<String>,
    #[arg(long, default_value = "clients.json")]
    pub client_registry: PathBuf,
    #[arg(long, num_args = 0..=1, default_missing_value = "", value_parser = parse_path)]
    pub usage_state: Option<PathBuf>,
    #[arg(long, default_value = "porta0")]
    pub interface: String,
    #[arg(long, default_value = "10.66.0.0/24")]
    pub pool: ipnet::Ipv4Net,
    #[arg(long, num_args = 0..=1, default_missing_value = "", value_parser = parse_path)]
    pub lease_state: Option<PathBuf>,
    #[arg(long, default_value = "1.1.1.1")]
    pub dns: String,
    #[arg(long, default_value_t = 1400)]
    pub mtu: u16,
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    pub auto_mtu: bool,
    #[arg(long, default_value = "")]
    pub token: String,
    #[arg(long, default_value = "")]
    pub metrics_token: String,
    #[arg(long, action = ArgAction::SetTrue)]
    pub json_logs: bool,
    #[arg(long, default_value = "")]
    pub egress_interface: String,
    #[arg(long, default_value = "3s", value_parser = parse_duration)]
    pub readiness_timeout: Duration,
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    pub readiness_require_nat: bool,
    #[arg(long, default_value = "")]
    pub readiness_egress_url: String,
    #[arg(long, default_value = "")]
    pub readiness_dns_name: String,
    #[arg(skip)]
    pub admin_token: String,
}

impl fmt::Debug for Config {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Config")
            .field("listen", &self.listen)
            .field("acme_domain", &self.acme_domain)
            .field("acme_email", &redacted(&self.acme_email))
            .field("acme_cache", &self.acme_cache)
            .field("acme_http_listen", &self.acme_http_listen)
            .field("tls_cert", &self.tls_cert)
            .field("tls_key", &self.tls_key)
            .field("behind_proxy", &self.behind_proxy)
            .field("trust_proxy_headers", &self.trust_proxy_headers)
            .field("landing_page", &self.landing_page)
            .field("landing_template_dir", &self.landing_template_dir)
            .field("disable_forward_proxy", &self.disable_forward_proxy)
            .field("client_downloads", &self.client_downloads)
            .field("admin_listen", &self.admin_listen)
            .field("client_registry", &self.client_registry)
            .field("usage_state", &self.usage_state)
            .field("interface", &self.interface)
            .field("pool", &self.pool)
            .field("lease_state", &self.lease_state)
            .field("dns", &self.dns)
            .field("mtu", &self.mtu)
            .field("auto_mtu", &self.auto_mtu)
            .field("token", &redacted(&self.token))
            .field("metrics_token", &redacted(&self.metrics_token))
            .field("json_logs", &self.json_logs)
            .field("egress_interface", &self.egress_interface)
            .field("readiness_timeout", &self.readiness_timeout)
            .field("readiness_require_nat", &self.readiness_require_nat)
            .field("readiness_egress_url", &self.readiness_egress_url)
            .field("readiness_dns_name", &self.readiness_dns_name)
            .field("admin_token", &redacted(&self.admin_token))
            .finish()
    }
}

fn redacted(value: &str) -> Option<&'static str> {
    (!value.is_empty()).then_some("[REDACTED]")
}

impl Config {
    pub fn parse_and_validate() -> Result<Self> {
        let mut config = Self::parse();
        config.apply_environment();
        config.validate()?;
        Ok(config)
    }

    pub fn try_parse_and_validate_from<I, T>(arguments: I) -> Result<Self>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let mut config = Self::try_parse_from(arguments)?;
        config.apply_environment();
        config.validate()?;
        Ok(config)
    }

    fn apply_environment(&mut self) {
        Self::normalize_optional_path(&mut self.tls_cert);
        Self::normalize_optional_path(&mut self.tls_key);
        Self::normalize_optional_path(&mut self.landing_template_dir);
        Self::normalize_optional_path(&mut self.client_downloads);
        Self::normalize_optional_path(&mut self.usage_state);
        Self::normalize_optional_path(&mut self.lease_state);
        if let Ok(value) = std::env::var("PORTA_TOKEN") {
            if !value.is_empty() {
                self.token = value;
            }
        }
        if let Ok(value) = std::env::var("PORTA_METRICS_TOKEN") {
            if !value.is_empty() {
                self.metrics_token = value;
            }
        }
        self.admin_token = std::env::var("PORTA_ADMIN_TOKEN").unwrap_or_default();
        if self.usage_state.is_none() {
            self.usage_state = Some(
                self.client_registry
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new(""))
                    .join("usage.json"),
            );
        }
    }

    fn validate(&mut self) -> Result<()> {
        if !self.token.is_empty() && self.token.len() < 16 {
            bail!("PORTA_TOKEN must contain at least 16 characters");
        }
        if !self.metrics_token.is_empty() && self.metrics_token.len() < 16 {
            bail!("PORTA_METRICS_TOKEN must contain at least 16 characters");
        }
        if !self.admin_token.is_empty() && self.admin_token.len() < 24 {
            bail!("PORTA_ADMIN_TOKEN must contain at least 24 characters");
        }
        if self
            .admin_listen
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        {
            if self.admin_token.is_empty() {
                bail!("PORTA_ADMIN_TOKEN is required when the admin listener is enabled");
            }
            validate_loopback_address(self.admin_listen.as_deref().unwrap(), "--admin-listen")?;
        } else {
            self.admin_listen = None;
        }
        if let Some(path) = &self.client_downloads {
            if !path.is_absolute() {
                bail!("--client-downloads must be an absolute path");
            }
            if !path
                .metadata()
                .with_context(|| format!("open client downloads directory {}", path.display()))?
                .is_dir()
            {
                bail!("--client-downloads must name a directory");
            }
        }
        if self.mtu < 576 || self.mtu > 9000 {
            bail!("MTU {} is outside 576..9000", self.mtu);
        }
        if self.readiness_timeout.is_zero() {
            bail!("--readiness-timeout must be positive");
        }
        if !self.dns.is_empty() {
            let dns = self.dns.parse::<Ipv4Addr>().context(
                "advertised DNS must be a unicast IPv4 address, not loopback or link-local",
            )?;
            if dns.is_loopback()
                || dns.is_link_local()
                || dns.is_broadcast()
                || dns.is_unspecified()
                || dns.is_multicast()
            {
                bail!("advertised DNS must be a unicast IPv4 address, not loopback or link-local");
            }
        }
        let has_static_cert = self.tls_cert.is_some() || self.tls_key.is_some();
        if self.tls_cert.is_some() != self.tls_key.is_some() {
            bail!("--tls-cert and --tls-key must be provided together");
        }
        let domain = self
            .acme_domain
            .as_deref()
            .map(normalize_domain)
            .unwrap_or_default();
        self.acme_domain = (!domain.is_empty()).then_some(domain.clone());
        if self.behind_proxy {
            if self.acme_domain.is_some() || !self.acme_email.trim().is_empty() || has_static_cert {
                bail!("--behind-proxy cannot be combined with ACME or static TLS options");
            }
            validate_loopback_address(&self.listen, "--listen for --behind-proxy")?;
        } else if has_static_cert {
            if self.acme_domain.is_some() || !self.acme_email.trim().is_empty() {
                bail!("static TLS cannot be combined with --acme-domain or --acme-email");
            }
        } else {
            if !valid_dns_name(&domain) {
                bail!("--acme-domain is required and must be a fully qualified DNS name without a scheme or port");
            }
            if self.acme_cache.as_os_str().is_empty() {
                bail!("--acme-cache must not be empty when --acme-domain is set");
            }
        }
        if !self.behind_proxy {
            parse_listen_address(&self.listen)
                .with_context(|| "public listen address must use a fixed port from 1 to 65535")?;
        }
        if !self.readiness_egress_url.is_empty() {
            let uri = self
                .readiness_egress_url
                .parse::<http::Uri>()
                .context("--readiness-egress-url must be an HTTP(S) URL without credentials")?;
            let valid_scheme = matches!(uri.scheme_str(), Some("http" | "https"));
            let valid_authority = uri
                .authority()
                .is_some_and(|authority| !authority.as_str().contains('@'));
            if !valid_scheme || !valid_authority {
                bail!("--readiness-egress-url must be an HTTP(S) URL without credentials");
            }
        }
        if !self.readiness_dns_name.is_empty() && self.dns.is_empty() {
            bail!("--dns must be an IP address when --readiness-dns-name is configured");
        }
        Ok(())
    }

    fn normalize_optional_path(path: &mut Option<PathBuf>) {
        if path
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            *path = None;
        }
    }

    pub fn dns_address(&self) -> Result<Option<Ipv4Addr>> {
        if self.dns.is_empty() {
            Ok(None)
        } else {
            Ok(Some(self.dns.parse()?))
        }
    }

    pub fn listen_address(&self) -> Result<SocketAddr> {
        parse_listen_address(&self.listen)
    }

    pub fn admin_address(&self) -> Result<Option<SocketAddr>> {
        self.admin_listen
            .as_deref()
            .map(parse_listen_address)
            .transpose()
    }
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    humantime::parse_duration(value).map_err(|error| error.to_string())
}

fn parse_path(value: &str) -> Result<PathBuf, String> {
    if value.contains('\0') {
        Err("path contains a NUL byte".into())
    } else {
        Ok(PathBuf::from(value))
    }
}

pub fn version_requested<I, T>(arguments: I) -> bool
where
    I: IntoIterator<Item = T>,
    T: AsRef<std::ffi::OsStr>,
{
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    arguments.len() == 1
        && matches!(
            arguments[0].as_ref().to_str(),
            Some("--version" | "-version")
        )
}

fn parse_listen_address(value: &str) -> Result<SocketAddr> {
    if let Some(port) = value.strip_prefix(':') {
        let port = port.parse::<u16>()?;
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));
    }
    Ok(value.parse()?)
}

fn validate_loopback_address(value: &str, option: &str) -> Result<()> {
    let address = parse_listen_address(value).with_context(|| format!("parse {option}"))?;
    if !address.ip().is_loopback() {
        bail!("{option} requires a loopback address");
    }
    Ok(())
}

fn normalize_domain(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn valid_dns_name(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 253
        || !value.contains('.')
        || value.parse::<IpAddr>().is_ok()
    {
        return false;
    }
    value.split('.').all(|label| {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_dns_names_like_go_server() {
        assert!(valid_dns_name("vpn.example.com"));
        assert!(!valid_dns_name("localhost"));
        assert!(!valid_dns_name("127.0.0.1"));
        assert!(!valid_dns_name("-vpn.example.com"));
        assert!(!valid_dns_name("vpn-.example.com"));
    }

    #[test]
    fn accepts_go_style_wildcard_listen_address() {
        assert_eq!(
            parse_listen_address(":8443").unwrap(),
            SocketAddr::from(([0, 0, 0, 0], 8443))
        );
    }

    #[test]
    fn version_flags_match_the_go_server() {
        assert!(version_requested(["--version"]));
        assert!(version_requested(["-version"]));
        assert!(!version_requested(["-V"]));
        assert!(!version_requested(["--version", "extra"]));
    }

    #[test]
    fn accepts_static_tls_mode_without_acme() {
        let directory = tempfile::tempdir().unwrap();
        let downloads = directory.path().join("downloads");
        std::fs::create_dir(&downloads).unwrap();
        let config = Config::try_parse_and_validate_from([
            "porta-server",
            "--listen=:8443",
            "--admin-listen=",
            "--tls-cert=/etc/porta/server.crt",
            "--tls-key=/etc/porta/server.key",
            &format!("--client-downloads={}", downloads.display()),
        ])
        .unwrap();
        assert_eq!(config.admin_listen, None);
        assert_eq!(config.usage_state.unwrap(), PathBuf::from("usage.json"));
    }

    #[test]
    fn rejects_public_behind_proxy_listener() {
        let error = Config::try_parse_and_validate_from([
            "porta-server",
            "--behind-proxy",
            "--listen=0.0.0.0:8443",
            "--admin-listen=",
        ])
        .unwrap_err();
        assert!(error.to_string().contains("requires a loopback address"));
    }

    #[test]
    fn empty_optional_paths_match_go_flag_behavior() {
        let config = Config::try_parse_and_validate_from([
            "porta-server",
            "--behind-proxy",
            "--listen=127.0.0.1:8443",
            "--admin-listen=",
            "--client-downloads=",
            "--lease-state=",
        ])
        .unwrap();
        assert_eq!(config.client_downloads, None);
        assert_eq!(config.lease_state, None);
        assert_eq!(config.usage_state, Some(PathBuf::from("usage.json")));
    }

    #[test]
    fn rejects_zero_readiness_timeout() {
        let error = Config::try_parse_and_validate_from([
            "porta-server",
            "--behind-proxy",
            "--listen=127.0.0.1:8443",
            "--admin-listen=",
            "--readiness-timeout=0s",
        ])
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("--readiness-timeout must be positive"));
    }

    #[test]
    fn debug_output_redacts_credentials() {
        let mut config = Config::try_parse_from(["porta-server"]).unwrap();
        config.token = "token-secret-value".to_string();
        config.metrics_token = "metrics-secret-value".to_string();
        config.admin_token = "admin-secret-value".to_string();
        let output = format!("{config:?}");
        assert!(!output.contains("secret-value"));
        assert!(output.contains("[REDACTED]"));
    }
}
