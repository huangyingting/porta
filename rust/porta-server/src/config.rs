use anyhow::{bail, Context, Result};
use clap::{ArgAction, Parser, ValueEnum};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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
    /// IPv4 prefix routed through the tunnel (repeatable). Without any, clients
    /// use a full tunnel.
    #[arg(long = "route", value_name = "CIDR")]
    pub routes: Vec<ipnet::Ipv4Net>,
    /// With --route: DNS domain resolved through the tunnel's DNS server
    /// (repeatable). Other names keep using the device's resolver.
    #[arg(long = "dns-domain", value_name = "DOMAIN")]
    pub dns_domains: Vec<String>,
    /// Let every client reach every other client's devices and subnets.
    /// Without it, only devices of one account or of accounts that share an
    /// access group reach each other.
    #[arg(long, default_value_t = false, num_args = 0..=1, default_missing_value = "true", action = ArgAction::Set)]
    pub client_to_client: bool,
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
    /// HTTPS origin of the next-hop Porta gateway. Client traffic leaves
    /// through that gateway instead of this host (cascade relay).
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    pub upstream: Option<String>,
    #[arg(long, default_value = "porta-up0")]
    pub upstream_interface: String,
    /// Fixed address of the upstream interface. Relayed client traffic is
    /// masqueraded to it, then translated to the next hop's lease.
    #[arg(long, default_value = "169.254.66.1")]
    pub upstream_address: Ipv4Addr,
    #[arg(long, value_enum, default_value_t = UpstreamTransport::Auto)]
    pub upstream_transport: UpstreamTransport,
    /// Private device key used to enroll with the next hop. Defaults to
    /// upstream-identity.json beside the client registry.
    #[arg(long, num_args = 0..=1, default_missing_value = "", value_parser = parse_path)]
    pub upstream_identity: Option<PathBuf>,
    #[arg(long, num_args = 0..=1, default_missing_value = "", value_parser = parse_path)]
    pub upstream_ca: Option<PathBuf>,
    #[arg(long, default_value = "")]
    pub upstream_thumbprint: String,
    #[arg(skip)]
    pub admin_token: String,
    #[arg(skip)]
    pub upstream_token: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum UpstreamTransport {
    #[default]
    Auto,
    H3,
    H2,
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
            .field("routes", &self.routes)
            .field("dns_domains", &self.dns_domains)
            .field("auto_mtu", &self.auto_mtu)
            .field("token", &redacted(&self.token))
            .field("metrics_token", &redacted(&self.metrics_token))
            .field("json_logs", &self.json_logs)
            .field("egress_interface", &self.egress_interface)
            .field("readiness_timeout", &self.readiness_timeout)
            .field("readiness_require_nat", &self.readiness_require_nat)
            .field("readiness_egress_url", &self.readiness_egress_url)
            .field("readiness_dns_name", &self.readiness_dns_name)
            .field("upstream", &self.upstream)
            .field("upstream_interface", &self.upstream_interface)
            .field("upstream_address", &self.upstream_address)
            .field("upstream_transport", &self.upstream_transport)
            .field("upstream_identity", &self.upstream_identity)
            .field("upstream_ca", &self.upstream_ca)
            .field("upstream_thumbprint", &self.upstream_thumbprint)
            .field("admin_token", &redacted(&self.admin_token))
            .field("upstream_token", &redacted(&self.upstream_token))
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
        self.upstream_token = std::env::var("PORTA_UPSTREAM_TOKEN").unwrap_or_default();
        Self::normalize_optional_path(&mut self.upstream_identity);
        Self::normalize_optional_path(&mut self.upstream_ca);
        if self
            .upstream
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            self.upstream = None;
        }
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
        self.validate_upstream()?;
        self.validate_routing()?;
        Ok(())
    }

    fn validate_routing(&mut self) -> Result<()> {
        const MAX_ROUTES: usize = 64;
        const MAX_DNS_DOMAINS: usize = 16;
        if self.routes.len() > MAX_ROUTES {
            bail!("at most {MAX_ROUTES} --route prefixes are supported");
        }
        for route in &mut self.routes {
            *route = route.trunc();
            if route.prefix_len() == 0 {
                bail!("--route 0.0.0.0/0 is a full tunnel; omit --route instead");
            }
            if route.addr().is_loopback() || route.addr().is_multicast() {
                bail!("--route {route} is not a routable unicast prefix");
            }
        }
        self.routes.sort();
        self.routes.dedup();
        if self.dns_domains.len() > MAX_DNS_DOMAINS {
            bail!("at most {MAX_DNS_DOMAINS} --dns-domain values are supported");
        }
        if !self.dns_domains.is_empty() {
            if self.routes.is_empty() {
                bail!("--dns-domain requires --route; a full tunnel resolves every name through the tunnel");
            }
            if self.dns.is_empty() {
                bail!("--dns-domain requires --dns");
            }
        }
        for domain in &mut self.dns_domains {
            *domain = normalize_domain(domain);
            let single_label = !domain.contains('.')
                && !domain.is_empty()
                && domain
                    .bytes()
                    .all(|value| value.is_ascii_alphanumeric() || value == b'-');
            if !(valid_dns_name(domain) || single_label) {
                bail!("--dns-domain {domain:?} is not a DNS name");
            }
        }
        self.dns_domains.sort();
        self.dns_domains.dedup();
        Ok(())
    }

    fn validate_upstream(&mut self) -> Result<()> {
        let Some(upstream) = self.upstream.as_deref() else {
            return Ok(());
        };
        self.upstream = Some(normalize_https_origin(upstream).context(
            "--upstream must be the HTTPS origin of the next-hop gateway, for example https://exit.example.com",
        )?);
        if self.upstream_token.is_empty() {
            bail!("PORTA_UPSTREAM_TOKEN is required with --upstream");
        }
        if !valid_interface_name(&self.upstream_interface) {
            bail!("--upstream-interface must be a valid interface name");
        }
        if self.upstream_interface == self.interface
            || (!self.egress_interface.is_empty()
                && self.upstream_interface == self.egress_interface)
        {
            bail!("--upstream-interface must differ from --interface and --egress-interface");
        }
        let address = self.upstream_address;
        if address.is_unspecified()
            || address.is_loopback()
            || address.is_multicast()
            || address.is_broadcast()
            || self.pool.contains(&address)
        {
            bail!("--upstream-address must be a unicast address outside --pool");
        }
        if let Some(path) = &self.upstream_ca {
            if !path.is_absolute() {
                bail!("--upstream-ca must be an absolute path");
            }
        }
        let identity = match self.upstream_identity.take() {
            Some(path) => path,
            None => self
                .client_registry
                .parent()
                .unwrap_or_else(|| std::path::Path::new(""))
                .join("upstream-identity.json"),
        };
        self.upstream_identity = Some(if identity.is_absolute() {
            identity
        } else {
            std::env::current_dir()
                .context("resolve --upstream-identity")?
                .join(identity)
        });
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

pub(crate) fn parse_listen_address(value: &str) -> Result<SocketAddr> {
    let address = if let Some(port) = value.strip_prefix(':') {
        let port = port.parse::<u16>()?;
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
    } else {
        value.parse()?
    };
    if address.port() == 0 {
        bail!("listen port must be between 1 and 65535");
    }
    Ok(address)
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

fn normalize_https_origin(value: &str) -> Result<String> {
    let uri = value.trim().parse::<http::Uri>()?;
    let authority = uri
        .authority()
        .filter(|authority| !authority.as_str().contains('@') && !authority.host().is_empty())
        .context("missing host")?;
    if uri.scheme_str() != Some("https")
        || !matches!(uri.path(), "" | "/")
        || uri.query().is_some()
        || authority.port_u16() == Some(0)
    {
        bail!("not an HTTPS origin");
    }
    Ok(format!(
        "https://{}",
        authority.as_str().to_ascii_lowercase()
    ))
}

fn valid_interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() < 16
        && value
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'_' | b'-' | b'.'))
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
    fn accepts_go_style_wildcard_as_dual_stack_address() {
        assert_eq!(
            parse_listen_address(":8443").unwrap(),
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 8443))
        );
        assert_eq!(
            parse_listen_address("0.0.0.0:8443").unwrap(),
            SocketAddr::from(([0, 0, 0, 0], 8443))
        );
    }

    #[test]
    fn rejects_zero_listen_ports() {
        assert!(parse_listen_address(":0").is_err());
        assert!(parse_listen_address("127.0.0.1:0").is_err());
        assert!(parse_listen_address("[::1]:0").is_err());
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
        config.upstream_token = "upstream-secret-value".to_string();
        let output = format!("{config:?}");
        assert!(!output.contains("secret-value"));
        assert!(output.contains("[REDACTED]"));
    }

    fn relay_config(arguments: &[&str], token: &str) -> Result<Config> {
        let mut config = Config::try_parse_from(
            [
                "porta-server",
                "--behind-proxy",
                "--listen=127.0.0.1:8443",
                "--admin-listen=",
                "--client-registry=/var/lib/porta/clients.json",
            ]
            .into_iter()
            .chain(arguments.iter().copied()),
        )?;
        config.upstream_token = token.to_owned();
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn split_routes_and_dns_domains_are_validated_and_normalized() {
        let config = relay_config(&[], "").unwrap();
        assert!(config.routes.is_empty());
        let config = relay_config(
            &[
                "--route",
                "10.20.30.40/16",
                "--route",
                "10.20.0.0/16",
                "--route",
                "192.168.5.0/24",
                "--dns-domain",
                "Corp.Example.",
                "--dns-domain",
                "internal",
            ],
            "",
        )
        .unwrap();
        assert_eq!(
            config.routes,
            vec![
                "10.20.0.0/16".parse().unwrap(),
                "192.168.5.0/24".parse().unwrap()
            ]
        );
        assert_eq!(config.dns_domains, vec!["corp.example", "internal"]);
        for (arguments, message) in [
            (vec!["--route", "0.0.0.0/0"], "full tunnel"),
            (vec!["--route", "127.0.0.0/8"], "routable"),
            (vec!["--dns-domain", "corp.example"], "requires --route"),
            (
                vec!["--route", "10.0.0.0/8", "--dns-domain", "bad_domain"],
                "not a DNS name",
            ),
        ] {
            let error = relay_config(&arguments, "").unwrap_err();
            assert!(
                format!("{error:#}").contains(message),
                "{arguments:?}: {error:#}"
            );
        }
    }

    #[test]
    fn upstream_is_optional_and_normalized_to_an_origin() {
        let config = relay_config(&[], "").unwrap();
        assert_eq!(config.upstream, None);
        assert_eq!(config.upstream_identity, None);

        let config = relay_config(
            &["--upstream", "https://Exit.Example.com:8443/"],
            "upstream-account-token",
        )
        .unwrap();
        assert_eq!(
            config.upstream.as_deref(),
            Some("https://exit.example.com:8443")
        );
        assert_eq!(config.upstream_interface, "porta-up0");
        assert_eq!(config.upstream_transport, UpstreamTransport::Auto);
        assert_eq!(
            config.upstream_identity,
            Some(PathBuf::from("/var/lib/porta/upstream-identity.json"))
        );
    }

    #[test]
    fn upstream_requires_a_token_https_origin_and_distinct_interface() {
        for (arguments, token, message) in [
            (
                vec!["--upstream", "https://exit.example.com"],
                "",
                "PORTA_UPSTREAM_TOKEN",
            ),
            (
                vec!["--upstream", "http://exit.example.com"],
                "token",
                "HTTPS origin",
            ),
            (
                vec!["--upstream", "https://exit.example.com/path"],
                "token",
                "HTTPS origin",
            ),
            (
                vec!["--upstream", "https://user@exit.example.com"],
                "token",
                "HTTPS origin",
            ),
            (
                vec![
                    "--upstream",
                    "https://exit.example.com",
                    "--upstream-interface",
                    "porta0",
                ],
                "token",
                "must differ",
            ),
            (
                vec![
                    "--upstream",
                    "https://exit.example.com",
                    "--upstream-interface",
                    "bad/name",
                ],
                "token",
                "valid interface name",
            ),
            (
                vec![
                    "--upstream",
                    "https://exit.example.com",
                    "--upstream-ca",
                    "ca.pem",
                ],
                "token",
                "absolute path",
            ),
            (
                vec![
                    "--upstream",
                    "https://exit.example.com",
                    "--upstream-address",
                    "10.66.0.9",
                ],
                "token",
                "outside --pool",
            ),
        ] {
            let error = relay_config(&arguments, token).unwrap_err();
            assert!(
                format!("{error:#}").contains(message),
                "{arguments:?}: {error:#}"
            );
        }
    }
}
