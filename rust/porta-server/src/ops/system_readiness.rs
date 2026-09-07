use crate::ops::readiness::{Probe, Readiness, ReadinessCheck};
use anyhow::{anyhow, bail, Context, Result};
use futures_util::FutureExt;
use ipnet::Ipv4Net;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug)]
pub struct SystemReadinessConfig {
    pub interface: String,
    pub gateway: Ipv4Addr,
    pub pool: Ipv4Net,
    pub mtu: u32,
    pub egress_interface: Option<String>,
    pub require_nat: bool,
    pub require_input_guard: bool,
    pub public_port: u16,
    pub auto_mtu: bool,
    pub timeout: Duration,
    pub egress_url: Option<String>,
    pub dns_name: Option<String>,
    pub dns_address: Option<IpAddr>,
}

pub fn system_readiness(config: SystemReadinessConfig) -> Result<Readiness> {
    validate_config(&config)?;
    let config = Arc::new(config);
    let mut checks = Vec::with_capacity(12);

    checks.push(required_probe("tun_link", {
        let config = config.clone();
        move |cancellation| {
            let config = config.clone();
            async move {
                let link = read_link(&config.interface, cancellation).await?;
                if !link.flags.iter().any(|flag| flag == "UP") {
                    bail!("interface {} is down", config.interface);
                }
                Ok(())
            }
        }
    }));
    checks.push(required_probe("tun_address", {
        let config = config.clone();
        move |cancellation| {
            let config = config.clone();
            async move {
                let link = read_link(&config.interface, cancellation).await?;
                if link.addr_info.iter().any(|address| {
                    address.family == "inet"
                        && address.local == config.gateway
                        && address.prefix_len == config.pool.prefix_len()
                }) {
                    return Ok(());
                }
                bail!(
                    "{} lacks gateway address {}/{}",
                    config.interface,
                    config.gateway,
                    config.pool.prefix_len()
                )
            }
        }
    }));
    checks.push(required_probe("tun_mtu", {
        let config = config.clone();
        move |cancellation| {
            let config = config.clone();
            async move {
                let link = read_link(&config.interface, cancellation).await?;
                if link.mtu != config.mtu {
                    bail!(
                        "interface {} MTU is {}, want {}",
                        config.interface,
                        link.mtu,
                        config.mtu
                    );
                }
                Ok(())
            }
        }
    }));
    checks.push(required_probe("pool_route", {
        let config = config.clone();
        move |cancellation| {
            let config = config.clone();
            async move {
                let routes = read_routes(
                    &["exact".to_string(), config.pool.to_string()],
                    cancellation,
                )
                .await?;
                if routes.iter().any(|route| {
                    route.destination == config.pool.to_string()
                        && route.device == config.interface
                        && route.usable()
                }) {
                    return Ok(());
                }
                bail!("no pool route through {}", config.interface)
            }
        }
    }));
    checks.push(required_probe("egress_route", {
        let config = config.clone();
        move |cancellation| {
            let config = config.clone();
            async move {
                readiness_egress(&config, cancellation).await?;
                Ok(())
            }
        }
    }));
    checks.push(required_probe("ipv4_forwarding", {
        move |cancellation| async move {
            let value = read_file("/proc/sys/net/ipv4/ip_forward", cancellation).await?;
            if value.trim() != "1" {
                bail!("net.ipv4.ip_forward is not enabled");
            }
            Ok(())
        }
    }));
    checks.push(required_probe("porta_forward_rules", {
        let config = config.clone();
        move |cancellation| {
            let config = config.clone();
            async move { check_porta_rules(&config, false, cancellation).await }
        }
    }));
    checks.push(optional_or_required_probe(
        "porta_nat_rules",
        config.require_nat,
        config.require_nat.then(|| {
            let config = config.clone();
            move |cancellation| {
                let config = config.clone();
                async move { check_porta_rules(&config, true, cancellation).await }
            }
        }),
    ));
    checks.push(optional_or_required_probe(
        "porta_input_guard",
        config.require_input_guard,
        config.require_input_guard.then(|| {
            let config = config.clone();
            move |cancellation| {
                let config = config.clone();
                async move { check_porta_input_guard(&config, cancellation).await }
            }
        }),
    ));
    checks.push(optional_probe(
        "external_egress",
        config.egress_url.clone().map(|url| {
            move |cancellation| {
                let url = url.clone();
                async move { probe_http(&url, cancellation).await }
            }
        }),
    ));
    checks.push(optional_probe(
        "external_dns",
        config
            .dns_name
            .clone()
            .zip(config.dns_address)
            .map(|(name, server)| {
                move |cancellation| {
                    let name = name.clone();
                    async move { probe_dns(server, &name, cancellation).await }
                }
            }),
    ));
    checks.push(optional_or_required_probe(
        "mtu_feedback",
        config.auto_mtu,
        config.auto_mtu.then(|| {
            let interface = config.interface.clone();
            move |cancellation| {
                let interface = interface.clone();
                async move { check_mtu_feedback(&interface, cancellation).await }
            }
        }),
    ));

    Ok(Readiness::new(checks, config.timeout))
}

fn validate_config(config: &SystemReadinessConfig) -> Result<()> {
    if config.timeout.is_zero() {
        bail!("--readiness-timeout must be positive");
    }
    if config.interface.is_empty() {
        bail!("readiness interface must not be empty");
    }
    if config.mtu == 0 {
        bail!("readiness MTU must be positive");
    }
    if config.require_input_guard && config.public_port == 0 {
        bail!("public listener port is invalid for input-guard readiness");
    }
    if let Some(url) = config.egress_url.as_deref() {
        let parsed = reqwest::Url::parse(url)
            .context("--readiness-egress-url must be an HTTP(S) URL without credentials")?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            bail!("--readiness-egress-url must be an HTTP(S) URL without credentials");
        }
    }
    if config.dns_name.is_some() && config.dns_address.is_none() {
        bail!("--dns must be an IP address when --readiness-dns-name is configured");
    }
    Ok(())
}

fn required_probe<F, Fut>(name: &str, probe: F) -> ReadinessCheck
where
    F: Fn(CancellationToken) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    ReadinessCheck {
        name: name.to_string(),
        required: true,
        probe: Some(boxed_probe(probe)),
    }
}

fn optional_probe<F, Fut>(name: &str, probe: Option<F>) -> ReadinessCheck
where
    F: Fn(CancellationToken) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    optional_or_required_probe(name, false, probe)
}

fn optional_or_required_probe<F, Fut>(
    name: &str,
    required: bool,
    probe: Option<F>,
) -> ReadinessCheck
where
    F: Fn(CancellationToken) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    ReadinessCheck {
        name: name.to_string(),
        required,
        probe: probe.map(boxed_probe),
    }
}

fn boxed_probe<F, Fut>(probe: F) -> Probe
where
    F: Fn(CancellationToken) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    Arc::new(move |cancellation| probe(cancellation).boxed())
}

#[derive(Debug, Deserialize)]
struct Link {
    ifname: String,
    #[serde(default)]
    flags: Vec<String>,
    mtu: u32,
    #[serde(default)]
    addr_info: Vec<LinkAddress>,
}

#[derive(Debug, Deserialize)]
struct LinkAddress {
    family: String,
    local: Ipv4Addr,
    #[serde(rename = "prefixlen")]
    prefix_len: u8,
}

async fn read_link(interface: &str, cancellation: CancellationToken) -> Result<Link> {
    let arguments = ["-j", "-4", "address", "show", "dev", interface];
    let data = run_command("ip", &arguments, cancellation).await?;
    let mut links: Vec<Link> = serde_json::from_slice(&data).context("decode interface state")?;
    if links.len() != 1 || links[0].ifname != interface {
        bail!("interface {interface} was not found");
    }
    Ok(links.remove(0))
}

#[derive(Clone, Debug, Deserialize)]
struct ReadinessRoute {
    #[serde(default, rename = "dst")]
    destination: String,
    #[serde(default, rename = "dev")]
    device: String,
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    metric: i64,
    #[serde(default)]
    flags: Vec<String>,
}

impl ReadinessRoute {
    fn usable(&self) -> bool {
        (self.kind.is_empty() || self.kind == "unicast")
            && !self.flags.iter().any(|flag| flag == "linkdown")
    }
}

async fn read_routes(
    selector: &[String],
    cancellation: CancellationToken,
) -> Result<Vec<ReadinessRoute>> {
    let mut arguments = vec![
        "-j".to_string(),
        "-4".to_string(),
        "route".to_string(),
        "show".to_string(),
    ];
    arguments.extend_from_slice(selector);
    let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let data = run_command("ip", &borrowed, cancellation).await?;
    serde_json::from_slice(&data).context("decode routes")
}

async fn readiness_egress(
    config: &SystemReadinessConfig,
    cancellation: CancellationToken,
) -> Result<String> {
    let mut routes = read_routes(&["default".to_string()], cancellation.clone()).await?;
    if routes.is_empty() {
        bail!("no default route");
    }
    routes.sort_by_key(|route| route.metric);
    let route = &routes[0];
    if route.device.is_empty()
        || route.device == config.interface
        || !route.usable()
        || config
            .egress_interface
            .as_deref()
            .is_some_and(|interface| !interface.is_empty() && interface != route.device)
    {
        bail!("preferred default route is not usable on the configured egress interface");
    }
    if routes
        .iter()
        .skip(1)
        .any(|other| other.metric == route.metric && other.device != route.device)
    {
        bail!("default routes have ambiguous equal-priority egress interfaces");
    }
    let link = read_link(&route.device, cancellation).await?;
    if !link.flags.iter().any(|flag| flag == "UP") {
        bail!("egress interface {} is down", route.device);
    }
    Ok(route.device.clone())
}

async fn check_mtu_feedback(interface: &str, cancellation: CancellationToken) -> Result<()> {
    let accept_local = read_file(
        &format!("/proc/sys/net/ipv4/conf/{interface}/accept_local"),
        cancellation.clone(),
    )
    .await?;
    if accept_local.trim() != "1" {
        bail!("automatic MTU requires net/ipv4/conf/{interface}/accept_local=1 for ICMP feedback");
    }
    let mut effective_rpf = 0u8;
    for name in ["all", interface] {
        let path = format!("/proc/sys/net/ipv4/conf/{name}/rp_filter");
        let value = read_file(&path, cancellation.clone()).await?;
        let setting = value
            .trim()
            .parse::<u8>()
            .ok()
            .filter(|setting| *setting <= 2)
            .ok_or_else(|| anyhow!("invalid rp_filter setting at {path}"))?;
        effective_rpf = effective_rpf.max(setting);
    }
    if effective_rpf == 1 {
        bail!(
            "strict reverse-path filtering blocks MTU feedback; set net/ipv4/conf/{interface}/rp_filter=2"
        );
    }
    Ok(())
}

async fn read_file(path: &str, cancellation: CancellationToken) -> Result<String> {
    tokio::select! {
        _ = cancellation.cancelled() => bail!("operation cancelled"),
        result = tokio::fs::read_to_string(path) => {
            result.with_context(|| format!("read {path}"))
        }
    }
}

async fn run_command(
    program: &str,
    arguments: &[&str],
    cancellation: CancellationToken,
) -> Result<Vec<u8>> {
    let mut command = tokio::process::Command::new(program);
    command
        .args(arguments)
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let output = tokio::select! {
        _ = cancellation.cancelled() => bail!("operation cancelled"),
        output = command.output() => output.with_context(|| format!("execute {program}"))?,
    };
    if !output.status.success() {
        bail!(
            "{program}: exit status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

async fn probe_http(url: &str, cancellation: CancellationToken) -> Result<()> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build readiness HTTP client")?;
    let mut response = tokio::select! {
        _ = cancellation.cancelled() => bail!("operation cancelled"),
        response = client.get(url).send() => response?,
    };
    if !response.status().is_success() {
        bail!("egress HTTP status {}", response.status().as_u16());
    }
    let mut read = 0usize;
    while read < 4096 {
        let chunk = tokio::select! {
            _ = cancellation.cancelled() => bail!("operation cancelled"),
            chunk = response.chunk() => chunk?,
        };
        let Some(chunk) = chunk else {
            break;
        };
        read += chunk.len().min(4096 - read);
    }
    Ok(())
}

async fn probe_dns(server: IpAddr, name: &str, cancellation: CancellationToken) -> Result<()> {
    let id = rand::random::<u16>();
    let query = dns_query(id, name)?;
    let bind = match server {
        IpAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        IpAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(SocketAddr::new(server, 53)).await?;
    tokio::select! {
        _ = cancellation.cancelled() => bail!("operation cancelled"),
        result = socket.send(&query) => {
            if result? != query.len() {
                bail!("short DNS query write");
            }
        }
    }
    let mut response = [0u8; 4096];
    let length = tokio::select! {
        _ = cancellation.cancelled() => bail!("operation cancelled"),
        result = socket.recv(&mut response) => result?,
    };
    let response = &response[..length];
    if response.len() < 12 || u16::from_be_bytes([response[0], response[1]]) != id {
        bail!("invalid DNS response");
    }
    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & 0x8000 == 0 {
        bail!("DNS response bit is not set");
    }
    if flags & 0x0200 != 0 {
        return probe_dns_tcp(server, &query, id, cancellation).await;
    }
    validate_dns_response(response)
}

async fn probe_dns_tcp(
    server: IpAddr,
    query: &[u8],
    id: u16,
    cancellation: CancellationToken,
) -> Result<()> {
    let mut stream = tokio::select! {
        _ = cancellation.cancelled() => bail!("operation cancelled"),
        result = TcpStream::connect(SocketAddr::new(server, 53)) => result?,
    };
    let length = u16::try_from(query.len()).context("DNS query is too large")?;
    tokio::select! {
        _ = cancellation.cancelled() => bail!("operation cancelled"),
        result = async {
            stream.write_all(&length.to_be_bytes()).await?;
            stream.write_all(query).await
        } => result?,
    }
    let response_length = tokio::select! {
        _ = cancellation.cancelled() => bail!("operation cancelled"),
        result = stream.read_u16() => result? as usize,
    };
    let mut response = vec![0; response_length];
    tokio::select! {
        _ = cancellation.cancelled() => bail!("operation cancelled"),
        result = stream.read_exact(&mut response) => {
            result?;
        }
    }
    if response.len() < 2 || u16::from_be_bytes([response[0], response[1]]) != id {
        bail!("invalid DNS response");
    }
    validate_dns_response(&response)
}

fn dns_query(id: u16, name: &str) -> Result<Vec<u8>> {
    let mut query = Vec::with_capacity(name.len() + 18);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            bail!("invalid DNS probe name");
        }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    Ok(query)
}

fn validate_dns_response(response: &[u8]) -> Result<()> {
    if response.len() < 12 {
        bail!("invalid DNS response");
    }
    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & 0x000f != 0 {
        bail!("DNS query failed with response code {}", flags & 0x000f);
    }
    let questions = u16::from_be_bytes([response[4], response[5]]) as usize;
    let answers = u16::from_be_bytes([response[6], response[7]]) as usize;
    let mut offset = 12;
    for _ in 0..questions {
        offset = skip_dns_name(response, offset)?;
        offset = offset.checked_add(4).context("invalid DNS question")?;
        if offset > response.len() {
            bail!("invalid DNS question");
        }
    }
    for _ in 0..answers {
        offset = skip_dns_name(response, offset)?;
        if offset + 10 > response.len() {
            bail!("invalid DNS answer");
        }
        let record_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let class = u16::from_be_bytes([response[offset + 2], response[offset + 3]]);
        let data_length = u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
        offset += 10;
        if offset + data_length > response.len() {
            bail!("invalid DNS answer");
        }
        if record_type == 1 && class == 1 && data_length == 4 {
            return Ok(());
        }
        offset += data_length;
    }
    bail!("DNS query returned no IPv4 addresses")
}

fn skip_dns_name(message: &[u8], mut offset: usize) -> Result<usize> {
    loop {
        let length = *message.get(offset).context("invalid DNS name")?;
        offset += 1;
        if length == 0 {
            return Ok(offset);
        }
        if length & 0xc0 == 0xc0 {
            if message.get(offset).is_none() {
                bail!("invalid DNS name");
            }
            return Ok(offset + 1);
        }
        if length & 0xc0 != 0 || offset + length as usize > message.len() {
            bail!("invalid DNS name");
        }
        offset += length as usize;
    }
}

#[derive(Debug, Deserialize)]
struct NftChain {
    name: String,
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    hook: String,
    #[serde(default, rename = "prio")]
    priority: i64,
    #[serde(default)]
    policy: String,
}

#[derive(Clone, Debug, Deserialize)]
struct NftRule {
    chain: String,
    expr: Vec<Map<String, Value>>,
}

#[derive(Debug, Deserialize)]
struct NftDocument {
    nftables: Vec<NftEntry>,
}

#[derive(Debug, Deserialize)]
struct NftEntry {
    #[serde(default)]
    chain: Option<NftChain>,
    #[serde(default)]
    rule: Option<NftRule>,
}

async fn check_porta_rules(
    config: &SystemReadinessConfig,
    nat: bool,
    cancellation: CancellationToken,
) -> Result<()> {
    let egress = readiness_egress(config, cancellation.clone()).await?;
    let data = run_command("nft", &["-j", "list", "table", "ip", "porta"], cancellation).await?;
    let table: NftDocument =
        serde_json::from_slice(&data).context("decode Porta nftables rules")?;
    let (chain_name, chain_type, hook) = if nat {
        ("postrouting", "nat", "postrouting")
    } else {
        ("forward", "filter", "forward")
    };
    let mut found_chain = false;
    let mut rules = Vec::new();
    for entry in table.nftables {
        if let Some(chain) = entry.chain {
            if chain.name == chain_name {
                found_chain =
                    chain.kind == chain_type && chain.hook == hook && chain.policy == "accept";
            }
        }
        if let Some(rule) = entry.rule {
            if rule.chain == chain_name {
                rules.push(rule);
            }
        }
    }
    if !found_chain {
        bail!("Porta {chain_name} base chain is missing or has the wrong hook/type/policy");
    }
    if nat {
        if !rules.first().is_some_and(|rule| {
            matches_porta_rule(rule, "", &egress, Some(config.pool), false, "masquerade")
        }) {
            bail!("Porta pool masquerade rule is missing or preceded by another rule");
        }
    } else if rules.len() < 2
        || !matches_porta_rule(&rules[0], &config.interface, &egress, None, false, "accept")
        || !matches_porta_rule(&rules[1], &egress, &config.interface, None, true, "accept")
    {
        bail!(
            "Porta outbound/established-return forwarding rules are missing or preceded by other rules"
        );
    }
    Ok(())
}

async fn check_porta_input_guard(
    config: &SystemReadinessConfig,
    cancellation: CancellationToken,
) -> Result<()> {
    let egress = readiness_egress(config, cancellation.clone()).await?;
    let data = run_command(
        "nft",
        &["-j", "list", "table", "inet", "porta_guard"],
        cancellation,
    )
    .await?;
    let table: NftDocument = serde_json::from_slice(&data).context("decode Porta input guard")?;
    let mut found_chain = false;
    let mut rules = Vec::new();
    for entry in table.nftables {
        if let Some(chain) = entry.chain {
            if chain.name == "input" {
                found_chain = chain.kind == "filter"
                    && chain.hook == "input"
                    && chain.priority == -10
                    && chain.policy == "accept";
            }
        }
        if let Some(rule) = entry.rule {
            if rule.chain == "input" {
                rules.push(rule);
            }
        }
    }
    if !found_chain {
        bail!("Porta input guard base chain is missing or has the wrong hook/type/priority/policy");
    }
    let expected = [
        InputGuardRule::new("tcp", "ip", "tcp4", 200, 400, true),
        InputGuardRule::new("tcp", "ip6", "tcp6", 200, 400, true),
        InputGuardRule::new("udp", "ip", "udp4", 500, 1000, false),
        InputGuardRule::new("udp", "ip6", "udp6", 500, 1000, false),
    ];
    if rules.len() != expected.len() {
        bail!(
            "Porta input guard has {} rules, want {}",
            rules.len(),
            expected.len()
        );
    }
    for (index, (rule, expected)) in rules.iter().zip(expected.iter()).enumerate() {
        if !matches_input_guard_rule(rule, &egress, config.public_port, expected) {
            bail!(
                "Porta input guard rule {} is missing or malformed",
                index + 1
            );
        }
    }
    Ok(())
}

struct InputGuardRule {
    protocol: &'static str,
    address_protocol: &'static str,
    meter: &'static str,
    rate: u64,
    burst: u64,
    tcp_flags: bool,
}

impl InputGuardRule {
    const fn new(
        protocol: &'static str,
        address_protocol: &'static str,
        meter: &'static str,
        rate: u64,
        burst: u64,
        tcp_flags: bool,
    ) -> Self {
        Self {
            protocol,
            address_protocol,
            meter,
            rate,
            burst,
            tcp_flags,
        }
    }
}

fn matches_input_guard_rule(
    rule: &NftRule,
    interface: &str,
    port: u16,
    expected: &InputGuardRule,
) -> bool {
    let wanted = if expected.tcp_flags { 7 } else { 6 };
    if rule.expr.len() != wanted
        || !matches_meta(&rule.expr[0], "iifname", interface)
        || !matches_payload(
            &rule.expr[1],
            expected.protocol,
            "dport",
            &Value::from(port),
        )
        || !matches_new_state(&rule.expr[2])
    {
        return false;
    }
    let mut index = 3;
    if expected.tcp_flags {
        if !matches_initial_syn(&rule.expr[index]) {
            return false;
        }
        index += 1;
    }
    matches_input_meter(&rule.expr[index], expected)
        && rule.expr[index + 1]
            .get("counter")
            .is_some_and(|counter| !counter.is_null())
        && has_null_verdict(&rule.expr[index + 2], "drop")
}

fn matches_meta(expression: &Map<String, Value>, key: &str, right: &str) -> bool {
    let Some(matcher) = expression.get("match").and_then(Value::as_object) else {
        return false;
    };
    matcher.get("op").and_then(Value::as_str) == Some("==")
        && matcher.get("right").and_then(Value::as_str) == Some(right)
        && matcher
            .get("left")
            .and_then(Value::as_object)
            .and_then(|left| left.get("meta"))
            .and_then(Value::as_object)
            .and_then(|meta| meta.get("key"))
            .and_then(Value::as_str)
            == Some(key)
}

fn matches_payload(
    expression: &Map<String, Value>,
    protocol: &str,
    field: &str,
    right: &Value,
) -> bool {
    let Some(matcher) = expression.get("match").and_then(Value::as_object) else {
        return false;
    };
    let payload = matcher
        .get("left")
        .and_then(Value::as_object)
        .and_then(|left| left.get("payload"))
        .and_then(Value::as_object);
    matcher.get("op").and_then(Value::as_str) == Some("==")
        && matcher.get("right") == Some(right)
        && payload
            .and_then(|payload| payload.get("protocol"))
            .and_then(Value::as_str)
            == Some(protocol)
        && payload
            .and_then(|payload| payload.get("field"))
            .and_then(Value::as_str)
            == Some(field)
}

fn matches_new_state(expression: &Map<String, Value>) -> bool {
    let Some(matcher) = expression.get("match").and_then(Value::as_object) else {
        return false;
    };
    if !matches!(matcher.get("op").and_then(Value::as_str), Some("in" | "=="))
        || matcher
            .get("left")
            .and_then(Value::as_object)
            .and_then(|left| left.get("ct"))
            .and_then(Value::as_object)
            .and_then(|ct| ct.get("key"))
            .and_then(Value::as_str)
            != Some("state")
    {
        return false;
    }
    match matcher.get("right") {
        Some(Value::String(state)) => state == "new",
        Some(Value::Array(states)) => states.as_slice() == [Value::from("new")],
        Some(Value::Object(object)) => object
            .get("set")
            .and_then(Value::as_array)
            .is_some_and(|states| states.as_slice() == [Value::from("new")]),
        _ => false,
    }
}

fn matches_initial_syn(expression: &Map<String, Value>) -> bool {
    let Some(matcher) = expression.get("match").and_then(Value::as_object) else {
        return false;
    };
    let Some(bitwise) = matcher
        .get("left")
        .and_then(Value::as_object)
        .and_then(|left| left.get("&"))
        .and_then(Value::as_array)
    else {
        return false;
    };
    if matcher.get("op").and_then(Value::as_str) != Some("==")
        || matcher.get("right").and_then(Value::as_str) != Some("syn")
        || bitwise.len() != 2
    {
        return false;
    }
    let payload = bitwise[0]
        .as_object()
        .and_then(|value| value.get("payload"))
        .and_then(Value::as_object);
    let flags = bitwise[1].as_array();
    payload
        .and_then(|payload| payload.get("protocol"))
        .and_then(Value::as_str)
        == Some("tcp")
        && payload
            .and_then(|payload| payload.get("field"))
            .and_then(Value::as_str)
            == Some("flags")
        && flags.is_some_and(|flags| {
            flags.len() == 4
                && ["fin", "syn", "rst", "ack"]
                    .iter()
                    .all(|flag| flags.contains(&Value::from(*flag)))
        })
}

fn matches_input_meter(expression: &Map<String, Value>, expected: &InputGuardRule) -> bool {
    let Some(meter) = expression.get("meter").and_then(Value::as_object) else {
        return false;
    };
    if meter.get("name").and_then(Value::as_str) != Some(expected.meter)
        || meter.get("size").and_then(Value::as_u64) != Some(65535)
    {
        return false;
    }
    let Some(element) = meter
        .get("key")
        .and_then(Value::as_object)
        .and_then(|key| key.get("elem"))
        .and_then(Value::as_object)
    else {
        return false;
    };
    let payload = element
        .get("val")
        .and_then(Value::as_object)
        .and_then(|value| value.get("payload"))
        .and_then(Value::as_object);
    if payload
        .and_then(|payload| payload.get("protocol"))
        .and_then(Value::as_str)
        != Some(expected.address_protocol)
        || payload
            .and_then(|payload| payload.get("field"))
            .and_then(Value::as_str)
            != Some("saddr")
        || element.get("timeout").and_then(Value::as_u64) != Some(10)
    {
        return false;
    }
    let Some(limit) = meter
        .get("stmt")
        .and_then(Value::as_object)
        .and_then(|statement| statement.get("limit"))
        .and_then(Value::as_object)
    else {
        return false;
    };
    !limit.contains_key("rate_unit")
        && !limit.contains_key("burst_unit")
        && limit.get("rate").and_then(Value::as_u64) == Some(expected.rate)
        && limit.get("burst").and_then(Value::as_u64) == Some(expected.burst)
        && limit.get("per").and_then(Value::as_str) == Some("second")
        && limit.get("inv").and_then(Value::as_bool) == Some(true)
}

fn has_null_verdict(expression: &Map<String, Value>, verdict: &str) -> bool {
    expression.get(verdict).is_some_and(Value::is_null)
}

fn matches_porta_rule(
    rule: &NftRule,
    input: &str,
    output: &str,
    pool: Option<Ipv4Net>,
    established: bool,
    verdict: &str,
) -> bool {
    let mut wanted = BTreeSet::from(["oifname", verdict]);
    if !input.is_empty() {
        wanted.insert("iifname");
    }
    if pool.is_some() {
        wanted.insert("source");
    }
    if established {
        wanted.insert("state");
    }
    for expression in &rule.expr {
        if expression.len() != 1 {
            return false;
        }
        if expression.contains_key("counter") {
            continue;
        }
        if has_null_verdict(expression, verdict) {
            wanted.remove(verdict);
            continue;
        }
        let Some(matcher) = expression.get("match").and_then(Value::as_object) else {
            return false;
        };
        let Some(left) = matcher.get("left").and_then(Value::as_object) else {
            return false;
        };
        if matcher.get("op").and_then(Value::as_str) == Some("==") {
            if let Some(key) = left
                .get("meta")
                .and_then(Value::as_object)
                .and_then(|meta| meta.get("key"))
                .and_then(Value::as_str)
            {
                match key {
                    "iifname"
                        if !input.is_empty()
                            && matcher.get("right").and_then(Value::as_str) == Some(input) =>
                    {
                        wanted.remove("iifname");
                        continue;
                    }
                    "oifname" if matcher.get("right").and_then(Value::as_str) == Some(output) => {
                        wanted.remove("oifname");
                        continue;
                    }
                    _ => return false,
                }
            }
            if let Some(pool) = pool {
                let payload = left.get("payload").and_then(Value::as_object);
                let prefix = matcher
                    .get("right")
                    .and_then(Value::as_object)
                    .and_then(|right| right.get("prefix"))
                    .and_then(Value::as_object);
                if payload
                    .and_then(|payload| payload.get("protocol"))
                    .and_then(Value::as_str)
                    == Some("ip")
                    && payload
                        .and_then(|payload| payload.get("field"))
                        .and_then(Value::as_str)
                        == Some("saddr")
                    && prefix
                        .and_then(|prefix| prefix.get("addr"))
                        .and_then(Value::as_str)
                        .is_some_and(|address| address == pool.network().to_string())
                    && prefix
                        .and_then(|prefix| prefix.get("len"))
                        .and_then(Value::as_u64)
                        == Some(pool.prefix_len() as u64)
                {
                    wanted.remove("source");
                    continue;
                }
            }
        }
        if established
            && left
                .get("ct")
                .and_then(Value::as_object)
                .and_then(|ct| ct.get("key"))
                .and_then(Value::as_str)
                == Some("state")
            && matches!(matcher.get("op").and_then(Value::as_str), Some("in" | "=="))
        {
            let states = match matcher.get("right") {
                Some(Value::Array(states)) => Some(states),
                Some(Value::Object(object)) => object.get("set").and_then(Value::as_array),
                _ => None,
            };
            if states.is_some_and(|states| {
                states.len() == 2
                    && states.contains(&Value::from("established"))
                    && states.contains(&Value::from("related"))
            }) {
                wanted.remove("state");
                continue;
            }
        }
        return false;
    }
    wanted.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rule(expressions: Value) -> NftRule {
        serde_json::from_value(json!({"chain": "forward", "expr": expressions})).unwrap()
    }

    #[test]
    fn validates_readiness_configuration_without_network_access() {
        let base = SystemReadinessConfig {
            interface: "porta0".to_string(),
            gateway: "10.66.0.1".parse().unwrap(),
            pool: "10.66.0.0/24".parse().unwrap(),
            mtu: 1400,
            egress_interface: Some("eth0".to_string()),
            require_nat: true,
            require_input_guard: true,
            public_port: 8443,
            auto_mtu: true,
            timeout: Duration::from_secs(1),
            egress_url: None,
            dns_name: None,
            dns_address: None,
        };
        assert!(validate_config(&base).is_ok());
        assert!(system_readiness(base.clone()).is_ok());

        let mut invalid = base.clone();
        invalid.timeout = Duration::ZERO;
        assert!(validate_config(&invalid).is_err());
        invalid = base.clone();
        invalid.egress_url = Some("https://user@example.com/".to_string());
        assert!(validate_config(&invalid).is_err());
        invalid = base;
        invalid.dns_name = Some("health.example".to_string());
        assert!(validate_config(&invalid).is_err());
    }

    #[test]
    fn forwarding_state_encodings_match_go_behavior_exactly() {
        for (states, expected) in [
            (json!(["established", "related"]), true),
            (json!({"set": ["established", "related"]}), true),
            (json!(["related", "established"]), true),
            (json!(["established"]), false),
            (json!(["established", "related", "new"]), false),
            (json!({"set": ["established", "new"]}), false),
            (json!("established"), false),
        ] {
            let rule = rule(json!([
                {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}},
                {"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"porta0"}},
                {"match":{"op":"in","left":{"ct":{"key":"state"}},"right":states}},
                {"accept":null}
            ]));
            assert_eq!(
                matches_porta_rule(&rule, "eth0", "porta0", None, true, "accept"),
                expected,
                "{states}"
            );
        }
    }

    #[test]
    fn nat_rule_is_scoped_to_egress_and_pool() {
        let valid = rule(json!([
            {"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"eth0"}},
            {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},
                "right":{"prefix":{"addr":"10.66.0.0","len":24}}}},
            {"masquerade":null}
        ]));
        let pool = Some("10.66.0.0/24".parse().unwrap());
        assert!(matches_porta_rule(
            &valid,
            "",
            "eth0",
            pool,
            false,
            "masquerade"
        ));

        let wrong_pool = rule(json!([
            {"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"eth0"}},
            {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},
                "right":{"prefix":{"addr":"10.99.0.0","len":24}}}},
            {"masquerade":null}
        ]));
        assert!(!matches_porta_rule(
            &wrong_pool,
            "",
            "eth0",
            pool,
            false,
            "masquerade"
        ));
    }

    #[test]
    fn input_guard_rejects_malformed_meter_and_ordering() {
        let expected = InputGuardRule::new("tcp", "ip", "tcp4", 200, 400, true);
        let expressions = json!([
            {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}},
            {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":8443}},
            {"match":{"op":"in","left":{"ct":{"key":"state"}},"right":"new"}},
            {"match":{"op":"==","left":{"&":[{"payload":{"protocol":"tcp","field":"flags"}},
                ["fin","syn","rst","ack"]]},"right":"syn"}},
            {"meter":{"key":{"elem":{"val":{"payload":{"protocol":"ip","field":"saddr"}},
                "timeout":10}},"stmt":{"limit":{"rate":200,"burst":400,"per":"second","inv":true}},
                "size":65535,"name":"tcp4"}},
            {"counter":{"packets":0,"bytes":0}},
            {"drop":null}
        ]);
        let valid = rule(expressions.clone());
        assert!(matches_input_guard_rule(&valid, "eth0", 8443, &expected));

        let mut malformed = expressions.as_array().unwrap().clone();
        malformed[0] = json!({"meter":{"name":"tcp4"}});
        assert!(!matches_input_guard_rule(
            &rule(Value::Array(malformed)),
            "eth0",
            8443,
            &expected
        ));

        let mut byte_rate = expressions.as_array().unwrap().clone();
        byte_rate[4]["meter"]["stmt"]["limit"]["rate_unit"] = json!("mbytes");
        assert!(!matches_input_guard_rule(
            &rule(Value::Array(byte_rate)),
            "eth0",
            8443,
            &expected
        ));
    }
}
