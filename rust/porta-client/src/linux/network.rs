use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ipnet::IpNet;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::io::AsyncWriteExt as _;
use tokio::process::Command;
use tokio::time::timeout;

use crate::tunnel::Lease;

const STATE_VERSION: u8 = 2;
const ROUTE_PROTOCOL: u16 = 186;
const MAX_STATE_SIZE: u64 = 1024 * 1024;
const MAX_ENDPOINTS: usize = 256;
const MAX_ACTIONS: usize = 2048;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("{0}")]
    Invalid(String),
    #[error("{action}: {source}")]
    Io {
        action: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("{command}: {detail}")]
    Command { command: String, detail: String },
    #[error("decode network recovery state: {0}")]
    Decode(#[from] serde_json::Error),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EndpointState {
    ip: String,
    port: u16,
}

impl EndpointState {
    fn address(&self) -> Result<IpAddr, NetworkError> {
        self.ip
            .parse()
            .map_err(|_| NetworkError::Invalid("invalid network journal endpoint".to_owned()))
    }

    fn prefix(&self) -> Result<String, NetworkError> {
        let address = self.address()?;
        Ok(format!(
            "{address}/{}",
            if address.is_ipv4() { 32 } else { 128 }
        ))
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
struct Action {
    kind: String,
    interface: String,
    index: u32,
    #[serde(skip_serializing_if = "String::is_empty")]
    link_kind: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    link_address: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    link_alias: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    previous_alias: String,
    #[serde(skip_serializing_if = "is_zero_u8")]
    family: u8,
    #[serde(skip_serializing_if = "String::is_empty")]
    destination: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    gateway: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    address: String,
    #[serde(skip_serializing_if = "is_zero_u16")]
    mtu: u16,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    was_up: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct NetworkState {
    version: u8,
    table: String,
    metric: u32,
    #[serde(skip_serializing_if = "String::is_empty")]
    interface: String,
    #[serde(skip_serializing_if = "is_zero_u32")]
    index: u32,
    endpoints: Vec<EndpointState>,
    undo: Vec<Action>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct LinkInfo {
    #[serde(rename = "ifindex")]
    index: u32,
    #[serde(rename = "ifname")]
    name: String,
    #[serde(default)]
    address: String,
    #[serde(default, rename = "ifalias")]
    alias: String,
    mtu: u32,
    #[serde(default)]
    flags: Vec<String>,
    #[serde(default, rename = "linkinfo")]
    link_info: LinkKind,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct LinkKind {
    #[serde(default, rename = "info_kind")]
    kind: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct RouteInfo {
    #[serde(default, rename = "dst")]
    destination: String,
    #[serde(default, rename = "dev")]
    device: String,
    #[serde(default)]
    gateway: String,
    #[serde(default)]
    metric: u32,
    #[serde(default)]
    protocol: Value,
    #[serde(default, rename = "type")]
    route_type: String,
    #[serde(default)]
    multipath: Value,
    #[serde(default)]
    nexthops: Value,
    #[serde(default)]
    nhid: u32,
}

impl RouteInfo {
    fn is_multipath(&self) -> bool {
        !self.multipath.is_null() || !self.nexthops.is_null() || self.nhid != 0
    }
}

pub struct NetworkManager {
    state_path: PathBuf,
    _lock: File,
    state: NetworkState,
    commands: Arc<dyn CommandRunner>,
}

impl NetworkManager {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, NetworkError> {
        Self::open_with_commands(path.into(), Arc::new(SystemCommandRunner))
    }

    fn open_with_commands(
        state_path: PathBuf,
        commands: Arc<dyn CommandRunner>,
    ) -> Result<Self, NetworkError> {
        if state_path.as_os_str().is_empty() || state_path.file_name().is_none() {
            return Err(NetworkError::Invalid(
                "network recovery state path is required".to_owned(),
            ));
        }
        let state_path = absolute(state_path)?;
        prepare_directory(&state_path)?;
        let lock = open_lock(&lock_path(&state_path))?;
        let state = match read_state(&state_path)? {
            Some(state) => {
                validate_state(&state)?;
                state
            }
            None => NetworkState::default(),
        };
        Ok(Self {
            state_path,
            _lock: lock,
            state,
            commands,
        })
    }

    pub fn recovery_endpoints(&self) -> Result<Vec<SocketAddr>, NetworkError> {
        self.state
            .endpoints
            .iter()
            .map(|endpoint| Ok(SocketAddr::new(endpoint.address()?, endpoint.port)))
            .collect()
    }

    pub async fn prepare(&mut self, endpoint: SocketAddr) -> Result<(), NetworkError> {
        let endpoint = parse_endpoint(endpoint)?;
        self.preflight(&endpoint).await?;
        if self.state.table.is_empty() {
            self.initialize_state()?;
        }
        if !self.state.endpoints.contains(&endpoint) {
            if self.state.endpoints.len() >= MAX_ENDPOINTS {
                return Err(NetworkError::Invalid(
                    "protected endpoint limit reached; explicit cleanup is required".to_owned(),
                ));
            }
            self.state.endpoints.push(endpoint.clone());
            if let Err(error) = self.persist() {
                self.state.endpoints.pop();
                return Err(error);
            }
        }
        self.protect().await?;
        self.ensure_escape(&endpoint).await
    }

    pub async fn up(
        &mut self,
        interface: &str,
        endpoint: SocketAddr,
        lease: Lease,
    ) -> Result<(), NetworkError> {
        validate_lease(interface, lease)?;
        self.prepare(endpoint).await?;
        if lease.dns
            == Some(match endpoint.ip() {
                IpAddr::V4(address) => address,
                IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
            })
        {
            return Err(NetworkError::Invalid(
                "tunnel DNS cannot be the physical transport endpoint".to_owned(),
            ));
        }
        let mut link = self
            .link(interface)
            .await?
            .ok_or_else(|| NetworkError::Invalid("TUN interface does not exist".to_owned()))?;
        if link.link_info.kind != "tun" || !link.flags.iter().any(|flag| flag == "POINTOPOINT") {
            return Err(NetworkError::Invalid(
                "automatic networking requires a point-to-point TUN interface".to_owned(),
            ));
        }
        let alias = format!("porta:{}", self.state.table);
        let mut previous_interface = self.state.interface.as_str();
        let mut previous_index = self.state.index;
        if previous_interface.is_empty() {
            if let Some(action) = self
                .state
                .undo
                .iter()
                .find(|action| matches!(action.kind.as_str(), "link" | "alias"))
            {
                previous_interface = &action.interface;
                previous_index = action.index;
            }
        }
        if !previous_interface.is_empty()
            && (previous_interface != interface
                || previous_index != link.index
                || link.alias != alias)
        {
            self.cleanup_matching(|action| action.kind != "escape")
                .await?;
            self.state.interface.clear();
            self.state.index = 0;
            self.persist()?;
            link = self
                .link(interface)
                .await?
                .ok_or_else(|| NetworkError::Invalid("TUN interface does not exist".to_owned()))?;
        }
        if link.alias != alias {
            if !link.alias.is_empty() {
                return Err(NetworkError::Invalid(
                    "automatic networking refuses to overwrite a pre-existing interface alias"
                        .to_owned(),
                ));
            }
            let action = link_action("alias", &link, &alias);
            self.record(action).await?;
            self.invoke(
                "ip",
                &["link", "set", "dev", interface, "alias", &alias],
                "",
            )
            .await?;
            link.alias = alias.clone();
        }
        if !self.has_action("link", interface, "") {
            if !self.addresses(interface).await?.is_empty() {
                return Err(NetworkError::Invalid(
                    "refusing to configure a TUN interface with pre-existing addresses".to_owned(),
                ));
            }
            let mut action = link_action("link", &link, &alias);
            action.mtu = u16::try_from(link.mtu).map_err(|_| {
                NetworkError::Invalid("TUN interface MTU cannot be restored safely".to_owned())
            })?;
            action.was_up = link.flags.iter().any(|flag| flag == "UP");
            self.record(action).await?;
        }
        if self.state.interface != interface || self.state.index != link.index {
            self.state.interface = interface.to_owned();
            self.state.index = link.index;
            self.persist()?;
        }
        self.invoke(
            "ip",
            &[
                "link",
                "set",
                "dev",
                interface,
                "mtu",
                &lease.mtu.to_string(),
                "up",
            ],
            "",
        )
        .await?;
        let address = lease.address.to_string();
        if !self.has_action("address", interface, &address) {
            let mut action = link_action("address", &link, &alias);
            action.address = address.clone();
            self.record(action).await?;
        }
        if !self.addresses(interface).await?.contains(&address) {
            self.invoke(
                "ip",
                &[
                    "-4",
                    "address",
                    "add",
                    &address,
                    "dev",
                    interface,
                    "noprefixroute",
                ],
                "",
            )
            .await?;
        }
        for destination in ["0.0.0.0/1", "128.0.0.0/1"] {
            let mut action = link_action("route", &link, &alias);
            action.family = 4;
            action.destination = destination.to_owned();
            self.ensure_route(action).await?;
        }
        let dns = lease
            .dns
            .expect("validated automatic Linux lease includes DNS");
        let dns_destination = format!("{dns}/32");
        let mut dns_route = link_action("dns-route", &link, &alias);
        dns_route.family = 4;
        dns_route.destination = dns_destination.clone();
        self.ensure_route(dns_route).await?;
        if !self.has_action("dns", interface, "") {
            for property in ["dns", "domain"] {
                let output = self
                    .invoke("resolvectl", &[property, interface], "")
                    .await?;
                let current = output
                    .trim()
                    .split_once(':')
                    .map(|(_, value)| value.trim())
                    .ok_or_else(|| {
                        NetworkError::Invalid(
                            "could not inspect TUN resolver configuration".to_owned(),
                        )
                    })?;
                if !current.is_empty() {
                    return Err(NetworkError::Invalid(
                        "refusing to overwrite pre-existing TUN resolver configuration".to_owned(),
                    ));
                }
            }
            self.record(link_action("dns", &link, &alias)).await?;
        }
        for arguments in [
            vec!["dns", interface, &dns.to_string()],
            vec!["domain", interface, "~."],
            vec!["default-route", interface, "yes"],
        ] {
            self.invoke("resolvectl", &arguments, "").await?;
        }
        let endpoint = parse_endpoint(endpoint)?;
        let previous = std::mem::replace(&mut self.state.endpoints, vec![endpoint.clone()]);
        if let Err(error) = self.persist() {
            self.state.endpoints = previous;
            return Err(error);
        }
        self.protect().await?;
        let address_copy = address.clone();
        let dns_copy = dns_destination.clone();
        let endpoint_prefix = endpoint.prefix()?;
        self.cleanup_matching(move |action| {
            (action.kind == "address" && action.address != address_copy)
                || (action.kind == "dns-route" && action.destination != dns_copy)
                || (action.kind == "escape" && action.destination != endpoint_prefix)
        })
        .await
    }

    pub async fn down(&mut self) -> Result<(), NetworkError> {
        self.cleanup_matching(|_| true).await?;
        if !self.state.table.is_empty() && self.table_exists().await? {
            let table = self.state.table.clone();
            self.invoke("nft", &["-f", "-"], &format!("delete table inet {table}\n"))
                .await?;
        }
        match fs::remove_file(&self.state_path) {
            Ok(()) => sync_directory(&self.state_path)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(NetworkError::Io {
                    action: "remove network recovery state",
                    source,
                });
            }
        }
        self.state = NetworkState::default();
        Ok(())
    }

    fn initialize_state(&mut self) -> Result<(), NetworkError> {
        let mut random = [0_u8; 8];
        rand::rng().fill_bytes(&mut random);
        self.state = NetworkState {
            version: STATE_VERSION,
            table: format!("porta_{}", hex::encode(random)),
            metric: 40_000 + ((u32::from(random[0]) << 4) + u32::from(random[1])) % 10_001,
            ..NetworkState::default()
        };
        if let Err(error) = self.persist() {
            self.state = NetworkState::default();
            return Err(error);
        }
        Ok(())
    }

    async fn preflight(&self, endpoint: &EndpointState) -> Result<(), NetworkError> {
        self.commands.check_resolver()?;
        self.invoke("resolvectl", &["status"], "").await?;
        self.check_rules(4).await?;
        if endpoint.address()?.is_ipv6() {
            self.check_rules(6).await?;
        }
        Ok(())
    }

    async fn protect(&self) -> Result<(), NetworkError> {
        let exists = self.table_exists().await?;
        let mut script = String::new();
        if exists {
            script.push_str(&format!("flush chain inet {} output\n", self.state.table));
        } else {
            script.push_str(&format!(
                "add table inet {} {{ comment \"Porta client {}\"; }}\n",
                self.state.table, self.state.table
            ));
            script.push_str(&format!(
                "add chain inet {} output {{ type filter hook output priority -150; policy drop; }}\n",
                self.state.table
            ));
        }
        let mut add = |rule: &str| {
            script.push_str(&format!(
                "add rule inet {} output {rule}\n",
                self.state.table
            ));
        };
        add(r#"oifname "lo" accept"#);
        if !self.state.interface.is_empty() {
            if let Some(link) = self
                .action_link(&Action {
                    interface: self.state.interface.clone(),
                    index: self.state.index,
                    link_alias: format!("porta:{}", self.state.table),
                    link_kind: "tun".to_owned(),
                    ..Action::default()
                })
                .await?
            {
                add(&format!(
                    "oifname \"{}\" meta oif {} accept",
                    link.name, link.index
                ));
            }
        }
        add("udp dport { 53, 853 } drop");
        add("tcp dport { 53, 853 } drop");
        let mut ipv6 = false;
        for endpoint in &self.state.endpoints {
            let family = if endpoint.address()?.is_ipv4() {
                "ip"
            } else {
                ipv6 = true;
                "ip6"
            };
            for protocol in ["tcp", "udp"] {
                add(&format!(
                    "{family} daddr {} {protocol} dport {} accept",
                    endpoint.ip, endpoint.port
                ));
            }
        }
        if ipv6 {
            add("ip6 daddr { fe80::/10, ff02::/16 } ip6 hoplimit 255 icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept");
        }
        self.invoke("nft", &["-f", "-"], &script).await?;
        Ok(())
    }

    async fn table_exists(&self) -> Result<bool, NetworkError> {
        let output = self.invoke("nft", &["-j", "list", "tables"], "").await?;
        let listing: Value = serde_json::from_str(&output)?;
        let tables = listing
            .get("nftables")
            .and_then(Value::as_array)
            .ok_or_else(|| NetworkError::Invalid("invalid nftables listing".to_owned()))?;
        let mut found = false;
        for item in tables {
            let Some(table) = item.get("table") else {
                continue;
            };
            if table.get("family").and_then(Value::as_str) == Some("inet")
                && table.get("name").and_then(Value::as_str) == Some(&self.state.table)
            {
                found = true;
                break;
            }
        }
        if !found {
            return Ok(false);
        }
        let output = self
            .invoke(
                "nft",
                &["-j", "list", "table", "inet", &self.state.table],
                "",
            )
            .await?;
        let listing: Value = serde_json::from_str(&output)?;
        let owned = listing
            .get("nftables")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|item| item.get("table"))
            .any(|table| {
                table.get("family").and_then(Value::as_str) == Some("inet")
                    && table.get("name").and_then(Value::as_str) == Some(&self.state.table)
                    && table.get("comment").and_then(Value::as_str)
                        == Some(format!("Porta client {}", self.state.table).as_str())
            });
        if !owned {
            return Err(NetworkError::Invalid(
                "refusing to modify an nftables table without the journal ownership marker"
                    .to_owned(),
            ));
        }
        Ok(true)
    }

    async fn check_rules(&self, family: u8) -> Result<(), NetworkError> {
        let family_argument = format!("-{family}");
        let output = self
            .invoke("ip", &["-j", &family_argument, "rule", "show"], "")
            .await?;
        let rules: Vec<HashMap<String, Value>> = serde_json::from_str(&output)?;
        let mut local = false;
        let mut main = false;
        for rule in rules {
            if rule.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "priority" | "src" | "dst" | "table" | "protocol"
                )
            }) {
                return Err(NetworkError::Invalid(
                    "automatic full tunneling does not support custom policy-routing rules"
                        .to_owned(),
                ));
            }
            let priority = rule.get("priority").and_then(Value::as_u64).unwrap_or(0);
            let table = text_or_number(rule.get("table"));
            let source = rule.get("src").and_then(Value::as_str).unwrap_or_default();
            let destination = rule.get("dst").and_then(Value::as_str).unwrap_or_default();
            if !matches!(source, "" | "all") || !matches!(destination, "" | "all") {
                return Err(NetworkError::Invalid(
                    "automatic full tunneling does not support source/destination policy routing"
                        .to_owned(),
                ));
            }
            match (priority, table.as_str()) {
                (0, "local" | "255") => local = true,
                (32766, "main" | "254") => main = true,
                (32767, "default" | "253") => {}
                _ => {
                    return Err(NetworkError::Invalid(
                        "automatic full tunneling requires the standard local/main/default routing policy"
                            .to_owned(),
                    ));
                }
            }
        }
        if !local || !main {
            return Err(NetworkError::Invalid(
                "automatic full tunneling requires local and main routing rules".to_owned(),
            ));
        }
        Ok(())
    }

    async fn ensure_escape(&mut self, endpoint: &EndpointState) -> Result<(), NetworkError> {
        let family = if endpoint.address()?.is_ipv4() { 4 } else { 6 };
        let destination = endpoint.prefix()?;
        let routes = self.routes(family, Some(("exact", &destination))).await?;
        if routes.len() > 1 {
            return Err(NetworkError::Invalid(
                "multiple endpoint host routes are unsupported".to_owned(),
            ));
        }
        if let Some(route) = routes.first() {
            self.validate_physical_route(route, family).await?;
            return Ok(());
        }
        let family_argument = format!("-{family}");
        let output = self
            .invoke(
                "ip",
                &["-j", &family_argument, "route", "get", &endpoint.ip],
                "",
            )
            .await?;
        let mut candidates: Vec<RouteInfo> = serde_json::from_str(&output)?;
        if candidates.len() != 1 {
            return Err(NetworkError::Invalid(
                "could not determine a unique physical endpoint route".to_owned(),
            ));
        }
        let mut chosen = candidates.remove(0);
        if chosen.device == self.state.interface && !self.state.interface.is_empty() {
            let defaults = self.routes(family, Some(("default", ""))).await?;
            let mut defaults = defaults
                .into_iter()
                .filter(|route| route.device != self.state.interface)
                .collect::<Vec<_>>();
            defaults.sort_by_key(|route| route.metric);
            chosen = defaults.first().cloned().ok_or_else(|| {
                NetworkError::Invalid(
                    "no supported physical gateway route for the tunnel endpoint".to_owned(),
                )
            })?;
            if defaults
                .get(1)
                .is_some_and(|route| route.metric == chosen.metric)
            {
                return Err(NetworkError::Invalid(
                    "multiple equal-cost physical gateways are unsupported".to_owned(),
                ));
            }
        }
        let link = self.validate_physical_route(&chosen, family).await?;
        let action = Action {
            kind: "escape".to_owned(),
            family,
            destination,
            interface: chosen.device,
            index: link.index,
            link_kind: link.link_info.kind,
            link_address: link.address,
            gateway: chosen.gateway,
            ..Action::default()
        };
        self.ensure_route(action).await
    }

    async fn validate_physical_route(
        &self,
        route: &RouteInfo,
        family: u8,
    ) -> Result<LinkInfo, NetworkError> {
        if !valid_interface(&route.device)
            || route.device == self.state.interface
            || !matches!(route.route_type.as_str(), "" | "unicast")
            || route.is_multipath()
        {
            return Err(NetworkError::Invalid(
                "no supported physical gateway route for the tunnel endpoint".to_owned(),
            ));
        }
        let link = self.link(&route.device).await?.ok_or_else(|| {
            NetworkError::Invalid("physical endpoint interface does not exist".to_owned())
        })?;
        if matches!(link.link_info.kind.as_str(), "tun" | "wireguard") {
            return Err(NetworkError::Invalid(
                "tunnel endpoint escape must use a non-tunnel interface".to_owned(),
            ));
        }
        if !route.gateway.is_empty() {
            let gateway: IpAddr = route
                .gateway
                .parse()
                .map_err(|_| NetworkError::Invalid("invalid physical gateway".to_owned()))?;
            if gateway.is_ipv4() != (family == 4) {
                return Err(NetworkError::Invalid("invalid physical gateway".to_owned()));
            }
        }
        Ok(link)
    }

    async fn ensure_route(&mut self, action: Action) -> Result<(), NetworkError> {
        let routes = self
            .routes(action.family, Some(("exact", action.destination.as_str())))
            .await?;
        if routes.len() > 1 {
            return Err(NetworkError::Invalid(format!(
                "multiple routes conflict with owned destination {}",
                action.destination
            )));
        }
        let recorded = self.state.undo.contains(&action);
        if let Some(route) = routes.first() {
            if recorded && self.owned_route(route, &action) {
                return Ok(());
            }
            return Err(NetworkError::Invalid(format!(
                "refusing to overwrite existing route {}",
                action.destination
            )));
        }
        if !recorded {
            self.record(action.clone()).await?;
        }
        let arguments = self.route_arguments("add", &action);
        self.invoke_owned("ip", arguments, "").await?;
        Ok(())
    }

    async fn cleanup_matching(
        &mut self,
        wanted: impl Fn(&Action) -> bool,
    ) -> Result<(), NetworkError> {
        let mut index = self.state.undo.len();
        while index > 0 {
            index -= 1;
            let action = self.state.undo[index].clone();
            if !wanted(&action) {
                continue;
            }
            self.undo(&action).await?;
            let previous = self.state.undo.clone();
            self.state.undo.remove(index);
            if let Err(error) = self.persist() {
                self.state.undo = previous;
                return Err(error);
            }
        }
        Ok(())
    }

    async fn undo(&self, action: &Action) -> Result<(), NetworkError> {
        let mut link = self.action_link(action).await?;
        if link.is_none() && action.kind == "escape" && !stable_link_identity(action) {
            let named = self.link(&action.interface).await?;
            if named
                .as_ref()
                .is_some_and(|link| link.index == action.index)
            {
                link = named;
            } else if self.link_by_index(action.index).await?.is_some() {
                return Err(NetworkError::Invalid(
                    "cannot verify renamed MAC-less escape interface ownership".to_owned(),
                ));
            }
        }
        let Some(link) = link else {
            return Ok(());
        };
        match action.kind.as_str() {
            "alias" => {
                self.invoke(
                    "ip",
                    &[
                        "link",
                        "set",
                        "dev",
                        &link.name,
                        "alias",
                        &action.previous_alias,
                    ],
                    "",
                )
                .await?;
            }
            "route" | "escape" | "dns-route" => {
                let routes = self
                    .routes(action.family, Some(("exact", action.destination.as_str())))
                    .await?;
                if routes.iter().any(|route| self.owned_route(route, action)) {
                    self.invoke_owned("ip", self.route_arguments("del", action), "")
                        .await?;
                }
            }
            "address" => {
                if self.addresses(&link.name).await?.contains(&action.address) {
                    self.invoke(
                        "ip",
                        &["-4", "address", "del", &action.address, "dev", &link.name],
                        "",
                    )
                    .await?;
                }
            }
            "dns" => {
                self.invoke("resolvectl", &["revert", &link.name], "")
                    .await?;
            }
            "link" => {
                self.invoke(
                    "ip",
                    &[
                        "link",
                        "set",
                        "dev",
                        &link.name,
                        "mtu",
                        &action.mtu.to_string(),
                        if action.was_up { "up" } else { "down" },
                    ],
                    "",
                )
                .await?;
            }
            _ => {
                return Err(NetworkError::Invalid(
                    "unsupported network journal action".to_owned(),
                ));
            }
        }
        Ok(())
    }

    async fn action_link(&self, action: &Action) -> Result<Option<LinkInfo>, NetworkError> {
        let links = self.links().await?;
        if !action.link_alias.is_empty() {
            return Ok(links.into_iter().find(|link| {
                link.alias == action.link_alias
                    && link.index == action.index
                    && link.link_info.kind == action.link_kind
            }));
        }
        Ok(links
            .iter()
            .find(|link| {
                link.name == action.interface
                    && link.index == action.index
                    && same_link_identity(action, link)
            })
            .or_else(|| {
                links
                    .iter()
                    .find(|link| link.index == action.index && same_link_identity(action, link))
            })
            .cloned())
    }

    async fn record(&mut self, action: Action) -> Result<(), NetworkError> {
        if self.state.undo.len() >= MAX_ACTIONS {
            return Err(NetworkError::Invalid(
                "network journal action limit reached; explicit cleanup is required".to_owned(),
            ));
        }
        self.state.undo.push(action);
        if let Err(error) = self.persist() {
            self.state.undo.pop();
            return Err(error);
        }
        Ok(())
    }

    fn has_action(&self, kind: &str, interface: &str, address: &str) -> bool {
        self.state.undo.iter().any(|action| {
            action.kind == kind
                && action.interface == interface
                && (address.is_empty() || action.address == address)
        })
    }

    async fn links(&self) -> Result<Vec<LinkInfo>, NetworkError> {
        let output = self.invoke("ip", &["-j", "-d", "link", "show"], "").await?;
        Ok(serde_json::from_str(&output)?)
    }

    async fn link(&self, name: &str) -> Result<Option<LinkInfo>, NetworkError> {
        Ok(self
            .links()
            .await?
            .into_iter()
            .find(|link| link.name == name))
    }

    async fn link_by_index(&self, index: u32) -> Result<Option<LinkInfo>, NetworkError> {
        Ok(self
            .links()
            .await?
            .into_iter()
            .find(|link| link.index == index))
    }

    async fn addresses(&self, interface: &str) -> Result<Vec<String>, NetworkError> {
        let output = self
            .invoke("ip", &["-j", "address", "show", "dev", interface], "")
            .await?;
        let listing: Value = serde_json::from_str(&output)?;
        let mut addresses = Vec::new();
        for link in listing.as_array().into_iter().flatten() {
            for address in link
                .get("addr_info")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let (Some(local), Some(prefix)) = (
                    address.get("local").and_then(Value::as_str),
                    address.get("prefixlen").and_then(Value::as_u64),
                ) {
                    addresses.push(format!("{local}/{prefix}"));
                }
            }
        }
        Ok(addresses)
    }

    async fn routes(
        &self,
        family: u8,
        selector: Option<(&str, &str)>,
    ) -> Result<Vec<RouteInfo>, NetworkError> {
        let mut arguments = vec![
            "-j".to_owned(),
            "-N".to_owned(),
            format!("-{family}"),
            "route".to_owned(),
            "show".to_owned(),
            "table".to_owned(),
            "main".to_owned(),
        ];
        if let Some((kind, value)) = selector {
            arguments.push(kind.to_owned());
            if !value.is_empty() {
                arguments.push(value.to_owned());
            }
        }
        let output = self.invoke_owned("ip", arguments, "").await?;
        Ok(serde_json::from_str(&output)?)
    }

    fn owned_route(&self, route: &RouteInfo, action: &Action) -> bool {
        route.device == action.interface
            && route.gateway == action.gateway
            && route.metric == self.state.metric
            && text_or_number(Some(&route.protocol)) == ROUTE_PROTOCOL.to_string()
    }

    fn route_arguments(&self, operation: &str, action: &Action) -> Vec<String> {
        let mut arguments = vec![
            format!("-{}", action.family),
            "route".to_owned(),
            operation.to_owned(),
            action.destination.clone(),
            "table".to_owned(),
            "main".to_owned(),
        ];
        if !action.gateway.is_empty() {
            arguments.extend(["via".to_owned(), action.gateway.clone()]);
        }
        arguments.extend([
            "dev".to_owned(),
            action.interface.clone(),
            "proto".to_owned(),
            ROUTE_PROTOCOL.to_string(),
            "metric".to_owned(),
            self.state.metric.to_string(),
        ]);
        arguments
    }

    fn persist(&self) -> Result<(), NetworkError> {
        let encoded = serde_json::to_vec(&self.state)?;
        let mut random = [0_u8; 8];
        rand::rng().fill_bytes(&mut random);
        let pending = self
            .state_path
            .with_extension(format!("pending-{}", hex::encode(random)));
        let result = (|| -> std::io::Result<()> {
            let mut options = OpenOptions::new();
            use std::os::unix::fs::OpenOptionsExt as _;
            options
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
            let mut file = options.open(&pending)?;
            file.write_all(&encoded)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&pending, &self.state_path)?;
            File::open(
                self.state_path
                    .parent()
                    .expect("absolute state path has parent"),
            )?
            .sync_all()
        })();
        let _ = fs::remove_file(&pending);
        result.map_err(|source| NetworkError::Io {
            action: "persist network recovery state",
            source,
        })
    }

    async fn invoke(
        &self,
        program: &str,
        arguments: &[&str],
        input: &str,
    ) -> Result<String, NetworkError> {
        self.invoke_owned(
            program,
            arguments.iter().map(|value| (*value).to_owned()).collect(),
            input,
        )
        .await
    }

    async fn invoke_owned(
        &self,
        program: &str,
        arguments: Vec<String>,
        input: &str,
    ) -> Result<String, NetworkError> {
        self.commands
            .run(program, arguments, input.to_owned())
            .await
    }
}

#[async_trait]
trait CommandRunner: Send + Sync {
    fn check_resolver(&self) -> Result<(), NetworkError>;

    async fn run(
        &self,
        program: &str,
        arguments: Vec<String>,
        input: String,
    ) -> Result<String, NetworkError>;
}

struct SystemCommandRunner;

#[async_trait]
impl CommandRunner for SystemCommandRunner {
    fn check_resolver(&self) -> Result<(), NetworkError> {
        check_stub_resolver()
    }

    async fn run(
        &self,
        program: &str,
        arguments: Vec<String>,
        input: String,
    ) -> Result<String, NetworkError> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(NetworkError::Invalid(
                "automatic Linux networking requires root".to_owned(),
            ));
        }
        let display = format!("{program} {}", arguments.join(" "));
        let mut command = Command::new(program);
        command
            .args(&arguments)
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|source| NetworkError::Io {
            action: "start network command",
            source,
        })?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| NetworkError::Invalid("network command has no stdin".to_owned()))?;
        let input = input.into_bytes();
        let output = timeout(Duration::from_secs(10), async move {
            if !input.is_empty() {
                stdin.write_all(&input).await?;
            }
            drop(stdin);
            child.wait_with_output().await
        })
        .await
        .map_err(|_| NetworkError::Command {
            command: display.clone(),
            detail: "deadline exceeded".to_owned(),
        })?
        .map_err(|source| NetworkError::Io {
            action: "run network command",
            source,
        })?;
        if !output.status.success() {
            return Err(NetworkError::Command {
                command: display,
                detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }
        String::from_utf8(output.stdout).map_err(|error| {
            NetworkError::Invalid(format!("network command returned invalid UTF-8: {error}"))
        })
    }
}

fn is_zero_u8(value: &u8) -> bool {
    *value == 0
}

fn is_zero_u16(value: &u16) -> bool {
    *value == 0
}

fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

fn link_action(kind: &str, link: &LinkInfo, alias: &str) -> Action {
    Action {
        kind: kind.to_owned(),
        interface: link.name.clone(),
        index: link.index,
        link_kind: link.link_info.kind.clone(),
        link_address: link.address.clone(),
        link_alias: alias.to_owned(),
        ..Action::default()
    }
}

fn stable_link_identity(action: &Action) -> bool {
    !action.link_address.is_empty() && action.link_address != "00:00:00:00:00:00"
}

fn same_link_identity(action: &Action, link: &LinkInfo) -> bool {
    stable_link_identity(action)
        && action.link_address.eq_ignore_ascii_case(&link.address)
        && action.link_kind == link.link_info.kind
}

fn valid_link_address(address: &str) -> bool {
    if address.is_empty() {
        return true;
    }
    let separator = if address.contains(':') {
        ':'
    } else if address.contains('-') {
        '-'
    } else {
        return false;
    };
    let octets = address.split(separator).collect::<Vec<_>>();
    matches!(octets.len(), 6 | 8 | 20)
        && octets
            .iter()
            .all(|octet| octet.len() == 2 && u8::from_str_radix(octet, 16).is_ok())
}

fn absolute(path: PathBuf) -> Result<PathBuf, NetworkError> {
    if path.is_absolute() {
        return Ok(path);
    }
    Ok(std::env::current_dir()
        .map_err(|source| NetworkError::Io {
            action: "resolve network recovery state path",
            source,
        })?
        .join(path))
}

fn lock_path(path: &Path) -> PathBuf {
    let mut value = OsString::from(path.as_os_str());
    value.push(".lock");
    PathBuf::from(value)
}

fn prepare_directory(path: &Path) -> Result<(), NetworkError> {
    let directory = path.parent().ok_or_else(|| {
        NetworkError::Invalid("network recovery state path is required".to_owned())
    })?;
    use std::os::unix::fs::DirBuilderExt as _;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(directory)
        .map_err(|source| NetworkError::Io {
            action: "create network recovery directory",
            source,
        })?;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let metadata = fs::symlink_metadata(directory).map_err(|source| NetworkError::Io {
        action: "inspect network recovery directory",
        source,
    })?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(NetworkError::Invalid(
            "network state directory must be a non-symlink directory owned by the current user and not writable by other users"
                .to_owned(),
        ));
    }
    Ok(())
}

fn open_lock(path: &Path) -> Result<File, NetworkError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| NetworkError::Io {
            action: "open network recovery lock",
            source,
        })?;
    validate_private_file(&file)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(NetworkError::Io {
            action: "lock network recovery state",
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(file)
}

fn read_state(path: &Path) -> Result<Option<NetworkState>, NetworkError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(source) => {
            return Err(NetworkError::Io {
                action: "open network recovery state",
                source,
            });
        }
    };
    validate_private_file(&file)?;
    let mut encoded = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_STATE_SIZE + 1)
        .read_to_end(&mut encoded)
        .map_err(|source| NetworkError::Io {
            action: "read network recovery state",
            source,
        })?;
    if encoded.len() as u64 > MAX_STATE_SIZE {
        return Err(NetworkError::Invalid(
            "network recovery state exceeds maximum size".to_owned(),
        ));
    }
    Ok(Some(serde_json::from_slice(&encoded)?))
}

fn validate_private_file(file: &File) -> Result<(), NetworkError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let metadata = file.metadata().map_err(|source| NetworkError::Io {
        action: "inspect network recovery file",
        source,
    })?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(NetworkError::Invalid(
            "network recovery files must be private, singly linked regular files owned by the current user"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_state(state: &NetworkState) -> Result<(), NetworkError> {
    if state.version != STATE_VERSION
        || state.table.len() != "porta_".len() + 16
        || !state.table.starts_with("porta_")
        || hex::decode(&state.table["porta_".len()..]).is_err()
        || !(40_000..=50_000).contains(&state.metric)
        || (!state.interface.is_empty() && (!valid_interface(&state.interface) || state.index == 0))
        || state.endpoints.len() > MAX_ENDPOINTS
        || state.undo.len() > MAX_ACTIONS
    {
        return Err(NetworkError::Invalid(
            "invalid network journal header".to_owned(),
        ));
    }
    for endpoint in &state.endpoints {
        let parsed = parse_endpoint(SocketAddr::new(endpoint.address()?, endpoint.port))?;
        if parsed != *endpoint {
            return Err(NetworkError::Invalid(
                "invalid network journal endpoint".to_owned(),
            ));
        }
    }
    for action in &state.undo {
        validate_action(action, state)?;
    }
    Ok(())
}

fn validate_action(action: &Action, state: &NetworkState) -> Result<(), NetworkError> {
    if !valid_interface(&action.interface)
        || action.index == 0
        || action.link_kind.len() > 64
        || action.link_address.len() > 64
        || !valid_link_address(&action.link_address)
        || action.link_alias.len() > 128
        || action.previous_alias.len() > 128
    {
        return Err(NetworkError::Invalid(
            "invalid network journal action interface".to_owned(),
        ));
    }
    if action.kind != "escape"
        && (action.link_alias != format!("porta:{}", state.table) || action.link_kind != "tun")
    {
        return Err(NetworkError::Invalid(
            "network journal action lacks tunnel ownership".to_owned(),
        ));
    }
    match action.kind.as_str() {
        "alias" if action.previous_alias.is_empty() => Ok(()),
        "link" if (68..=u16::MAX).contains(&action.mtu) => Ok(()),
        "address" => action
            .address
            .parse::<ipnet::Ipv4Net>()
            .ok()
            .filter(|prefix| valid_unicast(prefix.addr()))
            .map(|_| ())
            .ok_or_else(|| NetworkError::Invalid("invalid network journal address".to_owned())),
        "route" | "escape" | "dns-route" => {
            let prefix: IpNet = action
                .destination
                .parse()
                .map_err(|_| NetworkError::Invalid("invalid network journal route".to_owned()))?;
            let gateway = if action.gateway.is_empty() {
                None
            } else {
                Some(action.gateway.parse::<IpAddr>().map_err(|_| {
                    NetworkError::Invalid("invalid network journal gateway".to_owned())
                })?)
            };
            if !matches!(action.family, 4 | 6)
                || prefix.addr().is_ipv4() != (action.family == 4)
                || (action.kind == "route"
                    && !matches!(action.destination.as_str(), "0.0.0.0/1" | "128.0.0.0/1"))
                || (action.kind == "escape"
                    && prefix.prefix_len() != if action.family == 4 { 32 } else { 128 })
                || (action.kind == "dns-route"
                    && (action.family != 4
                        || prefix.prefix_len() != 32
                        || !valid_unicast(match prefix.addr() {
                            IpAddr::V4(address) => address,
                            IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
                        })))
                || gateway.is_some_and(|gateway| gateway.is_ipv4() != (action.family == 4))
            {
                return Err(NetworkError::Invalid(
                    "invalid network journal route".to_owned(),
                ));
            }
            Ok(())
        }
        "dns" => Ok(()),
        _ => Err(NetworkError::Invalid(
            "invalid network journal action".to_owned(),
        )),
    }
}

fn parse_endpoint(endpoint: SocketAddr) -> Result<EndpointState, NetworkError> {
    if endpoint.port() == 0
        || matches!(endpoint.port(), 53 | 853)
        || !usable_endpoint(endpoint.ip())
    {
        return Err(NetworkError::Invalid(
            "tunnel endpoint requires a unicast IP and non-DNS TCP/UDP port".to_owned(),
        ));
    }
    Ok(EndpointState {
        ip: endpoint.ip().to_string(),
        port: endpoint.port(),
    })
}

fn usable_endpoint(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => valid_unicast(address),
        IpAddr::V6(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_unicast_link_local()
        }
    }
}

fn valid_unicast(address: Ipv4Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_multicast()
        && address != Ipv4Addr::BROADCAST
}

fn validate_lease(interface: &str, lease: Lease) -> Result<(), NetworkError> {
    if !valid_interface(interface)
        || !valid_unicast(lease.address.addr())
        || lease
            .dns
            .is_none_or(|dns| !valid_unicast(dns) || dns == lease.address.addr())
        || !(576..=9000).contains(&lease.mtu)
    {
        return Err(NetworkError::Invalid(
            "automatic Linux networking requires an IPv4 unicast lease and DNS server, and MTU 576..9000"
                .to_owned(),
        ));
    }
    Ok(())
}

fn valid_interface(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name != "lo"
        && name
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'_' | b'-' | b'.'))
}

fn check_stub_resolver() -> Result<(), NetworkError> {
    let target = fs::canonicalize("/etc/resolv.conf").map_err(|source| NetworkError::Io {
        action: "inspect resolver configuration",
        source,
    })?;
    if target != Path::new("/run/systemd/resolve/stub-resolv.conf")
        && target != Path::new("/usr/lib/systemd/resolv.conf")
    {
        return Err(NetworkError::Invalid(
            "automatic DNS requires /etc/resolv.conf linked to systemd-resolved's local stub; other resolver managers are unsupported"
                .to_owned(),
        ));
    }
    let contents = fs::read_to_string("/etc/resolv.conf").map_err(|source| NetworkError::Io {
        action: "read resolver configuration",
        source,
    })?;
    let mut found = false;
    for line in contents.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.first() != Some(&"nameserver") {
            continue;
        }
        if !matches!(fields.get(1), Some(&"127.0.0.53" | &"127.0.0.54")) {
            return Err(NetworkError::Invalid(
                "automatic DNS requires exclusively systemd-resolved loopback stub nameservers"
                    .to_owned(),
            ));
        }
        found = true;
    }
    if !found {
        return Err(NetworkError::Invalid(
            "systemd-resolved stub has no nameserver".to_owned(),
        ));
    }
    Ok(())
}

fn text_or_number(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => value.to_string(),
        _ => String::new(),
    }
}

fn sync_directory(path: &Path) -> Result<(), NetworkError> {
    File::open(path.parent().expect("absolute state path has parent"))
        .and_then(|directory| directory.sync_all())
        .map_err(|source| NetworkError::Io {
            action: "sync network recovery directory",
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_validation_rejects_injection_and_unowned_actions() {
        let state = NetworkState {
            version: STATE_VERSION,
            table: "porta_0011223344556677".to_owned(),
            metric: 40_100,
            endpoints: vec![EndpointState {
                ip: "198.51.100.10".to_owned(),
                port: 443,
            }],
            ..NetworkState::default()
        };
        assert!(validate_state(&state).is_ok());

        let mut injected = state.clone();
        injected.table = "porta_x; flush ruleset".to_owned();
        assert!(validate_state(&injected).is_err());

        let mut unowned = state;
        unowned.undo.push(Action {
            kind: "route".to_owned(),
            interface: "porta0".to_owned(),
            index: 10,
            link_kind: "tun".to_owned(),
            destination: "0.0.0.0/1".to_owned(),
            family: 4,
            ..Action::default()
        });
        assert!(validate_state(&unowned).is_err());
    }

    #[test]
    fn endpoint_and_interface_validation_are_strict() {
        assert!(parse_endpoint("198.51.100.10:443".parse().unwrap()).is_ok());
        for endpoint in [
            "0.0.0.0:443",
            "127.0.0.1:443",
            "224.0.0.1:443",
            "1.1.1.1:53",
        ] {
            assert!(
                parse_endpoint(endpoint.parse().unwrap()).is_err(),
                "{endpoint}"
            );
        }
        assert!(valid_interface("porta0"));
        assert!(!valid_interface("lo"));
        assert!(!valid_interface("porta0;reboot"));
    }

    #[test]
    fn accepts_supported_linux_link_layer_address_lengths() {
        assert!(valid_link_address(""));
        assert!(valid_link_address("02:00:00:00:00:01"));
        assert!(valid_link_address("02-00-00-ff-fe-00-00-01"));
        assert!(valid_link_address(
            "00:00:02:c9:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01"
        ));
        assert!(!valid_link_address("02:00:00:00:00"));
        assert!(!valid_link_address("02:00:00:00:00:zz"));
    }
}

#[cfg(test)]
#[path = "network_recovery_tests.rs"]
mod recovery_tests;
