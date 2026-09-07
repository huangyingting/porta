use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::process::Stdio;
#[cfg(windows)]
use std::time::Duration;
#[cfg(windows)]
use tokio::io::AsyncWriteExt as _;
#[cfg(windows)]
use tokio::process::Command;
#[cfg(windows)]
use tokio::time::timeout;

use crate::tunnel::Lease;

#[cfg(windows)]
use super::paths;

const EXACT_OWNERSHIP_STATE_VERSION: i32 = 2;
const NATIVE_MTU_STATE_VERSION: i32 = 3;
const MAX_STATE_SIZE: u64 = 1024 * 1024;
const MAX_GUARD_FILTERS: usize = 128;
#[cfg(windows)]
const COMMAND_TIMEOUT: Duration = Duration::from_secs(20);
#[cfg(windows)]
const NETWORK_SCRIPT: &str = include_str!("network.ps1");

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("{0}")]
    Invalid(String),
    #[error(
        "another Porta process owns this network state; disconnect or close that process first"
    )]
    StateInUse,
    #[error("{action}: {source}")]
    Io {
        action: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("{command}: {detail}")]
    Command { command: String, detail: String },
    #[error("{action}: Windows error {code:#x}")]
    Windows { action: &'static str, code: u32 },
    #[error("{0}")]
    Combined(String),
    #[error("Windows network configuration is unavailable on this platform")]
    Unsupported,
    #[error("decode network recovery journal: {0}")]
    Decode(#[from] serde_json::Error),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct EndpointState {
    ip: IpAddr,
    port: u16,
}

impl Default for EndpointState {
    fn default() -> Self {
        Self {
            ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 0,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct RouteState {
    #[serde(skip_serializing_if = "String::is_empty")]
    kind: String,
    prefix: String,
    interface_index: i32,
    interface_guid: String,
    next_hop: String,
    metric: i32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct DnsState {
    interface_index: i32,
    automatic: bool,
    original: Vec<String>,
    applied: String,
    pending: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct MtuState {
    original: u32,
    applied: i32,
    pending: i32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct NetworkState {
    version: i32,
    interface: String,
    server_ip: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    guard_key: String,
    endpoint: EndpointState,
    #[serde(skip_serializing_if = "String::is_empty")]
    application: String,
    #[serde(skip_serializing_if = "is_zero_u64")]
    interface_luid: u64,
    #[serde(skip_serializing_if = "is_zero_i32")]
    interface_index: i32,
    #[serde(skip_serializing_if = "String::is_empty")]
    interface_guid: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    original_dhcp: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    addresses: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    routes: Vec<RouteState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dns: Option<DnsState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mtu: Option<MtuState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GuardSpec {
    key: String,
    interface_luid: u64,
    endpoint: EndpointState,
    application: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Condition {
    Loopback,
    Interface(u64),
    Application(String),
    Address(IpNet),
    Protocol(u8),
    RemotePort(u16),
    LocalPort(u16),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Filter {
    layer: &'static str,
    permit: bool,
    conditions: Vec<Condition>,
}

pub struct NetworkManager {
    state_path: PathBuf,
    directory: File,
    lock: Option<File>,
    state: NetworkState,
    protected: bool,
}

impl NetworkManager {
    pub fn open(state_path: PathBuf) -> Result<Self, NetworkError> {
        if state_path.as_os_str().is_empty() || state_path.file_name().is_none() {
            return Err(NetworkError::Invalid(
                "network recovery state path is required".to_owned(),
            ));
        }
        let state_path = absolute(state_path)?;
        let directory = prepare_directory(&state_path)?;
        let state = match read_state(&state_path)? {
            Some(state) => {
                validate_state(&state)?;
                state
            }
            None => NetworkState::default(),
        };
        Ok(Self {
            state_path,
            directory,
            lock: None,
            state,
            protected: false,
        })
    }

    pub fn needs_cleanup(&self) -> bool {
        !self.state.interface.is_empty() || !self.state.guard_key.is_empty()
    }

    pub fn recovery_endpoints(&self) -> Result<Vec<SocketAddr>, NetworkError> {
        if self.state.guard_key.is_empty() {
            return Ok(Vec::new());
        }
        Ok(vec![endpoint_socket(&self.state.endpoint)?])
    }

    pub fn protected(&self) -> bool {
        self.protected
    }

    pub async fn prepare(
        &mut self,
        interface_name: &str,
        remote_address: &SocketAddr,
    ) -> Result<(), NetworkError> {
        self.prepare_inner(interface_name, remote_address, false)
            .await
    }

    pub async fn up(
        &mut self,
        interface_name: &str,
        remote_address: &SocketAddr,
        lease: Lease,
    ) -> Result<(), NetworkError> {
        validate_lease(interface_name, remote_address, lease)?;
        self.prepare_inner(interface_name, remote_address, true)
            .await?;

        let dns = lease.dns.expect("validated DNS");
        let configure = self
            .invoke([
                OsString::from("configure-interface"),
                self.state_path.as_os_str().to_owned(),
                OsString::from(lease.address.to_string()),
                OsString::from(dns.to_string()),
                OsString::from(lease.mtu.to_string()),
            ])
            .await;
        let reload = self.reload_required();
        combine(configure.map(|_| ()), reload)?;

        self.apply_mtu(u32::from(lease.mtu))?;

        let up = self
            .invoke([
                OsString::from("up"),
                self.state_path.as_os_str().to_owned(),
                OsString::from(lease.address.to_string()),
                OsString::from(dns.to_string()),
                OsString::from(lease.mtu.to_string()),
            ])
            .await;
        let reload = self.reload_required();
        combine(up.map(|_| ()), reload)
    }

    pub async fn reconfigure(
        &mut self,
        interface_name: &str,
        remote_address: &SocketAddr,
        lease: Lease,
    ) -> Result<(), NetworkError> {
        self.up(interface_name, remote_address, lease).await
    }

    pub async fn down(&mut self) -> Result<(), NetworkError> {
        self.acquire()?;
        if !self.needs_cleanup() {
            remove_if_exists(
                &pending_path(&self.state_path),
                "remove pending network state",
            )?;
            return self.release();
        }

        self.restore_mtu()?;
        let down = self
            .invoke([
                OsString::from("down"),
                self.state_path.as_os_str().to_owned(),
            ])
            .await;
        let reload = self.reload_required();
        combine(down.map(|_| ()), reload)?;

        if !self.state.guard_key.is_empty() {
            remove_guard(&self.state.guard_key)?;
            self.protected = false;
        }
        remove_if_exists(
            &pending_path(&self.state_path),
            "remove pending network state",
        )?;
        remove_if_exists(&self.state_path, "remove network state")?;
        self.state = NetworkState::default();
        self.release()
    }

    async fn prepare_inner(
        &mut self,
        interface_name: &str,
        remote_address: &SocketAddr,
        require_interface: bool,
    ) -> Result<(), NetworkError> {
        let interface_name = interface_name.trim();
        if interface_name.is_empty() || interface_name.contains('\0') {
            return Err(NetworkError::Invalid(
                "tunnel interface name is required".to_owned(),
            ));
        }
        let endpoint = parse_endpoint(remote_address)?;
        self.acquire()?;
        if !self.state.interface.is_empty() && self.state.interface != interface_name {
            return Err(NetworkError::Invalid(
                "saved network state belongs to a different interface; explicitly disconnect it first"
                    .to_owned(),
            ));
        }

        let mut interface_luid = 0;
        let mut interface_guid = String::new();
        if require_interface {
            interface_luid = native_interface_luid(interface_name)?;
            interface_guid = native_interface_guid(interface_luid)?;
            if self.state.interface_luid != 0
                && (self.state.interface_luid != interface_luid
                    || !self
                        .state
                        .interface_guid
                        .eq_ignore_ascii_case(&interface_guid))
            {
                let retire = self
                    .invoke([
                        OsString::from("retire-interface"),
                        self.state_path.as_os_str().to_owned(),
                    ])
                    .await;
                let reload = self.reload_required();
                combine(retire.map(|_| ()), reload).map_err(|error| {
                    NetworkError::Combined(format!(
                        "retire replaced tunnel interface while retaining protection: {error}"
                    ))
                })?;
                if self.state.interface_luid != 0 {
                    return Err(NetworkError::Invalid(
                        "previous tunnel interface still exists; explicitly disconnect it first"
                            .to_owned(),
                    ));
                }
            }
        }

        let mut next = self.state.clone();
        if next.version == 0 {
            next.version = EXACT_OWNERSHIP_STATE_VERSION;
        }
        next.interface = interface_name.to_owned();
        next.server_ip = endpoint.ip.to_string();
        next.endpoint = endpoint.clone();
        if next.guard_key.is_empty() {
            next.guard_key = object_key(&self.state_path.to_string_lossy().to_lowercase(), -2);
        }
        next.application = std::env::current_exe()
            .map_err(|source| NetworkError::Io {
                action: "determine transport executable",
                source,
            })?
            .to_string_lossy()
            .into_owned();
        if require_interface {
            next.interface_luid = interface_luid;
            next.interface_guid = interface_guid;
        }

        let previous = std::mem::replace(&mut self.state, next);
        if let Err(error) = self.persist() {
            self.state = previous;
            return Err(error);
        }
        let spec = GuardSpec {
            key: self.state.guard_key.clone(),
            interface_luid,
            endpoint,
            application: self.state.application.clone(),
        };
        replace_guard(&spec).map_err(|error| {
            NetworkError::Combined(format!(
                "activate persistent Windows leak protection (explicit Disconnect restores owned state): {error}"
            ))
        })?;
        self.protected = true;

        let prepare = self
            .invoke([
                OsString::from("prepare"),
                self.state_path.as_os_str().to_owned(),
            ])
            .await;
        let reload = self.reload_required();
        combine(prepare.map(|_| ()), reload)
    }

    fn acquire(&mut self) -> Result<(), NetworkError> {
        if self.lock.is_some() {
            return Ok(());
        }
        validate_directory(&self.directory)?;
        let lock = open_lock(&lock_path(&self.state_path))?;
        remove_if_exists(
            &pending_path(&self.state_path),
            "remove abandoned pending network state",
        )?;
        let state = match read_state(&self.state_path) {
            Ok(Some(state)) => {
                if let Err(error) = validate_state(&state) {
                    drop(lock);
                    return Err(error);
                }
                state
            }
            Ok(None) => NetworkState::default(),
            Err(error) => {
                drop(lock);
                return Err(error);
            }
        };
        self.state = state;
        self.lock = Some(lock);
        Ok(())
    }

    fn release(&mut self) -> Result<(), NetworkError> {
        if let Some(lock) = self.lock.take() {
            unlock_file(&lock)?;
        }
        Ok(())
    }

    fn reload_required(&mut self) -> Result<(), NetworkError> {
        let state = read_state(&self.state_path)?.ok_or_else(|| {
            NetworkError::Invalid("network recovery journal disappeared".to_owned())
        })?;
        validate_state(&state)?;
        self.state = state;
        Ok(())
    }

    fn persist(&self) -> Result<(), NetworkError> {
        let bytes = serde_json::to_vec(&self.state)?;
        validate_directory(&self.directory)?;
        let pending = pending_path(&self.state_path);
        remove_if_exists(&pending, "remove abandoned pending network state")?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
            };
            options
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let mut file = options.open(&pending).map_err(|source| NetworkError::Io {
            action: "write network state",
            source,
        })?;
        secure_new_file(&pending, &file, "secure pending network state")?;
        let write_result = file
            .write_all(&bytes)
            .and_then(|_| file.sync_all())
            .and_then(|_| file.flush());
        drop(file);
        if let Err(source) = write_result {
            let _ = fs::remove_file(&pending);
            return Err(NetworkError::Io {
                action: "flush network state",
                source,
            });
        }
        if let Err(error) = replace_journal(&pending, &self.state_path) {
            let _ = fs::remove_file(&pending);
            return Err(error);
        }
        secure_existing_file(&self.state_path, "secure network state")?;
        Ok(())
    }

    fn apply_mtu(&mut self, mtu: u32) -> Result<(), NetworkError> {
        if self.state.interface_luid == 0 {
            return Err(NetworkError::Invalid(
                "tunnel interface identity is unavailable for native MTU configuration".to_owned(),
            ));
        }
        if self.state.mtu.is_none() {
            let original = native_interface_mtu(self.state.interface_luid)?;
            if original == 0 {
                return Err(NetworkError::Invalid(
                    "Windows IP Helper API returned a zero tunnel interface MTU".to_owned(),
                ));
            }
            self.state.mtu = Some(MtuState {
                original,
                applied: 0,
                pending: 0,
            });
        }
        self.state.version = NATIVE_MTU_STATE_VERSION;
        self.state.mtu.as_mut().expect("MTU state").pending = mtu as i32;
        self.persist()?;
        set_native_interface_mtu(self.state.interface_luid, mtu)?;
        let state = self.state.mtu.as_mut().expect("MTU state");
        state.applied = mtu as i32;
        state.pending = 0;
        self.persist()
    }

    fn restore_mtu(&mut self) -> Result<(), NetworkError> {
        let Some(mtu) = self.state.mtu.clone() else {
            return Ok(());
        };
        if self.state.interface_luid == 0 || self.state.interface_guid.is_empty() {
            return Ok(());
        }
        let Ok(current_guid) = native_interface_guid(self.state.interface_luid) else {
            return Ok(());
        };
        if !current_guid.eq_ignore_ascii_case(&self.state.interface_guid) {
            return Ok(());
        }
        let current = native_interface_mtu(self.state.interface_luid)?;
        let owned = (mtu.applied != 0 && current == mtu.applied as u32)
            || (mtu.pending != 0 && current == mtu.pending as u32);
        if owned {
            set_native_interface_mtu(self.state.interface_luid, mtu.original)?;
        }
        self.state.mtu = None;
        self.persist()
    }

    async fn invoke<I>(&self, arguments: I) -> Result<String, NetworkError>
    where
        I: IntoIterator<Item = OsString>,
    {
        invoke_powershell(&self.state_path, arguments).await
    }
}

fn validate_lease(
    interface_name: &str,
    remote_address: &SocketAddr,
    lease: Lease,
) -> Result<(), NetworkError> {
    if interface_name.trim().is_empty() {
        return Err(NetworkError::Invalid(
            "tunnel interface name is required".to_owned(),
        ));
    }
    if !valid_ipv4_unicast(lease.address.addr()) {
        return Err(NetworkError::Invalid(
            "full tunnel requires a valid IPv4 lease".to_owned(),
        ));
    }
    let dns = lease.dns.filter(|address| valid_ipv4_unicast(*address));
    let Some(dns) = dns else {
        return Err(NetworkError::Invalid(
            "full tunnel requires an IPv4 DNS resolver reachable through the tunnel".to_owned(),
        ));
    };
    if !(576..=9000).contains(&lease.mtu) {
        return Err(NetworkError::Invalid(format!(
            "tunnel MTU {} is outside 576..9000",
            lease.mtu
        )));
    }
    let endpoint = parse_endpoint(remote_address)?;
    if endpoint.ip == IpAddr::V4(dns) {
        return Err(NetworkError::Invalid(
            "tunnel DNS cannot be the transport endpoint (its host route bypasses the tunnel)"
                .to_owned(),
        ));
    }
    Ok(())
}

fn parse_endpoint(address: &SocketAddr) -> Result<EndpointState, NetworkError> {
    if address.port() == 0 {
        return Err(NetworkError::Invalid(
            "tunnel endpoint port is invalid".to_owned(),
        ));
    }
    if matches!(address.port(), 53 | 853) {
        return Err(NetworkError::Invalid(
            "DNS ports 53 and 853 cannot be exempted for the tunnel transport".to_owned(),
        ));
    }
    if let SocketAddr::V6(address) = address {
        if address.scope_id() != 0 {
            return Err(NetworkError::Invalid(
                "tunnel endpoint must be an unscoped unicast IP address".to_owned(),
            ));
        }
    }
    let ip = unmap(address.ip());
    if !valid_ip_unicast(ip) {
        return Err(NetworkError::Invalid(
            "tunnel endpoint must be an unscoped unicast IP address".to_owned(),
        ));
    }
    Ok(EndpointState {
        ip,
        port: address.port(),
    })
}

fn endpoint_socket(endpoint: &EndpointState) -> Result<SocketAddr, NetworkError> {
    let address = match endpoint.ip {
        IpAddr::V4(address) => SocketAddr::from((address, endpoint.port)),
        IpAddr::V6(address) => SocketAddr::from((address, endpoint.port)),
    };
    let parsed = parse_endpoint(&address)?;
    if parsed != *endpoint {
        return Err(NetworkError::Invalid(
            "invalid pinned recovery endpoint".to_owned(),
        ));
    }
    Ok(address)
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        other => other,
    }
}

fn valid_ip_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => valid_ipv4_unicast(address),
        IpAddr::V6(address) => valid_ipv6_unicast(address),
    }
}

fn valid_ipv4_unicast(address: Ipv4Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_multicast()
        && address != Ipv4Addr::BROADCAST
}

fn valid_ipv6_unicast(address: Ipv6Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_multicast()
        && !is_ipv6_link_local(address)
}

fn is_ipv6_link_local(address: Ipv6Addr) -> bool {
    let first = address.segments()[0];
    first & 0xffc0 == 0xfe80
}

fn validate_state(state: &NetworkState) -> Result<(), NetworkError> {
    if state.version != EXACT_OWNERSHIP_STATE_VERSION && state.version != NATIVE_MTU_STATE_VERSION {
        return Err(NetworkError::Invalid(format!(
            "unsupported version {}; restore older journals with the client that created them",
            state.version
        )));
    }
    if state.interface.trim().is_empty()
        || state.interface.contains('\0')
        || !valid_journal_guid(&state.guard_key)
    {
        return Err(NetworkError::Invalid(
            "missing interface or guard ownership".to_owned(),
        ));
    }
    let endpoint = endpoint_socket(&state.endpoint)?;
    if endpoint.ip() != state.endpoint.ip
        || state.server_ip != state.endpoint.ip.to_string()
        || parse_endpoint(&endpoint)? != state.endpoint
    {
        return Err(NetworkError::Invalid("invalid pinned endpoint".to_owned()));
    }
    if state.interface_luid != 0 && !valid_journal_guid(&state.interface_guid) {
        return Err(NetworkError::Invalid(
            "missing tunnel adapter identity".to_owned(),
        ));
    }
    let owns_tunnel_interface = !state.addresses.is_empty()
        || state.dns.is_some()
        || state.mtu.is_some()
        || state
            .routes
            .iter()
            .any(|route| matches!(route.kind.as_str(), "tunnel" | "dns"));
    if owns_tunnel_interface
        && (state.interface_luid == 0 || !valid_journal_guid(&state.interface_guid))
    {
        return Err(NetworkError::Invalid(
            "network recovery ownership is not bound to a tunnel adapter".to_owned(),
        ));
    }
    for route in &state.routes {
        let prefix: IpNet = route
            .prefix
            .parse()
            .map_err(|_| NetworkError::Invalid("invalid route ownership".to_owned()))?;
        let next_hop: IpAddr = route
            .next_hop
            .parse()
            .map_err(|_| NetworkError::Invalid("invalid route ownership".to_owned()))?;
        if next_hop.is_ipv4() != prefix.addr().is_ipv4()
            || route.interface_index <= 0
            || !valid_journal_guid(&route.interface_guid)
            || route.metric < 0
        {
            return Err(NetworkError::Invalid("invalid route ownership".to_owned()));
        }
        match route.kind.as_str() {
            "tunnel" => {
                if route.prefix != "0.0.0.0/1" && route.prefix != "128.0.0.0/1" {
                    return Err(NetworkError::Invalid("invalid tunnel route".to_owned()));
                }
            }
            "dns" | "escape" => {
                let host_bits = if prefix.addr().is_ipv4() { 32 } else { 128 };
                if prefix.prefix_len() != host_bits
                    || (route.kind == "dns" && !prefix.addr().is_ipv4())
                {
                    return Err(NetworkError::Invalid("invalid owned host route".to_owned()));
                }
            }
            _ => {
                return Err(NetworkError::Invalid("missing route kind".to_owned()));
            }
        }
    }
    for address in &state.addresses {
        let prefix: ipnet::Ipv4Net = address
            .parse()
            .map_err(|_| NetworkError::Invalid("invalid owned address".to_owned()))?;
        if !valid_ipv4_unicast(prefix.addr()) {
            return Err(NetworkError::Invalid("invalid owned address".to_owned()));
        }
    }
    if let Some(mtu) = &state.mtu {
        if mtu.original == 0 || !optional_mtu(mtu.applied) || !optional_mtu(mtu.pending) {
            return Err(NetworkError::Invalid(
                "invalid MTU recovery state".to_owned(),
            ));
        }
    }
    if let Some(dns) = &state.dns {
        if dns.interface_index <= 0 || dns.original.len() > 16 {
            return Err(NetworkError::Invalid(
                "invalid DNS recovery state".to_owned(),
            ));
        }
        for value in &dns.original {
            if value.is_empty() {
                continue;
            }
            let address: IpAddr = value
                .parse()
                .map_err(|_| NetworkError::Invalid("invalid DNS recovery state".to_owned()))?;
            if address.is_unspecified() || address.is_multicast() {
                return Err(NetworkError::Invalid(
                    "invalid DNS recovery state".to_owned(),
                ));
            }
        }
        for value in [&dns.applied, &dns.pending] {
            if value.is_empty() {
                continue;
            }
            let address: Ipv4Addr = value
                .parse()
                .map_err(|_| NetworkError::Invalid("invalid DNS recovery state".to_owned()))?;
            if !valid_ipv4_unicast(address) {
                return Err(NetworkError::Invalid(
                    "invalid DNS recovery state".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn optional_mtu(value: i32) -> bool {
    value == 0 || (576..=9000).contains(&value)
}

fn valid_journal_guid(value: &str) -> bool {
    parse_guid(value).is_some()
}

fn object_key(owner: &str, index: i32) -> String {
    let mut hash = Sha256::digest(format!("Porta full tunnel v1:{owner}:{index}").as_bytes());
    hash[6] = (hash[6] & 0x0f) | 0x50;
    hash[8] = (hash[8] & 0x3f) | 0x80;
    format!(
        "{}-{}-{}-{}-{}",
        hex::encode(&hash[0..4]),
        hex::encode(&hash[4..6]),
        hex::encode(&hash[6..8]),
        hex::encode(&hash[8..10]),
        hex::encode(&hash[10..16])
    )
}

fn guard_filters(spec: &GuardSpec) -> Vec<Filter> {
    let mut filters = Vec::new();
    for family in [4_u8, 6_u8] {
        for kind in ["packet", "transport", "connect", "accept"] {
            let layer = layer_name(kind, family);
            filters.push(Filter {
                layer,
                permit: true,
                conditions: vec![Condition::Loopback],
            });
            if family == 4 && spec.interface_luid != 0 {
                filters.push(Filter {
                    layer,
                    permit: true,
                    conditions: vec![Condition::Interface(spec.interface_luid)],
                });
            }
            if (family == 4) == spec.endpoint.ip.is_ipv4() {
                let endpoint = IpNet::new(spec.endpoint.ip, if family == 4 { 32 } else { 128 })
                    .expect("valid endpoint prefix");
                if kind == "packet" {
                    filters.push(Filter {
                        layer,
                        permit: true,
                        conditions: vec![Condition::Address(endpoint)],
                    });
                } else {
                    for protocol in [6_u8, 17_u8] {
                        let mut conditions = vec![
                            Condition::Address(endpoint),
                            Condition::Protocol(protocol),
                            Condition::RemotePort(spec.endpoint.port),
                        ];
                        if kind == "connect" || kind == "accept" {
                            conditions.push(Condition::Application(spec.application.clone()));
                        }
                        filters.push(Filter {
                            layer,
                            permit: true,
                            conditions,
                        });
                    }
                }
            }
            if family == 6 && spec.endpoint.ip.is_ipv6() {
                for prefix in ["fe80::/10", "ff02::/16"] {
                    let address = Condition::Address(prefix.parse().expect("static IPv6 prefix"));
                    if kind == "packet" {
                        filters.push(Filter {
                            layer,
                            permit: true,
                            conditions: vec![address],
                        });
                    } else {
                        let mut types = vec![133_u16, 135_u16, 136_u16];
                        if kind == "accept" {
                            types.push(134);
                        }
                        for icmp_type in types {
                            filters.push(Filter {
                                layer,
                                permit: true,
                                conditions: vec![
                                    address.clone(),
                                    Condition::Protocol(58),
                                    Condition::LocalPort(icmp_type),
                                    Condition::RemotePort(0),
                                ],
                            });
                        }
                    }
                }
            }
            filters.push(Filter {
                layer,
                permit: false,
                conditions: Vec::new(),
            });
        }
        filters.push(Filter {
            layer: if family == 4 { "forward4" } else { "forward6" },
            permit: false,
            conditions: Vec::new(),
        });
    }
    filters
}

fn layer_name(kind: &str, family: u8) -> &'static str {
    match (kind, family) {
        ("packet", 4) => "packet4",
        ("packet", 6) => "packet6",
        ("transport", 4) => "transport4",
        ("transport", 6) => "transport6",
        ("connect", 4) => "connect4",
        ("connect", 6) => "connect6",
        ("accept", 4) => "accept4",
        ("accept", 6) => "accept6",
        _ => unreachable!("known policy layer"),
    }
}

fn absolute(path: PathBuf) -> Result<PathBuf, NetworkError> {
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map(|directory| directory.join(path))
            .map_err(|source| NetworkError::Io {
                action: "resolve network state path",
                source,
            })?
    };
    Ok(clean_path(&path))
}

fn clean_path(path: &Path) -> PathBuf {
    use std::path::Component;

    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                clean.pop();
            }
            component => clean.push(component.as_os_str()),
        }
    }
    clean
}

fn prepare_directory(path: &Path) -> Result<File, NetworkError> {
    let parent = path.parent().ok_or_else(|| {
        NetworkError::Invalid("network state path has no parent directory".to_owned())
    })?;
    prepare_owned_directory(parent).map_err(|source| NetworkError::Io {
        action: "create network ownership directory",
        source,
    })
}

fn read_state(path: &Path) -> Result<Option<NetworkState>, NetworkError> {
    let file = match open_state_file(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(NetworkError::Io {
                action: "read network helper state",
                source,
            });
        }
    };
    secure_open_file(path, &file, "secure network state")?;
    let length = file
        .metadata()
        .map_err(|source| NetworkError::Io {
            action: "inspect network helper state",
            source,
        })?
        .len();
    if length > MAX_STATE_SIZE {
        return Err(NetworkError::Invalid(
            "network recovery journal exceeds 1 MiB".to_owned(),
        ));
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take(MAX_STATE_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| NetworkError::Io {
            action: "read network helper state",
            source,
        })?;
    if bytes.len() as u64 > MAX_STATE_SIZE {
        return Err(NetworkError::Invalid(
            "network recovery journal exceeds 1 MiB".to_owned(),
        ));
    }
    Ok(Some(serde_json::from_slice(&bytes)?))
}

#[cfg(windows)]
fn prepare_owned_directory(path: &Path) -> std::io::Result<File> {
    paths::prepare_admin_directory(path)
}

#[cfg(not(windows))]
fn prepare_owned_directory(path: &Path) -> std::io::Result<File> {
    fs::create_dir_all(path)?;
    File::open(path)
}

#[cfg(windows)]
fn validate_directory(directory: &File) -> Result<(), NetworkError> {
    paths::validate_admin_directory(directory).map_err(|source| NetworkError::Io {
        action: "validate network ownership directory",
        source,
    })
}

#[cfg(not(windows))]
fn validate_directory(_directory: &File) -> Result<(), NetworkError> {
    Ok(())
}

#[cfg(windows)]
fn open_state_file(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};

    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(windows))]
fn open_state_file(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

#[cfg(windows)]
fn secure_open_file(_path: &Path, file: &File, action: &'static str) -> Result<(), NetworkError> {
    paths::validate_admin_file(file).map_err(|source| NetworkError::Io { action, source })
}

#[cfg(not(windows))]
fn secure_open_file(_path: &Path, _file: &File, _action: &'static str) -> Result<(), NetworkError> {
    Ok(())
}

fn secure_existing_file(path: &Path, action: &'static str) -> Result<(), NetworkError> {
    let file = open_state_file(path).map_err(|source| NetworkError::Io { action, source })?;
    secure_open_file(path, &file, action)
}

#[cfg(windows)]
fn secure_new_file(path: &Path, file: &File, action: &'static str) -> Result<(), NetworkError> {
    paths::secure_new_admin_file(path, file).map_err(|source| NetworkError::Io { action, source })
}

#[cfg(not(windows))]
fn secure_new_file(_path: &Path, _file: &File, _action: &'static str) -> Result<(), NetworkError> {
    Ok(())
}

fn lock_path(path: &Path) -> PathBuf {
    append_suffix(path, ".lock")
}

fn pending_path(path: &Path) -> PathBuf {
    append_suffix(path, ".pending")
}

fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}

fn remove_if_exists(path: &Path, action: &'static str) -> Result<(), NetworkError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(NetworkError::Io { action, source }),
    }
}

fn combine(
    first: Result<(), NetworkError>,
    second: Result<(), NetworkError>,
) -> Result<(), NetworkError> {
    match (first, second) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(NetworkError::Combined(format!("{first}; {second}"))),
    }
}

#[cfg(windows)]
async fn invoke_powershell<I>(state_path: &Path, arguments: I) -> Result<String, NetworkError>
where
    I: IntoIterator<Item = OsString>,
{
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

    let arguments = arguments.into_iter().collect::<Vec<_>>();
    let operation = arguments
        .first()
        .ok_or_else(|| NetworkError::Invalid("network helper operation is required".to_owned()))?;
    let passed_state = arguments
        .get(1)
        .ok_or_else(|| NetworkError::Invalid("network helper state path is required".to_owned()))?;
    if Path::new(passed_state) != state_path {
        return Err(NetworkError::Invalid(
            "network helper state path does not match".to_owned(),
        ));
    }
    let operation_text = operation.to_string_lossy();
    let expected = match operation_text.as_ref() {
        "prepare" | "down" | "retire-interface" => 2,
        "configure-interface" | "up" => 5,
        _ => {
            return Err(NetworkError::Invalid(
                "invalid network helper operation".to_owned(),
            ))
        }
    };
    if arguments.len() != expected {
        return Err(NetworkError::Invalid(
            "invalid network helper arguments".to_owned(),
        ));
    }
    let system_directory = paths::system_directory().map_err(|source| NetworkError::Io {
        action: "locate trusted Windows system directory",
        source,
    })?;
    let windows_directory = system_directory.parent().ok_or_else(|| {
        NetworkError::Invalid("Windows system directory has no parent".to_owned())
    })?;
    let powershell = system_directory
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    let powershell_directory = powershell.parent().expect("PowerShell path has a parent");
    let trusted_path = std::env::join_paths([system_directory.as_path(), powershell_directory])
        .map_err(|error| NetworkError::Invalid(format!("build trusted Windows PATH: {error}")))?;
    let module_path = powershell_directory.join("Modules");
    let windows_temp = windows_directory.join("Temp");
    let system_drive = windows_directory
        .components()
        .next()
        .map(|component| component.as_os_str().to_os_string());
    let mut command = Command::new(powershell);
    command
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-Command")
        .arg("-")
        .current_dir(&system_directory)
        .env_clear()
        .env("SystemRoot", windows_directory)
        .env("WINDIR", windows_directory)
        .env("PATH", trusted_path)
        .env("PATHEXT", ".COM;.EXE;.BAT;.CMD")
        .env("ComSpec", system_directory.join("cmd.exe"))
        .env("PSModulePath", module_path)
        .env("TEMP", &windows_temp)
        .env("TMP", windows_temp)
        .env("PORTA_NETWORK_OPERATION", operation)
        .env("PORTA_NETWORK_STATE_PATH", state_path)
        .env(
            "PORTA_NETWORK_ADDRESS_CIDR",
            arguments.get(2).map_or_else(OsString::new, Clone::clone),
        )
        .env(
            "PORTA_NETWORK_DNS_SERVER",
            arguments.get(3).map_or_else(OsString::new, Clone::clone),
        )
        .env(
            "PORTA_NETWORK_MTU",
            arguments
                .get(4)
                .cloned()
                .unwrap_or_else(|| OsString::from("1100")),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .kill_on_drop(true);
    if let Some(system_drive) = system_drive {
        command.env("SystemDrive", system_drive);
    }
    let output = timeout(COMMAND_TIMEOUT, async move {
        let mut child = command.spawn()?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "network helper standard input is unavailable",
            )
        })?;
        stdin.write_all(b"\xef\xbb\xbf").await?;
        stdin.write_all(NETWORK_SCRIPT.as_bytes()).await?;
        stdin.shutdown().await?;
        drop(stdin);
        child.wait_with_output().await
    })
    .await
    .map_err(|_| NetworkError::Command {
        command: "network helper".to_owned(),
        detail: "timed out after 20 seconds".to_owned(),
    })?
    .map_err(|source| NetworkError::Io {
        action: "start network helper",
        source,
    })?;
    if !output.status.success() {
        let detail = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr)
        );
        return Err(NetworkError::Command {
            command: "network helper".to_owned(),
            detail: detail.trim().to_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(not(windows))]
async fn invoke_powershell<I>(_state_path: &Path, _arguments: I) -> Result<String, NetworkError>
where
    I: IntoIterator<Item = OsString>,
{
    Err(NetworkError::Unsupported)
}

#[cfg(windows)]
fn open_lock(path: &Path) -> Result<File, NetworkError> {
    use fs2::FileExt;
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let (file, created) = match options.create_new(true).open(path) {
        Ok(file) => (file, true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            options.create_new(false);
            (
                options.open(path).map_err(|source| NetworkError::Io {
                    action: "open network ownership lock",
                    source,
                })?,
                false,
            )
        }
        Err(source) => {
            return Err(NetworkError::Io {
                action: "open network ownership lock",
                source,
            });
        }
    };
    if created {
        secure_new_file(path, &file, "secure network ownership lock")?;
    } else {
        paths::adopt_admin_file(path, &file).map_err(|source| NetworkError::Io {
            action: "secure network ownership lock",
            source,
        })?;
    }
    FileExt::try_lock_exclusive(&file).map_err(|source| {
        if source.kind() == std::io::ErrorKind::WouldBlock {
            NetworkError::StateInUse
        } else {
            NetworkError::Io {
                action: "lock network ownership",
                source,
            }
        }
    })?;
    Ok(file)
}

#[cfg(not(windows))]
fn open_lock(path: &Path) -> Result<File, NetworkError> {
    OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(path)
        .map_err(|source| NetworkError::Io {
            action: "open network ownership lock",
            source,
        })
}

#[cfg(windows)]
fn unlock_file(file: &File) -> Result<(), NetworkError> {
    use fs2::FileExt;

    FileExt::unlock(file).map_err(|source| NetworkError::Io {
        action: "unlock network ownership",
        source,
    })
}

#[cfg(not(windows))]
fn unlock_file(_file: &File) -> Result<(), NetworkError> {
    Ok(())
}

#[cfg(windows)]
fn replace_journal(source: &Path, destination: &Path) -> Result<(), NetworkError> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        return Err(NetworkError::Io {
            action: "replace network state",
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace_journal(source: &Path, destination: &Path) -> Result<(), NetworkError> {
    fs::rename(source, destination).map_err(|source| NetworkError::Io {
        action: "replace network state",
        source,
    })
}

#[cfg(windows)]
fn native_interface_luid(name: &str) -> Result<u64, NetworkError> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceAliasToLuid;
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    let name: Vec<u16> = OsStr::new(name).encode_wide().chain(Some(0)).collect();
    let mut luid = NET_LUID_LH::default();
    let code = unsafe { ConvertInterfaceAliasToLuid(name.as_ptr(), &mut luid) };
    if code != 0 {
        return Err(NetworkError::Windows {
            action: "resolve tunnel interface LUID",
            code,
        });
    }
    let value = unsafe { luid.Value };
    if value == 0 {
        return Err(NetworkError::Invalid(
            "tunnel interface LUID is zero".to_owned(),
        ));
    }
    Ok(value)
}

#[cfg(not(windows))]
fn native_interface_luid(_name: &str) -> Result<u64, NetworkError> {
    Err(NetworkError::Unsupported)
}

#[cfg(windows)]
fn native_interface_guid(luid: u64) -> Result<String, NetworkError> {
    use windows_sys::core::GUID;
    use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceLuidToGuid;
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    let luid = NET_LUID_LH { Value: luid };
    let mut guid = GUID::default();
    let code = unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) };
    if code != 0 {
        return Err(NetworkError::Windows {
            action: "resolve tunnel interface GUID",
            code,
        });
    }
    if guid.data1 == 0 && guid.data2 == 0 && guid.data3 == 0 && guid.data4 == [0; 8] {
        return Err(NetworkError::Invalid(
            "tunnel interface GUID is zero".to_owned(),
        ));
    }
    Ok(format_guid(guid))
}

#[cfg(not(windows))]
fn native_interface_guid(_luid: u64) -> Result<String, NetworkError> {
    Err(NetworkError::Unsupported)
}

#[cfg(windows)]
fn native_interface_mtu(luid: u64) -> Result<u32, NetworkError> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetIpInterfaceEntry, MIB_IPINTERFACE_ROW,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    let mut row = MIB_IPINTERFACE_ROW {
        Family: AF_INET,
        InterfaceLuid: NET_LUID_LH { Value: luid },
        ..Default::default()
    };
    let code = unsafe { GetIpInterfaceEntry(&mut row) };
    if code != 0 {
        return Err(NetworkError::Windows {
            action: "GetIpInterfaceEntry",
            code,
        });
    }
    Ok(row.NlMtu)
}

#[cfg(not(windows))]
fn native_interface_mtu(_luid: u64) -> Result<u32, NetworkError> {
    Err(NetworkError::Unsupported)
}

#[cfg(windows)]
fn set_native_interface_mtu(luid: u64, mtu: u32) -> Result<(), NetworkError> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetIpInterfaceEntry, SetIpInterfaceEntry, MIB_IPINTERFACE_ROW,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    let mut row = MIB_IPINTERFACE_ROW {
        Family: AF_INET,
        InterfaceLuid: NET_LUID_LH { Value: luid },
        ..Default::default()
    };
    let code = unsafe { GetIpInterfaceEntry(&mut row) };
    if code != 0 {
        return Err(NetworkError::Windows {
            action: "GetIpInterfaceEntry before update",
            code,
        });
    }
    row.NlMtu = mtu;
    row.SitePrefixLength = 0;
    let code = unsafe { SetIpInterfaceEntry(&mut row) };
    if code != 0 {
        return Err(NetworkError::Windows {
            action: "SetIpInterfaceEntry",
            code,
        });
    }
    Ok(())
}

#[cfg(not(windows))]
fn set_native_interface_mtu(_luid: u64, _mtu: u32) -> Result<(), NetworkError> {
    Err(NetworkError::Unsupported)
}

#[cfg(windows)]
fn replace_guard(spec: &GuardSpec) -> Result<(), NetworkError> {
    with_wfp_transaction(|engine| install_guard(engine, spec))
}

#[cfg(not(windows))]
fn replace_guard(_spec: &GuardSpec) -> Result<(), NetworkError> {
    Err(NetworkError::Unsupported)
}

#[cfg(windows)]
fn remove_guard(owner: &str) -> Result<(), NetworkError> {
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmSubLayerDeleteByKey0;

    with_wfp_transaction(|engine| {
        delete_filters(engine, owner)?;
        let key = guid_from_key(&object_key(owner, -1));
        let code = unsafe { FwpmSubLayerDeleteByKey0(engine, &key) };
        if code != 0 && code != 0x8032_0007 {
            return Err(NetworkError::Windows {
                action: "remove owned WFP sublayer",
                code,
            });
        }
        Ok(())
    })
}

#[cfg(not(windows))]
fn remove_guard(_owner: &str) -> Result<(), NetworkError> {
    Err(NetworkError::Unsupported)
}

#[cfg(windows)]
fn with_wfp_transaction(
    change: impl FnOnce(windows_sys::Win32::Foundation::HANDLE) -> Result<(), NetworkError>,
) -> Result<(), NetworkError> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FwpmEngineClose0, FwpmEngineOpen0, FwpmTransactionAbort0, FwpmTransactionBegin0,
        FwpmTransactionCommit0,
    };
    use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

    let mut engine: HANDLE = null_mut();
    let code = unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), null(), &mut engine) };
    if code != 0 {
        return Err(NetworkError::Windows {
            action: "FwpmEngineOpen0",
            code,
        });
    }
    let result = (|| {
        let code = unsafe { FwpmTransactionBegin0(engine, 0) };
        if code != 0 {
            return Err(NetworkError::Windows {
                action: "FwpmTransactionBegin0",
                code,
            });
        }
        match change(engine) {
            Ok(()) => {
                let code = unsafe { FwpmTransactionCommit0(engine) };
                if code == 0 {
                    Ok(())
                } else {
                    unsafe {
                        FwpmTransactionAbort0(engine);
                    }
                    Err(NetworkError::Windows {
                        action: "FwpmTransactionCommit0",
                        code,
                    })
                }
            }
            Err(error) => {
                unsafe {
                    FwpmTransactionAbort0(engine);
                }
                Err(error)
            }
        }
    })();
    let close = unsafe { FwpmEngineClose0(engine) };
    combine(
        result,
        if close == 0 {
            Ok(())
        } else {
            Err(NetworkError::Windows {
                action: "FwpmEngineClose0",
                code: close,
            })
        },
    )
}

#[cfg(windows)]
fn delete_filters(
    engine: windows_sys::Win32::Foundation::HANDLE,
    owner: &str,
) -> Result<(), NetworkError> {
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmFilterDeleteByKey0;

    for index in 0..MAX_GUARD_FILTERS {
        let key = guid_from_key(&object_key(owner, index as i32));
        let code = unsafe { FwpmFilterDeleteByKey0(engine, &key) };
        if code != 0 && code != 0x8032_0003 {
            return Err(NetworkError::Windows {
                action: "remove owned WFP filter",
                code,
            });
        }
    }
    Ok(())
}

#[cfg(windows)]
fn install_guard(
    engine: windows_sys::Win32::Foundation::HANDLE,
    spec: &GuardSpec,
) -> Result<(), NetworkError> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt as _;
    use std::ptr::{null_mut, NonNull};
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FwpmGetAppIdFromFileName0, FwpmSubLayerAdd0, FWPM_DISPLAY_DATA0, FWPM_SUBLAYER0,
        FWPM_SUBLAYER_FLAG_PERSISTENT, FWP_BYTE_BLOB,
    };

    let policy = guard_filters(spec);
    if policy.len() > MAX_GUARD_FILTERS {
        return Err(NetworkError::Invalid("too many guard filters".to_owned()));
    }
    let path: Vec<u16> = OsStr::new(&spec.application)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut app_id: *mut FWP_BYTE_BLOB = null_mut();
    let code = unsafe { FwpmGetAppIdFromFileName0(path.as_ptr(), &mut app_id) };
    if code != 0 {
        return Err(NetworkError::Windows {
            action: "FwpmGetAppIdFromFileName0",
            code,
        });
    }
    let app_id = NonNull::new(app_id).ok_or_else(|| {
        NetworkError::Invalid("WFP returned an empty application identity".to_owned())
    })?;
    struct AppId(*mut c_void);
    impl Drop for AppId {
        fn drop(&mut self) {
            unsafe {
                windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmFreeMemory0(
                    &mut self.0,
                );
            }
        }
    }
    let _app_id_guard = AppId(app_id.as_ptr().cast());

    let mut name: Vec<u16> = OsStr::new("Porta persistent full-tunnel guard")
        .encode_wide()
        .chain(Some(0))
        .collect();
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: guid_from_key(&object_key(&spec.key, -1)),
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: null_mut(),
        },
        flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
        weight: u16::MAX,
        ..Default::default()
    };
    let code = unsafe { FwpmSubLayerAdd0(engine, &sublayer, null_mut()) };
    if code != 0 && code != 0x8032_0009 {
        return Err(NetworkError::Windows {
            action: "add persistent WFP sublayer",
            code,
        });
    }
    delete_filters(engine, &spec.key)?;
    for (index, filter) in policy.iter().enumerate() {
        add_guard_filter(
            engine,
            &spec.key,
            index,
            filter,
            name.as_mut_ptr(),
            app_id.as_ptr(),
        )
        .map_err(|error| {
            NetworkError::Combined(format!("install {} filter {index}: {error}", filter.layer))
        })?;
    }
    drop(_app_id_guard);
    Ok(())
}

#[cfg(windows)]
fn add_guard_filter(
    engine: windows_sys::Win32::Foundation::HANDLE,
    owner: &str,
    index: usize,
    rule: &Filter,
    name: *mut u16,
    app_id: *mut windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB,
) -> Result<(), NetworkError> {
    use std::ptr::null_mut;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FwpmFilterAdd0, FWPM_ACTION0, FWPM_DISPLAY_DATA0, FWPM_FILTER0,
        FWPM_FILTER_FLAG_PERSISTENT, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_UINT64, FWP_VALUE0,
        FWP_VALUE0_0,
    };

    let mut conditions = NativeConditions::new(&rule.conditions, app_id);
    let mut weight = Box::new(if rule.permit { 100_u64 } else { 1_u64 });
    let filter = FWPM_FILTER0 {
        filterKey: guid_from_key(&object_key(owner, index as i32)),
        displayData: FWPM_DISPLAY_DATA0 {
            name,
            description: null_mut(),
        },
        flags: FWPM_FILTER_FLAG_PERSISTENT,
        layerKey: layer_guid(rule.layer),
        subLayerKey: guid_from_key(&object_key(owner, -1)),
        weight: FWP_VALUE0 {
            r#type: FWP_UINT64,
            Anonymous: FWP_VALUE0_0 {
                uint64: weight.as_mut(),
            },
        },
        numFilterConditions: conditions.values.len() as u32,
        filterCondition: if conditions.values.is_empty() {
            null_mut()
        } else {
            conditions.values.as_mut_ptr()
        },
        action: FWPM_ACTION0 {
            r#type: if rule.permit {
                FWP_ACTION_PERMIT
            } else {
                FWP_ACTION_BLOCK
            },
            ..FWPM_ACTION0::default()
        },
        ..Default::default()
    };
    let code = unsafe { FwpmFilterAdd0(engine, &filter, null_mut(), null_mut()) };
    if code != 0 {
        return Err(NetworkError::Windows {
            action: "FwpmFilterAdd0",
            code,
        });
    }
    Ok(())
}

#[cfg(windows)]
#[allow(clippy::vec_box)] // WFP condition values retain pointers into these stable allocations.
struct NativeConditions {
    values: Vec<
        windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER_CONDITION0,
    >,
    _luids: Vec<Box<u64>>,
    _v4_masks: Vec<
        Box<windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_V4_ADDR_AND_MASK>,
    >,
    _v6_masks: Vec<
        Box<windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_V6_ADDR_AND_MASK>,
    >,
}

#[cfg(windows)]
impl NativeConditions {
    fn new(
        input: &[Condition],
        app_id: *mut windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB,
    ) -> Self {
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
            FWPM_FILTER_CONDITION0, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_FLAG_IS_LOOPBACK,
            FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ALL_SET,
            FWP_UINT16, FWP_UINT32, FWP_UINT64, FWP_UINT8, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK,
            FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK,
        };

        let mut result = Self {
            values: Vec::with_capacity(input.len()),
            _luids: Vec::new(),
            _v4_masks: Vec::new(),
            _v6_masks: Vec::new(),
        };
        for condition in input {
            let mut native = FWPM_FILTER_CONDITION0 {
                matchType: FWP_MATCH_EQUAL,
                ..Default::default()
            };
            match condition {
                Condition::Loopback => {
                    native.fieldKey = condition_guid("loopback");
                    native.matchType = FWP_MATCH_FLAGS_ALL_SET;
                    native.conditionValue = FWP_CONDITION_VALUE0 {
                        r#type: FWP_UINT32,
                        Anonymous: FWP_CONDITION_VALUE0_0 {
                            uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                        },
                    };
                }
                Condition::Interface(luid) => {
                    native.fieldKey = condition_guid("interface");
                    let mut value = Box::new(*luid);
                    native.conditionValue = FWP_CONDITION_VALUE0 {
                        r#type: FWP_UINT64,
                        Anonymous: FWP_CONDITION_VALUE0_0 {
                            uint64: value.as_mut(),
                        },
                    };
                    result._luids.push(value);
                }
                Condition::Application(_) => {
                    native.fieldKey = condition_guid("application");
                    native.conditionValue = FWP_CONDITION_VALUE0 {
                        r#type: FWP_BYTE_BLOB_TYPE,
                        Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: app_id },
                    };
                }
                Condition::Protocol(protocol) => {
                    native.fieldKey = condition_guid("protocol");
                    native.conditionValue = FWP_CONDITION_VALUE0 {
                        r#type: FWP_UINT8,
                        Anonymous: FWP_CONDITION_VALUE0_0 { uint8: *protocol },
                    };
                }
                Condition::RemotePort(port) | Condition::LocalPort(port) => {
                    native.fieldKey =
                        condition_guid(if matches!(condition, Condition::RemotePort(_)) {
                            "port"
                        } else {
                            "local-port"
                        });
                    native.conditionValue = FWP_CONDITION_VALUE0 {
                        r#type: FWP_UINT16,
                        Anonymous: FWP_CONDITION_VALUE0_0 { uint16: *port },
                    };
                }
                Condition::Address(prefix) => match prefix {
                    IpNet::V4(prefix) => {
                        native.fieldKey = condition_guid("address");
                        let bits = prefix.prefix_len();
                        let mut mask = Box::new(FWP_V4_ADDR_AND_MASK {
                            addr: u32::from_be_bytes(prefix.addr().octets()),
                            mask: if bits == 0 {
                                0
                            } else {
                                u32::MAX << (32 - bits)
                            },
                        });
                        native.conditionValue = FWP_CONDITION_VALUE0 {
                            r#type: FWP_V4_ADDR_MASK,
                            Anonymous: FWP_CONDITION_VALUE0_0 {
                                v4AddrMask: mask.as_mut(),
                            },
                        };
                        result._v4_masks.push(mask);
                    }
                    IpNet::V6(prefix) => {
                        native.fieldKey = condition_guid("address");
                        let mut mask = Box::new(FWP_V6_ADDR_AND_MASK {
                            addr: prefix.addr().octets(),
                            prefixLength: prefix.prefix_len(),
                        });
                        native.conditionValue = FWP_CONDITION_VALUE0 {
                            r#type: FWP_V6_ADDR_MASK,
                            Anonymous: FWP_CONDITION_VALUE0_0 {
                                v6AddrMask: mask.as_mut(),
                            },
                        };
                        result._v6_masks.push(mask);
                    }
                },
            }
            result.values.push(native);
        }
        result
    }
}

#[cfg(windows)]
fn layer_guid(layer: &str) -> windows_sys::core::GUID {
    guid_from_key(match layer {
        "packet4" => "1e5c9fae-8a84-4135-a331-950b54229ecd",
        "packet6" => "a3b3ab6b-3564-488c-9117-f34e82142763",
        "transport4" => "09e61aea-d214-46e2-9b21-b26b0b2f28c8",
        "transport6" => "e1735bde-013f-4655-b351-a49e15762df0",
        "connect4" => "c38d57d1-05a7-4c33-904f-7fbceee60e82",
        "connect6" => "4a72393b-319f-44bc-84c3-ba54dcb3b6b4",
        "accept4" => "e1cd9fe7-f4b5-4273-96c0-592e487b8650",
        "accept6" => "a3b42c97-9f04-4672-b87e-cee9c483257f",
        "forward4" => "a82acc24-4ee1-4ee1-b465-fd1d25cb10a4",
        "forward6" => "7b964818-19c7-493a-b71f-832c3684d28c",
        _ => unreachable!("known WFP layer"),
    })
}

#[cfg(windows)]
fn condition_guid(condition: &str) -> windows_sys::core::GUID {
    guid_from_key(match condition {
        "interface" => "4cd62a49-59c3-4969-b7f3-bda5d32890a4",
        "application" => "d78e1e87-8644-4ea5-9437-d809ecefc971",
        "address" => "b235ae9a-1d64-49b8-a44c-5ff3d9095045",
        "port" => "c35a604d-d22b-4e1a-91b4-68f674ee674b",
        "local-port" => "0c1ba1af-5765-453f-af22-a8f791ac775b",
        "protocol" => "3971ef2b-623e-4f9a-8cb1-6e79b806b9a7",
        "loopback" => "632ce23b-5167-435c-86d7-e903684aa80c",
        _ => unreachable!("known WFP condition"),
    })
}

fn parse_guid(value: &str) -> Option<[u8; 16]> {
    let value = value
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .unwrap_or(value);
    if value.len() != 36
        || value.as_bytes().get(8) != Some(&b'-')
        || value.as_bytes().get(13) != Some(&b'-')
        || value.as_bytes().get(18) != Some(&b'-')
        || value.as_bytes().get(23) != Some(&b'-')
    {
        return None;
    }
    let compact = value.replace('-', "");
    let decoded = hex::decode(compact).ok()?;
    decoded.try_into().ok()
}

#[cfg(windows)]
fn guid_from_key(value: &str) -> windows_sys::core::GUID {
    let bytes = parse_guid(value).expect("static or generated GUID");
    windows_sys::core::GUID::from_u128(u128::from_be_bytes(bytes))
}

#[cfg(windows)]
fn format_guid(guid: windows_sys::core::GUID) -> String {
    format!(
        "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}}}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        hex::encode(&guid.data4[2..])
    )
}

fn is_zero_i32(value: &i32) -> bool {
    *value == 0
}

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn test_state() -> NetworkState {
        NetworkState {
            version: NATIVE_MTU_STATE_VERSION,
            interface: "Porta".to_owned(),
            server_ip: "192.0.2.1".to_owned(),
            guard_key: "{aaaaaaaa-aaaa-5aaa-8aaa-aaaaaaaaaaaa}".to_owned(),
            endpoint: EndpointState {
                ip: "192.0.2.1".parse().unwrap(),
                port: 443,
            },
            application: r"C:\Porta\porta.exe".to_owned(),
            interface_luid: 77,
            interface_index: 77,
            interface_guid: "{77777777-7777-7777-7777-777777777777}".to_owned(),
            original_dhcp: "Disabled".to_owned(),
            addresses: vec!["10.0.0.2/24".to_owned()],
            routes: vec![RouteState {
                kind: "escape".to_owned(),
                prefix: "192.0.2.1/32".to_owned(),
                interface_index: 7,
                interface_guid: "{11111111-1111-1111-1111-111111111111}".to_owned(),
                next_hop: "192.0.2.254".to_owned(),
                metric: 1,
            }],
            dns: Some(DnsState {
                interface_index: 77,
                automatic: false,
                original: vec!["9.9.9.9".to_owned()],
                applied: "1.1.1.1".to_owned(),
                pending: String::new(),
            }),
            mtu: Some(MtuState {
                original: 1500,
                applied: 1280,
                pending: 0,
            }),
        }
    }

    fn test_spec(ip: &str) -> GuardSpec {
        GuardSpec {
            key: "test".to_owned(),
            interface_luid: 77,
            endpoint: EndpointState {
                ip: ip.parse().unwrap(),
                port: 443,
            },
            application: r"C:\Porta\porta.exe".to_owned(),
        }
    }

    #[test]
    fn journal_versions_two_and_three_are_compatible() {
        for version in [EXACT_OWNERSHIP_STATE_VERSION, NATIVE_MTU_STATE_VERSION] {
            let mut state = test_state();
            state.version = version;
            let data = serde_json::to_vec(&state).unwrap();
            let decoded: NetworkState = serde_json::from_slice(&data).unwrap();
            validate_state(&decoded).unwrap();
        }
    }

    #[test]
    fn journal_rejects_incomplete_or_inexact_ownership() {
        type StateDamage = Box<dyn Fn(&mut NetworkState)>;
        let damages: Vec<StateDamage> = vec![
            Box::new(|state| state.version = 4),
            Box::new(|state| state.interface.clear()),
            Box::new(|state| state.guard_key.clear()),
            Box::new(|state| state.interface_guid.clear()),
            Box::new(|state| state.server_ip = "203.0.113.1".to_owned()),
            Box::new(|state| state.routes[0].interface_guid.clear()),
            Box::new(|state| state.mtu = Some(MtuState::default())),
            Box::new(|state| {
                state.dns.as_mut().unwrap().pending = "invalid".to_owned();
            }),
        ];
        for damage in damages {
            let mut state = test_state();
            damage(&mut state);
            assert!(validate_state(&state).is_err());
        }
    }

    #[test]
    fn object_keys_are_stable_unique_and_owner_scoped() {
        let mut seen = HashSet::new();
        for owner in ["profile-a", "profile-b"] {
            for index in -2..MAX_GUARD_FILTERS as i32 {
                let key = object_key(owner, index);
                assert_eq!(key, object_key(owner, index));
                assert_eq!(key.len(), 36);
                assert!(valid_journal_guid(&key));
                assert!(seen.insert(key));
            }
        }
    }

    #[test]
    fn policy_has_final_blocks_and_narrow_transport_permits() {
        for endpoint in ["192.0.2.1", "2001:db8::1"] {
            let spec = test_spec(endpoint);
            let filters = guard_filters(&spec);
            assert!(filters.len() <= MAX_GUARD_FILTERS);
            for layer in [
                "packet4",
                "transport4",
                "connect4",
                "accept4",
                "packet6",
                "transport6",
                "connect6",
                "accept6",
                "forward4",
                "forward6",
            ] {
                let rules: Vec<_> = filters
                    .iter()
                    .filter(|filter| filter.layer == layer)
                    .collect();
                assert!(!rules.is_empty(), "missing {layer}");
                assert!(!rules.last().unwrap().permit, "{layer} lacks final block");
            }
            for filter in filters.iter().filter(|filter| {
                filter.permit
                    && (filter.layer.starts_with("connect") || filter.layer.starts_with("accept"))
                    && filter
                        .conditions
                        .iter()
                        .any(|condition| matches!(condition, Condition::RemotePort(443)))
            }) {
                assert!(filter
                    .conditions
                    .iter()
                    .any(|condition| matches!(condition, Condition::Protocol(6 | 17))));
                assert!(filter.conditions.iter().any(
                    |condition| matches!(condition, Condition::Application(path) if path == &spec.application)
                ));
            }
            assert!(filters
                .iter()
                .filter(|filter| filter.layer.starts_with("forward"))
                .all(|filter| !filter.permit));
        }
    }

    #[test]
    fn no_interface_policy_never_adds_interface_permits() {
        let mut spec = test_spec("192.0.2.1");
        spec.interface_luid = 0;
        assert!(guard_filters(&spec).iter().all(|filter| {
            !filter
                .conditions
                .iter()
                .any(|condition| matches!(condition, Condition::Interface(_)))
        }));
    }

    #[test]
    fn endpoint_rejects_dns_ports_and_scoped_or_non_unicast_addresses() {
        for endpoint in [
            "0.0.0.0:443".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
            "192.0.2.1:53".parse().unwrap(),
            "192.0.2.1:853".parse().unwrap(),
            "[fe80::1%7]:443".parse().unwrap(),
        ] {
            assert!(parse_endpoint(&endpoint).is_err(), "{endpoint}");
        }
    }
}
