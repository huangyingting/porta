use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use thiserror::Error;

const STATE_VERSION: u32 = 2;
static TEMP_FILE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Error)]
pub enum PoolError {
    #[error("address pool is exhausted")]
    Exhausted,
    #[error("{0}")]
    Invalid(String),
    #[error("{context}: {source}")]
    Io {
        context: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("lease state was replaced but directory sync failed: {0}")]
    Durability(#[source] io::Error),
    #[error("{context}: {source}")]
    Json {
        context: &'static str,
        #[source]
        source: serde_json::Error,
    },
}

pub type Result<T> = std::result::Result<T, PoolError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lease {
    pub address: Ipv4Addr,
    pub prefix_bits: u8,
    pub gateway: Ipv4Addr,
    generation: u64,
    client_id: String,
}

impl Lease {
    pub fn prefix(&self) -> Ipv4Net {
        Ipv4Net::new(self.address, self.prefix_bits).expect("validated IPv4 prefix")
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }
}

#[derive(Clone, Copy, Debug)]
struct LeaseRecord {
    address: Ipv4Addr,
    generation: u64,
    active: bool,
}

#[derive(Clone, Debug)]
struct ActiveLeaseGroup {
    id: String,
    generation: u64,
    references: usize,
}

#[derive(Debug)]
struct PoolInner {
    by_client: HashMap<String, LeaseRecord>,
    by_address: HashMap<Ipv4Addr, String>,
    groups: HashMap<String, ActiveLeaseGroup>,
    next_generation: u64,
}

#[derive(Debug)]
pub struct Pool {
    prefix: Ipv4Net,
    gateway: Ipv4Addr,
    state_path: Option<PathBuf>,
    inner: Mutex<PoolInner>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct PersistedLease {
    #[serde(default)]
    address: String,
    #[serde(default)]
    generation: u64,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct PoolState {
    version: u32,
    leases: BTreeMap<String, PersistedLease>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pool: Option<String>,
}

impl Pool {
    pub fn new(cidr: impl AsRef<str>) -> Result<Self> {
        Self::new_with_path(cidr.as_ref(), None)
    }

    pub fn new_persistent(cidr: impl AsRef<str>, state_path: impl AsRef<Path>) -> Result<Self> {
        let state_path = state_path.as_ref();
        if state_path.as_os_str().is_empty() {
            return Err(PoolError::Invalid(
                "lease state path is required".to_owned(),
            ));
        }
        Self::new_with_path(cidr.as_ref(), Some(state_path.to_owned()))
    }

    pub fn from_prefix(prefix: Ipv4Net) -> Result<Self> {
        Self::from_prefix_with_path(prefix, None)
    }

    pub fn from_prefix_persistent(prefix: Ipv4Net, state_path: impl AsRef<Path>) -> Result<Self> {
        let state_path = state_path.as_ref();
        if state_path.as_os_str().is_empty() {
            return Err(PoolError::Invalid(
                "lease state path is required".to_owned(),
            ));
        }
        Self::from_prefix_with_path(prefix, Some(state_path.to_owned()))
    }

    fn new_with_path(cidr: &str, state_path: Option<PathBuf>) -> Result<Self> {
        let prefix = parse_ipv4_prefix(cidr)?;
        Self::from_prefix_with_path(prefix, state_path)
    }

    fn from_prefix_with_path(prefix: Ipv4Net, state_path: Option<PathBuf>) -> Result<Self> {
        let prefix = Ipv4Net::new(prefix.network(), prefix.prefix_len())
            .expect("an existing IPv4 network has a valid prefix");
        if !(16..=30).contains(&prefix.prefix_len()) {
            return Err(PoolError::Invalid(format!(
                "pool prefix /{} is outside /16../30",
                prefix.prefix_len()
            )));
        }
        let gateway = increment(prefix.network())
            .expect("a /16../30 IPv4 network always has a gateway address");
        let pool = Self {
            prefix,
            gateway,
            state_path,
            inner: Mutex::new(PoolInner {
                by_client: HashMap::new(),
                by_address: HashMap::new(),
                groups: HashMap::new(),
                next_generation: 0,
            }),
        };
        if pool.state_path.is_some() {
            pool.load_state()?;
        }
        Ok(pool)
    }

    pub fn acquire(&self, client_id: &str) -> Result<Lease> {
        self.acquire_inner(client_id, "")
    }

    pub fn acquire_group(&self, client_id: &str, group_id: &str) -> Result<Lease> {
        if group_id.is_empty() {
            return Err(PoolError::Invalid("lease group ID is required".to_owned()));
        }
        self.acquire_inner(client_id, group_id)
    }

    fn acquire_inner(&self, client_id: &str, group_id: &str) -> Result<Lease> {
        self.acquire_inner_with_sync(client_id, group_id, sync_directory)
    }

    fn acquire_inner_with_sync(
        &self,
        client_id: &str,
        group_id: &str,
        sync_directory: fn(&Path) -> io::Result<()>,
    ) -> Result<Lease> {
        if !valid_client_id(client_id) {
            return Err(PoolError::Invalid("invalid client ID".to_owned()));
        }

        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        if !group_id.is_empty() {
            if let Some(group) = inner.groups.get(client_id).cloned() {
                if group.id == group_id {
                    if let Some(record) = inner.by_client.get(client_id).copied() {
                        if record.generation == group.generation && record.active {
                            inner
                                .groups
                                .get_mut(client_id)
                                .expect("the matching group still exists")
                                .references += 1;
                            return Ok(self.lease(client_id, record));
                        }
                    }
                }
            }
        }

        inner.next_generation += 1;
        let generation = inner.next_generation;
        if let Some(previous) = inner.by_client.get(client_id).copied() {
            let previous_group = inner.groups.get(client_id).cloned();
            let replacement = LeaseRecord {
                generation,
                active: true,
                ..previous
            };
            inner.by_client.insert(client_id.to_owned(), replacement);
            if let Err(error) = self.persist_state_locked(&inner, sync_directory) {
                if matches!(error, PoolError::Durability(_)) {
                    abandon_committed_lease(&mut inner, client_id);
                } else {
                    inner.by_client.insert(client_id.to_owned(), previous);
                    match previous_group {
                        Some(group) => {
                            inner.groups.insert(client_id.to_owned(), group);
                        }
                        None => {
                            inner.groups.remove(client_id);
                        }
                    }
                }
                return Err(error);
            }
            activate_group(&mut inner, client_id, group_id, generation);
            return Ok(self.lease(client_id, replacement));
        }

        let broadcast = broadcast(self.prefix);
        let mut candidate = increment(self.gateway);
        while let Some(address) = candidate {
            if address >= broadcast {
                break;
            }
            if !inner.by_address.contains_key(&address) {
                let record = LeaseRecord {
                    address,
                    generation,
                    active: true,
                };
                inner.by_client.insert(client_id.to_owned(), record);
                inner.by_address.insert(address, client_id.to_owned());
                if let Err(error) = self.persist_state_locked(&inner, sync_directory) {
                    if matches!(error, PoolError::Durability(_)) {
                        abandon_committed_lease(&mut inner, client_id);
                    } else {
                        inner.by_client.remove(client_id);
                        inner.by_address.remove(&address);
                    }
                    return Err(error);
                }
                activate_group(&mut inner, client_id, group_id, generation);
                return Ok(self.lease(client_id, record));
            }
            candidate = increment(address);
        }

        // Inactive reservations still own their addresses: cross-identity reuse is
        // unsafe until old conntrack state can be retired fail-closed.
        Err(PoolError::Exhausted)
    }

    pub fn release(&self, lease: &Lease) {
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        let Some(record) = inner.by_client.get(&lease.client_id).copied() else {
            return;
        };
        if record.generation != lease.generation {
            return;
        }
        if let Some(group) = inner.groups.get_mut(&lease.client_id) {
            if group.generation == lease.generation {
                if group.references > 1 {
                    group.references -= 1;
                    return;
                }
                inner.groups.remove(&lease.client_id);
            }
        }
        inner.by_client.insert(
            lease.client_id.clone(),
            LeaseRecord {
                active: false,
                ..record
            },
        );
    }

    pub fn register_lease<F>(&self, lease: &Lease, register: F) -> bool
    where
        F: FnOnce(),
    {
        let inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        let valid = inner
            .by_client
            .get(&lease.client_id)
            .is_some_and(|record| record.active && record.generation == lease.generation);
        if valid {
            register();
        }
        valid
    }

    pub fn gateway(&self) -> Ipv4Addr {
        self.gateway
    }

    pub fn network(&self) -> Ipv4Net {
        self.prefix
    }

    fn lease(&self, client_id: &str, record: LeaseRecord) -> Lease {
        Lease {
            address: record.address,
            prefix_bits: self.prefix.prefix_len(),
            gateway: self.gateway,
            generation: record.generation,
            client_id: client_id.to_owned(),
        }
    }

    fn load_state(&self) -> Result<()> {
        let path = self.state_path.as_ref().expect("checked by caller");
        let data = match fs::read(path) {
            Ok(data) => data,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(source) => {
                return Err(PoolError::Io {
                    context: "read lease state",
                    source,
                });
            }
        };
        let state: PoolState = serde_json::from_slice(&data).map_err(|source| PoolError::Json {
            context: "decode lease state",
            source,
        })?;
        if state.version != STATE_VERSION {
            return Err(PoolError::Invalid(format!(
                "unsupported lease state version {}",
                state.version
            )));
        }
        if let Some(persisted_pool) = &state.pool {
            let parsed = parse_ipv4_prefix(persisted_pool).map_err(|_| {
                PoolError::Invalid(format!(
                    "lease state contains invalid pool {persisted_pool:?}"
                ))
            })?;
            if parsed != self.prefix {
                return Err(PoolError::Invalid(format!(
                    "lease state pool {persisted_pool} is incompatible with {}",
                    self.prefix
                )));
            }
        }

        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        for (client_id, persisted) in state.leases {
            if persisted.generation == 0 {
                return Err(PoolError::Invalid(format!(
                    "lease state contains zero generation for {client_id:?}"
                )));
            }
            self.restore_lease(
                &mut inner,
                &client_id,
                &persisted.address,
                persisted.generation,
            )?;
            inner.next_generation = inner.next_generation.max(persisted.generation);
        }
        Ok(())
    }

    fn restore_lease(
        &self,
        inner: &mut PoolInner,
        client_id: &str,
        value: &str,
        generation: u64,
    ) -> Result<()> {
        if !valid_client_id(client_id) {
            return Err(PoolError::Invalid(format!(
                "lease state contains invalid client ID {client_id:?}"
            )));
        }
        let address = value.parse::<Ipv4Addr>().map_err(|_| {
            PoolError::Invalid(format!(
                "lease state contains invalid address {value:?} for {client_id:?}"
            ))
        })?;
        let broadcast = broadcast(self.prefix);
        if !self.prefix.contains(&address) || address <= self.gateway || address >= broadcast {
            return Err(PoolError::Invalid(format!(
                "lease state contains invalid address {value:?} for {client_id:?}"
            )));
        }
        if let Some(previous) = inner.by_address.get(&address) {
            return Err(PoolError::Invalid(format!(
                "lease state assigns {address} to both {previous:?} and {client_id:?}"
            )));
        }
        inner.by_client.insert(
            client_id.to_owned(),
            LeaseRecord {
                address,
                generation,
                active: false,
            },
        );
        inner.by_address.insert(address, client_id.to_owned());
        Ok(())
    }

    fn persist_state_locked(
        &self,
        inner: &PoolInner,
        sync_directory: fn(&Path) -> io::Result<()>,
    ) -> Result<()> {
        let Some(path) = &self.state_path else {
            return Ok(());
        };
        let leases = inner
            .by_client
            .iter()
            .map(|(client_id, record)| {
                (
                    client_id.clone(),
                    PersistedLease {
                        address: record.address.to_string(),
                        generation: record.generation,
                    },
                )
            })
            .collect();
        let state = PoolState {
            version: STATE_VERSION,
            leases,
            pool: Some(self.prefix.to_string()),
        };
        let mut data = serde_json::to_vec(&state).map_err(|source| PoolError::Json {
            context: "encode lease state",
            source,
        })?;
        data.push(b'\n');
        write_state_atomically(path, &data, sync_directory)
    }
}

fn abandon_committed_lease(inner: &mut PoolInner, client_id: &str) {
    // Directory-sync failure cannot undo a rename or free the persisted reservation.
    inner
        .by_client
        .get_mut(client_id)
        .expect("committed lease remains reserved")
        .active = false;
    inner.groups.remove(client_id);
}

fn activate_group(inner: &mut PoolInner, client_id: &str, group_id: &str, generation: u64) {
    if group_id.is_empty() {
        inner.groups.remove(client_id);
    } else {
        inner.groups.insert(
            client_id.to_owned(),
            ActiveLeaseGroup {
                id: group_id.to_owned(),
                generation,
                references: 1,
            },
        );
    }
}

fn valid_client_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn parse_ipv4_prefix(value: &str) -> Result<Ipv4Net> {
    let (address, bits) = value
        .split_once('/')
        .ok_or_else(|| PoolError::Invalid("parse pool: missing prefix length".to_owned()))?;
    let address = IpAddr::from_str(address)
        .map_err(|error| PoolError::Invalid(format!("parse pool: {error}")))?;
    let IpAddr::V4(address) = address else {
        return Err(PoolError::Invalid(
            "the address pool must be IPv4".to_owned(),
        ));
    };
    let bits = bits
        .parse::<u8>()
        .map_err(|error| PoolError::Invalid(format!("parse pool: {error}")))?;
    let prefix = Ipv4Net::new(address, bits)
        .map_err(|error| PoolError::Invalid(format!("parse pool: {error}")))?;
    Ipv4Net::new(prefix.network(), prefix.prefix_len())
        .map_err(|error| PoolError::Invalid(format!("parse pool: {error}")))
}

fn increment(address: Ipv4Addr) -> Option<Ipv4Addr> {
    u32::from(address).checked_add(1).map(Ipv4Addr::from)
}

fn broadcast(prefix: Ipv4Net) -> Ipv4Addr {
    let host_bits = 32 - prefix.prefix_len();
    Ipv4Addr::from(u32::from(prefix.network()) | ((1_u32 << host_bits) - 1))
}

fn state_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn write_state_atomically(
    path: &Path,
    data: &[u8],
    sync_directory: fn(&Path) -> io::Result<()>,
) -> Result<()> {
    let directory = state_directory(path);
    create_state_directory(directory).map_err(|source| PoolError::Io {
        context: "create lease state directory",
        source,
    })?;

    let (temporary_path, mut temporary) =
        create_temporary(directory, ".leases-").map_err(|source| PoolError::Io {
            context: "create lease state temporary file",
            source,
        })?;
    let result = (|| {
        temporary.write_all(data).map_err(|source| PoolError::Io {
            context: "write lease state",
            source,
        })?;
        temporary.sync_all().map_err(|source| PoolError::Io {
            context: "sync lease state",
            source,
        })?;
        drop(temporary);
        fs::rename(&temporary_path, path).map_err(|source| PoolError::Io {
            context: "replace lease state",
            source,
        })?;
        sync_directory(directory).map_err(PoolError::Durability)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }

    fn create_state_directory(directory: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;

            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(directory)
        }
        #[cfg(not(unix))]
        {
            fs::create_dir_all(directory)
        }
    }
    result
}

fn create_temporary(directory: &Path, prefix: &str) -> io::Result<(PathBuf, File)> {
    for _ in 0..128 {
        let id = TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!("{prefix}{}-{id}", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create a unique temporary state file",
    ))
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{mpsc, Arc};
    use std::thread;
    use std::time::Duration;
    use tempfile::tempdir;

    #[test]
    fn validates_ipv4_pool_and_reserves_special_addresses() {
        assert!(Pool::new("2001:db8::/64").is_err());
        assert!(Pool::new("10.0.0.0/15").is_err());
        assert!(Pool::new("10.0.0.0/31").is_err());

        let pool = Pool::new("10.66.0.7/29").unwrap();
        assert_eq!(pool.network().to_string(), "10.66.0.0/29");
        assert_eq!(pool.gateway(), "10.66.0.1".parse::<Ipv4Addr>().unwrap());
        let lease = pool.acquire("client-a").unwrap();
        assert_eq!(lease.address, "10.66.0.2".parse::<Ipv4Addr>().unwrap());
        assert_ne!(lease.address, pool.network().network());
        assert_ne!(lease.address, broadcast(pool.network()));
    }

    #[test]
    fn reconnect_replaces_generation_without_releasing_current_lease() {
        let pool = Pool::new("10.66.0.0/29").unwrap();
        let first = pool.acquire("client-a").unwrap();
        let second = pool.acquire("client-a").unwrap();
        assert_eq!(first.address, second.address);
        assert!(!pool.register_lease(&first, || panic!("stale lease registered")));
        assert!(pool.register_lease(&second, || {}));
        pool.release(&first);
        assert_ne!(pool.acquire("client-b").unwrap().address, second.address);
    }

    #[test]
    fn registration_serializes_reconnect_replacement() {
        let pool = Arc::new(Pool::new("10.66.0.0/30").unwrap());
        let lease = pool.acquire("client-a").unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let registering = {
            let pool = pool.clone();
            thread::spawn(move || {
                pool.register_lease(&lease, || {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                })
            })
        };
        entered_rx.recv().unwrap();
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let reconnecting = {
            let pool = pool.clone();
            thread::spawn(move || {
                acquired_tx.send(pool.acquire("client-a")).unwrap();
            })
        };
        assert!(acquired_rx.recv_timeout(Duration::from_millis(20)).is_err());
        release_tx.send(()).unwrap();
        assert!(registering.join().unwrap());
        reconnecting.join().unwrap();
        assert!(acquired_rx.recv().unwrap().is_ok());
    }

    #[test]
    fn grouped_lanes_share_a_generation_until_the_last_release() {
        let pool = Pool::new("10.66.0.0/30").unwrap();
        let first = pool.acquire_group("client-a", "session-12345678").unwrap();
        let second = pool.acquire_group("client-a", "session-12345678").unwrap();
        assert_eq!(first, second);
        pool.release(&first);
        assert!(matches!(
            pool.acquire("client-b"),
            Err(PoolError::Exhausted)
        ));
        pool.release(&second);
        assert!(!pool.register_lease(&second, || panic!("released lease registered")));
        assert!(matches!(
            pool.acquire("client-b"),
            Err(PoolError::Exhausted)
        ));
        let reconnected = pool.acquire_group("client-a", "session-87654321").unwrap();
        assert_eq!(reconnected.address, first.address);
        assert!(reconnected.generation() > first.generation());
    }

    #[test]
    fn full_pool_keeps_inactive_reservations_identity_specific() {
        let pool = Pool::new("10.66.0.0/29").unwrap();
        let mut leases = Vec::new();
        for client in ["a", "b", "c", "d", "e"] {
            let lease = pool.acquire(client).unwrap();
            pool.release(&lease);
            leases.push(lease);
        }
        let refreshed = pool.acquire("a").unwrap();
        pool.release(&refreshed);
        assert!(matches!(pool.acquire("f"), Err(PoolError::Exhausted)));
        for previous in leases {
            let current = pool.acquire(previous.client_id()).unwrap();
            assert_eq!(current.address, previous.address);
            assert!(current.generation() > previous.generation());
        }
    }

    #[test]
    fn reads_go_compatible_state_and_writes_a_go_readable_schema() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("leases.json");
        fs::write(
            &path,
            br#"{"version":2,"leases":{"client-a":{"address":"10.66.0.4","generation":7}}}
"#,
        )
        .unwrap();
        let pool = Pool::new_persistent("10.66.0.0/29", &path).unwrap();
        assert_eq!(
            pool.acquire("client-a").unwrap().address,
            "10.66.0.4".parse::<Ipv4Addr>().unwrap()
        );
        let value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(value["version"], 2);
        assert_eq!(value["leases"]["client-a"]["address"], "10.66.0.4");
        assert!(value["leases"]["client-a"]["generation"].as_u64().unwrap() > 7);
    }

    #[test]
    fn rejects_duplicate_addresses_and_incompatible_pool_state() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("leases.json");
        fs::write(
            &path,
            br#"{"version":2,"leases":{"a":{"address":"10.66.0.2","generation":1},"b":{"address":"10.66.0.2","generation":2}}}
"#,
        )
        .unwrap();
        assert!(Pool::new_persistent("10.66.0.0/29", &path).is_err());

        fs::write(
            &path,
            br#"{"version":2,"pool":"10.66.0.0/29","leases":{}}
"#,
        )
        .unwrap();
        assert!(Pool::new_persistent("10.67.0.0/29", &path).is_err());
    }

    #[test]
    fn persistent_restart_preserves_identity_reservations() {
        let directory = tempdir().unwrap();
        for (bits, clients) in [(30, 1), (29, 5)] {
            let path = directory.path().join(format!("leases-{bits}.json"));
            let cidr = format!("10.66.0.0/{bits}");
            let mut leases = Vec::new();
            {
                let pool = Pool::new_persistent(&cidr, &path).unwrap();
                for index in 0..clients {
                    let lease = pool.acquire(&format!("client-{index}")).unwrap();
                    pool.release(&lease);
                    leases.push(lease);
                }
                assert!(matches!(
                    pool.acquire("new-client"),
                    Err(PoolError::Exhausted)
                ));
            }
            for _ in 0..2 {
                let persisted = fs::read(&path).unwrap();
                let pool = Pool::new_persistent(&cidr, &path).unwrap();
                assert!(matches!(
                    pool.acquire("new-client"),
                    Err(PoolError::Exhausted)
                ));
                assert_eq!(fs::read(&path).unwrap(), persisted);
                for previous in &mut leases {
                    let current = pool.acquire(previous.client_id()).unwrap();
                    assert_eq!(current.address, previous.address);
                    assert!(current.generation() > previous.generation());
                    pool.release(&current);
                    *previous = current;
                }
                assert!(matches!(
                    pool.acquire("new-client"),
                    Err(PoolError::Exhausted)
                ));
            }
        }
    }

    fn fail_directory_sync(_directory: &Path) -> io::Result<()> {
        Err(io::Error::other("injected directory sync failure"))
    }

    #[test]
    fn committed_new_lease_survives_directory_sync_failure() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("leases.json");
        let pool = Pool::new_persistent("10.66.0.0/30", &path).unwrap();
        assert!(pool
            .acquire_inner_with_sync("client-a", "first-group", fail_directory_sync)
            .is_err());
        let disk: PoolState = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let persisted = &disk.leases["client-a"];
        {
            let inner = pool.inner.lock().unwrap();
            let record = inner
                .by_client
                .get("client-a")
                .expect("a committed reservation must not be rolled back");
            assert_eq!(record.address.to_string(), persisted.address);
            assert_eq!(record.generation, persisted.generation);
            assert!(!record.active);
            assert!(!inner.groups.contains_key("client-a"));
        }
        assert!(matches!(
            pool.acquire("client-b"),
            Err(PoolError::Exhausted)
        ));
        let recovered = pool.acquire("client-a").unwrap();
        assert_eq!(recovered.address.to_string(), persisted.address);
        assert!(recovered.generation() > persisted.generation);
        pool.release(&recovered);
        drop(pool);

        let reopened = Pool::new_persistent("10.66.0.0/30", &path).unwrap();
        assert!(matches!(
            reopened.acquire("client-b"),
            Err(PoolError::Exhausted)
        ));
        assert_eq!(
            reopened.acquire("client-a").unwrap().address,
            recovered.address
        );
    }

    #[test]
    fn committed_replacement_does_not_restore_obsolete_generation() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("leases.json");
        let pool = Pool::new_persistent("10.66.0.0/30", &path).unwrap();
        let first = pool.acquire_group("client-a", "first-group").unwrap();
        let second = pool.acquire_group("client-a", "first-group").unwrap();
        assert!(pool
            .acquire_inner_with_sync("client-a", "replacement", fail_directory_sync)
            .is_err());
        let disk: PoolState = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let persisted = &disk.leases["client-a"];
        assert!(persisted.generation > first.generation());
        {
            let inner = pool.inner.lock().unwrap();
            let record = inner.by_client.get("client-a").unwrap();
            assert_eq!(record.generation, persisted.generation);
            assert!(!record.active);
            assert!(!inner.groups.contains_key("client-a"));
        }
        assert!(!pool.register_lease(&first, || panic!("obsolete lease registered")));
        pool.release(&first);
        pool.release(&second);
        let recovered = pool.acquire_group("client-a", "replacement").unwrap();
        assert_eq!(recovered.address, first.address);
        assert!(recovered.generation() > persisted.generation);
        pool.release(&first);
        assert!(pool.register_lease(&recovered, || {}));
    }

    #[test]
    fn failed_rename_preserves_previous_lease_and_group_references() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("leases.json");
        let backup = directory.path().join("previous.json");
        let pool = Pool::new_persistent("10.66.0.0/29", &path).unwrap();
        let first = pool.acquire_group("client-a", "first-group").unwrap();
        let second = pool.acquire_group("client-a", "first-group").unwrap();
        fs::rename(&path, &backup).unwrap();
        fs::create_dir(&path).unwrap();

        for (client, group) in [("client-a", "replacement"), ("client-b", "new-group")] {
            assert!(matches!(
                pool.acquire_group(client, group),
                Err(PoolError::Io {
                    context: "replace lease state",
                    ..
                })
            ));
            let inner = pool.inner.lock().unwrap();
            assert_eq!(inner.by_client.len(), 1);
            assert_eq!(inner.by_address.len(), 1);
            assert_eq!(inner.by_client["client-a"].generation, first.generation());
            assert_eq!(inner.groups["client-a"].references, 2);
        }
        assert!(pool.register_lease(&first, || {}));
        pool.release(&first);
        assert!(pool.register_lease(&second, || {}));
        pool.release(&second);
        assert!(!pool.register_lease(&second, || panic!("released lease registered")));

        fs::remove_dir(&path).unwrap();
        fs::rename(&backup, &path).unwrap();
        assert_eq!(
            pool.acquire("client-b").unwrap().address,
            "10.66.0.3".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}
