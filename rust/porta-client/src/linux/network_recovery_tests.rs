use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{json, Value};
use tempfile::TempDir;

use super::*;

#[derive(Default)]
struct FakeState {
    links: HashMap<String, LinkInfo>,
    addresses: HashMap<String, Vec<String>>,
    routes: HashMap<String, Vec<RouteInfo>>,
    tables: HashMap<String, String>,
    dns: HashMap<String, String>,
    domains: HashMap<String, String>,
    commands: Vec<String>,
    scripts: Vec<String>,
    mutations: usize,
    fail_at: usize,
    fail_after: bool,
    fail_match: String,
    resolver_error: bool,
}

struct FakeCommands {
    journal: PathBuf,
    state: Mutex<FakeState>,
}

impl FakeCommands {
    fn new(journal: PathBuf) -> Self {
        let physical = LinkInfo {
            index: 2,
            name: "eth0".to_owned(),
            address: "02:00:00:00:00:02".to_owned(),
            alias: String::new(),
            mtu: 1500,
            flags: vec!["UP".to_owned()],
            link_info: LinkKind::default(),
        };
        let tunnel = LinkInfo {
            index: 10,
            name: "porta0".to_owned(),
            address: "00:00:00:00:00:00".to_owned(),
            alias: String::new(),
            mtu: 1500,
            flags: vec!["POINTOPOINT".to_owned()],
            link_info: LinkKind {
                kind: "tun".to_owned(),
            },
        };
        Self {
            journal,
            state: Mutex::new(FakeState {
                links: HashMap::from([
                    (physical.name.clone(), physical),
                    (tunnel.name.clone(), tunnel),
                ]),
                ..FakeState::default()
            }),
        }
    }

    fn set_failure(&self, fail_at: usize, fail_after: bool) {
        let mut state = self.state.lock().unwrap();
        state.fail_at = fail_at;
        state.fail_after = fail_after;
    }

    fn clear_failure(&self) {
        let mut state = self.state.lock().unwrap();
        state.fail_at = 0;
        state.fail_match.clear();
    }

    fn reset_mutations(&self) {
        self.state.lock().unwrap().mutations = 0;
    }

    fn mutation_count(&self) -> usize {
        self.state.lock().unwrap().mutations
    }

    fn apply(
        state: &mut FakeState,
        program: &str,
        arguments: &[String],
        input: &str,
    ) -> Result<String, NetworkError> {
        match program {
            "nft" => {
                if !input.is_empty() {
                    state.scripts.push(input.to_owned());
                    for line in input.lines() {
                        let fields = line.split_whitespace().collect::<Vec<_>>();
                        if line.starts_with("delete table ") {
                            state.tables.remove(fields[3]);
                        } else if line.starts_with("add table ") {
                            state.tables.insert(
                                fields[3].to_owned(),
                                format!("Porta client {}", fields[3]),
                            );
                        }
                    }
                    return Ok(String::new());
                }
                let tables = state
                    .tables
                    .iter()
                    .filter(|(table, _)| {
                        arguments
                            .get(4)
                            .is_none_or(|requested| requested == *table)
                    })
                    .map(|(table, comment)| {
                        json!({"table": {"family": "inet", "name": table, "comment": comment}})
                    })
                    .collect::<Vec<_>>();
                Ok(json!({"nftables": tables}).to_string())
            }
            "resolvectl" => {
                match arguments.first().map(String::as_str) {
                    Some("status") => return Ok("Global\nresolv.conf mode: stub".to_owned()),
                    Some("dns") if arguments.len() == 2 => {
                        return Ok(format!(
                            "Link 10 ({}): {}",
                            arguments[1],
                            state.dns.get(&arguments[1]).map_or("", String::as_str)
                        ));
                    }
                    Some("dns") => {
                        state.dns.insert(arguments[1].clone(), arguments[2].clone());
                    }
                    Some("domain") if arguments.len() == 2 => {
                        return Ok(format!(
                            "Link 10 ({}): {}",
                            arguments[1],
                            state.domains.get(&arguments[1]).map_or("", String::as_str)
                        ));
                    }
                    Some("domain") => {
                        state
                            .domains
                            .insert(arguments[1].clone(), arguments[2].clone());
                    }
                    Some("default-route") => {}
                    Some("revert") => {
                        state.dns.remove(&arguments[1]);
                        state.domains.remove(&arguments[1]);
                    }
                    _ => {
                        return Err(NetworkError::Invalid(
                            "unexpected fake resolver operation".to_owned(),
                        ));
                    }
                }
                Ok(String::new())
            }
            "ip" => {
                let command = arguments.join(" ");
                if command.contains("rule show") {
                    return Ok(
                        r#"[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]"#
                            .to_owned(),
                    );
                }
                if command == "-j -d link show" {
                    return Ok(serde_json::to_string(
                        &state.links.values().collect::<Vec<_>>(),
                    )?);
                }
                if command.starts_with("link set dev ") {
                    let link = state.links.get_mut(&arguments[3]).ok_or_else(|| {
                        NetworkError::Invalid("fake link does not exist".to_owned())
                    })?;
                    if arguments[4] == "alias" {
                        link.alias.clone_from(&arguments[5]);
                    } else {
                        link.mtu = arguments[5].parse().unwrap();
                        link.flags = vec!["POINTOPOINT".to_owned()];
                        if arguments[6] == "up" {
                            link.flags.push("UP".to_owned());
                        }
                    }
                    return Ok(String::new());
                }
                if command.starts_with("-j address show dev ") {
                    let addresses = state
                        .addresses
                        .get(&arguments[4])
                        .into_iter()
                        .flatten()
                        .map(|address| {
                            let prefix: IpNet = address.parse().unwrap();
                            json!({
                                "local": prefix.addr().to_string(),
                                "prefixlen": prefix.prefix_len()
                            })
                        })
                        .collect::<Vec<_>>();
                    return Ok(json!([{"addr_info": addresses}]).to_string());
                }
                if arguments.get(1).map(String::as_str) == Some("address") {
                    let addresses = state.addresses.entry(arguments[5].clone()).or_default();
                    if arguments[2] == "add" {
                        if !addresses.contains(&arguments[3]) {
                            addresses.push(arguments[3].clone());
                        }
                    } else {
                        addresses.retain(|address| address != &arguments[3]);
                    }
                    return Ok(String::new());
                }
                if command.contains("route show table main") {
                    let family = &arguments[2];
                    let selector = arguments.last().unwrap();
                    if selector == "default" {
                        let gateway = if family == "-6" {
                            "fe80::1"
                        } else {
                            "192.0.2.1"
                        };
                        return Ok(serde_json::to_string(&[RouteInfo {
                            destination: "default".to_owned(),
                            device: "eth0".to_owned(),
                            gateway: gateway.to_owned(),
                            metric: 100,
                            ..RouteInfo::default()
                        }])?);
                    }
                    return Ok(serde_json::to_string(
                        state
                            .routes
                            .get(&format!("{family} {selector}"))
                            .map_or(&[][..], Vec::as_slice),
                    )?);
                }
                if command.contains("route get") {
                    let (device, gateway) = if arguments[1] == "-6" {
                        ("eth0", "fe80::1")
                    } else if state.routes.contains_key("-4 0.0.0.0/1") {
                        ("porta0", "")
                    } else {
                        ("eth0", "192.0.2.1")
                    };
                    return Ok(serde_json::to_string(&[RouteInfo {
                        destination: arguments[4].clone(),
                        device: device.to_owned(),
                        gateway: gateway.to_owned(),
                        ..RouteInfo::default()
                    }])?);
                }
                if arguments.get(1).map(String::as_str) == Some("route") {
                    let key = format!("{} {}", arguments[0], arguments[3]);
                    if arguments[2] == "del" {
                        state.routes.remove(&key);
                        return Ok(String::new());
                    }
                    if state.routes.contains_key(&key) {
                        return Err(NetworkError::Invalid("fake route exists".to_owned()));
                    }
                    let mut route = RouteInfo {
                        destination: arguments[3].clone(),
                        ..RouteInfo::default()
                    };
                    let mut index = 4;
                    while index + 1 < arguments.len() {
                        match arguments[index].as_str() {
                            "dev" => route.device.clone_from(&arguments[index + 1]),
                            "via" => route.gateway.clone_from(&arguments[index + 1]),
                            "metric" => route.metric = arguments[index + 1].parse().unwrap(),
                            "proto" => {
                                route.protocol =
                                    Value::from(arguments[index + 1].parse::<u64>().unwrap());
                            }
                            _ => {}
                        }
                        index += 2;
                    }
                    state.routes.insert(key, vec![route]);
                    Ok(String::new())
                } else {
                    Err(NetworkError::Invalid(format!(
                        "unexpected fake command: {program} {command}"
                    )))
                }
            }
            _ => Err(NetworkError::Invalid(format!(
                "unexpected fake program: {program}"
            ))),
        }
    }
}

#[async_trait]
impl CommandRunner for FakeCommands {
    fn check_resolver(&self) -> Result<(), NetworkError> {
        if self.state.lock().unwrap().resolver_error {
            return Err(NetworkError::Invalid(
                "unsupported fake resolver".to_owned(),
            ));
        }
        Ok(())
    }

    async fn run(
        &self,
        program: &str,
        arguments: Vec<String>,
        input: String,
    ) -> Result<String, NetworkError> {
        let mut state = self.state.lock().unwrap();
        let display = format!("{program} {}", arguments.join(" "));
        state.commands.push(display.clone());
        if !state.fail_match.is_empty() && display.contains(&state.fail_match) {
            return Err(NetworkError::Invalid("injected command failure".to_owned()));
        }
        let mutating = !input.is_empty()
            || (program == "ip"
                && !arguments.iter().any(|argument| argument == "show")
                && !arguments.iter().any(|argument| argument == "get"))
            || (program == "resolvectl"
                && (arguments
                    .first()
                    .is_some_and(|argument| argument == "revert")
                    || arguments.len() > 2));
        let mut fail = false;
        if mutating {
            state.mutations += 1;
            fail = state.fail_at != 0 && state.mutations == state.fail_at;
            let encoded = fs::read(&self.journal).map_err(|_| {
                NetworkError::Invalid(format!(
                    "mutation without durable ownership journal: {display}"
                ))
            })?;
            let journal: NetworkState = serde_json::from_slice(&encoded).map_err(|_| {
                NetworkError::Invalid(format!(
                    "mutation with invalid ownership journal: {display}"
                ))
            })?;
            if journal.table.is_empty() {
                return Err(NetworkError::Invalid(format!(
                    "mutation without initialized ownership journal: {display}"
                )));
            }
            if program != "nft" && state.tables.is_empty() {
                return Err(NetworkError::Invalid(format!(
                    "network mutation without active protection: {display}"
                )));
            }
            let journaled = program == "nft"
                || journal.undo.iter().any(|action| match program {
                    "resolvectl" => {
                        action.kind == "dns"
                            && action_owns_interface(action, &arguments[1], &state.links)
                    }
                    "ip" if arguments.first().is_some_and(|value| value == "link") => {
                        let kind = if arguments.get(4).is_some_and(|value| value == "alias") {
                            "alias"
                        } else {
                            "link"
                        };
                        action.kind == kind
                            && action_owns_interface(action, &arguments[3], &state.links)
                    }
                    "ip" if arguments.get(1).is_some_and(|value| value == "address") => {
                        action.kind == "address"
                            && action.address == arguments[3]
                            && action_owns_interface(action, &arguments[5], &state.links)
                    }
                    "ip" if arguments.get(1).is_some_and(|value| value == "route") => {
                        action.destination == arguments[3]
                            && matches!(action.kind.as_str(), "route" | "escape" | "dns-route")
                    }
                    _ => false,
                });
            if !journaled {
                return Err(NetworkError::Invalid(format!(
                    "mutation missing write-ahead undo action: {display}"
                )));
            }
            if fail && !state.fail_after {
                return Err(NetworkError::Invalid(
                    "injected pre-apply failure".to_owned(),
                ));
            }
        }
        let output = Self::apply(&mut state, program, &arguments, &input)?;
        if fail {
            return Err(NetworkError::Invalid(
                "injected ambiguous post-apply failure".to_owned(),
            ));
        }
        Ok(output)
    }
}

fn action_owns_interface(action: &Action, name: &str, links: &HashMap<String, LinkInfo>) -> bool {
    action.interface == name
        || links
            .get(name)
            .is_some_and(|link| link.index == action.index)
}

fn test_lease() -> Lease {
    Lease {
        address: "10.77.0.2/24".parse().unwrap(),
        gateway: Some("10.77.0.1".parse().unwrap()),
        dns: Some("1.1.1.1".parse().unwrap()),
        mtu: 1280,
    }
}

fn new_fake() -> (TempDir, PathBuf, Arc<FakeCommands>, NetworkManager) {
    let directory = tempfile::tempdir_in(".").unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.path().join("network.json");
    let commands = Arc::new(FakeCommands::new(path.clone()));
    let manager = NetworkManager::open_with_commands(path.clone(), commands.clone()).unwrap();
    (directory, path, commands, manager)
}

fn snapshot(commands: &FakeCommands) -> std::sync::MutexGuard<'_, FakeState> {
    commands.state.lock().unwrap()
}

#[tokio::test]
async fn automatic_full_tunnel_is_journaled_and_cleaned_in_order() {
    let (_directory, path, commands, mut manager) = new_fake();
    let endpoint = "198.51.100.10:443".parse().unwrap();
    manager.prepare(endpoint).await.unwrap();
    manager.up("porta0", endpoint, test_lease()).await.unwrap();
    {
        let state = snapshot(&commands);
        assert_eq!(state.routes.len(), 4);
        assert_eq!(state.dns.get("porta0").map(String::as_str), Some("1.1.1.1"));
        assert_eq!(state.domains.get("porta0").map(String::as_str), Some("~."));
        assert_eq!(state.links["porta0"].mtu, 1280);
        assert_eq!(
            state.addresses.get("porta0").unwrap(),
            &["10.77.0.2/24".to_owned()]
        );
        let rules = state.scripts.last().unwrap();
        for required in [
            r#"oifname "lo" accept"#,
            r#"oifname "porta0" meta oif 10 accept"#,
            "udp dport { 53, 853 } drop",
            "tcp dport { 53, 853 } drop",
            "ip daddr 198.51.100.10 udp dport 443 accept",
        ] {
            assert!(rules.contains(required), "missing {required} in {rules}");
        }
    }
    manager.down().await.unwrap();
    {
        let state = snapshot(&commands);
        assert!(state.tables.is_empty());
        assert!(state.routes.is_empty());
        assert!(state.addresses.get("porta0").is_none_or(Vec::is_empty));
        assert!(state.dns.is_empty());
        assert_eq!(state.links["porta0"].mtu, 1500);
        assert!(!state.links["porta0"].flags.iter().any(|flag| flag == "UP"));
        assert!(state
            .scripts
            .last()
            .unwrap()
            .starts_with("delete table inet porta_"));
    }
    assert!(!path.exists());
}

#[tokio::test]
async fn interrupted_setup_resumes_without_removing_protection() {
    let (_baseline_directory, _path, baseline_commands, mut baseline) = new_fake();
    baseline
        .up("porta0", "198.51.100.10:443".parse().unwrap(), test_lease())
        .await
        .unwrap();
    let mutation_count = baseline_commands.mutation_count();
    assert!(mutation_count > 1);

    for failure in 1..=mutation_count {
        let (_directory, path, commands, mut manager) = new_fake();
        commands.set_failure(failure, true);
        assert!(
            manager
                .up("porta0", "198.51.100.10:443".parse().unwrap(), test_lease())
                .await
                .is_err(),
            "mutation {failure} unexpectedly succeeded"
        );
        commands.clear_failure();
        drop(manager);
        let mut recovered = NetworkManager::open_with_commands(path, commands.clone()).unwrap();
        recovered
            .up("porta0", "198.51.100.10:443".parse().unwrap(), test_lease())
            .await
            .unwrap();
        let state = snapshot(&commands);
        assert_eq!(state.addresses["porta0"].len(), 1, "mutation {failure}");
        assert_eq!(state.routes.len(), 4, "mutation {failure}");
        assert_eq!(state.tables.len(), 1, "mutation {failure}");
        assert!(
            state
                .scripts
                .iter()
                .all(|script| !script.contains("delete table")),
            "mutation {failure} removed the guard while resuming"
        );
    }
}

#[tokio::test]
async fn every_interrupted_cleanup_is_retryable_after_restart() {
    let (_baseline_directory, _path, baseline_commands, mut baseline) = new_fake();
    baseline
        .up("porta0", "198.51.100.10:443".parse().unwrap(), test_lease())
        .await
        .unwrap();
    baseline_commands.reset_mutations();
    baseline.down().await.unwrap();
    let mutation_count = baseline_commands.mutation_count();
    assert!(mutation_count > 1);

    for failure in 1..=mutation_count {
        for fail_after in [false, true] {
            let (_directory, path, commands, mut manager) = new_fake();
            manager
                .up("porta0", "198.51.100.10:443".parse().unwrap(), test_lease())
                .await
                .unwrap();
            commands.reset_mutations();
            commands.set_failure(failure, fail_after);
            assert!(
                manager.down().await.is_err(),
                "cleanup mutation {failure}, after={fail_after} unexpectedly succeeded"
            );
            if failure < mutation_count {
                assert_eq!(
                    snapshot(&commands).tables.len(),
                    1,
                    "cleanup mutation {failure}, after={fail_after} removed guard early"
                );
            }
            commands.clear_failure();
            drop(manager);
            let mut recovered = NetworkManager::open_with_commands(path, commands.clone()).unwrap();
            recovered.down().await.unwrap();
            let state = snapshot(&commands);
            assert!(state.tables.is_empty());
            assert!(state.routes.is_empty());
            assert!(state.addresses.get("porta0").is_none_or(Vec::is_empty));
            assert!(state.dns.is_empty());
        }
    }
}

#[test]
fn existing_empty_or_unowned_journals_fail_closed() {
    let directory = tempfile::tempdir_in(".").unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.path().join("network.json");
    fs::write(&path, b"{}").unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(&path, permissions).unwrap();
    let commands = Arc::new(FakeCommands::new(path.clone()));
    assert!(NetworkManager::open_with_commands(path, commands.clone()).is_err());
    assert!(snapshot(&commands).commands.is_empty());

    let mut state = NetworkState {
        version: STATE_VERSION,
        table: "porta_0011223344556677".to_owned(),
        metric: 40_100,
        ..NetworkState::default()
    };
    state.undo.push(Action {
        kind: "escape".to_owned(),
        interface: "eth0".to_owned(),
        index: 2,
        link_address: "not-a-mac".to_owned(),
        family: 4,
        destination: "198.51.100.10/32".to_owned(),
        ..Action::default()
    });
    assert!(validate_state(&state).is_err());
}

#[tokio::test]
async fn reused_physical_interface_index_does_not_receive_stale_cleanup() {
    let (_directory, _path, commands, mut manager) = new_fake();
    manager
        .up("porta0", "198.51.100.10:443".parse().unwrap(), test_lease())
        .await
        .unwrap();
    {
        let mut state = commands.state.lock().unwrap();
        state.links.remove("eth0");
        state.links.insert(
            "other0".to_owned(),
            LinkInfo {
                index: 2,
                name: "other0".to_owned(),
                address: "02:00:00:00:00:99".to_owned(),
                alias: String::new(),
                mtu: 9000,
                flags: vec!["UP".to_owned()],
                link_info: LinkKind::default(),
            },
        );
        state.routes.get_mut("-4 198.51.100.10/32").unwrap()[0].device = "other0".to_owned();
    }
    manager.down().await.unwrap();
    let state = snapshot(&commands);
    assert_eq!(state.routes["-4 198.51.100.10/32"].len(), 1);
    assert_eq!(state.links["other0"].mtu, 9000);
}

#[tokio::test]
async fn renamed_physical_interface_retains_escape_route_cleanup_ownership() {
    let (_directory, _path, commands, mut manager) = new_fake();
    manager
        .up("porta0", "198.51.100.10:443".parse().unwrap(), test_lease())
        .await
        .unwrap();
    {
        let mut state = commands.state.lock().unwrap();
        let mut physical = state.links.remove("eth0").unwrap();
        physical.name = "wan0".to_owned();
        state.links.insert(physical.name.clone(), physical);
        state.routes.get_mut("-4 198.51.100.10/32").unwrap()[0].device = "wan0".to_owned();
    }

    manager.down().await.unwrap();
    assert!(!snapshot(&commands)
        .routes
        .contains_key("-4 198.51.100.10/32"));
}
