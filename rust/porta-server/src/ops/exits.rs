//! Per-account exit selection: policy routing rules that send one lease's
//! traffic to its account's exit instead of the gateway default.
//!
//! `server-up.sh` installs a routing table per named exit and, on a cascade
//! relay, the default rule that sends client traffic to the upstream. This
//! module owns one higher-priority rule per lease whose account selects
//! another exit. It reconciles the kernel against the wanted rules, so a
//! late release cannot remove a newer session's rule and a restarted helper
//! or crashed daemon leaves nothing stale behind.

use anyhow::{bail, Context, Result};
use futures_util::future::BoxFuture;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Just above the cascade relay's default rule (10066), so selected exits win.
pub const EXIT_RULE_PRIORITY: u32 = 10065;
const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);

/// Runs `ip` with the given arguments and returns its output.
pub trait RuleCommands: Send + Sync {
    fn run(&self, arguments: Vec<String>) -> BoxFuture<'_, Result<String>>;
}

struct IpCommand;

impl RuleCommands for IpCommand {
    fn run(&self, arguments: Vec<String>) -> BoxFuture<'_, Result<String>> {
        Box::pin(async move {
            let output = tokio::process::Command::new("ip")
                .args(&arguments)
                .kill_on_drop(true)
                .output()
                .await
                .context("run ip")?;
            if !output.status.success() {
                bail!(
                    "ip {}: {}",
                    arguments.join(" "),
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        })
    }
}

pub struct ExitRules {
    interface: String,
    tables: HashMap<String, u32>,
    names: Vec<String>,
    /// Wanted table by lease, with the generation of the session that set it.
    desired: Mutex<HashMap<Ipv4Addr, (u32, u64)>>,
    generation: AtomicU64,
    apply: tokio::sync::Mutex<()>,
    commands: Arc<dyn RuleCommands>,
}

impl std::fmt::Debug for ExitRules {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExitRules")
            .field("interface", &self.interface)
            .field("exits", &self.names)
            .finish_non_exhaustive()
    }
}

impl ExitRules {
    /// `tables` maps each selectable exit name to its routing table.
    pub fn new(interface: impl Into<String>, tables: Vec<(String, u32)>) -> Arc<Self> {
        Self::with_commands(interface, tables, Arc::new(IpCommand))
    }

    pub fn with_commands(
        interface: impl Into<String>,
        tables: Vec<(String, u32)>,
        commands: Arc<dyn RuleCommands>,
    ) -> Arc<Self> {
        Arc::new(Self {
            interface: interface.into(),
            names: tables.iter().map(|(name, _)| name.clone()).collect(),
            tables: tables.into_iter().collect(),
            desired: Mutex::new(HashMap::new()),
            generation: AtomicU64::new(0),
            apply: tokio::sync::Mutex::new(()),
            commands,
        })
    }

    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Routes `lease` through `exit` before returning; the returned
    /// generation releases exactly this assignment.
    pub async fn assign(&self, lease: Ipv4Addr, exit: &str) -> Result<u64> {
        let table = *self
            .tables
            .get(exit)
            .with_context(|| format!("exit {exit:?} is not offered by this gateway"))?;
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        self.desired.lock().insert(lease, (table, generation));
        self.reconcile().await?;
        Ok(generation)
    }

    /// Returns `lease` to the default exit unless a newer session took it.
    pub fn release(self: &Arc<Self>, lease: Ipv4Addr, generation: u64) {
        let released = {
            let mut desired = self.desired.lock();
            if desired
                .get(&lease)
                .is_some_and(|(_, current)| *current == generation)
            {
                desired.remove(&lease);
                true
            } else {
                false
            }
        };
        if released {
            let rules = self.clone();
            tokio::spawn(async move {
                if let Err(error) = rules.reconcile().await {
                    tracing::warn!(%error, %lease, "could not remove the exit selection rule");
                }
            });
        }
    }

    /// Makes the kernel's exit rules match the wanted ones.
    pub async fn reconcile(&self) -> Result<()> {
        let _apply = self.apply.lock().await;
        let listing = self
            .commands
            .run(arguments(&[
                "-j",
                "-4",
                "rule",
                "show",
                "priority",
                &EXIT_RULE_PRIORITY.to_string(),
            ]))
            .await?;
        let current = parse_rules(&listing, &self.interface)?;
        let desired = self
            .desired
            .lock()
            .iter()
            .map(|(lease, (table, _))| (*lease, *table))
            .collect::<HashMap<_, _>>();
        let (remove, add) = plan(&current, &desired);
        for (action, rules) in [("del", remove), ("add", add)] {
            for (lease, table) in rules {
                self.commands
                    .run(arguments(&[
                        "-4",
                        "rule",
                        action,
                        "priority",
                        &EXIT_RULE_PRIORITY.to_string(),
                        "iif",
                        &self.interface,
                        "from",
                        &lease.to_string(),
                        "lookup",
                        &table.to_string(),
                    ]))
                    .await?;
            }
        }
        Ok(())
    }

    /// Removes stale rules now, then repairs drift until cancelled.
    pub async fn run(self: Arc<Self>, cancellation: CancellationToken) -> Result<()> {
        loop {
            if let Err(error) = self.reconcile().await {
                tracing::warn!(%error, "could not reconcile exit selection rules");
            }
            tokio::select! {
                _ = cancellation.cancelled() => break,
                _ = tokio::time::sleep(RECONCILE_INTERVAL) => {}
            }
        }
        // Leave no exit rules behind; leases fall back to the default exit.
        self.desired.lock().clear();
        self.reconcile().await
    }
}

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

/// Exit rules of `interface` in an `ip -j rule show` listing.
fn parse_rules(listing: &str, interface: &str) -> Result<Vec<(Ipv4Addr, u32)>> {
    let rules: Vec<serde_json::Value> = if listing.trim().is_empty() {
        Vec::new()
    } else {
        serde_json::from_str(listing).context("decode ip rule listing")?
    };
    let mut parsed = Vec::new();
    for rule in rules {
        let text = |name: &str| rule.get(name).and_then(serde_json::Value::as_str);
        if rule.get("priority").and_then(serde_json::Value::as_u64)
            != Some(u64::from(EXIT_RULE_PRIORITY))
            || text("iif") != Some(interface)
        {
            continue;
        }
        let (Some(source), Some(table)) = (text("src"), text("table")) else {
            continue;
        };
        let Ok(source) = source.parse::<Ipv4Addr>() else {
            continue;
        };
        let table = match table {
            "main" => 254,
            "default" => 253,
            "local" => 255,
            number => number.parse().context("decode ip rule table")?,
        };
        parsed.push((source, table));
    }
    Ok(parsed)
}

/// Rules to delete and to add so that `current` matches `desired`.
type RulePlan = (Vec<(Ipv4Addr, u32)>, Vec<(Ipv4Addr, u32)>);

fn plan(current: &[(Ipv4Addr, u32)], desired: &HashMap<Ipv4Addr, u32>) -> RulePlan {
    let remove = current
        .iter()
        .filter(|(lease, table)| desired.get(lease) != Some(table))
        .copied()
        .collect();
    let mut add = desired
        .iter()
        .filter(|(lease, table)| !current.contains(&(**lease, **table)))
        .map(|(lease, table)| (*lease, *table))
        .collect::<Vec<_>>();
    add.sort();
    (remove, add)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeIp {
        rules: Mutex<Vec<(Ipv4Addr, u32)>>,
        calls: Mutex<Vec<String>>,
    }

    impl RuleCommands for FakeIp {
        fn run(&self, arguments: Vec<String>) -> BoxFuture<'_, Result<String>> {
            Box::pin(async move {
                self.calls.lock().push(arguments.join(" "));
                let mut rules = self.rules.lock();
                if arguments[0] == "-j" {
                    let listing = rules
                        .iter()
                        .map(|(source, table)| {
                            serde_json::json!({
                                "priority": EXIT_RULE_PRIORITY,
                                "src": source.to_string(),
                                "iif": "porta0",
                                "table": if *table == 254 { "main".to_owned() } else { table.to_string() },
                            })
                        })
                        .collect::<Vec<_>>();
                    return Ok(serde_json::to_string(&listing).unwrap());
                }
                let rule = (
                    arguments[8].parse().unwrap(),
                    arguments[10].parse().unwrap(),
                );
                if arguments[2] == "add" {
                    rules.push(rule);
                } else {
                    rules.retain(|existing| *existing != rule);
                }
                Ok(String::new())
            })
        }
    }

    #[tokio::test]
    async fn assignments_reconcile_and_late_releases_keep_newer_sessions() {
        let ip = Arc::new(FakeIp::default());
        let stale: Ipv4Addr = "10.66.0.9".parse().unwrap();
        ip.rules.lock().push((stale, 10067));
        let rules = ExitRules::with_commands(
            "porta0",
            vec![("local".into(), 254), ("us".into(), 10067)],
            ip.clone(),
        );
        let lease: Ipv4Addr = "10.66.0.5".parse().unwrap();
        assert!(rules.assign(lease, "eu").await.is_err());
        let first = rules.assign(lease, "us").await.unwrap();
        // The stale rule from an earlier run is gone; the lease routes via "us".
        assert_eq!(*ip.rules.lock(), vec![(lease, 10067)]);

        // A reconnect switches to "local" before the old session releases.
        let second = rules.assign(lease, "local").await.unwrap();
        rules.release(lease, first);
        rules.reconcile().await.unwrap();
        assert_eq!(*ip.rules.lock(), vec![(lease, 254)]);
        assert!(ip
            .calls
            .lock()
            .iter()
            .any(|call| call == "-4 rule add priority 10065 iif porta0 from 10.66.0.5 lookup 254"));

        rules.release(lease, second);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(ip.rules.lock().is_empty());
    }

    #[test]
    fn listings_ignore_other_interfaces_and_priorities() {
        let listing = r#"[{"priority":10065,"src":"10.66.0.5","iif":"porta0","table":"main"},
            {"priority":10065,"src":"10.66.0.6","iif":"other0","table":"10067"},
            {"priority":10066,"iif":"porta0","table":"10066"}]"#;
        assert_eq!(
            parse_rules(listing, "porta0").unwrap(),
            vec![("10.66.0.5".parse().unwrap(), 254)]
        );
        assert!(parse_rules("", "porta0").unwrap().is_empty());
    }
}
