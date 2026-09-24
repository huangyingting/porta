use anyhow::Result;
use futures_util::future::{BoxFuture, FutureExt};
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

pub type Probe =
    Arc<dyn Fn(CancellationToken) -> BoxFuture<'static, Result<()>> + Send + Sync + 'static>;

#[derive(Clone)]
pub struct ReadinessCheck {
    pub name: String,
    pub required: bool,
    pub probe: Option<Probe>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ComponentState {
    pub status: &'static str,
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReadinessReport {
    pub status: &'static str,
    pub components: BTreeMap<String, ComponentState>,
}

#[derive(Clone)]
pub struct Readiness {
    checks: Arc<[ReadinessCheck]>,
    timeout: Duration,
}

impl Readiness {
    pub fn new(checks: Vec<ReadinessCheck>, timeout: Duration) -> Self {
        Self {
            checks: checks.into(),
            timeout: if timeout.is_zero() {
                Duration::from_secs(3)
            } else {
                timeout
            },
        }
    }

    pub async fn check(&self) -> ReadinessReport {
        if self.checks.is_empty() {
            return unavailable("local forwarding probes are not configured");
        }
        let cancellation = CancellationToken::new();
        let mut tasks = JoinSet::new();
        let mut components = BTreeMap::new();
        let mut required = 0usize;
        for check in self.checks.iter() {
            if check.required {
                required += 1;
            }
            let Some(probe) = check.probe.clone() else {
                components.insert(
                    check.name.clone(),
                    ComponentState {
                        status: "disabled",
                        required: check.required,
                        error: None,
                    },
                );
                continue;
            };
            let name = check.name.clone();
            let is_required = check.required;
            let token = cancellation.child_token();
            tasks.spawn(async move {
                let result = std::panic::AssertUnwindSafe(probe(token))
                    .catch_unwind()
                    .await;
                (
                    name,
                    match result {
                        Ok(result) => ComponentState {
                            status: if result.is_ok() { "ok" } else { "error" },
                            required: is_required,
                            error: result.err().map(|error| error.to_string()),
                        },
                        Err(_) => ComponentState {
                            status: "error",
                            required: is_required,
                            error: Some("readiness probe panicked".to_string()),
                        },
                    },
                )
            });
        }
        let timed = tokio::time::timeout(self.timeout, async {
            while let Some(result) = tasks.join_next().await {
                if let Ok((name, state)) = result {
                    components.insert(name, state);
                }
            }
        })
        .await;
        if timed.is_err() {
            cancellation.cancel();
            tasks.abort_all();
            for check in self.checks.iter() {
                if check.probe.is_some() && !components.contains_key(&check.name) {
                    components.insert(
                        check.name.clone(),
                        ComponentState {
                            status: "error",
                            required: check.required,
                            error: Some("context deadline exceeded".to_string()),
                        },
                    );
                }
            }
        }
        if required == 0 {
            components.insert(
                "local_forwarding".to_string(),
                ComponentState {
                    status: "unknown",
                    required: true,
                    error: Some("no required local forwarding probes".to_string()),
                },
            );
        }
        let ready = required > 0
            && components
                .values()
                .all(|state| !state.required || state.status == "ok");
        ReadinessReport {
            status: if ready { "ready" } else { "not_ready" },
            components,
        }
    }
}

fn unavailable(message: &str) -> ReadinessReport {
    ReadinessReport {
        status: "not_ready",
        components: BTreeMap::from([(
            "local_forwarding".to_string(),
            ComponentState {
                status: "unknown",
                required: true,
                error: Some(message.to_string()),
            },
        )]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::bail;

    #[tokio::test]
    async fn required_failure_gates_readiness() {
        let readiness = Readiness::new(
            vec![
                ReadinessCheck {
                    name: "tun".to_string(),
                    required: true,
                    probe: Some(Arc::new(|_| Box::pin(async { Ok(()) }))),
                },
                ReadinessCheck {
                    name: "nat".to_string(),
                    required: true,
                    probe: Some(Arc::new(|_| Box::pin(async { bail!("missing rule") }))),
                },
            ],
            Duration::from_secs(1),
        );
        let report = readiness.check().await;
        assert_eq!(report.status, "not_ready");
        assert_eq!(report.components["tun"].status, "ok");
        assert_eq!(report.components["nat"].status, "error");
    }

    #[tokio::test]
    async fn missing_probes_are_not_ready() {
        let report = Readiness::new(Vec::new(), Duration::from_secs(1))
            .check()
            .await;
        assert_eq!(report.status, "not_ready");
        assert_eq!(report.components["local_forwarding"].status, "unknown");
    }
}
