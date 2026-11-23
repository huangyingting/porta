//! Account federation: a replica gateway mirrors the accounts, devices and
//! policies of a primary gateway, so one profile can list both and fail
//! over between them. The primary serves its registry to replicas that
//! present the shared federation token; replicas poll it, keep the last copy
//! for restarts, and treat accounts as read-only.

use crate::state::registry::{ClientRegistry, RegistryFile};
use parking_lot::Mutex;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

/// Path of the primary's registry endpoint on its public listener.
pub const REGISTRY_PATH: &str = "/federation/v1/registry";
const SYNC_INTERVAL: Duration = Duration::from_secs(15);
const RETRY_INTERVAL: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REGISTRY_BYTES: usize = 64 << 20;
pub const MIN_TOKEN_LENGTH: usize = 32;

/// The latest sync with the primary, for operators.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct FederationStatus {
    pub primary: String,
    pub connected: bool,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub last_sync: Option<OffsetDateTime>,
    pub clients: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub struct FederationSync {
    url: String,
    token: Zeroizing<String>,
    http: reqwest::Client,
    registry: Arc<ClientRegistry>,
    status: Arc<Mutex<FederationStatus>>,
}

impl FederationSync {
    /// Starts an empty status for `primary`, to report before syncing.
    pub fn status_for(primary: &str) -> Arc<Mutex<FederationStatus>> {
        Arc::new(Mutex::new(FederationStatus {
            primary: primary.to_owned(),
            ..FederationStatus::default()
        }))
    }

    pub fn new(
        primary: &str,
        token: Zeroizing<String>,
        ca: Option<&Path>,
        registry: Arc<ClientRegistry>,
        status: Arc<Mutex<FederationStatus>>,
    ) -> anyhow::Result<Self> {
        let mut builder = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none());
        if let Some(path) = ca {
            let pem = std::fs::read(path)?;
            builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&pem)?);
        }
        Ok(Self {
            url: format!("{}{REGISTRY_PATH}", primary.trim_end_matches('/')),
            token,
            http: builder.build()?,
            registry,
            status,
        })
    }

    pub fn status(&self) -> Arc<Mutex<FederationStatus>> {
        self.status.clone()
    }

    /// Mirrors the primary until cancelled.
    pub async fn run(self, cancellation: CancellationToken) -> anyhow::Result<()> {
        loop {
            let delay = match self.sync().await {
                Ok(clients) => {
                    let mut status = self.status.lock();
                    status.connected = true;
                    status.last_sync = Some(OffsetDateTime::now_utc());
                    status.clients = clients;
                    status.error = None;
                    SYNC_INTERVAL
                }
                Err(error) => {
                    tracing::warn!(%error, primary = %self.url, "could not mirror accounts from the primary gateway");
                    let mut status = self.status.lock();
                    status.connected = false;
                    status.error = Some(error);
                    RETRY_INTERVAL
                }
            };
            tokio::select! {
                _ = cancellation.cancelled() => return Ok(()),
                _ = tokio::time::sleep(delay) => {}
            }
        }
    }

    async fn sync(&self) -> Result<usize, String> {
        let response = self
            .http
            .get(&self.url)
            .header("Authorization", format!("Bearer {}", self.token.as_str()))
            .send()
            .await
            .map_err(|error| format!("request failed: {error}"))?;
        if !response.status().is_success() {
            return Err(format!("primary returned {}", response.status()));
        }
        let body = response
            .bytes()
            .await
            .map_err(|error| format!("read the registry: {error}"))?;
        if body.len() > MAX_REGISTRY_BYTES {
            return Err("the primary's registry is too large".into());
        }
        let file: RegistryFile =
            serde_json::from_slice(&body).map_err(|error| format!("invalid registry: {error}"))?;
        let sync = self
            .registry
            .replace_from_primary(file)
            .await
            .map_err(|error| error.to_string())?;
        if sync.ended_accounts > 0 || sync.ended_devices > 0 {
            tracing::info!(
                accounts = sync.ended_accounts,
                devices = sync.ended_devices,
                "ended sessions the primary gateway revoked"
            );
        }
        Ok(sync.clients)
    }
}
