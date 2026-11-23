use crate::data::ratelimit::{AccountRateLimiter, Direction as RateDirection, RateLimiters};
use crate::data::router::{Router, RouterError, Session as RouterSession};
use crate::ops::abuse::{AbuseGuard, Surface};
use crate::ops::metrics::Metrics as OperationalMetrics;
use crate::proxy::service::{
    AuthenticationLimiter, AuthenticationReservation, AuthorizedSession,
    Authorizer as ProxyAuthorizer, BoxError as ProxyError, Identity as ProxyIdentity,
    UsageHooks as ProxyUsage, UsageSession as ProxyUsageSession, DEVICE_ID as PROXY_DEVICE_ID,
};
use crate::state::pool::{Lease as PoolLease, Pool, PoolError};
use crate::state::registry::{
    AccountLimits, ClientRegistry as StateRegistry, RegistryError as StateRegistryError,
    UsagePeriod,
};
use crate::state::sessions::SessionGuard;
use crate::state::usage;
use crate::transport::session::{
    Authenticated, AuthenticationError, AuthenticationRequest, Authenticator, Cleanup,
    ClientIdentity as TransportIdentity, DenialReason, Lease, LeaseAllocator, LeaseError,
    LeaseMode, LeaseRequest, Metrics, PacketRouter, PacketSource, QueueDrop, RouteError, RouteKind,
    RouteRequest, RouteSession, TokenCancellation, Usage, UsageMetadata, UsageSession,
};
use crate::web::admin::{
    ClientIdentity as WebIdentity, ClientLimits as WebClientLimits, ClientRegistry as WebRegistry,
    ClientSummary as WebClientSummary, DeviceSummary as WebDeviceSummary,
    RegistryError as WebRegistryError,
};
use crate::wire::device_auth;
use bytes::Bytes;
use futures_util::future::BoxFuture;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

pub struct NativeAuthenticator {
    registry: Arc<StateRegistry>,
    abuse: Arc<AbuseGuard>,
}

impl NativeAuthenticator {
    pub fn new(registry: Arc<StateRegistry>, abuse: Arc<AbuseGuard>) -> Arc<Self> {
        Arc::new(Self { registry, abuse })
    }
}

impl Authenticator for NativeAuthenticator {
    fn authenticate(
        &self,
        request: AuthenticationRequest,
    ) -> BoxFuture<'static, Result<Authenticated, AuthenticationError>> {
        let registry = self.registry.clone();
        let abuse = self.abuse.clone();
        Box::pin(async move {
            let Some(reservation) = abuse.reserve(Surface::Native, request.peer.ip()) else {
                return Err(AuthenticationError::RateLimited {
                    retry_after_seconds: 5,
                });
            };
            let proof = device_auth::Proof {
                device_id: request.proof.device_id,
                name: request.proof.name,
                public_key: request.proof.public_key,
                timestamp: request.proof.timestamp,
                nonce: request.proof.nonce,
                signature: request.proof.signature,
            };
            // Enrollment must publish its in-memory state even if the HTTP request
            // disappears while the registry's detached persistence task is running.
            let session = tokio::spawn(async move {
                registry
                    .authenticate_device_session(
                        &request.bearer_token,
                        &proof,
                        request.method.as_str(),
                        &request.path,
                    )
                    .await
            })
            .await
            .map_err(|error| {
                tracing::error!(%error, "native authentication task failed");
                AuthenticationError::Unauthorized
            })?
            .map_err(|error| match error {
                StateRegistryError::Expired => {
                    AuthenticationError::Forbidden(DenialReason::AccountExpired)
                }
                StateRegistryError::QuotaExceeded => {
                    AuthenticationError::Forbidden(DenialReason::QuotaExceeded)
                }
                StateRegistryError::Unauthorized
                | StateRegistryError::Disabled
                | StateRegistryError::DeviceLimit
                | StateRegistryError::Draining
                | StateRegistryError::InvalidDeviceProof => AuthenticationError::Unauthorized,
                error => {
                    tracing::error!(%error, "native authentication failed");
                    AuthenticationError::Unauthorized
                }
            })?;
            reservation.refund();
            Ok(Authenticated {
                identity: TransportIdentity {
                    account_id: session.identity.account_id,
                    lease_id: session.identity.lease_id,
                },
                cancellation: Arc::new(TokenCancellation::new(session.cancellation)),
                cleanup: Arc::new(RegistrySessionCleanup::new(session.guard)),
            })
        })
    }
}

struct RegistrySessionCleanup {
    guard: Mutex<Option<SessionGuard>>,
}

impl RegistrySessionCleanup {
    fn new(guard: SessionGuard) -> Self {
        Self {
            guard: Mutex::new(Some(guard)),
        }
    }
}

impl Cleanup for RegistrySessionCleanup {
    fn close(&self) {
        self.guard.lock().take();
    }
}

pub struct RegistryProxyAuthorizer {
    registry: Arc<StateRegistry>,
}

impl RegistryProxyAuthorizer {
    pub fn new(registry: Arc<StateRegistry>) -> Arc<Self> {
        Arc::new(Self { registry })
    }
}

impl ProxyAuthorizer for RegistryProxyAuthorizer {
    fn authorize<'a>(
        &'a self,
        token: &'a str,
        device_id: &'a str,
        parent_cancellation: CancellationToken,
    ) -> BoxFuture<'a, Result<AuthorizedSession, ProxyError>> {
        Box::pin(async move {
            if device_id != PROXY_DEVICE_ID {
                return Err("invalid proxy device".into());
            }
            let registry = self.registry.clone();
            let token = Zeroizing::new(token.to_owned());
            // Keep enrollment and persistence together when a CONNECT is cancelled.
            let session =
                tokio::spawn(async move { registry.authenticate_proxy_session(&token).await })
                    .await
                    .map_err(|error| -> ProxyError { Box::new(error) })?
                    .map_err(|error| -> ProxyError { Box::new(error) })?;
            let session_cancellation = session.cancellation;
            let cancellation = CancellationToken::new();
            let merged = cancellation.clone();
            let bridge = tokio::spawn(async move {
                tokio::select! {
                    _ = parent_cancellation.cancelled() => {}
                    _ = session_cancellation.cancelled() => {}
                }
                merged.cancel();
            });
            let guard = session.guard;
            Ok(AuthorizedSession::new(
                ProxyIdentity {
                    account_id: session.identity.account_id.into_boxed_str(),
                    device_id: session.device_id.into_boxed_str(),
                },
                cancellation,
                move || {
                    bridge.abort();
                    drop(guard);
                },
            ))
        })
    }
}

pub struct AbuseLimiter {
    abuse: Arc<AbuseGuard>,
}

impl AbuseLimiter {
    pub fn new(abuse: Arc<AbuseGuard>) -> Arc<Self> {
        Arc::new(Self { abuse })
    }
}

struct AbuseReservation<'a>(Option<crate::ops::abuse::Reservation<'a>>);

impl AuthenticationReservation for AbuseReservation<'_> {
    fn refund(mut self: Box<Self>) {
        if let Some(reservation) = self.0.take() {
            reservation.refund();
        }
    }
}

impl AuthenticationLimiter for AbuseLimiter {
    fn reserve(&self, client: std::net::IpAddr) -> Option<Box<dyn AuthenticationReservation + '_>> {
        self.abuse
            .reserve(Surface::Proxy, client)
            .map(|reservation| {
                Box::new(AbuseReservation(Some(reservation)))
                    as Box<dyn AuthenticationReservation + '_>
            })
    }
}

pub struct ProxyUsageAdapter {
    store: Arc<usage::Store>,
}

impl ProxyUsageAdapter {
    pub fn new(store: Arc<usage::Store>) -> Arc<Self> {
        Arc::new(Self { store })
    }
}

struct ProxyUsageHandle {
    session: usage::Session,
}

impl ProxyUsageSession for ProxyUsageHandle {
    fn add_uploaded(&self, bytes: u64) {
        self.session.add_uploaded(bytes, 0);
    }

    fn add_downloaded(&self, bytes: u64) {
        self.session.add_downloaded(bytes, 0);
    }
}

impl ProxyUsage for ProxyUsageAdapter {
    fn begin(
        &self,
        identity: &ProxyIdentity,
        kind: &'static str,
        target: &str,
    ) -> Box<dyn ProxyUsageSession> {
        Box::new(ProxyUsageHandle {
            session: self.store.begin(
                "",
                identity.account_id.to_string(),
                identity.device_id.to_string(),
                kind,
                "",
                target,
            ),
        })
    }
}

pub struct WebRegistryAdapter {
    registry: Arc<StateRegistry>,
    usage: Arc<usage::Store>,
}

impl WebRegistryAdapter {
    pub fn new(registry: Arc<StateRegistry>, usage: Arc<usage::Store>) -> Arc<Self> {
        Arc::new(Self { registry, usage })
    }

    fn summary(&self, id: &str) -> Result<WebClientSummary, WebRegistryError> {
        let snapshot = self.usage.snapshot();
        self.registry
            .list_with_usage(&snapshot)
            .into_iter()
            .find(|client| client.id == id)
            .map(web_client_summary)
            .ok_or(WebRegistryError::NotFound)
    }
}

/// Applies account expiry, monthly data quotas, and throughput limits.
///
/// Authentication rejects expired and over-quota accounts immediately; this
/// task additionally ends sessions that cross a limit while connected and
/// keeps the data-path rate limiters in sync with the registry.
pub struct AccountPolicyEnforcer {
    registry: Arc<StateRegistry>,
    usage: Arc<usage::Store>,
    limiters: Arc<RateLimiters>,
}

/// How often limits are evaluated; quota overshoot is bounded by the
/// account's traffic during one interval.
pub const POLICY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

impl AccountPolicyEnforcer {
    pub fn new(
        registry: Arc<StateRegistry>,
        usage: Arc<usage::Store>,
        limiters: Arc<RateLimiters>,
    ) -> Self {
        Self {
            registry,
            usage,
            limiters,
        }
    }

    pub async fn run(&self, cancellation: CancellationToken) {
        let mut interval = tokio::time::interval(POLICY_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = cancellation.cancelled() => return,
                _ = interval.tick() => self.enforce(time::OffsetDateTime::now_utc()).await,
            }
        }
    }

    pub async fn enforce(&self, now: time::OffsetDateTime) {
        let policies = self.registry.account_policies();
        self.limiters.configure(
            policies
                .iter()
                .map(|policy| (policy.id.clone(), policy.limits.rate_limit_kbps)),
        );
        let snapshot = self.usage.snapshot();
        let month = usage_month(now);
        for policy in policies {
            if policy.limits.expired_at(now) {
                if policy.active_sessions > 0 {
                    let ended = self.registry.end_sessions(&policy.id).await;
                    tracing::info!(account_id = %policy.id, ended, "account expired; sessions ended");
                }
                continue;
            }
            let Some(quota) = policy.limits.monthly_quota_bytes else {
                self.registry.set_quota_blocked(&policy.id, false).await;
                continue;
            };
            let total = account_usage_bytes(&snapshot, &policy.id);
            let period = match policy.usage_period {
                Some(period) if period.month == month => period,
                _ => {
                    // A new month, or a newly configured quota, counts from now.
                    let period = UsagePeriod {
                        month: month.clone(),
                        baseline_bytes: total,
                    };
                    if let Err(error) = self
                        .registry
                        .set_usage_period(&policy.id, period.clone())
                        .await
                    {
                        tracing::warn!(%error, account_id = %policy.id, "start quota period failed");
                        continue;
                    }
                    period
                }
            };
            let used = total.saturating_sub(period.baseline_bytes);
            let blocked = used >= quota;
            if self.registry.set_quota_blocked(&policy.id, blocked).await {
                if blocked {
                    tracing::info!(account_id = %policy.id, used, quota, "monthly data quota exhausted; sessions ended");
                } else {
                    tracing::info!(account_id = %policy.id, used, quota, "account is within its monthly data quota again");
                }
            }
        }
    }
}

/// Lifetime uploaded plus downloaded IP bytes of an account.
pub fn account_usage_bytes(snapshot: &usage::Snapshot, account_id: &str) -> u64 {
    snapshot
        .clients
        .get(account_id)
        .map_or(0, |client| client.bytes_uploaded + client.bytes_downloaded)
}

/// Quota periods are UTC calendar months.
pub fn usage_month(now: time::OffsetDateTime) -> String {
    let now = now.to_offset(time::UtcOffset::UTC);
    format!("{:04}-{:02}", now.year(), u8::from(now.month()))
}

impl WebRegistry for WebRegistryAdapter {
    fn list_clients(&self) -> Result<Vec<WebClientSummary>, WebRegistryError> {
        let snapshot = self.usage.snapshot();
        Ok(self
            .registry
            .list_with_usage(&snapshot)
            .into_iter()
            .map(web_client_summary)
            .collect())
    }

    fn create_client<'a>(
        &'a self,
        name: &'a str,
        max_devices: usize,
    ) -> BoxFuture<'a, Result<(WebClientSummary, String), WebRegistryError>> {
        let registry = self.registry.clone();
        let name = name.to_owned();
        Box::pin(async move {
            join_web_mutation(tokio::spawn(async move {
                registry
                    .create(name, max_devices)
                    .await
                    .map(|(summary, token)| (web_client_summary(summary), token))
                    .map_err(web_registry_error)
            }))
            .await
        })
    }

    fn update_client<'a>(
        &'a self,
        id: &'a str,
        name: &'a str,
        max_devices: usize,
        enabled: bool,
    ) -> BoxFuture<'a, Result<WebClientSummary, WebRegistryError>> {
        let registry = self.registry.clone();
        let id = id.to_owned();
        let name = name.to_owned();
        Box::pin(async move {
            join_web_mutation(tokio::spawn(async move {
                registry
                    .update(&id, name, max_devices, enabled)
                    .await
                    .map(web_client_summary)
                    .map_err(web_registry_error)
            }))
            .await
        })
    }

    fn delete_client<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Result<(), WebRegistryError>> {
        let registry = self.registry.clone();
        let usage = self.usage.clone();
        let id = id.to_owned();
        Box::pin(async move {
            join_web_mutation(tokio::spawn(async move {
                registry.delete(&id).await.map_err(web_registry_error)?;
                usage.delete_client(&id).map_err(|error| {
                    tracing::error!(%error, client_id = id, "delete client usage failed");
                    WebRegistryError::Internal
                })
            }))
            .await
        })
    }

    fn rotate_client_token<'a>(
        &'a self,
        id: &'a str,
    ) -> BoxFuture<'a, Result<String, WebRegistryError>> {
        let registry = self.registry.clone();
        let id = id.to_owned();
        Box::pin(async move {
            join_web_mutation(tokio::spawn(async move {
                registry.rotate_token(&id).await.map_err(web_registry_error)
            }))
            .await
        })
    }

    fn disconnect<'a>(
        &'a self,
        client_id: &'a str,
        device_id: Option<&'a str>,
    ) -> BoxFuture<'a, Result<usize, WebRegistryError>> {
        let registry = self.registry.clone();
        let client_id = client_id.to_owned();
        let device_id = device_id.map(str::to_owned);
        Box::pin(async move {
            join_web_mutation(tokio::spawn(async move {
                registry
                    .disconnect(&client_id, device_id.as_deref())
                    .await
                    .map_err(web_registry_error)
            }))
            .await
        })
    }

    fn forget_device<'a>(
        &'a self,
        client_id: &'a str,
        device_id: &'a str,
    ) -> BoxFuture<'a, Result<(), WebRegistryError>> {
        let registry = self.registry.clone();
        let usage = self.usage.clone();
        let client_id = client_id.to_owned();
        let device_id = device_id.to_owned();
        Box::pin(async move {
            join_web_mutation(tokio::spawn(async move {
                let device_bytes = {
                    let snapshot = usage.snapshot();
                    let device = usage::device(&snapshot, &client_id, &device_id);
                    device.bytes_uploaded + device.bytes_downloaded
                };
                let retirement = registry
                    .retire_device(&client_id, &device_id)
                    .await
                    .map_err(web_registry_error)?;
                // Deleting the device's counters lowers the account's lifetime
                // total; lower the quota baseline too so period usage is kept.
                let period = registry
                    .account_policies()
                    .into_iter()
                    .find(|policy| policy.id == client_id)
                    .and_then(|policy| policy.usage_period);
                if let Some(period) = period {
                    let adjusted = UsagePeriod {
                        baseline_bytes: period.baseline_bytes.saturating_sub(device_bytes),
                        ..period
                    };
                    if let Err(error) = registry.set_usage_period(&client_id, adjusted).await {
                        tracing::warn!(%error, client_id, "adjust quota baseline failed");
                    }
                }
                let result = usage
                    .delete_device(&client_id, &device_id)
                    .map_err(|error| {
                        tracing::error!(
                            %error,
                            client_id,
                            device_id,
                            "delete device usage failed"
                        );
                        WebRegistryError::Internal
                    });
                drop(retirement);
                result
            }))
            .await
        })
    }

    fn authenticate_portal(&self, token: &str) -> Result<WebIdentity, WebRegistryError> {
        self.registry
            .authenticate_portal(token)
            .map(|identity| WebIdentity {
                id: identity.id,
                name: identity.name,
            })
            .map_err(web_registry_error)
    }

    fn portal_client_active(&self, client_id: &str, token_hash: &str) -> bool {
        self.registry.portal_client_active(client_id, token_hash)
    }

    fn set_client_limits<'a>(
        &'a self,
        id: &'a str,
        limits: WebClientLimits,
    ) -> BoxFuture<'a, Result<WebClientSummary, WebRegistryError>> {
        let registry = self.registry.clone();
        let owned_id = id.to_owned();
        Box::pin(async move {
            join_web_mutation(tokio::spawn(async move {
                registry
                    .set_limits(
                        &owned_id,
                        AccountLimits {
                            expires_at: limits.expires_at,
                            monthly_quota_bytes: limits.monthly_quota_bytes,
                            rate_limit_kbps: limits.rate_limit_kbps,
                        },
                    )
                    .await
                    .map(|_| ())
                    .map_err(web_registry_error)
            }))
            .await?;
            self.summary(id)
        })
    }

    fn reset_client_usage<'a>(
        &'a self,
        id: &'a str,
    ) -> BoxFuture<'a, Result<WebClientSummary, WebRegistryError>> {
        let registry = self.registry.clone();
        let usage = self.usage.clone();
        let owned_id = id.to_owned();
        Box::pin(async move {
            join_web_mutation(tokio::spawn(async move {
                let period = UsagePeriod {
                    month: usage_month(time::OffsetDateTime::now_utc()),
                    baseline_bytes: account_usage_bytes(&usage.snapshot(), &owned_id),
                };
                registry
                    .set_usage_period(&owned_id, period)
                    .await
                    .map_err(web_registry_error)?;
                registry.set_quota_blocked(&owned_id, false).await;
                Ok(())
            }))
            .await?;
            self.summary(id)
        })
    }
}

async fn join_web_mutation<T>(
    task: tokio::task::JoinHandle<Result<T, WebRegistryError>>,
) -> Result<T, WebRegistryError> {
    task.await.map_err(|error| {
        tracing::error!(%error, "client registry mutation task failed");
        WebRegistryError::Internal
    })?
}

fn web_registry_error(error: StateRegistryError) -> WebRegistryError {
    match error {
        StateRegistryError::NotFound => WebRegistryError::NotFound,
        StateRegistryError::Unauthorized | StateRegistryError::InvalidDeviceProof => {
            WebRegistryError::Unauthorized
        }
        StateRegistryError::Disabled
        | StateRegistryError::Expired
        | StateRegistryError::QuotaExceeded => WebRegistryError::Disabled,
        StateRegistryError::InvalidInput(message) => WebRegistryError::Invalid(message),
        error => {
            tracing::error!(%error, "client registry operation failed");
            WebRegistryError::Internal
        }
    }
}

fn web_client_summary(summary: crate::state::registry::ClientSummary) -> WebClientSummary {
    WebClientSummary {
        id: summary.id,
        name: summary.name,
        max_devices: summary.max_devices,
        enabled: summary.enabled,
        created_at: format_time(summary.created_at),
        device_count: summary.device_count,
        active_sessions: summary.active_sessions as u64,
        connections_total: summary.connections_total,
        bytes_uploaded: summary.bytes_uploaded,
        bytes_downloaded: summary.bytes_downloaded,
        packets_uploaded: summary.packets_uploaded,
        packets_downloaded: summary.packets_downloaded,
        last_connected: summary.last_connected.map(format_time),
        last_disconnected: summary.last_disconnected.map(format_time),
        expires_at: summary.limits.expires_at.map(format_time),
        monthly_quota_bytes: summary.limits.monthly_quota_bytes,
        rate_limit_kbps: summary.limits.rate_limit_kbps,
        quota_used_bytes: summary.quota_used_bytes,
        status: summary.status.to_owned(),
        devices: summary
            .devices
            .into_iter()
            .map(|device| WebDeviceSummary {
                id: device.id,
                name: device.name,
                first_seen: format_time(device.first_seen),
                last_seen: format_time(device.last_seen),
                active_sessions: device.active_sessions as u64,
                connections_total: device.connections_total,
                bytes_uploaded: device.bytes_uploaded,
                bytes_downloaded: device.bytes_downloaded,
                packets_uploaded: device.packets_uploaded,
                packets_downloaded: device.packets_downloaded,
                last_connected: device.last_connected.map(format_time),
                last_disconnected: device.last_disconnected.map(format_time),
                transport: device.transport,
                assigned_address: device.assigned_address,
                target: device.target,
            })
            .collect(),
    }
}

fn format_time(value: time::OffsetDateTime) -> String {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

#[derive(Clone)]
pub struct PoolAdapter {
    pool: Arc<Pool>,
    next_id: Arc<AtomicU64>,
    active: Arc<Mutex<HashMap<u64, PoolLease>>>,
}

impl PoolAdapter {
    pub fn new(pool: Arc<Pool>) -> Arc<Self> {
        Arc::new(Self {
            pool,
            next_id: Arc::new(AtomicU64::new(0)),
            active: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn lease(&self, id: u64) -> Option<PoolLease> {
        self.active.lock().get(&id).cloned()
    }

    fn map_lease(&self, lease: PoolLease) -> Lease {
        let opaque_id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let value = Lease {
            address: lease.address,
            prefix_len: lease.prefix_bits,
            gateway: lease.gateway,
            opaque_id,
        };
        self.active.lock().insert(opaque_id, lease);
        value
    }

    fn release_lease(&self, lease: &Lease) {
        if let Some(lease) = self.active.lock().remove(&lease.opaque_id) {
            self.pool.release(&lease);
        }
    }
}

impl LeaseAllocator for PoolAdapter {
    fn acquire(&self, request: LeaseRequest) -> BoxFuture<'static, Result<Lease, LeaseError>> {
        let pool = self.pool.clone();
        let adapter = self.clone();
        Box::pin(async move {
            let acquired = tokio::task::spawn_blocking(move || {
                let acquired = match request.mode {
                    LeaseMode::Exclusive => pool.acquire(&request.lease_id),
                    LeaseMode::LaneGroup => pool.acquire_group(
                        &request.lease_id,
                        request.group_id.as_deref().unwrap_or_default(),
                    ),
                };
                acquired.map(|lease| PendingLease {
                    lease: Some(adapter.map_lease(lease)),
                    adapter,
                })
            })
            .await
            .map_err(|error| {
                tracing::error!(%error, "lease allocation task failed");
                LeaseError::Internal
            })?;
            match acquired {
                Ok(lease) => Ok(lease.commit()),
                Err(PoolError::Exhausted) => Err(LeaseError::Exhausted),
                Err(error) => {
                    tracing::error!(%error, "lease allocation failed");
                    Err(LeaseError::Internal)
                }
            }
        })
    }

    fn release(&self, lease: &Lease) {
        self.release_lease(lease);
    }
}

struct PendingLease {
    adapter: PoolAdapter,
    lease: Option<Lease>,
}

impl PendingLease {
    fn commit(mut self) -> Lease {
        self.lease.take().expect("pending lease is present")
    }
}

impl Drop for PendingLease {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            self.adapter.release_lease(&lease);
        }
    }
}

pub struct RouterAdapter {
    router: Arc<Router>,
    leases: Arc<PoolAdapter>,
    limiters: Arc<RateLimiters>,
    /// Uplink limiter by lease; leases are unique per live device session.
    uplink: Arc<parking_lot::RwLock<HashMap<Ipv4Addr, Arc<AccountRateLimiter>>>>,
}

impl RouterAdapter {
    pub fn new(router: Arc<Router>, leases: Arc<PoolAdapter>) -> Arc<Self> {
        Self::with_rate_limits(router, leases, RateLimiters::new())
    }

    pub fn with_rate_limits(
        router: Arc<Router>,
        leases: Arc<PoolAdapter>,
        limiters: Arc<RateLimiters>,
    ) -> Arc<Self> {
        Arc::new(Self {
            router,
            leases,
            limiters,
            uplink: Arc::default(),
        })
    }

    fn uplink_allowed(&self, lease: Ipv4Addr, bytes: usize) -> bool {
        if !self.limiters.any_limited() {
            return true;
        }
        let allowed = self
            .uplink
            .read()
            .get(&lease)
            .is_none_or(|limiter| limiter.allow(RateDirection::Uplink, bytes));
        if !allowed {
            self.limiters.record_drop();
        }
        allowed
    }
}

struct RouteHandle {
    session: RouterSession,
    address: Ipv4Addr,
    limiter: Arc<AccountRateLimiter>,
    limiters: Arc<RateLimiters>,
    uplink: Arc<parking_lot::RwLock<HashMap<Ipv4Addr, Arc<AccountRateLimiter>>>>,
}

impl RouteHandle {
    fn admit(&self, packet: &Bytes) -> bool {
        if self.limiter.allow(RateDirection::Downlink, packet.len()) {
            return true;
        }
        self.limiters.record_drop();
        false
    }
}

impl PacketSource for RouteHandle {
    fn next_packet(&self) -> BoxFuture<'_, Option<Bytes>> {
        Box::pin(async move {
            loop {
                let packet = self.session.recv().await?;
                if self.admit(&packet) {
                    return Some(packet);
                }
            }
        })
    }

    fn try_packet(&self) -> Option<Bytes> {
        loop {
            let packet = self.session.try_recv()?;
            if self.admit(&packet) {
                return Some(packet);
            }
        }
    }

    fn queued_bytes(&self) -> usize {
        self.session.queued_bytes()
    }
}

impl Cleanup for RouteHandle {
    fn close(&self) {
        self.session.close();
        let mut uplink = self.uplink.write();
        if uplink
            .get(&self.address)
            .is_some_and(|limiter| Arc::ptr_eq(limiter, &self.limiter))
        {
            uplink.remove(&self.address);
        }
    }
}

impl PacketRouter for RouterAdapter {
    fn register(
        &self,
        request: RouteRequest,
    ) -> BoxFuture<'static, Result<RouteSession, RouteError>> {
        let router = self.router.clone();
        let pool = self.leases.pool.clone();
        let lease = self.leases.lease(request.lease.opaque_id);
        let limiter = self.limiters.limiter(&request.account_id);
        let limiters = self.limiters.clone();
        let uplink = self.uplink.clone();
        Box::pin(async move {
            let lease = lease.ok_or(RouteError::Conflict)?;
            let mut registered = None;
            let current = pool.register_lease(&lease, || {
                registered = Some(match request.kind {
                    RouteKind::Http2Lane {
                        session_id,
                        lane,
                        lanes,
                        backend_connection,
                    } => router
                        .register_group(
                            &request.parent,
                            request.lease.address,
                            session_id,
                            usize::from(lane),
                            usize::from(lanes),
                            backend_connection,
                        )
                        .map(|registration| (registration.session, registration.collapsed)),
                    RouteKind::ConnectIp => Ok((
                        router.register(&request.parent, request.lease.address),
                        false,
                    )),
                });
            });
            if !current {
                return Err(RouteError::Conflict);
            }
            let (session, collapsed_backend) = registered
                .expect("current lease registration executes")
                .map_err(map_route_error)?;
            let cancellation = session.cancellation();
            let address = request.lease.address;
            uplink.write().insert(address, limiter.clone());
            let handle = Arc::new(RouteHandle {
                session,
                address,
                limiter,
                limiters,
                uplink,
            });
            Ok(RouteSession {
                downlink: handle.clone(),
                cancellation,
                collapsed_backend,
                cleanup: handle,
            })
        })
    }

    fn inject_from_client(
        &self,
        cancellation: CancellationToken,
        lease: Ipv4Addr,
        packet: Bytes,
    ) -> BoxFuture<'static, Result<(), RouteError>> {
        let router = self.router.clone();
        let allowed = self.uplink_allowed(lease, packet.len());
        Box::pin(async move {
            if !allowed {
                return Ok(());
            }
            router
                .inject(&cancellation, lease, &packet)
                .await
                .map_err(map_route_error)
        })
    }

    fn inject_validated(
        &self,
        cancellation: CancellationToken,
        packet: Bytes,
    ) -> BoxFuture<'static, Result<(), RouteError>> {
        let router = self.router.clone();
        Box::pin(async move {
            router
                .inject_validated(&cancellation, &packet)
                .await
                .map_err(map_route_error)
        })
    }
}

fn map_route_error(error: RouterError) -> RouteError {
    match error {
        RouterError::MissingGroupId
        | RouterError::InvalidLaneConfiguration
        | RouterError::LaneCountMismatch
        | RouterError::SourceSpoofed { .. } => RouteError::Conflict,
        RouterError::InvalidPacket(_) | RouterError::Device(_) => RouteError::Unavailable,
    }
}

pub struct UsageAdapter {
    store: Arc<usage::Store>,
}

impl UsageAdapter {
    pub fn new(store: Arc<usage::Store>) -> Arc<Self> {
        Arc::new(Self { store })
    }
}

struct UsageHandle {
    session: usage::Session,
}

impl UsageSession for UsageHandle {
    fn uploaded(&self, bytes: u64, packets: u64) {
        self.session.add_uploaded(bytes, packets);
    }

    fn downloaded(&self, bytes: u64, packets: u64) {
        self.session.add_downloaded(bytes, packets);
    }

    fn close(&self) {
        self.session.close();
    }
}

impl Usage for UsageAdapter {
    fn begin(&self, metadata: UsageMetadata) -> Arc<dyn UsageSession> {
        Arc::new(UsageHandle {
            session: self.store.begin(
                if metadata.session_id.is_empty() {
                    String::new()
                } else {
                    format!(
                        "vpn:{}:{}:{}",
                        metadata.account_id, metadata.device_id, metadata.session_id
                    )
                },
                metadata.account_id,
                metadata.device_id,
                metadata.transport,
                metadata.address.to_string(),
                "",
            ),
        })
    }
}

impl Metrics for OperationalMetrics {
    fn authentication_failed(&self) {
        OperationalMetrics::authentication_failed(self);
    }

    fn connected(&self) {
        OperationalMetrics::connected(self);
    }

    fn disconnected(&self) {
        OperationalMetrics::disconnected(self);
    }

    fn received_from_client(&self) {
        OperationalMetrics::received_from_client(self);
    }

    fn sent_to_client(&self) {
        OperationalMetrics::sent_to_client(self);
    }

    fn dropped_from_client(&self) {
        OperationalMetrics::dropped_from_client(self);
    }

    fn datagram_oversize(&self) {
        OperationalMetrics::datagram_oversize(self);
    }

    fn datagram_mtu_reduced(&self) {
        OperationalMetrics::datagram_mtu_reduced(self);
    }

    fn collapsed_lane_group(&self) {
        OperationalMetrics::lane_collapsed(self);
    }

    fn queue_drop(&self, _lane: i8, reason: QueueDrop) {
        OperationalMetrics::queue_drop(
            self,
            match reason {
                QueueDrop::Closed => "session_closed",
                QueueDrop::Full => "queue_full",
                QueueDrop::Tail => "queue_tail",
                QueueDrop::Oldest => "queue_oldest",
                QueueDrop::Expired => "queue_expired",
            },
        );
    }

    fn queue_bytes(&self, lane: i8, delta: isize) {
        if lane >= 0 {
            OperationalMetrics::adjust_queue_bytes(self, lane as usize, delta as i64);
        }
    }

    fn invalid_tun_packet(&self) {
        OperationalMetrics::queue_drop(self, "invalid_tun_packet");
    }

    fn mtu_fragmented(&self) {
        OperationalMetrics::mtu_action(self, "fragmented");
    }

    fn mtu_icmp_sent(&self) {
        OperationalMetrics::mtu_action(self, "icmp_sent");
    }

    fn mtu_icmp_suppressed(&self) {
        OperationalMetrics::mtu_action(self, "icmp_suppressed");
    }

    fn mtu_icmp_rate_limited(&self) {
        OperationalMetrics::mtu_action(self, "icmp_rate_limited");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::router::PacketDevice;
    use std::future::{pending, Future};
    use std::io;
    use std::pin::Pin;

    #[test]
    fn mtu_reduction_adapter_updates_operational_counter() {
        let metrics = OperationalMetrics::default();
        Metrics::datagram_mtu_reduced(&metrics);
        assert!(metrics
            .render_prometheus()
            .lines()
            .any(|line| line == "porta_datagram_mtu_reductions_total 1"));
    }

    #[derive(Default)]
    struct MemoryDevice {
        writes: Mutex<Vec<Vec<u8>>>,
    }

    impl PacketDevice for MemoryDevice {
        fn read_packet(&self) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send + '_>> {
            Box::pin(pending())
        }

        fn write_packet<'a>(
            &'a self,
            packet: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
            Box::pin(async move {
                self.writes.lock().push(packet.to_vec());
                Ok(())
            })
        }

        fn name(&self) -> &str {
            "memory"
        }
    }

    #[tokio::test]
    async fn adapters_preserve_lease_fencing_and_injection_paths() {
        let pool = Arc::new(Pool::new("10.66.0.0/30").unwrap());
        let leases = PoolAdapter::new(pool);
        let first = leases
            .acquire(LeaseRequest {
                lease_id: "client".into(),
                group_id: Some("first-group".into()),
                mode: LeaseMode::LaneGroup,
            })
            .await
            .unwrap();
        let current = leases
            .acquire(LeaseRequest {
                lease_id: "client".into(),
                group_id: Some("second-group".into()),
                mode: LeaseMode::LaneGroup,
            })
            .await
            .unwrap();
        assert_eq!(first.address, current.address);

        let device = Arc::new(MemoryDevice::default());
        let router =
            RouterAdapter::new(Arc::new(Router::new(device.clone(), None)), leases.clone());
        let stale = router
            .register(RouteRequest {
                lease: first.clone(),
                kind: RouteKind::ConnectIp,
                parent: CancellationToken::new(),
                account_id: "account".into(),
            })
            .await;
        assert!(matches!(stale, Err(RouteError::Conflict)));

        let route = router
            .register(RouteRequest {
                lease: current.clone(),
                kind: RouteKind::ConnectIp,
                parent: CancellationToken::new(),
                account_id: "account".into(),
            })
            .await
            .unwrap();
        let packet = ipv4_packet(current.address);
        router
            .inject_from_client(route.cancellation.clone(), current.address, packet.clone())
            .await
            .unwrap();
        router
            .inject_validated(route.cancellation.clone(), Bytes::from_static(b"icmp"))
            .await
            .unwrap();
        assert_eq!(device.writes.lock().len(), 2);

        route.cleanup.close();
        leases.release(&first);
        leases.release(&current);
    }

    const TOKEN: &str = "bootstrap-token-0123456789";

    async fn policy_fixture() -> (
        tempfile::TempDir,
        Arc<StateRegistry>,
        Arc<usage::Store>,
        Arc<RateLimiters>,
        String,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let registry = Arc::new(
            StateRegistry::open(directory.path().join("clients.json"), TOKEN)
                .await
                .unwrap(),
        );
        let id = registry.list()[0].id.clone();
        (
            directory,
            registry,
            Arc::new(usage::Store::in_memory()),
            RateLimiters::new(),
            id,
        )
    }

    #[tokio::test]
    async fn enforcer_blocks_exhausted_quotas_and_resets_each_month() {
        let (_directory, registry, usage, limiters, id) = policy_fixture().await;
        let enforcer =
            AccountPolicyEnforcer::new(registry.clone(), usage.clone(), limiters.clone());
        registry
            .set_limits(
                &id,
                AccountLimits {
                    monthly_quota_bytes: Some(1_000),
                    rate_limit_kbps: Some(1_000),
                    ..AccountLimits::default()
                },
            )
            .await
            .unwrap();
        let november = time::macros::datetime!(2026-11-20 12:00 UTC);
        enforcer.enforce(november).await;
        assert!(limiters.any_limited());
        assert_eq!(
            registry.account_policies()[0].usage_period,
            Some(UsagePeriod {
                month: "2026-11".into(),
                baseline_bytes: 0
            })
        );

        let session = usage.begin("s", &id, "device", "h3", "10.66.0.2", "");
        session.add_uploaded(600, 1);
        enforcer.enforce(november).await;
        assert!(registry.authenticate_proxy_session(TOKEN).await.is_ok());
        session.add_downloaded(600, 1);
        enforcer.enforce(november).await;
        assert!(matches!(
            registry.authenticate_proxy_session(TOKEN).await,
            Err(StateRegistryError::QuotaExceeded)
        ));
        let summary = &registry.list_with_usage(&usage.snapshot())[0];
        assert_eq!(summary.status, "quota_exceeded");
        assert_eq!(summary.quota_used_bytes, Some(1_200));

        // The next month starts a new period from the current total.
        enforcer
            .enforce(time::macros::datetime!(2026-12-01 00:00:05 UTC))
            .await;
        assert!(registry.authenticate_proxy_session(TOKEN).await.is_ok());
        assert_eq!(
            registry.account_policies()[0].usage_period,
            Some(UsagePeriod {
                month: "2026-12".into(),
                baseline_bytes: 1_200
            })
        );

        registry
            .set_limits(&id, AccountLimits::default())
            .await
            .unwrap();
        enforcer.enforce(november).await;
        assert!(!limiters.any_limited());
        session.close();
    }

    #[tokio::test]
    async fn admin_api_sets_limits_and_resets_quota_usage() {
        use crate::web::admin::AdminService;
        use crate::web::session::RequestContext;

        let (_directory, registry, usage, _limiters, id) = policy_fixture().await;
        let admin = AdminService::new(
            WebRegistryAdapter::new(registry.clone(), usage.clone()),
            b"admin-token-0123456789abcdef".to_vec(),
        );
        let put = |body: &str| {
            RequestContext::new("PUT", format!("/api/clients/{id}/limits"))
                .with_header("Authorization", "Bearer admin-token-0123456789abcdef")
                .with_body(body.as_bytes().to_vec())
        };
        let response = admin
            .handle(
                &put(r#"{"expires_at":"2030-01-01T00:00:00Z","monthly_quota_bytes":5000000000,"rate_limit_kbps":10000}"#),
                false,
            )
            .await
            .unwrap();
        assert_eq!(
            response.status,
            200,
            "{}",
            String::from_utf8_lossy(&response.body)
        );
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["client"]["expires_at"], "2030-01-01T00:00:00Z");
        assert_eq!(body["client"]["monthly_quota_bytes"], 5_000_000_000_u64);
        assert_eq!(body["client"]["rate_limit_kbps"], 10_000);
        assert_eq!(body["client"]["status"], "active");

        for invalid in [
            r#"{"monthly_quota_bytes":1}"#,
            r#"{"expires_at":"tomorrow","monthly_quota_bytes":null,"rate_limit_kbps":null}"#,
            r#"{"expires_at":null,"monthly_quota_bytes":null,"rate_limit_kbps":8}"#,
        ] {
            let response = admin.handle(&put(invalid), false).await.unwrap();
            assert_eq!(response.status, 400, "{invalid}");
        }

        let session = usage.begin("s", &id, "device", "h3", "10.66.0.2", "");
        session.add_uploaded(4_000, 2);
        registry
            .set_usage_period(
                &id,
                UsagePeriod {
                    month: usage_month(time::OffsetDateTime::now_utc()),
                    baseline_bytes: 0,
                },
            )
            .await
            .unwrap();
        registry.set_quota_blocked(&id, true).await;
        let reset = RequestContext::new("POST", format!("/api/clients/{id}/usage/reset"))
            .with_header("Authorization", "Bearer admin-token-0123456789abcdef");
        let response = admin.handle(&reset, false).await.unwrap();
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["client"]["quota_used_bytes"], 0);
        assert_eq!(body["client"]["status"], "active");
        session.close();
    }

    #[tokio::test]
    async fn uplink_is_policed_per_account() {
        let pool = Arc::new(Pool::new("10.66.0.0/30").unwrap());
        let leases = PoolAdapter::new(pool);
        let lease = leases
            .acquire(LeaseRequest {
                lease_id: "client".into(),
                group_id: None,
                mode: LeaseMode::Exclusive,
            })
            .await
            .unwrap();
        let device = Arc::new(MemoryDevice::default());
        let limiters = RateLimiters::new();
        limiters.configure([("account".to_owned(), Some(64))]);
        let router = RouterAdapter::with_rate_limits(
            Arc::new(Router::new(device.clone(), None)),
            leases.clone(),
            limiters,
        );
        let route = router
            .register(RouteRequest {
                lease: lease.clone(),
                kind: RouteKind::ConnectIp,
                parent: CancellationToken::new(),
                account_id: "account".into(),
            })
            .await
            .unwrap();
        let mut packet = vec![0_u8; 1400];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&1400_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&lease.address.octets());
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        let packet = Bytes::from(packet);
        for _ in 0..200 {
            router
                .inject_from_client(route.cancellation.clone(), lease.address, packet.clone())
                .await
                .unwrap();
        }
        // A 64 kbit/s account passes its 64 KiB burst, then drops the excess.
        let written = device.writes.lock().len();
        assert!((40..60).contains(&written), "{written} packets passed");
        route.cleanup.close();
        assert!(router.uplink.read().is_empty());
    }

    fn ipv4_packet(source: Ipv4Addr) -> Bytes {
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        Bytes::from(packet)
    }
}
