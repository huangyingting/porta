use crate::data::queue::DropReason;
use crate::data::ratelimit::{AccountRateLimiter, Direction as RateDirection, RateLimiters};
use crate::data::router::{Router, RouterError, Session as RouterSession};
use crate::ops::abuse::{AbuseGuard, Surface};
use crate::ops::exits::ExitRules;
use crate::ops::metrics::Metrics as OperationalMetrics;
use crate::proxy::service::{
    AuthenticationLimiter, AuthenticationReservation, AuthorizedSession,
    Authorizer as ProxyAuthorizer, BoxError as ProxyError, Identity as ProxyIdentity,
    UsageHooks as ProxyUsage, UsageSession as ProxyUsageSession, DEVICE_ID as PROXY_DEVICE_ID,
};
use crate::state::pool::{Lease as PoolLease, Pool, PoolError};
use crate::state::registry::{
    AccessPolicy, AccountLimits, ClientRegistry as StateRegistry, EnrollmentPolicy,
    RegistryError as StateRegistryError, UsagePeriod,
};
use crate::state::sessions::SessionGuard;
use crate::state::usage;
use crate::transport::session::{
    AccountStatus, Authenticated, AuthenticationError, AuthenticationRequest, Authenticator,
    Cleanup, ClientIdentity as TransportIdentity, DenialReason, Lease, LeaseAllocator, LeaseError,
    LeaseMode, LeaseRequest, Metrics, NetworkPolicy, PacketRouter, PacketSource, QueueDrop,
    RouteError, RouteKind, RouteRequest, RouteSession, TokenCancellation, Usage, UsageMetadata,
    UsageSession,
};
use crate::web::admin::{
    ClientAccess as WebClientAccess, ClientEnrollment as WebClientEnrollment,
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
    usage: Option<Arc<usage::Store>>,
}

impl NativeAuthenticator {
    pub fn new(registry: Arc<StateRegistry>, abuse: Arc<AbuseGuard>) -> Arc<Self> {
        Arc::new(Self {
            registry,
            abuse,
            usage: None,
        })
    }

    /// Also reports quota usage from `usage` to connecting clients.
    pub fn with_usage(
        registry: Arc<StateRegistry>,
        abuse: Arc<AbuseGuard>,
        usage: Arc<usage::Store>,
    ) -> Arc<Self> {
        Arc::new(Self {
            registry,
            abuse,
            usage: Some(usage),
        })
    }
}

/// Snapshot of an account's limits for the client's information.
pub fn account_status(
    registry: &StateRegistry,
    usage: Option<&usage::Store>,
    account_id: &str,
) -> AccountStatus {
    let Some(policy) = registry.account_policy(account_id) else {
        return AccountStatus::default();
    };
    let quota_used_bytes = policy
        .limits
        .monthly_quota_bytes
        .and(policy.usage_period.as_ref())
        .zip(usage)
        .map(|(period, usage)| {
            account_usage_bytes(&usage.snapshot(), account_id).saturating_sub(period.baseline_bytes)
        });
    AccountStatus {
        expires_at: policy
            .limits
            .expires_at
            .map(|expires_at| expires_at.unix_timestamp()),
        quota_bytes: policy.limits.monthly_quota_bytes,
        quota_used_bytes,
        rate_limit_kbps: policy.limits.rate_limit_kbps,
    }
}

impl Authenticator for NativeAuthenticator {
    fn authenticate(
        &self,
        request: AuthenticationRequest,
    ) -> BoxFuture<'static, Result<Authenticated, AuthenticationError>> {
        let registry = self.registry.clone();
        let abuse = self.abuse.clone();
        let usage = self.usage.clone();
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
            let status_registry = registry.clone();
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
                StateRegistryError::DevicePending => {
                    AuthenticationError::Forbidden(DenialReason::DevicePending)
                }
                StateRegistryError::EnrollmentClosed => {
                    AuthenticationError::Forbidden(DenialReason::EnrollmentClosed)
                }
                StateRegistryError::DeviceDenied => {
                    AuthenticationError::Forbidden(DenialReason::DeviceDenied)
                }
                // A client with several gateways moves on to the primary.
                StateRegistryError::EnrollOnPrimary => AuthenticationError::Unavailable(
                    "new devices enroll on the primary gateway first",
                ),
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
            let account = account_status(
                &status_registry,
                usage.as_deref(),
                &session.identity.account_id,
            );
            let network = network_policy(
                &status_registry,
                &session.identity.account_id,
                &session.device_id,
            );
            Ok(Authenticated {
                account,
                network,
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

/// The network rules of one device's tunnel.
pub fn network_policy(
    registry: &StateRegistry,
    account_id: &str,
    device_id: &str,
) -> NetworkPolicy {
    let device = registry.device_network(account_id, device_id);
    NetworkPolicy {
        allow: device.access.allow,
        deny: device.access.deny,
        group: device.access.group,
        exit: device.access.exit,
        subnets: device.subnets,
        published: registry
            .routed_subnets()
            .into_iter()
            .filter(|routed| routed.account_id != account_id || routed.device_id != device_id)
            .map(|routed| routed.subnet)
            .collect(),
    }
}

/// Current device names for the resolver.
pub trait NameSource: Send + Sync {
    /// Names relative to the resolver zone, by account and device ID.
    fn names(&self) -> HashMap<(String, String), String>;
}

impl NameSource for StateRegistry {
    fn names(&self) -> HashMap<(String, String), String> {
        self.dns_names()
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
    network: GatewayNetwork,
}

/// Gateway facts that access policies and subnet routes are checked against.
#[derive(Clone, Debug, Default)]
pub struct GatewayNetwork {
    /// Exit names an account may select.
    pub exits: Vec<String>,
    /// Networks no device may route, such as the client pool.
    pub reserved: Vec<ipnet::Ipv4Net>,
}

impl WebRegistryAdapter {
    pub fn new(registry: Arc<StateRegistry>, usage: Arc<usage::Store>) -> Arc<Self> {
        Self::with_network(registry, usage, GatewayNetwork::default())
    }

    pub fn with_network(
        registry: Arc<StateRegistry>,
        usage: Arc<usage::Store>,
        network: GatewayNetwork,
    ) -> Arc<Self> {
        Arc::new(Self {
            registry,
            usage,
            network,
        })
    }

    fn summary(&self, id: &str) -> Result<WebClientSummary, WebRegistryError> {
        let snapshot = self.usage.snapshot();
        let names = self.registry.dns_names();
        self.registry
            .list_with_usage(&snapshot)
            .into_iter()
            .find(|client| client.id == id)
            .map(|summary| web_client_summary(summary, &names))
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
        let names = self.registry.dns_names();
        Ok(self
            .registry
            .list_with_usage(&snapshot)
            .into_iter()
            .map(|summary| web_client_summary(summary, &names))
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
                let created = registry.create(name, max_devices).await;
                let names = registry.dns_names();
                created
                    .map(|(summary, token)| (web_client_summary(summary, &names), token))
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
                let updated = registry.update(&id, name, max_devices, enabled).await;
                let names = registry.dns_names();
                updated
                    .map(|summary| web_client_summary(summary, &names))
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

    fn set_client_enrollment<'a>(
        &'a self,
        id: &'a str,
        enrollment: WebClientEnrollment,
    ) -> BoxFuture<'a, Result<WebClientSummary, WebRegistryError>> {
        let registry = self.registry.clone();
        let owned_id = id.to_owned();
        Box::pin(async move {
            let policy = match enrollment.policy.as_str() {
                "open" => EnrollmentPolicy::Open,
                "approval" => EnrollmentPolicy::Approval,
                "closed" => EnrollmentPolicy::Closed,
                _ => {
                    return Err(WebRegistryError::Invalid(
                        "policy must be open, approval, or closed".into(),
                    ))
                }
            };
            let window = enrollment
                .open_for_minutes
                .map(|minutes| std::time::Duration::from_secs(u64::from(minutes) * 60));
            join_web_mutation(tokio::spawn(async move {
                registry
                    .set_enrollment(&owned_id, policy, window)
                    .await
                    .map(|_| ())
                    .map_err(web_registry_error)
            }))
            .await?;
            self.summary(id)
        })
    }

    fn set_client_access<'a>(
        &'a self,
        id: &'a str,
        access: WebClientAccess,
    ) -> BoxFuture<'a, Result<WebClientSummary, WebRegistryError>> {
        let registry = self.registry.clone();
        let owned_id = id.to_owned();
        let exits = self.network.exits.clone();
        Box::pin(async move {
            let access = AccessPolicy {
                allow: parse_prefixes(&access.allow)?,
                deny: parse_prefixes(&access.deny)?,
                group: access.group,
                exit: access.exit,
            };
            join_web_mutation(tokio::spawn(async move {
                registry
                    .set_access(&owned_id, access, &exits)
                    .await
                    .map(|_| ())
                    .map_err(web_registry_error)
            }))
            .await?;
            self.summary(id)
        })
    }

    fn set_device_subnets<'a>(
        &'a self,
        id: &'a str,
        device_id: &'a str,
        subnets: Vec<String>,
    ) -> BoxFuture<'a, Result<WebClientSummary, WebRegistryError>> {
        let registry = self.registry.clone();
        let owned_id = id.to_owned();
        let owned_device = device_id.to_owned();
        let reserved = self.network.reserved.clone();
        Box::pin(async move {
            let subnets = parse_prefixes(&subnets)?;
            join_web_mutation(tokio::spawn(async move {
                registry
                    .set_device_subnets(&owned_id, &owned_device, subnets, &reserved)
                    .await
                    .map(|_| ())
                    .map_err(web_registry_error)
            }))
            .await?;
            self.summary(id)
        })
    }

    fn review_device<'a>(
        &'a self,
        id: &'a str,
        device_id: &'a str,
        approve: bool,
    ) -> BoxFuture<'a, Result<WebClientSummary, WebRegistryError>> {
        let registry = self.registry.clone();
        let owned_id = id.to_owned();
        let device_id = device_id.to_owned();
        Box::pin(async move {
            join_web_mutation(tokio::spawn(async move {
                let result = if approve {
                    registry.approve_device(&owned_id, &device_id).await
                } else {
                    registry.deny_device(&owned_id, &device_id).await
                };
                result.map(|_| ()).map_err(web_registry_error)
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
        StateRegistryError::EnrollmentClosed | StateRegistryError::ReadOnly => {
            WebRegistryError::Invalid(error.to_string())
        }
        StateRegistryError::InvalidInput(message) => WebRegistryError::Invalid(message),
        error => {
            tracing::error!(%error, "client registry operation failed");
            WebRegistryError::Internal
        }
    }
}

fn parse_prefixes(values: &[String]) -> Result<Vec<ipnet::Ipv4Net>, WebRegistryError> {
    values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse::<ipnet::Ipv4Net>()
                .or_else(|_| value.parse::<Ipv4Addr>().map(ipnet::Ipv4Net::from))
                .map_err(|_| WebRegistryError::Invalid(format!("{value:?} is not an IPv4 prefix")))
        })
        .collect()
}

fn web_client_summary(
    summary: crate::state::registry::ClientSummary,
    names: &HashMap<(String, String), String>,
) -> WebClientSummary {
    let account_id = summary.id.clone();
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
        enrollment: summary.enrollment.to_owned(),
        enrollment_open_until: summary.enrollment_open_until.map(format_time),
        pending_devices: summary.pending_devices,
        access: WebClientAccess {
            allow: summary
                .access
                .allow
                .iter()
                .map(ToString::to_string)
                .collect(),
            deny: summary
                .access
                .deny
                .iter()
                .map(ToString::to_string)
                .collect(),
            group: summary.access.group,
            exit: summary.access.exit,
        },
        devices: summary
            .devices
            .into_iter()
            .map(|device| WebDeviceSummary {
                dns_name: names
                    .get(&(account_id.clone(), device.id.clone()))
                    .map(|name| format!("{name}.{}", crate::dns::ZONE))
                    .unwrap_or_default(),
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
                status: device.status.to_owned(),
                transport: device.transport,
                assigned_address: device.assigned_address,
                target: device.target,
                subnets: device.subnets.iter().map(ToString::to_string).collect(),
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
    /// Account and network policy of each live session, by lease.
    contexts: Arc<parking_lot::RwLock<HashMap<Ipv4Addr, Arc<RouteContext>>>>,
    switching: SwitchConfig,
}

/// Gateway-wide rules for traffic between clients.
#[derive(Clone, Debug, Default)]
pub struct SwitchConfig {
    /// Every client may reach every other client, as if in one group.
    pub client_to_client: bool,
    /// Destinations that access policies never block, such as the gateway
    /// address and its DNS server.
    pub always_reachable: Vec<Ipv4Addr>,
    /// Policy routing for accounts that select an exit.
    pub exits: Option<Arc<ExitRules>>,
    /// Device names for the built-in resolver.
    pub names: Option<Arc<dyn NameSource>>,
}

impl std::fmt::Debug for dyn NameSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NameSource")
    }
}

struct RouteContext {
    account_id: String,
    device_id: String,
    network: NetworkPolicy,
}

/// What happens to a packet a client sent.
#[derive(Debug, Eq, PartialEq)]
enum Verdict {
    /// Continue through the TUN device to the kernel: the exit or the
    /// gateway host.
    Kernel,
    /// Switch directly to the live session at this lease address.
    Deliver(Ipv4Addr),
    Drop(DropReason),
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
        Self::with_switching(router, leases, limiters, SwitchConfig::default())
    }

    pub fn with_switching(
        router: Arc<Router>,
        leases: Arc<PoolAdapter>,
        limiters: Arc<RateLimiters>,
        switching: SwitchConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            router,
            leases,
            limiters,
            uplink: Arc::default(),
            contexts: Arc::default(),
            switching,
        })
    }

    /// Whether two sessions' devices may exchange traffic.
    fn peers(&self, sender: &RouteContext, receiver: &RouteContext) -> bool {
        self.switching.client_to_client
            || sender.account_id == receiver.account_id
            || (sender.network.group.is_some() && sender.network.group == receiver.network.group)
    }

    /// Whether `querier` may learn about the device at `address`.
    fn visible(
        &self,
        querier: Ipv4Addr,
        asker: &RouteContext,
        address: Ipv4Addr,
        target: &RouteContext,
    ) -> bool {
        self.peers(asker, target)
            && asker.network.permits(address)
            && target.network.permits(querier)
    }

    /// Applies source validation, access policy and client-to-client rules
    /// to a packet from the session at `lease`.
    fn classify(&self, lease: Ipv4Addr, packet: &[u8]) -> Result<Verdict, RouterError> {
        let info = porta_wire::ip::parse_ipv4(packet)
            .map_err(|_| RouterError::InvalidPacket("client packet"))?;
        let (source, destination) = (info.source, info.destination);
        let contexts = self.contexts.read();
        let sender = contexts.get(&lease);
        let from_subnet = source != lease;
        if from_subnet && !sender.is_some_and(|sender| sender.network.routes_subnet(source)) {
            return Err(RouterError::SourceSpoofed {
                got: source,
                expected: lease,
            });
        }
        if let Some(target) = self.router.owner(destination) {
            if target == lease {
                return Ok(Verdict::Drop(DropReason::PolicyDenied));
            }
            let receiver = contexts.get(&target);
            let peers = self.switching.client_to_client
                || match (sender, receiver) {
                    (Some(sender), Some(receiver)) => self.peers(sender, receiver),
                    _ => false,
                };
            let permitted = sender.is_none_or(|sender| sender.network.permits(destination))
                && receiver.is_none_or(|receiver| receiver.network.permits(source));
            return Ok(if peers && permitted {
                Verdict::Deliver(target)
            } else {
                Verdict::Drop(DropReason::PolicyDenied)
            });
        }
        // Hosts behind a subnet router only exchange traffic with clients.
        if from_subnet {
            return Ok(Verdict::Drop(DropReason::PolicyDenied));
        }
        if self.switching.always_reachable.contains(&destination)
            || sender.is_none_or(|sender| sender.network.permits(destination))
        {
            Ok(Verdict::Kernel)
        } else {
            Ok(Verdict::Drop(DropReason::PolicyDenied))
        }
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
    context: Arc<RouteContext>,
    contexts: Arc<parking_lot::RwLock<HashMap<Ipv4Addr, Arc<RouteContext>>>>,
    /// The exit rule this session installed, released when it closes.
    exit: Option<(Arc<ExitRules>, u64)>,
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
        let mut contexts = self.contexts.write();
        if contexts
            .get(&self.address)
            .is_some_and(|context| Arc::ptr_eq(context, &self.context))
        {
            contexts.remove(&self.address);
        }
        drop(contexts);
        if let Some((exits, generation)) = &self.exit {
            exits.release(self.address, *generation);
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
        let contexts = self.contexts.clone();
        let exits = self.switching.exits.clone();
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
            // The exit rule is in place before the client can send.
            let exit = match (&request.network.exit, exits) {
                (None, _) => None,
                (Some(exit), Some(exits)) => match exits.assign(address, exit).await {
                    Ok(generation) => Some((exits, generation)),
                    Err(error) => {
                        tracing::warn!(%error, %address, "refusing a tunnel whose exit is unavailable");
                        session.close();
                        return Err(RouteError::Unavailable);
                    }
                },
                (Some(exit), None) => {
                    tracing::warn!(exit, %address, "refusing a tunnel for an exit this gateway does not offer");
                    session.close();
                    return Err(RouteError::Unavailable);
                }
            };
            uplink.write().insert(address, limiter.clone());
            let context = Arc::new(RouteContext {
                account_id: request.account_id,
                device_id: request.device_id,
                network: request.network,
            });
            contexts.write().insert(address, context.clone());
            router.set_subnets(address, &context.network.subnets);
            let handle = Arc::new(RouteHandle {
                session,
                address,
                limiter,
                limiters,
                uplink,
                context,
                contexts,
                exit,
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
        let verdict = self.classify(lease, &packet);
        Box::pin(async move {
            if !allowed {
                return Ok(());
            }
            match verdict.map_err(map_route_error)? {
                Verdict::Kernel => router
                    .inject_validated(&cancellation, &packet)
                    .await
                    .map_err(map_route_error),
                Verdict::Deliver(target) => {
                    match forwarded(&packet) {
                        Some(packet) => {
                            router.deliver(target, packet);
                        }
                        None => router.record_policy_drop(DropReason::TtlExpired),
                    }
                    Ok(())
                }
                Verdict::Drop(reason) => {
                    router.record_policy_drop(reason);
                    Ok(())
                }
            }
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

impl crate::dns::Directory for RouterAdapter {
    fn is_client(&self, address: Ipv4Addr) -> bool {
        self.contexts.read().contains_key(&address)
    }

    fn resolve(&self, querier: Ipv4Addr, name: &str) -> Option<Ipv4Addr> {
        let names = self.switching.names.as_ref()?.names();
        let contexts = self.contexts.read();
        let asker = contexts.get(&querier)?;
        contexts
            .iter()
            .filter(|(_, target)| {
                names
                    .get(&(target.account_id.clone(), target.device_id.clone()))
                    .is_some_and(|candidate| candidate == name)
            })
            .find(|(address, target)| self.visible(querier, asker, **address, target))
            .map(|(address, _)| *address)
    }

    fn reverse(&self, querier: Ipv4Addr, address: Ipv4Addr) -> Option<String> {
        let names = self.switching.names.as_ref()?.names();
        let contexts = self.contexts.read();
        let asker = contexts.get(&querier)?;
        let target = contexts.get(&address)?;
        if !self.visible(querier, asker, address, target) {
            return None;
        }
        names
            .get(&(target.account_id.clone(), target.device_id.clone()))
            .cloned()
    }
}

/// A copy of `packet` with its TTL decremented, as a router forwards it, or
/// `None` once the TTL is exhausted.
fn forwarded(packet: &[u8]) -> Option<Bytes> {
    let ttl = *packet.get(8)?;
    if ttl <= 1 {
        return None;
    }
    let mut packet = packet.to_vec();
    packet[8] = ttl - 1;
    porta_wire::ip::set_ipv4_header_checksum(&mut packet).ok()?;
    Some(Bytes::from(packet))
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
    audit: Option<Arc<crate::ops::audit::AuditLog>>,
}

impl UsageAdapter {
    pub fn new(store: Arc<usage::Store>) -> Arc<Self> {
        Self::with_audit(store, None)
    }

    /// Also records tunnel connections and disconnections in `audit`.
    pub fn with_audit(
        store: Arc<usage::Store>,
        audit: Option<Arc<crate::ops::audit::AuditLog>>,
    ) -> Arc<Self> {
        Arc::new(Self { store, audit })
    }
}

struct UsageHandle {
    session: usage::Session,
    audit: Option<(Arc<crate::ops::audit::AuditLog>, UsageMetadata)>,
    uploaded: AtomicU64,
    downloaded: AtomicU64,
}

fn tunnel_event(metadata: &UsageMetadata, action: &str) -> crate::ops::audit::AuditEvent {
    crate::ops::audit::AuditEvent::new(
        crate::ops::audit::Actor {
            kind: "client",
            id: metadata.account_id.clone(),
            name: String::new(),
        },
        action,
        metadata.device_id.clone(),
    )
    .address(Some(metadata.address))
}

impl UsageSession for UsageHandle {
    fn uploaded(&self, bytes: u64, packets: u64) {
        self.uploaded.fetch_add(bytes, Ordering::Relaxed);
        self.session.add_uploaded(bytes, packets);
    }

    fn downloaded(&self, bytes: u64, packets: u64) {
        self.downloaded.fetch_add(bytes, Ordering::Relaxed);
        self.session.add_downloaded(bytes, packets);
    }

    fn close(&self) {
        self.session.close();
        if let Some((audit, metadata)) = &self.audit {
            audit.record(
                tunnel_event(metadata, "tunnel.disconnect").detail(serde_json::json!({
                    "transport": metadata.transport,
                    "uploaded_bytes": self.uploaded.load(Ordering::Relaxed),
                    "downloaded_bytes": self.downloaded.load(Ordering::Relaxed),
                })),
            );
        }
    }
}

impl Usage for UsageAdapter {
    fn begin(&self, metadata: UsageMetadata) -> Arc<dyn UsageSession> {
        let audit = self.audit.clone().map(|audit| {
            audit.record(
                tunnel_event(&metadata, "tunnel.connect")
                    .detail(serde_json::json!({ "transport": metadata.transport })),
            );
            (audit, metadata.clone())
        });
        Arc::new(UsageHandle {
            audit,
            uploaded: AtomicU64::new(0),
            downloaded: AtomicU64::new(0),
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
                device_id: "device".into(),
                network: Default::default(),
            })
            .await;
        assert!(matches!(stale, Err(RouteError::Conflict)));

        let route = router
            .register(RouteRequest {
                lease: current.clone(),
                kind: RouteKind::ConnectIp,
                parent: CancellationToken::new(),
                account_id: "account".into(),
                device_id: "device".into(),
                network: Default::default(),
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

    fn addressed_packet(source: Ipv4Addr, destination: Ipv4Addr) -> Bytes {
        let mut packet = ipv4_packet(source).to_vec();
        packet[16..20].copy_from_slice(&destination.octets());
        porta_wire::ip::set_ipv4_header_checksum(&mut packet).unwrap();
        Bytes::from(packet)
    }

    fn context(account_id: &str, network: NetworkPolicy) -> Arc<RouteContext> {
        Arc::new(RouteContext {
            account_id: account_id.into(),
            device_id: format!("{account_id}-device"),
            network,
        })
    }

    #[tokio::test]
    async fn switching_enforces_sources_peers_and_access_policy() {
        let a: Ipv4Addr = "10.66.0.2".parse().unwrap();
        let b: Ipv4Addr = "10.66.0.3".parse().unwrap();
        let c: Ipv4Addr = "10.66.0.4".parse().unwrap();
        let lan: Ipv4Addr = "10.30.0.5".parse().unwrap();
        let internet: Ipv4Addr = "1.1.1.1".parse().unwrap();
        let gateway: Ipv4Addr = "10.66.0.1".parse().unwrap();
        let subnet: ipnet::Ipv4Net = "10.30.0.0/24".parse().unwrap();
        let build = |client_to_client| {
            let router = Arc::new(Router::new(Arc::new(MemoryDevice::default()), None));
            let pool = Arc::new(Pool::new("10.66.0.0/24").unwrap());
            let adapter = RouterAdapter::with_switching(
                router.clone(),
                PoolAdapter::new(pool),
                RateLimiters::new(),
                SwitchConfig {
                    client_to_client,
                    always_reachable: vec![gateway],
                    exits: None,
                    names: None,
                },
            );
            (router, adapter)
        };
        let parent = CancellationToken::new();
        let (router, adapter) = build(false);
        let _sessions = [a, b, c].map(|address| router.register(&parent, address));
        router.set_subnets(b, &[subnet]);
        let set = |address, account, network| {
            adapter
                .contexts
                .write()
                .insert(address, context(account, network));
        };
        let router_b = NetworkPolicy {
            subnets: vec![subnet],
            ..NetworkPolicy::default()
        };
        set(a, "alpha", NetworkPolicy::default());
        set(b, "beta", router_b.clone());
        set(c, "alpha", NetworkPolicy::default());
        let verdict = |from, source, destination| {
            adapter.classify(from, &addressed_packet(source, destination))
        };

        assert_eq!(verdict(a, a, internet).unwrap(), Verdict::Kernel);
        // Devices of one account reach each other; other accounts do not.
        assert_eq!(verdict(a, a, c).unwrap(), Verdict::Deliver(c));
        assert_eq!(
            verdict(a, a, b).unwrap(),
            Verdict::Drop(DropReason::PolicyDenied)
        );
        assert_eq!(
            verdict(a, a, lan).unwrap(),
            Verdict::Drop(DropReason::PolicyDenied)
        );
        // Only the subnet router may send from its subnet, and only to clients.
        assert!(matches!(
            verdict(a, lan, internet),
            Err(RouterError::SourceSpoofed { .. })
        ));
        assert_eq!(
            verdict(b, lan, internet).unwrap(),
            Verdict::Drop(DropReason::PolicyDenied)
        );

        // A shared group makes the accounts peers, including the subnet.
        let team = Some("team".to_owned());
        set(
            a,
            "alpha",
            NetworkPolicy {
                group: team.clone(),
                ..NetworkPolicy::default()
            },
        );
        set(
            b,
            "beta",
            NetworkPolicy {
                group: team.clone(),
                ..router_b.clone()
            },
        );
        assert_eq!(verdict(a, a, b).unwrap(), Verdict::Deliver(b));
        assert_eq!(verdict(a, a, lan).unwrap(), Verdict::Deliver(b));
        assert_eq!(verdict(b, lan, a).unwrap(), Verdict::Deliver(a));

        // Deny lists win over peering, in both directions.
        set(
            a,
            "alpha",
            NetworkPolicy {
                group: team.clone(),
                deny: vec![subnet],
                ..NetworkPolicy::default()
            },
        );
        assert_eq!(
            verdict(a, a, lan).unwrap(),
            Verdict::Drop(DropReason::PolicyDenied)
        );
        assert_eq!(
            verdict(b, lan, a).unwrap(),
            Verdict::Drop(DropReason::PolicyDenied)
        );

        // An allow list confines the exit but keeps the gateway reachable.
        set(
            a,
            "alpha",
            NetworkPolicy {
                allow: vec![subnet],
                ..NetworkPolicy::default()
            },
        );
        assert_eq!(
            verdict(a, a, internet).unwrap(),
            Verdict::Drop(DropReason::PolicyDenied)
        );
        assert_eq!(verdict(a, a, gateway).unwrap(), Verdict::Kernel);

        // --client-to-client makes every client a peer.
        let (router, adapter) = build(true);
        let _sessions = [a, b].map(|address| router.register(&parent, address));
        adapter
            .contexts
            .write()
            .insert(a, context("alpha", NetworkPolicy::default()));
        adapter
            .contexts
            .write()
            .insert(b, context("beta", NetworkPolicy::default()));
        assert_eq!(
            adapter.classify(a, &addressed_packet(a, b)).unwrap(),
            Verdict::Deliver(b)
        );
    }

    #[tokio::test]
    async fn switched_packets_reach_the_peer_with_a_decremented_ttl() {
        let pool = Arc::new(Pool::new("10.66.0.0/24").unwrap());
        let leases = PoolAdapter::new(pool);
        let mut routes = Vec::new();
        for name in ["first", "second"] {
            let lease = leases
                .acquire(LeaseRequest {
                    lease_id: name.into(),
                    group_id: None,
                    mode: LeaseMode::Exclusive,
                })
                .await
                .unwrap();
            routes.push(lease);
        }
        let device = Arc::new(MemoryDevice::default());
        let adapter = RouterAdapter::new(Arc::new(Router::new(device.clone(), None)), leases);
        let mut sessions = Vec::new();
        for lease in &routes {
            sessions.push(
                adapter
                    .register(RouteRequest {
                        lease: lease.clone(),
                        kind: RouteKind::ConnectIp,
                        parent: CancellationToken::new(),
                        account_id: "account".into(),
                        device_id: "device".into(),
                        network: NetworkPolicy::default(),
                    })
                    .await
                    .unwrap(),
            );
        }
        let (first, second) = (routes[0].address, routes[1].address);
        adapter
            .inject_from_client(
                sessions[0].cancellation.clone(),
                first,
                addressed_packet(first, second),
            )
            .await
            .unwrap();
        let switched = sessions[1].downlink.try_packet().unwrap();
        assert_eq!(switched[8], 63);
        assert!(porta_wire::ip::parse_ipv4(&switched).is_ok());
        assert!(device.writes.lock().is_empty());
        assert!(forwarded(&addressed_packet(first, second)[..]).is_some());
        let mut expiring = addressed_packet(first, second).to_vec();
        expiring[8] = 1;
        assert!(forwarded(&expiring).is_none());

        // A closed session's context and subnets disappear with it.
        sessions[1].cleanup.close();
        assert!(!adapter.contexts.read().contains_key(&second));
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
    async fn connecting_clients_receive_their_account_status() {
        let (_directory, registry, usage, _limiters, id) = policy_fixture().await;
        assert_eq!(
            account_status(&registry, Some(&usage), &id),
            AccountStatus::default()
        );
        let expires = time::macros::datetime!(2031-03-15 23:59:59 UTC);
        registry
            .set_limits(
                &id,
                AccountLimits {
                    expires_at: Some(expires),
                    monthly_quota_bytes: Some(10_000),
                    rate_limit_kbps: Some(5_000),
                },
            )
            .await
            .unwrap();
        // Usage is unknown until the enforcer starts the quota period.
        assert_eq!(
            account_status(&registry, Some(&usage), &id).quota_used_bytes,
            None
        );
        let session = usage.begin("s", &id, "device", "h3", "10.66.0.2", "");
        session.add_uploaded(1_500, 1);
        registry
            .set_usage_period(
                &id,
                UsagePeriod {
                    month: "2031-03".into(),
                    baseline_bytes: 500,
                },
            )
            .await
            .unwrap();
        let status = account_status(&registry, Some(&usage), &id);
        assert_eq!(status.expires_at, Some(expires.unix_timestamp()));
        assert_eq!(status.quota_bytes, Some(10_000));
        assert_eq!(status.quota_used_bytes, Some(1_000));
        assert_eq!(status.rate_limit_kbps, Some(5_000));

        let mut headers = http::HeaderMap::new();
        crate::transport::session::set_account_headers(&mut headers, &status);
        assert_eq!(
            headers["x-porta-account-expires"],
            expires.unix_timestamp().to_string()
        );
        assert_eq!(headers["x-porta-quota-used-bytes"], "1000");
        let mut headers = http::HeaderMap::new();
        crate::transport::session::set_account_headers(&mut headers, &AccountStatus::default());
        assert!(headers.is_empty());
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
                None,
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
            let response = admin.handle(&put(invalid), None).await.unwrap();
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
        let response = admin.handle(&reset, None).await.unwrap();
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
                device_id: "device".into(),
                network: Default::default(),
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
