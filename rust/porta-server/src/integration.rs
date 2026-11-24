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
use crate::state::pool::{Ipv6Pool, Lease as PoolLease, Pool, PoolError};
use crate::state::registry::{
    AccessPolicy, AccountLimits, ClientRegistry as StateRegistry, EnrollmentPolicy,
    RegistryError as StateRegistryError, UsagePeriod,
};
use crate::state::sessions::SessionGuard;
use crate::state::usage;
use crate::transport::session::{
    AccountStatus, Authenticated, AuthenticationError, AuthenticationRequest, Authenticator,
    Cleanup, ClientIdentity as TransportIdentity, DenialReason, Ipv6Lease, Lease, LeaseAllocator,
    LeaseError, LeaseMode, LeaseRequest, Metrics, NetworkPolicy, PacketRouter, PacketSource,
    QueueDrop, RouteError, RouteKind, RouteRequest, RouteSession, TokenCancellation, Usage,
    UsageMetadata, UsageSession,
};
use crate::web::admin::{
    ClientAccess as WebClientAccess, ClientEnrollment as WebClientEnrollment,
    ClientIdentity as WebIdentity, ClientLimits as WebClientLimits, ClientRegistry as WebRegistry,
    ClientSummary as WebClientSummary, DeviceSummary as WebDeviceSummary,
    RegistryError as WebRegistryError,
};
use crate::wire::device_auth;
use crate::wire::peer::{Fingerprint, Peer, MAX_PEERS};
use bytes::Bytes;
use futures_util::future::BoxFuture;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
                if request.standard {
                    registry
                        .authenticate_standard_session(&request.bearer_token)
                        .await
                } else {
                    registry
                        .authenticate_device_session(
                            &request.bearer_token,
                            &proof,
                            request.method.as_str(),
                            &request.path,
                        )
                        .await
                }
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
                StateRegistryError::StandardClientsDisabled => {
                    AuthenticationError::Forbidden(DenialReason::StandardClientsDisabled)
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
            let standard_clients = enrollment.standard_clients;
            join_web_mutation(tokio::spawn(async move {
                registry
                    .set_enrollment(&owned_id, policy, window)
                    .await
                    .map_err(web_registry_error)?;
                if let Some(allowed) = standard_clients {
                    registry
                        .set_standard_clients(&owned_id, allowed)
                        .await
                        .map_err(web_registry_error)?;
                }
                Ok(())
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
                allow: parse_access_prefixes(&access.allow)?,
                deny: parse_access_prefixes(&access.deny)?,
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

/// Parses IPv4 or IPv6 prefixes, or bare addresses as host prefixes.
fn parse_access_prefixes(values: &[String]) -> Result<Vec<ipnet::IpNet>, WebRegistryError> {
    values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse::<ipnet::IpNet>()
                .or_else(|_| value.parse::<IpAddr>().map(ipnet::IpNet::from))
                .map_err(|_| WebRegistryError::Invalid(format!("{value:?} is not an IP prefix")))
        })
        .collect()
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
        standard_clients: summary.standard_clients,
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
    ipv6: Option<Ipv6Pool>,
    next_id: Arc<AtomicU64>,
    active: Arc<Mutex<HashMap<u64, PoolLease>>>,
}

impl PoolAdapter {
    pub fn new(pool: Arc<Pool>) -> Arc<Self> {
        Self::with_ipv6(pool, None)
    }

    /// Dual-stack leases: each also carries the paired address in `ipv6`.
    pub fn with_ipv6(pool: Arc<Pool>, ipv6: Option<Ipv6Pool>) -> Arc<Self> {
        Arc::new(Self {
            pool,
            ipv6,
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
            ipv6: self.ipv6.and_then(|ipv6| {
                Some(Ipv6Lease {
                    address: ipv6.address(lease.address)?,
                    prefix_len: ipv6.prefix().prefix_len(),
                    gateway: ipv6.gateway(),
                })
            }),
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
    peers: Arc<PeerDirectory>,
    switching: SwitchConfig,
}

/// Gateway-wide rules for traffic between clients.
#[derive(Clone, Debug, Default)]
pub struct SwitchConfig {
    /// Every client may reach every other client, as if in one group.
    pub client_to_client: bool,
    /// Devices learn each other's public addresses to connect directly.
    pub peer_to_peer: bool,
    /// Destinations that access policies never block, such as the gateway
    /// addresses and its DNS server.
    pub always_reachable: Vec<IpAddr>,
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
    /// The session's IPv6 address, when it has one.
    ipv6: Option<std::net::Ipv6Addr>,
}

/// Whether two sessions' devices may exchange traffic.
fn may_peer(client_to_client: bool, first: &RouteContext, second: &RouteContext) -> bool {
    client_to_client
        || first.account_id == second.account_id
        || (first.network.group.is_some() && first.network.group == second.network.group)
}

/// Sessions published for direct paths, and the peer list each receives.
///
/// A change to one device only rewrites the lists of devices that may peer
/// with it, and inside the runtime rewrites are coalesced, so a gateway
/// restart that reconnects every device costs a few passes, not one per
/// device.
#[derive(Default)]
struct PeerDirectory {
    client_to_client: bool,
    state: Mutex<PeerState>,
    publisher: std::sync::OnceLock<Arc<tokio::sync::Notify>>,
}

#[derive(Default)]
struct PeerState {
    announced: std::collections::BTreeMap<Ipv4Addr, Announced>,
    by_account: HashMap<String, std::collections::BTreeSet<Ipv4Addr>>,
    by_group: HashMap<String, std::collections::BTreeSet<Ipv4Addr>>,
    /// Which session published each certificate fingerprint.
    fingerprints: HashMap<Fingerprint, Ipv4Addr>,
    /// Sessions whose lists may be stale; `all_dirty` covers every one.
    dirty: std::collections::HashSet<Ipv4Addr>,
    all_dirty: bool,
}

struct Announced {
    context: Arc<RouteContext>,
    endpoint: SocketAddr,
    fingerprint: Fingerprint,
    updates: tokio::sync::watch::Sender<Vec<Peer>>,
}

/// How long changes collect before peer lists are rewritten.
const PEER_PUBLISH_DELAY: std::time::Duration = std::time::Duration::from_millis(100);

impl PeerDirectory {
    fn announce(
        self: &Arc<Self>,
        lease: Ipv4Addr,
        context: Arc<RouteContext>,
        endpoint: SocketAddr,
        fingerprint: Fingerprint,
    ) -> Option<tokio::sync::watch::Receiver<Vec<Peer>>> {
        let mut state = self.state.lock();
        // Fingerprints are visible to peers; a device offering another's
        // would displace that device in its peers' lists.
        if state
            .fingerprints
            .get(&fingerprint)
            .is_some_and(|owner| *owner != lease)
        {
            return None;
        }
        // A reconnect may change the account or group, and with it the
        // devices whose lists hold this one.
        if let Some(previous) = state.announced.remove(&lease) {
            self.mark_peers_of(&mut state, lease, &previous.context);
            state.unindex(lease, &previous.context);
            state.fingerprints.remove(&previous.fingerprint);
        }
        state.fingerprints.insert(fingerprint, lease);
        state.index(lease, &context);
        // The new session gets its list at once; its peers' lists follow.
        let entry = Announced {
            context,
            endpoint: SocketAddr::new(endpoint.ip().to_canonical(), endpoint.port()),
            fingerprint,
            updates: tokio::sync::watch::channel(Vec::new()).0,
        };
        let own = state.list_for(self.client_to_client, lease, &entry);
        entry.updates.send_replace(own);
        let receiver = entry.updates.subscribe();
        state.announced.insert(lease, entry);
        let context = state.announced[&lease].context.clone();
        self.mark_peers_of(&mut state, lease, &context);
        state.dirty.remove(&lease);
        drop(state);
        self.schedule();
        Some(receiver)
    }

    /// Removes the session at `lease` if `context` is still its session.
    fn withdraw(self: &Arc<Self>, lease: Ipv4Addr, context: &Arc<RouteContext>) {
        let mut state = self.state.lock();
        if !state
            .announced
            .get(&lease)
            .is_some_and(|entry| Arc::ptr_eq(&entry.context, context))
        {
            return;
        }
        if let Some(entry) = state.announced.remove(&lease) {
            state.fingerprints.remove(&entry.fingerprint);
        }
        state.unindex(lease, context);
        self.mark_peers_of(&mut state, lease, context);
        state.dirty.remove(&lease);
        drop(state);
        self.schedule();
    }

    /// Marks the lists that may include the device at `lease`.
    fn mark_peers_of(&self, state: &mut PeerState, lease: Ipv4Addr, context: &RouteContext) {
        if self.client_to_client {
            state.all_dirty = true;
            return;
        }
        let candidates = state.candidates(false, context).collect::<Vec<_>>();
        state.dirty.extend(candidates);
        state.dirty.insert(lease);
    }

    /// Rewrites stale lists now, or soon when running inside the runtime.
    fn schedule(self: &Arc<Self>) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            self.publish();
            return;
        };
        let publisher = self.publisher.get_or_init(|| {
            let notify = Arc::new(tokio::sync::Notify::new());
            let directory = Arc::downgrade(self);
            let wake = notify.clone();
            runtime.spawn(async move {
                loop {
                    wake.notified().await;
                    tokio::time::sleep(PEER_PUBLISH_DELAY).await;
                    let Some(directory) = directory.upgrade() else {
                        return;
                    };
                    directory.publish();
                }
            });
            notify
        });
        publisher.notify_one();
    }

    /// Sends every stale session the devices it and they may both reach:
    /// the same rules as traffic switched through the gateway, in both
    /// directions.
    fn publish(&self) {
        let mut state = self.state.lock();
        let targets: Vec<Ipv4Addr> = if state.all_dirty {
            state.announced.keys().copied().collect()
        } else {
            state.dirty.iter().copied().collect()
        };
        state.dirty.clear();
        state.all_dirty = false;
        for address in targets {
            let Some(entry) = state.announced.get(&address) else {
                continue;
            };
            let peers = state.list_for(self.client_to_client, address, entry);
            entry.updates.send_if_modified(|current| {
                let changed = *current != peers;
                if changed {
                    *current = peers;
                }
                changed
            });
        }
    }

    fn published(&self) -> usize {
        self.state.lock().announced.len()
    }
}

impl PeerState {
    fn index(&mut self, lease: Ipv4Addr, context: &RouteContext) {
        self.by_account
            .entry(context.account_id.clone())
            .or_default()
            .insert(lease);
        if let Some(group) = &context.network.group {
            self.by_group
                .entry(group.clone())
                .or_default()
                .insert(lease);
        }
    }

    fn unindex(&mut self, lease: Ipv4Addr, context: &RouteContext) {
        fn remove(
            index: &mut HashMap<String, std::collections::BTreeSet<Ipv4Addr>>,
            key: &str,
            lease: Ipv4Addr,
        ) {
            if let Some(members) = index.get_mut(key) {
                members.remove(&lease);
                if members.is_empty() {
                    index.remove(key);
                }
            }
        }
        remove(&mut self.by_account, &context.account_id, lease);
        if let Some(group) = &context.network.group {
            remove(&mut self.by_group, group, lease);
        }
    }

    /// Devices that may peer with `context`, in address order: everyone
    /// with `client_to_client`, otherwise its account and access group.
    fn candidates<'a>(
        &'a self,
        client_to_client: bool,
        context: &RouteContext,
    ) -> Box<dyn Iterator<Item = Ipv4Addr> + 'a> {
        if client_to_client {
            return Box::new(self.announced.keys().copied());
        }
        let mut members = self
            .by_account
            .get(&context.account_id)
            .cloned()
            .unwrap_or_default();
        if let Some(group) = context
            .network
            .group
            .as_ref()
            .and_then(|group| self.by_group.get(group))
        {
            members.extend(group.iter().copied());
        }
        Box::new(members.into_iter())
    }

    /// The first `MAX_PEERS` devices, by address, that the device at
    /// `address` and they may both reach.
    fn list_for(&self, client_to_client: bool, address: Ipv4Addr, entry: &Announced) -> Vec<Peer> {
        let own = &entry.context;
        self.candidates(client_to_client, own)
            .filter(|other| *other != address)
            .filter_map(|other| {
                let peer = self.announced.get(&other)?;
                (may_peer(client_to_client, own, &peer.context)
                    && own.network.permits(IpAddr::V4(other))
                    && peer.context.network.permits(IpAddr::V4(address)))
                .then(|| Peer {
                    address: other,
                    address6: own.ipv6.zip(peer.context.ipv6).and_then(|(mine, theirs)| {
                        (own.network.permits(IpAddr::V6(theirs))
                            && peer.context.network.permits(IpAddr::V6(mine)))
                        .then_some(theirs)
                    }),
                    endpoint: peer.endpoint,
                    fingerprint: peer.fingerprint,
                })
            })
            .take(MAX_PEERS)
            .collect()
    }
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
            peers: Arc::new(PeerDirectory {
                client_to_client: switching.client_to_client,
                ..PeerDirectory::default()
            }),
            switching,
        })
    }

    fn peers(&self, sender: &RouteContext, receiver: &RouteContext) -> bool {
        may_peer(self.switching.client_to_client, sender, receiver)
    }

    /// Sessions currently published for direct paths.
    pub fn published_peers(&self) -> usize {
        self.peers.published()
    }

    /// Whether `querier` may learn about the device at `address`.
    fn visible(
        &self,
        querier: IpAddr,
        asker: &RouteContext,
        address: IpAddr,
        target: &RouteContext,
    ) -> bool {
        self.peers(asker, target)
            && asker.network.permits(address)
            && target.network.permits(querier)
    }

    /// Applies source validation, access policy and client-to-client rules
    /// to a packet from the session at `lease`.
    fn classify(&self, lease: Ipv4Addr, packet: &[u8]) -> Result<Verdict, RouterError> {
        let info = porta_wire::ip::parse_ip(packet)
            .map_err(|_| RouterError::InvalidPacket("client packet"))?;
        let (source, destination) = (info.source, info.destination);
        let contexts = self.contexts.read();
        let sender = contexts.get(&lease);
        let own_source = match source {
            IpAddr::V4(source) => source == lease,
            IpAddr::V6(source) => {
                sender.is_some_and(|sender| sender.ipv6.is_some())
                    && self
                        .router
                        .ipv6()
                        .and_then(|ipv6| ipv6.ipv4_address(source))
                        == Some(lease)
            }
        };
        let from_subnet = !own_source;
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
    peers: Arc<PeerDirectory>,
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
        self.peers.withdraw(self.address, &self.context);
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
        let peers = self.peers.clone();
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
                ipv6: request.lease.ipv6.map(|ipv6| ipv6.address),
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
                peers,
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

    fn offers_peers(&self) -> bool {
        self.switching.peer_to_peer
    }

    fn announce_peer(
        &self,
        lease: Ipv4Addr,
        endpoint: SocketAddr,
        fingerprint: Fingerprint,
    ) -> Option<tokio::sync::watch::Receiver<Vec<Peer>>> {
        if !self.switching.peer_to_peer {
            return None;
        }
        // Holding the session table keeps a closing session from being
        // published after its withdrawal.
        let contexts = self.contexts.read();
        let context = contexts.get(&lease)?.clone();
        let announced = self.peers.announce(lease, context, endpoint, fingerprint);
        if announced.is_none() {
            tracing::warn!(%lease, "refusing a direct-path offer with another device's certificate");
        }
        announced
    }
}

impl crate::dns::Directory for RouterAdapter {
    fn is_client(&self, address: Ipv4Addr) -> bool {
        self.contexts.read().contains_key(&address)
    }

    fn resolve(&self, querier: Ipv4Addr, name: &str) -> Option<crate::dns::DeviceAddresses> {
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
            .find(|(address, target)| {
                self.visible(IpAddr::V4(querier), asker, IpAddr::V4(**address), target)
            })
            .map(|(address, target)| crate::dns::DeviceAddresses {
                ipv4: *address,
                // Only devices that both have IPv6 reach each other over it.
                ipv6: target.ipv6.zip(asker.ipv6).and_then(|(ipv6, own)| {
                    self.visible(IpAddr::V6(own), asker, IpAddr::V6(ipv6), target)
                        .then_some(ipv6)
                }),
            })
    }

    fn reverse(&self, querier: Ipv4Addr, address: IpAddr) -> Option<String> {
        let names = self.switching.names.as_ref()?.names();
        let contexts = self.contexts.read();
        let asker = contexts.get(&querier)?;
        let (lease, own) = match address {
            IpAddr::V4(address) => (address, IpAddr::V4(querier)),
            IpAddr::V6(address) => (
                self.router.ipv6()?.ipv4_address(address)?,
                IpAddr::V6(asker.ipv6?),
            ),
        };
        let target = contexts.get(&lease)?;
        if let IpAddr::V6(address) = address {
            if target.ipv6 != Some(address) {
                return None;
            }
        }
        if !self.visible(own, asker, address, target) {
            return None;
        }
        names
            .get(&(target.account_id.clone(), target.device_id.clone()))
            .cloned()
    }
}

/// A copy of `packet` with its TTL or hop limit decremented, as a router
/// forwards it, or `None` once the limit is exhausted.
fn forwarded(packet: &[u8]) -> Option<Bytes> {
    let mut packet = packet.to_vec();
    porta_wire::ip::decrement_hop_limit(&mut packet).then(|| Bytes::from(packet))
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
                match metadata.address6 {
                    Some(address6) => format!("{}, {address6}", metadata.address),
                    None => metadata.address.to_string(),
                },
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

    fn traffic(&self, from_client: u64, to_client: u64) {
        OperationalMetrics::traffic(self, from_client, to_client);
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
            ipv6: None,
        })
    }

    #[test]
    fn peer_lists_follow_switching_rules_both_ways_and_withdrawals() {
        let directory = Arc::new(PeerDirectory::default());
        let a: Ipv4Addr = "10.66.0.2".parse().unwrap();
        let b: Ipv4Addr = "10.66.0.3".parse().unwrap();
        let c: Ipv4Addr = "10.66.0.4".parse().unwrap();
        let d: Ipv4Addr = "10.66.0.5".parse().unwrap();
        let alpha = context("alpha", NetworkPolicy::default());
        let mut dual = context("alpha", NetworkPolicy::default());
        Arc::get_mut(&mut dual).unwrap().ipv6 = Some("fd66::3".parse().unwrap());
        // One account, but its policy keeps it away from a.
        let fenced = context(
            "alpha",
            NetworkPolicy {
                deny: vec!["10.66.0.2/32".parse().unwrap()],
                ..NetworkPolicy::default()
            },
        );
        let endpoint = |port| SocketAddr::new("198.51.100.7".parse().unwrap(), port);
        let mut first = directory
            .announce(a, alpha.clone(), endpoint(1000), [1; 32])
            .unwrap();
        assert!(first.borrow_and_update().is_empty());
        let mut second = directory
            .announce(b, dual.clone(), endpoint(2000), [2; 32])
            .unwrap();
        directory
            .announce(c, fenced.clone(), endpoint(3000), [3; 32])
            .unwrap();
        let other = directory
            .announce(
                d,
                context("beta", NetworkPolicy::default()),
                "[::ffff:203.0.113.9]:4000".parse().unwrap(),
                [4; 32],
            )
            .unwrap();
        assert!(first.has_changed().unwrap());
        let peers = first.borrow_and_update().clone();
        assert_eq!(
            peers,
            vec![Peer {
                address: b,
                // a has no IPv6, so b's is not offered.
                address6: None,
                endpoint: endpoint(2000),
                fingerprint: [2; 32],
            }]
        );
        assert_eq!(
            second
                .borrow_and_update()
                .iter()
                .map(|peer| peer.address)
                .collect::<Vec<_>>(),
            vec![a, c]
        );
        assert!(other.borrow().is_empty());

        // Reconnecting under another account leaves the old account's lists,
        // and moving back returns to them.
        drop(second);
        let moved = context("gamma", NetworkPolicy::default());
        directory
            .announce(b, moved.clone(), endpoint(2000), [2; 32])
            .unwrap();
        assert!(first.borrow_and_update().is_empty());
        directory
            .announce(b, dual.clone(), endpoint(2000), [2; 32])
            .unwrap();
        assert_eq!(first.borrow_and_update().len(), 1);

        // A stale session's withdrawal does not remove its successor.
        directory.withdraw(b, &moved);
        directory.withdraw(b, &alpha);
        assert!(!first.has_changed().unwrap());
        directory.withdraw(b, &dual);
        assert!(first.borrow_and_update().is_empty());

        // Another device's fingerprint is refused; a reconnect may reuse its own.
        let beta = context("beta", NetworkPolicy::default());
        assert!(directory
            .announce(d, beta.clone(), endpoint(4000), [1; 32])
            .is_none());
        assert!(directory
            .announce(a, alpha.clone(), endpoint(1000), [1; 32])
            .is_some());
        // Withdrawing releases the fingerprint.
        directory.withdraw(a, &alpha);
        assert!(directory
            .announce(d, beta, endpoint(4000), [1; 32])
            .is_some());

        let switching = Arc::new(PeerDirectory {
            client_to_client: true,
            ..PeerDirectory::default()
        });
        let first = switching
            .announce(a, alpha, endpoint(1000), [1; 32])
            .unwrap();
        switching
            .announce(
                d,
                context("beta", NetworkPolicy::default()),
                "[::ffff:203.0.113.9]:4000".parse().unwrap(),
                [4; 32],
            )
            .unwrap();
        assert_eq!(
            first.borrow()[0].endpoint,
            "203.0.113.9:4000".parse::<SocketAddr>().unwrap()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn peer_lists_stay_cheap_when_thousands_of_devices_reconnect() {
        let address = |index: u32| Ipv4Addr::from(0x0a40_0000 + index);
        let endpoint =
            |index: u32| SocketAddr::new("198.51.100.7".parse().unwrap(), 1024 + index as u16);
        let fingerprint = |index: u32| {
            let mut fingerprint = [0_u8; 32];
            fingerprint[..4].copy_from_slice(&index.to_be_bytes());
            fingerprint
        };
        for client_to_client in [true, false] {
            let directory = Arc::new(PeerDirectory {
                client_to_client,
                ..PeerDirectory::default()
            });
            let started = std::time::Instant::now();
            // Without client-to-client, accounts of two devices each.
            let receivers = (0..4_000_u32)
                .map(|index| {
                    let account = if client_to_client {
                        "one".to_owned()
                    } else {
                        format!("a{}", index / 2)
                    };
                    directory
                        .announce(
                            address(index),
                            context(&account, NetworkPolicy::default()),
                            endpoint(index),
                            fingerprint(index),
                        )
                        .unwrap()
                })
                .collect::<Vec<_>>();
            assert!(
                started.elapsed() < std::time::Duration::from_secs(5),
                "announcing took {:?}",
                started.elapsed()
            );
            tokio::time::sleep(PEER_PUBLISH_DELAY * 4).await;
            let expected = if client_to_client { MAX_PEERS } else { 1 };
            for (index, receiver) in receivers.iter().enumerate() {
                let peers = receiver.borrow();
                assert_eq!(peers.len(), expected, "device {index}");
                assert!(peers
                    .iter()
                    .all(|peer| peer.address != address(index as u32)));
                assert!(peers
                    .windows(2)
                    .all(|pair| pair[0].address < pair[1].address));
            }
            if !client_to_client {
                assert_eq!(receivers[0].borrow()[0].address, address(1));
                assert_eq!(receivers[1].borrow()[0].address, address(0));
            }
            assert_eq!(directory.published(), 4_000);
        }
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
                    peer_to_peer: false,
                    always_reachable: vec![IpAddr::V4(gateway)],
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
                deny: vec![subnet.into()],
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
                allow: vec![subnet.into()],
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

    fn ipv6_packet(source: std::net::Ipv6Addr, destination: std::net::Ipv6Addr) -> Bytes {
        let mut packet = vec![0; 48];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&8_u16.to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        Bytes::from(packet)
    }

    #[tokio::test]
    async fn dual_stack_leases_switch_route_and_validate_ipv6() {
        let pool = Arc::new(Pool::new("10.66.0.0/24").unwrap());
        let ipv6 = Ipv6Pool::new(
            "10.66.0.0/24".parse().unwrap(),
            "fd66::/64".parse().unwrap(),
        )
        .unwrap();
        let leases = PoolAdapter::with_ipv6(pool, Some(ipv6));
        let device = Arc::new(MemoryDevice::default());
        let router = Arc::new(Router::with_ipv6(device.clone(), None, Some(ipv6)));
        let adapter = RouterAdapter::with_switching(
            router.clone(),
            leases.clone(),
            RateLimiters::new(),
            SwitchConfig {
                always_reachable: vec![IpAddr::V6(ipv6.gateway())],
                ..SwitchConfig::default()
            },
        );
        let mut sessions = Vec::new();
        let mut addresses = Vec::new();
        for (name, account) in [("first", "alpha"), ("second", "alpha"), ("third", "beta")] {
            let lease = leases
                .acquire(LeaseRequest {
                    lease_id: name.into(),
                    group_id: None,
                    mode: LeaseMode::Exclusive,
                })
                .await
                .unwrap();
            let lease6 = lease.ipv6.unwrap();
            assert_eq!(Some(lease6.address), ipv6.address(lease.address));
            assert_eq!((lease6.prefix_len, lease6.gateway), (64, ipv6.gateway()));
            sessions.push(
                adapter
                    .register(RouteRequest {
                        lease: lease.clone(),
                        kind: RouteKind::ConnectIp,
                        parent: CancellationToken::new(),
                        account_id: account.into(),
                        device_id: name.into(),
                        network: NetworkPolicy::default(),
                    })
                    .await
                    .unwrap(),
            );
            addresses.push((lease.address, lease6.address));
        }
        let [(a, a6), (b, b6), (c, c6)] = addresses[..] else {
            unreachable!()
        };
        let internet: std::net::Ipv6Addr = "2001:db8::80".parse().unwrap();
        assert_eq!(
            adapter.classify(a, &ipv6_packet(a6, internet)).unwrap(),
            Verdict::Kernel
        );
        assert_eq!(
            adapter.classify(a, &ipv6_packet(a6, b6)).unwrap(),
            Verdict::Deliver(b)
        );
        assert_eq!(
            adapter.classify(a, &ipv6_packet(a6, c6)).unwrap(),
            Verdict::Drop(DropReason::PolicyDenied)
        );
        assert!(matches!(
            adapter.classify(a, &ipv6_packet(b6, internet)),
            Err(RouterError::SourceSpoofed { .. })
        ));
        assert_eq!(router.owner(IpAddr::V6(c6)), Some(c));

        // Switched IPv6 packets reach the peer with a decremented hop limit.
        adapter
            .inject_from_client(sessions[1].cancellation.clone(), b, ipv6_packet(b6, a6))
            .await
            .unwrap();
        let switched = sessions[0].downlink.try_packet().unwrap();
        assert_eq!(switched[7], 63);

        // IPv6 allow lists confine IPv6 destinations; the gateway stays
        // reachable.
        adapter.contexts.write().insert(
            a,
            Arc::new(RouteContext {
                account_id: "alpha".into(),
                device_id: "first".into(),
                network: NetworkPolicy {
                    allow: vec!["2001:db8:1::/48".parse().unwrap()],
                    ..NetworkPolicy::default()
                },
                ipv6: Some(a6),
            }),
        );
        assert_eq!(
            adapter.classify(a, &ipv6_packet(a6, internet)).unwrap(),
            Verdict::Drop(DropReason::PolicyDenied)
        );
        assert_eq!(
            adapter
                .classify(a, &ipv6_packet(a6, ipv6.gateway()))
                .unwrap(),
            Verdict::Kernel
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
