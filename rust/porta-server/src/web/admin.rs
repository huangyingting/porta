use super::landing::{is_operational_path, serve_asset, set_crawler_policy};
use super::portal::{create_client_access, ClientAccessInput};
use super::session::{constant_time_eq, RequestContext, Response};
use crate::ops::audit::{Actor, AuditEvent, AuditLog};
use crate::state::admins::{AdminError, AdminInput, AdminRole, AdminStore};
use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::Zeroizing;

const ADMIN_HTML: &str = include_str!("../../assets/admin.html");

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceSummary {
    pub id: String,
    pub name: String,
    pub first_seen: String,
    pub last_seen: String,
    pub active_sessions: u64,
    pub connections_total: u64,
    pub bytes_uploaded: u64,
    pub bytes_downloaded: u64,
    pub packets_uploaded: u64,
    pub packets_downloaded: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_connected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_disconnected: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub transport: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub assigned_address: String,
    /// `approved`, `pending`, or `denied`.
    #[serde(default)]
    pub status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub target: String,
    /// Networks behind the device that the gateway routes to it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subnets: Vec<String>,
    /// Name clients resolve through the built-in resolver.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub dns_name: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientSummary {
    pub id: String,
    pub name: String,
    pub max_devices: usize,
    pub enabled: bool,
    pub created_at: String,
    pub device_count: usize,
    pub active_sessions: u64,
    pub connections_total: u64,
    pub bytes_uploaded: u64,
    pub bytes_downloaded: u64,
    pub packets_uploaded: u64,
    pub packets_downloaded: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_connected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_disconnected: Option<String>,
    pub devices: Vec<DeviceSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monthly_quota_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_kbps: Option<u32>,
    /// Traffic counted against the monthly quota in the current period.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota_used_bytes: Option<u64>,
    /// `active`, `disabled`, `expired`, or `quota_exceeded`.
    #[serde(default)]
    pub status: String,
    /// `open`, `approval`, or `closed`.
    #[serde(default)]
    pub enrollment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_open_until: Option<String>,
    #[serde(default)]
    pub pending_devices: usize,
    #[serde(default)]
    pub access: ClientAccess,
    /// Standard CONNECT-IP clients may connect with the token alone.
    #[serde(default)]
    pub standard_clients: bool,
}

/// Network access rules of an account, as returned in summaries and
/// accepted by `PUT /api/clients/{id}/access`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientAccess {
    /// Destination prefixes the account may reach; empty allows all.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Destination prefixes the account may never reach.
    #[serde(default)]
    pub deny: Vec<String>,
    /// Accounts in the same group reach each other's devices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Named exit; unset uses the gateway default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<String>,
}

/// Body of `PUT /api/clients/{id}/devices/{device}/subnets`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DeviceSubnets {
    pub subnets: Vec<String>,
}

/// Body of `PUT /api/clients/{id}/enrollment`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClientEnrollment {
    /// `open`, `approval`, or `closed`.
    pub policy: String,
    /// Lets new devices enroll directly for this many minutes.
    #[serde(default)]
    pub open_for_minutes: Option<u32>,
    /// Allows or stops standard CONNECT-IP clients, which have no Porta
    /// device key; unset keeps the current setting.
    #[serde(default)]
    pub standard_clients: Option<bool>,
}

/// Account limits accepted by `PUT /api/clients/{id}/limits`. Every field
/// is required so that `null` explicitly removes a limit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClientLimits {
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<time::OffsetDateTime>,
    pub monthly_quota_bytes: Option<u64>,
    pub rate_limit_kbps: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientIdentity {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryError {
    NotFound,
    Unauthorized,
    Disabled,
    Invalid(String),
    Internal,
}

pub trait ClientRegistry: Send + Sync {
    fn list_clients(&self) -> Result<Vec<ClientSummary>, RegistryError>;
    fn create_client<'a>(
        &'a self,
        name: &'a str,
        max_devices: usize,
    ) -> BoxFuture<'a, Result<(ClientSummary, String), RegistryError>>;
    fn update_client<'a>(
        &'a self,
        id: &'a str,
        name: &'a str,
        max_devices: usize,
        enabled: bool,
    ) -> BoxFuture<'a, Result<ClientSummary, RegistryError>>;
    fn delete_client<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Result<(), RegistryError>>;
    fn rotate_client_token<'a>(
        &'a self,
        id: &'a str,
    ) -> BoxFuture<'a, Result<String, RegistryError>>;
    fn disconnect<'a>(
        &'a self,
        client_id: &'a str,
        device_id: Option<&'a str>,
    ) -> BoxFuture<'a, Result<usize, RegistryError>>;
    fn forget_device<'a>(
        &'a self,
        client_id: &'a str,
        device_id: &'a str,
    ) -> BoxFuture<'a, Result<(), RegistryError>>;
    fn authenticate_portal(&self, token: &str) -> Result<ClientIdentity, RegistryError>;
    fn portal_client_active(&self, client_id: &str, token_hash: &str) -> bool;
    fn set_client_limits<'a>(
        &'a self,
        _id: &'a str,
        _limits: ClientLimits,
    ) -> BoxFuture<'a, Result<ClientSummary, RegistryError>> {
        Box::pin(async {
            Err(RegistryError::Invalid(
                "account limits are unsupported".into(),
            ))
        })
    }
    fn set_client_enrollment<'a>(
        &'a self,
        _id: &'a str,
        _enrollment: ClientEnrollment,
    ) -> BoxFuture<'a, Result<ClientSummary, RegistryError>> {
        Box::pin(async {
            Err(RegistryError::Invalid(
                "enrollment control is unsupported".into(),
            ))
        })
    }
    /// Approves (`true`) or denies (`false`) a device.
    fn review_device<'a>(
        &'a self,
        _id: &'a str,
        _device_id: &'a str,
        _approve: bool,
    ) -> BoxFuture<'a, Result<ClientSummary, RegistryError>> {
        Box::pin(async {
            Err(RegistryError::Invalid(
                "enrollment control is unsupported".into(),
            ))
        })
    }
    fn set_client_access<'a>(
        &'a self,
        _id: &'a str,
        _access: ClientAccess,
    ) -> BoxFuture<'a, Result<ClientSummary, RegistryError>> {
        Box::pin(async {
            Err(RegistryError::Invalid(
                "access policies are unsupported".into(),
            ))
        })
    }
    /// Assigns the networks a device routes for other clients.
    fn set_device_subnets<'a>(
        &'a self,
        _id: &'a str,
        _device_id: &'a str,
        _subnets: Vec<String>,
    ) -> BoxFuture<'a, Result<ClientSummary, RegistryError>> {
        Box::pin(async {
            Err(RegistryError::Invalid(
                "subnet routing is unsupported".into(),
            ))
        })
    }
    /// Starts a new quota period now, clearing the account's quota usage.
    fn reset_client_usage<'a>(
        &'a self,
        _id: &'a str,
    ) -> BoxFuture<'a, Result<ClientSummary, RegistryError>> {
        Box::pin(async {
            Err(RegistryError::Invalid(
                "account limits are unsupported".into(),
            ))
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminInputJson {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    sso_email: Option<String>,
    #[serde(default)]
    disabled: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CodeInput {
    code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordChange {
    current: String,
    password: String,
}

/// Whether `actor`'s role allows `method` on `path`.
fn permitted(actor: &AdminActor, method: &str, path: &str) -> bool {
    if path == "/api/me" || path.starts_with("/api/me/") {
        return true;
    }
    if path == "/api/admins" || path.starts_with("/api/admins/") {
        return actor.role == AdminRole::Owner;
    }
    if path.starts_with("/api/audit") {
        return actor.role >= AdminRole::Operator;
    }
    matches!(method, "GET" | "HEAD") || actor.role >= AdminRole::Operator
}

/// An audit action and target for an admin API request, such as
/// `PUT /api/clients/{id}/limits` and the client ID.
fn describe_request(method: &str, path: &str) -> (String, String) {
    let parts = path
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    let mut template = Vec::new();
    let mut targets = Vec::new();
    for (index, part) in parts.iter().enumerate() {
        let parent = index.checked_sub(1).map(|previous| parts[previous]);
        match parent {
            Some("clients") if index == 2 => {
                template.push("{client}");
                targets.push(*part);
            }
            Some("devices") => {
                template.push("{device}");
                targets.push(*part);
            }
            Some("admins") if index == 2 => {
                template.push("{admin}");
                targets.push(*part);
            }
            _ => template.push(part),
        }
    }
    (
        format!("{method} /{}", template.join("/")),
        targets.join("/"),
    )
}

fn admin_error(error: AdminError) -> Response {
    match error {
        AdminError::NotFound => json_error(404, "Administrator not found"),
        AdminError::Invalid(message) => json_error(400, &message),
        AdminError::InvalidCredentials | AdminError::CodeRequired => {
            json_error(400, "The credentials are not valid")
        }
        AdminError::Io(_) | AdminError::Decode(_) => {
            tracing::error!(%error, "administrator store failed");
            json_error(503, "The administrator store is unavailable")
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientInput {
    name: String,
    max_devices: usize,
    enabled: Option<bool>,
}

/// Gateway-wide state for `GET /api/gateway`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct GatewayStatus {
    pub version: String,
    /// Present when this gateway is a cascade relay.
    pub upstream: Option<UpstreamStatus>,
    /// Every next hop: the default upstream and the named exits.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub upstreams: Vec<UpstreamStatus>,
    /// Split-tunnel prefixes advertised to clients; empty for a full tunnel.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dns_domains: Vec<String>,
    /// IPv6 prefix of dual-stack clients (`--ipv6-pool`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_pool: Option<String>,
    /// Every client reaches every other client (`--client-to-client`).
    pub client_to_client: bool,
    /// Devices connect directly where they can (`--peer-to-peer`).
    pub peer_to_peer: bool,
    /// The built-in resolver serves device names (`--dns-resolver`).
    pub dns_resolver: bool,
    /// Exit names an account's access policy may select.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exits: Vec<String>,
    /// Account federation with other gateways.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation: Option<FederationInfo>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct FederationInfo {
    /// `primary` serves accounts to replicas; `replica` mirrors them.
    pub role: &'static str,
    #[serde(flatten)]
    pub status: crate::ops::federation::FederationStatus,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct UpstreamStatus {
    /// Exit name; empty for the default upstream.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    pub url: String,
    pub interface: String,
    pub connected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub type GatewayStatusProvider = Arc<dyn Fn() -> GatewayStatus + Send + Sync>;

pub struct AdminService {
    registry: Arc<dyn ClientRegistry>,
    admin_token: Zeroizing<Vec<u8>>,
    gateway: Option<GatewayStatusProvider>,
    admins: Option<Arc<AdminStore>>,
    audit: Option<Arc<AuditLog>>,
}

/// Who is using the admin API, and with which role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminActor {
    /// `token` for the break-glass token, `admin` or `sso`.
    pub kind: &'static str,
    pub id: String,
    pub name: String,
    pub role: AdminRole,
}

impl AdminActor {
    pub fn break_glass() -> Self {
        Self {
            kind: "token",
            id: String::new(),
            name: "break-glass token".into(),
            role: AdminRole::Owner,
        }
    }

    pub fn audit_actor(&self) -> Actor {
        Actor {
            kind: self.kind,
            id: self.id.clone(),
            name: self.name.clone(),
        }
    }
}

impl AdminService {
    pub fn new(registry: Arc<dyn ClientRegistry>, admin_token: impl Into<Vec<u8>>) -> Self {
        Self {
            registry,
            admin_token: Zeroizing::new(admin_token.into()),
            gateway: None,
            admins: None,
            audit: None,
        }
    }

    pub fn with_gateway_status(mut self, provider: GatewayStatusProvider) -> Self {
        self.gateway = Some(provider);
        self
    }

    /// Named administrators and the audit log.
    pub fn with_identity(
        mut self,
        admins: Option<Arc<AdminStore>>,
        audit: Option<Arc<AuditLog>>,
    ) -> Self {
        self.admins = admins;
        self.audit = audit;
        self
    }

    pub fn registry(&self) -> &Arc<dyn ClientRegistry> {
        &self.registry
    }

    /// Serves the admin page and API. `actor` is the signed-in portal
    /// administrator; without one, the break-glass bearer token is required.
    pub async fn handle(
        &self,
        request: &RequestContext,
        actor: Option<AdminActor>,
    ) -> Option<Response> {
        if let Some(mut response) = serve_asset(request) {
            set_admin_security_headers(&mut response);
            return Some(response);
        }
        if request.method == "GET" && is_operational_path(&request.path) {
            return None;
        }
        if request.path == "/" {
            if !request.is_get_or_head() {
                return Some(Response::not_found());
            }
            let mut response = Response::html(200, ADMIN_HTML.as_bytes().to_vec());
            response.set_header("Cache-Control", "no-store");
            set_admin_security_headers(&mut response);
            return Some(response.without_body_for_head(request));
        }
        if !request.path.starts_with("/api/") {
            return Some(with_admin_headers(Response::not_found()));
        }
        let actor = match actor {
            Some(actor) => actor,
            None if admin_authorized(
                request.header("authorization"),
                self.admin_token.as_slice(),
            ) =>
            {
                AdminActor::break_glass()
            }
            None => {
                let mut response = json_error(401, "Invalid admin token");
                response.set_header("WWW-Authenticate", "******\"porta-admin\"");
                set_admin_security_headers(&mut response);
                return Some(response);
            }
        };
        if !permitted(&actor, &request.method, &request.path) {
            let response = json_error(403, "Your administrator role does not allow this");
            self.audit_request(&actor, request, 403);
            return Some(with_admin_headers(response));
        }
        let response = self.dispatch(request, &actor).await;
        if !request.is_get_or_head() {
            self.audit_request(&actor, request, response.status);
        }
        Some(with_admin_headers(response))
    }

    fn audit_request(&self, actor: &AdminActor, request: &RequestContext, status: u16) {
        let Some(audit) = &self.audit else {
            return;
        };
        let (action, target) = describe_request(&request.method, &request.path);
        audit.record(
            AuditEvent::new(actor.audit_actor(), action, target)
                .outcome(match status {
                    200..=399 => "ok",
                    401 | 403 => "denied",
                    _ => "failed",
                })
                .address(request.client_ip.or(request.peer_ip))
                .detail(serde_json::json!({ "status": status })),
        );
    }

    async fn dispatch(&self, request: &RequestContext, actor: &AdminActor) -> Response {
        if request.path == "/api/me" || request.path.starts_with("/api/me/") {
            return self.me(request, actor);
        }
        if request.path == "/api/admins" || request.path.starts_with("/api/admins/") {
            return self.manage_admins(request);
        }
        if request.path == "/api/audit" || request.path == "/api/audit/export" {
            return self.audit_log(request);
        }
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/api/gateway") => {
                let status = self.gateway.as_ref().map_or_else(
                    || GatewayStatus {
                        version: crate::VERSION.trim().to_owned(),
                        ..GatewayStatus::default()
                    },
                    |provider| provider(),
                );
                json_response(200, &status)
            }
            ("GET", "/api/clients") => match self.registry.list_clients() {
                Ok(clients) => json_response(200, &serde_json::json!({ "clients": clients })),
                Err(error) => registry_error(error),
            },
            ("POST", "/api/clients") => {
                let input: ClientInput = match decode_json(request) {
                    Ok(input) => input,
                    Err(response) => return response,
                };
                let name = match validate_client_input(&input.name, input.max_devices) {
                    Ok(name) => name,
                    Err(error) => return registry_error(error),
                };
                match self.registry.create_client(name, input.max_devices).await {
                    Ok((client, token)) => json_response(
                        201,
                        &serde_json::json!({ "client": client, "token": token }),
                    ),
                    Err(error) => registry_error(error),
                }
            }
            ("POST", "/api/client-access") => {
                let input: ClientAccessInput = match decode_json(request) {
                    Ok(input) => input,
                    Err(response) => return response,
                };
                create_client_access(
                    self.registry.as_ref(),
                    std::str::from_utf8(self.admin_token.as_slice()).unwrap_or_default(),
                    input,
                )
            }
            _ => self.client_action(request).await,
        }
    }

    fn me(&self, request: &RequestContext, actor: &AdminActor) -> Response {
        let store = self.admins.as_ref().filter(|_| actor.kind != "token");
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/api/me") => {
                let totp = store
                    .and_then(|store| store.list().into_iter().find(|admin| admin.id == actor.id))
                    .is_some_and(|admin| admin.totp);
                json_response(
                    200,
                    &serde_json::json!({
                        "kind": actor.kind,
                        "id": actor.id,
                        "name": actor.name,
                        "role": actor.role,
                        "totp": totp,
                        "admins": self.admins.is_some(),
                        "audit": self.audit.is_some(),
                    }),
                )
            }
            ("POST", "/api/me/totp") => match store.map(|store| store.begin_totp(&actor.id)) {
                Some(Ok(enrollment)) => json_response(
                    200,
                    &serde_json::json!({
                        "secret": enrollment.secret,
                        "uri": enrollment.uri,
                        "qr_code": super::portal::qr_code_data_uri(&enrollment.uri).unwrap_or_default(),
                    }),
                ),
                Some(Err(error)) => admin_error(error),
                None => json_error(
                    400,
                    "Only named administrators can use two-factor authentication",
                ),
            },
            ("PUT", "/api/me/totp") => {
                let input: CodeInput = match decode_json(request) {
                    Ok(input) => input,
                    Err(response) => return response,
                };
                match store.map(|store| {
                    store.confirm_totp(&actor.id, &input.code, time::OffsetDateTime::now_utc())
                }) {
                    Some(Ok(())) => json_response(200, &serde_json::json!({ "totp": true })),
                    Some(Err(AdminError::InvalidCredentials)) => {
                        json_error(400, "That code is not valid; check your device's clock")
                    }
                    Some(Err(error)) => admin_error(error),
                    None => json_error(
                        400,
                        "Only named administrators can use two-factor authentication",
                    ),
                }
            }
            ("PUT", "/api/me/password") => {
                let input: PasswordChange = match decode_json(request) {
                    Ok(input) => input,
                    Err(response) => return response,
                };
                match store
                    .map(|store| store.change_password(&actor.id, &input.current, &input.password))
                {
                    Some(Ok(())) => Response::new(204),
                    Some(Err(AdminError::InvalidCredentials)) => {
                        json_error(400, "The current password is incorrect")
                    }
                    Some(Err(error)) => admin_error(error),
                    None => json_error(400, "Only named administrators have passwords"),
                }
            }
            _ => Response::not_found(),
        }
    }

    fn manage_admins(&self, request: &RequestContext) -> Response {
        let Some(store) = &self.admins else {
            return json_error(404, "Named administrators are not enabled");
        };
        let parts = request
            .path
            .trim_start_matches("/api/admins")
            .split('/')
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>();
        let input = || -> Result<AdminInput, Response> {
            let input: AdminInputJson = decode_json(request)?;
            let role =
                match input.role.as_deref() {
                    Some(role) => Some(AdminRole::parse(role).ok_or_else(|| {
                        json_error(400, "role must be viewer, operator, or owner")
                    })?),
                    None => None,
                };
            Ok(AdminInput {
                username: input.username.unwrap_or_default(),
                role,
                password: input.password.filter(|password| !password.is_empty()),
                sso_email: input.sso_email,
                disabled: input.disabled,
            })
        };
        match (request.method.as_str(), parts.as_slice()) {
            ("GET", []) => json_response(200, &serde_json::json!({ "admins": store.list() })),
            ("POST", []) => match input() {
                Ok(input) => match store.create(input) {
                    Ok(admin) => json_response(201, &serde_json::json!({ "admin": admin })),
                    Err(error) => admin_error(error),
                },
                Err(response) => response,
            },
            ("PUT", [id]) => match input() {
                Ok(input) => match store.update(id, input) {
                    Ok(admin) => json_response(200, &serde_json::json!({ "admin": admin })),
                    Err(error) => admin_error(error),
                },
                Err(response) => response,
            },
            ("DELETE", [id]) => match store.delete(id) {
                Ok(()) => Response::new(204),
                Err(error) => admin_error(error),
            },
            ("DELETE", [id, "totp"]) => match store.remove_totp(id) {
                Ok(()) => Response::new(204),
                Err(error) => admin_error(error),
            },
            _ => Response::not_found(),
        }
    }

    fn audit_log(&self, request: &RequestContext) -> Response {
        let Some(audit) = &self.audit else {
            return json_error(404, "The audit log is not enabled");
        };
        if !request.is_get_or_head() {
            return Response::not_found();
        }
        if request.path == "/api/audit/export" {
            let mut response = Response::text(200, "application/x-ndjson", audit.export());
            response.set_header(
                "Content-Disposition",
                "attachment; filename=\"porta-audit.jsonl\"",
            );
            response.set_header("Cache-Control", "no-store");
            return response;
        }
        let limit = request
            .query
            .split('&')
            .find_map(|pair| pair.strip_prefix("limit="))
            .and_then(|value| value.parse().ok())
            .unwrap_or(200);
        json_response(200, &serde_json::json!({ "events": audit.recent(limit) }))
    }

    async fn client_action(&self, request: &RequestContext) -> Response {
        let Some(suffix) = request.path.strip_prefix("/api/clients/") else {
            return Response::not_found();
        };
        let parts = suffix.split('/').collect::<Vec<_>>();
        if parts.first().is_none_or(|part| part.is_empty()) {
            return Response::not_found();
        }
        let Some(client_id) = path_unescape(parts[0]) else {
            return Response::not_found();
        };
        match (request.method.as_str(), parts.as_slice()) {
            ("PUT", [_]) => {
                let input: ClientInput = match decode_json(request) {
                    Ok(input) => input,
                    Err(response) => return response,
                };
                let enabled = input.enabled.unwrap_or(true);
                let name = match validate_client_input(&input.name, input.max_devices) {
                    Ok(name) => name,
                    Err(error) => return registry_error(error),
                };
                match self
                    .registry
                    .update_client(&client_id, name, input.max_devices, enabled)
                    .await
                {
                    Ok(client) => json_response(200, &serde_json::json!({ "client": client })),
                    Err(error) => registry_error(error),
                }
            }
            ("PUT", [_, "limits"]) => {
                let limits: ClientLimits = match decode_json(request) {
                    Ok(limits) => limits,
                    Err(response) => return response,
                };
                match self.registry.set_client_limits(&client_id, limits).await {
                    Ok(client) => json_response(200, &serde_json::json!({ "client": client })),
                    Err(error) => registry_error(error),
                }
            }
            ("PUT", [_, "enrollment"]) => {
                let enrollment: ClientEnrollment = match decode_json(request) {
                    Ok(enrollment) => enrollment,
                    Err(response) => return response,
                };
                match self
                    .registry
                    .set_client_enrollment(&client_id, enrollment)
                    .await
                {
                    Ok(client) => json_response(200, &serde_json::json!({ "client": client })),
                    Err(error) => registry_error(error),
                }
            }
            ("PUT", [_, "access"]) => {
                let access: ClientAccess = match decode_json(request) {
                    Ok(access) => access,
                    Err(response) => return response,
                };
                match self.registry.set_client_access(&client_id, access).await {
                    Ok(client) => json_response(200, &serde_json::json!({ "client": client })),
                    Err(error) => registry_error(error),
                }
            }
            ("PUT", [_, "devices", device, "subnets"]) => {
                let Some(device) = path_unescape(device) else {
                    return Response::not_found();
                };
                let input: DeviceSubnets = match decode_json(request) {
                    Ok(input) => input,
                    Err(response) => return response,
                };
                match self
                    .registry
                    .set_device_subnets(&client_id, &device, input.subnets)
                    .await
                {
                    Ok(client) => json_response(200, &serde_json::json!({ "client": client })),
                    Err(error) => registry_error(error),
                }
            }
            ("POST", [_, "devices", device, action @ ("approve" | "deny")]) => {
                let Some(device) = path_unescape(device) else {
                    return Response::not_found();
                };
                match self
                    .registry
                    .review_device(&client_id, &device, *action == "approve")
                    .await
                {
                    Ok(client) => json_response(200, &serde_json::json!({ "client": client })),
                    Err(error) => registry_error(error),
                }
            }
            ("POST", [_, "usage", "reset"]) => {
                match self.registry.reset_client_usage(&client_id).await {
                    Ok(client) => json_response(200, &serde_json::json!({ "client": client })),
                    Err(error) => registry_error(error),
                }
            }
            ("DELETE", [_]) => match self.registry.delete_client(&client_id).await {
                Ok(()) => Response::new(204),
                Err(error) => registry_error(error),
            },
            ("POST", [_, "token"]) => match self.registry.rotate_client_token(&client_id).await {
                Ok(token) => json_response(200, &serde_json::json!({ "token": token })),
                Err(error) => registry_error(error),
            },
            ("POST", [_, "disconnect"]) => {
                disconnect_response(self.registry.disconnect(&client_id, None).await)
            }
            ("POST", [_, "devices", device, "disconnect"]) => {
                let Some(device) = path_unescape(device) else {
                    return Response::not_found();
                };
                disconnect_response(self.registry.disconnect(&client_id, Some(&device)).await)
            }
            ("DELETE", [_, "devices", device]) => {
                let Some(device) = path_unescape(device) else {
                    return Response::not_found();
                };
                match self.registry.forget_device(&client_id, &device).await {
                    Ok(()) => Response::new(204),
                    Err(error) => registry_error(error),
                }
            }
            _ => Response::not_found(),
        }
    }
}

fn disconnect_response(result: Result<usize, RegistryError>) -> Response {
    match result {
        Ok(count) => json_response(200, &serde_json::json!({ "disconnected_sessions": count })),
        Err(error) => registry_error(error),
    }
}

pub fn validate_client_input(name: &str, max_devices: usize) -> Result<&str, RegistryError> {
    let name = name.trim();
    if name.is_empty() || name.len() > 80 {
        return Err(RegistryError::Invalid(
            "client name must contain 1 to 80 characters".into(),
        ));
    }
    if !(1..=100).contains(&max_devices) {
        return Err(RegistryError::Invalid(
            "device limit must be between 1 and 100".into(),
        ));
    }
    Ok(name)
}

fn decode_json<T: for<'de> Deserialize<'de>>(request: &RequestContext) -> Result<T, Response> {
    if request.body.len() > 16 << 10 {
        return Err(json_error(400, "Invalid request body"));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(&request.body);
    let value =
        T::deserialize(&mut deserializer).map_err(|_| json_error(400, "Invalid request body"))?;
    deserializer
        .end()
        .map_err(|_| json_error(400, "Invalid request body"))?;
    Ok(value)
}

fn registry_error(error: RegistryError) -> Response {
    match error {
        RegistryError::NotFound => json_error(404, "Client or device not found"),
        RegistryError::Invalid(message) => json_error(400, &message),
        RegistryError::Unauthorized | RegistryError::Disabled => {
            json_error(400, "Client access is not available for this token")
        }
        RegistryError::Internal => json_error(500, "Internal server error"),
    }
}

fn json_error(status: u16, message: &str) -> Response {
    json_response(status, &serde_json::json!({ "error": message }))
}

pub fn json_response<T: Serialize + ?Sized>(status: u16, value: &T) -> Response {
    match serde_json::to_vec(value) {
        Ok(mut body) => {
            body.push(b'\n');
            Response::json(status, body)
        }
        Err(_) => Response::json(500, b"{\"error\":\"Internal server error\"}\n".to_vec()),
    }
}

fn with_admin_headers(mut response: Response) -> Response {
    set_admin_security_headers(&mut response);
    response
}

pub fn admin_authorized(header: Option<&str>, expected: &[u8]) -> bool {
    let Some(provided) = header.and_then(|header| header.strip_prefix("Bearer ")) else {
        return false;
    };
    !expected.is_empty() && constant_time_eq(provided.as_bytes(), expected)
}

pub fn set_admin_security_headers(response: &mut Response) {
    set_crawler_policy(response);
    response.set_header(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    );
    response.set_header("Referrer-Policy", "no-referrer");
    response.set_header("X-Content-Type-Options", "nosniff");
    response.set_header("X-Frame-Options", "DENY");
}

fn path_unescape(value: &str) -> Option<String> {
    let mut output = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return None;
            }
            let high = hex_value(bytes[index + 1])?;
            let low = hex_value(bytes[index + 2])?;
            output.push(high << 4 | low);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).ok()
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemoryRegistry {
        clients: Mutex<Vec<ClientSummary>>,
    }

    impl ClientRegistry for MemoryRegistry {
        fn list_clients(&self) -> Result<Vec<ClientSummary>, RegistryError> {
            Ok(self.clients.lock().unwrap().clone())
        }
        fn create_client<'a>(
            &'a self,
            name: &'a str,
            max_devices: usize,
        ) -> BoxFuture<'a, Result<(ClientSummary, String), RegistryError>> {
            Box::pin(async move {
                let client = ClientSummary {
                    id: "client-id".into(),
                    name: name.into(),
                    max_devices,
                    enabled: true,
                    ..ClientSummary::default()
                };
                self.clients.lock().unwrap().push(client.clone());
                Ok((client, "new-client-token-0123456789".into()))
            })
        }
        fn update_client<'a>(
            &'a self,
            id: &'a str,
            name: &'a str,
            max_devices: usize,
            enabled: bool,
        ) -> BoxFuture<'a, Result<ClientSummary, RegistryError>> {
            Box::pin(async move {
                let mut clients = self.clients.lock().unwrap();
                let client = clients
                    .iter_mut()
                    .find(|client| client.id == id)
                    .ok_or(RegistryError::NotFound)?;
                client.name = name.into();
                client.max_devices = max_devices;
                client.enabled = enabled;
                Ok(client.clone())
            })
        }
        fn delete_client<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Result<(), RegistryError>> {
            Box::pin(async move {
                let mut clients = self.clients.lock().unwrap();
                let position = clients
                    .iter()
                    .position(|client| client.id == id)
                    .ok_or(RegistryError::NotFound)?;
                clients.remove(position);
                Ok(())
            })
        }
        fn rotate_client_token<'a>(
            &'a self,
            id: &'a str,
        ) -> BoxFuture<'a, Result<String, RegistryError>> {
            Box::pin(async move {
                self.clients
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|client| client.id == id)
                    .then(|| "rotated-client-token-0123456789".into())
                    .ok_or(RegistryError::NotFound)
            })
        }
        fn disconnect<'a>(
            &'a self,
            client_id: &'a str,
            _device_id: Option<&'a str>,
        ) -> BoxFuture<'a, Result<usize, RegistryError>> {
            Box::pin(async move {
                self.clients
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|client| client.id == client_id)
                    .then_some(2)
                    .ok_or(RegistryError::NotFound)
            })
        }
        fn forget_device<'a>(
            &'a self,
            _client_id: &'a str,
            _device_id: &'a str,
        ) -> BoxFuture<'a, Result<(), RegistryError>> {
            Box::pin(async { Ok(()) })
        }
        fn authenticate_portal(&self, token: &str) -> Result<ClientIdentity, RegistryError> {
            (token == "client-token-0123456789")
                .then(|| ClientIdentity {
                    id: "client-id".into(),
                    name: "Operations".into(),
                })
                .ok_or(RegistryError::Unauthorized)
        }
        fn portal_client_active(&self, _client_id: &str, _token_hash: &str) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn api_requires_auth_and_manages_clients() {
        let registry = Arc::new(MemoryRegistry::default());
        let service = AdminService::new(registry, b"admin-token-0123456789".to_vec());
        assert_eq!(
            service
                .handle(&RequestContext::new("GET", "/api/clients"), None)
                .await
                .unwrap()
                .status,
            401
        );
        let create = RequestContext::new("POST", "/api/clients")
            .with_header("Authorization", "Bearer admin-token-0123456789")
            .with_body(br#"{"name":"Operations","max_devices":4}"#.to_vec());
        let response = service.handle(&create, None).await.unwrap();
        assert_eq!(response.status, 201);
        assert!(String::from_utf8_lossy(&response.body).contains("Operations"));
        assert!(!String::from_utf8_lossy(&response.body).contains("token_hash"));
    }

    #[tokio::test]
    async fn page_is_complete_and_never_embeds_credentials() {
        let service = AdminService::new(
            Arc::new(MemoryRegistry::default()),
            b"admin-token-0123456789".to_vec(),
        );
        let response = service
            .handle(&RequestContext::new("GET", "/"), None)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&response.body);
        for text in [
            "Porta Control",
            "Client overview",
            "Search clients or devices",
            "Disconnect now",
        ] {
            assert!(body.contains(text));
        }
        assert!(!body.contains("admin-token-0123456789"));
        assert!(response
            .header("Content-Security-Policy")
            .unwrap()
            .contains("frame-ancestors 'none'"));
    }

    #[tokio::test]
    async fn roles_limit_the_api_and_every_mutation_is_audited() {
        let directory = tempfile::tempdir().unwrap();
        let admins =
            Arc::new(AdminStore::open(directory.path().join("admins.json"), "Porta").unwrap());
        let audit = Arc::new(AuditLog::open(directory.path().join("audit.log")).unwrap());
        let service = AdminService::new(
            Arc::new(MemoryRegistry::default()),
            b"admin-token-0123456789".to_vec(),
        )
        .with_identity(Some(admins.clone()), Some(audit.clone()));
        let actor = |role| AdminActor {
            kind: "admin",
            id: "a1".into(),
            name: "alice".into(),
            role,
        };
        let json = |method: &str, path: &str, body: &str| {
            RequestContext::new(method, path)
                .with_header("Content-Type", "application/json")
                .with_body(body.as_bytes().to_vec())
        };
        let status = |response: Option<Response>| response.unwrap().status;

        let viewer = Some(actor(AdminRole::Viewer));
        assert_eq!(
            status(
                service
                    .handle(&RequestContext::new("GET", "/api/clients"), viewer.clone())
                    .await
            ),
            200
        );
        let create = json("POST", "/api/clients", r#"{"name":"Team","max_devices":2}"#);
        assert_eq!(status(service.handle(&create, viewer.clone()).await), 403);
        assert_eq!(
            status(
                service
                    .handle(&RequestContext::new("GET", "/api/audit"), viewer)
                    .await
            ),
            403
        );

        let operator = Some(actor(AdminRole::Operator));
        assert_eq!(status(service.handle(&create, operator.clone()).await), 201);
        assert_eq!(
            status(
                service
                    .handle(&RequestContext::new("GET", "/api/admins"), operator.clone())
                    .await
            ),
            403
        );

        // The break-glass token acts as an owner.
        let new_admin = json(
            "POST",
            "/api/admins",
            r#"{"username":"bob","role":"operator","password":"a long enough password"}"#,
        )
        .with_header("Authorization", "Bearer admin-token-0123456789");
        assert_eq!(status(service.handle(&new_admin, None).await), 201);
        assert_eq!(admins.list()[0].username, "bob");
        let invalid_role = json(
            "POST",
            "/api/admins",
            r#"{"username":"carol","role":"root","password":"a long enough password"}"#,
        );
        assert_eq!(
            status(
                service
                    .handle(&invalid_role, Some(actor(AdminRole::Owner)))
                    .await
            ),
            400
        );

        let me = service
            .handle(&RequestContext::new("GET", "/api/me"), operator)
            .await
            .unwrap();
        let me: serde_json::Value = serde_json::from_slice(&me.body).unwrap();
        assert_eq!(me["role"], "operator");
        assert_eq!(me["name"], "alice");

        let events = audit.recent(10);
        let actions = events
            .iter()
            .map(|event| {
                (
                    event["action"].as_str().unwrap().to_owned(),
                    event["outcome"].as_str().unwrap().to_owned(),
                )
            })
            .collect::<Vec<_>>();
        assert!(actions.contains(&("POST /api/clients".to_owned(), "denied".to_owned())));
        assert!(actions.contains(&("POST /api/clients".to_owned(), "ok".to_owned())));
        assert!(actions.contains(&("POST /api/admins".to_owned(), "ok".to_owned())));
        assert!(actions.contains(&("POST /api/admins".to_owned(), "failed".to_owned())));
        let token_event = events
            .iter()
            .find(|event| event["action"] == "POST /api/admins" && event["outcome"] == "ok")
            .unwrap();
        assert_eq!(token_event["actor"]["kind"], "token");
        // Successful reads are not audited, denied ones are, and bodies such
        // as passwords never are.
        assert!(!actions
            .iter()
            .any(|(action, outcome)| action.starts_with("GET ") && outcome == "ok"));
        assert!(actions.contains(&("GET /api/admins".to_owned(), "denied".to_owned())));
        assert!(!String::from_utf8(audit.export())
            .unwrap()
            .contains("long enough"));
    }

    #[test]
    fn audit_actions_name_routes_and_targets() {
        assert_eq!(
            describe_request("PUT", "/api/clients/c1/devices/d-2/subnets"),
            (
                "PUT /api/clients/{client}/devices/{device}/subnets".to_owned(),
                "c1/d-2".to_owned()
            )
        );
        assert_eq!(
            describe_request("DELETE", "/api/admins/a1/totp"),
            (
                "DELETE /api/admins/{admin}/totp".to_owned(),
                "a1".to_owned()
            )
        );
        assert_eq!(
            describe_request("POST", "/api/clients"),
            ("POST /api/clients".to_owned(), String::new())
        );
    }
}
