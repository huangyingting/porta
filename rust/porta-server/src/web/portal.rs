use super::admin::{json_response, AdminService, ClientRegistry, RegistryError};
use super::downloads::{open_download_file, DownloadService, CLIENT_DOWNLOAD_PREFIX};
use super::landing::set_crawler_policy;
use super::session::{
    constant_time_eq, expired_session_cookie, form_urlencode, hash_token, html_escape, parse_form,
    unix_time_now, CredentialCipher, PortalRole, PortalSession, RequestContext, Response,
    SessionStore, PORTAL_COOKIE_NAME, PORTAL_SESSION_TTL_SECS,
};
use crate::ops::abuse::{AbuseGuard, Surface};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::TryRngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io::Read;
use std::net::IpAddr;
use std::sync::Arc;
use zeroize::Zeroizing;

pub const DOWNLOAD_TICKET_TTL_SECS: u64 = 10 * 60;
pub const CLIENT_ACCESS_ERROR: &str =
    "This access link is invalid or no longer authorized. Ask your administrator for a new link.";
pub const PORTAL_JOIN_SCRIPT_PATH: &str = "/assets/portal-join.js";
pub const PORTAL_CLIENT_SCRIPT_PATH: &str = "/assets/portal-client.js";

const PORTAL_ACCESS_HTML: &str = include_str!("../../assets/portal-access.html");
const PORTAL_DOWNLOADS_HTML: &str = include_str!("../../assets/portal-downloads.html");
const PORTAL_JOIN_HTML: &str = include_str!("../../assets/portal-join.html");
const PORTAL_JOIN_SCRIPT: &str = include_str!("../../assets/portal-join.js");
const PORTAL_CLIENT_SETUP_HTML: &str = include_str!("../../assets/portal-client-setup.html");
const PORTAL_CLIENT_SCRIPT: &str = include_str!("../../assets/portal-client.js");

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientAccessInput {
    pub origin: String,
    pub token: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientAccessClaim {
    pub client_id: String,
    pub token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileQrInput {
    pub name: String,
    pub server: String,
    pub token: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DownloadProfile {
    pub server: String,
    pub token: String,
    pub qr_code: String,
    pub notice: String,
    pub setup_uri: String,
}

pub struct Portal {
    registry: Arc<dyn ClientRegistry>,
    admin: AdminService,
    admin_token: Zeroizing<String>,
    downloads_directory: String,
    downloads: DownloadService,
    trust_proxy_headers: bool,
    download_ticket_key: Zeroizing<[u8; 32]>,
    token_cipher: CredentialCipher,
    sessions: SessionStore,
    abuse: Option<Arc<AbuseGuard>>,
}

impl Portal {
    pub fn new(
        registry: Arc<dyn ClientRegistry>,
        admin_token: impl Into<String>,
        downloads_directory: impl Into<String>,
        trust_proxy_headers: bool,
    ) -> Result<Self, &'static str> {
        let admin_token = admin_token.into();
        let downloads_directory = downloads_directory.into();
        let mut download_ticket_key = [0_u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut download_ticket_key)
            .map_err(|_| "generate download ticket key")?;
        let token_cipher = CredentialCipher::derive(&download_ticket_key, "session-token-v1");
        Ok(Self {
            admin: AdminService::new(Arc::clone(&registry), admin_token.as_bytes().to_vec()),
            registry,
            admin_token: Zeroizing::new(admin_token),
            downloads: DownloadService::new(downloads_directory.clone()),
            downloads_directory,
            trust_proxy_headers,
            download_ticket_key: Zeroizing::new(download_ticket_key),
            token_cipher,
            sessions: SessionStore::default(),
            abuse: None,
        })
    }

    pub fn set_abuse_guard(&mut self, abuse: Option<Arc<AbuseGuard>>) {
        self.abuse = abuse;
    }

    pub async fn handle(&self, request: &RequestContext) -> Option<Response> {
        let now = unix_time_now();
        match request.path.as_str() {
            PORTAL_JOIN_SCRIPT_PATH => Some(serve_portal_script(request, PORTAL_JOIN_SCRIPT)),
            PORTAL_CLIENT_SCRIPT_PATH => Some(serve_portal_script(request, PORTAL_CLIENT_SCRIPT)),
            "/join" => {
                if !request.is_get_or_head() {
                    Some(Response::not_found())
                } else {
                    Some(join_response(request, "", 200))
                }
            }
            "/join/redeem" => {
                if request.method != "POST" {
                    Some(Response::not_found())
                } else {
                    Some(self.redeem_client_access(request, now))
                }
            }
            "/access" if request.is_get_or_head() => {
                Some(access_page_response(request, false, 200))
            }
            "/access" if request.method == "POST" => Some(self.sign_in(request, now)),
            "/portal/logout" if request.method == "POST" => Some(self.sign_out(request)),
            "/portal/admin" => Some(self.serve_admin_page(request, now).await),
            "/portal/downloads" => Some(self.serve_downloads_page(request, now)),
            path if path.starts_with("/api/") => self.serve_admin_api(request, now).await,
            path if path.starts_with(CLIENT_DOWNLOAD_PREFIX) => {
                Some(self.serve_download(request, now))
            }
            _ => None,
        }
    }

    fn sign_in(&self, request: &RequestContext, now: u64) -> Response {
        let Some(form) = parse_form(&request.body, 4 << 10) else {
            return access_page_response(request, true, 401);
        };
        let token = form
            .iter()
            .find_map(|(key, value)| (key == "token").then_some(value.trim()))
            .unwrap_or_default();
        if !(16..=512).contains(&token.len()) {
            return access_page_response(request, true, 401);
        }
        let reservation = match self.reserve_authentication(request, Surface::Portal) {
            Ok(reservation) => reservation,
            Err(mut response) => {
                response.set_header("Retry-After", "5");
                return response;
            }
        };
        if !self.admin_token.is_empty()
            && constant_time_eq(token.as_bytes(), self.admin_token.as_bytes())
        {
            if let Some(reservation) = reservation {
                reservation.refund();
            }
            return self.start_session(PortalSession::admin(now), "/portal/admin", now);
        }
        let session = match self.client_session(token, now) {
            Ok(session) => session,
            Err(RegistryError::Unauthorized | RegistryError::Disabled) => {
                return access_page_response(request, true, 401)
            }
            Err(_) => {
                return Response::text(
                    503,
                    "text/plain; charset=utf-8",
                    b"service unavailable\n".to_vec(),
                )
            }
        };
        if let Some(reservation) = reservation {
            reservation.refund();
        }
        self.start_session(session, "/portal/downloads", now)
    }

    fn reserve_authentication(
        &self,
        request: &RequestContext,
        surface: Surface,
    ) -> Result<Option<crate::ops::abuse::Reservation<'_>>, Response> {
        let Some(abuse) = &self.abuse else {
            return Ok(None);
        };
        let address = request
            .client_ip
            .or(request.peer_ip)
            .unwrap_or_else(|| std::net::Ipv4Addr::UNSPECIFIED.into());
        abuse
            .reserve(surface, address)
            .map(Some)
            .ok_or_else(|| match surface {
                Surface::Portal => access_page_response(request, true, 429),
                Surface::Invitation => join_response(request, CLIENT_ACCESS_ERROR, 429),
                _ => Response::not_found(),
            })
    }

    fn client_session(&self, token: &str, now: u64) -> Result<PortalSession, RegistryError> {
        let identity = self.registry.authenticate_portal(token)?;
        let token_hash = hash_token(token);
        let encrypted_token = self
            .token_cipher
            .seal(token.as_bytes(), &format!("{}\n{token_hash}", identity.id))
            .map_err(|_| RegistryError::Internal)?;
        Ok(PortalSession {
            role: PortalRole::Client,
            client_id: identity.id,
            client_name: identity.name,
            token_hash,
            encrypted_token,
            expires_at: now.saturating_add(PORTAL_SESSION_TTL_SECS),
        })
    }

    fn start_session(&self, session: PortalSession, destination: &str, now: u64) -> Response {
        match self.sessions.start(session, now) {
            Ok((_, cookie)) => {
                let mut response = Response::redirect(destination);
                response.set_header("Set-Cookie", cookie);
                response
            }
            Err(_) => Response::text(
                503,
                "text/plain; charset=utf-8",
                b"service unavailable\n".to_vec(),
            ),
        }
    }

    fn sign_out(&self, request: &RequestContext) -> Response {
        if let Some(id) = request.cookie(PORTAL_COOKIE_NAME) {
            self.sessions.remove(id);
        }
        let mut response = Response::redirect("/");
        response.set_header("Set-Cookie", expired_session_cookie());
        response
    }

    async fn serve_admin_page(&self, request: &RequestContext, now: u64) -> Response {
        if !request.is_get_or_head() {
            return Response::not_found();
        }
        if self
            .session(request, now)
            .is_none_or(|session| session.role != PortalRole::Admin)
        {
            return Response::redirect("/");
        }
        let mut admin_request = request.clone();
        admin_request.path = "/".into();
        self.admin
            .handle(&admin_request, true)
            .await
            .unwrap_or_else(Response::not_found)
    }

    async fn serve_admin_api(&self, request: &RequestContext, now: u64) -> Option<Response> {
        if self
            .session(request, now)
            .is_none_or(|session| session.role != PortalRole::Admin)
        {
            return if request.is_get_or_head() {
                None
            } else {
                Some(Response::not_found())
            };
        }
        if !request.is_get_or_head()
            && !same_origin_portal_request(request, self.trust_proxy_headers)
        {
            return Some(Response::text(
                403,
                "text/plain; charset=utf-8",
                b"invalid request origin\n".to_vec(),
            ));
        }
        self.admin.handle(request, true).await
    }

    fn serve_downloads_page(&self, request: &RequestContext, now: u64) -> Response {
        if !request.is_get_or_head() {
            return Response::not_found();
        }
        let Some(session) = self.session(request, now) else {
            return Response::redirect("/");
        };
        let name = if session.role == PortalRole::Admin {
            "Administrator".to_owned()
        } else {
            session.client_name.clone()
        };
        let mut profile = None;
        if request.method == "GET" && session.role == PortalRole::Client {
            let binding = format!("{}\n{}", session.client_id, session.token_hash);
            let token = match self
                .token_cipher
                .open(&session.encrypted_token, &binding, 4096)
            {
                Ok(token) if hash_token(&String::from_utf8_lossy(&token)) == session.token_hash => {
                    String::from_utf8_lossy(&token).into_owned()
                }
                _ => {
                    return Response::text(
                        503,
                        "text/plain; charset=utf-8",
                        b"profile configuration unavailable; sign in again\n".to_vec(),
                    )
                }
            };
            let origin = match client_access_origin(&format!(
                "https://{}",
                portal_request_host(request, self.trust_proxy_headers)
            )) {
                Ok(origin) => origin,
                Err(_) => {
                    return Response::text(
                        503,
                        "text/plain; charset=utf-8",
                        b"public server address is invalid\n".to_vec(),
                    )
                }
            };
            let input = ProfileQrInput {
                name: session.client_name.clone(),
                server: origin.clone(),
                token: token.clone(),
            };
            let mut value = DownloadProfile {
                server: origin,
                token,
                ..DownloadProfile::default()
            };
            match profile_qr_payload(&input) {
                Ok(payload) => {
                    value.setup_uri = payload.clone();
                    match qr_code_data_uri(&payload) {
                        Ok(image) => value.qr_code = image,
                        Err(_) => value.notice = "QR setup is unavailable for this credential. Use the server and token for manual setup.".into(),
                    }
                }
                Err(_) => value.notice = "QR setup is unavailable for this credential. Use the server and token for manual setup.".into(),
            }
            profile = Some(value);
        }
        let artifacts = available_downloads(&self.downloads_directory);
        let rows = artifacts
            .iter()
            .map(|artifact| {
                let ticket = self.issue_download_ticket(&artifact.name, now + DOWNLOAD_TICKET_TTL_SECS);
                let recommended = if artifact.recommended { "<span class=\"recommended\">Recommended</span>" } else { "" };
                format!(
                    "<article class=\"download-row\"><div class=\"platform-icon\">{}</div><div class=\"package\"><div class=\"platform-line\"><h2>{}</h2>{recommended}</div><p>{}</p></div><div class=\"meta\"><span>{}</span><span>{}</span></div><a class=\"download-button\" href=\"/download/{}?ticket={}\" download>Download <span>↓</span></a></article>",
                    artifact.platform.chars().next().unwrap_or('?'),
                    html_escape(artifact.platform),
                    html_escape(artifact.description),
                    html_escape(artifact.architecture),
                    format_download_size(artifact.size),
                    artifact.name,
                    html_escape(&ticket),
                )
            })
            .collect::<String>();
        let rows = if rows.is_empty() {
            "<div class=\"empty\"><strong>Downloads are being prepared.</strong><span>Check back shortly.</span></div>".into()
        } else {
            rows
        };
        let release_tickets = ReleaseDownloadTickets {
            checksums: self.issue_download_ticket("SHA256SUMS", now + DOWNLOAD_TICKET_TTL_SECS),
            signature: self.issue_download_ticket("SHA256SUMS.sig", now + DOWNLOAD_TICKET_TTL_SECS),
            certificate: self
                .issue_download_ticket("release-signing-cert.der", now + DOWNLOAD_TICKET_TTL_SECS),
        };
        let body = downloads_page_html(
            &name,
            &portal_request_host(request, self.trust_proxy_headers),
            &read_download_version(&self.downloads_directory),
            &rows,
            &release_tickets,
            profile.as_ref(),
        );
        let mut response = Response::html(200, body.into_bytes());
        response.set_header("Cache-Control", "no-store");
        set_portal_security_headers(&mut response);
        response.without_body_for_head(request)
    }

    fn serve_download(&self, request: &RequestContext, now: u64) -> Response {
        if self.session(request, now).is_none() {
            let name = request
                .path
                .strip_prefix(CLIENT_DOWNLOAD_PREFIX)
                .unwrap_or_default();
            let ticket = query_parameter(&request.query, "ticket").unwrap_or_default();
            if !self.valid_download_ticket(name, &ticket, now) {
                return Response::not_found();
            }
        }
        self.downloads
            .handle(request)
            .unwrap_or_else(Response::not_found)
    }

    fn session(&self, request: &RequestContext, now: u64) -> Option<PortalSession> {
        let id = request.cookie(PORTAL_COOKIE_NAME)?;
        let session = self.sessions.get(id, now)?;
        if session.role == PortalRole::Client
            && !self
                .registry
                .portal_client_active(&session.client_id, &session.token_hash)
        {
            self.sessions.remove(id);
            return None;
        }
        Some(session)
    }

    pub fn issue_download_ticket(&self, name: &str, expires_at: u64) -> String {
        let expires = expires_at.to_be_bytes();
        let mut data = Vec::with_capacity(name.len() + 9);
        data.extend_from_slice(name.as_bytes());
        data.push(0);
        data.extend_from_slice(&expires);
        let mac = hmac_sha256(self.download_ticket_key.as_slice(), &data);
        let mut payload = Vec::with_capacity(40);
        payload.extend_from_slice(&expires);
        payload.extend_from_slice(&mac);
        URL_SAFE_NO_PAD.encode(payload)
    }

    pub fn valid_download_ticket(&self, name: &str, ticket: &str, now: u64) -> bool {
        let Ok(payload) = URL_SAFE_NO_PAD.decode(ticket) else {
            return false;
        };
        if payload.len() != 40 {
            return false;
        }
        let expires_at = u64::from_be_bytes(payload[..8].try_into().expect("ticket expiry"));
        if now > expires_at {
            return false;
        }
        let expected = self.issue_download_ticket(name, expires_at);
        super::session::constant_time_eq(expected.as_bytes(), ticket.as_bytes())
    }

    fn redeem_client_access(&self, request: &RequestContext, now: u64) -> Response {
        if !same_origin_portal_request(request, self.trust_proxy_headers) {
            return join_response(request, CLIENT_ACCESS_ERROR, 403);
        }
        if !request.query.is_empty() {
            return join_response(request, CLIENT_ACCESS_ERROR, 400);
        }
        let Some(form) = parse_form(&request.body, 4 << 10) else {
            return join_response(request, CLIENT_ACCESS_ERROR, 400);
        };
        if form.len() != 1 || form[0].0 != "ticket" {
            return join_response(request, CLIENT_ACCESS_ERROR, 400);
        }
        let origin = match client_access_origin(&format!(
            "https://{}",
            portal_request_host(request, self.trust_proxy_headers)
        )) {
            Ok(origin) => origin,
            Err(_) => return join_response(request, CLIENT_ACCESS_ERROR, 400),
        };
        let reservation = match self.reserve_authentication(request, Surface::Invitation) {
            Ok(reservation) => reservation,
            Err(mut response) => {
                response.set_header("Retry-After", "5");
                return response;
            }
        };
        let claim = match open_client_access(&self.admin_token, &origin, &form[0].1) {
            Ok(claim) => claim,
            Err(_) => return join_response(request, CLIENT_ACCESS_ERROR, 401),
        };
        let session = match self.client_session(&claim.token, now) {
            Ok(session) if session.client_id == claim.client_id => session,
            Ok(_) | Err(RegistryError::Unauthorized | RegistryError::Disabled) => {
                return join_response(request, CLIENT_ACCESS_ERROR, 401)
            }
            Err(_) => {
                return join_response(request, "Service unavailable. Please try again later.", 503)
            }
        };
        if let Some(reservation) = reservation {
            reservation.refund();
        }
        self.start_session(session, "/portal/downloads", now)
    }
}

pub fn create_client_access(
    registry: &dyn ClientRegistry,
    admin_token: &str,
    input: ClientAccessInput,
) -> Response {
    let origin = match client_access_origin(&input.origin) {
        Ok(origin) => origin,
        Err(_) => return error_json(400, "A valid public HTTPS origin is required"),
    };
    if !(16..=512).contains(&input.token.len()) {
        return error_json(400, "Invalid client token");
    }
    let identity = match registry.authenticate_portal(&input.token) {
        Ok(identity) => identity,
        Err(_) => return error_json(400, "Client access is not available for this token"),
    };
    if let Err(message) = profile_qr_payload(&ProfileQrInput {
        name: identity.name,
        server: origin.clone(),
        token: input.token.clone(),
    }) {
        return error_json(400, message);
    }
    let ticket = match seal_client_access(
        admin_token,
        &origin,
        &ClientAccessClaim {
            client_id: identity.id,
            token: input.token,
            expires_at: None,
        },
    ) {
        Ok(ticket) => ticket,
        Err(_) => return error_json(500, "Unable to create client access"),
    };
    let link = format!("{origin}/join#invite={ticket}");
    if link.len() > 2048 {
        return error_json(400, "Client access link is too large for a QR code");
    }
    let image = match qr_code_data_uri(&link) {
        Ok(image) => image,
        Err(_) => return error_json(500, "Unable to create access QR code"),
    };
    json_response(200, &serde_json::json!({ "url": link, "image": image }))
}

fn error_json(status: u16, message: &str) -> Response {
    json_response(status, &serde_json::json!({ "error": message }))
}

pub fn seal_client_access(
    admin_token: &str,
    origin: &str,
    claim: &ClientAccessClaim,
) -> Result<String, &'static str> {
    if admin_token.len() < 16 {
        return Err(CLIENT_ACCESS_ERROR);
    }
    let value = serde_json::to_vec(claim).map_err(|_| CLIENT_ACCESS_ERROR)?;
    CredentialCipher::derive(admin_token.as_bytes(), "client-access-v1")
        .seal(&value, &format!("client-access-v1\n{origin}"))
        .map_err(|_| CLIENT_ACCESS_ERROR)
}

pub fn open_client_access(
    admin_token: &str,
    origin: &str,
    ticket: &str,
) -> Result<ClientAccessClaim, &'static str> {
    if admin_token.len() < 16 {
        return Err(CLIENT_ACCESS_ERROR);
    }
    let value = CredentialCipher::derive(admin_token.as_bytes(), "client-access-v1")
        .open(ticket, &format!("client-access-v1\n{origin}"), 4096)
        .map_err(|_| CLIENT_ACCESS_ERROR)?;
    let mut decoder = serde_json::Deserializer::from_slice(&value);
    let claim = ClientAccessClaim::deserialize(&mut decoder).map_err(|_| CLIENT_ACCESS_ERROR)?;
    decoder.end().map_err(|_| CLIENT_ACCESS_ERROR)?;
    if claim.client_id.is_empty() || !(16..=512).contains(&claim.token.len()) {
        return Err(CLIENT_ACCESS_ERROR);
    }
    Ok(claim)
}

pub fn client_access_origin(origin: &str) -> Result<String, &'static str> {
    let parsed = parse_https_origin(origin).ok_or(CLIENT_ACCESS_ERROR)?;
    let host = parsed.host.to_ascii_lowercase();
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    if parsed.port.is_some_and(|port| port != 443) {
        Ok(format!("https://{host}:{}", parsed.port.unwrap()))
    } else {
        Ok(format!("https://{host}"))
    }
}

struct ParsedOrigin {
    host: String,
    port: Option<u16>,
}

fn parse_https_origin(value: &str) -> Option<ParsedOrigin> {
    if value.len() > 512
        || value.trim() != value
        || !value.starts_with("https://")
        || value.contains('?')
        || value.contains('#')
        || value.contains('@')
    {
        return None;
    }
    let authority = value.strip_prefix("https://")?;
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    if authority.is_empty() || authority.contains('/') {
        return None;
    }
    let (host, port) = if authority.starts_with('[') {
        let close = authority.find(']')?;
        let host = &authority[1..close];
        if !host.contains(':') || host.parse::<IpAddr>().ok()?.is_ipv4() {
            return None;
        }
        let suffix = &authority[close + 1..];
        let port = if suffix.is_empty() {
            None
        } else {
            Some(suffix.strip_prefix(':')?.parse::<u16>().ok()?)
        };
        (host, port)
    } else {
        if authority.matches(':').count() > 1 {
            return None;
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port.parse::<u16>().ok()?)),
            None => (authority, None),
        };
        if host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_ipv6())
        {
            return None;
        }
        (host, port)
    };
    if port == Some(0) || !valid_profile_qr_host(host) {
        return None;
    }
    Some(ParsedOrigin {
        host: host.into(),
        port,
    })
}

fn valid_profile_qr_host(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    let labels = host.split('.').collect::<Vec<_>>();
    for label in &labels {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return false;
        }
    }
    labels.len() == 1
        || labels
            .last()
            .and_then(|label| label.bytes().next())
            .is_some_and(|byte| byte.is_ascii_alphabetic())
}

pub fn profile_qr_payload(input: &ProfileQrInput) -> Result<String, &'static str> {
    if parse_https_origin(&input.server).is_none() {
        return Err(
            "Enter a valid HTTPS server origin, without a path, credentials, query, or fragment",
        );
    }
    if input.token.is_empty()
        || input.token.len() > 512
        || input.token.trim() != input.token
        || !input
            .token
            .bytes()
            .all(|character| (b' '..=b'~').contains(&character))
    {
        return Err("Invalid client token");
    }
    if input.name.len() > 80
        || input.name.trim() != input.name
        || input.name.chars().any(char::is_control)
    {
        return Err("Invalid profile name");
    }
    let mut parameters = Vec::with_capacity(4);
    if !input.name.is_empty() {
        parameters.push(format!("name={}", form_urlencode(&input.name)));
    }
    parameters.push(format!("server={}", form_urlencode(&input.server)));
    parameters.push(format!("token={}", form_urlencode(&input.token)));
    parameters.push("v=1".into());
    let payload = format!("porta://profile?{}", parameters.join("&"));
    if payload.len() > 2048 {
        return Err("Profile is too large for a QR code");
    }
    Ok(payload)
}

pub fn profile_qr_code(input: &ProfileQrInput) -> Result<String, &'static str> {
    let payload = profile_qr_payload(input)?;
    qr_code_data_uri(&payload).map_err(|_| "Unable to generate profile QR code")
}

pub fn same_origin_portal_request(request: &RequestContext, trust_proxy_headers: bool) -> bool {
    let Some(origin) = request.header("origin") else {
        return true;
    };
    let Some(parsed) = parse_https_origin(origin) else {
        return false;
    };
    let origin_host = if parsed.host.contains(':') {
        format!(
            "[{}]{}",
            parsed.host,
            parsed.port.map_or(String::new(), |port| format!(":{port}"))
        )
    } else {
        format!(
            "{}{}",
            parsed.host,
            parsed.port.map_or(String::new(), |port| format!(":{port}"))
        )
    };
    origin_host.eq_ignore_ascii_case(&portal_request_host(request, trust_proxy_headers))
}

pub fn portal_request_host(request: &RequestContext, trust_proxy_headers: bool) -> String {
    if trust_proxy_headers && request.peer_ip.is_some_and(|address| address.is_loopback()) {
        if let Some(host) = request.header("x-forwarded-host").map(str::trim) {
            if !host.is_empty() && !host.contains(',') {
                return host.to_owned();
            }
        }
    }
    request.host.clone()
}

#[derive(Clone)]
struct DownloadArtifact {
    name: String,
    platform: &'static str,
    architecture: &'static str,
    description: &'static str,
    size: u64,
    recommended: bool,
}

struct ReleaseDownloadTickets {
    checksums: String,
    signature: String,
    certificate: String,
}

const DOWNLOAD_CATALOG: &[(&str, &str, &str, &str, bool)] = &[
    (
        "porta-client-windows-amd64.zip",
        "Windows",
        "x86-64",
        "Desktop app, command line client, and Wintun runtime",
        true,
    ),
    (
        "porta-android-arm64-v8a.apk",
        "Android",
        "ARM64",
        "For most modern Android phones and tablets",
        false,
    ),
    (
        "porta-client-linux-amd64",
        "Linux",
        "x86-64",
        "Command line client for Intel and AMD systems",
        false,
    ),
    (
        "porta-client-linux-arm64",
        "Linux",
        "ARM64",
        "Command line client for ARM servers and devices",
        false,
    ),
    (
        "porta-android-armeabi-v7a.apk",
        "Android",
        "ARMv7",
        "For older 32-bit Android devices",
        false,
    ),
    (
        "porta-android-x86_64.apk",
        "Android",
        "x86-64",
        "For Android emulators and x86-64 devices",
        false,
    ),
];

fn available_downloads(directory: &str) -> Vec<DownloadArtifact> {
    DOWNLOAD_CATALOG
        .iter()
        .filter_map(|(name, platform, architecture, description, recommended)| {
            let file = open_download_file(directory, name).ok()?;
            let metadata = file.metadata().ok()?;
            metadata.is_file().then(|| DownloadArtifact {
                name: (*name).into(),
                platform,
                architecture,
                description,
                size: metadata.len(),
                recommended: *recommended,
            })
        })
        .collect()
}

fn read_download_version(directory: &str) -> String {
    let Ok(file) = open_download_file(directory, "CLIENT_VERSION") else {
        return "Unknown".into();
    };
    let mut value = String::new();
    if file.take(128).read_to_string(&mut value).is_err() || value.trim().is_empty() {
        "Unknown".into()
    } else {
        value.trim().into()
    }
}

pub fn format_download_size(size: u64) -> String {
    if size >= 1024 * 1024 {
        format!("{:.1} MB", size as f64 / (1024.0 * 1024.0))
    } else if size >= 1024 {
        format!("{:.0} KB", size as f64 / 1024.0)
    } else {
        format!("{size} B")
    }
}

fn access_page_response(request: &RequestContext, invalid: bool, status: u16) -> Response {
    let message = if invalid {
        "<p class=\"error\" role=\"alert\">Access could not be verified.</p>"
    } else {
        ""
    };
    let body = render_asset_template(PORTAL_ACCESS_HTML, &[("%%PORTA_ACCESS_MESSAGE%%", message)]);
    let mut response = Response::html(status, body.into_bytes());
    response.set_header("Cache-Control", "no-store");
    set_portal_security_headers(&mut response);
    response.without_body_for_head(request)
}

fn join_response(request: &RequestContext, message: &str, status: u16) -> Response {
    let state = if message.is_empty() { "auto" } else { "error" };
    let heading = if message.is_empty() {
        "Opening downloads"
    } else {
        "Link unavailable"
    };
    let detail = if message.is_empty() {
        "Preparing your private access. No access key needed."
    } else {
        message
    };
    let detail = html_escape(detail);
    let body = render_asset_template(
        PORTAL_JOIN_HTML,
        &[
            ("%%PORTA_JOIN_STATE%%", state),
            ("%%PORTA_JOIN_HEADING%%", heading),
            ("%%PORTA_JOIN_DETAIL%%", &detail),
        ],
    );
    let mut response = Response::html(status, body.into_bytes());
    response.set_header("Cache-Control", "no-store");
    response.set_header("Referrer-Policy", "same-origin");
    set_portal_security_headers_without_referrer(&mut response);
    response.without_body_for_head(request)
}

fn serve_portal_script(request: &RequestContext, script: &str) -> Response {
    if !request.is_get_or_head() {
        return Response::not_found();
    }
    let mut response = Response::text(
        200,
        "text/javascript; charset=utf-8",
        script.as_bytes().to_vec(),
    );
    response.set_header("Cache-Control", "no-cache");
    set_portal_security_headers(&mut response);
    response.without_body_for_head(request)
}

fn client_setup_html(profile: Option<&DownloadProfile>) -> String {
    let Some(profile) = profile else {
        return String::new();
    };
    let qr = profile
        .qr_code
        .strip_prefix("data:image/png;base64,")
        .and_then(|encoded| STANDARD.decode(encoded).ok())
        .filter(|image| !image.is_empty())
        .map(|_| format!("<img id=\"setup-qr\" class=\"setup-qr\" src=\"{}\" alt=\"Private Porta profile QR code containing your server and token\">", html_escape(&profile.qr_code)))
        .unwrap_or_else(|| "<p class=\"setup-unavailable\">Profile QR unavailable. Use the server and token below to add your profile manually.</p>".into());
    let notice = if profile.notice.is_empty() {
        String::new()
    } else {
        format!(
            "<p class=\"setup-notice\">{}</p>",
            html_escape(&profile.notice)
        )
    };
    let setup = if profile.setup_uri.is_empty() {
        String::new()
    } else {
        format!(
            "<div class=\"setup-phone\"><p>On this phone: copy setup, then <strong>Add profile &gt; Paste setup</strong> in Porta. Review and save.</p><input id=\"setup-uri\" type=\"hidden\" value=\"{}\"><button id=\"setup-copy-uri\" type=\"button\">Copy setup</button></div>",
            html_escape(&profile.setup_uri)
        )
    };
    let server = html_escape(&profile.server);
    let token = html_escape(&profile.token);
    render_asset_template(
        PORTAL_CLIENT_SETUP_HTML,
        &[
            ("%%PORTA_SETUP_NOTICE%%", &notice),
            ("%%PORTA_SETUP_QR%%", &qr),
            ("%%PORTA_SETUP_COPY%%", &setup),
            ("%%PORTA_SETUP_SERVER%%", &server),
            ("%%PORTA_SETUP_TOKEN%%", &token),
        ],
    )
}

fn render_asset_template(template: &str, replacements: &[(&str, &str)]) -> String {
    let mut rendered = String::with_capacity(template.len());
    let mut index = 0;
    while index < template.len() {
        let rest = &template[index..];
        if let Some((token, value)) = replacements
            .iter()
            .find(|(token, _)| rest.starts_with(*token))
        {
            rendered.push_str(value);
            index += token.len();
            continue;
        }
        let character = rest
            .chars()
            .next()
            .expect("template slice should not be empty");
        rendered.push(character);
        index += character.len_utf8();
    }
    rendered
}

fn downloads_page_html(
    client_name: &str,
    host: &str,
    version: &str,
    rows: &str,
    release_tickets: &ReleaseDownloadTickets,
    profile: Option<&DownloadProfile>,
) -> String {
    let version = html_escape(version);
    let client_name = html_escape(client_name);
    let host = html_escape(host);
    let setup = client_setup_html(profile);
    let checksums = html_escape(&release_tickets.checksums);
    let signature = html_escape(&release_tickets.signature);
    let certificate = html_escape(&release_tickets.certificate);
    render_asset_template(
        PORTAL_DOWNLOADS_HTML,
        &[
            ("%%PORTA_VERSION%%", &version),
            ("%%PORTA_CLIENT_NAME%%", &client_name),
            ("%%PORTA_HOST%%", &host),
            ("%%PORTA_DOWNLOAD_ROWS%%", rows),
            ("%%PORTA_CLIENT_SETUP%%", &setup),
            ("%%PORTA_CHECKSUMS_TICKET%%", &checksums),
            ("%%PORTA_SIGNATURE_TICKET%%", &signature),
            ("%%PORTA_CERTIFICATE_TICKET%%", &certificate),
        ],
    )
}

pub fn set_portal_security_headers(response: &mut Response) {
    set_portal_security_headers_without_referrer(response);
    response.set_header("Referrer-Policy", "no-referrer");
}

fn set_portal_security_headers_without_referrer(response: &mut Response) {
    set_crawler_policy(response);
    response.set_header(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    );
    response.set_header("X-Content-Type-Options", "nosniff");
    response.set_header("X-Frame-Options", "DENY");
}

fn query_parameter(query: &str, key: &str) -> Option<String> {
    parse_form(query.as_bytes(), 8192)?
        .into_iter()
        .find_map(|(candidate, value)| (candidate == key).then_some(value))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn qr_code_data_uri(payload: &str) -> Result<String, ()> {
    let qr = QrCode::encode(payload.as_bytes())?;
    Ok(format!(
        "data:image/png;base64,{}",
        STANDARD.encode(qr.to_png(512))
    ))
}

// Compact QR Model 2 byte-mode encoder (medium error correction). The implementation
// follows ISO/IEC 18004 and keeps QR generation local, so invitation credentials are
// never sent to an external image service.
struct QrCode {
    version: usize,
    size: usize,
    modules: Vec<bool>,
    function: Vec<bool>,
}

impl QrCode {
    fn encode(data: &[u8]) -> Result<Self, ()> {
        let version = (1..=40)
            .find(|version| {
                let count_bits = if *version <= 9 { 8 } else { 16 };
                4 + count_bits + data.len() * 8 <= qr_data_codewords(*version) * 8
                    && data.len() < (1_usize << count_bits)
            })
            .ok_or(())?;
        let capacity = qr_data_codewords(version);
        let mut bits = Vec::with_capacity(capacity * 8);
        append_bits(&mut bits, 0b0100, 4);
        append_bits(
            &mut bits,
            data.len() as u32,
            if version <= 9 { 8 } else { 16 },
        );
        for byte in data {
            append_bits(&mut bits, u32::from(*byte), 8);
        }
        bits.resize((bits.len() + 4).min(capacity * 8), false);
        while bits.len() % 8 != 0 {
            bits.push(false);
        }
        let mut codewords = pack_bits(&bits);
        for pad in [0xec, 0x11].into_iter().cycle() {
            if codewords.len() >= capacity {
                break;
            }
            codewords.push(pad);
        }
        let size = version * 4 + 17;
        let mut qr = Self {
            version,
            size,
            modules: vec![false; size * size],
            function: vec![false; size * size],
        };
        qr.draw_function_patterns();
        let all = qr.add_ecc_and_interleave(&codewords);
        qr.draw_codewords(&all);
        let mut best_mask = 0;
        let mut best_penalty = u32::MAX;
        for mask in 0..8 {
            qr.apply_mask(mask);
            qr.draw_format_bits(mask);
            let penalty = qr.penalty();
            if penalty < best_penalty {
                best_penalty = penalty;
                best_mask = mask;
            }
            qr.apply_mask(mask);
        }
        qr.apply_mask(best_mask);
        qr.draw_format_bits(best_mask);
        Ok(qr)
    }

    fn index(&self, x: usize, y: usize) -> usize {
        y * self.size + x
    }

    fn set_function(&mut self, x: usize, y: usize, dark: bool) {
        let index = self.index(x, y);
        self.modules[index] = dark;
        self.function[index] = true;
    }

    fn draw_function_patterns(&mut self) {
        for coordinate in 0..self.size {
            self.set_function(6, coordinate, coordinate % 2 == 0);
            self.set_function(coordinate, 6, coordinate % 2 == 0);
        }
        self.draw_finder(3, 3);
        self.draw_finder(self.size - 4, 3);
        self.draw_finder(3, self.size - 4);
        let align = self.alignment_positions();
        for (row, y) in align.iter().enumerate() {
            for (column, x) in align.iter().enumerate() {
                let last = align.len() - 1;
                if !((row == 0 && (column == 0 || column == last)) || (row == last && column == 0))
                {
                    self.draw_alignment(*x, *y);
                }
            }
        }
        self.draw_format_bits(0);
        self.draw_version();
    }

    fn draw_finder(&mut self, center_x: usize, center_y: usize) {
        for dy in -4_i32..=4 {
            for dx in -4_i32..=4 {
                let x = center_x as i32 + dx;
                let y = center_y as i32 + dy;
                if x >= 0 && y >= 0 && x < self.size as i32 && y < self.size as i32 {
                    let distance = dx.abs().max(dy.abs());
                    self.set_function(x as usize, y as usize, distance != 2 && distance != 4);
                }
            }
        }
    }

    fn draw_alignment(&mut self, center_x: usize, center_y: usize) {
        for dy in -2_i32..=2 {
            for dx in -2_i32..=2 {
                self.set_function(
                    (center_x as i32 + dx) as usize,
                    (center_y as i32 + dy) as usize,
                    dx.abs().max(dy.abs()) != 1,
                );
            }
        }
    }

    fn alignment_positions(&self) -> Vec<usize> {
        if self.version == 1 {
            return Vec::new();
        }
        let count = self.version / 7 + 2;
        let step = (self.version * 8 + count * 3 + 5) / (count * 4 - 4) * 2;
        let mut result = (0..count - 1)
            .map(|index| self.size - 7 - index * step)
            .collect::<Vec<_>>();
        result.push(6);
        result.reverse();
        result
    }

    fn draw_format_bits(&mut self, mask: usize) {
        let data = mask as u32;
        let mut remainder = data;
        for _ in 0..10 {
            remainder = (remainder << 1) ^ ((remainder >> 9) * 0x537);
        }
        let bits = (data << 10 | remainder) ^ 0x5412;
        for index in 0..6 {
            self.set_function(8, index, bit(bits, index));
        }
        self.set_function(8, 7, bit(bits, 6));
        self.set_function(8, 8, bit(bits, 7));
        self.set_function(7, 8, bit(bits, 8));
        for index in 9..15 {
            self.set_function(14 - index, 8, bit(bits, index));
        }
        for index in 0..8 {
            self.set_function(self.size - 1 - index, 8, bit(bits, index));
        }
        for index in 8..15 {
            self.set_function(8, self.size - 15 + index, bit(bits, index));
        }
        self.set_function(8, self.size - 8, true);
    }

    fn draw_version(&mut self) {
        if self.version < 7 {
            return;
        }
        let data = self.version as u32;
        let mut remainder = data;
        for _ in 0..12 {
            remainder = (remainder << 1) ^ ((remainder >> 11) * 0x1f25);
        }
        let bits = data << 12 | remainder;
        for index in 0..18 {
            let a = self.size - 11 + index % 3;
            let b = index / 3;
            self.set_function(a, b, bit(bits, index));
            self.set_function(b, a, bit(bits, index));
        }
    }

    fn add_ecc_and_interleave(&self, data: &[u8]) -> Vec<u8> {
        let blocks = QR_MEDIUM_BLOCKS[self.version] as usize;
        let ecc_len = QR_MEDIUM_ECC[self.version] as usize;
        let raw = qr_raw_modules(self.version) / 8;
        let short_blocks = blocks - raw % blocks;
        let short_len = raw / blocks;
        let divisor = reed_solomon_divisor(ecc_len);
        let mut offset = 0;
        let mut split = Vec::with_capacity(blocks);
        for block_index in 0..blocks {
            let data_len = short_len - ecc_len + usize::from(block_index >= short_blocks);
            let mut block = data[offset..offset + data_len].to_vec();
            offset += data_len;
            let ecc = reed_solomon_remainder(&block, &divisor);
            if block_index < short_blocks {
                block.push(0);
            }
            block.extend_from_slice(&ecc);
            split.push(block);
        }
        let mut result = Vec::with_capacity(raw);
        for index in 0..=short_len {
            for (block_index, block) in split.iter().enumerate() {
                if index != short_len - ecc_len || block_index >= short_blocks {
                    result.push(block[index]);
                }
            }
        }
        result
    }

    fn draw_codewords(&mut self, data: &[u8]) {
        let mut bit_index = 0;
        let mut right = self.size - 1;
        while right >= 1 {
            if right == 6 {
                right = 5;
            }
            for vertical in 0..self.size {
                for offset in 0..2 {
                    let x = right - offset;
                    let upward = (right + 1) & 2 == 0;
                    let y = if upward {
                        self.size - 1 - vertical
                    } else {
                        vertical
                    };
                    let index = self.index(x, y);
                    if !self.function[index] && bit_index < data.len() * 8 {
                        self.modules[index] =
                            ((data[bit_index >> 3] >> (7 - (bit_index & 7))) & 1) != 0;
                        bit_index += 1;
                    }
                }
            }
            right = right.saturating_sub(2);
            if right == 0 {
                break;
            }
        }
    }

    fn apply_mask(&mut self, mask: usize) {
        for y in 0..self.size {
            for x in 0..self.size {
                let invert = match mask {
                    0 => (x + y) % 2 == 0,
                    1 => y % 2 == 0,
                    2 => x % 3 == 0,
                    3 => (x + y) % 3 == 0,
                    4 => (x / 3 + y / 2) % 2 == 0,
                    5 => x * y % 2 + x * y % 3 == 0,
                    6 => (x * y % 2 + x * y % 3) % 2 == 0,
                    7 => ((x + y) % 2 + x * y % 3) % 2 == 0,
                    _ => false,
                };
                let index = self.index(x, y);
                if invert && !self.function[index] {
                    self.modules[index] = !self.modules[index];
                }
            }
        }
    }

    fn penalty(&self) -> u32 {
        let mut score = 0;
        for y in 0..self.size {
            score += line_penalty((0..self.size).map(|x| self.modules[self.index(x, y)]));
        }
        for x in 0..self.size {
            score += line_penalty((0..self.size).map(|y| self.modules[self.index(x, y)]));
        }
        for y in 0..self.size - 1 {
            for x in 0..self.size - 1 {
                let color = self.modules[self.index(x, y)];
                if self.modules[self.index(x + 1, y)] == color
                    && self.modules[self.index(x, y + 1)] == color
                    && self.modules[self.index(x + 1, y + 1)] == color
                {
                    score += 3;
                }
            }
        }
        let dark = self.modules.iter().filter(|module| **module).count() as i32;
        let total = (self.size * self.size) as i32;
        score + ((((dark * 20 - total * 10).abs() + total - 1) / total - 1).max(0) * 10) as u32
    }

    fn to_png(&self, dimensions: usize) -> Vec<u8> {
        let border = 4;
        let span = self.size + border * 2;
        let scale = (dimensions / span).max(1);
        let drawn = span * scale;
        let margin = dimensions.saturating_sub(drawn) / 2;
        let row_bytes = dimensions.div_ceil(8);
        let mut image = vec![0xff_u8; (row_bytes + 1) * dimensions];
        for y in 0..dimensions {
            image[y * (row_bytes + 1)] = 0;
        }
        for module_y in 0..self.size {
            for module_x in 0..self.size {
                if !self.modules[self.index(module_x, module_y)] {
                    continue;
                }
                let start_x = margin + (module_x + border) * scale;
                let start_y = margin + (module_y + border) * scale;
                for y in start_y..(start_y + scale).min(dimensions) {
                    for x in start_x..(start_x + scale).min(dimensions) {
                        let byte = y * (row_bytes + 1) + 1 + x / 8;
                        image[byte] &= !(1 << (7 - x % 8));
                    }
                }
            }
        }
        png_grayscale_1bit(dimensions as u32, dimensions as u32, &image)
    }
}

fn append_bits(bits: &mut Vec<bool>, value: u32, count: usize) {
    for index in (0..count).rev() {
        bits.push(((value >> index) & 1) != 0);
    }
}

fn pack_bits(bits: &[bool]) -> Vec<u8> {
    let mut output = vec![0_u8; bits.len() / 8];
    for (index, value) in bits.iter().enumerate() {
        output[index / 8] |= u8::from(*value) << (7 - index % 8);
    }
    output
}

fn bit(value: u32, index: usize) -> bool {
    ((value >> index) & 1) != 0
}

fn qr_raw_modules(version: usize) -> usize {
    let mut result = (16 * version + 128) * version + 64;
    if version >= 2 {
        let align = version / 7 + 2;
        result -= (25 * align - 10) * align - 55;
        if version >= 7 {
            result -= 36;
        }
    }
    result
}

fn qr_data_codewords(version: usize) -> usize {
    qr_raw_modules(version) / 8
        - QR_MEDIUM_ECC[version] as usize * QR_MEDIUM_BLOCKS[version] as usize
}

fn reed_solomon_divisor(degree: usize) -> Vec<u8> {
    let mut result = vec![0_u8; degree];
    result[degree - 1] = 1;
    let mut root = 1_u8;
    for _ in 0..degree {
        for index in 0..degree {
            result[index] = reed_solomon_multiply(result[index], root);
            if index + 1 < degree {
                result[index] ^= result[index + 1];
            }
        }
        root = reed_solomon_multiply(root, 2);
    }
    result
}

fn reed_solomon_remainder(data: &[u8], divisor: &[u8]) -> Vec<u8> {
    let mut result = vec![0_u8; divisor.len()];
    for byte in data {
        let factor = byte ^ result[0];
        result.rotate_left(1);
        *result.last_mut().expect("nonempty divisor") = 0;
        for (value, coefficient) in result.iter_mut().zip(divisor) {
            *value ^= reed_solomon_multiply(*coefficient, factor);
        }
    }
    result
}

fn reed_solomon_multiply(left: u8, right: u8) -> u8 {
    let mut product = 0_u8;
    for index in (0..8).rev() {
        product = (product << 1) ^ ((product >> 7) * 0x1d);
        product ^= ((right >> index) & 1) * left;
    }
    product
}

fn line_penalty<I: Iterator<Item = bool>>(line: I) -> u32 {
    let values = line.collect::<Vec<_>>();
    let mut score = 0;
    let mut run = 1;
    for index in 1..values.len() {
        if values[index] == values[index - 1] {
            run += 1;
            if run == 5 {
                score += 3;
            } else if run > 5 {
                score += 1;
            }
        } else {
            run = 1;
        }
    }
    for window in values.windows(11) {
        let first = [
            true, false, true, true, true, false, true, false, false, false, false,
        ];
        let second = [
            false, false, false, false, true, false, true, true, true, false, true,
        ];
        if window == first || window == second {
            score += 40;
        }
    }
    score
}

fn png_grayscale_1bit(width: u32, height: u32, image: &[u8]) -> Vec<u8> {
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut header = Vec::with_capacity(13);
    header.extend_from_slice(&width.to_be_bytes());
    header.extend_from_slice(&height.to_be_bytes());
    header.extend_from_slice(&[1, 0, 0, 0, 0]);
    png_chunk(&mut png, b"IHDR", &header);
    let mut zlib = vec![0x78, 0x01];
    for (index, chunk) in image.chunks(65_535).enumerate() {
        let final_block = index == image.len().saturating_sub(1) / 65_535;
        zlib.push(u8::from(final_block));
        let length = chunk.len() as u16;
        zlib.extend_from_slice(&length.to_le_bytes());
        zlib.extend_from_slice(&(!length).to_le_bytes());
        zlib.extend_from_slice(chunk);
    }
    zlib.extend_from_slice(&adler32(image).to_be_bytes());
    png_chunk(&mut png, b"IDAT", &zlib);
    png_chunk(&mut png, b"IEND", &[]);
    png
}

fn png_chunk(output: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    output.extend_from_slice(&(data.len() as u32).to_be_bytes());
    output.extend_from_slice(kind);
    output.extend_from_slice(data);
    let start = output.len() - data.len() - 4;
    let checksum = crc32(&output[start..]);
    output.extend_from_slice(&checksum.to_be_bytes());
}

fn crc32(data: &[u8]) -> u32 {
    let mut value = u32::MAX;
    for byte in data {
        value ^= u32::from(*byte);
        for _ in 0..8 {
            value = (value >> 1) ^ (0xedb8_8320 & (0_u32.wrapping_sub(value & 1)));
        }
    }
    !value
}

fn adler32(data: &[u8]) -> u32 {
    let mut first = 1_u32;
    let mut second = 0_u32;
    for byte in data {
        first = (first + u32::from(*byte)) % 65_521;
        second = (second + first) % 65_521;
    }
    second << 16 | first
}

const QR_MEDIUM_ECC: [u8; 41] = [
    0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
];
const QR_MEDIUM_BLOCKS: [u8; 41] = [
    0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23,
    25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::abuse::Policy;
    use crate::ops::metrics::Metrics;
    use crate::web::admin::{ClientIdentity, ClientSummary, DeviceSummary};
    use std::net::Ipv4Addr;
    use std::sync::Mutex;
    use std::time::Duration;

    struct Registry {
        enabled: Mutex<bool>,
        token_hash: Mutex<String>,
    }

    impl Registry {
        fn new(token: &str) -> Self {
            Self {
                enabled: Mutex::new(true),
                token_hash: Mutex::new(hash_token(token)),
            }
        }
    }

    impl ClientRegistry for Registry {
        fn list_clients(&self) -> Result<Vec<ClientSummary>, RegistryError> {
            Ok(Vec::new())
        }
        fn create_client<'a>(
            &'a self,
            _: &'a str,
            _: usize,
        ) -> futures_util::future::BoxFuture<'a, Result<(ClientSummary, String), RegistryError>>
        {
            Box::pin(async { Err(RegistryError::Internal) })
        }
        fn update_client<'a>(
            &'a self,
            _: &'a str,
            _: &'a str,
            _: usize,
            _: bool,
        ) -> futures_util::future::BoxFuture<'a, Result<ClientSummary, RegistryError>> {
            Box::pin(async { Err(RegistryError::Internal) })
        }
        fn delete_client<'a>(
            &'a self,
            _: &'a str,
        ) -> futures_util::future::BoxFuture<'a, Result<(), RegistryError>> {
            Box::pin(async { Err(RegistryError::Internal) })
        }
        fn rotate_client_token<'a>(
            &'a self,
            _: &'a str,
        ) -> futures_util::future::BoxFuture<'a, Result<String, RegistryError>> {
            Box::pin(async { Err(RegistryError::Internal) })
        }
        fn disconnect<'a>(
            &'a self,
            _: &'a str,
            _: Option<&'a str>,
        ) -> futures_util::future::BoxFuture<'a, Result<usize, RegistryError>> {
            Box::pin(async { Ok(0) })
        }
        fn forget_device<'a>(
            &'a self,
            _: &'a str,
            _: &'a str,
        ) -> futures_util::future::BoxFuture<'a, Result<(), RegistryError>> {
            Box::pin(async { Ok(()) })
        }
        fn authenticate_portal(&self, token: &str) -> Result<ClientIdentity, RegistryError> {
            if *self.enabled.lock().unwrap()
                && hash_token(token) == *self.token_hash.lock().unwrap()
            {
                Ok(ClientIdentity {
                    id: "client".into(),
                    name: "Phone".into(),
                })
            } else {
                Err(RegistryError::Unauthorized)
            }
        }
        fn portal_client_active(&self, client_id: &str, token_hash: &str) -> bool {
            client_id == "client"
                && *self.enabled.lock().unwrap()
                && token_hash == *self.token_hash.lock().unwrap()
        }
    }

    #[test]
    fn invitation_is_random_origin_bound_and_admin_key_bound() {
        let claim = ClientAccessClaim {
            client_id: "client".into(),
            token: "client-access-test-token-0123456789".into(),
            expires_at: None,
        };
        let origin = "https://porta.example.com:8443";
        let first = seal_client_access("admin-token-0123456789", origin, &claim).unwrap();
        let second = seal_client_access("admin-token-0123456789", origin, &claim).unwrap();
        assert_ne!(first, second);
        assert_eq!(
            open_client_access("admin-token-0123456789", origin, &first).unwrap(),
            claim
        );
        assert!(
            open_client_access("admin-token-0123456789", "https://other.example", &first).is_err()
        );
        assert!(open_client_access("rotated-admin-token-012345", origin, &first).is_err());
    }

    #[test]
    fn qr_codes_are_local_512_pixel_pngs() {
        let image = qr_code_data_uri("https://porta.example.com/join#invite=private").unwrap();
        let png = STANDARD
            .decode(image.strip_prefix("data:image/png;base64,").unwrap())
            .unwrap();
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(u32::from_be_bytes(png[16..20].try_into().unwrap()), 512);
        assert_eq!(u32::from_be_bytes(png[20..24].try_into().unwrap()), 512);
    }

    #[test]
    fn profile_payload_matches_android_fixture_and_rejects_bad_inputs() {
        let input = ProfileQrInput {
            name: "Example + phone".into(),
            server: "https://[2001:db8::1]:8443".into(),
            token: "example-not-a-secret+123/=&?%".into(),
        };
        assert_eq!(
            profile_qr_payload(&input).unwrap(),
            "porta://profile?name=Example+%2B+phone&server=https%3A%2F%2F%5B2001%3Adb8%3A%3A1%5D%3A8443&token=example-not-a-secret%2B123%2F%3D%26%3F%25&v=1"
        );
        for server in [
            "http://example.com",
            "https://user@example.com",
            "https://example.com/path",
            "https://example.com?x",
        ] {
            let mut invalid = input.clone();
            invalid.server = server.into();
            assert!(profile_qr_payload(&invalid).is_err());
        }
    }

    #[test]
    fn origin_normalization_and_proxy_rules_match_go() {
        assert_eq!(
            client_access_origin("https://EXAMPLE.com:443/").unwrap(),
            "https://example.com"
        );
        assert_eq!(
            client_access_origin("https://[2001:db8::1]:8443/").unwrap(),
            "https://[2001:db8::1]:8443"
        );
        let mut request = RequestContext::new("POST", "/api/clients")
            .with_host("127.0.0.1:8080")
            .with_header("Origin", "https://porta.example.com")
            .with_header("X-Forwarded-Host", "porta.example.com");
        request.peer_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(!same_origin_portal_request(&request, false));
        assert!(same_origin_portal_request(&request, true));
    }

    #[test]
    fn join_and_setup_markup_escape_credentials() {
        let request = RequestContext::new("GET", "/join");
        let page = join_response(&request, "<script>secret</script>", 400);
        let page = String::from_utf8(page.body).unwrap();
        assert!(page.contains("data-join-state=\"error\""));
        assert!(!page.contains("<script>secret</script>"));

        let profile = DownloadProfile {
            server: "https://porta.test/\"<server>".into(),
            token: "\" autofocus onfocus=\"alert(1)".into(),
            notice: "<script>alert(1)</script>".into(),
            setup_uri: "porta://profile?v=1&token=\"<setup>".into(),
            ..DownloadProfile::default()
        };
        let setup = client_setup_html(Some(&profile));
        assert!(!setup.contains(&profile.token));
        assert!(!setup.contains(&profile.notice));
        assert!(setup.contains("type=\"password\""));
        assert!(setup.contains("Copy setup"));
    }

    fn assert_private_portal_headers(response: &Response) {
        assert_eq!(
            response.header("Content-Type"),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(response.header("Cache-Control"), Some("no-store"));
        assert_eq!(response.header("Referrer-Policy"), Some("no-referrer"));
        assert_eq!(
            response.header("Content-Security-Policy"),
            Some("default-src 'self'; script-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        );
    }

    #[test]
    fn access_page_restores_go_layout_and_responsive_styles() {
        for (method, invalid, status) in [("GET", false, 200), ("POST", true, 401)] {
            let request = RequestContext::new(method, "/access");
            let response = access_page_response(&request, invalid, status);
            assert_eq!(response.status, status);
            assert_private_portal_headers(&response);
            let page = String::from_utf8(response.body).unwrap();
            for fragment in [
                "font-weight:200 900;font-display:swap",
                "*{box-sizing:border-box}",
                "body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(",
                ".card{width:min(430px,100%);padding:30px;border:1px solid rgba(255,255,255,.9);border-radius:22px;background:rgba(255,255,255,.86);box-shadow:0 28px 80px rgba(35,40,68,.12)}",
                ".brand{display:flex;align-items:center;gap:10px;",
                "h1{margin:44px 0 10px;font-size:38px;letter-spacing:-.05em}",
                ".field{display:grid;gap:7px;margin-top:24px}",
                ".field input:focus{border-color:#8f86ef;box-shadow:0 0 0 3px rgba(102,92,246,.1)}",
                "outline:none;font:inherit;font-size:14px",
                "button{width:100%;margin-top:12px;border:0;border-radius:11px;background:#171923;color:white;",
                "font:inherit;font-size:13px;font-weight:750",
                ".note{margin:14px 0 0;font-size:11px}",
                "@media(max-width:430px){body{place-items:start center;padding:14px}.card{margin-top:8vh;padding:23px;border-radius:18px}h1{margin-top:32px;font-size:34px}.field{margin-top:20px}}",
                "<a class=\"brand\" href=\"/\">",
                "<form method=\"post\" action=\"/access\">",
                "<div class=\"field\">",
                "<input id=\"token\" name=\"token\" type=\"password\" autocomplete=\"current-password\" autofocus required>",
                "<p class=\"note\">Credentials are exchanged for a secure, temporary browser session.</p>",
            ] {
                assert!(page.contains(fragment), "missing access design: {fragment}");
            }
            assert_eq!(
                page.contains(
                    "<p class=\"error\" role=\"alert\">Access could not be verified.</p>"
                ),
                invalid
            );
            assert!(!page.contains("%%PORTA_"));
            assert!(!page.contains("<script"));
        }
        let head = access_page_response(&RequestContext::new("HEAD", "/access"), false, 200);
        assert_eq!(head.status, 200);
        assert_private_portal_headers(&head);
        assert!(head.body.is_empty());
    }

    #[test]
    fn downloads_page_restores_go_layout_and_responsive_styles() {
        let tickets = ReleaseDownloadTickets {
            checksums: "checksums-ticket".into(),
            signature: "signature-ticket".into(),
            certificate: "certificate-ticket".into(),
        };
        let page = downloads_page_html("Phone", "porta.test", "v1.2.3", "", &tickets, None);
        for fragment in [
            "@font-face{font-family:\"Mona Sans\";src:url(\"/assets/mona-sans.woff2\") format(\"woff2-variations\");font-weight:200 900;font-display:swap}",
            ":root{font-family:\"Mona Sans\",sans-serif;color:#171923;background:#f5f6fa;--violet:#6558ed;--line:#e2e4ea}",
            "*{box-sizing:border-box}",
            "body{margin:0;min-height:100vh;background:radial-gradient(circle at 85% 0,rgba(115,217,208,.3),transparent 25rem),#f5f6fa}",
            ".page{width:min(900px,calc(100% - 28px));margin:auto;padding:24px 0 44px}",
            ".top{display:flex;justify-content:space-between;align-items:center}",
            ".brand{display:flex;align-items:center;gap:9px;font-size:15px;font-weight:800}",
            ".logout{border:1px solid var(--line);border-radius:8px;",
            "font-family:inherit;font-size:11px;cursor:pointer",
            ".hero{display:grid;grid-template-columns:1fr auto;gap:24px;align-items:end;margin:38px 0 22px}",
            ".eyebrow{color:var(--violet);",
            ".version{display:inline-flex;margin-left:7px;padding:3px 7px;border-radius:999px;background:#ece9ff;",
            "h1{margin:8px 0 8px;font-size:clamp(36px,5vw,48px);line-height:1;letter-spacing:-.05em}",
            ".lead{max-width:560px;margin:0;color:#747987;font-size:13px;line-height:1.6}",
            ".endpoint{min-width:240px;padding:12px 14px;",
            ".endpoint small{display:block;",
            ".files{display:grid;gap:8px}",
            ".download-row{display:grid;grid-template-columns:40px minmax(0,1fr) auto 118px;gap:13px;align-items:center;padding:13px 14px;",
            ".platform-icon{display:grid;place-items:center;width:40px;height:40px;border-radius:11px;background:linear-gradient(145deg,#ece9ff,#e5f8f5);",
            ".platform-line{display:flex;align-items:center;gap:7px}",
            ".platform-line h2{margin:0;font-size:15px;letter-spacing:-.02em}",
            ".package p{margin:3px 0 0;color:#7d828f;font-size:11px;line-height:1.4}",
            ".recommended{padding:3px 6px;border-radius:5px;background:#e6f7f2;color:#218568;",
            ".meta{display:flex;gap:5px}",
            ".meta span{padding:5px 7px;border-radius:6px;background:#f1f2f6;",
            ".download-button{display:flex;align-items:center;justify-content:space-between;border-radius:8px;background:#171923;color:white;",
            ".support{display:flex;justify-content:space-between;gap:18px;",
            ".support a{color:#665cf6;text-decoration:none}",
            ".release-links{display:flex;flex-wrap:wrap;gap:8px 12px}",
            ".empty{padding:34px;border:1px dashed #ccd0da;border-radius:13px;text-align:center}",
            "@media(max-width:680px){.hero{grid-template-columns:1fr;margin-top:32px}.endpoint{min-width:0}.download-row{grid-template-columns:40px minmax(0,1fr) 104px}.meta{display:none}}",
            "@media(max-width:430px){.page{width:min(100% - 20px,900px)}.download-row{grid-template-columns:36px minmax(0,1fr)}.platform-icon{width:36px;height:36px}.download-button{grid-column:1/-1}.support{align-items:flex-start;flex-direction:column}}",
            "<main class=\"page\">",
            "<div class=\"top\">",
            "<div class=\"brand\"><img src=\"/assets/porta-mark.svg\" alt=\"\">Porta</div>",
            "<form method=\"post\" action=\"/portal/logout\"><button class=\"logout\">Sign out</button></form>",
            "<section class=\"hero\">",
            "<div class=\"eyebrow\">Client version <span class=\"version\">v1.2.3</span></div>",
            "<p class=\"lead\">Welcome, Phone.",
            "<div class=\"endpoint\"><small>Server address</small><code>https://porta.test</code></div>",
            "<section class=\"files\">",
            "<div class=\"support\">",
            "<span>Verify package integrity before installation.</span>",
            "<span class=\"release-links\">",
        ] {
            assert!(page.contains(fragment), "missing downloads design: {fragment}");
        }
        assert!(!page.contains("%%PORTA_"));
    }

    #[test]
    fn downloads_page_escapes_values_without_replacing_injected_template_markers() {
        let name = "<name> & \"' %%PORTA_DOWNLOAD_ROWS%%";
        let host = "porta.test/\"<&' %%PORTA_CLIENT_SETUP%%";
        let version = "<version> & \"' %%PORTA_CLIENT_NAME%%";
        let tickets = ReleaseDownloadTickets {
            checksums: "<checksums> & \"' %%PORTA_SIGNATURE_TICKET%%".into(),
            signature: "<signature> & \"' %%PORTA_CERTIFICATE_TICKET%%".into(),
            certificate: "<certificate> & \"' %%PORTA_VERSION%%".into(),
        };
        let profile = DownloadProfile {
            server: "https://\"<&' %%PORTA_SETUP_TOKEN%% %%PORTA_DOWNLOAD_ROWS%%".into(),
            token: "<private> & \"' %%PORTA_CLIENT_NAME%%".into(),
            notice: "<notice> & \"' %%PORTA_SETUP_SERVER%%".into(),
            setup_uri: "porta://profile?v=1&token=\"<&' %%PORTA_VERSION%%".into(),
            qr_code: "javascript:alert(1)".into(),
        };
        let rows = "<article class=\"download-row\">trusted row</article>";
        let page = downloads_page_html(name, host, version, rows, &tickets, Some(&profile));
        for value in [
            name,
            host,
            version,
            &tickets.checksums,
            &tickets.signature,
            &tickets.certificate,
            &profile.server,
            &profile.token,
            &profile.notice,
            &profile.setup_uri,
        ] {
            assert!(!page.contains(value), "unescaped value: {value}");
            assert!(
                page.contains(&html_escape(value)),
                "missing escaped value: {value}"
            );
        }
        for (file, ticket) in [
            ("SHA256SUMS", &tickets.checksums),
            ("SHA256SUMS.sig", &tickets.signature),
            ("release-signing-cert.der", &tickets.certificate),
        ] {
            assert!(page.contains(&format!(
                "href=\"/download/{file}?ticket={}\" download",
                html_escape(ticket)
            )));
        }
        assert_eq!(page.matches(rows).count(), 1);
        assert_eq!(page.matches("id=\"client-setup\"").count(), 1);
        assert!(page.contains(&format!(
            "id=\"setup-token\" type=\"password\" value=\"{}\"",
            html_escape(&profile.token)
        )));
        assert!(!page.contains(&profile.qr_code));
    }

    #[test]
    fn downloads_portal_keeps_all_packages_signed_links_and_client_only_setup() {
        let directory = tempfile::tempdir_in(".").unwrap();
        for (name, ..) in DOWNLOAD_CATALOG {
            std::fs::write(directory.path().join(name), b"package").unwrap();
        }
        std::fs::write(directory.path().join("CLIENT_VERSION"), b"v1.2.3\n").unwrap();
        let client_token = "client-token-0123456789";
        let admin_token = "admin-token-0123456789";
        let registry: Arc<dyn ClientRegistry> = Arc::new(Registry::new(client_token));
        let portal = Portal::new(
            registry,
            admin_token,
            directory.path().to_str().unwrap(),
            false,
        )
        .unwrap();
        let now = 1_000;
        let request_for_token = |token: &str| {
            let sign_in = portal.sign_in(
                &RequestContext::new("POST", "/access")
                    .with_body(format!("token={}", form_urlencode(token)).into_bytes()),
                now,
            );
            assert_eq!(sign_in.status, 303);
            RequestContext::new("GET", "/portal/downloads")
                .with_host("porta.test")
                .with_header(
                    "Cookie",
                    sign_in
                        .header("Set-Cookie")
                        .unwrap()
                        .split(';')
                        .next()
                        .unwrap(),
                )
        };
        let client_request = request_for_token(client_token);
        let admin_request = request_for_token(admin_token);
        for (request, is_client) in [(&client_request, true), (&admin_request, false)] {
            let response = portal.serve_downloads_page(request, now);
            assert_eq!(response.status, 200);
            assert_private_portal_headers(&response);
            let page = String::from_utf8(response.body).unwrap();
            assert_eq!(page.matches("<article class=\"download-row\">").count(), 6);
            assert_eq!(page.matches("<span class=\"recommended\">").count(), 1);
            assert_eq!(page.matches("<div class=\"meta\">").count(), 6);
            assert!(page.contains("<span class=\"version\">v1.2.3</span>"));
            for name in DOWNLOAD_CATALOG.iter().map(|artifact| artifact.0).chain([
                "SHA256SUMS",
                "SHA256SUMS.sig",
                "release-signing-cert.der",
            ]) {
                let prefix = format!("href=\"/download/{name}?ticket=");
                let ticket = page
                    .split_once(&prefix)
                    .unwrap()
                    .1
                    .split('"')
                    .next()
                    .unwrap();
                assert!(portal.valid_download_ticket(name, ticket, now), "{name}");
            }
            for fragment in [
                "id=\"client-setup\"",
                "id=\"setup-qr\" class=\"setup-qr\" src=\"data:image/png;base64,",
                "id=\"setup-server\" value=\"https://porta.test\"",
                "id=\"setup-token\" type=\"password\"",
                "id=\"setup-copy-server\"",
                "id=\"setup-copy-token\"",
                "id=\"setup-reveal-token\"",
                "id=\"setup-copy-uri\"",
                "id=\"setup-uri\" type=\"hidden\" value=\"porta://profile?",
                "<script defer src=\"/assets/portal-client.js\"></script>",
                client_token,
            ] {
                assert_eq!(page.contains(fragment), is_client, "{fragment}");
            }
            assert!(!page.contains(admin_token));
            assert!(!page.contains("%%PORTA_"));
            assert_eq!(page.matches("<script").count(), usize::from(is_client));
            let mut head_request = (*request).clone();
            head_request.method = "HEAD".into();
            let head = portal.serve_downloads_page(&head_request, now);
            assert_eq!(head.status, 200);
            assert_private_portal_headers(&head);
            assert!(head.body.is_empty());
        }
        for (name, ..) in DOWNLOAD_CATALOG {
            std::fs::remove_file(directory.path().join(name)).unwrap();
        }
        let empty = portal.serve_downloads_page(&admin_request, now);
        let page = String::from_utf8(empty.body).unwrap();
        assert!(page.contains("<div class=\"empty\"><strong>Downloads are being prepared.</strong><span>Check back shortly.</span></div>"));
        assert!(!page.contains("<article class=\"download-row\">"));
    }

    #[tokio::test]
    async fn imports_do_not_expose_persisted_hashes() {
        let _ = DeviceSummary::default();
        let registry: Arc<dyn ClientRegistry> = Arc::new(Registry::new("client-token-0123456789"));
        let portal = Portal::new(registry, "admin-token-0123456789", "", false).unwrap();
        let request = RequestContext::new("POST", "/access")
            .with_body(b"token=client-token-0123456789".to_vec());
        let response = portal.handle(&request).await.unwrap();
        assert_eq!(response.status, 303);
        assert_eq!(response.header("Location"), Some("/portal/downloads"));
        assert!(response
            .header("Set-Cookie")
            .unwrap()
            .contains("Secure; HttpOnly; SameSite=Strict"));
    }

    #[tokio::test]
    async fn access_invitation_redeems_into_client_session() {
        let token = "client-token-0123456789";
        let registry: Arc<dyn ClientRegistry> = Arc::new(Registry::new(token));
        let portal =
            Portal::new(Arc::clone(&registry), "admin-token-0123456789", "", false).unwrap();
        let issued = create_client_access(
            registry.as_ref(),
            "admin-token-0123456789",
            ClientAccessInput {
                origin: "https://porta.example.com:8443".into(),
                token: token.into(),
            },
        );
        assert_eq!(issued.status, 200);
        let value: serde_json::Value = serde_json::from_slice(&issued.body).unwrap();
        let url = value["url"].as_str().unwrap();
        assert!(!url.contains(token));
        let ticket = url.split("#invite=").nth(1).unwrap();
        let request = RequestContext::new("POST", "/join/redeem")
            .with_host("porta.example.com:8443")
            .with_header("Origin", "https://porta.example.com:8443")
            .with_body(format!("ticket={}", form_urlencode(ticket)).into_bytes());
        let response = portal.handle(&request).await.unwrap();
        assert_eq!(response.status, 303);
        assert_eq!(response.header("Location"), Some("/portal/downloads"));
        assert!(response.header("Set-Cookie").is_some());
    }

    #[tokio::test]
    async fn failed_portal_and_invitation_authentication_are_rate_limited() {
        let registry: Arc<dyn ClientRegistry> = Arc::new(Registry::new("client-token-0123456789"));
        let mut portal = Portal::new(registry, "admin-token-0123456789", "", false).unwrap();
        portal.set_abuse_guard(Some(Arc::new(AbuseGuard::new(
            [Policy {
                burst: 1,
                refill_interval: Duration::from_secs(3600),
            }; 4],
            64,
            Duration::from_secs(3600),
            Arc::new(Metrics::default()),
        ))));

        let mut sign_in = RequestContext::new("POST", "/access")
            .with_body(b"token=wrong-token-0123456789".to_vec());
        sign_in.client_ip = Some(Ipv4Addr::new(192, 0, 2, 1).into());
        assert_eq!(portal.handle(&sign_in).await.unwrap().status, 401);
        let limited = portal.handle(&sign_in).await.unwrap();
        assert_eq!(limited.status, 429);
        assert_eq!(limited.header("Retry-After"), Some("5"));

        let mut redeem = RequestContext::new("POST", "/join/redeem")
            .with_host("porta.example.com")
            .with_header("Origin", "https://porta.example.com")
            .with_body(b"ticket=invalid-ticket-value".to_vec());
        redeem.client_ip = Some(Ipv4Addr::new(192, 0, 2, 2).into());
        assert_eq!(portal.handle(&redeem).await.unwrap().status, 401);
        let limited = portal.handle(&redeem).await.unwrap();
        assert_eq!(limited.status, 429);
        assert_eq!(limited.header("Retry-After"), Some("5"));
    }
}
