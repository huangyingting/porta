use super::landing::{is_operational_path, serve_asset, set_crawler_policy};
use super::portal::{create_client_access, ClientAccessInput};
use super::session::{constant_time_eq, RequestContext, Response};
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
    #[serde(skip_serializing_if = "String::is_empty")]
    pub target: String,
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
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientInput {
    name: String,
    max_devices: usize,
    enabled: Option<bool>,
}

pub struct AdminService {
    registry: Arc<dyn ClientRegistry>,
    admin_token: Zeroizing<Vec<u8>>,
}

impl AdminService {
    pub fn new(registry: Arc<dyn ClientRegistry>, admin_token: impl Into<Vec<u8>>) -> Self {
        Self {
            registry,
            admin_token: Zeroizing::new(admin_token.into()),
        }
    }

    pub fn registry(&self) -> &Arc<dyn ClientRegistry> {
        &self.registry
    }

    pub async fn handle(&self, request: &RequestContext, portal_admin: bool) -> Option<Response> {
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
        if !portal_admin
            && !admin_authorized(request.header("authorization"), self.admin_token.as_slice())
        {
            let mut response = json_error(401, "Invalid admin token");
            response.set_header("WWW-Authenticate", "******\"porta-admin\"");
            set_admin_security_headers(&mut response);
            return Some(response);
        }
        let response = match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/api/clients") => match self.registry.list_clients() {
                Ok(clients) => json_response(200, &serde_json::json!({ "clients": clients })),
                Err(error) => registry_error(error),
            },
            ("POST", "/api/clients") => {
                let input: ClientInput = match decode_json(request) {
                    Ok(input) => input,
                    Err(response) => return Some(with_admin_headers(response)),
                };
                let name = match validate_client_input(&input.name, input.max_devices) {
                    Ok(name) => name,
                    Err(error) => return Some(with_admin_headers(registry_error(error))),
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
                    Err(response) => return Some(with_admin_headers(response)),
                };
                create_client_access(
                    self.registry.as_ref(),
                    std::str::from_utf8(self.admin_token.as_slice()).unwrap_or_default(),
                    input,
                )
            }
            _ => self.client_action(request).await,
        };
        Some(with_admin_headers(response))
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
                .handle(&RequestContext::new("GET", "/api/clients"), false)
                .await
                .unwrap()
                .status,
            401
        );
        let create = RequestContext::new("POST", "/api/clients")
            .with_header("Authorization", "Bearer admin-token-0123456789")
            .with_body(br#"{"name":"Operations","max_devices":4}"#.to_vec());
        let response = service.handle(&create, false).await.unwrap();
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
            .handle(&RequestContext::new("GET", "/"), false)
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
}
