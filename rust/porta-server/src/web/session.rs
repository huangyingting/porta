use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::TryRngCore;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::Mutex;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const PORTAL_COOKIE_NAME: &str = "porta_session";
pub const PORTAL_SESSION_TTL_SECS: u64 = 8 * 60 * 60;
pub const MAX_PORTAL_SESSIONS: usize = 4096;
pub const MAX_PORTAL_SESSIONS_PER_LOGIN: usize = 8;

pub fn normalized_headers(headers: &http::HeaderMap) -> BTreeMap<String, String> {
    let mut normalized = BTreeMap::new();
    for name in headers.keys() {
        let value = if name == http::header::COOKIE {
            headers
                .get_all(name)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .collect::<Vec<_>>()
                .join("; ")
        } else {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned()
        };
        if !value.is_empty() {
            normalized.insert(name.as_str().to_ascii_lowercase(), value);
        }
    }
    normalized
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RequestContext {
    pub method: String,
    pub path: String,
    pub query: String,
    pub host: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub peer_ip: Option<IpAddr>,
    pub client_ip: Option<IpAddr>,
}

impl RequestContext {
    pub fn new(method: impl Into<String>, target: impl AsRef<str>) -> Self {
        let target = target.as_ref();
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        Self {
            method: method.into().to_ascii_uppercase(),
            path: path.to_owned(),
            query: query.to_owned(),
            ..Self::default()
        }
    }

    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.host = host.into();
        self
    }

    pub fn with_header(mut self, name: impl AsRef<str>, value: impl Into<String>) -> Self {
        self.headers
            .insert(name.as_ref().to_ascii_lowercase(), value.into());
        self
    }

    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    pub fn cookie(&self, name: &str) -> Option<&str> {
        self.header("cookie")?.split(';').find_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            (key == name).then_some(value)
        })
    }

    pub fn is_get_or_head(&self) -> bool {
        self.method == "GET" || self.method == "HEAD"
    }
}

#[derive(Debug)]
pub struct FileResponse {
    pub file: std::fs::File,
    pub length: u64,
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub file: Option<FileResponse>,
}

impl Response {
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: BTreeMap::new(),
            body: Vec::new(),
            file: None,
        }
    }

    pub fn text(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        let mut response = Self::new(status);
        response.set_header("Content-Type", content_type);
        response.body = body.into();
        response
    }

    pub fn html(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self::text(status, "text/html; charset=utf-8", body)
    }

    pub fn json(status: u16, body: impl Into<Vec<u8>>) -> Self {
        let mut response = Self::text(status, "application/json; charset=utf-8", body);
        response.set_header("Cache-Control", "no-store");
        response
    }

    pub fn not_found() -> Self {
        Self::text(
            404,
            "text/plain; charset=utf-8",
            b"404 page not found\n".to_vec(),
        )
    }

    pub fn redirect(location: &str) -> Self {
        let mut response = Self::new(303);
        response.set_header("Location", location);
        response.set_header("Cache-Control", "no-store");
        response
    }

    pub fn set_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.headers.insert(name.into(), value.into());
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value.as_str()))
    }

    pub fn without_body_for_head(mut self, request: &RequestContext) -> Self {
        if request.method == "HEAD" {
            self.body.clear();
            self.file = None;
        }
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PortalRole {
    Client,
    Admin,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortalSession {
    pub role: PortalRole,
    pub client_id: String,
    pub client_name: String,
    pub token_hash: String,
    pub encrypted_token: String,
    pub expires_at: u64,
}

impl PortalSession {
    pub fn admin(now: u64) -> Self {
        Self {
            role: PortalRole::Admin,
            client_id: String::new(),
            client_name: String::new(),
            token_hash: String::new(),
            encrypted_token: String::new(),
            expires_at: now.saturating_add(PORTAL_SESSION_TTL_SECS),
        }
    }

    fn scope(&self) -> SessionScope {
        SessionScope {
            role: self.role,
            client_id: self.client_id.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct SessionScope {
    role: PortalRole,
    client_id: String,
}

#[derive(Default)]
struct SessionState {
    sessions: HashMap<String, PortalSession>,
    by_expiry: BTreeSet<(u64, String)>,
    by_scope: HashMap<SessionScope, BTreeSet<(u64, String)>>,
}

pub struct SessionStore {
    state: Mutex<SessionState>,
    max_sessions: usize,
    max_per_login: usize,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new(MAX_PORTAL_SESSIONS, MAX_PORTAL_SESSIONS_PER_LOGIN)
    }
}

impl SessionStore {
    pub fn new(max_sessions: usize, max_per_login: usize) -> Self {
        Self {
            state: Mutex::new(SessionState::default()),
            max_sessions: max_sessions.max(1),
            max_per_login: max_per_login.max(1),
        }
    }

    pub fn start(&self, session: PortalSession, now: u64) -> Result<(String, String), CryptoError> {
        let mut id_bytes = [0_u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut id_bytes)
            .map_err(|_| CryptoError::Random)?;
        let id = URL_SAFE_NO_PAD.encode(id_bytes);
        let scope = session.scope();
        let mut state = self.state.lock().expect("portal session mutex poisoned");
        prune_locked(&mut state, now);
        while state.by_scope.get(&scope).map_or(0, BTreeSet::len) >= self.max_per_login {
            let oldest = state
                .by_scope
                .get(&scope)
                .and_then(|entries| entries.first().cloned());
            if let Some((_, oldest_id)) = oldest {
                remove_locked(&mut state, &oldest_id);
            } else {
                break;
            }
        }
        while state.sessions.len() >= self.max_sessions {
            let oldest = state.by_expiry.first().cloned();
            if let Some((_, oldest_id)) = oldest {
                remove_locked(&mut state, &oldest_id);
            } else {
                break;
            }
        }
        state.by_expiry.insert((session.expires_at, id.clone()));
        state
            .by_scope
            .entry(scope)
            .or_default()
            .insert((session.expires_at, id.clone()));
        state.sessions.insert(id.clone(), session);
        Ok((id.clone(), session_cookie(&id)))
    }

    pub fn get(&self, id: &str, now: u64) -> Option<PortalSession> {
        let mut state = self.state.lock().expect("portal session mutex poisoned");
        let session = state.sessions.get(id)?.clone();
        if session.expires_at <= now {
            remove_locked(&mut state, id);
            return None;
        }
        Some(session)
    }

    pub fn remove(&self, id: &str) {
        let mut state = self.state.lock().expect("portal session mutex poisoned");
        remove_locked(&mut state, id);
    }

    pub fn len(&self) -> usize {
        self.state
            .lock()
            .expect("portal session mutex poisoned")
            .sessions
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.state
            .lock()
            .expect("portal session mutex poisoned")
            .sessions
            .is_empty()
    }
}

fn prune_locked(state: &mut SessionState, now: u64) {
    loop {
        let Some((expires_at, id)) = state.by_expiry.first().cloned() else {
            return;
        };
        if expires_at > now {
            return;
        }
        remove_locked(state, &id);
    }
}

fn remove_locked(state: &mut SessionState, id: &str) {
    let Some(session) = state.sessions.remove(id) else {
        return;
    };
    let entry = (session.expires_at, id.to_owned());
    state.by_expiry.remove(&entry);
    let scope = session.scope();
    if let Some(entries) = state.by_scope.get_mut(&scope) {
        entries.remove(&entry);
        if entries.is_empty() {
            state.by_scope.remove(&scope);
        }
    }
}

pub fn session_cookie(id: &str) -> String {
    format!(
        "{PORTAL_COOKIE_NAME}={id}; Path=/; Max-Age={PORTAL_SESSION_TTL_SECS}; Secure; HttpOnly; SameSite=Strict"
    )
}

pub fn expired_session_cookie() -> String {
    format!("{PORTAL_COOKIE_NAME}=; Path=/; Max-Age=-1; Secure; HttpOnly; SameSite=Strict")
}

pub fn unix_time_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

pub fn html_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&#34;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

pub fn form_urlencode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(char::from(*byte))
            }
            b' ' => encoded.push('+'),
            _ => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                encoded.push('%');
                encoded.push(char::from(HEX[(byte >> 4) as usize]));
                encoded.push(char::from(HEX[(byte & 0x0f) as usize]));
            }
        }
    }
    encoded
}

pub fn parse_form(body: &[u8], max_size: usize) -> Option<Vec<(String, String)>> {
    if body.len() > max_size {
        return None;
    }
    let body = std::str::from_utf8(body).ok()?;
    if body.is_empty() {
        return Some(Vec::new());
    }
    body.split('&')
        .map(|field| {
            let (key, value) = field.split_once('=').unwrap_or((field, ""));
            Some((form_urldecode(key)?, form_urldecode(value)?))
        })
        .collect()
}

fn form_urldecode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                decoded.push((hex_nibble(bytes[index + 1])? << 4) | hex_nibble(bytes[index + 2])?);
                index += 3;
            }
            b'%' => return None,
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).ok()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CredentialCipher {
    key: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    Invalid,
    Random,
}

impl CredentialCipher {
    pub fn derive(secret: &[u8], purpose: &str) -> Self {
        let key = hmac_sha256(
            secret,
            format!("porta/portal-credentials/{purpose}").as_bytes(),
        );
        Self { key }
    }

    pub fn seal(&self, value: &[u8], binding: &str) -> Result<String, CryptoError> {
        let mut nonce = [0_u8; 12];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| CryptoError::Random)?;
        let (ciphertext, tag) = aes_256_gcm_seal(&self.key, &nonce, value, binding.as_bytes());
        let mut encoded = Vec::with_capacity(12 + ciphertext.len() + 16);
        encoded.extend_from_slice(&nonce);
        encoded.extend_from_slice(&ciphertext);
        encoded.extend_from_slice(&tag);
        Ok(URL_SAFE_NO_PAD.encode(encoded))
    }

    pub fn open(
        &self,
        encoded: &str,
        binding: &str,
        max_encoded: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        if encoded.is_empty() || encoded.len() > max_encoded {
            return Err(CryptoError::Invalid);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| CryptoError::Invalid)?;
        if decoded.len() < 12 + 16 {
            return Err(CryptoError::Invalid);
        }
        let (nonce, sealed) = decoded.split_at(12);
        let (ciphertext, tag) = sealed.split_at(sealed.len() - 16);
        let nonce: [u8; 12] = nonce.try_into().map_err(|_| CryptoError::Invalid)?;
        let tag: [u8; 16] = tag.try_into().map_err(|_| CryptoError::Invalid)?;
        aes_256_gcm_open(&self.key, &nonce, ciphertext, binding.as_bytes(), &tag)
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn aes_256_gcm_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let cipher = Aes256Gcm::new_from_slice(key).expect("AES-256 key has the required length");
    let mut ciphertext = plaintext.to_vec();
    let nonce = Nonce::from(*nonce);
    let tag = cipher
        .encrypt_in_place_detached(&nonce, aad, &mut ciphertext)
        .expect("AES-GCM message length is within supported limits");
    (ciphertext, tag.into())
}

fn aes_256_gcm_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("AES-256 key has the required length");
    let mut plaintext = ciphertext.to_vec();
    let nonce = Nonce::from(*nonce);
    let tag = Tag::from(*tag);
    cipher
        .decrypt_in_place_detached(&nonce, aad, &mut plaintext, &tag)
        .map_err(|_| CryptoError::Invalid)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combines_split_cookie_fields() {
        let mut headers = http::HeaderMap::new();
        headers.append(http::header::COOKIE, "theme=dark".parse().unwrap());
        headers.append(
            http::header::COOKIE,
            "porta_session=authenticated".parse().unwrap(),
        );
        let context = RequestContext {
            headers: normalized_headers(&headers),
            ..RequestContext::default()
        };
        assert_eq!(
            context.headers.get("cookie").map(String::as_str),
            Some("theme=dark; porta_session=authenticated")
        );
        assert_eq!(context.cookie("porta_session"), Some("authenticated"));
    }

    #[test]
    fn sessions_are_secure_bounded_and_expire() {
        let store = SessionStore::new(4, 2);
        let session = PortalSession {
            role: PortalRole::Client,
            client_id: "client".into(),
            client_name: "Client".into(),
            token_hash: "hash".into(),
            encrypted_token: "sealed".into(),
            expires_at: 100,
        };
        let (first, cookie) = store.start(session.clone(), 0).unwrap();
        assert!(cookie.contains("Secure; HttpOnly; SameSite=Strict"));
        let (second, _) = store.start(session.clone(), 0).unwrap();
        let (third, _) = store.start(session, 0).unwrap();
        assert_eq!(store.len(), 2);
        let retained = [&first, &second, &third]
            .into_iter()
            .filter(|id| store.get(id, 1).is_some())
            .count();
        assert_eq!(retained, 2);
        assert_eq!(store.len(), 2);
        assert!(store.get("missing", 200).is_none());
    }

    #[test]
    fn aes_gcm_matches_nist_vector() {
        let key = [0_u8; 32];
        let nonce = [0_u8; 12];
        let plaintext = [0_u8; 16];
        let (ciphertext, tag) = aes_256_gcm_seal(&key, &nonce, &plaintext, b"");
        assert_eq!(hex::encode(&ciphertext), "cea7403d4d606b6e074ec5d3baf39d18");
        assert_eq!(hex::encode(tag), "d0d1c8a799996bf0265b98b5d48ab919");
        assert_eq!(
            aes_256_gcm_open(&key, &nonce, &ciphertext, b"", &tag).unwrap(),
            plaintext
        );
    }

    #[test]
    fn form_codec_is_strict() {
        assert_eq!(
            parse_form(b"name=Example+%2B+phone", 4096).unwrap(),
            vec![("name".into(), "Example + phone".into())]
        );
        assert!(parse_form(b"ticket=%ZZ", 4096).is_none());
        assert_eq!(form_urlencode("a b+"), "a+b%2B");
    }
}
