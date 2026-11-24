//! Named administrator accounts: roles, local passwords with optional TOTP,
//! and single sign-on bindings. The shared `PORTA_ADMIN_TOKEN` remains a
//! break-glass credential outside this store.

use aws_lc_rs::{hmac, pbkdf2, rand::SecureRandom};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::num::NonZeroU32;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use thiserror::Error;
use time::OffsetDateTime;

const STORE_VERSION: u32 = 1;
#[cfg(not(test))]
const PASSWORD_ITERATIONS: u32 = 600_000;
#[cfg(test)]
const PASSWORD_ITERATIONS: u32 = 1_000;
const MIN_PASSWORD_LENGTH: usize = 12;
const TOTP_STEP: i64 = 30;
const TOTP_DIGITS: u32 = 1_000_000;
pub const MAX_ADMINS: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AdminRole {
    /// Reads accounts, devices and gateway state.
    Viewer,
    /// Also manages accounts, devices and access policies.
    Operator,
    /// Also manages administrators.
    Owner,
}

impl AdminRole {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "viewer" => Some(Self::Viewer),
            "operator" => Some(Self::Operator),
            "owner" => Some(Self::Owner),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Operator => "operator",
            Self::Owner => "owner",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdminRecord {
    pub id: String,
    pub username: String,
    pub role: AdminRole,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password_hash: String,
    /// Base32 TOTP secret once confirmed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub totp_secret: String,
    /// Secret awaiting its first valid code.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pending_totp_secret: String,
    /// Verified OIDC email that signs in as this administrator.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sso_email: String,
    #[serde(default)]
    pub disabled: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// What the admin API reports about an administrator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AdminSummary {
    pub id: String,
    pub username: String,
    pub role: AdminRole,
    pub password: bool,
    pub totp: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub sso_email: String,
    pub disabled: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// A signed-in administrator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminIdentity {
    pub id: String,
    pub username: String,
    pub role: AdminRole,
}

#[derive(Debug, Error)]
pub enum AdminError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("a one-time code is required")]
    CodeRequired,
    #[error("administrator not found")]
    NotFound,
    #[error("{0}")]
    Invalid(String),
    #[error("administrator store I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("decode administrator store: {0}")]
    Decode(#[from] serde_json::Error),
}

#[derive(Default, Deserialize, Serialize)]
struct StoreFile {
    version: u32,
    admins: Vec<AdminRecord>,
}

/// Parameters of a new or updated administrator.
#[derive(Clone, Debug, Default)]
pub struct AdminInput {
    pub username: String,
    pub role: Option<AdminRole>,
    pub password: Option<String>,
    pub sso_email: Option<String>,
    pub disabled: Option<bool>,
}

/// A TOTP enrollment to show the administrator once.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TotpEnrollment {
    pub secret: String,
    pub uri: String,
}

pub struct AdminStore {
    path: PathBuf,
    admins: Mutex<Vec<AdminRecord>>,
    /// Last accepted TOTP step per administrator, to refuse replays.
    used_steps: Mutex<HashMap<String, i64>>,
    issuer: String,
}

impl AdminStore {
    /// Opens the store at `path`, creating an empty one if it is missing.
    /// `issuer` labels TOTP enrollments in authenticator apps.
    pub fn open(path: impl Into<PathBuf>, issuer: impl Into<String>) -> Result<Self, AdminError> {
        let path = path.into();
        let admins = match std::fs::read(&path) {
            Ok(data) => {
                let file: StoreFile = serde_json::from_slice(&data)?;
                if file.version != STORE_VERSION {
                    return Err(AdminError::Invalid(format!(
                        "unsupported administrator store version {}",
                        file.version
                    )));
                }
                file.admins
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            path,
            admins: Mutex::new(admins),
            used_steps: Mutex::new(HashMap::new()),
            issuer: issuer.into(),
        })
    }

    pub fn list(&self) -> Vec<AdminSummary> {
        self.admins.lock().iter().map(summarize).collect()
    }

    pub fn get(&self, id: &str) -> Option<AdminIdentity> {
        self.admins
            .lock()
            .iter()
            .find(|admin| admin.id == id && !admin.disabled)
            .map(identity)
    }

    pub fn create(&self, input: AdminInput) -> Result<AdminSummary, AdminError> {
        let username = validate_username(&input.username)?;
        let role = input
            .role
            .ok_or_else(|| AdminError::Invalid("role is required".into()))?;
        let password_hash = match input.password.as_deref() {
            Some(password) => hash_password(password)?,
            None => String::new(),
        };
        let sso_email = validate_email(input.sso_email.as_deref().unwrap_or_default())?;
        if password_hash.is_empty() && sso_email.is_empty() {
            return Err(AdminError::Invalid(
                "an administrator needs a password or a single sign-on email".into(),
            ));
        }
        self.mutate(|admins| {
            if admins.len() >= MAX_ADMINS {
                return Err(AdminError::Invalid(format!(
                    "at most {MAX_ADMINS} administrators are supported"
                )));
            }
            ensure_unique(admins, None, &username, &sso_email)?;
            let record = AdminRecord {
                id: random_hex(8)?,
                username: username.clone(),
                role,
                password_hash: password_hash.clone(),
                totp_secret: String::new(),
                pending_totp_secret: String::new(),
                sso_email: sso_email.clone(),
                disabled: input.disabled.unwrap_or(false),
                created_at: OffsetDateTime::now_utc(),
            };
            let summary = summarize(&record);
            admins.push(record);
            Ok(summary)
        })
    }

    pub fn update(&self, id: &str, input: AdminInput) -> Result<AdminSummary, AdminError> {
        let password_hash = match input.password.as_deref() {
            Some(password) => Some(hash_password(password)?),
            None => None,
        };
        let sso_email = match input.sso_email.as_deref() {
            Some(email) => Some(validate_email(email)?),
            None => None,
        };
        self.mutate(|admins| {
            let index = admins
                .iter()
                .position(|admin| admin.id == id)
                .ok_or(AdminError::NotFound)?;
            if let Some(email) = &sso_email {
                let username = admins[index].username.clone();
                ensure_unique(admins, Some(id), &username, email)?;
            }
            let admin = &mut admins[index];
            if let Some(role) = input.role {
                admin.role = role;
            }
            if let Some(disabled) = input.disabled {
                admin.disabled = disabled;
            }
            if let Some(hash) = &password_hash {
                admin.password_hash.clone_from(hash);
            }
            if let Some(email) = &sso_email {
                admin.sso_email.clone_from(email);
            }
            if admin.password_hash.is_empty() && admin.sso_email.is_empty() {
                return Err(AdminError::Invalid(
                    "an administrator needs a password or a single sign-on email".into(),
                ));
            }
            Ok(summarize(admin))
        })
    }

    pub fn delete(&self, id: &str) -> Result<(), AdminError> {
        self.mutate(|admins| {
            let before = admins.len();
            admins.retain(|admin| admin.id != id);
            if admins.len() == before {
                return Err(AdminError::NotFound);
            }
            Ok(())
        })?;
        self.used_steps.lock().remove(id);
        Ok(())
    }

    /// Replaces a password after checking the current one.
    pub fn change_password(
        &self,
        id: &str,
        current: &str,
        password: &str,
    ) -> Result<(), AdminError> {
        let hash = hash_password(password)?;
        self.mutate(|admins| {
            let admin = admins
                .iter_mut()
                .find(|admin| admin.id == id)
                .ok_or(AdminError::NotFound)?;
            if admin.password_hash.is_empty() || !verify_password(&admin.password_hash, current) {
                return Err(AdminError::InvalidCredentials);
            }
            admin.password_hash = hash;
            Ok(())
        })
    }

    /// Starts TOTP enrollment; the secret applies once confirmed.
    pub fn begin_totp(&self, id: &str) -> Result<TotpEnrollment, AdminError> {
        let mut secret = [0_u8; 20];
        aws_lc_rs::rand::SystemRandom::new()
            .fill(&mut secret)
            .map_err(|_| AdminError::Invalid("could not generate a TOTP secret".into()))?;
        let encoded = base32_encode(&secret);
        let username = self.mutate(|admins| {
            let admin = admins
                .iter_mut()
                .find(|admin| admin.id == id)
                .ok_or(AdminError::NotFound)?;
            admin.pending_totp_secret.clone_from(&encoded);
            Ok(admin.username.clone())
        })?;
        let label = form_component(&format!("{}:{username}", self.issuer));
        Ok(TotpEnrollment {
            uri: format!(
                "otpauth://totp/{label}?secret={encoded}&issuer={}&algorithm=SHA1&digits=6&period=30",
                form_component(&self.issuer)
            ),
            secret: encoded,
        })
    }

    /// Activates the pending TOTP secret when `code` is valid for it.
    pub fn confirm_totp(
        &self,
        id: &str,
        code: &str,
        now: OffsetDateTime,
    ) -> Result<(), AdminError> {
        self.mutate(|admins| {
            let admin = admins
                .iter_mut()
                .find(|admin| admin.id == id)
                .ok_or(AdminError::NotFound)?;
            let secret = base32_decode(&admin.pending_totp_secret)
                .ok_or_else(|| AdminError::Invalid("start TOTP enrollment first".into()))?;
            if totp_step(&secret, code, now).is_none() {
                return Err(AdminError::InvalidCredentials);
            }
            admin.totp_secret = std::mem::take(&mut admin.pending_totp_secret);
            Ok(())
        })
    }

    pub fn remove_totp(&self, id: &str) -> Result<(), AdminError> {
        self.mutate(|admins| {
            let admin = admins
                .iter_mut()
                .find(|admin| admin.id == id)
                .ok_or(AdminError::NotFound)?;
            admin.totp_secret.clear();
            admin.pending_totp_secret.clear();
            Ok(())
        })
    }

    /// Checks a local sign-in. A missing code for an administrator with TOTP
    /// is reported separately so the form can ask for it.
    pub fn authenticate(
        &self,
        username: &str,
        password: &str,
        code: &str,
        now: OffsetDateTime,
    ) -> Result<AdminIdentity, AdminError> {
        let username = username.trim().to_ascii_lowercase();
        let admin = self
            .admins
            .lock()
            .iter()
            .find(|admin| admin.username == username)
            .cloned();
        let Some(admin) = admin.filter(|admin| !admin.disabled && !admin.password_hash.is_empty())
        else {
            // Spend the same work for unknown names as for wrong passwords.
            let _ = verify_password(&dummy_hash(), password);
            return Err(AdminError::InvalidCredentials);
        };
        if !verify_password(&admin.password_hash, password) {
            return Err(AdminError::InvalidCredentials);
        }
        if !admin.totp_secret.is_empty() {
            if code.trim().is_empty() {
                return Err(AdminError::CodeRequired);
            }
            let secret = base32_decode(&admin.totp_secret).ok_or(AdminError::InvalidCredentials)?;
            let step = totp_step(&secret, code, now).ok_or(AdminError::InvalidCredentials)?;
            let mut used = self.used_steps.lock();
            if used.get(&admin.id).is_some_and(|last| step <= *last) {
                return Err(AdminError::InvalidCredentials);
            }
            used.insert(admin.id.clone(), step);
        }
        Ok(identity(&admin))
    }

    /// The administrator bound to a verified single sign-on email.
    pub fn sso_admin(&self, email: &str) -> Option<AdminIdentity> {
        let email = email.trim().to_ascii_lowercase();
        if email.is_empty() {
            return None;
        }
        self.admins
            .lock()
            .iter()
            .find(|admin| admin.sso_email == email && !admin.disabled)
            .map(identity)
    }

    fn mutate<T>(
        &self,
        change: impl FnOnce(&mut Vec<AdminRecord>) -> Result<T, AdminError>,
    ) -> Result<T, AdminError> {
        let mut admins = self.admins.lock();
        let mut candidate = admins.clone();
        let result = change(&mut candidate)?;
        persist(&self.path, &candidate)?;
        *admins = candidate;
        Ok(result)
    }
}

fn summarize(admin: &AdminRecord) -> AdminSummary {
    AdminSummary {
        id: admin.id.clone(),
        username: admin.username.clone(),
        role: admin.role,
        password: !admin.password_hash.is_empty(),
        totp: !admin.totp_secret.is_empty(),
        sso_email: admin.sso_email.clone(),
        disabled: admin.disabled,
        created_at: admin.created_at,
    }
}

fn identity(admin: &AdminRecord) -> AdminIdentity {
    AdminIdentity {
        id: admin.id.clone(),
        username: admin.username.clone(),
        role: admin.role,
    }
}

fn ensure_unique(
    admins: &[AdminRecord],
    except: Option<&str>,
    username: &str,
    email: &str,
) -> Result<(), AdminError> {
    for admin in admins
        .iter()
        .filter(|admin| Some(admin.id.as_str()) != except)
    {
        if admin.username == username {
            return Err(AdminError::Invalid(format!("{username} already exists")));
        }
        if !email.is_empty() && admin.sso_email == email {
            return Err(AdminError::Invalid(format!(
                "{email} already signs in as {}",
                admin.username
            )));
        }
    }
    Ok(())
}

fn validate_username(value: &str) -> Result<String, AdminError> {
    let username = value.trim().to_ascii_lowercase();
    if username.is_empty()
        || username.len() > 64
        || !username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@'))
    {
        return Err(AdminError::Invalid(
            "usernames use 1-64 letters, digits, '.', '_', '-' or '@'".into(),
        ));
    }
    Ok(username)
}

fn validate_email(value: &str) -> Result<String, AdminError> {
    let email = value.trim().to_ascii_lowercase();
    if email.is_empty() {
        return Ok(email);
    }
    let valid = email.len() <= 254
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && domain.contains('.') && !domain.starts_with('.')
        })
        && !email.chars().any(char::is_whitespace);
    if !valid {
        return Err(AdminError::Invalid(format!(
            "{value:?} is not an email address"
        )));
    }
    Ok(email)
}

fn persist(path: &Path, admins: &[AdminRecord]) -> Result<(), AdminError> {
    let data = serde_json::to_vec_pretty(&StoreFile {
        version: STORE_VERSION,
        admins: admins.to_vec(),
    })?;
    let temporary = path.with_extension("json.new");
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&data)?;
        file.sync_all()?;
    }
    std::fs::rename(&temporary, path)?;
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn random_hex(bytes: usize) -> Result<String, AdminError> {
    let mut value = vec![0_u8; bytes];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut value)
        .map_err(|_| AdminError::Invalid("could not generate an identifier".into()))?;
    Ok(hex::encode(value))
}

/// A well-formed hash with the production cost, checked when the username
/// is unknown.
fn dummy_hash() -> String {
    format!(
        "pbkdf2-sha256${PASSWORD_ITERATIONS}$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    )
}

/// `pbkdf2-sha256$<iterations>$<salt>$<hash>` with unpadded base64.
pub fn hash_password(password: &str) -> Result<String, AdminError> {
    if password.chars().count() < MIN_PASSWORD_LENGTH || password.len() > 1024 {
        return Err(AdminError::Invalid(format!(
            "passwords need at least {MIN_PASSWORD_LENGTH} characters"
        )));
    }
    let mut salt = [0_u8; 16];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| AdminError::Invalid("could not generate a salt".into()))?;
    let mut hash = [0_u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PASSWORD_ITERATIONS).expect("nonzero iterations"),
        &salt,
        password.as_bytes(),
        &mut hash,
    );
    Ok(format!(
        "pbkdf2-sha256${PASSWORD_ITERATIONS}${}${}",
        STANDARD_NO_PAD.encode(salt),
        STANDARD_NO_PAD.encode(hash)
    ))
}

pub fn verify_password(encoded: &str, password: &str) -> bool {
    let mut parts = encoded.split('$');
    let (Some("pbkdf2-sha256"), Some(iterations), Some(salt), Some(hash), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return false;
    };
    let (Some(iterations), Ok(salt), Ok(hash)) = (
        iterations.parse::<u32>().ok().and_then(NonZeroU32::new),
        STANDARD_NO_PAD.decode(salt),
        STANDARD_NO_PAD.decode(hash),
    ) else {
        return false;
    };
    pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        &salt,
        password.as_bytes(),
        &hash,
    )
    .is_ok()
}

/// The 30-second step a six-digit `code` is valid for, allowing one step of
/// clock drift either way (RFC 6238 with HMAC-SHA1).
pub fn totp_step(secret: &[u8], code: &str, now: OffsetDateTime) -> Option<i64> {
    let code = code.trim().replace(' ', "");
    if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let current = now.unix_timestamp().div_euclid(TOTP_STEP);
    (current - 1..=current + 1).find(|step| {
        let expected = format!("{:06}", hotp(secret, *step as u64));
        aws_lc_rs::constant_time::verify_slices_are_equal(expected.as_bytes(), code.as_bytes())
            .is_ok()
    })
}

pub fn hotp(secret: &[u8], counter: u64) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let digest = hmac::sign(&key, &counter.to_be_bytes());
    let digest = digest.as_ref();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let value = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    value % TOTP_DIGITS
}

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn base32_encode(data: &[u8]) -> String {
    let mut output = String::new();
    let mut buffer = 0_u32;
    let mut bits = 0;
    for byte in data {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(char::from(BASE32[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        output.push(char::from(BASE32[((buffer << (5 - bits)) & 31) as usize]));
    }
    output
}

pub fn base32_decode(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() {
        return None;
    }
    let mut output = Vec::new();
    let mut buffer = 0_u32;
    let mut bits = 0;
    for character in value.trim_end_matches('=').bytes() {
        let index = BASE32
            .iter()
            .position(|known| *known == character.to_ascii_uppercase())? as u32;
        buffer = (buffer << 5) | index;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
        }
    }
    Some(output)
}

fn form_component(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_matches_rfc_6238_and_allows_one_step_of_drift() {
        // RFC 6238 appendix B, SHA-1 seed.
        let secret = b"12345678901234567890";
        assert_eq!(hotp(secret, 59 / 30), 287_082);
        assert_eq!(hotp(secret, 1_111_111_109 / 30), 81_804);
        let at = OffsetDateTime::from_unix_timestamp(1_111_111_109).unwrap();
        assert_eq!(totp_step(secret, "081804", at), Some(1_111_111_109 / 30));
        let later = OffsetDateTime::from_unix_timestamp(1_111_111_109 + 30).unwrap();
        assert!(totp_step(secret, "081804", later).is_some());
        let much_later = OffsetDateTime::from_unix_timestamp(1_111_111_109 + 90).unwrap();
        assert!(totp_step(secret, "081804", much_later).is_none());
        assert!(totp_step(secret, "81804", at).is_none());
        assert_eq!(base32_decode(&base32_encode(secret)).unwrap(), secret);
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn passwords_and_totp_sign_in_and_codes_cannot_be_replayed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("admins.json");
        let store = AdminStore::open(&path, "Porta").unwrap();
        assert!(matches!(
            store.create(AdminInput {
                username: "alice".into(),
                role: Some(AdminRole::Owner),
                password: Some("short".into()),
                ..AdminInput::default()
            }),
            Err(AdminError::Invalid(_))
        ));
        let alice = store
            .create(AdminInput {
                username: " Alice ".into(),
                role: Some(AdminRole::Owner),
                password: Some("correct horse battery".into()),
                ..AdminInput::default()
            })
            .unwrap();
        assert_eq!(alice.username, "alice");
        assert!(store
            .create(AdminInput {
                username: "alice".into(),
                role: Some(AdminRole::Viewer),
                password: Some("another long password".into()),
                ..AdminInput::default()
            })
            .is_err());
        let now = OffsetDateTime::now_utc();
        assert_eq!(
            store
                .authenticate("ALICE", "correct horse battery", "", now)
                .unwrap()
                .role,
            AdminRole::Owner
        );
        assert!(matches!(
            store.authenticate("alice", "wrong password!!", "", now),
            Err(AdminError::InvalidCredentials)
        ));
        assert!(matches!(
            store.authenticate("bob", "correct horse battery", "", now),
            Err(AdminError::InvalidCredentials)
        ));

        let enrollment = store.begin_totp(&alice.id).unwrap();
        assert!(enrollment
            .uri
            .starts_with("otpauth://totp/Porta%3Aalice?secret="));
        let secret = base32_decode(&enrollment.secret).unwrap();
        let code =
            |at: OffsetDateTime| format!("{:06}", hotp(&secret, (at.unix_timestamp() / 30) as u64));
        // Unconfirmed secrets do not apply yet.
        assert!(store
            .authenticate("alice", "correct horse battery", "", now)
            .is_ok());
        assert!(store.confirm_totp(&alice.id, "000000", now).is_err() || code(now) == "000000");
        store.confirm_totp(&alice.id, &code(now), now).unwrap();
        assert!(matches!(
            store.authenticate("alice", "correct horse battery", "", now),
            Err(AdminError::CodeRequired)
        ));
        store
            .authenticate("alice", "correct horse battery", &code(now), now)
            .unwrap();
        assert!(matches!(
            store.authenticate("alice", "correct horse battery", &code(now), now),
            Err(AdminError::InvalidCredentials)
        ));

        // The store survives a restart; disabled administrators cannot sign in.
        let store = AdminStore::open(&path, "Porta").unwrap();
        assert!(store.list()[0].totp);
        store
            .update(
                &alice.id,
                AdminInput {
                    disabled: Some(true),
                    ..AdminInput::default()
                },
            )
            .unwrap();
        let later = now + time::Duration::seconds(60);
        assert!(store
            .authenticate("alice", "correct horse battery", &code(later), later)
            .is_err());
        assert!(store.get(&alice.id).is_none());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn sso_emails_are_unique_and_map_to_enabled_administrators() {
        let directory = tempfile::tempdir().unwrap();
        let store = AdminStore::open(directory.path().join("admins.json"), "Porta").unwrap();
        let carol = store
            .create(AdminInput {
                username: "carol".into(),
                role: Some(AdminRole::Viewer),
                sso_email: Some("Carol@Example.com".into()),
                ..AdminInput::default()
            })
            .unwrap();
        assert_eq!(store.sso_admin("carol@example.COM").unwrap().id, carol.id);
        assert!(store.sso_admin("dave@example.com").is_none());
        assert!(store
            .create(AdminInput {
                username: "dave".into(),
                role: Some(AdminRole::Viewer),
                sso_email: Some("carol@example.com".into()),
                ..AdminInput::default()
            })
            .is_err());
        assert!(store
            .create(AdminInput {
                username: "erin".into(),
                role: Some(AdminRole::Viewer),
                ..AdminInput::default()
            })
            .is_err());
    }

    use std::os::unix::fs::PermissionsExt;
}
