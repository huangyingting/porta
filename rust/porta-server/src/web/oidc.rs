//! OpenID Connect sign-in for administrators: the authorization code flow
//! with PKCE (S256) and a nonce. The ID token's signature (RS256 or ES256
//! from the issuer's JWKS), issuer, audience, expiry and nonce are verified
//! before its verified email is mapped to an administrator.

use aws_lc_rs::digest;
use aws_lc_rs::rand::SecureRandom;
use aws_lc_rs::signature::{self, UnparsedPublicKey};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use parking_lot::Mutex;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use thiserror::Error;
use zeroize::Zeroizing;

const PENDING_LIFETIME: Duration = Duration::from_secs(600);
const MAX_PENDING: usize = 256;
const KEYS_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
const CLOCK_SKEW: i64 = 60;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<Zeroizing<String>>,
    pub redirect_url: String,
    /// Extra trusted CA for the issuer, for private identity providers.
    pub ca: Option<PathBuf>,
}

#[derive(Debug, Error)]
#[error("{0}")]
pub struct OidcError(String);

fn error(message: impl Into<String>) -> OidcError {
    OidcError(message.into())
}

#[derive(Clone, Debug, Deserialize)]
struct Metadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

#[derive(Clone, Debug, Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

struct Pending {
    nonce: String,
    verifier: String,
    created: Instant,
}

/// What a verified ID token says about the user.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcIdentity {
    pub subject: String,
    pub email: String,
    pub email_verified: bool,
}

pub struct OidcClient {
    config: OidcConfig,
    http: reqwest::Client,
    metadata: tokio::sync::Mutex<Option<Metadata>>,
    keys: tokio::sync::Mutex<Option<(Vec<Jwk>, Instant)>>,
    pending: Mutex<HashMap<String, Pending>>,
}

impl OidcClient {
    pub fn new(config: OidcConfig) -> Result<Self, OidcError> {
        let mut builder = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none());
        if let Some(path) = &config.ca {
            let pem = std::fs::read(path)
                .map_err(|failure| error(format!("read {}: {failure}", path.display())))?;
            let certificate = reqwest::Certificate::from_pem(&pem)
                .map_err(|failure| error(format!("parse {}: {failure}", path.display())))?;
            builder = builder.add_root_certificate(certificate);
        }
        let http = builder
            .build()
            .map_err(|failure| error(format!("create the OIDC HTTP client: {failure}")))?;
        Ok(Self {
            config,
            http,
            metadata: tokio::sync::Mutex::new(None),
            keys: tokio::sync::Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
        })
    }

    /// The identity provider URL that starts a sign-in.
    pub async fn start(&self) -> Result<String, OidcError> {
        let metadata = self.metadata().await?;
        let state = random_token(16)?;
        let nonce = random_token(16)?;
        let verifier = random_token(32)?;
        let challenge =
            URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, verifier.as_bytes()));
        {
            let mut pending = self.pending.lock();
            pending.retain(|_, entry| entry.created.elapsed() < PENDING_LIFETIME);
            if pending.len() >= MAX_PENDING {
                return Err(error("too many sign-ins in progress; try again shortly"));
            }
            pending.insert(
                state.clone(),
                Pending {
                    nonce: nonce.clone(),
                    verifier,
                    created: Instant::now(),
                },
            );
        }
        let mut url = reqwest::Url::parse(&metadata.authorization_endpoint)
            .map_err(|failure| error(format!("invalid authorization endpoint: {failure}")))?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.redirect_url)
            .append_pair("scope", "openid email profile")
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(url.into())
    }

    /// Redeems the authorization `code` of the sign-in started with `state`.
    pub async fn finish(&self, code: &str, state: &str) -> Result<OidcIdentity, OidcError> {
        let pending = self
            .pending
            .lock()
            .remove(state)
            .filter(|entry| entry.created.elapsed() < PENDING_LIFETIME)
            .ok_or_else(|| error("the sign-in expired or was already used; start again"))?;
        let metadata = self.metadata().await?;
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.config.redirect_url.as_str()),
            ("client_id", self.config.client_id.as_str()),
            ("code_verifier", pending.verifier.as_str()),
        ];
        let secret = self
            .config
            .client_secret
            .as_ref()
            .map(|secret| secret.to_string());
        if let Some(secret) = &secret {
            form.push(("client_secret", secret.as_str()));
        }
        let body = form
            .iter()
            .map(|(name, value)| format!("{name}={}", form_component(value)))
            .collect::<Vec<_>>()
            .join("&");
        let response = self
            .http
            .post(&metadata.token_endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|failure| error(format!("token request failed: {failure}")))?;
        if !response.status().is_success() {
            return Err(error(format!(
                "token endpoint returned {}",
                response.status()
            )));
        }
        #[derive(Deserialize)]
        struct TokenResponse {
            id_token: String,
        }
        let token: TokenResponse = json(response)
            .await
            .map_err(|failure| error(format!("invalid token response: {failure}")))?;
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let keys = self.keys(false).await?;
        match verify_id_token(&token.id_token, &keys, &self.config, &pending.nonce, now) {
            Err(KeyLookup::UnknownKey) => {
                // The provider may have rotated its keys.
                let keys = self.keys(true).await?;
                verify_id_token(&token.id_token, &keys, &self.config, &pending.nonce, now)
                    .map_err(KeyLookup::into_error)
            }
            result => result.map_err(KeyLookup::into_error),
        }
    }

    async fn metadata(&self) -> Result<Metadata, OidcError> {
        let mut cached = self.metadata.lock().await;
        if let Some(metadata) = cached.as_ref() {
            return Ok(metadata.clone());
        }
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer.trim_end_matches('/')
        );
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|failure| error(format!("discovery failed: {failure}")))?;
        let metadata: Metadata = json(response)
            .await
            .map_err(|failure| error(format!("invalid discovery document: {failure}")))?;
        if metadata.issuer.trim_end_matches('/') != self.config.issuer.trim_end_matches('/') {
            return Err(error("the discovery document names a different issuer"));
        }
        *cached = Some(metadata.clone());
        Ok(metadata)
    }

    async fn keys(&self, refresh: bool) -> Result<Vec<Jwk>, OidcError> {
        let mut cached = self.keys.lock().await;
        if let Some((keys, fetched)) = cached.as_ref() {
            if !refresh || fetched.elapsed() < KEYS_REFRESH_INTERVAL {
                return Ok(keys.clone());
            }
        }
        let metadata = self.metadata().await?;
        let response = self
            .http
            .get(&metadata.jwks_uri)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|failure| error(format!("could not fetch signing keys: {failure}")))?;
        let set: JwkSet = json(response)
            .await
            .map_err(|failure| error(format!("invalid signing keys: {failure}")))?;
        *cached = Some((set.keys.clone(), Instant::now()));
        Ok(set.keys)
    }
}

enum KeyLookup {
    UnknownKey,
    Invalid(String),
}

impl KeyLookup {
    fn into_error(self) -> OidcError {
        match self {
            Self::UnknownKey => error("the ID token is signed with an unknown key"),
            Self::Invalid(message) => error(message),
        }
    }
}

fn invalid(message: impl Into<String>) -> KeyLookup {
    KeyLookup::Invalid(message.into())
}

fn verify_id_token(
    token: &str,
    keys: &[Jwk],
    config: &OidcConfig,
    nonce: &str,
    now: i64,
) -> Result<OidcIdentity, KeyLookup> {
    let parts = token.split('.').collect::<Vec<_>>();
    let [header, payload, signature] = parts.as_slice() else {
        return Err(invalid("the ID token is not a signed JWT"));
    };
    let decode = |part: &str| {
        URL_SAFE_NO_PAD
            .decode(part)
            .map_err(|_| invalid("invalid JWT encoding"))
    };
    #[derive(Deserialize)]
    struct Header {
        alg: String,
        #[serde(default)]
        kid: Option<String>,
    }
    let header: Header =
        serde_json::from_slice(&decode(header)?).map_err(|_| invalid("invalid JWT header"))?;
    let (kty, algorithm): (&str, &'static dyn signature::VerificationAlgorithm) =
        match header.alg.as_str() {
            "RS256" => ("RSA", &signature::RSA_PKCS1_2048_8192_SHA256),
            "ES256" => ("EC", &signature::ECDSA_P256_SHA256_FIXED),
            other => return Err(invalid(format!("unsupported ID token algorithm {other}"))),
        };
    let candidates = keys
        .iter()
        .filter(|key| key.kty == kty)
        .filter(|key| header.kid.is_none() || key.kid == header.kid)
        .collect::<Vec<_>>();
    let key = match candidates.as_slice() {
        [key] => *key,
        [] => return Err(KeyLookup::UnknownKey),
        _ => return Err(invalid("the ID token's signing key is ambiguous")),
    };
    let message = format!("{}.{}", parts[0], parts[1]);
    let signature = decode(signature)?;
    let verified = match kty {
        "RSA" => {
            let (Some(n), Some(e)) = (&key.n, &key.e) else {
                return Err(invalid("incomplete RSA signing key"));
            };
            signature::RsaPublicKeyComponents {
                n: decode(n)?,
                e: decode(e)?,
            }
            .verify(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                message.as_bytes(),
                &signature,
            )
            .is_ok()
        }
        _ => {
            let (Some("P-256"), Some(x), Some(y)) = (key.crv.as_deref(), &key.x, &key.y) else {
                return Err(invalid("unsupported EC signing key"));
            };
            let mut point = vec![0x04];
            point.extend(decode(x)?);
            point.extend(decode(y)?);
            UnparsedPublicKey::new(algorithm, point)
                .verify(message.as_bytes(), &signature)
                .is_ok()
        }
    };
    if !verified {
        return Err(invalid("the ID token signature is invalid"));
    }
    #[derive(Deserialize)]
    struct Claims {
        iss: String,
        sub: String,
        aud: serde_json::Value,
        #[serde(default)]
        azp: Option<String>,
        exp: i64,
        #[serde(default)]
        iat: Option<i64>,
        #[serde(default)]
        nonce: Option<String>,
        #[serde(default)]
        email: Option<String>,
        #[serde(default)]
        email_verified: Option<serde_json::Value>,
    }
    let claims: Claims = serde_json::from_slice(&decode(payload)?)
        .map_err(|_| invalid("invalid ID token claims"))?;
    if claims.iss.trim_end_matches('/') != config.issuer.trim_end_matches('/') {
        return Err(invalid("the ID token comes from another issuer"));
    }
    let audiences = match &claims.aud {
        serde_json::Value::String(audience) => vec![audience.as_str()],
        serde_json::Value::Array(values) => values
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect(),
        _ => Vec::new(),
    };
    if !audiences.contains(&config.client_id.as_str())
        || (audiences.len() > 1 && claims.azp.as_deref() != Some(config.client_id.as_str()))
    {
        return Err(invalid("the ID token is for another client"));
    }
    if claims.exp + CLOCK_SKEW < now || claims.iat.is_some_and(|issued| issued - CLOCK_SKEW > now) {
        return Err(invalid("the ID token has expired"));
    }
    if claims.nonce.as_deref() != Some(nonce) {
        return Err(invalid("the ID token does not belong to this sign-in"));
    }
    Ok(OidcIdentity {
        subject: claims.sub,
        email: claims.email.unwrap_or_default().to_ascii_lowercase(),
        email_verified: matches!(claims.email_verified, Some(serde_json::Value::Bool(true)))
            || matches!(&claims.email_verified, Some(serde_json::Value::String(value)) if value == "true"),
    })
}

async fn json<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> Result<T, String> {
    let body = response
        .bytes()
        .await
        .map_err(|failure| failure.to_string())?;
    serde_json::from_slice(&body).map_err(|failure| failure.to_string())
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

fn random_token(bytes: usize) -> Result<String, OidcError> {
    let mut value = vec![0_u8; bytes];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut value)
        .map_err(|_| error("could not generate a random value"))?;
    Ok(URL_SAFE_NO_PAD.encode(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

    fn config() -> OidcConfig {
        OidcConfig {
            issuer: "https://id.example".into(),
            client_id: "porta".into(),
            client_secret: None,
            redirect_url: "https://vpn.example/auth/oidc/callback".into(),
            ca: None,
        }
    }

    fn sign(key: &EcdsaKeyPair, kid: &str, claims: serde_json::Value) -> String {
        let header =
            URL_SAFE_NO_PAD.encode(serde_json::json!({"alg": "ES256", "kid": kid}).to_string());
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
        let message = format!("{header}.{payload}");
        let signature = key
            .sign(&aws_lc_rs::rand::SystemRandom::new(), message.as_bytes())
            .unwrap();
        format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
    }

    #[test]
    fn id_tokens_are_checked_for_signature_issuer_audience_expiry_and_nonce() {
        let document = EcdsaKeyPair::generate_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &aws_lc_rs::rand::SystemRandom::new(),
        )
        .unwrap();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, document.as_ref()).unwrap();
        let point = key.public_key().as_ref();
        let jwk = Jwk {
            kty: "EC".into(),
            kid: Some("k1".into()),
            n: None,
            e: None,
            crv: Some("P-256".into()),
            x: Some(URL_SAFE_NO_PAD.encode(&point[1..33])),
            y: Some(URL_SAFE_NO_PAD.encode(&point[33..65])),
        };
        let now = 1_900_000_000;
        let claims = serde_json::json!({
            "iss": "https://id.example", "sub": "user-1", "aud": "porta", "exp": now + 300,
            "iat": now, "nonce": "n1", "email": "Alice@Example.com", "email_verified": true,
        });
        let identity = verify_id_token(
            &sign(&key, "k1", claims.clone()),
            std::slice::from_ref(&jwk),
            &config(),
            "n1",
            now,
        )
        .ok()
        .unwrap();
        assert_eq!(identity.email, "alice@example.com");
        assert!(identity.email_verified);

        let mutate = |field: &str, value: serde_json::Value| {
            let mut claims = claims.clone();
            claims[field] = value;
            claims
        };
        for (claims, nonce) in [
            (mutate("iss", "https://evil.example".into()), "n1"),
            (mutate("aud", "other".into()), "n1"),
            (mutate("aud", serde_json::json!(["porta", "other"])), "n1"),
            (mutate("exp", (now - 120).into()), "n1"),
            (claims.clone(), "n2"),
        ] {
            assert!(verify_id_token(
                &sign(&key, "k1", claims),
                std::slice::from_ref(&jwk),
                &config(),
                nonce,
                now
            )
            .is_err());
        }
        // An unknown key ID asks for a key refresh; a tampered token fails.
        assert!(matches!(
            verify_id_token(
                &sign(&key, "k2", claims.clone()),
                std::slice::from_ref(&jwk),
                &config(),
                "n1",
                now
            ),
            Err(KeyLookup::UnknownKey)
        ));
        let token = sign(&key, "k1", claims);
        let mut parts = token.split('.').map(str::to_owned).collect::<Vec<_>>();
        parts[1] = URL_SAFE_NO_PAD.encode(
            serde_json::json!({"iss": "https://id.example", "sub": "admin", "aud": "porta", "exp": now + 300, "nonce": "n1"})
                .to_string(),
        );
        assert!(matches!(
            verify_id_token(&parts.join("."), &[jwk], &config(), "n1", now),
            Err(KeyLookup::Invalid(_))
        ));
    }
}
