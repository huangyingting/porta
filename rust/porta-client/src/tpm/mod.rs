//! A small TPM 2.0 client: enough to keep Porta's device key in a TPM, sign
//! with it, and prove to the gateway that the key lives there. The proof is
//! credential activation: the gateway encrypts a secret to the TPM's
//! endorsement key, bound to the device key's name, and only that TPM, with
//! that key loaded, can recover it (TPM2_ActivateCredential).

pub mod transport;

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use porta_wire::tpm::{Public, Reader, ALG_NULL, ALG_SHA256};
use rand::Rng as _;
use thiserror::Error;

use transport::Transport;

const TAG_NO_SESSIONS: u16 = 0x8001;
const TAG_SESSIONS: u16 = 0x8002;
const TAG_HASHCHECK: u16 = 0x8024;

const CC_NV_READ: u32 = 0x0000_014E;
const CC_ACTIVATE_CREDENTIAL: u32 = 0x0000_0147;
const CC_CREATE: u32 = 0x0000_0153;
const CC_CREATE_PRIMARY: u32 = 0x0000_0131;
const CC_LOAD: u32 = 0x0000_0157;
const CC_POLICY_SECRET: u32 = 0x0000_0151;
const CC_SIGN: u32 = 0x0000_015D;
const CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
const CC_NV_READ_PUBLIC: u32 = 0x0000_0169;
const CC_READ_PUBLIC: u32 = 0x0000_0173;
const CC_START_AUTH_SESSION: u32 = 0x0000_0176;

const RH_OWNER: u32 = 0x4000_0001;
const RH_NULL: u32 = 0x4000_0007;
const RS_PW: u32 = 0x4000_0009;
const RH_ENDORSEMENT: u32 = 0x4000_000B;
/// Where Windows and many vendors persist the storage root key and the RSA
/// endorsement key.
const PERSISTENT_SRK: u32 = 0x8100_0001;
const PERSISTENT_EK: u32 = 0x8101_0001;
/// The TCG NV index of the RSA 2048 endorsement key certificate.
const NV_EK_CERTIFICATE: u32 = 0x01C0_0002;
/// TPMA_NV_AUTHREAD: the index authorizes reads with its own auth value.
const NV_AUTHREAD: u32 = 1 << 18;
const SESSION_POLICY: u8 = 0x01;
const CONTINUE_SESSION: u8 = 0x01;
const NV_CHUNK: u16 = 512;

#[derive(Debug, Error)]
pub enum TpmError {
    #[error("no TPM is available: {0}")]
    Unavailable(String),
    #[error("TPM I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("the TPM refused a command (response code {0:#x})")]
    Code(u32),
    #[error("the TPM sent a malformed response")]
    Malformed,
    #[error("the TPM has no endorsement key certificate")]
    NoCertificate,
    #[error("the saved TPM key is invalid")]
    InvalidKey,
}

impl From<porta_wire::tpm::MalformedTpm> for TpmError {
    fn from(_: porta_wire::tpm::MalformedTpm) -> Self {
        Self::Malformed
    }
}

/// How a command is authorized: the empty password, or a policy session.
#[derive(Clone, Copy)]
enum Auth {
    Password,
    Policy(u32),
}

pub struct Tpm {
    transport: Box<dyn Transport>,
}

/// The endorsement key's public area and certificate.
pub struct Endorsement {
    pub public: Vec<u8>,
    pub certificate: Vec<u8>,
}

/// Where a device key's parent lives: the persistent storage root key, or a
/// storage root recreated from Porta's template each time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Parent {
    Persistent,
    Primary,
}

impl Parent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Persistent => "persistent",
            Self::Primary => "primary",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "persistent" => Some(Self::Persistent),
            "primary" => Some(Self::Primary),
            _ => None,
        }
    }
}

impl Tpm {
    /// The TPM to use: `PORTA_TPM_TCP=host:port` names a simulator;
    /// otherwise the platform's TPM.
    pub fn open() -> Result<Arc<Self>, TpmError> {
        if let Some(address) = std::env::var_os("PORTA_TPM_TCP") {
            let address = address
                .to_str()
                .and_then(|value| value.parse().ok())
                .ok_or_else(|| TpmError::Unavailable("PORTA_TPM_TCP is not host:port".into()))?;
            return Ok(Self::with_transport(Box::new(transport::Socket::new(
                address,
            ))));
        }
        #[cfg(windows)]
        {
            let tbs =
                transport::Tbs::open().map_err(|error| TpmError::Unavailable(error.to_string()))?;
            Ok(Self::with_transport(Box::new(tbs)))
        }
        #[cfg(target_os = "linux")]
        {
            let device = transport::Device::open(std::path::Path::new("/dev/tpmrm0"))
                .map_err(|error| TpmError::Unavailable(format!("/dev/tpmrm0: {error}")))?;
            Ok(Self::with_transport(Box::new(device)))
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        Err(TpmError::Unavailable(
            "this platform has no TPM support".into(),
        ))
    }

    pub fn with_transport(transport: Box<dyn Transport>) -> Arc<Self> {
        Arc::new(Self { transport })
    }

    /// Runs a command; returns the response's handles and parameters.
    fn run(
        &self,
        code: u32,
        handles: &[u32],
        auths: &[Auth],
        parameters: &[u8],
        response_handles: usize,
    ) -> Result<(Vec<u32>, Vec<u8>), TpmError> {
        let mut body = Vec::with_capacity(64 + parameters.len());
        for handle in handles {
            body.extend(handle.to_be_bytes());
        }
        if !auths.is_empty() {
            let mut area = Vec::new();
            for auth in auths {
                match *auth {
                    Auth::Password => {
                        area.extend(RS_PW.to_be_bytes());
                        area.extend(0_u16.to_be_bytes());
                        area.push(CONTINUE_SESSION);
                        area.extend(0_u16.to_be_bytes());
                    }
                    Auth::Policy(session) => {
                        let mut nonce = [0_u8; 16];
                        rand::rng().fill_bytes(&mut nonce);
                        area.extend(session.to_be_bytes());
                        area.extend((nonce.len() as u16).to_be_bytes());
                        area.extend(nonce);
                        area.push(0);
                        area.extend(0_u16.to_be_bytes());
                    }
                }
            }
            body.extend((area.len() as u32).to_be_bytes());
            body.extend(area);
        }
        body.extend(parameters);
        let tag = if auths.is_empty() {
            TAG_NO_SESSIONS
        } else {
            TAG_SESSIONS
        };
        let mut command = Vec::with_capacity(10 + body.len());
        command.extend(tag.to_be_bytes());
        command.extend(((10 + body.len()) as u32).to_be_bytes());
        command.extend(code.to_be_bytes());
        command.extend(body);

        let response = self.transport.transmit(&command)?;
        let mut reader = Reader(&response);
        let response_tag = reader.u16()?;
        let size = reader.u32()? as usize;
        let result = reader.u32()?;
        if size != response.len() {
            return Err(TpmError::Malformed);
        }
        if result != 0 {
            return Err(TpmError::Code(result));
        }
        let mut handles = Vec::with_capacity(response_handles);
        for _ in 0..response_handles {
            handles.push(reader.u32()?);
        }
        let parameters = if response_tag == TAG_SESSIONS {
            let length = reader.u32()? as usize;
            reader.bytes(length)?.to_vec()
        } else {
            reader.rest().to_vec()
        };
        Ok((handles, parameters))
    }

    fn flush(&self, handle: u32) {
        let _ = self.run(CC_FLUSH_CONTEXT, &[], &[], &handle.to_be_bytes(), 0);
    }

    /// The `TPMT_PUBLIC` of a loaded or persistent object.
    fn read_public(&self, handle: u32) -> Result<Vec<u8>, TpmError> {
        let (_, parameters) = self.run(CC_READ_PUBLIC, &[handle], &[], &[], 0)?;
        Ok(Reader(&parameters).sized()?.to_vec())
    }

    fn create_primary(
        &self,
        hierarchy: u32,
        template: &Public,
    ) -> Result<(u32, Vec<u8>), TpmError> {
        let mut parameters = sensitive_create();
        put_sized(&mut parameters, &template.encode());
        parameters.extend(0_u16.to_be_bytes()); // outsideInfo
        parameters.extend(0_u32.to_be_bytes()); // creationPCR
        let (handles, response) = self.run(
            CC_CREATE_PRIMARY,
            &[hierarchy],
            &[Auth::Password],
            &parameters,
            1,
        )?;
        let public = Reader(&response).sized()?.to_vec();
        Ok((handles[0], public))
    }

    /// The parent to create device keys under, and whether to flush it.
    fn storage_root(&self) -> Result<(Parent, u32, bool), TpmError> {
        if self.read_public(PERSISTENT_SRK).is_ok() {
            return Ok((Parent::Persistent, PERSISTENT_SRK, false));
        }
        let (handle, _) = self.create_primary(RH_OWNER, &Public::storage_root_ecc())?;
        Ok((Parent::Primary, handle, true))
    }

    fn load_parent(&self, parent: Parent) -> Result<(u32, bool), TpmError> {
        match parent {
            Parent::Persistent => Ok((PERSISTENT_SRK, false)),
            Parent::Primary => {
                let (handle, _) = self.create_primary(RH_OWNER, &Public::storage_root_ecc())?;
                Ok((handle, true))
            }
        }
    }

    /// Generates a new device key in the TPM.
    pub fn create_device_key(self: &Arc<Self>) -> Result<DeviceKey, TpmError> {
        let (parent, handle, transient) = self.storage_root()?;
        let mut parameters = sensitive_create();
        put_sized(&mut parameters, &Public::device_key().encode());
        parameters.extend(0_u16.to_be_bytes());
        parameters.extend(0_u32.to_be_bytes());
        let result = self.run(CC_CREATE, &[handle], &[Auth::Password], &parameters, 0);
        if transient {
            self.flush(handle);
        }
        let (_, response) = result?;
        let mut reader = Reader(&response);
        let private = reader.sized()?.to_vec();
        let public = reader.sized()?.to_vec();
        DeviceKey::from_parts(Arc::clone(self), parent, private, public)
    }

    /// The endorsement key, and whether to flush it after use.
    fn endorsement_key(&self) -> Result<(u32, Vec<u8>, bool), TpmError> {
        if let Ok(public) = self.read_public(PERSISTENT_EK) {
            if is_rsa_endorsement(&public) {
                return Ok((PERSISTENT_EK, public, false));
            }
        }
        let (handle, public) = self.create_primary(RH_ENDORSEMENT, &Public::endorsement_rsa())?;
        Ok((handle, public, true))
    }

    /// The RSA endorsement key and its certificate.
    pub fn endorsement(&self) -> Result<Endorsement, TpmError> {
        let (handle, public, transient) = self.endorsement_key()?;
        if transient {
            self.flush(handle);
        }
        let certificate = match self.read_nv(NV_EK_CERTIFICATE) {
            Ok(certificate) => certificate,
            Err(error) => platform_ek_certificate().ok_or(match error {
                TpmError::Code(_) => TpmError::NoCertificate,
                error => error,
            })?,
        };
        Ok(Endorsement {
            public,
            certificate: trim_der(certificate),
        })
    }

    fn read_nv(&self, index: u32) -> Result<Vec<u8>, TpmError> {
        let (_, response) = self.run(CC_NV_READ_PUBLIC, &[index], &[], &[], 0)?;
        let mut reader = Reader(&response);
        let public = reader.sized()?;
        let mut public = Reader(public);
        let _index = public.u32()?;
        let _name_alg = public.u16()?;
        let attributes = public.u32()?;
        let _policy = public.sized()?;
        let size = public.u16()?;
        let authorization = if attributes & NV_AUTHREAD != 0 {
            index
        } else {
            RH_OWNER
        };
        let mut data = Vec::with_capacity(usize::from(size));
        while data.len() < usize::from(size) {
            let chunk = NV_CHUNK.min(size - data.len() as u16);
            let mut parameters = chunk.to_be_bytes().to_vec();
            parameters.extend((data.len() as u16).to_be_bytes());
            let (_, response) = self.run(
                CC_NV_READ,
                &[authorization, index],
                &[Auth::Password],
                &parameters,
                0,
            )?;
            data.extend(Reader(&response).sized()?);
        }
        Ok(data)
    }
}

/// An empty `TPM2B_SENSITIVE_CREATE`: no auth value, no data.
fn sensitive_create() -> Vec<u8> {
    vec![0x00, 0x04, 0x00, 0x00, 0x00, 0x00]
}

fn put_sized(out: &mut Vec<u8>, value: &[u8]) {
    out.extend((value.len() as u16).to_be_bytes());
    out.extend(value);
}

fn is_rsa_endorsement(public: &[u8]) -> bool {
    Public::decode(public).is_ok_and(|public| {
        let template = Public::endorsement_rsa();
        public.kind == template.kind
            && public.attributes == template.attributes
            && public.auth_policy == template.auth_policy
    })
}

/// NV certificates may be padded after the DER structure.
fn trim_der(mut certificate: Vec<u8>) -> Vec<u8> {
    if certificate.len() > 4 && certificate[0] == 0x30 && certificate[1] == 0x82 {
        let length = usize::from(u16::from_be_bytes([certificate[2], certificate[3]])) + 4;
        if length <= certificate.len() {
            certificate.truncate(length);
        }
    }
    certificate
}

/// Windows keeps endorsement certificates it downloaded from the TPM vendor,
/// as fTPMs often have none in NV.
#[cfg(windows)]
fn platform_ek_certificate() -> Option<Vec<u8>> {
    windows_ek::certificate()
}

#[cfg(not(windows))]
fn platform_ek_certificate() -> Option<Vec<u8>> {
    None
}

/// A device key in the TPM: its public area, and its private area wrapped
/// by the storage root key, which only that TPM can load.
pub struct DeviceKey {
    tpm: Arc<Tpm>,
    parent: Parent,
    private: Vec<u8>,
    public: Vec<u8>,
    spki: Vec<u8>,
}

impl DeviceKey {
    pub fn from_parts(
        tpm: Arc<Tpm>,
        parent: Parent,
        private: Vec<u8>,
        public: Vec<u8>,
    ) -> Result<Self, TpmError> {
        let decoded = Public::decode(&public).map_err(|_| TpmError::InvalidKey)?;
        let template = Public::device_key();
        if decoded.kind != template.kind
            || decoded.name_alg != ALG_SHA256
            || decoded.attributes != template.attributes
            || decoded.parameters != template.parameters
        {
            return Err(TpmError::InvalidKey);
        }
        let spki = decoded.p256_spki().ok_or(TpmError::InvalidKey)?;
        Ok(Self {
            tpm,
            parent,
            private,
            public,
            spki,
        })
    }

    pub fn tpm(&self) -> &Arc<Tpm> {
        &self.tpm
    }

    pub fn parent(&self) -> Parent {
        self.parent
    }

    /// The `TPM2B_PRIVATE` contents, safe to store: only this TPM can use them.
    pub fn private_blob(&self) -> &[u8] {
        &self.private
    }

    /// The `TPMT_PUBLIC`.
    pub fn public_area(&self) -> &[u8] {
        &self.public
    }

    /// The DER `SubjectPublicKeyInfo`.
    pub fn spki(&self) -> &[u8] {
        &self.spki
    }

    /// Loads the key; the caller flushes the handle.
    fn load(&self) -> Result<u32, TpmError> {
        let (parent, transient) = self.tpm.load_parent(self.parent)?;
        let mut parameters = Vec::with_capacity(self.private.len() + self.public.len() + 4);
        put_sized(&mut parameters, &self.private);
        put_sized(&mut parameters, &self.public);
        let result = self
            .tpm
            .run(CC_LOAD, &[parent], &[Auth::Password], &parameters, 1);
        if transient {
            self.tpm.flush(parent);
        }
        Ok(result?.0[0])
    }

    /// Signs a SHA-256 `digest`; returns a DER ECDSA signature.
    pub fn sign(&self, digest: &[u8; 32]) -> Result<Vec<u8>, TpmError> {
        let handle = self.load()?;
        let mut parameters = Vec::with_capacity(48);
        put_sized(&mut parameters, digest);
        parameters.extend(ALG_NULL.to_be_bytes()); // the key's own scheme
        parameters.extend(TAG_HASHCHECK.to_be_bytes());
        parameters.extend(RH_NULL.to_be_bytes());
        parameters.extend(0_u16.to_be_bytes());
        let result = self
            .tpm
            .run(CC_SIGN, &[handle], &[Auth::Password], &parameters, 0);
        self.tpm.flush(handle);
        let (_, response) = result?;
        let mut reader = Reader(&response);
        let _algorithm = reader.u16()?;
        let _hash = reader.u16()?;
        let r = reader.sized()?;
        let s = reader.sized()?;
        let pad = |value: &[u8]| -> Result<[u8; 32], TpmError> {
            if value.len() > 32 {
                return Err(TpmError::Malformed);
            }
            let mut padded = [0_u8; 32];
            padded[32 - value.len()..].copy_from_slice(value);
            Ok(padded)
        };
        let signature = p256::ecdsa::Signature::from_scalars(pad(r)?, pad(s)?)
            .map_err(|_| TpmError::Malformed)?;
        let signature = signature.normalize_s();
        Ok(signature.to_der().as_bytes().to_vec())
    }

    /// Recovers the secret a gateway encrypted to this TPM's endorsement key
    /// for this key's name. `credential_blob` and `encrypted_secret` are the
    /// `TPM2B_ID_OBJECT` and `TPM2B_ENCRYPTED_SECRET`, size included.
    pub fn activate_credential(
        &self,
        credential_blob: &[u8],
        encrypted_secret: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        let (endorsement, _, endorsement_transient) = self.tpm.endorsement_key()?;
        let flush_endorsement = || {
            if endorsement_transient {
                self.tpm.flush(endorsement);
            }
        };
        let key = match self.load() {
            Ok(key) => key,
            Err(error) => {
                flush_endorsement();
                return Err(error);
            }
        };
        let result = (|| {
            // A policy session satisfying the endorsement key's policy.
            let mut parameters = Vec::new();
            let mut nonce = [0_u8; 16];
            rand::rng().fill_bytes(&mut nonce);
            put_sized(&mut parameters, &nonce);
            parameters.extend(0_u16.to_be_bytes()); // encryptedSalt
            parameters.push(SESSION_POLICY);
            parameters.extend(ALG_NULL.to_be_bytes()); // symmetric
            parameters.extend(ALG_SHA256.to_be_bytes());
            let (handles, _) = self.tpm.run(
                CC_START_AUTH_SESSION,
                &[RH_NULL, RH_NULL],
                &[],
                &parameters,
                1,
            )?;
            let session = handles[0];
            let activated = (|| {
                let mut parameters = Vec::new();
                parameters.extend(0_u16.to_be_bytes()); // nonceTPM
                parameters.extend(0_u16.to_be_bytes()); // cpHashA
                parameters.extend(0_u16.to_be_bytes()); // policyRef
                parameters.extend(0_i32.to_be_bytes()); // expiration
                self.tpm.run(
                    CC_POLICY_SECRET,
                    &[RH_ENDORSEMENT, session],
                    &[Auth::Password],
                    &parameters,
                    0,
                )?;
                let mut parameters = credential_blob.to_vec();
                parameters.extend(encrypted_secret);
                let (_, response) = self.tpm.run(
                    CC_ACTIVATE_CREDENTIAL,
                    &[key, endorsement],
                    &[Auth::Password, Auth::Policy(session)],
                    &parameters,
                    0,
                )?;
                Ok::<_, TpmError>(Reader(&response).sized()?.to_vec())
            })();
            if activated.is_err() {
                self.tpm.flush(session);
            }
            activated
        })();
        self.tpm.flush(key);
        flush_endorsement();
        result
    }
}

/// Proves to the gateway that `key` lives in this TPM, which records the
/// device as hardware-protected.
pub async fn attest(
    config: &crate::tunnel::ClientConfig,
    key: Arc<DeviceKey>,
) -> Result<porta_wire::attestation::AttestationResult, crate::tunnel::ClientError> {
    use crate::tunnel::ClientError;
    let tpm = Arc::clone(key.tpm());
    let endorsement = tokio::task::spawn_blocking(move || tpm.endorsement())
        .await
        .map_err(ClientError::permanent)?
        .map_err(ClientError::permanent)?;
    let request = porta_wire::attestation::TpmChallengeRequest {
        endorsement_key: URL_SAFE_NO_PAD.encode(&endorsement.public),
        endorsement_certificates: vec![URL_SAFE_NO_PAD.encode(&endorsement.certificate)],
        device_key: URL_SAFE_NO_PAD.encode(key.public_area()),
    };
    let challenge = crate::tunnel::tpm_challenge(config, &request).await?;
    let decode = |value: &str| {
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| ClientError::permanent("the gateway's challenge is malformed"))
    };
    let credential_blob = decode(&challenge.credential_blob)?;
    let encrypted_secret = decode(&challenge.encrypted_secret)?;
    let secret = tokio::task::spawn_blocking(move || {
        key.activate_credential(&credential_blob, &encrypted_secret)
    })
    .await
    .map_err(ClientError::permanent)?
    .map_err(|error| {
        ClientError::permanent(format!("the TPM could not answer the challenge: {error}"))
    })?;
    crate::tunnel::attest(
        config,
        &porta_wire::attestation::AttestationRequest::Tpm {
            challenge: challenge.challenge,
            secret: URL_SAFE_NO_PAD.encode(secret),
        },
    )
    .await
}

#[cfg(windows)]
mod windows_ek {
    use windows_sys::Win32::Security::Cryptography::{
        CertCloseStore, CertEnumCertificatesInStore, CertOpenStore, NCryptFreeObject,
        NCryptGetProperty, NCryptOpenStorageProvider, CERT_QUERY_ENCODING_TYPE,
        CERT_STORE_PROV_SERIALIZED, CRYPT_INTEGER_BLOB, NCRYPT_PROV_HANDLE,
    };

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// The endorsement certificate Windows keeps for this TPM, from the
    /// Platform Crypto Provider's `PCP_EKCERT` property: one DER
    /// certificate, or a serialized certificate store.
    pub fn certificate() -> Option<Vec<u8>> {
        let provider_name = wide("Microsoft Platform Crypto Provider");
        let property = wide("PCP_EKCERT");
        let mut provider: NCRYPT_PROV_HANDLE = 0;
        // SAFETY: valid output pointer and NUL-terminated name.
        if unsafe { NCryptOpenStorageProvider(&mut provider, provider_name.as_ptr(), 0) } != 0 {
            return None;
        }
        let mut size = 0_u32;
        // SAFETY: querying the size with a null buffer.
        let queried = unsafe {
            NCryptGetProperty(
                provider,
                property.as_ptr(),
                std::ptr::null_mut(),
                0,
                &mut size,
                0,
            )
        };
        let mut value = vec![0_u8; size as usize];
        let read = queried == 0
            && size > 0
            // SAFETY: the buffer holds `size` bytes.
            && unsafe {
                NCryptGetProperty(provider, property.as_ptr(), value.as_mut_ptr(), size, &mut size, 0)
            } == 0;
        // SAFETY: the handle came from NCryptOpenStorageProvider.
        unsafe { NCryptFreeObject(provider) };
        if !read {
            return None;
        }
        value.truncate(size as usize);
        if value.first() == Some(&0x30) {
            return Some(value);
        }
        let blob = CRYPT_INTEGER_BLOB {
            cbData: value.len() as u32,
            pbData: value.as_mut_ptr(),
        };
        // SAFETY: the blob outlives the store, which is closed below.
        let store = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_SERIALIZED,
                CERT_QUERY_ENCODING_TYPE::default(),
                0,
                0,
                std::ptr::from_ref(&blob).cast(),
            )
        };
        if store.is_null() {
            return None;
        }
        // SAFETY: enumerating from the start of a valid store.
        let context = unsafe { CertEnumCertificatesInStore(store, std::ptr::null()) };
        let certificate = (!context.is_null()).then(|| {
            // SAFETY: a valid certificate context from the store.
            let context = unsafe { &*context };
            // SAFETY: the encoded certificate is valid for its length.
            unsafe {
                std::slice::from_raw_parts(context.pbCertEncoded, context.cbCertEncoded as usize)
            }
            .to_vec()
        });
        // SAFETY: closing the store also frees the context.
        unsafe { CertCloseStore(store, 0) };
        certificate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs against the platform's TPM when `PORTA_TPM_NATIVE_TEST` is set,
    /// as on CI's Windows runners; it reports instead when there is none.
    #[test]
    fn a_real_tpm_keeps_and_uses_a_device_key() {
        use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
        use p256::pkcs8::DecodePublicKey as _;
        if std::env::var_os("PORTA_TPM_NATIVE_TEST").is_none() {
            return;
        }
        let tpm = match Tpm::open() {
            Ok(tpm) => tpm,
            Err(error) => {
                eprintln!("no TPM to test: {error}");
                return;
            }
        };
        let key = tpm.create_device_key().unwrap();
        let digest = [7_u8; 32];
        let verifying = p256::ecdsa::VerifyingKey::from_public_key_der(key.spki()).unwrap();
        let signature = p256::ecdsa::Signature::from_der(&key.sign(&digest).unwrap()).unwrap();
        verifying.verify_prehash(&digest, &signature).unwrap();
        let reloaded = DeviceKey::from_parts(
            Arc::clone(&tpm),
            key.parent(),
            key.private_blob().to_vec(),
            key.public_area().to_vec(),
        )
        .unwrap();
        let signature = p256::ecdsa::Signature::from_der(&reloaded.sign(&digest).unwrap()).unwrap();
        verifying.verify_prehash(&digest, &signature).unwrap();
        match tpm.endorsement() {
            Ok(endorsement) => {
                assert!(is_rsa_endorsement(&endorsement.public));
                assert_eq!(endorsement.certificate.first(), Some(&0x30));
                eprintln!(
                    "the TPM's endorsement certificate has {} bytes",
                    endorsement.certificate.len()
                );
            }
            Err(error) => eprintln!("the TPM's endorsement key is unavailable: {error}"),
        }
        if let Some(marker) = std::env::var_os("PORTA_TPM_NATIVE_TEST_MARKER") {
            std::fs::write(marker, key.parent().as_str()).unwrap();
        }
    }
}
