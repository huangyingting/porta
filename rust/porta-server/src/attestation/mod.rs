//! Device key attestation: verifying that a device's signing key lives in
//! secure hardware (an Android TEE or StrongBox, or a TPM), and the gateway
//! endpoints devices send their evidence to.

pub mod android;
pub mod der;
pub mod service;
pub mod x509;

use thiserror::Error;

/// Why evidence was refused. Clients show the message.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AttestationError {
    /// The evidence is malformed or does not describe the device key.
    #[error("{0}")]
    Invalid(&'static str),
    /// The evidence is well formed but not trustworthy.
    #[error("{0}")]
    Untrusted(&'static str),
}

impl AttestationError {
    pub const fn invalid(message: &'static str) -> Self {
        Self::Invalid(message)
    }

    pub const fn untrusted(message: &'static str) -> Self {
        Self::Untrusted(message)
    }
}
