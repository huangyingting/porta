//! TPM 2.0 structures shared by clients, which create and use keys in a TPM,
//! and the gateway, which checks what a TPM reports: `TPMT_PUBLIC` areas,
//! their names, and the key templates Porta uses.

use sha2::{Digest, Sha256};
use thiserror::Error;

pub const ALG_RSA: u16 = 0x0001;
pub const ALG_SHA256: u16 = 0x000B;
pub const ALG_AES: u16 = 0x0006;
pub const ALG_NULL: u16 = 0x0010;
pub const ALG_ECDSA: u16 = 0x0018;
pub const ALG_ECC: u16 = 0x0023;
pub const ALG_CFB: u16 = 0x0043;
pub const ECC_NIST_P256: u16 = 0x0003;

/// `TPMA_OBJECT` bits.
pub mod attributes {
    pub const FIXED_TPM: u32 = 1 << 1;
    pub const FIXED_PARENT: u32 = 1 << 4;
    pub const SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
    pub const USER_WITH_AUTH: u32 = 1 << 6;
    pub const ADMIN_WITH_POLICY: u32 = 1 << 7;
    pub const NO_DA: u32 = 1 << 10;
    pub const RESTRICTED: u32 = 1 << 16;
    pub const DECRYPT: u32 = 1 << 17;
    pub const SIGN: u32 = 1 << 18;
}

/// The authorization policy of the TCG default endorsement key templates:
/// PolicySecret(TPM_RH_ENDORSEMENT).
pub const EK_POLICY: [u8; 32] = [
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
    0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA,
];

#[derive(Debug, Error, Eq, PartialEq)]
#[error("malformed TPM structure")]
pub struct MalformedTpm;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Public {
    pub kind: u16,
    pub name_alg: u16,
    pub attributes: u32,
    pub auth_policy: Vec<u8>,
    pub parameters: Parameters,
    pub unique: Unique,
}

/// A symmetric definition, scheme or KDF: an algorithm and, unless it is
/// `TPM_ALG_NULL`, its details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Symmetric {
    pub algorithm: u16,
    pub key_bits: u16,
    pub mode: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scheme {
    pub algorithm: u16,
    pub hash: u16,
}

impl Symmetric {
    pub const NULL: Self = Self {
        algorithm: ALG_NULL,
        key_bits: 0,
        mode: 0,
    };
    pub const AES_128_CFB: Self = Self {
        algorithm: ALG_AES,
        key_bits: 128,
        mode: ALG_CFB,
    };
}

impl Scheme {
    pub const NULL: Self = Self {
        algorithm: ALG_NULL,
        hash: 0,
    };
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Parameters {
    Rsa {
        symmetric: Symmetric,
        scheme: Scheme,
        key_bits: u16,
        exponent: u32,
    },
    Ecc {
        symmetric: Symmetric,
        scheme: Scheme,
        curve: u16,
        kdf: Scheme,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Unique {
    Rsa(Vec<u8>),
    Ecc { x: Vec<u8>, y: Vec<u8> },
}

impl Public {
    /// The TCG default RSA 2048 endorsement key (template L-1), whose
    /// certificate TPM vendors provision.
    pub fn endorsement_rsa() -> Self {
        use attributes::*;
        Self {
            kind: ALG_RSA,
            name_alg: ALG_SHA256,
            attributes: FIXED_TPM
                | FIXED_PARENT
                | SENSITIVE_DATA_ORIGIN
                | ADMIN_WITH_POLICY
                | RESTRICTED
                | DECRYPT,
            auth_policy: EK_POLICY.to_vec(),
            parameters: Parameters::Rsa {
                symmetric: Symmetric::AES_128_CFB,
                scheme: Scheme::NULL,
                key_bits: 2048,
                exponent: 0,
            },
            unique: Unique::Rsa(vec![0; 256]),
        }
    }

    /// An ECC P-256 storage root key, for TPMs without a persistent one.
    pub fn storage_root_ecc() -> Self {
        use attributes::*;
        Self {
            kind: ALG_ECC,
            name_alg: ALG_SHA256,
            attributes: FIXED_TPM
                | FIXED_PARENT
                | SENSITIVE_DATA_ORIGIN
                | USER_WITH_AUTH
                | NO_DA
                | RESTRICTED
                | DECRYPT,
            auth_policy: Vec::new(),
            parameters: Parameters::Ecc {
                symmetric: Symmetric::AES_128_CFB,
                scheme: Scheme::NULL,
                curve: ECC_NIST_P256,
                kdf: Scheme::NULL,
            },
            unique: Unique::Ecc {
                x: vec![0; 32],
                y: vec![0; 32],
            },
        }
    }

    /// Porta's device key: an ECDSA P-256 signing key generated in the TPM
    /// that cannot leave it.
    pub fn device_key() -> Self {
        use attributes::*;
        Self {
            kind: ALG_ECC,
            name_alg: ALG_SHA256,
            attributes: FIXED_TPM
                | FIXED_PARENT
                | SENSITIVE_DATA_ORIGIN
                | USER_WITH_AUTH
                | NO_DA
                | SIGN,
            auth_policy: Vec::new(),
            parameters: Parameters::Ecc {
                symmetric: Symmetric::NULL,
                scheme: Scheme {
                    algorithm: ALG_ECDSA,
                    hash: ALG_SHA256,
                },
                curve: ECC_NIST_P256,
                kdf: Scheme::NULL,
            },
            unique: Unique::Ecc {
                x: Vec::new(),
                y: Vec::new(),
            },
        }
    }

    /// The marshalled `TPMT_PUBLIC`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(320);
        out.extend(self.kind.to_be_bytes());
        out.extend(self.name_alg.to_be_bytes());
        out.extend(self.attributes.to_be_bytes());
        put_sized(&mut out, &self.auth_policy);
        match &self.parameters {
            Parameters::Rsa {
                symmetric,
                scheme,
                key_bits,
                exponent,
            } => {
                put_symmetric(&mut out, symmetric);
                put_scheme(&mut out, scheme);
                out.extend(key_bits.to_be_bytes());
                out.extend(exponent.to_be_bytes());
            }
            Parameters::Ecc {
                symmetric,
                scheme,
                curve,
                kdf,
            } => {
                put_symmetric(&mut out, symmetric);
                put_scheme(&mut out, scheme);
                out.extend(curve.to_be_bytes());
                put_scheme(&mut out, kdf);
            }
        }
        match &self.unique {
            Unique::Rsa(modulus) => put_sized(&mut out, modulus),
            Unique::Ecc { x, y } => {
                put_sized(&mut out, x);
                put_sized(&mut out, y);
            }
        }
        out
    }

    /// Parses a `TPMT_PUBLIC`, which must be all of `encoded`.
    pub fn decode(encoded: &[u8]) -> Result<Self, MalformedTpm> {
        let mut reader = Reader(encoded);
        let public = Self::read(&mut reader)?;
        if reader.0.is_empty() {
            Ok(public)
        } else {
            Err(MalformedTpm)
        }
    }

    pub(crate) fn read(reader: &mut Reader<'_>) -> Result<Self, MalformedTpm> {
        let kind = reader.u16()?;
        let name_alg = reader.u16()?;
        let attributes = reader.u32()?;
        let auth_policy = reader.sized()?.to_vec();
        let (parameters, unique) = match kind {
            ALG_RSA => {
                let symmetric = read_symmetric(reader)?;
                let scheme = read_scheme(reader)?;
                let key_bits = reader.u16()?;
                let exponent = reader.u32()?;
                let modulus = reader.sized()?.to_vec();
                (
                    Parameters::Rsa {
                        symmetric,
                        scheme,
                        key_bits,
                        exponent,
                    },
                    Unique::Rsa(modulus),
                )
            }
            ALG_ECC => {
                let symmetric = read_symmetric(reader)?;
                let scheme = read_scheme(reader)?;
                let curve = reader.u16()?;
                let kdf = read_scheme(reader)?;
                let x = reader.sized()?.to_vec();
                let y = reader.sized()?.to_vec();
                (
                    Parameters::Ecc {
                        symmetric,
                        scheme,
                        curve,
                        kdf,
                    },
                    Unique::Ecc { x, y },
                )
            }
            _ => return Err(MalformedTpm),
        };
        Ok(Self {
            kind,
            name_alg,
            attributes,
            auth_policy,
            parameters,
            unique,
        })
    }

    /// The DER `SubjectPublicKeyInfo` of a P-256 key.
    pub fn p256_spki(&self) -> Option<Vec<u8>> {
        use p256::pkcs8::EncodePublicKey as _;
        let (Parameters::Ecc { curve, .. }, Unique::Ecc { x, y }) =
            (&self.parameters, &self.unique)
        else {
            return None;
        };
        if *curve != ECC_NIST_P256 || x.len() > 32 || y.len() > 32 {
            return None;
        }
        let mut point = vec![0x04];
        point.extend(std::iter::repeat_n(0, 32 - x.len()));
        point.extend(x);
        point.extend(std::iter::repeat_n(0, 32 - y.len()));
        point.extend(y);
        p256::PublicKey::from_sec1_bytes(&point)
            .ok()?
            .to_public_key_der()
            .ok()
            .map(|der| der.as_bytes().to_vec())
    }
}

/// The TPM name of a marshalled `TPMT_PUBLIC` with a SHA-256 name
/// algorithm: the algorithm identifier, then the digest.
pub fn name(encoded_public: &[u8]) -> Vec<u8> {
    let mut name = ALG_SHA256.to_be_bytes().to_vec();
    name.extend(Sha256::digest(encoded_public));
    name
}

fn put_sized(out: &mut Vec<u8>, value: &[u8]) {
    out.extend((value.len() as u16).to_be_bytes());
    out.extend(value);
}

fn put_symmetric(out: &mut Vec<u8>, symmetric: &Symmetric) {
    out.extend(symmetric.algorithm.to_be_bytes());
    if symmetric.algorithm != ALG_NULL {
        out.extend(symmetric.key_bits.to_be_bytes());
        out.extend(symmetric.mode.to_be_bytes());
    }
}

fn put_scheme(out: &mut Vec<u8>, scheme: &Scheme) {
    out.extend(scheme.algorithm.to_be_bytes());
    if scheme.algorithm != ALG_NULL {
        out.extend(scheme.hash.to_be_bytes());
    }
}

fn read_symmetric(reader: &mut Reader<'_>) -> Result<Symmetric, MalformedTpm> {
    let algorithm = reader.u16()?;
    if algorithm == ALG_NULL {
        return Ok(Symmetric::NULL);
    }
    Ok(Symmetric {
        algorithm,
        key_bits: reader.u16()?,
        mode: reader.u16()?,
    })
}

fn read_scheme(reader: &mut Reader<'_>) -> Result<Scheme, MalformedTpm> {
    let algorithm = reader.u16()?;
    if algorithm == ALG_NULL {
        return Ok(Scheme::NULL);
    }
    Ok(Scheme {
        algorithm,
        hash: reader.u16()?,
    })
}

/// Reads big-endian TPM fields from the front of a buffer.
pub struct Reader<'a>(pub &'a [u8]);

impl<'a> Reader<'a> {
    pub fn bytes(&mut self, count: usize) -> Result<&'a [u8], MalformedTpm> {
        if self.0.len() < count {
            return Err(MalformedTpm);
        }
        let (head, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(head)
    }

    pub fn u8(&mut self) -> Result<u8, MalformedTpm> {
        Ok(self.bytes(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, MalformedTpm> {
        Ok(u16::from_be_bytes(self.bytes(2)?.try_into().unwrap()))
    }

    pub fn u32(&mut self) -> Result<u32, MalformedTpm> {
        Ok(u32::from_be_bytes(self.bytes(4)?.try_into().unwrap()))
    }

    /// A `TPM2B_*`: a 16-bit size, then that many bytes.
    pub fn sized(&mut self) -> Result<&'a [u8], MalformedTpm> {
        let size = usize::from(self.u16()?);
        self.bytes(size)
    }

    pub fn rest(&self) -> &'a [u8] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_round_trip_through_marshalling() {
        for public in [
            Public::endorsement_rsa(),
            Public::storage_root_ecc(),
            Public::device_key(),
        ] {
            let encoded = public.encode();
            assert_eq!(Public::decode(&encoded).unwrap(), public);
            assert!(Public::decode(&encoded[..encoded.len() - 1]).is_err());
            let mut longer = encoded.clone();
            longer.push(0);
            assert!(Public::decode(&longer).is_err());
        }
        // TCG EK template L-1 attributes and its well-known first bytes.
        let ek = Public::endorsement_rsa().encode();
        assert_eq!(&ek[..8], &[0x00, 0x01, 0x00, 0x0B, 0x00, 0x03, 0x00, 0xB2]);
        assert_eq!(name(&ek).len(), 34);
        assert_eq!(&name(&ek)[..2], &[0x00, 0x0B]);
    }

    #[test]
    fn p256_points_become_subject_public_key_info() {
        use p256::elliptic_curve::Generate as _;
        use p256::pkcs8::EncodePublicKey as _;
        let key = p256::ecdsa::SigningKey::generate();
        let point = key.verifying_key().to_sec1_point(false);
        let point = point.as_bytes();
        let mut public = Public::device_key();
        public.unique = Unique::Ecc {
            x: point[1..33].to_vec(),
            y: point[33..].to_vec(),
        };
        assert_eq!(
            public.p256_spki().unwrap(),
            key.verifying_key().to_public_key_der().unwrap().as_bytes()
        );
        assert!(Public::endorsement_rsa().p256_spki().is_none());
    }
}
