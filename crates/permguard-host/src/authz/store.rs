// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host's recovery principal: its commitment, and the contract of the store that keeps it
//! (`1-architecture/2` Stores).
//!
//! Every caller of a Plane or a Host API is a token of the Authority Plane, or anonymous under a
//! public grant; the bootstrap principal is the one exception, an offline certificate that holds
//! the per-Host operations on its own Host API (`2-security/8` Authorization). It is committed
//! once, offline, by `permguard host grants bootstrap`, and never rewritten: a second commitment
//! to the same certificate is the first, one to another is refused.
//!
//! | Backend            | Keeps the commitment in                |
//! | ------------------ | -------------------------------------- |
//! | [`files`], default | `host/authz/bootstrap.cbor`, immutable |

pub mod files;
#[cfg(any(test, feature = "test-support"))]
pub mod suite;

use permguard_core::authz::Principal;
use permguard_objects::cbor::{self, Value};

use crate::operations::mutation::Applying;

pub use files::DIRECTORY;

/// The principal the bootstrap commitment names for a certificate fingerprint.
pub fn bootstrap_principal(fingerprint: &str) -> Result<Principal, AuthzError> {
    let fingerprint = fingerprint.trim().to_ascii_lowercase();
    let hex = fingerprint.strip_prefix("sha256:").unwrap_or(&fingerprint);
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AuthzError::Invalid(format!(
            "`{fingerprint}` is not a certificate fingerprint: 64 hex characters, optionally \
             prefixed `sha256:`"
        )));
    }
    Principal::new(format!("cert:sha256:{hex}"))
        .map_err(|error| AuthzError::Invalid(error.to_string()))
}

/// The fingerprint a bootstrap commits for the first certificate of `pem`: the SHA-256 of its
/// DER, `sha256:<hex>`, what `openssl x509 -fingerprint -sha256` prints and the mapper compares.
pub fn certificate_fingerprint(pem: &[u8]) -> Result<String, AuthzError> {
    use base64::Engine as _;
    use sha2::Digest as _;

    let text = std::str::from_utf8(pem)
        .map_err(|_| AuthzError::Invalid("the certificate file is not PEM text".to_owned()))?;
    let body = text
        .split("-----BEGIN CERTIFICATE-----")
        .nth(1)
        .and_then(|rest| rest.split("-----END CERTIFICATE-----").next())
        .ok_or_else(|| AuthzError::Invalid("the file holds no PEM certificate".to_owned()))?;
    let compact: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(compact)
        .map_err(|_| AuthzError::Invalid("the PEM certificate is not base64".to_owned()))?;
    if der.is_empty() {
        return Err(AuthzError::Invalid(
            "the PEM certificate is empty".to_owned(),
        ));
    }
    Ok(format!(
        "sha256:{}",
        permguard_core::encoding::hex(&sha2::Sha256::digest(&der))
    ))
}

/// What the store refuses, beyond what the volume does.
#[derive(Debug)]
pub enum AuthzError {
    /// A fingerprint that is not one, or a commitment to another certificate than the one held.
    Invalid(String),
    /// The commitment held does not read as one: it is not taken for none.
    Record(String),
    /// The store could not be read or written: a commitment may have been written all the same.
    Unavailable(Box<dyn std::error::Error + Send + Sync>),
}

impl std::fmt::Display for AuthzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(detail) | Self::Record(detail) => f.write_str(detail),
            Self::Unavailable(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for AuthzError {}

/// The bootstrap commitment: the one recovery principal, written once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bootstrap {
    pub principal: Principal,
    pub fingerprint: String,
    pub created_at: u64,
}

impl Bootstrap {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, AuthzError> {
        cbor::encode(&Value::Map(vec![
            (
                Value::Int(1),
                Value::Text(self.principal.as_str().to_owned()),
            ),
            (Value::Int(2), Value::Text(self.fingerprint.clone())),
            (
                Value::Int(3),
                Value::Int(i64::try_from(self.created_at).unwrap_or(i64::MAX)),
            ),
        ]))
        .map_err(|error| AuthzError::Invalid(format!("encoding the bootstrap: {error}")))
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let Value::Map(pairs) = cbor::decode_canonical(bytes).ok()? else {
            return None;
        };
        let mut principal = None;
        let mut fingerprint = None;
        let mut created_at = None;
        for (key, value) in pairs {
            match (key, value) {
                (Value::Int(1), Value::Text(text)) => principal = Principal::new(text).ok(),
                (Value::Int(2), Value::Text(text)) => fingerprint = Some(text),
                (Value::Int(3), Value::Int(at)) if at >= 0 => created_at = Some(at as u64),
                _ => return None,
            }
        }
        Some(Self {
            principal: principal?,
            fingerprint: fingerprint?,
            created_at: created_at?,
        })
    }
}

/// The store of the recovery principal's commitment: the only way the Host reads and writes it
/// (`1-architecture/8` Store contracts).
pub trait BootstrapStore: Send + Sync {
    /// The commitment, when one was written. One that is there and does not read is an error,
    /// never none: a Host does not serve as one that commits to nobody because its commitment
    /// was damaged.
    fn bootstrap(&self) -> Result<Option<Bootstrap>, AuthzError>;

    /// Commits to the certificate `fingerprint` names, once, inside the operation `applying`: a
    /// second commitment naming the same certificate is the first; one naming another is refused
    /// and changes nothing. Answers the commitment held and whether this call wrote it. Of the
    /// commitments that arrive together one is written, whatever each names.
    fn commit(
        &self,
        applying: &Applying<'_>,
        fingerprint: &str,
        now: u64,
    ) -> Result<(Bootstrap, bool), AuthzError>;
}

#[cfg(test)]
mod tests;
