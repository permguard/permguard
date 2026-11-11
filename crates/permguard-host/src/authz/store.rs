// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host's recovery principal on the volume: `host/authz/bootstrap.cbor`.
//!
//! ```text
//! host/authz/
//! └── bootstrap.cbor    immutable commitment to the recovery principal's certificate
//! ```
//!
//! Every caller of a Plane or a Host API is a token of the Authority Plane, or anonymous under a
//! public grant; the bootstrap principal is the one exception, an offline certificate that holds
//! the per-Host operations on its own Host API (`2-security/8` Authorization). It is committed
//! once, offline, by `permguard host grants bootstrap`, and the file is never rewritten: a second
//! commitment to the same certificate is the first, one to another is refused.

use std::sync::{Arc, Mutex};

use permguard_core::authz::Principal;
use permguard_objects::cbor::{self, Value};

use crate::operations::mutation::Applying;
use crate::storage::dir::Dir;
use crate::storage::volume::Volume;
use crate::storage::write::{Published, publish_immutable};
use crate::storage::{Rebuildable, StorageError};

/// The directory below `host/`.
pub const DIRECTORY: &str = "authz";
const BOOTSTRAP: &str = "bootstrap.cbor";

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

/// What the store refuses, beyond what the volume does.
#[derive(Debug)]
pub enum AuthzError {
    /// A fingerprint that is not one, or a commitment to another certificate than the one held.
    Invalid(String),
    /// The file could not be read or written.
    Storage(StorageError),
}

impl std::fmt::Display for AuthzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(detail) => f.write_str(detail),
            Self::Storage(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for AuthzError {}

impl From<StorageError> for AuthzError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

/// The bootstrap commitment: the one recovery principal, written once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bootstrap {
    pub principal: Principal,
    pub fingerprint: String,
    pub created_at: u64,
}

impl Bootstrap {
    fn encode(&self) -> Result<Vec<u8>, AuthzError> {
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

    fn decode(bytes: &[u8]) -> Option<Self> {
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

/// The recovery principal's store on one volume.
pub struct BootstrapStore {
    dir: Rebuildable<Dir>,
    bootstrap: Mutex<Option<Bootstrap>>,
}

impl std::fmt::Debug for BootstrapStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapStore")
            .field("committed", &self.bootstrap().is_some())
            .finish()
    }
}

impl BootstrapStore {
    /// Opens the store of `volume`, reading the commitment when one was written.
    pub fn open(volume: &Volume) -> Result<Arc<Self>, AuthzError> {
        let dir = volume.host().subdir(DIRECTORY, true)?;
        let bootstrap = dir
            .read(BOOTSTRAP)?
            .and_then(|bytes| Bootstrap::decode(&bytes));
        Ok(Arc::new(Self {
            dir: Rebuildable::new(dir),
            bootstrap: Mutex::new(bootstrap),
        }))
    }

    /// The bootstrap commitment, when one was written.
    pub fn bootstrap(&self) -> Option<Bootstrap> {
        self.bootstrap
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Writes the bootstrap commitment once: a second bootstrap naming the same fingerprint is the
    /// first; one naming another is refused, the file being immutable. Answers the commitment held
    /// and whether this call wrote it.
    pub fn commit(
        &self,
        _applying: &Applying<'_>,
        fingerprint: &str,
        now: u64,
    ) -> Result<(Bootstrap, bool), AuthzError> {
        let principal = bootstrap_principal(fingerprint)?;
        let commitment = Bootstrap {
            principal: principal.clone(),
            fingerprint: fingerprint.trim().to_ascii_lowercase(),
            created_at: now,
        };
        let bytes = commitment.encode()?;
        let same_principal = |existing: &[u8]| {
            Bootstrap::decode(existing).is_some_and(|held| held.principal == principal)
        };
        let published = publish_immutable(
            self.dir.get(),
            BOOTSTRAP,
            &bytes,
            &|content| Bootstrap::decode(content).is_some(),
            &same_principal,
        )
        .map_err(|error| match error {
            StorageError::Corruption(_) => AuthzError::Invalid(format!(
                "{} already commits to another recovery principal; a bootstrap is written once",
                self.dir.get().child_path(BOOTSTRAP).display()
            )),
            other => AuthzError::Storage(other),
        })?;
        let held = self
            .dir
            .get()
            .read(BOOTSTRAP)?
            .and_then(|bytes| Bootstrap::decode(&bytes))
            .unwrap_or(commitment);
        *self
            .bootstrap
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(held.clone());
        Ok((held, matches!(published, Published::Written)))
    }
}

/// Seconds since the Unix epoch, for the offline commands.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use permguard_core::assurance::AssuranceProfile;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "pg-authz-bootstrap-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch");
        root
    }

    #[test]
    fn the_bootstrap_is_written_once_and_read_back_at_open() {
        let root = scratch("once");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let store = BootstrapStore::open(&volume).expect("opens");
        assert_eq!(store.bootstrap(), None);
        let fingerprint = "AB".repeat(32);
        let (commitment, written) = store
            .commit(&Applying::for_tests(1), &fingerprint, 10)
            .expect("committed");
        assert!(written);
        assert_eq!(
            commitment.principal.as_str(),
            format!("cert:sha256:{}", "ab".repeat(32))
        );
        // The same fingerprint again: the same commitment, not written again.
        let (again, written) = store
            .commit(
                &Applying::for_tests(2),
                &format!("sha256:{fingerprint}"),
                20,
            )
            .expect("idempotent");
        assert_eq!(again, commitment);
        assert!(!written);
        // Another fingerprint, or none: refused, the file is immutable.
        assert!(matches!(
            store.commit(&Applying::for_tests(3), &"cd".repeat(32), 30),
            Err(AuthzError::Invalid(_))
        ));
        assert!(matches!(
            store.commit(&Applying::for_tests(4), "nonsense", 30),
            Err(AuthzError::Invalid(_))
        ));
        drop(store);
        let reopened = BootstrapStore::open(&volume).expect("reopens");
        assert_eq!(reopened.bootstrap(), Some(commitment));
    }
}
