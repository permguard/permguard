// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a Host keeps of the Authority Plane it verifies tokens of, so that a start decides at
//! once: the contract of the store (`1-architecture/2` Stores).
//!
//! The key set and the status lists are kept signed as they arrived. What verifies a token is
//! held in memory by [`AuthorityTrust`](super::authority::AuthorityTrust), verified again from
//! this store at start: nothing read here is trusted before it verifies.
//!
//! | Backend            | Keeps them in     |
//! | ------------------ | ----------------- |
//! | [`files`], default | `host/authority/` |

pub mod files;
#[cfg(any(test, feature = "test-support"))]
pub mod suite;

use serde::{Deserialize, Serialize};

pub use files::DIRECTORY;

/// The key set as it is kept: the issuer it was taken for and its JWKs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeptKeys {
    pub issuer: String,
    pub keys: Vec<serde_json::Value>,
}

/// What a kept list is known by, once its token verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Named {
    pub issuer: String,
    pub uri: String,
    pub iat: u64,
}

/// Why the store did not read or keep.
#[derive(Debug)]
pub struct HeldError(pub Box<dyn std::error::Error + Send + Sync>);

impl std::fmt::Display for HeldError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for HeldError {}

/// The store of what a Host holds of the Authority Plane: the only way the Host reads and keeps
/// it (`1-architecture/8` Store contracts).
pub trait HeldStore: Send + Sync {
    /// The key set kept; `None` when none was, or when what is there does not read as one: a
    /// key set is fetched again, and until then no token verifies.
    fn keys(&self) -> Result<Option<KeptKeys>, HeldError>;

    /// Keeps `keys` in place of the key set kept.
    fn keep_keys(&self, keys: &KeptKeys) -> Result<(), HeldError>;

    /// Every list token kept that `verify` names as the list it is kept as, once: what `verify`
    /// does not name, or names as another list than the one it is kept as, is dropped from the
    /// store. What a start holds.
    fn restore(&self, verify: &dyn Fn(&str) -> Option<Named>) -> Result<Vec<String>, HeldError>;

    /// Keeps `token` as the list `named`, in place of an older one of its issuer and `uri`.
    /// Answers whether it was kept: a list not newer than the one kept changes nothing, whoever
    /// kept that one, so a list fetched late never puts an older one back.
    fn keep_list(&self, named: &Named, token: &str) -> Result<bool, HeldError>;

    /// Drops the list of `issuer` and `uri`, when one is kept.
    fn drop_list(&self, issuer: &str, uri: &str) -> Result<(), HeldError>;
}
