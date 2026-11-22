// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a custody keeps of each key, and the contract of the store that keeps it
//! (`1-architecture/4` Stores).
//!
//! A slot names one key: a ring key's thumbprint, an identity epoch. Every custody keeps one
//! thing in it, of one [`Kind`]: the key itself, sealed or in the clear, or a reference to a key
//! a token or a KMS holds. The store keeps bytes and reads none of them: what a slot must hold is
//! its custody's to check.
//!
//! | Backend            | Keeps a slot in                                             |
//! | ------------------ | ----------------------------------------------------------- |
//! | [`files`], default | `<slot>.key` or `<slot>.ref`, `0600`, below a `0700` directory |

pub mod files;
#[cfg(any(test, feature = "test-support"))]
pub mod suite;

use super::KeyError;

/// What a custody keeps in a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// The key itself: PKCS#8 in the clear, or a sealed key.
    Key,
    /// A reference to a key held elsewhere: a token's label, a KMS key's name.
    Reference,
}

/// Refuses what is not a slot: letters, digits, `-` and `_`, an identity epoch or a ring key's
/// base64url thumbprint (owner decision of 2026-10-08).
pub fn check(slot: &str) -> Result<(), KeyError> {
    if slot.is_empty()
        || !slot
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(KeyError::Malformed(format!(
            "`{slot}` is not a key slot: letters, digits, `-` and `_`"
        )));
    }
    Ok(())
}

/// The store of what the custodies keep: the only way a key provider reads and writes it
/// (`1-architecture/8` Store contracts). A slot that is no slot is refused by every call.
pub trait SlotStore: Send + Sync {
    /// What the slot holds of `kind`; `None` when nothing.
    fn read(&self, kind: Kind, slot: &str) -> Result<Option<Vec<u8>>, KeyError>;

    /// Fills the slot, once: one that holds anything of `kind` answers [`KeyError::Exists`] and
    /// keeps what it holds. Of the keys that arrive together for one slot, one fills it and the
    /// others are refused.
    fn fill(&self, kind: Kind, slot: &str, bytes: &[u8]) -> Result<(), KeyError>;

    /// Replaces what the slot holds of `kind`: what the custody that sealed a key does to seal
    /// one found in the clear, or to wrap it again.
    fn replace(&self, kind: Kind, slot: &str, bytes: &[u8]) -> Result<(), KeyError>;

    /// The slots that hold anything of `kind`.
    fn slots(&self, kind: Kind) -> Result<Vec<String>, KeyError>;

    /// Empties the slot of `kind`; nothing when it holds nothing.
    fn empty(&self, kind: Kind, slot: &str) -> Result<(), KeyError>;

    /// Where the slot is kept, for a refusal an operator reads.
    fn place(&self, kind: Kind, slot: &str) -> String;
}
