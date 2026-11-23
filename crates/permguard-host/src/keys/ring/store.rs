// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The contract of the store that keeps a ring's records (`1-architecture/4` Stores).
//!
//! A ring is its entries: every lifecycle and epoch transition, added in order and never
//! changed. The store keeps them, with what is built or signed from them, and one order alone,
//! their sequence: which entry may follow which, what a view holds and what a binding binds are
//! [`Ring`](super::Ring)'s, the same on every backend. Nothing read here is trusted before it is
//! replayed and checked.
//!
//! | Record     | Written                                                        |
//! | ---------- | -------------------------------------------------------------- |
//! | entry      | added by a transition, before the change shows anywhere        |
//! | view       | replaced after a transition; rebuilt from the entries          |
//! | binding    | replaced when the identity binds the current set               |
//! | kept binding | once per `bound` entry, before the entry                     |
//! | public key | once per key, under its thumbprint, kept for good              |
//! | retired ring | once per retired Host, when its identity is reset            |
//!
//! | Backend                   | Keeps them in       |
//! | ------------------------- | ------------------- |
//! | [`files`](super::files), default | `host/keys/<ring>/` |

use permguard_objects::cbor::Value;

use super::RingError;
use crate::operations::mutation::Applying;

/// The public records of one ring, each as the bytes the store answers: what an import carries
/// to another backend at rest (iteration 03, WP-27.6). The private keys are its custody's, in
/// the ring's slots.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Records {
    /// The journal's entries, in order, each as the canonical item it was added as.
    pub entries: Vec<Vec<u8>>,
    /// The materialized view.
    pub view: Option<Vec<u8>>,
    /// The identity-signed binding of the current set.
    pub binding: Option<Vec<u8>>,
    /// Every binding issued, by the sequence of its `bound` entry.
    pub kept_bindings: Vec<(u64, Vec<u8>)>,
    /// Every key published, by thumbprint.
    pub public_keys: Vec<(String, Vec<u8>)>,
}

/// A ring's records, and those a reset kept of it for each retired Host, by its `host_id` as
/// text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Exported {
    pub current: Records,
    pub retired: Vec<(String, Records)>,
}

/// The store of one ring's records: the only way the ring reads and writes them
/// (`1-architecture/8` Store contracts).
pub trait RingStore: Send + Sync {
    /// Every entry, oldest first, each as the CBOR item it was added as.
    fn entries(&self) -> Result<Vec<Value>, RingError>;

    /// Adds `entry` as the entry `seq`, which is the one after the last held, the first being 1:
    /// any other sequence is refused with [`RingError::Refused`] and nothing is added, so of the
    /// transitions that read the same ring and arrive together one is added and the others learn
    /// the ring moved. Any other failure leaves it unknown whether the entry is held: the ring
    /// takes no transition until it has read its entries again.
    fn append(&self, seq: u64, entry: &[u8]) -> Result<(), RingError>;

    /// The materialized view.
    fn view(&self) -> Result<Option<Vec<u8>>, RingError>;

    /// Replaces the materialized view.
    fn replace_view(&self, view: &[u8]) -> Result<(), RingError>;

    /// The binding of the current set.
    fn binding(&self) -> Result<Option<Vec<u8>>, RingError>;

    /// Replaces the binding of the current set.
    fn replace_binding(&self, envelope: &[u8]) -> Result<(), RingError>;

    /// Keeps `envelope` as the binding the `bound` entry `seq` is about to record. Written
    /// before that entry: one whose entry never reached the store counts for nothing and is
    /// replaced by the next binding of that sequence.
    fn keep_binding(&self, seq: u64, envelope: &[u8]) -> Result<(), RingError>;

    /// The binding kept for the `bound` entry `seq`.
    fn kept_binding(&self, seq: u64) -> Result<Option<Vec<u8>>, RingError>;

    /// Every binding kept.
    fn kept_bindings(&self) -> Result<Vec<Vec<u8>>, RingError>;

    /// The public key published under `thumbprint`, as the JWK it was published as.
    fn public(&self, thumbprint: &str) -> Result<Option<Vec<u8>>, RingError>;

    /// Publishes `jwk` under `thumbprint`, once: the same key again is the first, another is
    /// refused.
    fn publish_public(&self, thumbprint: &str, jwk: &[u8]) -> Result<(), RingError>;

    /// Keeps the public records of the ring, its entries, view, bindings and public keys, as the
    /// evidence of the retired Host `old_host_id`, inside the operation `applying`. What is held
    /// stays as it is.
    fn retire(&self, applying: &Applying<'_>, old_host_id: &[u8; 16]) -> Result<(), RingError>;

    /// Removes every entry: what a retired ring loses first, so that it opens as a new ring.
    fn forget_entries(&self) -> Result<(), RingError>;

    /// Removes the view, the bindings and the public keys: what is left of a retired ring once
    /// its private keys are destroyed. The evidence kept of a retired Host stays.
    fn clear(&self) -> Result<(), RingError>;
}
