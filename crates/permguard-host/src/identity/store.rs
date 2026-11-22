// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The contract of the store that keeps the Host identity's records (`1-architecture/2` Stores).
//!
//! The identity is several records that change in a fixed order, and the store keeps the records,
//! not the order: verifying a chain, signing, generating a key and deciding what an interrupted
//! change left are [`Identity`](super::Identity)'s, the same on every backend. Nothing read here
//! is trusted before it verifies.
//!
//! | Record              | Written                                              |
//! | ------------------- | ---------------------------------------------------- |
//! | provisioning record | once, last, by a provisioning; removed by a reset    |
//! | document            | replaced by a provisioning, a rotation, a completion |
//! | successions         | added by a rotation                                  |
//! | public key          | once per epoch                                       |
//! | start               | replaced at every open                               |
//! | reset under way     | set by a reset, cleared when the next identity stands |
//! | retired identity    | once per identity, with the record of its reset      |
//!
//! | Backend                   | Keeps them in    |
//! | ------------------------- | ---------------- |
//! | [`files`](super::files), default | `host/identity/` |

use permguard_objects::cbor::Value;

use super::IdentityError;
use crate::operations::mutation::Applying;

/// What the store holds of one epoch's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldEpoch {
    pub epoch: u64,
    /// Its public key is published.
    pub public: bool,
    /// A private key of it rests in the store itself: a custody that keeps its keys beside the
    /// identity. A custody that holds them elsewhere never shows here.
    pub private: bool,
}

/// An identity a reset retired, as its evidence is kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retired {
    /// The retired `host_id`, as text.
    pub host_id: String,
    /// The record of the reset that retired it; `None` when the evidence was kept and the record
    /// was not written yet.
    pub reset: Option<Vec<u8>>,
    /// Whether its provisioning record is among the evidence.
    pub init: bool,
}

/// The store of the Host identity's records: the only way the Host reads and writes them
/// (`1-architecture/8` Store contracts).
///
/// A record that is there and does not read is the caller's to refuse: the store answers bytes,
/// and [`Identity`](super::Identity) verifies them. A change made by a rotation or a reset runs
/// inside one operation of the mutation engine, whose unit of work its calls share.
pub trait IdentityStore: Send + Sync {
    /// The provisioning record, when the identity is provisioned.
    fn init(&self) -> Result<Option<Vec<u8>>, IdentityError>;

    /// Writes the provisioning record, once: the same record again is the first, another is
    /// refused.
    fn publish_init(&self, record: &[u8]) -> Result<(), IdentityError>;

    /// Removes the provisioning record: what a reset does before it provisions the next
    /// identity.
    fn remove_init(&self) -> Result<(), IdentityError>;

    /// The signed document of the current epoch.
    fn document(&self) -> Result<Option<Vec<u8>>, IdentityError>;

    /// Replaces the signed document.
    fn replace_document(&self, envelope: &[u8]) -> Result<(), IdentityError>;

    /// Every succession record, oldest first, each as the CBOR item it was added as.
    fn successions(&self) -> Result<Vec<Value>, IdentityError>;

    /// Adds a succession record after the ones held.
    fn append_succession(&self, envelope: &[u8]) -> Result<(), IdentityError>;

    /// The public key published for `epoch`.
    fn public(&self, epoch: u64) -> Result<Option<Vec<u8>>, IdentityError>;

    /// Publishes the public key of `epoch`, once: the same key again is the first, another is
    /// refused.
    fn publish_public(&self, epoch: u64, key: &[u8]) -> Result<(), IdentityError>;

    /// Removes the public key of `epoch`: one no succession names, replaced by the rotation that
    /// finds it.
    fn remove_public(&self, epoch: u64) -> Result<(), IdentityError>;

    /// Every epoch the store holds key material of, lowest first.
    fn held_epochs(&self) -> Result<Vec<HeldEpoch>, IdentityError>;

    /// Whether a start of this identity was ever recorded: an identity that was opened.
    fn started(&self) -> Result<bool, IdentityError>;

    /// Records this start in place of the one before.
    fn record_start(&self, record: &[u8]) -> Result<(), IdentityError>;

    /// Removes the document, the successions, the start and every key the store holds: what an
    /// interrupted provisioning or a retired identity left, before the next is provisioned. The
    /// provisioning record, the reset under way and the retired identities stay.
    fn clear(&self) -> Result<(), IdentityError>;

    /// The identity a reset under way retires, as it was marked.
    fn resetting(&self) -> Result<Option<Vec<u8>>, IdentityError>;

    /// Marks a reset of `host_id` under way, inside the operation `applying`.
    fn mark_resetting(
        &self,
        applying: &Applying<'_>,
        host_id: &[u8; 16],
    ) -> Result<(), IdentityError>;

    /// Clears the mark of a reset under way; nothing when none is.
    fn clear_resetting(&self) -> Result<(), IdentityError>;

    /// Keeps the public records of the identity held, its provisioning record, document,
    /// successions and public keys, as the evidence of the retired `host_id`, with the record of
    /// its reset, inside the operation `applying`. Nothing private is kept, and what is held
    /// stays as it is.
    fn retire(
        &self,
        applying: &Applying<'_>,
        host_id: &[u8; 16],
        reset: &[u8],
    ) -> Result<(), IdentityError>;

    /// Every identity a reset retired, by `host_id`.
    fn retired(&self) -> Result<Vec<Retired>, IdentityError>;
}
