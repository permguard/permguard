// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The peer Hosts this one trusts, and the last epoch each was seen at (WP-2.3; owner decision
//! of 2026-10-08).
//!
//! | Backend            | Keeps the seen epochs in            |
//! | ------------------ | ----------------------------------- |
//! | [`files`], default | `host/peers/`, one file a peer Host |
//!
//! A peer is trusted only when `host.peers[]` pins its `host_id` to its first identity
//! fingerprint. Its presentation is verified from that key along its succession chain; the
//! result is then held against the last epoch a session with it was established at: a lower
//! epoch is rollback, and a chain whose key at that epoch is another is equivocation. Both are
//! refused. The seen epoch advances only once a proof has verified.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, PoisonError, RwLock};

use permguard_core::PinnedPeer;
use permguard_objects::cbor::Value;
use permguard_objects::cose::Sign1;
use permguard_objects::digest::Digest;

use crate::identity::record::{Document, Labelled, RecordError, encode, uint};
use crate::identity::{self, Verified};
use crate::session::record::Operation;

use super::record::Presentation;

pub mod files;
#[cfg(any(test, feature = "test-support"))]
pub mod suite;

pub use files::DIRECTORY;

/// Why a peer is refused when no pin names it: a coordinator whose identity was reset presents a
/// first key the member never pinned (BUG-0164).
pub const UNPINNED: &str = "no pin names the peer and its first key";

/// Why a peer's identity was not accepted.
#[derive(Debug)]
pub enum PeerRefusal {
    /// The presentation does not verify.
    Identity(String),
    /// No pin names the presented Host, or its first key is not the pinned one.
    Unpinned,
    /// An epoch below the one a session was already established at.
    Rollback { seen: u64, presented: u64 },
    /// A chain whose key at an epoch already seen is another key.
    Equivocation { epoch: u64 },
    /// The seen epochs could not be read or written: nothing is accepted.
    Storage(String),
}

impl fmt::Display for PeerRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identity(detail) => write!(f, "the peer's identity does not verify: {detail}"),
            Self::Unpinned => f.write_str(UNPINNED),
            Self::Rollback { seen, presented } => write!(
                f,
                "the peer presents epoch {presented}, below epoch {seen} already seen: rollback"
            ),
            Self::Equivocation { epoch } => write!(
                f,
                "the peer presents another key for epoch {epoch}, already seen: equivocation"
            ),
            Self::Storage(detail) => write!(f, "the peers' seen epochs: {detail}"),
        }
    }
}

impl std::error::Error for PeerRefusal {}

impl From<RecordError> for PeerRefusal {
    fn from(error: RecordError) -> Self {
        Self::Storage(error.0)
    }
}

/// The last epoch a session with a peer was established at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    pub host_id: [u8; 16],
    pub epoch: u64,
    pub fingerprint: String,
    pub at: u64,
}

impl Seen {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        encode(vec![
            (Value::Int(1), Value::Bytes(self.host_id.to_vec())),
            (Value::Int(2), uint(self.epoch)?),
            (Value::Int(3), Value::Text(self.fingerprint.clone())),
            (Value::Int(4), uint(self.at)?),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut map = Labelled::read(bytes, "a seen peer")?;
        let seen = Self {
            host_id: map.id(1)?,
            epoch: map.uint(2)?,
            fingerprint: map.text(3)?,
            at: map.uint(4)?,
        };
        map.finish()?;
        Ok(seen)
    }
}

/// Pins beside the configured ones: the peers the memberships name (WP-4.1).
pub trait PinSource: Send + Sync {
    /// The first fingerprint a membership pins `host_id` to for a session of `operation`, when
    /// one does: a membership that ended still lets its member read how it ended, and nothing
    /// else.
    fn pin(&self, host_id: &[u8; 16], operation: Option<Operation>) -> Option<String>;
}

/// The store of the seen epochs: the only way the Host reads and advances them
/// (`1-architecture/8` Store contracts).
pub trait SeenStore: Send + Sync {
    /// The last epoch a session with `host_id` was established at. A record that is there and
    /// does not read, or names another Host, is a refusal, never a peer not seen.
    fn seen(&self, host_id: &[u8; 16]) -> Result<Option<Seen>, PeerRefusal>;

    /// Records that a session with `verified` was established at `at`: its epoch becomes the
    /// seen one when it is higher. The identity is held against what the store holds in the step
    /// that writes, with [`check`]: a presentation below the epoch held is a rollback, another
    /// key at that epoch equivocation, and neither moves it. So of the sessions established
    /// together, one with an older presentation never moves the epoch back.
    fn advance(&self, verified: &Verified, at: u64) -> Result<(), PeerRefusal>;
}

/// The pinned peers and their seen epochs.
pub struct Peers {
    pins: BTreeMap<[u8; 16], String>,
    source: RwLock<Option<Arc<dyn PinSource>>>,
    seen: Arc<dyn SeenStore>,
}

impl fmt::Debug for Peers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Peers")
            .field("pinned", &self.pins.len())
            .finish_non_exhaustive()
    }
}

impl Peers {
    /// The peers `pins` names, with the seen epochs `seen` keeps.
    pub fn new(seen: Arc<dyn SeenStore>, pins: &[PinnedPeer]) -> Self {
        Self {
            pins: pins
                .iter()
                .map(|pin| (pin.host_id(), pin.fingerprint().to_owned()))
                .collect(),
            source: RwLock::new(None),
            seen,
        }
    }

    /// Adds the memberships' pins to the configured ones.
    pub fn with_source(&self, source: Arc<dyn PinSource>) {
        *self.source.write().unwrap_or_else(PoisonError::into_inner) = Some(source);
    }

    /// The first fingerprint `host_id` is pinned to: configured, a membership's, or `extra`, the
    /// pin a join brings for the coordinator it names.
    fn pinned(
        &self,
        host_id: &[u8; 16],
        extra: Option<&([u8; 16], String)>,
        operation: Option<Operation>,
    ) -> Option<String> {
        if let Some(pin) = self.pins.get(host_id) {
            return Some(pin.clone());
        }
        if let Some((pinned, fingerprint)) = extra
            && pinned == host_id
        {
            return Some(fingerprint.clone());
        }
        self.source
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .and_then(|source| source.pin(host_id, operation))
    }

    /// The first fingerprint any pin names `host_id` by for a session of `operation`: configured,
    /// or a membership's.
    pub fn pinned_for(&self, host_id: &[u8; 16], operation: Option<Operation>) -> Option<String> {
        self.pinned(host_id, None, operation)
    }

    /// Whether a pin names `host_id` for a session of `operation`.
    pub fn is_pinned(&self, host_id: &[u8; 16], operation: Option<Operation>) -> bool {
        self.pinned(host_id, None, operation).is_some()
    }

    /// The last epoch a session with `host_id` was established at.
    pub fn seen(&self, host_id: &[u8; 16]) -> Result<Option<Seen>, PeerRefusal> {
        self.seen.seen(host_id)
    }

    /// Verifies `presentation` from its pin for a session of `operation` and against its seen
    /// epoch: the peer's current identity, or why it is refused.
    pub fn accept(
        &self,
        presentation: &Presentation,
        extra: Option<&([u8; 16], String)>,
        operation: Option<Operation>,
    ) -> Result<Verified, PeerRefusal> {
        // The pin first, from what costs one digest: an unpinned client never makes this Host
        // walk a succession chain. The document is read here only for the Host it claims.
        let claimed = Sign1::decode(&presentation.document)
            .ok()
            .and_then(|envelope| Document::decode(envelope.payload_unverified()).ok())
            .ok_or_else(|| {
                PeerRefusal::Identity("the identity document does not read".to_owned())
            })?;
        let first = Digest::compute(&presentation.first_public_key).to_string();
        let pin = self.pinned(&claimed.host_id, extra, operation);
        if pin.as_ref() != Some(&first) {
            return Err(PeerRefusal::Unpinned);
        }
        let verified = identity::verify_published(
            &presentation.document,
            &presentation.successions,
            &presentation.first_public_key,
        )
        .map_err(|error| PeerRefusal::Identity(error.to_string()))?;
        match pin {
            Some(pinned) if pinned == verified.first_fingerprint() => {}
            _ => return Err(PeerRefusal::Unpinned),
        }
        if let Some(seen) = self.seen(&verified.host_id)? {
            check(&seen, &verified)?;
        }
        Ok(verified)
    }

    /// Verifies `presentation` with no pin, for an enrollment (WP-4.1): the chain from its own
    /// first key, and against its seen epoch when one was. The enrolling Host becomes pinned
    /// only by the membership the enrollment creates, its first fingerprint in the request the
    /// coordinator's operator approves.
    pub fn accept_enrolling(&self, presentation: &Presentation) -> Result<Verified, PeerRefusal> {
        let verified = identity::verify_published(
            &presentation.document,
            &presentation.successions,
            &presentation.first_public_key,
        )
        .map_err(|error| PeerRefusal::Identity(error.to_string()))?;
        // A Host a pin already names enrolls only with the key that pin names: an enrolling
        // chain never stands in for a Host this one trusts under another key.
        if let Some(pin) = self.pinned(&verified.host_id, None, Some(Operation::Membership))
            && pin != verified.first_fingerprint()
        {
            return Err(PeerRefusal::Unpinned);
        }
        if let Some(seen) = self.seen(&verified.host_id)? {
            check(&seen, &verified)?;
        }
        Ok(verified)
    }

    /// Records that a session with `verified` was established at `at`: its epoch becomes the
    /// seen one when it is higher. Checked again by the store in the step that writes, so a
    /// concurrent session with an older presentation never moves it back.
    pub fn advance(&self, verified: &Verified, at: u64) -> Result<(), PeerRefusal> {
        self.seen.advance(verified, at)
    }
}

/// A presentation against what was seen: never below, and the key at the seen epoch unchanged.
pub fn check(seen: &Seen, verified: &Verified) -> Result<(), PeerRefusal> {
    if verified.epoch < seen.epoch {
        return Err(PeerRefusal::Rollback {
            seen: seen.epoch,
            presented: verified.epoch,
        });
    }
    let at_seen = seen
        .epoch
        .checked_sub(1)
        .and_then(|index| usize::try_from(index).ok())
        .and_then(|index| verified.fingerprints.get(index));
    if at_seen != Some(&seen.fingerprint) {
        return Err(PeerRefusal::Equivocation { epoch: seen.epoch });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
