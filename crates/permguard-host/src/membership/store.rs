// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The contract of the store that keeps a Host's memberships (`1-architecture/3` Stores).
//!
//! The memberships are their entries: every transition, hash-chained, added in order and never
//! changed. Beside them a membership keeps documents, each named within its kind, and a
//! coordinator keeps the checkpoints its members ship. The store keeps all of it and one order
//! alone, the sequence of the entries: which transition may follow which, what a manifest
//! grants and what a document is worth are [`Store`](super::Store)'s, the same on every backend.
//! Nothing read here is trusted before it is decoded and checked.
//!
//! | Backend                          | Keeps them in    |
//! | -------------------------------- | ---------------- |
//! | [`files`](super::files), default | `host/members/`  |

use permguard_objects::cbor::Value;

use super::MembershipError;

/// What holds the fence of an identity reset on a store instances share (X171).
pub trait Fence: Send + Sync {
    /// Whether the fence still holds: the connection it is held on may have been dropped, which
    /// lets every instance take changes again.
    fn held(&self) -> bool;
}

/// A document a membership keeps beside its entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Doc<'a> {
    /// The lease a member holds for a task.
    Lease {
        membership: &'a [u8; 16],
        task: &'a str,
    },
    /// The last progress report a coordinator kept of a task.
    Progress {
        membership: &'a [u8; 16],
        task: &'a str,
    },
    /// The last session a coordinator leased for a task.
    Session {
        membership: &'a [u8; 16],
        task: &'a str,
    },
    /// The last manifest epoch a coordinator delivered to the member.
    Delivered { membership: &'a [u8; 16] },
    /// The receipt of the zone keys of a task, for one resource.
    ZoneReceipt {
        membership: &'a [u8; 16],
        task: &'a str,
        resource: &'a str,
    },
    /// One answered request of a task: the slot `seq` of its replay window.
    ReplaySlot {
        membership: &'a [u8; 16],
        task: &'a str,
        slot: u64,
    },
    /// The verification a coordinator asked of the member, with when.
    Verification { membership: &'a [u8; 16] },
    /// The exact answer the operation `operation` gave a verification.
    VerificationResult { operation: &'a [u8; 16] },
    /// The acknowledgements a member keeps of the checkpoints a task shipped.
    Acks {
        membership: &'a [u8; 16],
        task: &'a str,
    },
    /// The name of a trail a coordinator keeps checkpoints of.
    TrailName {
        membership: &'a [u8; 16],
        trail: &'a str,
    },
    /// How many checkpoints of a trail are kept, and the last one's digest.
    TrailLast {
        membership: &'a [u8; 16],
        trail: &'a str,
    },
    /// The member's last anchor of a trail.
    TrailAnchor {
        membership: &'a [u8; 16],
        trail: &'a str,
    },
    /// The last fork found of a trail.
    TrailFork {
        membership: &'a [u8; 16],
        trail: &'a str,
    },
}

/// The documents of one kind a membership keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listing<'a> {
    /// Every zone receipt of a task, one per resource.
    ZoneReceipts {
        membership: &'a [u8; 16],
        task: &'a str,
    },
    /// Every slot of a task's replay window, named by its number in decimal.
    ReplaySlots {
        membership: &'a [u8; 16],
        task: &'a str,
    },
    /// The fork found of every trail of a membership, named by its trail.
    TrailForks { membership: &'a [u8; 16] },
}

/// One document of a listing: its name within the listing, and its bytes or why it does not
/// read. One that does not read is listed, never hidden: the reader decides what it is worth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub name: String,
    pub bytes: Result<Vec<u8>, String>,
}

/// A change of one document: it is given the document as it stands, `None` when there is none,
/// and answers the document to keep, or `None` to leave it as it is.
pub type Change<'a> = &'a mut dyn FnMut(Option<&[u8]>) -> Result<Option<Vec<u8>>, MembershipError>;

/// The store of a Host's memberships: the only way the Host reads and writes them
/// (`1-architecture/8` Store contracts).
pub trait MemberStore: Send + Sync {
    /// Every entry, oldest first, each as the CBOR item it was added as.
    fn entries(&self) -> Result<Vec<Value>, MembershipError>;

    /// Fences the memberships every instance of the store keeps, for an identity reset: answers
    /// what holds the fence, which lifts it when dropped, once every change another instance had
    /// under way has ended, and refuses when that does not happen within the store's bound (an
    /// earlier reset still fencing, a change holding on) (iteration 03, X171). `None` on a store
    /// one process keeps, whose fence is that process's.
    fn fence_all(&self) -> Result<Option<Box<dyn Fence>>, MembershipError> {
        Ok(None)
    }

    /// Whether another instance fenced the memberships for an identity reset. Asked inside the
    /// unit of work of a change that would create authority under the identity, it also holds the
    /// fence off until that unit ends; asked outside one, it says so of this instant alone.
    /// `false` on a store one process keeps.
    fn fenced_elsewhere(&self) -> Result<bool, MembershipError> {
        Ok(false)
    }

    /// The entries after the entry `seq`, oldest first: what was added since a reader read up to
    /// it (iteration 03, WP-28.4).
    fn entries_after(&self, seq: u64) -> Result<Vec<Value>, MembershipError> {
        Ok(self
            .entries()?
            .into_iter()
            .skip(usize::try_from(seq).unwrap_or(usize::MAX))
            .collect())
    }

    /// Whether other instances share what this store keeps: the memberships are then read again
    /// before a change and while they are read (WP-28.4). A volume's store is one process's.
    fn shared(&self) -> bool {
        false
    }

    /// Adds `entry` as the entry `seq`, which is the one after the last held, the first being 1:
    /// any other sequence is refused with [`MembershipError::Conflict`] and nothing is added, so
    /// of the transitions that read the same memberships and arrive together one is added and
    /// the others learn they moved.
    fn append(&self, seq: u64, entry: &[u8]) -> Result<(), MembershipError>;

    /// Replaces the summary of the entries: a view, the entries being authoritative.
    fn replace_summary(&self, summary: &[u8]) -> Result<(), MembershipError>;

    /// Keeps the manifest of `epoch` of a membership, named by its `digest`, as the one of that
    /// epoch and as the current one: a view of the entry that records it.
    fn keep_manifest(
        &self,
        membership: &[u8; 16],
        epoch: u64,
        digest: &str,
        envelope: &[u8],
    ) -> Result<(), MembershipError>;

    /// Keeps an invitation as issued: a view of the entry that records it.
    fn keep_invitation(&self, invite: &[u8; 16], invitation: &[u8]) -> Result<(), MembershipError>;

    /// The document `doc`, whole; `None` when none is kept.
    fn doc(&self, doc: &Doc<'_>) -> Result<Option<Vec<u8>>, MembershipError>;

    /// Keeps `bytes` as the document `doc`, in place of the one before.
    fn keep(&self, doc: &Doc<'_>, bytes: &[u8]) -> Result<(), MembershipError>;

    /// Changes the document `doc` in place: `change` is given it as it stands and what it
    /// answers is kept, as one step for every other change of that document. An error of
    /// `change` is answered and nothing is kept.
    fn change(&self, doc: &Doc<'_>, change: Change<'_>) -> Result<(), MembershipError>;

    /// Removes the document `doc`; answers whether one was kept.
    fn remove(&self, doc: &Doc<'_>) -> Result<bool, MembershipError>;

    /// The documents of `listing`, in the order of their names.
    fn list(&self, listing: &Listing<'_>) -> Result<Vec<Listed>, MembershipError>;

    /// The checkpoint kept at `count` of a trail, the first being 1.
    fn checkpoint(
        &self,
        membership: &[u8; 16],
        trail: &str,
        count: u64,
    ) -> Result<Option<Vec<u8>>, MembershipError>;

    /// Publishes `envelope` as the checkpoint `count` of a trail, once: the same checkpoint
    /// again is the first, another at that place is refused.
    fn publish_checkpoint(
        &self,
        membership: &[u8; 16],
        trail: &str,
        count: u64,
        envelope: &[u8],
    ) -> Result<(), MembershipError>;
}
