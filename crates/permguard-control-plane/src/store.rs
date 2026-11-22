// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The contract of the store that keeps one ledger, and of what hands the store of each ledger
//! out (`3-control-plane/1` Stores).
//!
//! A ledger is its objects, immutable and named by the digest of their canonical bytes, and its
//! refs, each a head with a counter that only rises. The store keeps them with the rules that
//! make them a ledger: an object lands once and is served only while it still hashes to its
//! name; a ref moves by compare-and-swap from the state the caller read, and carries the
//! operation that moved it. What a push may land, what a statement signs and what a collection
//! may sweep are the Plane's, the same on every backend.
//!
//! | Backend            | Keeps a ledger in                                        |
//! | ------------------ | -------------------------------------------------------- |
//! | [`files`], default | `<zones>/<zone>/ledgers/<ledger>/` on the local filesystem |
//! | `permguard-s3`     | objects on S3, the rest in PostgreSQL                    |

pub mod files;
#[cfg(any(test, feature = "test-support"))]
pub mod suite;

use std::sync::Arc;

use permguard_host::operations::journal::OperationId;
use permguard_host::operations::mutation::{Applying, Domain, Observed};
use permguard_notp::ExpectedRef;
use permguard_objects::digest::Digest;
use permguard_objects::grammar::GrammarError;
use permguard_objects::object::{Object, ObjectError};

pub use files::{FileLedgers, FileObjectStore, object_check, testing};

/// One object as it sits on the shelf: what it is, how big, and how old.
///
/// Age is the file's, which is exactly right for the only question asked of
/// it: *could this still belong to a transfer in flight?*
#[derive(Debug, Clone)]
pub struct StoredObject {
    pub digest: Digest,
    pub bytes: u64,
    pub modified: std::time::SystemTime,
}

/// The state of one ref: `(head, counter, previous_ref_digest)` (WP-7.1). A ref written before
/// the previous digest existed reads as a state without one, and its next write names it.
pub use permguard_objects::refstate::RefState;

/// The outcome of a compare-and-swap ref update, per the idempotency table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefUpdate {
    /// The head moved: a genuine update, counter incremented.
    Updated(RefState),
    /// The current head already equals the new head: a retry landed —
    /// success, counter untouched.
    AlreadyCurrent(RefState),
}

/// The domain of the ref updates (WP-3.6): what recovery asks of the ledgers' refs.
pub const REFS_DOMAIN: &str = "ledger.refs";

/// The operation of one ref update.
pub const REF_UPDATE: &str = "ledger.ref.update";

/// The refs of every ledger, as the mutation transaction's domain: an operation shows when the
/// ref its intent targets, `<zone>/<ledger>/<ref>`, was written by it.
#[derive(Clone)]
pub struct RefDomain {
    pub ledgers: Arc<dyn Ledgers>,
}

impl RefDomain {
    /// The intent's target of an update of `name` in the ledger `zone`/`ledger`.
    pub fn target(zone: &str, ledger: &str, name: &str) -> String {
        format!("{zone}/{ledger}/{name}")
    }
}

impl Domain for RefDomain {
    fn name(&self) -> &'static str {
        REFS_DOMAIN
    }

    fn observe(
        &self,
        operation_id: &OperationId,
        target: Option<&str>,
    ) -> std::result::Result<Option<Observed>, String> {
        let Some((zone, ledger, name)) =
            target
                .and_then(|target| target.split_once('/'))
                .and_then(|(zone, rest)| {
                    rest.split_once('/')
                        .map(|(ledger, name)| (zone, ledger, name))
                })
        else {
            return Ok(None);
        };
        // Ids from the catalog, never a path the target could climb out of.
        if [zone, ledger]
            .iter()
            .any(|id| id.is_empty() || id.contains(['/', '\\']) || id.starts_with('.'))
        {
            return Ok(None);
        }
        let store = self.ledgers.ledger(zone, ledger);
        // A ref that does not read is not a ref that was never written: the first stops the
        // recovery, the second fails the operation.
        let Some(written) = store
            .ref_operation(name)
            .map_err(|error| error.to_string())?
        else {
            return Ok(None);
        };
        if written != operation_id.to_string() {
            return Ok(None);
        }
        let Some(state) = store.read_ref(name).map_err(|error| error.to_string())? else {
            return Ok(None);
        };
        Ok(Some(Observed {
            revision: state.counter,
            target: target.map(str::to_owned),
        }))
    }
}

/// Why the store refused.
#[derive(Debug, Clone)]
pub enum StoreError {
    /// The object bytes were rejected by the model (non-canonical, over a
    /// limit, wrong schema).
    Object(ObjectError),
    /// A name failed its grammar.
    Grammar(GrammarError),
    /// The CAS found a different current state. Carries what is current, so
    /// the caller can answer with the truth.
    Conflict { current: Option<RefState> },
    /// A stored object's bytes no longer hash to its name: detection, not
    /// recovery — the caller reports it and recovery comes from replicas.
    Corrupt { digest: Digest },
    /// The on-disk layout was written by a different version: refused,
    /// never reinterpreted.
    Incompatible { found: String },
    /// The filesystem failed.
    Backend { detail: String },
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Object(e) => write!(f, "object rejected: {e}"),
            StoreError::Grammar(e) => write!(f, "name rejected: {e}"),
            StoreError::Conflict { .. } => write!(f, "the ref moved: compare-and-swap conflict"),
            StoreError::Corrupt { digest } => write!(f, "stored object {digest} is corrupt"),
            StoreError::Incompatible { found } => write!(
                f,
                "the store layout is `{found}`; this build speaks `{FORMAT}`"
            ),
            StoreError::Backend { detail } => write!(f, "the object store failed: {detail}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<ObjectError> for StoreError {
    fn from(e: ObjectError) -> Self {
        StoreError::Object(e)
    }
}

impl From<GrammarError> for StoreError {
    fn from(e: GrammarError) -> Self {
        StoreError::Grammar(e)
    }
}

pub(crate) fn backend(context: &str, error: impl std::fmt::Display) -> StoreError {
    StoreError::Backend {
        detail: format!("{context}: {error}"),
    }
}

pub(crate) type Result<T> = std::result::Result<T, StoreError>;

/// The one layout this build reads and writes, pinned in `FORMAT`.
pub const FORMAT: &str = "1";

/// A state's `ref_digest`, which only a counter past `i64` could refuse.
pub fn ref_digest(state: &RefState) -> Result<Digest> {
    state
        .ref_digest()
        .map_err(|error| backend("the ref digest", error))
}

/// What publishing an object did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Landed {
    /// The object was written.
    Written,
    /// The store already held it: nothing was written.
    AlreadyThere,
}

/// A ledger's transfer sessions, held for one reader and writer at a time: the hold is taken
/// when this is asked for and let go when it is dropped, so a session read under it is the
/// session the next write replaces. The store keeps each record as the bytes it was given;
/// what a session is, is [`crate::transfer`]'s.
pub trait TransferSessions {
    /// The record of the session `transfer_id`, when one is kept.
    fn get(&self, transfer_id: &[u8; 16]) -> Result<Option<Vec<u8>>>;

    /// The record of every session kept, in the order of their ids.
    fn list(&self) -> Result<Vec<Vec<u8>>>;

    /// Keeps `record` as the session `transfer_id`, durably, in place of what it was.
    fn put(&self, transfer_id: &[u8; 16], record: &[u8]) -> Result<()>;

    /// Removes the session `transfer_id`; nothing when none is kept.
    fn remove(&self, transfer_id: &[u8; 16]) -> Result<()>;
}

/// The store of one ledger: the only way the Control Plane reads and writes its objects, its
/// refs, its head statements and its transfer sessions (`1-architecture/8` Store contracts).
pub trait LedgerStore: Send + Sync {
    /// Whether an object is present: the negotiation primitive. Presence, not integrity.
    fn has_object(&self, digest: &Digest) -> bool;

    /// Ingests one object, fail-closed: canonical decode, limits and grammars first, then
    /// published under its digest without replacement. Answers the digest, the decoded object
    /// and whether it was written: content already held writes nothing, and of two pushes of one
    /// object that arrive together one writes. A name that holds other content is
    /// [`StoreError::Corrupt`], left as it was.
    fn publish_object(&self, bytes: &[u8]) -> Result<(Digest, Object, Landed)>;

    /// [`Self::publish_object`], for a caller that does not ask whether it wrote.
    fn put_object(&self, bytes: &[u8]) -> Result<(Digest, Object)> {
        self.publish_object(bytes)
            .map(|(digest, decoded, _)| (digest, decoded))
    }

    /// Reads one object, verified on the way out: bytes that no longer hash to their name are
    /// [`StoreError::Corrupt`], never served.
    fn get_object(&self, digest: &Digest) -> Result<Option<Vec<u8>>>;

    /// Every object held: its digest, its size at rest and how old it is. Nothing is read.
    fn list_objects(&self) -> Result<Vec<StoredObject>>;

    /// Removes one object and answers the bytes it freed; one that is not there frees none.
    fn remove_object(&self, digest: &Digest) -> Result<u64>;

    /// Keeps `heads` as roots of the collection: what a root reaches is never swept while the
    /// ledger exists. Kept once, a root is never removed.
    fn keep_roots(&self, heads: &[Digest]) -> Result<()>;

    /// The roots kept, sorted.
    fn roots(&self) -> Result<Vec<Digest>>;

    /// A ref's state. A ref that is there and does not read is an error, never a ref that is
    /// not there.
    fn read_ref(&self, name: &str) -> Result<Option<RefState>>;

    /// The operation that wrote the ref `name`, when its record names one.
    fn ref_operation(&self, name: &str) -> Result<Option<String>>;

    /// Every ref, by name.
    fn list_refs(&self) -> Result<Vec<(String, RefState)>>;

    /// The idempotent compare-and-swap of the specification, over the ref state the caller
    /// expects, `(counter, ref_digest)`, inside the operation `applying`, whose id the ref
    /// carries from then on:
    ///
    /// | current state                         | result                                  |
    /// | ------------------------------------- | --------------------------------------- |
    /// | head `== new`                         | `AlreadyCurrent`, counter untouched     |
    /// | `(counter, ref_digest) == expected`   | the successor state, written atomically |
    /// | anything else                         | `Conflict`, carrying what is current    |
    ///
    /// `expected = None` is the creation case: it succeeds only while the ref does not exist,
    /// and the counter starts at 1. Of the updates that read one state and arrive together, one
    /// is written and the others are answered what is current.
    fn update_ref(
        &self,
        applying: &Applying<'_>,
        name: &str,
        expected: Option<&ExpectedRef>,
        new: &Digest,
    ) -> Result<RefUpdate>;

    /// Makes the ref `name` durable, so that an answer saying where it is never rests on a
    /// write another update has not made durable yet.
    fn make_ref_durable(&self, name: &str) -> Result<()>;

    /// Makes the objects `digests` name durable, so that a ref about to reach them never
    /// outlives them.
    fn make_durable(&self, digests: &std::collections::BTreeSet<Digest>) -> Result<()>;

    /// Removes what writes interrupted by a crash left in this ledger, once older than
    /// `older_than`; answers how many.
    fn sweep_temporaries(&self, older_than: std::time::Duration) -> Result<usize>;

    /// What Load verifies of this ledger before the Plane serves it, reading only: its layout
    /// is this build's, and every ref reads and names a head the store holds. Answers how many
    /// refs it checked.
    fn verify_at_load(&self) -> Result<usize>;

    /// Keeps the signed head statement of a ref: a cache, replaced at every update, verified
    /// against the current ref before it is served.
    fn write_signature(&self, name: &str, envelope: &[u8]) -> Result<()>;

    /// The cached statement of a ref, if any.
    fn read_signature(&self, name: &str) -> Result<Option<Vec<u8>>>;

    /// This ledger's transfer sessions, held until the answer is dropped: the backend takes its
    /// hold and hands [`crate::transfer::Transfers`] its [`TransferSessions`].
    fn transfers(&self) -> Result<crate::transfer::Transfers<'_>>;

    /// The bytes this ledger's objects take at rest, for its quota.
    fn stored_bytes(&self) -> Result<u64>;
}

/// The ledgers of a Control Plane: what hands out the store of each. One store a ledger for the
/// life of the process, so that everything that reads and writes a ledger does it through the
/// same one: a push, a collection, an export and a recovery meet in its holds.
pub trait Ledgers: Send + Sync {
    /// The store of the ledger `ledger` of the zone `zone`, both catalog ids.
    fn ledger(&self, zone: &str, ledger: &str) -> Arc<dyn LedgerStore>;
}
