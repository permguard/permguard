// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The fourth role a language may play: **remembering**.
//!
//! [`Evaluating`](crate::evaluating::Evaluating) answers *may this subject do this to this?* from
//! the request alone. A temporal runtime answers a different question — *may this happen, given
//! what has already happened?* — and the difference is not a bigger request. It is that the
//! partition has a past, that the past has to be durable before a decision may depend on it, and
//! that two decisions in one history stream have an order.
//!
//! So the temporal half is a separate role, asked for and never assumed, exactly like the other
//! three. A Cedar partition answers `None` here and a caller that wanted a temporal partition
//! learns so at load, rather than by submitting an event to a runtime that will quietly treat it
//! as a stateless query.
//!
//! # What this role does not decide
//!
//! Durability, ordering, replay, retention, producer identity and the wire contract are the
//! plane's, not the language's — they are the same whichever temporal runtime is behind them, and
//! a language that implemented them would be implementing them again. What arrives here is an
//! occurrence that is already durable; what leaves is what the schemas say about it and what the
//! policies decided.
//!
//! # The two-step, and why it is two
//!
//! [`Temporal::check`] validates an occurrence against the loaded schemas and derives its history
//! key. [`Temporal::apply`] observes it and, for a decision kind, decides. They are separate
//! because everything between them is the plane's: an event is checked against **every** addressed
//! partition before it is journalled, and applied only after it is durable. A single call would
//! have to either journal what might be refused or decide on what might be lost.

use std::collections::BTreeMap;

use crate::occurrence::Occurrence;
use crate::temporal::Contract;

/// An occurrence this partition accepts, with everything the schema derived for it.
#[derive(Debug, Clone)]
pub struct Checked {
    /// Whether this occurrence's kind produces a verdict.
    pub decides: bool,
    /// The pin values the server derived, by dotted field path, in the schema's order.
    ///
    /// Each is rendered as its canonical typed encoding: the text the history key is hashed over,
    /// and the text the signed record carries beside that hash.
    pub pins: Vec<(Vec<String>, String)>,
    /// The logged fields the server injected because the schema pins them.
    ///
    /// Kept apart from what the caller sent so the record can show both, and so a plane replaying
    /// a record does not have to re-derive them to know which were the server's.
    pub injected: BTreeMap<Vec<String>, String>,
}

impl Checked {
    /// The history key's pin names, in the schema's order.
    pub fn pin_names(&self) -> Vec<String> {
        self.pins.iter().map(|(path, _)| path.join(".")).collect()
    }

    /// The pin values, positionally matching [`Checked::pin_names`].
    pub fn pin_values(&self) -> Vec<String> {
        self.pins.iter().map(|(_, value)| value.clone()).collect()
    }
}

/// Why an occurrence is not one this partition accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub code: &'static str,
    pub message: String,
}

impl Refused {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        // A temporal refusal reaches the wire as its code: an unregistered one fails any test that
        // builds it.
        debug_assert!(
            permguard_core::codes::is_registered(code),
            "`{code}` is not a registered stable code"
        );
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Refused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Refused {}

/// What applying one occurrence concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applied {
    /// A history-only kind: observed, and there is no verdict to fabricate.
    Observed,
    /// A decision kind: the runtime's verdict, in Permguard's own terms.
    Decided(crate::evaluate::Verdict),
}

/// The remembering half of a compiled partition.
///
/// `&self` throughout: a temporal runtime's own state is its business, and a partition that
/// serialises application internally is the one that can promise ordering. What a caller must not
/// be able to do is apply two occurrences of one history stream concurrently and discover the
/// order afterwards.
pub trait Temporal: Send + Sync {
    /// What this partition's loaded schemas say it accepts.
    fn contract(&self) -> &Contract;

    /// Validates one occurrence against the loaded schemas and derives its history key.
    ///
    /// Everything checkable before the occurrence is durable happens here: that the action and
    /// kind are declared, that the fields it carries are declared and typed as declared, that the
    /// attributed entities are legal, and that a pin the caller also sent agrees with the value
    /// the schema's own source says it must have.
    ///
    /// Refuses rather than repairs. A pin the caller sent with a different value is not a value to
    /// choose between: one of the two is a lie about the request, and picking either would decide
    /// which.
    fn check(&self, occurrence: &Occurrence) -> Result<Checked, Refused>;

    /// Discards this partition's history and rebuilds it from an ordered run.
    ///
    /// # Why a rebuild rather than an insert
    ///
    /// A temporal engine is fed events in timestamp order — that is what lets it answer "within
    /// the last hour" without holding every event for ever. Replication does not respect that
    /// order: a plane that has been unreachable delivers its history *after* events that happened
    /// later, and feeding one of those into an engine that has already moved past it either
    /// corrupts its windows or is silently ignored. Both are wrong, and the second is worse
    /// because nothing reports it.
    ///
    /// So a late arrival is not inserted. The affected history is rebuilt: the engine is replaced
    /// with a fresh one and the whole ordered run is observed into it. Expensive, and bounded —
    /// the run is bounded by retention, which is bounded by the longest window any loaded policy
    /// looks back over. A plane whose peers are reachable never pays it.
    ///
    /// # One history, not the partition
    ///
    /// `history` names *which* history: the digest of the derived key for a partition whose schema
    /// pins one, and the empty string for a partition with global history. A schema that pins the
    /// caller has one history per caller, and they are independent — so rebuilding the one that a
    /// late arrival landed in must not discard the others, and a plane holding a thousand callers'
    /// histories must not replay a thousand of them to absorb one event.
    ///
    /// What the implementation keeps in memory is bounded, and eviction is not allowed to change a
    /// verdict: an evicted history is rebuilt from the durable record before it answers again.
    ///
    /// `occurrences` must already be in the deterministic order the caller documents; this does not
    /// sort, because the order across producers is a replication decision rather than a runtime
    /// one, and a runtime that re-sorted could disagree with the store that recorded them.
    ///
    /// # The deadline
    ///
    /// A replay is part of the decision that needed it, and stops when that decision's replay
    /// budget runs out (DOGWOOD-03): past `deadline` the rebuild is abandoned between two events,
    /// refused `evaluation_deadline_exceeded`, and the history keeps what it had. It never goes on
    /// consuming work after the caller has been answered.
    fn rebuild(
        &self,
        history: &str,
        occurrences: &[Occurrence],
        deadline: Option<std::time::Instant>,
    ) -> Result<(), Refused>;

    /// Charges this partition's warm histories to `budget`, under `zone` (DOGWOOD-02).
    ///
    /// Called by the plane each time it hands the partition work; the first call binds it, and
    /// later ones are no-ops. A partition never bound charges a budget of its own under the
    /// default bounds, so its warm state is bounded either way.
    fn bind_warm(&self, budget: &std::sync::Arc<crate::warm::Budget>, zone: &str) {
        let _ = (budget, zone);
    }

    /// Checks this partition against the input its manifest declares, at load and where a ledger
    /// is authored (TL-5c): a version 2 partition's one-sided fields must be declared, and the
    /// declarations belong to version 2 only.
    fn check_input(&self, input: Option<&str>) -> Result<(), String> {
        let _ = input;
        Ok(())
    }

    /// How many occurrences this partition's `history` has been given since it was built or last
    /// rebuilt.
    ///
    /// # Why a plane needs this
    ///
    /// A temporal engine's history lives in memory; the journal on disk is the authority. The two
    /// agree only because the plane feeds one from the other, and there are two ordinary moments
    /// when they do not: a restart, and a cache eviction that recompiles a partition. Both leave an
    /// engine that has observed nothing sitting in front of a ledger with a history — and a decision
    /// taken then is not wrong in a way anybody notices. It is a `deny` that looks exactly like a
    /// correct one, because the login it should have seen is on disk and not in the engine.
    ///
    /// Zero is what says "this engine has been told nothing yet", which is what the plane replays
    /// against. It is not a watermark and cannot be one: an engine does not know what sequences are,
    /// and the plane is the only thing that knows what it has fed in.
    fn observed(&self, history: &str) -> u64;

    /// Observes one **already durable** occurrence, and decides it when its kind decides.
    ///
    /// Called after the event is journalled and settled, never before: a decision that depended on
    /// history the process then lost would be a decision nothing can reproduce.
    ///
    /// `history` names which history the occurrence belongs to — the digest of its derived key, or
    /// the empty string for a partition with global history. Passed in rather than derived here,
    /// and deliberately: the same string is what the durable record carries and what the journal's
    /// index is scanned by, so a partition deciding under one key while the record was stored under
    /// another is a state this signature does not have.
    fn apply(&self, history: &str, occurrence: &Occurrence, checked: &Checked) -> Applied;

    /// [`Temporal::apply`], for a plane that has just replayed `history` or found it warm.
    ///
    /// A history the warm budget evicted between that replay and this call holds nothing, and
    /// observing the occurrence into an empty engine would decide against one record while the
    /// plane believes the history whole. Such a history answers `E` rather than being rebuilt
    /// empty, and the plane marks it for replay (after the review).
    fn apply_replayed(&self, history: &str, occurrence: &Occurrence, checked: &Checked) -> Applied {
        self.apply(history, occurrence, checked)
    }
}

// ─── The interface, as the wire carries it ───────────────────────────────────
