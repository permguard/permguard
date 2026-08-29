// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The fourth role a language may play: **remembering**.
//!
//! [`Evaluating`](crate::evaluate::Evaluating) answers *may this subject do this to this?* from
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

use crate::dogwood::occurrence::Occurrence;

/// What a compiled temporal partition says about itself, derived from its loaded schemas.
///
/// Read by the event store (for bounds), by validation (for what an occurrence may say) and by
/// discovery (for what a caller may send). Derived once at load, never per request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Contract {
    /// The furthest back any policy in this partition may look, in seconds.
    ///
    /// The retention floor: history younger than this is still being read, so it cannot be
    /// deleted, and an event later than this window is answering nobody.
    pub max_window_seconds: i64,
    /// Every event kind the schema derives, sorted.
    pub kinds: Vec<String>,
    /// The kinds that produce a verdict. The rest are history-only and return a receipt.
    pub decision_kinds: Vec<String>,
    /// The pinned field paths that partition this partition's history, in the schema's order.
    ///
    /// Empty means the schema declares no universal symmetric pin, so every evaluation ranges
    /// over the whole retained history — which is what `history: { scope: global }` acknowledges.
    pub history_pins: Vec<Vec<String>>,
    /// The signature of every `(action, kind)` the schema derives.
    pub signatures: Vec<Signature>,
}

impl Contract {
    /// Whether this partition's history is partitioned by a universal symmetric pin.
    pub fn is_partitioned(&self) -> bool {
        !self.history_pins.is_empty()
    }

    /// Whether a kind of that name produces a verdict.
    pub fn decides(&self, kind: &str) -> bool {
        self.decision_kinds.iter().any(|held| held == kind)
    }

    /// The signature of one `(action, kind)`, when the schema derives it.
    pub fn signature(&self, action: &str, kind: &str) -> Option<&Signature> {
        self.signatures
            .iter()
            .find(|held| held.action == action && held.kind == kind)
    }
}

/// One derived event's shape: what an occurrence of this `(action, kind)` may carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// The qualified action, as a policy names it: `Acme::Action::Transfer`.
    pub action: String,
    pub kind: String,
    /// Whether this kind produces a verdict.
    pub decision: bool,
    /// Every declared leaf field, by dotted path, with the type the schema gives it.
    pub fields: Vec<Field>,
    /// The pins this event carries, each a field forced to equal a request-side value.
    pub pins: Vec<Pin>,
}

/// One declared leaf field of an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub path: Vec<String>,
    /// The declared type, as the runtime renders it. Text because it is a *contract about* the
    /// type rather than the type itself: two runtimes need not share a type lattice.
    pub declared: String,
}

/// One schema-declared pin: a logged field forced to equal an authoritative request value.
///
/// The caller never sends these. The server reads the source the schema names — the principal, the
/// resource, or a request-context path — and injects the logged field before anything is
/// persisted. A caller that also sent the field must have sent the same value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    /// The logged field this pin fills, by dotted path.
    pub field: Vec<String>,
    /// Where its value comes from.
    pub source: PinSource,
}

/// The authoritative root a pin's value is read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinSource {
    /// The request's principal entity.
    Principal,
    /// The request's resource entity.
    Resource,
    /// A path into the request context.
    Context(Vec<String>),
}

impl PinSource {
    /// How the source reads in a diagnostic, in the words a policy author wrote it.
    pub fn describe(&self) -> String {
        match self {
            Self::Principal => "principal".to_owned(),
            Self::Resource => "resource".to_owned(),
            Self::Context(path) => format!("context.{}", path.join(".")),
        }
    }
}

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
    fn rebuild(&self, history: &str, occurrences: &[Occurrence]) -> Result<(), Refused>;

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
}

// ─── The interface, as the wire carries it ───────────────────────────────────

/// The name of this interface, as a ledger's `profiles.<name>.type` declares it and as the
/// discovery document identifies it.
///
/// `temporal` names the API's semantics; `dogwood` names its first runtime. Another temporal
/// runtime must be able to implement this interface without the interface being renamed, and the
/// stateless one must be able to stay exactly as it is.
pub const INTERFACE: &str = "permguard.api.pdp.temporal.v1alpha1";

/// Where an occurrence is submitted.
///
/// One route, and `POST` only. There are no `GET` event routes on a data plane: a plane's journal
/// is a shipping buffer whose retention is set by what the policies still read, not an archive to
/// query. Reading events is the control plane's, where the history is whole.
pub const SUBMISSION_PATH: &str = "/temporal/v1alpha1/events";

/// Where a data plane publishes the configuration of this interface.
///
/// Kept beside [`SUBMISSION_PATH`] because both are part of the versioned client/server contract:
/// a transport client must not depend on a data-plane implementation crate just to discover the
/// route it is compiled to call.
pub const CONFIGURATION_PATH: &str = "/.well-known/permguard-pdp-temporal-v1alpha1-configuration";

/// What this interface offers, as a caller configures itself from it.
///
/// A capability is a promise: each of these names something implemented, tested, and answered
/// identically over both transports.
///
/// | URN | What it promises |
/// | --- | --- |
/// | `store-in-payload` | `store.zone` and `store.ledger` name the store in the body, not the URL |
/// | `typed-events` | the occurrence's `type` is a registered contract, checked and never obeyed |
/// | `schema-derived-pins` | the history key comes from the loaded schema, never from the caller |
/// | `history-receipts` | a history-only kind returns a receipt, not a fabricated verdict |
/// | `durable-before-decided` | the occurrence is durable before it is observed or answered |
pub const CAPABILITIES: [&str; 5] = [
    "urn:permguard:pdp:temporal:v1alpha1:store-in-payload",
    "urn:permguard:pdp:temporal:v1alpha1:typed-events",
    "urn:permguard:pdp:temporal:v1alpha1:schema-derived-pins",
    "urn:permguard:pdp:temporal:v1alpha1:history-receipts",
    "urn:permguard:pdp:temporal:v1alpha1:durable-before-decided",
];

/// One submission, as the wire carries it.
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitRequest {
    /// Which policy store to decide against.
    #[serde(default)]
    pub store: Option<StoreBody>,
    /// The typed occurrence.
    #[serde(default)]
    pub event: Option<EventBody>,
}

/// Which store an occurrence belongs to.
///
/// In the payload, never the URL — the same rule the stateless interface follows, and for the same
/// reason: a store named in a path is a store a proxy can rewrite.
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoreBody {
    #[serde(default)]
    pub zone: Option<String>,
    #[serde(default)]
    pub ledger: Option<String>,
    /// Which of the ledger's profiles. It must be one of this interface's type.
    #[serde(default)]
    pub profile: Option<String>,
}

/// The typed occurrence: what contract it is, and its payload.
///
/// `type` is an **assertion**, checked against what the addressed partitions accept — never a
/// selector. A caller that could choose the contract would be choosing the validator for data it
/// also supplies.
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventBody {
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}

/// What one submission concluded.
///
/// Two shapes, told apart by `outcome`, because a history-only kind has no verdict and inventing
/// one would be the single most dangerous thing this interface could do: a caller cannot tell a
/// fabricated permit from a decided one.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct SubmitResponse {
    /// `decided` or `accepted`.
    pub outcome: Outcome,
    /// The occurrence's identifier, as the caller stated it.
    pub event_id: String,
    /// Where this occurrence sits in this plane's stream for the ledger.
    pub watermark: Watermark,
    /// Present exactly when `outcome` is `decided`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<bool>,
    /// The decision's own identifier, matching its audit record. Present with `decision`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,
    /// The policies that decided it, by identity.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<String>,
    /// What every addressed partition answered, in profile order.
    ///
    /// Empty for a history-only event. The aggregate decision above remains authoritative; these
    /// entries make an objection, silence or runtime failure attributable instead of collapsing
    /// several independent policy sets into one unexplained boolean.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evaluations: Vec<PartitionEvaluation>,
    /// Why, for an operator and for a caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
    /// Which history this decision ranged over, and how fresh it was.
    ///
    /// Always present, including for a plane that reads only its own events: an auditor
    /// reproducing a decision needs to know *what was visible*, and "local" is an answer to that
    /// question rather than the absence of one.
    pub history: HistoryScope,
}

/// One temporal partition's answer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct PartitionEvaluation {
    pub partition: String,
    pub decision: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
}

/// Checks a partition's declared history scope against what its schemas actually say.
///
/// # Why this is a check and not a default
///
/// A Dogwood event schema may declare a *universal symmetric pin* — a field pinned the same way on
/// every kind, `callerPrincipal` in upstream's own examples. When it does, each evaluation ranges
/// over one principal's history rather than the ledger's, and both the memory a plane holds and the
/// work one decision costs are bounded by what one principal did.
///
/// When it does not, every evaluation ranges over the whole retained history of the partition. That
/// is a legitimate thing to want, and it is also the shape that turns a busy ledger into an
/// evaluation whose cost grows with the tenant's traffic. So it is not inherited from a pin
/// somebody forgot to write: the manifest has to say `history: { scope: global }`, and this is what
/// makes the manifest and the schema agree.
///
/// Both directions are refused, because both are somebody's mistake:
///
/// * declared `global`, schema partitioned — the manifest claims an unbounded workload the schema
///   does not have. Left alone, an operator provisions for a cost that never arrives and, worse,
///   reads the declaration as documentation of a partitioning that is actually there.
/// * not declared, schema unpartitioned — the unbounded workload nobody accepted. This is the
///   direction that hurts: it is discovered as a plane that slows down as a tenant gets busier.
pub fn check_history_scope(
    partition: &str,
    declared: Option<permguard_objects::manifest::HistoryScope>,
    contract: &Contract,
) -> Result<(), String> {
    match (declared, contract.is_partitioned()) {
        (None, true) | (Some(permguard_objects::manifest::HistoryScope::Global), false) => Ok(()),
        (Some(permguard_objects::manifest::HistoryScope::Global), true) => Err(format!(
            "the partition `{partition}` declares `history: {{ scope: global }}` and its event \
             schema pins {} on every kind, so its history is already partitioned by that. Remove \
             the declaration, or remove the pin if the whole ledger really is meant to be in scope",
            pins_of(contract)
        )),
        (None, false) => Err(format!(
            "the partition `{partition}` has no universal symmetric pin, so every evaluation \
             ranges over its whole retained history and costs what the tenant's traffic costs. \
             That is a workload to accept out loud: declare `history: {{ scope: global }}` on the \
             partition, or pin a field the same way on every kind — `callerPrincipal`, for one \
             history per principal"
        )),
    }
}

/// The pinned paths, as a manifest author would write them.
fn pins_of(contract: &Contract) -> String {
    contract
        .history_pins
        .iter()
        .map(|path| format!("`{}`", path.join(".")))
        .collect::<Vec<String>>()
        .join(", ")
}

/// Which history a decision ranged over.
///
/// # Why this travels with the answer
///
/// The same request, decided by two planes with different imported history, can legitimately
/// differ — and nothing in the request or the ledger explains why. This is what explains it. It is
/// also what an auditor replays against: a watermark identifies exactly the set of events that
/// were visible, and without it a decision cannot be reproduced.
///
/// This is deliberately not called consistency without qualification. Replication is asynchronous;
/// a shared mode ranges over what had *arrived*, and saying so plainly is the difference between a
/// documented bound and an implied guarantee nobody can keep.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct HistoryScope {
    /// `local`, `shared-eventual` or `shared-bounded`.
    pub mode: String,
    /// The opaque import watermark this decision saw, for a shared mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watermark: Option<String>,
    /// How long ago the imported history was last refreshed, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staleness_seconds: Option<u64>,
    /// How many recorded holes this history has that nobody has accepted.
    ///
    /// Distinct from staleness, and reported even when the decision was given: staleness is
    /// history this plane has not caught up with yet, a gap is history it will never hold. A
    /// decision made through a hole is a decision over fewer occurrences than happened, and an
    /// auditor reproducing it has to be able to see that.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub gaps: u64,
}

fn is_zero(count: &u64) -> bool {
    *count == 0
}

impl HistoryScope {
    /// A decision that ranged over this plane's own events and no others.
    pub fn local() -> Self {
        Self {
            mode: "local".to_owned(),
            watermark: None,
            staleness_seconds: None,
            // A plane reading only its own events has nothing imported to have a hole in.
            gaps: 0,
        }
    }
}

/// What a submission did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// A decision kind: `decision` carries the verdict.
    Decided,
    /// A history-only kind: durably recorded and observed, and there is no verdict.
    Accepted,
}

/// Where an occurrence sits in this plane's stream.
///
/// The caller's proof that the event is durable, and the coordinate a later read cites. Not a
/// global order: there is no truthful total order across producers, and this says which producer
/// instance and which position within it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Watermark {
    /// The producer instance this plane is running as.
    pub instance: String,
    /// This occurrence's position in that instance's stream for this ledger.
    pub sequence: u64,
    /// The derived history key's digest — the index key, never a substitute for its values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<String>,
}

/// The two audiences of one reason.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Reason {
    pub code: String,
    pub message: String,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use permguard_objects::manifest::HistoryScope as Declared;

    /// A contract with, or without, a universal symmetric pin.
    fn contract(pinned: bool) -> Contract {
        Contract {
            max_window_seconds: 3_600,
            kinds: vec!["request".to_owned()],
            decision_kinds: vec!["request".to_owned()],
            history_pins: match pinned {
                true => vec![vec!["callerPrincipal".to_owned()]],
                false => Vec::new(),
            },
            signatures: Vec::new(),
        }
    }

    /// The manifest and the schema must agree about what a decision ranges over.
    ///
    /// # What this is actually about
    ///
    /// Whether a partition's history is bounded per key or spans the whole ledger is the single
    /// biggest thing about what one decision costs, and it is decided by a detail of the event
    /// schema — a field pinned identically on every kind. Nothing about the manifest hints at it.
    ///
    /// So the manifest has to state it, and stating it wrongly is refused in both directions: an
    /// unpinned schema with no declaration is the unbounded workload nobody accepted, and a pinned
    /// schema declaring `global` is a claim about cost that the schema contradicts.
    #[test]
    fn a_declared_history_scope_must_match_what_the_schema_says() {
        // Pinned and undeclared: the ordinary, bounded partition.
        check_history_scope("session", None, &contract(true)).expect("this is the good shape");

        // Unpinned and declared: unbounded, and accepted out loud.
        check_history_scope("audit", Some(Declared::Global), &contract(false))
            .expect("an operator said so");

        // Unpinned and undeclared: the workload nobody agreed to.
        let refused = check_history_scope("audit", None, &contract(false))
            .expect_err("an unbounded history is not something to inherit by omission");
        assert!(refused.contains("history: { scope: global }"), "{refused}");
        assert!(
            refused.contains("callerPrincipal"),
            "and it names the way out: {refused}"
        );

        // Pinned and declared: a claim the schema contradicts.
        let refused = check_history_scope("session", Some(Declared::Global), &contract(true))
            .expect_err("the declaration and the schema disagree");
        assert!(refused.contains("callerPrincipal"), "{refused}");
    }
}
