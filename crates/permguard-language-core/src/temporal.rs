// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The temporal interface's wire model: what a submission carries, what it answers, and which
//! history a decision ranged over. What a temporal partition is, and how it checks and decides an
//! occurrence, is the decision point's (`permguard_pdp_core::temporal`).

/// The name of this interface, as a ledger's `profiles.<name>.type` declares it and as the
/// discovery document identifies it.
///
/// `temporal` names the API's semantics; `dogwood` names its first runtime. Another temporal
/// runtime must be able to implement this interface without the interface being renamed, and the
/// stateless one must be able to stay exactly as it is.
pub const INTERFACE: &str = permguard_core::domains::interface::PDP_TEMPORAL_V1ALPHA1;

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
    permguard_core::domains::capability::TEMPORAL_V1ALPHA1_STORE_IN_PAYLOAD,
    permguard_core::domains::capability::TEMPORAL_V1ALPHA1_TYPED_EVENTS,
    permguard_core::domains::capability::TEMPORAL_V1ALPHA1_SCHEMA_DERIVED_PINS,
    permguard_core::domains::capability::TEMPORAL_V1ALPHA1_HISTORY_RECEIPTS,
    permguard_core::domains::capability::TEMPORAL_V1ALPHA1_DURABLE_BEFORE_DECIDED,
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
    /// `decided`, `accepted` or `indeterminate`.
    pub outcome: Outcome,
    /// The occurrence's identifier, as the caller stated it.
    pub event_id: String,
    /// Where this occurrence sits in this plane's stream for the ledger.
    pub watermark: Watermark,
    /// Present exactly when `outcome` is `decided`: absent for a history-only receipt and for an
    /// indeterminate result alike, so neither can be read as a decided deny.
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
    /// The exact vector frontier a shared decision observed: each imported run, how far it held
    /// it, what it still retained and its holes (WP-6.4a); empty for `local`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frontier: Vec<permguard_core::frontier::FrontierRun>,
    /// The revision of the origin set that defines the required origins, in hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_set_revision: Option<String>,
    /// The freshness bound in force, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_staleness_seconds: Option<u64>,
    /// The required origins a `shared-eventual` decision is degraded by: stale, behind or gapped.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub degraded: Vec<String>,
    /// The time the runtime's windows range over: `occurred_at`.
    #[serde(default = "occurred_at")]
    pub time: String,
    /// How many logical occurrences of this history a digest conflict quarantined: left out of a
    /// `shared-eventual` decision (WP-6.4b); omitted at zero.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub quarantined: u64,
}

fn occurred_at() -> String {
    permguard_core::frontier::TIME_OCCURRED_AT.to_owned()
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
            frontier: Vec::new(),
            origin_set_revision: None,
            max_staleness_seconds: None,
            degraded: Vec::new(),
            time: occurred_at(),
            quarantined: 0,
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
    /// A decision kind whose profile result is `indeterminate`: a partition could not evaluate the
    /// occurrence and no policy denied it. The occurrence is durable and receipted; `decision` is
    /// absent, because the verdict it did not get is never fabricated as a deny.
    Indeterminate,
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
