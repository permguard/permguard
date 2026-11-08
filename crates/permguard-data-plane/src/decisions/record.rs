// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What one decision record is made of: the decision as the path hands it over, the epoch of the
//! stream it is written to, and the body built from both (WP-6.1). The writing itself is the
//! Host's: see [`super::host`].

use std::collections::BTreeMap;

use permguard_decisions::record::{
    ActionRef, Body, Build, Commitments, DecisionBody, Inputs, MarkerBody, Party, Predecessor,
    Reason, Sampling, StoreRef, Trace,
};
use permguard_decisions::{Commitment, commitment};
use serde_json::Value;

/// What one decision has to say about itself, in the vocabulary of the
/// decision path rather than of the record.
#[derive(Debug, Clone)]
pub struct Decided<'a> {
    /// The handle the caller was given back.
    pub id: &'a str,
    /// When, RFC 3339 in UTC.
    pub at: String,
    /// The zone that owns the ledger.
    pub zone: &'a str,
    /// The ledger that answered.
    pub ledger: &'a str,
    /// The zone's id: with the ledger's, the resource of the Host stream the record lands on
    /// (WP-6.1).
    pub zone_id: &'a str,
    /// The ledger's id.
    pub ledger_id: &'a str,
    /// The zone and the ledger as their 16 UUID bytes: the scope input tags are keyed by
    /// (WP-3.3). Absent for a ledger whose ids are not UUIDs: its tags are then `unavailable`.
    pub scope: Option<permguard_decisions::commitment::Scope>,
    /// The exact commit it answered from.
    pub commit: &'a str,
    /// Where that commit stood in the ledger's history.
    pub counter: u64,
    /// Which profile was asked for.
    pub profile: &'a str,
    /// Who asked, already pseudonymised.
    pub subject: (String, String),
    /// The subject attributes the deployment named in `include`.
    pub subject_properties: Option<serde_json::Map<String, Value>>,
    /// About what.
    pub resource: (String, String),
    /// The resource attributes the deployment named in `include`.
    pub resource_properties: Option<serde_json::Map<String, Value>>,
    /// The context members the deployment named in `include`.
    pub included_context: Option<serde_json::Map<String, Value>>,
    /// To do what.
    pub action: String,
    /// On whose behalf, where the request said so — pseudonymised.
    pub principal: Option<(String, String)>,
    /// The caller's context, for the commitment.
    pub context: Option<Value>,
    /// The entity graph, for the commitment.
    pub partition_inputs: Option<Value>,
    /// The partitions that declare an input and were addressed with none.
    pub absent_inputs: Vec<String>,
    /// The answer.
    pub permit: bool,
    /// Which of the algebra's four results it was: the record keeps an evaluation that failed
    /// apart from a policy deny.
    pub outcome: permguard_decisions::record::Outcome,
    /// The `evaluation_*` codes behind an indeterminate outcome, sorted and distinct; empty for
    /// the other three.
    pub causes: Vec<&'static str>,
    /// Which policies decided.
    pub policies: Vec<String>,
    /// The class of the outcome.
    pub reason: String,
    /// The trace the request belonged to.
    pub trace: Option<(String, String)>,
    /// The caller's own correlation handle.
    pub request_id: Option<String>,
    /// How long it took.
    pub latency_us: u64,
    /// The occurrence this decision was made about, for a temporal one.
    pub event: Option<permguard_decisions::record::EventRef>,
    /// The exact interface the question was asked through (IFACE-05).
    pub interface: Option<String>,
    /// Who asked, as the transport authenticated them, already pseudonymised (IFACE-04).
    pub actor: Option<(String, String)>,
    /// The canonical question, for the commitment: never written in clear.
    pub question: Option<Value>,
    /// Each partition of the profile and its runtime's descriptor digest.
    pub descriptors: std::collections::BTreeMap<String, String>,
    /// The status list version the caller's access token was checked against (WP-12.5).
    pub token_status: Option<permguard_core::authz::TokenStatusRef>,
}

/// What writing one record established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Written {
    /// A record was appended and is durable.
    Recorded {
        /// Where it sits.
        seq: u64,
    },
    /// Nothing was written, deliberately: sampling. No hole, and no claim.
    SampledOut,
    /// The spool reached a bound, so the stream ended and a new one began.
    ///
    /// The decision itself was still answered: the version 1 spool's `open` behaviour, which no
    /// plane configures since WP-6.1.
    Discontinued {
        /// How many written records were discarded.
        lost: u64,
    },
    /// Nothing was written because this decision is already durable here.
    ///
    /// A retry of a decision the journal already holds, answered from the
    /// record it holds rather than by appending a second one under the same
    /// identity.
    AlreadyRecorded {
        /// Where the record that answers it sits.
        seq: u64,
    },
    /// Nothing was written and nothing could be: the plane is configured to
    /// refuse rather than decide unrecorded, and the caller must be refused.
    Refused(String),
}

/// The epoch a stream is currently in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Epoch {
    /// This plane's released version.
    pub version: String,
    /// The digest of the binary, where a deployment attests it.
    pub build: Option<String>,
    /// Engine versions, by language.
    pub engines: BTreeMap<String, String>,
    /// The rate at which permits are recorded.
    pub sampling: String,
}

/// How the journal behaves when the spool reaches a bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhenFull {
    /// Keep answering: the stream ends with a signed discontinuity.
    Open,
    /// Refuse to decide rather than decide unrecorded.
    Closed,
}

/// The build an epoch declares.
fn build_of(epoch: &Epoch) -> Build {
    Build {
        version: epoch.version.clone(),
        build: epoch.build.clone(),
        engines: if epoch.engines.is_empty() {
            None
        } else {
            Some(epoch.engines.clone())
        },
    }
}

/// The body of the marker that governs the records after it.
pub fn marker_body(
    epoch: &Epoch,
    commitment: &Commitment,
    predecessor: Option<Predecessor>,
) -> Body {
    Body::Marker(Box::new(MarkerBody {
        predecessor,
        pdp: build_of(epoch),
        sampling: Sampling {
            permits: epoch.sampling.clone(),
        },
        commitments: Commitments {
            alg: commitment::COMMITMENT_ALGORITHM.to_owned(),
            key_version: commitment.version().to_owned(),
        },
    }))
}

/// The body of one decision's record.
pub fn decision_body(epoch: &Epoch, commitment: &Commitment, decided: &Decided<'_>) -> Body {
    Body::Decision(Box::new(DecisionBody {
        id: decided.id.to_owned(),
        pdp: Build {
            version: epoch.version.clone(),
            build: None,
            engines: None,
        },
        store: StoreRef {
            zone: decided.zone.to_owned(),
            ledger: decided.ledger.to_owned(),
            commit: decided.commit.to_owned(),
            counter: decided.counter,
            profile: decided.profile.to_owned(),
        },
        subject: party(
            &decided.subject,
            normalized_map(decided.subject_properties.clone()),
        ),
        resource: party(
            &decided.resource,
            normalized_map(decided.resource_properties.clone()),
        ),
        action: ActionRef {
            name: decided.action.clone(),
        },
        principal: decided
            .principal
            .as_ref()
            .map(|principal| party(principal, None)),
        inputs: Inputs {
            context: commit_to(commitment, decided.scope.as_ref(), decided.context.as_ref()),
            partition_inputs: commit_to(
                commitment,
                decided.scope.as_ref(),
                decided.partition_inputs.as_ref(),
            ),
            absent: decided.absent_inputs.clone(),
            external: Vec::new(),
        },
        decision: decided.permit,
        outcome: Some(decided.outcome),
        causes: (!decided.causes.is_empty())
            .then(|| decided.causes.iter().map(|&code| code.to_owned()).collect()),
        policies: decided.policies.clone(),
        reason: Reason {
            code: decided.reason.clone(),
        },
        trace: decided.trace.as_ref().map(|(trace_id, span_id)| Trace {
            trace_id: trace_id.clone(),
            span_id: span_id.clone(),
        }),
        request_id: decided.request_id.clone(),
        context: normalized_map(decided.included_context.clone()),
        latency_us: decided.latency_us,
        event: decided.event.clone(),
        interface: decided.interface.clone(),
        actor: decided.actor.as_ref().map(|actor| party(actor, None)),
        // Committed as `inputs` are, under the same key and with the same caveat: without the
        // ledger's key it reads `unavailable`. `commit_to` normalises first, so canonicalising
        // cannot fail and the member is never silently dropped.
        question: commit_to(
            commitment,
            decided.scope.as_ref(),
            decided.question.as_ref(),
        ),
        descriptors: (!decided.descriptors.is_empty()).then(|| decided.descriptors.clone()),
        token_status: decided.token_status.clone(),
    }))
}

/// Commits to a caller-supplied value, whatever it carries.
///
/// Normalised first, so the commitment is **total**: a caller who put a
/// float in the context must not be able to make the record silently
/// non-committal about what the decision saw — that would hand whoever is
/// being audited a way to degrade their own audit trail.
fn commit_to(
    commitment: &Commitment,
    scope: Option<&permguard_decisions::commitment::Scope>,
    value: Option<&Value>,
) -> Option<String> {
    value.and_then(|value| {
        commitment
            .commit_in(scope, &permguard_decisions::jcs::normalized(value))
            .ok()
    })
}

/// A caller-supplied map, made canonicalisable.
///
/// The `include`d cleartext fields travel inside the record, and the
/// record is digested canonically: a float among them would otherwise fail
/// the append — a refusal that the caller chose the trigger for.
fn normalized_map(
    map: Option<serde_json::Map<String, Value>>,
) -> Option<serde_json::Map<String, Value>> {
    map.map(|map| {
        map.into_iter()
            .map(|(key, value)| {
                let value = permguard_decisions::jcs::normalized(&value);
                (key, value)
            })
            .collect()
    })
}

/// Whether the permit `id` is one of the recorded ones at `rate`.
///
/// Derived from the decision's own handle rather than from a random draw,
/// so the same decision is sampled the same way wherever the question is
/// asked again — and so a plane cannot be made to record more by retrying.
pub(crate) fn keeps_permit(rate: f64, id: &str) -> bool {
    if rate >= 1.0 {
        return true;
    }
    if rate <= 0.0 {
        return false;
    }
    let bucket = id.bytes().fold(0u64, |hash, byte| {
        hash.wrapping_mul(31).wrapping_add(u64::from(byte))
    });

    (bucket % 10_000) < (rate * 10_000.0) as u64
}

fn party(pair: &(String, String), properties: Option<serde_json::Map<String, Value>>) -> Party {
    Party {
        kind: pair.0.clone(),
        id: pair.1.clone(),
        properties: properties.filter(|properties| !properties.is_empty()),
    }
}

pub(crate) fn now() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs() as i64)
        .unwrap_or_default();

    permguard_core::time::to_rfc3339(seconds)
}
