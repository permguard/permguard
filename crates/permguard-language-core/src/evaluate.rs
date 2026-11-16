// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The third role a language plays: **evaluating** a decision.
//!
//! [`Language`](crate::role::Language) says what a policy *is*;
//! [`Authoring`](crate::role::Authoring) turns files into policies; this one
//! answers the only question a PDP is asked — *may this subject do this to
//! this?*
//!
//! # Compile once, evaluate many
//!
//! The role is split in two on purpose. `Evaluating::compile` does the
//! expensive work — parsing every policy, building the engine's own program,
//! checking it against the schema — and hands back an `Evaluator` that is
//! immutable, shareable and cheap to call. Both are the decision point's
//! (`permguard_pdp_core::evaluate`); what they read and answer is here. A data plane compiles a partition
//! when it loads it and then answers requests out of memory; nothing on the
//! decision path re-parses a policy.
//!
//! # The typed algebra
//!
//! A partition answers one of four things, and a boolean cannot hold them: a
//! policy permitted (`P`), a policy denied (`D`), nothing matched (`A`), or
//! the partition could not evaluate at all (`E`). [`Verdict`] is that result,
//! and [`resolve`] combines a profile's verdicts exactly as the languages
//! model states — an explicit deny wins; otherwise any failure makes the
//! result *indeterminate*; otherwise a permit permits; otherwise the request
//! is denied by default. An evaluation failure is therefore never a policy
//! deny and never a permit: it fails closed at enforcement and stays
//! distinguishable everywhere it is reported, which is what lets an operator
//! tell a policy saying no from an engine that could not say anything.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

/// One entity the request names: the subject, or the resource.
///
/// `kind` is the entity *type* in the language's own namespace — `User`,
/// `acme::Document` — and `id` its identifier inside that type. `properties`
/// are the attributes a policy may read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entity {
    pub kind: String,
    pub id: String,
    pub properties: Map<String, Value>,
}

/// The operation being attempted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Action {
    /// The action name — bare (`read`) or qualified (`acme::Action::"read"`
    /// written as `acme::Action::read`); a language resolves the shape it
    /// speaks.
    pub name: String,
    pub properties: Map<String, Value>,
}

/// One decision request, language-agnostic: the profile's own shape.
#[derive(Debug, Clone, Default)]
pub struct Query {
    pub subject: Entity,
    pub resource: Entity,
    pub action: Action,
    /// Environmental attributes — time, address, whatever a policy reads.
    pub context: Map<String, Value>,
    /// When this request stops being worth answering.
    ///
    /// # Why a decision carries its own deadline
    ///
    /// The transport has a request timeout, and it ends the *response* — it does not end the work.
    /// A policy evaluation runs on a blocking thread; when the HTTP layer gives up, the future
    /// holding that thread is dropped and the thread keeps going. The data plane keeps the
    /// concurrency permit until that work actually returns, but without a deadline the abandoned
    /// work could still occupy the whole bounded pool and starve requests whose answers are wanted.
    ///
    /// So the work is told when to stop, rather than being told to stop. Every engine checks this
    /// before it starts and — where its interpreter allows it, which is Rego's — while it runs.
    /// `None` is no deadline: a workspace decided offline by `permguard test` is answering to a
    /// person, not to a socket.
    pub deadline: Option<std::time::Instant>,
    /// This partition's own input, normalised into what its runtime reads.
    ///
    /// Addressed to the partition by name and to no other: two partitions of one profile — two
    /// Cedar partitions with different schemas included — hold different worlds, and a store
    /// legal in one is refused by the other. A partition nobody addressed reads its type's empty
    /// input, never a neighbour's.
    pub input: crate::input::PartitionData,
}

impl Query {
    /// How long is left, or `None` for a query with no deadline.
    pub fn remaining(&self) -> Option<std::time::Duration> {
        self.deadline
            .map(|deadline| deadline.saturating_duration_since(std::time::Instant::now()))
    }

    /// Whether there is no point starting.
    pub fn expired(&self) -> bool {
        self.remaining().is_some_and(|left| left.is_zero())
    }
}

/// One policy as the store holds it: its derived identity, the optional
/// authored alias, and the verbatim source bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPolicy {
    /// The policy identity — what a decision cites, and what survives a
    /// rename.
    pub id: String,
    /// The authored handle, when the source declared one.
    pub alias: Option<String>,
    /// The verbatim authored bytes.
    pub source: Vec<u8>,
}

/// One partition's answer: the typed algebra of the languages model.
///
/// `P` and `D` name the policies that decided them; `A` and `E` name none. `E` carries a stable
/// error code — one of the four `evaluation_*` codes of the native PDP contract — and a message
/// for the operator, and never a policy identity: a partition that did not evaluate has nothing
/// to cite.
///
/// Build one with the constructors rather than the variants: they are where the algebra's rules
/// about empty lists live, and [`resolve`] reads a variant built around them the same way.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Verdict {
    /// `P`: a policy permitted it.
    Permit { determining: Vec<String> },
    /// `D`: a policy denied it. `beside` is a failure of another of the partition's policies:
    /// the deny still stands, because nothing the failed policy could return turns it into a
    /// permit, and the failure is still reported.
    Deny {
        determining: Vec<String>,
        beside: Option<EvaluationError>,
    },
    /// `A`: no rule matched; the partition has no opinion. The default: a partition that has
    /// said nothing.
    #[default]
    Abstain,
    /// `E`: the partition could not evaluate the request.
    Error { code: &'static str, message: String },
}

impl Verdict {
    /// A permit, decided by these policies.
    pub fn permit(determining: Vec<String>) -> Self {
        Self::Permit { determining }
    }

    /// A deny, decided by these policies.
    ///
    /// A deny nothing decided is not a deny: a policy saying no and no policy saying yes are the
    /// two things the algebra exists to tell apart, so an empty list is an [`Verdict::Abstain`].
    pub fn deny(determining: Vec<String>) -> Self {
        if determining.is_empty() {
            return Self::Abstain;
        }

        Self::Deny {
            determining,
            beside: None,
        }
    }

    /// The answer of a partition whose engine reported errors beside the policies that denied.
    ///
    /// A deny rule that determined the answer dominates the failure inside the partition exactly
    /// as an explicit deny dominates a failed partition: `D`, with the failure kept beside it. A
    /// deny no rule determined is only the engine failing closed, so it is the failure: `E`.
    pub fn deny_despite_failure(determining: Vec<String>, message: impl Into<String>) -> Self {
        Self::deny(determining).despite(Self::engine_failed(message))
    }

    /// This answer, once `failure` — an `E` — happened in the same partition.
    ///
    /// A deny a rule determined stands, with the failure kept beside it: nothing the failure
    /// could have produced turns it into a permit. Every other answer gives way to the failure —
    /// a permit beside one is not defensible, and silence beside one is not an answer.
    pub fn despite(self, failure: Self) -> Self {
        match (self, failure.error()) {
            (
                Self::Deny {
                    determining,
                    beside,
                },
                Some(failed),
            ) => Self::Deny {
                determining,
                beside: beside.or(Some(failed)),
            },
            _ => failure,
        }
    }

    /// No rule matched.
    pub fn abstain() -> Self {
        Self::Abstain
    }

    /// `E` with the code of its cause: one of the four below, and no other.
    fn failed(code: &'static str, message: impl Into<String>) -> Self {
        Self::Error {
            code,
            message: message.into(),
        }
    }

    /// `E`: the decision's deadline passed before or while this partition ran.
    pub fn deadline_exceeded(message: impl Into<String>) -> Self {
        Self::failed(
            permguard_core::codes::pdp_native::EVALUATION_DEADLINE_EXCEEDED,
            message,
        )
    }

    /// `E`: the engine panicked, or the pool lost its job.
    pub fn panicked(message: impl Into<String>) -> Self {
        Self::failed(
            permguard_core::codes::pdp_native::EVALUATION_PANICKED,
            message,
        )
    }

    /// `E`: the engine reported errors.
    pub fn engine_failed(message: impl Into<String>) -> Self {
        Self::failed(
            permguard_core::codes::pdp_native::EVALUATION_FAILED,
            message,
        )
    }

    /// `E`: the engine could not represent the request.
    pub fn input_rejected(message: impl Into<String>) -> Self {
        Self::failed(
            permguard_core::codes::pdp_native::EVALUATION_INPUT_REJECTED,
            message,
        )
    }

    /// Whether this is a `P`.
    pub fn permitted(&self) -> bool {
        matches!(self, Self::Permit { .. })
    }

    /// The policies that decided a `P` or a `D`; none for `A` and `E`.
    pub fn determining(&self) -> &[String] {
        match self {
            Self::Permit { determining } | Self::Deny { determining, .. } => determining,
            Self::Abstain | Self::Error { .. } => &[],
        }
    }

    /// What failed in this partition: the cause of an `E`, or the failure beside a `D`.
    pub fn failure(&self) -> Option<EvaluationError> {
        match self {
            Self::Deny {
                beside: Some(failure),
                ..
            } => Some(failure.clone()),
            other => other.error(),
        }
    }

    /// The failure, when this is an `E`.
    pub fn error(&self) -> Option<EvaluationError> {
        match self {
            Self::Error { code, message } => Some(EvaluationError {
                code,
                message: message.clone(),
            }),
            _ => None,
        }
    }
}

/// One partition's failure: the stable code of its cause, and the sentence for an operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationError {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for EvaluationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

/// What a profile's verdicts resolve to: the four results of the algebra.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// A policy denied it.
    Deny,
    /// A partition could not evaluate it, and no policy denied it.
    Indeterminate,
    /// A policy permitted it and nothing objected or failed.
    Permit,
    /// Nothing permitted it, and nothing objected or failed.
    DenyByDefault,
}

impl Resolution {
    /// The spelling the record and the metrics use.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Indeterminate => "indeterminate",
            Self::Permit => "permit",
            Self::DenyByDefault => "deny_by_default",
        }
    }
}

/// What a request concluded once every partition of a profile has answered.
///
/// The three lists are kept apart because a reason has to tell them apart: a
/// request that nothing permitted and a request a policy refused are both a
/// deny, and only the second has something to name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Which of the four results the profile reached.
    pub resolution: Resolution,
    /// What permitted it, across every partition.
    pub permits: Vec<String>,
    /// What refused it — policies that said no, not partitions that said
    /// nothing.
    pub denials: Vec<String>,
    /// Every failure behind it, with the code of each cause: the partitions that could not
    /// evaluate the request, and the failures beside a deny that stood anyway. Only the first
    /// make a result indeterminate.
    pub errors: Vec<EvaluationError>,
}

impl Default for Outcome {
    fn default() -> Self {
        Self {
            resolution: Resolution::DenyByDefault,
            permits: Vec::new(),
            denials: Vec::new(),
            errors: Vec::new(),
        }
    }
}

impl Outcome {
    /// Whether the profile permitted: the one result enforcement may allow.
    pub fn permitted(&self) -> bool {
        self.resolution == Resolution::Permit
    }

    /// Whether the profile could not decide: fail-closed, and not a policy deny.
    pub fn indeterminate(&self) -> bool {
        self.resolution == Resolution::Indeterminate
    }

    /// What made it indeterminate: the codes of its failures, sorted and distinct. None for the
    /// other three results — a failure beside a deny that stood did not decide anything.
    pub fn causes(&self) -> Vec<&'static str> {
        if !self.indeterminate() {
            return Vec::new();
        }
        let mut codes: Vec<&'static str> = self.errors.iter().map(|error| error.code).collect();
        codes.sort_unstable();
        codes.dedup();
        codes
    }

    /// The policies a decision cites: what permitted it, or what refused it. An indeterminate or
    /// default result cites nothing — no policy made it.
    pub fn determining(&self) -> &[String] {
        match self.resolution {
            Resolution::Permit => &self.permits,
            Resolution::Deny => &self.denials,
            Resolution::Indeterminate | Resolution::DenyByDefault => &[],
        }
    }
}

/// Combines what every partition of a profile answered into one decision.
///
/// The resolution, exactly as the languages model states it: **any `D` is a
/// deny; else any `E` is indeterminate; else any `P` is a permit; else the
/// request is denied by default.** An explicit deny dominates a failure because
/// nothing the failed partition could have answered would turn deny-overrides
/// into a permit; a permit beside a failure is indeterminate, because releasing
/// a permit after a policy failed to evaluate is not defensible; and silence is
/// not a deny, only the absence of a permit.
///
/// It lives here, beside [`Verdict`], rather than in whoever asks: the data
/// plane serving a PDP and the CLI testing a workspace before it is pushed have
/// to agree about what a set of verdicts means, and the way to guarantee that
/// is for there to be one definition of it.
pub fn resolve(verdicts: impl IntoIterator<Item = Verdict>) -> Outcome {
    let mut outcome = Outcome::default();

    for verdict in verdicts {
        match verdict {
            // A permit or a deny that cites nothing was built around the constructors. Read the
            // way they would have built it: a deny nothing decided is silence, and a permit
            // nothing decided is an attribution the engine lost — not something to release.
            Verdict::Permit { determining } if determining.is_empty() => {
                outcome.errors.push(EvaluationError {
                    code: permguard_core::codes::pdp_native::EVALUATION_FAILED,
                    message: "the partition permitted and named no policy that did".to_owned(),
                });
            }
            Verdict::Permit { determining } => outcome.permits.extend(determining),
            Verdict::Deny {
                determining,
                beside,
            } if determining.is_empty() => outcome.errors.extend(beside),
            Verdict::Deny {
                determining,
                beside,
            } => {
                outcome.denials.extend(determining);
                outcome.errors.extend(beside);
            }
            Verdict::Abstain => {}
            Verdict::Error { code, message } => {
                outcome.errors.push(EvaluationError { code, message });
            }
        }
    }

    outcome.resolution = if !outcome.denials.is_empty() {
        Resolution::Deny
    } else if !outcome.errors.is_empty() {
        Resolution::Indeterminate
    } else if !outcome.permits.is_empty() {
        Resolution::Permit
    } else {
        Resolution::DenyByDefault
    };

    outcome
}

/// The properties of the three named entities, as a language may want them
/// folded into its own entity graph.
///
/// Provided here rather than in each language because the mapping is the
/// profile's, not the language's: the request names three entities with
/// attributes, and whichever engine answers must see those attributes.
pub fn named_entities(query: &Query) -> BTreeMap<(String, String), Map<String, Value>> {
    let mut named = BTreeMap::new();
    named.insert(
        (query.subject.kind.clone(), query.subject.id.clone()),
        query.subject.properties.clone(),
    );
    named.insert(
        (query.resource.kind.clone(), query.resource.id.clone()),
        query.resource.properties.clone(),
    );

    named
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule the whole system rests on, stated once and asserted here.
    #[test]
    fn an_explicit_deny_overrides_a_permit_and_silence_does_not() {
        let outcome = resolve([
            Verdict::permit(vec!["p1".to_owned()]),
            // Nothing determined this deny: it is "no policy said yes".
            Verdict::deny(Vec::new()),
        ]);

        assert!(outcome.permitted(), "silence is not a refusal");
        assert_eq!(outcome.determining(), ["p1".to_owned()]);

        let outcome = resolve([
            Verdict::permit(vec!["p1".to_owned()]),
            Verdict::deny(vec!["f1".to_owned()]),
        ]);

        assert!(!outcome.permitted(), "a policy saying no is");
        assert_eq!(outcome.determining(), ["f1".to_owned()]);
    }

    #[test]
    fn nothing_permitting_is_a_deny_with_nothing_to_cite() {
        let outcome = resolve([Verdict::deny(Vec::new()), Verdict::deny(Vec::new())]);

        assert!(!outcome.permitted());
        assert!(outcome.determining().is_empty());
    }

    #[test]
    fn a_partition_that_could_not_evaluate_never_becomes_a_permit() {
        let outcome = resolve([
            Verdict::permit(vec!["p1".to_owned()]),
            Verdict::engine_failed("the entity graph is not legal"),
        ]);

        assert!(!outcome.permitted(), "fail-closed, whatever else permitted");
        assert_eq!(
            outcome.resolution,
            Resolution::Indeterminate,
            "and not a deny"
        );
        assert!(outcome.determining().is_empty(), "no policy made it");
        assert_eq!(outcome.errors.len(), 1);

        // An explicit deny dominates: nothing the failed partition could have said would have
        // turned deny-overrides into a permit.
        let denied = resolve([
            Verdict::deny(vec!["d1".to_owned()]),
            Verdict::engine_failed("the entity graph is not legal"),
        ]);
        assert_eq!(denied.resolution, Resolution::Deny);
        assert_eq!(denied.determining(), ["d1".to_owned()]);
    }

    /// `E` carries the code of its cause and the sentence, never a policy: a partition that did
    /// not evaluate has nothing to cite. Every code is one of the native contract's.
    #[test]
    fn an_error_carries_a_registered_code_and_no_policy() {
        let registered: Vec<&str> = permguard_core::codes::all()
            .into_iter()
            .map(|(_, value)| value)
            .collect();
        for (verdict, code) in [
            (
                Verdict::deadline_exceeded("too late"),
                permguard_core::codes::pdp_native::EVALUATION_DEADLINE_EXCEEDED,
            ),
            (
                Verdict::panicked("an engine came apart"),
                permguard_core::codes::pdp_native::EVALUATION_PANICKED,
            ),
            (
                Verdict::engine_failed("cedar: an attribute does not exist"),
                permguard_core::codes::pdp_native::EVALUATION_FAILED,
            ),
            (
                Verdict::input_rejected("the entity graph is not legal"),
                permguard_core::codes::pdp_native::EVALUATION_INPUT_REJECTED,
            ),
        ] {
            assert!(!verdict.permitted(), "fail-closed");
            assert!(verdict.determining().is_empty(), "nothing to cite");
            let error = verdict.error().expect("an `E` says why");
            assert_eq!(error.code, code);
            assert!(registered.contains(&code), "`{code}` is registered");
            assert_eq!(
                resolve([verdict]).resolution,
                Resolution::Indeterminate,
                "alone, it is indeterminate"
            );
        }
    }

    /// A deny nothing decided is an abstain: the two things the algebra exists to tell apart
    /// cannot be conflated by a caller handing an empty list to the wrong constructor.
    #[test]
    fn a_deny_with_no_policy_is_an_abstain() {
        assert_eq!(Verdict::deny(Vec::new()), Verdict::Abstain);
        assert_eq!(
            resolve([Verdict::deny(Vec::new())]).resolution,
            Resolution::DenyByDefault
        );
    }

    /// A deny rule that determined a partition's answer dominates a failure inside it, exactly
    /// as an explicit deny dominates a failed partition; the failure is kept, not dropped. A deny
    /// no rule determined is the engine failing closed: that is the failure itself.
    #[test]
    fn a_deny_beside_a_failure_stands_and_keeps_the_failure() {
        let verdict =
            Verdict::deny_despite_failure(vec!["f1".to_owned()], "an attribute is missing");
        assert_eq!(verdict.determining(), ["f1".to_owned()]);
        assert!(verdict.error().is_none(), "a `D`, not an `E`");
        let failure = verdict.failure().expect("the failure is kept beside it");
        assert_eq!(
            failure.code,
            permguard_core::codes::pdp_native::EVALUATION_FAILED
        );

        let outcome = resolve([Verdict::permit(vec!["p1".to_owned()]), verdict]);
        assert_eq!(outcome.resolution, Resolution::Deny);
        assert_eq!(outcome.determining(), ["f1".to_owned()]);
        assert_eq!(outcome.errors.len(), 1, "counted, never dropped");

        let failed_closed = Verdict::deny_despite_failure(Vec::new(), "a provider could not run");
        assert_eq!(
            failed_closed.error().map(|error| error.code),
            Some(permguard_core::codes::pdp_native::EVALUATION_FAILED)
        );
        assert_eq!(
            resolve([Verdict::permit(vec!["p1".to_owned()]), failed_closed]).resolution,
            Resolution::Indeterminate,
            "a deny nothing decided does not outrank a permit's failure"
        );
    }

    /// A late or failed partition gives way to its failure unless a deny rule determined its
    /// answer: that deny stands, the failure beside it — the deadline included.
    #[test]
    fn only_a_determined_deny_survives_a_failure_beside_it() {
        let late = || Verdict::deadline_exceeded("too late");
        let kept = Verdict::deny(vec!["f1".to_owned()]).despite(late());
        assert_eq!(kept.determining(), ["f1".to_owned()]);
        assert_eq!(
            kept.failure().map(|failure| failure.code),
            Some(permguard_core::codes::pdp_native::EVALUATION_DEADLINE_EXCEEDED)
        );
        for gives_way in [
            Verdict::permit(vec!["p1".to_owned()]),
            Verdict::abstain(),
            Verdict::engine_failed("an earlier failure"),
        ] {
            assert_eq!(gives_way.despite(late()), late());
        }
    }

    /// The causes of an indeterminate result are its failures' codes, sorted and distinct; a
    /// result a deny decided has none, whatever failed beside it.
    #[test]
    fn the_causes_are_sorted_distinct_and_only_for_an_indeterminate_result() {
        let outcome = resolve([
            Verdict::engine_failed("one"),
            Verdict::deadline_exceeded("two"),
            Verdict::engine_failed("three"),
        ]);
        assert_eq!(
            outcome.causes(),
            [
                permguard_core::codes::pdp_native::EVALUATION_DEADLINE_EXCEEDED,
                permguard_core::codes::pdp_native::EVALUATION_FAILED,
            ]
        );

        let denied = resolve([
            Verdict::deny_despite_failure(vec!["f1".to_owned()], "beside"),
            Verdict::engine_failed("elsewhere"),
        ]);
        assert_eq!(denied.resolution, Resolution::Deny);
        assert_eq!(denied.errors.len(), 2, "both failures are kept");
        assert!(
            denied.causes().is_empty(),
            "and neither is a cause of a deny"
        );
    }

    /// A variant built around the constructors reads as the constructors would have built it: a
    /// deny citing nothing is silence, a permit citing nothing is a lost attribution and never
    /// released.
    #[test]
    fn variants_built_around_the_constructors_resolve_safely() {
        let silent = Verdict::Deny {
            determining: Vec::new(),
            beside: None,
        };
        assert_eq!(resolve([silent]).resolution, Resolution::DenyByDefault);

        let unattributed = Verdict::Permit {
            determining: Vec::new(),
        };
        let outcome = resolve([unattributed]);
        assert_eq!(outcome.resolution, Resolution::Indeterminate);
        assert_eq!(
            outcome.errors.first().map(|error| error.code),
            Some(permguard_core::codes::pdp_native::EVALUATION_FAILED)
        );
    }

    #[test]
    fn the_named_entities_carry_their_properties() {
        let mut query = Query::default();
        query.subject.kind = "User".to_owned();
        query.subject.id = "alice".to_owned();
        query
            .subject
            .properties
            .insert("department".to_owned(), Value::from("sales"));
        query.resource.kind = "Document".to_owned();
        query.resource.id = "budget".to_owned();

        let named = named_entities(&query);
        assert_eq!(named.len(), 2);
        assert_eq!(
            named[&("User".to_owned(), "alice".to_owned())]["department"],
            Value::from("sales")
        );
    }
}
