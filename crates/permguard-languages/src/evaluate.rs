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
//! The role is split in two on purpose. [`Evaluating::compile`] does the
//! expensive work — parsing every policy, building the engine's own program,
//! checking it against the schema — and hands back an [`Evaluator`] that is
//! immutable, shareable and cheap to call. A data plane compiles a partition
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

/// One partition's answer, and what it cost.
#[derive(Debug)]
pub struct Answered {
    pub verdict: Verdict,
    pub elapsed: std::time::Duration,
}

/// Evaluates every partition of a profile — together, and in the profile's order.
///
/// # Why this is one function
///
/// The data plane serving a request and `permguard test` deciding one off disk must not be able to
/// disagree about *how many* partitions answered, in what order their verdicts were combined, or
/// what happens when one of them comes apart. Written twice, the second one is sequential for a
/// while and then is not, and a workspace that passed locally denies in production for a reason
/// nobody can see.
///
/// # What parallel does not change
///
/// The answers come back in the order the partitions were given, whatever order they finished in,
/// and [`resolve`] then combines them exactly as it did when they were asked one at a time. Deny
/// still overrides, silence is still not a deny, and a partition that could not answer at all
/// still makes the result indeterminate.
pub fn evaluate_all(work: Vec<(std::sync::Arc<dyn Evaluator>, Query)>) -> Vec<Answered> {
    let count = work.len();
    let jobs: Vec<Box<dyn FnOnce() -> Answered + Send + 'static>> = work
        .into_iter()
        .map(|(evaluator, query)| {
            Box::new(move || {
                let started = std::time::Instant::now();
                // The panic boundary is the job's own, so it is the same wherever the job runs: on
                // a pool worker, on the calling thread as the first job, on the calling thread
                // because the queue was full, or on a pool with no workers at all. Only the
                // partition that came apart is `E`; a `D` beside it still stands.
                let verdict = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    evaluate_one(evaluator.as_ref(), &query)
                }))
                // The panic's own words stay out: an engine's message can carry policy text or
                // tenant data, and this one travels into a decision's reason.
                .unwrap_or_else(|_| {
                    Verdict::panicked("the partition's engine came apart during evaluation")
                });

                Answered {
                    verdict,
                    elapsed: started.elapsed(),
                }
            }) as Box<dyn FnOnce() -> Answered + Send + 'static>
        })
        .collect();

    match crate::fanout::Fanout::shared().run(jobs) {
        Ok(answered) => answered,
        // Every job catches its own panic, so a hole means the pool itself lost a job it had
        // accepted. An answer short of a partition is not this request's answer: every partition
        // is reported as unable to evaluate — `E`, which resolves to indeterminate — the same
        // fail-closed rule as any other fault, applied to the one fault that has no engine to blame.
        Err(lost) => (0..count)
            .map(|_| Answered {
                verdict: Verdict::panicked(lost.to_string()),
                elapsed: std::time::Duration::ZERO,
            })
            .collect(),
    }
}

/// One partition's evaluation, inside the deadline.
fn evaluate_one(evaluator: &dyn Evaluator, query: &Query) -> Verdict {
    // Checked here, on the thread that is about to do the work, rather than before dispatching: a
    // job may sit briefly behind others, and the answer to "is this still worth doing" is only
    // true at the moment of doing it.
    if query.expired() {
        return Verdict::deadline_exceeded(
            "the decision ran out of time before this partition was evaluated",
        );
    }
    // Entered with room to recurse in, whatever thread this is: an engine handed a stack it cannot
    // measure declines rather than answers. See `crate::headroom`.
    let verdict = crate::headroom::with(|| evaluator.evaluate(query));
    // A synchronous provider cannot be interrupted once it has entered upstream's engine. That does
    // not make its late answer valid: in particular, a permit produced after the caller's decision
    // budget is a result Permguard must never release. Checked against the same absolute deadline
    // on the way out: a late answer gives way to the lateness, except a deny a rule determined,
    // which the deadline cannot turn into a permit and which stands with the lateness beside it.
    if query.expired() {
        return verdict.despite(Verdict::deadline_exceeded(
            "the partition answered after the decision deadline",
        ));
    }

    verdict
}

/// A compiled, immutable set of policies, ready to answer requests.
///
/// Shared across threads and across requests: everything expensive already
/// happened in [`Evaluating::compile`].
pub trait Evaluator: Send + Sync {
    /// Answers one request. Never errors: a request that cannot be evaluated
    /// is a [`Verdict::Error`], which the profile resolves to indeterminate.
    fn evaluate(&self, query: &Query) -> Verdict;

    /// Checks a materialised input against this partition's compiled schema.
    ///
    /// Run **before any policy is consulted**, which is the difference between a bad request and a
    /// denied one: a caller that sent an entity its schema does not declare has made a mistake
    /// nobody's policy can express an opinion about, and hearing `deny` for it would send them
    /// looking through the rules. The schema is already compiled — this is a check, not a parse.
    ///
    /// The default accepts: a partition whose type has nothing beyond its shape to check has
    /// nothing to do here, and the shape was checked when the input was normalised.
    fn check_input(&self, input: &crate::input::PartitionData) -> Result<(), String> {
        let _ = input;

        Ok(())
    }

    /// The same check, by `deadline`, telling an input refused from a check that could not run.
    ///
    /// `Ok(Ok(()))` admits the input and `Ok(Err(why))` refuses it — the caller's mistake, a
    /// `400`. `Err(why)` is a check that could not run at all — the partition failing, which a
    /// plane answers as `evaluation_indeterminate`. The default runs [`Evaluator::check_input`] in
    /// process, where it always runs; a partition evaluated in a supervised worker overrides it.
    fn check_input_by(
        &self,
        input: &crate::input::PartitionData,
        deadline: Option<std::time::Instant>,
    ) -> Result<Result<(), String>, String> {
        let _ = deadline;

        Ok(self.check_input(input))
    }

    /// How much memory this compiled program holds, for the cache that decides what to keep: a
    /// conservative estimate of what the engine keeps, never below it (LANG-07,
    /// `tests/footprint.rs`). Not the size of the sources, which undercounts by an order of
    /// magnitude.
    fn footprint(&self) -> usize;

    /// The policies it was compiled from, by identity, for a report that has
    /// to say what is loaded.
    fn policies(&self) -> Vec<String>;

    /// The remembering half of this compiled partition, when its runtime has one.
    ///
    /// Asked for, never assumed — exactly like [`Language::authoring`](crate::role::Language) and
    /// [`Language::evaluating`](crate::role::Language). A stateless runtime answers `None`, and a
    /// caller that wanted to submit an event learns so at load rather than by having one accepted
    /// as something else.
    fn temporal(&self) -> Option<&dyn crate::temporal::Temporal> {
        None
    }
}

/// The compiling half: sources in, an [`Evaluator`] out.
pub trait Evaluating: Send + Sync {
    /// Compiles a partition's policies against the artifacts it carries.
    ///
    /// A schema is not decoration: when the partition carries one, every policy is **validated
    /// against it** here, and a policy that does not type-check refuses the load. A ledger that
    /// would evaluate differently than it reads is not one to serve.
    ///
    /// `artifacts` is everything the partition holds that is not a policy, by registered type. A
    /// runtime asks for the types it owns by name; a runtime with one schema asks for one, and a
    /// runtime with an action schema, an event schema, a macro library and provider programs asks
    /// for those — without the signature, or the walk that filled it, knowing either of them.
    fn compile(
        &self,
        policies: &[StoredPolicy],
        artifacts: &crate::artifact::Artifacts,
    ) -> Result<Box<dyn Evaluator>, String>;
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

    use super::*;

    /// Two partitions of one profile really are evaluated at the same time.
    ///
    /// Not "both were called" — a sequential loop satisfies that. Each evaluator waits on a
    /// barrier the other must reach, so the pair answers only if they overlap in time. A
    /// sequential `evaluate_all` deadlocks here and the test times out rather than passing.
    #[test]
    fn two_partitions_of_a_profile_are_evaluated_at_the_same_time() {
        struct Meeting(std::sync::Arc<std::sync::Barrier>, &'static str);
        impl Evaluator for Meeting {
            fn evaluate(&self, _query: &Query) -> Verdict {
                self.0.wait();

                Verdict::permit(vec![self.1.to_owned()])
            }
            fn footprint(&self) -> usize {
                0
            }
            fn policies(&self) -> Vec<String> {
                vec![self.1.to_owned()]
            }
        }

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let work: Vec<(std::sync::Arc<dyn Evaluator>, Query)> = ["first", "second"]
            .into_iter()
            .map(|name| {
                (
                    std::sync::Arc::new(Meeting(std::sync::Arc::clone(&barrier), name))
                        as std::sync::Arc<dyn Evaluator>,
                    Query::default(),
                )
            })
            .collect();

        let answered = evaluate_all(work);
        assert_eq!(answered.len(), 2);
        // And in the order they were given, not the order they finished.
        assert_eq!(answered[0].verdict.determining(), ["first".to_owned()]);
        assert_eq!(answered[1].verdict.determining(), ["second".to_owned()]);
        // The combination is the same one a sequential run reached: both permitted, nothing
        // objected, so the profile permits.
        assert!(resolve(answered.into_iter().map(|held| held.verdict)).permitted());
    }

    /// A decision past its deadline refuses its partitions instead of evaluating them.
    ///
    /// The point is not that it denies — everything fail-closed denies. It is that the evaluator
    /// is **never called**: work whose answer nobody is waiting for does not get a thread.
    #[test]
    fn a_decision_out_of_time_does_not_start_its_partitions() {
        struct MustNotRun(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Evaluator for MustNotRun {
            fn evaluate(&self, _query: &Query) -> Verdict {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);

                Verdict::permit(vec!["p1".to_owned()])
            }
            fn footprint(&self) -> usize {
                0
            }
            fn policies(&self) -> Vec<String> {
                Vec::new()
            }
        }

        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let expired = Query {
            deadline: Some(std::time::Instant::now() - std::time::Duration::from_millis(1)),
            ..Query::default()
        };
        let work: Vec<(std::sync::Arc<dyn Evaluator>, Query)> = vec![(
            std::sync::Arc::new(MustNotRun(std::sync::Arc::clone(&ran))),
            expired,
        )];

        let outcome = resolve(evaluate_all(work).into_iter().map(|held| held.verdict));

        assert!(
            !ran.load(std::sync::atomic::Ordering::SeqCst),
            "the evaluator was called for a decision nobody is waiting for"
        );
        assert!(!outcome.permitted(), "and it fails closed");
        assert_eq!(outcome.errors.len(), 1, "saying why");

        // And with time left, the very same partition is evaluated.
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let in_time = Query {
            deadline: Some(std::time::Instant::now() + std::time::Duration::from_secs(30)),
            ..Query::default()
        };
        let work: Vec<(std::sync::Arc<dyn Evaluator>, Query)> = vec![(
            std::sync::Arc::new(MustNotRun(std::sync::Arc::clone(&ran))),
            in_time,
        )];
        assert!(resolve(evaluate_all(work).into_iter().map(|held| held.verdict)).permitted());
        assert!(ran.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// A synchronous provider may return after its caller's budget; its permit
    /// is then too late to be an authorization answer.
    #[test]
    fn a_partition_that_finishes_after_the_deadline_fails_closed() {
        struct SlowPermit;
        impl Evaluator for SlowPermit {
            fn evaluate(&self, _query: &Query) -> Verdict {
                std::thread::sleep(std::time::Duration::from_millis(20));
                Verdict::permit(vec!["late-permit".to_owned()])
            }
            fn footprint(&self) -> usize {
                0
            }
            fn policies(&self) -> Vec<String> {
                vec!["late-permit".to_owned()]
            }
        }

        let query = Query {
            deadline: Some(std::time::Instant::now() + std::time::Duration::from_millis(5)),
            ..Query::default()
        };
        let outcome = resolve(
            evaluate_all(vec![(std::sync::Arc::new(SlowPermit), query)])
                .into_iter()
                .map(|held| held.verdict),
        );

        assert!(!outcome.permitted(), "a late permit is never released");
        assert_eq!(outcome.errors.len(), 1);
        assert!(
            outcome.errors[0]
                .message
                .contains("after the decision deadline")
        );
    }

    /// A partition that comes apart mid-evaluation is `E`, not a short answer: the request is
    /// indeterminate, whatever else permitted.
    #[test]
    fn a_partition_that_panics_makes_the_whole_request_indeterminate() {
        struct Fine;
        struct Broken;
        impl Evaluator for Fine {
            fn evaluate(&self, _query: &Query) -> Verdict {
                Verdict::permit(vec!["p1".to_owned()])
            }
            fn footprint(&self) -> usize {
                0
            }
            fn policies(&self) -> Vec<String> {
                Vec::new()
            }
        }
        impl Evaluator for Broken {
            fn evaluate(&self, _query: &Query) -> Verdict {
                panic!("an engine came apart")
            }
            fn footprint(&self) -> usize {
                0
            }
            fn policies(&self) -> Vec<String> {
                Vec::new()
            }
        }

        let work: Vec<(std::sync::Arc<dyn Evaluator>, Query)> = vec![
            (std::sync::Arc::new(Fine), Query::default()),
            (std::sync::Arc::new(Broken), Query::default()),
        ];
        let outcome = resolve(evaluate_all(work).into_iter().map(|held| held.verdict));

        assert!(!outcome.permitted(), "fail-closed, whatever else permitted");
        assert_eq!(outcome.resolution, Resolution::Indeterminate);
        assert_eq!(
            outcome.errors.first().map(|error| error.code),
            Some(permguard_core::codes::pdp_native::EVALUATION_PANICKED),
            "and it says an answer is missing, and why"
        );
    }

    /// An evaluator that answers what it was built with, after an optional pause, or panics.
    struct Scripted {
        answer: Option<Verdict>,
        pause: std::time::Duration,
        ran_on: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl Evaluator for Scripted {
        fn evaluate(&self, _query: &Query) -> Verdict {
            std::thread::sleep(self.pause);
            if let Ok(mut ran_on) = self.ran_on.lock() {
                ran_on.push(std::thread::current().name().unwrap_or_default().to_owned());
            }
            match &self.answer {
                Some(verdict) => verdict.clone(),
                None => panic!("an engine came apart"),
            }
        }
        fn footprint(&self) -> usize {
            0
        }
        fn policies(&self) -> Vec<String> {
            Vec::new()
        }
    }

    fn scripted(
        answer: Option<Verdict>,
        pause_ms: u64,
        ran_on: &std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) -> (std::sync::Arc<dyn Evaluator>, Query) {
        (
            std::sync::Arc::new(Scripted {
                answer,
                pause: std::time::Duration::from_millis(pause_ms),
                ran_on: std::sync::Arc::clone(ran_on),
            }),
            Query::default(),
        )
    }

    /// LANG-05: the first partition runs on the calling thread, outside any pool worker, and its
    /// panic is still `E` `evaluation_panicked` rather than a panic of the caller.
    #[test]
    fn a_panic_in_the_one_partition_the_caller_runs_is_an_evaluation_failure() {
        let ran_on = std::sync::Arc::default();
        let answered = evaluate_all(vec![scripted(None, 0, &ran_on)]);

        assert_eq!(answered.len(), 1);
        assert_eq!(
            answered[0].verdict.error().map(|error| error.code),
            Some(permguard_core::codes::pdp_native::EVALUATION_PANICKED)
        );
    }

    /// Only the partition that came apart is `E`: a deny a policy decided beside it stands.
    #[test]
    fn a_panic_beside_a_deny_does_not_take_the_deny_with_it() {
        let ran_on = std::sync::Arc::default();
        let answered = evaluate_all(vec![
            scripted(Some(Verdict::deny(vec!["d1".to_owned()])), 0, &ran_on),
            scripted(None, 0, &ran_on),
        ]);

        assert_eq!(answered[0].verdict.determining(), ["d1".to_owned()]);
        assert_eq!(
            answered[1].verdict.error().map(|error| error.code),
            Some(permguard_core::codes::pdp_native::EVALUATION_PANICKED)
        );
        let outcome = resolve(answered.into_iter().map(|held| held.verdict));
        assert_eq!(outcome.resolution, Resolution::Deny);
    }

    /// With the queue full, the caller runs the overflow itself — and every one of those jobs has
    /// the same boundary as a worker's: each panic is that partition's `E`, none is lost.
    #[test]
    fn panics_on_workers_and_on_the_overflowing_caller_are_each_their_partitions_failure() {
        let ran_on = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let count = 64;
        let work = (0..count).map(|_| scripted(None, 10, &ran_on)).collect();

        let answered = evaluate_all(work);

        assert_eq!(answered.len(), count, "no partition is lost");
        assert!(answered.iter().all(|held| {
            held.verdict.error().map(|error| error.code)
                == Some(permguard_core::codes::pdp_native::EVALUATION_PANICKED)
        }));
        let ran_on = ran_on.lock().expect("not poisoned");
        let on_the_caller = ran_on
            .iter()
            .filter(|name| name.as_str() != "permguard-evaluate")
            .count();
        assert!(
            on_the_caller > 1,
            "the caller ran its own job and the overflow: {on_the_caller} of {count}"
        );
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
