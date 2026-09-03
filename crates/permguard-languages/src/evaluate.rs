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
//! # Fail-closed, by construction
//!
//! [`Evaluator::evaluate`] cannot return "I do not know": a request the
//! language refuses is a [`Verdict`] that denies and carries the reason. The
//! caller reports it; it never turns into a permit, and it never turns into a
//! transport error either — a deny is an answer.

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

/// What one evaluation concluded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Verdict {
    /// `true` permit, `false` deny. Nothing in between.
    pub permitted: bool,
    /// The identities of the policies that decided it — what the reason
    /// cites, so the audit trail stays whole across renames.
    pub determining: Vec<String>,
    /// Present when the request could not be evaluated. The verdict then
    /// denies: fail-closed is the contract, and this is the reason why.
    pub error: Option<String>,
}

impl Verdict {
    /// A permit, decided by these policies.
    pub fn permit(determining: Vec<String>) -> Self {
        Self {
            permitted: true,
            determining,
            error: None,
        }
    }

    /// A deny, decided by these policies.
    pub fn deny(determining: Vec<String>) -> Self {
        Self {
            permitted: false,
            determining,
            error: None,
        }
    }

    /// A deny because the request could not be evaluated at all.
    pub fn refused(reason: impl Into<String>) -> Self {
        Self {
            permitted: false,
            determining: Vec::new(),
            error: Some(reason.into()),
        }
    }
}

/// What a request concluded once every partition of a profile has answered.
///
/// The three lists are kept apart because a reason has to tell them apart: a
/// request that nothing permitted and a request a policy refused are both a
/// deny, and only the second has something to name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    /// The answer. `false` unless something permitted and nothing objected.
    pub permitted: bool,
    /// What permitted it, across every partition.
    pub permits: Vec<String>,
    /// What refused it — policies that said no, not partitions that said
    /// nothing.
    pub denials: Vec<String>,
    /// Partitions that could not evaluate the request at all.
    pub errors: Vec<String>,
}

impl Outcome {
    /// The policies a decision cites: what permitted it, or what refused it.
    pub fn determining(&self) -> &[String] {
        if self.permitted {
            &self.permits
        } else {
            &self.denials
        }
    }
}

/// Combines what every partition of a profile answered into one decision.
///
/// The resolution, in one line: **an explicit deny wins, and silence is not a
/// deny.** A partition that permits nothing has said nothing; a partition that
/// names a policy refusing the request has objected, and one objection is
/// enough. A partition that could not evaluate at all is an objection too —
/// fail-closed is the only resolution an authorization system can defend.
///
/// It lives here, beside [`Verdict`], rather than in whoever asks: the data
/// plane serving a PDP and the CLI testing a workspace before it is pushed have
/// to agree about what a set of verdicts means, and the way to guarantee that
/// is for there to be one definition of it.
pub fn resolve(verdicts: impl IntoIterator<Item = Verdict>) -> Outcome {
    let mut outcome = Outcome::default();

    for verdict in verdicts {
        if let Some(error) = verdict.error {
            outcome.errors.push(error);

            continue;
        }
        if verdict.permitted {
            outcome.permits.extend(verdict.determining);
        } else {
            // A deny with nothing determining it is "no policy said yes", which
            // is not the same as a policy saying no — only the latter overrides.
            outcome.denials.extend(verdict.determining);
        }
    }

    outcome.permitted =
        outcome.errors.is_empty() && outcome.denials.is_empty() && !outcome.permits.is_empty();

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
/// still overrides, silence is still not a deny, and a partition that could not answer at all is
/// still an objection.
pub fn evaluate_all(work: Vec<(std::sync::Arc<dyn Evaluator>, Query)>) -> Vec<Answered> {
    let count = work.len();
    let jobs: Vec<Box<dyn FnOnce() -> Answered + Send + 'static>> = work
        .into_iter()
        .map(|(evaluator, query)| {
            Box::new(move || {
                let started = std::time::Instant::now();
                // Checked here, on the thread that is about to do the work, rather than before
                // dispatching: a job may sit briefly behind others, and the answer to "is this
                // still worth doing" is only true at the moment of doing it.
                let verdict = if query.expired() {
                    Verdict::refused(
                        "the decision ran out of time before this partition was evaluated"
                            .to_owned(),
                    )
                } else {
                    // Entered with room to recurse in, whatever thread this is: an engine
                    // handed a stack it cannot measure declines rather than answers. See
                    // `crate::headroom`.
                    let verdict = crate::headroom::with(|| evaluator.evaluate(&query));
                    // A synchronous provider cannot be interrupted once it has
                    // entered upstream's engine. That does not make its late
                    // answer valid: in particular, a permit produced after the
                    // caller's decision budget is a result Permguard must never
                    // release. Check the same absolute deadline on the way out
                    // and replace every late answer with a fail-closed refusal.
                    match query.expired() {
                        true => Verdict::refused(
                            "the partition answered after the decision deadline".to_owned(),
                        ),
                        false => verdict,
                    }
                };

                Answered {
                    verdict,
                    elapsed: started.elapsed(),
                }
            }) as Box<dyn FnOnce() -> Answered + Send + 'static>
        })
        .collect();

    match crate::fanout::Fanout::shared().run(jobs) {
        Ok(answered) => answered,
        // An answer short of a partition is not this request's answer. Every partition is reported
        // as unable to evaluate, which denies — the same fail-closed rule as any other engine
        // fault, applied to the one fault that has no engine to blame.
        Err(lost) => (0..count)
            .map(|_| Answered {
                verdict: Verdict::refused(lost.to_string()),
                elapsed: std::time::Duration::ZERO,
            })
            .collect(),
    }
}

/// A compiled, immutable set of policies, ready to answer requests.
///
/// Shared across threads and across requests: everything expensive already
/// happened in [`Evaluating::compile`].
pub trait Evaluator: Send + Sync {
    /// Answers one request. Never errors: a request that cannot be evaluated
    /// is a [`Verdict::refused`], which denies.
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

    /// Roughly how much memory this compiled program holds, for the cache
    /// that decides what to keep. An estimate — the sources it was built
    /// from plus what the engine keeps beside them.
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

        assert!(outcome.permitted, "silence is not a refusal");
        assert_eq!(outcome.determining(), ["p1".to_owned()]);

        let outcome = resolve([
            Verdict::permit(vec!["p1".to_owned()]),
            Verdict::deny(vec!["f1".to_owned()]),
        ]);

        assert!(!outcome.permitted, "a policy saying no is");
        assert_eq!(outcome.determining(), ["f1".to_owned()]);
    }

    #[test]
    fn nothing_permitting_is_a_deny_with_nothing_to_cite() {
        let outcome = resolve([Verdict::deny(Vec::new()), Verdict::deny(Vec::new())]);

        assert!(!outcome.permitted);
        assert!(outcome.determining().is_empty());
    }

    #[test]
    fn a_partition_that_could_not_evaluate_never_becomes_a_permit() {
        let outcome = resolve([
            Verdict::permit(vec!["p1".to_owned()]),
            Verdict::refused("the entity graph is not legal"),
        ]);

        assert!(!outcome.permitted, "fail-closed, whatever else permitted");
        assert_eq!(outcome.errors.len(), 1);
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
        assert_eq!(answered[0].verdict.determining, ["first".to_owned()]);
        assert_eq!(answered[1].verdict.determining, ["second".to_owned()]);
        // The combination is the same one a sequential run reached: both permitted, nothing
        // objected, so the profile permits.
        assert!(resolve(answered.into_iter().map(|held| held.verdict)).permitted);
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
        assert!(!outcome.permitted, "and it fails closed");
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
        assert!(resolve(evaluate_all(work).into_iter().map(|held| held.verdict)).permitted);
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

        assert!(!outcome.permitted, "a late permit is never released");
        assert_eq!(outcome.errors.len(), 1);
        assert!(outcome.errors[0].contains("after the decision deadline"));
    }

    /// A partition that comes apart mid-evaluation is a deny, not a short answer.
    #[test]
    fn a_partition_that_panics_denies_the_whole_request() {
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

        assert!(!outcome.permitted, "fail-closed, whatever else permitted");
        assert!(
            !outcome.errors.is_empty(),
            "and it says an answer is missing"
        );
    }

    #[test]
    fn a_refused_request_denies_and_says_why() {
        let refused = Verdict::refused("the action is empty");

        assert!(!refused.permitted, "fail-closed");
        assert_eq!(refused.error.as_deref(), Some("the action is empty"));
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
