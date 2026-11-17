// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The evaluating half of a policy language, and the one path every evaluation takes.
//!
//! [`Evaluating`] compiles a partition and [`Evaluator`] answers one query; [`evaluate_all`] runs
//! every partition of a profile, together and in the profile's order, on the process's pool, with
//! the deadline, the panic boundary and the stack headroom each evaluation is held to. What a
//! query and a verdict are, and how verdicts combine, is the request model's
//! (`permguard_language_core::evaluate`).

use permguard_language_core::evaluate::{Query, Verdict};
pub use permguard_language_core::evaluating::{Evaluating, Evaluator};

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
/// and [`resolve`](permguard_language_core::evaluate::resolve) then combines them exactly as it did when they were asked one at a time. Deny
/// still overrides, silence is still not a deny, and a partition that could not answer at all
/// still makes the result indeterminate.
pub fn evaluate_all(work: Vec<(std::sync::Arc<dyn Evaluator>, Query)>) -> Vec<Answered> {
    evaluate_all_on(crate::fanout::Fanout::shared(), work)
}

/// [`evaluate_all`] on `pool`: the process's own in production, a private one in a test that must
/// not share its workers with whatever else the test binary runs at the time.
pub(crate) fn evaluate_all_on(
    pool: &crate::fanout::Fanout,
    work: Vec<(std::sync::Arc<dyn Evaluator>, Query)>,
) -> Vec<Answered> {
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

    match pool.run(jobs) {
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
    // measure declines rather than answers. See `permguard_language_core::headroom`.
    let verdict = permguard_language_core::headroom::with(|| evaluator.evaluate(query));
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

#[cfg(test)]
mod tests {
    use super::*;
    use permguard_language_core::evaluate::{Resolution, resolve};

    /// Two partitions of one profile really are evaluated at the same time.
    ///
    /// Not "both were called" — a sequential loop satisfies that. Each evaluator waits on a
    /// barrier the other must reach, so the pair answers only if they overlap in time. A
    /// sequential `evaluate_all` deadlocks here and the test times out rather than passing.
    ///
    /// On a pool of its own: the process's pool is shared with every test the binary runs at
    /// once, and a pool whose queue is full runs jobs on the caller, one after another — the
    /// documented degradation, which this barrier would turn into a hang.
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

        let answered = evaluate_all_on(&crate::fanout::Fanout::with_workers(2), work);
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
}
