// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The conformance suite of [`ReplayStore`]: what every backend of the contract does the same
//! way (`1-architecture/8` Store contracts).
//!
//! [`run`] takes how a backend makes one empty store and runs every case on a store of its own.
//! A case panics with what it expected, as a test does. A backend proves what only it can, that
//! its plans survive its own restart, what it drops past the window and the results it holds
//! from before WP-3.6, in its own tests.
//!
//! | Case                              | Rule of the contract                                     |
//! | --------------------------------- | -------------------------------------------------------- |
//! | `an_empty_store`                  | nothing held, no operation found                         |
//! | `a_plan_is_kept_and_read`         | a plan is read whole by its principal, and by its id     |
//! | `a_plan_is_consumed_once`         | a second consumption is refused; an unknown plan too     |
//! | `an_approval_joins_its_plan`      | what `decide` answers is recorded; a refusal is not      |
//! | `an_operation_is_found`           | an approval and a consumption are found by recovery      |
//! | `a_decision_reads_its_plan`       | of the approvals that arrive together, one is decided    |
//! | `consumptions_together_spend_one` | of the consumptions that arrive together, one succeeds   |

#![allow(clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

use permguard_core::{ErrorClass, codes};

use super::{Plan, PlanApproval, ReplayError, ReplayStore, Unapproved};
use crate::api::Refusal;
use crate::operations::journal::OperationId;
use crate::operations::mutation::Applying;

const NOW: u64 = 1_800_000_000;

/// How a suite runs something inside one operation of the mutation engine: the token it is
/// given is one the engine built, a new operation at every call, from any thread.
pub type Operate<'a> = &'a (dyn Fn(&mut dyn FnMut(&Applying<'_>)) + Sync);

fn plan(principal: &str, plan_id: &str) -> Plan {
    Plan {
        plan_id: plan_id.to_owned(),
        operation: "host.keys.revoke".to_owned(),
        target: "host.operations/kid-1".to_owned(),
        revision: 7,
        digest: "sha256:00".to_owned(),
        expires: NOW + 600,
        principal: principal.to_owned(),
        kind: "keys.revoke".to_owned(),
        receipt: "cmVjZWlwdA".to_owned(),
        approvals_required: 1,
        approvals: Vec::new(),
        created_at: NOW,
    }
}

fn approval(principal: &str, applying: &Applying<'_>) -> PlanApproval {
    PlanApproval {
        principal: principal.to_owned(),
        approved_at: NOW + 1,
        envelope: "ZW52ZWxvcGU".to_owned(),
        operation_id: applying.operation_id().to_string(),
        token: None,
    }
}

fn full() -> Refusal {
    Refusal::new(
        ErrorClass::Conflict,
        codes::host::PLAN_APPROVAL_REFUSED,
        "the plan holds every approval it requires",
    )
}

/// Keeps `plan` in an operation of its own.
fn kept<S: ReplayStore + ?Sized>(store: &S, operate: Operate<'_>, plan: &Plan) {
    operate(&mut |applying| store.write_plan(applying, plan).expect("planned"));
}

/// Consumes the plan in an operation of its own and answers what the store said.
fn consumed<S: ReplayStore + ?Sized>(
    store: &S,
    operate: Operate<'_>,
    principal: &str,
    plan_id: &str,
) -> Result<(), ReplayError> {
    let mut said = None;
    operate(&mut |applying| said = Some(store.consume(applying, principal, plan_id)));
    said.expect("the operation ran")
}

/// Runs every case, each on a store `make` has just made empty; `operate` runs what it is given
/// inside one operation of the plans' domain.
pub fn run<S: ReplayStore + ?Sized>(make: &dyn Fn() -> Arc<S>, operate: Operate<'_>) {
    an_empty_store(&*make());
    a_plan_is_kept_and_read(&*make(), operate);
    a_plan_is_consumed_once(&*make(), operate);
    an_approval_joins_its_plan(&*make(), operate);
    an_operation_is_found(&*make(), operate);
    a_decision_reads_its_plan(&*make(), operate);
    consumptions_together_spend_one(&*make(), operate);
}

fn an_empty_store<S: ReplayStore + ?Sized>(store: &S) {
    assert_eq!(store.held().expect("the results read"), 0);
    assert!(
        store
            .result("alice", "r1", NOW)
            .expect("the result reads")
            .is_none()
    );
    assert!(store.plans().expect("the plans read").is_empty());
    assert!(store.plan("alice", "p1").expect("the plan reads").is_none());
    assert!(store.find("p1").expect("the plan reads").is_none());
    let operation = OperationId::from_bytes([7; 16]);
    assert!(
        store
            .operation(&operation, Some("p1"))
            .expect("the operation reads")
            .is_none()
    );
    assert!(
        store
            .operation(&operation, Some("consume:p1"))
            .expect("the operation reads")
            .is_none()
    );
    assert!(
        store
            .operation(&operation, None)
            .expect("the operation reads")
            .is_none()
    );
}

fn a_plan_is_kept_and_read<S: ReplayStore + ?Sized>(store: &S, operate: Operate<'_>) {
    let first = plan("alice", "p1");
    let second = plan("bob", "p2");
    kept(store, operate, &first);
    kept(store, operate, &second);
    assert_eq!(
        store.plan("alice", "p1").expect("the plan reads"),
        Some((first.clone(), false)),
        "read whole, and not run"
    );
    assert!(
        store.plan("bob", "p1").expect("the plan reads").is_none(),
        "a plan is its principal's"
    );
    assert_eq!(
        store.find("p2").expect("the plan reads"),
        Some((second.clone(), false)),
        "found by its id, whoever made it"
    );
    let mut listed = store.plans().expect("the plans read");
    listed.sort_by(|a, b| a.0.plan_id.cmp(&b.0.plan_id));
    assert_eq!(listed, vec![(first, false), (second, false)]);
}

fn a_plan_is_consumed_once<S: ReplayStore + ?Sized>(store: &S, operate: Operate<'_>) {
    let held = plan("alice", "p1");
    kept(store, operate, &held);
    assert!(
        matches!(
            consumed(store, operate, "bob", "p1"),
            Err(ReplayError::PlanUnknown)
        ),
        "another principal's plan is not held for this one"
    );
    assert!(matches!(
        consumed(store, operate, "alice", "p9"),
        Err(ReplayError::PlanUnknown)
    ));
    assert_eq!(
        store.plan("alice", "p1").expect("the plan reads"),
        Some((held.clone(), false)),
        "a refusal wrote nothing"
    );
    consumed(store, operate, "alice", "p1").expect("consumed");
    assert_eq!(
        store.plan("alice", "p1").expect("the plan reads"),
        Some((held.clone(), true)),
        "kept, and marked run"
    );
    assert_eq!(
        store.find("p1").expect("the plan reads"),
        Some((held, true))
    );
    assert!(
        matches!(
            consumed(store, operate, "alice", "p1"),
            Err(ReplayError::PlanConsumed)
        ),
        "a plan is run once"
    );
}

fn an_approval_joins_its_plan<S: ReplayStore + ?Sized>(store: &S, operate: Operate<'_>) {
    let held = plan("alice", "p1");
    kept(store, operate, &held);

    // No plan of that id: nothing is decided.
    operate(&mut |applying| {
        let asked = AtomicUsize::new(0);
        let answered = store
            .approve(applying, "p9", &|_, _| {
                asked.fetch_add(1, Ordering::Relaxed);
                Ok(approval("bob", applying))
            })
            .expect("answered");
        assert!(answered.is_none());
        assert_eq!(asked.load(Ordering::Relaxed), 0);
    });

    // A refusal of the decision is the answer, and records nothing.
    operate(&mut |applying| {
        let Err(Unapproved::Refused(refused)) = store.approve(applying, "p1", &|_, _| Err(full()))
        else {
            panic!("the decision's refusal is the answer, told apart from a store that failed");
        };
        assert_eq!(
            refused.error().expect("a refusal").code(),
            codes::host::PLAN_APPROVAL_REFUSED
        );
    });
    assert_eq!(
        store.find("p1").expect("the plan reads"),
        Some((held.clone(), false))
    );

    // What the decision answers joins the plan it was given.
    let mut made = None;
    operate(&mut |applying| {
        let recorded = approval("bob", applying);
        let answered = store
            .approve(applying, "p1", &|plan, consumed| {
                assert_eq!(plan, &held, "the plan as it stands");
                assert!(!consumed);
                Ok(recorded.clone())
            })
            .expect("approved")
            .expect("the plan is held");
        assert_eq!(answered.approvals, vec![recorded.clone()]);
        made = Some(recorded);
    });
    let recorded = made.expect("the operation ran");
    let (approved, run) = store
        .find("p1")
        .expect("the plan reads")
        .expect("the plan is held");
    assert!(!run);
    assert_eq!(approved.approvals, vec![recorded]);

    // A plan that was run is given to the decision as run.
    consumed(store, operate, "alice", "p1").expect("consumed");
    operate(&mut |applying| {
        let refused = store.approve(applying, "p1", &|_, consumed| {
            assert!(consumed, "the decision is told the plan was run");
            Err(full())
        });
        assert!(matches!(refused, Err(Unapproved::Refused(_))));
    });
}

fn an_operation_is_found<S: ReplayStore + ?Sized>(store: &S, operate: Operate<'_>) {
    let held = plan("alice", "p1");
    kept(store, operate, &held);
    let mut seen = None;
    operate(&mut |applying| {
        store
            .approve(applying, "p1", &|_, _| Ok(approval("bob", applying)))
            .expect("approved")
            .expect("the plan is held");
        seen = Some(applying.operation_id());
    });
    let approving = seen.expect("the operation ran");
    let found = store
        .operation(&approving, Some("p1"))
        .expect("the operation reads")
        .expect("the approval is found by its operation");
    assert_eq!(found.revision, held.revision);
    assert_eq!(found.target.as_deref(), Some("p1"));
    assert!(
        store
            .operation(&OperationId::from_bytes([9; 16]), Some("p1"))
            .expect("the operation reads")
            .is_none(),
        "an operation that approved nothing leaves nothing to find"
    );

    // A plan not yet consumed shows no consumption; once consumed, it does.
    assert!(
        store
            .operation(&approving, Some("consume:p1"))
            .expect("the operation reads")
            .is_none()
    );
    consumed(store, operate, "alice", "p1").expect("consumed");
    let found = store
        .operation(&approving, Some("consume:p1"))
        .expect("the operation reads")
        .expect("the consumption is found");
    assert_eq!(found.revision, held.revision);
    assert_eq!(found.target.as_deref(), Some("consume:p1"));
}

fn a_decision_reads_its_plan<S: ReplayStore + ?Sized>(store: &S, operate: Operate<'_>) {
    const THREADS: usize = 8;
    const ROUNDS: usize = 6;
    for round in 0..ROUNDS {
        let plan_id = format!("p{round}");
        kept(store, operate, &plan("alice", &plan_id));
        let approved = AtomicUsize::new(0);
        // Every thread is inside its operation before any asks the store: the approvals arrive
        // together, whatever the engine did to bring them there.
        let together = Barrier::new(THREADS);
        std::thread::scope(|scope| {
            for thread in 0..THREADS {
                let (plan_id, approved, together) = (&plan_id, &approved, &together);
                scope.spawn(move || {
                    operate(&mut |applying| {
                        together.wait();
                        // The rule of a plan that requires one approval: it takes one.
                        let answered = store.approve(applying, plan_id, &|plan, _| {
                            if plan.approvals.is_empty() {
                                Ok(approval(&format!("approver-{thread}"), applying))
                            } else {
                                Err(full())
                            }
                        });
                        if answered.is_ok() {
                            approved.fetch_add(1, Ordering::Relaxed);
                        }
                    });
                });
            }
        });
        assert_eq!(
            approved.load(Ordering::Relaxed),
            1,
            "one decision saw the plan without an approval"
        );
        let (held, _) = store
            .find(&plan_id)
            .expect("the plan reads")
            .expect("the plan is held");
        assert_eq!(held.approvals.len(), 1, "and one approval was recorded");
    }
}

fn consumptions_together_spend_one<S: ReplayStore + ?Sized>(store: &S, operate: Operate<'_>) {
    const THREADS: usize = 8;
    const ROUNDS: usize = 6;
    for round in 0..ROUNDS {
        let plan_id = format!("p{round}");
        kept(store, operate, &plan("alice", &plan_id));
        let spent = AtomicUsize::new(0);
        // Every thread is inside its operation before any asks the store.
        let together = Barrier::new(THREADS);
        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                let (plan_id, spent, together) = (&plan_id, &spent, &together);
                scope.spawn(move || {
                    operate(&mut |applying| {
                        together.wait();
                        match store.consume(applying, "alice", plan_id) {
                            Ok(()) => {
                                spent.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(ReplayError::PlanConsumed) => {}
                            Err(other) => panic!("a consumption answered {other}"),
                        }
                    });
                });
            }
        });
        assert_eq!(
            spent.load(Ordering::Relaxed),
            1,
            "one consumption spends a plan, the others are refused"
        );
    }
}
