// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::*;
use crate::api::grants::CreateGrant;
use crate::api::testing::{Recording, actor, admin, facade, reopen_with, scratch, tampered};
use crate::gc::{Entry, Kept};

const PLANE: &str = "control-plane";
const OPERATOR: &str = "spiffe://acme/operators/gc";
/// Holds `gc.manage` on the whole Control Plane.
const SWEEPER: &str = "spiffe://acme/operators/sweeper";

/// A job that answers fixed reports and remembers what it was asked.
#[derive(Default)]
struct Fake {
    plans: Mutex<Vec<String>>,
    runs: Mutex<Vec<(String, String)>>,
    fail: std::sync::atomic::AtomicBool,
}

fn report(scope: &Resource, removed: u64) -> Report {
    Report {
        entries: vec![Entry {
            resource: scope.to_string(),
            candidates: 2,
            candidate_bytes: 20,
            removed,
            removed_bytes: removed * 10,
            kept: vec![Kept {
                reason: "grace".to_owned(),
                count: 1,
            }],
        }],
        resumes_at: None,
        skipped: Vec::new(),
        omitted: 0,
    }
}

impl GcJob for Fake {
    fn plan(&self, scope: &Resource) -> Result<Report, GcError> {
        self.plans.lock().expect("plans").push(scope.to_string());
        Ok(report(scope, 0))
    }

    fn run(&self, scope: &Resource, plan_id: &str) -> Result<Report, GcError> {
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(GcError::Failed("the store would not list".to_owned()));
        }
        self.runs
            .lock()
            .expect("runs")
            .push((scope.to_string(), plan_id.to_owned()));
        Ok(report(scope, 2))
    }
}

fn provided(api: &HostApi, fail: bool) -> Arc<Fake> {
    let fake = Arc::new(Fake {
        fail: fail.into(),
        ..Fake::default()
    });
    api.gc_jobs()
        .provide(gc::OBJECTS, PLANE, Arc::clone(&fake) as Arc<dyn GcJob>)
        .expect("provided");
    fake
}

fn code(refusal: &Refusal) -> &str {
    refusal.error().expect("a domain refusal").code()
}

fn plan(request_id: &str, resource: Option<&str>) -> PlanGc {
    PlanGc {
        request_id: request_id.to_owned(),
        resource: resource.map(str::to_owned),
    }
}

fn run(request_id: &str, receipt: &str) -> RunGc {
    RunGc {
        request_id: request_id.to_owned(),
        receipt: receipt.to_owned(),
    }
}

/// `gc.manage` to `principal` on what `selector` covers.
async fn grant(api: &HostApi, request_id: &str, principal: &str, selector: &str) {
    api.create_grant(
        &admin(),
        CreateGrant {
            request_id: request_id.to_owned(),
            expected_revision: None,
            principal: principal.to_owned(),
            operations: vec![operations::GC_MANAGE.to_owned()],
            selector: selector.to_owned(),
            resource_types: vec!["*".to_owned()],
            constraints: Default::default(),
            expires_at: None,
        },
    )
    .await
    .expect("granted");
}

/// A facade where [`SWEEPER`] holds `gc.manage` on the Control Plane.
async fn swept(tag: &str) -> HostApi {
    let api = facade(tag);
    grant(&api, "sweeper", SWEEPER, "plane/control-plane/*").await;
    api
}

fn sweeper() -> Actor {
    actor(SWEEPER)
}

#[tokio::test]
async fn a_plan_changes_nothing_and_its_run_spends_it_once() {
    let api = swept("gc-once").await;
    let fake = provided(&api, false);
    let planned = api
        .plan_gc(&sweeper(), gc::OBJECTS, plan("p", None))
        .expect("planned");
    assert_eq!(
        planned.resource, "plane/control-plane",
        "the Plane by default"
    );
    assert_eq!(planned.report, report(&Resource::plane(PLANE), 0));
    assert_eq!(planned.approvals_required, 0, "no approval");
    assert!(
        fake.runs.lock().expect("runs").is_empty(),
        "a plan sweeps nothing"
    );
    let receipt = crate::operations::plan::read_receipt(
        &URL_SAFE_NO_PAD.decode(&planned.receipt).expect("base64url"),
    )
    .expect("a receipt");
    assert_eq!(receipt.operation, crate::operations::plan::GC_OBJECTS);
    assert_eq!(receipt.target, "plane/control-plane");
    assert_eq!(receipt.principal, SWEEPER);

    let ran = api
        .run_gc(&sweeper(), gc::OBJECTS, run("r1", &planned.receipt))
        .expect("ran");
    assert_eq!(ran.plan_id, planned.plan_id);
    assert_eq!(ran.report, report(&Resource::plane(PLANE), 2));
    assert_eq!(
        *fake.runs.lock().expect("runs"),
        vec![("plane/control-plane".to_owned(), planned.plan_id.clone())],
        "the Plane's run names the plan"
    );
    // A retry answers the first run and sweeps nothing more.
    let retried = api
        .run_gc(&sweeper(), gc::OBJECTS, run("r1", &planned.receipt))
        .expect("replayed");
    assert_eq!(retried, ran);
    assert_eq!(fake.runs.lock().expect("runs").len(), 1);
    // Another run of the same receipt is refused: it was spent.
    let again = api
        .run_gc(&sweeper(), gc::OBJECTS, run("r2", &planned.receipt))
        .expect_err("spent");
    assert_eq!(code(&again), codes::host::PLAN_EXPIRED);
    assert_eq!(fake.runs.lock().expect("runs").len(), 1);
}

#[tokio::test]
async fn the_grant_is_checked_on_the_scope_the_plan_names() {
    let api = swept("gc-scope").await;
    let fake = provided(&api, false);
    let zone = "plane/control-plane/zone/z1";
    let ledger = "plane/control-plane/zone/z1/ledger/l1";
    grant(&api, "g", OPERATOR, &format!("{zone}/*")).await;
    let operator = actor(OPERATOR);
    for scope in [zone, ledger] {
        let planned = api
            .plan_gc(&operator, gc::OBJECTS, plan(scope, Some(scope)))
            .expect("planned within the grant");
        assert_eq!(planned.resource, scope);
        api.run_gc(
            &operator,
            gc::OBJECTS,
            run(&format!("run {scope}"), &planned.receipt),
        )
        .expect("ran within the grant");
    }
    for scope in [None, Some("plane/control-plane/zone/z2")] {
        let refused = api
            .plan_gc(&operator, gc::OBJECTS, plan("outside", scope))
            .expect_err("outside the grant");
        assert!(
            matches!(refused, Refusal::Denied(_)),
            "{scope:?}: {refused:?}"
        );
    }
    // Nor does a principal without the grant learn whether the job exists.
    let stranger = actor("spiffe://acme/operators/stranger");
    let refused = api
        .plan_gc(&stranger, "nothing", plan("p", None))
        .expect_err("no grant");
    assert!(matches!(refused, Refusal::Denied(_)), "{refused:?}");
    // The run of a plan made on the whole Plane is refused to the zone's operator.
    let whole = api
        .plan_gc(&sweeper(), gc::OBJECTS, plan("whole", None))
        .expect("planned");
    let refused = api
        .run_gc(&operator, gc::OBJECTS, run("steal", &whole.receipt))
        .expect_err("outside the grant");
    assert!(matches!(refused, Refusal::Denied(_)), "{refused:?}");
    assert_eq!(
        fake.plans.lock().expect("plans").len(),
        3,
        "a refused caller planned nothing"
    );
    let swept: Vec<String> = fake
        .runs
        .lock()
        .expect("runs")
        .iter()
        .map(|(scope, _)| scope.clone())
        .collect();
    assert_eq!(
        swept,
        vec![zone.to_owned(), ledger.to_owned()],
        "each run its plan's scope"
    );
    // A Host-wide holder of `gc.manage` lists the plans, the receipt shown to the planner alone.
    let listed = api.plans(&admin(), None).expect("listed");
    let shown = listed
        .plans
        .iter()
        .find(|plan| plan.plan_id == whole.plan_id)
        .expect("the gc plan is listed");
    assert_eq!(shown.operation, crate::operations::plan::GC_OBJECTS);
    assert!(shown.receipt.is_empty());
}

#[tokio::test]
async fn a_scope_outside_the_plane_or_a_job_nobody_provides_is_refused() {
    let api = swept("gc-refusals").await;
    // A job no Plane provides names no Plane to admit on: the Host's grant is asked.
    let refused = api
        .plan_gc(&sweeper(), gc::OBJECTS, plan("p", None))
        .expect_err("not provided");
    assert!(matches!(refused, Refusal::Denied(_)), "{refused:?}");
    let refused = api
        .plan_gc(&admin(), gc::OBJECTS, plan("p", None))
        .expect_err("not provided");
    assert_eq!(code(&refused), codes::common::UNAVAILABLE);
    let fake = provided(&api, false);
    let refused = api
        .plan_gc(&admin(), "mirrors", plan("p", None))
        .expect_err("not a job yet");
    assert_eq!(code(&refused), codes::common::NOT_FOUND);
    // Outside every grant the sweeper holds: refused before anything is told.
    let refused = api
        .plan_gc(&sweeper(), gc::OBJECTS, plan("p", Some("plane/data-plane")))
        .expect_err("outside the grant");
    assert!(matches!(refused, Refusal::Denied(_)), "{refused:?}");
    // Admitted, and still not the Control Plane's to sweep.
    grant(&api, "data", SWEEPER, "plane/data-plane/*").await;
    for (who, scope) in [
        (admin(), "host"),
        (admin(), "zone/z1"),
        (sweeper(), "plane/data-plane"),
        (sweeper(), "plane/data-plane/zone/z1"),
    ] {
        let refused = api
            .plan_gc(&who, gc::OBJECTS, plan("p", Some(scope)))
            .expect_err("outside the Plane");
        assert_eq!(code(&refused), codes::common::INVALID_ARGUMENT, "{scope}");
    }
    let refused = api
        .plan_gc(&sweeper(), gc::OBJECTS, plan("", None))
        .expect_err("no request id");
    assert_eq!(code(&refused), codes::host::REQUEST_ID_REQUIRED);
    assert!(
        fake.plans.lock().expect("plans").is_empty(),
        "nothing refused reached the job"
    );
}

#[tokio::test]
async fn a_receipt_that_is_not_this_jobs_plan_does_not_run() {
    let api = swept("gc-receipts").await;
    let fake = provided(&api, false);
    let planned = api
        .plan_gc(&sweeper(), gc::OBJECTS, plan("p", None))
        .expect("planned");
    let refused = api
        .run_gc(
            &sweeper(),
            gc::OBJECTS,
            run("r1", &tampered(&planned.receipt)),
        )
        .expect_err("tampered");
    assert_eq!(code(&refused), codes::host::PLAN_DIGEST_MISMATCH);
    let refused = api
        .run_gc(
            &admin(),
            gc::OBJECTS,
            run("r2", &crate::api::testing::unknown_receipt()),
        )
        .expect_err("another operation's");
    assert!(
        [codes::host::PLAN_UNKNOWN, codes::host::PLAN_EXPIRED].contains(&code(&refused)),
        "{refused:?}"
    );
    let refused = api
        .run_gc(&admin(), gc::OBJECTS, run("r3", "not a receipt"))
        .expect_err("garbage");
    assert_eq!(code(&refused), codes::common::INVALID_ARGUMENT);
    // Another principal holding the grant cannot run the planner's receipt.
    let other = actor(other_principal());
    grant(&api, "g", other_principal(), "plane/control-plane/*").await;
    let refused = api
        .run_gc(&other, gc::OBJECTS, run("r4", &planned.receipt))
        .expect_err("not the planner");
    assert_eq!(code(&refused), codes::host::PLAN_UNKNOWN);
    assert!(fake.runs.lock().expect("runs").is_empty(), "nothing ran");
    // The planner still can.
    api.run_gc(&sweeper(), gc::OBJECTS, run("r5", &planned.receipt))
        .expect("ran");
}

fn other_principal() -> &'static str {
    "spiffe://acme/operators/other"
}

#[tokio::test]
async fn a_run_that_fails_is_refused_and_a_plan_and_a_run_are_audited() {
    let trail = Arc::new(Recording::default());
    let (api, _, volume) = reopen_with(
        &scratch("gc-audit"),
        vec![crate::keys::ring::HOST_OPERATIONS],
        Arc::clone(&trail),
    );
    grant(&api, "sweeper", SWEEPER, "plane/control-plane/*").await;
    let failing = Arc::new(Fake {
        fail: true.into(),
        ..Fake::default()
    });
    api.gc_jobs()
        .provide(gc::OBJECTS, PLANE, Arc::clone(&failing) as Arc<dyn GcJob>)
        .expect("provided");
    let planned = api
        .plan_gc(&sweeper(), gc::OBJECTS, plan("p", None))
        .expect("planned");
    let refused = api
        .run_gc(&sweeper(), gc::OBJECTS, run("r", &planned.receipt))
        .expect_err("the job failed");
    assert_eq!(code(&refused), codes::common::UNAVAILABLE);
    let events = trail.events.lock().expect("events").clone();
    let recorded = |action: &str, phase: &str| {
        events.iter().any(|(recorded, _, target, at)| {
            recorded == action
                && target.as_deref() == Some("objects:plane/control-plane")
                && *at == Some(phase)
        })
    };
    assert!(recorded(AUDIT_PLANNED, "applied"), "{events:?}");
    assert!(
        recorded(AUDIT_RAN, "failed"),
        "a failed run is recorded failed: {events:?}"
    );
    assert!(!recorded(AUDIT_RAN, "applied"), "{events:?}");
    // Once the sweep runs again, a run is recorded applied.
    failing
        .fail
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let planned = api
        .plan_gc(&sweeper(), gc::OBJECTS, plan("p2", None))
        .expect("planned");
    api.run_gc(&sweeper(), gc::OBJECTS, run("r2", &planned.receipt))
        .expect("ran");
    let events = trail.events.lock().expect("events").clone();
    assert!(
        events
            .iter()
            .any(|(action, _, _, phase)| action == AUDIT_RAN && *phase == Some("applied")),
        "{events:?}"
    );
    drop(volume);
}
