// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use permguard_core::authz::Selector;

use super::*;
use crate::api::grants::{CreateGrant, PlanRevoke, RunRevoke};
use crate::api::keys::{PlanKeyRevoke, RunKeyRevoke};
use crate::api::status::Assurance;
use crate::api::testing::{actor, admin, facade, facade_with};
use crate::keys::ring::{DATA_ATTEST, HOST_OPERATIONS};

const SECOND: &str = "spiffe://acme/operators/second";
const THIRD: &str = "spiffe://acme/operators/third";

fn code(refusal: &Refusal) -> &str {
    refusal.error().expect("a domain refusal").code()
}

/// A grant of `operations` on the Host to `principal`.
async fn grant(api: &HostApi, request_id: &str, principal: &str, operations: &[&str]) -> String {
    api.create_grant(
        &admin(),
        CreateGrant {
            request_id: request_id.to_owned(),
            expected_revision: None,
            principal: principal.to_owned(),
            operations: operations.iter().map(|op| (*op).to_owned()).collect(),
            selector: Selector::under(Resource::host()).to_string(),
            resource_types: vec!["*".to_owned()],
            constraints: Default::default(),
            expires_at: None,
        },
    )
    .await
    .expect("granted")
    .grant
    .grant_id
}

fn revoke(request_id: &str) -> PlanRevoke {
    PlanRevoke {
        request_id: request_id.to_owned(),
        expected_revision: None,
    }
}

fn run(request_id: &str, receipt: &str) -> RunRevoke {
    RunRevoke {
        request_id: request_id.to_owned(),
        receipt: receipt.to_owned(),
    }
}

/// The facade under `regulated`: dual control in force.
fn regulated(mut api: HostApi) -> HostApi {
    api.assurance = Assurance {
        profile: "regulated".to_owned(),
        enforcement: "local".to_owned(),
        added_controls: Vec::new(),
        relaxations: Vec::new(),
    };
    api
}

/// The kid of `ring`'s active key.
fn active_kid(api: &HostApi, ring: &str) -> String {
    api.ring(ring)
        .expect("public")
        .keys
        .into_iter()
        .next()
        .expect("a key")
        .kid
}

#[tokio::test]
async fn a_run_consumes_the_receipt_once() {
    let api = facade("plans-once");
    let target = grant(&api, "g", "spiffe://acme/x", &[operations::LIFECYCLE_READ]).await;
    let planned = api
        .plan_revoke(&admin(), &target, revoke("p"))
        .await
        .expect("planned");
    assert_eq!(
        planned.approvals_required, 0,
        "a grant revocation needs none"
    );
    assert!(planned.plan_digest.starts_with("sha256:"));
    let receipt = URL_SAFE_NO_PAD.decode(&planned.receipt).expect("base64url");
    let read = plan::read_receipt(&receipt).expect("a receipt");
    assert_eq!(read.operation, GRANT_REVOKE);
    assert_eq!(read.target, target);
    assert_eq!(read.principal, admin_principal());
    api.run_revoke(&admin(), &target, run("r1", &planned.receipt))
        .await
        .expect("revoked");
    let again = api
        .run_revoke(&admin(), &target, run("r2", &planned.receipt))
        .await
        .expect_err("run once");
    assert_eq!(code(&again), codes::host::PLAN_EXPIRED);
}

fn admin_principal() -> String {
    crate::api::testing::ADMIN.to_owned()
}

#[tokio::test]
async fn a_receipt_for_one_plan_does_not_authorize_another() {
    let api = facade("plans-other");
    let first = grant(&api, "g1", "spiffe://acme/x", &[operations::LIFECYCLE_READ]).await;
    let second = grant(&api, "g2", "spiffe://acme/y", &[operations::LIFECYCLE_READ]).await;
    let planned = api
        .plan_revoke(&admin(), &first, revoke("p1"))
        .await
        .expect("planned");
    // The receipt of the first grant's plan presented for the second grant.
    let refused = api
        .run_revoke(&admin(), &second, run("r1", &planned.receipt))
        .await
        .expect_err("another grant");
    assert_eq!(code(&refused), codes::host::PLAN_UNKNOWN);
    // Its bytes changed: not the receipt the plan step answered.
    let refused = api
        .run_revoke(
            &admin(),
            &first,
            run("r2", &crate::api::testing::tampered(&planned.receipt)),
        )
        .await
        .expect_err("tampered");
    assert_eq!(code(&refused), codes::host::PLAN_DIGEST_MISMATCH);
    // Not the planner: the plan is not held for it.
    let other = actor(SECOND);
    grant(&api, "g3", SECOND, &[operations::AUTHZ_ADMIN]).await;
    let refused = api
        .run_revoke(&other, &first, run("r3", &planned.receipt))
        .await
        .expect_err("another principal");
    assert_eq!(code(&refused), codes::host::PLAN_UNKNOWN);
}

#[tokio::test]
async fn a_replayed_run_answers_its_result_and_another_receipt_is_refused() {
    let api = facade("plans-replay");
    let first = grant(&api, "g1", "spiffe://acme/x", &[operations::LIFECYCLE_READ]).await;
    let second = grant(&api, "g2", "spiffe://acme/y", &[operations::LIFECYCLE_READ]).await;
    let planned = api
        .plan_revoke(&admin(), &first, revoke("p1"))
        .await
        .expect("planned");
    let other = api
        .plan_revoke(&admin(), &second, revoke("p2"))
        .await
        .expect("planned");
    let done = api
        .run_revoke(&admin(), &first, run("r", &planned.receipt))
        .await
        .expect("revoked");
    let replayed = api
        .run_revoke(&admin(), &first, run("r", &planned.receipt))
        .await
        .expect("the stored result");
    assert_eq!(replayed, done);
    let refused = api
        .run_revoke(&admin(), &second, run("r", &other.receipt))
        .await
        .expect_err("the request id names another run");
    assert_eq!(code(&refused), codes::host::REQUEST_ID_REUSED);
}

#[tokio::test]
async fn a_plan_needs_host_operations_to_sign_its_receipt() {
    let api = facade_with("plans-no-ring", Vec::new());
    let target = grant(&api, "g", "spiffe://acme/x", &[operations::LIFECYCLE_READ]).await;
    let refused = api
        .plan_revoke(&admin(), &target, revoke("p"))
        .await
        .expect_err("nothing signs the receipt");
    assert_eq!(code(&refused), codes::common::UNAVAILABLE);
}

#[tokio::test]
async fn under_regulated_reset_and_key_revocation_are_refused_below_the_approval_count() {
    let api = regulated(facade_with(
        "plans-regulated",
        vec![HOST_OPERATIONS, DATA_ATTEST],
    ));
    let kid = active_kid(&api, DATA_ATTEST);
    let planned = api
        .plan_key_revoke(
            &admin(),
            DATA_ATTEST,
            PlanKeyRevoke {
                request_id: "k".to_owned(),
                kid: kid.clone(),
                reason: "drill".to_owned(),
                compromised_at: None,
                expected_epoch: None,
            },
        )
        .await
        .expect("planned");
    assert_eq!(planned.approvals_required, 1);
    let now = api.time.now_secs();
    let latest = crate::api::grants::rfc3339(now + 86_400);
    let earliest = crate::api::grants::rfc3339(now + 86_400 - 60);
    assert!(
        earliest.as_str() <= planned.expires.as_str()
            && planned.expires.as_str() <= latest.as_str(),
        "a day: {}",
        planned.expires
    );
    let refused = api
        .run_key_revoke(
            &admin(),
            DATA_ATTEST,
            RunKeyRevoke {
                request_id: "kr".to_owned(),
                receipt: planned.receipt.clone(),
            },
        )
        .await
        .expect_err("below the count");
    assert_eq!(code(&refused), codes::host::PLAN_APPROVALS_MISSING);
    // A grant revocation needs none, even here.
    let target = grant(&api, "g", "spiffe://acme/x", &[operations::LIFECYCLE_READ]).await;
    let grant_plan = api
        .plan_revoke(&admin(), &target, revoke("p"))
        .await
        .expect("planned");
    assert_eq!(grant_plan.approvals_required, 0);
    // The identity reset needs one.
    assert_eq!(
        plan::approvals_required(IDENTITY_RESET, api.dual_control()),
        1
    );
    // Added below `regulated`, the control is in force too.
    let mut added = facade("plans-added");
    added.assurance.added_controls = vec![
        permguard_core::assurance::Control::OperationsDualControl
            .name()
            .to_owned(),
    ];
    assert!(added.dual_control());
    assert!(!facade("plans-not").dual_control());
}

#[tokio::test]
async fn the_planner_cannot_approve_its_own_plan_and_an_approval_counts_once_per_principal() {
    let api = regulated(facade_with(
        "plans-approve",
        vec![HOST_OPERATIONS, DATA_ATTEST],
    ));
    let kid = active_kid(&api, DATA_ATTEST);
    let planned = api
        .plan_key_revoke(
            &admin(),
            DATA_ATTEST,
            PlanKeyRevoke {
                request_id: "k".to_owned(),
                kid: kid.clone(),
                reason: "drill".to_owned(),
                compromised_at: None,
                expected_epoch: None,
            },
        )
        .await
        .expect("planned");
    let approve = |request_id: &str| ApprovePlan {
        request_id: request_id.to_owned(),
    };
    let refused = api
        .approve_plan(&admin(), &planned.plan_id, approve("a0"))
        .await
        .expect_err("the planner");
    assert_eq!(code(&refused), codes::host::PLAN_SELF_APPROVAL);
    // A principal without the operation's grant is denied.
    grant(&api, "g-second-read", SECOND, &[operations::LIFECYCLE_READ]).await;
    let refused = api
        .approve_plan(&actor(SECOND), &planned.plan_id, approve("a1"))
        .await
        .expect_err("no keys.admin");
    assert!(matches!(refused, Refusal::Denied(_)), "{refused:?}");
    // With it, one approval, attested by the Host.
    grant(&api, "g-second", SECOND, &[operations::KEYS_ADMIN]).await;
    let approved = api
        .approve_plan(&actor(SECOND), &planned.plan_id, approve("a2"))
        .await
        .expect("approved");
    assert_eq!(approved.plan.status, "ready");
    assert_eq!(approved.plan.approvals.len(), 1);
    let envelope = URL_SAFE_NO_PAD
        .decode(&approved.plan.approvals[0].approval)
        .expect("base64url");
    let sign1 = permguard_objects::cose::Sign1::decode(&envelope).expect("an envelope");
    let attested = Approval::decode(sign1.payload_unverified()).expect("an approval");
    assert_eq!(attested.principal, SECOND);
    assert_eq!(attested.plan_digest.to_string(), planned.plan_digest);
    assert!(
        approved.plan.receipt.is_empty(),
        "the receipt is the planner's alone"
    );
    // A retry with the same request id answers what the approval answered.
    let retried = api
        .approve_plan(&actor(SECOND), &planned.plan_id, approve("a2"))
        .await
        .expect("the stored answer");
    assert_eq!(retried, approved);
    // The approval presented as a receipt is no receipt.
    let refused = api
        .run_key_revoke(
            &admin(),
            DATA_ATTEST,
            RunKeyRevoke {
                request_id: "kx".to_owned(),
                receipt: approved.plan.approvals[0].approval.clone(),
            },
        )
        .await
        .expect_err("an approval");
    assert_eq!(code(&refused), codes::common::INVALID_ARGUMENT);
    // Twice by the same principal, or once more than required: refused.
    let refused = api
        .approve_plan(&actor(SECOND), &planned.plan_id, approve("a3"))
        .await
        .expect_err("twice");
    assert_eq!(code(&refused), codes::host::PLAN_APPROVAL_REFUSED);
    grant(&api, "g-third", THIRD, &[operations::KEYS_ADMIN]).await;
    let refused = api
        .approve_plan(&actor(THIRD), &planned.plan_id, approve("a4"))
        .await
        .expect_err("no more required");
    assert_eq!(code(&refused), codes::host::PLAN_APPROVAL_REFUSED);
    // The planner runs it now.
    api.run_key_revoke(
        &admin(),
        DATA_ATTEST,
        RunKeyRevoke {
            request_id: "kr".to_owned(),
            receipt: planned.receipt.clone(),
        },
    )
    .await
    .expect("revoked once approved");
    // Run, it is listed consumed and takes no approval.
    let consumed = api.plans(&admin(), Some("consumed")).expect("listed");
    assert_eq!(consumed.plans.len(), 1);
    assert_eq!(consumed.plans[0].plan_id, planned.plan_id);
    let refused = api
        .approve_plan(&actor(THIRD), &planned.plan_id, approve("a6"))
        .await
        .expect_err("consumed");
    assert_eq!(code(&refused), codes::host::PLAN_EXPIRED);
    // An unknown plan.
    let refused = api
        .approve_plan(&actor(SECOND), "00", approve("a5"))
        .await
        .expect_err("unknown");
    assert_eq!(code(&refused), codes::host::PLAN_UNKNOWN);
}

#[tokio::test]
async fn plans_are_listed_to_the_holders_of_their_operations_grant() {
    let api = regulated(facade_with(
        "plans-list",
        vec![HOST_OPERATIONS, DATA_ATTEST],
    ));
    let kid = active_kid(&api, DATA_ATTEST);
    api.plan_key_revoke(
        &admin(),
        DATA_ATTEST,
        PlanKeyRevoke {
            request_id: "k".to_owned(),
            kid,
            reason: "drill".to_owned(),
            compromised_at: None,
            expected_epoch: None,
        },
    )
    .await
    .expect("planned");
    let target = grant(&api, "g", "spiffe://acme/x", &[operations::LIFECYCLE_READ]).await;
    api.plan_revoke(&admin(), &target, revoke("p"))
        .await
        .expect("planned");
    let all = api.plans(&admin(), None).expect("listed");
    assert_eq!(all.plans.len(), 2);
    let pending = api.plans(&admin(), Some("pending")).expect("listed");
    assert_eq!(pending.plans.len(), 1);
    assert_eq!(pending.plans[0].operation, KEYS_REVOKE);
    let ready = api.plans(&admin(), Some("ready")).expect("listed");
    assert_eq!(ready.plans[0].operation, GRANT_REVOKE);
    // A principal with `authz.admin` alone sees the grant plan only.
    grant(&api, "g-second", SECOND, &[operations::AUTHZ_ADMIN]).await;
    let seen = api.plans(&actor(SECOND), None).expect("listed");
    assert_eq!(
        seen.plans
            .iter()
            .map(|plan| plan.operation.as_str())
            .collect::<Vec<_>>(),
        vec![GRANT_REVOKE]
    );
    // The receipt is the planner's capability: listed to the planner alone.
    assert!(seen.plans[0].receipt.is_empty());
    assert!(all.plans.iter().all(|plan| !plan.receipt.is_empty()));
    assert!(matches!(
        api.plans(&Actor::Anonymous, None),
        Err(Refusal::Denied(_))
    ));
    let refused = api
        .plans(&admin(), Some("done"))
        .expect_err("no such status");
    assert_eq!(code(&refused), codes::common::INVALID_ARGUMENT);
}

/// A plan requiring two approvals takes one per distinct principal: the same principal twice is
/// refused while the count is not reached.
#[tokio::test]
async fn a_principal_approves_a_plan_once_whatever_the_count() {
    let api = regulated(facade_with("plans-two", vec![HOST_OPERATIONS]));
    let plan_id = "0123456789abcdef0123456789abcdef";
    let digest = plan::plan_digest(KEYS_REVOKE, "data.attest:k", 1, &[]);
    api.replay
        .plan(
            &crate::operations::mutation::Applying::for_tests(9),
            Plan {
                plan_id: plan_id.to_owned(),
                operation: "keys.revoke".to_owned(),
                target: "data.attest\nk".to_owned(),
                revision: 1,
                digest: digest.to_string(),
                expires: api.time.now_secs() + 3_600,
                principal: admin_principal(),
                kind: KEYS_REVOKE.to_owned(),
                approvals_required: 2,
                ..Plan::default()
            },
        )
        .expect("planned");
    grant(&api, "g-second", SECOND, &[operations::KEYS_ADMIN]).await;
    grant(&api, "g-third", THIRD, &[operations::KEYS_ADMIN]).await;
    let approve = |request_id: &str| ApprovePlan {
        request_id: request_id.to_owned(),
    };
    let first = api
        .approve_plan(&actor(SECOND), plan_id, approve("a1"))
        .await
        .expect("approved");
    assert_eq!(first.plan.status, "pending");
    let refused = api
        .approve_plan(&actor(SECOND), plan_id, approve("a2"))
        .await
        .expect_err("twice");
    assert_eq!(code(&refused), codes::host::PLAN_APPROVAL_REFUSED);
    let second = api
        .approve_plan(&actor(THIRD), plan_id, approve("a3"))
        .await
        .expect("approved");
    assert_eq!(second.plan.status, "ready");
    assert_eq!(second.plan.approvals.len(), 2);
}
