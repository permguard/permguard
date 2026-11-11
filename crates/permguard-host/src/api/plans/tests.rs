// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use super::*;
use crate::api::keys::{PlanKeyRevoke, RunKeyRevoke};
use crate::api::status::Assurance;
use crate::api::testing::{actor, admin, facade, facade_with, grant_to};
use crate::keys::ring::{CONTROL_ATTEST, DATA_ATTEST, HOST_OPERATIONS};

const SECOND: &str = "sa:second";
const THIRD: &str = "sa:third";

fn code(refusal: &Refusal) -> &str {
    refusal.error().expect("a domain refusal").code()
}

/// `operations` on the Host to `principal`'s token.
fn grant(principal: &str, operations: &[&str]) {
    grant_to(principal, operations, "host/*");
}

/// A plan of the revocation of `ring`'s active key, by the administrator.
async fn plan_key(
    api: &HostApi,
    ring: &str,
    request_id: &str,
) -> Result<crate::api::Planned, Refusal> {
    let kid = active_kid(api, ring);
    api.plan_key_revoke(
        &admin(),
        ring,
        PlanKeyRevoke {
            request_id: request_id.to_owned(),
            kid,
            reason: "drill".to_owned(),
            compromised_at: None,
            expected_epoch: None,
        },
    )
    .await
}

/// The run of the key revocation `receipt` names, on `ring`.
async fn run_key(
    api: &HostApi,
    actor: &Actor,
    ring: &str,
    request_id: &str,
    receipt: &str,
) -> Result<crate::api::keys::KeyRevoked, Refusal> {
    api.run_key_revoke(
        actor,
        ring,
        RunKeyRevoke {
            request_id: request_id.to_owned(),
            receipt: receipt.to_owned(),
        },
    )
    .await
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
    let api = facade_with("plans-once", vec![HOST_OPERATIONS, DATA_ATTEST]);
    let planned = plan_key(&api, DATA_ATTEST, "p").await.expect("planned");
    assert_eq!(
        planned.approvals_required, 0,
        "no approval outside dual control"
    );
    assert!(planned.plan_digest.starts_with("sha256:"));
    let receipt = URL_SAFE_NO_PAD.decode(&planned.receipt).expect("base64url");
    let read = plan::read_receipt(&receipt).expect("a receipt");
    assert_eq!(read.operation, KEYS_REVOKE);
    assert!(read.target.starts_with(DATA_ATTEST), "{}", read.target);
    assert_eq!(read.principal, admin_principal());
    run_key(&api, &admin(), DATA_ATTEST, "r1", &planned.receipt)
        .await
        .expect("revoked");
    let again = run_key(&api, &admin(), DATA_ATTEST, "r2", &planned.receipt)
        .await
        .expect_err("run once");
    assert_eq!(code(&again), codes::host::PLAN_EXPIRED);
}

fn admin_principal() -> String {
    crate::api::testing::ADMIN.to_owned()
}

#[tokio::test]
async fn a_receipt_for_one_plan_does_not_authorize_another() {
    let api = facade_with(
        "plans-other",
        vec![HOST_OPERATIONS, DATA_ATTEST, CONTROL_ATTEST],
    );
    let planned = plan_key(&api, DATA_ATTEST, "p1").await.expect("planned");
    // The receipt of one ring's plan presented for another ring.
    let refused = run_key(&api, &admin(), CONTROL_ATTEST, "r1", &planned.receipt)
        .await
        .expect_err("another ring");
    assert_eq!(code(&refused), codes::host::PLAN_UNKNOWN);
    // Its bytes changed: not the receipt the plan step answered.
    let refused = run_key(
        &api,
        &admin(),
        DATA_ATTEST,
        "r2",
        &crate::api::testing::tampered(&planned.receipt),
    )
    .await
    .expect_err("tampered");
    assert_eq!(code(&refused), codes::host::PLAN_DIGEST_MISMATCH);
    // Not the planner: the plan is not held for it.
    grant(SECOND, &[operations::KEYS_ADMIN]);
    let refused = run_key(&api, &actor(SECOND), DATA_ATTEST, "r3", &planned.receipt)
        .await
        .expect_err("another principal");
    assert_eq!(code(&refused), codes::host::PLAN_UNKNOWN);
}

#[tokio::test]
async fn a_replayed_run_answers_its_result_and_another_receipt_is_refused() {
    let api = facade_with(
        "plans-replay",
        vec![HOST_OPERATIONS, DATA_ATTEST, CONTROL_ATTEST],
    );
    let planned = plan_key(&api, DATA_ATTEST, "p1").await.expect("planned");
    let other = plan_key(&api, CONTROL_ATTEST, "p2").await.expect("planned");
    let done = run_key(&api, &admin(), DATA_ATTEST, "r", &planned.receipt)
        .await
        .expect("revoked");
    let replayed = run_key(&api, &admin(), DATA_ATTEST, "r", &planned.receipt)
        .await
        .expect("the stored result");
    assert_eq!(replayed, done);
    let refused = run_key(&api, &admin(), CONTROL_ATTEST, "r", &other.receipt)
        .await
        .expect_err("the request id names another run");
    assert_eq!(code(&refused), codes::host::REQUEST_ID_REUSED);
}

#[tokio::test]
async fn a_plan_needs_host_operations_to_sign_its_receipt() {
    let api = facade_with("plans-no-ring", vec![DATA_ATTEST]);
    let refused = plan_key(&api, DATA_ATTEST, "p")
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
    let latest = crate::api::rfc3339(now + 86_400);
    let earliest = crate::api::rfc3339(now + 86_400 - 60);
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
    grant(SECOND, &[operations::LIFECYCLE_READ]);
    let refused = api
        .approve_plan(&actor(SECOND), &planned.plan_id, approve("a1"))
        .await
        .expect_err("no keys.admin");
    assert!(matches!(refused, Refusal::Denied(_)), "{refused:?}");
    // With it, one approval, attested by the Host.
    grant(SECOND, &[operations::KEYS_ADMIN]);
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
    grant(THIRD, &[operations::KEYS_ADMIN]);
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
        vec![HOST_OPERATIONS, DATA_ATTEST, CONTROL_ATTEST],
    ));
    plan_key(&api, DATA_ATTEST, "k1").await.expect("planned");
    plan_key(&api, CONTROL_ATTEST, "k2").await.expect("planned");
    let all = api.plans(&admin(), None).expect("listed");
    assert_eq!(all.plans.len(), 2);
    let pending = api.plans(&admin(), Some("pending")).expect("listed");
    assert_eq!(
        pending.plans.len(),
        2,
        "dual control: each awaits an approval"
    );
    assert!(
        pending
            .plans
            .iter()
            .all(|plan| plan.operation == KEYS_REVOKE)
    );
    assert!(
        api.plans(&admin(), Some("ready"))
            .expect("listed")
            .plans
            .is_empty()
    );
    // A holder of `keys.admin` sees them, never their receipts.
    grant(SECOND, &[operations::KEYS_ADMIN]);
    let seen = api.plans(&actor(SECOND), None).expect("listed");
    assert_eq!(seen.plans.len(), 2);
    assert!(seen.plans.iter().all(|plan| plan.receipt.is_empty()));
    assert!(all.plans.iter().all(|plan| !plan.receipt.is_empty()));
    // A holder of no plan's operation, and nobody, are refused.
    grant(THIRD, &[operations::LIFECYCLE_READ]);
    assert!(matches!(
        api.plans(&actor(THIRD), None),
        Err(Refusal::Denied(denial)) if denial.http_status() == 403
    ));
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
    grant(SECOND, &[operations::KEYS_ADMIN]);
    grant(THIRD, &[operations::KEYS_ADMIN]);
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
