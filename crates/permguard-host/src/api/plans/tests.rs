// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use std::sync::Arc;

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

/// BUG-0100: an offline plan names no authenticated planner, so under dual control it requires
/// one approval more than its operation, each by a distinct principal: one holder of
/// `identity.admin` approving an offline reset leaves it short, and the run step refuses it.
#[tokio::test]
async fn an_offline_plan_under_dual_control_is_not_completed_by_one_approver() {
    const ALICE: &str = "spiffe://acme/operators/alice";
    let api = regulated(facade_with("plans-offline", vec![HOST_OPERATIONS]));
    let signer = api
        .keys
        .rings()
        .iter()
        .find(|ring| ring.id() == HOST_OPERATIONS)
        .cloned()
        .expect("the operations ring");
    let now = api.time.now_secs();
    let issue = |principal: &Principal, dual_control: bool| {
        sign_plan(
            Some(signer.as_ref() as &dyn plan::PlanSigner),
            Issue {
                kind: plan::IDENTITY_RESET,
                internal: plan::IDENTITY_RESET,
                stored_target: "emergency\n".to_owned(),
                target: "host".to_owned(),
                revision: 1,
                parameters: &[("mode", "emergency")],
                principal,
            },
            [1; 16],
            dual_control,
            now,
        )
        .expect("signed")
    };
    let offline_planner = Principal::new(plan::OFFLINE_PLANNER).expect("a principal");
    let offline = issue(&offline_planner, true);
    assert_eq!(offline.approvals_required, 2);
    let alice = Principal::new(ALICE).expect("a principal");
    assert_eq!(
        issue(&alice, true).approvals_required,
        1,
        "an authenticated planner"
    );
    assert_eq!(
        issue(&offline_planner, false).approvals_required,
        0,
        "no dual control"
    );

    // Planned offline, as `host identity reset plan` keeps it; alice approves over the Host API.
    api.replay
        .plan(
            &crate::operations::mutation::Applying::for_tests(1),
            offline.plan.clone(),
        )
        .expect("kept");
    grant_to(
        ALICE,
        &[permguard_core::authz::operations::IDENTITY_ADMIN],
        &permguard_core::authz::Selector::under(permguard_core::authz::Resource::host())
            .to_string(),
    );
    api.approve_plan(
        &actor(ALICE),
        &offline.plan.plan_id,
        ApprovePlan {
            request_id: "offline-a1".to_owned(),
        },
    )
    .await
    .expect("one approval");
    let refused = held_plan(
        &api.replay,
        &offline_planner,
        &offline.envelope,
        now,
        &Standing::offline(),
    )
    .expect_err("one approver does not complete dual control alone");
    assert_eq!(code(&refused), codes::host::PLAN_APPROVALS_MISSING);
}

/// A receipt is its Host identity's: the plan an identity reset ran names the identity it
/// retired, and after the restart it runs nothing on the one provisioned in its place, even when
/// its consumption was lost and the new identity is at the same epoch.
#[tokio::test]
async fn a_receipt_of_another_host_identity_runs_nothing() {
    let api = facade_with("plans-identity", vec![HOST_OPERATIONS]);
    let signer = api
        .keys
        .rings()
        .iter()
        .find(|ring| ring.id() == HOST_OPERATIONS)
        .cloned()
        .expect("the operations ring");
    let now = api.time.now_secs();
    let planner = Principal::new("sa:planner").expect("a principal");
    let this = api.identity.as_ref().expect("an identity").host_id();
    let retired = {
        let mut other = this;
        other[15] ^= 1;
        other
    };
    let issue = |host_id: [u8; 16]| {
        let issued = sign_plan(
            Some(signer.as_ref() as &dyn plan::PlanSigner),
            Issue {
                kind: plan::IDENTITY_RESET,
                internal: plan::IDENTITY_RESET,
                stored_target: "emergency\n".to_owned(),
                target: "host".to_owned(),
                revision: 1,
                parameters: &[("mode", "emergency")],
                principal: &planner,
            },
            host_id,
            false,
            now,
        )
        .expect("signed");
        api.replay
            .plan(
                &crate::operations::mutation::Applying::for_tests(1),
                issued.plan.clone(),
            )
            .expect("kept");
        issued
    };
    let before_the_reset = issue(retired);
    let refused = api
        .presented_plan(&planner, &before_the_reset.receipt, now)
        .expect_err("a receipt of the retired identity");
    assert_eq!(code(&refused), codes::host::PLAN_UNKNOWN);
    // The plan is held and would be presented, were the identity not compared.
    held_plan(
        &api.replay,
        &planner,
        &before_the_reset.envelope,
        now,
        &api.standing(),
    )
    .expect("held, unconsumed, complete");
    let own = issue(this);
    api.presented_plan(&planner, &own.receipt, now)
        .expect("a receipt of this identity is presented");
}

/// The standing of every token the tests' bearers present, which a test revokes at will.
#[derive(Default)]
struct Tokens {
    revoked: std::sync::atomic::AtomicBool,
    not_held: std::sync::atomic::AtomicBool,
}

impl TokenStanding for Tokens {
    fn standing(&self, _uri: &str, _index: u64, _now: u64) -> Option<bool> {
        use std::sync::atomic::Ordering::SeqCst;
        if self.not_held.load(SeqCst) {
            return None;
        }
        Some(!self.revoked.load(SeqCst))
    }
}

/// BUG-0099: an approval stands while it is younger than the approval ttl and, made with an
/// access token, while the token is `VALID`; a list not held reads as not standing; offline the
/// ttl alone bounds it.
#[test]
fn an_approval_stands_for_its_ttl_and_while_its_token_is_valid() {
    let approval = |approved_at: u64, token: bool| PlanApproval {
        principal: SECOND.to_owned(),
        approved_at,
        envelope: String::new(),
        operation_id: String::new(),
        token: token.then(|| TokenEntry {
            uri: "https://authority.test/l".to_owned(),
            index: 7,
        }),
    };
    let tokens = Tokens::default();
    let standing = Standing {
        ttl: std::time::Duration::from_secs(3_600),
        tokens: Some(&tokens),
    };
    assert!(standing.stands(&approval(1_000, true), 1_000 + 3_599));
    assert!(
        !standing.stands(&approval(1_000, true), 1_000 + 3_600),
        "aged out"
    );
    assert!(
        standing.stands(&approval(1_000, false), 1_000 + 3_599),
        "by certificate"
    );
    assert!(!standing.stands(&approval(1_000, false), 1_000 + 3_600));
    tokens
        .revoked
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(!standing.stands(&approval(1_000, true), 1_001), "revoked");
    assert!(standing.stands(&approval(1_000, false), 1_001));
    tokens
        .revoked
        .store(false, std::sync::atomic::Ordering::SeqCst);
    tokens
        .not_held
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(
        !standing.stands(&approval(1_000, true), 1_001),
        "no list held"
    );
    let offline = Standing::offline();
    assert!(offline.stands(&approval(1_000, true), 1_000 + 3_599));
    assert!(!offline.stands(&approval(1_000, true), 1_000 + 3_600));
    // Two approvals of one principal count once.
    let plan = Plan {
        approvals: vec![approval(1_000, false), approval(1_001, false)],
        ..Plan::default()
    };
    assert_eq!(standing.count(&plan, 1_002), 1);
}

/// BUG-0099: an approval whose approver's token was revoked no longer counts: the run is refused
/// `plan_approvals_missing`, naming the lapse, the plan is listed `pending` with the approval
/// `lapsed`, and a fresh approval with the same revoked token does not stand either.
#[tokio::test]
async fn an_approval_lapses_when_its_approvers_token_is_revoked() {
    let tokens = Arc::new(Tokens::default());
    let api = regulated(facade_with(
        "plans-lapsed",
        vec![HOST_OPERATIONS, DATA_ATTEST],
    ))
    .with_approvals(
        DEFAULT_APPROVAL_TTL,
        Arc::clone(&tokens) as Arc<dyn TokenStanding>,
    );
    let planned = plan_key(&api, DATA_ATTEST, "k").await.expect("planned");
    grant(SECOND, &[operations::KEYS_ADMIN]);
    let approve = |request_id: &str| ApprovePlan {
        request_id: request_id.to_owned(),
    };
    let approved = api
        .approve_plan(&actor(SECOND), &planned.plan_id, approve("a1"))
        .await
        .expect("approved");
    assert_eq!(approved.plan.status, "ready");
    assert!(!approved.plan.approvals[0].lapsed);

    tokens
        .revoked
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let refused = run_key(&api, &admin(), DATA_ATTEST, "r1", &planned.receipt)
        .await
        .expect_err("the approval lapsed");
    assert_eq!(code(&refused), codes::host::PLAN_APPROVALS_MISSING);
    assert!(
        format!("{refused:?}").contains("lapsed"),
        "the refusal names the lapse: {refused:?}"
    );
    let listed = api.plans(&admin(), None).expect("listed");
    let plan = listed
        .plans
        .iter()
        .find(|plan| plan.plan_id == planned.plan_id)
        .expect("listed");
    assert_eq!(plan.status, "pending");
    assert!(plan.approvals[0].lapsed, "{plan:?}");

    // The approver may approve again; with the token still revoked, it does not stand.
    let again = api
        .approve_plan(&actor(SECOND), &planned.plan_id, approve("a2"))
        .await
        .expect("a lapsed approval can be given again");
    assert_eq!(again.plan.status, "pending");

    // Once the token stands again, so do its approvals, and the run proceeds.
    tokens
        .revoked
        .store(false, std::sync::atomic::Ordering::SeqCst);
    run_key(&api, &admin(), DATA_ATTEST, "r2", &planned.receipt)
        .await
        .expect("approved and run");
}
