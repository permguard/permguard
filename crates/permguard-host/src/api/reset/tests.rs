// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use super::*;
use crate::api::members::tests::{enrolled, task_view};
use crate::api::members::{ApproveMember, TaskView};
use crate::api::testing::{admin, reopen, scratch};
use crate::keys::ring::HOST_OPERATIONS;
use crate::membership::record::Pending;
use crate::membership::tests::{Host, decisions};
use crate::operations::mutation::Applying;

fn code(refusal: &Refusal) -> &str {
    refusal.error().expect("a domain refusal").code()
}

fn plan(request_id: &str, mode: &str) -> PlanIdentityReset {
    PlanIdentityReset {
        request_id: request_id.to_owned(),
        mode: mode.to_owned(),
        reason: "the identity key is believed compromised".to_owned(),
    }
}

fn run(request_id: &str, planned: &IdentityResetPlan) -> RunIdentityReset {
    RunIdentityReset {
        request_id: request_id.to_owned(),
        plan_id: planned.plan_id.clone(),
        plan_digest: planned.plan_digest.clone(),
    }
}

/// A membership this facade's Host is a member of, its coordinator `coordinator`, which nobody
/// reaches: the facade composes no peer client.
fn joined(api: &HostApi, coordinator: &Host) -> [u8; 16] {
    let identity = api.identity.as_deref().expect("an identity");
    let mut membership_id = [0x5c; 16];
    membership_id[6] = 0x70 | (membership_id[6] & 0x0F);
    membership_id[8] = 0x80 | (membership_id[8] & 0x3F);
    let _: TaskView = task_view();
    api.memberships
        .as_deref()
        .expect("memberships")
        .store
        .join(
            &Applying::for_tests(80),
            &Pending {
                membership_id,
                invite_id: [0x6c; 16],
                coordinator: coordinator.host_ref(),
                member: crate::membership::record::HostRef {
                    host_id: identity.host_id(),
                    epoch: identity.epoch(),
                    fingerprint: identity.first_fingerprint().to_owned(),
                },
                selector: permguard_core::authz::Selector::parse("plane/data/*")
                    .expect("a selector"),
                tasks: vec![decisions("plane/data/*")],
                member_assurance: permguard_core::assurance::AssuranceProfile::Production,
                ring_statements: Vec::new(),
                requested_at: crate::authz::store::now(),
                coordinator_address: Some("https://coordinator.invalid:7443".to_owned()),
                identity: None,
            },
            crate::authz::store::now(),
        )
        .expect("joined");
    membership_id
}

#[tokio::test]
async fn a_normal_reset_refuses_while_a_coordinator_is_unreached_and_an_emergency_one_completes() {
    let root = scratch("reset");
    let (api, _, _volume) = reopen(&root, vec![HOST_OPERATIONS]);
    let old = api.identity.as_deref().expect("an identity").host_id_text();

    // What this Host coordinates: one active membership, one pending; and one it is a member of.
    let active = Host::new("reset-active");
    let (active_id, _) = enrolled(&api, &active, "enrol-1").await;
    let revision = api.member(&admin(), &active_id).expect("read").revision;
    api.approve_member(
        &admin(),
        &active_id,
        ApproveMember {
            request_id: "approve-1".to_owned(),
            expected_revision: revision,
            narrow: None,
            lease_policy: None,
            assurance: None,
        },
    )
    .await
    .expect("approved");
    let waiting = Host::new("reset-pending");
    let (pending_id, _) = enrolled(&api, &waiting, "enrol-2").await;
    let coordinator = Host::new("reset-coordinator");
    let member_id = uuid_text(&joined(&api, &coordinator));

    let planned = api
        .plan_identity_reset(&admin(), plan("plan-1", "normal"))
        .await
        .expect("planned");
    let steps: Vec<(&str, &str)> = planned
        .memberships
        .iter()
        .map(|held| (held.membership_id.as_str(), held.step.as_str()))
        .collect();
    for (id, step) in [
        (active_id.as_str(), "revoke_local"),
        (pending_id.as_str(), "reject_local"),
        (member_id.as_str(), "revoke_remote"),
    ] {
        assert!(steps.contains(&(id, step)), "{id} {step}: {steps:?}");
    }

    // Normal: the coordinator nobody reaches is named, and nothing changed.
    let refused = api
        .run_identity_reset(&admin(), run("run-1", &planned))
        .await
        .expect_err("a coordinator did not acknowledge");
    assert_eq!(code(&refused), codes::host::IDENTITY_RESET_INCOMPLETE);
    let message = refused.error().expect("an error").to_string();
    assert!(
        message.contains(&coordinator.identity.host_id_text()),
        "{message}"
    );
    assert!(!api.identity.as_deref().expect("an identity").is_retired());
    assert_eq!(
        api.member(&admin(), &active_id).expect("read").status,
        "active"
    );

    // A plan the memberships moved past is refused.
    let stale = api
        .plan_identity_reset(&admin(), plan("plan-2", "emergency"))
        .await
        .expect("planned");
    let late = Host::new("reset-late");
    enrolled(&api, &late, "enrol-3").await;
    let moved = api
        .run_identity_reset(&admin(), run("run-2", &stale))
        .await
        .expect_err("the memberships moved");
    assert_eq!(code(&moved), codes::host::REVISION_MISMATCH);

    // Emergency: the unreached membership orphaned and named, the coordinated ones ended here,
    // the identity reset.
    let planned = api
        .plan_identity_reset(&admin(), plan("plan-3", "emergency"))
        .await
        .expect("planned");
    let done = api
        .run_identity_reset(&admin(), run("run-3", &planned))
        .await
        .expect("reset");
    assert_eq!(done.old_host_id, old);
    assert_ne!(done.host_id, old);
    assert!(done.restart_required);
    assert_eq!(done.orphaned.len(), 1);
    assert_eq!(done.orphaned[0].membership_id, member_id);
    assert_eq!(
        done.orphaned[0].coordinator.host_id,
        coordinator.identity.host_id_text()
    );
    let ended: Vec<(&str, &str)> = done
        .ended
        .iter()
        .map(|held| (held.membership_id.as_str(), held.status.as_str()))
        .collect();
    assert!(
        ended.contains(&(active_id.as_str(), "revoked")),
        "{ended:?}"
    );
    assert!(
        ended.contains(&(pending_id.as_str(), "rejected")),
        "{ended:?}"
    );
    assert_eq!(ended.len(), 3, "the late pending one too: {ended:?}");

    // The retry answers what the run answered; the process signs and serves nothing more.
    let again = api
        .run_identity_reset(&admin(), run("run-3", &planned))
        .await
        .expect("replayed");
    assert_eq!(again, done);
    assert!(api.identity.as_deref().expect("an identity").is_retired());
    assert_eq!(
        code(&api.identity(&admin()).expect_err("retired")),
        codes::host::IDENTITY_UNAVAILABLE
    );
    assert_eq!(
        code(
            &api.plan_identity_reset(&admin(), plan("plan-4", "normal"))
                .await
                .expect_err("retired")
        ),
        codes::host::IDENTITY_UNAVAILABLE
    );
    let listed = api.members(&admin(), None).expect("listed");
    assert!(
        listed
            .members
            .iter()
            .all(|held| matches!(held.status.as_str(), "revoked" | "rejected" | "orphaned")),
        "every membership ended"
    );
}

#[tokio::test]
async fn a_reset_plan_is_refused_without_its_grant_or_with_an_unknown_mode() {
    let root = scratch("reset-gates");
    let (api, _, _volume) = reopen(&root, vec![HOST_OPERATIONS]);
    assert!(matches!(
        api.plan_identity_reset(
            &crate::api::testing::actor("spiffe://acme/stranger"),
            plan("p", "normal")
        )
        .await,
        Err(Refusal::Denied(_))
    ));
    assert_eq!(
        code(
            &api.plan_identity_reset(&admin(), plan("p", "gentle"))
                .await
                .expect_err("no such mode")
        ),
        codes::common::INVALID_ARGUMENT
    );
    let unknown = api
        .run_identity_reset(
            &admin(),
            RunIdentityReset {
                request_id: "r".to_owned(),
                plan_id: "11".repeat(16),
                plan_digest: "00".repeat(32),
            },
        )
        .await
        .expect_err("no such plan");
    assert_eq!(code(&unknown), codes::host::PLAN_UNKNOWN);
}
