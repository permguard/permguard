// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use std::sync::Arc;

use super::*;
use crate::api::testing::{Recording, actor, admin, facade_with, reopen_with, scratch};
use crate::keys::ring::{CONTROL_ATTEST, DATA_ATTEST};

fn code(refusal: &Refusal) -> &str {
    refusal.error().expect("a domain refusal").code()
}

#[test]
fn the_ring_is_public_with_its_epoch_digest_and_binding_and_the_list_is_gated() {
    let api = facade_with("keys", vec![DATA_ATTEST]);
    let view = api.ring(DATA_ATTEST).expect("public");
    assert_eq!(view.keys.len(), 1);
    assert!(view.keys[0].kid.starts_with("data.attest:"));
    assert_eq!(view.epoch, Some(1));
    assert_eq!(view.cache_max_age, 300);
    assert_eq!(view.digest.len(), 64);
    let binding = URL_SAFE_NO_PAD
        .decode(view.binding.as_deref().expect("bound"))
        .expect("base64url");
    let payload = crate::keys::record::Binding::decode(
        permguard_objects::cose::Sign1::decode(&binding)
            .expect("cose")
            .payload_unverified(),
    )
    .expect("a binding");
    assert_eq!(hex(&payload.key_set_digest), view.digest);
    assert_eq!(payload.epoch, 1);

    let identity = api.ring(HOST_IDENTITY).expect("the identity ring");
    assert!(identity.binding.is_none(), "its chain authenticates it");
    assert!(identity.keys[0].kid.starts_with("host.identity:"));

    let unknown = api.ring("nope").expect_err("unknown");
    assert_eq!(code(&unknown), codes::host::RING_UNKNOWN);
    let rings = api.rings(&admin()).expect("the administrator lists");
    let names: Vec<&str> = rings.rings.iter().map(|ring| ring.ring.as_str()).collect();
    assert_eq!(names, vec![HOST_IDENTITY, DATA_ATTEST]);
    assert_eq!(rings.rings[1].digest, view.digest);
    assert_eq!(rings.rings[1].epoch, 1);
    // `keys.read` is public on the test facade too: the list admits anonymous.
    assert!(api.rings(&Actor::Anonymous).is_ok());
    assert!(api.rings(&actor("spiffe://acme/other")).is_ok());
}

fn rotate(request_id: &str, expected_epoch: u64) -> RotateRing {
    RotateRing {
        request_id: request_id.to_owned(),
        expected_epoch,
    }
}

#[tokio::test]
async fn a_rotation_needs_keys_admin_states_its_epoch_and_is_replayed() {
    let trail = Arc::new(Recording::default());
    let (api, _, volume) =
        reopen_with(&scratch("keys-rotate"), vec![CONTROL_ATTEST], trail.clone());
    std::mem::forget(volume);
    let refused = api
        .rotate_ring(
            &actor("spiffe://acme/nobody"),
            CONTROL_ATTEST,
            rotate("r1", 1),
        )
        .await
        .expect_err("no grant");
    assert!(matches!(refused, Refusal::Denied(_)));
    let refused = api
        .rotate_ring(&admin(), HOST_IDENTITY, rotate("r1", 1))
        .await
        .expect_err("the identity rotates elsewhere");
    assert_eq!(code(&refused), codes::host::RING_NOT_MUTABLE);
    let stale = api
        .rotate_ring(&admin(), CONTROL_ATTEST, rotate("r0", 5))
        .await
        .expect_err("a stale epoch");
    assert!(matches!(stale, Refusal::Conflict { revision: 1, .. }));

    let rotated = api
        .rotate_ring(&admin(), CONTROL_ATTEST, rotate("r1", 1))
        .await
        .expect("rotated");
    assert_eq!(rotated.receipt.revision, 2);
    assert!(rotated.kid.starts_with("control.attest:"));
    let again = api
        .rotate_ring(&admin(), CONTROL_ATTEST, rotate("r1", 1))
        .await
        .expect("replayed");
    assert_eq!(again, rotated, "the stored answer, not a second rotation");
    let pending = api
        .rotate_ring(&admin(), CONTROL_ATTEST, rotate("r2", 2))
        .await
        .expect_err("a successor waits");
    assert_eq!(code(&pending), codes::host::KEY_ROTATION_PENDING);

    let view = api.ring(CONTROL_ATTEST).expect("public");
    assert_eq!(view.epoch, Some(2));
    assert!(view.keys.iter().any(|key| key.kid == rotated.kid));
    let phases: Vec<_> = trail
        .events
        .lock()
        .expect("lock")
        .iter()
        .filter(|record| record.0 == AUDIT_ROTATED)
        .map(|record| (record.2.clone(), record.3))
        .collect();
    assert_eq!(
        phases,
        vec![
            (Some("control.attest:epoch:2".to_owned()), Some("intent")),
            (Some("control.attest:epoch:2".to_owned()), Some("applied")),
        ]
    );
}

fn plan(request_id: &str, kid: &str, reason: &str) -> PlanKeyRevoke {
    PlanKeyRevoke {
        request_id: request_id.to_owned(),
        kid: kid.to_owned(),
        reason: reason.to_owned(),
        compromised_at: Some("2026-10-08T10:00:00Z".to_owned()),
        expected_epoch: None,
    }
}

#[tokio::test]
async fn a_revocation_is_planned_then_run_and_the_key_leaves_the_set() {
    let api = facade_with("keys-revoke", vec![DATA_ATTEST]);
    let kid = api.ring(DATA_ATTEST).expect("public").keys[0].kid.clone();

    for (name, bad) in [
        ("an empty reason", plan("p0", &kid, "")),
        ("a control character", plan("p0", &kid, "a\nb")),
        (
            "a compromise in the future",
            PlanKeyRevoke {
                compromised_at: Some("2999-01-01T00:00:00Z".to_owned()),
                ..plan("p0", &kid, "compromise")
            },
        ),
        (
            "a time that is not RFC 3339",
            PlanKeyRevoke {
                compromised_at: Some("yesterday".to_owned()),
                ..plan("p0", &kid, "compromise")
            },
        ),
    ] {
        let refused = api
            .plan_key_revoke(&admin(), DATA_ATTEST, bad)
            .await
            .expect_err(name);
        assert_eq!(code(&refused), codes::common::INVALID_ARGUMENT, "{name}");
    }
    let unknown = api
        .plan_key_revoke(&admin(), DATA_ATTEST, plan("p1", "data.attest:nope", "x"))
        .await
        .expect_err("no such key");
    assert_eq!(code(&unknown), codes::host::KEY_UNKNOWN);
    assert!(matches!(
        api.plan_key_revoke(
            &actor("spiffe://acme/nobody"),
            DATA_ATTEST,
            plan("p1", &kid, "x")
        )
        .await,
        Err(Refusal::Denied(_))
    ));

    let planned = api
        .plan_key_revoke(&admin(), DATA_ATTEST, plan("p2", &kid, "key-compromise"))
        .await
        .expect("planned");
    assert_eq!(planned.revision, 1);
    let mismatch = api
        .run_key_revoke(
            &admin(),
            DATA_ATTEST,
            RunKeyRevoke {
                request_id: "x1".to_owned(),
                plan_id: planned.plan_id.clone(),
                plan_digest: "0".repeat(64),
            },
        )
        .await
        .expect_err("another digest");
    assert_eq!(code(&mismatch), codes::host::PLAN_DIGEST_MISMATCH);
    let elsewhere = api
        .run_key_revoke(
            &admin(),
            CONTROL_ATTEST,
            RunKeyRevoke {
                request_id: "x2".to_owned(),
                plan_id: planned.plan_id.clone(),
                plan_digest: planned.plan_digest.clone(),
            },
        )
        .await
        .expect_err("a ring this process does not compose");
    assert_eq!(code(&elsewhere), codes::host::RING_UNKNOWN);

    let revoked = api
        .run_key_revoke(
            &admin(),
            DATA_ATTEST,
            RunKeyRevoke {
                request_id: "x3".to_owned(),
                plan_id: planned.plan_id.clone(),
                plan_digest: planned.plan_digest.clone(),
            },
        )
        .await
        .expect("revoked");
    assert_eq!(revoked.kid, kid);
    assert_eq!(revoked.receipt.revision, 2);
    let view = api.ring(DATA_ATTEST).expect("public");
    assert!(view.keys.iter().all(|key| key.kid != kid), "out at once");
    assert_eq!(view.keys.len(), 1, "an active replacement");
    assert_eq!(view.epoch, Some(3));

    let terminal = api
        .plan_key_revoke(&admin(), DATA_ATTEST, plan("p3", &kid, "again"))
        .await
        .expect_err("revoked already");
    assert_eq!(code(&terminal), codes::host::KEY_REVOKED);
}

#[test]
fn a_revocation_target_reads_back_as_planned() {
    let held = Revocation {
        ring: DATA_ATTEST.to_owned(),
        kid: "data.attest:k".to_owned(),
        reason: "key-compromise".to_owned(),
        compromised_at: Some(7),
    };
    let read = Revocation::parse(&held.target()).expect("parses");
    assert_eq!(
        (read.ring, read.kid, read.reason, read.compromised_at),
        (
            held.ring.clone(),
            held.kid.clone(),
            held.reason.clone(),
            Some(7)
        )
    );
    let none = Revocation {
        compromised_at: None,
        ..held
    };
    assert_eq!(
        Revocation::parse(&none.target())
            .expect("parses")
            .compromised_at,
        None
    );
    assert!(Revocation::parse("a\nb").is_none());
    assert!(Revocation::parse("a\nb\nc\nx").is_none());
    assert!(Revocation::parse("a\nb\nc\n\nextra").is_none());
}
