// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use std::sync::Arc;

use super::*;

fn receipt() -> PlanReceipt {
    PlanReceipt {
        plan_id: [1; 16],
        operation: KEYS_REVOKE.to_owned(),
        target: "host.operations:kid".to_owned(),
        revision: 3,
        principal: "spiffe://acme/operators/root".to_owned(),
        plan_digest: plan_digest(
            KEYS_REVOKE,
            "host.operations:kid",
            3,
            &[("reason", "drill")],
        ),
        expires: 1_800_000_600,
        nonce: [2; 16],
        approvals_required: 1,
        host_id: [3; 16],
        created_at: 1_800_000_000,
    }
}

#[test]
fn a_receipt_round_trips_and_refuses_what_it_does_not_name() {
    let receipt = receipt();
    let bytes = receipt.encode().expect("encodes");
    assert_eq!(PlanReceipt::decode(&bytes).expect("decodes"), receipt);
    let Value::Map(mut pairs) = cbor::decode_canonical(&bytes).expect("cbor") else {
        panic!("a map")
    };
    let mut extra = pairs.clone();
    extra.push((Value::Int(12), Value::Int(0)));
    assert!(PlanReceipt::decode(&cbor::encode(&Value::Map(extra)).expect("cbor")).is_err());
    pairs.retain(|(key, _)| *key != Value::Int(8));
    let refused = PlanReceipt::decode(&cbor::encode(&Value::Map(pairs)).expect("cbor"));
    assert!(
        matches!(&refused, Err(RecordError::Malformed(m)) if m.contains("label 8 is required")),
        "{refused:?}"
    );
    let mut other = receipt;
    other.operation = "catalog.delete".to_owned();
    assert!(PlanReceipt::decode(&other.encode().expect("encodes")).is_err());
}

#[test]
fn an_approval_round_trips() {
    let approval = Approval {
        plan_digest: receipt().plan_digest,
        principal: "spiffe://acme/operators/second".to_owned(),
        approved_at: 1_800_000_100,
        host_id: [3; 16],
    };
    let bytes = approval.encode().expect("encodes");
    assert_eq!(Approval::decode(&bytes).expect("decodes"), approval);
}

#[test]
fn the_plan_digest_binds_the_operation_target_revision_and_parameters() {
    let base = plan_digest(KEYS_REVOKE, "t", 3, &[("reason", "drill")]);
    assert_eq!(
        base,
        plan_digest(KEYS_REVOKE, "t", 3, &[("reason", "drill")])
    );
    for other in [
        plan_digest(GRANT_REVOKE, "t", 3, &[("reason", "drill")]),
        plan_digest(KEYS_REVOKE, "u", 3, &[("reason", "drill")]),
        plan_digest(KEYS_REVOKE, "t", 4, &[("reason", "drill")]),
        plan_digest(KEYS_REVOKE, "t", 3, &[("reason", "drills")]),
        plan_digest(KEYS_REVOKE, "t", 3, &[]),
    ] {
        assert_ne!(base, other);
    }
}

#[test]
fn a_plan_requiring_approvals_lives_a_day() {
    assert_eq!(approvals_required(IDENTITY_RESET, true), 1);
    assert_eq!(approvals_required(KEYS_REVOKE, true), 1);
    assert_eq!(approvals_required(GRANT_REVOKE, true), 0);
    assert_eq!(approvals_required(MEMBERSHIP_REVOKE, true), 0);
    for operation in OPERATIONS {
        assert_eq!(approvals_required(operation, false), 0);
    }
    assert_eq!(lifetime(0), Duration::from_secs(600));
    assert_eq!(lifetime(1), Duration::from_secs(86_400));
}

#[test]
fn a_receipt_signed_by_host_operations_verifies_with_its_published_keys() {
    use crate::keys::ring::{Policy, directory, export};
    use permguard_core::KeyManager as _;

    let root = std::env::temp_dir().join(format!(
        "permguard-host-plan-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let volume = crate::storage::volume::Volume::claim(
        &root,
        permguard_core::assurance::AssuranceProfile::Development,
    )
    .expect("claimed");
    let time = Arc::new(crate::time::TimeGuard::system(Duration::from_secs(30)));
    let ring = Ring::open(
        &volume,
        HOST_OPERATIONS,
        permguard_objects::crypto::suite::Suite::Ed25519Sha256V1,
        Policy {
            publish_ahead: Duration::from_secs(600),
            rotate_every: Duration::from_secs(86_400),
            retain: Duration::from_secs(86_400),
        },
        time,
    )
    .expect("the ring opens");
    ring.maintain().expect("the first key");
    let receipt = receipt();
    let envelope = ring.sign_receipt(&receipt).expect("signed");
    let approval = Approval {
        plan_digest: receipt.plan_digest.clone(),
        principal: "spiffe://acme/operators/second".to_owned(),
        approved_at: 1_800_000_100,
        host_id: [3; 16],
    };
    let attested = ring.sign_approval(&approval).expect("signed");
    let keys = Keys::from_document(
        &export(directory(&volume, HOST_OPERATIONS).expect("dir").path()).expect("exported"),
    )
    .expect("the keys read");
    assert_eq!(verify_receipt(&keys, &envelope).expect("verifies"), receipt);
    assert_eq!(read_receipt(&envelope).expect("reads"), receipt);
    assert_eq!(
        verify_approval(&keys, &attested).expect("verifies"),
        approval
    );
    // One is never taken for the other.
    assert!(verify_receipt(&keys, &attested).is_err());
    assert!(read_receipt(&attested).is_err());
    // Another ring signs neither.
    let other = Ring::open(
        &volume,
        crate::keys::ring::DATA_ATTEST,
        permguard_objects::crypto::suite::Suite::Ed25519Sha256V1,
        Policy {
            publish_ahead: Duration::from_secs(600),
            rotate_every: Duration::from_secs(86_400),
            retain: Duration::from_secs(86_400),
        },
        Arc::new(crate::time::TimeGuard::system(Duration::from_secs(30))),
    )
    .expect("the ring opens");
    other.maintain().expect("the first key");
    assert!(other.sign_receipt(&receipt).is_err());
    assert!(other.sign_approval(&approval).is_err());
    drop(volume);
    let _ = std::fs::remove_dir_all(root);
}
