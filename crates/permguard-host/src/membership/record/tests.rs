// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use permguard_objects::cbor::{self, Value};

use super::*;

fn host(byte: u8) -> HostRef {
    let mut host_id = [byte; 16];
    host_id[6] = (host_id[6] & 0x0F) | 0x70;
    host_id[8] = (host_id[8] & 0x3F) | 0x80;
    HostRef {
        host_id,
        epoch: 1,
        fingerprint: format!("sha256:{}", "ab".repeat(32)),
    }
}

fn limits() -> Limits {
    Limits {
        max_body_bytes: 1024,
        max_concurrency: 2,
        max_rate_per_minute: 60,
        max_batch_records: 10,
        retention_seconds: 3600,
    }
}

pub(crate) fn task(id: &str, task_type: TaskType, selector: &str) -> Task {
    Task {
        task_id: id.to_owned(),
        task_type,
        selector: Selector::parse(selector).expect("a selector"),
        resource_types: vec!["decision".to_owned()],
        required: true,
        limits: limits(),
        assurance_requirements: Vec::new(),
    }
}

fn policy() -> LeasePolicy {
    LeasePolicy {
        max_session_seconds: 3600,
        offline_grace_seconds: 600,
        clock_skew_seconds: 30,
        dormant_after_seconds: 86_400,
        revoke_after_seconds: 2 * 86_400,
    }
}

fn manifest(epoch: u64) -> Manifest {
    Manifest {
        membership_id: host(0x44).host_id,
        coordinator: host(0x11),
        member: host(0x22),
        selector: Selector::parse("plane/data/*").expect("a selector"),
        tasks: vec![task("decisions", TaskType::DecisionsShip, "plane/data/*")],
        member_assurance: AssuranceProfile::Production,
        min_assurance: Some(AssuranceProfile::Development),
        ring_pins: vec![RingPin {
            owner: Role::Coordinator,
            ring: "host.operations".to_owned(),
            epoch: 3,
            key_set_digest: [9; 32],
            binding: vec![0x80],
        }],
        epoch,
        lease_policy: policy(),
        previous: (epoch > 1).then(|| Digest::compute(b"previous")),
        issued_at: 10,
        not_after: 20,
        status: Status::Active,
    }
}

/// Adds the label 99 to the top-level map of `bytes`.
fn foreign(bytes: &[u8]) -> Vec<u8> {
    let mut value = cbor::decode_canonical(bytes).expect("canonical");
    if let Value::Map(pairs) = &mut value {
        pairs.push((Value::Int(99), Value::Int(0)));
    }
    cbor::encode(&value).expect("encodes")
}

#[test]
fn every_record_reads_back_and_refuses_a_foreign_label() {
    let statement = RingStatement {
        ring: "data.attest".to_owned(),
        epoch: 1,
        suite: Suite::Ed25519Sha256V1,
        keys: vec!["{}".to_owned()],
        binding: vec![0x80],
    };
    let pending = Pending {
        membership_id: host(0x44).host_id,
        invite_id: host(0x33).host_id,
        coordinator: host(0x11),
        member: host(0x22),
        selector: Selector::parse("plane/data/*").expect("a selector"),
        tasks: vec![task("decisions", TaskType::DecisionsShip, "plane/data/*")],
        member_assurance: AssuranceProfile::Production,
        ring_statements: vec![statement.clone()],
        requested_at: 5,
        coordinator_address: Some("https://coordinator:7443".to_owned()),
        identity: Some(vec![0xA0]),
    };
    let request = EnrollRequest {
        invite_id: host(0x33).host_id,
        token_proof: [1; 64],
        selector: Selector::parse("plane/data/*").expect("a selector"),
        tasks: vec![task("decisions", TaskType::DecisionsShip, "plane/data/*")],
        member: host(0x22),
        ring_statements: vec![statement],
    };
    let invitation = Invitation {
        invite_id: host(0x33).host_id,
        token_key: [2; 32],
        selector: Selector::parse("plane/data/*").expect("a selector"),
        tasks: vec![task("decisions", TaskType::DecisionsShip, "plane/data/*")],
        expires: 9,
        expected_fingerprint: None,
        min_assurance: Some(AssuranceProfile::Production),
        max_uses: 1,
        created_at: 1,
        created_by: "operator".to_owned(),
    };
    let entry = Entry {
        seq: 1,
        kind: Kind::Orphaned,
        subject: host(0x44).host_id,
        epoch: Some(2),
        at: 3,
        operation_id: Some([5; 16]),
        previous: chain(None),
        detail: None,
        statements: Vec::new(),
    };
    let membership = MembershipRequest {
        action: Action::Revoke,
        membership_id: host(0x44).host_id,
        held_epoch: Some(3),
    };
    let answer = MembershipAnswer {
        status: Status::Suspended,
        manifests: vec![vec![0x80]],
        ring_statements: Vec::new(),
    };
    let enroll_answer = EnrollAnswer {
        membership_id: host(0x44).host_id,
        status: Status::Pending,
    };

    let manifest = manifest(2);
    assert_eq!(
        Manifest::decode(&manifest.encode().expect("e")).expect("d"),
        manifest
    );
    assert_eq!(
        Pending::decode(&pending.encode().expect("e")).expect("d"),
        pending
    );
    assert_eq!(
        EnrollRequest::decode(&request.encode().expect("e")).expect("d"),
        request
    );
    assert_eq!(
        Invitation::decode(&invitation.encode().expect("e")).expect("d"),
        invitation
    );
    assert_eq!(
        Entry::decode(&entry.encode().expect("e")).expect("d"),
        entry
    );
    assert_eq!(
        MembershipRequest::decode(&membership.encode().expect("e")).expect("d"),
        membership
    );
    assert_eq!(
        MembershipAnswer::decode(&answer.encode().expect("e")).expect("d"),
        answer
    );
    assert_eq!(
        EnrollAnswer::decode(&enroll_answer.encode().expect("e")).expect("d"),
        enroll_answer
    );

    assert!(Manifest::decode(&foreign(&manifest.encode().expect("e"))).is_err());
    assert!(Pending::decode(&foreign(&pending.encode().expect("e"))).is_err());
    assert!(EnrollRequest::decode(&foreign(&request.encode().expect("e"))).is_err());
    assert!(Invitation::decode(&foreign(&invitation.encode().expect("e"))).is_err());
    assert!(Entry::decode(&foreign(&entry.encode().expect("e"))).is_err());
    assert!(MembershipRequest::decode(&foreign(&membership.encode().expect("e"))).is_err());
    assert!(MembershipAnswer::decode(&foreign(&answer.encode().expect("e"))).is_err());
    assert!(EnrollAnswer::decode(&foreign(&enroll_answer.encode().expect("e"))).is_err());
}

#[test]
fn a_task_type_carries_its_roles_and_an_unknown_one_is_refused() {
    assert_eq!(TaskType::PolicyMirror.provider(), Role::Coordinator);
    assert_eq!(TaskType::DecisionsShip.provider(), Role::Member);
    assert_eq!(TaskType::EventsShip.provider(), Role::Member);
    assert_eq!(TaskType::EventsImport.provider(), Role::Coordinator);
    assert_eq!(TaskType::AuditCheckpoints.provider(), Role::Member);
    assert_eq!(TaskType::ZoneSecrets.provider(), Role::Coordinator);
    for task in TaskType::ALL {
        assert_ne!(task.provider(), task.consumer());
        assert_eq!(task.as_str().parse::<TaskType>().expect("reads"), task);
    }
    assert!("policy.push".parse::<TaskType>().is_err());

    // A task whose roles are not its type's is refused.
    let bytes = manifest(1).encode().expect("encodes");
    let mut value = cbor::decode_canonical(&bytes).expect("canonical");
    if let Value::Map(pairs) = &mut value
        && let Some((_, Value::Array(tasks))) =
            pairs.iter_mut().find(|(key, _)| *key == Value::Int(5))
        && let Value::Map(task) = &mut tasks[0]
        && let Some((_, role)) = task.iter_mut().find(|(key, _)| *key == Value::Int(3))
    {
        *role = Value::Text("coordinator".to_owned());
    }
    let swapped = cbor::encode(&value).expect("encodes");
    assert!(Manifest::decode(&swapped).is_err());
}

#[test]
fn only_the_transitions_of_the_table_are_allowed() {
    use Status::*;
    let all = [
        Pending, Active, Suspended, Revoked, Rejected, Expired, Orphaned,
    ];
    let allowed = [
        (Pending, Active),
        (Pending, Rejected),
        (Pending, Expired),
        (Active, Suspended),
        (Active, Expired),
        (Active, Revoked),
        (Active, Active),
        (Suspended, Active),
        (Suspended, Expired),
        (Suspended, Revoked),
        (Pending, Orphaned),
        (Active, Orphaned),
        (Suspended, Orphaned),
    ];
    for from in all {
        for to in all {
            assert_eq!(
                from.allows(to),
                allowed.contains(&(from, to)),
                "{from} → {to}"
            );
        }
    }
    for terminal in [Revoked, Rejected, Expired, Orphaned] {
        assert!(terminal.is_terminal());
    }
}

#[test]
fn a_manifest_names_its_predecessor_except_at_genesis_and_a_lease_policy_orders_its_clocks() {
    let mut genesis = manifest(1);
    genesis.previous = Some(Digest::compute(b"x"));
    assert!(Manifest::decode(&genesis.encode().expect("encodes")).is_err());
    let mut orphan = manifest(2);
    orphan.previous = None;
    assert!(Manifest::decode(&orphan.encode().expect("encodes")).is_err());

    let mut inverted = manifest(1);
    inverted.lease_policy.revoke_after_seconds = inverted.lease_policy.dormant_after_seconds;
    assert!(Manifest::decode(&inverted.encode().expect("encodes")).is_err());
}

#[test]
fn limits_narrow_field_by_field() {
    let wide = limits();
    let mut narrow = limits();
    narrow.max_concurrency = 1;
    assert!(narrow.within(&wide));
    narrow.retention_seconds = wide.retention_seconds + 1;
    assert!(!narrow.within(&wide));
}
