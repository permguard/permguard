// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use permguard_core::assurance::{Control, EvidenceClass};
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
        version: 1,
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
        assurance_binding: None,
        ring_pins: vec![RingPin {
            retiring: false,
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
        capabilities: crate::membership::tests::member_capabilities(),
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
        capabilities: crate::membership::tests::member_capabilities(),
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

/// A binding of `manifest(2)`'s member for its task: one declared claim, one approved.
fn binding() -> AssuranceBinding {
    let claims = vec![
        Claim {
            control: Control::CustodyEncrypted,
            class: EvidenceClass::Declared,
            by: "production".to_owned(),
            record: None,
        },
        Claim {
            control: Control::OperationsDualControl,
            class: EvidenceClass::OperatorApproved,
            by: "spiffe://acme/operators/root".to_owned(),
            record: Some(Digest::compute(b"approval")),
        },
    ];
    let task_ids = vec!["decisions".to_owned()];
    let policy_revision = Digest::compute(b"policy");
    AssuranceBinding {
        result_digest: result_digest(&host(0x22), &task_ids, &policy_revision, &claims)
            .expect("digested"),
        member: host(0x22),
        task_ids,
        policy_revision,
        claims,
        appraised_by: "spiffe://acme/operators/root".to_owned(),
        issued_at: 10,
        expires_at: 20,
        verdict: Verdict::Accepted,
    }
}

/// WP-4.2: a manifest's binding reads back, and what it does not name, or names wrongly, is
/// refused.
#[test]
fn a_binding_round_trips_and_refuses_what_it_does_not_name() {
    // The binding's task requires both controls it claims.
    let mut requiring = task("decisions", TaskType::DecisionsShip, "plane/data/*");
    requiring.assurance_requirements = vec![
        Control::CustodyEncrypted.name().to_owned(),
        Control::OperationsDualControl.name().to_owned(),
    ];
    let with = |binding: AssuranceBinding| Manifest {
        assurance_binding: Some(binding),
        tasks: vec![requiring.clone()],
        ..manifest(2)
    };
    let held = with(binding());
    let bytes = held.encode().expect("encodes");
    assert_eq!(Manifest::decode(&bytes).expect("reads back"), held);
    let refused = |binding: AssuranceBinding, why: &str| {
        let bytes = with(binding).encode().expect("encodes");
        assert!(Manifest::decode(&bytes).is_err(), "{why}");
    };
    // Its digest is over what it says, recomputed.
    refused(
        AssuranceBinding {
            result_digest: Digest::compute(b"other"),
            ..binding()
        },
        "a result digest of something else",
    );
    // A binding names the manifest's own member and tasks it grants.
    let mut other = binding();
    other.member = host(0x33);
    other.result_digest = result_digest(
        &other.member,
        &other.task_ids,
        &other.policy_revision,
        &other.claims,
    )
    .expect("digested");
    refused(other, "another member");
    let mut ungranted = binding();
    ungranted.task_ids = vec!["events".to_owned()];
    ungranted.result_digest = result_digest(
        &ungranted.member,
        &ungranted.task_ids,
        &ungranted.policy_revision,
        &ungranted.claims,
    )
    .expect("digested");
    refused(ungranted, "a task the manifest does not grant");
    // A task that requires no control is never in a binding.
    let unrequiring = Manifest {
        assurance_binding: Some(binding()),
        ..manifest(2)
    };
    assert!(Manifest::decode(&unrequiring.encode().expect("encodes")).is_err());
    // Claims sorted by name, each once; a declaration has no record and nothing else lacks one.
    let resealed = |mut binding: AssuranceBinding| {
        binding.result_digest = result_digest(
            &binding.member,
            &binding.task_ids,
            &binding.policy_revision,
            &binding.claims,
        )
        .expect("digested");
        binding
    };
    let mut unsorted = binding();
    unsorted.claims.reverse();
    refused(resealed(unsorted), "claims out of order");
    let mut twice = binding();
    twice.claims[1] = twice.claims[0].clone();
    refused(resealed(twice), "a control claimed twice");
    let mut recorded = binding();
    recorded.claims[0].record = Some(Digest::compute(b"x"));
    refused(resealed(recorded), "a declaration with a record");
    let mut bare = binding();
    bare.claims[1].record = None;
    refused(resealed(bare), "an approval without its record");
    // A claim spells its control and class exactly: a record has one encoding.
    for (control, class) in [
        (" custody.encrypted", "declared"),
        (Control::CustodyEncrypted.name(), "declared "),
    ] {
        let bytes = with(binding()).encode().expect("encodes");
        let mut value = cbor::decode_canonical(&bytes).expect("canonical");
        if let Value::Map(pairs) = &mut value {
            for (key, inner) in pairs.iter_mut() {
                if *key == Value::Int(8)
                    && let Value::Map(fields) = inner
                {
                    for (label, claims) in fields.iter_mut() {
                        if *label == Value::Int(4)
                            && let Value::Array(claims) = claims
                            && let Value::Map(first) = &mut claims[0]
                        {
                            first[0].1 = Value::Text(control.to_owned());
                            first[1].1 = Value::Text(class.to_owned());
                        }
                    }
                }
            }
        }
        assert!(
            Manifest::decode(&cbor::encode(&value).expect("encodes")).is_err(),
            "{control:?} {class:?}"
        );
    }
    let mut vouched = binding();
    vouched.claims[0].by = "spiffe://acme/operators/root".to_owned();
    refused(
        resealed(vouched),
        "a declaration vouched for by other than a profile",
    );
    let mut empty = binding();
    empty.claims.clear();
    refused(resealed(empty), "no claim");
    refused(
        AssuranceBinding {
            issued_at: 21,
            ..binding()
        },
        "expires before it was issued",
    );
    // A label the binding does not name.
    let mut value = cbor::decode_canonical(&bytes).expect("canonical");
    if let Value::Map(pairs) = &mut value {
        for (key, inner) in pairs.iter_mut() {
            if *key == Value::Int(8)
                && let Value::Map(binding) = inner
            {
                binding.push((Value::Int(99), Value::Int(0)));
            }
        }
    }
    assert!(Manifest::decode(&cbor::encode(&value).expect("encodes")).is_err());
    // A revoked binding reads back as revoked.
    let revoked = with(AssuranceBinding {
        verdict: Verdict::Revoked,
        ..binding()
    });
    assert_eq!(
        Manifest::decode(&revoked.encode().expect("encodes")).expect("reads back"),
        revoked
    );
    // An operator approval's reason is printable and bounded.
    assert!(check_reason("ticket 42").is_ok());
    for reason in ["", "  ", "a\nb", &"x".repeat(MAX_REASON_BYTES + 1)] {
        assert!(check_reason(reason).is_err(), "{reason:?}");
    }
}

/// WP-4.3: the task session's records read back, and refuse what they bound or forbid.
#[test]
fn the_task_session_records_read_back_and_refuse_what_they_forbid() {
    let request = LeaseRequest {
        membership_id: host(0x44).host_id,
        task_id: "decisions".to_owned(),
        epoch: 1,
        resource: "plane/data/zone/z1".to_owned(),
        member_boot_id: [0xB1; 16],
        evidence: vec![("tpm-quote".to_owned(), vec![0xEE; 8])],
    };
    let bytes = request.encode().expect("encodes");
    assert_eq!(LeaseRequest::decode(&bytes).expect("reads back"), request);
    assert!(LeaseRequest::decode(&foreign(&bytes)).is_err());
    for refused in [
        LeaseRequest {
            epoch: 0,
            ..request.clone()
        },
        LeaseRequest {
            task_id: "Decisions".to_owned(),
            ..request.clone()
        },
        LeaseRequest {
            resource: "nowhere".to_owned(),
            ..request.clone()
        },
        LeaseRequest {
            evidence: vec![("tpm-quote".to_owned(), vec![0xEE]); 5],
            ..request.clone()
        },
    ] {
        let bytes = refused.encode().expect("encodes");
        assert!(LeaseRequest::decode(&bytes).is_err(), "{refused:?}");
    }
    // An empty evidence array is written by nobody and read by nothing.
    let mut value = cbor::decode_canonical(&bytes).expect("canonical");
    if let Value::Map(pairs) = &mut value {
        for (key, item) in pairs.iter_mut() {
            if *key == Value::Int(6) {
                *item = Value::Array(Vec::new());
            }
        }
    }
    assert!(LeaseRequest::decode(&cbor::encode(&value).expect("encodes")).is_err());

    let lease = Lease {
        membership_id: host(0x44).host_id,
        task_id: "decisions".to_owned(),
        epoch: 1,
        coordinator: host(0x11).host_id,
        member: host(0x22).host_id,
        coordinator_boot_id: [0xB0; 16],
        member_boot_id: [0xB1; 16],
        selector: Selector::parse("plane/data/*").expect("a selector"),
        resource: "plane/data/zone/z1".to_owned(),
        limits: limits(),
        issued_at: 10,
        expires_at: 20,
        channel_binding: [0xC1; 32],
        binding_digest: Some(Digest::compute(b"binding")),
    };
    let bytes = lease.encode().expect("encodes");
    assert_eq!(Lease::decode(&bytes).expect("reads back"), lease);
    assert!(Lease::decode(&foreign(&bytes)).is_err());
    for refused in [
        Lease {
            expires_at: 10,
            ..lease.clone()
        },
        Lease {
            epoch: 0,
            ..lease.clone()
        },
    ] {
        assert!(Lease::decode(&refused.encode().expect("encodes")).is_err());
    }

    let message = TaskMessage {
        kind: MessageKind::Handler,
        membership_id: host(0x44).host_id,
        task_id: "decisions".to_owned(),
        epoch: 1,
        request_id: "r-1".to_owned(),
        body: b"hello".to_vec(),
    };
    let bytes = message.encode().expect("encodes");
    assert_eq!(TaskMessage::decode(&bytes).expect("reads back"), message);
    assert!(TaskMessage::decode(&foreign(&bytes)).is_err());
    for refused in [
        TaskMessage {
            request_id: String::new(),
            ..message.clone()
        },
        TaskMessage {
            request_id: "r".repeat(MAX_REQUEST_ID_BYTES + 1),
            ..message.clone()
        },
        TaskMessage {
            body: vec![0; MAX_BODY_BYTES + 1],
            ..message.clone()
        },
    ] {
        assert!(TaskMessage::decode(&refused.encode().expect("encodes")).is_err());
    }
    // One peer frame carries the largest message.
    let largest = TaskMessage {
        body: vec![0; MAX_BODY_BYTES],
        ..message.clone()
    }
    .encode()
    .expect("encodes");
    assert!(largest.len() <= crate::session::record::MAX_FRAME_BYTES);
    let answer = TaskAnswer {
        request_id: "r-1".to_owned(),
        body: b"echo".to_vec(),
    };
    let bytes = answer.encode().expect("encodes");
    assert_eq!(TaskAnswer::decode(&bytes).expect("reads back"), answer);
    assert!(TaskAnswer::decode(&foreign(&bytes)).is_err());
    let answer = LeaseAnswer {
        lease: vec![0x84],
        manifest: Some(vec![0x84]),
    };
    let bytes = answer.encode().expect("encodes");
    assert_eq!(LeaseAnswer::decode(&bytes).expect("reads back"), answer);
    assert!(LeaseAnswer::decode(&foreign(&bytes)).is_err());
}

fn report() -> TaskProgress {
    TaskProgress {
        membership_id: host(0x44).host_id,
        task_id: "decisions".to_owned(),
        manifest_epoch: 1,
        member_boot_id: [0xB1; 16],
        report_seq: 7,
        reported_at: 1_800_000_040,
        resources: vec![ProgressResource {
            resource: "plane/data/zone/z1".to_owned(),
            state: "serving".to_owned(),
            frontier: Some("42".to_owned()),
            checkpoint_digest: Some(Digest::compute(b"checkpoint")),
            verified_at: Some(1_800_000_039),
            reason: Some("verified".to_owned()),
        }],
    }
}

/// WP-4.4: a progress report, its answer and what the coordinator keeps read back, refuse a
/// foreign label, an unknown message kind, and a report out of its bounds.
#[test]
fn a_progress_report_round_trips_and_refuses_what_it_does_not_name() {
    let report = report();
    let bytes = report.encode().expect("encodes");
    assert_eq!(TaskProgress::decode(&bytes).expect("reads back"), report);
    assert!(TaskProgress::decode(&foreign(&bytes)).is_err());
    for refused in [
        TaskProgress {
            task_id: "Decisions".to_owned(),
            ..report.clone()
        },
        TaskProgress {
            resources: vec![ProgressResource {
                state: String::new(),
                ..report.resources[0].clone()
            }],
            ..report.clone()
        },
        TaskProgress {
            resources: vec![ProgressResource {
                resource: "not a resource".to_owned(),
                ..report.resources[0].clone()
            }],
            ..report.clone()
        },
    ] {
        let encoded = refused.encode().expect("encodes");
        assert!(TaskProgress::decode(&encoded).is_err(), "{refused:?}");
    }
    let answer = ProgressAnswer {
        report_seq: 7,
        received_at: 1_800_000_041,
    };
    let encoded = answer.encode().expect("encodes");
    assert_eq!(
        ProgressAnswer::decode(&encoded).expect("reads back"),
        answer
    );
    assert!(ProgressAnswer::decode(&foreign(&encoded)).is_err());
    let kept = KeptProgress {
        report: bytes.clone(),
        received_at: 1_800_000_041,
    };
    let encoded = kept.encode().expect("encodes");
    assert_eq!(KeptProgress::decode(&encoded).expect("reads back"), kept);
    // What is kept is a report, or nothing reads back.
    assert!(
        KeptProgress::decode(
            &KeptProgress {
                report: b"not a report".to_vec(),
                received_at: 1,
            }
            .encode()
            .expect("encodes")
        )
        .is_err()
    );
    // A message names its kind only when it is not the handler's, and only a known one.
    let message = TaskMessage {
        kind: MessageKind::Progress,
        membership_id: report.membership_id,
        task_id: "decisions".to_owned(),
        epoch: 1,
        request_id: "progress-7".to_owned(),
        body: bytes,
    };
    let encoded = message.encode().expect("encodes");
    assert_eq!(TaskMessage::decode(&encoded).expect("reads back"), message);
    let Value::Map(mut pairs) = cbor::decode_canonical(&encoded).expect("cbor") else {
        panic!("a map")
    };
    for (label, value) in &mut pairs {
        if *label == Value::Int(6) {
            *value = Value::Text("handler".to_owned());
        }
    }
    assert!(
        TaskMessage::decode(&cbor::encode(&Value::Map(pairs)).expect("encodes")).is_err(),
        "the handler's kind is the absent label, never spelled"
    );
}

/// WP-4.4: a report takes at most 256 resources and 64 KiB, each refused before it is parsed.
#[test]
fn a_progress_report_over_its_bound_is_refused() {
    let resource = report().resources[0].clone();
    let many = TaskProgress {
        resources: vec![resource; MAX_PROGRESS_RESOURCES + 1],
        ..report()
    };
    assert!(many.encode().is_err(), "the encoder refuses it too");
    assert!(TaskProgress::decode(&vec![0xA0; MAX_PROGRESS_BYTES + 1]).is_err());
    let at_bound = TaskProgress {
        resources: vec![report().resources[0].clone(); MAX_PROGRESS_RESOURCES],
        ..report()
    };
    let encoded = at_bound.encode().expect("within its bounds");
    assert!(encoded.len() <= MAX_PROGRESS_BYTES);
    assert_eq!(
        TaskProgress::decode(&encoded).expect("reads back"),
        at_bound
    );
}

/// WP-4.4: a watch's request and events read back in key order, refuse keys out of order or
/// twice, and a heartbeat is an event without hints.
#[test]
fn a_watch_request_and_its_hints_round_trip() {
    let request = WatchRequest {
        positions: vec![("a".to_owned(), 1), ("b".to_owned(), 2)],
    };
    let encoded = request.encode().expect("encodes");
    assert_eq!(WatchRequest::decode(&encoded).expect("reads back"), request);
    assert!(WatchRequest::decode(&foreign(&encoded)).is_err());
    let event = WatchEvent {
        hints: vec![WatchHint {
            key: "a".to_owned(),
            head: "h".to_owned(),
            counter: 3,
        }],
    };
    let encoded = event.encode().expect("encodes");
    assert_eq!(WatchEvent::decode(&encoded).expect("reads back"), event);
    let heartbeat = WatchEvent { hints: Vec::new() };
    assert_eq!(
        WatchEvent::decode(&heartbeat.encode().expect("encodes")).expect("reads back"),
        heartbeat
    );
    // Keys out of order, or twice, are refused: one encoding.
    let unordered = Value::Map(vec![(
        Value::Int(1),
        Value::Array(vec![
            Value::Map(vec![
                (Value::Int(1), Value::Text("b".to_owned())),
                (Value::Int(2), Value::Int(1)),
            ]),
            Value::Map(vec![
                (Value::Int(1), Value::Text("a".to_owned())),
                (Value::Int(2), Value::Int(1)),
            ]),
        ]),
    )]);
    assert!(WatchRequest::decode(&cbor::encode(&unordered).expect("encodes")).is_err());
    assert!(WatchRequest::decode(&vec![0xA0; MAX_BODY_BYTES + 1]).is_err());
}

/// WP-4.4: a Host's capabilities are listed in order, each once, at a version from 1.
#[test]
fn capabilities_are_listed_in_order_and_each_once() {
    let capability = |version| Capability {
        task_type: TaskType::DecisionsShip,
        version,
        role: ContractRole::Provider,
    };
    let encoded =
        capabilities_value(&[capability(2), capability(1), capability(1)]).expect("encodes");
    let Value::Array(values) = encoded.clone() else {
        panic!("an array")
    };
    assert_eq!(
        read_capabilities(values).expect("reads back"),
        vec![capability(1), capability(2)],
        "sorted, the duplicate gone"
    );
    let Value::Array(mut values) = encoded else {
        panic!("an array")
    };
    values.reverse();
    assert!(read_capabilities(values).is_err(), "out of order");
    assert!(Capability::read(capability(0).value().expect("encodes")).is_err());
    assert_eq!(
        ContractRole::of(TaskType::PolicyMirror, Role::Coordinator),
        ContractRole::Provider
    );
    assert_eq!(
        ContractRole::of(TaskType::DecisionsShip, Role::Coordinator),
        ContractRole::Consumer
    );
}

/// WP-4.4 (review): a task's concurrency and rate are enforced, so neither may be 0.
#[test]
fn a_task_refuses_a_zero_concurrency_or_rate() {
    let task = |edit: fn(&mut Limits)| {
        let mut limits = limits();
        edit(&mut limits);
        Task {
            version: 1,
            task_id: "decisions".to_owned(),
            task_type: TaskType::DecisionsShip,
            selector: permguard_core::authz::Selector::parse("plane/data/*").expect("a selector"),
            resource_types: Vec::new(),
            required: true,
            limits,
            assurance_requirements: Vec::new(),
        }
    };
    assert!(task(|_| {}).check().is_ok());
    assert!(task(|limits| limits.max_concurrency = 0).check().is_err());
    assert!(
        task(|limits| limits.max_rate_per_minute = 0)
            .check()
            .is_err()
    );
}

/// WP-4.5: a manifest pins one current set per owner and ring, and a retiring one only beside a
/// current set of a later epoch; a cutover names 1 to 64 streams, in order, each once.
#[test]
fn a_retiring_pin_needs_a_later_current_set_and_a_cutover_names_its_streams_once() {
    let pin = |epoch: u64, retiring: bool| RingPin {
        owner: Role::Member,
        ring: "data.attest".to_owned(),
        epoch,
        key_set_digest: [epoch as u8; 32],
        binding: vec![0x84],
        retiring,
    };
    let with = |pins: Vec<RingPin>| Manifest {
        ring_pins: pins,
        ..manifest(2)
    };
    let good = with(vec![pin(2, false), pin(1, true)]);
    let bytes = good.encode().expect("encodes");
    assert_eq!(Manifest::decode(&bytes).expect("reads back"), good);
    for refused in [
        vec![pin(2, false), pin(1, false)],
        vec![pin(1, true)],
        vec![pin(1, false), pin(2, true)],
        vec![pin(3, false), pin(2, true), pin(1, true)],
    ] {
        let encoded = with(refused.clone()).encode().expect("encodes");
        assert!(Manifest::decode(&encoded).is_err(), "{refused:?}");
    }
    // Label 6 is `true` or absent, never `false`.
    let Value::Map(mut pairs) = pin(1, true).value().expect("a value") else {
        panic!("a map")
    };
    for (label, value) in &mut pairs {
        if *label == Value::Int(6) {
            *value = Value::Bool(false);
        }
    }
    assert!(RingPin::read(Value::Map(pairs)).is_err());

    let cutover = Cutover {
        ring: "data.attest".to_owned(),
        epoch: 2,
        streams: vec![("a".to_owned(), 1), ("b".to_owned(), 2)],
    };
    let bytes = cutover.encode().expect("encodes");
    assert_eq!(Cutover::decode(&bytes).expect("reads back"), cutover);
    assert!(Cutover::decode(&foreign(&bytes)).is_err());
    // A member signing no stream under the ring cuts over with none (after the review).
    let none = Cutover {
        streams: Vec::new(),
        ..cutover.clone()
    };
    assert_eq!(
        Cutover::decode(&none.encode().expect("encodes")).expect("reads back"),
        none
    );
    let twice = Value::Map(vec![
        (Value::Int(1), Value::Text("data.attest".to_owned())),
        (Value::Int(2), Value::Int(2)),
        (
            Value::Int(3),
            Value::Array(vec![
                Value::Map(vec![
                    (Value::Int(1), Value::Text("a".to_owned())),
                    (Value::Int(2), Value::Int(1)),
                ]),
                Value::Map(vec![
                    (Value::Int(1), Value::Text("a".to_owned())),
                    (Value::Int(2), Value::Int(2)),
                ]),
            ]),
        ),
    ]);
    assert!(Cutover::decode(&cbor::encode(&twice).expect("encodes")).is_err());
    let acknowledgement = Acknowledgement {
        ring: "data.attest".to_owned(),
        epoch: 2,
        stream: "a".to_owned(),
        through_seq: 0,
    };
    let bytes = acknowledgement.encode().expect("encodes");
    assert_eq!(
        Acknowledgement::decode(&bytes).expect("reads back"),
        acknowledgement
    );
    assert!(Acknowledgement::decode(&vec![0xA0; 2048]).is_err());
}
