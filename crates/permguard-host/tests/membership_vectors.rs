// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The membership's golden vectors (`contracts/vectors/membership.json`, WP-4.1), computed by an
//! independent generator and reproduced here byte for byte by the Rust codecs.

#![allow(clippy::expect_used)]

use permguard_core::assurance::AssuranceProfile;
use permguard_core::authz::Selector;
use permguard_core::domains::protected;
use permguard_host::membership::record::{
    EnrollRequest, Entry, HostRef, Invitation, Kind, LeasePolicy, Limits, Manifest, Pending,
    RingPin, RingStatement, Role, Status, Task, TaskType, chain, manifest_digest, request_digest,
};
use permguard_host::membership::{token_proof, token_public};
use permguard_host::session::record::{Hello, Operation, Role as SessionRole, Transcript};
use permguard_objects::cose::Sign1;
use permguard_objects::crypto::suite::Suite;
use permguard_objects::digest::Digest;
use serde_json::Value;

fn vectors() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/vectors/membership.json"
    ))
    .expect("the vectors read");
    serde_json::from_str(&text).expect("the vectors parse")
}

fn hex(value: &Value) -> Vec<u8> {
    let text = value.as_str().expect("hex text");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn id(value: &Value) -> [u8; 16] {
    hex(value).try_into().expect("16 bytes")
}

fn text(value: &Value) -> String {
    value.as_str().expect("text").to_owned()
}

const AT: u64 = 1_800_000_000;

fn task() -> Task {
    Task {
        task_id: "decisions".to_owned(),
        task_type: TaskType::DecisionsShip,
        selector: Selector::parse("plane/data/*").expect("a selector"),
        resource_types: vec!["decision".to_owned()],
        required: true,
        limits: Limits {
            max_body_bytes: 1_048_576,
            max_concurrency: 4,
            max_rate_per_minute: 600,
            max_batch_records: 1000,
            retention_seconds: 2_592_000,
        },
        assurance_requirements: Vec::new(),
    }
}

#[test]
fn the_membership_records_are_the_bytes_the_independent_generator_computed() {
    let v = vectors();
    let coordinator = HostRef {
        host_id: id(&v["coordinator"]["host_id"]),
        epoch: 1,
        fingerprint: text(&v["coordinator"]["fingerprint"]),
    };
    let member = HostRef {
        host_id: id(&v["member"]["host_id"]),
        epoch: 1,
        fingerprint: text(&v["member"]["fingerprint"]),
    };
    let invite_id = id(&v["invite_id"]);
    let membership_id = id(&v["membership_id"]);
    let token = hex(&v["token"]);
    let token_key = token_public(&token);
    assert_eq!(token_key.to_vec(), hex(&v["token_key"]));

    let invitation = Invitation {
        invite_id,
        token_key,
        selector: Selector::parse("plane/data/*").expect("a selector"),
        tasks: vec![task()],
        expires: AT + 86_400,
        expected_fingerprint: Some(member.fingerprint.clone()),
        min_assurance: None,
        max_uses: 1,
        created_at: AT,
        created_by: "spiffe://acme/operators/root".to_owned(),
    };
    assert_eq!(invitation.encode().expect("encodes"), hex(&v["invitation"]));
    assert_eq!(
        Invitation::decode(&hex(&v["invitation"])).expect("decodes"),
        invitation
    );

    let exporter: [u8; 32] = hex(&v["exporter"]).try_into().expect("32 bytes");
    let proof = token_proof(&token, &coordinator.host_id, &member.host_id, &exporter);
    assert_eq!(proof.to_vec(), hex(&v["token_proof"]));

    let statement = RingStatement {
        ring: "data.attest".to_owned(),
        epoch: 1,
        suite: Suite::Ed25519Sha256V1,
        keys: vec![text(&v["ring_statement"]["jwk"])],
        binding: hex(&v["ring_statement"]["binding"]),
    };
    let request = EnrollRequest {
        invite_id,
        token_proof: proof,
        selector: Selector::parse("plane/data/*").expect("a selector"),
        tasks: vec![task()],
        member: member.clone(),
        ring_statements: vec![statement.clone()],
    };
    let request_bytes = request.encode().expect("encodes");
    assert_eq!(request_bytes, hex(&v["request"]["bytes"]));
    assert_eq!(
        request_digest(&request_bytes).to_string(),
        text(&v["request"]["digest"])
    );
    assert_eq!(
        EnrollRequest::decode(&request_bytes).expect("decodes"),
        request
    );

    // The hello and transcript of an enrollment session carry the request's digest.
    let hello = Hello::decode(&hex(&v["hello"])).expect("the hello decodes");
    assert_eq!(hello.operation, Operation::Enroll);
    assert_eq!(hello.request_digest, Some(request_digest(&request_bytes)));
    assert_eq!(hello.encode().expect("encodes"), hex(&v["hello"]));
    let transcript =
        Transcript::decode(&hex(&v["transcript_initiator"])).expect("the transcript decodes");
    assert_eq!(
        transcript.request_digest,
        Some(request_digest(&request_bytes))
    );
    assert_eq!(transcript.signer, SessionRole::Initiator);
    assert_eq!(
        transcript.encode().expect("encodes"),
        hex(&v["transcript_initiator"])
    );

    let ring_digest: [u8; 32] = hex(&v["ring_statement"]["digest"])
        .try_into()
        .expect("32 bytes");
    let manifest = |epoch: u64, status: Status, previous: Option<Digest>| Manifest {
        membership_id,
        coordinator: coordinator.clone(),
        member: member.clone(),
        selector: Selector::parse("plane/data/*").expect("a selector"),
        tasks: vec![task()],
        member_assurance: AssuranceProfile::Production,
        min_assurance: None,
        ring_pins: vec![RingPin {
            owner: Role::Member,
            ring: "data.attest".to_owned(),
            epoch: 1,
            key_set_digest: ring_digest,
            binding: statement.binding.clone(),
        }],
        epoch,
        lease_policy: LeasePolicy {
            max_session_seconds: 3600,
            offline_grace_seconds: 86_400,
            clock_skew_seconds: 30,
            dormant_after_seconds: 2_592_000,
            revoke_after_seconds: 7_776_000,
        },
        previous,
        issued_at: AT + epoch,
        not_after: AT + 365 * 86_400,
        status,
    };
    let genesis = manifest(1, Status::Active, None);
    assert_eq!(
        genesis.encode().expect("encodes"),
        hex(&v["manifest_genesis"]["payload"])
    );
    let envelope = hex(&v["manifest_genesis"]["cose_sign1"]);
    let digest = manifest_digest(&envelope);
    assert_eq!(digest.to_string(), text(&v["manifest_genesis"]["digest"]));
    let operations = hex(&v["operations"]["public_key"]);
    let signed = Sign1::decode(&envelope).expect("a COSE_Sign1");
    assert_eq!(
        signed.header().expect("a header").kid,
        text(&v["operations"]["kid"]).into_bytes()
    );
    let payload = signed
        .verify(
            Suite::Ed25519Sha256V1,
            &operations,
            protected::MEMBERSHIP_MANIFEST,
        )
        .expect("verifies under the operations key");
    assert_eq!(Manifest::decode(payload).expect("decodes"), genesis);
    let successor = manifest(2, Status::Suspended, Some(digest));
    assert_eq!(
        successor.encode().expect("encodes"),
        hex(&v["manifest_successor"]["payload"])
    );

    let pending = Pending {
        membership_id,
        invite_id,
        coordinator,
        member,
        selector: Selector::parse("plane/data/*").expect("a selector"),
        tasks: vec![task()],
        member_assurance: AssuranceProfile::Production,
        ring_statements: vec![statement],
        requested_at: AT + 1,
        coordinator_address: None,
        identity: None,
    };
    assert_eq!(pending.encode().expect("encodes"), hex(&v["pending"]));

    let genesis_chain = chain(None);
    assert_eq!(
        genesis_chain.to_string(),
        text(&v["journal"]["genesis_chain"])
    );
    let first = Entry {
        seq: 1,
        kind: Kind::Invited,
        subject: invite_id,
        epoch: None,
        at: AT,
        operation_id: None,
        previous: genesis_chain,
        detail: Some(hex(&v["invitation"])),
        statements: Vec::new(),
    };
    let first_bytes = first.encode().expect("encodes");
    assert_eq!(first_bytes, hex(&v["journal"]["first"]));
    let second = Entry {
        seq: 2,
        kind: Kind::Enrolled,
        subject: membership_id,
        epoch: None,
        at: AT + 1,
        operation_id: None,
        previous: chain(Some(&first_bytes)),
        detail: Some(hex(&v["pending"])),
        statements: Vec::new(),
    };
    let second_bytes = second.encode().expect("encodes");
    assert_eq!(second_bytes, hex(&v["journal"]["second"]));
    let third = Entry {
        seq: 3,
        kind: Kind::Manifest,
        subject: membership_id,
        epoch: Some(1),
        at: AT + 1,
        operation_id: Some([0x55; 16]),
        previous: chain(Some(&second_bytes)),
        detail: Some(envelope),
        statements: Vec::new(),
    };
    assert_eq!(
        third.encode().expect("encodes"),
        hex(&v["journal"]["third"])
    );
    assert_eq!(
        Entry::decode(&hex(&v["journal"]["third"])).expect("decodes"),
        third
    );
}
