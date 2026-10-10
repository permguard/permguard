// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use permguard_core::assurance::{AssuranceProfile, Control, EvidenceClass};
use permguard_core::authz::{Resource, Selector};
use permguard_objects::digest::Digest;

use super::*;
use crate::membership::record::{
    AssuranceBinding, HostRef, LeasePolicy, Limits, Manifest, Status, Task, TaskType, Verdict,
};

/// The id the test verifier is registered under.
pub(crate) const VERIFIER: &str = "nonce-check";

/// A verifier that accepts evidence made of the nonce it is asked about followed by the control
/// names it shows, comma-separated: stale or foreign evidence names another nonce.
pub(crate) struct NonceVerifier;

impl Verifier for NonceVerifier {
    fn appraise(
        &self,
        _member: &HostRef,
        nonce: &[u8; 32],
        evidence: &[u8],
        now: u64,
    ) -> Result<Appraised, String> {
        let (bound, claims) = evidence.split_at_checked(32).ok_or("too short")?;
        if bound != nonce {
            return Err("the evidence is bound to another nonce".to_owned());
        }
        let claims = std::str::from_utf8(claims).map_err(|_| "not text")?;
        Ok(Appraised {
            controls: claims
                .split(',')
                .filter(|name| !name.is_empty())
                .map(str::parse)
                .collect::<Result<_, _>>()?,
            expires_at: now + 3600,
        })
    }
}

/// Evidence the test verifier accepts for `controls` against `nonce`.
pub(crate) fn evidence(nonce: &[u8; 32], controls: &[Control]) -> Vec<u8> {
    let mut bytes = nonce.to_vec();
    bytes.extend_from_slice(
        controls
            .iter()
            .map(|control| control.name())
            .collect::<Vec<_>>()
            .join(",")
            .as_bytes(),
    );
    bytes
}

/// The test policy: `custody.encrypted` declared, `operations.dual_control` approved by an
/// operator, `custody.hsm` attested; thirty days at most.
pub(crate) fn policy() -> Policy {
    Policy::new(
        BTreeMap::from([
            (Control::CustodyEncrypted, EvidenceClass::Declared),
            (
                Control::OperationsDualControl,
                EvidenceClass::OperatorApproved,
            ),
            (Control::CustodyHsm, EvidenceClass::Attested),
        ]),
        Duration::from_secs(30 * 86_400),
    )
}

/// The test policy with the test verifier registered.
pub(crate) fn appraisal() -> Appraisal {
    Appraisal::new(
        policy(),
        Verifiers::default().register(VERIFIER, Arc::new(NonceVerifier)),
    )
}

const NOW: u64 = 1_800_000_000;
const OPERATOR: &str = "spiffe://acme/operators/root";
const ID: [u8; 16] = [
    0x01, 0x9d, 0x3c, 0x5a, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0x44,
];

fn member() -> HostRef {
    HostRef {
        host_id: [0x22; 16],
        epoch: 1,
        fingerprint: format!("sha256:{}", "22".repeat(32)),
    }
}

fn task(id: &str, requirements: &[Control]) -> Task {
    Task {
        task_id: id.to_owned(),
        task_type: TaskType::DecisionsShip,
        selector: Selector::parse("plane/data/*").expect("a selector"),
        resource_types: vec!["decision".to_owned()],
        required: true,
        limits: Limits {
            max_body_bytes: 1 << 20,
            max_concurrency: 4,
            max_rate_per_minute: 600,
            max_batch_records: 1000,
            retention_seconds: 86_400,
        },
        assurance_requirements: requirements.iter().map(|c| c.name().to_owned()).collect(),
    }
}

const NONCE: [u8; 32] = [0xA7; 32];

fn request<'a>(
    tasks: &'a [Task],
    declared: AssuranceProfile,
    approvals: &'a [Approval],
    evidence: &'a [Evidence],
) -> Request<'a> {
    static MEMBER: std::sync::LazyLock<HostRef> = std::sync::LazyLock::new(member);
    Request {
        membership_id: &ID,
        member: &MEMBER,
        declared,
        tasks,
        approvals,
        evidence,
        principal: OPERATOR,
        nonce: &NONCE,
        now: NOW,
    }
}

fn approval(control: Control, expires_at: u64) -> Approval {
    Approval {
        control,
        reason: "witnessed under change ticket 42".to_owned(),
        expires_at,
    }
}

fn attestation(controls: &[Control]) -> Evidence {
    Evidence {
        verifier: VERIFIER.to_owned(),
        evidence: evidence(&NONCE, controls),
    }
}

fn manifest(tasks: Vec<Task>, binding: Option<AssuranceBinding>) -> Manifest {
    Manifest {
        membership_id: ID,
        coordinator: HostRef {
            host_id: [0x11; 16],
            epoch: 1,
            fingerprint: format!("sha256:{}", "11".repeat(32)),
        },
        member: member(),
        selector: Selector::parse("plane/data/*").expect("a selector"),
        tasks,
        member_assurance: AssuranceProfile::Production,
        min_assurance: None,
        assurance_binding: binding,
        ring_pins: Vec::new(),
        epoch: 1,
        lease_policy: LeasePolicy {
            max_session_seconds: 3600,
            offline_grace_seconds: 86_400,
            clock_skew_seconds: 30,
            dormant_after_seconds: 2_592_000,
            revoke_after_seconds: 7_776_000,
        },
        previous: None,
        issued_at: NOW,
        not_after: NOW + 365 * 86_400,
        status: Status::Active,
    }
}

fn resource() -> Resource {
    Resource::parse("plane/data/zone/z1").expect("a resource")
}

fn refused(result: Result<impl std::fmt::Debug, MembershipError>) -> String {
    match result {
        Err(MembershipError::AssuranceRefused(detail)) => detail,
        other => panic!("refused for assurance, not {other:?}"),
    }
}

/// All three controls, one per class: the binding the appraisal accepts for them.
fn every_class() -> (Vec<Task>, Outcome) {
    let tasks = vec![task(
        "decisions",
        &[
            Control::CustodyEncrypted,
            Control::OperationsDualControl,
            Control::CustodyHsm,
        ],
    )];
    let approvals = [approval(Control::OperationsDualControl, NOW + 7 * 86_400)];
    let evidence = [attestation(&[Control::CustodyHsm])];
    let outcome = appraisal()
        .appraise(&request(
            &tasks,
            AssuranceProfile::Production,
            &approvals,
            &evidence,
        ))
        .expect("accepted");
    (tasks, outcome)
}

#[test]
fn every_required_control_is_recorded_with_the_class_accepted() {
    let (_, outcome) = every_class();
    let binding = outcome.binding.expect("a binding");
    let claims: Vec<(&str, EvidenceClass, &str, bool)> = binding
        .claims
        .iter()
        .map(|claim| {
            (
                claim.control.name(),
                claim.class,
                claim.by.as_str(),
                claim.record.is_some(),
            )
        })
        .collect();
    // Sorted by the control's name, each with who vouches for it.
    assert_eq!(
        claims,
        [
            (
                permguard_core::domains::assurance::CUSTODY_ENCRYPTED,
                EvidenceClass::Declared,
                "production",
                false
            ),
            (
                permguard_core::domains::assurance::CUSTODY_HSM,
                EvidenceClass::Attested,
                VERIFIER,
                true
            ),
            (
                permguard_core::domains::assurance::OPERATIONS_DUAL_CONTROL,
                EvidenceClass::OperatorApproved,
                OPERATOR,
                true
            ),
        ]
    );
    assert_eq!(binding.member, member());
    assert_eq!(binding.task_ids, ["decisions"]);
    assert_eq!(binding.policy_revision, policy().revision());
    assert_eq!(binding.appraised_by, OPERATOR);
    assert_eq!(binding.verdict, Verdict::Accepted);
    assert_eq!(binding.issued_at, NOW);
    // The verifier's result runs an hour: the shortest expiry bounds the binding.
    assert_eq!(binding.expires_at, NOW + 3600);
    assert_eq!(
        binding.result_digest,
        crate::membership::record::result_digest(
            &binding.member,
            &binding.task_ids,
            &binding.policy_revision,
            &binding.claims
        )
        .expect("digested")
    );
}

#[test]
fn a_stronger_class_satisfies_a_weaker_requirement_and_never_the_reverse() {
    // `custody.encrypted` needs only a declaration: an operator's approval satisfies it too.
    let tasks = vec![task("decisions", &[Control::CustodyEncrypted])];
    let approvals = [approval(Control::CustodyEncrypted, NOW + 86_400)];
    let binding = appraisal()
        .appraise(&request(
            &tasks,
            AssuranceProfile::Development,
            &approvals,
            &[],
        ))
        .expect("an approval satisfies a declaration")
        .binding
        .expect("a binding");
    assert_eq!(binding.claims[0].class, EvidenceClass::OperatorApproved);
    // `operations.dual_control` needs an operator: an attestation satisfies it.
    let tasks = vec![task("decisions", &[Control::OperationsDualControl])];
    let evidence = [attestation(&[Control::OperationsDualControl])];
    let binding = appraisal()
        .appraise(&request(
            &tasks,
            AssuranceProfile::Production,
            &[],
            &evidence,
        ))
        .expect("an attestation satisfies an approval")
        .binding
        .expect("a binding");
    assert_eq!(binding.claims[0].class, EvidenceClass::Attested);
    // `custody.hsm` needs an attestation: an operator's approval never does.
    let tasks = vec![task("decisions", &[Control::CustodyHsm])];
    let approvals = [approval(Control::CustodyHsm, NOW + 86_400)];
    let why = refused(appraisal().appraise(&request(
        &tasks,
        AssuranceProfile::Regulated,
        &approvals,
        &[],
    )));
    assert!(
        why.contains(permguard_core::domains::assurance::CUSTODY_HSM)
            && why.contains("attested")
            && why.contains("operator-approved"),
        "{why}"
    );
}

#[test]
fn a_control_the_policy_does_not_appraise_makes_the_task_unapprovable() {
    let tasks = vec![task("decisions", &[Control::Tls13Only])];
    let approvals = [approval(Control::Tls13Only, NOW + 86_400)];
    let why = refused(appraisal().appraise(&request(
        &tasks,
        AssuranceProfile::Regulated,
        &approvals,
        &[],
    )));
    assert!(why.contains("does not appraise `tls.1_3_only`"), "{why}");
    let requirements = appraisal()
        .requirements(&tasks, AssuranceProfile::Regulated)
        .expect("read");
    assert_eq!(
        requirements,
        [Requirement {
            control: Control::Tls13Only,
            wants: None,
            declared: true
        }]
    );
}

#[test]
fn attested_needs_a_registered_verifier_over_this_revisions_nonce() {
    let tasks = vec![task("decisions", &[Control::CustodyHsm])];
    // Evidence bound to another revision's nonce is refused.
    let stale = [Evidence {
        verifier: VERIFIER.to_owned(),
        evidence: evidence(&[0x01; 32], &[Control::CustodyHsm]),
    }];
    let why =
        refused(appraisal().appraise(&request(&tasks, AssuranceProfile::Production, &[], &stale)));
    // Refused, and the verifier's own words stay out of the answer.
    assert!(why.contains("refused the evidence"), "{why}");
    assert!(!why.contains("another nonce"), "{why}");
    // Evidence showing another control leaves this one short.
    let other = [attestation(&[Control::CustodyEncrypted])];
    let why =
        refused(appraisal().appraise(&request(&tasks, AssuranceProfile::Production, &[], &other)));
    assert!(
        why.contains(permguard_core::domains::assurance::CUSTODY_HSM),
        "{why}"
    );
    // This revision's nonce: accepted.
    let fresh = [attestation(&[Control::CustodyHsm])];
    appraisal()
        .appraise(&request(&tasks, AssuranceProfile::Production, &[], &fresh))
        .expect("accepted");
    // The nonce names the coordinator, the membership and the state.
    let state = Digest::compute(b"state");
    let one = nonce(&[0x11; 16], &ID, &state);
    assert_ne!(one, nonce(&[0x12; 16], &ID, &state));
    assert_ne!(one, nonce(&[0x11; 16], &[0x45; 16], &state));
    assert_ne!(one, nonce(&[0x11; 16], &ID, &Digest::compute(b"other")));
}

#[test]
fn with_no_verifier_attested_is_unavailable() {
    let lone = Appraisal::new(policy(), Verifiers::default());
    let tasks = vec![task("decisions", &[Control::CustodyHsm])];
    let evidence = [attestation(&[Control::CustodyHsm])];
    assert!(matches!(
        lone.appraise(&request(
            &tasks,
            AssuranceProfile::Production,
            &[],
            &evidence
        )),
        Err(MembershipError::AssuranceUnavailable(_))
    ));
    // Without evidence and with no verifier to give one: unavailable here, whatever the
    // declaration says.
    assert!(matches!(
        lone.appraise(&request(&tasks, AssuranceProfile::Regulated, &[], &[])),
        Err(MembershipError::AssuranceUnavailable(_))
    ));
    // With a verifier registered, the same short request is refused: evidence could be given.
    refused(appraisal().appraise(&request(&tasks, AssuranceProfile::Regulated, &[], &[])));
}

#[test]
fn an_attestation_stands_only_while_its_verifier_is_registered() {
    let tasks = vec![task("decisions", &[Control::CustodyHsm])];
    let evidence = [attestation(&[Control::CustodyHsm])];
    let binding = appraisal()
        .appraise(&request(
            &tasks,
            AssuranceProfile::Production,
            &[],
            &evidence,
        ))
        .expect("accepted")
        .binding
        .expect("a binding");
    let held = manifest(tasks, Some(binding.clone()));
    appraisal()
        .admit(&held, "decisions", &resource(), NOW)
        .expect("admitted while the verifier is registered");
    assert!(appraisal().is_current(&binding, NOW));
    // The verifier removed from the composition: its result no longer stands.
    let removed = Appraisal::new(policy(), Verifiers::default());
    let why = refused(removed.admit(&held, "decisions", &resource(), NOW));
    assert!(why.contains("no longer registered"), "{why}");
    assert!(!removed.is_current(&binding, NOW));
}

#[test]
fn an_operator_approval_is_audited_whole_and_signed_by_digest() {
    let (_, outcome) = every_class();
    let binding = outcome.binding.expect("a binding");
    let [record] = outcome.approvals.as_slice() else {
        panic!("one approval: {:?}", outcome.approvals);
    };
    assert_eq!(record.membership_id, ID);
    assert_eq!(record.control, Control::OperationsDualControl);
    assert_eq!(record.principal, OPERATOR);
    assert_eq!(record.task_ids, ["decisions"]);
    assert_eq!(record.reason, "witnessed under change ticket 42");
    assert_eq!(record.expires_at, NOW + 7 * 86_400);
    assert_eq!(record.approved_at, NOW);
    let claim = binding
        .claim(Control::OperationsDualControl)
        .expect("claimed");
    assert_eq!(
        claim.record.as_ref(),
        Some(&record.digest().expect("digested"))
    );
    // The signed binding carries the digest, never the operator's words.
    let bytes = binding.encode().expect("encodes");
    assert!(
        !bytes
            .windows(record.reason.len())
            .any(|window| window == record.reason.as_bytes())
    );
    // An approval needs a reason, an expiry ahead, a control a task requires, and comes once.
    let tasks = vec![task("decisions", &[Control::OperationsDualControl])];
    for approvals in [
        vec![Approval {
            reason: " ".to_owned(),
            ..approval(Control::OperationsDualControl, NOW + 60)
        }],
        vec![approval(Control::OperationsDualControl, NOW)],
        vec![approval(Control::CustodyHsm, NOW + 60)],
        vec![
            approval(Control::OperationsDualControl, NOW + 60),
            approval(Control::OperationsDualControl, NOW + 120),
        ],
    ] {
        assert!(
            matches!(
                appraisal().appraise(&request(
                    &tasks,
                    AssuranceProfile::Production,
                    &approvals,
                    &[]
                )),
                Err(MembershipError::Invalid(_))
            ),
            "{approvals:?}"
        );
    }
}

#[test]
fn evidence_is_kept_by_digest_alone() {
    let (_, outcome) = every_class();
    let binding = outcome.binding.expect("a binding");
    let claim = binding.claim(Control::CustodyHsm).expect("claimed");
    let piece = evidence(&NONCE, &[Control::CustodyHsm]);
    assert_eq!(
        claim.record,
        Some(crate::membership::record::evidence_digest(VERIFIER, &piece).expect("digested"))
    );
    let bytes = binding.encode().expect("encodes");
    assert!(
        !bytes
            .windows(piece.len())
            .any(|window| window == piece.as_slice())
    );
    // Nor in a log line.
    let shown = format!("{:?}", attestation(&[Control::CustodyHsm]));
    assert!(!shown.contains("167"), "{shown}");
    assert!(shown.contains("bytes"), "{shown}");
}

#[test]
fn a_binding_under_another_policy_admits_nothing_until_appraised_again() {
    let (tasks, outcome) = every_class();
    let manifest = manifest(tasks, outcome.binding);
    appraisal()
        .admit(&manifest, "decisions", &resource(), NOW)
        .expect("admitted under the policy it was appraised under");
    // The same controls with a shorter longest binding: another revision.
    let mut controls = BTreeMap::new();
    for control in [
        Control::CustodyEncrypted,
        Control::OperationsDualControl,
        Control::CustodyHsm,
    ] {
        controls.insert(control, policy().wants(control).expect("in the policy"));
    }
    let changed = Appraisal::new(
        Policy::new(controls, Duration::from_secs(86_400)),
        Verifiers::default(),
    );
    assert_ne!(changed.policy.revision(), policy().revision());
    let why = refused(changed.admit(&manifest, "decisions", &resource(), NOW));
    assert!(why.contains("another policy"), "{why}");
    assert!(!changed.is_current(manifest.assurance_binding.as_ref().expect("held"), NOW));
}

#[test]
fn an_expired_binding_admits_nothing() {
    let (tasks, outcome) = every_class();
    let binding = outcome.binding.expect("a binding");
    let expires = binding.expires_at;
    let manifest = manifest(tasks, Some(binding));
    appraisal()
        .admit(&manifest, "decisions", &resource(), expires - 1)
        .expect("a second before");
    let why = refused(appraisal().admit(&manifest, "decisions", &resource(), expires));
    assert!(why.contains("expired"), "{why}");
}

#[test]
fn a_revoked_binding_admits_nothing() {
    let (tasks, outcome) = every_class();
    let binding = outcome.binding.expect("a binding");
    let revoked = Appraisal::revoked(&binding, "spiffe://acme/operators/security", NOW + 10);
    assert_eq!(revoked.verdict, Verdict::Revoked);
    assert_eq!(revoked.expires_at, NOW + 10);
    assert_eq!(revoked.appraised_by, "spiffe://acme/operators/security");
    assert_eq!(revoked.claims, binding.claims, "what it had accepted stays");
    let manifest = manifest(tasks, Some(revoked));
    let why = refused(appraisal().admit(&manifest, "decisions", &resource(), NOW + 1));
    assert!(why.contains("revoked"), "{why}");
}

#[test]
fn no_admission_outlives_its_binding() {
    let tasks = vec![task("decisions", &[Control::OperationsDualControl])];
    let approvals = [approval(Control::OperationsDualControl, NOW + 600)];
    let binding = appraisal()
        .appraise(&request(
            &tasks,
            AssuranceProfile::Production,
            &approvals,
            &[],
        ))
        .expect("accepted")
        .binding
        .expect("a binding");
    assert_eq!(binding.expires_at, NOW + 600, "the approval's expiry");
    let digest = binding.digest().expect("digested");
    let admitted = appraisal()
        .admit(
            &manifest(tasks, Some(binding)),
            "decisions",
            &resource(),
            NOW,
        )
        .expect("admitted");
    assert_eq!(admitted.binding, Some(digest));
    assert_eq!(admitted.not_after, Some(NOW + 600));
    // The policy's longest binding bounds a declaration.
    let tasks = vec![task("decisions", &[Control::CustodyEncrypted])];
    let binding = appraisal()
        .appraise(&request(&tasks, AssuranceProfile::Production, &[], &[]))
        .expect("accepted")
        .binding
        .expect("a binding");
    assert_eq!(binding.expires_at, NOW + 30 * 86_400);
}

#[test]
fn an_expired_attestation_never_falls_back_to_the_declaration() {
    // The member declares `regulated`, whose floor holds `custody.hsm`; the policy wants it
    // attested.
    let tasks = vec![task("decisions", &[Control::CustodyHsm])];
    let evidence = [attestation(&[Control::CustodyHsm])];
    let binding = appraisal()
        .appraise(&request(
            &tasks,
            AssuranceProfile::Regulated,
            &[],
            &evidence,
        ))
        .expect("accepted")
        .binding
        .expect("a binding");
    let expires = binding.expires_at;
    let mut held = manifest(tasks.clone(), Some(binding));
    held.member_assurance = AssuranceProfile::Regulated;
    refused(appraisal().admit(&held, "decisions", &resource(), expires));
    // Appraised again with the declaration alone: still refused.
    refused(appraisal().appraise(&request(&tasks, AssuranceProfile::Regulated, &[], &[])));
}

#[test]
fn a_declaration_never_satisfies_what_the_policy_wants_appraised() {
    for control in [Control::OperationsDualControl, Control::CustodyHsm] {
        let tasks = vec![task("decisions", &[control])];
        let why =
            refused(appraisal().appraise(&request(&tasks, AssuranceProfile::Regulated, &[], &[])));
        assert!(why.contains("only `declared`"), "{control}: {why}");
    }
    // A declaration below the control's floor meets not even a declared requirement.
    let tasks = vec![task("decisions", &[Control::CustodyEncrypted])];
    let why =
        refused(appraisal().appraise(&request(&tasks, AssuranceProfile::Development, &[], &[])));
    assert!(why.contains("nothing was offered"), "{why}");
}

/// H-01: a member lying about one required control fails task admission without a fresh accepted
/// binding.
#[test]
fn lying_about_one_required_control_fails_admission_without_a_fresh_accepted_binding() {
    // The member declares `regulated`: it claims an HSM it does not have.
    let tasks = vec![task(
        "decisions",
        &[Control::CustodyEncrypted, Control::CustodyHsm],
    )];
    refused(appraisal().appraise(&request(&tasks, AssuranceProfile::Regulated, &[], &[])));
    // A manifest without a binding admits nothing for the task.
    let mut bare = manifest(tasks.clone(), None);
    bare.member_assurance = AssuranceProfile::Regulated;
    refused(appraisal().admit(&bare, "decisions", &resource(), NOW));
    // A binding that holds the declared control and not the lied one does not either.
    let declared_only = appraisal()
        .appraise(&request(
            &[task("decisions", &[Control::CustodyEncrypted])],
            AssuranceProfile::Regulated,
            &[],
            &[],
        ))
        .expect("accepted")
        .binding;
    let mut partial = manifest(tasks.clone(), declared_only);
    partial.member_assurance = AssuranceProfile::Regulated;
    let why = refused(appraisal().admit(&partial, "decisions", &resource(), NOW));
    assert!(
        why.contains(permguard_core::domains::assurance::CUSTODY_HSM),
        "{why}"
    );
    // A fresh accepted attestation admits it.
    let evidence = [attestation(&[Control::CustodyHsm])];
    let binding = appraisal()
        .appraise(&request(
            &tasks,
            AssuranceProfile::Regulated,
            &[],
            &evidence,
        ))
        .expect("accepted")
        .binding;
    appraisal()
        .admit(&manifest(tasks, binding), "decisions", &resource(), NOW)
        .expect("admitted");
}

#[test]
fn admission_takes_an_active_membership_one_task_and_a_resource_inside_it() {
    let tasks = vec![task("open", &[])];
    let mut held = manifest(tasks, None);
    let admitted = appraisal()
        .admit(&held, "open", &resource(), NOW)
        .expect("a task requiring no control");
    assert_eq!(
        admitted,
        Admitted {
            binding: None,
            not_after: None
        }
    );
    for (task_id, resource) in [
        ("other", resource()),
        (
            "open",
            Resource::parse("plane/control").expect("a resource"),
        ),
    ] {
        assert!(matches!(
            appraisal().admit(&held, task_id, &resource, NOW),
            Err(MembershipError::Invalid(_))
        ));
    }
    held.status = Status::Suspended;
    assert!(matches!(
        appraisal().admit(&held, "open", &resource(), NOW),
        Err(MembershipError::Invalid(_))
    ));
}

#[test]
fn no_requirement_takes_no_approval_and_no_evidence() {
    let tasks = vec![task("open", &[])];
    let outcome = appraisal()
        .appraise(&request(&tasks, AssuranceProfile::Production, &[], &[]))
        .expect("nothing to appraise");
    assert_eq!(outcome.binding, None);
    let approvals = [approval(Control::CustodyEncrypted, NOW + 60)];
    assert!(matches!(
        appraisal().appraise(&request(
            &tasks,
            AssuranceProfile::Production,
            &approvals,
            &[]
        )),
        Err(MembershipError::Invalid(_))
    ));
}

#[test]
fn the_policy_revision_is_the_vectors_digest() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../contracts/vectors/membership.json"
    ))
    .expect("the vectors parse");
    let policy = Policy::new(
        BTreeMap::from([
            (Control::CustodyEncrypted, EvidenceClass::Declared),
            (Control::CustodyHsm, EvidenceClass::Attested),
            (
                Control::OperationsDualControl,
                EvidenceClass::OperatorApproved,
            ),
        ]),
        Duration::from_secs(2_592_000),
    );
    assert_eq!(
        policy.revision().to_string(),
        vectors["assurance"]["policy"]["revision"]
    );
}

/// Admission reads the binding it is handed, whatever produced it: a task the binding does not
/// cover, or a claim weaker than the policy wants, admits nothing.
#[test]
fn admission_rechecks_the_tasks_and_the_classes_the_binding_holds() {
    let tasks = vec![
        task("a", &[Control::OperationsDualControl]),
        task("b", &[Control::OperationsDualControl]),
    ];
    let approvals = [approval(Control::OperationsDualControl, NOW + 600)];
    let only_a = appraisal()
        .appraise(&request(
            &tasks[..1],
            AssuranceProfile::Production,
            &approvals,
            &[],
        ))
        .expect("accepted")
        .binding
        .expect("a binding");
    let held = manifest(tasks.clone(), Some(only_a.clone()));
    appraisal()
        .admit(&held, "a", &resource(), NOW)
        .expect("covered");
    let why = refused(appraisal().admit(&held, "b", &resource(), NOW));
    assert!(why.contains("does not cover"), "{why}");
    // A claim weaker than the policy wants, under the same revision.
    let mut weaker = only_a;
    weaker.claims[0].class = EvidenceClass::Declared;
    let why = refused(appraisal().admit(&manifest(tasks, Some(weaker)), "a", &resource(), NOW));
    assert!(why.contains(Control::OperationsDualControl.name()), "{why}");
}

#[test]
fn a_requirement_names_a_control_exactly() {
    let mut spaced = task("decisions", &[]);
    spaced.assurance_requirements = vec![format!(" {}", Control::CustodyHsm.name())];
    assert!(matches!(
        required(&[spaced]),
        Err(MembershipError::Invalid(_))
    ));
}
