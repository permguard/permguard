// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use std::time::Duration;

use permguard_core::KeyManager as _;

use super::record::{Action, MembershipAnswer, MembershipRequest};
use super::*;
use crate::keys::ring::Policy;
use crate::time::TimeGuard;

/// One Host: a volume, an identity, its rings bound by the identity, and its membership store.
pub(crate) struct Host {
    root: std::path::PathBuf,
    _volume: Volume,
    pub(crate) identity: Arc<Identity>,
    pub(crate) rings: Vec<Arc<Ring>>,
    pub(crate) store: Arc<Store>,
}

fn now() -> u64 {
    crate::authz::store::now()
}

impl Host {
    pub(crate) fn new(tag: &str) -> Self {
        Self::timed(tag, Arc::new(TimeGuard::system(Duration::from_secs(30))))
    }

    /// A Host whose rings run on `time`.
    pub(crate) fn timed(tag: &str, time: Arc<TimeGuard>) -> Self {
        let root = std::env::temp_dir().join(format!(
            "permguard-host-members-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let volume = Volume::claim(
            &root,
            permguard_core::assurance::AssuranceProfile::Development,
        )
        .expect("claimed");
        let provider: Arc<dyn crate::keys::KeyProvider> =
            Arc::new(crate::keys::FileKeyProvider::new(
                identity::directories(&volume).expect("the identity").1,
            ));
        let identity = Arc::new(
            Identity::provision(
                &volume,
                provider,
                Suite::Ed25519Sha256V1,
                now(),
                now() * 1000,
            )
            .expect("provisioned"),
        );
        let rings = [HOST_OPERATIONS, CONTROL_ATTEST, DATA_ATTEST]
            .into_iter()
            .map(|id| {
                let ring = Arc::new(
                    Ring::open(
                        &volume,
                        id,
                        Suite::Ed25519Sha256V1,
                        Policy {
                            publish_ahead: Duration::from_secs(600),
                            rotate_every: Duration::from_secs(3600),
                            retain: Duration::from_secs(7200),
                        },
                        Arc::clone(&time),
                    )
                    .expect("the ring opens")
                    .with_binder(identity.clone()),
                );
                ring.maintain().expect("the first key");
                ring
            })
            .collect();
        let store = Store::open(&volume).expect("the store opens");
        Self {
            root,
            _volume: volume,
            identity,
            rings,
            store,
        }
    }

    pub(crate) fn volume(&self) -> &Volume {
        &self._volume
    }

    pub(crate) fn coordinator(&self) -> Coordinator<'_> {
        Coordinator {
            identity: &self.identity,
            rings: &self.rings,
        }
    }

    /// A copy of this Host's volume, claimed and opened beside it: the same Host, its rings and
    /// memberships, another boot id (F-31).
    pub(crate) fn copy(&self, tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "permguard-host-members-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let status = std::process::Command::new("cp")
            .arg("-Rp")
            .arg(&self.root)
            .arg(&root)
            .status()
            .expect("cp runs");
        assert!(status.success(), "the volume is copied");
        let volume = Volume::claim(
            &root,
            permguard_core::assurance::AssuranceProfile::Development,
        )
        .expect("the copy is claimed");
        let provider: Arc<dyn crate::keys::KeyProvider> =
            Arc::new(crate::keys::FileKeyProvider::new(
                identity::directories(&volume).expect("the identity").1,
            ));
        let identity = Arc::new(Identity::open(&volume, provider).expect("the copy opens"));
        let time = Arc::new(TimeGuard::system(Duration::from_secs(30)));
        let rings = [HOST_OPERATIONS, CONTROL_ATTEST, DATA_ATTEST]
            .into_iter()
            .map(|id| {
                Arc::new(
                    Ring::open(
                        &volume,
                        id,
                        Suite::Ed25519Sha256V1,
                        Policy {
                            publish_ahead: Duration::from_secs(600),
                            rotate_every: Duration::from_secs(3600),
                            retain: Duration::from_secs(7200),
                        },
                        Arc::clone(&time),
                    )
                    .expect("the ring opens")
                    .with_binder(identity.clone()),
                )
            })
            .collect();
        let store = Store::open(&volume).expect("the store opens");
        Self {
            root,
            _volume: volume,
            identity,
            rings,
            store,
        }
    }

    pub(crate) fn verified(&self) -> identity::Verified {
        identity::verify_published(
            &self.identity.document(),
            &self.identity.successions(),
            self.identity.first_public_key(),
        )
        .expect("verifies")
    }

    /// The presentation its sessions open with.
    pub(crate) fn presentation(&self) -> Vec<u8> {
        crate::session::record::Presentation {
            document: self.identity.document(),
            successions: self.identity.successions(),
            first_public_key: self.identity.first_public_key().to_vec(),
        }
        .encode()
        .expect("a presentation")
    }

    pub(crate) fn host_ref(&self) -> HostRef {
        HostRef {
            host_id: self.identity.host_id(),
            epoch: self.identity.epoch(),
            fingerprint: self.identity.first_fingerprint().to_owned(),
        }
    }

    pub(crate) fn statement(&self, ring: &str) -> RingStatement {
        statement_of(
            self.rings
                .iter()
                .find(|held| held.id() == ring)
                .expect("the ring"),
        )
        .expect("a statement")
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

pub(crate) const EXPORTER: [u8; 32] = [0xE1; 32];

thread_local! {
    /// The exporter the loopback's next task connections report instead of [`EXPORTER`]: a test
    /// that needs two connections to differ sets it (WP-4.7).
    pub(crate) static TASK_EXPORTER: std::cell::Cell<Option<[u8; 32]>> =
        const { std::cell::Cell::new(None) };
}

pub(crate) fn decisions(selector: &str) -> Task {
    Task {
        version: 1,
        task_id: "decisions".to_owned(),
        task_type: TaskType::DecisionsShip,
        selector: Selector::parse(selector).expect("a selector"),
        resource_types: vec!["decision".to_owned()],
        required: true,
        limits: record::Limits {
            max_body_bytes: 1 << 20,
            max_concurrency: 4,
            max_rate_per_minute: 600,
            max_batch_records: 1000,
            retention_seconds: 30 * 86_400,
        },
        assurance_requirements: Vec::new(),
    }
}

fn capabilities() -> Capabilities {
    Capabilities::default().declare(TaskType::DecisionsShip, Role::Coordinator)
}

/// Every contract at version 1, both sides: what a member declares when a test does not care.
pub(crate) fn member_capabilities() -> Vec<crate::membership::record::Capability> {
    TaskType::ALL
        .into_iter()
        .fold(Capabilities::default(), |capabilities, task| {
            capabilities
                .declare(task, Role::Coordinator)
                .declare(task, Role::Member)
        })
        .list()
}

/// An approval that brings nothing for the tasks' controls: what a task requiring none needs.
pub(crate) fn offered_nothing() -> Offered<'static> {
    static NOTHING: std::sync::LazyLock<appraisal::Appraisal> =
        std::sync::LazyLock::new(appraisal::Appraisal::default);
    Offered {
        appraisal: &NOTHING,
        approvals: &[],
        evidence: &[],
        principal: "spiffe://acme/operators/root",
    }
}

/// An invitation from `coordinator` for decisions under `plane/data/*`, and its token.
/// An invitation from `coordinator` that expects `member`, and its token.
pub(crate) fn invite_for(coordinator: &Host, member: &Host) -> (Invitation, [u8; 32]) {
    invite(
        coordinator,
        Some(member.identity.first_fingerprint().to_owned()),
    )
}

fn invite(coordinator: &Host, expected: Option<String>) -> (Invitation, [u8; 32]) {
    coordinator
        .store
        .invite(
            &Applying::for_tests(1),
            NewInvite {
                selector: Selector::parse("plane/data/*").expect("a selector"),
                tasks: vec![decisions("plane/data/*")],
                expires: None,
                expected_fingerprint: expected,
                min_assurance: Some(AssuranceProfile::Production),
            },
            "operator",
            now(),
        )
        .expect("invited")
}

/// The request `member` sends with `token` on a connection whose exporter is `exporter`.
fn request(
    coordinator: &Host,
    member: &Host,
    invitation: &Invitation,
    token: &[u8; 32],
    exporter: &[u8; 32],
) -> EnrollRequest {
    EnrollRequest {
        capabilities: member_capabilities(),
        invite_id: invitation.invite_id,
        token_proof: token_proof(
            token,
            &coordinator.identity.host_id(),
            &member.identity.host_id(),
            exporter,
        ),
        selector: Selector::parse("plane/data/*").expect("a selector"),
        tasks: vec![decisions("plane/data/*")],
        member: member.host_ref(),
        ring_statements: vec![member.statement(DATA_ATTEST)],
    }
}

/// Enrolls `member` with `coordinator`: the pending membership on both sides.
fn enroll(coordinator: &Host, member: &Host) -> Pending {
    let (invitation, token) = invite(
        coordinator,
        Some(member.identity.first_fingerprint().to_owned()),
    );
    let request = request(coordinator, member, &invitation, &token, &EXPORTER);
    let verified = member.verified();
    let pending = coordinator
        .store
        .check_enroll(
            &coordinator.coordinator(),
            &Enrolling {
                peer: &verified,
                presentation: &member.presentation(),
                declared_assurance: AssuranceProfile::Production,
                exporter: &EXPORTER,
            },
            &request,
            now(),
        )
        .expect("the enrollment checks");
    coordinator
        .store
        .enroll(&Applying::for_tests(2), &pending, now())
        .expect("enrolled");
    member
        .store
        .join(
            &Applying::for_tests(3),
            &Pending {
                coordinator_address: Some("https://coordinator:7443".to_owned()),
                ..pending.clone()
            },
            now(),
        )
        .expect("joined");
    pending
}

#[test]
fn a_coordinator_verification_schedule_survives_reopen_replays_and_only_the_proven_member_consumes_it()
 {
    let coordinator = Host::new("verify-schedule-c");
    let member = Host::new("verify-schedule-m");
    let pending = enroll(&coordinator, &member);
    let id = pending.membership_id;
    let scheduled_at = now();

    assert_eq!(
        coordinator
            .store
            .schedule_verification(&id, scheduled_at)
            .expect("scheduled"),
        scheduled_at
    );
    assert_eq!(
        coordinator
            .store
            .schedule_verification(&id, scheduled_at + 1)
            .expect("an exact replay is idempotent"),
        scheduled_at
    );
    assert!(
        member
            .store
            .schedule_verification(&id, scheduled_at)
            .is_err(),
        "the member side proves immediately instead of scheduling a coordinator challenge"
    );

    let reopened = Store::open(coordinator.volume()).expect("the store reopens");
    assert_eq!(
        reopened.verification_scheduled(&id).expect("readable"),
        Some(scheduled_at)
    );
    assert!(
        !reopened
            .satisfy_verification(&id, &coordinator.identity.host_id())
            .expect("a different proven Host changes nothing")
    );
    assert_eq!(
        reopened
            .verification_scheduled(&id)
            .expect("still readable"),
        Some(scheduled_at)
    );
    assert!(
        reopened
            .satisfy_verification(&id, &member.identity.host_id())
            .expect("the member's proven session consumes the schedule")
    );
    assert_eq!(
        reopened.verification_scheduled(&id).expect("readable"),
        None
    );
}

#[test]
fn verification_recovery_keeps_the_exact_result_after_consumption_and_a_later_schedule() {
    let coordinator = Host::new("verify-recovery-c");
    let member = Host::new("verify-recovery-m");
    let pending = enroll(&coordinator, &member);
    let id = pending.membership_id;
    let first_at = now();
    let first_result = "the exact first answer".to_owned();
    let first_revision = coordinator.store.membership(&id).expect("held").revision;
    let mutations = crate::operations::mutation::Mutations::open_offline(
        coordinator.volume(),
        "verification-recovery-test",
    )
    .expect("the mutation engine opens");
    let request_id = "verify-recovery-request".to_owned();
    let begin = crate::operations::mutation::Begin {
        domain: DOMAIN,
        operation: VERIFY,
        action: AUDIT_VERIFIED,
        initiator: crate::operations::journal::Initiator::Principal(
            "spiffe://acme/operators/root".to_owned(),
        ),
        request: Some(crate::operations::journal::RequestKey {
            request_id,
            digest: "the same request digest".to_owned(),
        }),
        target: Some(uuid_text(&id)),
    };
    let interrupted = mutations.run::<String, String>(begin.clone(), |applying| {
        coordinator
            .store
            .schedule_verification_mutation(applying, &id, first_at)
            .expect("applied before the simulated crash");
        coordinator
            .store
            .record_verification_result(applying, &id, first_revision, &first_result)
            .expect("the exact result is durable before the simulated crash");
        Err(crate::operations::mutation::Failure::Indeterminate(
            "the process crashed after domain apply".to_owned(),
        ))
    });
    assert!(matches!(
        interrupted,
        Err(crate::operations::mutation::MutationError::Indeterminate(_))
    ));
    assert!(
        coordinator
            .store
            .satisfy_verification(&id, &member.identity.host_id())
            .expect("the first pending marker is consumed")
    );

    let later = Applying::for_tests(42);
    let later_at = first_at + 1;
    coordinator
        .store
        .schedule_verification_mutation(&later, &id, later_at)
        .expect("a later verification is scheduled");
    coordinator
        .store
        .record_verification_result(&later, &id, first_revision, &"the later answer".to_owned())
        .expect("the later exact result is durable");
    assert!(
        coordinator
            .store
            .record_verification_result(
                &later,
                &id,
                first_revision,
                &"a different answer".to_owned(),
            )
            .is_err(),
        "an operation's exact result is immutable"
    );

    let recovered = mutations
        .recover(&Memberships(coordinator.store.as_ref()))
        .expect("the interrupted operation recovers");
    assert_eq!(recovered.reconciled.len(), 1);
    let replayed = mutations
        .run::<String, String>(begin, |_| unreachable!("recovery already applied it"))
        .expect("the recovered request replays");
    let operation_id = match replayed {
        crate::operations::mutation::Outcome::Reconciled {
            operation_id,
            revision,
            target,
        } => {
            assert_eq!(revision, first_revision);
            assert_eq!(target.as_deref(), Some(uuid_text(&id).as_str()));
            operation_id
        }
        other => panic!("the interrupted apply reconciles, not {other:?}"),
    };
    assert_eq!(
        coordinator
            .store
            .verification_result::<String>(&operation_id)
            .expect("the first exact result reads"),
        first_result
    );
    assert_eq!(
        Memberships(coordinator.store.as_ref())
            .observe(&operation_id, Some(&uuid_text(&[0x55; 16]))),
        None,
        "the immutable result belongs only to its original target"
    );
    assert_eq!(
        coordinator
            .store
            .verification_scheduled(&id)
            .expect("the later marker reads"),
        Some(later_at)
    );
}

/// What the member's sync would receive, and accepts.
fn sync(coordinator: &Host, member: &Host, id: &[u8; 16]) -> Status {
    let held = member.store.membership(id).expect("held").epoch();
    let answer = coordinator
        .store
        .answer(
            &coordinator.coordinator(),
            id,
            &member.identity.host_id(),
            Some(held),
        )
        .expect("answered");
    let accepted = member
        .store
        .check_sync(id, &coordinator.verified(), &answer, now())
        .expect("the manifests verify");
    for (manifest, envelope, digest) in accepted {
        member
            .store
            .accept(
                &Applying::for_tests(9),
                &manifest,
                &envelope,
                &digest,
                now(),
            )
            .expect("accepted");
    }
    member.store.membership(id).expect("held").status
}

#[test]
fn the_lifecycle_between_two_hosts() {
    let (c, m) = (Host::new("life-c"), Host::new("life-m"));
    let pending = enroll(&c, &m);
    let id = pending.membership_id;
    assert_eq!(
        c.store.membership(&id).expect("held").status,
        Status::Pending
    );
    assert_eq!(sync(&c, &m, &id), Status::Pending, "nothing to accept yet");

    let (manifest, _, _) = c
        .store
        .check_approve(
            &c.coordinator(),
            &capabilities(),
            &id,
            None,
            None,
            &offered_nothing(),
            Some(1),
            now(),
        )
        .expect("approvable");
    c.store
        .approve(&Applying::for_tests(4), &c.coordinator(), &manifest, now())
        .expect("approved");
    assert_eq!(sync(&c, &m, &id), Status::Active);

    for (to, op) in [
        (Status::Suspended, 5u8),
        (Status::Active, 6),
        (Status::Active, 7),
        (Status::Revoked, 8),
    ] {
        let next = c
            .store
            .check_successor(&c.coordinator(), &id, to, None, now())
            .expect("a successor");
        c.store
            .transition(&Applying::for_tests(op), &c.coordinator(), &next, now())
            .expect("issued");
        assert_eq!(sync(&c, &m, &id), to);
    }
    let held = c.store.membership(&id).expect("held");
    assert_eq!(held.epoch(), 5, "every manifest revision is a new epoch");
    assert_eq!(m.store.membership(&id).expect("held").epoch(), 5);

    // A membership that ended pins its member for one thing: reading how it ended.
    use crate::session::peers::PinSource as _;
    use crate::session::record::Operation;
    let member = m.identity.host_id();
    let fingerprint = Some(m.identity.first_fingerprint().to_owned());
    assert_eq!(
        c.store.pin(&member, Some(Operation::Membership)),
        fingerprint
    );
    for operation in [Some(Operation::Task), Some(Operation::Enroll), None] {
        assert_eq!(c.store.pin(&member, operation), None, "{operation:?}");
    }
    // The member pins its coordinator for nothing any more: it reads with the pin it holds.
    assert_eq!(
        m.store
            .pin(&c.identity.host_id(), Some(Operation::Membership)),
        None
    );

    // Terminal: nothing leaves `revoked`.
    assert!(matches!(
        c.store
            .check_successor(&c.coordinator(), &id, Status::Active, None, now()),
        Err(MembershipError::Transition { .. })
    ));

    // The files the blueprint lays out, and a reopened store rebuilt from the journal.
    let members = c.root.join("host/members");
    for file in [FORMAT, JOURNAL, SNAPSHOT] {
        assert!(members.join(file).is_file(), "{file}");
    }
    let dir = members.join(MANIFESTS).join(hex(&id));
    assert!(dir.join(CURRENT).is_file());
    assert_eq!(
        std::fs::read_dir(dir.join(HISTORY))
            .expect("history")
            .count(),
        5
    );
    let reopened = Store::open(&c._volume).expect("reopens");
    assert_eq!(reopened.membership(&id), c.store.membership(&id));
    let reopened = Store::open(&m._volume).expect("reopens");
    assert_eq!(reopened.membership(&id), m.store.membership(&id));
}

#[test]
fn a_token_enrolls_once_and_its_proof_binds_the_connection() {
    let (c, m) = (Host::new("token-c"), Host::new("token-m"));
    let (invitation, token) = invite(&c, None);
    let verified = m.verified();
    let check = |request: &EnrollRequest, declared: AssuranceProfile, exporter: &[u8; 32]| {
        c.store.check_enroll(
            &c.coordinator(),
            &Enrolling {
                peer: &verified,
                presentation: &m.presentation(),
                declared_assurance: declared,
                exporter,
            },
            request,
            now(),
        )
    };
    let good = request(&c, &m, &invitation, &token, &EXPORTER);
    // A proof computed for another connection, or with another token, is refused.
    assert!(matches!(
        check(&good, AssuranceProfile::Production, &[0xE2; 32]),
        Err(MembershipError::Enrollment(_))
    ));
    assert!(matches!(
        check(
            &request(&c, &m, &invitation, &[7; 32], &EXPORTER),
            AssuranceProfile::Production,
            &EXPORTER
        ),
        Err(MembershipError::Enrollment(_))
    ));
    // Below the invitation's floor.
    assert!(matches!(
        check(&good, AssuranceProfile::Development, &EXPORTER),
        Err(MembershipError::Enrollment(_))
    ));
    // Asking for more than offered.
    let mut wider = good.clone();
    wider.selector = Selector::parse("plane/control/*").expect("a selector");
    assert!(check(&wider, AssuranceProfile::Production, &EXPORTER).is_err());

    let pending = check(&good, AssuranceProfile::Production, &EXPORTER).expect("checks");
    c.store
        .enroll(&Applying::for_tests(2), &pending, now())
        .expect("enrolled");
    assert!(
        matches!(
            check(&good, AssuranceProfile::Production, &EXPORTER),
            Err(MembershipError::Enrollment(_))
        ),
        "a second use"
    );
    assert_eq!(c.store.invitations(now())[0].1, "consumed");

    // The token never reaches the volume.
    for entry in walk(&c.root) {
        let bytes = std::fs::read(&entry).expect("reads");
        assert!(
            !bytes.windows(token.len()).any(|window| window == token),
            "{} holds the token",
            entry.display()
        );
    }
    assert!(
        c.root
            .join(format!(
                "host/members/invites/{}.cbor",
                hex(&invitation.invite_id)
            ))
            .is_file()
    );
}

fn walk(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("lists").flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files
}

#[test]
fn an_expected_fingerprint_refuses_another_member() {
    let (c, m, other) = (Host::new("fp-c"), Host::new("fp-m"), Host::new("fp-o"));
    let (invitation, token) = invite(&c, Some(m.identity.first_fingerprint().to_owned()));
    let verified = other.verified();
    let refused = c.store.check_enroll(
        &c.coordinator(),
        &Enrolling {
            peer: &verified,
            presentation: &other.presentation(),
            declared_assurance: AssuranceProfile::Production,
            exporter: &EXPORTER,
        },
        &request(&c, &other, &invitation, &token, &EXPORTER),
        now(),
    );
    assert!(matches!(refused, Err(MembershipError::Enrollment(_))));
}

#[test]
fn approval_narrows_and_never_widens() {
    let (c, m) = (Host::new("narrow-c"), Host::new("narrow-m"));
    let id = enroll(&c, &m).membership_id;
    let approve = |narrow: Option<Narrow>, capabilities: &Capabilities| {
        c.store.check_approve(
            &c.coordinator(),
            capabilities,
            &id,
            narrow.as_ref(),
            None,
            &offered_nothing(),
            None,
            now(),
        )
    };
    let wider = Narrow {
        selector: Selector::parse("plane/control/*").expect("a selector"),
        tasks: vec![decisions("plane/control/*")],
    };
    assert!(matches!(
        approve(Some(wider), &capabilities()),
        Err(MembershipError::Widened(_))
    ));
    let mut more = decisions("plane/data/*");
    more.limits.max_concurrency += 1;
    assert!(matches!(
        approve(
            Some(Narrow {
                selector: Selector::parse("plane/data/*").expect("a selector"),
                tasks: vec![more],
            }),
            &capabilities()
        ),
        Err(MembershipError::Widened(_))
    ));
    let narrower = Narrow {
        selector: Selector::parse("plane/data/zone/z1/*").expect("a selector"),
        tasks: vec![decisions("plane/data/zone/z1/*")],
    };
    let (manifest, _, _) = approve(Some(narrower), &capabilities()).expect("narrowed");
    assert_eq!(manifest.selector.to_string(), "plane/data/zone/z1/*");
    assert!(
        manifest
            .ring_pins
            .iter()
            .any(|pin| pin.owner == Role::Member && pin.ring == DATA_ATTEST),
        "the member's data ring is pinned for decisions.ship"
    );
    assert!(matches!(
        approve(None, &Capabilities::default()),
        Err(MembershipError::TaskUnserved(_))
    ));
}

/// WP-4.2: a requirement names a registered control, the coordinator's policy must appraise it,
/// and an approval stands only on the evidence the policy wants; the member accepts the manifest
/// carrying the binding.
#[test]
fn a_task_requiring_a_control_is_approved_only_on_the_evidence_the_policy_wants() {
    let (c, m) = (Host::new("assurance-c"), Host::new("assurance-m"));
    let mut task = decisions("plane/data/*");
    let offer = |task: &Task| NewInvite {
        selector: Selector::parse("plane/data/*").expect("a selector"),
        tasks: vec![task.clone()],
        expires: None,
        expected_fingerprint: None,
        min_assurance: None,
    };
    task.assurance_requirements = vec!["hsm".to_owned()];
    assert!(matches!(
        c.store
            .invite(&Applying::for_tests(1), offer(&task), "operator", now()),
        Err(MembershipError::Invalid(_))
    ));
    task.assurance_requirements = vec![permguard_core::domains::assurance::CUSTODY_HSM.to_owned()];
    let (invitation, token) = c
        .store
        .invite(&Applying::for_tests(1), offer(&task), "operator", now())
        .expect("invited");
    let mut asked = request(&c, &m, &invitation, &token, &EXPORTER);
    asked.tasks = vec![task];
    let verified = m.verified();
    let pending = c
        .store
        .check_enroll(
            &c.coordinator(),
            &Enrolling {
                peer: &verified,
                presentation: &m.presentation(),
                declared_assurance: AssuranceProfile::Regulated,
                exporter: &EXPORTER,
            },
            &asked,
            now(),
        )
        .expect("checks");
    c.store
        .enroll(&Applying::for_tests(2), &pending, now())
        .expect("enrolled");
    m.store
        .join(
            &Applying::for_tests(3),
            &Pending {
                coordinator_address: Some("https://coordinator:7443".to_owned()),
                ..pending.clone()
            },
            now(),
        )
        .expect("joined");
    let id = pending.membership_id;
    let approve = |offered: &Offered<'_>| {
        c.store.check_approve(
            &c.coordinator(),
            &capabilities(),
            &id,
            None,
            None,
            offered,
            None,
            now(),
        )
    };
    // A policy that appraises nothing: unapprovable.
    assert!(matches!(
        approve(&offered_nothing()),
        Err(MembershipError::AssuranceRefused(_))
    ));
    // The test policy wants `custody.hsm` attested: the `regulated` declaration is not enough.
    let appraisal = appraisal::tests::appraisal();
    let with = |evidence: &[appraisal::Evidence]| {
        approve(&Offered {
            appraisal: &appraisal,
            approvals: &[],
            evidence,
            principal: "operator",
        })
    };
    assert!(matches!(
        with(&[]),
        Err(MembershipError::AssuranceRefused(_))
    ));
    // Evidence bound to the pending request's nonce is accepted.
    let state = Digest::compute(&pending.encode().expect("encodes"));
    let nonce = appraisal::nonce(&c.identity.host_id(), &id, &state);
    let evidence = [appraisal::Evidence {
        verifier: appraisal::tests::VERIFIER.to_owned(),
        evidence: appraisal::tests::evidence(
            &nonce,
            &[permguard_core::assurance::Control::CustodyHsm],
        ),
    }];
    let (manifest, _, approvals) = with(&evidence).expect("approvable");
    assert!(approvals.is_empty());
    let binding = manifest.assurance_binding.clone().expect("a binding");
    assert_eq!(binding.task_ids, ["decisions"]);
    c.store
        .approve(&Applying::for_tests(4), &c.coordinator(), &manifest, now())
        .expect("approved");
    // The member verifies and keeps the manifest with its binding.
    assert_eq!(sync(&c, &m, &id), Status::Active);
    let held = m.store.membership(&id).expect("held");
    assert_eq!(
        held.manifest.expect("a manifest").0.assurance_binding,
        Some(binding)
    );
}

#[test]
fn same_epoch_other_digest_is_equivocation_and_a_skipped_revision_is_refused() {
    let (c, m) = (Host::new("equiv-c"), Host::new("equiv-m"));
    let id = enroll(&c, &m).membership_id;
    let (manifest, _, _) = c
        .store
        .check_approve(
            &c.coordinator(),
            &capabilities(),
            &id,
            None,
            None,
            &offered_nothing(),
            None,
            now(),
        )
        .expect("approvable");
    c.store
        .approve(&Applying::for_tests(4), &c.coordinator(), &manifest, now())
        .expect("approved");
    assert_eq!(sync(&c, &m, &id), Status::Active);

    // The coordinator's key signs another epoch-1 manifest: equivocation.
    let operations = c
        .rings
        .iter()
        .find(|ring| ring.id() == HOST_OPERATIONS)
        .expect("the ring");
    let other = Manifest {
        issued_at: manifest.issued_at + 1,
        ..manifest.clone()
    };
    let envelope = sign_manifest(operations, &other).expect("signed");
    let answer = c
        .store
        .answer(&c.coordinator(), &id, &m.identity.host_id(), Some(0))
        .expect("answered");
    let forged = MembershipAnswer {
        manifests: vec![envelope],
        ..answer.clone()
    };
    assert!(matches!(
        m.store.check_sync(&id, &c.verified(), &forged, now()),
        Err(MembershipError::Equivocation(_))
    ));

    // An epoch-3 manifest when the member holds 1: not the successor.
    let skipped = Manifest {
        epoch: 3,
        previous: Some(Digest::compute(b"elsewhere")),
        ..manifest.clone()
    };
    let skipped = MembershipAnswer {
        manifests: vec![sign_manifest(operations, &skipped).expect("signed")],
        ..answer.clone()
    };
    assert!(matches!(
        m.store.check_sync(&id, &c.verified(), &skipped, now()),
        Err(MembershipError::NotSuccessor(_))
    ));

    // A manifest signed by a key outside the bound operations set does not verify.
    let data = c
        .rings
        .iter()
        .find(|ring| ring.id() == DATA_ATTEST)
        .expect("the ring");
    let foreign = MembershipAnswer {
        manifests: vec![sign_manifest(data, &other).expect("signed")],
        ..answer
    };
    assert!(matches!(
        m.store.check_sync(&id, &c.verified(), &foreign, now()),
        Err(MembershipError::Unverified(_))
    ));
}

#[test]
fn a_tampered_journal_does_not_open() {
    let (c, m) = (Host::new("tamper-c"), Host::new("tamper-m"));
    enroll(&c, &m);
    let journal = c.root.join("host/members").join(JOURNAL);
    // An earlier entry changed: the next one's chain no longer names it. (The last entry has no
    // successor to name it; its bytes still have to decode as an entry the history allows.)
    let mut bytes = std::fs::read(&journal).expect("reads");
    bytes[40] ^= 1;
    std::fs::write(&journal, bytes).expect("written");
    assert!(Store::open(&c._volume).is_err());
}

#[test]
fn a_member_may_be_orphaned_and_a_terminal_membership_may_not() {
    let (c, m) = (Host::new("orphan-c"), Host::new("orphan-m"));
    let id = enroll(&c, &m).membership_id;
    m.store
        .orphan(&Applying::for_tests(5), &id, now())
        .expect("orphaned");
    assert_eq!(
        m.store.membership(&id).expect("held").status,
        Status::Orphaned
    );
    assert!(m.store.orphan(&Applying::for_tests(6), &id, now()).is_err());
    assert!(
        m.store.pins().is_empty(),
        "an orphaned membership pins nobody"
    );
}

#[test]
fn the_request_actions_read_back() {
    let request = MembershipRequest {
        action: Action::Fetch,
        membership_id: [1; 16],
        held_epoch: None,
    };
    assert_eq!(
        MembershipRequest::decode(&request.encode().expect("e")).expect("d"),
        request
    );
}

pub(crate) mod protocol {
    //! The whole protocol through real sessions: the member's `Initiator`, the coordinator's
    //! `Responder` serving `Coordinating`, one in-memory connection whose exporter both sides
    //! read.

    use super::*;
    use crate::api::testing::Recording;
    use crate::membership::member::{Connector, Exchange, Exchanged, Join, Member, Target};
    use crate::membership::service::Coordinating;
    use crate::operations::journal::Initiator as Who;
    use crate::operations::mutation::Mutations;
    use crate::session::peers::Peers;
    use crate::session::{Context, Frame, Initiator, Request, Responder};

    /// A task handler that answers each body with `echo:` before it.
    pub(crate) struct Echo;

    impl crate::membership::task::TaskHandler for Echo {
        fn handle(
            &self,
            _context: &crate::membership::task::TaskContext,
            body: &[u8],
        ) -> Result<Vec<u8>, crate::session::Refusal> {
            // How often it was reached, so a test tells a replay from a second answer (WP-4.4).
            if body == b"count?" {
                static COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                let count = COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                return Ok(format!("count={count}").into_bytes());
            }
            // An answer over the task message bound, which the router never sends.
            if body == b"big?" {
                return Ok(vec![0; crate::membership::record::MAX_BODY_BYTES + 1]);
            }
            // What the handler is told: the version and the limits it applies (WP-4.4).
            if body == b"context?" {
                return Ok(format!(
                    "version={} batch={} retention={}",
                    _context.version,
                    _context.limits.max_batch_records,
                    _context.limits.retention_seconds
                )
                .into_bytes());
            }
            // A store the handler cannot reach now (WP-5.4).
            if body == b"unavailable?" {
                return Err(crate::session::Refusal {
                    code: permguard_core::codes::stream::STORE_UNAVAILABLE,
                    reason: "the store cannot answer now".to_owned(),
                });
            }
            Ok([b"echo:".as_slice(), body].concat())
        }

        // A fork, reported through the session's incidents (WP-5.3).
        fn handle_with(
            &self,
            context: &crate::membership::task::TaskContext,
            body: &[u8],
            incidents: &dyn crate::membership::task::Incidents,
        ) -> Result<Vec<u8>, crate::session::Refusal> {
            // Two reports in one message: the second, the membership suspended, does nothing.
            if body == b"fork twice?" {
                for _ in 0..2 {
                    incidents
                        .stream_forked("data/decisions/forked/run", 3)
                        .map_err(|reason| crate::session::Refusal {
                            code: permguard_core::codes::common::UNAVAILABLE,
                            reason,
                        })?;
                }
                return Ok(b"forked".to_vec());
            }
            if body == b"fork?" {
                incidents
                    .stream_forked("data/decisions/forked/run", 3)
                    .map_err(|reason| crate::session::Refusal {
                        code: permguard_core::codes::common::UNAVAILABLE,
                        reason,
                    })?;
                return Ok(b"forked".to_vec());
            }
            self.handle(context, body)
        }
    }

    /// What the protocol harness registers on `role`'s side: `decisions.ship` at versions 1 and
    /// 2 and `events.ship` at 1 (WP-4.4).
    pub(crate) fn harness(role: Role) -> Capabilities {
        [
            (TaskType::DecisionsShip, 1),
            (TaskType::DecisionsShip, 2),
            (TaskType::EventsShip, 1),
            (TaskType::EventsImport, 1),
        ]
        .into_iter()
        .fold(Capabilities::default(), |capabilities, (task, version)| {
            capabilities.register(record::Capability {
                task_type: task,
                version,
                role: record::ContractRole::of(task, role),
            })
        })
    }

    pub(crate) struct Side {
        pub(crate) host: Host,
        pub(crate) mutations: Arc<Mutations>,
        pub(crate) context: Context,
        pub(crate) tasks: Arc<crate::membership::task::Tasks>,
        pub(crate) trail: Arc<Recording>,
    }

    impl Side {
        pub(crate) fn new(tag: &str, service: bool) -> Self {
            Self::of(Host::new(tag), service)
        }

        /// The side of `host`, serving as a coordinator when `service`.
        pub(crate) fn of(host: Host, service: bool) -> Self {
            Self::timed(
                host,
                service,
                Arc::new(TimeGuard::system(Duration::from_secs(30))),
            )
        }

        /// The side of `host` on `time`.
        pub(crate) fn timed(host: Host, service: bool, time: Arc<TimeGuard>) -> Self {
            Self::handling(host, service, time, |_, _| {
                crate::membership::task::TaskHandlers::default()
            })
        }

        /// [`Side::timed`], its coordinator serving the handlers `handlers` builds besides the
        /// harness's echo (WP-4.7).
        pub(crate) fn handling(
            host: Host,
            service: bool,
            time: Arc<TimeGuard>,
            handlers: impl FnOnce(&Host, &Arc<TimeGuard>) -> crate::membership::task::TaskHandlers,
        ) -> Self {
            let trail = Arc::new(Recording::default());
            let mutations = Arc::new(
                Mutations::open(
                    &host._volume,
                    Arc::clone(&trail) as Arc<dyn crate::operations::mutation::Projection>,
                    Arc::clone(&time),
                )
                .expect("the engine opens"),
            );
            let peers = Arc::new(Peers::open(&host._volume, &[]).expect("the peers"));
            peers.with_source(Arc::clone(&host.store) as Arc<dyn crate::session::peers::PinSource>);
            let registry = Arc::new(crate::keys::registry::Registry::new(
                Some(Arc::clone(&host.identity)),
                host.rings.clone(),
            ));
            let tasks = Arc::new(crate::membership::task::Tasks {
                appraisal: Arc::new(appraisal::tests::appraisal()),
                handlers: handlers(&host, &time)
                    .register(TaskType::DecisionsShip, 1, Arc::new(Echo))
                    .expect("one handler"),
                ..crate::membership::task::Tasks::default()
            });
            let service = service.then(|| {
                Arc::new(Coordinating {
                    store: Arc::clone(&host.store),
                    mutations: Arc::clone(&mutations),
                    identity: Arc::clone(&host.identity),
                    keys: registry,
                    capabilities: capabilities(),
                    time: Arc::clone(&time),
                    tasks: Arc::clone(&tasks),
                }) as Arc<dyn crate::session::Service>
            });
            let context = Context {
                identity: Arc::clone(&host.identity),
                peers,
                time,
                declared_assurance: AssuranceProfile::Production,
                audit: None,
                metrics: permguard_core::Metrics::none(),
                service,
            };
            Self {
                host,
                mutations,
                context,
                tasks,
                trail,
            }
        }
    }

    /// The member's connection to the coordinator, in memory; `tamper` changes the request after
    /// its digest went into the hello.
    pub(crate) struct Loopback<'a> {
        pub(crate) member: &'a Side,
        pub(crate) coordinator: &'a Side,
        pub(crate) tamper: bool,
    }

    /// An open task session in memory: the coordinator's responder, kept with the session, and
    /// the watch it became.
    struct LoopTask {
        responder: Responder,
        watch: Option<Box<dyn crate::session::Watching>>,
    }

    impl crate::membership::member::TaskChannel for LoopTask {
        fn exchange(
            &mut self,
            message: Vec<u8>,
        ) -> permguard_core::BoxFuture<'_, Result<Vec<u8>, crate::session::Refusal>> {
            let result = match self.responder.receive(Frame::Task(message)) {
                Ok(mut frames) => match frames.pop() {
                    Some(Frame::Task(answer)) => Ok(answer),
                    Some(Frame::Refusal { code }) => Err(crate::session::Refusal {
                        code: Box::leak(code.into_boxed_str()),
                        reason: "refused".to_owned(),
                    }),
                    other => panic!("an answer, not {other:?}"),
                },
                Err(refusal) => Err(refusal),
            };
            if let Some(watch) = self.responder.take_watch() {
                self.watch = Some(watch);
            }
            Box::pin(std::future::ready(result))
        }

        /// What the watch yields now: its hints, else a heartbeat, as the transport would send
        /// them without waiting.
        fn receive(
            &mut self,
        ) -> permguard_core::BoxFuture<'_, Result<Vec<u8>, crate::session::Refusal>> {
            let result = match self.watch.as_mut() {
                Some(watch) => match watch.poll() {
                    Ok(Some(frame)) => Ok(frame),
                    Ok(None) => watch.heartbeat(),
                    Err(refusal) => Err(refusal),
                },
                None => Err(crate::session::Refusal {
                    code: permguard_core::codes::common::INVALID_ARGUMENT,
                    reason: "no watch".to_owned(),
                }),
            };
            Box::pin(std::future::ready(result))
        }
    }

    impl Connector for Loopback<'_> {
        fn exchange(
            &self,
            target: Target,
            exchange: Exchange,
        ) -> permguard_core::BoxFuture<'_, Result<Exchanged, crate::session::Refusal>> {
            let result = (|| {
                let exporter = EXPORTER;
                let mut bytes = (exchange.build)(&exporter)?;
                let digest = record::request_digest(&bytes);
                if self.tamper {
                    bytes.push(0);
                }
                let mut initiator = Initiator::new(
                    self.member.context.clone(),
                    exporter,
                    Request {
                        peer: target.host_id,
                        operation: exchange.operation,
                        membership_id: exchange.membership_id.as_ref().map(uuid_text),
                        task: None,
                        request_digest: Some(digest),
                        // As the server's connector: only a join brings its own pin.
                        pin: (exchange.operation == crate::session::record::Operation::Enroll)
                            .then(|| (target.host_id, target.fingerprint.clone())),
                    },
                );
                let mut responder = Responder::new(self.coordinator.context.clone(), exporter);
                let mut outbound = initiator.start()?;
                while initiator.session().is_none() {
                    let mut inbound = Vec::new();
                    for frame in outbound.drain(..) {
                        inbound.extend(responder.receive(frame)?);
                    }
                    for frame in inbound {
                        outbound.extend(initiator.receive(frame)?);
                    }
                }
                let answer = match responder.receive(Frame::Task(bytes))?.pop() {
                    Some(Frame::Task(answer)) => answer,
                    Some(Frame::Refusal { code }) => {
                        return Err(crate::session::Refusal {
                            code: Box::leak(code.into_boxed_str()),
                            reason: "refused".to_owned(),
                        });
                    }
                    other => panic!("an answer, not {other:?}"),
                };
                Ok(Exchanged {
                    peer: initiator.peer().expect("verified").clone(),
                    answer,
                })
            })();
            Box::pin(std::future::ready(result))
        }

        fn open_task(
            &self,
            target: Target,
            open: crate::membership::member::TaskOpen,
        ) -> permguard_core::BoxFuture<
            '_,
            Result<crate::membership::member::TaskOpened, crate::session::Refusal>,
        > {
            let result = (|| {
                let exporter = super::TASK_EXPORTER
                    .with(std::cell::Cell::get)
                    .unwrap_or(EXPORTER);
                let mut initiator = Initiator::new(
                    self.member.context.clone(),
                    exporter,
                    Request {
                        peer: target.host_id,
                        operation: crate::session::record::Operation::Task,
                        membership_id: Some(uuid_text(&open.membership_id)),
                        task: Some(open.task_id.clone()),
                        request_digest: None,
                        pin: None,
                    },
                );
                let mut responder = Responder::new(self.coordinator.context.clone(), exporter);
                let mut outbound = initiator.start()?;
                while initiator.session().is_none() {
                    let mut inbound = Vec::new();
                    for frame in outbound.drain(..) {
                        inbound.extend(responder.receive(frame)?);
                    }
                    for frame in inbound {
                        outbound.extend(initiator.receive(frame)?);
                    }
                }
                let answer = match responder.receive(Frame::Task(open.request))?.pop() {
                    Some(Frame::Task(answer)) => answer,
                    other => panic!("a lease answer, not {other:?}"),
                };
                Ok(crate::membership::member::TaskOpened {
                    peer: initiator.peer().expect("verified").clone(),
                    // `tamper` reports another connection than the one the lease was bound to.
                    exporter: if self.tamper { [0xE2; 32] } else { exporter },
                    answer,
                    channel: Box::new(LoopTask {
                        responder,
                        watch: None,
                    }),
                })
            })();
            Box::pin(std::future::ready(result))
        }
    }

    pub(crate) fn member<'a>(side: &'a Side, connector: &'a dyn Connector) -> Member<'a> {
        Member {
            store: &side.host.store,
            mutations: &side.mutations,
            identity: &side.host.identity,
            rings: &side.host.rings,
            capabilities: Box::leak(Box::new(harness(Role::Member))),
            connector,
            declared_assurance: AssuranceProfile::Production,
            time: &side.context.time,
            streams: None,
            shipping: None,
        }
    }

    /// A membership of `m` with `c`, joined over the loopback, approved with `lease_policy` and
    /// synced: active on both sides.
    pub(crate) async fn active(c: &Side, m: &Side, lease_policy: Option<LeasePolicy>) -> [u8; 16] {
        let (invitation, token) = invite(
            &c.host,
            Some(m.host.identity.first_fingerprint().to_owned()),
        );
        let loopback = Loopback {
            member: m,
            coordinator: c,
            tamper: false,
        };
        let member = member(m, &loopback);
        let who = || Who::Principal("spiffe://acme/operators/member".to_owned());
        let id = member
            .join(who(), join_of(c, &invitation, &token))
            .await
            .expect("joined")
            .request
            .membership_id;
        let (manifest, _, _) = c
            .host
            .store
            .check_approve(
                &c.host.coordinator(),
                &capabilities(),
                &id,
                None,
                lease_policy,
                &offered_nothing(),
                None,
                now(),
            )
            .expect("approvable");
        c.host
            .store
            .approve(
                &Applying::for_tests(41),
                &c.host.coordinator(),
                &manifest,
                now(),
            )
            .expect("approved");
        member.sync(who(), &id).await.expect("synced");
        id
    }

    /// [`active`], its task requiring `controls`, approved on an attestation of them by the test
    /// verifier against the pending request's nonce (WP-4.2).
    pub(crate) async fn active_requiring(
        c: &Side,
        m: &Side,
        controls: &[permguard_core::assurance::Control],
    ) -> [u8; 16] {
        let mut task = decisions("plane/data/*");
        task.assurance_requirements = controls.iter().map(|c| c.name().to_owned()).collect();
        active_with(c, m, task, controls, &[]).await
    }

    /// A membership of `m` with `c` granting `task`, approved on an attestation of `attested`
    /// against the pending request's nonce and on the operator's `approvals`.
    pub(crate) async fn active_with(
        c: &Side,
        m: &Side,
        task: Task,
        attested: &[permguard_core::assurance::Control],
        approvals: &[appraisal::Approval],
    ) -> [u8; 16] {
        let controls = attested;
        let (invitation, token) = c
            .host
            .store
            .invite(
                &Applying::for_tests(1),
                NewInvite {
                    selector: Selector::parse("plane/data/*").expect("a selector"),
                    tasks: vec![task.clone()],
                    expires: None,
                    expected_fingerprint: Some(m.host.identity.first_fingerprint().to_owned()),
                    min_assurance: None,
                },
                "operator",
                now(),
            )
            .expect("invited");
        let loopback = Loopback {
            member: m,
            coordinator: c,
            tamper: false,
        };
        let member = member(m, &loopback);
        let who = || Who::Principal("spiffe://acme/operators/member".to_owned());
        let id = member
            .join(
                who(),
                Join {
                    tasks: vec![task],
                    ..join_of(c, &invitation, &token)
                },
            )
            .await
            .expect("joined")
            .request
            .membership_id;
        let pending = c.host.store.membership(&id).expect("held").request;
        let nonce = appraisal::nonce(
            &c.host.identity.host_id(),
            &id,
            &Digest::compute(&pending.encode().expect("encodes")),
        );
        let evidence: Vec<appraisal::Evidence> = if controls.is_empty() {
            Vec::new()
        } else {
            vec![appraisal::Evidence {
                verifier: appraisal::tests::VERIFIER.to_owned(),
                evidence: appraisal::tests::evidence(&nonce, controls),
            }]
        };
        let (manifest, _, _) = c
            .host
            .store
            .check_approve(
                &c.host.coordinator(),
                &harness(Role::Coordinator),
                &id,
                None,
                None,
                &Offered {
                    appraisal: &c.tasks.appraisal,
                    approvals,
                    evidence: &evidence,
                    principal: "operator",
                },
                None,
                now(),
            )
            .expect("approvable");
        c.host
            .store
            .approve(
                &Applying::for_tests(43),
                &c.host.coordinator(),
                &manifest,
                now(),
            )
            .expect("approved");
        member.sync(who(), &id).await.expect("synced");
        id
    }

    /// Moves `id` to `to` on the coordinator: a successor, a new epoch.
    pub(crate) fn move_to(c: &Side, id: &[u8; 16], to: Status, operation: u8) {
        let manifest = c
            .host
            .store
            .check_successor(&c.host.coordinator(), id, to, None, now())
            .expect("a successor");
        c.host
            .store
            .transition(
                &Applying::for_tests(operation),
                &c.host.coordinator(),
                &manifest,
                now(),
            )
            .expect("issued");
    }

    pub(crate) fn join_of(c: &Side, invitation: &Invitation, token: &[u8; 32]) -> Join {
        Join {
            coordinator: Target {
                address: "https://coordinator:7443".to_owned(),
                host_id: c.host.identity.host_id(),
                fingerprint: c.host.identity.first_fingerprint().to_owned(),
            },
            invite_id: invitation.invite_id,
            token: token.to_vec(),
            selector: Selector::parse("plane/data/*").expect("a selector"),
            tasks: vec![decisions("plane/data/*")],
        }
    }

    #[tokio::test]
    async fn a_member_joins_syncs_and_revokes_through_proven_sessions() {
        let (c, m) = (Side::new("proto-c", true), Side::new("proto-m", false));
        let (invitation, token) = invite(
            &c.host,
            Some(m.host.identity.first_fingerprint().to_owned()),
        );
        let loopback = Loopback {
            member: &m,
            coordinator: &c,
            tamper: false,
        };
        let member = member(&m, &loopback);
        let who = || Who::Principal("spiffe://acme/operators/member".to_owned());
        let held = member
            .join(who(), join_of(&c, &invitation, &token))
            .await
            .expect("joined");
        let id = held.request.membership_id;
        assert_eq!(held.status, Status::Pending);
        assert_eq!(
            c.host.store.membership(&id).expect("enrolled").status,
            Status::Pending
        );
        // A join retried after it was recorded answers the membership, not a spent token.
        let again = member
            .join(who(), join_of(&c, &invitation, &token))
            .await
            .expect("the retry answers");
        assert_eq!(again.request.membership_id, id);
        assert_eq!(c.host.store.memberships().len(), 1);
        // The coordinator pins the member, the member the coordinator.
        assert!(
            c.host
                .store
                .pins()
                .iter()
                .any(|(host, _)| *host == m.host.identity.host_id())
        );
        assert!(
            m.host
                .store
                .pins()
                .iter()
                .any(|(host, _)| *host == c.host.identity.host_id())
        );

        let (manifest, _, _) = c
            .host
            .store
            .check_approve(
                &c.host.coordinator(),
                &capabilities(),
                &id,
                None,
                None,
                &offered_nothing(),
                None,
                now(),
            )
            .expect("approvable");
        c.host
            .store
            .approve(
                &Applying::for_tests(40),
                &c.host.coordinator(),
                &manifest,
                now(),
            )
            .expect("approved");
        assert_eq!(
            member.sync(who(), &id).await.expect("synced").status,
            Status::Active
        );
        let fenced = c
            .host
            .store
            .check_successor(&c.host.coordinator(), &id, Status::Active, None, now())
            .expect("a fence");
        c.host
            .store
            .transition(
                &Applying::for_tests(41),
                &c.host.coordinator(),
                &fenced,
                now(),
            )
            .expect("fenced");
        let synced = member.sync(who(), &id).await.expect("synced");
        assert_eq!((synced.status, synced.epoch()), (Status::Active, 2));
        // A second sync is a retry: nothing new.
        assert_eq!(member.sync(who(), &id).await.expect("again").epoch(), 2);

        let revoked = member
            .revoke(who(), &id)
            .await
            .expect("revoked at the coordinator");
        assert_eq!(revoked.status, Status::Revoked);
        assert_eq!(
            c.host.store.membership(&id).expect("held").status,
            Status::Revoked
        );
        // A join retried now answers the membership held, revoked: the spent token goes nowhere.
        let retried = member
            .join(who(), join_of(&c, &invitation, &token))
            .await
            .expect("answered locally");
        assert_eq!(retried.status, Status::Revoked);
        assert_eq!(c.host.store.memberships().len(), 1);
    }

    #[tokio::test]
    async fn a_request_whose_bytes_are_not_the_ones_the_transcript_signed_is_refused() {
        let (c, m) = (
            Side::new("proto-tamper-c", true),
            Side::new("proto-tamper-m", false),
        );
        let (invitation, token) = invite(&c.host, None);
        let loopback = Loopback {
            member: &m,
            coordinator: &c,
            tamper: true,
        };
        let refused = member(&m, &loopback)
            .join(
                Who::Principal("operator".to_owned()),
                join_of(&c, &invitation, &token),
            )
            .await
            .expect_err("tampered");
        assert!(
            refused.to_string().contains("the transcript signed"),
            "{refused}"
        );
        assert_eq!(
            c.host.store.invitations(now())[0].1,
            "issued",
            "nothing consumed"
        );
    }

    #[tokio::test]
    async fn a_pending_membership_revoked_by_its_member_ends_by_a_rejection() {
        let (c, m) = (Side::new("pending-c", true), Side::new("pending-m", false));
        let (invitation, token) = invite(&c.host, None);
        let loopback = Loopback {
            member: &m,
            coordinator: &c,
            tamper: false,
        };
        let member = member(&m, &loopback);
        let who = || Who::Principal("spiffe://acme/operators/member".to_owned());
        let held = member
            .join(who(), join_of(&c, &invitation, &token))
            .await
            .expect("joined");
        let id = held.request.membership_id;
        // Never approved: the coordinator ends it by a genesis in `rejected`, the receipt.
        let revoked = member.revoke(who(), &id).await.expect("a receipt");
        assert_eq!(revoked.status, Status::Rejected);
        assert_eq!(revoked.epoch(), 1);
        assert_eq!(
            c.host.store.membership(&id).expect("held").status,
            Status::Rejected
        );
        // A join retried with another request is refused, not answered with the membership.
        let mut other = join_of(&c, &invitation, &token);
        other.selector = Selector::parse("plane/data/zone/z/*").expect("a selector");
        other.tasks = vec![decisions("plane/data/zone/z/*")];
        assert!(matches!(
            member.join(who(), other).await,
            Err(MembershipError::Invalid(_))
        ));
    }
}

#[test]
fn every_membership_action_is_a_registered_mutation() {
    for action in [
        AUDIT_INVITED,
        AUDIT_INVITE_REVOKED,
        AUDIT_ENROLLED,
        AUDIT_APPROVED,
        AUDIT_REJECTED,
        AUDIT_SUSPENDED,
        AUDIT_RESUMED,
        AUDIT_FENCED,
        AUDIT_REVOKE_PLANNED,
        AUDIT_REVOKED,
        AUDIT_JOINED,
        AUDIT_SYNCED,
        AUDIT_ORPHANED,
        repin::AUDIT_REPINNED,
        repin::AUDIT_CUTOVER,
        repin::AUDIT_ACKNOWLEDGED,
        repin::AUDIT_PIN_RETIRED,
    ] {
        let schema = crate::audit::REGISTRY
            .iter()
            .find(|schema| schema.action == action)
            .unwrap_or_else(|| panic!("`{action}` is not registered"));
        assert!(schema.phases, "`{action}` is recorded at each phase");
        assert!(schema.facts.is_empty(), "`{action}` carries no facts");
    }
}

#[test]
fn an_invitation_lives_at_most_seven_days_and_an_expired_one_enrolls_nobody() {
    let (c, m) = (Host::new("expiry-c"), Host::new("expiry-m"));
    let offer = |expires: Option<u64>| NewInvite {
        selector: Selector::parse("plane/data/*").expect("a selector"),
        tasks: vec![decisions("plane/data/*")],
        expires,
        expected_fingerprint: None,
        min_assurance: None,
    };
    let at = now();
    for expires in [Some(at), Some(at + INVITE_MAX_SECONDS + 1)] {
        assert!(matches!(
            c.store
                .invite(&Applying::for_tests(1), offer(expires), "operator", at),
            Err(MembershipError::Invalid(_))
        ));
    }
    let (invitation, token) = c
        .store
        .invite(
            &Applying::for_tests(2),
            offer(Some(at + 60)),
            "operator",
            at,
        )
        .expect("invited");
    assert_eq!(invitation.expires, at + 60);
    let (default, _) = c
        .store
        .invite(&Applying::for_tests(3), offer(None), "operator", at)
        .expect("invited");
    assert_eq!(default.expires, at + INVITE_DEFAULT_SECONDS);

    // Past its expiry the invitation is listed as expired and enrolls nobody.
    let verified = m.verified();
    let enrolling = Enrolling {
        peer: &verified,
        presentation: &m.presentation(),
        declared_assurance: AssuranceProfile::Production,
        exporter: &EXPORTER,
    };
    let request = request(&c, &m, &invitation, &token, &EXPORTER);
    assert!(matches!(
        c.store
            .check_enroll(&c.coordinator(), &enrolling, &request, at + 61),
        Err(MembershipError::Enrollment(_))
    ));
    assert!(
        c.store
            .invitations(at + 61)
            .iter()
            .any(|(held, status)| held.invite_id == invitation.invite_id && *status == "expired")
    );
    // Before it, the same request enrolls, under a UUIDv7 membership id.
    let pending = c
        .store
        .check_enroll(&c.coordinator(), &enrolling, &request, at + 1)
        .expect("enrolls");
    assert!(crate::identity::record::is_uuid_v7(&pending.membership_id));
    assert_eq!(
        pending.identity.as_deref(),
        Some(m.presentation().as_slice())
    );
    // A presentation of another Host than the session proved is refused.
    let other = Host::new("expiry-other");
    let impostor = Enrolling {
        presentation: &other.presentation(),
        ..enrolling
    };
    assert!(matches!(
        c.store
            .check_enroll(&c.coordinator(), &impostor, &request, at + 1),
        Err(MembershipError::Enrollment(_))
    ));
}

#[test]
fn recovery_sees_the_operation_that_wrote_a_membership_and_no_other() {
    let (c, m) = (Host::new("observe-c"), Host::new("observe-m"));
    let pending = enroll(&c, &m);
    // `enroll` wrote under the test token 2.
    let written = Applying::for_tests(2).operation_id();
    let observed = Memberships(&c.store)
        .observe(&written, None)
        .expect("the enrollment is observed");
    assert_eq!(
        observed.target,
        Some(crate::identity::record::uuid_text(&pending.membership_id))
    );
    assert!(
        Memberships(&c.store)
            .observe(&Applying::for_tests(42).operation_id(), None)
            .is_none()
    );
    // After a reopen, from the journal alone.
    let reopened = Store::open(&c._volume).expect("reopens");
    assert!(Memberships(&reopened).observe(&written, None).is_some());
}

#[test]
fn two_enrollments_racing_for_one_invitation_leave_one_and_a_store_that_opens() {
    let (c, m) = (Host::new("race-c"), Host::new("race-m"));
    let (invitation, token) = invite(&c, None);
    let verified = m.verified();
    let presentation = m.presentation();
    let enrolling = || Enrolling {
        peer: &verified,
        presentation: &presentation,
        declared_assurance: AssuranceProfile::Production,
        exporter: &EXPORTER,
    };
    let request = request(&c, &m, &invitation, &token, &EXPORTER);
    // Both checked before either writes, as two sessions would.
    let first = c
        .store
        .check_enroll(&c.coordinator(), &enrolling(), &request, now())
        .expect("checks");
    let second = c
        .store
        .check_enroll(&c.coordinator(), &enrolling(), &request, now())
        .expect("checks too");
    c.store
        .enroll(&Applying::for_tests(2), &first, now())
        .expect("the first enrolls");
    assert!(matches!(
        c.store.enroll(&Applying::for_tests(3), &second, now()),
        Err(MembershipError::Enrollment(_))
    ));
    assert_eq!(c.store.memberships().len(), 1);
    // Nothing refused reached the journal: the store opens as it was.
    let reopened = Store::open(&c._volume).expect("reopens");
    assert_eq!(reopened.memberships().len(), 1);
}

#[test]
fn an_invitation_naming_a_task_twice_is_refused_before_anything_is_written() {
    let c = Host::new("twice-c");
    let refused = c.store.invite(
        &Applying::for_tests(1),
        NewInvite {
            selector: Selector::parse("plane/data/*").expect("a selector"),
            tasks: vec![decisions("plane/data/*"), decisions("plane/data/*")],
            expires: None,
            expected_fingerprint: None,
            min_assurance: None,
        },
        "operator",
        now(),
    );
    assert!(matches!(refused, Err(MembershipError::Invalid(_))));
    assert!(
        Store::open(&c._volume)
            .expect("reopens")
            .invitations(now())
            .is_empty()
    );
}

#[test]
fn a_membership_pins_its_peer_as_far_as_its_status_lets_it() {
    use crate::session::peers::PinSource as _;
    use crate::session::record::Operation;
    let (c, m) = (Host::new("gate-c"), Host::new("gate-m"));
    let pending = enroll(&c, &m);
    let member = m.identity.host_id();
    let fingerprint = Some(m.identity.first_fingerprint().to_owned());
    // Pending: only to read its manifests.
    assert_eq!(
        c.store.pin(&member, Some(Operation::Membership)),
        fingerprint
    );
    assert_eq!(c.store.pin(&member, Some(Operation::Task)), None);
    let (manifest, _, _) = c
        .store
        .check_approve(
            &c.coordinator(),
            &capabilities(),
            &pending.membership_id,
            None,
            None,
            &offered_nothing(),
            None,
            now(),
        )
        .expect("approvable");
    c.store
        .approve(&Applying::for_tests(4), &c.coordinator(), &manifest, now())
        .expect("approved");
    // Active: for every session.
    assert_eq!(c.store.pin(&member, Some(Operation::Task)), fingerprint);
    let next = c
        .store
        .check_successor(
            &c.coordinator(),
            &pending.membership_id,
            Status::Suspended,
            None,
            now(),
        )
        .expect("a successor");
    c.store
        .transition(&Applying::for_tests(5), &c.coordinator(), &next, now())
        .expect("suspended");
    // Suspended: only to read.
    assert_eq!(c.store.pin(&member, Some(Operation::Task)), None);
    assert_eq!(
        c.store.pin(&member, Some(Operation::Membership)),
        fingerprint
    );
}

#[test]
fn a_member_refuses_a_genesis_wider_than_its_request() {
    let (c, m) = (Host::new("strict-c"), Host::new("strict-m"));
    let pending = enroll(&c, &m);
    let id = pending.membership_id;
    let (mut wider, _, _) = c
        .store
        .check_approve(
            &c.coordinator(),
            &capabilities(),
            &id,
            None,
            None,
            &offered_nothing(),
            None,
            now(),
        )
        .expect("approvable");
    // Signed by the coordinator's real key, but wider than the member asked.
    wider.tasks[0].limits.max_concurrency += 1;
    let envelope = sign_manifest(
        c.rings
            .iter()
            .find(|ring| ring.id() == HOST_OPERATIONS)
            .expect("the operations ring"),
        &wider,
    )
    .expect("signed");
    let statements = wider
        .ring_pins
        .iter()
        .filter(|pin| pin.owner == Role::Coordinator)
        .map(|pin| c.statement(&pin.ring))
        .collect();
    let answer = MembershipAnswer {
        status: Status::Active,
        manifests: vec![envelope],
        ring_statements: statements,
    };
    assert!(matches!(
        m.store.check_sync(&id, &c.verified(), &answer, now()),
        Err(MembershipError::Widened(_))
    ));
}

#[test]
fn a_member_refuses_a_manifest_already_past_its_not_after() {
    let (c, m) = (Host::new("late-c"), Host::new("late-m"));
    let pending = enroll(&c, &m);
    let id = pending.membership_id;
    let (genesis, _, _) = c
        .store
        .check_approve(
            &c.coordinator(),
            &capabilities(),
            &id,
            None,
            None,
            &offered_nothing(),
            None,
            now(),
        )
        .expect("approvable");
    let envelope = sign_manifest(
        c.rings
            .iter()
            .find(|ring| ring.id() == HOST_OPERATIONS)
            .expect("the operations ring"),
        &genesis,
    )
    .expect("signed");
    let statements = genesis
        .ring_pins
        .iter()
        .filter(|pin| pin.owner == Role::Coordinator)
        .map(|pin| c.statement(&pin.ring))
        .collect();
    let answer = MembershipAnswer {
        status: Status::Active,
        manifests: vec![envelope],
        ring_statements: statements,
    };
    // The same answer is taken before its `not_after` and refused from it on.
    assert!(
        m.store
            .check_sync(&id, &c.verified(), &answer, genesis.not_after - 1)
            .is_ok()
    );
    assert!(matches!(
        m.store
            .check_sync(&id, &c.verified(), &answer, genesis.not_after),
        Err(MembershipError::Unverified(_))
    ));
}

#[test]
fn a_selector_is_within_another_only_when_everything_it_covers_is() {
    let within = |inner: &str, outer: &str| {
        selector_within(
            &Selector::parse(inner).expect("a selector"),
            &Selector::parse(outer).expect("a selector"),
        )
    };
    assert!(within("plane/data/zone/a", "plane/data/zone/a"));
    assert!(within("plane/data/zone/a", "plane/data/*"));
    assert!(within("plane/data/zone/a/*", "plane/data/*"));
    assert!(within("plane/data/*", "plane/data/*"));
    // What lies below `plane/data` is not in a selector of `plane/data` alone.
    assert!(!within("plane/data/*", "plane/data"));
    assert!(!within("plane/data/zone/a/*", "plane/data/zone/a"));
    assert!(!within("plane/data/*", "plane/data/zone/a/*"));
    assert!(!within("plane/control", "plane/data/*"));
}

#[test]
fn an_enrollment_too_large_to_keep_is_refused_before_anything_is_written() {
    let (c, m) = (Host::new("large-c"), Host::new("large-m"));
    let (invitation, token) = invite(&c, None);
    let verified = m.verified();
    let presentation = m.presentation();
    let enrolling = Enrolling {
        peer: &verified,
        presentation: &presentation,
        declared_assurance: AssuranceProfile::Production,
        exporter: &EXPORTER,
    };
    let mut request = request(&c, &m, &invitation, &token, &EXPORTER);
    // JSON whitespace keeps the key's thumbprint and grows the record past its bound.
    let key = request.ring_statements[0].keys[0].clone();
    request.ring_statements[0].keys[0] = format!(
        "{}{}",
        key.trim_end_matches('}'),
        " ".repeat(record::MAX_RECORD_BYTES)
    ) + "}";
    assert!(matches!(
        c.store
            .check_enroll(&c.coordinator(), &enrolling, &request, now()),
        Err(MembershipError::Enrollment(_))
    ));
    assert!(c.store.memberships().is_empty());
    assert!(
        Store::open(&c._volume)
            .expect("reopens")
            .memberships()
            .is_empty()
    );
}

/// Enrolls `member` with `coordinator` for `task` alone, the member declaring `declared`: the
/// pending membership's id (WP-4.4).
fn enroll_task(
    coordinator: &Host,
    member: &Host,
    task: Task,
    declared: Vec<record::Capability>,
) -> [u8; 16] {
    let (invitation, token) = coordinator
        .store
        .invite(
            &Applying::for_tests(1),
            NewInvite {
                selector: Selector::parse("plane/data/*").expect("a selector"),
                tasks: vec![task.clone()],
                expires: None,
                expected_fingerprint: Some(member.identity.first_fingerprint().to_owned()),
                min_assurance: Some(AssuranceProfile::Production),
            },
            "operator",
            now(),
        )
        .expect("invited");
    let statements = rings_needed(std::slice::from_ref(&task))
        .into_iter()
        .filter(|(owner, _)| *owner == Role::Member)
        .map(|(_, ring)| member.statement(ring))
        .collect();
    let request = EnrollRequest {
        capabilities: declared,
        invite_id: invitation.invite_id,
        token_proof: token_proof(
            &token,
            &coordinator.identity.host_id(),
            &member.identity.host_id(),
            &EXPORTER,
        ),
        selector: Selector::parse("plane/data/*").expect("a selector"),
        tasks: vec![task],
        member: member.host_ref(),
        ring_statements: statements,
    };
    let verified = member.verified();
    let pending = coordinator
        .store
        .check_enroll(
            &coordinator.coordinator(),
            &Enrolling {
                peer: &verified,
                presentation: &member.presentation(),
                declared_assurance: AssuranceProfile::Production,
                exporter: &EXPORTER,
            },
            &request,
            now(),
        )
        .expect("the enrollment checks");
    coordinator
        .store
        .enroll(&Applying::for_tests(2), &pending, now())
        .expect("enrolled");
    pending.membership_id
}

fn unserved(result: Result<impl std::fmt::Debug, MembershipError>) -> String {
    match result {
        Err(MembershipError::TaskUnserved(detail)) => detail,
        other => panic!("refused `task_unserved`, not {other:?}"),
    }
}

/// F-29 (WP-4.4): a Host whose Planes register no `policy.mirror` provider, no Control Plane,
/// refuses the task at approval; the Control Plane's declaration registers it.
#[test]
fn a_host_without_the_policy_mirror_provider_is_refused_at_approval() {
    let (c, m) = (Host::new("f29-c"), Host::new("f29-m"));
    let mut mirror = decisions("plane/data/*");
    mirror.task_id = "mirror".to_owned();
    mirror.task_type = TaskType::PolicyMirror;
    mirror.resource_types = vec!["ledger".to_owned()];
    let id = enroll_task(&c, &m, mirror, member_capabilities());
    let approve = |capabilities: &Capabilities| {
        c.store.check_approve(
            &c.coordinator(),
            capabilities,
            &id,
            None,
            None,
            &offered_nothing(),
            None,
            now(),
        )
    };
    // The Host's own contracts and a Data Plane's: nothing provides `policy.mirror`.
    let data_only = Capabilities::host().with_declared(
        &crate::composition::Declaration::new("data")
            .uses_task(TaskType::PolicyMirror, 1)
            .handles_task(TaskType::DecisionsShip, 1),
    );
    let refused = unserved(approve(&data_only));
    assert!(
        refused.contains("provider of `policy.mirror` version 1"),
        "{refused}"
    );
    // With the Control Plane's declaration the capability holds; whatever else approval checks
    // comes after it.
    let with_control = data_only.with_declared(
        &crate::composition::Declaration::new("control").handles_task(TaskType::PolicyMirror, 1),
    );
    assert!(
        !matches!(
            approve(&with_control),
            Err(MembershipError::TaskUnserved(_))
        ),
        "the provider is registered"
    );
}

/// WP-4.4: the member's side of a task is what it declared in its request: none, or the wrong
/// side, refuses the approval.
#[test]
fn approval_refuses_a_member_without_the_matching_client_contract() {
    let side = |role| record::Capability {
        task_type: TaskType::DecisionsShip,
        version: 1,
        role,
    };
    for declared in [Vec::new(), vec![side(record::ContractRole::Consumer)]] {
        let (c, m) = (Host::new("client-c"), Host::new("client-m"));
        let id = enroll_task(&c, &m, decisions("plane/data/*"), declared);
        let refused = unserved(c.store.check_approve(
            &c.coordinator(),
            &capabilities(),
            &id,
            None,
            None,
            &offered_nothing(),
            None,
            now(),
        ));
        assert!(
            refused.contains("the member registered no provider of `decisions.ship` version 1"),
            "{refused}"
        );
    }
    let (c, m) = (Host::new("client-ok-c"), Host::new("client-ok-m"));
    let id = enroll_task(
        &c,
        &m,
        decisions("plane/data/*"),
        vec![side(record::ContractRole::Provider)],
    );
    c.store
        .check_approve(
            &c.coordinator(),
            &capabilities(),
            &id,
            None,
            None,
            &offered_nothing(),
            None,
            now(),
        )
        .expect("both sides registered");
}

/// WP-4.4: the version is the task's, signed: a side registered at another version serves
/// nothing, and an approval may not change it.
#[test]
fn approval_refuses_a_version_the_provider_did_not_register() {
    let (c, m) = (Host::new("version-c"), Host::new("version-m"));
    let mut second = decisions("plane/data/*");
    second.version = 2;
    let member_side = |version| record::Capability {
        task_type: TaskType::DecisionsShip,
        version,
        role: record::ContractRole::Provider,
    };
    let id = enroll_task(&c, &m, second.clone(), vec![member_side(1), member_side(2)]);
    let approve = |capabilities: &Capabilities, narrow: Option<&Narrow>| {
        c.store.check_approve(
            &c.coordinator(),
            capabilities,
            &id,
            narrow,
            None,
            &offered_nothing(),
            None,
            now(),
        )
    };
    // The coordinator consumes version 1 only.
    let refused = unserved(approve(&capabilities(), None));
    assert!(
        refused.contains("consumer of `decisions.ship` version 2"),
        "{refused}"
    );
    let both = capabilities().register(record::Capability {
        task_type: TaskType::DecisionsShip,
        version: 2,
        role: record::ContractRole::Consumer,
    });
    let (manifest, _, _) = approve(&both, None).expect("version 2 on both sides");
    assert_eq!(manifest.tasks[0].version, 2);
    // A narrowing that changes the version widens it.
    assert!(matches!(
        approve(
            &both,
            Some(&Narrow {
                selector: Selector::parse("plane/data/*").expect("a selector"),
                tasks: vec![decisions("plane/data/*")],
            })
        ),
        Err(MembershipError::Widened(_))
    ));
}

/// WP-7.2b: the `control.attest` set a mirror verifies under is the coordinator's pin in force,
/// never a retiring one nor a member's, with the held statement that matches it, whatever else is
/// held beside it.
#[test]
fn the_control_attest_pin_in_force_is_chosen_with_its_matching_statement() {
    let c = Host::new("pin-pick");
    let held = c.statement(CONTROL_ATTEST);
    let pin = |owner: Role, retiring: bool, epoch: u64| RingPin {
        owner,
        ring: CONTROL_ATTEST.to_owned(),
        epoch,
        key_set_digest: super::keys_digest(&held).expect("a digest"),
        binding: held.binding.clone(),
        retiring,
    };
    let current = pin(Role::Coordinator, false, held.epoch);
    let retiring = pin(Role::Coordinator, true, held.epoch + 1);
    let other = c.statement(HOST_OPERATIONS);
    let statements = vec![other.clone(), held.clone()];

    let pins = vec![retiring.clone(), current.clone()];
    let (chosen, statement) =
        super::pinned_control_attest(&pins, &statements).expect("the pin in force");
    assert_eq!(chosen, &current, "never the retiring pin");
    assert_eq!(
        statement, &held,
        "the statement that matches, not the first held"
    );

    assert!(super::pinned_control_attest(&[retiring], &statements).is_none());
    assert!(
        super::pinned_control_attest(&[pin(Role::Member, false, held.epoch)], &statements)
            .is_none(),
        "a member's pin is not the coordinator's"
    );
    assert!(
        super::pinned_control_attest(std::slice::from_ref(&current), &[other]).is_none(),
        "no statement of the pinned set held"
    );

    // Verified under the coordinator's identity, and under no other Host's.
    let ring =
        super::verified_control_attest(std::slice::from_ref(&current), &statements, &c.verified())
            .expect("the coordinator's binding");
    assert_eq!(
        (ring.epoch, ring.key_set_digest, ring.binding.clone()),
        (
            current.epoch,
            current.key_set_digest,
            current.binding.clone()
        )
    );
    assert_eq!(ring.keys, held.keys);
    let stranger = Host::new("pin-pick-stranger");
    assert!(
        super::verified_control_attest(&[current], &statements, &stranger.verified()).is_none(),
        "a binding is the coordinator's or nothing"
    );
}
