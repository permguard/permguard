// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use permguard_core::codes;

use super::*;
use crate::membership::member::{Connector, Member, Target, TaskOpen, TaskState};
use crate::membership::record::{LeasePolicy, Role};
use crate::membership::tests::protocol::{Loopback, Side, active, member, move_to};
use crate::membership::tests::{EXPORTER, Host};
use crate::membership::{MembershipError, verify_lease};
use crate::operations::journal::Initiator as Who;
use crate::time::{ManualClock, ManualMonotonic, TimeGuard};

const RESOURCE: &str = "plane/data/zone/z1";

fn who() -> Who {
    Who::Principal("spiffe://acme/operators/member".to_owned())
}

fn loopback<'a>(m: &'a Side, c: &'a Side) -> Loopback<'a> {
    Loopback {
        member: m,
        coordinator: c,
        tamper: false,
    }
}

fn code_of(error: &MembershipError) -> &str {
    match error {
        MembershipError::Remote { code, .. } => code,
        other => panic!("a remote refusal, not {other:?}"),
    }
}

/// The facts of the last record of `action` in `side`'s trail.
fn facts(side: &Side, action: &str) -> Vec<(String, String)> {
    side.trail
        .facts
        .lock()
        .expect("lock")
        .iter()
        .rev()
        .find(|(recorded, _)| recorded == action)
        .map(|(_, facts)| facts.clone())
        .unwrap_or_else(|| panic!("no `{action}` recorded"))
}

/// A coordinator on a manual clock at the real time: the clock and the side. Built after the
/// member, so nothing the member signed is in its frozen clock's future.
fn timed_coordinator(tag: &str) -> (Arc<ManualClock>, Arc<ManualMonotonic>, Side) {
    // A few seconds ahead of the real clock, so a binding the member signs just after is not in
    // this coordinator's future; well inside the 30 s skew.
    let wall = Arc::new(ManualClock::at(
        i64::try_from(crate::authz::store::now() + 3).expect("in range"),
    ));
    let mono = Arc::new(ManualMonotonic::default());
    let time = Arc::new(TimeGuard::new(
        wall.clone(),
        mono.clone(),
        Duration::from_secs(30),
    ));
    (
        wall,
        mono,
        Side::timed(Host::timed(tag, Arc::clone(&time)), true, time),
    )
}

#[tokio::test]
async fn a_lease_is_bound_to_its_connection_and_task() {
    let (c, m) = (Side::new("lease-c", true), Side::new("lease-m", false));
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    let mut task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    let lease = &task.lease;
    assert_eq!(lease.membership_id, id);
    assert_eq!(lease.task_id, "decisions");
    assert_eq!(lease.epoch, 1);
    assert_eq!(lease.coordinator, c.host.identity.host_id());
    assert_eq!(lease.member, m.host.identity.host_id());
    assert_eq!(lease.coordinator_boot_id, c.host.identity.boot_id());
    assert_eq!(lease.member_boot_id, m.host.identity.boot_id());
    assert_eq!(lease.selector.to_string(), "plane/data/*");
    assert_eq!(lease.resource, RESOURCE);
    assert_eq!(lease.channel_binding, channel_binding(&EXPORTER));
    assert_eq!(lease.binding_digest, None, "the task requires no control");
    assert!(lease.expires_at > lease.issued_at);
    // One message, one answer, on the same connection.
    assert_eq!(
        task.send("r-1", b"hello".to_vec()).await.expect("answered"),
        b"echo:hello"
    );
    // The coordinator holds the session open with both boot ids, and the trail the lease.
    let open = c.tasks.live.of(&id);
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].member_boot_id, m.host.identity.boot_id());
    let issued = facts(&c, AUDIT_LEASE_ISSUED);
    assert!(issued.contains(&("task".to_owned(), "decisions".to_owned())));
    // Dropped with its connection: the session is closed on the coordinator.
    drop(task);
    assert!(c.tasks.live.of(&id).is_empty());

    // A connection other than the one the lease was bound to is refused by the member.
    let tampered = Loopback {
        member: &m,
        coordinator: &c,
        tamper: true,
    };
    let refused = member(&m, &tampered)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .err()
        .expect("another connection");
    assert!(
        matches!(refused, MembershipError::Unverified(_)),
        "{refused}"
    );
}

#[tokio::test]
async fn a_lease_is_issued_only_for_an_active_membership_its_peer_its_epoch_and_a_contained_resource()
 {
    let (c, m) = (Side::new("admit-c", true), Side::new("admit-m", false));
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    let member = member(&m, &connector);
    for (task, resource, code) in [
        (
            "decisions",
            "plane/control",
            codes::common::INVALID_ARGUMENT,
        ),
        ("events", RESOURCE, codes::common::INVALID_ARGUMENT),
    ] {
        let refused = member
            .open_task(who(), &id, task, resource, Vec::new())
            .await
            .err()
            .expect("refused");
        assert_eq!(code_of(&refused), code, "{task} {resource}");
    }
    // Suspended: the coordinator pins its member for `membership` sessions only (WP-4.1), so a
    // task session is refused at its hello; the member, synced, does not even ask.
    move_to(&c, &id, Status::Suspended, 51);
    let refused = member
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .err()
        .expect("suspended");
    assert_eq!(code_of(&refused), codes::host::SESSION_REFUSED);
    member.sync(who(), &id).await.expect("synced");
    assert!(matches!(
        member
            .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
            .await,
        Err(MembershipError::Transition { .. })
    ));
}

#[tokio::test]
async fn a_message_naming_another_membership_task_or_epoch_is_refused() {
    let (c, m) = (
        Side::new("envelope-c", true),
        Side::new("envelope-m", false),
    );
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    // Each refusal ends its session: one session per message.
    for change in [
        (|message: &mut TaskMessage| message.task_id = "events".to_owned()) as fn(&mut TaskMessage),
        |message| message.membership_id = [0x99; 16],
    ] {
        let task = member(&m, &connector)
            .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
            .await
            .expect("leased");
        let mut session = CoordinatorSession::of(task);
        let mut message = session.message();
        change(&mut message);
        let refused = session.raw(message).await.expect_err("another one");
        assert_eq!(refused.code, codes::common::INVALID_ARGUMENT);
        assert!(c.tasks.live.of(&id).is_empty(), "the session ended");
    }
}

/// Sends raw task messages on a member's open session.
struct CoordinatorSession {
    task: crate::membership::member::MemberTask,
}

impl CoordinatorSession {
    fn of(task: crate::membership::member::MemberTask) -> Self {
        Self { task }
    }

    fn message(&self) -> TaskMessage {
        TaskMessage {
            kind: crate::membership::record::MessageKind::Handler,
            membership_id: self.task.lease.membership_id,
            task_id: self.task.lease.task_id.clone(),
            epoch: self.task.lease.epoch,
            request_id: "r-raw".to_owned(),
            body: Vec::new(),
        }
    }

    async fn raw(&mut self, message: TaskMessage) -> Result<Vec<u8>, Refusal> {
        self.task
            .channel_for_tests()
            .exchange(message.encode().expect("encodes"))
            .await
    }
}

#[tokio::test]
async fn a_stale_epoch_is_rejected_and_audited() {
    let (c, m) = (Side::new("stale-c", true), Side::new("stale-m", false));
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    let member = member(&m, &connector);
    let mut task = member
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    // A fence: the session's epoch is behind, and the message is rejected, audited, the session
    // ended.
    move_to(&c, &id, Status::Active, 52);
    let refused = task.send("r-1", Vec::new()).await.expect_err("stale");
    assert_eq!(code_of(&refused), codes::host::EPOCH_STALE);
    let recorded = facts(&c, AUDIT_EPOCH_STALE);
    assert!(recorded.contains(&("presented".to_owned(), "1".to_owned())));
    assert!(recorded.contains(&("current".to_owned(), "2".to_owned())));
    assert!(c.tasks.live.of(&id).is_empty(), "the session ended");
    // A lease asked at the old epoch is refused too, and audited; the member syncs on that
    // refusal and is leased again (WP-4.5, after the review).
    drop(task);
    let stale = |side: &Side| {
        side.trail
            .facts
            .lock()
            .expect("lock")
            .iter()
            .filter(|(action, _)| action == AUDIT_EPOCH_STALE)
            .count()
    };
    let before = stale(&c);
    let task = member
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("synced, then leased at the new epoch");
    assert_eq!(task.lease.epoch, 2);
    assert_eq!(stale(&c), before + 1, "the stale lease request is audited");
}

#[tokio::test]
async fn an_unknown_epoch_holds_the_membership_until_it_is_revoked() {
    let (c, m) = (Side::new("unknown-c", true), Side::new("unknown-m", false));
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    // A lease request naming an epoch the coordinator never issued.
    let request = LeaseRequest {
        membership_id: id,
        task_id: "decisions".to_owned(),
        epoch: 7,
        resource: RESOURCE.to_owned(),
        member_boot_id: m.host.identity.boot_id(),
        evidence: Vec::new(),
    };
    let refused = connector
        .open_task(
            Target {
                address: "https://coordinator:7443".to_owned(),
                host_id: c.host.identity.host_id(),
                fingerprint: c.host.identity.first_fingerprint().to_owned(),
            },
            TaskOpen {
                membership_id: id,
                task_id: "decisions".to_owned(),
                request: request.encode().expect("encodes"),
            },
        )
        .await
        .err()
        .expect("unknown");
    assert_eq!(refused.code, codes::host::EPOCH_UNKNOWN);
    let recorded = facts(&c, AUDIT_EPOCH_UNKNOWN);
    assert!(recorded.contains(&("presented".to_owned(), "7".to_owned())));
    assert_eq!(
        c.host.store.membership(&id).expect("held").held_epoch,
        Some(7)
    );
    // Held: no lease, no fence, no resume; only a revocation.
    let refused = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .err()
        .expect("held");
    assert_eq!(code_of(&refused), codes::host::MEMBERSHIP_HELD);
    for to in [Status::Active, Status::Suspended] {
        assert!(matches!(
            c.host.store.check_successor(
                &c.host.coordinator(),
                &id,
                to,
                None,
                crate::authz::store::now()
            ),
            Err(MembershipError::Held(_))
        ));
    }
    move_to(&c, &id, Status::Revoked, 53);
    assert_eq!(
        c.host.store.membership(&id).expect("held").status,
        Status::Revoked
    );
    // The hold survives a reopening of the store: it is in the journal.
    let reopened = crate::membership::Store::open(c.host.volume()).expect("reopens");
    assert_eq!(reopened.membership(&id).expect("held").held_epoch, Some(7));
}

#[tokio::test]
async fn an_expired_lease_ends_the_session_and_the_member_falls_to_grace_then_offline() {
    let m = Side::new("expiry-m", false);
    let (wall, mono, c) = timed_coordinator("expiry-c");
    let policy = LeasePolicy {
        max_session_seconds: 60,
        offline_grace_seconds: 600,
        clock_skew_seconds: 30,
        dormant_after_seconds: 86_400,
        revoke_after_seconds: 2 * 86_400,
    };
    let id = active(&c, &m, Some(policy)).await;
    let connector = loopback(&m, &c);
    let mut task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    let lease = task.lease.clone();
    assert_eq!(lease.expires_at, lease.issued_at + 60);
    // The coordinator's clock passes the lease: the message is refused, the session ended.
    wall.jump(61);
    mono.advance(Duration::from_secs(61));
    let refused = task.send("r-1", Vec::new()).await.expect_err("expired");
    assert_eq!(code_of(&refused), codes::host::LEASE_EXPIRED);
    // On the member: live, then grace, then offline; never extended.
    let boot = m.host.identity.boot_id();
    let state =
        |at| Member::task_state(&m.host.store, &id, "decisions", &boot, at).expect("a state");
    assert_eq!(
        state(lease.issued_at),
        TaskState::Live {
            expires_at: lease.expires_at
        }
    );
    assert_eq!(
        state(lease.expires_at),
        TaskState::Grace {
            until: lease.issued_at + 600
        }
    );
    assert_eq!(state(lease.issued_at + 600), TaskState::Offline);
    assert_eq!(
        Member::task_state(&m.host.store, &id, "events", &boot, lease.issued_at).expect("a state"),
        TaskState::Unleased
    );
}

#[tokio::test]
async fn a_copied_volume_beside_the_original_suspends_the_membership_with_a_clone_alarm() {
    let (c, m) = (Side::new("clone-c", true), Side::new("clone-m", false));
    let id = active(&c, &m, None).await;
    let original = loopback(&m, &c);
    let mut task = member(&m, &original)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    // F-31: the member's volume copied and started beside it: the same Host, another boot id.
    let copy = Side::of(m.host.copy("clone-copy"), false);
    assert_eq!(copy.host.identity.host_id(), m.host.identity.host_id());
    assert_ne!(copy.host.identity.boot_id(), m.host.identity.boot_id());
    let cloned = loopback(&copy, &c);
    let refused = member(&copy, &cloned)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .err()
        .expect("a clone");
    assert_eq!(code_of(&refused), codes::host::CLONE_SUSPECTED);
    // Suspended, a new epoch, and the alarm names both incarnations.
    let held = c.host.store.membership(&id).expect("held");
    assert_eq!(held.status, Status::Suspended);
    assert_eq!(held.epoch(), 2);
    let alarm = facts(&c, AUDIT_CLONE_ALARM);
    let hex = |bytes: [u8; 16]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
    assert!(alarm.contains(&("open_boot_id".to_owned(), hex(m.host.identity.boot_id()))));
    assert!(alarm.contains(&("new_boot_id".to_owned(), hex(copy.host.identity.boot_id()))));
    // The original's open session is fenced at its next message.
    let refused = task.send("r-1", Vec::new()).await.expect_err("fenced");
    assert_eq!(code_of(&refused), codes::host::EPOCH_STALE);
}

/// WP-5.3: a handler reporting a stream's fork through the session's incidents records the
/// incident in the `security` trail and suspends the membership: a new epoch, and the session's
/// next message is stale.
#[tokio::test]
async fn a_handler_incident_suspends_the_membership() {
    let (c, m) = (
        Side::new("incident-c", true),
        Side::new("incident-m", false),
    );
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    let mut task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    assert_eq!(
        task.send("r-1", b"fork?".to_vec()).await.expect("answered"),
        b"forked"
    );
    let held = c.host.store.membership(&id).expect("held");
    assert_eq!(held.status, Status::Suspended);
    assert_eq!(held.epoch(), 2);
    let incident = facts(&c, AUDIT_STREAM_FORKED);
    assert!(incident.contains(&("stream".to_owned(), "data/decisions/forked/run".to_owned())));
    assert!(incident.contains(&("at_seq".to_owned(), "3".to_owned())));
    let refused = task.send("r-2", Vec::new()).await.expect_err("fenced");
    assert_eq!(code_of(&refused), codes::host::EPOCH_STALE);
}

/// WP-5.3, after the mutants: a fork reported again once the membership is suspended is neither
/// recorded nor suspended twice.
#[tokio::test]
async fn a_second_report_of_a_suspended_membership_does_nothing() {
    let (c, m) = (
        Side::new("incident2-c", true),
        Side::new("incident2-m", false),
    );
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    let mut task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    assert_eq!(
        task.send("r-1", b"fork twice?".to_vec())
            .await
            .expect("answered"),
        b"forked"
    );
    assert_eq!(c.host.store.membership(&id).expect("held").epoch(), 2);
    let recorded = c
        .trail
        .facts
        .lock()
        .expect("lock")
        .iter()
        .filter(|(action, _)| action == AUDIT_STREAM_FORKED)
        .count();
    assert_eq!(recorded, 1);
}

#[tokio::test]
async fn a_restored_member_is_stale_until_it_syncs_and_then_leases_under_its_new_boot_id() {
    let (c, m) = (Side::new("restore-c", true), Side::new("restore-m", false));
    let id = active(&c, &m, None).await;
    // A backup of the member, taken at epoch 1; the original fenced past it and gone.
    let restored = Side::of(m.host.copy("restore-copy"), false);
    move_to(&c, &id, Status::Active, 54);
    drop(m);
    let connector = loopback(&restored, &c);
    let member = member(&restored, &connector);
    // Refused as stale, audited, then synced and leased (WP-4.5, after the review).
    let task = member
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("a fresh lease");
    let recorded = facts(&c, AUDIT_EPOCH_STALE);
    assert!(recorded.contains(&("presented".to_owned(), "1".to_owned())));
    assert!(recorded.contains(&("current".to_owned(), "2".to_owned())));
    assert_eq!(task.lease.epoch, 2, "the fence confirmed, no new epoch");
    assert_eq!(task.lease.member_boot_id, restored.host.identity.boot_id());
}

#[tokio::test]
async fn no_lease_is_issued_while_the_clock_is_in_anomaly() {
    let m = Side::new("anomaly-m", false);
    let (wall, _mono, c) = timed_coordinator("anomaly-c");
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    wall.jump(-120);
    let refused = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .err()
        .expect("anomaly");
    assert_eq!(code_of(&refused), codes::common::UNAVAILABLE);
}

#[tokio::test]
async fn a_lease_issued_in_the_future_beyond_the_skew_is_refused_by_the_member() {
    let m = Side::new("skew-m", false);
    let (wall, mono, c) = timed_coordinator("skew-c");
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    // Within the signed skew (30 s, three seconds of it already ahead): accepted.
    wall.jump(20);
    mono.advance(Duration::from_secs(20));
    let within = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("within the skew");
    drop(within);
    // Beyond it: refused, however valid the signature.
    wall.jump(600);
    mono.advance(Duration::from_secs(600));
    let refused = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .err()
        .expect("beyond the skew");
    assert!(
        matches!(refused, MembershipError::Unverified(_)),
        "{refused}"
    );
}

#[tokio::test]
async fn only_the_member_side_opens_a_task_session() {
    let (c, m) = (
        Side::new("direction-c", true),
        Side::new("direction-m", false),
    );
    let id = active(&c, &m, None).await;
    // The coordinator's own side refuses to open one: it never dials its member.
    let reverse = loopback(&c, &m);
    let refused = member(&c, &reverse)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .err()
        .expect("never from the coordinator");
    assert!(matches!(refused, MembershipError::Unknown(_)), "{refused}");
    assert_eq!(
        c.host.store.membership(&id).expect("held").role,
        Role::Coordinator
    );
}

#[tokio::test]
async fn a_lease_signed_by_a_key_outside_the_pinned_operations_set_is_refused() {
    let (c, m) = (Side::new("pinned-c", true), Side::new("pinned-m", false));
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    let task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    let held = m.host.store.membership(&id).expect("held");
    let (manifest, ..) = held.manifest.expect("a manifest");
    let statements = m.host.store.statements_held(&id, manifest.epoch);
    // The same lease signed by the coordinator's `data.attest`: not the pinned operations set.
    let other = c
        .host
        .rings
        .iter()
        .find(|ring| ring.id() == crate::keys::ring::DATA_ATTEST)
        .expect("the ring");
    let forged = sign_lease(other, &task.lease).expect("signed");
    assert!(matches!(
        verify_lease(&forged, &c.host.verified(), &manifest, &statements),
        Err(MembershipError::Unverified(_))
    ));
    // The real one verifies.
    let real = m
        .host
        .store
        .lease(&id, "decisions")
        .expect("read")
        .expect("kept");
    assert_eq!(
        verify_lease(&real, &c.host.verified(), &manifest, &statements).expect("verifies"),
        task.lease
    );
}

#[tokio::test]
async fn the_member_keeps_its_lease_and_reads_it_back_after_a_restart() {
    let (c, m) = (Side::new("keep-c", true), Side::new("keep-m", false));
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    let task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    let reopened = crate::membership::Store::open(m.host.volume()).expect("reopens");
    let kept = reopened
        .lease(&id, "decisions")
        .expect("read")
        .expect("kept");
    let sign1 = Sign1::decode(&kept).expect("COSE");
    assert_eq!(
        Lease::decode(sign1.payload_unverified()).expect("a lease"),
        task.lease
    );
    assert_eq!(
        Member::task_state(
            &reopened,
            &id,
            "decisions",
            &m.host.identity.boot_id(),
            task.lease.issued_at,
        )
        .expect("a state"),
        TaskState::Live {
            expires_at: task.lease.expires_at
        }
    );
}

#[tokio::test]
async fn a_lease_carries_the_binding_digest_and_an_appraisal_at_the_session_revises_the_manifest() {
    use permguard_core::assurance::Control;

    let (c, m) = (Side::new("bound-c", true), Side::new("bound-m", false));
    let id =
        crate::membership::tests::protocol::active_requiring(&c, &m, &[Control::CustodyHsm]).await;
    let held = c.host.store.membership(&id).expect("held");
    let (manifest, _, digest) = held.manifest.expect("a manifest");
    let binding = manifest.assurance_binding.clone().expect("a binding");
    let connector = loopback(&m, &c);
    let member = member(&m, &connector);
    let task = member
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    assert_eq!(
        task.lease.binding_digest,
        Some(binding.digest().expect("digested"))
    );
    drop(task);
    // Evidence at the session: appraised against this revision's nonce, a new epoch, accepted by
    // the member before the lease.
    let nonce = crate::membership::appraisal::nonce(&c.host.identity.host_id(), &id, &digest);
    let evidence = crate::membership::appraisal::tests::evidence(&nonce, &[Control::CustodyHsm]);
    let task = member
        .open_task(
            who(),
            &id,
            "decisions",
            RESOURCE,
            vec![(
                crate::membership::appraisal::tests::VERIFIER.to_owned(),
                evidence,
            )],
        )
        .await
        .expect("appraised and leased");
    assert_eq!(task.lease.epoch, 2);
    let (revised, ..) = m
        .host
        .store
        .membership(&id)
        .expect("held")
        .manifest
        .expect("the revision");
    assert_eq!(revised.epoch, 2);
    let renewed = revised.assurance_binding.expect("renewed");
    assert_eq!(
        task.lease.binding_digest,
        Some(renewed.digest().expect("digested"))
    );
    assert_eq!(
        renewed.appraised_by,
        crate::identity::record::subject(&m.host.identity.host_id())
    );
}

/// The coordinator's service, called as a proven session would call it: its own guards, past
/// the hello's.
fn direct(
    coordinator: &Side,
    peer: &Host,
    id: &[u8; 16],
    request: &LeaseRequest,
) -> Result<Vec<u8>, Refusal> {
    let session = Session {
        role: crate::session::record::Role::Responder,
        peer: peer.identity.host_id(),
        peer_epoch: peer.identity.epoch(),
        peer_declared_assurance: permguard_core::assurance::AssuranceProfile::Production,
        operation: crate::session::record::Operation::Task,
        membership_id: Some(crate::identity::record::uuid_text(id)),
        task: Some(request.task_id.clone()),
        request_digest: None,
    };
    coordinator
        .context
        .service
        .as_ref()
        .expect("a coordinator")
        .open_task(
            &session,
            &peer.verified(),
            &EXPORTER,
            &request.encode().expect("encodes"),
        )
        .map(|(answer, _session)| answer)
}

fn lease_request(m: &Side, id: &[u8; 16], epoch: u64) -> LeaseRequest {
    LeaseRequest {
        membership_id: *id,
        task_id: "decisions".to_owned(),
        epoch,
        resource: RESOURCE.to_owned(),
        member_boot_id: m.host.identity.boot_id(),
        evidence: Vec::new(),
    }
}

#[tokio::test]
async fn the_coordinators_own_guards_refuse_another_peer_a_pending_or_suspended_membership_and_the_reverse_direction()
 {
    let (c, m) = (Side::new("guards-c", true), Side::new("guards-m", true));
    let id = active(&c, &m, None).await;
    // Another Host, whatever its proof, is no member of this membership.
    let stranger = Host::new("guards-stranger");
    let refused = direct(&c, &stranger, &id, &lease_request(&m, &id, 1)).expect_err("a stranger");
    assert_eq!(refused.code, codes::host::MEMBERSHIP_UNKNOWN);
    // The member's own service refuses its coordinator: the coordinator never dials.
    let refused = direct(&m, &c.host, &id, &lease_request(&m, &id, 1)).expect_err("reverse");
    assert_eq!(refused.code, codes::host::MEMBERSHIP_UNKNOWN);
    // Suspended at the current epoch: refused by the status, not by a pin.
    move_to(&c, &id, Status::Suspended, 61);
    let refused = direct(&c, &m.host, &id, &lease_request(&m, &id, 2)).expect_err("suspended");
    assert_eq!(refused.code, codes::host::MEMBERSHIP_TRANSITION_REFUSED);
    // Pending: refused before any epoch is read, and never held.
    let pending = {
        let (invitation, token) = crate::membership::tests::invite_for(&c.host, &m.host);
        let connector = loopback(&m, &c);
        member(&m, &connector)
            .join(
                who(),
                crate::membership::tests::protocol::join_of(&c, &invitation, &token),
            )
            .await
            .expect("joined")
            .request
            .membership_id
    };
    let refused =
        direct(&c, &m.host, &pending, &lease_request(&m, &pending, 1)).expect_err("pending");
    assert_eq!(refused.code, codes::host::MEMBERSHIP_TRANSITION_REFUSED);
    assert_eq!(
        c.host.store.membership(&pending).expect("held").held_epoch,
        None
    );
}

#[tokio::test]
async fn no_lease_is_issued_by_the_service_itself_while_the_clock_is_in_anomaly() {
    let m = Side::new("anomaly-direct-m", false);
    let (wall, _mono, c) = timed_coordinator("anomaly-direct-c");
    let id = active(&c, &m, None).await;
    // Past the hello: the service's own gate.
    wall.jump(-120);
    let refused = direct(&c, &m.host, &id, &lease_request(&m, &id, 1)).expect_err("anomaly");
    assert_eq!(refused.code, codes::common::UNAVAILABLE);
    assert!(c.tasks.live.of(&id).is_empty());
}

#[tokio::test]
async fn a_message_from_an_epoch_never_issued_holds_the_membership() {
    let (c, m) = (
        Side::new("message-unknown-c", true),
        Side::new("message-unknown-m", false),
    );
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    let task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    let mut session = CoordinatorSession::of(task);
    let message = TaskMessage {
        epoch: 9,
        ..session.message()
    };
    let refused = session.raw(message).await.expect_err("unknown");
    assert_eq!(refused.code, codes::host::EPOCH_UNKNOWN);
    assert_eq!(
        c.host.store.membership(&id).expect("held").held_epoch,
        Some(9)
    );
    assert!(c.tasks.live.of(&id).is_empty(), "the session ended");
}

#[tokio::test]
async fn a_lease_runs_no_longer_than_its_binding_or_its_manifest() {
    use permguard_core::assurance::Control;

    // The binding: an operator's approval lapsing in two minutes, the session bound an hour.
    let (c, m) = (
        Side::new("cap-binding-c", true),
        Side::new("cap-binding-m", false),
    );
    let mut requiring = crate::membership::tests::decisions("plane/data/*");
    requiring.assurance_requirements = vec![Control::OperationsDualControl.name().to_owned()];
    let approvals = [crate::membership::appraisal::Approval {
        control: Control::OperationsDualControl,
        reason: "witnessed".to_owned(),
        expires_at: crate::authz::store::now() + 120,
    }];
    let id =
        crate::membership::tests::protocol::active_with(&c, &m, requiring, &[], &approvals).await;
    let binding = c
        .host
        .store
        .membership(&id)
        .expect("held")
        .manifest
        .expect("a manifest")
        .0
        .assurance_binding
        .expect("a binding");
    let connector = loopback(&m, &c);
    let task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    assert_eq!(
        task.lease.expires_at, binding.expires_at,
        "cut at the binding"
    );
    assert!(task.lease.expires_at < task.lease.issued_at + 3600);
    drop(task);

    // The manifest: a session bound longer than the manifest lives.
    let (c2, m2) = (
        Side::new("cap-manifest-c", true),
        Side::new("cap-manifest-m", false),
    );
    let policy = LeasePolicy {
        max_session_seconds: 400 * 86_400,
        offline_grace_seconds: 600,
        clock_skew_seconds: 30,
        dormant_after_seconds: 86_400,
        revoke_after_seconds: 2 * 86_400,
    };
    let id2 = active(&c2, &m2, Some(policy)).await;
    let not_after = c2
        .host
        .store
        .membership(&id2)
        .expect("held")
        .manifest
        .expect("a manifest")
        .0
        .not_after;
    let connector = loopback(&m2, &c2);
    let task = member(&m2, &connector)
        .open_task(who(), &id2, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    assert_eq!(task.lease.expires_at, not_after, "cut at the manifest");
}

#[tokio::test]
async fn a_member_restarted_after_its_session_closed_leases_again_without_an_alarm() {
    let (c, m) = (Side::new("restart-c", true), Side::new("restart-m", false));
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    let task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    // The connection closed, then the process came back: another boot id, no session open.
    drop(task);
    let restarted = Side::of(m.host.copy("restart-again"), false);
    let connector = loopback(&restarted, &c);
    let task = member(&restarted, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased again");
    assert_eq!(task.lease.member_boot_id, restarted.host.identity.boot_id());
    assert_eq!(
        c.host.store.membership(&id).expect("held").status,
        Status::Active
    );
    // The predecessor's lease, on the restarted volume's copy, is none for this incarnation.
    let other = Side::of(restarted.host.copy("restart-third"), false);
    assert_eq!(
        Member::task_state(
            &other.host.store,
            &id,
            "decisions",
            &other.host.identity.boot_id(),
            task.lease.issued_at
        )
        .expect("a state"),
        TaskState::Unleased
    );
}

#[tokio::test]
async fn no_lease_is_signed_once_the_operations_key_rotated_past_the_pinned_one() {
    let m = Side::new("rotated-m", false);
    let (wall, mono, c) = timed_coordinator("rotated-c");
    let id = active(&c, &m, None).await;
    // The coordinator's `host.operations` rotates: a successor prepublished, then active.
    for step in [3_100, 700] {
        wall.jump(step);
        mono.advance(Duration::from_secs(step.unsigned_abs()));
        for ring in &c.host.rings {
            ring.maintain_now().expect("maintained");
        }
    }
    let refused = direct(&c, &m.host, &id, &lease_request(&m, &id, 1)).expect_err("rotated");
    assert_eq!(refused.code, codes::common::UNAVAILABLE);
    assert!(refused.reason.contains("re-pin"), "{refused:?}");
    assert!(c.tasks.live.of(&id).is_empty());
}

#[tokio::test]
async fn a_body_over_the_tasks_signed_limit_is_refused_and_the_session_kept() {
    let (c, m) = (Side::new("limit-c", true), Side::new("limit-m", false));
    let mut small = crate::membership::tests::decisions("plane/data/*");
    small.limits.max_body_bytes = 1024;
    let id = crate::membership::tests::protocol::active_with(&c, &m, small, &[], &[]).await;
    let connector = loopback(&m, &c);
    let mut task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    let limit = usize::try_from(task.lease.limits.max_body_bytes).expect("in range");
    let refused = task
        .send("r-big", vec![0; limit + 1])
        .await
        .expect_err("over the limit");
    assert_eq!(code_of(&refused), codes::common::INVALID_ARGUMENT);
    assert_eq!(
        task.send("r-ok", b"small".to_vec()).await.expect("kept"),
        b"echo:small"
    );
}

#[tokio::test]
async fn no_lease_is_answered_that_the_security_trail_did_not_record() {
    let (c, m) = (Side::new("trail-c", true), Side::new("trail-m", false));
    let id = active(&c, &m, None).await;
    c.trail
        .refuse
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let refused = direct(&c, &m.host, &id, &lease_request(&m, &id, 1)).expect_err("unrecorded");
    assert_eq!(refused.code, codes::host::AUDIT_UNAVAILABLE);
    assert!(c.tasks.live.of(&id).is_empty(), "no session either");
}

#[tokio::test]
async fn a_lease_request_naming_another_membership_or_task_than_its_session_is_refused() {
    let (c, m) = (Side::new("scope-c", true), Side::new("scope-m", false));
    let id = active(&c, &m, None).await;
    let session = |membership: &[u8; 16], task: &str| Session {
        role: crate::session::record::Role::Responder,
        peer: m.host.identity.host_id(),
        peer_epoch: m.host.identity.epoch(),
        peer_declared_assurance: permguard_core::assurance::AssuranceProfile::Production,
        operation: crate::session::record::Operation::Task,
        membership_id: Some(crate::identity::record::uuid_text(membership)),
        task: Some(task.to_owned()),
        request_digest: None,
    };
    let service = c.context.service.as_ref().expect("a coordinator");
    let request = lease_request(&m, &id, 1).encode().expect("encodes");
    for (membership, task) in [([0x99; 16], "decisions"), (id, "events")] {
        let refused = service
            .open_task(
                &session(&membership, task),
                &m.host.verified(),
                &EXPORTER,
                &request,
            )
            .map(|_| ())
            .expect_err("another scope");
        assert_eq!(refused.code, codes::common::INVALID_ARGUMENT);
    }
}

#[tokio::test]
async fn a_hold_committed_after_a_fence_was_checked_stops_the_fence_and_holds_only_with_a_manifest()
{
    let (c, m) = (Side::new("race-c", true), Side::new("race-m", false));
    let id = active(&c, &m, None).await;
    let now = crate::authz::store::now();
    let fenced = c
        .host
        .store
        .check_successor(&c.host.coordinator(), &id, Status::Active, None, now)
        .expect("checked before the hold");
    c.host
        .store
        .hold(
            &crate::operations::mutation::Applying::for_tests(71),
            &id,
            5,
            now,
        )
        .expect("held");
    assert!(matches!(
        c.host.store.transition(
            &crate::operations::mutation::Applying::for_tests(72),
            &c.host.coordinator(),
            &fenced,
            now
        ),
        Err(MembershipError::Held(_))
    ));
    // A pending membership is never held.
    let (invitation, token) = crate::membership::tests::invite_for(&c.host, &m.host);
    let connector = loopback(&m, &c);
    let pending = member(&m, &connector)
        .join(
            who(),
            crate::membership::tests::protocol::join_of(&c, &invitation, &token),
        )
        .await
        .expect("joined")
        .request
        .membership_id;
    assert!(matches!(
        c.host.store.hold(
            &crate::operations::mutation::Applying::for_tests(73),
            &pending,
            1,
            now
        ),
        Err(MembershipError::Invalid(_))
    ));
}

#[tokio::test]
async fn a_lease_fenced_since_it_was_issued_carries_no_message_naming_the_new_epoch() {
    let (c, m) = (
        Side::new("fenced-lease-c", true),
        Side::new("fenced-lease-m", false),
    );
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    let task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    move_to(&c, &id, Status::Active, 81);
    // The message names the current epoch; its session's lease is of the one before.
    let mut session = CoordinatorSession::of(task);
    let message = TaskMessage {
        epoch: 2,
        ..session.message()
    };
    let refused = session.raw(message).await.expect_err("a fenced lease");
    assert_eq!(refused.code, codes::host::EPOCH_STALE);
}

#[tokio::test]
async fn a_clone_bringing_evidence_is_refused_before_its_evidence_revises_anything() {
    use permguard_core::assurance::Control;

    let (c, m) = (
        Side::new("clone-evidence-c", true),
        Side::new("clone-evidence-m", false),
    );
    let id =
        crate::membership::tests::protocol::active_requiring(&c, &m, &[Control::CustodyHsm]).await;
    let original = loopback(&m, &c);
    let _task = member(&m, &original)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    let (_, _, digest) = c
        .host
        .store
        .membership(&id)
        .expect("held")
        .manifest
        .expect("a manifest");
    let copy = Side::of(m.host.copy("clone-evidence-copy"), false);
    let nonce = crate::membership::appraisal::nonce(&c.host.identity.host_id(), &id, &digest);
    let evidence = crate::membership::appraisal::tests::evidence(&nonce, &[Control::CustodyHsm]);
    let cloned = loopback(&copy, &c);
    let refused = member(&copy, &cloned)
        .open_task(
            who(),
            &id,
            "decisions",
            RESOURCE,
            vec![(
                crate::membership::appraisal::tests::VERIFIER.to_owned(),
                evidence,
            )],
        )
        .await
        .err()
        .expect("a clone");
    assert_eq!(code_of(&refused), codes::host::CLONE_SUSPECTED);
    // Suspended at the next epoch, and no appraisal revision before it.
    let held = c.host.store.membership(&id).expect("held");
    assert_eq!(held.status, Status::Suspended);
    assert_eq!(held.epoch(), 2);
}

/// A connector that forges the lease its coordinator answers: re-signed by the coordinator's
/// own operations key, with other limits than the manifest grants.
struct Forging<'a> {
    inner: Loopback<'a>,
    operations: Arc<crate::keys::ring::Ring>,
}

impl Connector for Forging<'_> {
    fn exchange(
        &self,
        target: Target,
        exchange: crate::membership::member::Exchange,
    ) -> permguard_core::BoxFuture<'_, Result<crate::membership::member::Exchanged, Refusal>> {
        self.inner.exchange(target, exchange)
    }

    fn open_task(
        &self,
        target: Target,
        open: TaskOpen,
    ) -> permguard_core::BoxFuture<'_, Result<crate::membership::member::TaskOpened, Refusal>> {
        Box::pin(async move {
            let mut opened = self.inner.open_task(target, open).await?;
            let answer = LeaseAnswer::decode(&opened.answer).expect("an answer");
            let sign1 = Sign1::decode(&answer.lease).expect("COSE");
            let mut lease = Lease::decode(sign1.payload_unverified()).expect("a lease");
            lease.limits.max_body_bytes += 1;
            opened.answer = LeaseAnswer {
                lease: sign_lease(&self.operations, &lease).expect("re-signed"),
                manifest: answer.manifest,
            }
            .encode()
            .expect("encodes");
            Ok(opened)
        })
    }
}

#[tokio::test]
async fn a_lease_granting_other_limits_than_the_manifest_is_refused_by_the_member() {
    let (c, m) = (Side::new("forged-c", true), Side::new("forged-m", false));
    let id = active(&c, &m, None).await;
    let forging = Forging {
        inner: loopback(&m, &c),
        operations: Arc::clone(
            c.host
                .rings
                .iter()
                .find(|ring| ring.id() == crate::keys::ring::HOST_OPERATIONS)
                .expect("the ring"),
        ),
    };
    let refused = member(&m, &forging)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .err()
        .expect("other limits");
    assert!(
        matches!(refused, MembershipError::Unverified(_)),
        "{refused}"
    );
}

/// A decisions task under `plane/data/*` with `edit` applied to it.
fn decisions_with(
    edit: impl FnOnce(&mut crate::membership::record::Task),
) -> crate::membership::record::Task {
    let mut task = crate::membership::tests::decisions("plane/data/*");
    edit(&mut task);
    task
}

/// WP-4.4: the task's signed `max_concurrency` bounds its open sessions; one closing frees a
/// place.
#[tokio::test]
async fn a_session_over_the_tasks_concurrency_is_refused_task_busy() {
    let (c, m) = (Side::new("busy-c", true), Side::new("busy-m", false));
    let task = decisions_with(|task| task.limits.max_concurrency = 1);
    let id = crate::membership::tests::protocol::active_with(&c, &m, task, &[], &[]).await;
    let connector = loopback(&m, &c);
    let first = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    let refused = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .err()
        .expect("busy");
    assert_eq!(code_of(&refused), codes::host::TASK_BUSY);
    assert_eq!(c.tasks.live.of(&id).len(), 1, "no second session");
    drop(first);
    member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("a place again");
}

/// WP-4.4: the task's signed `max_rate_per_minute` bounds its messages, the session kept; the
/// window slides with the coordinator's clock.
#[tokio::test]
async fn messages_over_the_tasks_rate_are_refused_and_the_session_kept() {
    let m = Side::new("rate-m", false);
    let (wall, mono, c) = timed_coordinator("rate-c");
    let task = decisions_with(|task| task.limits.max_rate_per_minute = 2);
    let id = crate::membership::tests::protocol::active_with(&c, &m, task, &[], &[]).await;
    let connector = loopback(&m, &c);
    let mut task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    task.send("r-1", b"a".to_vec()).await.expect("first");
    task.send("r-2", b"b".to_vec()).await.expect("second");
    let refused = task
        .send("r-3", b"c".to_vec())
        .await
        .expect_err("over the rate");
    assert_eq!(code_of(&refused), codes::host::RATE_LIMITED);
    let step = 61;
    wall.jump(i64::try_from(step).expect("in range"));
    mono.advance(Duration::from_secs(step));
    assert_eq!(
        task.send("r-4", b"d".to_vec())
            .await
            .expect("the window slid"),
        b"echo:d"
    );
}

/// WP-4.4: the handler is told the task's version and the limits it applies itself.
#[tokio::test]
async fn the_handler_is_given_the_batch_and_retention_limits() {
    let (c, m) = (Side::new("context-c", true), Side::new("context-m", false));
    let task = decisions_with(|task| {
        task.limits.max_batch_records = 77;
        task.limits.retention_seconds = 3_600;
    });
    let id = crate::membership::tests::protocol::active_with(&c, &m, task, &[], &[]).await;
    let connector = loopback(&m, &c);
    let mut task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    assert_eq!(
        task.send("r-1", b"context?".to_vec())
            .await
            .expect("answered"),
        b"version=1 batch=77 retention=3600"
    );
}

/// WP-4.4: a message reaches the handler registered for its task's version; a declared
/// version no handler serves yet answers `not_served_yet`, the session kept.
#[tokio::test]
async fn a_message_reaches_the_handler_of_its_tasks_version() {
    let (c, m) = (Side::new("version-c", true), Side::new("version-m", false));
    let task = decisions_with(|task| task.version = 2);
    let id = crate::membership::tests::protocol::active_with(&c, &m, task, &[], &[]).await;
    let connector = loopback(&m, &c);
    let mut task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    let refused = task
        .send("r-1", b"hello".to_vec())
        .await
        .expect_err("no handler of version 2");
    assert_eq!(code_of(&refused), codes::host::NOT_SERVED_YET);
    // The session holds: a progress report still lands.
    task.report(&progress(&task, 1)).await.expect("kept");
}

/// WP-4.4: an identical repeat is answered its stored answer without reaching the handler, a
/// restart included; the same request id with another message is refused, the session kept.
#[tokio::test]
async fn an_identical_repeat_is_answered_its_stored_answer_across_a_restart() {
    use crate::membership::replay::{Gate, message_digest};

    let (c, m) = (Side::new("replay-c", true), Side::new("replay-m", false));
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    let mut task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    let first = task.send("r-1", b"hello".to_vec()).await.expect("answered");
    assert_eq!(
        task.send("r-1", b"hello".to_vec()).await.expect("replayed"),
        first
    );
    // The handler is not reached again: its count stays.
    let counted = task.send("r-c", b"count?".to_vec()).await.expect("counted");
    assert_eq!(
        task.send("r-c", b"count?".to_vec())
            .await
            .expect("replayed"),
        counted
    );
    // An answer over the bound is refused, kept nowhere, the session kept.
    let refused = task
        .send("r-big", b"big?".to_vec())
        .await
        .expect_err("over the bound");
    assert_eq!(code_of(&refused), codes::common::UNAVAILABLE);
    let refused = task
        .send("r-1", b"another".to_vec())
        .await
        .expect_err("the id answered another message");
    assert_eq!(code_of(&refused), codes::host::REQUEST_ID_REUSED);
    assert_eq!(
        task.send("r-2", b"kept".to_vec())
            .await
            .expect("the session holds"),
        b"echo:kept"
    );
    // Read back by a store opened again, as after a restart.
    let message = crate::membership::record::TaskMessage {
        membership_id: id,
        task_id: "decisions".to_owned(),
        epoch: 1,
        request_id: "r-1".to_owned(),
        body: b"hello".to_vec(),
        kind: crate::membership::record::MessageKind::Handler,
    }
    .encode()
    .expect("encodes");
    let reopened = crate::membership::Store::open(c.host.volume()).expect("reopened");
    let Gate::Replay(stored) = reopened
        .gate(&id, "decisions", "r-1", &message_digest(&message, RESOURCE))
        .expect("read")
    else {
        panic!("the answer is kept on disk")
    };
    let answer = crate::membership::record::TaskAnswer::decode(&stored).expect("an answer");
    assert_eq!(answer.body, first);
}

/// Remembers `answer` to `request_id` of task `t` of `id`, as a handler's answer is kept.
fn remembered(store: &crate::membership::Store, id: &[u8; 16], request_id: &str, digest: [u8; 32]) {
    use crate::membership::replay::Gate;
    let Gate::New(reservation) = store.gate(id, "t", request_id, &digest).expect("read") else {
        panic!("a new request")
    };
    store.remember(reservation, b"answer").expect("kept");
}

/// WP-4.4: the window keeps the last 1024 answers of a task; an older one is forgotten.
#[test]
fn the_replay_window_forgets_what_is_older_than_it() {
    use crate::membership::replay::{Gate, WINDOW};

    let host = crate::membership::tests::Host::new("window");
    let id = [0x42; 16];
    for at in 0..=WINDOW {
        remembered(&host.store, &id, &format!("r-{at}"), [0; 32]);
    }
    let reopened = crate::membership::Store::open(host.volume()).expect("reopened");
    assert!(
        matches!(
            reopened.gate(&id, "t", "r-0", &[0; 32]).expect("read"),
            Gate::New(_)
        ),
        "slid out of the window"
    );
    assert!(matches!(
        reopened.gate(&id, "t", "r-1", &[0; 32]).expect("read"),
        Gate::Replay(answer) if answer == b"answer"
    ));
    assert!(matches!(
        reopened.gate(&id, "t", "r-1", &[1; 32]).expect("read"),
        Gate::Reused
    ));
}

/// WP-4.4 (review): a request being answered is refused to a second session naming it, until
/// its answer is kept; a reservation dropped unkept frees the id.
#[test]
fn a_request_being_answered_is_refused_to_a_concurrent_repeat() {
    use crate::membership::replay::Gate;

    let host = crate::membership::tests::Host::new("in-flight");
    let id = [0x43; 16];
    let Gate::New(first) = host.store.gate(&id, "t", "r-1", &[0; 32]).expect("read") else {
        panic!("a new request")
    };
    assert!(
        matches!(
            host.store.gate(&id, "t", "r-1", &[0; 32]).expect("read"),
            Gate::Reused
        ),
        "the same id while it is answered"
    );
    drop(first);
    let Gate::New(again) = host.store.gate(&id, "t", "r-1", &[0; 32]).expect("read") else {
        panic!("freed by the drop")
    };
    host.store.remember(again, b"answer").expect("kept");
    assert!(matches!(
        host.store.gate(&id, "t", "r-1", &[0; 32]).expect("read"),
        Gate::Replay(_)
    ));
}

/// WP-4.4 (review): a temporary a crash left is swept and a slot that does not read is skipped,
/// so the task keeps answering; the requests they held are no longer remembered.
#[test]
fn a_leftover_temporary_or_a_bad_slot_does_not_close_the_task() {
    use crate::membership::replay::Gate;

    let host = crate::membership::tests::Host::new("bad-slot");
    let id = [0x44; 16];
    remembered(&host.store, &id, "r-0", [0; 32]);
    remembered(&host.store, &id, "r-1", [0; 32]);
    let dir = host
        .volume()
        .host()
        .path()
        .join("members/replay")
        .join("44".repeat(16))
        .join("t");
    std::fs::write(dir.join(".tmp-0002.cbor"), b"half a write").expect("a temporary");
    std::fs::write(dir.join("0000.cbor"), b"not a slot").expect("corrupted");
    let reopened = crate::membership::Store::open(host.volume()).expect("reopened");
    assert!(
        matches!(
            reopened.gate(&id, "t", "r-1", &[0; 32]).expect("read"),
            Gate::Replay(_)
        ),
        "the good slot still answers"
    );
    assert!(
        matches!(
            reopened.gate(&id, "t", "r-0", &[0; 32]).expect("read"),
            Gate::New(_)
        ),
        "the bad one is forgotten"
    );
    assert!(!dir.join(".tmp-0002.cbor").exists(), "the temporary swept");
}

fn progress(
    task: &crate::membership::member::MemberTask,
    seq: u64,
) -> crate::membership::record::TaskProgress {
    crate::membership::record::TaskProgress {
        membership_id: task.lease.membership_id,
        task_id: task.lease.task_id.clone(),
        manifest_epoch: task.lease.epoch,
        member_boot_id: task.lease.member_boot_id,
        report_seq: seq,
        reported_at: 1_800_000_000 + seq,
        resources: vec![crate::membership::record::ProgressResource {
            resource: RESOURCE.to_owned(),
            state: "serving".to_owned(),
            frontier: None,
            checkpoint_digest: None,
            verified_at: Some(1_799_999_000),
            reason: None,
        }],
    }
}

/// WP-4.4: a progress report is kept exactly, with the coordinator's `received_at`, before it
/// is answered; a report not above the one held is refused, the session kept.
#[tokio::test]
async fn a_progress_report_is_kept_with_its_received_at_and_a_lower_seq_is_refused() {
    let m = Side::new("progress-m", false);
    let (wall, mono, c) = timed_coordinator("progress-c");
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    let mut task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    let step = 5;
    wall.jump(i64::try_from(step).expect("in range"));
    mono.advance(Duration::from_secs(step));
    let report = progress(&task, 3);
    let answer = task.report(&report).await.expect("kept");
    assert_eq!(answer.report_seq, 3);
    assert_eq!(answer.received_at, c.context.time.now_secs());
    let (held, received_at) = c
        .host
        .store
        .progress(&id, "decisions")
        .expect("read")
        .expect("held");
    assert_eq!(held, report, "the exact report");
    assert_eq!(received_at, answer.received_at);
    assert_ne!(
        held.resources[0].verified_at,
        Some(received_at),
        "the member's time is not the coordinator's"
    );
    for seq in [3, 2] {
        let refused = task
            .report(&progress(&task, seq))
            .await
            .expect_err("not above the held one");
        assert_eq!(code_of(&refused), codes::host::REPORT_OUT_OF_ORDER);
    }
    task.report(&progress(&task, 4)).await.expect("above it");
    assert_eq!(
        task.send("r-1", b"kept".to_vec())
            .await
            .expect("the session holds"),
        b"echo:kept"
    );
}

/// WP-4.4: a report names its session's membership, task, epoch and incarnation, or is refused.
#[tokio::test]
async fn a_report_naming_another_epoch_or_boot_id_is_refused() {
    let (c, m) = (
        Side::new("misreport-c", true),
        Side::new("misreport-m", false),
    );
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    let mut task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    let mut other_epoch = progress(&task, 1);
    other_epoch.manifest_epoch = 2;
    let mut other_boot = progress(&task, 1);
    other_boot.member_boot_id = [0xEE; 16];
    let mut other_task = progress(&task, 1);
    other_task.task_id = "other".to_owned();
    let mut other_membership = progress(&task, 1);
    other_membership.membership_id = [0x99; 16];
    for report in [other_epoch, other_boot, other_task, other_membership] {
        let refused = task.report(&report).await.expect_err("another session's");
        assert_eq!(code_of(&refused), codes::common::INVALID_ARGUMENT);
    }
    assert!(
        c.host
            .store
            .progress(&id, "decisions")
            .expect("read")
            .is_none(),
        "nothing kept"
    );
}

/// WP-4.4: every lease writes the task's last session, from the coordinator's clock and with
/// the member's incarnation.
#[tokio::test]
async fn last_session_at_is_written_at_each_lease_issued() {
    let m = Side::new("last-m", false);
    let (wall, mono, c) = timed_coordinator("last-c");
    let id = active(&c, &m, None).await;
    assert!(
        c.host
            .store
            .last_session(&id, "decisions")
            .expect("read")
            .is_none(),
        "no session yet"
    );
    let connector = loopback(&m, &c);
    let first = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    let last = c
        .host
        .store
        .last_session(&id, "decisions")
        .expect("read")
        .expect("written");
    assert_eq!(last.at, first.lease.issued_at);
    assert_eq!(last.member_boot_id, m.host.identity.boot_id());
    drop(first);
    // Within the member's skew: a later lease it still accepts.
    let step = 20;
    wall.jump(i64::try_from(step).expect("in range"));
    mono.advance(Duration::from_secs(step));
    let second = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased again");
    let last = c
        .host
        .store
        .last_session(&id, "decisions")
        .expect("read")
        .expect("written");
    assert_eq!(last.at, second.lease.issued_at);
}

/// WP-4.4: a report older than the lease policy's `max_session_seconds`, or of another epoch,
/// is stale; silence leaves nothing reported and nothing stale.
#[tokio::test]
async fn a_report_past_its_session_bound_is_stale_and_silence_changes_nothing() {
    use crate::membership::progress::stale;

    assert!(!stale(1, 1_000, 1, 3_600, 4_600));
    assert!(stale(1, 1_000, 1, 3_600, 4_601), "past its session bound");
    assert!(stale(1, 1_000, 2, 3_600, 1_001), "of another epoch");

    let m = Side::new("stale-m", false);
    let (wall, mono, c) = timed_coordinator("stale-c");
    let id = active(&c, &m, None).await;
    let manifest = || {
        c.host
            .store
            .membership(&id)
            .expect("held")
            .manifest
            .expect("active")
            .0
    };
    let silent = c
        .host
        .store
        .observed(&manifest(), c.context.time.now_secs())
        .expect("read");
    assert_eq!(silent.len(), 1);
    assert!(
        silent[0].progress.is_none() && !silent[0].stale && silent[0].last_session_at.is_none()
    );
    let connector = loopback(&m, &c);
    let mut task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    task.report(&progress(&task, 1)).await.expect("kept");
    let fresh = c
        .host
        .store
        .observed(&manifest(), c.context.time.now_secs())
        .expect("read");
    assert!(!fresh[0].stale);
    let step = manifest().lease_policy.max_session_seconds + 1;
    wall.jump(i64::try_from(step).expect("in range"));
    mono.advance(Duration::from_secs(step));
    let late = c
        .host
        .store
        .observed(&manifest(), c.context.time.now_secs())
        .expect("read");
    assert!(late[0].stale, "past the session bound");
    assert_eq!(
        late[0].progress, fresh[0].progress,
        "the report itself unchanged"
    );
}

/// WP-4.4: a watch takes its session; hints the hub publishes for its task and resource arrive
/// coalesced by key, the newest counter winning, never one the member already holds; a quiet
/// watch heartbeats.
#[tokio::test]
async fn a_watch_coalesces_by_key_and_sends_heartbeats_while_quiet() {
    use crate::membership::record::{TaskType, WatchHint};
    use permguard_core::authz::Resource;

    let (c, m) = (Side::new("watch-c", true), Side::new("watch-m", false));
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    let mut task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    task.watch(vec![("l1".to_owned(), 3)])
        .await
        .expect("watching");
    assert_eq!(c.tasks.hub.live(), 1);
    let hint = |key: &str, counter| WatchHint {
        key: key.to_owned(),
        head: format!("head-{counter}"),
        counter,
    };
    let here = Resource::parse(RESOURCE).expect("a resource");
    let elsewhere = Resource::parse("plane/data/zone/z2").expect("a resource");
    // Already held, another task type, outside the lease's resource: none delivered.
    c.tasks
        .hub
        .publish(TaskType::DecisionsShip, &here, &hint("l1", 3));
    c.tasks
        .hub
        .publish(TaskType::EventsShip, &here, &hint("l1", 9));
    c.tasks
        .hub
        .publish(TaskType::DecisionsShip, &elsewhere, &hint("l1", 9));
    assert!(
        task.next_event()
            .await
            .expect("a heartbeat")
            .hints
            .is_empty(),
        "nothing for this watch: a heartbeat"
    );
    // Two advances of one key coalesce; another key rides along.
    c.tasks
        .hub
        .publish(TaskType::DecisionsShip, &here, &hint("l1", 4));
    c.tasks
        .hub
        .publish(TaskType::DecisionsShip, &here, &hint("l1", 6));
    c.tasks
        .hub
        .publish(TaskType::DecisionsShip, &here, &hint("l2", 1));
    let event = task.next_event().await.expect("hints");
    assert_eq!(event.hints, vec![hint("l1", 6), hint("l2", 1)]);
    // The session belongs to the watch now.
    let refused = task
        .send("r-1", b"hello".to_vec())
        .await
        .expect_err("a watch's session");
    assert_eq!(code_of(&refused), codes::common::INVALID_ARGUMENT);
    drop(task);
    assert_eq!(c.tasks.hub.live(), 0, "the watch went with its session");
}

/// WP-4.4: a queue past its bound ends the watch `watch_overflow`; a fence ends it
/// `epoch_stale`.
#[tokio::test]
async fn a_watch_ends_on_overflow_and_on_a_fence() {
    use crate::membership::record::{MAX_WATCH_KEYS, Status, TaskType, WatchHint};
    use permguard_core::authz::Resource;

    let here = Resource::parse(RESOURCE).expect("a resource");
    let (c, m) = (
        Side::new("overflow-c", true),
        Side::new("overflow-m", false),
    );
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    let mut task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    task.watch(Vec::new()).await.expect("watching");
    for at in 0..=MAX_WATCH_KEYS {
        c.tasks.hub.publish(
            TaskType::DecisionsShip,
            &here,
            &WatchHint {
                key: format!("k{at:05}"),
                head: "h".to_owned(),
                counter: 1,
            },
        );
    }
    let ended = task.next_event().await.expect_err("overflowed");
    assert_eq!(code_of(&ended), codes::host::WATCH_OVERFLOW);

    let (c, m) = (Side::new("fenced-c", true), Side::new("fenced-m", false));
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    let mut task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    task.watch(Vec::new()).await.expect("watching");
    move_to(&c, &id, Status::Suspended, 61);
    let ended = task.next_event().await.expect_err("fenced");
    assert_eq!(code_of(&ended), codes::host::EPOCH_STALE);
}

/// WP-4.4 (review): a restarted member numbers its reports from anew; the incarnation's own
/// order holds.
#[test]
fn a_restarted_member_numbers_its_reports_from_anew() {
    let host = crate::membership::tests::Host::new("renumber");
    let report = |boot: u8, seq: u64| crate::membership::record::TaskProgress {
        membership_id: [0x45; 16],
        task_id: "decisions".to_owned(),
        manifest_epoch: 1,
        member_boot_id: [boot; 16],
        report_seq: seq,
        reported_at: 1_800_000_000,
        resources: Vec::new(),
    };
    let keep = |progress: &crate::membership::record::TaskProgress| {
        host.store.keep_progress(
            progress,
            &progress.encode().expect("encodes"),
            1_800_000_001,
        )
    };
    keep(&report(0xA1, 5)).expect("kept");
    keep(&report(0xB2, 1)).expect("a new incarnation starts again");
    assert!(matches!(
        keep(&report(0xB2, 1)),
        Err(MembershipError::OutOfOrder(_))
    ));
}

/// WP-4.4 (review): a watch ends when its lease does.
#[tokio::test]
async fn a_watch_ends_with_its_lease() {
    let m = Side::new("watch-lease-m", false);
    let (wall, mono, c) = timed_coordinator("watch-lease-c");
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    let mut task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    task.watch(Vec::new()).await.expect("watching");
    let step = task.lease.expires_at - task.lease.issued_at;
    wall.jump(i64::try_from(step).expect("in range"));
    mono.advance(Duration::from_secs(step));
    let ended = task.next_event().await.expect_err("expired");
    assert_eq!(code_of(&ended), codes::host::LEASE_EXPIRED);
}

/// The stream engine a member's ship pass drives: one batch due, the answers it was given.
#[derive(Default)]
struct Shipping {
    /// The body shipped; `batch` when empty.
    body: Vec<u8>,
    deferred: std::sync::Mutex<usize>,
    shipped: std::sync::Mutex<bool>,
    answers: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
    retained: std::sync::Mutex<Vec<Vec<String>>>,
}

impl crate::composition::StreamShipping for Shipping {
    fn due(
        &self,
        subscription: &crate::composition::Subscribed<'_>,
    ) -> Result<Vec<String>, String> {
        assert_eq!(subscription.task_id, "decisions");
        Ok(if *self.shipped.lock().expect("lock") {
            Vec::new()
        } else {
            vec![RESOURCE.to_owned()]
        })
    }

    fn next(
        &self,
        _: &crate::composition::Subscribed<'_>,
        resource: &str,
        max_bytes: u64,
    ) -> Result<Option<crate::composition::Shipment>, String> {
        assert_eq!(resource, RESOURCE);
        assert!(max_bytes > 0, "the lease's bound");
        let mut shipped = self.shipped.lock().expect("lock");
        if *shipped {
            return Ok(None);
        }
        *shipped = true;
        Ok(Some(crate::composition::Shipment {
            request_id: "ship-1".to_owned(),
            body: if self.body.is_empty() {
                b"batch".to_vec()
            } else {
                self.body.clone()
            },
            run: [1; 16],
            first_seq: 1,
            last_seq: 1,
        }))
    }

    fn answered(
        &self,
        _: &crate::composition::Subscribed<'_>,
        _: &str,
        shipment: &crate::composition::Shipment,
        answer: &[u8],
    ) -> Result<bool, String> {
        self.answers
            .lock()
            .expect("lock")
            .push((shipment.request_id.clone(), answer.to_vec()));
        Ok(true)
    }

    fn deferred(&self, _: &crate::composition::Subscribed<'_>, _: &str) -> Result<(), String> {
        *self.deferred.lock().expect("lock") += 1;
        Ok(())
    }

    fn retain(&self, _: &[u8; 16], task_ids: &[String]) -> Result<(), String> {
        self.retained.lock().expect("lock").push(task_ids.to_vec());
        Ok(())
    }
}

/// WP-5.4: the member's ship pass keeps the subscriptions to the manifest's ship tasks, opens a
/// session on each due stream's resource, sends what the engine has ready and hands the engine
/// each answer; nothing due, nothing opened.
#[tokio::test]
async fn the_ship_pass_sends_what_the_engine_has_due_and_hands_back_the_answers() {
    let (c, m) = (Side::new("ship-c", true), Side::new("ship-m", false));
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    let engine = Shipping::default();
    let acting = Member {
        shipping: Some(&engine),
        ..member(&m, &connector)
    };
    assert_eq!(acting.ship_due(who()).await, 1);
    assert_eq!(
        engine.answers.lock().expect("lock").clone(),
        vec![("ship-1".to_owned(), b"echo:batch".to_vec())]
    );
    assert!(
        engine
            .retained
            .lock()
            .expect("lock")
            .iter()
            .all(|tasks| tasks.contains(&"decisions".to_owned()))
    );
    assert_eq!(acting.ship_due(who()).await, 0, "nothing due");
    let _ = id;
}

/// WP-5.4, after the mutants: a store the coordinator cannot reach now backs the subscription off;
/// a membership the member revoked drops its subscriptions.
#[tokio::test]
async fn a_deferral_backs_off_and_an_ended_membership_drops_its_subscriptions() {
    let (c, m) = (Side::new("ship2-c", true), Side::new("ship2-m", false));
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    let engine = Shipping {
        body: b"unavailable?".to_vec(),
        ..Shipping::default()
    };
    let acting = Member {
        shipping: Some(&engine),
        ..member(&m, &connector)
    };
    assert_eq!(acting.ship_due(who()).await, 0);
    assert_eq!(*engine.deferred.lock().expect("lock"), 1);
    assert!(engine.answers.lock().expect("lock").is_empty());
    acting.revoke(who(), &id).await.expect("revoked");
    engine.retained.lock().expect("lock").clear();
    acting.ship_due(who()).await;
    assert_eq!(
        engine.retained.lock().expect("lock").clone(),
        vec![Vec::<String>::new()]
    );
}
