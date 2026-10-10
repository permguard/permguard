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
    // A lease asked at the old epoch is refused too; synced, the member is leased again.
    drop(task);
    let refused = member
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .err()
        .expect("stale");
    assert_eq!(code_of(&refused), codes::host::EPOCH_STALE);
    member.sync(who(), &id).await.expect("synced");
    let task = member
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased at the new epoch");
    assert_eq!(task.lease.epoch, 2);
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
    let refused = member
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .err()
        .expect("stale");
    assert_eq!(code_of(&refused), codes::host::EPOCH_STALE);
    member.sync(who(), &id).await.expect("synced");
    let task = member
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("a fresh lease");
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
