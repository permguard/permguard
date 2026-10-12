// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use permguard_core::codes;

use super::*;
use crate::identity::record::uuid_text;
use crate::membership::record::LeasePolicy;
use crate::membership::tests::Host;
use crate::membership::tests::protocol::{Loopback, Side, active, harness, member, move_to};
use crate::operations::journal::Initiator as Who;
use crate::operations::mutation::Applying;
use crate::time::{ManualClock, ManualMonotonic, TimeGuard};

const RESOURCE: &str = "plane/data/zone/z1";
const DORMANT_AFTER: u64 = 100;
const REVOKE_AFTER: u64 = 300;

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

fn policy() -> LeasePolicy {
    LeasePolicy {
        max_session_seconds: 60,
        offline_grace_seconds: 600,
        clock_skew_seconds: 30,
        dormant_after_seconds: DORMANT_AFTER,
        revoke_after_seconds: REVOKE_AFTER,
    }
}

/// The coordinator's clocks, moved together.
struct Clocks {
    wall: Arc<ManualClock>,
    mono: Arc<ManualMonotonic>,
}

impl Clocks {
    fn advance(&self, seconds: u64) {
        self.wall.jump(i64::try_from(seconds).expect("in range"));
        self.mono.advance(Duration::from_secs(seconds));
    }
}

/// A coordinator on a manual clock a few seconds ahead of the real one, so a binding the member
/// signs just after is not in its future.
fn timed_coordinator(tag: &str) -> (Clocks, Side) {
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
        Clocks { wall, mono },
        Side::timed(Host::timed(tag, Arc::clone(&time)), true, time),
    )
}

/// The coordinating side of `c`, as its server's pass drives it.
fn coordinating(c: &Side) -> Coordinating {
    Coordinating {
        store: Arc::clone(&c.host.store),
        mutations: Arc::clone(&c.mutations),
        identity: Arc::clone(&c.host.identity),
        keys: Arc::new(crate::keys::registry::Registry::new(
            Some(Arc::clone(&c.host.identity)),
            c.host.rings.clone(),
        )),
        capabilities: harness(Role::Coordinator),
        time: Arc::clone(&c.context.time),
        tasks: Arc::clone(&c.tasks),
    }
}

fn status(c: &Side, id: &[u8; 16]) -> Status {
    c.host.store.membership(id).expect("held").status
}

/// The audit records of `action` the system's dormancy initiated about `id`.
fn by_dormancy(c: &Side, action: &str, id: &[u8; 16]) -> usize {
    c.trail
        .events
        .lock()
        .expect("lock")
        .iter()
        .filter(|(recorded, subject, target, _)| {
            recorded == action
                && subject == &format!("system:{INITIATOR}")
                && target.as_deref() == Some(uuid_text(id).as_str())
        })
        .count()
}

/// Moves the coordinator's clock past the approval of `id`, which the protocol harness signs at
/// the real time: a lease taken then is the later of the two, however long the setup ran.
fn caught_up(clocks: &Clocks, c: &Side, id: &[u8; 16]) {
    let approved_at = c.host.store.active_since(id).expect("active");
    let now = c.context.time.now_secs();
    if approved_at >= now {
        clocks.advance(approved_at - now + 1);
    }
}

/// A membership of `m` with `c` under the short thresholds, leased once: the lease's time.
async fn leased_once(clocks: &Clocks, c: &Side, m: &Side) -> ([u8; 16], u64) {
    let id = active(c, m, Some(policy())).await;
    caught_up(clocks, c, &id);
    let connector = loopback(m, c);
    let task = member(m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    (id, task.lease.issued_at)
}

/// WP-4.6, done when: a member silent past `dormant_after` is suspended and audited
/// `host.membership.dormant`, and past `revoke_after` revoked and audited
/// `host.membership.revoked`, each by the system's dormancy, at the next epoch.
#[tokio::test]
async fn a_silent_member_is_suspended_then_revoked_at_the_thresholds() {
    let m = Side::new("dormant-m", false);
    let (clocks, c) = timed_coordinator("dormant-c");
    let (id, leased_at) = leased_once(&clocks, &c, &m).await;
    let pass = coordinating(&c);
    assert_eq!(
        c.host.store.dormant_since(&id).expect("read"),
        Some(leased_at)
    );
    // A sync is no session: it does not move the clock (owner decision).
    clocks.advance(5);
    member(&m, &loopback(&m, &c))
        .sync(who(), &id)
        .await
        .expect("synced");
    assert_eq!(
        c.host.store.dormant_since(&id).expect("read"),
        Some(leased_at),
        "the sync moved nothing"
    );
    // The member's copy is never the dormancy's: only its coordinator measures it.
    assert_eq!(m.host.store.dormant_since(&id).expect("read"), None);
    assert_eq!(
        m.host.store.dormancy(&id, u64::MAX).expect("read"),
        None,
        "nothing is ever due on the member's side"
    );
    let silent = c.context.time.now_secs() - leased_at;
    clocks.advance(DORMANT_AFTER - silent - 1);
    assert_eq!(pass.dormancy_due(), 0, "one second short of dormant_after");
    assert_eq!(status(&c, &id), Status::Active);
    clocks.advance(1);
    assert_eq!(pass.dormancy_due(), 1);
    assert_eq!(status(&c, &id), Status::Suspended);
    assert_eq!(c.host.store.membership(&id).expect("held").epoch(), 2);
    assert_eq!(by_dormancy(&c, AUDIT_DORMANT, &id), 2, "intent and outcome");
    assert_eq!(pass.dormancy_due(), 0, "suspended once");
    assert_eq!(
        c.host
            .store
            .dormancy(&id, c.context.time.now_secs())
            .expect("read"),
        None,
        "nothing is due of a suspended membership before revoke_after"
    );
    clocks.advance(REVOKE_AFTER - DORMANT_AFTER - 1);
    assert_eq!(pass.dormancy_due(), 0, "one second short of revoke_after");
    assert_eq!(status(&c, &id), Status::Suspended);
    clocks.advance(1);
    assert_eq!(pass.dormancy_due(), 1);
    assert_eq!(status(&c, &id), Status::Revoked);
    assert_eq!(c.host.store.membership(&id).expect("held").epoch(), 3);
    assert_eq!(by_dormancy(&c, AUDIT_REVOKED, &id), 2, "intent and outcome");
    clocks.advance(REVOKE_AFTER);
    assert_eq!(pass.dormancy_due(), 0, "terminal");
}

/// WP-4.6: once the threshold passed, a lease is refused before the pass suspends the
/// membership, so the pass's cadence opens no window.
#[tokio::test]
async fn a_lease_past_the_threshold_is_refused_before_the_pass_suspends() {
    let m = Side::new("window-m", false);
    let (clocks, c) = timed_coordinator("window-c");
    let (id, leased_at) = leased_once(&clocks, &c, &m).await;
    clocks.advance(DORMANT_AFTER - (c.context.time.now_secs() - leased_at));
    let connector = loopback(&m, &c);
    let refused = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .map(|_| ())
        .expect_err("dormant");
    match refused {
        MembershipError::Remote { code, .. } => {
            assert_eq!(code, codes::host::MEMBERSHIP_TRANSITION_REFUSED);
        }
        other => panic!("a remote refusal, not {other:?}"),
    }
    assert_eq!(status(&c, &id), Status::Active, "the pass has not run");
    assert_eq!(
        c.host
            .store
            .last_session(&id, "decisions")
            .expect("read")
            .expect("kept")
            .at,
        leased_at,
        "no lease was issued"
    );
}

/// WP-4.6: dormancy is measured from the coordinator's leases, never from what the member
/// reports: a progress report does not move the clock, a lease does.
#[tokio::test]
async fn the_dormancy_clock_reads_only_the_coordinators_leases() {
    let m = Side::new("claim-m", false);
    let (clocks, c) = timed_coordinator("claim-c");
    let id = active(&c, &m, Some(policy())).await;
    caught_up(&clocks, &c, &id);
    let connector = loopback(&m, &c);
    let mut task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    let leased_at = task.lease.issued_at;
    clocks.advance(5);
    let report = crate::membership::record::TaskProgress {
        membership_id: id,
        task_id: task.lease.task_id.clone(),
        manifest_epoch: task.lease.epoch,
        member_boot_id: task.lease.member_boot_id,
        report_seq: 1,
        reported_at: c.context.time.now_secs() + 3600,
        resources: vec![crate::membership::record::ProgressResource {
            resource: RESOURCE.to_owned(),
            state: "serving".to_owned(),
            frontier: None,
            checkpoint_digest: None,
            verified_at: None,
            reason: None,
        }],
    };
    task.report(&report).await.expect("kept");
    assert!(
        c.host
            .store
            .progress(&id, "decisions")
            .expect("read")
            .is_some(),
        "the report is kept"
    );
    assert_eq!(
        c.host.store.dormant_since(&id).expect("read"),
        Some(leased_at),
        "the report moved nothing"
    );
    clocks.advance(DORMANT_AFTER - (c.context.time.now_secs() - leased_at));
    assert_eq!(coordinating(&c).dormancy_due(), 1);
    assert_eq!(status(&c, &id), Status::Suspended);
}

/// WP-4.6: a dormant member resumes only through an operator's resume, at a new epoch, and its
/// clock restarts there; the pass never resumes it.
#[tokio::test]
async fn a_dormant_member_resumes_only_by_an_operator_and_its_clock_restarts() {
    let m = Side::new("resume-m", false);
    let (clocks, c) = timed_coordinator("resume-c");
    let (id, leased_at) = leased_once(&clocks, &c, &m).await;
    let pass = coordinating(&c);
    clocks.advance(DORMANT_AFTER - (c.context.time.now_secs() - leased_at));
    assert_eq!(pass.dormancy_due(), 1);
    assert_eq!(status(&c, &id), Status::Suspended);
    clocks.advance(10);
    assert_eq!(pass.dormancy_due(), 0, "the pass does not resume");
    assert_eq!(status(&c, &id), Status::Suspended);
    // The operator's resume, at the coordinator's time as the Host API issues it.
    let now = c.context.time.now_secs();
    let resumed = c
        .host
        .store
        .check_successor(&c.host.coordinator(), &id, Status::Active, None, now)
        .expect("a successor");
    c.host
        .store
        .transition(
            &Applying::for_tests(71),
            &c.host.coordinator(),
            &resumed,
            now,
        )
        .expect("resumed");
    assert_eq!(resumed.epoch, 3, "the resume bumps the epoch");
    assert_eq!(c.host.store.dormant_since(&id).expect("read"), Some(now));
    assert_eq!(pass.dormancy_due(), 0, "the clock restarted at the resume");
    clocks.advance(DORMANT_AFTER - 1);
    assert_eq!(pass.dormancy_due(), 0);
    assert_eq!(status(&c, &id), Status::Active);
    clocks.advance(1);
    assert_eq!(pass.dormancy_due(), 1);
    assert_eq!(status(&c, &id), Status::Suspended);
}

/// WP-4.6: a wall clock set back never shortens a dormancy: the guard carries its time forward
/// by monotonic time.
#[tokio::test]
async fn a_clock_set_back_does_not_shorten_the_dormancy_clock() {
    let m = Side::new("back-m", false);
    let (clocks, c) = timed_coordinator("back-c");
    let (id, leased_at) = leased_once(&clocks, &c, &m).await;
    let silent = c.context.time.now_secs() - leased_at;
    clocks.wall.jump(-86_400);
    clocks
        .mono
        .advance(Duration::from_secs(DORMANT_AFTER - silent));
    assert_eq!(coordinating(&c).dormancy_due(), 1);
    assert!(c.context.time.anomaly().is_some(), "the jump is an anomaly");
    assert_eq!(status(&c, &id), Status::Suspended);
}

/// WP-4.6, owner decision: revocation is unconditional. A membership an operator suspended, or
/// one held for review, is revoked at `revoke_after`; a held one is not suspended at
/// `dormant_after`, its hold already refusing its sessions.
#[tokio::test]
async fn a_member_suspended_by_an_operator_or_held_is_revoked_too() {
    let (m1, m2) = (Side::new("operator-m", false), Side::new("held-m", false));
    let (clocks, c) = timed_coordinator("unconditional-c");
    let (suspended, first) = leased_once(&clocks, &c, &m1).await;
    let (held, second) = leased_once(&clocks, &c, &m2).await;
    move_to(&c, &suspended, Status::Suspended, 72);
    c.host
        .store
        .hold(
            &Applying::for_tests(73),
            &held,
            9,
            c.context.time.now_secs(),
        )
        .expect("held");
    let pass = coordinating(&c);
    clocks.advance(DORMANT_AFTER);
    assert_eq!(pass.dormancy_due(), 0, "neither is suspended again");
    assert_eq!(status(&c, &suspended), Status::Suspended);
    assert_eq!(status(&c, &held), Status::Active);
    assert_eq!(
        c.host
            .store
            .dormancy(&held, c.context.time.now_secs())
            .expect("read"),
        None
    );
    let elapsed = c.context.time.now_secs() - first.max(second);
    clocks.advance(REVOKE_AFTER - elapsed);
    assert_eq!(pass.dormancy_due(), 2);
    assert_eq!(status(&c, &suspended), Status::Revoked);
    assert_eq!(status(&c, &held), Status::Revoked);
    assert_eq!(by_dormancy(&c, AUDIT_REVOKED, &suspended), 2);
    assert_eq!(by_dormancy(&c, AUDIT_REVOKED, &held), 2);
}

/// WP-4.6, done when: the member's own volume does not bypass the check. Its manifest and
/// lease stay on its disk, but the coordinator leases nothing to it; revocation is terminal, and
/// it takes part again only through a new invitation and approval.
#[tokio::test]
async fn a_dormant_members_own_volume_does_not_lease_and_it_enrolls_again_only_anew() {
    let m = Side::new("volume-m", false);
    let (clocks, c) = timed_coordinator("volume-c");
    let (id, leased_at) = leased_once(&clocks, &c, &m).await;
    let pass = coordinating(&c);
    clocks.advance(DORMANT_AFTER - (c.context.time.now_secs() - leased_at));
    assert_eq!(pass.dormancy_due(), 1);
    assert_eq!(
        m.host.store.membership(&id).expect("held").status,
        Status::Active,
        "the member's volume still holds it active"
    );
    let connector = loopback(&m, &c);
    member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .map(|_| ())
        .expect_err("suspended");
    assert!(c.tasks.live.of(&id).is_empty(), "no session");
    assert_eq!(
        c.host
            .store
            .last_session(&id, "decisions")
            .expect("read")
            .expect("kept")
            .at,
        leased_at,
        "no lease was issued"
    );
    clocks.advance(REVOKE_AFTER - DORMANT_AFTER);
    assert_eq!(pass.dormancy_due(), 1);
    assert_eq!(status(&c, &id), Status::Revoked);
    member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .map(|_| ())
        .expect_err("revoked");
    assert!(
        c.host
            .store
            .check_successor(
                &c.host.coordinator(),
                &id,
                Status::Active,
                None,
                c.context.time.now_secs()
            )
            .is_err(),
        "terminal: no resume"
    );
    // A new invitation and approval: a new membership, active on both sides.
    let again = active(&c, &m, Some(policy())).await;
    assert_ne!(again, id);
    assert_eq!(status(&c, &again), Status::Active);
    assert_eq!(
        m.host.store.membership(&again).expect("held").status,
        Status::Active
    );
}

/// WP-4.6: the clock's start is the journal's, so a restart keeps it: a store reopened from the
/// volume reads the same start and calls for the same transitions at the same thresholds.
#[tokio::test]
async fn the_dormancy_clock_survives_a_restart_from_the_journal() {
    let m = Side::new("restart-m", false);
    let (clocks, c) = timed_coordinator("restart-c");
    let id = active(&c, &m, Some(policy())).await;
    let approved_at = c.host.store.active_since(&id).expect("active");
    let reopened = crate::membership::Store::open(c.host.volume()).expect("reopens");
    assert_eq!(reopened.active_since(&id), Some(approved_at));
    assert_eq!(
        reopened.dormant_since(&id).expect("read"),
        Some(approved_at),
        "never leased: the clock starts at the approval"
    );
    caught_up(&clocks, &c, &id);
    let connector = loopback(&m, &c);
    let task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    let leased_at = task.lease.issued_at;
    let reopened = crate::membership::Store::open(c.host.volume()).expect("reopens");
    assert_eq!(reopened.dormant_since(&id).expect("read"), Some(leased_at));
    assert_eq!(
        reopened
            .dormancy(&id, leased_at + DORMANT_AFTER - 1)
            .expect("read"),
        None
    );
    assert_eq!(
        reopened
            .dormancy(&id, leased_at + DORMANT_AFTER)
            .expect("read"),
        Some(Due::Suspend)
    );
    assert_eq!(
        reopened
            .dormancy(&id, leased_at + REVOKE_AFTER)
            .expect("read"),
        Some(Due::Revoke)
    );
}
