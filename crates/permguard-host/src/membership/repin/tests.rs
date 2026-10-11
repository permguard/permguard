// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use permguard_core::codes;
use permguard_core::keys::Sign as _;

use super::*;
use crate::keys::ring::{ActivationGate, DATA_ATTEST, HOST_OPERATIONS};
use crate::membership::member::Connector;
use crate::membership::record::Cutover;
use crate::membership::service::Coordinating;
use crate::membership::tests::Host;
use crate::membership::tests::protocol::{Loopback, Side, active, harness, member, move_to};
use crate::operations::journal::Initiator as Who;

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

/// The coordinating side of `c`, as its sessions are served.
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

/// Prepublishes a successor in `host`'s `ring`, and binds the new set: its epoch rises.
fn rotate(host: &Host, ring: &str, operation: u8) -> u64 {
    let ring = host
        .rings
        .iter()
        .find(|held| held.id() == ring)
        .expect("the ring");
    ring.rotate(&Applying::for_tests(operation), ring.epoch())
        .expect("rotated");
    ring.maintain_now().expect("bound");
    ring.epoch()
}

fn manifest_of(side: &Side, id: &[u8; 16]) -> Manifest {
    side.host
        .store
        .membership(id)
        .expect("held")
        .manifest
        .expect("a manifest")
        .0
}

fn member_pins(manifest: &Manifest) -> Vec<(u64, bool)> {
    manifest
        .ring_pins
        .iter()
        .filter(|pin| pin.owner == Role::Member && pin.ring == DATA_ATTEST)
        .map(|pin| (pin.epoch, pin.retiring))
        .collect()
}

/// WP-4.5: a member whose ring moved re-pins it on its task session: the coordinator issues the
/// manifest at the next epoch, the new set current and the replaced one retiring, and answers a
/// new lease on the same connection, so the session goes on; a later revision keeps the pins.
#[tokio::test]
async fn a_repin_revises_the_manifest_and_the_session_goes_on() {
    let (c, m) = (Side::new("repin-c", true), Side::new("repin-m", false));
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    let mut task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    let epoch = rotate(&m.host, DATA_ATTEST, 90);
    member(&m, &connector)
        .repin(who(), &mut task, DATA_ATTEST)
        .await
        .expect("re-pinned");
    let at_coordinator = manifest_of(&c, &id);
    assert_eq!(at_coordinator.epoch, 2);
    assert_eq!(
        member_pins(&at_coordinator),
        vec![(epoch, false), (1, true)]
    );
    assert_eq!(
        manifest_of(&m, &id),
        at_coordinator,
        "the member holds the same manifest"
    );
    assert_eq!(task.lease.epoch, 2, "a new lease at the new epoch");
    assert_eq!(
        c.host
            .store
            .delivered(&id)
            .expect("read")
            .expect("kept")
            .epoch,
        2,
        "the re-pin delivered its manifest"
    );
    assert_eq!(c.tasks.live.of(&id)[0].epoch, 2);
    assert_eq!(
        task.send("r-1", b"after".to_vec())
            .await
            .expect("the session goes on"),
        b"echo:after"
    );
    assert!(
        c.trail
            .events
            .lock()
            .expect("lock")
            .iter()
            .any(|(action, ..)| action == AUDIT_REPINNED),
        "the re-pin is recorded"
    );
    // A later revision keeps the member's pins as the re-pin left them.
    move_to(&c, &id, Status::Suspended, 91);
    assert_eq!(
        member_pins(&manifest_of(&c, &id)),
        vec![(epoch, false), (1, true)]
    );
    // The new set's statement is journaled: its keys stay readable.
    let pin = manifest_of(&c, &id)
        .ring_pins
        .into_iter()
        .find(|pin| pin.owner == Role::Member && !pin.retiring)
        .expect("a pin");
    assert_eq!(
        c.host
            .store
            .member_statement(&id, &pin)
            .expect("kept")
            .epoch,
        epoch
    );
}

/// WP-4.5: the exact current set is an idempotent retry; a lower epoch is a rollback and the same
/// epoch with another set an equivocation, both refused and recorded; one grace at a time.
#[tokio::test]
async fn a_repin_is_retried_exactly_and_refuses_rollback_and_equivocation() {
    let (c, m) = (Side::new("retry-c", true), Side::new("retry-m", false));
    let id = active(&c, &m, None).await;
    let old = m.host.statement(DATA_ATTEST);
    // A copy of the member's volume: the same identity, which will move its ring otherwise.
    let twin = m.host.copy("retry-twin");
    let connector = loopback(&m, &c);
    let mut task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    rotate(&m.host, DATA_ATTEST, 92);
    let repinning = member(&m, &connector);
    repinning
        .repin(who(), &mut task, DATA_ATTEST)
        .await
        .expect("re-pinned");
    // The exact retry: nothing new is issued.
    repinning
        .repin(who(), &mut task, DATA_ATTEST)
        .await
        .expect("retried");
    assert_eq!(manifest_of(&c, &id).epoch, 2);

    let service = coordinating(&c);
    let peer = m.host.verified();
    let rollback = service
        .repin(&peer, &id, &old, c.context.time.now_secs() + 1)
        .expect_err("lower");
    assert!(
        matches!(rollback, MembershipError::NotSuccessor(_)),
        "{rollback}"
    );
    rotate(&twin, DATA_ATTEST, 93);
    let other = twin.statement(DATA_ATTEST);
    assert_eq!(other.epoch, 2);
    let equivocal = service
        .repin(&peer, &id, &other, c.context.time.now_secs() + 1)
        .expect_err("two sets");
    assert!(
        matches!(equivocal, MembershipError::Equivocation(_)),
        "{equivocal}"
    );
    // Over the session too, each recorded.
    let refused = task
        .exchange_for_tests(
            crate::membership::record::MessageKind::Repin,
            old.encode().expect("encodes"),
        )
        .await
        .expect_err("a rollback");
    assert_eq!(code_of(&refused), codes::host::MANIFEST_NOT_SUCCESSOR);
    let refused = task
        .exchange_for_tests(
            crate::membership::record::MessageKind::Repin,
            other.encode().expect("encodes"),
        )
        .await
        .expect_err("an equivocation");
    assert_eq!(code_of(&refused), codes::host::MANIFEST_EQUIVOCATION);
    let recorded = c.trail.facts.lock().expect("lock").clone();
    for action in [
        crate::membership::task::AUDIT_REPIN_ROLLBACK,
        crate::membership::task::AUDIT_REPIN_EQUIVOCATION,
    ] {
        assert!(recorded.iter().any(|(held, _)| held == action), "{action}");
    }
    // A move that only removes a key, the prepublished one revoked, is an archive: taken during
    // the grace, the current pin replaced and the retiring one kept (after the review).
    let ring = m
        .host
        .rings
        .iter()
        .find(|held| held.id() == DATA_ATTEST)
        .expect("the ring");
    let active = ring.active_key_id().expect("active");
    let prepublished = ring
        .view()
        .expect("a view")
        .keys
        .into_iter()
        .map(|key| key.kid)
        .find(|kid| kid.as_str() != active.as_str())
        .expect("the prepublished key");
    ring.revoke(
        &Applying::for_tests(94),
        &prepublished,
        "drill",
        None,
        ring.epoch(),
    )
    .expect("revoked");
    ring.maintain_now().expect("bound");
    let archived = ring.epoch();
    service
        .repin(
            &peer,
            &id,
            &m.host.statement(DATA_ATTEST),
            c.context.time.now_secs() + 1,
        )
        .expect("an archive during the grace");
    assert_eq!(
        member_pins(&manifest_of(&c, &id)),
        vec![(archived, false), (1, true)]
    );
    // A move that adds a key waits for the first grace to end.
    ring.rotate(&Applying::for_tests(95), ring.epoch())
        .expect("rotated");
    ring.maintain_now().expect("bound");
    let pending = service
        .repin(
            &peer,
            &id,
            &m.host.statement(DATA_ATTEST),
            c.context.time.now_secs() + 1,
        )
        .expect_err("one grace at a time");
    assert!(
        matches!(pending, MembershipError::Transition { .. }),
        "{pending}"
    );
}

/// WP-4.5: a set signed by another identity, or a ring the membership does not pin, is refused.
#[tokio::test]
async fn a_repin_under_another_identity_or_ring_is_refused() {
    let (c, m) = (
        Side::new("stranger-c", true),
        Side::new("stranger-m", false),
    );
    let id = active(&c, &m, None).await;
    let service = coordinating(&c);
    let peer = m.host.verified();
    let stranger = Host::new("stranger-x");
    rotate(&stranger, DATA_ATTEST, 95);
    let refused = service
        .repin(
            &peer,
            &id,
            &stranger.statement(DATA_ATTEST),
            c.context.time.now_secs() + 1,
        )
        .expect_err("another identity's set");
    assert!(
        matches!(refused, MembershipError::Unverified(_)),
        "{refused}"
    );
    let unpinned = service
        .repin(
            &peer,
            &id,
            &m.host.statement(HOST_OPERATIONS),
            c.context.time.now_secs() + 1,
        )
        .expect_err("a ring the membership does not pin");
    assert!(
        matches!(unpinned, MembershipError::Invalid(_)),
        "{unpinned}"
    );
    assert_eq!(manifest_of(&c, &id).epoch, 1, "nothing issued");
}

/// WP-4.5: a cutover is journaled before it is answered, read back after a restart; one outside
/// a re-pin's grace, or moving a stream's `from_seq`, is refused.
#[tokio::test]
async fn a_cutover_is_durable_before_it_is_acknowledged() {
    let (c, m) = (Side::new("cutover-c", true), Side::new("cutover-m", false));
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    let mut task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    let cutover = |epoch: u64, from: u64| Cutover {
        ring: DATA_ATTEST.to_owned(),
        epoch,
        streams: vec![("decisions-stream".to_owned(), from)],
    };
    // Before any re-pin there is no grace to cut over in.
    let outside = task.cutover(&cutover(1, 10)).await.expect_err("no re-pin");
    assert_eq!(code_of(&outside), codes::common::INVALID_ARGUMENT);
    let epoch = rotate(&m.host, DATA_ATTEST, 96);
    member(&m, &connector)
        .repin(who(), &mut task, DATA_ATTEST)
        .await
        .expect("re-pinned");
    let stale = task
        .cutover(&cutover(epoch - 1, 10))
        .await
        .expect_err("another epoch");
    assert_eq!(code_of(&stale), codes::common::INVALID_ARGUMENT);
    task.cutover(&cutover(epoch, 10)).await.expect("journaled");
    task.cutover(&cutover(epoch, 10))
        .await
        .expect("the same again");
    let moved = task.cutover(&cutover(epoch, 11)).await.expect_err("fixed");
    assert_eq!(code_of(&moved), codes::host::MANIFEST_EQUIVOCATION);
    let reopened = crate::membership::Store::open(c.host.volume()).expect("reopened");
    let state = reopened.cutover(&id, DATA_ATTEST).expect("kept");
    assert_eq!(state.epoch, epoch);
    assert_eq!(state.streams.get("decisions-stream"), Some(&10));
}

/// WP-4.5: below a stream's cutover only the retiring set verifies, at or above it only the new
/// one; once every stream is acknowledged below its cutover, a revision drops the retiring pin.
#[tokio::test]
async fn the_old_set_verifies_only_below_each_streams_cutover_and_retires_once_acknowledged() {
    let (c, m) = (Side::new("grace-c", true), Side::new("grace-m", false));
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    let mut task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    let epoch = rotate(&m.host, DATA_ATTEST, 97);
    member(&m, &connector)
        .repin(who(), &mut task, DATA_ATTEST)
        .await
        .expect("re-pinned");
    let pins = |stream: &str, seq: u64| -> Vec<(u64, bool)> {
        c.host
            .store
            .verifying_pins(&id, DATA_ATTEST, stream, seq)
            .iter()
            .map(|pin| (pin.epoch, pin.retiring))
            .collect()
    };
    assert_eq!(pins("a", 5).len(), 2, "before a cutover, either set");
    task.cutover(&Cutover {
        ring: DATA_ATTEST.to_owned(),
        epoch,
        streams: vec![("a".to_owned(), 10), ("b".to_owned(), 3)],
    })
    .await
    .expect("journaled");
    assert_eq!(pins("a", 9), vec![(1, true)]);
    assert_eq!(pins("a", 10), vec![(epoch, false)]);
    assert_eq!(pins("b", 2), vec![(1, true)]);

    let service = coordinating(&c);
    let acknowledge = |stream: &str, through: u64| {
        service.acknowledge(
            &id,
            &Acknowledgement {
                ring: DATA_ATTEST.to_owned(),
                epoch,
                stream: stream.to_owned(),
                through_seq: through,
            },
        )
    };
    assert!(
        acknowledge("unknown", 1).is_err(),
        "a stream the cutover names not"
    );
    assert!(!acknowledge("a", 9).expect("acknowledged"), "b is not yet");
    let before = manifest_of(&c, &id).epoch;
    assert!(
        acknowledge("b", 2).expect("acknowledged"),
        "every stream now"
    );
    let after = manifest_of(&c, &id);
    assert_eq!(after.epoch, before + 1);
    assert_eq!(
        member_pins(&after),
        vec![(epoch, false)],
        "the retiring pin dropped"
    );
    let reopened = crate::membership::Store::open(c.host.volume()).expect("reopened");
    assert!(reopened.cutover(&id, DATA_ATTEST).expect("kept").complete());
}

/// A gate answering what it is told.
struct Fixed(std::sync::atomic::AtomicBool);

impl ActivationGate for Fixed {
    fn may_activate(&self, _ring: &str, _epoch: u64) -> bool {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// WP-4.5: a ring keeps its active key while its gate is shut, a prepublished key past its window
/// included, and activates it once the gate opens.
#[test]
fn a_ring_activates_its_prepublished_key_only_once_the_gate_opens() {
    let time = Arc::new(crate::time::TimeGuard::system(Duration::from_secs(30)));
    let host = Host::new("gate-ring");
    let ring = Arc::new(
        crate::keys::ring::Ring::open(
            host.volume(),
            crate::keys::ring::CONTROL_ATTEST,
            permguard_objects::crypto::suite::Suite::Ed25519Sha256V1,
            crate::keys::ring::Policy {
                publish_ahead: Duration::ZERO,
                rotate_every: Duration::from_secs(3600),
                retain: Duration::from_secs(7200),
            },
            time,
        )
        .expect("the ring opens"),
    );
    let gate = Arc::new(Fixed(std::sync::atomic::AtomicBool::new(false)));
    ring.set_gate(Arc::clone(&gate) as Arc<dyn ActivationGate>);
    ring.maintain_now()
        .expect("the first key, whatever the gate");
    let first = ring.active_key_id().expect("active");
    ring.rotate(&Applying::for_tests(98), ring.epoch())
        .expect("rotated");
    ring.maintain_now().expect("held");
    assert_eq!(
        ring.active_key_id().expect("active"),
        first,
        "the gate is shut"
    );
    gate.0.store(true, std::sync::atomic::Ordering::SeqCst);
    ring.maintain_now().expect("activated");
    assert_ne!(
        ring.active_key_id().expect("active"),
        first,
        "the gate opened"
    );
}

/// WP-4.5: a member's ring may not activate the key of an epoch a membership does not pin yet;
/// once the re-pin is persisted it may.
#[tokio::test]
async fn a_member_ring_does_not_activate_before_its_repin_is_persisted() {
    let (c, m) = (Side::new("gate-c", true), Side::new("gate-m", false));
    let id = active(&c, &m, None).await;
    let gate = PinGate {
        store: Arc::clone(&m.host.store),
    };
    let epoch = rotate(&m.host, DATA_ATTEST, 99);
    assert!(!gate.may_activate(DATA_ATTEST, epoch), "the pin lags");
    assert!(gate.may_activate(DATA_ATTEST, 1), "the pinned epoch itself");
    let connector = loopback(&m, &c);
    let repinned = member(&m, &connector).repin_due(who()).await;
    assert_eq!(repinned, 1);
    assert!(
        gate.may_activate(DATA_ATTEST, epoch),
        "the re-pin is persisted"
    );
    assert_eq!(manifest_of(&m, &id).epoch, 2);
}

/// WP-4.5, the reverse direction: a coordinator whose `host.operations` moved revises every
/// membership it coordinates, and its ring activates the new key only once the member received
/// that revision.
#[tokio::test]
async fn a_coordinator_ring_activates_only_once_every_member_holds_its_new_pin() {
    let (c, m) = (Side::new("reverse-c", true), Side::new("reverse-m", false));
    let id = active(&c, &m, None).await;
    let gate = PinGate {
        store: Arc::clone(&c.host.store),
    };
    let service = coordinating(&c);
    let epoch = rotate(&c.host, HOST_OPERATIONS, 100);
    assert!(!gate.may_activate(HOST_OPERATIONS, epoch), "the pin lags");
    assert_eq!(service.revise_coordinated().expect("revised"), 1);
    assert_eq!(service.revise_coordinated().expect("nothing more"), 0);
    let revised = manifest_of(&c, &id);
    assert!(
        revised
            .ring_pins
            .iter()
            .any(|pin| pin.owner == Role::Coordinator
                && pin.ring == HOST_OPERATIONS
                && pin.epoch == epoch)
    );
    assert!(
        !gate.may_activate(HOST_OPERATIONS, epoch),
        "revised, but not yet delivered"
    );
    let connector = loopback(&m, &c);
    let _ = member(&m, &connector)
        .sync(who(), &id)
        .await
        .expect("synced");
    assert!(
        gate.may_activate(HOST_OPERATIONS, epoch),
        "delivered by the sync"
    );
    assert_eq!(manifest_of(&m, &id).epoch, revised.epoch);
    let _: &dyn Connector = &connector;
}

/// WP-4.5 (after the review): a member signing no stream under the ring cuts over with none once
/// its ring activated the new key, and the coordinator retires the replaced pin at once.
#[tokio::test]
async fn a_streamless_cutover_retires_the_replaced_pin_once_the_key_activated() {
    let c = Side::new("streamless-c", true);
    let wall = Arc::new(crate::time::ManualClock::at(
        i64::try_from(crate::authz::store::now()).expect("in range"),
    ));
    let mono = Arc::new(crate::time::ManualMonotonic::default());
    let time = Arc::new(crate::time::TimeGuard::new(
        wall.clone(),
        mono.clone(),
        Duration::from_secs(30),
    ));
    let m = Side::timed(Host::timed("streamless-m", Arc::clone(&time)), false, time);
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    let acting = member(&m, &connector);
    let epoch = rotate(&m.host, DATA_ATTEST, 101);
    assert_eq!(acting.repin_due(who()).await, 1);
    assert_eq!(
        acting.cutover_due(who()).await,
        0,
        "the new key waits its window: no cutover yet"
    );
    // The window passes on the member's clock and its ring activates the key.
    wall.jump(601);
    mono.advance(Duration::from_secs(601));
    m.host
        .rings
        .iter()
        .find(|ring| ring.id() == DATA_ATTEST)
        .expect("the ring")
        .maintain_now()
        .expect("activated");
    assert_eq!(acting.cutover_due(who()).await, 1);
    let at_coordinator = manifest_of(&c, &id);
    assert_eq!(
        member_pins(&at_coordinator),
        vec![(epoch, false)],
        "retired"
    );
    assert!(
        c.host
            .store
            .cutover(&id, DATA_ATTEST)
            .expect("kept")
            .streams
            .is_empty()
    );
    assert_eq!(acting.cutover_due(who()).await, 0, "nothing retires twice");
}

/// WP-4.5 (after the review): a complete cutover whose retirement did not run, a crash between
/// the acknowledgement and the revision, is retired by the pass.
#[tokio::test]
async fn the_pass_retires_a_complete_cutover_left_behind() {
    let (c, m) = (Side::new("retire-c", true), Side::new("retire-m", false));
    let id = active(&c, &m, None).await;
    let connector = loopback(&m, &c);
    let mut task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("leased");
    let epoch = rotate(&m.host, DATA_ATTEST, 102);
    member(&m, &connector)
        .repin(who(), &mut task, DATA_ATTEST)
        .await
        .expect("re-pinned");
    task.cutover(&Cutover {
        ring: DATA_ATTEST.to_owned(),
        epoch,
        streams: vec![("s".to_owned(), 5)],
    })
    .await
    .expect("journaled");
    // The acknowledgement written, the revision not.
    assert!(
        c.host
            .store
            .record_acknowledgement(
                &Applying::for_tests(103),
                &id,
                &Acknowledgement {
                    ring: DATA_ATTEST.to_owned(),
                    epoch,
                    stream: "s".to_owned(),
                    through_seq: 4,
                },
                c.context.time.now_secs(),
            )
            .expect("acknowledged")
    );
    assert_eq!(
        member_pins(&manifest_of(&c, &id)),
        vec![(epoch, false), (1, true)]
    );
    let service = coordinating(&c);
    assert_eq!(service.retire_due().expect("retired"), 1);
    assert_eq!(member_pins(&manifest_of(&c, &id)), vec![(epoch, false)]);
    assert_eq!(service.retire_due().expect("nothing more"), 0);
}

/// WP-4.5 (after the review): a member whose coordinator moved past the epoch it holds syncs and
/// asks for the session again, instead of staying stale.
#[tokio::test]
async fn a_member_behind_its_coordinators_epoch_syncs_and_leases() {
    let (c, m) = (Side::new("behind-c", true), Side::new("behind-m", false));
    let id = active(&c, &m, None).await;
    // A fence: the coordinator issues the next epoch the member has not seen.
    move_to(&c, &id, Status::Active, 104);
    assert_eq!(manifest_of(&m, &id).epoch, 1);
    let connector = loopback(&m, &c);
    let task = member(&m, &connector)
        .open_task(who(), &id, "decisions", RESOURCE, Vec::new())
        .await
        .expect("synced, then leased");
    assert_eq!(task.lease.epoch, 2);
    assert_eq!(manifest_of(&m, &id).epoch, 2);
}

/// WP-4.5: a coordinator's ring waits for every member it coordinates, not only one.
#[tokio::test]
async fn the_coordinators_gate_waits_for_every_member() {
    let c = Side::new("every-c", true);
    let (m1, m2) = (Side::new("every-m1", false), Side::new("every-m2", false));
    let first = active(&c, &m1, None).await;
    let second = active(&c, &m2, None).await;
    let gate = PinGate {
        store: Arc::clone(&c.host.store),
    };
    let epoch = rotate(&c.host, HOST_OPERATIONS, 105);
    assert_eq!(coordinating(&c).revise_coordinated().expect("revised"), 2);
    let leased = loopback(&m1, &c);
    let _session = member(&m1, &leased)
        .open_task(who(), &first, "decisions", RESOURCE, Vec::new())
        .await
        .expect("synced, then leased");
    assert!(
        !gate.may_activate(HOST_OPERATIONS, epoch),
        "the second member has not received it"
    );
    let synced = loopback(&m2, &c);
    member(&m2, &synced)
        .sync(who(), &second)
        .await
        .expect("synced");
    assert!(gate.may_activate(HOST_OPERATIONS, epoch));
}
