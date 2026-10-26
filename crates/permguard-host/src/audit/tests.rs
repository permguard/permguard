// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use permguard_core::assurance::AssuranceProfile;
use permguard_core::{AuditEvent, AuditOutcome, AuditPhase, Fact, Subject};

use super::trail::{self, Trail};
use super::*;
use crate::time::{ManualClock, ManualMonotonic, TimeGuard};

const START: i64 = 1_800_000_000;

fn scratch(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-host-audit-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    path
}

fn stamp() -> Stamp {
    Stamp {
        host_id: [1; 16],
        boot_id: [2; 16],
        build: "9.9.9".to_owned(),
        config_revision: Digest::compute(b"settings"),
    }
}

fn guard() -> (Arc<ManualClock>, Arc<TimeGuard>) {
    let wall = Arc::new(ManualClock::at(START));
    let time = Arc::new(TimeGuard::new(
        wall.clone(),
        Arc::new(ManualMonotonic::default()),
        Duration::from_secs(30),
    ));
    (wall, time)
}

fn open_engine(volume: &Volume, time: Arc<TimeGuard>) -> Engine {
    Engine::open(volume, stamp(), time, None).expect("the engine opens")
}

/// A registry with the shapes the process's registry does not use yet.
const TEST_REGISTRY: &[ActionSchema] = &[
    action("zone.created", Class::Security, CONTROL),
    action("server.start", Class::Operations, HOST),
    action("authz.decision", Class::Access, DATA),
    ActionSchema {
        action: "audit.access_dropped",
        class: Class::Access,
        root: DATA,
        facts: &[("dropped", FactType::Uint)],
        max_bytes: 8 * 1024,
        phases: false,
    },
    ActionSchema {
        action: "grants.mutate",
        class: Class::Security,
        root: HOST,
        facts: &[
            ("reason", FactType::Text(64)),
            ("count", FactType::Uint),
            ("forced", FactType::Bool),
        ],
        max_bytes: 1024,
        phases: true,
    },
];

#[test]
fn the_registry_is_well_formed_and_refuses_a_forbidden_fact() {
    check_registry(REGISTRY).expect("the process's registry");
    const BAD: &[ActionSchema] = &[ActionSchema {
        action: "keys.rotated",
        class: Class::Security,
        root: HOST,
        facts: &[("signing_key", FactType::Text(64))],
        max_bytes: 1024,
        phases: false,
    }];
    let refused = check_registry(BAD).expect_err("a key is never a fact");
    assert!(refused.contains("signing_key"), "{refused}");
    const TWICE: &[ActionSchema] = &[
        action("server.start", Class::Operations, HOST),
        action("server.start", Class::Security, HOST),
    ];
    assert!(check_registry(TWICE).is_err(), "one class per action");
    const HUGE: &[ActionSchema] = &[ActionSchema {
        max_bytes: record::MAX_RECORD_BYTES + 1,
        ..action("server.start", Class::Operations, HOST)
    }];
    assert!(check_registry(HUGE).is_err(), "no schema outgrows a record");
}

/// The Host refuses an unregistered action, which would fail the grant it records: every action
/// the Host API's grants record is registered, as a `security` action of the Host.
#[test]
fn every_action_the_host_records_is_registered() {
    use crate::operations::grants::{
        AUDIT_EXPIRED, AUDIT_ISSUED, AUDIT_REVOKE_PLANNED, AUDIT_REVOKED,
    };
    for action in [
        AUDIT_ISSUED,
        AUDIT_REVOKE_PLANNED,
        AUDIT_REVOKED,
        AUDIT_EXPIRED,
    ] {
        let schema = REGISTRY
            .iter()
            .find(|schema| schema.action == action)
            .unwrap_or_else(|| panic!("`{action}` is not registered"));
        assert_eq!(
            (schema.class, schema.root, schema.phases),
            (Class::Security, HOST, true),
            "{action}: a security mutation, recorded at each phase"
        );
    }
    for action in [
        "server.start",
        "server.stop",
        "service.start",
        "service.stop",
        "host.clock_anomaly",
        "host.clock_restored",
    ] {
        assert!(
            REGISTRY.iter().any(|schema| schema.action == action),
            "`{action}` is not registered"
        );
    }
    let mark = REGISTRY
        .iter()
        .find(|schema| schema.action == "audit.access_dropped")
        .expect("the gap mark");
    assert_eq!((mark.class, mark.root), (Class::Access, DATA));
}

#[test]
fn a_trail_chains_and_continues_its_sequence_across_days_and_restarts() {
    let root = scratch("chain");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (wall, time) = guard();
    let first = open_engine(&volume, Arc::clone(&time));
    for zone in ["z1", "z2"] {
        first
            .append(
                &AuditEvent::new("zone.created", Subject::System("catalog")).on(zone),
                None,
            )
            .expect("a security record");
    }
    drop(first);
    // The next day, another process.
    wall.jump(86_400);
    let second = open_engine(&volume, Arc::clone(&time));
    second
        .append(
            &AuditEvent::new("zone.created", Subject::System("catalog")).on("z3"),
            None,
        )
        .expect("a security record");
    let dir = second
        .trail_dir(Class::Security, CONTROL)
        .expect("the trail");
    assert_eq!(trail::verify(&dir).expect("the chain verifies"), 3);
    assert_eq!(
        trail::days(&dir).expect("listed").len(),
        2,
        "one file a day"
    );
    let records = trail::read_day(&dir, &trail::days(&dir).expect("listed")[1]).expect("read");
    assert_eq!(
        records[0].seq, 2,
        "the sequence continues across the restart"
    );
    assert_eq!(records[0].trail, "security:plane/control");
    assert_eq!(records[0].component, "control-plane");
    assert_eq!(records[0].outcome, "ok");
    assert_eq!(records[0].at, START as u64 + 86_400);
    assert!(dir.exists(trail::META).expect("looked"));
    assert!(dir.subdir(trail::CHECKPOINTS, false).is_ok());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn an_altered_record_breaks_the_chain() {
    let root = scratch("altered");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let engine = open_engine(&volume, time);
    for target in ["a", "b"] {
        engine
            .append(
                &AuditEvent::new("zone.created", Subject::System("catalog")).on(target),
                None,
            )
            .expect("appended");
    }
    let dir = engine.trail_dir(Class::Security, CONTROL).expect("trail");
    let day = trail::days(&dir).expect("listed").remove(0);
    let path = dir.child_path(&day);
    let mut bytes = std::fs::read(&path).expect("read");
    // The first `a` of the file, in the first record's `trail` text, becomes `x`: same length,
    // still canonical, and that record's digest changes.
    let at = bytes.iter().position(|b| *b == b'a').expect("a letter a");
    bytes[at] = b'x';
    std::fs::write(&path, bytes).expect("altered");
    let refused = trail::verify(&dir).expect_err("the chain is broken");
    assert!(refused.to_string().contains("does not chain"), "{refused}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn an_unregistered_action_an_undeclared_fact_or_a_wrong_resource_appends_nothing() {
    let root = scratch("refused");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let engine = Engine::with_registry(&volume, TEST_REGISTRY, stamp(), time, None).expect("opens");
    let id = [7u8; 16];
    let long = "t".repeat(2048);
    let cases: Vec<(AuditEvent<'_>, &str)> = vec![
        (
            AuditEvent::new("zone.vanished", Subject::System("catalog")),
            "not a registered",
        ),
        (
            AuditEvent::new("zone.created", Subject::System("catalog"))
                .with_facts(&[("note", Fact::Text("x"))]),
            "declares no fact",
        ),
        (
            AuditEvent::new("grants.mutate", Subject::System("host"))
                .in_operation(&id, AuditPhase::Intent)
                .with_facts(&[("count", Fact::Text("1"))]),
            "declared type",
        ),
        (
            AuditEvent::new("grants.mutate", Subject::System("host"))
                .in_operation(&id, AuditPhase::Intent)
                .with_facts(&[("reason", Fact::Text("Bearer abcdefgh.ijklmnop.qrstuvwx"))]),
            "shaped like a token",
        ),
        (
            AuditEvent::new("grants.mutate", Subject::System("host"))
                .in_operation(&id, AuditPhase::Intent)
                .with_facts(&[("reason", Fact::Text("eyJhbGciOi.eyJzdWIiOiJ.c2lnbmF0dXJl"))]),
            "shaped like a token",
        ),
        (
            AuditEvent::new("zone.created", Subject::System("catalog"))
                .in_resource("plane/data/zone/z1"),
            "not below it",
        ),
        (
            AuditEvent::new("zone.created", Subject::System("catalog"))
                .in_resource("plane/controlled"),
            "not below it",
        ),
        (
            AuditEvent::new("zone.created", Subject::System("catalog"))
                .in_resource("plane/control/../data"),
            "not below it",
        ),
        (
            AuditEvent::new("zone.created", Subject::System("catalog"))
                .in_resource("plane/control/zone//z1"),
            "not below it",
        ),
        (
            AuditEvent::new("grants.mutate", Subject::System("host")),
            "names none",
        ),
        (
            AuditEvent::new("zone.created", Subject::System("catalog"))
                .in_operation(&id, AuditPhase::Applied),
            "simple observation",
        ),
        (
            AuditEvent::new("grants.mutate", Subject::System("host"))
                .in_operation(&id, AuditPhase::Intent)
                .on(&long),
            "more than its schema allows",
        ),
    ];
    for (event, says) in cases {
        let refused = engine.append(&event, None).expect_err(says);
        assert!(refused.to_string().contains(says), "{says}: {refused}");
        assert!(
            refused.to_string().contains("nothing was appended"),
            "{refused}"
        );
    }
    let trails = root.join("host/audit/trails");
    assert!(
        std::fs::read_dir(&trails).expect("listed").next().is_none(),
        "no trail was even opened"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_narrower_resource_has_its_own_trail_and_facts_and_phases_are_recorded() {
    let root = scratch("narrow");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let engine = Engine::with_registry(&volume, TEST_REGISTRY, stamp(), time, None).expect("opens");
    engine
        .append(
            &AuditEvent::new("zone.created", Subject::System("catalog"))
                .in_resource("plane/control/zone/z1"),
            None,
        )
        .expect("narrowed below the root");
    let id = [7u8; 16];
    engine
        .append(
            &AuditEvent::new("grants.mutate", Subject::System("host"))
                .in_operation(&id, AuditPhase::Applied)
                .with_outcome(AuditOutcome::Failed)
                .with_facts(&[
                    ("reason", Fact::Text("quota")),
                    ("count", Fact::Uint(3)),
                    ("forced", Fact::Bool(false)),
                ]),
            None,
        )
        .expect("a mutation's phase");
    let narrowed = engine
        .trail_dir(Class::Security, "plane/control/zone/z1")
        .expect("its own trail");
    assert_eq!(trail::verify(&narrowed).expect("verifies"), 1);
    let host = engine.trail_dir(Class::Security, HOST).expect("trail");
    let record = trail::read_day(&host, &trail::days(&host).expect("listed")[0])
        .expect("read")
        .remove(0);
    assert_eq!(record.operation_id, Some(id));
    assert_eq!(record.phase.as_deref(), Some("applied"));
    assert_eq!(record.outcome, "failed");
    assert_eq!(record.facts["count"], record::FactValue::Uint(3));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_security_failure_is_answered_and_an_operations_failure_is_counted_and_degrades_readiness() {
    let root = scratch("failure");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let engine = open_engine(&volume, time);
    let health = Health::new();
    engine.observe(health.clone());
    let failing = permguard_core::fault::inject(
        root.join("host/audit/trails"),
        permguard_core::fault::Fault::Fsync,
    );
    let refused = engine
        .append(
            &AuditEvent::new("zone.created", Subject::System("catalog")),
            None,
        )
        .expect_err("a security record that is not durable fails its caller");
    assert!(matches!(refused, Refused::Storage(_)), "{refused}");
    engine
        .append(
            &AuditEvent::new("server.start", Subject::System("host")),
            None,
        )
        .expect("an operations record that is lost does not stop the operation");
    assert_eq!(engine.lost(), 1);
    let report = health.lifecycle().report(permguard_core::lifecycle::HOST);
    assert!(
        report.degraded.iter().any(|d| d.capability == CAPABILITY),
        "{:?}",
        report.degraded
    );
    drop(failing);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn access_records_are_queued_and_a_drop_is_counted_and_marked_in_its_trail() {
    let root = scratch("access");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let engine = Engine::with_queue(&volume, TEST_REGISTRY, stamp(), time, None, 1).expect("opens");
    {
        // The writer cannot reach any trail: at most one record in its hands and one queued.
        let _held = engine.inner.open.lock().expect("the trail map");
        for _ in 0..5 {
            engine
                .append(
                    &AuditEvent::new("authz.decision", Subject::Principal("alice")),
                    None,
                )
                .expect("an access record never fails its caller");
        }
    }
    engine.close();
    let dropped = engine.dropped();
    assert!(dropped >= 3, "{dropped}");
    let access = engine.trail_dir(Class::Access, DATA).expect("trail");
    let records =
        trail::read_day(&access, &trail::days(&access).expect("listed")[0]).expect("read");
    let marked: u64 = records
        .iter()
        .filter(|record| record.action == "audit.access_dropped")
        .map(|record| match record.facts["dropped"] {
            record::FactValue::Uint(count) => count,
            ref other => panic!("{other:?}"),
        })
        .sum();
    assert_eq!(
        marked, dropped,
        "every drop is marked in the trail that has the gap"
    );
    assert_eq!(
        records
            .iter()
            .filter(|record| record.action == "authz.decision")
            .count() as u64,
        5 - dropped
    );
    assert_eq!(
        trail::verify(&access).expect("verifies"),
        records.len() as u64
    );
    // Closed: a late access record is written where it is asked, not dropped.
    engine
        .append(
            &AuditEvent::new("authz.decision", Subject::Principal("bob")),
            None,
        )
        .expect("written");
    assert_eq!(engine.dropped(), dropped);
    assert_eq!(
        trail::verify(&access).expect("verifies"),
        records.len() as u64 + 1
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_failed_append_leaves_nothing_and_the_chain_continues() {
    let root = scratch("failed-append");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let engine = open_engine(&volume, time);
    let created = |target: &str| {
        engine.append(
            &AuditEvent::new("zone.created", Subject::System("catalog")).on(target),
            None,
        )
    };
    created("a").expect("appended");
    let dir = engine.trail_dir(Class::Security, CONTROL).expect("trail");
    let day = dir.child_path(&trail::days(&dir).expect("listed")[0]);
    let before = std::fs::read(&day).expect("read");
    {
        // The record's own flush fails; the cut that follows it flushes.
        let _failing = permguard_core::fault::inject(
            root.join("host/audit/trails"),
            permguard_core::fault::Fault::FsyncTimes { remaining: 1 },
        );
        created("b").expect_err("not durable");
    }
    assert_eq!(
        std::fs::read(&day).expect("read"),
        before,
        "the bytes were cut"
    );
    created("c").expect("appended");
    assert_eq!(
        trail::verify(&dir).expect("the chain verifies"),
        2,
        "a, then c"
    );
    let _ = std::fs::remove_dir_all(root);
}

/// A record whose fields the trail sets, at `at`.
fn bare(at: u64) -> record::AuditRecord {
    record::AuditRecord {
        trail: "operations:host".to_owned(),
        seq: 0,
        operation_id: None,
        phase: None,
        host_id: [1; 16],
        boot_id: [2; 16],
        component: "host".to_owned(),
        action: "server.start".to_owned(),
        principal: "host".to_owned(),
        resource: HOST.to_owned(),
        target: None,
        outcome: "ok".to_owned(),
        facts: std::collections::BTreeMap::new(),
        build: "9.9.9".to_owned(),
        config_revision: Digest::compute(b"settings"),
        at,
        monotonic_offset: 0,
        previous: Digest::compute(b""),
    }
}

fn trails_of(volume: &Volume) -> Dir {
    volume
        .host()
        .subdir(DIRECTORY, true)
        .and_then(|dir| dir.subdir(TRAILS, true))
        .expect("trails")
}

/// TD-3, found by the Compose lab: a trail's directory exists a moment before its `META.cbor`;
/// a listing taken between the two waits for the trail to be created rather than reading it as a
/// trail whose `META.cbor` cannot be read.
#[test]
fn a_listing_waits_for_a_trail_being_created() {
    let root = scratch("creating");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let engine = open_engine(&volume, time);
    let trails = trails_of(&volume);
    std::thread::scope(|scope| {
        // What `Inner::trail` holds while it creates one: the directory first, then its META.
        let creating = engine.inner.open.lock().expect("the lock");
        trail::directory(&trails, Class::Security, CONTROL, true).expect("the directory");
        let listing = scope.spawn(|| engine.trails_held());
        std::thread::sleep(Duration::from_millis(300));
        Trail::open(&trails, Class::Security, CONTROL, None).expect("its META");
        drop(creating);
        let listed = listing
            .join()
            .expect("the listing")
            .expect("no unreadable trail");
        assert!(
            listed.contains(&(Class::Security, CONTROL.to_owned())),
            "{listed:?}"
        );
    });
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_clock_stepped_back_across_midnight_does_not_write_to_an_earlier_day() {
    let root = scratch("step-back");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let trails = trails_of(&volume);
    let midnight = (START as u64 / 86_400 + 1) * 86_400;
    let mut opened = Trail::open(&trails, Class::Operations, HOST, None).expect("opens");
    opened.append(bare(midnight + 10)).expect("after midnight");
    opened
        .append(bare(midnight - 10))
        .expect("the clock stepped back");
    let dir = trail::directory(&trails, Class::Operations, HOST, false).expect("trail");
    assert_eq!(
        trail::days(&dir).expect("listed"),
        vec![trail::day_name(midnight)],
        "both records in the later day"
    );
    // Reopened, the trail still writes no earlier than its last day.
    drop(opened);
    let mut reopened = Trail::open(&trails, Class::Operations, HOST, None).expect("opens");
    reopened.append(bare(midnight - 20)).expect("still back");
    assert_eq!(trail::days(&dir).expect("listed").len(), 1);
    assert_eq!(trail::verify(&dir).expect("verifies"), 3);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_trail_reopened_after_an_empty_last_day_continues_from_the_day_before() {
    let root = scratch("empty-day");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let trails = trails_of(&volume);
    let day = 86_400;
    let mut opened = Trail::open(&trails, Class::Operations, HOST, None).expect("opens");
    opened.append(bare(START as u64)).expect("appended");
    opened.append(bare(START as u64)).expect("appended");
    drop(opened);
    let dir = trail::directory(&trails, Class::Operations, HOST, false).expect("trail");
    // A crash after the next day's file was created and before its first record was whole.
    std::fs::write(
        dir.child_path(&trail::day_name(START as u64 + day)),
        &bare(START as u64 + day).encode().expect("encoded")[..10],
    )
    .expect("torn");
    let mut reopened = Trail::open(&trails, Class::Operations, HOST, None).expect("opens");
    assert_eq!(reopened.next_seq(), 2);
    reopened.append(bare(START as u64 + day)).expect("appended");
    assert_eq!(trail::verify(&dir).expect("verifies"), 3);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn without_a_pseudonym_root_a_principal_is_masked_in_the_trail() {
    let root = scratch("masked");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let engine = open_engine(&volume, time);
    engine
        .append(
            &AuditEvent::new("zone.created", Subject::Principal("alice@example.com")),
            None,
        )
        .expect("appended");
    let dir = engine.trail_dir(Class::Security, CONTROL).expect("trail");
    let day = dir.child_path(&trail::days(&dir).expect("listed")[0]);
    let bytes = std::fs::read(day).expect("read");
    assert!(
        !bytes.windows(5).any(|window| window == b"alice"),
        "the identifier reached the trail in clear"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_torn_final_record_is_cut_at_open_and_a_damaged_one_is_refused() {
    let root = scratch("torn");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    {
        let engine = open_engine(&volume, Arc::clone(&time));
        for target in ["a", "b"] {
            engine
                .append(
                    &AuditEvent::new("zone.created", Subject::System("catalog")).on(target),
                    None,
                )
                .expect("appended");
        }
    }
    let dir = trail::directory(
        &volume
            .host()
            .subdir(DIRECTORY, false)
            .expect("audit")
            .subdir(TRAILS, false)
            .expect("trails"),
        Class::Security,
        CONTROL,
        false,
    )
    .expect("trail");
    let day = trail::days(&dir).expect("listed").remove(0);
    let path = dir.child_path(&day);
    let whole = std::fs::read(&path).expect("read");
    std::fs::write(&path, &whole[..whole.len() - 5]).expect("torn");
    let engine = open_engine(&volume, Arc::clone(&time));
    engine
        .append(
            &AuditEvent::new("zone.created", Subject::System("catalog")).on("c"),
            None,
        )
        .expect("the torn record is cut and the trail continues");
    assert_eq!(
        trail::verify(&dir).expect("verifies"),
        2,
        "a, then c in b's place"
    );
    drop(engine);
    // A complete item that is not a record: corruption, and the trail refuses.
    let mut damaged = std::fs::read(&path).expect("read");
    damaged.extend_from_slice(&[0xa1, 0x63, b'x', b'y', b'z', 0x01]);
    std::fs::write(&path, &damaged).expect("damaged");
    let engine = open_engine(&volume, time);
    let refused = engine
        .append(
            &AuditEvent::new("zone.created", Subject::System("catalog")).on("d"),
            None,
        )
        .expect_err("a damaged trail refuses");
    assert!(refused.to_string().contains("does not read"), "{refused}");
    drop(engine);
    // An item whose damaged length runs past the end, with more bytes after it than any record
    // takes: corruption, not a torn write, and nothing is cut.
    let mut damaged = vec![0x5a, 0x7f, 0xff, 0xff, 0xff];
    damaged.resize(record::MAX_RECORD_BYTES + 16, 0);
    std::fs::write(&path, &damaged).expect("damaged");
    let refused = Trail::open(&trails_of(&volume), Class::Security, CONTROL, None)
        .expect_err("a damaged length refuses");
    assert!(refused.to_string().contains("not a record"), "{refused}");
    assert_eq!(
        std::fs::read(&path).expect("read"),
        damaged,
        "nothing was cut"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_text_shaped_like_a_secret_is_refused_and_an_ordinary_one_is_not() {
    for secret in [
        "Bearer abcdefgh",
        "basic dXNlcjpwYXNz",
        "Negotiate YIIBhwYGKwYBBQUCoII",
        "-----BEGIN PRIVATE KEY-----",
        "v4.public.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
        "v2.local.QAxIpVe-ECVNI1z4xQbm_qQYomyT3h8FtV8bxkz8pBJWkT8f7HtlOpbroPDEZUKop_vaglyp76CzYy375cHmKCW8e1CCkV0Lflu4GTDyXMqQdpZMM1E6OaoQW27gaRSvWBrR3IgbFIa0AkuUFw.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz",
        "ghp_0123456789abcdefghij",
        "AKIAIOSFODNN7EXAMPLE",
        "sk-0123456789abcdefghij",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl",
        "eyJhbGciOiJIUzI1NiJ9..c2lnbmF0dXJl",
        "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.",
        "eyJhbGciOiJSU0EtT0FFUCJ9.a2V5.aXY.Y2lwaGVy.dGFn",
        "aBcDeFgH12.iJkLmNoP34.qRsTuVwX56",
    ] {
        assert!(looks_secret(secret), "{secret}");
    }
    for ordinary in [
        "controlplane.permguard.internal",
        "abcdefgh.ijklmnop.qrstuvwx",
        "zone/z1",
        "quota",
        "grant/0198f4cc",
        "bearer",
        "v4.json",
        "sk-1",
    ] {
        assert!(!looks_secret(ordinary), "{ordinary}");
    }
}

/// The Host-local `audit.pseudonym` root of these tests, at `v1`, owned by the stamp's Host.
fn local_pseudonyms() -> crate::secrets::HostLocal {
    crate::secrets::HostLocal::new(
        crate::secrets::Root::from_material(&[9u8; 32], "v1".parse().expect("v1")).expect("a root"),
        stamp().host_id,
    )
}

#[test]
fn a_principal_is_pseudonymised_per_resource() {
    let pseudonyms = pseudonym::ResourcePseudonyms::new(local_pseudonyms());
    let control = pseudonyms
        .pseudonym(CONTROL, "principal", "alice")
        .expect("derived");
    let data = pseudonyms.pseudonym(DATA, "principal", "alice");
    assert_ne!(
        Some(control.clone()),
        data,
        "tenant-scoped: no correlation across resources"
    );
    assert_eq!(
        Some(control.clone()),
        pseudonyms.pseudonym(CONTROL, "principal", " alice ")
    );
    assert!(
        control.starts_with("v1:") && control.len() == 3 + 32,
        "{control}"
    );
    // Golden vector, computed apart from this code (`contracts/vectors/secrets.py`'s functions):
    // `derive_host_local(root, owner, "audit.pseudonym", owner, "plane/control", 1)`, then
    // HMAC-SHA256(key, domain ‖ det-CBOR(["principal", "alice"]))[0..16] (WP-3.3).
    assert_eq!(control, "v1:ab18ff52a8b800fe04ceeeaced2af862");

    let root = scratch("pseudonym");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let engine = Engine::open(
        &volume,
        stamp(),
        time,
        Some(pseudonym::ResourcePseudonyms::new(local_pseudonyms())),
    )
    .expect("opens");
    engine
        .append(
            &AuditEvent::new("zone.created", Subject::Principal("alice")),
            None,
        )
        .expect("appended");
    let dir = engine.trail_dir(Class::Security, CONTROL).expect("trail");
    let record = trail::read_day(&dir, &trail::days(&dir).expect("listed")[0])
        .expect("read")
        .remove(0);
    assert_eq!(record.principal, control);
    assert!(!format!("{record:?}").contains("alice"));
    let _ = std::fs::remove_dir_all(root);
}

// Checkpoints, anchors, reads and verification (WP-3.7).

const DAY: i64 = 86_400;

/// The volume's `host.operations` ring on `time`, with its first key.
fn operations_ring(volume: &Volume, time: Arc<TimeGuard>) -> Arc<crate::keys::ring::Ring> {
    use crate::keys::ring::{HOST_OPERATIONS, Policy, Ring};
    use permguard_core::KeyManager as _;
    let ring = Arc::new(
        Ring::open(
            volume,
            HOST_OPERATIONS,
            permguard_objects::crypto::suite::Suite::Ed25519Sha256V1,
            Policy {
                publish_ahead: Duration::from_secs(600),
                rotate_every: Duration::from_secs(3650 * 86_400),
                retain: Duration::from_secs(3650 * 86_400),
            },
            time,
        )
        .expect("the ring opens"),
    );
    ring.maintain().expect("the first key");
    ring
}

/// The keys `keys export` prints for the volume's `host.operations` ring.
fn keys_of(volume: &Volume) -> checkpoint::Keys {
    let dir = crate::keys::ring::directory(volume, crate::keys::ring::HOST_OPERATIONS)
        .expect("the ring directory");
    let document = crate::keys::ring::export(dir.path()).expect("exported");
    checkpoint::Keys::from_document(&document).expect("the keys read")
}

/// An engine sealing under the volume's `host.operations` ring.
fn sealing(volume: &Volume, time: Arc<TimeGuard>) -> (Engine, Arc<crate::keys::ring::Ring>) {
    let engine = open_engine(volume, Arc::clone(&time));
    let ring = operations_ring(volume, time);
    engine.seal_with(ring.clone());
    (engine, ring)
}

fn zone(engine: &Engine, target: &str) {
    engine
        .append(
            &AuditEvent::new("zone.created", Subject::System("catalog")).on(target),
            None,
        )
        .expect("a security record");
}

fn start(engine: &Engine) {
    engine
        .append(
            &AuditEvent::new("server.start", Subject::System("host")),
            None,
        )
        .expect("an operations record");
}

fn period(offset: i64) -> String {
    trail::period_of(&trail::day_name((START + offset) as u64))
}

fn checkpoint_names(dir: &Dir) -> Vec<String> {
    checkpoint::ordered(
        dir.subdir(trail::CHECKPOINTS, false)
            .expect("checkpoints")
            .names()
            .expect("listed"),
    )
}

fn envelope(dir: &Dir, name: &str) -> Vec<u8> {
    dir.subdir(trail::CHECKPOINTS, false)
        .expect("checkpoints")
        .read(name)
        .expect("read")
        .expect("present")
}

fn report(dir: &Dir, class: Class, resource: &str, keys: &checkpoint::Keys) -> verify::TrailReport {
    verify::verify_trail(dir, class, &trail::resource_digest(resource), keys)
}

#[test]
fn a_new_day_seals_the_previous_one() {
    let root = scratch("seal-day");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (wall, time) = guard();
    let (engine, ring) = sealing(&volume, time);
    zone(&engine, "a");
    zone(&engine, "b");
    let dir = engine.trail_dir(Class::Security, CONTROL).expect("trail");
    assert!(checkpoint_names(&dir).is_empty(), "the day has not ended");
    wall.jump(DAY);
    zone(&engine, "c");
    let names = checkpoint_names(&dir);
    assert_eq!(names, vec![format!("{}.cose", period(0))]);
    let keys = keys_of(&volume);
    let sealed = keys
        .verify(&envelope(&dir, &names[0]))
        .expect("verifies")
        .checkpoint;
    let first_day = trail::read_day(&dir, &trail::day_name(START as u64)).expect("read");
    assert_eq!(sealed.trail, "security:plane/control");
    assert_eq!(sealed.period, period(0));
    assert_eq!((sealed.first_seq, sealed.last_seq), (0, 1));
    assert_eq!(sealed.head_digest, first_day[1].digest().expect("digest"));
    assert_eq!(sealed.previous_checkpoint, checkpoint::no_checkpoint());
    assert_eq!(sealed.host_id, stamp().host_id);
    assert_eq!(sealed.key_set_epoch, ring.epoch());
    assert_eq!(sealed.created_at, (START + DAY) as u64);
    let found = report(&dir, Class::Security, CONTROL, &keys);
    assert!(found.problems.is_empty(), "{:?}", found.problems);
    assert_eq!(found.sealed_through, Some(period(0)));
    assert_eq!(found.unsealed, vec![period(DAY)]);
    assert_eq!((found.records, found.checkpoints), (3, 1));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn the_sweep_seals_a_day_that_ended_without_records() {
    let root = scratch("sweep");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (wall, time) = guard();
    let first = open_engine(&volume, Arc::clone(&time));
    zone(&first, "a");
    start(&first);
    drop(first);
    // The day ends with the process stopped; the next one sweeps at its start.
    wall.jump(DAY);
    let (engine, _ring) = sealing(&volume, time);
    let mut written = engine.sweep().expect("swept");
    written.sort();
    assert_eq!(written, vec![format!("{}.cose", period(0)); 2]);
    assert!(
        engine.sweep().expect("swept again").is_empty(),
        "sealed once"
    );
    let keys = keys_of(&volume);
    for (class, resource) in [(Class::Security, CONTROL), (Class::Operations, HOST)] {
        let dir = engine.trail_dir(class, resource).expect("trail");
        assert_eq!(checkpoint_names(&dir), vec![format!("{}.cose", period(0))]);
        let found = report(&dir, class, resource, &keys);
        assert!(found.problems.is_empty(), "{:?}", found.problems);
        assert!(found.unsealed.is_empty());
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn an_on_demand_checkpoint_is_extended_by_the_days_seal() {
    let root = scratch("on-demand");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (wall, time) = guard();
    let (engine, _ring) = sealing(&volume, time);
    zone(&engine, "a");
    zone(&engine, "b");
    let on_demand = engine
        .checkpoint(Class::Security, CONTROL)
        .expect("checkpointed")
        .expect("a checkpoint");
    assert_eq!(on_demand, format!("{}.1.cose", period(0)));
    assert_eq!(
        engine
            .checkpoint(Class::Security, CONTROL)
            .expect("checkpointed")
            .as_deref(),
        Some(on_demand.as_str()),
        "nothing new: the same checkpoint"
    );
    zone(&engine, "c");
    wall.jump(DAY);
    zone(&engine, "d");
    let dir = engine.trail_dir(Class::Security, CONTROL).expect("trail");
    let names = checkpoint_names(&dir);
    assert_eq!(
        names,
        vec![on_demand.clone(), format!("{}.cose", period(0))]
    );
    let keys = keys_of(&volume);
    let held = envelope(&dir, &on_demand);
    let seal = keys
        .verify(&envelope(&dir, &names[1]))
        .expect("verifies")
        .checkpoint;
    assert_eq!((seal.first_seq, seal.last_seq), (0, 2));
    assert_eq!(seal.previous_checkpoint, checkpoint::envelope_digest(&held));
    let found = report(&dir, Class::Security, CONTROL, &keys);
    assert!(found.problems.is_empty(), "{:?}", found.problems);
    assert_eq!(verify::verify_from(&dir, &held), Ok(3));
    assert!(
        engine.checkpoint(Class::Access, DATA).is_err(),
        "a trail that does not exist"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_rewritten_prefix_is_detected_from_an_older_checkpoint_alone() {
    let root = scratch("rewritten");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (wall, time) = guard();
    let ring = operations_ring(&volume, Arc::clone(&time));
    let history = |wall: &crate::time::ManualClock, time: Arc<TimeGuard>, targets: [&str; 3]| {
        let engine = open_engine(&volume, time);
        engine.seal_with(ring.clone());
        zone(&engine, targets[0]);
        zone(&engine, targets[1]);
        wall.jump(DAY);
        zone(&engine, targets[2]);
        wall.jump(DAY);
        zone(&engine, "d");
        engine
    };
    let engine = history(&wall, time, ["a", "b", "c"]);
    let dir = engine.trail_dir(Class::Security, CONTROL).expect("trail");
    // A verifier keeps the first day's seal outside the volume.
    let held = envelope(&dir, &format!("{}.cose", period(0)));
    assert_eq!(verify::verify_from(&dir, &held), Ok(3));
    drop(engine);

    // Someone holding the volume and its key rewrites the first day and everything after it:
    // a consistent chain, sealed again under the same key.
    std::fs::remove_dir_all(dir.path()).expect("the trail removed");
    let (rewall, retime) = guard();
    let rewritten = history(&rewall, retime, ["a", "x", "c"]);
    let dir = rewritten
        .trail_dir(Class::Security, CONTROL)
        .expect("trail");
    let keys = keys_of(&volume);
    let found = report(&dir, Class::Security, CONTROL, &keys);
    assert!(
        found.problems.is_empty(),
        "the volume alone cannot tell: {:?}",
        found.problems
    );
    let refused = verify::verify_from(&dir, &held).expect_err("the older checkpoint tells");
    assert!(refused.contains("rewritten"), "{refused}");
    let _ = std::fs::remove_dir_all(root);
}

/// A witness that co-signs while it answers.
struct Witness {
    answering: std::sync::atomic::AtomicBool,
    asked: std::sync::atomic::AtomicUsize,
}

impl Witness {
    fn new(answering: bool) -> Arc<Self> {
        Arc::new(Self {
            answering: std::sync::atomic::AtomicBool::new(answering),
            asked: std::sync::atomic::AtomicUsize::new(0),
        })
    }
}

impl checkpoint::CheckpointWitness for Witness {
    fn cosign(&self, envelope: &[u8]) -> Result<Vec<u8>, String> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        if self.answering.load(Ordering::SeqCst) {
            Ok(format!("witnessed {}", checkpoint::envelope_digest(envelope)).into_bytes())
        } else {
            Err("the witness did not answer in time".to_owned())
        }
    }
}

#[test]
fn a_witness_cosigns_each_checkpoint() {
    let root = scratch("witness");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (wall, time) = guard();
    let (engine, _ring) = sealing(&volume, time);
    let witness = Witness::new(true);
    engine.witness_with(witness.clone());
    zone(&engine, "a");
    wall.jump(DAY);
    zone(&engine, "b");
    let dir = engine.trail_dir(Class::Security, CONTROL).expect("trail");
    let seal = format!("{}.cose", period(0));
    assert_eq!(
        witness.asked.load(Ordering::SeqCst),
        0,
        "never asked under the trail's lock"
    );
    engine.sweep().expect("swept");
    let held = dir.subdir(trail::CHECKPOINTS, false).expect("checkpoints");
    assert_eq!(
        held.read(&checkpoint::witness_name(&seal)).expect("read"),
        Some(
            format!(
                "witnessed {}",
                checkpoint::envelope_digest(&envelope(&dir, &seal))
            )
            .into_bytes()
        )
    );
    let on_demand = engine
        .checkpoint(Class::Security, CONTROL)
        .expect("checkpointed")
        .expect("a checkpoint");
    assert!(
        held.exists(&checkpoint::witness_name(&on_demand))
            .expect("looked"),
        "asked on demand at once"
    );
    let found = report(&dir, Class::Security, CONTROL, &keys_of(&volume));
    assert!(found.problems.is_empty(), "{:?}", found.problems);
    assert_eq!((found.checkpoints, found.witnessed), (2, 2));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn an_unanswered_witness_degrades_and_never_skips_the_checkpoint() {
    let root = scratch("witness-silent");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (wall, time) = guard();
    let (engine, _ring) = sealing(&volume, time);
    let health = Health::new();
    engine.observe(health.clone());
    let witness = Witness::new(false);
    engine.witness_with(witness.clone());
    zone(&engine, "a");
    wall.jump(DAY);
    zone(&engine, "b");
    engine.sweep().expect("swept");
    let dir = engine.trail_dir(Class::Security, CONTROL).expect("trail");
    let seal = format!("{}.cose", period(0));
    assert_eq!(checkpoint_names(&dir), vec![seal.clone()], "sealed anyway");
    let held = dir.subdir(trail::CHECKPOINTS, false).expect("checkpoints");
    assert!(
        !held
            .exists(&checkpoint::witness_name(&seal))
            .expect("looked")
    );
    let degraded = |health: &Health| {
        health
            .lifecycle()
            .report(permguard_core::lifecycle::HOST)
            .degraded
            .iter()
            .any(|d| d.capability == WITNESS_CAPABILITY)
    };
    assert!(degraded(&health));
    witness.answering.store(true, Ordering::SeqCst);
    engine.sweep().expect("swept");
    assert!(
        held.exists(&checkpoint::witness_name(&seal))
            .expect("looked")
    );
    assert!(!degraded(&health), "restored once it answers");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn retention_deletes_only_sealed_days() {
    // Without a signer nothing is sealed, so nothing is deleted.
    let root = scratch("retention-unsealed");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (wall, time) = guard();
    let engine = open_engine(&volume, time);
    engine.retain_for(Duration::from_secs(2 * 86_400));
    for jump in [0, DAY, 4 * DAY] {
        wall.jump(jump);
        start(&engine);
    }
    let operations = engine.trail_dir(Class::Operations, HOST).expect("trail");
    assert_eq!(trail::days(&operations).expect("listed").len(), 3);
    assert_eq!(trail::anchor(&operations).expect("read"), None);
    drop(engine);
    let _ = std::fs::remove_dir_all(root);

    // Sealed, the days past the retention go, a `security` trail keeping every day.
    let root = scratch("retention-sealed");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (wall, time) = guard();
    let (engine, _ring) = sealing(&volume, time);
    engine.retain_for(Duration::from_secs(2 * 86_400));
    for jump in [0, DAY, 4 * DAY] {
        wall.jump(jump);
        start(&engine);
        start(&engine);
        zone(&engine, "z");
    }
    let operations = engine.trail_dir(Class::Operations, HOST).expect("trail");
    let security = engine.trail_dir(Class::Security, CONTROL).expect("trail");
    assert_eq!(
        trail::days(&operations).expect("listed"),
        vec![trail::day_name((START + 5 * DAY) as u64)]
    );
    assert_eq!(trail::days(&security).expect("listed").len(), 3);
    assert_eq!(
        checkpoint_names(&operations).len(),
        2,
        "checkpoints are never deleted"
    );
    let keys = keys_of(&volume);
    let found = report(&operations, Class::Operations, HOST, &keys);
    assert!(found.problems.is_empty(), "{:?}", found.problems);
    assert_eq!(found.first_seq, Some(4));
    assert_eq!(found.anchor.map(|anchor| anchor.low_watermark), Some(4));
    let found = report(&security, Class::Security, CONTROL, &keys);
    assert!(found.problems.is_empty(), "{:?}", found.problems);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_security_trail_is_kept_unless_its_retention_is_set() {
    let root = scratch("retention-security");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (wall, time) = guard();
    let (engine, _ring) = sealing(&volume, time);
    engine.retain_security_for(Duration::from_secs(2 * 86_400));
    for jump in [0, DAY, 4 * DAY] {
        wall.jump(jump);
        zone(&engine, "z");
    }
    let security = engine.trail_dir(Class::Security, CONTROL).expect("trail");
    assert_eq!(trail::days(&security).expect("listed").len(), 1);
    let anchor = trail::anchor(&security).expect("read").expect("an anchor");
    assert_eq!((anchor.low_watermark, anchor.through), (2, period(DAY)));
    let found = report(&security, Class::Security, CONTROL, &keys_of(&volume));
    assert!(found.problems.is_empty(), "{:?}", found.problems);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn an_anchor_is_written_before_a_prefix_goes_and_verifies() {
    let root = scratch("anchor");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let ring = operations_ring(&volume, time);
    let trails = trails_of(&volume);
    let mut opened = Trail::open(
        &trails,
        Class::Operations,
        HOST,
        Some(Duration::from_secs(2 * 86_400)),
    )
    .expect("opens");
    for offset in [0, 0, DAY, DAY, 5 * DAY] {
        opened
            .append(bare((START + offset) as u64))
            .expect("appended");
    }
    let today = trail::day_name((START + 5 * DAY) as u64);
    opened
        .seal_before(&today, ring.as_ref(), [1; 16], (START + 5 * DAY) as u64)
        .expect("sealed");
    let dir = trail::directory(&trails, Class::Operations, HOST, false).expect("trail");
    // The anchor cannot be written: nothing goes.
    {
        let _failing =
            permguard_core::fault::inject(dir.path(), permguard_core::fault::Fault::WriteFails);
        assert!(opened.prune(&today, None).is_err());
    }
    assert_eq!(trail::days(&dir).expect("listed").len(), 3);
    assert_eq!(trail::anchor(&dir).expect("read"), None);
    // The anchor alone cannot be replaced, the day files still could be deleted: nothing goes
    // before the anchor stands.
    let blocked = dir.child_path(checkpoint::ANCHOR);
    std::fs::create_dir(&blocked).expect("a directory where the anchor goes");
    assert!(opened.prune(&today, None).is_err());
    assert_eq!(trail::days(&dir).expect("listed").len(), 3);
    std::fs::remove_dir(&blocked).expect("removed");
    let anchor = opened
        .prune(&today, None)
        .expect("pruned")
        .expect("an anchor");
    assert_eq!(trail::anchor(&dir).expect("read"), Some(anchor.clone()));
    assert_eq!(trail::days(&dir).expect("listed"), vec![today]);
    let seal = envelope(&dir, &format!("{}.cose", period(DAY)));
    assert_eq!(anchor.checkpoint, checkpoint::envelope_digest(&seal));
    assert_eq!((anchor.low_watermark, anchor.through), (4, period(DAY)));
    let keys = keys_of(&volume);
    let found = report(&dir, Class::Operations, HOST, &keys);
    assert!(found.problems.is_empty(), "{:?}", found.problems);
    // The seal it names is gone: the anchor no longer verifies.
    std::fs::remove_file(
        dir.subdir(trail::CHECKPOINTS, false)
            .expect("checkpoints")
            .child_path(&format!("{}.cose", period(DAY))),
    )
    .expect("removed");
    let found = report(&dir, Class::Operations, HOST, &keys);
    assert!(
        found
            .problems
            .iter()
            .any(|problem| problem.contains("anchor names a checkpoint")),
        "{:?}",
        found.problems
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_sealed_day_takes_no_record_when_the_clock_steps_back() {
    let root = scratch("sealed-closed");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let ring = operations_ring(&volume, time);
    let trails = trails_of(&volume);
    let mut opened = Trail::open(&trails, Class::Operations, HOST, None).expect("opens");
    opened.append(bare(START as u64)).expect("appended");
    let tomorrow = trail::day_name((START + DAY) as u64);
    opened
        .seal_before(&tomorrow, ring.as_ref(), [1; 16], (START + DAY) as u64)
        .expect("sealed");
    opened.append(bare(START as u64 + 10)).expect("appended");
    let dir = trail::directory(&trails, Class::Operations, HOST, false).expect("trail");
    assert_eq!(
        trail::days(&dir).expect("listed"),
        vec![trail::day_name(START as u64), tomorrow],
        "the record goes to the day after the seal"
    );
    // Reopened, the trail still knows the day is closed.
    drop(opened);
    let mut reopened = Trail::open(&trails, Class::Operations, HOST, None).expect("opens");
    reopened.append(bare(START as u64 + 20)).expect("appended");
    assert_eq!(trail::days(&dir).expect("listed").len(), 2);
    let found = report(&dir, Class::Operations, HOST, &keys_of(&volume));
    assert!(found.problems.is_empty(), "{:?}", found.problems);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_sealed_day_that_goes_or_a_cut_tail_fails_verification_and_no_sequence_is_reused() {
    let root = scratch("sealed-gone");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (wall, time) = guard();
    let (engine, _ring) = sealing(&volume, Arc::clone(&time));
    zone(&engine, "a");
    zone(&engine, "b");
    wall.jump(DAY);
    zone(&engine, "c");
    let on_demand = engine
        .checkpoint(Class::Security, CONTROL)
        .expect("checkpointed")
        .expect("a checkpoint");
    drop(engine);
    let dir =
        trail::directory(&trails_of(&volume), Class::Security, CONTROL, false).expect("trail");
    let keys = keys_of(&volume);
    // The last day, which an on-demand checkpoint covers, is deleted.
    std::fs::remove_file(dir.child_path(&trail::day_name((START + DAY) as u64))).expect("removed");
    let found = report(&dir, Class::Security, CONTROL, &keys);
    assert!(
        found
            .problems
            .iter()
            .any(|problem| problem.contains(&on_demand) && problem.contains("gone")),
        "{:?}",
        found.problems
    );
    // Reopened, the trail continues after what its checkpoints sealed.
    let reopened = open_engine(&volume, Arc::clone(&time));
    zone(&reopened, "d");
    let last = trail::read_day(&dir, &trail::day_name((START + DAY) as u64)).expect("read");
    assert_eq!(last[0].seq, 3, "sequence 2 was sealed and is never reused");
    drop(reopened);
    // The first day, which its seal covers, is deleted.
    std::fs::remove_file(dir.child_path(&trail::day_name(START as u64))).expect("removed");
    let found = report(&dir, Class::Security, CONTROL, &keys);
    assert!(
        found
            .problems
            .iter()
            .any(|problem| problem.contains("no anchor")),
        "{:?}",
        found.problems
    );
    let _ = std::fs::remove_dir_all(root);
}

/// An `operations` trail on a volume whose first two days retention deleted: records 0 to 3
/// gone, 4 and 5 kept on the sixth day.
fn pruned(tag: &str) -> (std::path::PathBuf, Engine, Arc<crate::time::ManualClock>) {
    let root = scratch(tag);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (wall, time) = guard();
    let engine = open_engine(&volume, Arc::clone(&time));
    engine.seal_with(operations_ring(&volume, time));
    engine.retain_for(Duration::from_secs(2 * 86_400));
    for jump in [0, DAY, 4 * DAY] {
        wall.jump(jump);
        start(&engine);
        start(&engine);
    }
    (root, engine, wall)
}

#[test]
fn a_read_states_the_retention_gap() {
    let (root, engine, _) = pruned("read-gap");
    let page = engine
        .read(Class::Operations, HOST, &query::Query::default())
        .expect("read");
    assert_eq!(
        page.records.iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![4, 5]
    );
    assert_eq!(
        page.gaps,
        vec![query::Gap::Retention {
            below: 4,
            through: period(DAY)
        }]
    );
    assert_eq!((page.frontier, page.next), (6, None));
    // A read from the sixth day onwards does not reach the gap.
    let later = engine
        .read(
            Class::Operations,
            HOST,
            &query::Query {
                from: Some((START + 5 * DAY) as u64),
                ..query::Query::default()
            },
        )
        .expect("read");
    assert!(later.gaps.is_empty(), "{:?}", later.gaps);
    assert_eq!(later.records.len(), 2);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn an_export_states_the_retention_gap() {
    let (root, engine, _) = pruned("export-gap");
    let page = engine
        .export(Class::Operations, HOST, &query::Query::default())
        .expect("exported");
    assert_eq!(page.records.len(), 2);
    assert!(
        page.gaps.contains(&query::Gap::Retention {
            below: 4,
            through: period(DAY)
        }),
        "{:?}",
        page.gaps
    );
    assert_eq!(page.anchor.map(|anchor| anchor.low_watermark), Some(4));
    let held = engine
        .checkpoints(Class::Operations, HOST, None)
        .expect("listed");
    assert_eq!(
        held.files
            .iter()
            .map(|c| c.name.clone())
            .collect::<Vec<_>>(),
        vec![
            format!("{}.cose", period(0)),
            format!("{}.cose", period(DAY))
        ]
    );
    let one_day = engine
        .checkpoints(Class::Operations, HOST, Some(&period(DAY)))
        .expect("listed");
    assert_eq!((one_day.files.len(), one_day.omitted), (1, 0));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn an_export_keeps_its_frontier_while_records_arrive() {
    let root = scratch("frontier");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let engine = open_engine(&volume, time);
    for _ in 0..3 {
        start(&engine);
    }
    let one = |cursor: Option<String>| query::Query {
        limit: Some(1),
        cursor,
        ..query::Query::default()
    };
    let first = engine
        .export(Class::Operations, HOST, &one(None))
        .expect("exported");
    assert_eq!((first.records[0].seq, first.frontier), (0, 3));
    for _ in 0..2 {
        start(&engine);
    }
    let second = engine
        .export(Class::Operations, HOST, &one(first.next.clone()))
        .expect("exported");
    let third = engine
        .export(Class::Operations, HOST, &one(second.next.clone()))
        .expect("exported");
    assert_eq!(
        (second.records[0].seq, third.records[0].seq, third.frontier),
        (1, 2, 3)
    );
    assert_eq!(third.next, None, "the frontier holds");
    // A cursor altered, or issued for another query, is refused.
    let cursor = first.next.expect("a cursor");
    let mut altered = cursor.clone().into_bytes();
    altered[2] ^= 1;
    let altered = String::from_utf8(altered).expect("text");
    for refused in [
        engine.export(Class::Operations, HOST, &one(Some(altered))),
        engine.read(Class::Operations, HOST, &one(Some(cursor.clone()))),
        engine.export(Class::Security, HOST, &one(Some(cursor))),
    ] {
        assert!(
            matches!(refused, Err(query::QueryError::Cursor(_))),
            "{refused:?}"
        );
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_read_states_records_missing_from_the_day_files() {
    let root = scratch("missing");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (wall, time) = guard();
    let engine = open_engine(&volume, time);
    for jump in [0, DAY, DAY] {
        wall.jump(jump);
        start(&engine);
    }
    let dir = engine.trail_dir(Class::Operations, HOST).expect("trail");
    std::fs::remove_file(dir.child_path(&trail::day_name((START + DAY) as u64))).expect("removed");
    let page = engine
        .read(Class::Operations, HOST, &query::Query::default())
        .expect("read");
    assert_eq!(page.gaps, vec![query::Gap::Missing { from: 1, to: 1 }]);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_read_skips_a_record_still_being_appended() {
    let root = scratch("read-race");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let engine = open_engine(&volume, time);
    start(&engine);
    start(&engine);
    let dir = engine.trail_dir(Class::Operations, HOST).expect("trail");
    // What a concurrent append has written so far: the first bytes of the next record.
    let day = trail::day_name(START as u64);
    let mut bytes = std::fs::read(dir.child_path(&day)).expect("read");
    bytes.extend_from_slice(&bare(START as u64).encode().expect("encoded")[..10]);
    std::fs::write(dir.child_path(&day), bytes).expect("written");
    let page = engine
        .read(Class::Operations, HOST, &query::Query::default())
        .expect("a live trail reads");
    assert_eq!(page.records.len(), 2);
    assert!(page.gaps.is_empty(), "{:?}", page.gaps);
    let _ = std::fs::remove_dir_all(root);
}

/// A signer that refuses the trail `refused` names while `refusing` holds.
struct Refusing {
    ring: Arc<crate::keys::ring::Ring>,
    refused: &'static str,
    refusing: std::sync::atomic::AtomicBool,
}

impl checkpoint::CheckpointSigner for Refusing {
    fn seal(&self, checkpoint: &mut checkpoint::Checkpoint) -> Result<Vec<u8>, String> {
        if self.refusing.load(Ordering::SeqCst) && checkpoint.trail == self.refused {
            return Err("the custody did not answer".to_owned());
        }
        self.ring.seal(checkpoint)
    }
}

#[test]
fn a_trail_that_seals_does_not_clear_another_ones_failure() {
    let root = scratch("seal-degraded");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (wall, time) = guard();
    let engine = open_engine(&volume, Arc::clone(&time));
    let signer = Arc::new(Refusing {
        ring: operations_ring(&volume, time),
        refused: "security:plane/control",
        refusing: std::sync::atomic::AtomicBool::new(true),
    });
    engine.seal_with(signer.clone());
    let health = Health::new();
    engine.observe(health.clone());
    let degraded = |health: &Health| {
        health
            .lifecycle()
            .report(permguard_core::lifecycle::HOST)
            .degraded
            .iter()
            .any(|d| d.capability == CHECKPOINT_CAPABILITY)
    };
    zone(&engine, "a");
    start(&engine);
    wall.jump(DAY);
    zone(&engine, "b");
    assert!(degraded(&health), "the security trail did not seal");
    start(&engine);
    assert!(
        degraded(&health),
        "the operations trail sealed, and the security one still has not"
    );
    signer.refusing.store(false, Ordering::SeqCst);
    engine.sweep().expect("swept");
    assert!(!degraded(&health), "restored once every trail sealed");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_checkpoint_by_a_revoked_key_stands_only_where_a_later_one_covers_it() {
    let root = scratch("revoked");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let other_root = scratch("revoked-other");
    let other = Volume::claim(&other_root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let first = operations_ring(&volume, Arc::clone(&time));
    let second = operations_ring(&other, time);
    let document = |volume: &Volume| -> serde_json::Value {
        let dir = crate::keys::ring::directory(volume, crate::keys::ring::HOST_OPERATIONS)
            .expect("the ring directory");
        serde_json::from_str(&crate::keys::ring::export(dir.path()).expect("exported"))
            .expect("json")
    };
    let (one, two) = (document(&volume), document(&other));
    let revoked_kid = one["keys"][0]["kid"].as_str().expect("kid").to_owned();
    let mut keys: Vec<serde_json::Value> = one["keys"].as_array().expect("keys").clone();
    keys.extend(two["keys"].as_array().expect("keys").iter().cloned());
    let keys = checkpoint::Keys::from_document(
        &serde_json::json!({ "keys": keys, "revoked": [{ "kid": revoked_kid }] }).to_string(),
    )
    .expect("the keys read");

    let trails = trails_of(&volume);
    let mut opened = Trail::open(&trails, Class::Operations, HOST, None).expect("opens");
    let day = |offset: i64| trail::day_name((START + offset) as u64);
    opened.append(bare(START as u64)).expect("appended");
    opened.append(bare((START + DAY) as u64)).expect("appended");
    opened
        .seal_before(&day(DAY), first.as_ref(), [1; 16], (START + DAY) as u64)
        .expect("sealed by the key revoked later");
    let dir = trail::directory(&trails, Class::Operations, HOST, false).expect("trail");
    // Nothing by a key that is not revoked covers it yet.
    let found = report(&dir, Class::Operations, HOST, &keys);
    assert!(
        found
            .problems
            .iter()
            .any(|problem| problem.contains("revoked since, and no checkpoint")),
        "{:?}",
        found.problems
    );
    // A later checkpoint by another key chains over it: a warning, no longer a failure.
    opened
        .append(bare((START + 2 * DAY) as u64))
        .expect("appended");
    opened
        .seal_before(
            &day(2 * DAY),
            second.as_ref(),
            [1; 16],
            (START + 2 * DAY) as u64,
        )
        .expect("sealed by a key that is not revoked");
    let found = report(&dir, Class::Operations, HOST, &keys);
    assert!(found.problems.is_empty(), "{:?}", found.problems);
    assert_eq!(found.warnings.len(), 1, "{:?}", found.warnings);
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(other_root);
}

#[test]
fn an_ended_day_whose_seal_is_gone_fails_verification() {
    let root = scratch("seal-gone");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (wall, time) = guard();
    let (engine, _ring) = sealing(&volume, time);
    for jump in [0, DAY, DAY] {
        wall.jump(jump);
        start(&engine);
    }
    let dir = engine.trail_dir(Class::Operations, HOST).expect("trail");
    let keys = keys_of(&volume);
    let found = report(&dir, Class::Operations, HOST, &keys);
    assert!(found.problems.is_empty(), "{:?}", found.problems);
    assert_eq!(found.unsealed, vec![period(2 * DAY)], "only the last day");
    // The newest seal goes: the day it sealed has ended and now reads as unsealed.
    std::fs::remove_file(
        dir.subdir(trail::CHECKPOINTS, false)
            .expect("checkpoints")
            .child_path(&format!("{}.cose", period(DAY))),
    )
    .expect("removed");
    let found = report(&dir, Class::Operations, HOST, &keys);
    assert!(
        found
            .problems
            .iter()
            .any(|problem| problem.contains(&period(DAY)) && problem.contains("not sealed")),
        "{:?}",
        found.problems
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_prefix_rewritten_below_the_held_head_is_detected() {
    let root = scratch("prefix-below");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (wall, time) = guard();
    let (engine, _ring) = sealing(&volume, time);
    zone(&engine, "a");
    zone(&engine, "b");
    wall.jump(DAY);
    zone(&engine, "c");
    let dir = engine.trail_dir(Class::Security, CONTROL).expect("trail");
    let held = envelope(&dir, &format!("{}.cose", period(0)));
    assert_eq!(verify::verify_from(&dir, &held), Ok(2));
    // Record 0 changes and record 1, the head the held checkpoint sealed, stays as it was.
    let path = dir.child_path(&trail::day_name(START as u64));
    let mut bytes = std::fs::read(&path).expect("read");
    let at = bytes.iter().position(|b| *b == b'a').expect("a letter a");
    bytes[at] = b'x';
    std::fs::write(&path, bytes).expect("altered");
    let refused = verify::verify_from(&dir, &held).expect_err("the chain into the head breaks");
    assert!(refused.contains("rewritten"), "{refused}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn every_trail_is_checkpointed_at_once_and_one_that_cannot_be_read_refuses_it() {
    let root = scratch("checkpoint-all");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_wall, time) = guard();
    assert!(
        !open_engine(&volume, Arc::clone(&time)).seals(),
        "no signer: nothing sealed"
    );
    let (engine, _ring) = sealing(&volume, time);
    assert!(engine.seals());
    assert_eq!(
        engine.checkpoint_all().expect("nothing to seal"),
        Vec::<String>::new()
    );
    zone(&engine, "a");
    start(&engine);
    let sealed = engine.checkpoint_all().expect("checkpointed");
    assert_eq!(sealed.len(), 2, "one per trail: {sealed:?}");
    let keys = keys_of(&volume);
    for (class, resource) in [(Class::Security, CONTROL), (Class::Operations, HOST)] {
        let dir = engine.trail_dir(class, resource).expect("trail");
        let names = checkpoint_names(&dir);
        assert_eq!(names.len(), 1, "{names:?}");
        assert!(names[0].starts_with(&period(0)), "today's: {names:?}");
        assert!(sealed.contains(&names[0]), "{sealed:?} {names:?}");
        let found = report(&dir, class, resource, &keys);
        assert!(found.problems.is_empty(), "{:?}", found.problems);
    }

    // A trail whose META.cbor does not read is never skipped: the sweep logs it, this refuses.
    let broken = trails_of(&volume)
        .path()
        .join("security")
        .join("0".repeat(64));
    std::fs::create_dir_all(&broken).expect("a trail directory");
    std::fs::write(broken.join(trail::META), b"not cbor").expect("written");
    assert!(engine.sweep().is_ok(), "the sweep goes on");
    let refused = engine.checkpoint_all().expect_err("an unreadable trail");
    assert!(refused.to_string().contains(&"0".repeat(64)), "{refused}");
    let _ = std::fs::remove_dir_all(root);
}

/// An export floor a test sets: what the coordinator acknowledged of `operations:host`.
#[derive(Default)]
struct Floor(std::sync::Mutex<Option<Option<String>>>);

impl EgressFloor for Floor {
    fn acknowledged(&self, class: Class, resource: &str) -> Option<Option<String>> {
        if (class, resource) != (Class::Operations, HOST) {
            return None;
        }
        self.0.lock().expect("the floor").clone()
    }
}

/// WP-5.9: while a required task exports a trail, retention deletes a day only once the seal
/// that closes it is acknowledged; with nothing acknowledged nothing goes, and a trail no task
/// exports follows its retention alone.
#[test]
fn retention_waits_for_the_acknowledged_seal_of_an_exported_trail() {
    let root = scratch("retention-egress");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (wall, time) = guard();
    let (engine, _ring) = sealing(&volume, time);
    let floor = Arc::new(Floor::default());
    *floor.0.lock().expect("the floor") = Some(None);
    engine.gate_retention_with(Arc::clone(&floor) as Arc<dyn EgressFloor>);
    engine.retain_for(Duration::from_secs(2 * 86_400));
    for jump in [0, DAY, 4 * DAY] {
        wall.jump(jump);
        start(&engine);
    }
    let operations = engine.trail_dir(Class::Operations, HOST).expect("trail");
    assert_eq!(
        trail::days(&operations).expect("listed").len(),
        3,
        "nothing acknowledged: nothing goes, past its retention or not"
    );

    // The first day's seal acknowledged: that day goes, the next waits.
    *floor.0.lock().expect("the floor") = Some(Some(format!("{}.cose", period(0))));
    engine.sweep().expect("swept");
    assert_eq!(
        trail::days(&operations).expect("listed"),
        vec![
            trail::day_name((START + DAY) as u64),
            trail::day_name((START + 5 * DAY) as u64)
        ]
    );

    // Exported by no required task: the retention alone.
    *floor.0.lock().expect("the floor") = None;
    engine.sweep().expect("swept");
    assert_eq!(
        trail::days(&operations).expect("listed"),
        vec![trail::day_name((START + 5 * DAY) as u64)]
    );
    let _ = std::fs::remove_dir_all(root);
}
