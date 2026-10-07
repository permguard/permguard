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
    use crate::api::grants::{AUDIT_ISSUED, AUDIT_REVOKE_PLANNED, AUDIT_REVOKED};
    for action in [AUDIT_ISSUED, AUDIT_REVOKE_PLANNED, AUDIT_REVOKED] {
        let schema = REGISTRY
            .iter()
            .find(|schema| schema.action == action)
            .unwrap_or_else(|| panic!("`{action}` is not registered"));
        assert_eq!(
            (schema.class, schema.root),
            (Class::Security, HOST),
            "{action}"
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
fn retention_drops_old_days_of_operations_and_access_trails_and_never_of_security_ones() {
    let root = scratch("retention");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (wall, time) = guard();
    let engine = open_engine(&volume, time);
    engine.retain_for(Duration::from_secs(2 * 86_400));
    let both = |engine: &Engine| {
        engine
            .append(
                &AuditEvent::new("zone.created", Subject::System("catalog")),
                None,
            )
            .expect("security");
        engine
            .append(
                &AuditEvent::new("server.start", Subject::System("host")),
                None,
            )
            .expect("operations");
    };
    both(&engine);
    wall.jump(86_400);
    both(&engine);
    wall.jump(4 * 86_400);
    both(&engine);
    let operations = engine.trail_dir(Class::Operations, HOST).expect("trail");
    let security = engine.trail_dir(Class::Security, CONTROL).expect("trail");
    assert_eq!(trail::days(&operations).expect("listed").len(), 1);
    assert_eq!(trail::days(&security).expect("listed").len(), 3);
    assert_eq!(
        trail::verify(&operations).expect("verifies from the first day kept"),
        1
    );
    assert_eq!(trail::verify(&security).expect("verifies"), 3);
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

#[test]
fn a_principal_is_pseudonymised_per_resource() {
    let pseudonyms = pseudonym::ResourcePseudonyms::new(&[9u8; 32], "v1");
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
    // Golden vector, computed apart from this code (Python's `hmac` and `hashlib`): HKDF-SHA256
    // with no salt over the root, info = domain ‖ SHA-256(resource) ‖ "principal", then
    // HMAC-SHA256(key, domain ‖ "alice")[0..16].
    assert_eq!(control, "v1:2dbdd0064034d27f36f3e44f4e8466b2");

    let root = scratch("pseudonym");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (_, time) = guard();
    let engine = Engine::open(
        &volume,
        stamp(),
        time,
        Some(pseudonym::ResourcePseudonyms::new(&[9u8; 32], "v1")),
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
