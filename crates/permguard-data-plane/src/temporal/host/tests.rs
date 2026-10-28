// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use permguard_host::composition::StreamAppender;
use serde_json::json;

use super::*;
use crate::temporal::testing::MemoryProducer as Fake;

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-temporal-host-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("created");
    path
}

const HOST: [u8; 16] = [0xab; 16];

fn occurrence(id: u64, source: &str) -> Record {
    let at = permguard_events::index::render_epoch_seconds(1_700_000_000 + id as i64)
        .expect("an instant");
    let event = json!({"event_id": format!("e-{id}"), "kind": "response", "action": "Read"});
    Record {
        v: 1,
        record_type: permguard_events::record::RECORD_TYPE.to_owned(),
        stream: Stream {
            producer: Producer {
                class: PRODUCER_CLASS_DATA_PLANE.to_owned(),
                id: "proposed".to_owned(),
                instance: "proposed".to_owned(),
            },
            zone: "zone-id".to_owned(),
            ledger: "ledger-id".to_owned(),
        },
        seq: 0,
        prev: String::new(),
        event_type: permguard_core::domains::event::DOGWOOD_V1.to_owned(),
        event_id: format!("e-{id}"),
        source: Some(source.to_owned()),
        occurrence_digest: permguard_events::record::occurrence_digest_of(&event)
            .expect("a digest"),
        kind: "response".to_owned(),
        profile: "temporal".to_owned(),
        policy_partitions: vec!["governance".to_owned()],
        commit: "sha256:commit".to_owned(),
        history_key: None,
        occurred_at: at.clone(),
        observed_at: at,
        event,
    }
}

fn open(fake: &Arc<Fake>, directory: &Path, legacy: u64) -> HostLedger {
    HostLedger::open(
        StreamProducer::over(Arc::clone(fake) as Arc<dyn StreamAppender>),
        HOST,
        "zone-id",
        "ledger-id",
        directory.to_path_buf(),
        legacy,
    )
    .expect("opened")
}

fn query() -> Query {
    Query {
        event_type: permguard_core::domains::event::DOGWOOD_V1.to_owned(),
        history: String::new(),
        action: None,
        kind: None,
        from: 0,
        until: i64::MAX,
    }
}

#[test]
fn a_record_names_the_host_and_its_run_and_takes_the_ordinal_after_the_legacy_journal() {
    let fake = Arc::new(Fake::default());
    let directory = scratch("place");
    let mut ledger = open(&fake, &directory, 7);
    let placed = ledger
        .append(
            vec![occurrence(1, "alice"), occurrence(2, "alice")],
            256 * 1024,
        )
        .expect("appended");
    assert_eq!(
        placed
            .iter()
            .map(|(placed, _)| placed.ordinal)
            .collect::<Vec<_>>(),
        [8, 9],
        "after the legacy journal's last sequence"
    );
    let (first, record) = &placed[0];
    assert_eq!(record.stream.producer.id, hex(&HOST));
    assert_eq!(record.stream.producer.instance, first.run);
    assert_eq!((record.seq, record.prev.as_str()), (1, GENESIS));
    assert_eq!(placed[1].1.seq, 2);
    assert_eq!(placed[1].1.prev, first.digest, "chained by the digest");
    assert_eq!(record.source.as_deref(), Some("alice"));
    let read = ledger.read_from(0, 10).expect("read");
    assert_eq!(read.len(), 2);
    assert_eq!(read[0].0, 8);
    assert_eq!(read[0].1["event_id"], "e-1");
    assert_eq!(
        ledger.record_at(9).expect("read").expect("held")["event_id"],
        "e-2"
    );
    assert_eq!(
        ledger.record_at(7).expect("read"),
        None,
        "the legacy journal's"
    );
    // The ordinal base is fixed at the first open: a legacy journal that changed since is not
    // read as moving what was given.
    drop(ledger);
    let reopened = open(&fake, &directory, 3);
    assert_eq!(reopened.legacy_through(), 7);
    assert_eq!(reopened.last(), 9);
}

#[test]
fn ordinals_run_on_across_a_rollover_and_reads_cross_runs() {
    let fake = Arc::new(Fake::default());
    let directory = scratch("rollover");
    let mut ledger = open(&fake, &directory, 0);
    ledger
        .append(vec![occurrence(1, "a"), occurrence(2, "a")], 256 * 1024)
        .expect("appended");
    fake.rollover(ledger.resource());
    let placed = ledger
        .append(vec![occurrence(3, "a")], 256 * 1024)
        .expect("appended");
    assert_eq!(placed[0].0.ordinal, 3);
    assert_eq!(placed[0].1.seq, 1, "a new run starts again at one");
    let read = ledger.read_from(1, 10).expect("read");
    assert_eq!(
        read.iter().map(|(ordinal, _)| *ordinal).collect::<Vec<_>>(),
        [2, 3]
    );
    let scanned = ledger.scan(&query()).expect("scanned");
    assert_eq!(
        scanned
            .iter()
            .map(|(ordinal, _)| *ordinal)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    // Reopened, the runs and their bases are what they were.
    drop(ledger);
    let reopened = open(&fake, &directory, 0);
    assert_eq!(reopened.last(), 3);
    assert_eq!(
        reopened.record_at(3).expect("read").expect("held")["event_id"],
        "e-3"
    );
}

#[test]
fn a_record_the_plane_did_not_index_before_a_crash_is_caught_up_on_open() {
    let fake = Arc::new(Fake::default());
    let directory = scratch("catch-up");
    let mut ledger = open(&fake, &directory, 0);
    ledger
        .append(vec![occurrence(1, "a")], 256 * 1024)
        .expect("appended");
    drop(ledger);
    // Another process wrote two records, and a run, the plane never indexed.
    let mut other = open(&fake, &scratch("catch-up-other"), 0);
    other
        .append(vec![occurrence(2, "a")], 256 * 1024)
        .expect("appended");
    fake.rollover(other.resource());
    other
        .append(vec![occurrence(3, "b")], 256 * 1024)
        .expect("appended");
    drop(other);
    let reopened = open(&fake, &directory, 0);
    assert_eq!(reopened.last(), 3);
    assert_eq!(
        reopened
            .scan(&query())
            .expect("scanned")
            .iter()
            .map(|(ordinal, _)| *ordinal)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    let known = reopened
        .occurrence(Some("b"), "e-3")
        .expect("read")
        .expect("recovered");
    assert_eq!(known.seq, 3);
    assert!(known.response.is_null(), "a recovered entry has no answer");
}

#[test]
fn an_occurrence_is_keyed_by_its_source_and_its_answer_is_kept() {
    let fake = Arc::new(Fake::default());
    let directory = scratch("occurrence");
    let mut ledger = open(&fake, &directory, 0);
    ledger
        .append(vec![occurrence(1, "alice")], 256 * 1024)
        .expect("appended");
    assert!(
        ledger
            .occurrence(Some("alice"), "e-1")
            .expect("read")
            .is_some()
    );
    assert!(
        ledger
            .occurrence(Some("bob"), "e-1")
            .expect("read")
            .is_none(),
        "the same id from another source is another occurrence"
    );
    let mut known = ledger
        .occurrence(Some("alice"), "e-1")
        .expect("read")
        .expect("held");
    known.response = json!({"decision": true});
    ledger.keep_occurrence(&known).expect("kept");
    drop(ledger);
    let reopened = open(&fake, &directory, 0);
    assert_eq!(
        reopened
            .occurrence(Some("alice"), "e-1")
            .expect("read")
            .expect("held")
            .response,
        json!({"decision": true}),
        "the last write for a key wins"
    );
}

#[test]
fn a_temporary_a_crash_left_is_swept_and_the_entries_stand() {
    let fake = Arc::new(Fake::default());
    let directory = scratch("torn");
    let mut ledger = open(&fake, &directory, 0);
    ledger
        .append(vec![occurrence(1, "a")], 256 * 1024)
        .expect("appended");
    drop(ledger);
    let shard = std::fs::read_dir(directory.join(OCCURRENCES_DIR))
        .expect("listed")
        .find_map(|entry| {
            let entry = entry.ok()?;
            entry.file_type().ok()?.is_dir().then(|| entry.path())
        })
        .expect("a shard");
    let torn = shard.join(format!(
        "{}crashed",
        permguard_host::storage::dir::TEMP_PREFIX
    ));
    std::fs::write(&torn, b"{\"event_id\":\"e-2\",\"se").expect("torn");
    let reopened = open(&fake, &directory, 0);
    assert!(!torn.exists(), "swept");
    assert!(
        reopened
            .occurrence(Some("a"), "e-1")
            .expect("read")
            .is_some()
    );
}

#[test]
fn the_floor_is_what_no_window_reads_and_deleted_entries_are_forgotten() {
    let fake = Arc::new(Fake::default());
    let directory = scratch("floor");
    let mut ledger = open(&fake, &directory, 0);
    ledger
        .append((1..=4).map(|id| occurrence(id, "a")).collect(), 256 * 1024)
        .expect("appended");
    // Observed at 1_700_000_001 to _004: a horizon of _003 keeps the last two.
    let safe = ledger.retention_safe(1_700_000_003).expect("measured");
    assert_eq!(safe.len(), 1);
    assert_eq!(safe[0].1, 2);
    fake.delete_below(ledger.resource(), 0, 3);
    assert_eq!(
        ledger.forget_deleted().expect("forgotten"),
        4,
        "two index and two occurrence entries"
    );
    assert!(ledger.occurrence(Some("a"), "e-1").expect("read").is_none());
    assert!(ledger.occurrence(Some("a"), "e-3").expect("read").is_some());
    assert_eq!(
        ledger.retention_safe(1_700_000_003).expect("measured")[0].1,
        2,
        "what went is below the floor"
    );
}

#[test]
fn a_record_over_the_bound_is_refused_and_takes_nothing() {
    let fake = Arc::new(Fake::default());
    let directory = scratch("bound");
    let mut ledger = open(&fake, &directory, 0);
    assert!(ledger.append(vec![occurrence(1, "a")], 64).is_err());
    assert_eq!(ledger.last(), 0);
    assert!(ledger.read_from(0, 10).expect("read").is_empty());
}

#[test]
fn an_entry_naming_another_position_than_its_durable_record_refuses_the_ledger() {
    let fake = Arc::new(Fake::default());
    let directory = scratch("entry-mismatch");
    let mut ledger = open(&fake, &directory, 0);
    ledger
        .append(vec![occurrence(1, "a")], 256 * 1024)
        .expect("appended");
    let mut known = ledger
        .occurrence(Some("a"), "e-1")
        .expect("read")
        .expect("held");
    known.seq = 5;
    ledger.keep_occurrence(&known).expect("kept");
    drop(ledger);
    // The coverage forgotten, so the reopen walks the record again.
    std::fs::remove_file(
        directory
            .join(OCCURRENCES_DIR)
            .join(OCCURRENCES_COVERED_FILE),
    )
    .expect("removed");
    let refused = HostLedger::open(
        StreamProducer::over(Arc::clone(&fake) as Arc<dyn StreamAppender>),
        HOST,
        "zone-id",
        "ledger-id",
        directory.clone(),
        0,
    )
    .err()
    .expect("refused");
    assert!(matches!(refused, JournalError::Corrupt(_)), "{refused}");
}

#[test]
fn a_position_the_producer_deleted_reads_as_absent_not_as_the_next_record() {
    let fake = Arc::new(Fake::default());
    let directory = scratch("deleted-position");
    let mut ledger = open(&fake, &directory, 0);
    ledger
        .append((1..=3).map(|id| occurrence(id, "a")).collect(), 256 * 1024)
        .expect("appended");
    fake.delete_below(ledger.resource(), 0, 3);
    assert_eq!(ledger.record_at(1).expect("read"), None);
    assert_eq!(
        ledger.record_at(3).expect("read").expect("held")["event_id"],
        "e-3"
    );
}
