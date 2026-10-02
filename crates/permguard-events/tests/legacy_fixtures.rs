// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! An event journal as this release writes it, kept so that every later layout can prove it still
//! reads one.
//!
//! `tests/fixtures/legacy/v1/event-journal` is a volume fragment written by the current code:
//! `STATE`, `RESERVE`, one segment with two records, the occurrence index. In CI the fixture is
//! copied aside and opened by the current journal, which must recover the same two records.
//! Setting `PERMGUARD_CAPTURE_LEGACY_FIXTURES=1` rewrites the fixture from the current code
//! instead; that is done once per layout version and reviewed, never to make a failing test pass.
//!
//! The fixture is the v1 compatibility baseline: every later migration of this store must read it.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};

use permguard_core::domains;
use permguard_events::journal::{Bounds, Journal};
use permguard_events::record::{GENESIS, Producer, Stream, digest_of, occurrence_digest_of};
use serde_json::{Value, json};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/legacy/v1/event-journal"
);

fn scratch() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-legacy-event-journal-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("the scratch directory is created");
    path
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("the target directory is created");
    for entry in fs::read_dir(from).expect("the source directory is listed") {
        let entry = entry.expect("an entry is read");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("a file type").is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("a file is copied");
        }
    }
}

fn stream() -> Stream {
    Stream::new(
        Producer::data_plane("pdp-fixture", "inst-1"),
        "zone-a",
        "ledger-a",
    )
}

fn record(seq: u64, prev: &str, event_id: &str) -> Value {
    let event = json!({ "event_id": event_id, "kind": "request", "action": "Acme::Action::Read" });
    let occurrence_digest = occurrence_digest_of(&event).expect("the occurrence digests");
    json!({
        "v": 1,
        "record_type": domains::record::EVENT_V1,
        "stream": {
            "producer": { "class": domains::producer::DATA_PLANE_V1, "id": "pdp-fixture", "instance": "inst-1" },
            "zone": "zone-a",
            "ledger": "ledger-a"
        },
        "seq": seq,
        "prev": prev,
        "event_type": domains::event::DOGWOOD_V1,
        "event_id": event_id,
        "occurrence_digest": occurrence_digest,
        "kind": "request",
        "profile": "default",
        "policy_partitions": ["governance"],
        "commit": "sha256:0000000000000000000000000000000000000000000000000000000000000001",
        "occurred_at": "2026-10-01T00:00:00Z",
        "observed_at": "2026-10-01T00:00:01Z",
        "event": event
    })
}

fn build(directory: &Path) {
    let mut journal =
        Journal::open(directory, stream(), Bounds::default()).expect("the journal opens");
    let mut prev = GENESIS.to_owned();
    for (seq, id) in [(1, "evt-1"), (2, "evt-2")] {
        let appended = journal
            .append(&record(seq, &prev, id))
            .expect("the record appends");
        prev = appended.digest;
    }
}

fn verify(directory: &Path) {
    let journal = Journal::open(directory, stream(), Bounds::default()).expect("the fixture opens");
    assert_eq!(journal.state().next_seq, 3, "two records are recovered");
    let records = journal.read_from(0, 10).expect("the records read");
    assert_eq!(records.len(), 2);
    assert_eq!(records[1]["event_id"], "evt-2");
    assert_eq!(
        journal.state().head,
        digest_of(&records[1]).expect("the last record digests")
    );
    assert_eq!(journal.state().durable_through, 2);
    assert!(directory.join("STATE").exists());
}

#[test]
fn test_the_v1_event_journal_fixture_is_read_by_the_current_code() {
    let work = scratch();
    if std::env::var_os("PERMGUARD_CAPTURE_LEGACY_FIXTURES").is_some() {
        build(&work);
        let _ = fs::remove_dir_all(FIXTURE);
        copy_dir(&work, Path::new(FIXTURE));
    } else {
        copy_dir(Path::new(FIXTURE), &work);
    }
    verify(&work);
}
