// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Records and checks the fault and crash tests share.

#![allow(dead_code, clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use permguard_core::domains;
use permguard_decisions::spool::Spool;
use permguard_events::journal::Journal;
use permguard_events::record::{Producer, Stream, occurrence_digest_of};
use serde_json::{Value, json};

/// A fresh directory for one test, unique in this process and the next.
pub fn scratch(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let path = std::env::temp_dir().join(format!(
        "permguard-conformance-{name}-{}-{nanos}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("the scratch directory is created");
    path
}

/// The decision record at `seq` after `prev`.
pub fn decision(seq: u64, prev: &str) -> Value {
    json!({
        "v": 1,
        "stream": { "id": "pdp-conformance", "instance": "inst-1" },
        "seq": seq,
        "prev": prev,
        "at": "2026-10-01T00:00:00Z",
        "body": { "id": format!("d-{seq}"), "decision": seq.is_multiple_of(2), "policies": ["p"] }
    })
}

/// The event stream every journal here holds.
pub fn stream() -> Stream {
    Stream::new(
        Producer::data_plane("pdp-conformance", "inst-1"),
        "zone-a",
        "ledger-a",
    )
}

/// The event record at `seq` after `prev`, valid under the event record contract.
pub fn event(seq: u64, prev: &str) -> Value {
    let event_id = format!("evt-{seq}");
    let occurrence =
        json!({ "event_id": event_id, "kind": "request", "action": "Acme::Action::Read" });
    json!({
        "v": 1,
        "record_type": domains::record::EVENT_V1,
        "stream": {
            "producer": { "class": domains::producer::DATA_PLANE_V1, "id": "pdp-conformance", "instance": "inst-1" },
            "zone": "zone-a",
            "ledger": "ledger-a"
        },
        "seq": seq,
        "prev": prev,
        "event_type": domains::event::DOGWOOD_V1,
        "event_id": event_id,
        "occurrence_digest": occurrence_digest_of(&occurrence).expect("the occurrence digests"),
        "kind": "request",
        "profile": "default",
        "policy_partitions": ["governance"],
        "commit": "sha256:0000000000000000000000000000000000000000000000000000000000000001",
        "occurred_at": "2026-10-01T00:00:00Z",
        "observed_at": "2026-10-01T00:00:01Z",
        "event": occurrence
    })
}

/// Every record the spool holds, after checking that each names its predecessor's digest and that
/// the head is the last one's.
pub fn verified_spool(spool: &Spool) -> Vec<Value> {
    let records = spool.read_from(0, usize::MAX).expect("the spool reads");
    assert_eq!(records.len() as u64, spool.seq(), "one record per sequence");
    let mut prev = permguard_decisions::record::GENESIS.to_owned();
    for (index, record) in records.iter().enumerate() {
        assert_eq!(
            record["seq"],
            json!(index as u64 + 1),
            "sequences are contiguous"
        );
        assert_eq!(
            record["prev"],
            json!(prev),
            "record {} continues the chain",
            index + 1
        );
        prev = permguard_decisions::record::digest_of(record).expect("a record digests");
    }
    assert_eq!(spool.head(), prev, "the head is the last record's digest");
    records
}

/// Every record the journal holds, after the same chain check and the `STATE` invariants.
pub fn verified_journal(journal: &Journal) -> Vec<Value> {
    let records = journal.read_from(0, usize::MAX).expect("the journal reads");
    let state = journal.state();
    assert_eq!(
        records.len() as u64 + 1,
        state.next_seq,
        "one record per sequence"
    );
    assert!(
        state.durable_through < state.next_seq,
        "nothing is durable beyond what exists"
    );
    let mut prev = permguard_events::record::GENESIS.to_owned();
    for (index, record) in records.iter().enumerate() {
        assert_eq!(
            record["seq"],
            json!(index as u64 + 1),
            "sequences are contiguous"
        );
        assert_eq!(
            record["prev"],
            json!(prev),
            "record {} continues the chain",
            index + 1
        );
        prev = permguard_events::record::digest_of(record).expect("a record digests");
    }
    assert_eq!(state.head, prev, "the head is the last record's digest");
    records
}

/// The segment files of a store directory, with their sizes.
pub fn segment_bytes(directory: &Path) -> u64 {
    std::fs::read_dir(directory)
        .expect("the directory lists")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("seg-"))
        .map(|entry| entry.metadata().expect("metadata").len())
        .sum()
}
