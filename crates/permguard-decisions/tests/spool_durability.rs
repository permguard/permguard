// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The spool under interruption.
//!
//! Everything the specification claims about restarts, acknowledgements and
//! stream endings is a claim about what survives a process that stops without
//! warning. A "crash" here is what a crash actually leaves behind: the files
//! as they were at that instant, and a new process opening them. Nothing is
//! carried over in memory, because nothing would be.

#![allow(clippy::expect_used)]

use std::path::PathBuf;
use std::time::Duration;

use permguard_decisions::record::{
    Body, Build, Commitments, DiscontinuityBody, GENESIS, Lost, MarkerBody, Record, Sampling,
    Stream, VERSION,
};
use permguard_decisions::spool::{Bounds, RESERVE_BYTES, Spool, SpoolError, Terminal};
use serde_json::Value;

fn scratch(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "permguard-spool-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or_default()
    ));
    let _ = std::fs::remove_dir_all(&root);

    root
}

fn bounds() -> Bounds {
    Bounds {
        bytes: 1024 * 1024,
        age: Duration::from_secs(3600),
        segment_bytes: 512,
    }
}

/// A record of the shape the spool carries, at the position it must take.
fn marker_at(spool: &Spool) -> Value {
    let (seq, prev) = spool.next_position();
    Record {
        v: VERSION,
        stream: Stream::new("plane", spool.instance()),
        seq,
        prev,
        at: "2026-08-24T10:00:00Z".to_owned(),
        body: Body::Marker(Box::new(MarkerBody {
            predecessor: None,
            pdp: Build {
                version: "0.1.0".to_owned(),
                build: None,
                engines: None,
            },
            sampling: Sampling {
                permits: "1.0".to_owned(),
            },
            commitments: Commitments {
                alg: "HMAC-SHA256".to_owned(),
                key_version: "v1".to_owned(),
            },
        })),
    }
    .to_value()
    .expect("it renders")
}

fn terminal_record(terminal: Terminal) -> Result<Value, SpoolError> {
    Record {
        v: VERSION,
        stream: Stream::new("plane", &terminal.instance),
        seq: terminal.seq,
        prev: terminal.prev.clone(),
        at: "2026-08-24T11:00:00Z".to_owned(),
        body: Body::Discontinuity(Box::new(DiscontinuityBody {
            reason: terminal.reason.clone(),
            lost: Lost {
                from_seq: terminal.lost_from,
                count_estimate: terminal.lost_count,
            },
            successor: terminal.successor.clone(),
        })),
    }
    .to_value()
    .map_err(|error| SpoolError::Malformed(error.to_string()))
}

#[test]
fn a_second_writer_is_refused_rather_than_sharing_a_sequence() {
    let root = scratch("lock");
    let held = Spool::open(&root, bounds()).expect("the first writer opens it");

    let second = Spool::open(&root, bounds());
    assert!(
        matches!(second, Err(SpoolError::Locked(_))),
        "two writers would share a sequence, and that closes a stream at the far end"
    );

    // And the claim ends with the writer, so the next process is not blocked
    // by a predecessor that is no longer there.
    drop(held);
    assert!(
        Spool::open(&root, bounds()).is_ok(),
        "a claim that outlived its holder would make every restart a manual repair"
    );
}

#[test]
fn a_restart_continues_the_same_stream_at_the_same_position() {
    let root = scratch("restart");
    let (instance, seq, head) = {
        let mut spool = Spool::open(&root, bounds()).expect("it opens");
        for _ in 0..5 {
            let record = marker_at(&spool);
            spool.append(&record).expect("it appends");
        }
        (
            spool.instance().to_owned(),
            spool.seq(),
            spool.head().to_owned(),
        )
    };
    // Nothing to clean up: the claim is an advisory lock on an open file, and
    // the kernel released it when the previous spool was dropped. A lock held
    // by a file's *existence* would have made this the one thing an operator
    // has to do by hand after every crash — and doing it wrongly is exactly
    // how two writers come to share a sequence.
    let spool = Spool::open(&root, bounds()).expect("it reopens");
    assert_eq!(
        spool.instance(),
        instance,
        "the incarnation lives with the spool"
    );
    assert_eq!(
        spool.seq(),
        seq,
        "the sequence continues rather than restarting"
    );
    assert_eq!(spool.head(), head, "and so does the chain");
}

#[test]
fn a_torn_trailing_write_is_truncated_because_it_was_never_a_record() {
    let root = scratch("torn");
    {
        let mut spool = Spool::open(&root, bounds()).expect("it opens");
        for _ in 0..3 {
            let record = marker_at(&spool);
            spool.append(&record).expect("it appends");
        }
    }
    // A power loss in the middle of the fourth line.
    let segment = std::fs::read_dir(&root)
        .expect("the spool is there")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.to_string_lossy().contains("seg-"))
        .expect("a segment exists");
    let mut bytes = std::fs::read(&segment).expect("it reads");
    bytes.extend_from_slice(br#"{"v":1,"seq":4,"pre"#);
    std::fs::write(&segment, &bytes).expect("it writes");

    let spool = Spool::open(&root, bounds()).expect("it reopens");
    assert_eq!(spool.seq(), 3, "the half-written line is not a record");
    assert_eq!(
        spool.read_from(0, 100).expect("it reads").len(),
        3,
        "and it is gone from the segment, not merely skipped"
    );
}

#[test]
fn a_record_out_of_position_is_refused_rather_than_absorbed() {
    let root = scratch("position");
    let mut spool = Spool::open(&root, bounds()).expect("it opens");
    let first = marker_at(&spool);
    spool.append(&first).expect("it appends");

    // The same record again: right shape, wrong position.
    assert!(
        matches!(
            spool.append(&first),
            Err(SpoolError::OutOfOrder {
                expected: 2,
                found: 1
            })
        ),
        "a spool that absorbed a repeat would produce two records at one sequence"
    );

    let mut broken: Value = marker_at(&spool);
    broken["prev"] = serde_json::json!(GENESIS);
    assert!(
        matches!(spool.append(&broken), Err(SpoolError::NotChained { .. })),
        "and one that accepted a record naming the wrong predecessor would ship an unverifiable chain"
    );
}

#[test]
fn acknowledging_frees_what_it_covers_and_never_moves_backwards() {
    let root = scratch("ack");
    let mut spool = Spool::open(&root, bounds()).expect("it opens");
    let mut digests = Vec::new();
    for _ in 0..40 {
        let record = marker_at(&spool);
        digests.push(spool.append(&record).expect("it appends").digest);
    }
    let held = spool.bytes().expect("it measures");

    spool
        .acknowledge(30, digests[29].clone())
        .expect("it acknowledges");
    assert_eq!(spool.acked(), 30);
    assert!(
        spool.bytes().expect("it measures") < held,
        "acknowledged records stop occupying the disk"
    );
    assert!(
        spool
            .read_from(30, 100)
            .expect("it reads")
            .iter()
            .all(|record| record["seq"].as_u64().unwrap_or_default() > 30),
        "and the shipper reads from the acknowledged point"
    );

    spool
        .acknowledge(10, digests[9].clone())
        .expect("it ignores");
    assert_eq!(spool.acked(), 30, "a stale acknowledgement is not obeyed");

    assert!(
        matches!(
            spool.acknowledge(999, "sha256:x"),
            Err(SpoolError::AckAhead { .. })
        ),
        "and one for something never written is a receiver bug, not a truncation"
    );
}

#[test]
fn the_reserve_is_claimed_when_the_spool_is_created_not_when_it_is_needed() {
    let root = scratch("reserve");
    let _spool = Spool::open(&root, bounds()).expect("it opens");

    let reserve = std::fs::metadata(root.join("RESERVE")).expect("the reserve exists");
    assert_eq!(
        reserve.len(),
        RESERVE_BYTES,
        "a reservation made under pressure is a reservation that fails under pressure"
    );
}

#[test]
fn a_stream_that_ends_leaves_a_terminal_at_the_acknowledged_point() {
    let root = scratch("discontinue");
    let mut spool = Spool::open(&root, bounds()).expect("it opens");
    let mut digests = Vec::new();
    for _ in 0..20 {
        let record = marker_at(&spool);
        digests.push(spool.append(&record).expect("it appends").digest);
    }
    spool
        .acknowledge(9, digests[8].clone())
        .expect("it acknowledges");
    let closed_instance = spool.instance().to_owned();

    let ended = spool
        .discontinue("spool_full", terminal_record)
        .expect("the stream ends");

    assert_eq!(
        ended.terminal_seq, 10,
        "the terminal sits at acked + 1, which is the only position a receiver can chain"
    );
    let terminal = spool.terminal().expect("it reads").expect("one is waiting");
    assert_eq!(terminal["prev"], serde_json::json!(digests[8]));
    assert_eq!(terminal["kind"], serde_json::json!("discontinuity"));
    assert_eq!(
        terminal["lost"]["count_estimate"],
        serde_json::json!(11),
        "the records above the acknowledged point are what is being discarded"
    );
    assert_eq!(terminal["successor"], serde_json::json!(ended.successor));

    assert_eq!(spool.instance(), ended.successor, "the successor is live");
    assert_ne!(spool.instance(), closed_instance);
    assert_eq!(spool.seq(), 0, "the new stream starts at the genesis");
    assert_eq!(spool.head(), GENESIS);
    assert!(
        spool.read_from(0, 100).expect("it reads").is_empty(),
        "and the old stream's unshipped records are gone"
    );
}

#[test]
fn a_crash_between_the_terminal_and_the_successor_adopts_the_one_already_decided() {
    let root = scratch("adopt");
    let successor = {
        let mut spool = Spool::open(&root, bounds()).expect("it opens");
        let record = marker_at(&spool);
        let appended = spool.append(&record).expect("it appends");
        spool
            .acknowledge(1, appended.digest)
            .expect("it acknowledges");

        spool
            .discontinue("spool_full", terminal_record)
            .expect("the stream ends")
            .successor
    };
    let spool = Spool::open(&root, bounds()).expect("it reopens");
    assert_eq!(
        spool.instance(),
        successor,
        "recovery adopts the successor named in the terminal record"
    );
    let terminal = spool.terminal().expect("it reads").expect("still waiting");
    assert_eq!(
        terminal["successor"],
        serde_json::json!(successor),
        "and there is exactly one of them"
    );
    assert_eq!(
        spool.closing().map(|closing| closing.terminal_seq),
        Some(2),
        "the closed stream is still owed a shipment"
    );
}

#[test]
fn a_full_spool_is_noticed_before_it_is_a_problem() {
    let root = scratch("pressure");
    let tight = Bounds {
        bytes: 2048,
        age: Duration::from_secs(3600),
        segment_bytes: 512,
    };
    let mut spool = Spool::open(&root, tight).expect("it opens");

    assert_eq!(spool.pressure().expect("it measures"), None);
    while spool.pressure().expect("it measures").is_none() {
        let record = marker_at(&spool);
        spool.append(&record).expect("it appends");
    }

    assert_eq!(spool.pressure().expect("it measures"), Some("spool_full"));
    assert!(
        spool.discontinue("spool_full", terminal_record).is_ok(),
        "the terminal record fits, because its space was never in the bound"
    );
    assert_eq!(
        spool.pressure().expect("it measures"),
        None,
        "and the successor starts with room to work"
    );
}
