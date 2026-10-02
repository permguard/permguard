// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The decision spool and the event journal under an fsync failure and a full disk.
//!
//! Each test proves the same three things for one fault: the append that met the fault is refused,
//! so no caller is told its record is durable; nothing the store already acknowledged is lost; and
//! once the fault is lifted, the directory reopens to a valid chain. What a store must do about an
//! fsync error beyond refusing — whether the record that met it may ever be trusted — is the
//! fsync-finality rule of the storage contract, and is not decided here.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use permguard_conformance::fault::{self, Fault};
use permguard_decisions::spool::{Bounds as SpoolBounds, Spool};
use permguard_events::journal::{Bounds as JournalBounds, Journal};

use support::{decision, event, scratch, segment_bytes, stream, verified_journal, verified_spool};

fn spool_with(directory: &std::path::Path, records: u64) -> Spool {
    let mut spool = Spool::open(directory, SpoolBounds::default()).expect("the spool opens");
    for _ in 0..records {
        let (seq, prev) = spool.next_position();
        spool
            .append(&decision(seq, &prev))
            .expect("the record appends");
    }
    spool
}

fn journal_with(directory: &std::path::Path, records: u64) -> Journal {
    let mut journal =
        Journal::open(directory, stream(), JournalBounds::default()).expect("the journal opens");
    for _ in 0..records {
        let (seq, prev) = journal.next_position();
        journal
            .append(&event(seq, &prev))
            .expect("the record appends");
    }
    journal
}

#[test]
fn test_a_spool_refuses_the_append_an_fsync_failure_meets_and_reopens_to_a_valid_chain() {
    let directory = scratch("spool-fsync");
    let mut spool = spool_with(&directory, 3);

    let guard = fault::inject(&directory, Fault::Fsync);
    let (seq, prev) = spool.next_position();
    assert!(
        spool.append(&decision(seq, &prev)).is_err(),
        "an append whose flush failed is not acknowledged"
    );
    drop(guard);
    drop(spool);

    let reopened = Spool::open(&directory, SpoolBounds::default()).expect("the spool reopens");
    let records = verified_spool(&reopened);
    assert!(
        records.len() >= 3,
        "the three acknowledged records survive the fault"
    );
}

#[test]
fn test_a_full_disk_refuses_a_spool_append_writes_nothing_and_loses_nothing() {
    let directory = scratch("spool-full");
    let mut spool = spool_with(&directory, 3);
    let before = segment_bytes(&directory);

    let guard = fault::inject(&directory, Fault::DiskFull { remaining_bytes: 0 });
    let (seq, prev) = spool.next_position();
    assert!(spool.append(&decision(seq, &prev)).is_err());
    assert_eq!(
        segment_bytes(&directory),
        before,
        "a refused write leaves the segment as it was"
    );
    drop(guard);
    drop(spool);

    let reopened = Spool::open(&directory, SpoolBounds::default()).expect("the spool reopens");
    assert_eq!(
        verified_spool(&reopened).len(),
        3,
        "exactly the acknowledged records"
    );
}

#[test]
fn test_a_journal_refuses_the_append_an_fsync_failure_meets_and_does_not_advance_durability() {
    let directory = scratch("journal-fsync");
    let mut journal = journal_with(&directory, 3);
    let durable = journal.state().durable_through;
    assert_eq!(durable, 3);

    let guard = fault::inject(&directory, Fault::Fsync);
    let (seq, prev) = journal.next_position();
    assert!(
        journal.append(&event(seq, &prev)).is_err(),
        "an append whose flush failed is not acknowledged"
    );
    assert_eq!(
        journal.state().durable_through,
        durable,
        "the durable watermark does not move past a failed flush"
    );
    drop(guard);
    drop(journal);

    let reopened =
        Journal::open(&directory, stream(), JournalBounds::default()).expect("the journal reopens");
    let records = verified_journal(&reopened);
    assert!(
        records.len() >= 3,
        "the three acknowledged records survive the fault"
    );
}

#[test]
fn test_a_full_disk_refuses_a_journal_append_writes_nothing_and_loses_nothing() {
    let directory = scratch("journal-full");
    let mut journal = journal_with(&directory, 3);
    let before = segment_bytes(&directory);

    let guard = fault::inject(&directory, Fault::DiskFull { remaining_bytes: 0 });
    let (seq, prev) = journal.next_position();
    assert!(journal.append(&event(seq, &prev)).is_err());
    assert_eq!(
        segment_bytes(&directory),
        before,
        "a refused write leaves the segment as it was"
    );
    drop(guard);
    drop(journal);

    let reopened =
        Journal::open(&directory, stream(), JournalBounds::default()).expect("the journal reopens");
    assert_eq!(
        verified_journal(&reopened).len(),
        3,
        "exactly the acknowledged records"
    );
}

#[test]
fn test_a_fault_on_one_volume_does_not_reach_another() {
    let faulty = scratch("isolated-faulty");
    let healthy = scratch("isolated-healthy");
    let _guard = fault::inject(&faulty, Fault::Fsync);

    let mut spool = spool_with(&healthy, 2);
    let (seq, prev) = spool.next_position();
    spool
        .append(&decision(seq, &prev))
        .expect("a sibling volume is unaffected");
    assert_eq!(verified_spool(&spool).len(), 3);
}
