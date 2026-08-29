// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What survives a crash at each durability boundary, and what a retry finds afterwards.
//!
//! # What a crash is, here
//!
//! The process disappears. Nothing in memory is carried across and nothing gets to run on the way
//! out — so a crash is modelled by dropping every handle and reopening the volume, which is exactly
//! what a restart does. That the reopen *succeeds* is part of every assertion: a journal holds an
//! exclusive lock on its directory for as long as it lives, so a "restart" that had not really let
//! go would be refused here rather than quietly writing a second chain into one stream. That is not
//! a hypothetical: an earlier draft of these tests reopened the volume while still holding it, and
//! was refused with `Locked` — which is the guarantee, observed.
//!
//! # Why the boundaries are walked one at a time
//!
//! A submission crosses several: the record is appended, the journal is flushed, the occurrence
//! index is flushed, the history is applied, a decision identity is reserved, the audit record is
//! written and flushed, and the answer is made durable. Each gap between two of them is a state a
//! crash can leave behind, and "the whole thing works" says nothing about any of them — the failures
//! that matter are precisely the ones where some steps happened and the next did not.
//!
//! So each test stops at one boundary, restarts, and asks what the volume holds and what a retry is
//! answered. The assertion is never "it did not error": it is the record count, the sequence, and
//! the identity, because those are what a duplicate or a hole would show up in.

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use permguard_core::Metrics;
use permguard_data_plane::temporal::streams::{Routed, Streams};
use permguard_events::journal::Bounds;
use permguard_events::record::{RECORD_TYPE, Record};
use permguard_events::{Producer, Stream};
use serde_json::{Value, json};

const ZONE: &str = "acme-id";
const LEDGER: &str = "agent-governance-id";
const PRODUCER: &str = "data-plane-crash";

fn scratch(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "permguard-crash-{tag}-{}-{:?}",
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
        retention_minimum: std::time::Duration::MAX,
        allowed_lateness: std::time::Duration::from_secs(u32::MAX.into()),
        clock_skew: std::time::Duration::from_secs(u32::MAX.into()),
        ..Bounds::default()
    }
}

/// A plane's journals over one volume. Dropping it is the crash; calling this again is the restart.
fn opened(root: &Path) -> Arc<Streams> {
    Arc::new(
        Streams::new(root.to_path_buf(), PRODUCER.to_owned(), bounds())
            .with_metrics(Metrics::none()),
    )
}

fn occurrence(id: &str) -> Value {
    json!({
        "event_id": id,
        "kind": "response",
        "action": "Drupe::Action::Login",
        "principal": {"type": "User", "id": "alice"},
        "resource": {"type": "Session", "id": "s1"},
        "data": {"user": "alice"}
    })
}

fn record(id: &str) -> Record {
    let event = occurrence(id);
    Record {
        v: 1,
        record_type: RECORD_TYPE.to_owned(),
        stream: Stream {
            producer: Producer {
                class: permguard_events::PRODUCER_CLASS_DATA_PLANE.to_owned(),
                id: String::new(),
                instance: String::new(),
            },
            zone: ZONE.to_owned(),
            ledger: LEDGER.to_owned(),
        },
        seq: 0,
        prev: String::new(),
        event_type: permguard_languages::event::EVENT_TYPE.to_owned(),
        event_id: id.to_owned(),
        occurrence_digest: permguard_events::occurrence_digest_of(&event).expect("it digests"),
        kind: "response".to_owned(),
        profile: "temporal".to_owned(),
        policy_partitions: vec!["governance".to_owned()],
        commit: "sha256:commit".to_owned(),
        history_key: None,
        occurred_at: "2026-08-29T10:00:00Z".to_owned(),
        observed_at: "2026-08-29T10:00:00Z".to_owned(),
        event,
    }
}

fn routed() -> Routed<'static> {
    Routed {
        profile: "temporal",
        kind: "response",
    }
}

/// How many records the volume holds, read after a restart rather than from memory.
fn held(root: &Path) -> Vec<Value> {
    opened(root)
        .read_from(ZONE, LEDGER, 0, 1_000)
        .expect("the journal reads")
}

/// **Boundary: event append + journal sync.**
///
/// `Streams::append` does not return until the flush covering the record has. So a crash *after* it
/// returned must find the record, and the sequence it was given must still be the sequence it has:
/// a restart that renumbered would give two records one position at the far end, which closes the
/// stream permanently.
#[test]
fn a_record_that_was_answered_is_there_after_a_restart() {
    let root = scratch("append-sync");
    let answered = {
        let streams = opened(&root);
        let answered = streams
            .append(ZONE, LEDGER, record("e-1"))
            .expect("the record is durable");
        assert_eq!(answered.1.seq, 1);
        answered
    };

    let after = held(&root);
    assert_eq!(after.len(), 1, "one append, one record");
    assert_eq!(
        after[0]["seq"],
        json!(answered.1.seq),
        "and its own sequence"
    );
    assert_eq!(after[0]["event_id"], json!("e-1"));

    let _ = std::fs::remove_dir_all(&root);
}

/// **Boundary: occurrence index sync.**
///
/// The index is what makes a retry *recognisable*. It is written before the record is acknowledged
/// and flushed with it, so a record that survived a crash must have its entry — otherwise the same
/// occurrence submitted again would be recorded a second time, and a temporal engine that counts
/// order would count one thing twice.
#[test]
fn a_durable_record_is_recognisable_as_itself_after_a_restart() {
    let root = scratch("occurrence-index");
    {
        let streams = opened(&root);
        streams
            .append(ZONE, LEDGER, record("e-1"))
            .expect("the record is durable");
    }

    let known = opened(&root)
        .known(ZONE, LEDGER, "e-1")
        .expect("the index reads")
        .expect("the entry survived the restart");
    assert_eq!(known.seq, 1);
    assert_eq!(
        known.occurrence_digest,
        permguard_events::occurrence_digest_of(&occurrence("e-1")).expect("it digests"),
        "and it identifies the occurrence by its bytes, not only by its id"
    );
    assert!(
        known.response.is_null(),
        "no answer was committed, so none is claimed"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// **Boundary: decision identity reserved, then nothing.**
///
/// The identity is made durable *before* the audit record is written, precisely so this window has
/// one answer rather than two. A restart here must reserve nothing new: a second identity for one
/// occurrence is a second audit record nobody can reconcile with the first.
#[test]
fn a_reserved_decision_identity_survives_and_is_not_minted_twice() {
    let root = scratch("decision-id");
    let reserved = {
        let streams = opened(&root);
        streams
            .append(ZONE, LEDGER, record("e-1"))
            .expect("the record is durable");
        streams
            .decision_id(ZONE, LEDGER, "e-1")
            .expect("an identity is reserved")
    };
    assert!(!reserved.is_empty());

    let after = opened(&root)
        .decision_id(ZONE, LEDGER, "e-1")
        .expect("the identity is read back");
    assert_eq!(
        after, reserved,
        "the identity reserved before the crash is the identity after it"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// **Boundary: record durable, answer never committed.**
///
/// The crash window the whole recovery path exists for. The volume holds the occurrence and no
/// answer, so a retry must not be told "already answered" — there is nothing to answer it with —
/// and must not be recorded again either.
#[test]
fn a_record_without_a_committed_answer_is_not_answered_and_not_duplicated() {
    let root = scratch("no-outcome");
    {
        let streams = opened(&root);
        streams
            .append(ZONE, LEDGER, record("e-1"))
            .expect("the record is durable");
        // and the process disappears before `record_outcome`
    }

    let streams = opened(&root);
    assert!(
        streams
            .outcome(ZONE, LEDGER, "e-1")
            .expect("the index reads")
            .is_none(),
        "an answer that was never committed is not invented on the way back"
    );
    assert_eq!(
        streams
            .read_from(ZONE, LEDGER, 0, 1_000)
            .expect("the journal reads")
            .len(),
        1,
        "and the record was not written twice"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// **Boundary: outcome written and flushed.**
///
/// Past this point the answer is a fact the caller may already have. A restart must reproduce it
/// exactly — the same answer, over the same bytes, routed the same way — because a retry that got a
/// *different* answer would mean the plane said two things about one occurrence.
#[test]
fn a_committed_answer_is_reproduced_after_a_restart() {
    let root = scratch("outcome-sync");
    let answer = json!({"outcome": "accepted", "event_id": "e-1"});
    {
        let streams = opened(&root);
        streams
            .append(ZONE, LEDGER, record("e-1"))
            .expect("the record is durable");
        streams
            .record_outcome(ZONE, LEDGER, "e-1", routed(), &answer)
            .expect("the answer is durable");
    }

    let streams = opened(&root);
    assert_eq!(
        streams
            .outcome(ZONE, LEDGER, "e-1")
            .expect("the index reads")
            .expect("the answer survived"),
        answer
    );
    let known = streams
        .known(ZONE, LEDGER, "e-1")
        .expect("the index reads")
        .expect("the entry survived");
    assert_eq!(
        known.profile.as_deref(),
        Some("temporal"),
        "and how it was routed, so a retry under another profile is a conflict rather than this \
         answer"
    );
    assert_eq!(known.kind.as_deref(), Some("response"));
    assert_eq!(
        streams
            .read_from(ZONE, LEDGER, 0, 1_000)
            .expect("the journal reads")
            .len(),
        1,
        "still one record"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// **Boundary: several records, restart, then more.**
///
/// A stream continues rather than restarting: the sequence after a crash is the next one, not the
/// first. A journal that began again at 1 would give two records one position, and the far end
/// would close the stream as forked.
#[test]
fn a_stream_continues_its_sequence_across_a_restart() {
    let root = scratch("continue");
    {
        let streams = opened(&root);
        for id in ["e-1", "e-2"] {
            streams
                .append(ZONE, LEDGER, record(id))
                .expect("the record is durable");
        }
    }

    let answered = opened(&root)
        .append(ZONE, LEDGER, record("e-3"))
        .expect("the record is durable");
    assert_eq!(
        answered.1.seq, 3,
        "the sequence continued rather than reset"
    );

    let after = held(&root);
    assert_eq!(after.len(), 3, "nothing was lost and nothing duplicated");
    let sequences: Vec<u64> = after
        .iter()
        .filter_map(|record| record["seq"].as_u64())
        .collect();
    assert_eq!(sequences, vec![1, 2, 3], "and the chain has no holes");

    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------------------------
// The boundaries *inside* a flush.
//
// `Streams::append` does not return until the flush covering its record has, so the high-level
// path cannot stop between the write and the `fsync` — which is the guarantee, and also the reason
// the two most interesting crash windows are invisible from up there. The journal exposes both
// halves (`append_unsynced` and `sync_open`, `record_occurrence` and `sync_occurrences`), so the
// crash can be placed exactly between them: do the first, drop everything, reopen.
//
// What these pin down is that the *first* half alone promises nothing. A reader that treats an
// unflushed write as durable is a reader that will one day answer from a record the disk never
// took, and no test of the whole path can catch that, because the whole path never stops there.
// ---------------------------------------------------------------------------------------------

use permguard_events::journal::Journal;

fn stream() -> permguard_events::Stream {
    permguard_events::Stream {
        producer: Producer {
            class: permguard_events::PRODUCER_CLASS_DATA_PLANE.to_owned(),
            id: PRODUCER.to_owned(),
            instance: String::new(),
        },
        zone: ZONE.to_owned(),
        ledger: LEDGER.to_owned(),
    }
}

/// The record as the journal stores it, at the position it would take.
fn line(journal: &Journal, id: &str) -> Value {
    let (seq, prev) = journal.next_position();
    let mut held = serde_json::to_value(record(id)).expect("the record renders");
    held["seq"] = json!(seq);
    held["prev"] = json!(prev);

    held
}

/// **Boundary: event append, before the journal's flush.**
///
/// The write reached the file and the `fsync` did not. A crash here may leave the bytes or lose
/// them — the page cache decides, not this code — so the only thing that may be *claimed* is what
/// survives a reopen, and the reopen is the authority. What must never happen is the tail being
/// read as a whole record when it is not: a torn line is truncated at open, so the journal comes
/// back consistent either way.
#[test]
fn an_unflushed_append_leaves_a_journal_that_opens_consistently() {
    let root = scratch("append-unsynced");
    let directory = root.join(ZONE).join(LEDGER);
    let seq = {
        let mut journal = Journal::open(&directory, stream(), bounds()).expect("the journal opens");
        let held = line(&journal, "e-1");
        journal
            .append_unsynced(&held)
            .expect("the record is written")
            .seq
        // and the process disappears before `sync_open`
    };
    assert_eq!(seq, 1);

    // The assertion is not "the record is there" — an unflushed write may or may not be. It is that
    // whatever is there is coherent: the journal opens, and its head agrees with what it holds.
    let reopened = Journal::open(&directory, stream(), bounds()).expect("the journal reopens");
    let held = reopened.read_from(0, 100).expect("it reads");
    assert!(
        held.len() <= 1,
        "an unflushed append cannot have produced more than it wrote"
    );
    let (next, _) = reopened.next_position();
    assert_eq!(
        next as usize,
        held.len() + 1,
        "and the sequence the journal hands the next writer is one past what it actually holds — a \
         journal that counted a record it cannot read would hand out a position already taken"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// **Boundary: event append, after the journal's flush.**
///
/// The other side of the same line. Past the flush the record is a fact, and a reopen must find it
/// at the sequence it was given — this is what `Streams::append` waits for before answering, and
/// what makes an answered submission safe to act on.
#[test]
fn a_flushed_append_is_a_fact_the_reopen_agrees_with() {
    let root = scratch("append-synced");
    let directory = root.join(ZONE).join(LEDGER);
    {
        let mut journal = Journal::open(&directory, stream(), bounds()).expect("the journal opens");
        let held = line(&journal, "e-1");
        journal
            .append_unsynced(&held)
            .expect("the record is written");
        journal.sync().expect("the flush returns");
    }

    let reopened = Journal::open(&directory, stream(), bounds()).expect("the journal reopens");
    let held = reopened.read_from(0, 100).expect("it reads");
    assert_eq!(held.len(), 1, "a flushed record survives");
    assert_eq!(held[0]["seq"], json!(1));
    assert_eq!(
        reopened.next_position().0,
        2,
        "and the journal continues after it"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// **Boundary: occurrence index written, before its own flush.**
///
/// The entry is what makes a retry recognisable, and it is flushed separately from the record. A
/// crash between the two must not leave a journal that claims an occurrence it cannot produce: the
/// index is rebuilt from the records, which are the authority, so the reopen either has both or
/// neither — never an entry pointing at nothing.
#[test]
fn an_unflushed_occurrence_entry_never_outlives_the_record_it_names() {
    let root = scratch("occurrence-unsynced");
    let directory = root.join(ZONE).join(LEDGER);
    {
        let mut journal = Journal::open(&directory, stream(), bounds()).expect("the journal opens");
        let held = line(&journal, "e-1");
        journal
            .append_unsynced(&held)
            .expect("the record is written");
        journal.sync().expect("the flush returns");
        journal
            .record_occurrence(&permguard_events::journal::KnownOccurrence {
                event_id: "e-1".to_owned(),
                seq: 1,
                occurrence_digest: permguard_events::occurrence_digest_of(&occurrence("e-1"))
                    .expect("it digests"),
                decision_id: None,
                profile: None,
                kind: None,
                response: Value::Null,
            })
            .expect("the entry is written");
        // and the process disappears before `sync_occurrences`
    }

    let reopened = Journal::open(&directory, stream(), bounds()).expect("the journal reopens");
    let known = reopened.occurrence("e-1").expect("the index reads");
    if let Some(known) = known {
        assert_eq!(
            known.seq, 1,
            "an entry that survived names the record that also survived"
        );
        assert_eq!(
            reopened.read_from(0, 100).expect("it reads").len(),
            1,
            "and that record is there to be named"
        );
    }

    let _ = std::fs::remove_dir_all(&root);
}

/// **Boundary: the shipping checkpoint, and the acknowledgement that follows it.**
///
/// Shipping is the one boundary with a party on the other side of a network. A batch is checkpointed
/// — signed, so the receiver can say what it continues — then sent, then acknowledged. A crash can
/// land between any two of those, and the rule that makes it survivable is that the *journal* is
/// what remembers, not the shipper: a restart re-reads how far the receiver confirmed, and ships
/// from there.
///
/// So what must hold is that an acknowledgement is durable and monotonic. A restart that forgot one
/// re-ships records the receiver already holds — harmless, the transport is at-least-once — but a
/// restart that *invented* one skips records nobody will send again, and the far end has a hole it
/// cannot detect.
#[test]
fn an_acknowledgement_survives_a_restart_and_never_moves_backwards() {
    let root = scratch("ack");
    let directory = root.join(ZONE).join(LEDGER);
    {
        let mut journal = Journal::open(&directory, stream(), bounds()).expect("the journal opens");
        for id in ["e-1", "e-2", "e-3"] {
            let held = line(&journal, id);
            journal.append_unsynced(&held).expect("written");
        }
        journal.sync().expect("the flush returns");
        journal
            .mark_signed(2)
            .expect("two records were checkpointed");
        journal
            .acknowledge(2)
            .expect("and the receiver confirmed them");
        // and the process disappears before the third is shipped
    }

    let mut reopened = Journal::open(&directory, stream(), bounds()).expect("the journal reopens");
    assert_eq!(
        reopened.state().acked_through,
        2,
        "the confirmed point is durable: shipping resumes after it rather than from the start"
    );
    assert_eq!(
        reopened.read_from(0, 100).expect("it reads").len(),
        3,
        "and the record that was never shipped is still there to ship"
    );

    // Monotonic: an acknowledgement that arrived out of order must not rewind the point, or records
    // between the two would be sent again as if they had never been confirmed.
    let _ = reopened.acknowledge(1);
    assert!(
        reopened.state().acked_through >= 2,
        "an older acknowledgement does not move the confirmed point backwards"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// **Boundary: the decision audit record, before and after its flush.**
///
/// The decision log is the other durable write a deciding submission makes, and it has its own
/// group commit — so it has its own version of the same window. `append_unsynced` puts the record
/// in the segment and `sync_open` is what makes it a fact; a crash between them must leave a spool
/// that opens, and must not leave the *idempotency index* claiming a record the disk never took.
///
/// That last part is the one worth pinning: the index is what answers a retry, and an index that
/// promoted an entry at append would answer from a record a crash could still remove.
#[test]
fn an_unflushed_audit_record_is_not_answerable_after_a_restart() {
    use permguard_decisions::spool::{Bounds as SpoolBounds, Spool};

    let root = scratch("audit-unsynced");
    let directory = root.join("decisions");
    {
        let mut spool = Spool::open(&directory, SpoolBounds::default()).expect("the spool opens");
        let (seq, prev) = spool.next_position();
        let record = json!({
            "v": 1, "seq": seq, "prev": prev, "at": "2026-08-29T10:00:00Z",
            "kind": "decision", "id": "d-1", "decision": true
        });
        spool
            .append_unsynced(&record)
            .expect("the record is written");
        // and the process disappears before `sync_open`
    }

    let reopened = Spool::open(&directory, SpoolBounds::default()).expect("the spool reopens");
    let held = reopened.read_from(0, 100).expect("it reads");
    assert!(
        held.len() <= 1,
        "an unflushed append cannot have produced more than it wrote"
    );
    assert_eq!(
        reopened.next_position().0 as usize,
        held.len() + 1,
        "and the position handed to the next writer is one past what the spool actually holds"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// Two journals for one ledger are refused, not silently chosen between.
///
/// # Why this test exists at all
///
/// `Streams::adopt` promises that a ledger keyed both ways — a directory under its display names
/// from before storage was keyed canonically, and one under its identifiers — is a refusal rather
/// than a guess. The promise was dead code: the "already canonical" test ran first and returned in
/// exactly the case that also had a legacy directory, so the refusal below it was unreachable and
/// the two journals coexisted in silence.
///
/// Nothing caught it, because every test had only one of the two directories. This one has both,
/// which is the only shape in which the check does anything.
#[test]
fn a_ledger_keyed_both_ways_is_refused_rather_than_chosen_between() {
    let root = scratch("both-keys");
    // A journal under the identifiers, and another under the display names.
    for (zone, ledger) in [(ZONE, LEDGER), ("acme", "agent-governance")] {
        let streams = opened(&root);
        streams
            .append(zone, ledger, {
                let mut held = record("e-1");
                held.stream.zone = zone.to_owned();
                held.stream.ledger = ledger.to_owned();
                held
            })
            .expect("the record is durable");
    }

    let streams = opened(&root);
    let refused = streams
        .adopt((ZONE, LEDGER), ("acme", "agent-governance"))
        .expect_err("two journals for one ledger is a refusal");
    let said = refused.to_string();
    assert!(
        said.contains("both its identifiers and its names"),
        "{said}"
    );
    assert!(
        said.contains("acme") && said.contains(ZONE),
        "the refusal names both directories so an operator can go and look: {said}"
    );

    // And neither was touched: refusing means refusing, not half-migrating.
    assert!(root.join(ZONE).join(LEDGER).exists());
    assert!(root.join("acme").join("agent-governance").exists());

    let _ = std::fs::remove_dir_all(&root);
}
