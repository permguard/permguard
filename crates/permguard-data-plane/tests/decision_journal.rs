// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the journal writes, and what it deliberately does not.

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use permguard_core::Metrics;
use permguard_data_plane::decisions::journal::{Decided, Epoch, Journal, WhenFull, Written};
use permguard_decisions::spool::Bounds;
use permguard_decisions::{Commitment, chain};
use serde_json::{Value, json};

fn scratch(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "permguard-journal-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or_default()
    ));
    let _ = std::fs::remove_dir_all(&root);

    root
}

fn epoch(sampling: &str) -> Epoch {
    Epoch {
        version: "0.1.0".to_owned(),
        build: Some("sha256:9c4e".to_owned()),
        engines: BTreeMap::from([("cedar".to_owned(), "4.12.0".to_owned())]),
        sampling: sampling.to_owned(),
    }
}

fn journal(tag: &str, sampling: &str, when_full: WhenFull, bounds: Bounds) -> Journal {
    Journal::open(
        scratch(tag),
        "data-plane-test",
        epoch(sampling),
        when_full,
        bounds,
        Commitment::new(*b"a-commitment-key", "v1"),
        Metrics::none(),
    )
    .expect("the journal opens")
}

fn bounds() -> Bounds {
    Bounds {
        bytes: 1024 * 1024,
        age: Duration::from_secs(3600),
        segment_bytes: 4096,
    }
}

fn decided(id: &str, permit: bool) -> Decided<'_> {
    Decided {
        id,
        at: "2026-08-24T10:00:00Z".to_owned(),
        zone: "acme",
        ledger: "main-ledger",
        commit: "sha256:ec1773bf",
        counter: 3,
        profile: "default",
        subject: ("User".to_owned(), "pseudo:v1:9f2c".to_owned()),
        subject_properties: None,
        resource: ("Document".to_owned(), "budget-2026".to_owned()),
        resource_properties: None,
        included_context: None,
        action: "read".to_owned(),
        principal: None,
        context: Some(json!({ "ip": "10.0.0.1" })),
        partition_inputs: Some(json!({})),
        permit,
        policies: vec!["af4c4260".to_owned()],
        reason: "200".to_owned(),
        trace: None,
        request_id: Some("lab-1".to_owned()),
        latency_us: 143,
    }
}

fn everything(journal: &Journal) -> Vec<Value> {
    journal.pending(10_000).expect("it reads")
}

#[test]
fn a_stream_opens_with_the_marker_that_governs_it() {
    let journal = journal("marker", "1.0", WhenFull::Open, bounds());

    let records = everything(&journal);
    assert_eq!(records[0]["kind"], json!("marker"));
    assert_eq!(records[0]["seq"], json!(1));
    assert_eq!(
        records[0]["sampling"]["permits"],
        json!("1.0"),
        "a reader must be told what the log claims to be complete about"
    );
    assert_eq!(
        records[0]["pdp"]["engines"]["cedar"],
        json!("4.12.0"),
        "and which evaluation semantics produced what follows"
    );
    assert_eq!(
        records[0]["commitments"]["key_version"],
        json!("v1"),
        "and under which key the input commitments were taken"
    );
}

#[test]
fn what_is_written_is_a_chain_from_the_genesis() {
    let journal = journal("chain", "1.0", WhenFull::Open, bounds());
    for index in 0..20 {
        journal
            .record(&decided(&format!("id-{index}"), index % 3 != 0))
            .expect("it records");
    }

    let verified = chain::verify(&everything(&journal), None).expect("it is a chain");
    assert!(verified.from_genesis);
    assert_eq!(verified.last_seq, 21, "one marker and twenty decisions");
}

#[test]
fn the_caller_s_inputs_are_committed_to_and_not_kept() {
    let journal = journal("inputs", "1.0", WhenFull::Open, bounds());
    journal.record(&decided("id-1", true)).expect("it records");

    let record = everything(&journal)
        .into_iter()
        .find(|record| record["kind"] == json!("decision"))
        .expect("a decision was written");
    let context = record["inputs"]["context"]
        .as_str()
        .expect("a commitment was taken");

    assert!(context.starts_with("hmac-sha256:v1:"), "{context}");
    assert!(
        !serde_json::to_string(&record)
            .expect("it renders")
            .contains("10.0.0.1"),
        "the address the decision saw is committed to, never recorded"
    );
}

#[test]
fn a_deny_is_never_sampled_out_however_low_the_rate() {
    let journal = journal("sampling", "0.0", WhenFull::Open, bounds());

    for index in 0..50 {
        assert_eq!(
            journal
                .record(&decided(&format!("permit-{index}"), true))
                .expect("it records"),
            Written::SampledOut,
            "at a rate of zero, no permit is recorded"
        );
    }
    for index in 0..10 {
        assert!(
            matches!(
                journal
                    .record(&decided(&format!("deny-{index}"), false))
                    .expect("it records"),
                Written::Recorded { .. }
            ),
            "a log that drops refusals is not an audit trail"
        );
    }

    let denies = everything(&journal)
        .into_iter()
        .filter(|record| record["kind"] == json!("decision"))
        .count();
    assert_eq!(denies, 10);
}

#[test]
fn sampling_is_decided_by_the_record_not_by_a_coin() {
    // The same decision is sampled the same way wherever the question is asked
    // again, so a caller cannot be recorded more by retrying.
    let first = journal("stable-a", "0.5", WhenFull::Open, bounds());
    let second = journal("stable-b", "0.5", WhenFull::Open, bounds());

    for index in 0..200 {
        let id = format!("id-{index}");
        assert_eq!(
            first.record(&decided(&id, true)).expect("it records") == Written::SampledOut,
            second.record(&decided(&id, true)).expect("it records") == Written::SampledOut,
            "two planes must agree about {id}"
        );
    }
}

#[test]
fn a_full_spool_ends_the_stream_and_the_successor_says_what_it_continues() {
    let tight = Bounds {
        bytes: 4096,
        age: Duration::from_secs(3600),
        segment_bytes: 1024,
    };
    let journal = journal("full", "1.0", WhenFull::Open, tight);

    let mut ended = None;
    for index in 0..500 {
        match journal
            .record(&decided(&format!("id-{index}"), true))
            .expect("it records")
        {
            Written::Discontinued { lost } => {
                ended = Some(lost);
                break;
            }
            _ => continue,
        }
    }
    let lost = ended.expect("the spool filled and the stream ended");
    assert!(
        lost > 0,
        "records were discarded, and the log says how many"
    );

    let records = everything(&journal);
    assert_eq!(
        records[0]["kind"],
        json!("discontinuity"),
        "the terminal record of the closed stream ships before anything of the successor"
    );
    let successor = records[0]["successor"].as_str().expect("it names one");

    journal
        .acknowledge(0, "sha256:unused")
        .expect("the closed stream is finished with");
    let records = everything(&journal);
    assert_eq!(records[0]["kind"], json!("marker"));
    assert_eq!(records[0]["stream"]["instance"], json!(successor));
    assert_eq!(
        records[0]["predecessor"]["reason"],
        json!("spool_full"),
        "a successor names what it continues, so a verifier need not guess"
    );
    assert!(
        chain::verify(&records, None)
            .expect("it is a chain")
            .from_genesis,
        "and the new stream is internally complete: verification never crosses the hole"
    );
}

#[test]
fn only_the_attributes_somebody_named_are_kept_in_clear() {
    let journal = journal("include", "1.0", WhenFull::Open, bounds());
    let mut asked = decided("id-1", true);
    asked.subject_properties =
        Some(serde_json::from_value(json!({ "department": "HR" })).expect("a map"));
    asked.included_context =
        Some(serde_json::from_value(json!({ "ip": "10.0.0.1" })).expect("a map"));
    journal.record(&asked).expect("it records");

    let record = everything(&journal)
        .into_iter()
        .find(|record| record["kind"] == json!("decision"))
        .expect("a decision was written");

    assert_eq!(record["subject"]["properties"]["department"], json!("HR"));
    assert_eq!(record["context"]["ip"], json!("10.0.0.1"));
    assert!(
        record["resource"].get("properties").is_none(),
        "nothing nobody named appears"
    );
    // And what was *seen* is still committed to, whatever was kept.
    assert!(
        record["inputs"]["context"]
            .as_str()
            .is_some_and(|commitment| commitment.starts_with("hmac-sha256:")),
    );
}

#[test]
fn a_boxcarred_request_writes_one_record_per_evaluation() {
    // The audit trail a batch has to leave: three questions about three
    // different subjects and actions are three decisions, and folding them into
    // one record would attribute all of them to the first.
    let journal = journal("boxcar", "1.0", WhenFull::Open, bounds());
    for (index, permit) in [true, false, true].into_iter().enumerate() {
        let id = format!("id-{index}");
        let mut asked = decided(&id, permit);
        asked.action = format!("action-{index}");
        journal.record(&asked).expect("it records");
    }

    let written: Vec<_> = everything(&journal)
        .into_iter()
        .filter(|record| record["kind"] == json!("decision"))
        .collect();
    assert_eq!(written.len(), 3, "one per evaluation, not one per request");
    assert_eq!(
        written
            .iter()
            .map(|record| record["decision"].as_bool().unwrap_or_default())
            .collect::<Vec<_>>(),
        vec![true, false, true],
        "each keeps its own verdict"
    );
    assert_eq!(
        written
            .iter()
            .map(|record| record["action"]["name"].as_str().unwrap_or_default())
            .collect::<Vec<_>>(),
        vec!["action-0", "action-1", "action-2"],
        "and its own question"
    );
}

#[test]
fn a_plane_that_may_not_decide_unrecorded_says_so_instead_of_deciding() {
    let tight = Bounds {
        bytes: 2048,
        age: Duration::from_secs(3600),
        segment_bytes: 1024,
    };
    let journal = journal("closed", "1.0", WhenFull::Closed, tight);

    let mut refused = None;
    for index in 0..500 {
        if let Written::Refused(reason) = journal
            .record(&decided(&format!("id-{index}"), true))
            .expect("it records")
        {
            refused = Some(reason);
            break;
        }
    }

    assert_eq!(
        refused.as_deref(),
        Some("spool_full"),
        "chosen deliberately, and never a surprise"
    );
}

#[test]
fn a_caller_supplied_float_neither_breaks_the_record_nor_the_commitment() {
    // Legal JSON, legal policy input, hostile to a canonicaliser that refuses
    // fractions: the record must still be written, its digest must still
    // verify as a chain, and the commitment must still be present — a caller
    // must not be able to degrade their own audit trail by shaping a number.
    let journal = journal("floats", "1.0", WhenFull::Open, bounds());
    let mut asked = decided("float-1", true);
    asked.context = Some(json!({ "risk": 0.7, "amount": 12.5, "attempts": 3 }));
    asked.partition_inputs =
        Some(json!([{ "uid": {"type": "User", "id": "alice"}, "attrs": {"score": 0.25} }]));
    asked.subject_properties = Some(
        json!({ "clearance": 2, "trust": 0.9 })
            .as_object()
            .cloned()
            .expect("an object"),
    );
    asked.included_context = Some(
        json!({ "risk": 0.7 })
            .as_object()
            .cloned()
            .expect("an object"),
    );

    assert!(matches!(
        journal.record(&asked).expect("the decision is recorded"),
        Written::Recorded { .. }
    ));

    let records = everything(&journal);
    let verified = permguard_decisions::chain::verify(&records, None)
        .expect("the spool is a verifiable chain");
    assert!(verified.from_genesis);

    let decision = records
        .iter()
        .find(|record| record["kind"] == json!("decision"))
        .expect("the decision is in the spool");
    assert!(
        decision["inputs"]["context"]
            .as_str()
            .is_some_and(|commitment| commitment.starts_with("hmac-sha256:v1:")),
        "the context commitment is present, not silently omitted: {decision}"
    );
    assert!(
        decision["inputs"]["partition_inputs"]
            .as_str()
            .is_some_and(|commitment| commitment.starts_with("hmac-sha256:v1:")),
        "the partition-input commitment too: {decision}"
    );
    assert_eq!(
        decision["subject"]["properties"]["trust"],
        json!("0.9"),
        "a non-integer included property is carried as its decimal text"
    );
    assert_eq!(
        decision["subject"]["properties"]["clearance"],
        json!(2),
        "and an integer one stays a number"
    );
    assert_eq!(decision["context"]["risk"], json!("0.7"));
}

#[test]
fn concurrent_decisions_are_all_recorded_and_the_chain_has_no_holes() {
    // The regression this guards: reading the position and appending as two
    // separate lock holds let two concurrent decisions build for one sequence
    // — the loser was never recorded. And the group commit must hand every
    // writer its own durability, not only the one whose flush it was.
    let journal = std::sync::Arc::new(journal("concurrent", "1.0", WhenFull::Open, bounds()));
    let threads: Vec<_> = (0..8)
        .map(|worker| {
            let journal = std::sync::Arc::clone(&journal);
            std::thread::spawn(move || {
                for turn in 0..25 {
                    let id = format!("w{worker}-t{turn}");
                    let asked = decided(&id, turn % 2 == 0);
                    assert!(
                        matches!(
                            journal.record(&asked).expect("every decision is recorded"),
                            Written::Recorded { .. }
                        ),
                        "no decision may be lost to a position race"
                    );
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().expect("a worker panicked");
    }

    let records = everything(&journal);
    let verified = permguard_decisions::chain::verify(&records, None)
        .expect("what concurrency wrote is still one chain");
    assert!(verified.from_genesis);
    assert_eq!(
        verified.last_seq,
        1 + 8 * 25,
        "the marker plus every decision, none lost, none duplicated"
    );
}

#[test]
fn after_a_discontinuity_the_successor_still_waits_for_its_own_disk() {
    // The regression this guards: a discontinuity resets the sequence space,
    // and group-commit marks that survived it would cover every successor
    // sequence — records answered before they were durable, silently. What is
    // observable from outside: the successor's records are really on disk
    // when `record` returns.
    let journal = journal(
        "post-discontinuity",
        "1.0",
        WhenFull::Open,
        Bounds {
            bytes: 8_000,
            age: Duration::from_secs(3600),
            segment_bytes: 1_024,
        },
    );

    // Fill until the bound ends the stream once, then stop pushing: a second
    // discontinuity while the first terminal record is still unshipped is its
    // own (already covered) refusal, not what this test is about.
    let mut discontinued = false;
    for turn in 0..40 {
        let id = format!("d{turn}");
        match journal.record(&decided(&id, false)).expect("it records") {
            Written::Discontinued { .. } => {
                discontinued = true;
                break;
            }
            Written::Recorded { .. } => {}
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
    assert!(discontinued, "the tiny bound must have ended the stream");

    // The successor keeps recording — and each of these returns only once its
    // own record is durable in the successor's own sequence space.
    for turn in 0..2 {
        let id = format!("s{turn}");
        assert!(matches!(
            journal
                .record(&decided(&id, false))
                .expect("the successor records"),
            Written::Recorded { .. }
        ));
    }

    // While the closed stream's terminal record is unshipped, it is what the
    // shipper sees; acknowledging it is what lets the successor be read.
    let terminal = everything(&journal);
    assert_eq!(terminal.len(), 1, "the terminal ships alone");
    assert_eq!(terminal[0]["kind"], json!("discontinuity"));
    let digest =
        permguard_decisions::record::digest_of(&terminal[0]).expect("the terminal digests");
    journal
        .acknowledge(terminal[0]["seq"].as_u64().expect("a seq"), &digest)
        .expect("the terminal is acknowledged");

    let records = everything(&journal);
    let verified = permguard_decisions::chain::verify(&records, None)
        .expect("the successor is a verifiable chain");
    assert!(
        verified.from_genesis,
        "a successor begins at its own genesis"
    );
    let kinds: Vec<&str> = records
        .iter()
        .map(|record| record["kind"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        kinds.first(),
        Some(&"marker"),
        "the marker opens the successor"
    );
    assert!(
        kinds.iter().filter(|kind| **kind == "decision").count() >= 3,
        "and the decisions written after the break follow it: {kinds:?}"
    );
}
