// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The event store, against a real key ring and a real disk.
//!
//! Every property here is one a producer's history depends on: it deletes events its own policies
//! read on the strength of the number this answers with, and an investigator later decides what
//! happened from what this kept.
//!
//! | | |
//! | --- | --- |
//! | a batch is stored, and acknowledged by its last sequence | |
//! | a replay is deduplicated and the acknowledgement does not move | |
//! | a shipper that ran ahead is told exactly where to resume | |
//! | two different records at one sequence fork the stream, permanently | |
//! | a producer class or event type nobody registered is refused before anything is stored | |
//! | a tenant reads a partition that physically holds only its own records | |
//! | listing one event type does not read the other types the ledger retains | |
//! | records are stored byte for byte, so their digests still verify | |

#![allow(clippy::expect_used)]

use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use permguard_control_plane::events::ingest::{self, Accepted, Batch, Refused};
use permguard_control_plane::events::read::{self, Filters};
use permguard_control_plane::events::store::{EventStore, Scope};
use permguard_core::{KeyId, KeyManager, Maintenance, Signature};
use permguard_events::envelope::{Envelope, Signed};
use permguard_events::record::{GENESIS, PRODUCER_CLASS_DATA_PLANE, Producer, Record, Stream};
use permguard_events::{chain, record};
use permguard_std::keys::{DirectoryKeyManager, KeyPolicy};
use serde_json::{Value, json};

const ZONE: &str = "acme";
const LEDGER: &str = "agent-governance";
const DOGWOOD: &str = "permguard.dogwood.event.v1";

fn scratch(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "permguard-event-store-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&root);

    root
}

fn ring(tag: &str) -> DirectoryKeyManager {
    let keys = DirectoryKeyManager::new(
        scratch(&format!("{tag}-keys")),
        KeyPolicy {
            publish_ahead: Duration::from_secs(0),
            rotate_every: Duration::from_secs(3600),
            retain: Duration::from_secs(3600),
            verify_retain: Duration::from_secs(7200),
        },
    );
    keys.maintain().expect("the ring produces a key");

    keys
}

struct AliasedRing<'a> {
    inner: &'a DirectoryKeyManager,
    kid: String,
}

impl KeyManager for AliasedRing<'_> {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn public_keys(&self) -> permguard_core::keys::Result<Vec<permguard_core::Jwk>> {
        self.inner.public_keys().map(|mut keys| {
            for key in &mut keys {
                key.kid.clone_from(&self.kid);
            }
            keys
        })
    }

    fn active_key_id(&self) -> permguard_core::keys::Result<KeyId> {
        Ok(KeyId::new(self.kid.clone()))
    }

    fn sign(&self, payload: &[u8]) -> permguard_core::keys::Result<Signature> {
        self.inner.sign(payload).map(|signature| {
            Signature::new(
                KeyId::new(self.kid.clone()),
                signature.algorithm(),
                signature.bytes().to_vec(),
            )
        })
    }

    fn maintain(&self) -> permguard_core::keys::Result<Maintenance> {
        self.inner.maintain()
    }
}

fn store(tag: &str) -> EventStore {
    EventStore::open(scratch(tag)).expect("the store opens")
}

fn stream(instance: &str) -> Stream {
    Stream {
        producer: Producer {
            class: PRODUCER_CLASS_DATA_PLANE.to_owned(),
            id: "plane-a".to_owned(),
            instance: instance.to_owned(),
        },
        zone: ZONE.to_owned(),
        ledger: LEDGER.to_owned(),
    }
}

/// A chain of `count` records, alternating between two event kinds.
fn records(instance: &str, count: u64, event_type: &str) -> Vec<Value> {
    let mut built = Vec::new();
    let mut prev = GENESIS.to_owned();
    for seq in 1..=count {
        let occurred = permguard_events::index::render_epoch_seconds(1_700_000_000 + seq as i64)
            .expect("an instant");
        let kind = if seq % 2 == 0 { "response" } else { "request" };
        let event = json!({
            "event_id": format!("{instance}-{seq}"),
            "kind": kind,
            "action": "Drupe::Action::Login",
            "principal": "Drupe::OAuthUser::\"alice\"",
            "resource": "Drupe::Gateway::\"gw1\"",
            "logged": {"input": {"user": "alice", "server": "s1"}},
            "request_context": {"input": {"user": "alice", "server": "s1"}},
            "occurred_at": occurred,
        });
        let held = Record {
            v: 1,
            record_type: permguard_events::RECORD_TYPE.to_owned(),
            stream: stream(instance),
            seq,
            prev: prev.clone(),
            event_type: event_type.to_owned(),
            event_id: format!("{instance}-{seq}"),
            occurrence_digest: permguard_events::occurrence_digest_of(&event)
                .expect("the occurrence digests"),
            kind: kind.to_owned(),
            profile: "temporal".to_owned(),
            policy_partitions: vec!["governance".to_owned()],
            commit: "sha256:commit".to_owned(),
            history_key: None,
            occurred_at: occurred,
            observed_at: "2026-08-28T10:15:30Z".to_owned(),
            event,
        };
        let value = held.to_value().expect("the record renders");
        prev = record::digest_of(&value).expect("it digests");
        built.push(value);
    }

    built
}

fn records_for(producer: &str, instance: &str, count: u64, event_type: &str) -> Vec<Value> {
    let mut held = records(instance, count, event_type);
    let mut previous = GENESIS.to_owned();
    for record in &mut held {
        record["stream"]["producer"]["id"] = json!(producer);
        record["prev"] = json!(previous);
        previous = record::digest_of(record).expect("it digests");
    }

    held
}

/// One signed batch over `records`, continuing from `previous_head`.
fn batch(held: &[Value], previous_head: &str, keys: &dyn KeyManager) -> Batch {
    let verified = chain::verify(held, Some(previous_head)).expect("the records chain");
    let mut event_types: Vec<String> = held
        .iter()
        .filter_map(|record| Some(record.get("event_type")?.as_str()?.to_owned()))
        .collect();
    event_types.sort();
    event_types.dedup();

    let envelope = Envelope {
        stream: verified.stream.clone(),
        first_seq: verified.first_seq,
        last_seq: verified.last_seq,
        count: held.len() as u64,
        previous_head: previous_head.to_owned(),
        head: verified.head.clone(),
        merkle_root: permguard_decisions::merkle::root(&verified.digests).expect("a root"),
        event_types,
        record_version: 1,
        at: "2026-08-28T10:15:30Z".to_owned(),
    };

    Batch {
        signature: Signed::create(&envelope, keys).expect("it signs"),
        records: held.to_vec(),
    }
}

fn published(keys: &dyn KeyManager) -> Vec<permguard_core::Jwk> {
    keys.public_keys().expect("the ring publishes")
}

fn trusted(keys: &dyn KeyManager, producer: &str) -> Vec<ingest::ProducerTrust> {
    published(keys)
        .into_iter()
        .map(|key| ingest::ProducerTrust {
            key,
            producer: producer.to_owned(),
            zone: ZONE.to_owned(),
            ledger: LEDGER.to_owned(),
        })
        .collect()
}

fn accept(store: &EventStore, batch: &Batch, keys: &dyn KeyManager) -> Result<Accepted, Refused> {
    let producer = batch
        .records
        .first()
        .and_then(|record| record["stream"]["producer"]["id"].as_str())
        .unwrap_or("plane-a");
    ingest::accept(store, batch, &trusted(keys, producer), &[DOGWOOD])
}

fn cursor_key() -> permguard_stream::CursorKey {
    permguard_stream::CursorKey::new(b"a-test-cursor-key-of-32-bytes!!!!", &[])
        .expect("the key is long enough")
}

fn tenant() -> Scope {
    Scope::Tenant {
        zone: ZONE.to_owned(),
        ledger: LEDGER.to_owned(),
    }
}

fn window(records: usize) -> permguard_stream::Window {
    permguard_stream::Window {
        limit_records: records,
        ..permguard_stream::Window::default()
    }
}

#[test]
fn a_batch_is_stored_and_acknowledged_by_its_last_sequence() {
    let (keys, store) = (ring("ok"), store("ok"));

    assert_eq!(
        accept(
            &store,
            &batch(&records("i-1", 10, DOGWOOD), GENESIS, &keys),
            &keys
        ),
        Ok(Accepted::Ok {
            acked: 10,
            stored: 10
        })
    );
}

#[test]
fn a_substituted_key_cannot_replace_the_envelope_before_its_kid_conflict_is_found() {
    let (first, second, store) = (
        ring("kid-order-first"),
        ring("kid-order-second"),
        store("kid-order"),
    );
    let held = records("i-1", 5, DOGWOOD);
    accept(&store, &batch(&held[..3], GENESIS, &first), &first)
        .expect("the original evidence is accepted");
    let envelope = store
        .stream_path(&stream("i-1"))
        .expect("the stream path")
        .join("batch-00000000000000000001.jws");
    let original = std::fs::read(&envelope).expect("the original envelope is durable");
    let kid = published(&first)[0].kid.clone();
    let substituted = AliasedRing {
        inner: &second,
        kid,
    };
    let forged = batch(&held, GENESIS, &substituted);

    let refused = ingest::accept(
        &store,
        &forged,
        &trusted(&substituted, "plane-a"),
        &[DOGWOOD],
    );
    assert!(
        matches!(&refused, Err(Refused::Unverifiable(detail)) if detail.contains("different public key")),
        "{refused:?}"
    );
    assert_eq!(
        std::fs::read(&envelope).expect("the original envelope still reads"),
        original,
        "a refused substitution must not replace retained signed evidence"
    );
    assert_eq!(
        store
            .stream_state(&stream("i-1"))
            .expect("the state reads")
            .acked,
        3
    );
}

#[test]
fn a_replayed_batch_is_deduplicated_and_the_acknowledgement_does_not_move() {
    let (keys, store) = (ring("replay"), store("replay"));
    let held = batch(&records("i-1", 10, DOGWOOD), GENESIS, &keys);
    accept(&store, &held, &keys).expect("the first time");

    assert_eq!(
        accept(&store, &held, &keys),
        Ok(Accepted::Ok {
            acked: 10,
            stored: 0
        }),
        "a producer that did not hear the answer and sent it again added nothing"
    );
}

#[test]
fn a_shipper_that_runs_ahead_is_told_exactly_where_to_resume() {
    let (keys, store) = (ring("ahead"), store("ahead"));
    let all = records("i-1", 10, DOGWOOD);
    accept(&store, &batch(&all[..4], GENESIS, &keys), &keys).expect("the first four");

    // The batch is well formed and continues from *its own* predecessor — record 7. What is
    // wrong is only that this store stands at 4, which is exactly the case the answer is about.
    let head = record::digest_of(&all[6]).expect("it digests");
    let ahead = batch(&all[7..], &head, &keys);

    assert_eq!(
        accept(&store, &ahead, &keys),
        Ok(Accepted::OutOfOrder { expected_seq: 5 }),
        "nothing is stored, and the shipper is told where the hole begins"
    );
}

/// The one refusal that never becomes a retry.
#[test]
fn two_different_records_at_one_sequence_close_the_stream_for_good() {
    let (keys, store) = (ring("fork"), store("fork"));
    let first = records("i-1", 4, DOGWOOD);
    accept(&store, &batch(&first, GENESIS, &keys), &keys).expect("the first batch");

    // A second history for the same stream: same sequences, different content.
    let mut forked = first.clone();
    forked[2]["event_id"] = json!("something-else");
    forked[2]["event"]["event_id"] = json!("something-else");
    forked[2]["occurrence_digest"] = json!(
        permguard_events::occurrence_digest_of(&forked[2]["event"])
            .expect("the changed occurrence digests")
    );
    // Re-chain it so the *only* thing wrong is that it disagrees with what is stored.
    let mut prev = record::digest_of(&forked[1]).expect("it digests");
    for record in forked.iter_mut().skip(2) {
        record["prev"] = json!(prev);
        prev = record::digest_of(record).expect("it digests");
    }

    assert_eq!(
        accept(&store, &batch(&forked, GENESIS, &keys), &keys),
        Err(Refused::Fork { seq: 3 })
    );
    // And it stays closed: what is held is evidence, and nothing is written on top of it.
    assert!(matches!(
        accept(&store, &batch(&first, GENESIS, &keys), &keys),
        Err(Refused::Closed(_))
    ));
}

#[test]
fn a_producer_class_this_release_does_not_accept_is_refused_before_anything_is_stored() {
    let (keys, store) = (ring("class"), store("class"));
    let mut held = records("i-1", 3, DOGWOOD);
    for record in &mut held {
        record["stream"]["producer"]["class"] = json!("acme.pip.v1");
    }
    // Re-chain, so the class is the only thing wrong.
    let mut prev = GENESIS.to_owned();
    for record in &mut held {
        record["prev"] = json!(prev);
        prev = record::digest_of(record).expect("it digests");
    }

    let refused = accept(&store, &batch(&held, GENESIS, &keys), &keys)
        .expect_err("a class nobody registered is not a producer");
    assert!(matches!(refused, Refused::Unregistered(_)), "{refused}");
    assert!(refused.to_string().contains(PRODUCER_CLASS_DATA_PLANE));
}

#[test]
fn an_event_type_this_store_does_not_accept_is_refused_before_anything_is_stored() {
    let (keys, store) = (ring("type"), store("type"));
    let held = records("i-1", 3, "acme.whatever.v1");

    let refused = ingest::accept(
        &store,
        &batch(&held, GENESIS, &keys),
        &trusted(&keys, "plane-a"),
        &[DOGWOOD],
    )
    .expect_err("a type is never inferred from a payload");
    assert!(matches!(refused, Refused::Unregistered(_)), "{refused}");
}

#[test]
fn a_valid_signature_cannot_impersonate_another_producer_or_tenant() {
    let (keys, store) = (ring("bound-trust"), store("bound-trust"));
    let held = records("i-1", 1, DOGWOOD);
    let signed = batch(&held, GENESIS, &keys);
    let key = published(&keys).into_iter().next().expect("a public key");

    for trust in [
        ingest::ProducerTrust {
            key: key.clone(),
            producer: "plane-b".to_owned(),
            zone: ZONE.to_owned(),
            ledger: LEDGER.to_owned(),
        },
        ingest::ProducerTrust {
            key: key.clone(),
            producer: "plane-a".to_owned(),
            zone: "another-zone".to_owned(),
            ledger: LEDGER.to_owned(),
        },
        ingest::ProducerTrust {
            key: key.clone(),
            producer: "plane-a".to_owned(),
            zone: ZONE.to_owned(),
            ledger: "another-ledger".to_owned(),
        },
    ] {
        let refused = ingest::accept(&store, &signed, &[trust], &[DOGWOOD])
            .expect_err("a key is not authority to claim another identity or tenant");
        assert!(matches!(refused, Refused::Unattributable(_)), "{refused}");
    }

    assert!(
        store
            .segments(&Scope::for_stream(&stream("i-1")))
            .expect("the scope reads")
            .is_empty(),
        "an unauthorized but cryptographically valid batch reached storage"
    );
}

/// Bytes in, bytes out: a record whose digest changed would be indistinguishable from tampering.
#[test]
fn records_are_stored_verbatim_so_their_digests_still_verify() {
    let (keys, store) = (ring("verbatim"), store("verbatim"));
    let held = records("i-1", 5, DOGWOOD);
    accept(&store, &batch(&held, GENESIS, &keys), &keys).expect("the batch");

    let page = read::read(
        &store,
        &tenant(),
        &Filters::default(),
        &cursor_key(),
        &window(100),
    )
    .expect("it reads");

    assert_eq!(page.records.len(), 5);
    for (stored, original) in page.records.iter().zip(&held) {
        assert_eq!(
            record::digest_of(stored).expect("it digests"),
            record::digest_of(original).expect("it digests"),
            "the store re-rendered a record it was told to keep verbatim"
        );
    }
    // And the chain still links across them, which is what `contiguous` claims.
    assert!(chain::verify(&page.records, Some(GENESIS)).is_ok());
}

#[test]
fn each_tenant_reads_a_partition_that_physically_holds_only_its_own_records() {
    let (keys, store) = (ring("tenants"), store("tenants"));
    accept(
        &store,
        &batch(&records("i-1", 6, DOGWOOD), GENESIS, &keys),
        &keys,
    )
    .expect("stored");

    // The other tenant's directory does not exist at all — the isolation is the filesystem's, not
    // a predicate somewhere in a read path.
    let elsewhere = store.view_path("globex", LEDGER).expect("a path");
    assert!(!elsewhere.exists());

    let page = read::read(
        &store,
        &tenant(),
        &Filters::default(),
        &cursor_key(),
        &window(100),
    )
    .expect("it reads");
    assert_eq!(page.records.len(), 6);
}

/// The whole point of the type index.
#[test]
fn listing_one_event_type_does_not_read_the_other_types_the_ledger_retains() {
    let (keys, store) = (ring("index"), store("index"));
    // One stream of one type, and a second stream of another, in the same ledger.
    accept(
        &store,
        &batch(&records("i-1", 40, DOGWOOD), GENESIS, &keys),
        &keys,
    )
    .expect("stored");

    let mut other = records("i-2", 4, DOGWOOD);
    for record in &mut other {
        record["event_type"] = json!("permguard.dogwood.event.v1");
    }

    let key = cursor_key();
    let filtered = read::read(
        &store,
        &tenant(),
        &Filters {
            event_types: vec![DOGWOOD.to_owned()],
            ..Filters::default()
        },
        &key,
        &window(5),
    )
    .expect("it reads");

    assert_eq!(filtered.records.len(), 5);
    // Through the index: exactly the positions of the requested type were opened, and not one
    // record more. A scan would have examined every position it passed.
    assert_eq!(
        filtered.coverage.examined, 5,
        "the index named the positions; nothing else was read"
    );
    assert!(
        !filtered.coverage.contiguous,
        "a filtered view is a subsequence, and its chain does not link across the gaps"
    );
}

/// A filter that matches nothing still advances, or a consumer stops in the middle of a ledger.
#[test]
fn a_page_that_matches_nothing_still_advances_and_says_there_is_more() {
    let (keys, store) = (ring("sparse"), store("sparse"));
    accept(
        &store,
        &batch(&records("i-1", 20, DOGWOOD), GENESIS, &keys),
        &keys,
    )
    .expect("stored");

    let key = cursor_key();
    // `response` records are the even sequences, so a page of two positions from the start
    // matches at most one — and a page bounded before any match matches none.
    let filters = Filters {
        kind: Some("response".to_owned()),
        ..Filters::default()
    };
    let page = read::read(&store, &tenant(), &filters, &key, &window(3)).expect("it reads");

    assert!(
        !page.next.is_empty(),
        "an empty or short page still advances"
    );
    assert!(
        page.more,
        "and it says so, rather than looking like the end"
    );
    let continued = read::read(
        &store,
        &tenant(),
        &filters,
        &key,
        &permguard_stream::Window {
            from: Some(page.next),
            ..window(3)
        },
    )
    .expect("it continues");
    assert!(
        continued
            .records
            .iter()
            .all(|record| !page.records.contains(record)),
        "continuing returns what has not been returned"
    );
}

/// A producer's local sequence is not a tenant-view position.
#[test]
fn a_new_producer_cannot_append_behind_a_tenant_cursor() {
    let (keys, store) = (ring("merged-position"), store("merged-position"));
    let first = records_for("plane-a", "i-a", 10_001, DOGWOOD);
    accept(&store, &batch(&first, GENESIS, &keys), &keys).expect("plane A is stored");

    let key = cursor_key();
    let mut from = None;
    loop {
        let page = read::read(
            &store,
            &tenant(),
            &Filters::default(),
            &key,
            &permguard_stream::Window {
                from,
                limit_records: 1_000,
                ..permguard_stream::Window::default()
            },
        )
        .expect("the first producer is read");
        from = Some(page.next);
        if !page.more {
            break;
        }
    }

    // Its first local sequence arrives after the cursor has passed plane A's sequence 10,001.
    // Filing this under producer sequence 1 would put it back in the first physical segment and
    // make every resumed reader miss it.
    let second = records_for("plane-b", "i-b", 1, DOGWOOD);
    accept(&store, &batch(&second, GENESIS, &keys), &keys).expect("plane B is stored");
    let page = read::read(
        &store,
        &tenant(),
        &Filters::default(),
        &key,
        &permguard_stream::Window { from, ..window(10) },
    )
    .expect("the tenant tail resumes");

    assert_eq!(
        page.records.len(),
        1,
        "the new producer was filed behind the cursor"
    );
    assert_eq!(page.records[0]["stream"]["producer"]["id"], "plane-b");
}

/// One occurrence, by the identifier its caller stated.
#[test]
fn one_occurrence_is_found_by_its_identifier_and_absence_is_an_answer() {
    let (keys, store) = (ring("get"), store("get"));
    accept(
        &store,
        &batch(&records("i-1", 12, DOGWOOD), GENESIS, &keys),
        &keys,
    )
    .expect("stored");

    let key = cursor_key();
    let found = read::get(&store, &tenant(), "i-1-7", &key).expect("it reads");
    assert_eq!(
        found
            .as_ref()
            .and_then(|record| record.get("event_id"))
            .and_then(Value::as_str),
        Some("i-1-7")
    );

    assert_eq!(
        read::get(&store, &tenant(), "nothing-like-this", &key).expect("it reads"),
        None,
        "a search over a growing ledger concludes rather than running forever"
    );
}

/// A tenant verifies with inclusion paths, because its page is a subsequence.
#[test]
fn a_reader_that_asks_for_proof_gets_the_envelope_and_a_path_per_record() {
    let (keys, store) = (ring("proof"), store("proof"));
    accept(
        &store,
        &batch(&records("i-1", 6, DOGWOOD), GENESIS, &keys),
        &keys,
    )
    .expect("stored");

    let page = read::read(
        &store,
        &tenant(),
        &Filters::default(),
        &cursor_key(),
        &permguard_stream::Window {
            proof: true,
            ..window(100)
        },
    )
    .expect("it reads");

    assert_eq!(page.proof.len(), 1, "one batch covered these records");
    assert_eq!(page.inclusion.len(), page.records.len());
    // And each path actually reaches the root the signed envelope attests.
    for (record, path) in page.records.iter().zip(&page.inclusion) {
        let leaf = path.get("leaf").and_then(Value::as_str).expect("a leaf");
        assert_eq!(leaf, record::digest_of(record).expect("it digests"));
        let root = path.get("root").and_then(Value::as_str).expect("a root");
        let steps: Vec<permguard_decisions::merkle::Step> =
            serde_json::from_value(path.get("path").expect("a path").clone()).expect("steps");
        assert_eq!(
            permguard_decisions::merkle::recompute(leaf, &steps),
            root,
            "the path does not reach the root its envelope signed"
        );
    }
}

#[test]
fn a_proof_request_fails_closed_when_its_envelope_is_damaged() {
    let (keys, store) = (ring("proof-damaged"), store("proof-damaged"));
    accept(
        &store,
        &batch(&records("i-1", 2, DOGWOOD), GENESIS, &keys),
        &keys,
    )
    .expect("stored");
    let directory = store.stream_path(&stream("i-1")).expect("a stream path");
    let envelope = std::fs::read_dir(&directory)
        .expect("the stream reads")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("batch-"))
        })
        .expect("the envelope exists");
    std::fs::write(&envelope, b"{not an envelope").expect("the envelope is damaged");

    let refused = read::read(
        &store,
        &tenant(),
        &Filters::default(),
        &cursor_key(),
        &permguard_stream::Window {
            proof: true,
            ..window(100)
        },
    )
    .expect_err("a proof is never returned incomplete");
    assert!(matches!(refused, read::ReadError::Unavailable(_)));
}

#[test]
fn a_finite_export_keeps_its_snapshot_when_a_new_producer_arrives() {
    let (keys, store) = (ring("snapshot"), store("snapshot"));
    let first = records_for("plane-a", "i-a", 5, DOGWOOD);
    accept(&store, &batch(&first, GENESIS, &keys), &keys).expect("plane A is stored");

    let key = cursor_key();
    let first_page = read::read(&store, &tenant(), &Filters::default(), &key, &window(2))
        .expect("the snapshot starts");
    let bound = permguard_stream::Frontier::decode(&first_page.high_watermark)
        .expect("the watermark is a frontier");

    let newcomer = records_for("plane-b", "i-b", 1, DOGWOOD);
    accept(&store, &batch(&newcomer, GENESIS, &keys), &keys).expect("plane B is stored");

    let mut from = Some(first_page.next);
    let mut exported = first_page.records;
    loop {
        let page = read::read(
            &store,
            &tenant(),
            &Filters::default(),
            &key,
            &permguard_stream::Window {
                from,
                until: Some(bound.clone()),
                limit_records: 2,
                ..permguard_stream::Window::default()
            },
        )
        .expect("the snapshot continues");
        assert_eq!(
            permguard_stream::Frontier::decode(&page.high_watermark),
            Some(bound.clone()),
            "later pages must not replace the captured end with a moving one"
        );
        exported.extend(page.records);
        from = Some(page.next);
        if !page.more {
            break;
        }
    }

    assert_eq!(exported.len(), 5);
    assert!(exported.iter().all(|record| {
        record["stream"]["producer"]["id"] == serde_json::Value::String("plane-a".to_owned())
    }));
}

#[test]
fn a_lost_tenant_view_state_is_rebuilt_from_acknowledged_streams() {
    let (keys, store) = (ring("view-recovery"), store("view-recovery"));
    accept(
        &store,
        &batch(&records("i-1", 4, DOGWOOD), GENESIS, &keys),
        &keys,
    )
    .expect("stored");
    let root = store.root().to_path_buf();
    let view_state = store
        .view_path(ZONE, LEDGER)
        .expect("the view path")
        .join("VIEW_STATE");
    std::fs::remove_file(&view_state).expect("the derived state is lost");
    drop(store);

    let reopened = EventStore::open(root).expect("the store reopens");
    let page = read::read(
        &reopened,
        &tenant(),
        &Filters::default(),
        &cursor_key(),
        &window(100),
    )
    .expect("the derived state is rebuilt");
    assert_eq!(
        page.records.len(),
        4,
        "acknowledged history must not disappear until another ingest happens"
    );
}

#[test]
fn a_stale_tenant_view_commit_is_reconciled_with_the_producer_ack_after_restart() {
    let (keys, store) = (ring("view-stale"), store("view-stale"));
    accept(
        &store,
        &batch(&records("i-1", 4, DOGWOOD), GENESIS, &keys),
        &keys,
    )
    .expect("stored");
    let root = store.root().to_path_buf();
    let view_state = store
        .view_path(ZONE, LEDGER)
        .expect("the view path")
        .join("VIEW_STATE");
    let mut stale: Value = serde_json::from_slice(
        &std::fs::read(&view_state).expect("the committed view state reads"),
    )
    .expect("the committed view state parses");
    stale["committed"] = json!(0);
    std::fs::write(
        &view_state,
        serde_json::to_vec_pretty(&stale).expect("the stale state renders"),
    )
    .expect("the crash leaves the old tenant commit behind");
    drop(store);

    let reopened = EventStore::open(root).expect("the store reconciles its derived view");
    let page = read::read(
        &reopened,
        &tenant(),
        &Filters::default(),
        &cursor_key(),
        &window(100),
    )
    .expect("the acknowledged tenant history reads");
    assert_eq!(page.records.len(), 4);
}

#[test]
fn an_unacknowledged_tenant_suffix_is_discarded_after_restart() {
    let store = store("view-unacked");
    let root = store.root().to_path_buf();
    let records = records("i-1", 4, DOGWOOD);
    let references: Vec<&Value> = records.iter().collect();
    store
        .append_batch(&stream("i-1"), &references)
        .expect("the crash-window writes land but are not acknowledged");
    drop(store);

    let reopened = EventStore::open(root).expect("the store removes scratch tenant rows");
    let page = read::read(
        &reopened,
        &tenant(),
        &Filters::default(),
        &cursor_key(),
        &window(100),
    )
    .expect("the tenant view remains readable");
    assert!(
        page.records.is_empty(),
        "a producer that was never acknowledged still owns and must resend those records"
    );
}

#[test]
fn torn_segment_tails_are_truncated_before_restart_recovery() {
    let store = store("torn-segment");
    let root = store.root().to_path_buf();
    let held = records("i-1", 4, DOGWOOD);
    let references: Vec<&Value> = held.iter().collect();
    store
        .append_batch(&stream("i-1"), &references)
        .expect("the crash-window writes land");

    for scope in [Scope::for_stream(&stream("i-1")), tenant()] {
        let path = store
            .segments(&scope)
            .expect("the scope lists")
            .last()
            .expect("it has a segment")
            .1
            .clone();
        let mut segment = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("the segment opens");
        segment
            .write_all(br#"{"event_id":"interrupted"#)
            .expect("the interrupted append lands");
        segment.sync_all().expect("the crash bytes reach disk");
    }
    drop(store);

    let reopened = EventStore::open(root).expect("the torn tails are recovered");
    let page = read::read(
        &reopened,
        &tenant(),
        &Filters::default(),
        &cursor_key(),
        &window(100),
    )
    .expect("the recovered tenant view reads");
    assert!(
        page.records.is_empty(),
        "the complete but unacknowledged records remain producer-owned, and the partial row is \
         never treated as one"
    );
}

#[test]
fn a_complete_corrupt_segment_line_is_not_erased_as_a_torn_write() {
    let store = store("corrupt-segment");
    let root = store.root().to_path_buf();
    let held = records("i-1", 1, DOGWOOD);
    let references: Vec<&Value> = held.iter().collect();
    store
        .append_batch(&stream("i-1"), &references)
        .expect("one complete row lands");
    let path = store
        .segments(&tenant())
        .expect("the view lists")
        .last()
        .expect("it has a segment")
        .1
        .clone();
    let mut segment = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("the segment opens");
    segment
        .write_all(b"this is not an event record\n")
        .expect("the damaged line lands");
    segment.sync_all().expect("the damaged line reaches disk");
    drop(store);

    let error = match EventStore::open(root) {
        Ok(_) => panic!("complete corruption must stop the store"),
        Err(error) => error,
    };
    assert!(
        format!("{error:#}").contains("complete record"),
        "the operator is told this was durable corruption, not a recoverable torn tail: {error:#}"
    );
}

/// The key that signed is archived, so a batch stays verifiable after a rotation.
#[test]
fn the_key_that_signed_is_archived_beside_what_it_attests() {
    let (keys, store) = (ring("archive"), store("archive"));
    accept(
        &store,
        &batch(&records("i-1", 3, DOGWOOD), GENESIS, &keys),
        &keys,
    )
    .expect("stored");

    let archived = store.archived_keys().expect("it reads");
    assert!(!archived.is_empty());
    let published = published(&keys);
    assert!(
        archived
            .iter()
            .any(|held| published.iter().any(|key| key.kid == held.kid)),
        "the key a batch was signed under is kept, or that batch stops verifying when it rotates"
    );
}

/// A producer whose id could escape its own directory is refused rather than sanitised.
#[test]
fn a_producer_name_that_is_not_a_directory_name_is_refused() {
    let store = store("escape");
    let escaping = Stream {
        producer: Producer {
            class: PRODUCER_CLASS_DATA_PLANE.to_owned(),
            id: "../../etc".to_owned(),
            instance: "i-1".to_owned(),
        },
        zone: ZONE.to_owned(),
        ledger: LEDGER.to_owned(),
    };

    assert!(
        store.stream_path(&escaping).is_err(),
        "a sanitised name is a different name, and two producers could sanitise to one"
    );
}

/// A key id is a producer-local label, not a globally unique key identity.
///
/// Archiving keeps the key a batch was signed under, so that batch still verifies after the
/// producer has rotated. Two independent producers are allowed to choose the same label; the
/// content-addressed archive must keep both materials.
#[test]
fn the_archive_keeps_two_different_keys_under_one_key_id() {
    let store = EventStore::open(scratch("kid-collision")).expect("the store opens");
    let first_ring = ring("kid-collision-a");
    let other = ring("kid-collision-b");
    let first = published(&first_ring)
        .into_iter()
        .next()
        .expect("a published key");
    let mut second = published(&other)
        .into_iter()
        .next()
        .expect("a published key");
    second.kid.clone_from(&first.kid);
    assert_ne!(first, second, "two rings, two keys, one claimed id");

    store.archive_key(&first).expect("the first is archived");
    // Archiving the same key again is the ordinary case and stays quiet.
    store
        .archive_key(&first)
        .expect("the same key twice is not a conflict");

    store
        .archive_key(&second)
        .expect("another producer may reuse the label");

    // Both remain available to verify old evidence; a verifier uses the signature to select.
    let held = store.archived_keys().expect("the archive reads");
    assert_eq!(held.len(), 2);
    assert!(held.contains(&first));
    assert!(held.contains(&second));

    std::fs::write(
        store
            .root()
            .join(permguard_control_plane::events::store::KEYS_DIRECTORY)
            .join(".key.json.writing-123"),
        b"partial",
    )
    .expect("the crash remnant is written");
    assert_eq!(
        store
            .archived_keys()
            .expect("an uncommitted staging file is ignored")
            .len(),
        2
    );

    // A damaged archive is an error, not an empty archive: skipping it would report a corruption
    // as somebody else's bad signature.
    let path = store
        .root()
        .join(permguard_control_plane::events::store::KEYS_DIRECTORY)
        .join("broken.json");
    std::fs::write(&path, b"{ not json").expect("the file is written");
    assert!(
        store.archived_keys().is_err(),
        "an unreadable archived key fails closed rather than vanishing"
    );
}

/// The retention window is enforced by something that runs, not only by a number in a file.
///
/// `sweep` was written and nothing ever called it: the plane registered the decision store's
/// retention service and not the event store's, so `controlPlane.events.retention` was read at
/// startup and never used again. A deployment would have found out when the volume filled.
#[test]
fn the_event_store_sweeps_what_is_past_its_retention_window() {
    let (keys, store) = (ring("retention-sweep"), store("retention-sweep"));
    let all = records("i-1", 10_001, DOGWOOD);
    accept(&store, &batch(&all[..10_000], GENESIS, &keys), &keys)
        .expect("the first batch is stored");
    let head = record::digest_of(&all[9_999]).expect("the first batch has a head");
    accept(&store, &batch(&all[10_000..], &head, &keys), &keys)
        .expect("the second batch is stored");

    let held =
        permguard_control_plane::events::retention::sweep_once(&store, Duration::from_secs(3600))
            .expect("the sweep runs");
    assert_eq!(
        held.segments, 0,
        "nothing here is an hour old, so nothing leaves: {held:?}"
    );

    // Past a zero-length window, everything but the segment still being appended to may go.
    let swept =
        permguard_control_plane::events::retention::sweep_once(&store, Duration::from_secs(0))
            .expect("the sweep runs");
    assert_eq!(
        swept.segments, 2,
        "the tenant prefix and its producer copy leave together"
    );
    assert_eq!(
        store
            .segments(&Scope::for_stream(&stream("i-1")))
            .expect("the producer reads")
            .len(),
        1,
        "producer streams do not grow without bound behind retained tenant views"
    );

    // What survives is still readable: a sweep that removed segments rebuilds the index rather
    // than leaving it naming positions inside files that are gone.
    let page = read::read(
        &store,
        &tenant(),
        &Filters::default(),
        &cursor_key(),
        &window(100),
    )
    .expect("the tenant still reads");
    assert!(
        !page.records.is_empty(),
        "the newest segment is never swept, so a reader still finds the latest records: {swept:?}"
    );
}

/// A record larger than the byte bound is still returned, rather than a page nothing can fill.
///
/// Both bounds are ceilings on what a page carries. Applied naively, a record larger than the byte
/// bound is a record no page can ever include: every read returns nothing, advances nowhere, and a
/// consumer walks the same position for ever. A page that carries one record over its byte bound
/// is the only answer that keeps the stream readable.
#[test]
fn a_record_larger_than_the_byte_bound_is_still_returned() {
    let (keys, store) = (ring("oversize"), store("oversize"));
    let held = records("i-1", 3, DOGWOOD);
    accept(&store, &batch(&held, GENESIS, &keys), &keys).expect("the batch is stored");

    // One byte: every record this store holds is larger than the bound.
    let page = read::read(
        &store,
        &tenant(),
        &Filters::default(),
        &cursor_key(),
        &permguard_stream::Window {
            limit_bytes: 1,
            ..window(100)
        },
    )
    .expect("it reads");

    assert_eq!(
        page.records.len(),
        1,
        "one record over the bound, rather than a page that can never be filled"
    );
    assert!(!page.next.is_empty(), "and the position moved past it");

    // And the next read continues rather than repeating.
    let second = read::read(
        &store,
        &tenant(),
        &Filters::default(),
        &cursor_key(),
        &permguard_stream::Window {
            limit_bytes: 1,
            from: Some(page.next.clone()),
            ..window(100)
        },
    )
    .expect("it reads");
    assert_eq!(second.records.len(), 1);
    assert_ne!(
        second.records[0], page.records[0],
        "a consumer that kept reading would otherwise walk one position for ever"
    );
}

/// One process owns a store; the second is refused rather than corrupting it.
///
/// The per-stream gate inside the store serialises ingest *within* one process. It says nothing
/// about a second process opening the same directory — two planes pointed at one volume, a rolling
/// restart whose old pod has not exited — and each would hold its own gate while interleaving the
/// read-check-append that ingest is.
#[test]
fn a_second_process_cannot_open_a_store_another_one_holds() {
    let root = scratch("exclusive");
    let held = EventStore::open(&root).expect("the first opens it");

    let refused = match EventStore::open(&root) {
        Ok(_) => panic!("the second open should be refused"),
        Err(error) => error,
    };
    let message = format!("{refused:#}");
    assert!(
        message.contains("another process"),
        "the refusal says who has it: {message}"
    );

    // Released when the owner is done, so a restart is not locked out by its own predecessor.
    drop(held);
    EventStore::open(&root).expect("the store reopens once nobody holds it");
}

/// An unreadable scope is an error, never an empty one.
///
/// The dangerous shape it replaces: every failure to list a scope collapsed into "no segments", so
/// a store that could not read itself answered "this ledger is empty" — to a reader, to retention,
/// and to a sweep that would then believe there was nothing to keep.
#[test]
fn a_damaged_index_is_reported_rather_than_read_as_no_such_events() {
    let (keys, store) = (ring("damaged"), store("damaged"));
    accept(
        &store,
        &batch(&records("i-1", 4, DOGWOOD), GENESIS, &keys),
        &keys,
    )
    .expect("the batch is stored");

    // A scope that has never been written to is legitimately empty.
    let empty = permguard_control_plane::events::store::segments_in(
        &store.root().join("views").join("nobody"),
    )
    .expect("an absent scope is empty, not an error");
    assert!(empty.is_empty());

    // A damaged index entry is not a missing one: answering "no such events" about events the
    // segments hold is a wrong answer rather than an unavailable one.
    let directory = store.scope_path(&tenant()).expect("a scope path");
    let index = directory.join("index");
    let entry = std::fs::read_dir(&index)
        .expect("the index exists")
        .next()
        .expect("it has an entry")
        .expect("it reads")
        .path();
    std::fs::write(&entry, b"this is not a position\n").expect("it is written");

    let refused = read::read(
        &store,
        &tenant(),
        &Filters {
            event_types: vec![DOGWOOD.to_owned()],
            ..Filters::default()
        },
        &cursor_key(),
        &window(100),
    );
    assert!(
        refused.is_err(),
        "a damaged index fails closed rather than reporting an empty ledger"
    );
}
