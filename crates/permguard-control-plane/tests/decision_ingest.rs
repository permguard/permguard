// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The ingestion contract, exercised against a real key ring and a real disk.
//!
//! Every property here is one a producer's recovery depends on: it deletes its
//! only other copy of a record on the strength of the number this answers with.

#![allow(clippy::expect_used)]

use std::path::PathBuf;
use std::time::Duration;

use permguard_control_plane::decisions::store::Scope;
use permguard_control_plane::decisions::{Accepted, DecisionStore, Refused, ingest, read};
use permguard_core::KeyManager;
use permguard_decisions::envelope::{Batch, Envelope, Signed};
use permguard_decisions::record::{
    ActionRef, Body, Build, Commitments, DecisionBody, GENESIS, Inputs, MarkerBody, Party, Reason,
    Record, Sampling, StoreRef, Stream, VERSION,
};
use permguard_decisions::{chain, merkle, record};
use permguard_std::keys::{DirectoryKeyManager, KeyPolicy};
use serde_json::{Value, json};

fn scratch(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "permguard-ingest-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or_default()
    ));
    let _ = std::fs::remove_dir_all(&root);

    root
}

fn ring(tag: &str) -> DirectoryKeyManager {
    let keys = DirectoryKeyManager::new(
        scratch(tag),
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

fn store(tag: &str) -> DecisionStore {
    DecisionStore::open(scratch(tag)).expect("the store opens")
}

/// A stream of `count` records: a marker, then decisions alternating tenants.
fn stream(instance: &str, count: u64) -> Vec<Value> {
    let mut records = Vec::new();
    let mut prev = GENESIS.to_owned();
    for seq in 1..=count {
        let body = if seq == 1 {
            Body::Marker(Box::new(MarkerBody {
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
            }))
        } else {
            let zone = if seq.is_multiple_of(2) {
                "acme"
            } else {
                "other"
            };
            Body::Decision(Box::new(DecisionBody {
                id: format!("id-{seq}"),
                pdp: Build {
                    version: "0.1.0".to_owned(),
                    build: None,
                    engines: None,
                },
                store: StoreRef {
                    zone: zone.to_owned(),
                    ledger: "main-ledger".to_owned(),
                    commit: "sha256:ec1773bf".to_owned(),
                    counter: 3,
                    profile: "default".to_owned(),
                },
                subject: Party {
                    kind: "User".to_owned(),
                    id: "pseudo:v1:9f2c".to_owned(),
                    properties: None,
                },
                resource: Party {
                    kind: "Document".to_owned(),
                    id: "budget".to_owned(),
                    properties: None,
                },
                action: ActionRef {
                    name: "read".to_owned(),
                },
                principal: None,
                inputs: Inputs::default(),
                decision: true,
                policies: vec!["af4c4260".to_owned()],
                reason: Reason {
                    code: "200".to_owned(),
                },
                trace: None,
                request_id: None,
                context: None,
                latency_us: 143,
            }))
        };
        let value = Record {
            v: VERSION,
            stream: Stream::new("plane", instance),
            seq,
            prev: prev.clone(),
            at: "2026-08-24T10:00:00Z".to_owned(),
            body,
        };
        prev = value.digest().expect("it digests");
        records.push(value.to_value().expect("it renders"));
    }

    records
}

fn batch(records: &[Value], previous_head: &str, keys: &DirectoryKeyManager) -> Batch {
    let verified = chain::verify(records, None).expect("it is a chain");
    let leaves: Vec<String> = records
        .iter()
        .map(|value| record::digest_of(value).expect("it digests"))
        .collect();
    let envelope = Envelope {
        stream: verified.stream,
        first_seq: verified.first_seq,
        last_seq: verified.last_seq,
        count: records.len() as u64,
        previous_head: previous_head.to_owned(),
        head: verified.head,
        merkle_root: merkle::root(&leaves).expect("a root"),
        sampling: Sampling {
            permits: "1.0".to_owned(),
        },
        at: "2026-08-24T10:00:01Z".to_owned(),
    };

    Batch {
        signature: Signed::create(&envelope, keys).expect("it signs"),
        records: records.to_vec(),
    }
}

fn published(keys: &DirectoryKeyManager) -> Vec<permguard_core::Jwk> {
    keys.public_keys().expect("published")
}

#[test]
fn a_batch_is_stored_and_acknowledged_by_its_last_sequence() {
    let (keys, store) = (ring("ok"), store("ok"));
    let records = stream("inst", 10);

    assert_eq!(
        ingest::accept(&store, &batch(&records, GENESIS, &keys), &published(&keys)),
        Ok(Accepted::Ok {
            acked: 10,
            stored: 10
        })
    );
}

#[test]
fn a_replayed_batch_is_deduplicated_and_the_acknowledgement_does_not_move() {
    let (keys, store) = (ring("replay"), store("replay"));
    let records = stream("inst", 10);
    let batch = batch(&records, GENESIS, &keys);
    ingest::accept(&store, &batch, &published(&keys)).expect("it is accepted");

    // The producer did not hear the answer and sent it again.
    assert_eq!(
        ingest::accept(&store, &batch, &published(&keys)),
        Ok(Accepted::Ok {
            acked: 10,
            stored: 0
        }),
        "at-least-once delivery must not become at-least-once storage"
    );
    let page = read::page(
        &store,
        &Scope::Stream {
            pdp_id: "plane".to_owned(),
            instance: "inst".to_owned(),
        },
        None,
        1_000,
    )
    .expect("it reads");
    assert_eq!(page.records.len(), 10, "and nothing was stored twice");
}

#[test]
fn a_shipper_that_runs_ahead_is_told_exactly_where_to_resume() {
    let (keys, store) = (ring("ahead"), store("ahead"));
    let records = stream("inst", 20);
    ingest::accept(
        &store,
        &batch(&records[..5], GENESIS, &keys),
        &published(&keys),
    )
    .expect("the first five are accepted");

    let head_of_five = record::digest_of(&records[4]).expect("it digests");
    assert_eq!(
        ingest::accept(
            &store,
            &batch(&records[10..], &head_of_five, &keys),
            &published(&keys)
        ),
        Ok(Accepted::OutOfOrder { expected_seq: 6 }),
        "a gap is never skipped past"
    );

    let page = read::page(
        &store,
        &Scope::Stream {
            pdp_id: "plane".to_owned(),
            instance: "inst".to_owned(),
        },
        None,
        1_000,
    )
    .expect("it reads");
    assert_eq!(
        page.records.len(),
        5,
        "and nothing of the later batch was stored"
    );
}

#[test]
fn two_different_records_at_one_sequence_close_the_stream_for_good() {
    let (keys, store) = (ring("conflict"), store("conflict"));
    let records = stream("inst", 5);
    ingest::accept(&store, &batch(&records, GENESIS, &keys), &published(&keys))
        .expect("it is accepted");

    // A second producer — or an attacker — with the same stream identity.
    let mut forged = records.clone();
    forged[3]["at"] = json!("2030-01-01T00:00:00Z");
    // Rebuild the chain so the batch is internally valid: the conflict must be
    // caught by what is *stored*, not by the chain check.
    let mut prev = record::digest_of(&forged[2]).expect("it digests");
    for value in forged.iter_mut().skip(3) {
        value["prev"] = json!(prev);
        prev = record::digest_of(value).expect("it digests");
    }

    assert_eq!(
        ingest::accept(&store, &batch(&forged, GENESIS, &keys), &published(&keys)),
        Err(Refused::Conflict { seq: 4 })
    );

    // And it is terminal: nothing further is accepted, ever.
    assert!(
        matches!(
            ingest::accept(&store, &batch(&records, GENESIS, &keys), &published(&keys)),
            Err(Refused::Closed(_))
        ),
        "repairing history would be indistinguishable from an attacker doing the same"
    );
}

#[test]
fn a_batch_that_does_not_continue_the_stored_stream_is_refused() {
    // The link a per-batch check cannot see: each batch is internally perfect,
    // the sequence numbers run on, and the digests do not join. A store that
    // checked only sequence would accept a producer's history being replaced
    // with a different, equally well-formed one.
    let (keys, store) = (ring("continuity"), store("continuity"));
    let ours = stream("inst", 10);
    ingest::accept(
        &store,
        &batch(&ours[..5], GENESIS, &keys),
        &published(&keys),
    )
    .expect("the first five are accepted");

    // A second history for the same stream: the same sequence numbers, an
    // internally perfect chain, and different records.
    let mut theirs = stream("inst", 10);
    let mut prev = GENESIS.to_owned();
    for value in &mut theirs {
        value["at"] = json!("2030-01-01T00:00:00Z");
        value["prev"] = json!(prev);
        prev = record::digest_of(value).expect("it digests");
    }
    let forged = theirs[5..].to_vec();
    let head_of_five = record::digest_of(&ours[4]).expect("it digests");
    assert!(
        matches!(
            ingest::accept(
                &store,
                &batch(&forged, &head_of_five, &keys),
                &published(&keys)
            ),
            Err(Refused::Unverifiable(_))
        ),
        "the first record of the batch names a predecessor this store does not hold"
    );

    // And the envelope's own claim is checked too, not only the records: these
    // records do continue what is stored, and the signed envelope says they
    // continue the genesis. A producer must not be able to attest one history
    // and ship another.
    assert!(
        matches!(
            ingest::accept(
                &store,
                &batch(&ours[5..], GENESIS, &keys),
                &published(&keys)
            ),
            Err(Refused::Unverifiable(_))
        ),
        "an envelope that says it continues the genesis does not continue sequence 5"
    );
}

#[test]
fn a_batch_that_does_continue_it_is_accepted() {
    let (keys, store) = (ring("joins"), store("joins"));
    let records = stream("inst", 10);
    ingest::accept(
        &store,
        &batch(&records[..5], GENESIS, &keys),
        &published(&keys),
    )
    .expect("the first five are accepted");

    let head_of_five = record::digest_of(&records[4]).expect("it digests");
    assert_eq!(
        ingest::accept(
            &store,
            &batch(&records[5..], &head_of_five, &keys),
            &published(&keys)
        ),
        Ok(Accepted::Ok {
            acked: 10,
            stored: 5
        }),
        "the ordinary case still works: the batches join"
    );
}

#[test]
fn a_batch_nobody_can_attribute_is_refused_before_anything_is_stored() {
    let (ours, theirs, store) = (ring("ours"), ring("theirs"), store("unattributable"));
    let records = stream("inst", 4);

    assert!(matches!(
        ingest::accept(
            &store,
            &batch(&records, GENESIS, &theirs),
            &published(&ours)
        ),
        Err(Refused::Unattributable(_))
    ));

    let page = read::page(
        &store,
        &Scope::Stream {
            pdp_id: "plane".to_owned(),
            instance: "inst".to_owned(),
        },
        None,
        10,
    )
    .expect("it reads");
    assert!(page.records.is_empty());
}

#[test]
fn an_envelope_that_does_not_describe_its_own_records_is_refused() {
    let (keys, store) = (ring("mismatch"), store("mismatch"));
    let records = stream("inst", 6);
    let mut batch = batch(&records, GENESIS, &keys);
    // The signature still verifies — it covers the envelope. What fails is that
    // the envelope no longer describes what came with it.
    batch.records.pop();

    assert!(matches!(
        ingest::accept(&store, &batch, &published(&keys)),
        Err(Refused::Unverifiable(_))
    ));
}

#[test]
fn the_key_that_signed_is_archived_beside_what_it_attests() {
    let (keys, store) = (ring("archive"), store("archive"));
    ingest::accept(
        &store,
        &batch(&stream("inst", 3), GENESIS, &keys),
        &published(&keys),
    )
    .expect("it is accepted");

    let archived = store.archived_keys().expect("it lists");
    assert_eq!(
        archived.len(),
        1,
        "a batch signed today must verify in 2031"
    );
    assert_eq!(archived[0].kid, published(&keys)[0].kid);
}

#[test]
fn each_tenant_reads_a_partition_that_physically_holds_only_its_own_records() {
    let (keys, store) = (ring("views"), store("views"));
    ingest::accept(
        &store,
        &batch(&stream("inst", 11), GENESIS, &keys),
        &published(&keys),
    )
    .expect("it is accepted");

    let view = |zone: &str| {
        read::page(
            &store,
            &Scope::Tenant {
                zone: zone.to_owned(),
                ledger: "main-ledger".to_owned(),
            },
            None,
            1_000,
        )
        .expect("it reads")
        .records
    };

    let acme = view("acme");
    assert!(
        acme.iter()
            .filter(|record| record["kind"] == json!("decision"))
            .all(|record| record["store"]["zone"] == json!("acme")),
        "a partition cannot leak what it does not contain"
    );
    assert!(
        !view("other").is_empty(),
        "and the other tenant has its own"
    );

    // The epoch that governs these records is in the tenant's own view: without
    // it the tenant holds records whose completeness claim it cannot read.
    assert_eq!(
        acme.first().map(|record| record["kind"].clone()),
        Some(json!("marker")),
        "stream-level records belong in every view"
    );
    assert_eq!(acme[0]["sampling"]["permits"], json!("1.0"));
}

#[test]
fn an_offset_from_one_tenant_is_refused_under_another() {
    let (keys, store) = (ring("offsets"), store("offsets"));
    ingest::accept(
        &store,
        &batch(&stream("inst", 11), GENESIS, &keys),
        &published(&keys),
    )
    .expect("it is accepted");

    let acme = Scope::Tenant {
        zone: "acme".to_owned(),
        ledger: "main-ledger".to_owned(),
    };
    let other = Scope::Tenant {
        zone: "other".to_owned(),
        ledger: "main-ledger".to_owned(),
    };
    let page = read::page(&store, &acme, None, 2).expect("it reads");

    assert!(
        read::page(&store, &other, Some(&page.next), 2).is_err(),
        "an offset is bound to the scope that issued it"
    );
    let continued = read::page(&store, &acme, Some(&page.next), 100).expect("it continues");
    assert!(
        continued
            .records
            .iter()
            .all(|record| !page.records.contains(record)),
        "and continuing returns what has not been returned"
    );
}

/// Records that reached the disk and were never acknowledged.
///
/// Exactly what `DecisionStore::append` leaves behind when the process dies
/// before `acknowledge`: the lines are there, `STATE` still says nothing about
/// them, and the producer has not been told anything.
fn appended_without_acknowledging(store: &DecisionStore, records: &[Value]) {
    for value in records {
        store
            .append("plane", "inst", value)
            .expect("the store appends");
    }
}

fn stream_page(store: &DecisionStore) -> Vec<Value> {
    read::page(
        store,
        &Scope::Stream {
            pdp_id: "plane".to_owned(),
            instance: "inst".to_owned(),
        },
        None,
        1_000,
    )
    .expect("it reads")
    .records
}

#[test]
fn a_batch_retried_after_a_crash_between_append_and_acknowledge_is_stored_once() {
    let (keys, store) = (ring("crash-retry"), store("crash-retry"));
    let records = stream("inst", 6);
    appended_without_acknowledging(&store, &records);

    // The producer heard nothing, so it ships the same batch again.
    assert_eq!(
        ingest::accept(&store, &batch(&records, GENESIS, &keys), &published(&keys)),
        Ok(Accepted::Ok {
            acked: 6,
            stored: 6
        })
    );
    let stored = stream_page(&store);
    assert_eq!(
        stored.len(),
        6,
        "a crash before the acknowledgement must not turn one record into two"
    );
    let sequences: Vec<u64> = stored
        .iter()
        .map(|record| record["seq"].as_u64().unwrap_or_default())
        .collect();
    assert_eq!(
        sequences,
        (1..=6).collect::<Vec<u64>>(),
        "and what is stored is still one contiguous chain"
    );
}

#[test]
fn a_producer_may_write_a_different_record_at_a_sequence_nobody_acknowledged() {
    // The case that makes the tail scratch rather than history: the store
    // crashed with records 5 and 6 on disk and unacknowledged, and the producer
    // meanwhile came under pressure and ended its stream — so *its* record at
    // sequence 5 is now a terminal one. Only acknowledged records are immutable.
    let (keys, store) = (ring("unacked-differs"), store("unacked-differs"));
    let records = stream("inst", 6);
    ingest::accept(
        &store,
        &batch(&records[..4], GENESIS, &keys),
        &published(&keys),
    )
    .expect("the first four are acknowledged");
    appended_without_acknowledging(&store, &records[4..]);

    let mut replacement = records[4].clone();
    replacement["at"] = json!("2030-01-01T00:00:00Z");
    replacement["prev"] = json!(record::digest_of(&records[3]).expect("it digests"));
    let head_of_four = record::digest_of(&records[3]).expect("it digests");

    assert_eq!(
        ingest::accept(
            &store,
            &batch(std::slice::from_ref(&replacement), &head_of_four, &keys),
            &published(&keys)
        ),
        Ok(Accepted::Ok {
            acked: 5,
            stored: 1
        }),
        "a sequence the store never acknowledged is not a conflict"
    );
    let stored = stream_page(&store);
    assert_eq!(stored.len(), 5, "and the discarded tail is gone");
    assert_eq!(
        stored[4]["at"],
        json!("2030-01-01T00:00:00Z"),
        "what stands at sequence 5 is what the producer last shipped"
    );
}

#[test]
fn a_record_that_retention_removed_is_not_reported_as_a_broken_store() {
    // "Acknowledged and absent" is the ordinary end state of every record: the
    // store forgets on a schedule. A shipper replaying an old batch after an
    // outage must be answered, not told the store is broken.
    let (keys, store) = (ring("forgotten"), store("forgotten"));
    let records = stream("inst", 6);
    let batch = batch(&records, GENESIS, &keys);
    ingest::accept(&store, &batch, &published(&keys)).expect("it is accepted");

    for (_, path) in store
        .segments(&Scope::Stream {
            pdp_id: "plane".to_owned(),
            instance: "inst".to_owned(),
        })
        .expect("it lists")
    {
        std::fs::remove_file(&path).expect("retention removes whole segments");
    }

    assert_eq!(
        ingest::accept(&store, &batch, &published(&keys)),
        Ok(Accepted::Ok {
            acked: 6,
            stored: 0
        })
    );
}
