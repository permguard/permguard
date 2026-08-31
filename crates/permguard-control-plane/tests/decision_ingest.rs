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
use permguard_core::{KeyId, KeyManager, Maintenance, Signature};
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

/// A real key ring presented under a chosen key id, for substitution regression tests.
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
                event: None,
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

fn batch(records: &[Value], previous_head: &str, keys: &dyn KeyManager) -> Batch {
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

fn published(keys: &dyn KeyManager) -> Vec<ingest::ProducerTrust> {
    trusted_for(keys, "plane")
}

/// The published keys, bound to one exact producer — the binding ingest verifies against.
fn trusted_for(keys: &dyn KeyManager, pdp: &str) -> Vec<ingest::ProducerTrust> {
    keys.public_keys()
        .expect("published")
        .into_iter()
        .map(|key| ingest::ProducerTrust {
            key,
            pdp: pdp.to_owned(),
        })
        .collect()
}

/// One bounded page, read the way a consumer reads one.
///
/// The offset key is fixed here so a token this helper issues opens again in the same test — which
/// is the property the reader promises a consumer across restarts, and the one worth exercising.
fn page(
    store: &DecisionStore,
    scope: &Scope,
    from: Option<&str>,
    limit: usize,
) -> Result<permguard_control_plane::decisions::read::Page, read::ReadError> {
    let key = permguard_stream::CursorKey::new(b"a-test-cursor-key-of-32-bytes!!!!", &[])
        .expect("the key is long enough");

    read::read(
        store,
        scope,
        &key,
        &permguard_stream::Window {
            from: from.map(ToOwned::to_owned),
            limit_records: limit,
            ..permguard_stream::Window::default()
        },
    )
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
fn a_substituted_key_cannot_replace_the_envelope_before_its_kid_conflict_is_found() {
    let (first, second, store) = (
        ring("kid-order-first"),
        ring("kid-order-second"),
        store("kid-order"),
    );
    let records = stream("inst", 5);
    ingest::accept(
        &store,
        &batch(&records[..3], GENESIS, &first),
        &published(&first),
    )
    .expect("the original evidence is accepted");
    let envelope = store
        .root()
        .join("streams")
        .join("plane")
        .join("inst")
        .join("batch-00000000000000000001.jws");
    let original = std::fs::read(&envelope).expect("the original envelope is durable");
    let kid = published(&first)[0].key.kid.clone();
    let substituted = AliasedRing {
        inner: &second,
        kid,
    };

    let refused = ingest::accept(
        &store,
        &batch(&records, GENESIS, &substituted),
        &trusted_for(&substituted, "plane"),
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
            .stream_state("plane", "inst")
            .expect("the state reads")
            .acked,
        3
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
    let page = page(
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

    let page = page(
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
fn a_trusted_key_cannot_sign_for_a_producer_it_is_not_bound_to() {
    // The records — and therefore the envelope — declare the stream identity `plane`. The same
    // keys, trusted but bound to a *different* producer, must not attribute this batch: a valid
    // signature under somebody else's binding is the identity-borrowing attack, not a producer.
    let (keys, store) = (ring("bound"), store("bound"));
    let records = stream("inst", 4);

    let refused = ingest::accept(
        &store,
        &batch(&records, GENESIS, &keys),
        &trusted_for(&keys, "plane-b"),
    );
    assert!(
        matches!(&refused, Err(Refused::Unattributable(detail)) if detail.contains("not bound")),
        "{refused:?}"
    );

    // And the honest binding still works, so the refusal above is the binding, not the key.
    ingest::accept(&store, &batch(&records, GENESIS, &keys), &published(&keys))
        .expect("the bound producer is accepted");
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

    let page = page(
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
    assert_eq!(archived[0].kid, published(&keys)[0].key.kid);

    // A crash can leave a staging file beside committed keys. It is not evidence and must not be
    // parsed as though it were a committed archive entry.
    std::fs::write(
        store.root().join("verification-keys/.key.json.next-123"),
        b"partial",
    )
    .expect("the crash remnant is written");
    assert_eq!(store.archived_keys().expect("staging is ignored").len(), 1);
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
        page(
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
    let first = page(&store, &acme, None, 2).expect("it reads");

    assert!(
        page(&store, &other, Some(&first.next), 2).is_err(),
        "an offset is bound to the scope that issued it"
    );
    let continued = page(&store, &acme, Some(&first.next), 100).expect("it continues");
    assert!(
        continued
            .records
            .iter()
            .all(|record| !first.records.contains(record)),
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
    page(
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

/// One window, so the tests below state only what they are about.
fn window(records: usize) -> permguard_stream::Window {
    permguard_stream::Window {
        limit_records: records,
        ..permguard_stream::Window::default()
    }
}

fn cursor_key() -> permguard_stream::CursorKey {
    permguard_stream::CursorKey::new(b"a-test-cursor-key-of-32-bytes!!!!", &[])
        .expect("the key is long enough")
}

/// The failure a moving end causes, and the fix `until` is.
#[test]
fn an_export_finishes_against_its_own_snapshot_while_the_stream_keeps_growing() {
    let keys = ring("export-keys");
    let store = store("export");
    let acme = Scope::Tenant {
        zone: "acme".to_owned(),
        ledger: "main-ledger".to_owned(),
    };
    let records = stream("i-1", 10);
    ingest::accept(&store, &batch(&records, GENESIS, &keys), &published(&keys))
        .expect("the batch is accepted");

    // The first page captures the snapshot this export is of.
    let key = cursor_key();
    let first = read::read(&store, &acme, &key, &window(2)).expect("it reads");
    let snapshot = permguard_stream::Frontier::decode(&first.high_watermark)
        .expect("the watermark is one this build issued");

    // Meanwhile the stream keeps growing, which is what makes a moving end unfinishable.
    let more = stream("i-2", 10);
    ingest::accept(&store, &batch(&more, GENESIS, &keys), &published(&keys))
        .expect("the second batch is accepted");

    let mut walked = first.records.len();
    let mut bounded = permguard_stream::Window {
        from: Some(first.next),
        until: Some(snapshot),
        limit_records: 2,
        ..permguard_stream::Window::default()
    };
    let mut pages = 0;
    loop {
        pages += 1;
        assert!(pages < 100, "an export bounded by a snapshot terminates");
        let page = read::read(&store, &acme, &key, &bounded).expect("it reads");
        walked += page.records.len();
        if !page.more {
            break;
        }
        bounded.from = Some(page.next);
    }

    let everything = read::read(&store, &acme, &key, &window(1_000)).expect("it reads");
    assert!(
        walked < everything.records.len(),
        "the export covered its snapshot and not the records written after it: {walked} of {}",
        everything.records.len()
    );
}

/// A record count alone does not bound a response.
#[test]
fn the_byte_bound_stops_a_page_before_the_record_bound_does() {
    let keys = ring("bytes-keys");
    let store = store("bytes");
    let acme = Scope::Tenant {
        zone: "acme".to_owned(),
        ledger: "main-ledger".to_owned(),
    };
    let records = stream("i-1", 20);
    ingest::accept(&store, &batch(&records, GENESIS, &keys), &published(&keys))
        .expect("the batch is accepted");

    let key = cursor_key();
    let generous = read::read(&store, &acme, &key, &window(1_000)).expect("it reads");
    assert!(generous.records.len() > 2, "there is something to bound");

    let one_record_worth = serde_json::to_vec(&generous.records[0])
        .expect("it serializes")
        .len() as u64;
    let tight = read::read(
        &store,
        &acme,
        &key,
        &permguard_stream::Window {
            limit_records: 1_000,
            limit_bytes: one_record_worth + 1,
            ..permguard_stream::Window::default()
        },
    )
    .expect("it reads");

    assert_eq!(
        tight.records.len(),
        1,
        "the byte bound stopped it where the record bound would not have"
    );
    assert!(tight.more, "and it says there is more");
}

/// A record larger than the whole budget is still returned, or the consumer stalls forever.
#[test]
fn a_single_record_larger_than_the_budget_is_still_returned() {
    let keys = ring("huge-keys");
    let store = store("huge");
    let acme = Scope::Tenant {
        zone: "acme".to_owned(),
        ledger: "main-ledger".to_owned(),
    };
    let records = stream("i-1", 4);
    ingest::accept(&store, &batch(&records, GENESIS, &keys), &published(&keys))
        .expect("the batch is accepted");

    let page = read::read(
        &store,
        &acme,
        &cursor_key(),
        &permguard_stream::Window {
            limit_records: 10,
            limit_bytes: 1,
            ..permguard_stream::Window::default()
        },
    )
    .expect("it reads");

    assert_eq!(
        page.records.len(),
        1,
        "refusing it would leave the consumer stuck at that position for good"
    );
}

/// A new consumer can choose the retained beginning rather than guess at it.
#[test]
fn every_page_says_where_the_retained_beginning_is() {
    let keys = ring("oldest-keys");
    let store = store("oldest");
    let acme = Scope::Tenant {
        zone: "acme".to_owned(),
        ledger: "main-ledger".to_owned(),
    };
    ingest::accept(
        &store,
        &batch(&stream("i-1", 6), GENESIS, &keys),
        &published(&keys),
    )
    .expect("the batch is accepted");

    let key = cursor_key();
    let page = read::read(&store, &acme, &key, &window(2)).expect("it reads");
    assert!(!page.oldest_available.is_empty());

    // And it is an offset this store accepts: presenting it reads from the beginning again.
    let from_oldest = read::read(
        &store,
        &acme,
        &key,
        &permguard_stream::Window {
            from: Some(page.oldest_available),
            limit_records: 2,
            ..permguard_stream::Window::default()
        },
    )
    .expect("it reads");
    assert_eq!(from_oldest.records, page.records);
}

/// A tenant view is a subsequence, and the block says so rather than implying a chain.
#[test]
fn a_block_says_whether_its_records_are_a_contiguous_chain() {
    let keys = ring("coverage-keys");
    let store = store("coverage");
    let records = stream("i-1", 6);
    ingest::accept(&store, &batch(&records, GENESIS, &keys), &published(&keys))
        .expect("the batch is accepted");

    let key = cursor_key();
    let tenant = read::read(
        &store,
        &Scope::Tenant {
            zone: "acme".to_owned(),
            ledger: "main-ledger".to_owned(),
        },
        &key,
        &window(100),
    )
    .expect("it reads");
    let producer = read::read(
        &store,
        &Scope::Stream {
            pdp_id: "plane-a".to_owned(),
            instance: "i-1".to_owned(),
        },
        &key,
        &window(100),
    )
    .expect("it reads");

    assert!(
        !tenant.coverage.contiguous,
        "the records in between belong to other tenants and are not disclosed"
    );
    assert!(
        producer.coverage.contiguous,
        "a producer stream is a contiguous run, and its chain verifies across it"
    );
    assert!(producer.coverage.examined >= producer.records.len());
}

/// An offset a consumer edited is refused rather than obeyed.
#[test]
fn an_offset_a_consumer_edited_is_refused_by_the_signature() {
    use base64::Engine as _;

    let keys = ring("forge-keys");
    let store = store("forge");
    let acme = Scope::Tenant {
        zone: "acme".to_owned(),
        ledger: "main-ledger".to_owned(),
    };
    ingest::accept(
        &store,
        &batch(&stream("i-1", 6), GENESIS, &keys),
        &published(&keys),
    )
    .expect("the batch is accepted");

    let key = cursor_key();
    let page = read::read(&store, &acme, &key, &window(2)).expect("it reads");

    // The edit: flip a byte of the signed body, which is what an editable cursor would allow.
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&page.next)
        .expect("the token decodes");
    let mut sealed: Value = serde_json::from_slice(&raw).expect("it parses");
    sealed["c"] = json!("eyJ2IjoxfQ");
    let forged = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&sealed).expect("it serializes"));

    let refused = read::read(
        &store,
        &acme,
        &key,
        &permguard_stream::Window {
            from: Some(forged),
            ..window(2)
        },
    )
    .expect_err("an edited offset is not a position this server issued");

    assert!(matches!(refused, read::ReadError::Offset(_)), "{refused:?}");
}

/// An export declares its bound once, and cannot quietly change or drop it afterwards.
#[test]
fn an_export_cannot_change_or_drop_the_bound_it_declared() {
    let keys = ring("bound-keys");
    let store = store("bound");
    let acme = Scope::Tenant {
        zone: "acme".to_owned(),
        ledger: "main-ledger".to_owned(),
    };
    ingest::accept(
        &store,
        &batch(&stream("i-1", 8), GENESIS, &keys),
        &published(&keys),
    )
    .expect("the batch is accepted");

    let key = cursor_key();
    let first = read::read(&store, &acme, &key, &window(2)).expect("it reads");
    let snapshot = permguard_stream::Frontier::decode(&first.high_watermark).expect("a watermark");

    // The second page declares the bound. That is legal: the first page could not have.
    let second = read::read(
        &store,
        &acme,
        &key,
        &permguard_stream::Window {
            from: Some(first.next),
            until: Some(snapshot.clone()),
            ..window(2)
        },
    )
    .expect("an export declares its bound on its second page");

    // Dropping it afterwards would turn a finite export into an endless one.
    assert!(
        matches!(
            read::read(
                &store,
                &acme,
                &key,
                &permguard_stream::Window {
                    from: Some(second.next.clone()),
                    until: None,
                    ..window(2)
                },
            ),
            Err(read::ReadError::Offset(_))
        ),
        "dropping the bound is a different read, not a wider one"
    );

    // And so would moving it.
    let moved = permguard_stream::Frontier::of("tenant:acme:main-ledger", 9_999);
    assert!(
        matches!(
            read::read(
                &store,
                &acme,
                &key,
                &permguard_stream::Window {
                    from: Some(second.next),
                    until: Some(moved),
                    ..window(2)
                },
            ),
            Err(read::ReadError::Offset(_))
        ),
        "an export is of one snapshot"
    );
}
