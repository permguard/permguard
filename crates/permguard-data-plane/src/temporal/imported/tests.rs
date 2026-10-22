// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! WP-6.2c2b1: the imported origins as the Data Plane reads them.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use permguard_host::composition::{ConsumedPage, ConsumedRun, StreamConsumerReads};
use permguard_host::membership::import::{Checkpoint, CheckpointOrigin, CheckpointRun, Gap};
use serde_json::json;

use super::*;

const ZONE: &str = "zone-1";
const LEDGER: &str = "ledger-1";
const OWN: [u8; 16] = [9; 16];
const ORIGIN: [u8; 16] = [1; 16];
const RUN: [u8; 16] = [7; 16];
const EVENT_TYPE: &str = permguard_core::domains::event::DOGWOOD_V1;

/// An imported record of `producer`'s run `run` at `seq`, occurred at `at` (epoch seconds).
fn record(producer: [u8; 16], run: [u8; 16], seq: u64, at: i64, event_id: &str) -> Value {
    json!({
        "v": 1,
        "seq": seq,
        "event_type": EVENT_TYPE,
        "event_id": event_id,
        "source": "spiffe://acme/gateway",
        "occurrence_digest": format!("sha256:{event_id}"),
        "kind": "response",
        "occurred_at": permguard_core::time::to_rfc3339(at),
        "observed_at": permguard_core::time::to_rfc3339(at),
        "event": { "action": "Drupe::Action::Login" },
        "stream": {
            "producer": {
                "class": permguard_events::PRODUCER_CLASS_DATA_PLANE,
                "id": hex(&producer),
                "instance": hex(&run),
            },
            "zone": ZONE,
            "ledger": LEDGER,
        },
    })
}

/// One run the fake consumer holds.
struct Held {
    run: ConsumedRun,
    records: Vec<Value>,
}

/// The Host's consumer, as the plane reads it.
#[derive(Default)]
struct Consumer {
    runs: Mutex<Vec<Held>>,
    state: Mutex<Option<State>>,
    floor: Mutex<Option<Arc<dyn StreamFloor>>>,
    reads: Mutex<usize>,
}

impl StreamConsumerReads for Consumer {
    fn runs(&self, resource: &Resource) -> Result<Vec<ConsumedRun>, String> {
        assert_eq!(resource, &Resource::ledger("data", ZONE, LEDGER));
        Ok(self
            .runs
            .lock()
            .unwrap()
            .iter()
            .map(|held| held.run.clone())
            .collect())
    }

    fn locate(&self, _: &[u8; 16], _: &[u8; 16]) -> Result<Option<Resource>, String> {
        Ok(None)
    }

    fn records(
        &self,
        _: &Resource,
        producer: &[u8; 16],
        run: &[u8; 16],
        from: u64,
        limit: usize,
    ) -> Result<ConsumedPage, String> {
        *self.reads.lock().unwrap() += 1;
        let runs = self.runs.lock().unwrap();
        let held = runs
            .iter()
            .find(|held| held.run.producer == *producer && held.run.run == *run)
            .ok_or("no such run")?;
        let from = from.max(held.run.oldest_retained);
        Ok(ConsumedPage {
            // What it still holds, whatever its STATE says.
            records: (from..=held.run.acked)
                .take(limit)
                .filter_map(|seq| {
                    held.records
                        .get((seq - 1) as usize)
                        .map(|record| (seq, serde_json::to_vec(record).expect("bytes")))
                })
                .collect(),
            low_watermark: None,
        })
    }

    fn batch(
        &self,
        _: &Resource,
        _: &[u8; 16],
        _: &[u8; 16],
        _: u64,
    ) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }

    fn import_state(&self, _: &Resource) -> Result<Option<State>, String> {
        Ok(self.state.lock().unwrap().clone())
    }

    fn retain_above(&self, floor: Arc<dyn StreamFloor>) -> Result<(), String> {
        *self.floor.lock().unwrap() = Some(floor);
        Ok(())
    }

    fn resources(&self) -> Result<Vec<Resource>, String> {
        Ok(vec![Resource::ledger("data", ZONE, LEDGER)])
    }
}

fn held(producer: [u8; 16], run: [u8; 16], times: &[i64]) -> Held {
    Held {
        run: ConsumedRun {
            producer,
            run,
            acked: times.len() as u64,
            oldest_retained: 1,
        },
        records: times
            .iter()
            .enumerate()
            .map(|(at, time)| {
                record(
                    producer,
                    run,
                    at as u64 + 1,
                    *time,
                    &format!("e-{}-{}", producer[0], at + 1),
                )
            })
            .collect(),
    }
}

fn query(from: i64, until: i64) -> Query {
    Query {
        event_type: EVENT_TYPE.to_owned(),
        history: String::new(),
        action: None,
        kind: None,
        from,
        until,
    }
}

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-imported-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    path
}

fn imported(tag: &str, consumer: &Arc<Consumer>) -> Imported {
    Imported::new(
        StreamConsumer::over(Arc::clone(consumer) as Arc<dyn StreamConsumerReads>),
        OWN,
        scratch(tag),
    )
    .expect("the floor is registered")
}

fn ids(records: &[Value]) -> Vec<String> {
    records
        .iter()
        .map(|record| record["event_id"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn a_window_reads_the_imported_runs_it_covers_and_never_this_hosts_own() {
    let consumer = Arc::new(Consumer::default());
    consumer.runs.lock().unwrap().extend([
        held(ORIGIN, RUN, &[100, 200, 300]),
        held(OWN, [3; 16], &[150, 250]),
    ]);
    let imported = imported("window", &consumer);
    assert!(
        consumer.floor.lock().unwrap().is_some(),
        "the floor registered"
    );
    assert_eq!(
        ids(&imported
            .window(ZONE, LEDGER, &query(150, 300), None)
            .expect("read")),
        ["e-1-2", "e-1-3"]
    );

    // Caught up incrementally: a record admitted later is indexed and found.
    {
        let mut runs = consumer.runs.lock().unwrap();
        runs[0].records.push(record(ORIGIN, RUN, 4, 400, "e-1-4"));
        runs[0].run.acked = 4;
    }
    assert_eq!(
        ids(&imported
            .window(ZONE, LEDGER, &query(350, 450), None)
            .expect("read")),
        ["e-1-4"]
    );

    // Reopened: the persisted index serves without reading the indexed records again.
    let reopened = Imported::new(
        StreamConsumer::over(Arc::clone(&consumer) as Arc<dyn StreamConsumerReads>),
        OWN,
        imported.root.clone(),
    )
    .expect("reopened");
    *consumer.reads.lock().unwrap() = 0;
    assert_eq!(
        ids(&reopened
            .window(ZONE, LEDGER, &query(0, 150), None)
            .expect("read")),
        ["e-1-1"]
    );
    assert_eq!(
        *consumer.reads.lock().unwrap(),
        1,
        "the one window read, no re-indexing"
    );
}

#[test]
fn what_the_consumer_pruned_leaves_the_index_and_the_floor_follows_the_horizon() {
    let consumer = Arc::new(Consumer::default());
    consumer
        .runs
        .lock()
        .unwrap()
        .push(held(ORIGIN, RUN, &[100, 200, 300, 400]));
    let imported = imported("floor", &consumer);
    imported
        .window(ZONE, LEDGER, &query(0, 500), None)
        .expect("read");
    imported.refresh_floors(250).expect("measured");
    let floor = consumer.floor.lock().unwrap().clone().expect("registered");
    let resource = Resource::ledger("data", ZONE, LEDGER).to_string();
    assert_eq!(
        floor.retention_safe(&resource, &RUN),
        Some(2),
        "what no window reads"
    );
    assert_eq!(
        floor.retention_safe(&resource, &[8; 16]),
        None,
        "a run not measured"
    );

    // The consumer pruned through 2: its records leave the window.
    consumer.runs.lock().unwrap()[0].run.oldest_retained = 3;
    assert_eq!(
        ids(&imported
            .window(ZONE, LEDGER, &query(0, 500), None)
            .expect("read")),
        ["e-1-3", "e-1-4"]
    );
    imported.refresh_floors(1_000).expect("measured");
    assert_eq!(floor.retention_safe(&resource, &RUN), Some(4));
}

#[test]
fn the_shared_view_names_what_is_behind_the_verified_checkpoint() {
    let consumer = Arc::new(Consumer::default());
    consumer
        .runs
        .lock()
        .unwrap()
        .push(held(ORIGIN, RUN, &[100, 200]));
    let imported = imported("shared", &consumer);
    let none = imported.shared(ZONE, LEDGER).expect("read");
    assert!(none.state.is_none() && none.checkpoint.is_none() && none.behind.is_empty());

    let checkpoint = Checkpoint {
        coordinator: [2; 16],
        resource: Resource::ledger("data", ZONE, LEDGER).to_string(),
        revision: [3; 32],
        origins: vec![
            CheckpointOrigin {
                host_id: ORIGIN,
                runs: vec![CheckpointRun {
                    run: RUN,
                    acked: 5,
                    oldest_retained: 1,
                    admitted_at: None,
                }],
                pins: Vec::new(),
            },
            // This Host's own stream, named among the origins: never behind.
            CheckpointOrigin {
                host_id: OWN,
                runs: vec![CheckpointRun {
                    run: [3; 16],
                    acked: 9,
                    oldest_retained: 1,
                    admitted_at: None,
                }],
                pins: Vec::new(),
            },
        ],
        issued_at: 1,
        channel_binding: [4; 32],
        ring_epoch: 1,
        key_set_digest: [5; 32],
    };
    let signed = permguard_objects::cose::Sign1::sign_with(
        permguard_objects::crypto::suite::Suite::Ed25519Sha256V1,
        permguard_core::domains::protected::EVENT_IMPORT_CHECKPOINT,
        b"k",
        checkpoint.encode().expect("encodes"),
        |_| Ok(vec![0; 64]),
    )
    .expect("an envelope")
    .encode()
    .expect("encodes");
    *consumer.state.lock().unwrap() = Some(State {
        membership_id: [6; 16],
        revision: [3; 32],
        checkpoint: signed,
        verified_at: 1_800_000_000,
        gaps: vec![Gap {
            origin: ORIGIN,
            run: [8; 16],
            from: 1,
            through: Some(4),
            reason: permguard_host::membership::import::RETENTION.to_owned(),
            detected_at: 1,
            revision: [3; 32],
        }],
    });
    let shared = imported.shared(ZONE, LEDGER).expect("read");
    assert_eq!(
        shared.checkpoint.as_ref().map(|held| held.revision),
        Some([3; 32])
    );
    assert_eq!(shared.behind, vec![(ORIGIN, RUN, 2, 5)]);
    assert_eq!(shared.state.as_ref().map(|state| state.gaps.len()), Some(1));
    let before = shared.watermark.clone();
    {
        let mut runs = consumer.runs.lock().unwrap();
        for seq in 3..=5 {
            runs[0]
                .records
                .push(record(ORIGIN, RUN, seq, 300, &format!("e-1-{seq}")));
        }
        runs[0].run.acked = 5;
    }
    let caught = imported.shared(ZONE, LEDGER).expect("read");
    assert!(
        caught.behind.is_empty(),
        "held through what the checkpoint names"
    );
    assert_ne!(
        caught.watermark, before,
        "the rebuild mark moves with the index"
    );
}

#[test]
fn one_logical_occurrence_applies_once_and_a_conflicting_one_is_quarantined() {
    let a = record(ORIGIN, RUN, 1, 100, "dup");
    let mut b = record([2; 16], [5; 16], 1, 100, "dup");
    // The same occurrence, recorded by another plane: one applies.
    let (kept, quarantined) = deduplicated(vec![b.clone(), a.clone()]);
    assert_eq!((kept.len(), quarantined), (1, 0));
    assert_eq!(
        kept[0]["stream"]["producer"]["id"],
        hex(&ORIGIN),
        "the first in order"
    );
    // Another source's identifier is another occurrence.
    let mut other_source = b.clone();
    other_source["source"] = json!("spiffe://acme/other");
    let (kept, _) = deduplicated(vec![a.clone(), other_source]);
    assert_eq!(kept.len(), 2);
    // Different bytes for one key: every copy left out.
    b["occurrence_digest"] = json!("sha256:other");
    let lone = record(ORIGIN, RUN, 2, 200, "lone");
    let (kept, quarantined) = deduplicated(vec![a, b, lone]);
    assert_eq!(quarantined, 1);
    assert_eq!(ids(&kept), ["lone"]);
}

#[test]
fn an_identity_nobody_vouched_for_never_collapses_another_origins_occurrence() {
    for source in [Some("anonymous"), None] {
        let mut a = record(ORIGIN, RUN, 1, 100, "same");
        let mut b = record([2; 16], [5; 16], 1, 100, "same");
        b["occurrence_digest"] = json!("sha256:other");
        for held in [&mut a, &mut b] {
            match source {
                Some(source) => held["source"] = json!(source),
                None => {
                    held.as_object_mut().expect("a map").remove("source");
                }
            }
        }
        let (kept, quarantined) = deduplicated(vec![a.clone(), b.clone()]);
        assert_eq!((kept.len(), quarantined), (2, 0), "{source:?}: per origin");
        // Within one origin the same key is still one occurrence.
        let (kept, _) = deduplicated(vec![a.clone(), a]);
        assert_eq!(kept.len(), 1, "{source:?}");
    }
}

#[test]
fn a_record_the_index_names_and_the_consumer_lacks_is_refused_not_read_short() {
    let consumer = Arc::new(Consumer::default());
    let times: Vec<i64> = (0..200).map(|at| 100 + at).collect();
    consumer
        .runs
        .lock()
        .unwrap()
        .push(held(ORIGIN, RUN, &times));
    let reader = imported("short", &consumer);
    // Two records far apart: each read alone, nothing between them.
    *consumer.reads.lock().unwrap() = 0;
    assert_eq!(
        ids(&reader
            .window(ZONE, LEDGER, &query(100, 100), None)
            .expect("read")),
        ["e-1-1"]
    );
    assert_eq!(
        ids(&reader
            .window(ZONE, LEDGER, &query(299, 299), None)
            .expect("read")),
        ["e-1-200"]
    );
    assert_eq!(
        *consumer.reads.lock().unwrap(),
        3,
        "one to index the run, then one page each"
    );
    assert_eq!(
        reader
            .window(ZONE, LEDGER, &query(100, 299), None)
            .expect("read")
            .len(),
        200
    );

    // The consumer lost records its STATE and the index still name: refused, never read short.
    consumer.runs.lock().unwrap()[0].records.truncate(150);
    assert!(reader.window(ZONE, LEDGER, &query(100, 299), None).is_err());
}

#[test]
fn a_damaged_or_ahead_index_is_rebuilt_and_a_vanished_run_forgotten() {
    let consumer = Arc::new(Consumer::default());
    consumer
        .runs
        .lock()
        .unwrap()
        .push(held(ORIGIN, RUN, &[100, 200, 300]));
    let first = imported("rebuild", &consumer);
    assert_eq!(
        first
            .window(ZONE, LEDGER, &query(0, 400), None)
            .expect("read")
            .len(),
        3
    );
    let index = first
        .root
        .join(ZONE)
        .join(LEDGER)
        .join("imported")
        .join(hex(&ORIGIN))
        .join(hex(&RUN))
        .join("INDEX");
    std::fs::write(&index, b"not an index\n").expect("damaged");
    let reopened = Imported::new(
        StreamConsumer::over(Arc::clone(&consumer) as Arc<dyn StreamConsumerReads>),
        OWN,
        first.root.clone(),
    )
    .expect("reopened");
    assert_eq!(
        ids(&reopened
            .window(ZONE, LEDGER, &query(0, 400), None)
            .expect("read")),
        ["e-1-1", "e-1-2", "e-1-3"],
        "rebuilt from the consumer"
    );

    // The consumer restored to an older state: the index ahead of it is rebuilt.
    {
        let mut runs = consumer.runs.lock().unwrap();
        runs[0].records.truncate(2);
        runs[0].run.acked = 2;
    }
    assert_eq!(
        ids(&reopened
            .window(ZONE, LEDGER, &query(0, 400), None)
            .expect("read")),
        ["e-1-1", "e-1-2"]
    );
    // The run gone from the consumer: nothing of it is read.
    consumer.runs.lock().unwrap().clear();
    assert!(
        reopened
            .window(ZONE, LEDGER, &query(0, 400), None)
            .expect("read")
            .is_empty()
    );
}

#[test]
fn a_ledger_nobody_read_gets_its_floor_and_the_horizon_is_exclusive() {
    let consumer = Arc::new(Consumer::default());
    consumer
        .runs
        .lock()
        .unwrap()
        .push(held(ORIGIN, RUN, &[100, 200, 300]));
    let imported = imported("unread", &consumer);
    // No decision read the ledger.
    imported.refresh_floors(300).expect("measured");
    let floor = consumer.floor.lock().unwrap().clone().expect("registered");
    let resource = Resource::ledger("data", ZONE, LEDGER).to_string();
    assert_eq!(
        floor.retention_safe(&resource, &RUN),
        Some(2),
        "a record at the horizon is still read"
    );
}

#[test]
fn a_checkpoint_that_does_not_read_or_names_another_ledger_vouches_for_nothing() {
    let consumer = Arc::new(Consumer::default());
    consumer
        .runs
        .lock()
        .unwrap()
        .push(held(ORIGIN, RUN, &[100]));
    let imported = imported("corrupt", &consumer);
    let state = |checkpoint: Vec<u8>, revision: [u8; 32]| State {
        membership_id: [6; 16],
        revision,
        checkpoint,
        verified_at: 1,
        gaps: Vec::new(),
    };
    *consumer.state.lock().unwrap() = Some(state(b"not a checkpoint".to_vec(), [3; 32]));
    assert!(imported.shared(ZONE, LEDGER).is_err());
    let signed = |resource: &str| {
        permguard_objects::cose::Sign1::sign_with(
            permguard_objects::crypto::suite::Suite::Ed25519Sha256V1,
            permguard_core::domains::protected::EVENT_IMPORT_CHECKPOINT,
            b"k",
            Checkpoint {
                coordinator: [2; 16],
                resource: resource.to_owned(),
                revision: [3; 32],
                origins: Vec::new(),
                issued_at: 1,
                channel_binding: [4; 32],
                ring_epoch: 1,
                key_set_digest: [5; 32],
            }
            .encode()
            .expect("encodes"),
            |_| Ok(vec![0; 64]),
        )
        .expect("an envelope")
        .encode()
        .expect("encodes")
    };
    *consumer.state.lock().unwrap() = Some(state(
        signed(&Resource::ledger("data", ZONE, "elsewhere").to_string()),
        [3; 32],
    ));
    assert!(imported.shared(ZONE, LEDGER).is_err(), "another ledger");
    let ours = Resource::ledger("data", ZONE, LEDGER).to_string();
    *consumer.state.lock().unwrap() = Some(state(signed(&ours), [9; 32]));
    assert!(imported.shared(ZONE, LEDGER).is_err(), "another origin set");
    *consumer.state.lock().unwrap() = Some(state(signed(&ours), [3; 32]));
    assert!(imported.shared(ZONE, LEDGER).is_ok());
}

/// WP-6.4a, after the review: a replay reads no further than the frontier its decision captured —
/// a run read through its `covered_through`, a run the frontier does not name not read — and the
/// shared view's frontier names what the plane indexed, sorted, this Host's own run excluded.
#[test]
fn a_window_bound_by_a_frontier_reads_exactly_what_it_cites() {
    let consumer = Arc::new(Consumer::default());
    consumer.runs.lock().unwrap().extend([
        held(ORIGIN, RUN, &[100, 200, 300]),
        held([2; 16], [5; 16], &[150]),
        held(OWN, [3; 16], &[120]),
    ]);
    let imported = imported("window-bound", &consumer);
    let shared = imported.shared(ZONE, LEDGER).expect("the view");
    assert_eq!(
        shared
            .frontier
            .iter()
            .map(|run| (run.origin.clone(), run.covered_through))
            .collect::<Vec<_>>(),
        [("01".repeat(16), 3), ("02".repeat(16), 1)],
        "indexed, sorted, its own run left out"
    );

    let bound = [permguard_core::frontier::FrontierRun {
        origin: "01".repeat(16),
        run: "07".repeat(16),
        covered_through: 2,
        low_watermark: 1,
        gaps: Vec::new(),
    }];
    assert_eq!(
        ids(&imported
            .window(ZONE, LEDGER, &query(0, 1000), Some(&bound))
            .expect("read")),
        ["e-1-1", "e-1-2"],
        "through the cited sequence of the cited run, and no other run"
    );
}
