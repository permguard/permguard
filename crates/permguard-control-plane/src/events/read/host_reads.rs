// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! WP-6.2b: the public event reads over the legacy store and the Host's consumer.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use permguard_host::composition::{ConsumedPage, ConsumedRun, StreamConsumerReads};
use permguard_stream::engine::batch::{Envelope, Jws, KeyView, SealedBatch, digest_string};
use serde_json::json;

use super::*;

const ROOT: &[u8] = b"a-test-cursor-key-of-32-bytes!!!!";
const ZONE: &str = "zone-1";
const LEDGER: &str = "ledger-1";
const LOGIN: &str = permguard_core::domains::event::DOGWOOD_V1;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "permguard-event-host-reads-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("a directory");
    root
}

/// One consumer run the fake holds: its records, batched two at a time.
struct Run {
    resource: Resource,
    run: ConsumedRun,
    records: Vec<Vec<u8>>,
}

/// The Host's consumer, as a Plane reads it.
struct Held {
    runs: Mutex<Vec<Run>>,
}

impl Held {
    fn batch_of(run: &Run, seq: u64) -> Option<Vec<u8>> {
        let first = (seq - 1) / 2 * 2 + 1;
        let last = (first + 1).min(run.records.len() as u64);
        if seq > last {
            return None;
        }
        let records: Vec<&Vec<u8>> = (first..=last)
            .map(|at| &run.records[(at - 1) as usize])
            .collect();
        let leaves: Vec<String> = records
            .iter()
            .map(|record| digest_string(permguard_core::domains::digest::EVENT_RECORD, record))
            .collect();
        let envelope = Envelope {
            descriptor_version: 1,
            stream_key: KeyView {
                plane: "data".to_owned(),
                stream_type: "events".to_owned(),
                resource: run.resource.to_string(),
                producer_host_id: hex(&run.run.producer),
            },
            run: hex(&run.run.run),
            membership_id: None,
            epoch: None,
            first_seq: first,
            last_seq: last,
            count: last - first + 1,
            previous_head: "sha256:00".to_owned(),
            head: leaves.last().cloned().unwrap_or_default(),
            merkle_root: permguard_decisions::merkle::root(&leaves).expect("a root"),
            batch_id: format!("{}-{first}", hex(&run.run.run)),
            created_at: "2026-10-18T10:00:00Z".to_owned(),
            key_set_epoch: 1,
        };
        SealedBatch {
            signature: Jws {
                protected: "e30".to_owned(),
                payload: B64.encode(envelope.signed_bytes().expect("signed bytes")),
                signature: "c2ln".to_owned(),
            },
            records: records.iter().map(|record| B64.encode(record)).collect(),
        }
        .encode()
        .ok()
    }
}

impl StreamConsumerReads for Held {
    fn runs(&self, resource: &Resource) -> Result<Vec<ConsumedRun>, String> {
        Ok(self
            .runs
            .lock()
            .unwrap()
            .iter()
            .filter(|held| &held.resource == resource)
            .map(|held| held.run.clone())
            .collect())
    }

    fn locate(&self, producer: &[u8; 16], run: &[u8; 16]) -> Result<Option<Resource>, String> {
        Ok(self
            .runs
            .lock()
            .unwrap()
            .iter()
            .find(|held| held.run.producer == *producer && held.run.run == *run)
            .map(|held| held.resource.clone()))
    }

    fn records(
        &self,
        _: &Resource,
        producer: &[u8; 16],
        run: &[u8; 16],
        from: u64,
        limit: usize,
    ) -> Result<ConsumedPage, String> {
        let runs = self.runs.lock().unwrap();
        let held = runs
            .iter()
            .find(|held| held.run.producer == *producer && held.run.run == *run)
            .ok_or("no such run")?;
        let from = from.max(held.run.oldest_retained);
        Ok(ConsumedPage {
            records: (from..=held.run.acked)
                .take(limit)
                .map(|seq| (seq, held.records[(seq - 1) as usize].clone()))
                .collect(),
            low_watermark: None,
        })
    }

    fn batch(
        &self,
        _: &Resource,
        producer: &[u8; 16],
        run: &[u8; 16],
        seq: u64,
    ) -> Result<Option<Vec<u8>>, String> {
        let runs = self.runs.lock().unwrap();
        Ok(runs
            .iter()
            .find(|held| held.run.producer == *producer && held.run.run == *run)
            .and_then(|held| Self::batch_of(held, seq)))
    }

    fn signers(
        &self,
        resource: &Resource,
    ) -> Result<Vec<permguard_host::composition::ConsumedSigners>, String> {
        Ok(self
            .runs
            .lock()
            .unwrap()
            .iter()
            .filter(|held| &held.resource == resource)
            .map(|held| permguard_host::composition::ConsumedSigners {
                producer: held.run.producer,
                run: held.run.run,
                acked: held.run.acked,
                spans: vec![(
                    1,
                    format!("kid-{}", held.run.producer[0]),
                    json!({"kty": "OKP", "crv": "Ed25519", "x": "AAAA"}).to_string(),
                )],
            })
            .collect())
    }
}

/// An event of `producer`'s run `run` at `seq`, of type `event_type`, in its canonical encoding.
fn host_record(producer: u8, run: u8, seq: u64, event_type: &str) -> Vec<u8> {
    permguard_stream::jcs::canonicalize(&json!({
        "v": 1,
        "record_type": permguard_events::RECORD_TYPE,
        "event_type": event_type,
        "event_id": format!("h-{producer}-{run}-{seq}"),
        "seq": seq,
        "kind": "response",
        "occurred_at": "2026-10-18T10:00:00Z",
        "stream": {
            "producer": {
                "class": permguard_events::PRODUCER_CLASS_DATA_PLANE,
                "id": hex(&[producer; 16]),
                "instance": hex(&[run; 16]),
            },
            "zone": ZONE,
            "ledger": LEDGER,
        },
    }))
    .expect("canonical JSON")
}

fn run(resource: &Resource, producer: u8, run: u8, types: &[&str]) -> Run {
    Run {
        resource: resource.clone(),
        run: ConsumedRun {
            producer: [producer; 16],
            run: [run; 16],
            acked: types.len() as u64,
            oldest_retained: 1,
        },
        records: types
            .iter()
            .enumerate()
            .map(|(at, event_type)| host_record(producer, run, at as u64 + 1, event_type))
            .collect(),
    }
}

struct Fixture {
    store: Arc<EventStore>,
    consumer: StreamConsumer,
    held: Arc<Held>,
    keys: CursorKeys,
}

impl Fixture {
    /// Two producers holding runs of the ledger; no legacy record.
    fn new(tag: &str) -> Self {
        let root = scratch(tag);
        let resource = Resource::ledger("data", ZONE, LEDGER);
        let held = Arc::new(Held {
            runs: Mutex::new(vec![
                run(&resource, 2, 9, &[LOGIN, "other.v1", LOGIN]),
                run(&resource, 1, 7, &[LOGIN, LOGIN]),
            ]),
        });
        Self {
            store: Arc::new(EventStore::open(root.join("store")).expect("a store")),
            consumer: StreamConsumer::over(Arc::clone(&held) as Arc<dyn StreamConsumerReads>),
            held,
            keys: CursorKeys::from_root(ROOT, [1; 16], "events").expect("a cursor key"),
        }
    }

    fn sources(&self) -> Sources<'_> {
        Sources {
            store: self.store.as_ref(),
            host: Some(&self.consumer),
        }
    }

    fn read(&self, scope: &Scope, filters: &Filters, window: &Window) -> Page {
        read_with(&self.sources(), scope, filters, &self.keys, window).expect("it reads")
    }
}

fn tenant() -> Scope {
    Scope::Tenant {
        zone: ZONE.to_owned(),
        ledger: LEDGER.to_owned(),
    }
}

fn ids(page: &Page) -> Vec<String> {
    page.records
        .iter()
        .map(|record| record["event_id"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn the_tenant_view_reads_every_consumer_run_of_its_ledger_in_order() {
    let fixture = Fixture::new("tenant");
    let page = fixture.read(&tenant(), &Filters::default(), &Window::default());
    assert_eq!(
        ids(&page),
        ["h-2-9-1", "h-2-9-2", "h-2-9-3", "h-1-7-1", "h-1-7-2"],
        "each run in the order the consumer answers them"
    );
    assert!(!page.more, "read to the end");
    let watermark = Frontier::decode(&page.high_watermark).expect("a frontier");
    assert_eq!(
        watermark.covered_through(&format!("host:{}:{}", hex(&[1; 16]), hex(&[7; 16]))),
        3
    );
}

#[test]
fn pages_resume_across_runs_without_a_gap_or_a_repeat() {
    let fixture = Fixture::new("pages");
    let mut window = Window {
        limit_records: 2,
        ..Window::default()
    };
    let mut seen = Vec::new();
    for _ in 0..10 {
        let page = fixture.read(&tenant(), &Filters::default(), &window);
        seen.extend(ids(&page));
        if !page.more {
            break;
        }
        window.from = Some(page.next);
    }
    assert_eq!(
        seen,
        ["h-2-9-1", "h-2-9-2", "h-2-9-3", "h-1-7-1", "h-1-7-2"]
    );
}

#[test]
fn a_stream_read_names_one_host_run() {
    let fixture = Fixture::new("stream");
    let scope = Scope::Stream {
        zone: ZONE.to_owned(),
        ledger: LEDGER.to_owned(),
        class: permguard_events::PRODUCER_CLASS_DATA_PLANE.to_owned(),
        producer: hex(&[1; 16]),
        instance: hex(&[7; 16]),
    };
    let page = fixture.read(&scope, &Filters::default(), &Window::default());
    assert_eq!(ids(&page), ["h-1-7-1", "h-1-7-2"]);
    assert!(page.coverage.contiguous);
    // A run the consumer does not hold reads the legacy store, which holds nothing.
    let unknown = Scope::Stream {
        zone: ZONE.to_owned(),
        ledger: LEDGER.to_owned(),
        class: permguard_events::PRODUCER_CLASS_DATA_PLANE.to_owned(),
        producer: hex(&[1; 16]),
        instance: hex(&[8; 16]),
    };
    assert!(
        fixture
            .read(&unknown, &Filters::default(), &Window::default())
            .records
            .is_empty()
    );
}

#[test]
fn the_filters_apply_to_the_consumers_records() {
    let fixture = Fixture::new("filters");
    let filters = Filters {
        event_types: vec!["other.v1".to_owned()],
        ..Filters::default()
    };
    let page = fixture.read(&tenant(), &filters, &Window::default());
    assert_eq!(ids(&page), ["h-2-9-2"]);
    assert_eq!(page.coverage.examined, 5, "every consumer record examined");
    assert!(!page.more);
    let by_producer = Filters {
        producer: Some(hex(&[1; 16])),
        ..Filters::default()
    };
    assert_eq!(
        ids(&fixture.read(&tenant(), &by_producer, &Window::default())),
        ["h-1-7-1", "h-1-7-2"]
    );
}

#[test]
fn a_host_proof_carries_the_sealed_batch_and_its_paths() {
    let fixture = Fixture::new("proof");
    let page = fixture.read(
        &tenant(),
        &Filters::default(),
        &Window {
            proof: true,
            ..Window::default()
        },
    );
    // Run 9's batches 1-2 and 3, run 7's batch 1-2: each once.
    assert_eq!(page.proof.len(), 3);
    for entry in &page.proof {
        assert_eq!(entry["format"], crate::decisions::read::HOST_FORMAT);
        assert!(entry["signature"]["payload"].is_string());
    }
    assert_eq!(page.inclusion.len(), page.records.len());
    let runs = fixture.held.runs.lock().unwrap();
    let leaf = digest_string(
        permguard_core::domains::digest::EVENT_RECORD,
        &runs[1].records[1],
    );
    assert_eq!(page.inclusion[4]["leaf"], leaf, "the event domain");
}

#[test]
fn a_position_behind_retention_is_answered_and_a_lookup_finds_a_host_record() {
    let fixture = Fixture::new("expired");
    let first = fixture.read(
        &tenant(),
        &Filters::default(),
        &Window {
            limit_records: 1,
            ..Window::default()
        },
    );
    fixture.held.runs.lock().unwrap()[0].run.oldest_retained = 3;
    let refused = read_with(
        &fixture.sources(),
        &tenant(),
        &Filters::default(),
        &fixture.keys,
        &Window {
            from: Some(first.next),
            ..Window::default()
        },
    )
    .expect_err("behind retention");
    assert!(matches!(refused, ReadError::Expired { .. }), "{refused}");
    let found = get(&fixture.sources(), &tenant(), "h-1-7-2", &fixture.keys)
        .expect("it reads")
        .expect("found");
    assert_eq!(found["seq"], 2);
    assert_eq!(
        get(&fixture.sources(), &tenant(), "nothing", &fixture.keys).expect("it reads"),
        None
    );
}

/// Two legacy records of the tenant in the store, with the signed envelope covering them.
fn legacy(store: &EventStore) {
    let stream = permguard_events::Stream::new(
        permguard_events::Producer::data_plane("plane-before", "01931f2c"),
        ZONE,
        LEDGER,
    );
    let records: Vec<Value> = (1..=2)
        .map(|seq| {
            json!({
                "v": 1,
                "record_type": permguard_events::RECORD_TYPE,
                "event_type": LOGIN,
                "event_id": format!("l-{seq}"),
                "seq": seq,
                "kind": "response",
                "occurred_at": "2026-10-18T09:00:00Z",
                "stream": stream,
            })
        })
        .collect();
    store
        .append_batch(&stream, &records.iter().collect::<Vec<_>>())
        .expect("appended");
    let digests: Vec<String> = records
        .iter()
        .map(|record| permguard_events::digest_of(record).expect("a digest"))
        .collect();
    let envelope = permguard_events::envelope::Envelope {
        stream: stream.clone(),
        first_seq: 1,
        last_seq: 2,
        count: 2,
        previous_head: permguard_events::GENESIS.to_owned(),
        head: digests[1].clone(),
        merkle_root: permguard_decisions::merkle::root(&digests).expect("a root"),
        event_types: vec![LOGIN.to_owned()],
        record_version: 1,
        at: "2026-10-18T09:00:00Z".to_owned(),
    };
    store
        .keep_envelope(
            &stream,
            1,
            &json!({
                "protected": "e30",
                "payload": B64.encode(serde_json::to_vec(&envelope).expect("renders")),
                "signature": "c2ln",
            }),
        )
        .expect("kept");
    store
        .acknowledge(&stream, 2, &digests[1])
        .expect("acknowledged");
}

#[test]
fn the_legacy_store_is_read_first_and_its_proof_entry_names_its_format() {
    let fixture = Fixture::new("mixed");
    legacy(&fixture.store);
    let page = fixture.read(
        &tenant(),
        &Filters::default(),
        &Window {
            proof: true,
            ..Window::default()
        },
    );
    assert_eq!(
        ids(&page),
        [
            "l-1", "l-2", "h-2-9-1", "h-2-9-2", "h-2-9-3", "h-1-7-1", "h-1-7-2"
        ]
    );
    assert_eq!(
        page.proof[0]["format"],
        crate::decisions::read::LEGACY_FORMAT
    );
    assert!(
        page.proof[0]["payload"].is_string(),
        "the JWS members unchanged"
    );
    assert!(
        page.proof[1..]
            .iter()
            .all(|entry| entry["format"] == crate::decisions::read::HOST_FORMAT)
    );
    assert_eq!(page.inclusion.len(), page.records.len());
    assert!(!page.more);
    // Paged one at a time, the boundary between the sources loses nothing.
    let mut window = Window {
        limit_records: 1,
        ..Window::default()
    };
    let mut seen = Vec::new();
    for _ in 0..20 {
        let page = fixture.read(&tenant(), &Filters::default(), &window);
        seen.extend(ids(&page));
        if !page.more {
            break;
        }
        window.from = Some(page.next);
    }
    assert_eq!(seen.len(), 7, "{seen:?}");
}

/// The facade a test serves its reads and signers from, over the fixture's store and consumer.
fn facade(fixture: &Fixture) -> crate::events::http::EventFacade {
    crate::events::http::EventFacade {
        store: Arc::clone(&fixture.store),
        host: Some(fixture.consumer.clone()),
        producers: Arc::new(std::sync::RwLock::new(Vec::new())),
        local: None,
        cursor_key: fixture.keys.clone(),
        catalog: None,
        disclosure: permguard_core::Disclosure::Full,
        metrics: permguard_core::Metrics::none(),
        base_url: String::new(),
    }
}

#[test]
fn the_signers_read_answers_each_consumer_run_in_stream_order() {
    let fixture = Fixture::new("signers");
    let facade = facade(&fixture);
    let document = facade
        .signers_of(
            ZONE,
            LEDGER,
            0,
            0,
            &crate::events::http::StreamsAsked::default(),
        )
        .expect("answered");
    let streams: Vec<(String, String, u64)> = document
        .streams
        .iter()
        .map(|view| (view.producer.clone(), view.instance.clone(), view.acked))
        .collect();
    assert_eq!(
        streams,
        [
            (hex(&[1; 16]), hex(&[7; 16]), 2),
            (hex(&[2; 16]), hex(&[9; 16]), 3),
        ],
        "by (class, producer, instance)"
    );
    assert!(document.streams.iter().all(|view| view.producer_class
        == permguard_events::PRODUCER_CLASS_DATA_PLANE
        && view.spans.len() == 1));
    assert!(!document.truncated);
    // Narrowed to one producer, and resumed past the first stream.
    let narrowed = facade
        .signers_of(
            ZONE,
            LEDGER,
            0,
            0,
            &crate::events::http::StreamsAsked {
                producer: Some(hex(&[2; 16])),
                ..Default::default()
            },
        )
        .expect("answered");
    assert_eq!(narrowed.streams.len(), 1);
    let after = facade
        .signers_of(
            ZONE,
            LEDGER,
            0,
            0,
            &crate::events::http::StreamsAsked {
                after: Some(
                    permguard_stream::StreamPosition::new(
                        permguard_events::PRODUCER_CLASS_DATA_PLANE,
                        hex(&[1; 16]),
                        hex(&[7; 16]),
                    )
                    .expect("a position"),
                ),
                ..Default::default()
            },
        )
        .expect("answered");
    assert_eq!(after.streams.len(), 1);
    assert_eq!(after.streams[0].producer, hex(&[2; 16]));
}

/// The ring of a data plane sharing the process, as the facade reads it.
struct Ring(Vec<permguard_core::Jwk>);

impl permguard_core::keys::PublicSet for Ring {
    fn public_keys(&self) -> permguard_core::keys::Result<Vec<permguard_core::Jwk>> {
        Ok(self.0.clone())
    }
}

fn jwk(x: &str) -> permguard_core::Jwk {
    serde_json::from_value(json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x,
        "kid": x,
        "alg": "EdDSA",
        "use": "sig",
    }))
    .expect("a JWK")
}

/// WP-6.2b (owner decision of 2026-10-18): the ingest route trusts the ring sharing this process,
/// each of its keys bound to each legacy journal's producer, zone and ledger, read on every batch;
/// without a legacy journal it expects no batch at all.
#[test]
fn the_local_ring_is_trusted_for_each_legacy_journal_and_nothing_else() {
    let fixture = Fixture::new("local-trust");
    let mut facade = facade(&fixture);
    assert!(facade.accepted_producers().is_empty());
    assert!(
        !facade.expects_batches(),
        "nothing to drain, nothing expected"
    );
    assert!(!facade.awaits_trust());

    let ring = Arc::new(Ring(vec![jwk("AAAA"), jwk("BBBB")]));
    facade.local = Some(crate::events::http::LocalTrust {
        keys: Some(Arc::clone(&ring) as Arc<dyn permguard_core::keys::PublicSet>),
        bindings: vec![
            (
                "plane-before".to_owned(),
                ZONE.to_owned(),
                LEDGER.to_owned(),
            ),
            (
                "plane-before".to_owned(),
                ZONE.to_owned(),
                "ledger-2".to_owned(),
            ),
        ],
    });
    assert!(facade.expects_batches());
    assert!(!facade.awaits_trust(), "every journal has its keys");
    let trusted = facade.accepted_producers();
    assert_eq!(trusted.len(), 4, "every key for every journal");
    assert!(trusted.iter().all(|held| held.producer == "plane-before"
        && held.zone == ZONE
        && (held.ledger == LEDGER || held.ledger == "ledger-2")));
    // Never a wildcard: the ring is bound to exactly what the journals name.
    assert!(
        trusted
            .iter()
            .all(|held| held.zone != "*" && held.ledger != "*")
    );

    // An empty binding list trusts nothing and expects nothing.
    facade.local = Some(crate::events::http::LocalTrust {
        keys: Some(ring as Arc<dyn permguard_core::keys::PublicSet>),
        bindings: Vec::new(),
    });
    assert!(facade.accepted_producers().is_empty());
    assert!(!facade.expects_batches());

    // A journal waiting and no ring composed: nothing trusted, and the batches are expected, so
    // health says the store is degraded rather than waiting quietly.
    facade.local = Some(crate::events::http::LocalTrust {
        keys: None,
        bindings: vec![(
            "plane-before".to_owned(),
            ZONE.to_owned(),
            LEDGER.to_owned(),
        )],
    });
    assert!(facade.accepted_producers().is_empty());
    assert!(facade.expects_batches());
    assert!(facade.awaits_trust());
}

/// WP-6.2b, after the review: a run longer than one page may examine is searched to its end, and
/// an export bounded past the legacy store keeps `more` until its runs are read to the bound.
#[test]
fn a_lookup_past_the_examination_bound_finds_the_record_and_more_holds() {
    let root = scratch("long-run");
    let resource = Resource::ledger("data", ZONE, LEDGER);
    let count = permguard_stream::window::MAX_EXAMINED + 2;
    let types: Vec<&str> = vec![LOGIN; count];
    let held = Arc::new(Held {
        runs: Mutex::new(vec![run(&resource, 1, 7, &types)]),
    });
    let store = Arc::new(EventStore::open(root.join("store")).expect("a store"));
    let consumer = StreamConsumer::over(Arc::clone(&held) as Arc<dyn StreamConsumerReads>);
    let keys = CursorKeys::from_root(ROOT, [1; 16], "events").expect("a cursor key");
    let sources = Sources {
        store: store.as_ref(),
        host: Some(&consumer),
    };
    let last = format!("h-1-7-{count}");
    let found = get(&sources, &tenant(), &last, &keys)
        .expect("it reads")
        .expect("found past the bound");
    assert_eq!(found["event_id"], last);

    // A filtered export: the first page is bounded by the examination, and so is the second,
    // which must still say there is more.
    let filters = Filters {
        event_id: Some(last.clone()),
        ..Filters::default()
    };
    let first = read_with(&sources, &tenant(), &filters, &keys, &Window::default()).expect("read");
    assert!(first.records.is_empty() && first.coverage.scan_bounded && first.more);
    let bound = Frontier::decode(&first.high_watermark).expect("a frontier");
    let second = read_with(
        &sources,
        &tenant(),
        &filters,
        &keys,
        &Window {
            from: Some(first.next),
            until: Some(bound.clone()),
            ..Window::default()
        },
    )
    .expect("read");
    assert_eq!(second.records.len(), 1, "the record within the bound");
}

#[test]
fn a_page_holds_to_its_record_and_byte_bounds() {
    let fixture = Fixture::new("bounds");
    let mut window = Window {
        limit_records: 2,
        ..Window::default()
    };
    for _ in 0..10 {
        let page = fixture.read(&tenant(), &Filters::default(), &window);
        assert!(page.records.len() <= 2, "{}", page.records.len());
        if !page.more {
            break;
        }
        window.from = Some(page.next);
    }
    let tight = fixture.read(
        &tenant(),
        &Filters::default(),
        &Window {
            limit_bytes: 1,
            ..Window::default()
        },
    );
    assert_eq!(tight.records.len(), 1, "one record whatever the budget");
    assert!(tight.more);
}

#[test]
fn the_signers_read_narrows_the_consumer_runs_by_class() {
    let fixture = Fixture::new("signers-class");
    let facade = facade(&fixture);
    let none = facade
        .signers_of(
            ZONE,
            LEDGER,
            0,
            0,
            &crate::events::http::StreamsAsked {
                producer_class: Some("another.class".to_owned()),
                ..Default::default()
            },
        )
        .expect("answered");
    assert!(none.streams.is_empty());
    let one = facade
        .signers_of(
            ZONE,
            LEDGER,
            0,
            0,
            &crate::events::http::StreamsAsked {
                instance: Some(hex(&[7; 16])),
                ..Default::default()
            },
        )
        .expect("answered");
    assert_eq!(one.streams.len(), 1);
}

/// WP-6.2b, after the review: an export reads each consumer run up to the end its bound names,
/// and a run opened after the bound belongs to a later export, whatever the consumer acknowledged
/// since.
#[test]
fn an_export_reads_the_consumer_runs_to_its_bound_and_no_further() {
    let fixture = Fixture::new("bounded");
    let first = fixture.read(
        &tenant(),
        &Filters::default(),
        &Window {
            limit_records: 2,
            ..Window::default()
        },
    );
    assert_eq!(ids(&first), ["h-2-9-1", "h-2-9-2"]);
    let bound = Frontier::decode(&first.high_watermark).expect("a frontier");
    {
        // The ledger moves on: a run grows, and another opens.
        let resource = Resource::ledger("data", ZONE, LEDGER);
        let mut runs = fixture.held.runs.lock().unwrap();
        runs[1].records.push(host_record(1, 7, 3, LOGIN));
        runs[1].run.acked = 3;
        runs.push(run(&resource, 3, 5, &[LOGIN]));
    }
    let mut window = Window {
        limit_records: 2,
        from: Some(first.next),
        until: Some(bound.clone()),
        ..Window::default()
    };
    let mut seen = Vec::new();
    for _ in 0..10 {
        let page = fixture.read(&tenant(), &Filters::default(), &window);
        assert_eq!(
            Frontier::decode(&page.high_watermark).as_ref(),
            Some(&bound),
            "every page echoes its bound"
        );
        seen.extend(ids(&page));
        if !page.more {
            break;
        }
        window.from = Some(page.next);
    }
    assert_eq!(seen, ["h-2-9-3", "h-1-7-1", "h-1-7-2"]);
}

/// A stream scope reads a consumer run only when it names the data-plane class: another class
/// with the same identifiers is a legacy stream, and the legacy store holds none.
#[test]
fn a_stream_read_of_another_class_never_names_a_host_run() {
    let fixture = Fixture::new("class");
    let scope = Scope::Stream {
        zone: ZONE.to_owned(),
        ledger: LEDGER.to_owned(),
        class: "another-class".to_owned(),
        producer: hex(&[1; 16]),
        instance: hex(&[7; 16]),
    };
    let page = read_with(
        &fixture.sources(),
        &scope,
        &Filters::default(),
        &fixture.keys,
        &Window::default(),
    );
    assert!(
        page.as_ref().map_or(true, |page| page.records.is_empty()),
        "{:?}",
        page.map(|page| ids(&page))
    );
}

/// WP-6.2b, the review's blocking defect: an export whose run outlasts two examination bounds is
/// read to its end. The bound names the run's end, and neither the legacy part nor `more` may take
/// that for the run having been read.
#[test]
fn an_export_reads_a_run_longer_than_two_examination_bounds_to_its_end() {
    let root = scratch("longer-run");
    let resource = Resource::ledger("data", ZONE, LEDGER);
    let count = 2 * permguard_stream::window::MAX_EXAMINED + 2;
    let types: Vec<&str> = vec![LOGIN; count];
    let held = Arc::new(Held {
        runs: Mutex::new(vec![run(&resource, 1, 7, &types)]),
    });
    let store = Arc::new(EventStore::open(root.join("store")).expect("a store"));
    let consumer = StreamConsumer::over(Arc::clone(&held) as Arc<dyn StreamConsumerReads>);
    let keys = CursorKeys::from_root(ROOT, [1; 16], "events").expect("a cursor key");
    let sources = Sources {
        store: store.as_ref(),
        host: Some(&consumer),
    };
    let last = format!("h-1-7-{count}");
    let filters = Filters {
        event_id: Some(last.clone()),
        ..Filters::default()
    };
    let mut window = Window::default();
    let mut found = Vec::new();
    let mut pages = 0;
    loop {
        let page = read_with(&sources, &tenant(), &filters, &keys, &window).expect("read");
        pages += 1;
        found.extend(ids(&page));
        if !page.more || pages > 5 {
            break;
        }
        window.until = Frontier::decode(&page.high_watermark);
        window.from = Some(page.next);
    }
    assert_eq!(
        found,
        [last],
        "found on the third page, after two bounded ones"
    );
    assert_eq!(pages, 3);
}
