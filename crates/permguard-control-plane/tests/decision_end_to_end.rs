// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A data plane deciding, and a control plane keeping what it decided.
//!
//! Both halves are the real ones — a real journal on a real disk, a real
//! signed batch, the real ingestion. Only the socket between them is replaced,
//! because what is being tested is the contract, not the transport.

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use permguard_control_client::decisions::{
    DecisionReader, DecisionSink, Page, ReadError, ReadScope, ShipError, Shipped,
};
use permguard_control_plane::decisions::store::Scope;
use permguard_control_plane::decisions::{Accepted, DecisionStore, Refused, ingest, read};
use permguard_core::{KeyManager, Metrics};
use permguard_data_plane::decisions::journal::{Decided, Epoch, Journal, WhenFull};
use permguard_data_plane::decisions::shipper::{Round, Shipper};
use permguard_decisions::envelope::Batch;
use permguard_decisions::spool::Bounds;
use permguard_decisions::{Commitment, chain};
use permguard_std::keys::{DirectoryKeyManager, KeyPolicy};
use serde_json::{Value, json};

fn scratch(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "permguard-e2e-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or_default()
    ));
    let _ = std::fs::remove_dir_all(&root);

    root
}

fn ring(tag: &str) -> Arc<DirectoryKeyManager> {
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

    Arc::new(keys)
}

/// The socket, replaced: everything either side of it is the real thing.
struct DirectSink {
    store: Arc<DecisionStore>,
    keys: Arc<DirectoryKeyManager>,
    /// What the store answered, in order, so a test can read the conversation.
    seen: Mutex<Vec<String>>,
    /// Set to make the next shipment fail the way a network does.
    unavailable: Mutex<bool>,
}

impl DecisionSink for DirectSink {
    fn ship(&self, body: &Value) -> Result<Shipped, ShipError> {
        if *self.unavailable.lock().expect("not poisoned") {
            return Err(ShipError::Unavailable(
                "the control plane is down".to_owned(),
            ));
        }
        let batch: Batch =
            serde_json::from_value(body.clone()).map_err(|error| ShipError::Rejected {
                code: "malformed_batch".to_owned(),
                detail: error.to_string(),
            })?;
        let keys: Vec<ingest::ProducerTrust> = self
            .keys
            .public_keys()
            .expect("published")
            .into_iter()
            .map(|key| ingest::ProducerTrust {
                key,
                pdp: "plane-a".to_owned(),
            })
            .collect();

        match ingest::accept(&self.store, &batch, &keys) {
            Ok(Accepted::Ok { acked, stored }) => {
                self.seen
                    .lock()
                    .expect("not poisoned")
                    .push(format!("ok:{acked}:{stored}"));

                Ok(Shipped::Acknowledged { acked, stored })
            }
            Ok(Accepted::OutOfOrder { expected_seq }) => {
                self.seen
                    .lock()
                    .expect("not poisoned")
                    .push(format!("out_of_order:{expected_seq}"));

                Ok(Shipped::OutOfOrder { expected_seq })
            }
            Err(Refused::Unavailable(detail)) => Err(ShipError::Unavailable(detail)),
            Err(refused) => Err(ShipError::Rejected {
                code: "rejected".to_owned(),
                detail: refused.to_string(),
            }),
        }
    }
}

struct Pair {
    journal: Arc<Journal>,
    shipper: Shipper,
    store: Arc<DecisionStore>,
    sink: Arc<DirectSink>,
}

fn pair(tag: &str, bounds: Bounds) -> Pair {
    let keys = ring(&format!("{tag}-keys"));
    let store = Arc::new(DecisionStore::open(scratch(&format!("{tag}-store"))).expect("it opens"));
    let journal = Arc::new(
        Journal::open(
            scratch(&format!("{tag}-spool")),
            "plane-a",
            Epoch {
                version: "0.1.0".to_owned(),
                build: Some("sha256:9c4e".to_owned()),
                engines: BTreeMap::from([("cedar".to_owned(), "4.12.0".to_owned())]),
                sampling: "1.0".to_owned(),
            },
            WhenFull::Open,
            bounds,
            Commitment::new(*b"a-commitment-key", "v1"),
            Metrics::none(),
        )
        .expect("the journal opens"),
    );
    let sink = Arc::new(DirectSink {
        store: Arc::clone(&store),
        keys: Arc::clone(&keys),
        seen: Mutex::new(Vec::new()),
        unavailable: Mutex::new(false),
    });

    // The shipper takes both halves of the log, because a deployment gets
    // both from one client; this test only exercises the shipping one.
    struct Shared(Arc<DirectSink>);
    impl DecisionSink for Shared {
        fn ship(&self, body: &Value) -> Result<Shipped, ShipError> {
            self.0.ship(body)
        }
    }
    impl DecisionReader for Shared {
        fn read(
            &self,
            _scope: &ReadScope,
            _window: &permguard_control_client::decisions::ReadWindow,
        ) -> Result<Page, ReadError> {
            Err(ReadError::Unavailable(
                "this test reads through the store, not through the client".to_owned(),
            ))
        }

        fn signers(
            &self,
            _pdp_id: &str,
            _instance: &str,
            _from_seq: u64,
            _until_seq: u64,
        ) -> Result<Value, ReadError> {
            Err(ReadError::Unavailable(
                "this test reads through the store, not through the client".to_owned(),
            ))
        }
    }

    let shipper = Shipper::new(
        Arc::clone(&journal),
        Box::new(Shared(Arc::clone(&sink))),
        keys,
        256 * 1024,
        "1.0",
        Metrics::none(),
    );

    Pair {
        journal,
        shipper,
        store,
        sink,
    }
}

fn bounds() -> Bounds {
    Bounds {
        bytes: 1024 * 1024,
        age: Duration::from_secs(3600),
        segment_bytes: 4096,
    }
}

fn decided<'a>(id: &'a str, zone: &'a str, permit: bool) -> Decided<'a> {
    Decided {
        id,
        at: "2026-08-24T10:00:00Z".to_owned(),
        zone,
        ledger: "main-ledger",
        commit: "sha256:ec1773bf",
        counter: 3,
        profile: "default",
        subject: ("User".to_owned(), "pseudo:v1:9f2c".to_owned()),
        subject_properties: None,
        resource: ("Document".to_owned(), "budget".to_owned()),
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
        request_id: None,
        latency_us: 143,
        event: None,
    }
}

/// Every record of a scope, walked the way a consumer walks one.
///
/// Through the real bounded reader rather than a bulk call, because the bounds are the contract:
/// a helper that asked for ten thousand records at once would be testing a path no consumer takes.
fn read_all(store: &DecisionStore, scope: &Scope) -> Vec<Value> {
    let key = permguard_stream::CursorKey::new(b"a-test-cursor-key-of-32-bytes!!!!", &[])
        .expect("the key is long enough");
    let mut records = Vec::new();
    let mut window = permguard_stream::Window {
        limit_records: 100,
        ..permguard_stream::Window::default()
    };
    loop {
        let page = read::read(store, scope, &key, &window).expect("it reads");
        records.extend(page.records);
        if !page.more {
            break;
        }
        window.from = Some(page.next);
    }

    records
}

#[test]
fn what_a_plane_decided_reaches_the_store_verifiable_end_to_end() {
    let pair = pair("happy", bounds());
    for index in 0..50 {
        pair.journal
            .record(&decided(&format!("id-{index}"), "acme", index % 4 != 0))
            .expect("it records");
    }

    assert!(matches!(pair.shipper.round(), Round::Shipped { .. }));
    assert_eq!(
        pair.shipper.round(),
        Round::Idle,
        "and nothing is sent twice"
    );

    let stream = pair.journal.stream().expect("a stream");
    let held = read_all(
        &pair.store,
        &Scope::Stream {
            pdp_id: stream.id.clone(),
            instance: stream.instance.clone(),
        },
    );
    assert_eq!(held.len(), 51, "one marker and fifty decisions");

    let verified = chain::verify(&held, None).expect("what the store holds is a chain");
    assert!(
        verified.from_genesis,
        "and it is verifiable from the beginning, by anyone, without trusting the store"
    );
}

#[test]
fn a_control_plane_that_is_down_costs_spool_and_not_availability() {
    let pair = pair("outage", bounds());
    *pair.sink.unavailable.lock().expect("not poisoned") = true;

    for index in 0..20 {
        // The decision path is unaffected: recording is a local append.
        pair.journal
            .record(&decided(&format!("id-{index}"), "acme", true))
            .expect("it records");
    }
    assert!(matches!(pair.shipper.round(), Round::Deferred(_)));
    assert_eq!(
        pair.journal.pending(10_000).expect("it reads").len(),
        21,
        "nothing was truncated on the strength of an answer that never came"
    );

    *pair.sink.unavailable.lock().expect("not poisoned") = false;
    assert!(matches!(pair.shipper.round(), Round::Shipped { .. }));

    let stream = pair.journal.stream().expect("a stream");
    assert_eq!(
        read_all(
            &pair.store,
            &Scope::Stream {
                pdp_id: stream.id,
                instance: stream.instance
            }
        )
        .len(),
        21,
        "and everything arrives once the store comes back"
    );
}

#[test]
fn an_acknowledgement_the_producer_never_heard_is_not_a_duplicate_at_the_store() {
    let pair = pair("replay", bounds());
    for index in 0..10 {
        pair.journal
            .record(&decided(&format!("id-{index}"), "acme", true))
            .expect("it records");
    }

    // The batch lands; the answer is lost on the way back. The producer, not
    // having heard it, sends the same records again.
    let batch = pair.journal.pending(10_000).expect("it reads");
    assert!(matches!(pair.shipper.round(), Round::Shipped { .. }));
    let _ = batch;

    let stream = pair.journal.stream().expect("a stream");
    let scope = Scope::Stream {
        pdp_id: stream.id.clone(),
        instance: stream.instance.clone(),
    };
    let before = read_all(&pair.store, &scope).len();

    // A second round has nothing to send, which is the same guarantee from the
    // other side: the acknowledged records are gone from the spool.
    assert_eq!(pair.shipper.round(), Round::Idle);
    assert_eq!(read_all(&pair.store, &scope).len(), before);
}

#[test]
fn a_stream_that_ends_is_visible_at_the_store_before_its_successor_is() {
    let tight = Bounds {
        bytes: 4096,
        age: Duration::from_secs(3600),
        segment_bytes: 1024,
    };
    let pair = pair("discontinuity", tight);

    let mut ended = false;
    for index in 0..500 {
        if let permguard_data_plane::decisions::Written::Discontinued { .. } = pair
            .journal
            .record(&decided(&format!("id-{index}"), "acme", true))
            .expect("it records")
        {
            ended = true;
            break;
        }
    }
    assert!(ended, "the spool filled and the stream ended");

    // The terminal record ships on its own, first.
    assert!(matches!(
        pair.shipper.round(),
        Round::Shipped { records: 1, .. }
    ));
    // Then the successor's records.
    assert!(matches!(pair.shipper.round(), Round::Shipped { .. }));

    let closed = pair.sink.seen.lock().expect("not poisoned").len();
    assert!(closed >= 2);
}

#[test]
fn a_batch_the_store_refuses_on_its_merits_stops_the_shipper_instead_of_looping() {
    let pair = pair("rejected", bounds());
    pair.journal
        .record(&decided("id-1", "acme", true))
        .expect("it records");
    // A stream the store has already closed accepts nothing further.
    let stream = pair.journal.stream().expect("a stream");
    pair.store
        .close(&stream.id, &stream.instance, "a conflict, earlier")
        .expect("it closes");

    assert!(
        matches!(pair.shipper.round(), Round::Stopped { .. }),
        "retrying cannot change this answer, and spinning on it would hide the incident"
    );
    assert_eq!(
        pair.journal.pending(10).expect("it reads").len(),
        2,
        "and the records stay where they are, as evidence"
    );
}

#[test]
fn each_tenant_s_view_is_populated_from_the_one_producer_stream() {
    let pair = pair("tenancy", bounds());
    for index in 0..20 {
        let zone = if index % 2 == 0 { "acme" } else { "globex" };
        pair.journal
            .record(&decided(&format!("id-{index}"), zone, true))
            .expect("it records");
    }
    assert!(matches!(pair.shipper.round(), Round::Shipped { .. }));

    for zone in ["acme", "globex"] {
        let records = read_all(
            &pair.store,
            &Scope::Tenant {
                zone: zone.to_owned(),
                ledger: "main-ledger".to_owned(),
            },
        );
        assert!(
            records
                .iter()
                .filter(|record| record["kind"] == json!("decision"))
                .all(|record| record["store"]["zone"] == json!(zone)),
            "{zone} sees only its own"
        );
        assert_eq!(
            records.first().map(|record| record["kind"].clone()),
            Some(json!("marker")),
            "and the epoch that governs them, which carries no tenant data at all"
        );
    }
}

#[test]
fn the_signer_manifest_travels_with_the_decision_stream_on_both_sides() {
    let pair = pair("signers", bounds());
    for index in 0..10 {
        pair.journal
            .record(&decided(&format!("id-{index}"), "acme", true))
            .expect("it records");
    }

    assert!(matches!(pair.shipper.round(), Round::Shipped { .. }));

    let stream = pair.journal.stream().expect("a stream");

    // The producer's spool names the key that signed its stretch — from sequence 1, because the
    // stream's opening marker is part of what the first batch covers.
    let held = pair.journal.signers().expect("the manifest reads");
    let spans = held.spans();
    assert_eq!(spans.len(), 1, "one key is one fact");
    assert_eq!(spans[0].from, 1);
    assert_eq!(
        spans[0].jwk.get("kid").and_then(Value::as_str),
        Some(spans[0].kid.as_str()),
        "the public key itself travels, not only its name"
    );

    // And the store, from what it actually verified against.
    let store_held = pair
        .store
        .signers(&stream.id, &stream.instance)
        .expect("the store's manifest reads");
    assert_eq!(store_held.spans().len(), 1);
    assert_eq!(store_held.spans()[0].kid, spans[0].kid);
    assert_eq!(
        store_held.covering(3, 7).len(),
        1,
        "a bounded range still names the span covering it"
    );
}

#[test]
fn asking_for_the_signers_of_a_stream_nobody_holds_is_not_found() {
    // An empty manifest reads as "held, nothing signed yet"; a typo in a producer name must not
    // read as that.
    let pair = pair("unknown-signers", bounds());
    let facade = permguard_control_plane::decisions::http::DecisionFacade {
        store: Arc::clone(&pair.store),
        local: None,
        local_pdp: String::new(),
        cursor_key: permguard_stream::CursorKey::new(b"a-test-cursor-key-of-32-bytes!!!!", &[])
            .expect("a cursor key"),
        producers: Arc::new(std::sync::RwLock::new(Vec::new())),
        producer_files: Vec::new(),
        disclosure: permguard_core::Disclosure::Full,
        metrics: Metrics::none(),
    };

    let refused = facade
        .signers_of("no-such-plane", "no-such-instance", 0, 0)
        .expect_err("an unknown stream is a refusal");
    assert_eq!(refused.code(), "stream_unknown", "{refused:?}");
}
