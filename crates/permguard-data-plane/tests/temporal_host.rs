// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The event log on the Host's real stream engine (WP-6.2a, owner decisions of 2026-10-18): a
//! volume with its identity, its `host.operations` and `data.attest` rings and the engine's event
//! producer, composed as the server composes it.
//!
//! A record names the Host and its run at the engine's sequence, chained by the engine's digests;
//! the plane reads its history back from the producer across a restart and a rollover; the floor
//! it registers replaces the one the producer was built with.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use permguard_core::assurance::AssuranceProfile;
use permguard_core::authz::Resource;
use permguard_data_plane::temporal::streams::{HostSide, Streams, Written};
use permguard_events::journal::Bounds;
use permguard_events::record::{PRODUCER_CLASS_DATA_PLANE, Producer, RECORD_TYPE, Record, Stream};
use permguard_events::stream::{Codec, STREAM};
use permguard_host::composition::{Declaration, Host};
use permguard_host::identity::{Identity, Suite, directories};
use permguard_host::keys::FileKeyProvider;
use permguard_host::keys::ring::{DATA_ATTEST, HOST_OPERATIONS, Policy, Ring};
use permguard_host::storage::volume::Volume;
use permguard_host::time::TimeGuard;
use permguard_stream::engine::{Producer as EngineProducer, Served, Streams as Engine};
use serde_json::json;

const ZONE_ID: &str = "zone-1";
const LEDGER_ID: &str = "ledger-1";

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-temporal-host-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("created");
    path
}

/// A volume with what the Host composes for the event stream.
struct HostVolume {
    root: PathBuf,
    volume: Volume,
    identity: Arc<Identity>,
    operations: Arc<Ring>,
    attest: Arc<Ring>,
    time: Arc<TimeGuard>,
}

impl HostVolume {
    fn new(tag: &str) -> Self {
        let root = scratch(tag);
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let time = Arc::new(TimeGuard::system(Duration::from_secs(30)));
        let identity = Arc::new(
            Identity::provision(
                &volume,
                Arc::new(FileKeyProvider::new(
                    directories(&volume).expect("the identity directory").1,
                )),
                Suite::Ed25519Sha256V1,
                permguard_host::authz::store::now(),
                permguard_host::authz::store::now() * 1000,
            )
            .expect("provisioned"),
        );
        let ring = |id: &'static str| {
            let ring = Arc::new(
                Ring::open(
                    &volume,
                    id,
                    Suite::Ed25519Sha256V1,
                    Policy {
                        publish_ahead: Duration::from_secs(600),
                        rotate_every: Duration::from_secs(3600),
                        retain: Duration::from_secs(7200),
                    },
                    Arc::clone(&time),
                )
                .expect("the ring opens")
                .with_binder(identity.clone()),
            );
            permguard_core::KeyManager::maintain(ring.as_ref()).expect("the first key");
            ring
        };
        let operations = ring(HOST_OPERATIONS);
        let attest = ring(DATA_ATTEST);
        Self {
            root,
            volume,
            identity,
            operations,
            attest,
            time,
        }
    }

    /// The engine's event producer, as the server builds it: sealing under `data.attest`, kept
    /// whole until the plane registers its floor.
    fn producer(&self) -> Arc<EngineProducer<Codec>> {
        Arc::new(
            Engine::open(
                &self.volume,
                &self.identity,
                Arc::clone(&self.operations),
                Arc::clone(&self.time),
            )
            .expect("the engine opens")
            .register_producer(permguard_events::stream::descriptor(), Codec)
            .expect("registered")
            .with_signer(Arc::clone(&self.attest))
            .expect("the descriptor's ring")
            .with_retention_floor(Arc::new(permguard_stream::engine::retention::KeepWhole)),
        )
    }

    /// The plane's streams over `producer`, as the temporal interface composes them.
    fn streams(&self, producer: &Arc<EngineProducer<Codec>>) -> Streams {
        let registration = Host::builder()
            .streams(Arc::new(
                Served::default().with(STREAM, Arc::clone(producer)),
            ))
            .host_id(self.identity.host_id())
            .build()
            .register(Declaration::new("data").produces_stream(STREAM))
            .expect("registers");
        Streams::new(
            self.root.join("data/events"),
            self.root.join("planes/data/temporal"),
            HostSide {
                producer: registration
                    .stream_producer(STREAM)
                    .expect("declared")
                    .expect("composed"),
                host_id: self.identity.host_id(),
            },
            Bounds::default(),
        )
        .expect("the floor is registered")
    }

    fn host_hex(&self) -> String {
        hex(&self.identity.host_id())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn occurrence(id: u64, source: &str) -> Record {
    let at = permguard_events::index::render_epoch_seconds(1_700_000_000 + id as i64)
        .expect("an instant");
    let event = json!({"event_id": format!("e-{id}"), "kind": "response", "action": "Read"});
    Record {
        v: 1,
        record_type: RECORD_TYPE.to_owned(),
        stream: Stream {
            producer: Producer {
                class: PRODUCER_CLASS_DATA_PLANE.to_owned(),
                id: "proposed".to_owned(),
                instance: "proposed".to_owned(),
            },
            zone: ZONE_ID.to_owned(),
            ledger: LEDGER_ID.to_owned(),
        },
        seq: 0,
        prev: String::new(),
        event_type: "permguard.dogwood.event.v1".to_owned(),
        event_id: format!("e-{id}"),
        source: Some(source.to_owned()),
        occurrence_digest: permguard_events::occurrence_digest_of(&event).expect("a digest"),
        kind: "response".to_owned(),
        profile: "temporal".to_owned(),
        policy_partitions: vec!["governance".to_owned()],
        commit: "sha256:commit".to_owned(),
        history_key: None,
        occurred_at: at.clone(),
        observed_at: at,
        event,
    }
}

#[test]
fn an_event_names_the_host_and_its_run_on_the_real_engine() {
    let host = HostVolume::new("names");
    let producer = host.producer();
    let streams = host.streams(&producer);
    for id in 1..=3 {
        let (written, record) = streams
            .append(ZONE_ID, LEDGER_ID, occurrence(id, "alice"))
            .expect("durable");
        assert!(matches!(written, Written::Appended { seq, .. } if seq == id));
        assert_eq!(record.stream.producer.id, host.host_hex());
    }
    let resource = Resource::ledger("data", ZONE_ID, LEDGER_ID);
    let run = producer
        .state(&resource)
        .expect("state")
        .expect("a run")
        .run_id;
    // On the engine, at its sequences, chained by its digests: a version 1 event stream.
    let held: Vec<serde_json::Value> = producer
        .read(&resource, 1, 100)
        .expect("the stream reads")
        .records
        .into_iter()
        .map(|(_, value)| value)
        .collect();
    assert_eq!(held.len(), 3);
    for record in &held {
        assert_eq!(record["stream"]["producer"]["id"], host.host_hex());
        assert_eq!(record["stream"]["producer"]["instance"], hex(&run));
        assert_eq!(record["source"], "alice");
    }
    permguard_events::chain::verify(&held, None).expect("one unbroken chain");
    // The plane's read back is the engine's bytes.
    assert_eq!(
        streams.read_from(ZONE_ID, LEDGER_ID, 0, 100).expect("read"),
        held
    );
    // A retry from the same source is the stored position; from another, another occurrence.
    let (retried, _) = streams
        .append(ZONE_ID, LEDGER_ID, occurrence(2, "alice"))
        .expect("a retry is an answer");
    assert_eq!(retried, Written::Idempotent { seq: 2 });
    let (other, _) = streams
        .append(ZONE_ID, LEDGER_ID, occurrence(2, "bob"))
        .expect("another source");
    assert!(matches!(other, Written::Appended { seq: 4, .. }));
}

#[test]
fn the_history_reads_back_across_a_restart_and_a_rollover_on_the_real_engine() {
    let host = HostVolume::new("restart");
    let producer = host.producer();
    let streams = host.streams(&producer);
    streams
        .append(ZONE_ID, LEDGER_ID, occurrence(1, "alice"))
        .expect("durable");
    streams
        .append(ZONE_ID, LEDGER_ID, occurrence(2, "alice"))
        .expect("durable");
    drop(streams);
    let resource = Resource::ledger("data", ZONE_ID, LEDGER_ID);
    producer.rollover(&resource, None).expect("rolled over");
    drop(producer);

    let producer = host.producer();
    let streams = host.streams(&producer);
    let (written, record) = streams
        .append(ZONE_ID, LEDGER_ID, occurrence(3, "alice"))
        .expect("durable");
    assert!(
        matches!(written, Written::Appended { seq: 3, .. }),
        "the ordinal runs on: {written:?}"
    );
    assert_eq!(record.seq, 1, "the new run starts at one");
    let held = streams.read_from(ZONE_ID, LEDGER_ID, 0, 100).expect("read");
    assert_eq!(
        held.iter()
            .map(|record| record["event_id"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>(),
        ["e-1", "e-2", "e-3"]
    );
    assert_eq!(
        streams.record_at(ZONE_ID, LEDGER_ID, 2).expect("held")["event_id"],
        "e-2"
    );
    let (retried, _) = streams
        .append(ZONE_ID, LEDGER_ID, occurrence(1, "alice"))
        .expect("a retry after the restart");
    assert_eq!(retried, Written::Idempotent { seq: 1 });
}

/// What an earlier release journalled: `count` occurrences in the legacy journal of the ledger.
fn legacy_journal(root: &std::path::Path, count: u64) -> PathBuf {
    let directory = root.join("data/events").join(ZONE_ID).join(LEDGER_ID);
    let stream = Stream {
        producer: Producer {
            class: PRODUCER_CLASS_DATA_PLANE.to_owned(),
            id: "plane-before".to_owned(),
            instance: "01931f2c".to_owned(),
        },
        zone: ZONE_ID.to_owned(),
        ledger: LEDGER_ID.to_owned(),
    };
    let mut journal =
        permguard_events::journal::Journal::open(&directory, stream.clone(), Bounds::default())
            .expect("the legacy journal opens");
    for id in 1..=count {
        let (seq, prev) = journal.next_position();
        let mut held = occurrence(id, "ignored");
        held.source = None;
        held.stream = stream.clone();
        held.seq = seq;
        held.prev = prev;
        let appended = journal
            .append(&held.to_value().expect("renders"))
            .expect("durable");
        // As the old writer did: the entry that makes a retry recognisable, with the record.
        journal
            .record_occurrence(&permguard_events::journal::KnownOccurrence {
                event_id: held.event_id.clone(),
                source: None,
                seq: appended.seq,
                occurrence_digest: held.occurrence_digest.clone(),
                decision_id: None,
                profile: Some("temporal".to_owned()),
                kind: Some("response".to_owned()),
                response: json!({"decision": false}),
            })
            .expect("recorded");
    }
    journal.sync_occurrences().expect("flushed");
    directory
}

/// The digest of every file below a directory, its lock aside, to tell it was not written.
fn contents(directory: &std::path::Path) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(at) = pending.pop() {
        for entry in std::fs::read_dir(&at).expect("listed").flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if entry.file_name() != "LOCK" {
                found.push((
                    path.strip_prefix(directory)
                        .expect("below")
                        .to_string_lossy()
                        .into_owned(),
                    permguard_events::record::digest_hex(&std::fs::read(&path).expect("read")),
                ));
            }
        }
    }
    found.sort();
    found
}

/// WP-6.4b: this plane's journal as the logical index reads it. Its copy of a vouched-for key is
/// only one recorded under exactly that source, so a legacy occurrence, which no source vouched for,
/// is never another origin's occurrence; its records come in local order with their local
/// positions, the legacy journal's first.
#[test]
fn the_logical_index_reads_only_what_a_source_vouched_for_from_this_planes_journal() {
    use permguard_data_plane::temporal::imported::Local;

    let host = HostVolume::new("logical-local");
    legacy_journal(&host.root, 2);
    let producer = host.producer();
    let streams = host.streams(&producer);
    streams
        .append(ZONE_ID, LEDGER_ID, occurrence(3, "alice"))
        .expect("durable");

    // `e-1` is held, but the legacy journal holds it sourceless: no copy of alice's `e-1`.
    assert!(
        streams
            .copy(ZONE_ID, LEDGER_ID, "alice", "e-1")
            .expect("read")
            .is_none()
    );
    // `e-3` is alice's, and only alice's.
    let copy = streams
        .copy(ZONE_ID, LEDGER_ID, "alice", "e-3")
        .expect("read")
        .expect("held");
    assert_eq!(copy["event_id"], "e-3");
    assert_eq!(copy["stream"]["producer"]["id"], host.host_hex().as_str());
    assert!(
        streams
            .copy(ZONE_ID, LEDGER_ID, "bob", "e-3")
            .expect("read")
            .is_none()
    );

    let after = |from: u64, limit: usize| -> Vec<(u64, String)> {
        streams
            .after(ZONE_ID, LEDGER_ID, from, limit)
            .expect("read")
            .into_iter()
            .map(|(position, record)| (position, record["event_id"].as_str().unwrap().to_owned()))
            .collect()
    };
    assert_eq!(
        after(0, 10),
        [
            (1, "e-1".to_owned()),
            (2, "e-2".to_owned()),
            (3, "e-3".to_owned())
        ]
    );
    assert_eq!(after(1, 1), [(2, "e-2".to_owned())]);
    assert_eq!(after(2, 10), [(3, "e-3".to_owned())]);
    assert!(after(3, 10).is_empty());
}

/// WP-6.2a (owner decision of 2026-10-18): an upgraded plane's legacy journal is history, read
/// first and never appended to (its occurrence entries included); the Host runs' ordinals follow it, and a retry of what it holds is
/// the stored position from any source.
#[test]
fn a_legacy_journal_is_read_first_and_never_appended_to() {
    let host = HostVolume::new("legacy");
    let directory = legacy_journal(&host.root, 2);
    let before = contents(&directory);
    let producer = host.producer();
    let streams = host.streams(&producer);

    let (written, record) = streams
        .append(ZONE_ID, LEDGER_ID, occurrence(3, "alice"))
        .expect("durable");
    assert!(
        matches!(written, Written::Appended { seq: 3, .. }),
        "after the legacy journal's two: {written:?}"
    );
    assert_eq!(record.stream.producer.id, host.host_hex());
    let held = streams.read_from(ZONE_ID, LEDGER_ID, 0, 100).expect("read");
    assert_eq!(
        held.iter()
            .map(|record| record["stream"]["producer"]["id"]
                .as_str()
                .unwrap()
                .to_owned())
            .collect::<Vec<_>>(),
        ["plane-before", "plane-before", host.host_hex().as_str()],
        "the legacy journal first, then the Host's stream"
    );
    // A retry of a legacy occurrence, from whichever source: the stored position.
    let (retried, _) = streams
        .append(ZONE_ID, LEDGER_ID, {
            let mut retry = occurrence(1, "bob");
            retry.source = Some("bob".to_owned());
            retry
        })
        .expect("a retry across the upgrade");
    assert_eq!(retried, Written::Idempotent { seq: 1 });
    // Its answer kept beside the Host stream's entries, never in the legacy journal.
    streams
        .record_outcome(
            ZONE_ID,
            LEDGER_ID,
            "bob",
            "e-1",
            permguard_data_plane::temporal::streams::Routed {
                profile: "temporal",
                kind: "response",
            },
            &json!({"decision": true}),
        )
        .expect("kept");
    assert_eq!(
        streams
            .outcome(ZONE_ID, LEDGER_ID, "carol", "e-1")
            .expect("read"),
        Some(json!({"decision": true}))
    );
    assert_eq!(
        streams
            .scan(
                ZONE_ID,
                LEDGER_ID,
                &permguard_events::index::Query {
                    event_type: "permguard.dogwood.event.v1".to_owned(),
                    history: String::new(),
                    action: None,
                    kind: None,
                    from: 0,
                    until: i64::MAX,
                }
            )
            .expect("scanned")
            .iter()
            .map(|(position, _)| *position)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    drop(streams);
    assert_eq!(
        contents(&directory),
        before,
        "the legacy journal was not written"
    );
}

/// WP-6.2d: once the volume archived the legacy history, the plane never opens its old generation:
/// no journal is read, shipped or evicted, and its files, its lock among them, stay as they were.
#[test]
fn an_archived_legacy_journal_is_neither_opened_nor_written() {
    let host = HostVolume::new("archived");
    let directory = legacy_journal(&host.root, 2);
    std::fs::remove_file(directory.join("LOCK")).expect("the old writer's lock");
    // The same ledger journalled under its names too, as a release keying by name left it.
    let named = host.root.join("data/events/zone-name/ledger-name");
    std::fs::create_dir_all(&named).expect("created");
    for entry in std::fs::read_dir(&directory).expect("listed").flatten() {
        if entry.path().is_file() {
            std::fs::copy(entry.path(), named.join(entry.file_name())).expect("copied");
        }
    }
    let before = contents(&host.root.join("data/events"));
    let producer = host.producer();
    let streams = host.streams(&producer).without_legacy();
    assert!(
        streams.ledgers().is_empty(),
        "no legacy journal is shipped or evicted"
    );
    // Neither adopted nor refused as ambiguous: the archived journals are not read.
    streams
        .adopt((ZONE_ID, LEDGER_ID), ("zone-name", "ledger-name"))
        .expect("nothing to adopt in an archived legacy");

    let (written, _) = streams
        .append(ZONE_ID, LEDGER_ID, occurrence(3, "alice"))
        .expect("durable");
    assert!(
        matches!(written, Written::Appended { seq: 1, .. }),
        "the Host's runs alone: {written:?}"
    );
    let held = streams.read_from(ZONE_ID, LEDGER_ID, 0, 100).expect("read");
    assert_eq!(
        held.iter()
            .map(|record| record["stream"]["producer"]["id"]
                .as_str()
                .unwrap()
                .to_owned())
            .collect::<Vec<_>>(),
        [host.host_hex()],
        "nothing of the archived journal"
    );
    drop(streams);
    assert_eq!(
        contents(&host.root.join("data/events")),
        before,
        "nothing written"
    );
    assert!(!directory.join("LOCK").exists(), "never opened");
}

/// WP-6.2a: the floor the plane measures is what it registered on the engine (whose replacement
/// of its own floor the engine's tests show), per run.
#[test]
fn the_floor_the_plane_measures_is_per_run() {
    use permguard_host::composition::StreamFloor as _;
    let host = HostVolume::new("floor");
    let producer = host.producer();
    let streams = host.streams(&producer);
    for id in 1..=4 {
        streams
            .append(ZONE_ID, LEDGER_ID, occurrence(id, "alice"))
            .expect("durable");
    }
    let resource = Resource::ledger("data", ZONE_ID, LEDGER_ID);
    let run = producer
        .state(&resource)
        .expect("state")
        .expect("a run")
        .run_id;
    // Observed at 1_700_000_001 to _004: a horizon of _003 lets the first two go.
    streams.refresh_floors(1_700_000_003).expect("measured");
    let floors = streams.floors();
    assert_eq!(floors.retention_safe(&resource.to_string(), &run), Some(2));
    assert_eq!(
        floors.retention_safe(&resource.to_string(), &[9; 16]),
        None,
        "a run never measured is kept whole"
    );
    streams.refresh_floors(1_700_000_000).expect("measured");
    assert_eq!(
        floors.retention_safe(&resource.to_string(), &run),
        Some(0),
        "nothing observed before the horizon: nothing goes"
    );
}
