// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! An event, from the plane that recorded it to the plane that keeps it — and back again.
//!
//! Both halves of the exchange are the real ones: a real journal on a real disk, the real shipper
//! assembling and signing a batch, the real store verifying and keeping it, and the real puller
//! importing it back with its proofs. Between them there is a sink that hands the bytes over, which
//! is the only thing standing in for a network.
//!
//! | | |
//! | --- | --- |
//! | what one plane recorded is what the other holds, byte for byte | |
//! | the acknowledgement is what the producer may advance by, and no more | |
//! | a control plane that is down defers rather than losing history | |
//! | an imported record is verified before it is applied, and never re-signed | |
//! | one occurrence recorded by two planes is imported once and kept twice | |

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use permguard_control_client::events::{
    EventReader, EventSink, Page, ReadError, ReadScope, ReadWindow, ShipError, Shipped,
};
use permguard_control_plane::events::http::EventFacade;
use permguard_control_plane::events::read::Filters;
use permguard_control_plane::events::store::{EventStore, Scope};
use permguard_control_plane::events::{ingest, read};
use permguard_core::keys::{PublicSet as _, Sign as _};
use permguard_core::{Disclosure, KeyManager, Metrics};
use permguard_data_plane::temporal::imports::Imports;
use permguard_data_plane::temporal::shipper::{Round, Shipper};
use permguard_data_plane::temporal::streams::Streams;
use permguard_events::journal::Bounds;
use permguard_events::record::{PRODUCER_CLASS_DATA_PLANE, Record, Stream};
use permguard_std::keys::{DirectoryKeyManager, KeyPolicy};
use serde_json::{Value, json};

/// The authority every mirror of these tests lives under (WP-7.2a): a mirror in a configured URL's
/// shape is never served since WP-7.7.
const MIRROR_AUTHORITY: &str = "11111111111111111111111111111111";
/// The task the mirrors of these tests were listed by: the local task.
const MIRROR_TASK: &str = "00000000-0000-0000-0000-000000000000/local";

const ZONE: &str = "acme";
const LEDGER: &str = "agent-governance";
/// What a ledger is keyed by once resolved: records, streams and trust scopes all name these, and
/// the production pull path canonicalises an operator's subscription into them before subscribing.
const ZONE_ID: &str = "acme-id";
const LEDGER_ID: &str = "agent-governance-id";
const DOGWOOD: &str = "permguard.dogwood.event.v1";

fn scratch(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "pg-event-e2e-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&root);

    root
}

fn ring(tag: &str) -> Arc<DirectoryKeyManager> {
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

    Arc::new(keys)
}

/// The control plane, as a sink and a reader a data plane can reach.
///
/// The only thing standing in for a network: everything on both sides of it is the real code, and
/// the bytes that cross are the bytes a socket would carry.
struct Wire {
    facade: EventFacade,
    /// Set to defer every exchange, as a control plane that is down does.
    down: std::sync::atomic::AtomicBool,
}

impl EventSink for Wire {
    fn ship(&self, batch: &permguard_events::Batch) -> Result<Shipped, ShipError> {
        if self.down.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(ShipError::Unavailable(
                "the control plane is down".to_owned(),
            ));
        }
        // Through JSON, because that is what the wire carries and a struct handed straight over
        // would not exercise the rendering the signature was taken over.
        let carried: permguard_events::Batch =
            serde_json::from_slice(&serde_json::to_vec(batch).expect("it renders"))
                .expect("it parses");

        match self.facade.ingest(&carried) {
            Ok(ingest::Accepted::Ok { acked, .. }) => Ok(Shipped::Acknowledged { acked }),
            Ok(ingest::Accepted::OutOfOrder { expected_seq }) => {
                Ok(Shipped::OutOfOrder { expected_seq })
            }
            Err(refused) => Err(ShipError::Rejected {
                code: refused.code().to_owned(),
                detail: refused.to_string(),
            }),
        }
    }
}

impl EventReader for Wire {
    fn read(&self, scope: &ReadScope, window: &ReadWindow) -> Result<Page, ReadError> {
        let (held, kind) = match scope {
            ReadScope::Tenant { zone, ledger } => (
                Scope::Tenant {
                    zone: zone.clone(),
                    ledger: ledger.clone(),
                },
                "tenant",
            ),
            ReadScope::Stream {
                zone,
                ledger,
                class,
                producer,
                instance,
            } => (
                Scope::Stream {
                    zone: zone.clone(),
                    ledger: ledger.clone(),
                    class: class.clone(),
                    producer: producer.clone(),
                    instance: instance.clone(),
                },
                "stream",
            ),
        };
        let filters = Filters {
            event_types: window.filters.event_types.clone(),
            ..Filters::default()
        };
        let asked = permguard_stream::Window {
            from: window.from.clone(),
            until: window
                .until
                .as_deref()
                .and_then(permguard_stream::Frontier::decode),
            limit_records: window.limit_records,
            limit_bytes: window.limit_bytes,
            proof: window.proof,
        };

        match self.facade.read(&held, &filters, &asked, kind) {
            Ok(page) => Ok(
                serde_json::from_value(serde_json::to_value(page).expect("it renders"))
                    .expect("it parses"),
            ),
            Err(read::ReadError::Expired {
                oldest,
                oldest_sequence,
                requested_sequence,
            }) => Err(ReadError::Expired {
                oldest,
                oldest_sequence,
                requested_sequence,
            }),
            Err(error) => Err(ReadError::Refused {
                code: permguard_core::codes::stream::EVENT_STORE_UNAVAILABLE.to_owned(),
                detail: error.to_string(),
            }),
        }
    }

    fn signers(
        &self,
        zone: &str,
        ledger: &str,
        ask: &permguard_control_client::events::SignersAsk,
    ) -> Result<Value, ReadError> {
        let document = self
            .facade
            .signers_of(
                zone,
                ledger,
                ask.from_seq,
                ask.until_seq,
                &permguard_control_plane::events::http::StreamsAsked {
                    producer_class: ask.producer_class.clone(),
                    producer: ask.producer.clone(),
                    instance: ask.instance.clone(),
                    after: ask.after.clone().map(|(class, producer, instance)| {
                        permguard_stream::StreamPosition::new(class, producer, instance)
                            .expect("the test cursor is canonical")
                    }),
                },
            )
            .map_err(|error| ReadError::Unavailable(error.to_string()))?;

        serde_json::to_value(serde_json::json!({ "streams": document.streams }))
            .map_err(|error| ReadError::Unavailable(error.to_string()))
    }

    fn get(&self, zone: &str, ledger: &str, event_id: &str) -> Result<Option<Value>, ReadError> {
        read::get(
            &read::Sources {
                store: &self.facade.store,
                host: None,
            },
            &Scope::Tenant {
                zone: zone.to_owned(),
                ledger: ledger.to_owned(),
            },
            event_id,
            &self.facade.cursor_key,
        )
        .map_err(|error| ReadError::Refused {
            code: permguard_core::codes::stream::EVENT_STORE_UNAVAILABLE.to_owned(),
            detail: error.to_string(),
        })
    }
}

/// A control plane that accepts what this ring signs.
fn control(tag: &str, keys: &DirectoryKeyManager) -> Arc<Wire> {
    let store = EventStore::open(scratch(&format!("{tag}-store"))).expect("the store opens");
    let cursor_key =
        permguard_control_plane::decisions::cursorkey::load(store.root(), [1; 16], "events")
            .expect("an offset key is created");

    let published = keys.public_keys().expect("the ring publishes");
    let producers = ["plane-a", "plane-b"]
        .into_iter()
        .flat_map(|producer| {
            published.iter().cloned().map(move |key| {
                permguard_control_plane::events::ingest::ProducerTrust {
                    key,
                    producer: producer.to_owned(),
                    zone: "*".to_owned(),
                    ledger: "*".to_owned(),
                }
            })
        })
        .collect();

    Arc::new(Wire {
        facade: EventFacade {
            host: None,
            // These fixtures address records by identity, so there are no names to resolve.
            catalog: None,
            store: Arc::new(store),
            producers: Arc::new(std::sync::RwLock::new(producers)),
            local: None,
            cursor_key,
            disclosure: Disclosure::Full,
            metrics: Metrics::none(),
            base_url: "http://127.0.0.1:6443".to_owned(),
            describer: permguard_core::stages::Describer::detached("control-plane"),
            authorization: std::sync::Arc::new(
                permguard_host::composition::Authorization::permissive(),
            ),
        },
        down: std::sync::atomic::AtomicBool::new(false),
    })
}

/// A data plane upgraded beside the legacy journal `producer` wrote of `count` occurrences, on a
/// real disk: what its old shipper still sends until it is empty (WP-6.2a).
fn journals(tag: &str, producer: &str, count: u64) -> Arc<Streams> {
    let root = scratch(&format!("{tag}-events"));
    write_legacy(&root, producer, &occurrences(count, 1));
    streams_over(&root)
}

/// A plane's streams over `root`, on the Host's producer a test keeps in memory.
fn streams_over(root: &std::path::Path) -> Arc<Streams> {
    Arc::new(
        Streams::new(
            root.to_path_buf(),
            root.join("planes"),
            permguard_data_plane::temporal::testing::host_side(root),
            Bounds::default(),
        )
        .expect("the floor is registered"),
    )
}

/// Writes `records` as the legacy journal `producer` kept of the ledger below `root`, each
/// placed in that journal's own chain: what an earlier release recorded.
fn write_legacy(root: &std::path::Path, producer: &str, records: &[Record]) {
    let stream = Stream {
        producer: permguard_events::Producer {
            class: PRODUCER_CLASS_DATA_PLANE.to_owned(),
            id: producer.to_owned(),
            instance: "01931f2c".to_owned(),
        },
        zone: ZONE_ID.to_owned(),
        ledger: LEDGER_ID.to_owned(),
    };
    let mut journal = permguard_events::journal::Journal::open(
        root.join(ZONE_ID).join(LEDGER_ID),
        stream.clone(),
        Bounds::default(),
    )
    .expect("the legacy journal opens");
    for held in records {
        let (seq, prev) = journal.next_position();
        let mut held = held.clone();
        held.stream = stream.clone();
        held.seq = seq;
        held.prev = prev;
        journal
            .append(&held.to_value().expect("the record renders"))
            .expect("the record is durable");
    }
}

/// `count` occurrences from `from`, as a plane proposes them.
fn occurrences(count: u64, from: u64) -> Vec<Record> {
    let mut proposed = Vec::new();
    for index in 0..count {
        let seq = from + index;
        let occurred = permguard_events::index::render_epoch_seconds(1_700_000_000 + seq as i64)
            .expect("an instant");
        let event = json!({
            "event_id": format!("e-{seq}"),
            "kind": "response",
            "action": "Drupe::Action::Login",
            "principal": "Drupe::OAuthUser::\"alice\"",
            "resource": "Drupe::Gateway::\"gw1\"",
            "logged": {"input": {"user": "alice", "server": "s1"}, "output": {}},
            "request_context": {"input": {"user": "alice", "server": "s1"}},
            "occurred_at": occurred,
        });
        let held = Record {
            v: 1,
            record_type: permguard_events::RECORD_TYPE.to_owned(),
            stream: Stream {
                producer: permguard_events::Producer {
                    class: PRODUCER_CLASS_DATA_PLANE.to_owned(),
                    id: String::new(),
                    instance: String::new(),
                },
                zone: ZONE_ID.to_owned(),
                ledger: LEDGER_ID.to_owned(),
            },
            seq: 0,
            prev: String::new(),
            event_type: DOGWOOD.to_owned(),
            event_id: format!("e-{seq}"),
            source: None,
            occurrence_digest: permguard_events::occurrence_digest_of(&event)
                .expect("the occurrence digests"),
            kind: "response".to_owned(),
            profile: "temporal".to_owned(),
            policy_partitions: vec!["governance".to_owned()],
            commit: "sha256:commit".to_owned(),
            history_key: None,
            occurred_at: occurred.clone(),
            observed_at: occurred,
            event,
        };
        proposed.push(held);
    }
    proposed
}

#[test]
fn what_one_plane_recorded_is_what_the_other_holds_byte_for_byte() {
    let keys = ring("happy");
    let wire = control("happy", &keys);
    let streams = journals("happy", "plane-a", 12);

    let shipper = Shipper::new(
        Arc::clone(&streams),
        Box::new(Handed(Arc::clone(&wire))),
        Arc::new(permguard_events::envelope::RingSigner(
            Arc::clone(&keys) as Arc<dyn KeyManager>
        )),
        1024 * 1024,
        Metrics::none(),
    );

    let rounds = shipper.round();
    assert_eq!(rounds.len(), 1, "one ledger, one round");
    assert!(
        matches!(
            rounds[0].1,
            Round::Shipped {
                records: 12,
                acked: 12
            }
        ),
        "{:?}",
        rounds[0].1
    );

    // What the producer holds, and what the store holds, are the same bytes.
    let here = streams
        .read_from(ZONE_ID, LEDGER_ID, 0, 1_000)
        .expect("the journal reads");
    let there = read::read(
        &wire.facade.store,
        &Scope::Tenant {
            zone: ZONE_ID.to_owned(),
            ledger: LEDGER_ID.to_owned(),
        },
        &Filters::default(),
        &wire.facade.cursor_key,
        &permguard_stream::Window {
            limit_records: 1_000,
            ..permguard_stream::Window::default()
        },
    )
    .expect("the store reads");

    assert_eq!(here.len(), there.records.len());
    for (mine, theirs) in here.iter().zip(&there.records) {
        assert_eq!(
            permguard_events::digest_of(mine).expect("it digests"),
            permguard_events::digest_of(theirs).expect("it digests"),
            "a record changed on the way across"
        );
    }

    // And the journal has advanced only to what was acknowledged.
    let state = streams.state(ZONE_ID, LEDGER_ID).expect("the state reads");
    assert_eq!(state.acked_through, 12);
    assert_eq!(state.signed_through, 12);
}

/// An outage defers. It does not lose history, and it does not advance anything.
#[test]
fn a_control_plane_that_is_down_defers_and_the_history_stays() {
    let keys = ring("outage");
    let wire = control("outage", &keys);
    let streams = journals("outage", "plane-a", 5);
    wire.down.store(true, std::sync::atomic::Ordering::Relaxed);

    let shipper = Shipper::new(
        Arc::clone(&streams),
        Box::new(Handed(Arc::clone(&wire))),
        Arc::new(permguard_events::envelope::RingSigner(
            Arc::clone(&keys) as Arc<dyn KeyManager>
        )),
        1024 * 1024,
        Metrics::none(),
    );

    assert!(matches!(shipper.round()[0].1, Round::Deferred(_)));
    let state = streams.state(ZONE_ID, LEDGER_ID).expect("the state reads");
    assert_eq!(state.acked_through, 0, "nothing was acknowledged");
    assert_eq!(
        streams
            .read_from(ZONE_ID, LEDGER_ID, 0, 100)
            .expect("reads")
            .len(),
        5,
        "and every record is still here"
    );

    // And when it comes back, the same round ships them.
    wire.down.store(false, std::sync::atomic::Ordering::Relaxed);
    assert!(matches!(
        shipper.round()[0].1,
        Round::Shipped {
            records: 5,
            acked: 5
        }
    ));
}

/// The signed checkpoint is on the volume before the batch leaves it.
///
/// `signed_through` claims a persisted signed checkpoint covers it, and the journal's own layout
/// names a `checkpoint-*.jws`. Until this test, both were claims with nothing behind them: the
/// watermark was set from the control plane's acknowledgement — a statement about the receiver —
/// and no code wrote the file. A plane whose control plane never answered would then hold records
/// it had signed, with no local evidence that it had.
#[test]
fn the_signed_checkpoint_is_written_before_the_batch_is_shipped() {
    let keys = ring("checkpoint");
    let wire = control("checkpoint", &keys);
    let streams = journals("checkpoint", "plane-a", 4);
    // The receiver is unreachable, so nothing this test sees can have come from an acknowledgement.
    wire.down.store(true, std::sync::atomic::Ordering::Relaxed);

    let shipper = Shipper::new(
        Arc::clone(&streams),
        Box::new(Handed(Arc::clone(&wire))),
        Arc::new(permguard_events::envelope::RingSigner(
            Arc::clone(&keys) as Arc<dyn KeyManager>
        )),
        1024 * 1024,
        Metrics::none(),
    );
    assert!(matches!(shipper.round()[0].1, Round::Deferred(_)));

    let held = streams
        .checkpoints(ZONE_ID, LEDGER_ID)
        .expect("the checkpoints list");
    assert_eq!(
        held.len(),
        1,
        "the batch was signed, so it is attested: {held:?}"
    );

    // The file is the JWS this plane signed, and it verifies under this plane's own published keys.
    let compact = std::fs::read_to_string(&held[0]).expect("the checkpoint reads");
    let signed = permguard_events::envelope::Signed::from_compact(&compact)
        .expect("the checkpoint is a compact JWS");
    let published = keys.public_keys().expect("the ring publishes");
    let envelope = signed
        .verify(&published)
        .expect("the checkpoint verifies under the key that signed it");
    assert_eq!(envelope.first_seq, 1);
    assert_eq!(envelope.last_seq, 4);

    let state = streams.state(ZONE_ID, LEDGER_ID).expect("the state reads");
    assert_eq!(
        state.signed_through, 4,
        "signed by this plane, locally, before anybody acknowledged anything"
    );
    assert_eq!(
        state.acked_through, 0,
        "and acknowledgement is still a separate fact, which has not happened"
    );
}

/// The sink and the reader are the same wire, shared.
struct Handed(Arc<Wire>);

impl EventSink for Handed {
    fn ship(&self, batch: &permguard_events::Batch) -> Result<Shipped, ShipError> {
        self.0.ship(batch)
    }
}

impl EventReader for Handed {
    fn read(&self, scope: &ReadScope, window: &ReadWindow) -> Result<Page, ReadError> {
        self.0.read(scope, window)
    }

    fn signers(
        &self,
        zone: &str,
        ledger: &str,
        ask: &permguard_control_client::events::SignersAsk,
    ) -> Result<Value, ReadError> {
        self.0.signers(zone, ledger, ask)
    }

    fn get(&self, zone: &str, ledger: &str, event_id: &str) -> Result<Option<Value>, ReadError> {
        self.0.get(zone, ledger, event_id)
    }
}

/// Two data planes, one shared history: what one recorded is what the other decides against.
///
/// # What this is actually about
///
/// Every part of this loop is tested on its own — the journal, the shipper, the store's ingest, the
/// puller, the replay. None of that says the loop *closes*. The question a deployment actually has
/// is whether a login that happened on the plane in Frankfurt permits a read on the plane in
/// Dublin, and the only way to answer it is to run both planes, ship, pull, and ask.
///
/// It is also the only test where the replay's hardest requirement shows up: plane B has a journal
/// of its own *and* an imported history, and it must decide against **both**. A replay that fed the
/// engine only the imported half would pass every other test in this file and silently discard
/// everything plane B recorded itself.
mod two_planes {
    use super::*;

    use permguard_control_client::objects;
    use permguard_control_client::store::FsStore;
    use permguard_data_plane::authz::cache::Cache;
    use permguard_data_plane::authz::decide::Decider;
    use permguard_data_plane::authz::store::Identity;
    use permguard_data_plane::temporal::submit::Submitter;
    use permguard_objects::object::{Blob, Commit, Kind, Tree, TreeEntry};
    use permguard_objects::policy_id::{ANNOTATION_POLICY_ID, ANNOTATION_POLICY_KIND};
    use std::collections::BTreeMap;
    use std::path::Path;

    /// A file of the shipped example, which is what both planes serve.
    fn example(path: &str) -> String {
        let held = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/dogwood-session-access")
            .join(path);

        std::fs::read_to_string(&held)
            .unwrap_or_else(|error| panic!("reading {}: {error}", held.display()))
    }

    /// The example's ledger, mirrored under `root`.
    ///
    /// Both planes mirror the *same* commit, because that is the only interesting case: two planes
    /// serving different policies would disagree for a reason that has nothing to do with history.
    fn mirror(root: &Path) {
        let manifest =
            permguard_languages::manifest_file::from_yaml(example("manifest.yml").as_bytes())
                .expect("the example's manifest parses");
        let path = root
            .join(MIRROR_AUTHORITY)
            .join(format!("{ZONE}-id"))
            .join(format!("{LEDGER}-id"));
        std::fs::create_dir_all(&path).expect("the mirror directory is created");
        let store = FsStore::new(&path);
        let put_blob = |media_type: &str, data: &[u8]| {
            let blob = Blob {
                media_type: media_type.to_owned(),
                data: data.to_vec(),
            };
            let bytes = blob.encode().expect("the blob encodes");

            objects::put(&store, "objects", &bytes).expect("the blob is stored")
        };
        let manifest_digest = put_blob(
            permguard_objects::manifest::MEDIA_TYPE,
            &manifest.encode().expect("it encodes"),
        );

        let mut annotations = BTreeMap::new();
        annotations.insert(
            ANNOTATION_POLICY_ID.to_owned(),
            "01a0-read-after-login".to_owned(),
        );
        annotations.insert(ANNOTATION_POLICY_KIND.to_owned(), "policy".to_owned());
        let mut entries = vec![TreeEntry {
            kind: Kind::Blob,
            digest: put_blob(
                permguard_languages::MEDIA_TYPE_POLICY_DOGWOOD,
                example("governance/read-after-login.dw").as_bytes(),
            ),
            name: "read-after-login.dw".to_owned(),
            annotations,
        }];
        for (type_name, file) in [
            (
                permguard_languages::dogwood_artifacts::ACTION_SCHEMA,
                "governance/schema.cedarschema",
            ),
            (
                permguard_languages::dogwood_artifacts::EVENT_SCHEMA,
                "governance/events.dwschema",
            ),
        ] {
            let artifact =
                permguard_languages::artifact::artifact_type(type_name).expect("registered");
            entries.push(TreeEntry {
                kind: Kind::Blob,
                digest: put_blob(artifact.media_type(), example(file).as_bytes()),
                name: artifact.canonical_filename().expect("named").to_owned(),
                annotations: BTreeMap::new(),
            });
        }
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        let partition = objects::put(
            &store,
            "objects",
            &Tree { entries }.encode().expect("the tree encodes"),
        )
        .expect("stored");

        let root_tree = Tree {
            entries: vec![TreeEntry {
                kind: Kind::Tree,
                digest: partition,
                name: "governance".to_owned(),
                annotations: BTreeMap::new(),
            }],
        };
        let commit = Commit {
            tree: objects::put(
                &store,
                "objects",
                &root_tree.encode().expect("the tree encodes"),
            )
            .expect("stored"),
            manifest: manifest_digest,
            predecessors: Vec::new(),
            author: "tests".to_owned(),
            author_at: 1_700_000_000,
            message: "the shipped example".to_owned(),
        };
        let head = objects::put(
            &store,
            "objects",
            &commit.encode().expect("the commit encodes"),
        )
        .expect("stored");
        permguard_control_client::checkpoint::write(
            &store,
            "refs/main",
            &permguard_control_client::checkpoint::Checkpoint {
                head: head.to_string(),
                counter: 1,
                ref_digest: None,
                ..Default::default()
            },
        )
        .expect("the checkpoint is written");

        permguard_data_plane::authz::store::record(
            &path,
            &Identity {
                task: Some(MIRROR_TASK.to_owned()),
                authority: Some(MIRROR_AUTHORITY.to_owned()),
                zone_id: format!("{ZONE}-id"),
                zone_name: ZONE.to_owned(),
                ledger_id: format!("{LEDGER}-id"),
                ledger_name: LEDGER.to_owned(),
                server: "http://127.0.0.1:6443".to_owned(),
            },
        )
        .expect("recorded");
    }

    /// The example's occurrences are dated in 2026; a test is about the temporal semantics rather
    /// than about how long ago the README was written.
    fn bounds() -> Bounds {
        Bounds {
            retention_minimum: Duration::MAX,
            allowed_lateness: Duration::from_secs(u32::MAX.into()),
            clock_skew: Duration::from_secs(u32::MAX.into()),
            ..Bounds::default()
        }
    }

    /// One data plane: its own mirror of the example, and its own journals.
    fn plane(tag: &str, producer: &str) -> (Arc<Submitter>, Arc<Streams>) {
        let root = scratch(tag);
        let mirrors = root.join("mirrors");
        std::fs::create_dir_all(&mirrors).expect("the mirrors root is created");
        mirror(&mirrors);

        let _ = producer;
        let events = root.join("events");
        let streams = Arc::new(
            Streams::new(
                events.clone(),
                root.join("planes"),
                permguard_data_plane::temporal::testing::host_side(&events),
                bounds(),
            )
            .expect("the floor is registered"),
        );
        let decider = Arc::new(Decider::new(
            mirrors,
            Arc::new(Cache::new(64, 32 * 1024 * 1024)),
            Metrics::none(),
            None,
            256,
        ));

        (
            Arc::new(Submitter::new(
                decider,
                Arc::clone(&streams),
                permguard_data_plane::blocking::Blocking::new(
                    permguard_core::config::default_max_blocking(),
                    Metrics::none(),
                ),
                Metrics::none(),
            )),
            streams,
        )
    }

    /// One occurrence of the example, submitted.
    async fn submit(submitter: &Arc<Submitter>, fixture: &str) -> Value {
        let body: Value = serde_json::from_str(&example(fixture))
            .unwrap_or_else(|error| panic!("{fixture}: {error}"));
        let request: permguard_languages::temporal::SubmitRequest =
            serde_json::from_value(body).unwrap_or_else(|error| panic!("{fixture}: {error}"));

        serde_json::to_value(
            submitter
                .submit(&request, "anonymous", None)
                .await
                .unwrap_or_else(|error| panic!("{fixture}: {error:?}")),
        )
        .expect("the answer renders")
    }

    /// The authenticated name the gateway submits under: an identity trusted across origins.
    const GATEWAY: &str = "spiffe://acme/gateway";

    /// Origin A, the Host that recorded alice's login, and a third whose copy of it differs.
    const ORIGIN_A: [u8; 16] = [0xA1; 16];
    const ORIGIN_B: [u8; 16] = [0xB1; 16];
    const ORIGIN_C: [u8; 16] = [0xC1; 16];
    const RUN: [u8; 16] = [0x07; 16];

    /// One occurrence of the example, submitted under `source`.
    async fn submit_as(submitter: &Arc<Submitter>, fixture: &str, source: &str) -> Value {
        let body: Value = serde_json::from_str(&example(fixture))
            .unwrap_or_else(|error| panic!("{fixture}: {error}"));
        let request: permguard_languages::temporal::SubmitRequest =
            serde_json::from_value(body).unwrap_or_else(|error| panic!("{fixture}: {error}"));

        serde_json::to_value(
            submitter
                .submit(&request, source, None)
                .await
                .unwrap_or_else(|error| panic!("{fixture}: {error:?}")),
        )
        .expect("the answer renders")
    }

    /// The Host's consumer of `data/events` on plane B's Host: the origins' runs it imported over
    /// `events.import`, and the checkpoint it verified (WP-6.2c2a), as the Data Plane reads them.
    #[derive(Default)]
    struct HostConsumer {
        runs: std::sync::Mutex<Vec<([u8; 16], Vec<Value>)>>,
    }

    impl permguard_host::composition::StreamConsumerReads for HostConsumer {
        fn runs(
            &self,
            _: &permguard_core::authz::Resource,
        ) -> Result<Vec<permguard_host::composition::ConsumedRun>, String> {
            Ok(self
                .runs
                .lock()
                .expect("lock")
                .iter()
                .map(
                    |(origin, records)| permguard_host::composition::ConsumedRun {
                        producer: *origin,
                        run: RUN,
                        acked: records.len() as u64,
                        oldest_retained: 1,
                    },
                )
                .collect())
        }

        fn locate(
            &self,
            _: &[u8; 16],
            _: &[u8; 16],
        ) -> Result<Option<permguard_core::authz::Resource>, String> {
            Ok(None)
        }

        fn records(
            &self,
            _: &permguard_core::authz::Resource,
            producer: &[u8; 16],
            _: &[u8; 16],
            from: u64,
            limit: usize,
        ) -> Result<permguard_host::composition::ConsumedPage, String> {
            let runs = self.runs.lock().expect("lock");
            let records = runs
                .iter()
                .find(|(origin, _)| origin == producer)
                .map(|(_, records)| records.clone())
                .unwrap_or_default();
            Ok(permguard_host::composition::ConsumedPage {
                records: (from..=records.len() as u64)
                    .take(limit)
                    .map(|seq| {
                        (
                            seq,
                            serde_json::to_vec(&records[(seq - 1) as usize]).expect("bytes"),
                        )
                    })
                    .collect(),
                low_watermark: None,
            })
        }

        fn batch(
            &self,
            _: &permguard_core::authz::Resource,
            _: &[u8; 16],
            _: &[u8; 16],
            _: u64,
        ) -> Result<Option<Vec<u8>>, String> {
            Ok(None)
        }

        fn retain_above(
            &self,
            _: Arc<dyn permguard_host::composition::StreamFloor>,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    /// WP-6.2c2b2: alice logs in on plane A; plane A's Host ships it to the coordinator and plane
    /// B's Host imports it over `events.import` into its consumer (the sessions, the manifests and
    /// the batches' signatures are tested in `permguard-host`, `permguard-stream` and this crate's
    /// provider); plane B, in a shared mode, decides on it together with what it recorded itself,
    /// and an occurrence two origins recorded with different bytes is applied by neither.
    #[tokio::test]
    async fn a_login_on_one_plane_permits_a_read_on_another() {
        // Plane A records alice's login, on its Host's stream, under the gateway's name.
        let (frankfurt, recorded_a) = plane("plane-a", "plane-a");
        submit_as(&frankfurt, "events/1-login-request.json", GATEWAY).await;
        submit_as(&frankfurt, "events/2-login-response.json", GATEWAY).await;
        let held_a: Vec<Value> = recorded_a
            .read_from(ZONE_ID, LEDGER_ID, 0, 100)
            .expect("plane A's stream reads back");
        assert_eq!(held_a.len(), 2);

        // Plane B reads its Host's consumer under a shared mode.
        let (dublin, journals_b) = plane("plane-b", "plane-b");
        let consumer = Arc::new(HostConsumer::default());
        let imported = Arc::new(
            permguard_data_plane::temporal::imported::Imported::new(
                permguard_host::composition::StreamConsumer::over(Arc::clone(&consumer)
                    as Arc<dyn permguard_host::composition::StreamConsumerReads>),
                permguard_data_plane::temporal::testing::HOST_ID,
                scratch("plane-b-planes"),
            )
            .expect("the floor is registered"),
        );
        let dublin = Arc::new(
            Arc::try_unwrap(dublin)
                .unwrap_or_else(|_| panic!("the submitter is not shared yet"))
                .with_shared_history(
                    permguard_core::config::Consistency::SharedEventual,
                    Arc::new(Imports::new(scratch("plane-b-pull"))),
                    Duration::from_secs(3600),
                )
                .with_imported(imported),
        );

        // Before the import, plane B has never seen alice log in.
        let denied = submit(&dublin, "requests/1-read-before-login.json").await;
        assert_eq!(
            denied["decision"],
            json!(false),
            "plane B has imported nothing yet: {denied}"
        );

        // A login of its own, for bob, in plane B's own stream: what the import must not destroy.
        for file in ["1-login-request.json", "2-login-response.json"] {
            let mut body: Value = serde_json::from_str(&example(&format!("events/{file}")))
                .unwrap_or_else(|error| panic!("{file}: {error}"));
            rename_to_bob(&mut body);
            let request: permguard_languages::temporal::SubmitRequest =
                serde_json::from_value(body).unwrap_or_else(|error| panic!("{file}: {error}"));
            dublin
                .submit(&request, GATEWAY, None)
                .await
                .unwrap_or_else(|error| panic!("{file}: {error:?}"));
        }

        // Plane B's Host imported plane A's run.
        consumer
            .runs
            .lock()
            .expect("lock")
            .push((ORIGIN_A, held_a.clone()));

        let read = |event_id: &str, bob: bool| {
            let mut body: Value =
                serde_json::from_str(&example("requests/2-read-inside-window.json"))
                    .expect("the occurrence parses");
            if bob {
                rename_to_bob(&mut body);
            }
            body["event"]["data"]["event_id"] = json!(event_id);
            serde_json::from_value::<permguard_languages::temporal::SubmitRequest>(body)
                .expect("the request parses")
        };
        let permitted = serde_json::to_value(
            dublin
                .submit(&read("01J8Z9-read-after-import", false), GATEWAY, None)
                .await
                .expect("the ledger is served"),
        )
        .expect("the answer renders");
        assert_eq!(
            permitted["decision"],
            json!(true),
            "alice's login happened on plane A, and plane B decides against it: {permitted}"
        );
        assert_eq!(
            permitted["history"]["mode"], "shared-eventual",
            "{permitted}"
        );
        assert!(
            permitted["history"]["watermark"].is_string(),
            "an auditor reproducing this needs to know exactly what was visible: {permitted}"
        );

        // Bob, whose login plane B recorded itself before the import, still reads: the rebuild
        // the import caused replayed plane B's own history too.
        let bob = serde_json::to_value(
            dublin
                .submit(&read("01J8Z9-bob-read-after-import", true), GATEWAY, None)
                .await
                .expect("the ledger is served"),
        )
        .expect("the answer renders");
        assert_eq!(
            bob["decision"],
            json!(true),
            "plane B's own history survived the import that rebuilt its engine: {bob}"
        );

        // A second origin holding the same occurrence, byte for byte: it applies once, and alice
        // still reads (the positive control of what follows).
        consumer
            .runs
            .lock()
            .expect("lock")
            .push((ORIGIN_B, held_a.clone()));
        let duplicated = serde_json::to_value(
            dublin
                .submit(&read("01J8Z9-read-after-duplicate", false), GATEWAY, None)
                .await
                .expect("the ledger is served"),
        )
        .expect("the answer renders");
        assert_eq!(
            duplicated["decision"],
            json!(true),
            "the same login from two origins is one login: {duplicated}"
        );

        // A third origin recorded alice's login under the same name and identifier with other
        // bytes: the occurrence is quarantined from shared decisions, and alice reads no more.
        let mut conflicting = held_a.clone();
        for record in &mut conflicting {
            record["occurrence_digest"] = json!(format!("sha256:{}", "c".repeat(64)));
        }
        consumer
            .runs
            .lock()
            .expect("lock")
            .push((ORIGIN_C, conflicting));
        let quarantined = serde_json::to_value(
            dublin
                .submit(&read("01J8Z9-read-after-conflict", false), GATEWAY, None)
                .await
                .expect("the ledger is served"),
        )
        .expect("the answer renders");
        assert_eq!(
            quarantined["decision"],
            json!(false),
            "a login two origins disagree on is applied by neither: {quarantined}"
        );

        // Plane B's stream holds what plane B recorded, its chain its own.
        let held = journals_b
            .read_from(ZONE_ID, LEDGER_ID, 0, 100)
            .expect("the stream reads back");
        assert_eq!(
            held.len(),
            7,
            "one denied read, bob's two login events, and four reads after the import"
        );
        let host = permguard_data_plane::temporal::testing::HOST_ID
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        for record in &held {
            assert_eq!(
                record["stream"]["producer"]["id"],
                json!(host),
                "an imported record is never written into the importing plane's own chain"
            );
        }
    }

    /// The same occurrence, for a different principal and a different id.
    ///
    /// The example's event schema pins `callerPrincipal`, so alice's history and bob's are separate
    /// by construction — which is what makes "bob can still read" a statement about plane B's own
    /// history rather than about alice's arriving from plane A.
    fn rename_to_bob(body: &mut Value) {
        let data = &mut body["event"]["data"];
        data["principal"] = json!("Drupe::OAuthUser::\"bob\"");
        data["logged"]["input"]["user"] = json!("bob");
        data["request_context"]["input"]["user"] = json!("bob");
        let id = data["event_id"].as_str().unwrap_or_default().to_owned();
        data["event_id"] = json!(format!("{id}-bob"));
    }
}

#[test]
fn the_signer_manifest_travels_with_the_stream_on_both_sides() {
    let keys = ring("signers");
    let wire = control("signers", &keys);
    let streams = journals("signers", "plane-a", 12);

    let shipper = Shipper::new(
        Arc::clone(&streams),
        Box::new(Handed(Arc::clone(&wire))),
        Arc::new(permguard_events::envelope::RingSigner(
            Arc::clone(&keys) as Arc<dyn KeyManager>
        )),
        1024 * 1024,
        Metrics::none(),
    );
    let rounds = shipper.round();
    assert!(
        matches!(rounds[0].1, Round::Shipped { .. }),
        "{:?}",
        rounds[0].1
    );

    let kid = keys
        .active_key_id()
        .expect("a key signs")
        .as_str()
        .to_owned();

    // The producer's own journal names the key that signed its stretch, from its first record.
    let held = streams
        .signers(ZONE_ID, LEDGER_ID)
        .expect("the manifest reads");
    let spans = held.spans();
    assert_eq!(spans.len(), 1, "one key is one fact");
    assert_eq!(spans[0].from, 1);
    assert_eq!(spans[0].kid, kid);
    assert_eq!(
        spans[0].jwk.get("kid").and_then(Value::as_str),
        Some(kid.as_str()),
        "the public key itself travels, not only its name"
    );

    // And the store, from what it actually verified against — the consumer's own copy, good
    // after the producer is gone.
    let answered = wire
        .facade
        .signers_of(ZONE_ID, LEDGER_ID, 0, 0, &Default::default())
        .expect("the store answers");
    assert!(!answered.truncated);
    let answered = answered.streams;
    assert_eq!(answered.len(), 1, "one producer stream");
    assert_eq!(answered[0].acked, 12);
    assert_eq!(answered[0].spans.len(), 1);
    assert_eq!(answered[0].spans[0].kid, kid);

    // A bounded range still names the span covering it.
    let bounded = wire
        .facade
        .signers_of(ZONE_ID, LEDGER_ID, 3, 7, &Default::default())
        .expect("the store answers a range");
    assert_eq!(bounded.streams[0].spans.len(), 1);
    assert_eq!(bounded.streams[0].spans[0].kid, kid);

    // The filters narrow: the producer that shipped is found, a stranger is not — and neither
    // answer is truncation, because nothing was cut short.
    let producer = &answered[0].producer.clone();
    let found = wire
        .facade
        .signers_of(
            ZONE_ID,
            LEDGER_ID,
            0,
            0,
            &permguard_control_plane::events::http::StreamsAsked {
                producer: Some(producer.clone()),
                ..Default::default()
            },
        )
        .expect("the filter matches");
    assert_eq!(found.streams.len(), 1);
    assert!(!found.truncated);
    let nobody = wire
        .facade
        .signers_of(
            ZONE_ID,
            LEDGER_ID,
            0,
            0,
            &permguard_control_plane::events::http::StreamsAsked {
                producer: Some("somebody-else".to_owned()),
                ..Default::default()
            },
        )
        .expect("an unmatched filter is empty, not an error");
    assert!(nobody.streams.is_empty());
    assert!(!nobody.truncated);
}
