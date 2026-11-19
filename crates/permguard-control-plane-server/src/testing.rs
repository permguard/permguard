// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What this package's tests stand on: the Host handles, rings and signers a test composes without
//! a server, a catalog no gate may touch, an export over a ledger with a history, and the event
//! reads over a fake of the Host's consumer. Built from the domain's public items, for tests only;
//! the domain keeps its own for its own tests.

#![allow(clippy::expect_used, clippy::unwrap_used, dead_code)]

use std::sync::Arc;

use permguard_core::keys::PublicSet;
use permguard_host::composition::{Declaration, HeadStatementV1, LedgerExportV1, Signer};

/// A mutation transaction of the catalog over an offline engine of its own on a fresh volume
/// under `directory`, for a test.
pub fn catalog_mutations_for_tests(
    directory: &std::path::Path,
) -> permguard_host::composition::MutationHandle {
    let volume = permguard_host::storage::volume::Volume::claim(
        directory,
        permguard_core::assurance::AssuranceProfile::Development,
    )
    .unwrap_or_else(|error| unreachable!("a test volume is claimed: {error}"));
    let engine = permguard_host::operations::mutation::Mutations::open_offline(&volume, "test")
        .unwrap_or_else(|error| unreachable!("a test mutation transaction opens: {error}"));
    permguard_host::composition::MutationHandle::new(
        std::sync::Arc::new(engine),
        permguard_control_plane::catalog::CATALOG_DOMAIN,
    )
}

/// A mutation transaction of the catalog over `projection` instead of an audit engine, on the
/// volume under `directory`, fresh or reopened: for a test that sees, or refuses, the phases.
pub fn catalog_mutations_over(
    directory: &std::path::Path,
    projection: std::sync::Arc<dyn permguard_host::operations::mutation::Projection>,
) -> permguard_host::composition::MutationHandle {
    let volume = permguard_host::storage::volume::Volume::claim(
        directory,
        permguard_core::assurance::AssuranceProfile::Development,
    )
    .unwrap_or_else(|error| unreachable!("a test volume is claimed: {error}"));
    let engine = permguard_host::operations::mutation::Mutations::open(
        &volume,
        projection,
        std::sync::Arc::new(permguard_host::time::TimeGuard::system(
            std::time::Duration::from_secs(30),
        )),
    )
    .unwrap_or_else(|error| unreachable!("a test mutation transaction opens: {error}"));
    permguard_host::composition::MutationHandle::new(
        std::sync::Arc::new(engine),
        permguard_control_plane::catalog::CATALOG_DOMAIN,
    )
}

/// A mutation transaction of the ref updates over an offline engine of its own on a fresh volume
/// under `directory`, for a test.
pub fn ref_mutations_for_tests(
    directory: &std::path::Path,
) -> permguard_host::composition::MutationHandle {
    let handle = permguard_control_plane::store::testing::offline_ref_mutations(directory)
        .unwrap_or_else(|error| unreachable!("a test mutation transaction opens: {error}"));
    LAST_MUTATIONS.with(|last| *last.borrow_mut() = Some(handle.engine()));
    handle
}

thread_local! {
    /// The transaction [`ref_mutations_for_tests`] opened last on this thread: what a test raises
    /// a backup barrier on (BUG-0208).
    static LAST_MUTATIONS: std::cell::RefCell<
        Option<Arc<permguard_host::operations::mutation::Mutations>>,
    > = const { std::cell::RefCell::new(None) };
}

/// The transaction [`ref_mutations_for_tests`] opened last on this thread.
pub fn last_ref_mutations() -> Arc<permguard_host::operations::mutation::Mutations> {
    LAST_MUTATIONS
        .with(|last| last.borrow().clone())
        .unwrap_or_else(|| unreachable!("no test mutation transaction was opened on this thread"))
}

/// A ring a test holds itself.
pub type TestRing = Arc<dyn permguard_core::KeyManager>;

/// A test's ring that keeps no epoch, given one: epoch 1, the set digest over its published
/// keys. A head statement binds a ring's epoch and set (WP-7.1), and a ring that names none
/// cannot sign one.
struct EpochOne(TestRing);

impl permguard_core::keys::Sign for EpochOne {
    fn active_key_id(&self) -> permguard_core::keys::Result<permguard_core::KeyId> {
        self.0.active_key_id()
    }
    fn sign(&self, payload: &[u8]) -> permguard_core::keys::Result<permguard_core::Signature> {
        self.0.sign(payload)
    }
}

impl PublicSet for EpochOne {
    fn public_keys(&self) -> permguard_core::keys::Result<Vec<permguard_core::Jwk>> {
        self.0.public_keys()
    }
    fn key_set(&self) -> permguard_core::keys::Result<permguard_core::keys::KeySetView> {
        let keys = self.0.public_keys()?;
        let published = serde_json::to_vec(&permguard_core::JwkSet::new(keys))
            .map_err(|error| permguard_core::KeyError::backend(error.to_string()))?;
        Ok(permguard_core::keys::KeySetView {
            epoch: 1,
            digest: *permguard_objects::Digest::compute(&published).raw(),
            algorithm: "EdDSA",
        })
    }
}

impl permguard_core::KeyManager for EpochOne {
    fn name(&self) -> &'static str {
        self.0.name()
    }
    fn maintain(&self) -> permguard_core::keys::Result<permguard_core::Maintenance> {
        self.0.maintain()
    }
}

/// A head statement signer over `keys`, for a test that holds a ring of its own.
pub fn head_signer_for_tests(keys: TestRing) -> Signer<HeadStatementV1> {
    let keys: TestRing = Arc::new(EpochOne(keys));
    permguard_host::composition::Host::builder()
        .ring(permguard_host::composition::CONTROL_ATTEST, keys)
        .build()
        .register(Declaration::new(crate::PLANE).signs::<HeadStatementV1>())
        .ok()
        .and_then(|registration| registration.signer::<HeadStatementV1>().ok().flatten())
        .unwrap_or_else(|| unreachable!("a declared signer over a composed ring"))
}

/// A ring on disk under `root`, published and active, for a test that signs with it.
pub fn ring_for_tests(root: &std::path::Path) -> TestRing {
    use permguard_core::keys::KeyManager as _;

    let keys = Arc::new(permguard_std::keys::DirectoryKeyManager::new(
        root.join("keys"),
        permguard_std::keys::KeyPolicy {
            publish_ahead: std::time::Duration::ZERO,
            rotate_every: std::time::Duration::from_secs(3600),
            retain: std::time::Duration::from_secs(3600),
            verify_retain: std::time::Duration::from_secs(3600),
        },
    ));
    keys.maintain()
        .unwrap_or_else(|error| unreachable!("the ring publishes: {error}"));
    keys.maintain()
        .unwrap_or_else(|error| unreachable!("the ring activates: {error}"));
    keys
}

/// An export manifest signer over `keys`, composed as the Host's `host.operations`, for a test
/// that holds a ring of its own (WP-7.10).
pub fn export_signer_for_tests(keys: TestRing) -> Signer<LedgerExportV1> {
    let keys: TestRing = Arc::new(EpochOne(keys));
    permguard_host::composition::Host::builder()
        .ring(permguard_host::composition::HOST_OPERATIONS, keys)
        .build()
        .register(Declaration::new(crate::PLANE).signs::<LedgerExportV1>())
        .ok()
        .and_then(|registration| registration.signer::<LedgerExportV1>().ok().flatten())
        .unwrap_or_else(|| unreachable!("a declared signer over a composed ring"))
}

/// An audit handle over `recorder`, for a test that needs one without composing a server.
pub fn audit_for_tests(
    recorder: permguard_core::AuditRecorder,
) -> permguard_control_plane::handles::Audit {
    permguard_host::composition::Host::builder()
        .audit(recorder)
        .build()
        .register(permguard_control_plane::handles::declaration())
        .ok()
        .and_then(|registration| {
            registration
                .audit::<permguard_control_plane::handles::ControlPlaneAudit>()
                .ok()
                .flatten()
        })
        .unwrap_or_else(|| unreachable!("a declared schema with a composed recorder"))
}

/// A catalog no gate may consult before it admitted the caller: every lookup panics (after the
/// review).
pub struct Untouchable;

impl permguard_core::catalog::Catalog for Untouchable {
    fn name(&self) -> &'static str {
        "untouchable"
    }

    fn create_zone_with(
        &self,
        _: &str,
        _: &permguard_core::catalog::Write<'_>,
    ) -> Result<permguard_core::catalog::Zone, permguard_core::catalog::CatalogError> {
        panic!("looked up before the gate")
    }

    fn list_zones(
        &self,
    ) -> Result<Vec<permguard_core::catalog::Zone>, permguard_core::catalog::CatalogError> {
        panic!("looked up before the gate")
    }

    fn get_zone(
        &self,
        _: &permguard_core::catalog::Selector,
    ) -> Result<permguard_core::catalog::Zone, permguard_core::catalog::CatalogError> {
        panic!("looked up before the gate")
    }

    fn rename_zone_with(
        &self,
        _: &permguard_core::catalog::Selector,
        _: &str,
        _: &permguard_core::catalog::Write<'_>,
    ) -> Result<permguard_core::catalog::Zone, permguard_core::catalog::CatalogError> {
        panic!("looked up before the gate")
    }

    fn delete_zone_with(
        &self,
        _: &permguard_core::catalog::Selector,
        _: &permguard_core::catalog::Write<'_>,
    ) -> Result<permguard_core::catalog::Zone, permguard_core::catalog::CatalogError> {
        panic!("looked up before the gate")
    }

    fn create_ledger_with(
        &self,
        _: &permguard_core::catalog::Selector,
        _: &str,
        _: &permguard_core::catalog::Write<'_>,
    ) -> Result<permguard_core::catalog::Ledger, permguard_core::catalog::CatalogError> {
        panic!("looked up before the gate")
    }

    fn list_ledgers(
        &self,
        _: &permguard_core::catalog::Selector,
    ) -> Result<Vec<permguard_core::catalog::Ledger>, permguard_core::catalog::CatalogError> {
        panic!("looked up before the gate")
    }

    fn get_ledger(
        &self,
        _: &permguard_core::catalog::Selector,
        _: &permguard_core::catalog::Selector,
    ) -> Result<permguard_core::catalog::Ledger, permguard_core::catalog::CatalogError> {
        panic!("looked up before the gate")
    }

    fn rename_ledger_with(
        &self,
        _: &permguard_core::catalog::Selector,
        _: &permguard_core::catalog::Selector,
        _: &str,
        _: &permguard_core::catalog::Write<'_>,
    ) -> Result<permguard_core::catalog::Ledger, permguard_core::catalog::CatalogError> {
        panic!("looked up before the gate")
    }

    fn delete_ledger_with(
        &self,
        _: &permguard_core::catalog::Selector,
        _: &permguard_core::catalog::Selector,
        _: &permguard_core::catalog::Write<'_>,
    ) -> Result<permguard_core::catalog::Ledger, permguard_core::catalog::CatalogError> {
        panic!("looked up before the gate")
    }

    fn set_ledger_state_with(
        &self,
        _: &permguard_core::catalog::Selector,
        _: &permguard_core::catalog::Selector,
        _: permguard_core::catalog::LedgerState,
        _: &permguard_core::catalog::Write<'_>,
    ) -> Result<permguard_core::catalog::Ledger, permguard_core::catalog::CatalogError> {
        panic!("looked up before the gate")
    }
}

/// An export over a ledger with a history, as the domain's export tests build it.
pub mod exports {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use permguard_control_plane::catalog::exports::*;
    use permguard_control_plane::store::FileObjectStore;
    use permguard_core::catalog::{Catalog as _, Selector};
    use permguard_core::{Ledger, Zone};
    use permguard_objects::Digest;
    use permguard_objects::object::{Blob, Commit, Kind, Tree, TreeEntry};
    use permguard_std::catalog::FileCatalog;

    pub struct Fixture {
        pub catalog: Arc<FileCatalog>,
        pub exports: Exports,
        pub zone: Zone,
        pub ledger: Ledger,
        pub ring: super::TestRing,
        pub reached: std::collections::BTreeSet<Digest>,
        pub orphan: Digest,
        pub head: Digest,
    }

    fn blob(text: &str) -> Vec<u8> {
        Blob {
            media_type: permguard_core::domains::media::POLICY_CEDAR.to_owned(),
            data: text.as_bytes().to_vec(),
        }
        .encode()
        .expect("a blob")
    }

    pub fn fixture(tag: &str, max_bytes: usize) -> Fixture {
        let root = std::env::temp_dir().join(format!(
            "permguard-export-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let catalog = Arc::new(FileCatalog::new(root.join("zones")));
        let zone = catalog.create_zone("delivery").expect("a zone");
        let ledger = catalog
            .create_ledger(&Selector::Id(zone.id.clone()), "release")
            .expect("a ledger");
        let store = FileObjectStore::new(
            root.join("zones")
                .join(&zone.id)
                .join("ledgers")
                .join(&ledger.id),
        );
        let policy = store
            .put_object(&blob("permit (principal, action, resource);"))
            .expect("stored")
            .0;
        let manifest = store.put_object(&blob("the manifest")).expect("stored").0;
        let tree = store
            .put_object(
                &Tree {
                    entries: vec![TreeEntry {
                        kind: Kind::Blob,
                        digest: policy.clone(),
                        name: "rules.cedar".to_owned(),
                        annotations: BTreeMap::new(),
                    }],
                }
                .encode()
                .expect("a tree"),
            )
            .expect("stored")
            .0;
        let head = store
            .put_object(
                &Commit {
                    tree: tree.clone(),
                    manifest: manifest.clone(),
                    predecessors: Vec::new(),
                    author: "test".to_owned(),
                    author_at: 1,
                    message: "the first".to_owned(),
                }
                .encode()
                .expect("a commit"),
            )
            .expect("stored")
            .0;
        let orphan = store
            .put_object(&blob("no ref reaches this"))
            .expect("stored")
            .0;
        let mutations =
            permguard_control_plane::store::testing::offline_ref_mutations(&root.join("volume"))
                .expect("the transaction");
        permguard_control_plane::store::testing::update_ref(
            &mutations, &store, "main", None, &head,
        )
        .expect("the ref");
        store
            .write_signature("main", b"a head statement")
            .expect("the statement");
        let ring = super::ring_for_tests(&root.join("ring"));
        Fixture {
            catalog,
            exports: Exports::new(
                root.join("zones"),
                super::export_signer_for_tests(Arc::clone(&ring)),
                [7; 16],
                max_bytes,
            ),
            zone,
            ledger,
            ring,
            reached: [policy, manifest, tree, head.clone()].into_iter().collect(),
            orphan,
            head,
        }
    }
}

/// The event reads over a fake of the Host's consumer holding two producers' runs of one ledger.
pub mod events {
    use std::sync::{Arc, Mutex};

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use permguard_control_plane::decisions::cursorkey::CursorKeys;
    use permguard_control_plane::events::store::EventStore;
    use permguard_core::authz::Resource;
    use permguard_core::encoding::hex;
    use permguard_host::composition::{
        ConsumedPage, ConsumedRun, StreamConsumer, StreamConsumerReads,
    };
    use permguard_stream::engine::batch::{Envelope, Jws, KeyView, SealedBatch, digest_string};
    use serde_json::json;

    pub const ROOT: &[u8] = b"a-test-cursor-key-of-32-bytes!!!!";
    pub const ZONE: &str = "zone-1";
    pub const LEDGER: &str = "ledger-1";
    pub const LOGIN: &str = permguard_core::domains::event::DOGWOOD_V1;

    pub fn scratch(tag: &str) -> std::path::PathBuf {
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
    pub struct Run {
        pub resource: Resource,
        pub run: ConsumedRun,
        pub records: Vec<Vec<u8>>,
    }

    /// The Host's consumer, as a Plane reads it.
    pub struct Held {
        pub runs: Mutex<Vec<Run>>,
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
    pub fn host_record(producer: u8, run: u8, seq: u64, event_type: &str) -> Vec<u8> {
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

    pub fn run(resource: &Resource, producer: u8, run: u8, types: &[&str]) -> Run {
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

    pub struct Fixture {
        pub store: Arc<EventStore>,
        pub consumer: StreamConsumer,
        pub held: Arc<Held>,
        pub keys: CursorKeys,
    }

    impl Fixture {
        /// Two producers holding runs of the ledger; no legacy record.
        pub fn new(tag: &str) -> Self {
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
    }

    /// The facade a test serves its reads and signers from, over the fixture's store and consumer.
    pub fn facade(fixture: &Fixture) -> permguard_control_plane::events::facade::EventFacade {
        permguard_control_plane::events::facade::EventFacade {
            members: None,
            store: Arc::clone(&fixture.store),
            host: Some(fixture.consumer.clone()),
            cursor_key: fixture.keys.clone(),
            catalog: None,
            disclosure: permguard_core::Disclosure::Full,
            metrics: permguard_core::Metrics::none(),
            base_url: String::new(),
            describer: permguard_core::stages::Describer::detached("control-plane"),
            authorization: std::sync::Arc::new(
                permguard_host::composition::Authorization::permissive(),
            ),
        }
    }
}
