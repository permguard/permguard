// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A Host on a volume for the stream engine's integration tests: its identity, its
//! `host.operations` and `data.attest` rings, a producer sealing under the latter, and a reader of
//! every batch a stream left on disk, verified under the spans that name its keys (WP-5.2).

#![allow(clippy::expect_used, dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use permguard_core::assurance::AssuranceProfile;
use permguard_core::authz::Resource;
use permguard_core::domains::{digest, protected};
use permguard_core::keys::Jwk;
use permguard_host::identity::{Identity, Suite, directories, is_provisioned};
use permguard_host::keys::FileKeyProvider;
use permguard_host::keys::ring::{DATA_ATTEST, HOST_OPERATIONS, Policy, Ring};
use permguard_host::membership::record::TaskType;
use permguard_host::storage::volume::Volume;
use permguard_host::time::TimeGuard;
use permguard_stream::engine::batch::{Envelope, GENESIS_HEAD, SealedBatch};
use permguard_stream::engine::{
    Descriptor, Producer, RecordCodec, ResourceShape, Retention, STREAMS, Spans, Streams,
};

/// A record of the tests' streams: text.
pub struct Text;

impl RecordCodec for Text {
    type Record = String;

    fn encode(&self, record: &String) -> Result<Vec<u8>, String> {
        Ok(record.as_bytes().to_vec())
    }

    fn decode(&self, bytes: &[u8]) -> Result<String, String> {
        String::from_utf8(bytes.to_vec()).map_err(|error| error.to_string())
    }
}

pub fn descriptor() -> Descriptor {
    Descriptor {
        plane: "data".to_owned(),
        stream_type: "decisions".to_owned(),
        version: 1,
        batch_typ: protected::DECISION_BATCH,
        record_domain: digest::DECISION_RECORD,
        codec_version: 1,
        event_types: Vec::new(),
        resource_shape: ResourceShape::Ledger,
        max_record_bytes: 4096,
        max_batch_records: 100,
        retention: Retention::Evidence,
        subscription_required: true,
        ring: DATA_ATTEST,
        task: Some(TaskType::DecisionsShip),
    }
}

pub fn ledger(n: u8) -> Resource {
    Resource::ledger("data", "zone-a", format!("ledger-{n}"))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn unhex(text: &str) -> [u8; 16] {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect();
    bytes.try_into().expect("16 bytes")
}

pub fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("permguard-stream-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("a scratch directory");
    path
}

/// One Host on `root`, provisioned on first use and reopened after.
pub struct Host {
    pub root: PathBuf,
    pub volume: Volume,
    pub identity: Arc<Identity>,
    pub operations: Arc<Ring>,
    pub attest: Arc<Ring>,
    pub time: Arc<TimeGuard>,
}

impl Host {
    pub fn open(root: &Path, time: Arc<TimeGuard>, policy: Policy) -> Self {
        let volume = Volume::claim(root, AssuranceProfile::Development).expect("claimed");
        let provider = Arc::new(FileKeyProvider::new(
            directories(&volume).expect("the identity directory").1,
        ));
        let identity = Arc::new(if is_provisioned(&volume).expect("readable") {
            Identity::open(&volume, provider).expect("opened")
        } else {
            Identity::provision(
                &volume,
                provider,
                Suite::Ed25519Sha256V1,
                permguard_host::authz::store::now(),
                permguard_host::authz::store::now() * 1000,
            )
            .expect("provisioned")
        });
        let ring = |id: &'static str| {
            let ring = Arc::new(
                Ring::open(
                    &volume,
                    id,
                    Suite::Ed25519Sha256V1,
                    policy,
                    Arc::clone(&time),
                )
                .expect("the ring opens")
                .with_binder(identity.clone()),
            );
            permguard_core::KeyManager::maintain(ring.as_ref()).expect("maintained");
            ring
        };
        let operations = ring(HOST_OPERATIONS);
        let attest = ring(DATA_ATTEST);
        Self {
            root: root.to_path_buf(),
            volume,
            identity,
            operations,
            attest,
            time,
        }
    }

    pub fn maintain(&self) {
        permguard_core::KeyManager::maintain(self.operations.as_ref()).expect("maintained");
        permguard_core::KeyManager::maintain(self.attest.as_ref()).expect("maintained");
    }

    /// A producer of [`descriptor`] sealing under `data.attest`.
    pub fn sealer(&self) -> Producer<Text> {
        Streams::open(
            &self.volume,
            &self.identity,
            Arc::clone(&self.operations),
            Arc::clone(&self.time),
        )
        .expect("the engine opens")
        .register_producer(descriptor(), Text)
        .expect("registered")
        .with_signer(Arc::clone(&self.attest))
        .expect("the descriptor's ring")
    }

    /// The producer directory of `resource`.
    pub fn producer_dir(&self, resource: &Resource) -> PathBuf {
        let key = descriptor()
            .key(resource, self.identity.host_id())
            .expect("a key");
        self.root
            .join("host")
            .join(STREAMS)
            .join("data")
            .join("decisions")
            .join("1")
            .join("producer")
            .join(key.resource_component())
            .join(hex(&self.identity.host_id()))
    }
}

/// One verified batch: its run, envelope and records.
pub struct Opened {
    pub run: [u8; 16],
    pub envelope: Envelope,
    pub records: Vec<Vec<u8>>,
    pub kid: String,
}

/// Every batch of the stream in `dir`, run by run: each verified under the key of the span that
/// signs its first sequence alone, its range following the one before from 1, its previous head
/// the head before it or genesis. Panics on the first that is not.
pub fn every_batch(dir: &Path, spans: &Spans) -> Vec<Opened> {
    let mut runs: Vec<[u8; 16]> = std::fs::read_dir(dir.join("batches"))
        .map(|entries| {
            entries
                .map(|entry| entry.expect("an entry").file_name())
                .map(|name| unhex(&name.to_string_lossy()))
                .collect()
        })
        .unwrap_or_default();
    runs.sort();
    let mut opened = Vec::new();
    for run in &runs {
        let batches = dir.join("batches").join(hex(run));
        let mut names: Vec<(u64, u64)> = std::fs::read_dir(&batches)
            .map(|entries| {
                entries
                    .map(|entry| entry.expect("an entry").file_name())
                    .filter_map(|name| {
                        let name = name.to_string_lossy().into_owned();
                        let (first, last) = name.strip_suffix(".jws")?.split_once('-')?;
                        Some((first.parse().ok()?, last.parse().ok()?))
                    })
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        let mut sealed = 0;
        let mut head = GENESIS_HEAD.to_owned();
        for (first, last) in names {
            assert_eq!(
                first,
                sealed + 1,
                "run {} has a gap before {first}",
                hex(run)
            );
            let bytes =
                std::fs::read(batches.join(format!("{first}-{last}.jws"))).expect("readable");
            let span = spans
                .signing(run, first)
                .unwrap_or_else(|| panic!("no span signs {}:{first}", hex(run)));
            let jwk: Jwk = serde_json::from_str(&span.jwk).expect("a JWK");
            let batch = SealedBatch::decode(&bytes).expect("a canonical batch");
            let (envelope, records) = batch
                .verify(
                    std::slice::from_ref(&jwk),
                    protected::DECISION_BATCH,
                    digest::DECISION_RECORD,
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "{}:{first} does not verify under its span: {error}",
                        hex(run)
                    )
                });
            assert_eq!((envelope.first_seq, envelope.last_seq), (first, last));
            assert_eq!(envelope.previous_head, head, "{}:{first} forks", hex(run));
            assert_eq!(envelope.run, hex(run));
            head = envelope.head.clone();
            sealed = last;
            opened.push(Opened {
                run: *run,
                envelope,
                records,
                kid: span.kid.clone(),
            });
        }
    }
    opened
}
