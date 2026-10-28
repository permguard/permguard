// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! WP-7.12: a push interrupted at every step recovers to a consistent store.
//!
//! The test binary runs itself as the child: an ignored test pushes one commit through the engine
//! (negotiate, upload, commit) on the directory the parent names, and aborts at the crash point and
//! pass the parent chose (`PERMGUARD_CRASH_AT`, `PERMGUARD_CRASH_HIT`): every phase of the mutation
//! transaction the ref update runs in, and every step of the atomic writes of the session records
//! and the ref. The parent resolves what the crash left open, as a starting Control Plane does,
//! then retries the same push as a client would, and requires the ref at the pushed head at
//! counter 1, the session committed with nothing left reserved, and no operation left open.
//! Built with the `crash-points` feature only.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use permguard_control_plane::engine::{
    ANNOTATION_POLICY_ID, ANNOTATION_POLICY_KIND, Engine, EngineError, EngineLimits,
    LedgerIdentity, MEDIA_TYPE_MANIFEST, MEDIA_TYPE_POLICY_CEDAR, TransferPolicy,
};
use permguard_control_plane::store::{FileObjectStore, RefDomain};
use permguard_control_plane::transfer::{Direction, State};
use permguard_host::composition::MutationHandle;
use permguard_host::operations::mutation::Mutations;
use permguard_notp::{CommitPushRequest, NegotiatePushRequest, ObjectClaim, UploadObjectsRequest};
use permguard_objects::digest::Digest;
use permguard_objects::manifest::{
    KIND_POLICY, Manifest, PROFILE_PDP_V1, Partition, Profile, Requirement, Runtime,
};
use permguard_objects::object::{Blob, Commit, Kind, Tree, TreeEntry};
use permguard_objects::policy_id::derive_policy_id;
use permguard_objects::semver::Constraint;
use permguard_objects::statement::SignedHead;
use ring::signature::Ed25519KeyPair;

const CHILD_DIRECTORY: &str = "PERMGUARD_PUSH_CRASH_DIRECTORY";
const ZONE: &str = "zone-1";
const LEDGER: &str = "ledger-1";
const REQUEST: &str = "push-1";
/// A fixed key: the child and the parent sign alike.
const SEED: [u8; 32] = [0x2a; 32];

/// The crash points a push passes through: the transaction's phases and the atomic writes.
const POINTS: &[&str] = &[
    "mutation.intent_written",
    "mutation.intent_audited",
    "mutation.applied",
    "mutation.committed",
    "mutation.applied_audited",
    "mutation.projected",
    "view.temp_written",
    "view.temp_flushed",
    "view.renamed",
    "view.parent_flushed",
    "journal.frame_written",
    "journal.frame_flushed",
];

/// The passes tried at each point: the session records, the ref and the audit records each pass
/// through the writes, so the n-th pass is a different step of the push.
const HITS: u64 = 4;

fn manifest() -> Manifest {
    Manifest {
        kind: KIND_POLICY.into(),
        name: "crash".into(),
        description: String::new(),
        author: String::new(),
        license: String::new(),
        runtimes: BTreeMap::from([(
            "cedar".to_owned(),
            Runtime {
                language: Requirement {
                    name: "cedar".into(),
                    constraint: Constraint::parse(">=4.0.0").unwrap(),
                },
                engine: Requirement {
                    name: "permguard".into(),
                    constraint: Constraint::parse(">=0.1.0 <0.2.0").unwrap(),
                },
            },
        )]),
        partitions: BTreeMap::from([(
            "cedar".to_owned(),
            Partition {
                interfaces: Vec::new(),
                runtime: "cedar".into(),
                media_types: vec![MEDIA_TYPE_POLICY_CEDAR.to_owned()],
                schema: false,
                artifacts: Vec::new(),
                history: None,
                input: None,
            },
        )]),
        profiles: BTreeMap::from([(
            "default".to_owned(),
            Profile {
                r#type: PROFILE_PDP_V1.into(),
                partitions: vec!["cedar".into()],
            },
        )]),
    }
}

/// One commit's closure, and its head.
fn commit() -> (Vec<Vec<u8>>, Digest) {
    let source = "permit(principal, action, resource);";
    let policy = Blob {
        media_type: MEDIA_TYPE_POLICY_CEDAR.into(),
        data: source.as_bytes().to_vec(),
    }
    .encode()
    .unwrap();
    let manifest = Blob {
        media_type: MEDIA_TYPE_MANIFEST.into(),
        data: manifest().encode().unwrap(),
    }
    .encode()
    .unwrap();
    let annotations = BTreeMap::from([
        (
            ANNOTATION_POLICY_ID.to_owned(),
            derive_policy_id(source.as_bytes()),
        ),
        (ANNOTATION_POLICY_KIND.to_owned(), "policy".to_owned()),
    ]);
    let partition = Tree {
        entries: vec![TreeEntry {
            kind: Kind::Blob,
            digest: Digest::compute(&policy),
            name: "rules.cedar".into(),
            annotations,
        }],
    }
    .encode()
    .unwrap();
    let root = Tree {
        entries: vec![
            TreeEntry {
                kind: Kind::Tree,
                digest: Digest::compute(&partition),
                name: "cedar".into(),
                annotations: BTreeMap::new(),
            },
            TreeEntry {
                kind: Kind::Blob,
                digest: Digest::compute(&manifest),
                name: "manifest".into(),
                annotations: BTreeMap::new(),
            },
        ],
    }
    .encode()
    .unwrap();
    let commit = Commit {
        tree: Digest::compute(&root),
        manifest: Digest::compute(&manifest),
        predecessors: Vec::new(),
        author: "crash".into(),
        author_at: 1_787_836_800,
        message: "crash".into(),
    }
    .encode()
    .unwrap();
    let head = Digest::compute(&commit);
    (vec![policy, manifest, partition, root, commit], head)
}

/// The pieces of a Control Plane on `root`: the ledger's store and the mutation transaction.
struct Plane {
    store: FileObjectStore,
    mutations: MutationHandle,
    engine: Arc<Mutations>,
    key: Ed25519KeyPair,
}

impl Plane {
    fn open(root: &Path) -> Self {
        let volume = permguard_host::storage::volume::Volume::claim(
            &root.join("volume"),
            permguard_core::assurance::AssuranceProfile::Development,
        )
        .expect("the volume is claimed");
        let engine = Arc::new(Mutations::open_offline(&volume, "crash").expect("it opens"));
        std::mem::forget(volume);
        Self {
            store: FileObjectStore::new(root.join("zones").join(ZONE).join("ledgers").join(LEDGER)),
            mutations: MutationHandle::new(
                Arc::clone(&engine),
                permguard_control_plane::store::REFS_DOMAIN,
            ),
            engine,
            key: Ed25519KeyPair::from_seed_unchecked(&SEED).expect("the key"),
        }
    }

    fn engine(&self) -> Engine<'_> {
        Engine {
            store: &self.store,
            identity: LedgerIdentity {
                zone_id: ZONE.into(),
                ledger_id: LEDGER.into(),
            },
            authority: [0x11; 16],
            ring: (0, Digest::from_raw([0; 32])),
            limits: EngineLimits {
                max_batch_bytes: 8 * 1024 * 1024,
                max_batch_objects: 100,
                max_push_objects: 100,
                max_push_bytes: 8 * 1024 * 1024,
                ledger_quota_bytes: 64 * 1024 * 1024,
            },
            enabled: permguard_languages::registry::Enabled::everything(),
            clock: &permguard_core::time::SystemClock,
            caller: "operator".into(),
            transfer: TransferPolicy {
                ttl: std::time::Duration::from_secs(900),
                grace: std::time::Duration::from_secs(3600),
            },
            mutations: &self.mutations,
        }
    }

    /// One whole push, as a client runs it: negotiate (resuming a session it opened before),
    /// upload what is missing, commit.
    fn push(&self) -> Result<u64, EngineError> {
        let (objects, head) = commit();
        let engine = self.engine();
        let negotiated = engine.negotiate_push(&NegotiatePushRequest {
            r#ref: "main".into(),
            new_head: head.clone(),
            expected_ref: None,
            closure: objects
                .iter()
                .map(|bytes| ObjectClaim {
                    digest: Digest::compute(bytes),
                    size: bytes.len() as u64,
                })
                .collect(),
            request_id: REQUEST.into(),
        })?;
        let missing: Vec<Vec<u8>> = objects
            .into_iter()
            .filter(|bytes| negotiated.missing.contains(&Digest::compute(bytes)))
            .collect();
        if !missing.is_empty() {
            engine.upload(&UploadObjectsRequest {
                objects: missing,
                compression: None,
                transfer_id: negotiated.transfer_id,
            })?;
        }
        let signer = |statement: &permguard_objects::statement::HeadStatement| {
            SignedHead::sign(statement, &self.key, b"crash")
                .and_then(|signed| signed.encode())
                .map_err(|error| EngineError::Internal {
                    detail: error.to_string(),
                })
        };
        engine
            .commit_push(
                &CommitPushRequest {
                    r#ref: "main".into(),
                    new_head: head,
                    expected_ref: None,
                    transfer_id: negotiated.transfer_id,
                    request_id: REQUEST.into(),
                },
                &signer,
            )
            .map(|committed| committed.counter)
    }
}

/// The child: pushes until the crash point the parent chose aborts it.
#[test]
#[ignore = "the crash test's child, run by `a_push_interrupted_at_every_step_recovers`"]
fn child_pushes_until_it_crashes() {
    let Ok(root) = std::env::var(CHILD_DIRECTORY) else {
        return;
    };
    let plane = Plane::open(Path::new(&root));
    let _ = plane.push();
}

fn crash(root: &Path, point: &str, hit: u64) -> std::process::ExitStatus {
    Command::new(std::env::current_exe().expect("the test binary is known"))
        .args([
            "--ignored",
            "--exact",
            "child_pushes_until_it_crashes",
            "--nocapture",
        ])
        .env(CHILD_DIRECTORY, root)
        .env(permguard_host::storage::crash::CRASH_AT, point)
        .env(permguard_host::storage::crash::CRASH_HIT, hit.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("the child runs")
}

#[cfg(unix)]
fn aborted(status: std::process::ExitStatus) -> bool {
    use std::os::unix::process::ExitStatusExt as _;
    status.signal() == Some(6)
}

#[cfg(not(unix))]
fn aborted(status: std::process::ExitStatus) -> bool {
    matches!(status.code(), Some(3) | Some(-1_073_740_791))
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pg-push-crash-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory");
    dir
}

#[test]
fn a_push_interrupted_at_every_step_recovers() {
    let mut crashed = 0;
    for point in POINTS {
        for hit in 1..=HITS {
            let root = scratch(&format!("{}-{hit}", point.replace('.', "-")));
            let status = crash(&root, point, hit);
            if !aborted(status) {
                // The push passes the point fewer times than `hit`: it finished whole.
                assert!(
                    status.success(),
                    "{point} pass {hit}: the child failed otherwise"
                );
                continue;
            }
            crashed += 1;

            // What a starting Control Plane does: resolve the ref updates the crash left open.
            let plane = Plane::open(&root);
            plane
                .mutations
                .recover(&RefDomain {
                    zones_root: root.join("zones"),
                })
                .expect("recovery runs");
            assert!(
                plane.engine.open_intents().is_empty(),
                "{point} pass {hit}: an operation is left open"
            );

            // The client retries the same push, and it lands once.
            let counter = plane
                .push()
                .unwrap_or_else(|error| panic!("{point} pass {hit}: the retry failed: {error}"));
            assert_eq!(counter, 1, "{point} pass {hit}: the ref moved twice");
            let (_, head) = commit();
            let state = plane.store.read_ref("main").unwrap().expect("the ref");
            assert_eq!((state.head, state.counter), (head, 1), "{point} pass {hit}");
            let transfers = plane.store.transfers().unwrap();
            let session = transfers
                .find_request("operator", Direction::Push, REQUEST)
                .unwrap()
                .expect("the session is kept");
            assert_eq!(session.state, State::Committed, "{point} pass {hit}");
            assert_eq!(transfers.reserved().unwrap(), 0, "{point} pass {hit}");
            assert!(
                plane.engine.open_intents().is_empty(),
                "{point} pass {hit}: the retry left an operation open"
            );
        }
    }
    assert!(
        crashed >= POINTS.len(),
        "only {crashed} rounds crashed: the points are not on the push's path"
    );
}
