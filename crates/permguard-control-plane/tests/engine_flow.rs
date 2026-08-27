// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end NOTP flows against a scratch ledger: the worked example of the
//! specification, executed — push, retry, pull, branch, and the refusals.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};

use permguard_control_plane::engine::{
    ANNOTATION_POLICY_ALIAS, ANNOTATION_POLICY_ID, ANNOTATION_POLICY_KIND, Engine, EngineError,
    EngineLimits, LedgerIdentity, MEDIA_TYPE_MANIFEST, MEDIA_TYPE_POLICY_CEDAR,
};
use permguard_objects::digest::Digest;
use permguard_objects::manifest::{
    KIND_POLICY, Manifest, PROFILE_PDP_V1, Partition, Profile, Requirement, Runtime,
};
use permguard_objects::semver::Constraint;

fn cedar_manifest() -> Manifest {
    Manifest {
        kind: KIND_POLICY.into(),
        name: "test".into(),
        description: String::new(),
        author: String::new(),
        license: String::new(),
        runtimes: BTreeMap::from([(
            "cedar".to_string(),
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
            "cedar".to_string(),
            Partition {
                runtime: "cedar".into(),
                media_types: vec![MEDIA_TYPE_POLICY_CEDAR.to_string()],
                schema: false,
                input: None,
            },
        )]),
        profiles: BTreeMap::from([(
            "default".to_string(),
            Profile {
                r#type: PROFILE_PDP_V1.into(),
                partitions: vec!["cedar".into()],
            },
        )]),
    }
}
use permguard_control_plane::store::FileObjectStore;
use permguard_notp::*;
use permguard_objects::object::{Blob, Commit, Kind, Tree, TreeEntry};
use permguard_objects::policy_id::derive_policy_id;
use permguard_objects::statement::SignedHead;

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("permguard-engine-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn limits() -> EngineLimits {
    EngineLimits {
        max_batch_bytes: 8 * 1024 * 1024,
        max_batch_objects: 1000,
        max_push_objects: 1000,
        max_push_bytes: 64 * 1024 * 1024,
        ledger_quota_bytes: 256 * 1024 * 1024,
    }
}

struct Fixture {
    store: FileObjectStore,
    key: Ed25519KeyPair,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Self {
            store: FileObjectStore::new(scratch(tag)),
            key: Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap(),
        }
    }

    fn engine(&self) -> Engine<'_> {
        Engine {
            store: &self.store,
            identity: LedgerIdentity {
                zone_id: "zone-1".into(),
                ledger_id: "ledger-1".into(),
            },
            limits: limits(),
        }
    }

    fn signer(
        &self,
    ) -> impl Fn(&permguard_objects::statement::HeadStatement) -> Result<Vec<u8>, EngineError> + '_
    {
        move |statement| {
            SignedHead::sign(statement, &self.key, b"test-key")
                .map(|signed| signed.encode())
                .map_err(|e| EngineError::Internal {
                    detail: e.to_string(),
                })
        }
    }
}

/// Builds the closure of one commit holding one Cedar policy, returning
/// (all object bytes, head digest).
fn build_commit(policy_source: &str, predecessors: Vec<Digest>) -> (Vec<Vec<u8>>, Digest) {
    build_commit_with_id(policy_source, predecessors, None)
}

/// Rule 2 of the cascade in client form: an edit of an existing path carries
/// the previous id, so the second commit passes it explicitly.
fn build_commit_with_id(
    policy_source: &str,
    predecessors: Vec<Digest>,
    carried_id: Option<String>,
) -> (Vec<Vec<u8>>, Digest) {
    let policy = Blob {
        media_type: MEDIA_TYPE_POLICY_CEDAR.into(),
        data: policy_source.as_bytes().to_vec(),
    };
    let policy_bytes = policy.encode().unwrap();
    let policy_digest = Digest::compute(&policy_bytes);

    let manifest = cedar_manifest();
    let manifest_blob = Blob {
        media_type: MEDIA_TYPE_MANIFEST.into(),
        data: manifest.encode(),
    };
    let manifest_bytes = manifest_blob.encode().unwrap();
    let manifest_digest = Digest::compute(&manifest_bytes);

    let mut annotations = BTreeMap::new();
    annotations.insert(
        ANNOTATION_POLICY_ID.to_string(),
        carried_id.unwrap_or_else(|| derive_policy_id(policy_source.as_bytes())),
    );
    annotations.insert(ANNOTATION_POLICY_KIND.to_string(), "policy".to_string());

    let partition = Tree {
        entries: vec![TreeEntry {
            kind: Kind::Blob,
            digest: policy_digest,
            name: "billing-view.cedar".into(),
            annotations,
        }],
    };
    let partition_bytes = partition.encode().unwrap();
    let partition_digest = Digest::compute(&partition_bytes);

    let root = Tree {
        entries: vec![
            TreeEntry {
                kind: Kind::Tree,
                digest: partition_digest,
                name: "cedar".into(),
                annotations: BTreeMap::new(),
            },
            TreeEntry {
                kind: Kind::Blob,
                digest: manifest_digest.clone(),
                name: "manifest".into(),
                annotations: BTreeMap::new(),
            },
        ],
    };
    let root_bytes = root.encode().unwrap();
    let root_digest = Digest::compute(&root_bytes);

    let commit = Commit {
        tree: root_digest,
        manifest: manifest_digest,
        predecessors,
        author: "nicola.gallo@nitroagility.com".into(),
        author_at: 1_787_836_800,
        message: "Restrict billing view".into(),
    };
    let commit_bytes = commit.encode().unwrap();
    let head = Digest::compute(&commit_bytes);

    (
        vec![
            policy_bytes,
            manifest_bytes,
            partition_bytes,
            root_bytes,
            commit_bytes,
        ],
        head,
    )
}

fn push(
    fixture: &Fixture,
    objects: &[Vec<u8>],
    head: &Digest,
    expected_old: Option<Digest>,
) -> CommitPushResponse {
    let engine = fixture.engine();
    let claims = objects
        .iter()
        .map(|bytes| ObjectClaim {
            digest: Digest::compute(bytes),
            size: bytes.len() as u64,
        })
        .collect();
    let negotiated = engine
        .negotiate_push(&NegotiatePushRequest {
            r#ref: "main".into(),
            new_head: head.clone(),
            expected_old: expected_old.clone(),
            closure: claims,
        })
        .unwrap();
    let to_send: Vec<Vec<u8>> = objects
        .iter()
        .filter(|bytes| negotiated.missing.contains(&Digest::compute(bytes)))
        .cloned()
        .collect();
    engine
        .upload(&UploadObjectsRequest {
            objects: to_send,
            compression: None,
        })
        .unwrap();
    let signer = fixture.signer();
    engine
        .commit_push(
            &CommitPushRequest {
                r#ref: "main".into(),
                new_head: head.clone(),
                expected_old,
            },
            &signer,
        )
        .unwrap()
}

#[test]
fn push_then_pull_round_trips_the_worked_example() {
    let fixture = Fixture::new("happy");
    let (objects, head) = build_commit("permit(principal, action, resource);", vec![]);

    // Initial push: creation, counter 1, statement verifies.
    let committed = push(&fixture, &objects, &head, None);
    assert_eq!(committed.head, head);
    assert_eq!(committed.counter, 1);
    let envelope = SignedHead::decode(&committed.statement).unwrap();
    let statement = envelope.verify(fixture.key.public_key().as_ref()).unwrap();
    assert_eq!(statement.digest, head);
    assert_eq!(statement.counter, 1);
    assert_eq!(statement.r#ref, "main");

    // Retry of the same commit: idempotent success, counter untouched.
    let engine = fixture.engine();
    let signer = fixture.signer();
    let retried = engine
        .commit_push(
            &CommitPushRequest {
                r#ref: "main".into(),
                new_head: head.clone(),
                expected_old: None,
            },
            &signer,
        )
        .unwrap();
    assert_eq!(retried.counter, 1);

    // Second commit on top: negotiation only sends the delta.
    let carried = derive_policy_id(b"permit(principal, action, resource);");
    let (objects2, head2) = build_commit_with_id(
        "permit(principal in Group::\"billing\", action, resource);",
        vec![head.clone()],
        Some(carried),
    );
    let committed2 = push(&fixture, &objects2, &head2, Some(head.clone()));
    assert_eq!(committed2.counter, 2);

    // Clone: pull with empty have gets the full closure.
    let pulled = engine
        .negotiate_pull(
            &NegotiatePullRequest {
                r#ref: "main".into(),
                at: None,
                have: vec![],
            },
            &signer,
        )
        .unwrap();
    assert_eq!(pulled.head, head2);
    assert_eq!(pulled.counter, 2);
    assert!(pulled.missing.contains(&head2));
    let fetched = engine
        .fetch(&FetchObjectsRequest {
            accept_compression: None,
            digests: pulled.missing.clone(),
        })
        .unwrap();
    assert_eq!(fetched.objects.len(), pulled.missing.len());
    for bytes in &fetched.objects {
        assert!(pulled.missing.contains(&Digest::compute(bytes)));
    }

    // Incremental sync: have = first head, only the delta travels.
    let incremental = engine
        .negotiate_pull(
            &NegotiatePullRequest {
                r#ref: "main".into(),
                at: None,
                have: vec![head.clone()],
            },
            &signer,
        )
        .unwrap();
    assert!(incremental.missing.len() < pulled.missing.len());
    assert!(!incremental.missing.contains(&head));

    // Pinned pull: at = the first commit, reachable from main.
    let pinned = engine
        .negotiate_pull(
            &NegotiatePullRequest {
                r#ref: "main".into(),
                at: Some(head.clone()),
                have: vec![],
            },
            &signer,
        )
        .unwrap();
    assert!(pinned.missing.contains(&head));
    assert!(!pinned.missing.contains(&head2));

    // Pinned pull to an unreachable digest: refused.
    let stranger = Digest::compute(b"stranger");
    assert!(matches!(
        engine.negotiate_pull(
            &NegotiatePullRequest {
                r#ref: "main".into(),
                at: Some(stranger),
                have: vec![]
            },
            &signer,
        ),
        Err(EngineError::Validation {
            code: "not_reachable",
            ..
        })
    ));
}

#[test]
fn the_refusals_hold() {
    let fixture = Fixture::new("refusals");
    let engine = fixture.engine();
    let signer = fixture.signer();
    let (objects, head) = build_commit("permit(principal, action, resource);", vec![]);
    push(&fixture, &objects, &head, None);

    // Recreating an existing ref is refused: conflict.
    let (objects2, head2) = build_commit("forbid(principal, action, resource);", vec![]);
    for bytes in &objects2 {
        engine
            .upload(&UploadObjectsRequest {
                compression: None,
                objects: vec![bytes.clone()],
            })
            .unwrap();
    }
    assert!(matches!(
        engine.commit_push(
            &CommitPushRequest {
                r#ref: "main".into(),
                new_head: head2.clone(),
                expected_old: None
            },
            &signer,
        ),
        Err(EngineError::Validation {
            code: "not_a_root",
            ..
        }) | Err(EngineError::Conflict { .. })
    ));

    // Non-fast-forward: expected old that is not an ancestor.
    let (objects3, head3) = build_commit(
        "permit(principal, action, resource) when { true };",
        vec![head2.clone()],
    );
    for bytes in &objects3 {
        engine
            .upload(&UploadObjectsRequest {
                compression: None,
                objects: vec![bytes.clone()],
            })
            .unwrap();
    }
    assert!(matches!(
        engine.commit_push(
            &CommitPushRequest {
                r#ref: "main".into(),
                new_head: head3,
                expected_old: Some(head.clone())
            },
            &signer,
        ),
        Err(EngineError::Validation {
            code: "not_fast_forward",
            ..
        })
    ));

    // Committing with objects missing: not found.
    let (_, absent_head) = build_commit(
        "permit(principal, action, resource) when { 1 == 1 };",
        vec![head.clone()],
    );
    assert!(matches!(
        engine.commit_push(
            &CommitPushRequest {
                r#ref: "main".into(),
                new_head: absent_head,
                expected_old: Some(head.clone())
            },
            &signer,
        ),
        Err(EngineError::NotFound { .. })
    ));

    // A blob with an unregistered media type is refused at upload.
    let alien = Blob {
        media_type: "application/vnd.acme.unknown".into(),
        data: vec![1],
    }
    .encode()
    .unwrap();
    assert!(matches!(
        engine.upload(&UploadObjectsRequest {
            compression: None,
            objects: vec![alien]
        }),
        Err(EngineError::Validation {
            code: "media_type_unregistered",
            ..
        })
    ));

    // An unknown ref answers not found.
    assert!(matches!(
        engine.negotiate_pull(
            &NegotiatePullRequest {
                r#ref: "ghost".into(),
                at: None,
                have: vec![]
            },
            &signer
        ),
        Err(EngineError::NotFound { .. })
    ));
}

#[test]
fn branching_at_an_existing_commit_is_free() {
    let fixture = Fixture::new("branch");
    let engine = fixture.engine();
    let signer = fixture.signer();
    let (objects, head) = build_commit("permit(principal, action, resource);", vec![]);
    push(&fixture, &objects, &head, None);

    // Create `feature` at main's head: nothing uploaded, counter starts at 1.
    let branched = engine
        .commit_push(
            &CommitPushRequest {
                r#ref: "feature/login".into(),
                new_head: head.clone(),
                expected_old: None,
            },
            &signer,
        )
        .unwrap();
    assert_eq!(branched.head, head);
    assert_eq!(branched.counter, 1);

    // The advertised ref answers with a verifiable statement.
    let (state, envelope) = engine.get_ref("feature/login", &signer).unwrap();
    assert_eq!(state.head, head);
    let statement = SignedHead::decode(&envelope)
        .unwrap()
        .verify(fixture.key.public_key().as_ref())
        .unwrap();
    assert_eq!(statement.r#ref, "feature/login");
}

#[test]
fn policy_identity_is_recomputed_and_enforced() {
    let fixture = Fixture::new("identity");
    let engine = fixture.engine();
    let signer = fixture.signer();

    // A commit whose policy annotation does not match the cascade: rejected.
    let source = "permit(principal, action, resource);";
    let (mut objects, _) = build_commit(source, vec![]);

    // Rebuild the partition tree with a wrong id.
    let policy_bytes = objects[0].clone();
    let manifest_bytes = objects[1].clone();
    let mut annotations = BTreeMap::new();
    annotations.insert(
        ANNOTATION_POLICY_ID.to_string(),
        "00000000-0000-8000-8000-000000000000".to_string(),
    );
    annotations.insert(ANNOTATION_POLICY_KIND.to_string(), "policy".to_string());
    let partition = Tree {
        entries: vec![TreeEntry {
            kind: Kind::Blob,
            digest: Digest::compute(&policy_bytes),
            name: "billing-view.cedar".into(),
            annotations,
        }],
    };
    let partition_bytes = partition.encode().unwrap();
    let root = Tree {
        entries: vec![
            TreeEntry {
                kind: Kind::Tree,
                digest: Digest::compute(&partition_bytes),
                name: "cedar".into(),
                annotations: BTreeMap::new(),
            },
            TreeEntry {
                kind: Kind::Blob,
                digest: Digest::compute(&manifest_bytes),
                name: "manifest".into(),
                annotations: BTreeMap::new(),
            },
        ],
    };
    let root_bytes = root.encode().unwrap();
    let commit = Commit {
        tree: Digest::compute(&root_bytes),
        manifest: Digest::compute(&manifest_bytes),
        predecessors: vec![],
        author: "a".into(),
        author_at: 0,
        message: "wrong id".into(),
    };
    let commit_bytes = commit.encode().unwrap();
    let head = Digest::compute(&commit_bytes);
    objects = vec![
        policy_bytes,
        manifest_bytes,
        partition_bytes,
        root_bytes,
        commit_bytes,
    ];
    for bytes in &objects {
        engine
            .upload(&UploadObjectsRequest {
                compression: None,
                objects: vec![bytes.clone()],
            })
            .unwrap();
    }
    assert!(matches!(
        engine.commit_push(
            &CommitPushRequest {
                r#ref: "main".into(),
                new_head: head,
                expected_old: None
            },
            &signer,
        ),
        Err(EngineError::Validation {
            code: "policy_id_mismatch",
            ..
        })
    ));

    // An @alias never sets the id: the id stays derived from the bytes, and
    // the alias rides along as its own annotation, carrying identity across
    // renames.
    let declared_source = "@alias(\"billing-access\")\npermit(principal, action, resource);";
    let (objects2, head2) = {
        // build_commit derives the id; rebuild with the declared one.
        let policy = Blob {
            media_type: MEDIA_TYPE_POLICY_CEDAR.into(),
            data: declared_source.as_bytes().to_vec(),
        };
        let policy_bytes = policy.encode().unwrap();
        let manifest = cedar_manifest();
        let manifest_blob = Blob {
            media_type: MEDIA_TYPE_MANIFEST.into(),
            data: manifest.encode(),
        };
        let manifest_bytes = manifest_blob.encode().unwrap();
        let mut annotations = BTreeMap::new();
        annotations.insert(
            ANNOTATION_POLICY_ID.to_string(),
            derive_policy_id(declared_source.as_bytes()),
        );
        annotations.insert(
            ANNOTATION_POLICY_ALIAS.to_string(),
            "billing-access".to_string(),
        );
        annotations.insert(ANNOTATION_POLICY_KIND.to_string(), "policy".to_string());
        let partition = Tree {
            entries: vec![TreeEntry {
                kind: Kind::Blob,
                digest: Digest::compute(&policy_bytes),
                name: "billing-view.cedar".into(),
                annotations,
            }],
        };
        let partition_bytes = partition.encode().unwrap();
        let root = Tree {
            entries: vec![
                TreeEntry {
                    kind: Kind::Tree,
                    digest: Digest::compute(&partition_bytes),
                    name: "cedar".into(),
                    annotations: BTreeMap::new(),
                },
                TreeEntry {
                    kind: Kind::Blob,
                    digest: Digest::compute(&manifest_bytes),
                    name: "manifest".into(),
                    annotations: BTreeMap::new(),
                },
            ],
        };
        let root_bytes = root.encode().unwrap();
        let commit = Commit {
            tree: Digest::compute(&root_bytes),
            manifest: Digest::compute(&manifest_bytes),
            predecessors: vec![],
            author: "a".into(),
            author_at: 0,
            message: "declared id".into(),
        };
        let commit_bytes = commit.encode().unwrap();
        let head = Digest::compute(&commit_bytes);
        (
            vec![
                policy_bytes,
                manifest_bytes,
                partition_bytes,
                root_bytes,
                commit_bytes,
            ],
            head,
        )
    };
    for bytes in &objects2 {
        engine
            .upload(&UploadObjectsRequest {
                compression: None,
                objects: vec![bytes.clone()],
            })
            .unwrap();
    }
    let committed = engine
        .commit_push(
            &CommitPushRequest {
                r#ref: "declared".into(),
                new_head: head2,
                expected_old: None,
            },
            &signer,
        )
        .unwrap();
    assert_eq!(committed.counter, 1);
}

/// The transfer lifecycle of the specification: negotiate once, N batches,
/// finalize once — with the failure modes the review demands.
#[test]
fn multi_batch_transfer_lifecycle() {
    let fixture = Fixture::new("batches");
    let engine = fixture.engine();
    let signer = fixture.signer();
    let (objects, head) = build_commit("permit(principal, action, resource);", vec![]);

    // Negotiate ONCE: the full missing set comes back.
    let claims: Vec<ObjectClaim> = objects
        .iter()
        .map(|bytes| ObjectClaim {
            digest: Digest::compute(bytes),
            size: bytes.len() as u64,
        })
        .collect();
    let negotiated = engine
        .negotiate_push(&NegotiatePushRequest {
            r#ref: "main".into(),
            new_head: head.clone(),
            expected_old: None,
            closure: claims.clone(),
        })
        .unwrap();
    assert_eq!(negotiated.missing.len(), objects.len());

    // Split into batches of 2 — a "middle batch fails" is simply a batch
    // not yet sent; nothing already uploaded is ever re-sent.
    let batches: Vec<&[Vec<u8>]> = objects.chunks(2).collect();

    // Batch 1 lands; then a premature CommitPush MUST fail without touching
    // the ref: the server verifies completeness on disk, not client claims.
    engine
        .upload(&UploadObjectsRequest {
            compression: None,
            objects: batches[0].to_vec(),
        })
        .unwrap();
    assert!(matches!(
        engine.commit_push(
            &CommitPushRequest {
                r#ref: "main".into(),
                new_head: head.clone(),
                expected_old: None
            },
            &signer,
        ),
        Err(EngineError::NotFound { .. })
    ));
    assert!(
        fixture.store.read_ref("main").unwrap().is_none(),
        "the ref moved on a premature commit"
    );

    // The retry path: only what is still missing travels. Re-negotiating is
    // legal (stateless) and now reports fewer missing objects.
    let renegotiated = engine
        .negotiate_push(&NegotiatePushRequest {
            r#ref: "main".into(),
            new_head: head.clone(),
            expected_old: None,
            closure: claims.clone(),
        })
        .unwrap();
    assert!(renegotiated.missing.len() < objects.len());
    assert_eq!(renegotiated.missing.len(), objects.len() - batches[0].len());

    // Remaining batches, one request each, each independent and idempotent —
    // including a duplicate of batch 1, which is a harmless no-op.
    for batch in &batches[1..] {
        engine
            .upload(&UploadObjectsRequest {
                compression: None,
                objects: batch.to_vec(),
            })
            .unwrap();
    }
    engine
        .upload(&UploadObjectsRequest {
            compression: None,
            objects: batches[0].to_vec(),
        })
        .unwrap();

    // missing = [] now: the client proceeds straight to CommitPush.
    let done = engine
        .negotiate_push(&NegotiatePushRequest {
            r#ref: "main".into(),
            new_head: head.clone(),
            expected_old: None,
            closure: claims,
        })
        .unwrap();
    assert!(done.missing.is_empty());

    // Finalize ONCE: the ref moves only now.
    let committed = engine
        .commit_push(
            &CommitPushRequest {
                r#ref: "main".into(),
                new_head: head.clone(),
                expected_old: None,
            },
            &signer,
        )
        .unwrap();
    assert_eq!(committed.counter, 1);
    assert_eq!(fixture.store.read_ref("main").unwrap().unwrap().head, head);

    // Pull in batches: negotiate once, fetch in chunks, every chunk verified.
    let pulled = engine
        .negotiate_pull(
            &NegotiatePullRequest {
                r#ref: "main".into(),
                at: None,
                have: vec![],
            },
            &signer,
        )
        .unwrap();
    assert_eq!(pulled.missing.len(), objects.len());
    let mut fetched_total = 0;
    for chunk in pulled.missing.chunks(2) {
        let fetched = engine
            .fetch(&FetchObjectsRequest {
                accept_compression: None,
                digests: chunk.to_vec(),
            })
            .unwrap();
        for bytes in &fetched.objects {
            assert!(
                chunk.contains(&Digest::compute(bytes)),
                "an object came back under the wrong digest"
            );
        }
        fetched_total += fetched.objects.len();
    }
    assert_eq!(fetched_total, objects.len());

    // Pull with the closure already local: missing = [], straight to finalize.
    let nothing = engine
        .negotiate_pull(
            &NegotiatePullRequest {
                r#ref: "main".into(),
                at: None,
                have: vec![head.clone()],
            },
            &signer,
        )
        .unwrap();
    assert!(nothing.missing.is_empty());
}

/// Malformed bytes never land, whichever batch carries them; the objects of
/// the same batch that came before them do land (each object is verified and
/// stored independently — immutable, reusable on retry).
#[test]
fn tampered_uploads_are_rejected() {
    let fixture = Fixture::new("tampered");
    let engine = fixture.engine();
    let (objects, _) = build_commit("permit(principal, action, resource);", vec![]);

    let mut tampered = objects[0].clone();
    tampered.push(0x00);
    assert!(matches!(
        engine.upload(&UploadObjectsRequest {
            compression: None,
            objects: vec![tampered]
        }),
        Err(EngineError::Validation { .. })
    ));

    // A batch failing mid-way leaves the earlier objects stored: the retry
    // re-sends only what is still missing.
    let mut garbage_last = vec![objects[0].clone(), b"garbage".to_vec()];
    assert!(
        engine
            .upload(&UploadObjectsRequest {
                compression: None,
                objects: garbage_last.clone()
            })
            .is_err()
    );
    assert!(fixture.store.has_object(&Digest::compute(&objects[0])));
    garbage_last.pop();
    engine
        .upload(&UploadObjectsRequest {
            compression: None,
            objects: garbage_last,
        })
        .unwrap();
}

/// The alias carries identity across a rename: same bytes, same @alias, a
/// different entry name — the id must not change. Without an alias the same
/// rename is a new identity (git semantics), and a snapshot with two equal
/// aliases rejects.
#[test]
fn alias_carries_identity_across_renames() {
    let fixture = Fixture::new("alias-rename");
    let engine = fixture.engine();
    let signer = fixture.signer();

    let source = "@alias(\"billing-access\")\npermit(principal, action, resource);";
    let expected_id = derive_policy_id(source.as_bytes());

    let build = |entry_name: &str, predecessors: Vec<Digest>| -> (Vec<Vec<u8>>, Digest) {
        let policy = Blob {
            media_type: MEDIA_TYPE_POLICY_CEDAR.into(),
            data: source.as_bytes().to_vec(),
        };
        let policy_bytes = policy.encode().unwrap();
        let manifest = cedar_manifest();
        let manifest_blob = Blob {
            media_type: MEDIA_TYPE_MANIFEST.into(),
            data: manifest.encode(),
        };
        let manifest_bytes = manifest_blob.encode().unwrap();
        let mut annotations = BTreeMap::new();
        annotations.insert(ANNOTATION_POLICY_ID.to_string(), expected_id.clone());
        annotations.insert(
            ANNOTATION_POLICY_ALIAS.to_string(),
            "billing-access".to_string(),
        );
        annotations.insert(ANNOTATION_POLICY_KIND.to_string(), "policy".to_string());
        let partition = Tree {
            entries: vec![TreeEntry {
                kind: Kind::Blob,
                digest: Digest::compute(&policy_bytes),
                name: entry_name.into(),
                annotations,
            }],
        };
        let partition_bytes = partition.encode().unwrap();
        let root = Tree {
            entries: vec![
                TreeEntry {
                    kind: Kind::Tree,
                    digest: Digest::compute(&partition_bytes),
                    name: "cedar".into(),
                    annotations: BTreeMap::new(),
                },
                TreeEntry {
                    kind: Kind::Blob,
                    digest: Digest::compute(&manifest_bytes),
                    name: "manifest".into(),
                    annotations: BTreeMap::new(),
                },
            ],
        };
        let root_bytes = root.encode().unwrap();
        let commit = Commit {
            tree: Digest::compute(&root_bytes),
            manifest: Digest::compute(&manifest_bytes),
            predecessors,
            author: "a".into(),
            author_at: 0,
            message: format!("policy at {entry_name}"),
        };
        let commit_bytes = commit.encode().unwrap();
        let head = Digest::compute(&commit_bytes);
        (
            vec![
                policy_bytes,
                manifest_bytes,
                partition_bytes,
                root_bytes,
                commit_bytes,
            ],
            head,
        )
    };

    // Commit 1: the policy at its original name.
    let (objects, head) = build("billing-view.cedar", vec![]);
    for bytes in &objects {
        engine
            .upload(&UploadObjectsRequest {
                compression: None,
                objects: vec![bytes.clone()],
            })
            .unwrap();
    }
    engine
        .commit_push(
            &CommitPushRequest {
                r#ref: "main".into(),
                new_head: head.clone(),
                expected_old: None,
            },
            &signer,
        )
        .unwrap();

    // Commit 2: renamed entry, same alias — the SAME id must be accepted
    // (carried by alias, since no path matches).
    let (objects2, head2) = build("billing-access.cedar", vec![head.clone()]);
    for bytes in &objects2 {
        engine
            .upload(&UploadObjectsRequest {
                compression: None,
                objects: vec![bytes.clone()],
            })
            .unwrap();
    }
    let committed = engine
        .commit_push(
            &CommitPushRequest {
                r#ref: "main".into(),
                new_head: head2,
                expected_old: Some(head),
            },
            &signer,
        )
        .unwrap();
    assert_eq!(committed.counter, 2);
}

/// The closure of one commit whose partition declares `schema: true`,
/// carrying `policy_source` and, when given, `schema_source`.
fn build_schema_commit(policy_source: &str, schema_source: Option<&str>) -> (Vec<Vec<u8>>, Digest) {
    const MEDIA_TYPE_SCHEMA_CEDAR: &str = "application/vnd.permguard.schema.cedar";

    let mut manifest = cedar_manifest();
    let partition = manifest.partitions.get_mut("cedar").unwrap();
    partition.schema = true;
    partition
        .media_types
        .push(MEDIA_TYPE_SCHEMA_CEDAR.to_string());
    let manifest_blob = Blob {
        media_type: MEDIA_TYPE_MANIFEST.into(),
        data: manifest.encode(),
    };
    let manifest_bytes = manifest_blob.encode().unwrap();
    let manifest_digest = Digest::compute(&manifest_bytes);

    let policy = Blob {
        media_type: MEDIA_TYPE_POLICY_CEDAR.into(),
        data: policy_source.as_bytes().to_vec(),
    };
    let policy_bytes = policy.encode().unwrap();
    let mut annotations = BTreeMap::new();
    annotations.insert(
        ANNOTATION_POLICY_ID.to_string(),
        derive_policy_id(policy_source.as_bytes()),
    );
    annotations.insert(ANNOTATION_POLICY_KIND.to_string(), "policy".to_string());
    let mut entries = vec![TreeEntry {
        kind: Kind::Blob,
        digest: Digest::compute(&policy_bytes),
        name: "billing-view.cedar".into(),
        annotations,
    }];

    let mut objects = vec![policy_bytes, manifest_bytes];
    if let Some(schema_source) = schema_source {
        let schema = Blob {
            media_type: MEDIA_TYPE_SCHEMA_CEDAR.into(),
            data: schema_source.as_bytes().to_vec(),
        };
        let schema_bytes = schema.encode().unwrap();
        entries.push(TreeEntry {
            kind: Kind::Blob,
            digest: Digest::compute(&schema_bytes),
            name: "model.cedarschema".into(),
            annotations: BTreeMap::new(),
        });
        objects.push(schema_bytes);
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    let partition = Tree { entries };
    let partition_bytes = partition.encode().unwrap();
    let root = Tree {
        entries: vec![
            TreeEntry {
                kind: Kind::Tree,
                digest: Digest::compute(&partition_bytes),
                name: "cedar".into(),
                annotations: BTreeMap::new(),
            },
            TreeEntry {
                kind: Kind::Blob,
                digest: manifest_digest.clone(),
                name: "manifest".into(),
                annotations: BTreeMap::new(),
            },
        ],
    };
    let root_bytes = root.encode().unwrap();
    let commit = Commit {
        tree: Digest::compute(&root_bytes),
        manifest: manifest_digest,
        predecessors: vec![],
        author: "nicola.gallo@nitroagility.com".into(),
        author_at: 1_787_836_800,
        message: "With a schema".into(),
    };
    let commit_bytes = commit.encode().unwrap();
    let head = Digest::compute(&commit_bytes);
    objects.push(partition_bytes);
    objects.push(root_bytes);
    objects.push(commit_bytes);

    (objects, head)
}

/// Pushes a prepared closure and returns what `commit_push` answered, so a
/// test can assert the refusal instead of unwrapping past it.
fn try_push(
    fixture: &Fixture,
    objects: &[Vec<u8>],
    head: &Digest,
) -> Result<CommitPushResponse, EngineError> {
    let engine = fixture.engine();
    for bytes in objects {
        engine
            .upload(&UploadObjectsRequest {
                compression: None,
                objects: vec![bytes.clone()],
            })
            .unwrap();
    }
    let signer = fixture.signer();
    engine.commit_push(
        &CommitPushRequest {
            r#ref: "main".into(),
            new_head: head.clone(),
            expected_old: None,
        },
        &signer,
    )
}

const SCHEMA_COVERING: &str = "entity User;\nentity Document;\naction view appliesTo { principal: [User], resource: [Document] };\n";

#[test]
fn a_policy_that_satisfies_its_schema_is_accepted() {
    let fixture = Fixture::new("schema-ok");
    let (objects, head) = build_schema_commit(
        r#"permit(principal == User::"alice", action == Action::"view", resource);"#,
        Some(SCHEMA_COVERING),
    );

    assert!(try_push(&fixture, &objects, &head).is_ok());
}

#[test]
fn a_policy_that_does_not_satisfy_its_schema_is_refused_at_the_push() {
    // The error belongs to whoever pushed. Without this check the commit is
    // stored, mirrored, and every data plane serving the ledger turns into a
    // 503 at load — fail-closed, and far too late.
    let fixture = Fixture::new("schema-bad");
    let (objects, head) = build_schema_commit(
        r#"permit(principal == Ghost::"nobody", action == Action::"view", resource);"#,
        Some(SCHEMA_COVERING),
    );

    assert!(matches!(
        try_push(&fixture, &objects, &head),
        Err(EngineError::Validation {
            code: "schema_unsatisfied",
            ..
        })
    ));
}

#[test]
fn a_partition_that_declares_a_schema_must_carry_one() {
    let fixture = Fixture::new("schema-absent");
    let (objects, head) = build_schema_commit(
        r#"permit(principal == User::"alice", action == Action::"view", resource);"#,
        None,
    );

    assert!(matches!(
        try_push(&fixture, &objects, &head),
        Err(EngineError::Validation {
            code: "schema_missing",
            ..
        })
    ));
}
