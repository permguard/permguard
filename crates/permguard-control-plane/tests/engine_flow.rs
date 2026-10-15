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
    EngineLimits, LedgerIdentity, MEDIA_TYPE_MANIFEST, MEDIA_TYPE_POLICY_CEDAR, TransferPolicy,
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
                interfaces: Vec::new(),
                runtime: "cedar".into(),
                media_types: vec![MEDIA_TYPE_POLICY_CEDAR.to_string()],
                schema: false,
                artifacts: Vec::new(),
                history: None,
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
use permguard_objects::crypto::suite::Suite;
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
    mutations: permguard_host::composition::MutationHandle,
    /// The volume the mutation transaction keeps its journal and trails on.
    volume: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let volume = scratch(&format!("{tag}-volume"));
        Self {
            store: FileObjectStore::new(scratch(tag).join("ledger")),
            key: Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap(),
            mutations: permguard_control_plane::store::testing::offline_ref_mutations(&volume)
                .unwrap(),
            volume,
        }
    }

    fn engine(&self) -> Engine<'_> {
        Engine {
            store: &self.store,
            authority: [0x11; 16],
            // A test signer binds no ring: the engine names none.
            ring: (0, permguard_objects::Digest::from_raw([0; 32])),
            caller: "tester".into(),
            mutations: &self.mutations,
            transfer: TransferPolicy {
                ttl: std::time::Duration::from_secs(900),
                grace: std::time::Duration::from_secs(3600),
            },
            identity: LedgerIdentity {
                zone_id: "zone-1".into(),
                ledger_id: "ledger-1".into(),
            },
            limits: limits(),
            // A test has no deployment to consult: what the build carries is what it sees.
            enabled: permguard_languages::registry::Enabled::everything(),
            clock: &permguard_core::time::SystemClock,
        }
    }

    fn signer(
        &self,
    ) -> impl Fn(&permguard_objects::statement::HeadStatement) -> Result<Vec<u8>, EngineError> + '_
    {
        move |statement| {
            SignedHead::sign(statement, &self.key, b"test-key")
                .map(|signed| signed.encode().expect("it encodes"))
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
        data: manifest.encode().expect("it encodes"),
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

/// The ref state a push that read `old` as the head names: the current one when its head is
/// `old`, a state that is not current otherwise, and none for a creation.
fn expected(fixture: &Fixture, old: Option<&Digest>) -> Option<ExpectedRef> {
    let old = old?;
    match fixture.store.read_ref("main").unwrap() {
        Some(state) if state.head == *old => Some(ExpectedRef {
            counter: state.counter,
            digest: state.ref_digest().unwrap(),
        }),
        current => Some(ExpectedRef {
            counter: current.map_or(1, |state| state.counter),
            digest: Digest::compute(old.to_string().as_bytes()),
        }),
    }
}

/// The request id of a push of `head` to `name`, unique per ref and head as a client names it.
fn request_of(name: &str, head: &Digest) -> String {
    format!("{name}-{}", &head.to_string()["sha256:".len()..][..16])
}

fn claims(objects: &[Vec<u8>]) -> Vec<ObjectClaim> {
    objects
        .iter()
        .map(|bytes| ObjectClaim {
            digest: Digest::compute(bytes),
            size: bytes.len() as u64,
        })
        .collect()
}

/// Opens the push session of `head` on `name` over `objects`, as a client negotiates before it
/// uploads; the request id is the head's, as the CLI names it.
fn open(
    fixture: &Fixture,
    name: &str,
    head: &Digest,
    expected_ref: Option<ExpectedRef>,
    objects: &[Vec<u8>],
) -> Result<[u8; 16], EngineError> {
    Ok(fixture
        .engine()
        .negotiate_push(&NegotiatePushRequest {
            request_id: request_of(name, head),
            r#ref: name.into(),
            new_head: head.clone(),
            expected_ref,
            closure: claims(objects),
        })?
        .transfer_id)
}

/// The commit of the session `open` answered.
fn commit_request(
    name: &str,
    head: &Digest,
    expected_ref: Option<ExpectedRef>,
    transfer_id: [u8; 16],
) -> CommitPushRequest {
    CommitPushRequest {
        request_id: request_of(name, head),
        transfer_id,
        r#ref: name.into(),
        new_head: head.clone(),
        expected_ref,
    }
}

/// The session the test caller opened for `head`, still kept.
fn transfer_of(fixture: &Fixture, head: &Digest) -> [u8; 16] {
    fixture
        .store
        .transfers()
        .unwrap()
        .find_request(
            "tester",
            permguard_control_plane::transfer::Direction::Push,
            &request_of("main", head),
        )
        .unwrap()
        .expect("a session of this head")
        .transfer_id
}

/// One whole push of `objects` to `name`: negotiate, upload each object, commit; the outcome
/// answered, not unwrapped.
fn try_commit(
    fixture: &Fixture,
    name: &str,
    head: &Digest,
    expected_ref: Option<ExpectedRef>,
    objects: &[Vec<u8>],
) -> Result<CommitPushResponse, EngineError> {
    let engine = fixture.engine();
    let transfer_id = open(fixture, name, head, expected_ref.clone(), objects)?;
    for bytes in objects {
        engine.upload(&UploadObjectsRequest {
            transfer_id,
            compression: None,
            objects: vec![bytes.clone()],
        })?;
    }
    engine.commit_push(
        &commit_request(name, head, expected_ref, transfer_id),
        &fixture.signer(),
    )
}

fn push(
    fixture: &Fixture,
    objects: &[Vec<u8>],
    head: &Digest,
    expected_old: Option<Digest>,
) -> CommitPushResponse {
    let engine = fixture.engine();
    let expected_ref = expected(fixture, expected_old.as_ref());
    let negotiated = engine
        .negotiate_push(&NegotiatePushRequest {
            request_id: request_of("main", head),
            r#ref: "main".into(),
            new_head: head.clone(),
            expected_ref: expected_ref.clone(),
            closure: claims(objects),
        })
        .unwrap();
    let to_send: Vec<Vec<u8>> = objects
        .iter()
        .filter(|bytes| negotiated.missing.contains(&Digest::compute(bytes)))
        .cloned()
        .collect();
    engine
        .upload(&UploadObjectsRequest {
            transfer_id: negotiated.transfer_id,
            objects: to_send,
            compression: None,
        })
        .unwrap();
    let signer = fixture.signer();
    engine
        .commit_push(
            &commit_request("main", head, expected_ref, negotiated.transfer_id),
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
    let statement = envelope
        .verify(Suite::Ed25519Sha256V1, fixture.key.public_key().as_ref())
        .unwrap();
    assert_eq!(statement.digest, head);
    assert_eq!(statement.counter, 1);
    assert_eq!(statement.r#ref, "main");

    // Retry of the same commit: idempotent success, counter untouched.
    let engine = fixture.engine();
    let signer = fixture.signer();
    let retried = engine
        .commit_push(
            &commit_request("main", &head, None, transfer_of(&fixture, &head)),
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
                checkpoint: None,
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
            transfer_id: pulled.transfer_id,
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
                checkpoint: None,
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
                checkpoint: None,
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
                checkpoint: None,
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

    // Recreating an existing ref is refused: conflict, at negotiation already.
    let (objects2, head2) = build_commit("forbid(principal, action, resource);", vec![]);
    assert!(matches!(
        try_commit(&fixture, "main", &head2, None, &objects2),
        Err(EngineError::Conflict { .. })
    ));

    // Non-fast-forward: expected old that is not an ancestor.
    let (objects3, head3) = build_commit(
        "permit(principal, action, resource) when { true };",
        vec![head2.clone()],
    );
    let all: Vec<Vec<u8>> = objects2.iter().chain(&objects3).cloned().collect();
    assert!(matches!(
        try_commit(
            &fixture,
            "main",
            &head3,
            expected(&fixture, Some(&head)),
            &all
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
        try_commit(
            &fixture,
            "main",
            &absent_head,
            expected(&fixture, Some(&head)),
            &[]
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
    let (_, alien_head) = build_commit(
        "forbid(principal, action, resource) when { 2 == 2 };",
        vec![head.clone()],
    );
    let transfer_id = open(
        &fixture,
        "main",
        &alien_head,
        expected(&fixture, Some(&head)),
        std::slice::from_ref(&alien),
    )
    .unwrap();
    assert!(matches!(
        engine.upload(&UploadObjectsRequest {
            transfer_id,
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
                checkpoint: None,
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
    let branched = try_commit(&fixture, "feature/login", &head, None, &[]).unwrap();
    assert_eq!(branched.head, head);
    assert_eq!(branched.counter, 1);

    // The advertised ref answers with a verifiable statement.
    let (state, envelope) = engine.get_ref("feature/login", &signer).unwrap();
    assert_eq!(state.head, head);
    let statement = SignedHead::decode(&envelope)
        .unwrap()
        .verify(Suite::Ed25519Sha256V1, fixture.key.public_key().as_ref())
        .unwrap();
    assert_eq!(statement.r#ref, "feature/login");
}

#[test]
fn policy_identity_is_recomputed_and_enforced() {
    let fixture = Fixture::new("identity");

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
    assert!(matches!(
        try_commit(&fixture, "main", &head, None, &objects),
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
            data: manifest.encode().expect("it encodes"),
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
    let committed = try_commit(&fixture, "declared", &head2, None, &objects2).unwrap();
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
            request_id: request_of("main", &head),
            r#ref: "main".into(),
            new_head: head.clone(),
            expected_ref: None,
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
            transfer_id: negotiated.transfer_id,
            compression: None,
            objects: batches[0].to_vec(),
        })
        .unwrap();
    assert!(matches!(
        engine.commit_push(
            &commit_request("main", &head, None, negotiated.transfer_id),
            &signer,
        ),
        Err(EngineError::NotFound { .. })
    ));
    assert!(
        fixture.store.read_ref("main").unwrap().is_none(),
        "the ref moved on a premature commit"
    );

    // The retry path: only what is still missing travels. Re-negotiating with the same request
    // resumes the same session, and now reports fewer missing objects.
    let renegotiated = engine
        .negotiate_push(&NegotiatePushRequest {
            request_id: request_of("main", &head),
            r#ref: "main".into(),
            new_head: head.clone(),
            expected_ref: None,
            closure: claims.clone(),
        })
        .unwrap();
    assert_eq!(
        renegotiated.transfer_id, negotiated.transfer_id,
        "the session resumes"
    );
    assert_eq!(
        renegotiated.expiry, negotiated.expiry,
        "and keeps its expiry"
    );
    assert!(renegotiated.missing.len() < objects.len());
    assert_eq!(renegotiated.missing.len(), objects.len() - batches[0].len());

    // Remaining batches, one request each, each independent and idempotent —
    // including a duplicate of batch 1, which is a harmless no-op.
    for batch in &batches[1..] {
        engine
            .upload(&UploadObjectsRequest {
                transfer_id: negotiated.transfer_id,
                compression: None,
                objects: batch.to_vec(),
            })
            .unwrap();
    }
    engine
        .upload(&UploadObjectsRequest {
            transfer_id: negotiated.transfer_id,
            compression: None,
            objects: batches[0].to_vec(),
        })
        .unwrap();

    // missing = [] now: the client proceeds straight to CommitPush.
    let done = engine
        .negotiate_push(&NegotiatePushRequest {
            request_id: request_of("main", &head),
            r#ref: "main".into(),
            new_head: head.clone(),
            expected_ref: None,
            closure: claims,
        })
        .unwrap();
    assert!(done.missing.is_empty());

    // Finalize ONCE: the ref moves only now.
    let committed = engine
        .commit_push(
            &commit_request("main", &head, None, negotiated.transfer_id),
            &signer,
        )
        .unwrap();
    assert_eq!(committed.counter, 1);
    assert_eq!(fixture.store.read_ref("main").unwrap().unwrap().head, head);

    // Pull in batches: negotiate once, fetch in chunks, every chunk verified.
    let pulled = engine
        .negotiate_pull(
            &NegotiatePullRequest {
                checkpoint: None,
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
                transfer_id: pulled.transfer_id,
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
                checkpoint: None,
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
    let (objects, head) = build_commit("permit(principal, action, resource);", vec![]);

    let mut tampered = objects[0].clone();
    tampered.push(0x00);
    // Each declared, so the bytes themselves are what is refused.
    let declared = vec![objects[0].clone(), tampered.clone(), b"garbage".to_vec()];
    let transfer_id = open(&fixture, "main", &head, None, &declared).unwrap();
    assert!(matches!(
        engine.upload(&UploadObjectsRequest {
            transfer_id,
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
                transfer_id,
                compression: None,
                objects: garbage_last.clone()
            })
            .is_err()
    );
    assert!(fixture.store.has_object(&Digest::compute(&objects[0])));
    garbage_last.pop();
    engine
        .upload(&UploadObjectsRequest {
            transfer_id,
            compression: None,
            objects: garbage_last,
        })
        .unwrap();

    // An object the session never declared is refused before it is read.
    assert!(matches!(
        engine.upload(&UploadObjectsRequest {
            transfer_id,
            compression: None,
            objects: vec![objects[1].clone()]
        }),
        Err(EngineError::Transfer {
            code: "transfer_mismatch",
            ..
        })
    ));
}

/// The alias carries identity across a rename: same bytes, same @alias, a
/// different entry name — the id must not change. Without an alias the same
/// rename is a new identity (git semantics), and a snapshot with two equal
/// aliases rejects.
#[test]
fn alias_carries_identity_across_renames() {
    let fixture = Fixture::new("alias-rename");

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
            data: manifest.encode().expect("it encodes"),
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
    try_commit(&fixture, "main", &head, None, &objects).unwrap();

    // Commit 2: renamed entry, same alias — the SAME id must be accepted
    // (carried by alias, since no path matches).
    let (objects2, head2) = build("billing-access.cedar", vec![head.clone()]);
    let committed = try_commit(
        &fixture,
        "main",
        &head2,
        expected(&fixture, Some(&head)),
        &objects2,
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
        data: manifest.encode().expect("it encodes"),
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
    try_commit(fixture, "main", head, None, objects)
}

/// A second session of a head that already landed, opened under another request id: its
/// commit takes the idempotent path of a ref already where it asks.
fn reopen(fixture: &Fixture, head: &Digest, request_id: &str) -> CommitPushRequest {
    let transfer_id = fixture
        .engine()
        .negotiate_push(&NegotiatePushRequest {
            request_id: request_id.into(),
            r#ref: "main".into(),
            new_head: head.clone(),
            expected_ref: None,
            closure: Vec::new(),
        })
        .unwrap()
        .transfer_id;
    CommitPushRequest {
        request_id: request_id.into(),
        transfer_id,
        r#ref: "main".into(),
        new_head: head.clone(),
        expected_ref: None,
    }
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

/// The signed statement is a rebuildable cache (P4): a retried commit whose statement file was
/// lost is answered with a statement signed again, never with an empty one the client cannot
/// verify.
#[test]
fn a_retried_commit_whose_statement_was_lost_is_signed_again() {
    let fixture = Fixture::new("statement-lost");
    let (objects, head) = build_commit("permit(principal, action, resource);", vec![]);
    push(&fixture, &objects, &head, None);
    std::fs::remove_file(fixture.store.root().join("signatures").join("main"))
        .expect("the cached statement is removed");

    let signer = fixture.signer();
    let retried = fixture
        .engine()
        .commit_push(&reopen(&fixture, &head, "again"), &signer)
        .unwrap();
    let statement = SignedHead::decode(&retried.statement)
        .unwrap()
        .verify(Suite::Ed25519Sha256V1, fixture.key.public_key().as_ref())
        .unwrap();
    assert_eq!((statement.digest, statement.counter), (head, 1));
    assert!(
        fixture
            .store
            .root()
            .join("signatures")
            .join("main")
            .is_file(),
        "and the cache is rebuilt"
    );
}

/// Every file a populated ledger holds is one the store declares (P4), and nothing the
/// declaration calls rebuildable is anything else.
#[test]
fn every_file_of_a_populated_ledger_is_declared() {
    use permguard_host::storage::authority::Declared as _;

    let fixture = Fixture::new("declared");
    let (objects, head) = build_commit("permit(principal, action, resource);", vec![]);
    push(&fixture, &objects, &head, None);
    let carried = derive_policy_id(b"permit(principal, action, resource);");
    let (more, next) = build_commit_with_id(
        "permit(principal in Group::\"billing\", action, resource);",
        vec![head.clone()],
        Some(carried),
    );
    push(&fixture, &more, &next, Some(head));

    let declared: Vec<&str> = FileObjectStore::files()
        .iter()
        .map(|class| class.pattern)
        .collect();
    assert_eq!(
        declared,
        [
            "objects/<2 hex>/<62 hex>",
            "refs/<name>",
            "FORMAT",
            "signatures/<ref>",
            "transfers/<32 hex>.cbor"
        ]
    );
    let hex = |text: &str, length: usize| {
        text.len() == length && text.bytes().all(|byte| byte.is_ascii_hexdigit())
    };
    let mut files = Vec::new();
    let mut pending = vec![fixture.store.root().to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                let relative = path
                    .strip_prefix(fixture.store.root())
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                files.push(relative);
            }
        }
    }
    assert!(files.len() > 4, "{files:?}");
    for file in &files {
        let parts: Vec<&str> = file.split('/').collect();
        let matched = match parts.as_slice() {
            ["FORMAT"] => true,
            ["objects", fan, rest] => hex(fan, 2) && hex(rest, 62),
            ["transfers", session] => session.strip_suffix(".cbor").is_some_and(|id| hex(id, 32)),
            ["refs", name @ ..] | ["signatures", name @ ..] => {
                permguard_objects::grammar::validate_ref_name(&name.join("/")).is_ok()
            }
            _ => false,
        };
        assert!(matched, "`{file}` is not a file the store declares");
    }
}

/// A commit is a durable claim on the objects it reaches, including those negotiation told the
/// push not to send: their directories are flushed before the ref is written, and a flush that
/// fails stops the commit with the ref unmoved.
#[test]
fn a_commit_flushes_the_objects_it_reaches_before_writing_the_ref() {
    let fixture = Fixture::new("commit-durable");
    let (objects, head) = build_commit("permit(principal, action, resource);", vec![]);
    let engine = fixture.engine();
    let transfer_id = open(&fixture, "main", &head, None, &objects).unwrap();
    engine
        .upload(&UploadObjectsRequest {
            transfer_id,
            objects: objects.clone(),
            compression: None,
        })
        .unwrap();

    let signer = fixture.signer();
    {
        let _guard = permguard_core::fault::inject(
            fixture.store.root().join("objects"),
            permguard_core::fault::Fault::Fsync,
        );
        assert!(
            engine
                .commit_push(&commit_request("main", &head, None, transfer_id), &signer)
                .is_err(),
            "the objects could not be made durable, so the commit does not land"
        );
    }
    assert!(
        fixture.store.read_ref("main").unwrap().is_none(),
        "the ref did not move"
    );
}

/// A retried commit whose ref is already where it asks is answered only after the ref and its
/// directory are flushed.
#[test]
fn a_retried_commit_is_answered_only_after_its_ref_is_flushed() {
    let fixture = Fixture::new("retry-durable");
    let (objects, head) = build_commit("permit(principal, action, resource);", vec![]);
    push(&fixture, &objects, &head, None);
    let signer = fixture.signer();
    let again = reopen(&fixture, &head, "again");
    let refs = fixture.store.root().join("refs");
    for path in [refs.clone(), refs.join("main")] {
        // One failure only: a retry within the call would succeed, and the call must not.
        let _guard = permguard_core::fault::inject_exact(
            &path,
            permguard_core::fault::Fault::FsyncTimes { remaining: 1 },
        );
        assert!(
            fixture.engine().commit_push(&again, &signer).is_err(),
            "{}",
            path.display()
        );
    }
    let retried = fixture
        .engine()
        .commit_push(&again, &signer)
        .expect("answered once the flush succeeds");
    assert_eq!((retried.head, retried.counter), (head, 1));
}

/// WP-7.1: the statement cache serves only a statement of the ring in force; after a rotation
/// the same ref state is signed again, naming the new epoch and set.
#[test]
fn a_cached_statement_of_another_ring_is_signed_again() {
    let fixture = Fixture::new("ring-moved");
    let (objects, head) = build_commit("permit(principal, action, resource);", vec![]);
    push(&fixture, &objects, &head, None);
    let signer = fixture.signer();
    let (_, first) = fixture.engine().get_ref("main", &signer).unwrap();
    let (_, again) = fixture.engine().get_ref("main", &signer).unwrap();
    assert_eq!(first, again, "the cache serves the same ring's statement");

    // The epoch alone moves, then the set alone: each is a ring no longer in force.
    let zeros = Digest::from_raw([0; 32]);
    for ring in [(1, zeros.clone()), (0, Digest::compute(b"rotated set"))] {
        // The cache holds the statement of the ring the fixture names, so only one part differs.
        fixture.engine().get_ref("main", &signer).unwrap();
        let rotated = Engine {
            ring: ring.clone(),
            ..fixture.engine()
        };
        let (_, resigned) = rotated.get_ref("main", &signer).unwrap();
        let statement = SignedHead::decode(&resigned)
            .unwrap()
            .statement_unverified()
            .unwrap();
        assert_eq!((statement.ring_epoch, statement.key_set_digest), ring);
        assert_eq!(statement.digest, head, "the same ref state");
    }

    // The same head and counter under another ref state, a record rewritten beside the
    // engine: the statement names the state, so it is signed again. The cache first holds the
    // statement of the ring in force, so only the state differs.
    fixture.engine().get_ref("main", &signer).unwrap();
    let state = fixture.store.read_ref("main").unwrap().unwrap();
    let previous = Digest::compute(b"another history");
    std::fs::write(
        fixture.store.root().join("refs").join("main"),
        format!(
            "{{\"version\":1,\"head\":\"{}\",\"counter\":{},\"previous\":\"{previous}\"}}\n",
            state.head, state.counter
        ),
    )
    .unwrap();
    let (moved, resigned) = fixture.engine().get_ref("main", &signer).unwrap();
    let statement = SignedHead::decode(&resigned)
        .unwrap()
        .statement_unverified()
        .unwrap();
    assert_eq!(statement.ref_digest, moved.ref_digest().unwrap());
    assert_ne!(statement.ref_digest, state.ref_digest().unwrap());
}

/// WP-7.1: a negotiation naming a state that is not the current one conflicts before anything
/// is uploaded; a creation over an existing ref too; a retry of the head that landed does not.
#[test]
fn a_negotiation_naming_a_state_that_is_not_current_conflicts() {
    let fixture = Fixture::new("negotiate-stale");
    let (objects, head) = build_commit("permit(principal, action, resource);", vec![]);
    push(&fixture, &objects, &head, None);
    let (_, next) = build_commit("forbid(principal, action, resource);", vec![head.clone()]);
    let negotiate = |new_head: &Digest, expected_ref: Option<ExpectedRef>, request_id: &str| {
        fixture.engine().negotiate_push(&NegotiatePushRequest {
            r#ref: "main".into(),
            new_head: new_head.clone(),
            expected_ref,
            closure: Vec::new(),
            request_id: request_id.into(),
        })
    };

    let stale = ExpectedRef {
        counter: 1,
        digest: Digest::compute(b"not the state"),
    };
    assert!(matches!(
        negotiate(&next, Some(stale), "stale"),
        Err(EngineError::Conflict { current: Some(_) })
    ));
    assert!(matches!(
        negotiate(&next, None, "creation"),
        Err(EngineError::Conflict { current: Some(_) })
    ));
    negotiate(&head, None, "retry").expect("a retry of the landed head negotiates");
    negotiate(&next, expected(&fixture, Some(&head)), "next")
        .expect("the current state negotiates");
}

/// WP-7.12: a ref update is one operation of the Host's mutation transaction. Its record names
/// the operation, which is what recovery asks: the operation that wrote the ref is observed at
/// the ref's counter, any other is not.
#[test]
fn a_ref_update_names_its_operation_for_recovery() {
    use permguard_host::operations::journal::OperationId;
    use permguard_host::operations::mutation::Domain as _;

    let fixture = Fixture::new("operation");
    let (objects, head) = build_commit("permit(principal, action, resource);", vec![]);
    push(&fixture, &objects, &head, None);
    let written = fixture
        .store
        .ref_operation("main")
        .unwrap()
        .expect("the record names its operation");
    let bytes: [u8; 16] = (0..16)
        .map(|at| u8::from_str_radix(&written[at * 2..at * 2 + 2], 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let ledger = fixture.store.root();
    let zones = ledger.parent().unwrap().join("zones");
    std::fs::create_dir_all(zones.join("zone-1").join("ledgers")).unwrap();
    std::fs::rename(
        ledger,
        zones.join("zone-1").join("ledgers").join("ledger-1"),
    )
    .unwrap();
    let domain = permguard_control_plane::store::RefDomain { zones_root: zones };
    let target = permguard_control_plane::store::RefDomain::target("zone-1", "ledger-1", "main");
    let observed = domain
        .observe(&OperationId::from_bytes(bytes), Some(&target))
        .expect("the operation that wrote the ref is observed");
    assert_eq!(observed.revision, 1);
    assert!(
        domain
            .observe(&OperationId::from_bytes([0xee; 16]), Some(&target))
            .is_none(),
        "another operation is not"
    );
    assert!(
        domain
            .observe(&OperationId::from_bytes(bytes), Some("../escape/main"))
            .is_none(),
        "nor a target outside the zones"
    );
}

/// WP-7.12: a ref update the audit trail cannot record is refused before anything is applied,
/// and the transfer stays open for the retry once the trail is back.
#[test]
fn a_ref_update_the_audit_cannot_record_moves_nothing() {
    let fixture = Fixture::new("audit-down");
    let (objects, head) = build_commit("permit(principal, action, resource);", vec![]);
    let engine = fixture.engine();
    let transfer_id = open(&fixture, "main", &head, None, &objects).unwrap();
    engine
        .upload(&UploadObjectsRequest {
            transfer_id,
            objects: objects.clone(),
            compression: None,
        })
        .unwrap();
    let signer = fixture.signer();
    {
        let _guard = permguard_core::fault::inject(
            fixture.volume.join("host").join("audit").join("trails"),
            permguard_core::fault::Fault::Fsync,
        );
        let refused = engine
            .commit_push(&commit_request("main", &head, None, transfer_id), &signer)
            .expect_err("the intent cannot be recorded");
        assert!(
            matches!(refused, EngineError::AuditUnavailable { .. }),
            "{refused}"
        );
    }
    assert!(
        fixture.store.read_ref("main").unwrap().is_none(),
        "nothing was applied"
    );
    let committed = engine
        .commit_push(&commit_request("main", &head, None, transfer_id), &signer)
        .expect("the same transfer commits once the trail is back");
    assert_eq!(committed.counter, 1);
}

/// WP-7.12: a transfer is its caller's. Another caller naming it learns nothing of it, on upload
/// and on commit; the session it names is the one the commit is bound to.
#[test]
fn another_caller_cannot_use_a_transfer() {
    let fixture = Fixture::new("substitution");
    let (objects, head) = build_commit("permit(principal, action, resource);", vec![]);
    let transfer_id = open(&fixture, "main", &head, None, &objects).unwrap();
    let mallory = Engine {
        caller: "mallory".into(),
        ..fixture.engine()
    };
    assert!(matches!(
        mallory.upload(&UploadObjectsRequest {
            transfer_id,
            compression: None,
            objects: objects.clone(),
        }),
        Err(EngineError::Transfer {
            code: "transfer_unknown",
            ..
        })
    ));
    assert!(matches!(
        mallory.commit_push(
            &commit_request("main", &head, None, transfer_id),
            &fixture.signer()
        ),
        Err(EngineError::Transfer {
            code: "transfer_unknown",
            ..
        })
    ));
    // The rightful caller's commit, under another request id, is not the session's.
    let mut other = commit_request("main", &head, None, transfer_id);
    other.request_id = "another".into();
    assert!(matches!(
        fixture.engine().commit_push(&other, &fixture.signer()),
        Err(EngineError::Transfer {
            code: "transfer_mismatch",
            ..
        })
    ));
    assert!(fixture.store.read_ref("main").unwrap().is_none());
}

/// WP-7.12: a session past its expiry is closed before anything it reserved is released, and
/// refuses what names it; a new request opens a new one.
#[test]
fn an_expired_transfer_is_closed_and_releases_its_reservation() {
    let fixture = Fixture::new("expired");
    let (objects, head) = build_commit("permit(principal, action, resource);", vec![]);
    let instant = Engine {
        transfer: TransferPolicy {
            ttl: std::time::Duration::ZERO,
            grace: std::time::Duration::from_secs(3600),
        },
        ..fixture.engine()
    };
    let negotiated = instant
        .negotiate_push(&NegotiatePushRequest {
            request_id: "short".into(),
            r#ref: "main".into(),
            new_head: head.clone(),
            expected_ref: None,
            closure: claims(&objects),
        })
        .unwrap();
    assert!(matches!(
        instant.upload(&UploadObjectsRequest {
            transfer_id: negotiated.transfer_id,
            compression: None,
            objects: objects.clone(),
        }),
        Err(EngineError::Transfer {
            code: "transfer_expired",
            ..
        })
    ));
    let transfers = fixture.store.transfers().unwrap();
    let session = transfers.get(&negotiated.transfer_id).unwrap().unwrap();
    assert_eq!(
        session.state,
        permguard_control_plane::transfer::State::Expired,
        "closed durably"
    );
    assert_eq!(
        transfers.reserved().unwrap(),
        0,
        "its reservation is released"
    );
    assert_eq!(
        transfers.pins().unwrap().len(),
        objects.len(),
        "its pins hold for the grace"
    );
    drop(transfers);
    // The same request again is told the transfer ended.
    assert!(matches!(
        instant.negotiate_push(&NegotiatePushRequest {
            request_id: "short".into(),
            r#ref: "main".into(),
            new_head: head.clone(),
            expected_ref: None,
            closure: claims(&objects),
        }),
        Err(EngineError::Transfer {
            code: "transfer_expired",
            ..
        })
    ));
    // A new request pushes.
    try_commit(&fixture, "main", &head, None, &objects).expect("a new transfer commits");
}

/// WP-7.12: the quota is reserved at negotiation: a push the ledger cannot hold beside what the
/// open transfers reserved is refused before a byte arrives, and an upload cannot land past what
/// its own session reserved.
#[test]
fn the_quota_is_reserved_before_anything_lands() {
    let fixture = Fixture::new("quota");
    let (objects, head) = build_commit("permit(principal, action, resource);", vec![]);
    let declared: u64 = objects.iter().map(|bytes| bytes.len() as u64).sum();
    let tight = Engine {
        limits: EngineLimits {
            ledger_quota_bytes: declared + declared / 2,
            ..limits()
        },
        ..fixture.engine()
    };
    let first = tight
        .negotiate_push(&NegotiatePushRequest {
            request_id: "first".into(),
            r#ref: "main".into(),
            new_head: head.clone(),
            expected_ref: None,
            closure: claims(&objects),
        })
        .unwrap();
    assert_eq!(first.reservation, declared);
    let refused = tight.negotiate_push(&NegotiatePushRequest {
        request_id: "second".into(),
        r#ref: "other".into(),
        new_head: head.clone(),
        expected_ref: None,
        closure: claims(&objects),
    });
    assert!(
        matches!(refused, Err(EngineError::Unavailable { .. })),
        "the first transfer's reservation is held: {refused:?}"
    );

    // A session that declared less than it uploads cannot land past its reservation.
    let understated: Vec<ObjectClaim> = claims(&objects)
        .into_iter()
        .map(|claim| ObjectClaim { size: 1, ..claim })
        .collect();
    let small = fixture
        .engine()
        .negotiate_push(&NegotiatePushRequest {
            request_id: "understated".into(),
            r#ref: "small".into(),
            new_head: head.clone(),
            expected_ref: None,
            closure: understated,
        })
        .unwrap();
    assert!(matches!(
        fixture.engine().upload(&UploadObjectsRequest {
            transfer_id: small.transfer_id,
            compression: None,
            objects: objects.clone(),
        }),
        Err(EngineError::Unavailable { .. })
    ));
}

/// WP-7.12: a batch refused half way keeps what landed before the refusal, and its session
/// counts it; the refused object never lands, its blob checked before it is written.
#[test]
fn a_batch_refused_half_way_counts_what_landed() {
    let fixture = Fixture::new("half-batch");
    let (objects, head) = build_commit("permit(principal, action, resource);", vec![]);
    let alien = Blob {
        media_type: "application/vnd.acme.unknown".into(),
        data: vec![1],
    }
    .encode()
    .unwrap();
    let declared: Vec<Vec<u8>> = objects.iter().cloned().chain([alien.clone()]).collect();
    let transfer_id = open(&fixture, "main", &head, None, &declared).unwrap();
    assert!(
        fixture
            .engine()
            .upload(&UploadObjectsRequest {
                transfer_id,
                compression: None,
                objects: vec![objects[0].clone(), alien.clone()],
            })
            .is_err()
    );
    assert!(fixture.store.has_object(&Digest::compute(&objects[0])));
    assert!(
        !fixture.store.has_object(&Digest::compute(&alien)),
        "a blob its media type refuses never lands"
    );
    let session = fixture
        .store
        .transfers()
        .unwrap()
        .get(&transfer_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        session.landed,
        objects[0].len() as u64,
        "what landed is counted"
    );
}

/// WP-7.12: pulls end as they are fetched, and a round that finds nothing to fetch opens no
/// session, so one caller's rounds never run into a cap however often they come.
#[test]
fn repeated_pull_rounds_are_never_refused() {
    let fixture = Fixture::new("rounds");
    let (objects, head) = build_commit("permit(principal, action, resource);", vec![]);
    push(&fixture, &objects, &head, None);
    let engine = fixture.engine();
    let signer = fixture.signer();
    for round in 0..(permguard_control_plane::transfer::MAX_OPEN_PER_PRINCIPAL * 2) {
        let pulled = engine
            .negotiate_pull(
                &NegotiatePullRequest {
                    checkpoint: None,
                    r#ref: "main".into(),
                    at: None,
                    have: vec![],
                },
                &signer,
            )
            .unwrap_or_else(|error| panic!("round {round}: {error}"));
        engine
            .fetch(&FetchObjectsRequest {
                transfer_id: pulled.transfer_id,
                accept_compression: None,
                digests: pulled.missing.clone(),
            })
            .unwrap_or_else(|error| panic!("round {round}: {error}"));
        // Fetched whole, the session is gone: its id names nothing more.
        assert!(matches!(
            engine.fetch(&FetchObjectsRequest {
                transfer_id: pulled.transfer_id,
                accept_compression: None,
                digests: pulled.missing,
            }),
            Err(EngineError::Transfer {
                code: "transfer_unknown",
                ..
            })
        ));
        // A current mirror opens nothing.
        let current = engine
            .negotiate_pull(
                &NegotiatePullRequest {
                    checkpoint: None,
                    r#ref: "main".into(),
                    at: None,
                    have: vec![head.clone()],
                },
                &signer,
            )
            .unwrap();
        assert!(current.missing.is_empty());
    }
    let kept = fixture.store.transfers().unwrap().list().unwrap();
    assert!(
        kept.iter()
            .all(|session| session.direction == permguard_control_plane::transfer::Direction::Push),
        "no pull session outlives its fetch"
    );
}

/// WP-7.12: the same request id with other parameters is another push, refused; the session is
/// a push's, and a fetch naming it is told so; a fetch asks only what its negotiation answered.
#[test]
fn a_session_is_bound_to_its_request_and_direction() {
    let fixture = Fixture::new("bound");
    let (objects, head) = build_commit("permit(principal, action, resource);", vec![]);
    let engine = fixture.engine();
    let transfer_id = open(&fixture, "main", &head, None, &objects).unwrap();
    assert!(matches!(
        engine.negotiate_push(&NegotiatePushRequest {
            request_id: request_of("main", &head),
            r#ref: "main".into(),
            new_head: head.clone(),
            expected_ref: None,
            closure: claims(&objects[..1]),
        }),
        Err(EngineError::Transfer {
            code: "transfer_mismatch",
            ..
        })
    ));
    assert!(matches!(
        engine.fetch(&FetchObjectsRequest {
            transfer_id,
            accept_compression: None,
            digests: Vec::new(),
        }),
        Err(EngineError::Transfer {
            code: "transfer_mismatch",
            ..
        })
    ));

    push(&fixture, &objects, &head, None);
    let pulled = engine
        .negotiate_pull(
            &NegotiatePullRequest {
                checkpoint: None,
                r#ref: "main".into(),
                at: None,
                have: vec![],
            },
            &fixture.signer(),
        )
        .unwrap();
    assert!(matches!(
        engine.fetch(&FetchObjectsRequest {
            transfer_id: pulled.transfer_id,
            accept_compression: None,
            digests: vec![Digest::compute(b"never answered")],
        }),
        Err(EngineError::Transfer {
            code: "transfer_mismatch",
            ..
        })
    ));
}

/// WP-7.12: a commit refused for what its session is bound to ends the session, which releases
/// its reservation; the same commit again is told the transfer ended.
#[test]
fn a_refused_commit_aborts_its_transfer() {
    let fixture = Fixture::new("aborted");
    let (objects, head) = build_commit("permit(principal, action, resource);", vec![]);
    push(&fixture, &objects, &head, None);
    let (objects2, head2) = build_commit("forbid(principal, action, resource);", vec![]);
    // A transfer that creates `other`, opened while `other` does not exist yet.
    let transfer_id = open(&fixture, "other", &head2, None, &objects2).unwrap();
    let engine = fixture.engine();
    engine
        .upload(&UploadObjectsRequest {
            transfer_id,
            compression: None,
            objects: objects2.clone(),
        })
        .unwrap();
    // Another commit took `other` meanwhile.
    try_commit(&fixture, "other", &head, None, &[]).unwrap();
    let refused = engine
        .commit_push(
            &commit_request("other", &head2, None, transfer_id),
            &fixture.signer(),
        )
        .expect_err("the ref exists now");
    assert!(matches!(refused, EngineError::Conflict { .. }), "{refused}");
    let transfers = fixture.store.transfers().unwrap();
    let session = transfers.get(&transfer_id).unwrap().unwrap();
    assert_eq!(
        session.state,
        permguard_control_plane::transfer::State::Aborted
    );
    assert_eq!(transfers.reserved().unwrap(), 0);
    drop(transfers);
    assert!(matches!(
        engine.commit_push(
            &commit_request("other", &head2, None, transfer_id),
            &fixture.signer()
        ),
        Err(EngineError::Transfer {
            code: "transfer_expired",
            ..
        })
    ));
}

/// WP-7.12: one caller keeps a bounded number of pushes open on a ledger; another caller is not
/// held back by it.
#[test]
fn a_caller_keeps_a_bounded_number_of_pushes_open() {
    use permguard_control_plane::transfer::MAX_OPEN_PER_PRINCIPAL;

    let fixture = Fixture::new("cap");
    let (objects, head) = build_commit("permit(principal, action, resource);", vec![]);
    let engine = fixture.engine();
    let negotiate = |engine: &Engine<'_>, at: usize| {
        engine.negotiate_push(&NegotiatePushRequest {
            request_id: format!("push-{at}"),
            r#ref: "main".into(),
            new_head: head.clone(),
            expected_ref: None,
            closure: claims(&objects[..1]),
        })
    };
    for at in 0..MAX_OPEN_PER_PRINCIPAL {
        negotiate(&engine, at).unwrap();
    }
    assert!(matches!(
        negotiate(&engine, MAX_OPEN_PER_PRINCIPAL),
        Err(EngineError::Unavailable { .. })
    ));
    let other = Engine {
        caller: "another".into(),
        ..fixture.engine()
    };
    negotiate(&other, 0).expect("another caller opens its own");
}

/// WP-7.12: the ledger's bound holds at upload as well, on what it holds now: a quota lowered
/// after a transfer reserved refuses what would pass it.
#[test]
fn an_upload_past_the_ledger_quota_is_refused() {
    let fixture = Fixture::new("lowered");
    let (objects, head) = build_commit("permit(principal, action, resource);", vec![]);
    let transfer_id = open(&fixture, "main", &head, None, &objects).unwrap();
    let lowered = Engine {
        limits: EngineLimits {
            ledger_quota_bytes: 1,
            ..limits()
        },
        ..fixture.engine()
    };
    assert!(matches!(
        lowered.upload(&UploadObjectsRequest {
            transfer_id,
            compression: None,
            objects: objects.clone(),
        }),
        Err(EngineError::Unavailable { .. })
    ));
    assert!(!fixture.store.has_object(&Digest::compute(&objects[0])));
}
