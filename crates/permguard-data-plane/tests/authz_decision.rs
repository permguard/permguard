// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Decisions, end to end: a real mirror on a real volume, read by the real
//! decision path, over the real HTTP surface.
//!
//! Nothing here is a stand-in. The ledger is built out of the same objects a
//! `permguard apply` pushes — blobs, trees, a manifest, a commit, a
//! checkpoint — because the thing worth testing is precisely that a PDP can
//! turn *that* into an answer. A fake snapshot would test the test.
//!
//! What is asserted is the contract a PEP depends on:
//!
//! | | |
//! | --- | --- |
//! | a permit is a permit, and cites the policy that decided it | |
//! | a deny is a `200`, never an error | |
//! | a payload with no `zone`/`ledger` is a `400` | |
//! | a ledger this plane does not mirror is a `404` | |
//! | a ledger this engine may not serve is a `503`, and is blocked afterwards | |
//! | boxcarring, and its three semantics | |
//! | both languages answer the same contract | |

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use tower::ServiceExt as _;

use permguard_control_client::objects;
use permguard_control_client::store::FsStore;
use permguard_core::{Disclosure, Metrics};
use permguard_data_plane::authz::cache::Cache;
use permguard_data_plane::authz::decide::{Decider, Warmed};
use permguard_data_plane::authz::store::{Identity, Mirror};
use permguard_data_plane::authz::{block, http, wire};
use permguard_data_plane::decisions::journal::{Epoch, Journal, WhenFull};
use permguard_decisions::spool::Bounds;
use permguard_languages::registry;
use permguard_objects::manifest::{
    InputContract, Manifest, Partition, Profile, Requirement, Runtime,
};
use permguard_objects::object::{Blob, Commit, Kind, Tree, TreeEntry};
use permguard_objects::policy_id::{ANNOTATION_POLICY_ID, ANNOTATION_POLICY_KIND};
use permguard_objects::semver::Constraint;

/// One policy, as an author wrote it and the store keeps it.
struct Policy {
    id: &'static str,
    media_type: &'static str,
    source: &'static str,
}

const CEDAR_READ: Policy = Policy {
    id: "01a0-cedar-read",
    media_type: registry::MEDIA_TYPE_POLICY_CEDAR,
    source: r#"permit (principal, action == Action::"read", resource);"#,
};

/// Permits only through the group the request's entity store carries — so having that store or
/// not is the difference between permit and deny.
const CEDAR_GROUP: Policy = Policy {
    id: "01a0-cedar-group",
    media_type: registry::MEDIA_TYPE_POLICY_CEDAR,
    source: r#"permit (principal in Group::"finance", action == Action::"read", resource);"#,
};

const CEDAR_NOT_BOB: Policy = Policy {
    id: "01a0-cedar-not-bob",
    media_type: registry::MEDIA_TYPE_POLICY_CEDAR,
    source: r#"forbid (principal == user::"bob", action, resource);"#,
};

const REGO_READ: Policy = Policy {
    id: "01a0-rego-read",
    media_type: registry::MEDIA_TYPE_POLICY_REGO,
    source: "package gateway\n\nimport rego.v1\n\ndefault allow := false\n\nallow if {\n    input.action.name == \"list\"\n}\n",
};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pg-authz-e2e-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory is created");

    dir
}

/// The manifest of a ledger that declares these partitions, in these
/// languages, under the given engine range.
fn manifest(partitions: &[(&str, &str, bool)], engine_range: &str) -> Manifest {
    let mut runtimes = BTreeMap::new();
    let mut declared = BTreeMap::new();
    for (name, language, schema) in partitions {
        runtimes.insert(
            (*language).to_owned(),
            Runtime {
                language: Requirement {
                    name: (*language).to_owned(),
                    constraint: Constraint::parse(">=1.0.0").expect("a constraint"),
                },
                engine: Requirement {
                    name: registry::ENGINE_NAME.to_owned(),
                    constraint: Constraint::parse(engine_range).expect("a constraint"),
                },
            },
        );
        let media_types = match *language {
            "cedar" => vec![
                registry::MEDIA_TYPE_POLICY_CEDAR.to_owned(),
                registry::MEDIA_TYPE_SCHEMA_CEDAR.to_owned(),
            ],
            _ => vec![registry::MEDIA_TYPE_POLICY_REGO.to_owned()],
        };
        declared.insert(
            (*name).to_owned(),
            Partition {
                runtime: (*language).to_owned(),
                media_types,
                schema: *schema,
                // Every test partition accepts its runtime's own input, optionally: the tests
                // that address one need it declared, and the tests that do not are unaffected —
                // an optional input nobody sends is an empty one.
                input: Some(InputContract {
                    r#type: match *language {
                        "cedar" => permguard_languages::input::CEDAR_ENTITIES_V1,
                        _ => permguard_languages::input::REGO_DATA_V1,
                    }
                    .to_owned(),
                    required: false,
                }),
            },
        );
    }
    let mut profiles = BTreeMap::new();
    profiles.insert(
        "default".to_owned(),
        Profile {
            r#type: "permguard.pdp.v1".to_owned(),
            partitions: declared.keys().cloned().collect(),
        },
    );

    Manifest {
        kind: "policy".to_owned(),
        name: "e2e".to_owned(),
        description: "a ledger built by the decision tests".to_owned(),
        author: "Nitro Agility S.r.l.".to_owned(),
        license: "Apache-2.0".to_owned(),
        runtimes,
        partitions: declared,
        profiles,
    }
}

/// Writes a mirror the way a synchronization round leaves one: the objects,
/// the verified checkpoint, and the identity file that says what it is called.
fn provision(
    root: &Path,
    zone: &str,
    ledger: &str,
    manifest: &Manifest,
    contents: &[(&str, Vec<&Policy>, Option<&str>)],
) -> Mirror {
    let path = root.join(format!("{zone}-id")).join(format!("{ledger}-id"));
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

    let manifest_digest = put_blob(permguard_objects::manifest::MEDIA_TYPE, &manifest.encode());

    let mut root_entries = Vec::new();
    for (partition, policies, schema) in contents {
        let mut entries = Vec::new();
        for policy in policies {
            let digest = put_blob(policy.media_type, policy.source.as_bytes());
            let mut annotations = BTreeMap::new();
            annotations.insert(ANNOTATION_POLICY_ID.to_owned(), policy.id.to_owned());
            annotations.insert(ANNOTATION_POLICY_KIND.to_owned(), "policy".to_owned());
            entries.push(TreeEntry {
                kind: Kind::Blob,
                digest,
                name: format!("{}.policy", policy.id),
                annotations,
            });
        }
        if let Some(schema) = schema {
            let digest = put_blob(registry::MEDIA_TYPE_SCHEMA_CEDAR, schema.as_bytes());
            entries.push(TreeEntry {
                kind: Kind::Blob,
                digest,
                name: "schema.cedarschema".to_owned(),
                annotations: BTreeMap::new(),
            });
        }
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        let tree = Tree { entries };
        let bytes = tree.encode().expect("the tree encodes");
        let digest = objects::put(&store, "objects", &bytes).expect("the tree is stored");
        root_entries.push(TreeEntry {
            kind: Kind::Tree,
            digest,
            name: (*partition).to_owned(),
            annotations: BTreeMap::new(),
        });
    }
    root_entries.sort_by(|left, right| left.name.cmp(&right.name));
    let root_tree = Tree {
        entries: root_entries,
    };
    let root_bytes = root_tree.encode().expect("the root tree encodes");
    let root_digest = objects::put(&store, "objects", &root_bytes).expect("the tree is stored");

    let commit = Commit {
        tree: root_digest,
        manifest: manifest_digest,
        predecessors: Vec::new(),
        author: "tests".to_owned(),
        author_at: 1_700_000_000,
        message: "the ledger these tests decide against".to_owned(),
    };
    let commit_bytes = commit.encode().expect("the commit encodes");
    let commit_digest = objects::put(&store, "objects", &commit_bytes).expect("stored");

    permguard_control_client::checkpoint::write(
        &store,
        "refs/main",
        &permguard_control_client::checkpoint::Checkpoint {
            head: commit_digest.to_string(),
            counter: 1,
        },
    )
    .expect("the checkpoint is written");

    let identity = Identity {
        zone_id: format!("{zone}-id"),
        zone_name: zone.to_owned(),
        ledger_id: format!("{ledger}-id"),
        ledger_name: ledger.to_owned(),
        server: "http://127.0.0.1:7556".to_owned(),
    };
    permguard_data_plane::authz::store::record(&path, &identity).expect("the identity is recorded");

    Mirror { path, identity }
}

fn decider(root: &Path) -> Arc<Decider> {
    Arc::new(Decider::new(
        root.to_path_buf(),
        Arc::new(Cache::new(64, 8 * 1024 * 1024)),
        Metrics::none(),
        None,
        256,
    ))
}

fn decider_with_journal(root: &Path, journal: Journal) -> Arc<Decider> {
    Arc::new(
        Decider::new(
            root.to_path_buf(),
            Arc::new(Cache::new(64, 8 * 1024 * 1024)),
            Metrics::none(),
            None,
            256,
        )
        .with_journal(
            Some(Arc::new(journal)),
            None,
            permguard_core::decisions::IncludeSection::default(),
        ),
    )
}

fn journal_with_blocked_next_segment(tag: &str, when_full: WhenFull) -> Journal {
    let spool = scratch(tag);
    let journal = Journal::open(
        &spool,
        "plane",
        Epoch {
            version: "0.1.0".to_owned(),
            build: None,
            engines: BTreeMap::new(),
            sampling: "1.0".to_owned(),
        },
        when_full,
        Bounds {
            bytes: 64 * 1024 * 1024,
            age: std::time::Duration::from_secs(3600),
            segment_bytes: 1,
        },
        permguard_decisions::Commitment::new(*b"a-key-of-at-least-32-bytes-long!!", "v1"),
        Metrics::none(),
    )
    .expect("the journal opens");

    std::fs::create_dir(spool.join("seg-00000000000000000002.jsonl"))
        .expect("the next segment path is made unwritable as a file");

    journal
}

fn ask(zone: &str, ledger: &str, subject: &str, action: &str) -> wire::CheckRequest {
    serde_json::from_value(json!({
        "zone": zone,
        "ledger": ledger,
        "subject": {"type": "user", "id": subject},
        "resource": {"type": "document", "id": "budget"},
        "action": {"name": action},
    }))
    .expect("the payload parses")
}

#[tokio::test]
async fn a_permit_is_a_permit_and_cites_the_policy_that_decided_it() {
    let root = scratch("permit").join("mirrors");
    let manifest = manifest(&[("app", "cedar", false)], ">=0.0.0");
    provision(
        &root,
        "acme",
        "main-ledger",
        &manifest,
        &[("app", vec![&CEDAR_READ, &CEDAR_NOT_BOB], None)],
    );
    let decider = decider(&root);

    let answer = decider
        .decide(&ask("acme", "main-ledger", "alice", "read"), None)
        .await
        .expect("the ledger is served");

    assert!(answer.decision, "the policy permits reading");
    let context = answer.context.expect("a decision carries its context");
    assert_eq!(context.policies, vec![CEDAR_READ.id.to_owned()]);
    assert!(context.id.is_some(), "and its own identifier");
    assert!(
        context
            .reason_admin
            .expect("an operator reason")
            .message
            .contains(CEDAR_READ.id),
        "the reason names what decided it"
    );
}

#[tokio::test]
async fn a_forbid_denies_and_the_deny_is_an_answer() {
    let root = scratch("forbid").join("mirrors");
    let manifest = manifest(&[("app", "cedar", false)], ">=0.0.0");
    provision(
        &root,
        "acme",
        "main-ledger",
        &manifest,
        &[("app", vec![&CEDAR_READ, &CEDAR_NOT_BOB], None)],
    );
    let decider = decider(&root);

    let answer = decider
        .decide(&ask("acme", "main-ledger", "bob", "read"), None)
        .await
        .expect("a deny is an answer, not a refusal");

    assert!(!answer.decision);
    let context = answer.context.expect("a context");
    assert_eq!(context.policies, vec![CEDAR_NOT_BOB.id.to_owned()]);
    assert_eq!(
        context.reason_user.expect("a caller reason").code,
        "403",
        "the safe half says only what a caller may know"
    );
}

#[tokio::test]
async fn nothing_permitted_is_a_deny_with_no_policy_to_cite() {
    let root = scratch("silence").join("mirrors");
    let manifest = manifest(&[("app", "cedar", false)], ">=0.0.0");
    provision(
        &root,
        "acme",
        "main-ledger",
        &manifest,
        &[("app", vec![&CEDAR_READ], None)],
    );
    let decider = decider(&root);

    let answer = decider
        .decide(&ask("acme", "main-ledger", "alice", "delete"), None)
        .await
        .expect("answered");

    assert!(!answer.decision);
    let context = answer.context.expect("a context");
    assert!(context.policies.is_empty());
    assert!(
        context
            .reason_admin
            .expect("a reason")
            .message
            .contains("no policy permits"),
        "absent means no, and the reason says so"
    );
}

#[tokio::test]
async fn two_languages_answer_one_contract() {
    let root = scratch("both").join("mirrors");
    let manifest = manifest(
        &[("app", "cedar", false), ("gateway", "rego", false)],
        ">=0.0.0",
    );
    provision(
        &root,
        "acme",
        "main-ledger",
        &manifest,
        &[
            ("app", vec![&CEDAR_READ], None),
            ("gateway", vec![&REGO_READ], None),
        ],
    );
    let decider = decider(&root);

    // Cedar's partition permits `read`; Rego's permits `list`. A caller cannot
    // tell which answered — the profile is the same either way.
    assert!(
        decider
            .decide(&ask("acme", "main-ledger", "alice", "read"), None)
            .await
            .expect("answered")
            .decision
    );
    assert!(
        decider
            .decide(&ask("acme", "main-ledger", "alice", "list"), None)
            .await
            .expect("answered")
            .decision
    );
    assert!(
        !decider
            .decide(&ask("acme", "main-ledger", "alice", "delete"), None)
            .await
            .expect("answered")
            .decision
    );
}

#[tokio::test]
async fn boxcarring_resolves_by_the_semantic_the_caller_asked_for() {
    let root = scratch("boxcar").join("mirrors");
    let manifest = manifest(&[("app", "cedar", false)], ">=0.0.0");
    provision(
        &root,
        "acme",
        "main-ledger",
        &manifest,
        &[("app", vec![&CEDAR_READ], None)],
    );
    let decider = decider(&root);

    let batch = |semantic: &str| -> wire::CheckRequest {
        serde_json::from_value(json!({
            "zone": "acme", "ledger": "main-ledger",
            "subject": {"type": "user", "id": "alice"},
            "resource": {"type": "document", "id": "budget"},
            "options": {"evaluations_semantic": semantic},
            "evaluations": [
                {"action": {"name": "read"}, "request_id": "one"},
                {"action": {"name": "delete"}, "request_id": "two"},
                {"action": {"name": "read"}, "request_id": "three"}
            ]
        }))
        .expect("the payload parses")
    };

    let all = decider
        .decide(&batch("execute_all"), None)
        .await
        .expect("answered");
    let evaluations = all.evaluations.expect("a batch answers a batch");
    assert_eq!(evaluations.len(), 3, "every one is answered, in order");
    assert!(evaluations[0].decision);
    assert!(!evaluations[1].decision);
    assert!(evaluations[2].decision);
    assert!(!all.decision, "the batch as a whole is the conjunction");
    assert_eq!(evaluations[0].request_id.as_deref(), Some("one"));

    let stop_on_deny = decider
        .decide(&batch("deny_on_first_deny"), None)
        .await
        .expect("answered");
    assert!(
        !stop_on_deny.decision,
        "`&&` of a batch that reached a deny is a deny"
    );
    assert_eq!(
        stop_on_deny
            .evaluations
            .as_ref()
            .expect("evaluations")
            .len(),
        2,
        "it stops at the first deny"
    );

    let stop_on_permit = decider
        .decide(&batch("permit_on_first_permit"), None)
        .await
        .expect("answered");
    assert!(
        stop_on_permit.decision,
        "`||` of a batch that reached a permit is a permit"
    );
    assert_eq!(
        stop_on_permit
            .evaluations
            .as_ref()
            .expect("evaluations")
            .len(),
        1,
        "and at the first permit"
    );
}

/// The batch's verdict is the operator its semantic names, and `||` is not `&&`.
///
/// This is the case the test above cannot reach: its batch opens with a permit, so
/// `permit_on_first_permit` stops immediately and the conjunction of one permit is a permit by
/// accident. Open with a **deny** and the two operators disagree — which is the whole difference
/// between them, and was answered as a conjunction for both.
#[tokio::test]
async fn a_batch_that_opens_with_a_deny_resolves_by_its_own_operator() {
    let root = scratch("boxcar-or").join("mirrors");
    let manifest = manifest(&[("app", "cedar", false)], ">=0.0.0");
    provision(
        &root,
        "acme",
        "main-ledger",
        &manifest,
        &[("app", vec![&CEDAR_READ], None)],
    );
    let decider = decider(&root);

    // `delete` is permitted by nothing, `read` by the policy: a deny and then a permit.
    let batch = |semantic: &str| -> wire::CheckRequest {
        serde_json::from_value(json!({
            "zone": "acme", "ledger": "main-ledger",
            "subject": {"type": "user", "id": "alice"},
            "resource": {"type": "document", "id": "budget"},
            "options": {"evaluations_semantic": semantic},
            "evaluations": [
                {"action": {"name": "delete"}, "request_id": "first"},
                {"action": {"name": "read"}, "request_id": "second"}
            ]
        }))
        .expect("the payload parses")
    };

    let disjunction = decider
        .decide(&batch("permit_on_first_permit"), None)
        .await
        .expect("answered");
    let evaluations = disjunction
        .evaluations
        .as_ref()
        .expect("a batch answers a batch");
    assert_eq!(evaluations.len(), 2, "it runs on until a permit");
    assert!(!evaluations[0].decision && evaluations[1].decision);
    assert!(
        disjunction.decision,
        "`[deny, permit]` under `||` is a permit — this answered `deny` before"
    );

    let conjunction = decider
        .decide(&batch("deny_on_first_deny"), None)
        .await
        .expect("answered");
    assert_eq!(
        conjunction.evaluations.as_ref().expect("evaluations").len(),
        1,
        "`&&` stops on the deny it opened with"
    );
    assert!(!conjunction.decision, "and answers deny");

    let all = decider
        .decide(&batch("execute_all"), None)
        .await
        .expect("answered");
    assert_eq!(all.evaluations.as_ref().expect("evaluations").len(), 2);
    assert!(
        !all.decision,
        "`execute_all` is the conjunction, as documented"
    );
}

#[tokio::test]
async fn a_schema_is_enforced_at_load_and_a_request_outside_it_is_refused() {
    let root = scratch("schema").join("mirrors");
    let manifest = manifest(&[("app", "cedar", true)], ">=0.0.0");
    let schema = "entity user;\nentity document;\naction read appliesTo { principal: [user], resource: [document] };\n";
    provision(
        &root,
        "acme",
        "main-ledger",
        &manifest,
        &[("app", vec![&CEDAR_READ], Some(schema))],
    );
    let decider = decider(&root);

    assert!(
        decider
            .decide(&ask("acme", "main-ledger", "alice", "read"), None)
            .await
            .expect("the policies satisfy the schema")
            .decision
    );

    // An action the schema never declared cannot be evaluated. Fail-closed:
    // a deny, with the reason on the operator's side of the context.
    let answer = decider
        .decide(&ask("acme", "main-ledger", "alice", "teleport"), None)
        .await
        .expect("answered");
    assert!(!answer.decision);
    assert!(
        answer
            .context
            .expect("a context")
            .reason_admin
            .expect("a reason")
            .message
            .contains("could not be evaluated"),
        "the reason says the request was refused, not that a policy said no"
    );
}

#[tokio::test]
async fn an_engine_outside_the_manifests_range_refuses_and_stays_refused() {
    let root = scratch("gate").join("mirrors");
    // A range no build of this engine can satisfy.
    let manifest = manifest(&[("app", "cedar", false)], ">=99.0.0");
    let mirror = provision(
        &root,
        "acme",
        "main-ledger",
        &manifest,
        &[("app", vec![&CEDAR_READ], None)],
    );
    let decider = decider(&root);

    let refused = decider
        .decide(&ask("acme", "main-ledger", "alice", "read"), None)
        .await
        .expect_err("the load gate refuses");
    assert_eq!(refused.code(), "ledger_incompatible");

    // And it is written down, so the next round does not rediscover it.
    let block = block::read(&mirror.path).expect("the refusal is remembered");
    assert!(block.reason.contains("engine"), "{}", block.reason);

    // Warming the same commit is a file read, not a compile.
    assert!(matches!(decider.warm(&mirror), Warmed::Blocked(_)));
}

#[tokio::test]
async fn a_head_this_engine_cannot_serve_refuses_instead_of_answering_from_the_old_commit() {
    let root = scratch("no-fallback").join("mirrors");
    let mirror = provision(
        &root,
        "acme",
        "main-ledger",
        &manifest(&[("app", "cedar", false)], ">=0.0.0"),
        &[("app", vec![&CEDAR_READ], None)],
    );
    let decider = decider(&root);

    // Serving, and compiled: the old commit is in memory from here on.
    let answer = decider
        .decide(&ask("acme", "main-ledger", "alice", "read"), None)
        .await
        .expect("the ledger serves");
    assert!(answer.decision, "the policy permits at this commit");

    // The operator applies a newer commit this engine may not serve.
    provision(
        &root,
        "acme",
        "main-ledger",
        &manifest(&[("app", "cedar", false)], ">=99.0.0"),
        &[("app", vec![&CEDAR_READ], None)],
    );

    let refused = decider
        .decide(&ask("acme", "main-ledger", "alice", "read"), None)
        .await
        .expect_err("a head that cannot be served is refused");
    assert_eq!(
        refused.code(),
        "ledger_incompatible",
        "the superseded commit is still compiled in memory, and is deliberately not answered from"
    );
    assert!(matches!(decider.warm(&mirror), Warmed::Blocked(_)));
}

#[tokio::test]
async fn a_plane_that_may_not_decide_unrecorded_refuses_instead_of_answering() {
    let root = scratch("unrecordable").join("mirrors");
    provision(
        &root,
        "acme",
        "main-ledger",
        &manifest(&[("app", "cedar", false)], ">=0.0.0"),
        &[("app", vec![&CEDAR_READ], None)],
    );
    // A spool with no room at all, and a plane told to refuse rather than
    // decide unrecorded.
    let journal = Journal::open(
        scratch("unrecordable-spool"),
        "plane",
        Epoch {
            version: "0.1.0".to_owned(),
            build: None,
            engines: std::collections::BTreeMap::new(),
            sampling: "1.0".to_owned(),
        },
        WhenFull::Closed,
        Bounds {
            bytes: 1,
            age: std::time::Duration::from_secs(3600),
            segment_bytes: 512,
        },
        permguard_decisions::Commitment::new(*b"a-key-of-at-least-32-bytes-long!!", "v1"),
        Metrics::none(),
    )
    .expect("the journal opens");

    let decider = decider_with_journal(&root, journal);

    let refused = decider
        .decide(&ask("acme", "main-ledger", "alice", "read"), None)
        .await
        .expect_err("a decision it cannot record is not answered");

    assert_eq!(refused.code(), "decision_unrecordable");
    assert!(
        refused.to_string().contains("refuse rather than decide"),
        "{refused}"
    );
}

#[tokio::test]
async fn a_closed_journal_refuses_runtime_write_errors() {
    let root = scratch("closed-runtime-journal-error").join("mirrors");
    provision(
        &root,
        "acme",
        "main-ledger",
        &manifest(&[("app", "cedar", false)], ">=0.0.0"),
        &[("app", vec![&CEDAR_READ], None)],
    );
    let decider = decider_with_journal(
        &root,
        journal_with_blocked_next_segment("closed-runtime-journal-spool", WhenFull::Closed),
    );

    let refused = decider
        .decide(&ask("acme", "main-ledger", "alice", "read"), None)
        .await
        .expect_err("a decision it cannot record is not answered");

    assert_eq!(refused.code(), "decision_unrecordable");
    assert!(
        refused.to_string().contains("refuse rather than decide"),
        "{refused}"
    );
}

#[tokio::test]
async fn an_open_journal_keeps_answering_runtime_write_errors() {
    let root = scratch("open-runtime-journal-error").join("mirrors");
    provision(
        &root,
        "acme",
        "main-ledger",
        &manifest(&[("app", "cedar", false)], ">=0.0.0"),
        &[("app", vec![&CEDAR_READ], None)],
    );
    let decider = decider_with_journal(
        &root,
        journal_with_blocked_next_segment("open-runtime-journal-spool", WhenFull::Open),
    );

    let answer = decider
        .decide(&ask("acme", "main-ledger", "alice", "read"), None)
        .await
        .expect("open mode reports the journal incident and still answers");

    assert!(answer.decision, "the policy still permits reading");
}

#[tokio::test]
async fn a_ledger_this_plane_does_not_mirror_is_not_found() {
    let root = scratch("absent").join("mirrors");
    std::fs::create_dir_all(&root).expect("the root exists");
    let decider = decider(&root);

    let refused = decider
        .decide(&ask("acme", "main-ledger", "alice", "read"), None)
        .await
        .expect_err("nothing is mirrored");

    assert_eq!(refused.code(), "ledger_not_served");
}

#[tokio::test]
async fn a_ledger_with_no_history_is_unavailable_not_a_deny() {
    let root = scratch("empty").join("mirrors");
    let path = root.join("acme-id").join("main-ledger-id");
    std::fs::create_dir_all(&path).expect("the directory exists");
    permguard_data_plane::authz::store::record(
        &path,
        &Identity {
            zone_id: "acme-id".to_owned(),
            zone_name: "acme".to_owned(),
            ledger_id: "main-ledger-id".to_owned(),
            ledger_name: "main-ledger".to_owned(),
            server: "http://127.0.0.1:7556".to_owned(),
        },
    )
    .expect("the identity is recorded");
    let decider = decider(&root);

    let refused = decider
        .decide(&ask("acme", "main-ledger", "alice", "read"), None)
        .await
        .expect_err("there is nothing to decide with");

    assert_eq!(refused.code(), "ledger_empty");
}

#[tokio::test]
async fn warming_compiles_every_partition_and_a_second_pass_compiles_nothing() {
    let root = scratch("warm").join("mirrors");
    let manifest = manifest(
        &[("app", "cedar", false), ("gateway", "rego", false)],
        ">=0.0.0",
    );
    let mirror = provision(
        &root,
        "acme",
        "main-ledger",
        &manifest,
        &[
            ("app", vec![&CEDAR_READ], None),
            ("gateway", vec![&REGO_READ], None),
        ],
    );
    let decider = decider(&root);

    assert_eq!(decider.warm(&mirror), Warmed::Ready { compiled: 2 });
    assert_eq!(
        decider.warm(&mirror),
        Warmed::Ready { compiled: 0 },
        "the second pass finds both in memory"
    );
    let (entries, bytes) = decider.cache().holdings();
    assert_eq!(entries, 2);
    assert!(bytes > 0, "and the accounting knows what they weigh");
}

/// The HTTP surface, over the real router.
mod surface {
    use super::*;

    fn router(root: &Path) -> axum::Router {
        http::routes(http::Surface {
            decider: decider(root),
            disclosure: Disclosure::Full,
            base_url: "http://127.0.0.1:7656".to_owned(),
        })
    }

    pub(crate) async fn post(
        root: &Path,
        path: &str,
        body: Value,
    ) -> (StatusCode, Value, Option<String>) {
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header("x-request-id", "correlate-me")
            .body(Body::from(body.to_string()))
            .expect("the request builds");
        let response = router(root)
            .oneshot(request)
            .await
            .expect("the router answers");
        let status = response.status();
        let request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("the body reads")
            .to_bytes();

        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            request_id,
        )
    }

    #[tokio::test]
    async fn a_decision_is_a_200_and_echoes_the_request_id() {
        let root = scratch("http-ok").join("mirrors");
        let manifest = manifest(&[("app", "cedar", false)], ">=0.0.0");
        provision(
            &root,
            "acme",
            "main-ledger",
            &manifest,
            &[("app", vec![&CEDAR_READ, &CEDAR_NOT_BOB], None)],
        );

        let (status, body, request_id) = post(
            &root,
            "/access/v1/evaluation",
            json!({
                "zone": "acme", "ledger": "main-ledger",
                "subject": {"type": "user", "id": "alice"},
                "resource": {"type": "document", "id": "budget"},
                "action": {"name": "read"}
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["decision"], json!(true));
        assert_eq!(request_id.as_deref(), Some("correlate-me"));

        // A deny is the same 200 with a different answer.
        let (status, body, _) = post(
            &root,
            "/access/v1/evaluation",
            json!({
                "zone": "acme", "ledger": "main-ledger",
                "subject": {"type": "user", "id": "bob"},
                "resource": {"type": "document", "id": "budget"},
                "action": {"name": "read"}
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "a deny is not an error");
        assert_eq!(body["decision"], json!(false));
    }

    #[tokio::test]
    async fn a_payload_that_names_no_store_is_a_400_naming_what_is_missing() {
        let root = scratch("http-400").join("mirrors");
        std::fs::create_dir_all(&root).expect("the root exists");

        let (status, body, _) = post(
            &root,
            "/access/v1/evaluation",
            json!({"subject": {"type": "user", "id": "alice"}}),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], json!("zone_required"));
    }

    #[tokio::test]
    async fn a_ledger_this_plane_does_not_serve_is_a_404() {
        let root = scratch("http-404").join("mirrors");
        std::fs::create_dir_all(&root).expect("the root exists");

        let (status, body, _) = post(
            &root,
            "/access/v1/evaluation",
            json!({
                "zone": "acme", "ledger": "nope",
                "subject": {"type": "user", "id": "alice"},
                "resource": {"type": "document", "id": "budget"},
                "action": {"name": "read"}
            }),
        )
        .await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["code"], json!("ledger_not_served"));
    }

    #[tokio::test]
    async fn an_unserveable_ledger_is_a_503_which_is_not_a_deny() {
        let root = scratch("http-503").join("mirrors");
        let manifest = manifest(&[("app", "cedar", false)], ">=99.0.0");
        provision(
            &root,
            "acme",
            "main-ledger",
            &manifest,
            &[("app", vec![&CEDAR_READ], None)],
        );

        let (status, body, _) = post(
            &root,
            "/access/v1/evaluation",
            json!({
                "zone": "acme", "ledger": "main-ledger",
                "subject": {"type": "user", "id": "alice"},
                "resource": {"type": "document", "id": "budget"},
                "action": {"name": "read"}
            }),
        )
        .await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["code"], json!("ledger_incompatible"));
    }

    /// One helper for both discovery documents, so the two tests below differ only in the path.
    async fn fetch(root: &Path, path: &str) -> (StatusCode, Value) {
        let request = Request::builder()
            .uri(path)
            .body(Body::empty())
            .expect("the request builds");
        let response = router(root)
            .oneshot(request)
            .await
            .expect("the router answers");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("the body reads")
            .to_bytes();

        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// The interface names itself, the endpoints it advertises are the ones mounted, and it is
    /// published at **exactly one** path.
    ///
    /// The last clause is the one worth stating carefully. Asserting that some particular foreign
    /// path answers `404` proves nothing on its own: every path this surface does not mount
    /// answers `404`, so such a test passes for a reason that has nothing to do with the name in
    /// it. What actually matters is narrower and stronger — a caller must not be able to find this
    /// document under a second name, because the moment two paths serve it, one of them becomes a
    /// compatibility surface somebody has to keep honest.
    ///
    /// So the assertion is a count: of every path a reasonable person might reach for, exactly one
    /// answers, and it is the interface's own constant.
    #[tokio::test]
    async fn the_configuration_is_published_at_exactly_one_path_and_describes_this_interface() {
        let root = scratch("http-config").join("mirrors");
        std::fs::create_dir_all(&root).expect("the root exists");

        let declared = permguard_languages::request::CONFIGURATION_PATH;
        let (status, document) = fetch(&root, declared).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(document["interface"], json!("permguard.pdp.v1"));
        assert_eq!(
            document["endpoints"]["evaluation"],
            json!("http://127.0.0.1:7656/access/v1/evaluation")
        );
        assert_eq!(
            document["endpoints"]["evaluations"],
            json!("http://127.0.0.1:7656/access/v1/evaluations")
        );
        assert_eq!(document["store_scope"]["zone"], json!("required"));

        // Every capability is this interface's own. A URN borrowed from somebody else's
        // specification would be claiming their contract along with it.
        for capability in document["capabilities"]
            .as_array()
            .expect("capabilities is an array")
        {
            let urn = capability.as_str().expect("a URN is a string");
            assert!(urn.starts_with("urn:permguard:pdp:v1:"), "{urn}");
        }

        // The advertised endpoints really answer — an advertisement nobody honours is worse than
        // none, because a caller configures itself from it.
        for endpoint in ["evaluation", "evaluations"] {
            let path = document["endpoints"][endpoint]
                .as_str()
                .expect("an endpoint")
                .trim_start_matches("http://127.0.0.1:7656")
                .to_owned();
            let (status, _, _) = post(&root, &path, json!({})).await;
            assert_ne!(
                status,
                StatusCode::NOT_FOUND,
                "{endpoint} is advertised and not mounted"
            );
        }

        // And one path publishes it. The candidates are the shapes a second surface would take if
        // anyone added one: the interface's name without its version, and a bare product name.
        // Neither is served, and this is what says so — the generic `404` for an unknown path
        // would not, because it says nothing about *which* paths were meant to exist.
        let candidates = [
            declared,
            "/.well-known/permguard-pdp-configuration",
            "/.well-known/permguard-configuration",
        ];
        let mut publishing = Vec::new();
        for candidate in candidates {
            let (status, body) = fetch(&root, candidate).await;
            if status == StatusCode::OK && body["interface"] == json!("permguard.pdp.v1") {
                publishing.push(candidate);
            }
        }

        assert_eq!(
            publishing,
            vec![declared],
            "this document has exactly one address, and it is the one the interface declares"
        );
    }

    #[tokio::test]
    async fn a_body_that_is_not_json_is_refused_as_a_bad_request() {
        let root = scratch("http-garbage").join("mirrors");
        std::fs::create_dir_all(&root).expect("the root exists");

        let request = Request::builder()
            .method("POST")
            .uri("/access/v1/evaluation")
            .header("content-type", "application/json")
            .body(Body::from("not json"))
            .expect("the request builds");
        let response = router(&root)
            .oneshot(request)
            .await
            .expect("the router answers");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn an_expired_mirror_is_refused_and_a_fresh_one_is_served() {
    let root = scratch("expiry").join("mirrors");
    let manifest = manifest(&[("app", "cedar", false)], ">=0.0.0");
    let mirror = provision(
        &root,
        "acme",
        "main-ledger",
        &manifest,
        &[("app", vec![&CEDAR_READ], None)],
    );
    let decider = Arc::new(
        Decider::new(
            root.to_path_buf(),
            Arc::new(Cache::new(64, 8 * 1024 * 1024)),
            Metrics::none(),
            None,
            256,
        )
        .with_expiry(Some(std::time::Duration::from_millis(40))),
    );

    // Freshly confirmed: served.
    permguard_data_plane::authz::store::touch_synced(&mirror.path);
    let answer = decider
        .decide(&ask("acme", "main-ledger", "alice", "read"), None)
        .await
        .expect("a fresh mirror answers");
    assert!(answer.decision);

    // Past the bound: refused as unavailable, not decided from the old state.
    std::thread::sleep(std::time::Duration::from_millis(60));
    let refused = decider
        .decide(&ask("acme", "main-ledger", "alice", "read"), None)
        .await
        .expect_err("an expired mirror is refused");
    assert_eq!(refused.code(), "ledger_expired");
}

#[tokio::test]
async fn a_mirror_nobody_synchronizes_is_not_bounded_by_expiry() {
    // No SYNCED marker: a volume fed by other means. Its freshness belongs to
    // whoever feeds it, so the bound does not apply.
    let root = scratch("expiry-unsynced").join("mirrors");
    let manifest = manifest(&[("app", "cedar", false)], ">=0.0.0");
    provision(
        &root,
        "acme",
        "main-ledger",
        &manifest,
        &[("app", vec![&CEDAR_READ], None)],
    );
    let decider = Arc::new(
        Decider::new(
            root.to_path_buf(),
            Arc::new(Cache::new(64, 8 * 1024 * 1024)),
            Metrics::none(),
            None,
            256,
        )
        .with_expiry(Some(std::time::Duration::from_millis(1))),
    );

    let answer = decider
        .decide(&ask("acme", "main-ledger", "alice", "read"), None)
        .await
        .expect("answered");
    assert!(answer.decision);
}

/// Two Cedar partitions with **different schemas**, each given its own entity store.
///
/// This is the case a language cannot route: both partitions are Cedar, so anything addressed to
/// "the Cedar partitions" reaches both — and a store legal for one schema is refused by the other,
/// which used to mean a profile like this could not be answered at all. `partition_inputs`
/// addresses a partition by name, which is the only identity that separates them.
#[tokio::test]
async fn two_cedar_partitions_with_different_schemas_each_read_their_own_graph() {
    const FINANCE: Policy = Policy {
        id: "01a0-finance",
        media_type: registry::MEDIA_TYPE_POLICY_CEDAR,
        source: "@alias(\"finance-readers\")\npermit(principal in Group::\"finance\", action == Action::\"read\", resource);",
    };
    const OWNERS: Policy = Policy {
        id: "01a0-owners",
        media_type: registry::MEDIA_TYPE_POLICY_CEDAR,
        source: "@alias(\"team-owners\")\npermit(principal in Team::\"payments\", action == Action::\"read\", resource);",
    };
    // One schema knows `Group`, the other knows `Team`. Neither accepts the other's entities.
    const GROUPS: &str = "entity Group;\nentity User in [Group];\nentity Document;\naction read appliesTo { principal: [User], resource: [Document] };";
    const TEAMS: &str = "entity Team;\nentity User in [Team];\nentity Document;\naction read appliesTo { principal: [User], resource: [Document] };";

    let root = scratch("two-cedar").join("mirrors");
    let manifest = manifest(
        &[("groups", "cedar", true), ("teams", "cedar", true)],
        ">=0.0.0",
    );
    provision(
        &root,
        "acme",
        "main-ledger",
        &manifest,
        &[
            ("groups", vec![&FINANCE], Some(GROUPS)),
            ("teams", vec![&OWNERS], Some(TEAMS)),
        ],
    );
    let decider = decider(&root);

    let ask = |partitions: serde_json::Value| -> wire::CheckRequest {
        serde_json::from_value(json!({
            "zone": "acme", "ledger": "main-ledger",
            "subject": {"type": "User", "id": "alice"},
            "resource": {"type": "Document", "id": "budget"},
            "action": {"name": "read"},
            "partition_inputs": partitions
        }))
        .expect("the payload parses")
    };
    let store = |items: serde_json::Value| json!({"type": permguard_languages::input::CEDAR_ENTITIES_V1, "data": items});

    // Each partition is handed the graph its own schema declares.
    let answer = decider
        .decide(
            &ask(json!({
                "groups": store(json!([
                    {"uid": {"type": "Group", "id": "finance"}, "attrs": {}, "parents": []},
                    {"uid": {"type": "User", "id": "alice"}, "attrs": {},
                     "parents": [{"type": "Group", "id": "finance"}]}
                ])),
                "teams": store(json!([
                    {"uid": {"type": "Team", "id": "payments"}, "attrs": {}, "parents": []},
                    {"uid": {"type": "User", "id": "alice"}, "attrs": {},
                     "parents": [{"type": "Team", "id": "payments"}]}
                ]))
            })),
            None,
        )
        .await
        .expect("the ledger is served");

    assert!(answer.decision, "both schemas were satisfied");
    let cited = answer.context.expect("a context").policies;
    assert!(
        cited.contains(&FINANCE.id.to_owned()) && cited.contains(&OWNERS.id.to_owned()),
        "both partitions decided, not one: {cited:?}"
    );

    // And the stores are genuinely separate: give `teams` the group store and its own schema
    // refuses it — before any policy runs, because a store the schema does not declare is a bad
    // request and not a decision anybody's rules have an opinion about.
    let refused = decider
        .decide(
            &ask(json!({
                "teams": store(json!([
                    {"uid": {"type": "Group", "id": "finance"}, "attrs": {}, "parents": []}
                ]))
            })),
            None,
        )
        .await
        .expect_err("a store its schema does not declare");

    assert_eq!(refused.code(), "partition_input_schema");
    assert_eq!(refused.class(), permguard_core::ErrorClass::Validation);
    assert!(
        refused
            .disclosed_message(permguard_core::Disclosure::Full)
            .contains("teams"),
        "{refused:?}"
    );
}

/// The PDP over a **real socket**: the production client, the production server, and TCP between
/// them.
///
/// # Why this exists on top of everything above
///
/// The HTTP tests drive the router in process, and the conversion tests check each side of the
/// protobuf mapping on its own. Neither can see a field that is *lost between them* — and one was.
/// `partition_inputs` inside a boxcarred evaluation was a bare proto3 map, and a map cannot tell an
/// absent field from an empty one, so an evaluation stating `{}` arrived as "unset" and inherited
/// the request's defaults. The same payload was refused over HTTP and answered over gRPC.
///
/// So this asks both transports the same two questions and requires the same two answers. Nothing
/// is faked: the client is `permguard_control_client::pdp::client`, the one the CLI uses, and the
/// server is `PdpApi` over the same `Decider` the HTTP surface holds.
mod grpc_socket {
    use super::*;

    use permguard_data_plane::authz::grpc::PdpApi;

    /// Serves a real PDP on an ephemeral port, and answers its `grpc://` URL.
    fn serve(root: &Path) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port is free");
        let address = listener.local_addr().expect("the address is known");
        listener
            .set_nonblocking(true)
            .expect("the listener goes non-blocking for tokio");

        let api = PdpApi {
            decider: decider(root),
            disclosure: Disclosure::Full,
            base_url: format!("http://{address}"),
        };

        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("the server runtime starts");
            runtime.block_on(async move {
                let listener =
                    tokio::net::TcpListener::from_std(listener).expect("tokio adopts it");
                let incoming = async_stream::stream! {
                    loop {
                        match listener.accept().await {
                            Ok((stream, _)) => yield Ok(stream),
                            Err(error) => yield Err(error),
                        }
                    }
                };
                let _ = tonic::transport::Server::builder()
                    .add_service(
                        permguard_data_plane::v1::policy_decision_point_server::PolicyDecisionPointServer::new(api),
                    )
                    .serve_with_incoming(incoming)
                    .await;
            });
        });

        format!("grpc://{address}")
    }

    /// The two payloads: one whose evaluation inherits the request's inputs, one whose evaluation
    /// states `{}` — which replaces them with nothing.
    fn payloads() -> (Value, Value) {
        let store = json!({
            "type": permguard_languages::input::CEDAR_ENTITIES_V1,
            "data": [
                {"uid": {"type": "Group", "id": "finance"}, "attrs": {}, "parents": []},
                {"uid": {"type": "user", "id": "alice"}, "attrs": {},
                 "parents": [{"type": "Group", "id": "finance"}]}
            ]
        });
        let base = json!({
            "zone": "acme", "ledger": "main-ledger",
            "subject": {"type": "user", "id": "alice"},
            "resource": {"type": "document", "id": "budget"},
            "action": {"name": "read"},
            "partition_inputs": {"cedar": store}
        });

        let mut inherits = base.clone();
        inherits["evaluations"] = json!([{"request_id": "one"}]);

        let mut states_none = base;
        states_none["evaluations"] = json!([{"request_id": "one", "partition_inputs": {}}]);

        (inherits, states_none)
    }

    /// The two bindings describe the same interface, or "same contract, two transports" is a
    /// claim nobody checks.
    ///
    /// A caller configures itself from whichever document it can reach. If the gRPC one named a
    /// capability the HTTP one did not — or a different endpoint, or a different interface — a
    /// deployment would behave differently depending on how its PEP happened to connect.
    #[test]
    fn both_transports_publish_the_same_configuration() {
        let root = scratch("grpc-config").join("mirrors");
        std::fs::create_dir_all(&root).expect("the root exists");

        let url = serve(&root);
        let over_grpc = permguard_control_client::pdp::client(
            &url,
            &permguard_control_client::tls::TlsOptions::default(),
            Box::new(permguard_control_client::narrate::Silent),
        )
        .expect("the endpoint parses")
        .configuration()
        .expect("the plane answers");

        // The HTTP document the same plane would serve, built by the one function both call.
        let base = over_grpc["pdp"].as_str().expect("a pdp identifier");
        let over_http: Value =
            serde_json::from_str(&permguard_data_plane::authz::configuration::document(base))
                .expect("it is JSON");

        assert_eq!(
            over_grpc, over_http,
            "the same interface, described the same way, whichever transport asked"
        );
        assert_eq!(over_grpc["interface"], json!("permguard.pdp.v1"));
    }

    #[test]
    fn an_evaluation_stating_no_inputs_is_answered_the_same_over_both_transports() {
        let root = scratch("grpc-socket").join("mirrors");
        // One Cedar partition whose policy only permits through the group the store carries, so
        // *having* the store or not is the difference between permit and deny — which is exactly
        // what the lost field decided.
        let manifest = manifest(&[("cedar", "cedar", false)], ">=0.0.0");
        provision(
            &root,
            "acme",
            "main-ledger",
            &manifest,
            &[("cedar", vec![&CEDAR_GROUP], None)],
        );

        let url = serve(&root);
        let client = permguard_control_client::pdp::client(
            &url,
            &permguard_control_client::tls::TlsOptions::default(),
            Box::new(permguard_control_client::narrate::Silent),
        )
        .expect("the endpoint parses");

        let (inherits, states_none) = payloads();

        // Over the socket.
        let over_grpc_inherits = client.evaluate(&inherits).expect("the plane answers");
        let over_grpc_states_none = client.evaluate(&states_none).expect("the plane answers");

        // And the same two, in process, over HTTP.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let over_http = |body: Value| {
            let root = root.clone();
            runtime.block_on(async move {
                let (_, answer, _) =
                    crate::surface::post(&root, "/access/v1/evaluation", body).await;

                answer
            })
        };
        let over_http_inherits = over_http(inherits);
        let over_http_states_none = over_http(states_none);

        // Inheriting, the store is there and the group permits.
        assert_eq!(
            over_grpc_inherits["decision"],
            json!(true),
            "gRPC: what an evaluation does not state, it inherits"
        );
        assert_eq!(
            over_http_inherits["decision"], over_grpc_inherits["decision"],
            "and both transports say so"
        );

        // Stating `{}`, the store is gone: `alice` is in no group, and nothing permits.
        assert_eq!(
            over_grpc_states_none["decision"],
            json!(false),
            "gRPC: `{{}}` replaces the defaults whole — a bare map read it as `unset` and \
             inherited them, which is the bug this test exists for"
        );
        assert_eq!(
            over_http_states_none["decision"], over_grpc_states_none["decision"],
            "and both transports say so"
        );
    }
}
