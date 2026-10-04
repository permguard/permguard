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
use permguard_core::{Disclosure, Metrics, Recorder};
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

/// Errors for every `audit`: no principal carries a `clearance`, so Cedar reports an evaluation
/// error for this policy whenever its scope matches. Beside `CEDAR_READ` it is the allow-plus-error
/// case of the languages model, scoped to one action so the rest of the ledger still decides.
const CEDAR_CLEARANCE: Policy = Policy {
    id: "01a0-cedar-clearance",
    media_type: registry::MEDIA_TYPE_POLICY_CEDAR,
    source: r#"permit (principal, action == Action::"audit", resource) when { principal.clearance == "top" };"#,
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
                artifacts: Vec::new(),
                history: None,
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
            r#type: permguard_objects::manifest::PROFILE_PDP_NATIVE_V1.to_owned(),
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

    let manifest_digest = put_blob(
        permguard_objects::manifest::MEDIA_TYPE,
        &manifest.encode().expect("it encodes"),
    );

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
        server: "http://127.0.0.1:6443".to_owned(),
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

/// A partition that declares an optional input and is asked without it decides against the
/// empty one, legally — and the answer says so, so a reader can tell "the guardrail did not
/// object" from "the guardrail was given nothing to object with". Send the input and the field
/// is gone.
#[tokio::test]
async fn an_answer_names_the_declared_inputs_the_request_left_out() {
    let root = scratch("absent-inputs").join("mirrors");
    provision(
        &root,
        "acme",
        "main-ledger",
        &manifest(&[("app", "cedar", false)], ">=0.0.0"),
        &[("app", vec![&CEDAR_READ], None)],
    );
    let decider = decider(&root);

    let answer = decider
        .decide(&ask("acme", "main-ledger", "alice", "read"), None)
        .await
        .expect("an optional input may be omitted");
    assert_eq!(
        answer.context.as_ref().expect("a context").absent_inputs,
        vec!["app".to_owned()]
    );

    let mut with_store = ask("acme", "main-ledger", "alice", "read");
    with_store.partition_inputs = serde_json::from_value(json!({
        "app": {"type": "permguard.cedar.entities.v1", "data": []}
    }))
    .expect("the inputs parse");
    let answer = decider
        .decide(&with_store, None)
        .await
        .expect("the store is legal");
    assert!(
        answer
            .context
            .as_ref()
            .expect("a context")
            .absent_inputs
            .is_empty()
    );
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

    // An action the schema never declared cannot be represented by the engine: `E`
    // `evaluation_input_rejected`, which the profile resolves to indeterminate and the native
    // contract answers as a validation refusal — sending it again cannot help, and it is never a
    // deny a policy did not express.
    let refused = decider
        .decide(&ask("acme", "main-ledger", "alice", "teleport"), None)
        .await
        .expect_err("an evaluation nothing could perform is refused, not decided");
    assert_eq!(refused.class(), permguard_core::ErrorClass::Validation);
    assert_eq!(
        refused.code(),
        permguard_core::codes::pdp_native::EVALUATION_INPUT_REJECTED
    );
    assert_eq!(refused.http_status(), 400);
    assert!(
        refused
            .internal_detail()
            .is_some_and(|detail| detail.contains("teleport")),
        "the operator's detail names what could not be evaluated: {refused}"
    );
}

/// CEDAR-05: from `production` upward a Cedar partition carries a schema. The same schema-less
/// ledger serves under `development`, is refused as `ledger_incompatible` under `production` and
/// `regulated` and leaves no block behind, so lowering the floor takes effect at once; a Cedar
/// partition that carries its schema serves under `production`.
#[tokio::test]
async fn a_schema_less_cedar_partition_serves_only_below_production() {
    use permguard_core::assurance::AssuranceProfile;

    let root = scratch("floor").join("mirrors");
    let schemaless = manifest(&[("app", "cedar", false)], ">=0.0.0");
    let mirror = provision(
        &root,
        "acme",
        "main-ledger",
        &schemaless,
        &[("app", vec![&CEDAR_READ], None)],
    );
    let under = |profile| {
        Arc::new(
            Decider::new(
                root.clone(),
                Arc::new(Cache::new(64, 8 * 1024 * 1024)),
                Metrics::none(),
                None,
                256,
            )
            .with_profile(profile),
        )
    };

    for profile in [AssuranceProfile::Production, AssuranceProfile::Regulated] {
        let refused = under(profile)
            .decide(&ask("acme", "main-ledger", "alice", "read"), None)
            .await
            .expect_err("a schema-less Cedar partition is below the floor");
        assert_eq!(refused.code(), "ledger_incompatible", "{profile}");
        assert!(
            block::read(&mirror.path).is_none(),
            "a floor refusal is never written down"
        );
    }
    assert!(
        under(AssuranceProfile::Development)
            .decide(&ask("acme", "main-ledger", "alice", "read"), None)
            .await
            .expect("development serves it")
            .decision
    );

    let typed_root = scratch("floor-typed").join("mirrors");
    let typed = manifest(&[("app", "cedar", true)], ">=0.0.0");
    let schema = "entity user;\nentity document;\naction read appliesTo { principal: [user], resource: [document] };\n";
    provision(
        &typed_root,
        "acme",
        "main-ledger",
        &typed,
        &[("app", vec![&CEDAR_READ], Some(schema))],
    );
    let production = Decider::new(
        typed_root,
        Arc::new(Cache::new(64, 8 * 1024 * 1024)),
        Metrics::none(),
        None,
        256,
    )
    .with_profile(AssuranceProfile::Production);
    assert!(
        production
            .decide(&ask("acme", "main-ledger", "alice", "read"), None)
            .await
            .expect("a typed Cedar partition serves under production")
            .decision
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

/// Mirror identities are an internal routing key; the existing decision-log API is scoped by the
/// public names. Changing the two record fields to IDs without changing the read contract makes a
/// successfully written decision disappear from every REST, gRPC and CLI tenant query.
#[tokio::test]
async fn a_decision_addressed_by_identity_is_recorded_under_the_public_names() {
    let root = scratch("decision-public-scope").join("mirrors");
    provision(
        &root,
        "acme",
        "main-ledger",
        &manifest(&[("app", "cedar", false)], ">=0.0.0"),
        &[("app", vec![&CEDAR_READ], None)],
    );
    let spool = scratch("decision-public-scope-spool");
    let journal = Journal::open(
        &spool,
        "plane",
        Epoch {
            version: "0.1.0".to_owned(),
            build: None,
            engines: BTreeMap::new(),
            sampling: "1.0".to_owned(),
        },
        WhenFull::Closed,
        Bounds {
            bytes: 64 * 1024 * 1024,
            age: std::time::Duration::from_secs(3600),
            segment_bytes: 1024 * 1024,
        },
        permguard_decisions::Commitment::new(*b"a-key-of-at-least-32-bytes-long!!", "v1"),
        Metrics::none(),
    )
    .expect("the journal opens");
    let decider = decider_with_journal(&root, journal);

    decider
        .decide(&ask("acme-id", "main-ledger-id", "alice", "read"), None)
        .await
        .expect("the mirror is also addressable by identity");
    drop(decider);

    let mut decisions = Vec::new();
    for entry in std::fs::read_dir(&spool).expect("the spool can be listed") {
        let path = entry.expect("the spool entry is readable").path();
        if path.extension().and_then(std::ffi::OsStr::to_str) != Some("jsonl") {
            continue;
        }
        for line in std::fs::read_to_string(path)
            .expect("the segment can be read")
            .lines()
        {
            let record: Value = serde_json::from_str(line).expect("the record is JSON");
            if record["kind"] == json!("decision") {
                decisions.push(record);
            }
        }
    }

    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0]["store"]["zone"], json!("acme"));
    assert_eq!(decisions[0]["store"]["ledger"], json!("main-ledger"));
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
            server: "http://127.0.0.1:6443".to_owned(),
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
            base_url: "http://127.0.0.1:7443".to_owned(),
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

    /// The interface names itself, the endpoints it advertises are the ones mounted, and the
    /// obvious aliases of its path are not served.
    ///
    /// The last clause is deliberately modest, because a test cannot enumerate every path a router
    /// does not mount. What it *can* do is check the ones a well-meaning person would add — the
    /// name without its version, the bare product name — since a second address for this document
    /// is a compatibility surface somebody then has to keep honest. That the router mounts the
    /// document only at [`CONFIGURATION_PATH`](permguard_languages::request::CONFIGURATION_PATH)
    /// is guaranteed by construction, not by this test: the route is that constant.
    #[tokio::test]
    async fn the_configuration_describes_this_interface_and_its_aliases_are_not_served() {
        let root = scratch("http-config").join("mirrors");
        std::fs::create_dir_all(&root).expect("the root exists");

        let declared = permguard_languages::request::CONFIGURATION_PATH;
        let (status, document) = fetch(&root, declared).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(document["interface"], json!("permguard.api.pdp.native.v1"));
        assert_eq!(
            document["endpoints"]["evaluation"],
            json!("http://127.0.0.1:7443/access/v1/evaluation")
        );
        assert_eq!(
            document["endpoints"]["evaluations"],
            json!("http://127.0.0.1:7443/access/v1/evaluations")
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
                .trim_start_matches("http://127.0.0.1:7443")
                .to_owned();
            let (status, _, _) = post(&root, &path, json!({})).await;
            assert_ne!(
                status,
                StatusCode::NOT_FOUND,
                "{endpoint} is advertised and not mounted"
            );
        }

        // The aliases a second surface would most likely take: the interface's name without its
        // version, and a bare product name. Neither is served — and the point of naming them is
        // that the generic `404` for an unknown path says nothing about *which* paths somebody
        // might have meant to add.
        let candidates = [
            declared,
            "/.well-known/permguard-pdp-configuration",
            "/.well-known/permguard-configuration",
        ];
        let mut publishing = Vec::new();
        for candidate in candidates {
            let (status, body) = fetch(&root, candidate).await;
            if status == StatusCode::OK && body["interface"] == json!("permguard.api.pdp.native.v1")
            {
                publishing.push(candidate);
            }
        }

        assert_eq!(
            publishing,
            vec![declared],
            "of these, only the declared path publishes the configuration"
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
        let over_http: Value = serde_json::from_str(
            &permguard_data_plane::authz::configuration::document(base)
                .expect("the configuration serializes"),
        )
        .expect("it is JSON");

        assert_eq!(
            over_grpc, over_http,
            "the same interface, described the same way, whichever transport asked"
        );
        assert_eq!(over_grpc["interface"], json!("permguard.api.pdp.native.v1"));
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

/// Sixteen requests arriving on a cold ledger compile it once, not sixteen times.
///
/// # What this is actually about
///
/// Compiling is idempotent and expensive, so without a gate every request that arrives while the
/// first is compiling repeats the same work and throws it away. Two requests is merely wasteful; a
/// fleet's worth at a restart, at a commit change, or the moment an entry is evicted is a stampede
/// — all of them parsing the same policies at once, on the same machine, while the cache they
/// would each have hit sits empty until the first one finishes.
///
/// The compile counter is what makes it visible: it counts compilations, so N concurrent requests
/// on one cold partition must leave it at one.
#[tokio::test]
async fn concurrent_requests_on_a_cold_ledger_compile_it_once() {
    let root = scratch("stampede").join("mirrors");
    let registry = Arc::new(permguard_std::metrics::Registry::new());
    provision(
        &root,
        "acme",
        "main-ledger",
        &manifest(&[("app", "cedar", false)], ">=0.0.0"),
        &[("app", vec![&CEDAR_READ], None)],
    );
    let decider = Arc::new(Decider::new(
        root.clone(),
        Arc::new(Cache::new(64, 8 * 1024 * 1024)),
        Metrics::new(Arc::clone(&registry) as Arc<dyn Recorder>),
        None,
        256,
    ));

    // Sixteen at once, all cold, all for the same partition of the same commit.
    let mut asked = Vec::new();
    for _ in 0..16 {
        let decider = Arc::clone(&decider);
        asked.push(tokio::spawn(async move {
            decider
                .decide(&ask("acme", "main-ledger", "alice", "read"), None)
                .await
        }));
    }
    for held in asked {
        let answered = held.await.expect("the task finishes").expect("it decides");
        assert!(answered.decision, "every one of them is answered");
    }

    let compiled: f64 = registry
        .snapshot()
        .into_iter()
        .filter(|sample| sample.metric.name() == "permguard_authz_compilations_total")
        .map(|sample| match sample.reading {
            permguard_core::metrics::Reading::Value(value) => value,
            permguard_core::metrics::Reading::Distribution { sum, .. } => sum,
        })
        .sum();
    assert_eq!(
        compiled, 1.0,
        "sixteen concurrent requests on one cold partition compiled it {compiled} times"
    );
    let (entries, _) = decider.cache().holdings();
    assert_eq!(
        entries, 2,
        "and sixteen requests left one head and one partition behind, not sixteen of each"
    );
}

/// A decision whose budget the load already spent refuses rather than evaluating past it.
///
/// The budget bounds the *work*, and loading holds a blocking thread exactly as evaluating does.
/// Measured from after the load, a budget could be spent in full on top of a slow one and outlive
/// the response it was meant to fit inside — so it is measured from the start of the decision, and
/// a decision that reaches evaluation with nothing left refuses there: every partition is `E`
/// with `evaluation_deadline_exceeded`, the result is indeterminate, and the request is answered
/// with the typed refusal — fail-closed, and never a deny.
#[tokio::test]
async fn a_decision_whose_budget_the_load_already_spent_refuses() {
    let root = scratch("budget").join("mirrors");
    provision(
        &root,
        "acme",
        "main-ledger",
        &manifest(&[("app", "cedar", false)], ">=0.0.0"),
        &[("app", vec![&CEDAR_READ], None)],
    );
    // A budget of one nanosecond: whatever reading and compiling the mirror costs, it costs more
    // than that, so evaluation begins past the deadline.
    let decider = Decider::new(
        root.clone(),
        Arc::new(Cache::new(64, 8 * 1024 * 1024)),
        Metrics::none(),
        None,
        256,
    )
    .with_budget(Some(std::time::Duration::from_nanos(1)));

    let refused = decider
        .decide(&ask("acme", "main-ledger", "alice", "read"), None)
        .await
        .expect_err("a spent budget is an indeterminate result, not a decision");

    assert_eq!(
        refused.code(),
        permguard_core::codes::pdp_native::EVALUATION_INDETERMINATE,
        "fail-closed, and typed: {refused}"
    );
    let detail = refused.internal_detail().unwrap_or_default();
    assert!(
        detail.contains(permguard_core::codes::pdp_native::EVALUATION_DEADLINE_EXCEEDED)
            && detail.contains("time"),
        "and it says why, rather than denying mutely: {detail}"
    );
}

/// The PDP answers the same over REST and gRPC: every payload below is sent through the production
/// client once per transport, against one plane served on both, and must get the same canonical
/// answer or the same `{class, code}`.
mod parity {
    use super::*;

    use permguard_conformance::parity::{
        Outcome, assert_parity, expected_statuses, outcome, serve,
    };
    use permguard_data_plane::authz::grpc::PdpApi;
    use permguard_data_plane::v1::policy_decision_point_server::PolicyDecisionPoint as _;

    fn pdp(url: &str) -> Box<dyn permguard_control_client::pdp::Pdp> {
        permguard_control_client::pdp::client(
            url,
            &permguard_control_client::tls::TlsOptions::default(),
            Box::new(permguard_control_client::narrate::Silent),
        )
        .expect("the endpoint parses")
    }

    fn ask(subject: &str, action: &str) -> Value {
        json!({
            "zone": "acme", "ledger": "main-ledger",
            "subject": {"type": "user", "id": subject},
            "resource": {"type": "document", "id": "budget"},
            "action": {"name": action}
        })
    }

    #[test]
    fn test_every_payload_gets_the_same_answer_or_refusal_over_rest_and_grpc() {
        let root = scratch("parity").join("mirrors");
        let manifest = manifest(&[("app", "cedar", false)], ">=0.0.0");
        provision(
            &root,
            "acme",
            "main-ledger",
            &manifest,
            &[("app", vec![&CEDAR_READ, &CEDAR_NOT_BOB], None)],
        );
        let decider = decider(&root);
        let base_url = "http://127.0.0.1:7443".to_owned();
        let served = serve(
            http::routes(http::Surface {
                decider: decider.clone(),
                disclosure: Disclosure::Full,
                base_url: base_url.clone(),
            }),
            tonic::service::Routes::new(
                permguard_data_plane::v1::policy_decision_point_server::PolicyDecisionPointServer::new(
                    PdpApi {
                        decider,
                        disclosure: Disclosure::Full,
                        base_url,
                    },
                ),
            ),
        );
        let over_http = pdp(&served.http);
        let over_grpc = pdp(&served.grpc);

        let mut unknown_ledger = ask("alice", "read");
        unknown_ledger["ledger"] = json!("other-ledger");
        let mut boxcarred = ask("alice", "read");
        boxcarred["evaluations"] = json!([
            {"request_id": "one"},
            {"request_id": "two", "subject": {"type": "user", "id": "bob"}}
        ]);
        let mut subject_without_id = ask("alice", "read");
        subject_without_id["subject"] = json!({"type": "user"});
        let cases = [
            ("a permit", ask("alice", "read")),
            ("a deny", ask("bob", "read")),
            ("a boxcar of a permit and a deny", boxcarred),
            (
                "no store named",
                json!({"subject": {"type": "user", "id": "alice"}}),
            ),
            ("a ledger this plane does not serve", unknown_ledger),
            ("a subject without an id", subject_without_id),
        ];

        let mut refusals = 0;
        for (case, payload) in cases {
            let http = outcome(over_http.evaluate(&payload));
            let grpc = outcome(over_grpc.evaluate(&payload));
            if matches!(http, Outcome::Refused { .. }) {
                refusals += 1;
            }
            // The decision id is minted per call: two calls cannot share it.
            assert_parity(case, http.masked(&["id"]), grpc.masked(&["id"]));
        }
        assert!(refusals >= 3, "the refusals are exercised ({refusals})");
    }

    /// Below the client: each transport's raw status is the one its `{class, code}` maps to.
    #[tokio::test]
    async fn test_every_refusal_answers_the_status_its_class_maps_to_on_both_transports() {
        let root = scratch("parity-raw").join("mirrors");
        std::fs::create_dir_all(&root).expect("the root exists");

        let mut unknown_ledger = ask("alice", "read");
        unknown_ledger["ledger"] = json!("other-ledger");
        for (case, payload) in [
            (
                "no store named over HTTP",
                json!({"subject": {"type": "user", "id": "alice"}}),
            ),
            ("an unserved ledger over HTTP", unknown_ledger),
        ] {
            let (status, body, _) =
                crate::surface::post(&root, "/access/v1/evaluation", payload).await;
            let (class, code) = (
                body["class"].as_str().unwrap_or_default(),
                body["code"].as_str().unwrap_or_default(),
            );
            assert_eq!(
                status.as_u16(),
                expected_statuses(class, code).0,
                "`{case}`: `{class}/{code}`"
            );
        }

        let api = PdpApi {
            decider: decider(&root),
            disclosure: Disclosure::Full,
            base_url: "http://127.0.0.1:7443".to_owned(),
        };
        for (case, request) in [
            (
                "no store named over gRPC",
                permguard_data_plane::v1::EvaluateRequest::default(),
            ),
            (
                "an unserved ledger over gRPC",
                permguard_data_plane::v1::EvaluateRequest {
                    zone: "acme".to_owned(),
                    ledger: "other-ledger".to_owned(),
                    ..Default::default()
                },
            ),
        ] {
            let refused = api
                .evaluate(tonic::Request::new(request))
                .await
                .expect_err("the case is a refusal");
            let metadata = |key: &str| {
                refused
                    .metadata()
                    .get(key)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_owned()
            };
            let (class, code) = (
                metadata(permguard_core::GRPC_ERROR_CLASS),
                metadata(permguard_core::GRPC_ERROR_CODE),
            );
            assert_eq!(
                refused.code() as i32,
                expected_statuses(&class, &code).1,
                "`{case}`: `{class}/{code}`"
            );
        }
    }
}

/// H-13: identifiers a client chooses — tenant names, ledger names, request ids, principals —
/// never become a metric label and never reach a log line, on an answer or on a refusal.
mod adversarial_ids {
    use super::*;

    use std::sync::Mutex;

    const ZONE: &str = "zone-spy-7f3a91";
    const LEDGER: &str = "ledger-spy-91c2e0";
    const REQUEST: &str = "request-spy-55aa13";
    const SUBJECT: &str = "principal-spy-3b8d42";
    /// The id the transport drew for the request, which the log may carry.
    const DRAWN: &str = "5e1f0c9a7b3d2e48";
    const UNKNOWN_ZONE: &str = "zone-spy-unknown-0d1e";
    const UNKNOWN_LEDGER: &str = "ledger-spy-unknown-a4c7";
    const PARTITION: &str = "partition-spy-c0ffee";
    const PROFILE: &str = "profile-spy-unknown-6e2b";
    const SPIES: [&str; 8] = [
        ZONE,
        LEDGER,
        REQUEST,
        SUBJECT,
        UNKNOWN_ZONE,
        UNKNOWN_LEDGER,
        PARTITION,
        PROFILE,
    ];

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("not poisoned")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_adversarial_ids_never_become_labels_or_log_lines() {
        let root = scratch("adversarial-ids").join("mirrors");
        let manifest = manifest(&[(PARTITION, "cedar", false)], ">=0.0.0");
        let mirror = provision(
            &root,
            "acme",
            "main",
            &manifest,
            &[(PARTITION, vec![&CEDAR_READ, &CEDAR_CLEARANCE], None)],
        );
        // The names a client addresses the ledger by are the spies; the ids stay unrelated.
        permguard_data_plane::authz::store::record(
            &mirror.path,
            &Identity {
                zone_id: "acme-id".to_owned(),
                zone_name: ZONE.to_owned(),
                ledger_id: "main-id".to_owned(),
                ledger_name: LEDGER.to_owned(),
                server: "http://127.0.0.1:6443".to_owned(),
            },
        )
        .expect("the identity is recorded");

        let registry = Arc::new(permguard_std::metrics::Registry::new());
        // With a journal, so the line that leads from a log to the audit record is exercised too.
        let spool = scratch("adversarial-ids-spool");
        let journal = Journal::open(
            &spool,
            "plane",
            Epoch {
                version: "0.1.0".to_owned(),
                build: None,
                engines: BTreeMap::new(),
                sampling: "1.0".to_owned(),
            },
            WhenFull::Open,
            Bounds {
                bytes: 64 * 1024 * 1024,
                age: std::time::Duration::from_secs(3600),
                segment_bytes: 1024 * 1024,
            },
            permguard_decisions::Commitment::new(*b"a-key-of-at-least-32-bytes-long!!", "v1"),
            Metrics::none(),
        )
        .expect("the journal opens");
        let decider = Arc::new(
            Decider::new(
                root.clone(),
                Arc::new(Cache::new(64, 8 * 1024 * 1024)),
                Metrics::new(Arc::clone(&registry) as Arc<dyn Recorder>),
                None,
                256,
            )
            .with_journal(
                Some(Arc::new(journal)),
                None,
                permguard_core::decisions::IncludeSection::default(),
            ),
        );
        let logs = Captured::default();
        let writer = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .finish();
        // Global, because the decider runs part of its work on blocking threads a thread-local
        // subscriber would not see. No other test of this binary installs one.
        tracing::subscriber::set_global_default(subscriber).expect("one subscriber per process");

        let mut permitted = ask(ZONE, LEDGER, SUBJECT, "read");
        permitted.request_id = Some(REQUEST.to_owned());
        // The span the transport opens around every request, with the id it drew.
        let answer = {
            use tracing::Instrument as _;

            decider
                .decide(&permitted, None)
                .instrument(tracing::info_span!("request", request.id = DRAWN))
                .await
                .expect("an answer")
        };
        assert!(answer.decision, "the spy ledger answers like any other");
        for (zone, ledger) in [(ZONE, UNKNOWN_LEDGER), (UNKNOWN_ZONE, LEDGER)] {
            let mut refused = ask(zone, ledger, SUBJECT, "read");
            refused.request_id = Some(REQUEST.to_owned());
            assert!(
                decider.decide(&refused, None).await.is_err(),
                "{zone}/{ledger} is refused"
            );
        }
        // A profile the ledger does not declare: the refusal repeats it to the caller, and only
        // to the caller.
        let mut unknown_profile = ask(ZONE, LEDGER, SUBJECT, "read");
        unknown_profile.request_id = Some(REQUEST.to_owned());
        unknown_profile.profile = Some(PROFILE.to_owned());
        assert!(
            decider.decide(&unknown_profile, None).await.is_err(),
            "an undeclared profile is refused"
        );
        // An evaluation that fails: Cedar's own error names the spy subject, and the log names
        // the failure by its code alone.
        let mut failing = ask(ZONE, LEDGER, SUBJECT, "audit");
        failing.request_id = Some(REQUEST.to_owned());
        assert!(
            decider.decide(&failing, None).await.is_err(),
            "an indeterminate evaluation is refused"
        );

        let series = registry.snapshot();
        assert!(!series.is_empty(), "the decisions were measured");
        // Every value the decider recorded was inside its label's vocabulary: an incomplete
        // vocabulary would otherwise hide here as `other`.
        for refused in [
            permguard_core::metrics::LABEL_VALUES_REFUSED.name(),
            permguard_core::metrics::AGGREGATED_RESOURCES_REFUSED.name(),
        ] {
            assert!(
                !series.iter().any(|sample| sample.metric.name() == refused),
                "{refused} was recorded: a label value or a resource was refused"
            );
        }
        for sample in &series {
            for (name, value) in &sample.labels {
                for spy in SPIES {
                    assert!(
                        !value.contains(spy) && !name.contains(spy),
                        "`{spy}` became a label of {}: {name}={value}",
                        sample.metric.name()
                    );
                }
            }
        }
        let logged =
            String::from_utf8(logs.0.lock().expect("not poisoned").clone()).expect("logs are text");
        assert!(!logged.is_empty(), "the decisions were logged");
        assert!(
            logged
                .lines()
                .any(|line| line.contains("authz.evaluation_failed")
                    && line.contains(permguard_core::codes::pdp_native::EVALUATION_FAILED)
                    && line.contains("indeterminate")),
            "the failure is logged by its code:\n{logged}"
        );
        assert!(
            !logged.contains("clearance"),
            "the engine's own text never reaches a log line:\n{logged}"
        );
        for spy in SPIES {
            assert!(
                !logged.contains(spy),
                "`{spy}` reached a log line:\n{logged}"
            );
        }

        // Correlation survives: one log line carries the request's drawn id and the id of the
        // audit record the decision became, and that record is in the journal.
        drop(decider);
        let recorded: Vec<String> = std::fs::read_dir(&spool)
            .expect("the spool can be listed")
            .map(|entry| entry.expect("a spool entry").path())
            .filter(|path| path.extension().and_then(std::ffi::OsStr::to_str) == Some("jsonl"))
            .flat_map(|path| {
                std::fs::read_to_string(path)
                    .expect("the segment can be read")
                    .lines()
                    .map(|line| serde_json::from_str::<Value>(line).expect("the record is JSON"))
                    .collect::<Vec<_>>()
            })
            .filter(|record| record["kind"] == json!("decision"))
            .filter(|record| record["outcome"] == json!("permit"))
            .filter_map(|record| record["id"].as_str().map(ToOwned::to_owned))
            .collect();
        assert_eq!(recorded.len(), 1, "the answered decision was recorded");
        assert!(
            logged
                .lines()
                .any(|line| line.contains(DRAWN) && line.contains(&recorded[0])),
            "no log line joins request `{DRAWN}` to decision `{}`:\n{logged}",
            recorded[0]
        );
    }
}

/// TL-1: an evaluation nothing could decide is answered as what it is — a typed refusal, never a
/// deny — on both transports, and recorded as `indeterminate`.
mod indeterminate {
    use super::*;

    use permguard_conformance::parity::{Outcome, assert_parity, outcome, serve};
    use permguard_data_plane::authz::grpc::PdpApi;

    /// The wire payload: `audit` reaches `CEDAR_CLEARANCE`, which errors; anything else does not.
    fn asked(subject: &str, action: &str) -> Value {
        json!({
            "zone": "acme", "ledger": "main-ledger",
            "subject": {"type": "user", "id": subject},
            "resource": {"type": "document", "id": "budget"},
            "action": {"name": action}
        })
    }

    fn ledger(tag: &str) -> PathBuf {
        let root = scratch(tag).join("mirrors");
        provision(
            &root,
            "acme",
            "main-ledger",
            &manifest(&[("app", "cedar", false)], ">=0.0.0"),
            &[("app", vec![&CEDAR_READ, &CEDAR_CLEARANCE], None)],
        );

        root
    }

    /// The contract's status table: `503`, class `unavailable`, code `evaluation_indeterminate`,
    /// and no `decision` in the body — while a request the same ledger decides stays a `200`.
    #[tokio::test]
    async fn an_indeterminate_evaluation_is_a_typed_refusal_not_a_deny() {
        let root = ledger("indeterminate-http");

        let (status, body, _) =
            crate::surface::post(&root, "/access/v1/evaluation", asked("alice", "audit")).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(body["class"], json!("unavailable"), "{body}");
        assert_eq!(
            body["code"],
            json!(permguard_core::codes::pdp_native::EVALUATION_INDETERMINATE),
            "{body}"
        );
        assert!(
            body.get("decision").is_none(),
            "a refusal is not a decision: {body}"
        );
        assert!(
            body["message"]
                .as_str()
                .is_some_and(|message| message.contains("clearance")),
            "full disclosure names the failed partition's error: {body}"
        );

        // A policy deny on the same ledger is still a decision.
        let (status, body, _) =
            crate::surface::post(&root, "/access/v1/evaluation", asked("alice", "delete")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["decision"], json!(false), "{body}");
        assert_eq!(
            body["context"]["reason_admin"]["code"],
            json!("403"),
            "{body}"
        );
    }

    /// A batch with one evaluation nothing could decide is refused whole, naming it; the
    /// evaluations beside it are not answered as if the batch had decided.
    #[tokio::test]
    async fn a_batch_with_an_indeterminate_evaluation_is_refused_whole() {
        let root = ledger("indeterminate-batch");
        let mut payload = asked("alice", "read");
        payload["evaluations"] = json!([
            {"request_id": "reads"},
            {"request_id": "audits", "action": {"name": "audit"}},
        ]);

        let (status, body, _) = crate::surface::post(&root, "/access/v1/evaluation", payload).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(
            body["code"],
            json!(permguard_core::codes::pdp_native::EVALUATION_INDETERMINATE)
        );
        assert!(
            body["message"]
                .as_str()
                .is_some_and(|message| message.contains("`audits`")),
            "the refusal names the evaluation that could not be evaluated: {body}"
        );
        assert!(body.get("evaluations").is_none(), "{body}");
    }

    /// The same refusal over REST and gRPC, for the payload asked of the ledger at `root`.
    fn over_both(root: &Path, payload: &Value) -> (Outcome, Outcome) {
        let decider = decider(root);
        let base_url = "http://127.0.0.1:7443".to_owned();
        let served = serve(
            http::routes(http::Surface {
                decider: decider.clone(),
                disclosure: Disclosure::Full,
                base_url: base_url.clone(),
            }),
            tonic::service::Routes::new(
                permguard_data_plane::v1::policy_decision_point_server::PolicyDecisionPointServer::new(
                    PdpApi {
                        decider,
                        disclosure: Disclosure::Full,
                        base_url,
                    },
                ),
            ),
        );
        let pdp = |url: &str| {
            permguard_control_client::pdp::client(
                url,
                &permguard_control_client::tls::TlsOptions::default(),
                Box::new(permguard_control_client::narrate::Silent),
            )
            .expect("the endpoint parses")
        };

        (
            outcome(pdp(&served.http).evaluate(payload)),
            outcome(pdp(&served.grpc).evaluate(payload)),
        )
    }

    /// An input the engine rejects is the same `400` `validation` `evaluation_input_rejected` on
    /// both transports.
    #[test]
    fn test_an_input_the_engine_rejects_is_the_same_refusal_over_rest_and_grpc() {
        let root = scratch("input-rejected-parity").join("mirrors");
        let schema = "entity user;\nentity document;\naction read appliesTo { principal: [user], resource: [document] };\n";
        provision(
            &root,
            "acme",
            "main-ledger",
            &manifest(&[("app", "cedar", true)], ">=0.0.0"),
            &[("app", vec![&CEDAR_READ], Some(schema))],
        );

        let (over_http, over_grpc) = over_both(&root, &asked("alice", "teleport"));

        assert!(
            matches!(
                &over_http,
                Outcome::Refused { class, code }
                    if class == "validation"
                        && code == permguard_core::codes::pdp_native::EVALUATION_INPUT_REJECTED
            ),
            "{over_http:?}"
        );
        assert_parity("an input the engine rejects", over_http, over_grpc);
    }

    /// One facade, two transports: the indeterminate payload gets the same `{class, code}`.
    #[test]
    fn test_an_indeterminate_evaluation_is_the_same_refusal_over_rest_and_grpc() {
        let root = ledger("indeterminate-parity");
        let decider = decider(&root);
        let base_url = "http://127.0.0.1:7443".to_owned();
        let served = serve(
            http::routes(http::Surface {
                decider: decider.clone(),
                disclosure: Disclosure::Full,
                base_url: base_url.clone(),
            }),
            tonic::service::Routes::new(
                permguard_data_plane::v1::policy_decision_point_server::PolicyDecisionPointServer::new(
                    PdpApi {
                        decider,
                        disclosure: Disclosure::Full,
                        base_url,
                    },
                ),
            ),
        );
        let pdp = |url: &str| {
            permguard_control_client::pdp::client(
                url,
                &permguard_control_client::tls::TlsOptions::default(),
                Box::new(permguard_control_client::narrate::Silent),
            )
            .expect("the endpoint parses")
        };
        let payload = asked("alice", "audit");

        let over_http = outcome(pdp(&served.http).evaluate(&payload));
        let over_grpc = outcome(pdp(&served.grpc).evaluate(&payload));

        assert!(
            matches!(
                &over_http,
                Outcome::Refused { class, code }
                    if class == "unavailable"
                        && code == permguard_core::codes::pdp_native::EVALUATION_INDETERMINATE
            ),
            "{over_http:?}"
        );
        assert_parity("an indeterminate evaluation", over_http, over_grpc);
    }

    /// A journal that records every decision, permits included.
    fn journal(spool: &Path) -> Journal {
        Journal::open(
            spool,
            "plane",
            Epoch {
                version: "0.1.0".to_owned(),
                build: None,
                engines: BTreeMap::new(),
                sampling: "1.0".to_owned(),
            },
            WhenFull::Open,
            Bounds {
                bytes: 64 * 1024 * 1024,
                age: std::time::Duration::from_secs(3600),
                segment_bytes: 1024 * 1024,
            },
            permguard_decisions::Commitment::new(*b"a-key-of-at-least-32-bytes-long!!", "v1"),
            Metrics::none(),
        )
        .expect("the journal opens")
    }

    /// Every decision record the spool holds, in order.
    fn recorded(spool: &Path) -> Vec<Value> {
        let mut segments: Vec<PathBuf> = std::fs::read_dir(spool)
            .expect("the spool can be listed")
            .map(|entry| entry.expect("a spool entry").path())
            .filter(|path| path.extension().and_then(std::ffi::OsStr::to_str) == Some("jsonl"))
            .collect();
        segments.sort();
        segments
            .into_iter()
            .flat_map(|path| {
                std::fs::read_to_string(path)
                    .expect("the segment can be read")
                    .lines()
                    .map(|line| serde_json::from_str::<Value>(line).expect("the record is JSON"))
                    .collect::<Vec<_>>()
            })
            .filter(|record| record["kind"] == json!("decision"))
            .collect()
    }

    /// Refused on the wire, recorded in the log: the record says `indeterminate`, not a deny,
    /// cites no policy, and names its cause by code.
    #[tokio::test]
    async fn an_indeterminate_evaluation_is_recorded_as_such() {
        let root = ledger("indeterminate-record");
        let spool = scratch("indeterminate-record-spool");
        let decider = decider_with_journal(&root, journal(&spool));

        let refused = decider
            .decide(&ask("acme", "main-ledger", "alice", "audit"), None)
            .await
            .expect_err("an indeterminate evaluation is refused");
        assert_eq!(
            refused.code(),
            permguard_core::codes::pdp_native::EVALUATION_INDETERMINATE
        );
        drop(decider);

        let records = recorded(&spool);
        assert_eq!(records.len(), 1, "refused on the wire, recorded in the log");
        let record = &records[0];
        assert_eq!(record["outcome"], json!("indeterminate"), "{record}");
        assert_eq!(record["decision"], json!(false), "{record}");
        assert_eq!(
            record["reason"]["code"],
            json!(permguard_core::codes::pdp_native::EVALUATION_INDETERMINATE),
            "{record}"
        );
        assert!(
            record["policies"].as_array().is_some_and(Vec::is_empty),
            "an evaluation that failed cites no policy: {record}"
        );
        assert_eq!(
            record["causes"],
            json!([permguard_core::codes::pdp_native::EVALUATION_FAILED]),
            "the cause travels in evidence, by code: {record}"
        );
    }

    /// A batch refused whole still records every evaluation it reached: the decided one as a
    /// permit, the one nothing could decide as `indeterminate`.
    #[tokio::test]
    async fn a_refused_batch_records_every_evaluation_it_reached() {
        let root = ledger("indeterminate-batch-record");
        let spool = scratch("indeterminate-batch-record-spool");
        let decider = decider_with_journal(&root, journal(&spool));
        let batch: wire::CheckRequest = serde_json::from_value({
            let mut payload = asked("alice", "read");
            payload["evaluations"] = json!([
                {"request_id": "reads"},
                {"request_id": "audits", "action": {"name": "audit"}},
            ]);
            payload
        })
        .expect("the payload parses");

        let refused = decider
            .decide(&batch, None)
            .await
            .expect_err("a batch with an indeterminate evaluation is refused whole");
        assert_eq!(
            refused.code(),
            permguard_core::codes::pdp_native::EVALUATION_INDETERMINATE
        );
        drop(decider);

        let records = recorded(&spool);
        let outcomes: Vec<(&str, &str)> = records
            .iter()
            .map(|record| {
                (
                    record["request_id"].as_str().unwrap_or_default(),
                    record["outcome"].as_str().unwrap_or_default(),
                )
            })
            .collect();
        assert_eq!(
            outcomes,
            [("reads", "permit"), ("audits", "indeterminate")],
            "every evaluation that was decided is still recorded as evidence"
        );
        assert_eq!(records[0]["decision"], json!(true));
        assert!(records[0].get("causes").is_none(), "{}", records[0]);
    }

    /// The batch semantics only decide where a batch stops: `deny_on_first_deny` stops at the
    /// indeterminate evaluation, which is not a permit, and `permit_on_first_permit` refuses a
    /// batch whose indeterminate evaluation comes before its permit — whatever `||` would have
    /// answered.
    #[tokio::test]
    async fn an_indeterminate_evaluation_before_the_stop_refuses_the_batch_under_every_semantic() {
        let root = ledger("indeterminate-semantics");
        let spool = scratch("indeterminate-semantics-spool");
        let decider = decider_with_journal(&root, journal(&spool));
        let batch = |semantic: &str| -> wire::CheckRequest {
            let mut payload = asked("alice", "read");
            payload["options"] = json!({"evaluations_semantic": semantic});
            payload["evaluations"] = json!([
                {"request_id": "audits", "action": {"name": "audit"}},
                {"request_id": "reads"},
            ]);
            serde_json::from_value(payload).expect("the payload parses")
        };

        for semantic in [
            "execute_all",
            "deny_on_first_deny",
            "permit_on_first_permit",
        ] {
            let refused = decider
                .decide(&batch(semantic), None)
                .await
                .expect_err("refused, whatever the semantic would have answered");
            assert_eq!(
                refused.code(),
                permguard_core::codes::pdp_native::EVALUATION_INDETERMINATE,
                "{semantic}"
            );
        }
        drop(decider);

        let reached: Vec<String> = recorded(&spool)
            .iter()
            .map(|record| record["request_id"].as_str().unwrap_or_default().to_owned())
            .collect();
        assert_eq!(
            reached,
            ["audits", "reads", "audits", "audits", "reads"],
            "`execute_all` runs both, `deny_on_first_deny` stops at the indeterminate one, \
             `permit_on_first_permit` runs on to the permit"
        );
    }

    /// A forbid that fired dominates a failure of another policy in the same partition: `200`,
    /// a deny citing the forbid. The failure beside it is counted by cause, and the request's
    /// result is counted as the algebra's own — while a request the failure alone decides is
    /// counted `indeterminate`.
    #[tokio::test]
    async fn a_forbid_beside_a_failure_is_a_deny_and_both_are_counted_apart() {
        let root = scratch("indeterminate-forbid").join("mirrors");
        provision(
            &root,
            "acme",
            "main-ledger",
            &manifest(&[("app", "cedar", false)], ">=0.0.0"),
            &[(
                "app",
                vec![&CEDAR_READ, &CEDAR_CLEARANCE, &CEDAR_NOT_BOB],
                None,
            )],
        );
        let registry = Arc::new(permguard_std::metrics::Registry::new());
        let spool = scratch("indeterminate-forbid-spool");
        let decider = Arc::new(
            Decider::new(
                root.clone(),
                Arc::new(Cache::new(64, 8 * 1024 * 1024)),
                Metrics::new(Arc::clone(&registry) as Arc<dyn Recorder>),
                None,
                256,
            )
            .with_journal(
                Some(Arc::new(journal(&spool))),
                None,
                permguard_core::decisions::IncludeSection::default(),
            ),
        );

        let denied = decider
            .decide(&ask("acme", "main-ledger", "bob", "audit"), None)
            .await
            .expect("a deny a forbid determined is a decision");
        assert!(!denied.decision);
        let context = denied.context.expect("a context");
        assert_eq!(context.policies, ["01a0-cedar-not-bob".to_owned()]);
        assert_eq!(
            context.reason_admin.expect("a reason").code,
            "403",
            "a policy deny, not an indeterminate result"
        );

        decider
            .decide(&ask("acme", "main-ledger", "alice", "audit"), None)
            .await
            .expect_err("the failure alone is indeterminate");
        decider
            .decide(&ask("acme", "main-ledger", "alice", "write"), None)
            .await
            .expect("nothing permits a write");

        let counted = |name: &str, label: (&str, &str)| -> f64 {
            registry
                .snapshot()
                .into_iter()
                .filter(|sample| sample.metric.name() == name)
                .filter(|sample| {
                    sample
                        .labels
                        .iter()
                        .any(|(key, value)| key == label.0 && value == label.1)
                })
                .map(|sample| match sample.reading {
                    permguard_core::metrics::Reading::Value(value) => value,
                    permguard_core::metrics::Reading::Distribution { sum, .. } => sum,
                })
                .sum()
        };
        for (outcome, expected) in [
            ("deny", 1.0),
            ("indeterminate", 1.0),
            ("deny_by_default", 1.0),
            ("permit", 0.0),
        ] {
            assert_eq!(
                counted("permguard_authz_decisions_total", ("outcome", outcome)),
                expected,
                "decisions_total{{outcome={outcome}}}"
            );
        }
        assert_eq!(
            counted(
                "permguard_authz_partition_failures_total",
                (
                    "reason",
                    permguard_core::codes::pdp_native::EVALUATION_FAILED
                )
            ),
            2.0,
            "the failure beside the deny and the one that decided are both counted"
        );

        // The deny is recorded as a policy deny: its failure is no cause of it.
        drop(decider);
        let records = recorded(&spool);
        assert_eq!(records[0]["outcome"], json!("deny"), "{}", records[0]);
        assert!(records[0].get("causes").is_none(), "{}", records[0]);
        assert_eq!(
            records[1]["outcome"],
            json!("indeterminate"),
            "{}",
            records[1]
        );
        assert_eq!(
            records[1]["causes"],
            json!([permguard_core::codes::pdp_native::EVALUATION_FAILED])
        );
    }
}
