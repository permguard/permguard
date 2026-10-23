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
use permguard_data_plane::authz::{block, wire};

/// The decision routes behind the authentication boundary every served surface has (WP-2.4):
/// nobody presents a credential here, so every request is anonymous and the permissive
/// authorization admits it. These tests are about deciding, not about who may ask.
mod http {
    pub use permguard_data_plane::authz::http::Surface;

    pub fn routes(surface: Surface) -> axum::Router {
        permguard_data_plane::authz::http::routes(surface).layer(
            permguard_transport::ActorLayer::new(std::sync::Arc::new(permguard_core::NoRules)),
        )
    }
}

/// A gRPC request as the boundary would hand it on: anonymous.
fn anonymous_request<T>(inner: T) -> tonic::Request<T> {
    let mut request = tonic::Request::new(inner);
    request
        .extensions_mut()
        .insert(std::sync::Arc::new(permguard_core::authz::Actor::Anonymous));
    request
}

fn anonymous_interceptor(
    mut request: tonic::Request<()>,
) -> Result<tonic::Request<()>, tonic::Status> {
    request
        .extensions_mut()
        .insert(std::sync::Arc::new(permguard_core::authz::Actor::Anonymous));
    Ok(request)
}

/// The interceptor a served surface's boundary stands in for.
type Anonymising = fn(tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status>;

/// The decision service behind its boundary.
type ServedPdp = tonic::service::interceptor::InterceptedService<
    permguard_data_plane::v1::policy_decision_point_server::PolicyDecisionPointServer<
        permguard_data_plane::authz::grpc::PdpApi,
    >,
    Anonymising,
>;

/// The decision service as a surface serves it: behind the boundary, every request anonymous.
fn served(api: permguard_data_plane::authz::grpc::PdpApi) -> ServedPdp {
    permguard_data_plane::v1::policy_decision_point_server::PolicyDecisionPointServer::with_interceptor(
        api,
        anonymous_interceptor as Anonymising,
    )
}

/// Everything allowed: these tests are about deciding, not about who may ask.
fn permissive() -> Arc<permguard_host::composition::Authorization> {
    Arc::new(permguard_host::composition::Authorization::permissive())
}
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
                interfaces: Vec::new(),
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
    let path = root.join(uuid_of(zone)).join(uuid_of(ledger));
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
            ref_digest: None,
            // The Host and ref the head statement vouched for (WP-6.6b).
            authority_host_id: Some(AUTHORITY.to_owned()),
            reference: Some("main".to_owned()),
        },
    )
    .expect("the checkpoint is written");

    let identity = Identity {
        zone_id: uuid_of(zone),
        zone_name: zone.to_owned(),
        ledger_id: uuid_of(ledger),
        ledger_name: ledger.to_owned(),
        server: "http://127.0.0.1:6443".to_owned(),
    };
    permguard_data_plane::authz::store::record(&path, &identity).expect("the identity is recorded");

    Mirror { path, identity }
}

/// A zone or ledger id as the catalog mints it, a UUIDv7, derived from `name` so a test can name
/// it again: zone keys are keyed by ids of 16 bytes (WP-3.3).
/// The Host whose head statement every provisioned ledger carries.
const AUTHORITY: &str = "01937000-0000-7000-8000-00000000a0a0";

fn uuid_of(name: &str) -> String {
    use std::hash::{Hash as _, Hasher as _};
    let mut bytes = [0u8; 16];
    for (half, salt) in [(0usize, 0u8), (8, 1)] {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        (salt, name).hash(&mut hasher);
        bytes[half..half + 8].copy_from_slice(&hasher.finish().to_be_bytes());
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// The zone's shared pseudonyms, as the Host's coordinator holds them (WP-3.3).
fn subjects() -> Option<Arc<permguard_host::secrets::ZoneHandle>> {
    let coordinator = permguard_host::secrets::Coordinator::new(
        permguard_host::secrets::Root::from_material(
            &[0x5a; 32],
            permguard_host::secrets::KeyVersion::new(1).expect("v1"),
        )
        .expect("a root"),
        [1; 16],
    );
    Some(Arc::new(permguard_host::secrets::ZoneHandle::coordinated(
        permguard_host::secrets::ZonePurpose::AuditPseudonym,
        coordinator,
    )))
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
            subjects(),
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
    let schema = "entity user;\nentity document;\naction read appliesTo { principal: [user], resource: [document] };\n";

    // A typed partition that names no interfaces relies on the inference, refused from
    // `production` (`interfaces.explicit`, WP-7.1) and served below it.
    let implicit_root = scratch("floor-implicit").join("mirrors");
    provision(
        &implicit_root,
        "acme",
        "main-ledger",
        &manifest(&[("app", "cedar", true)], ">=0.0.0"),
        &[("app", vec![&CEDAR_READ], Some(schema))],
    );
    let implicit = |profile| {
        Decider::new(
            implicit_root.clone(),
            Arc::new(Cache::new(64, 8 * 1024 * 1024)),
            Metrics::none(),
            None,
            256,
        )
        .with_profile(profile)
    };
    let refused = implicit(AssuranceProfile::Production)
        .decide(&ask("acme", "main-ledger", "alice", "read"), None)
        .await
        .expect_err("the inference is refused under production");
    assert!(
        refused.to_string().contains("interfaces.explicit"),
        "{refused:?}"
    );
    assert!(
        implicit(AssuranceProfile::Development)
            .decide(&ask("acme", "main-ledger", "alice", "read"), None)
            .await
            .expect("development infers them")
            .decision
    );

    let mut typed = manifest(&[("app", "cedar", true)], ">=0.0.0");
    // From `production` a partition names its interfaces (`interfaces.explicit`, WP-7.1).
    for partition in typed.partitions.values_mut() {
        partition.interfaces = vec![permguard_objects::manifest::PROFILE_PDP_NATIVE_V1.to_owned()];
    }
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

/// REGO-03: from `production` a Rego partition runs only in its supervised worker. With no
/// worker able to start, the partition is refused — never compiled in-process instead — and the
/// refusal is not written down against the ledger; under `development` it is served in-process.
#[cfg(unix)]
#[tokio::test]
async fn a_rego_partition_runs_isolated_from_production_or_not_at_all() {
    use permguard_core::assurance::AssuranceProfile;
    use permguard_languages::worker::{Limits, Supervisors};

    let root = scratch("isolated").join("mirrors");
    let manifest = manifest(&[("app", "rego", false)], ">=0.0.0");
    let mirror = provision(
        &root,
        "acme",
        "main-ledger",
        &manifest,
        &[("app", vec![&REGO_READ], None)],
    );
    let nowhere = Arc::new(Supervisors::with_executable(
        PathBuf::from("/nonexistent/permguard-worker"),
        Vec::new(),
        Limits::default(),
        1,
    ));
    let under = |profile| {
        Arc::new(
            Decider::new(
                root.clone(),
                Arc::new(Cache::new(64, 8 * 1024 * 1024)),
                Metrics::none(),
                None,
                256,
            )
            .with_profile(profile)
            .with_supervisors(Arc::clone(&nowhere)),
        )
    };

    let refused = under(AssuranceProfile::Production)
        .decide(&ask("acme", "main-ledger", "alice", "list"), None)
        .await
        .expect_err("no worker, no in-process fallback");
    assert_eq!(refused.code(), "ledger_incompatible");
    assert!(
        block::read(&mirror.path).is_none(),
        "a worker that could not start is not the ledger's fault"
    );
    assert!(
        under(AssuranceProfile::Development)
            .decide(&ask("acme", "main-ledger", "alice", "list"), None)
            .await
            .expect("development evaluates in process")
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
        .decide(
            &ask(&uuid_of("acme"), &uuid_of("main-ledger"), "alice", "read"),
            None,
        )
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
    // WP-3.3: the subject is the zone's shared pseudonym, the same on every replica holding the
    // zone's key, and never the identifier.
    let zone = permguard_host::secrets::parse_uuid(&uuid_of("acme")).expect("a UUID");
    let expected = subjects()
        .expect("a handle")
        .pseudonym(&zone, "subject", "alice")
        .expect("a pseudonym");
    assert_eq!(decisions[0]["subject"]["id"], json!(expected));
    assert!(expected.starts_with("v1:"), "{expected}");
}

/// WP-3.3: a decision whose subject cannot be pseudonymised under its zone's key is never
/// recorded raw: a closed journal refuses to answer it.
#[tokio::test]
async fn a_subject_without_its_zone_key_is_never_recorded_raw() {
    let root = scratch("decision-no-zone-key").join("mirrors");
    provision(
        &root,
        "acme",
        "main-ledger",
        &manifest(&[("app", "cedar", false)], ">=0.0.0"),
        &[("app", vec![&CEDAR_READ], None)],
    );
    let spool = scratch("decision-no-zone-key-spool");
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
    let decider = Arc::new(
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
    );
    let refused = decider
        .decide(&ask("acme", "main-ledger", "alice", "read"), None)
        .await
        .expect_err("unrecordable");
    assert!(refused.to_string().contains("pseudonym key"), "{refused}");
    drop(decider);
    for entry in std::fs::read_dir(&spool).expect("the spool can be listed") {
        let path = entry.expect("an entry").path();
        if path.extension().and_then(std::ffi::OsStr::to_str) == Some("jsonl") {
            let text = std::fs::read_to_string(path).expect("read");
            assert!(!text.contains("alice"), "{text}");
        }
    }
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
    let path = root.join(uuid_of("acme")).join(uuid_of("main-ledger"));
    std::fs::create_dir_all(&path).expect("the directory exists");
    permguard_data_plane::authz::store::record(
        &path,
        &Identity {
            zone_id: uuid_of("acme"),
            zone_name: "acme".to_owned(),
            ledger_id: uuid_of("main-ledger"),
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

/// WP-7.5a, IFACE-03: what a warm compiled is what the first request finds. The warm keys each
/// partition by the interfaces it promises, or its runtime's for a legacy partition promising
/// none, and a decide by its profile's interface, the legacy spelling read as the native one:
/// both sides name the same entry, so no request compiles again.
#[tokio::test]
async fn a_warmed_partition_is_what_the_first_request_finds() {
    let root = scratch("warm-then-decide").join("mirrors");
    let mut manifest = manifest(
        &[("app", "cedar", false), ("gateway", "rego", false)],
        ">=0.0.0",
    );
    // One partition promises its interface, the other is the legacy inference.
    manifest
        .partitions
        .get_mut("gateway")
        .expect("declared")
        .interfaces = vec![permguard_objects::manifest::PROFILE_PDP_NATIVE_V1.to_owned()];
    // And a profile spelled the legacy way, asking the same interface.
    manifest.profiles.insert(
        "legacy".to_owned(),
        Profile {
            r#type: permguard_objects::manifest::PROFILE_PDP_V1.to_owned(),
            partitions: vec!["app".to_owned(), "gateway".to_owned()],
        },
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
    let registry = Arc::new(permguard_std::metrics::Registry::new());
    let decider = Decider::new(
        root.clone(),
        Arc::new(Cache::new(64, 8 * 1024 * 1024)),
        Metrics::new(Arc::clone(&registry) as Arc<dyn Recorder>),
        None,
        256,
    );
    // The compilations the decision path made: a request that finds the warm's entry makes none.
    let compiled = || -> f64 {
        registry
            .snapshot()
            .into_iter()
            .filter(|sample| sample.metric.name() == "permguard_authz_compilations_total")
            .map(|sample| match sample.reading {
                permguard_core::metrics::Reading::Value(value) => value,
                permguard_core::metrics::Reading::Distribution { sum, .. } => sum,
            })
            .sum()
    };
    assert_eq!(decider.warm(&mirror), Warmed::Ready { compiled: 2 });
    let warmed = compiled();

    for profile in ["default", "legacy"] {
        let mut request = ask("acme", "main-ledger", "alice", "read");
        request.profile = Some(profile.to_owned());
        decider.decide(&request, None).await.expect("decided");
        assert_eq!(
            compiled(),
            warmed,
            "`{profile}` found what the warm compiled, and compiled nothing of its own"
        );
    }
    // Two partitions and the head the requests loaded: no partition kept twice.
    assert_eq!(decider.cache().holdings().0, 3);
}

/// The HTTP surface, over the real router.
mod surface {
    use super::*;

    fn router(root: &Path) -> axum::Router {
        http::routes(http::Surface {
            authorization: permissive(),
            decider: decider(root),
            disclosure: Disclosure::Full,
            base_url: "http://127.0.0.1:7443".to_owned(),
            describer: permguard_core::stages::Describer::detached("data-plane"),
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
            authorization: permissive(),
            decider: decider(root),
            disclosure: Disclosure::Full,
            base_url: format!("http://{address}"),
            describer: permguard_core::stages::Describer::detached("data-plane"),
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
                    .add_service(served(api))
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
            &permguard_data_plane::authz::configuration::document(
                base,
                permguard_core::stages::Describer::detached("data-plane")
                    .header(permguard_core::domains::interface::PDP_NATIVE_V1)
                    .expect("served"),
                256,
                None,
            )
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

    /// WP-6.6a: the evidence object crosses gRPC as the REST answer writes it, and a nonce is
    /// refused over both while nothing signs.
    #[test]
    fn the_evidence_and_the_nonce_refusal_are_the_same_over_both_transports() {
        let root = scratch("grpc-evidence").join("mirrors");
        provision(
            &root,
            "acme",
            "main-ledger",
            &manifest(&[("app", "cedar", false)], ">=0.0.0"),
            &[("app", vec![&CEDAR_READ], None)],
        );
        let url = serve(&root);
        let client = permguard_control_client::pdp::client(
            &url,
            &permguard_control_client::tls::TlsOptions::default(),
            Box::new(permguard_control_client::narrate::Silent),
        )
        .expect("the endpoint parses");
        let body = json!({
            "zone": "acme", "ledger": "main-ledger",
            "subject": {"type": "user", "id": "alice"},
            "resource": {"type": "document", "id": "budget"},
            "action": {"name": "read"},
        });
        let over_grpc = client.evaluate(&body).expect("the plane answers");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let over_http = |body: Value| {
            let root = root.clone();
            runtime.block_on(async move {
                crate::surface::post(&root, "/access/v1/evaluation", body).await
            })
        };
        let (_, http_answer, _) = over_http(body.clone());
        assert_eq!(
            over_grpc["context"]["evidence"],
            json!({"mode": "disabled", "status": "disabled", "record_id": null, "position": null})
        );
        assert_eq!(
            over_grpc["context"]["evidence"], http_answer["context"]["evidence"],
            "one object, whichever transport"
        );

        let mut signed = body;
        signed["request_nonce"] = json!("AAECAwQFBgcICQoLDA0ODw");
        let refused = client.evaluate(&signed).expect_err("nothing signs");
        assert_eq!(
            (refused.class.as_str(), refused.reason.as_str()),
            ("unavailable", "response_signing_unavailable"),
            "{refused}"
        );
        let (status, http_refused, _) = over_http(signed);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(http_refused["code"], "response_signing_unavailable");
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
                authorization: permissive(),
                decider: decider.clone(),
                disclosure: Disclosure::Full,
                base_url: base_url.clone(),
                describer: permguard_core::stages::Describer::detached("data-plane"),
            }),
            tonic::service::Routes::new(served(PdpApi {
                authorization: permissive(),
                decider,
                disclosure: Disclosure::Full,
                base_url,
                describer: permguard_core::stages::Describer::detached("data-plane"),
            })),
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
            authorization: permissive(),
            decider: decider(&root),
            disclosure: Disclosure::Full,
            base_url: "http://127.0.0.1:7443".to_owned(),
            describer: permguard_core::stages::Describer::detached("data-plane"),
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
                .evaluate(anonymous_request(request))
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
                zone_id: uuid_of("acme"),
                zone_name: ZONE.to_owned(),
                ledger_id: uuid_of("main"),
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
                subjects(),
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
                authorization: permissive(),
                decider: decider.clone(),
                disclosure: Disclosure::Full,
                base_url: base_url.clone(),
                describer: permguard_core::stages::Describer::detached("data-plane"),
            }),
            tonic::service::Routes::new(served(PdpApi {
                authorization: permissive(),
                decider,
                disclosure: Disclosure::Full,
                base_url,
                describer: permguard_core::stages::Describer::detached("data-plane"),
            })),
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
                authorization: permissive(),
                decider: decider.clone(),
                disclosure: Disclosure::Full,
                base_url: base_url.clone(),
                describer: permguard_core::stages::Describer::detached("data-plane"),
            }),
            tonic::service::Routes::new(served(PdpApi {
                authorization: permissive(),
                decider,
                disclosure: Disclosure::Full,
                base_url,
                describer: permguard_core::stages::Describer::detached("data-plane"),
            })),
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
                subjects(),
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

/// The decision log on the Host's stream producer (WP-6.1): a volume with its identity, its
/// `host.operations` and `data.attest` rings and the engine's decision producer.
mod host_log {
    use std::sync::Arc;
    use std::time::Duration;

    use permguard_core::Metrics;
    use permguard_core::assurance::AssuranceProfile;
    use permguard_core::authz::{Resource, Selector};
    use permguard_data_plane::decisions::host::Bounds;
    use permguard_data_plane::decisions::journal::Epoch;
    use permguard_data_plane::decisions::{Decided, HostLog, Written};
    use permguard_decisions::record::{GENESIS, digest_of};
    use permguard_decisions::stream::{Codec, STREAM};
    use permguard_host::composition::{Declaration, Host, Subscribed};
    use permguard_host::identity::{Identity, Suite, directories};
    use permguard_host::keys::FileKeyProvider;
    use permguard_host::keys::ring::{DATA_ATTEST, HOST_OPERATIONS, Policy, Ring};
    use permguard_host::membership::record::TaskType;
    use permguard_host::storage::volume::Volume;
    use permguard_host::time::TimeGuard;
    use permguard_stream::engine::{Producer, Served, Streams};
    use serde_json::{Value, json};

    pub(super) struct HostStream {
        volume: Volume,
        identity: Arc<Identity>,
        operations: Arc<Ring>,
        attest: Arc<Ring>,
        time: Arc<TimeGuard>,
    }

    impl HostStream {
        pub(super) fn new(tag: &str) -> Self {
            let root = super::scratch(tag);
            std::fs::create_dir_all(&root).expect("a volume directory");
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
                volume,
                identity,
                operations,
                attest,
                time,
            }
        }

        /// The engine's decision producer on this volume, sealing under `data.attest`.
        pub(super) fn producer(&self) -> Arc<Producer<Codec>> {
            Arc::new(
                Streams::open(
                    &self.volume,
                    &self.identity,
                    Arc::clone(&self.operations),
                    Arc::clone(&self.time),
                )
                .expect("the engine opens")
                .register_producer(permguard_decisions::stream::descriptor(), Codec)
                .expect("registered")
                .with_signer(Arc::clone(&self.attest))
                .expect("the descriptor's ring"),
            )
        }

        /// The log a data plane composed on this Host records with, appending to `producer`.
        pub(super) fn log(&self, producer: &Arc<Producer<Codec>>, bounds: Bounds) -> HostLog {
            let registration = Host::builder()
                .streams(Arc::new(
                    Served::default().with(STREAM, Arc::clone(producer)),
                ))
                .host_id(self.identity.host_id())
                .build()
                .register(Declaration::new("data").produces_stream(STREAM))
                .expect("registers");
            HostLog::new(
                registration
                    .stream_producer(STREAM)
                    .expect("declared")
                    .expect("composed"),
                self.identity.host_id(),
                Epoch {
                    version: "0.1.0".to_owned(),
                    build: None,
                    engines: std::collections::BTreeMap::new(),
                    sampling: "1.0".to_owned(),
                },
                permguard_decisions::Commitment::new(*b"a-key-of-at-least-32-bytes-long!!", "v1"),
                bounds,
                Metrics::none(),
            )
        }

        /// The `data.attest` ring, which signs responses as it signs batches (WP-6.6b).
        pub(super) fn attest(&self) -> Arc<Ring> {
            Arc::clone(&self.attest)
        }

        pub(super) fn host_hex(&self) -> String {
            hex(&self.identity.host_id())
        }
    }

    pub(super) const LOOSE: Bounds = Bounds {
        max_bytes: 1 << 30,
        max_age_secs: 3600,
    };

    pub(super) fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    pub(super) fn ledger(zone_id: &str, ledger_id: &str) -> Resource {
        Resource::ledger("data", zone_id, ledger_id)
    }

    /// Every record of `resource`'s stream, in order, from sequence 1 of the current run.
    pub(super) fn records(producer: &Producer<Codec>, resource: &Resource) -> Vec<(u64, Value)> {
        producer
            .read(resource, 1, 1000)
            .expect("the stream reads")
            .records
    }

    /// A subscription of a coordinator's `decisions.ship` task covering `selector`.
    pub(super) fn shipping(selector: &Selector) -> Subscribed<'_> {
        Subscribed {
            membership_id: [7; 16],
            task_type: TaskType::DecisionsShip,
            task_id: "decisions",
            required: true,
            epoch: 1,
            selector,
        }
    }

    fn decided(id: &str, permit: bool) -> Decided<'_> {
        Decided {
            id,
            at: "2026-10-18T10:00:00Z".to_owned(),
            zone: "acme",
            ledger: "main-ledger",
            zone_id: "zone-1",
            ledger_id: "ledger-1",
            scope: None,
            commit: "sha256:ec1773bf",
            counter: 3,
            profile: "default",
            subject: ("User".to_owned(), "v1:9f2c".to_owned()),
            subject_properties: None,
            resource: ("Document".to_owned(), "budget".to_owned()),
            resource_properties: None,
            included_context: None,
            action: "read".to_owned(),
            principal: None,
            context: Some(json!({"ip": "10.0.0.1"})),
            partition_inputs: None,
            absent_inputs: Vec::new(),
            permit,
            outcome: if permit {
                permguard_decisions::record::Outcome::Permit
            } else {
                permguard_decisions::record::Outcome::Deny
            },
            causes: Vec::new(),
            policies: vec!["read".to_owned()],
            reason: if permit { "permit" } else { "deny" }.to_owned(),
            trace: None,
            request_id: None,
            latency_us: 12,
            event: None,
        }
    }

    /// WP-6.1, F-06 and F-09: a record names the Host and its run, at the engine's sequence and
    /// chained by the engine's digests; the first one this process writes to a run is preceded by
    /// its marker, and the chain verifies as a version 1 stream.
    #[test]
    fn a_decision_names_the_host_and_its_run() {
        let host = HostStream::new("host-log-names");
        let producer = host.producer();
        let log = host.log(&producer, LOOSE);
        assert_eq!(
            log.record(&decided("d-1", false)).expect("recorded"),
            Written::Recorded { seq: 2 },
            "after the marker governing it"
        );
        assert_eq!(
            log.record(&decided("d-2", true)).expect("recorded"),
            Written::Recorded { seq: 3 },
            "one marker per run"
        );
        let resource = ledger("zone-1", "ledger-1");
        let run = producer
            .state(&resource)
            .expect("state")
            .expect("a run")
            .run_id;
        let records = records(&producer, &resource);
        let values: Vec<Value> = records.iter().map(|(_, value)| value.clone()).collect();
        assert_eq!(
            records.iter().map(|(seq, _)| *seq).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        for (seq, record) in &records {
            assert_eq!(record["seq"], json!(seq), "the engine's sequence");
            assert_eq!(
                record["stream"]["id"],
                json!(host.host_hex()),
                "the host_id"
            );
            assert_eq!(record["stream"]["instance"], json!(hex(&run)), "the run");
        }
        assert_eq!(values[0]["kind"], json!("marker"));
        assert_eq!(values[0]["commitments"]["key_version"], json!("v1"));
        assert_eq!(values[0]["prev"], json!(GENESIS));
        assert_eq!(values[1]["kind"], json!("decision"));
        assert_eq!(values[1]["id"], json!("d-1"));
        assert_eq!(
            values[1]["store"]["zone"],
            json!("acme"),
            "the public names"
        );
        assert_eq!(
            values[1]["prev"],
            json!(digest_of(&values[0]).expect("a digest"))
        );
        assert_eq!(
            values[2]["prev"],
            json!(digest_of(&values[1]).expect("a digest"))
        );
        assert!(
            values[1]["inputs"]["context"]
                .as_str()
                .is_some_and(|tag| !tag.contains("10.0.0.1")),
            "the input is tagged, never kept"
        );
        let verified = permguard_decisions::chain::verify(&values, None).expect("the chain holds");
        assert_eq!(verified.last_seq, 3);
        assert!(
            values.iter().all(|value| value.get("pdp_id").is_none()),
            "no producer id"
        );
    }

    /// WP-6.1: a run the engine rolls over to starts at sequence 1 with its own marker, and so
    /// does the first decision a restarted process writes, in the run it resumes.
    #[test]
    fn a_marker_heads_every_run() {
        let host = HostStream::new("host-log-runs");
        let resource = ledger("zone-1", "ledger-1");
        let producer = host.producer();
        let log = host.log(&producer, LOOSE);
        log.record(&decided("d-1", false)).expect("recorded");
        let successor = producer.rollover(&resource, None).expect("rolled over");
        assert_eq!(
            log.record(&decided("d-2", false)).expect("recorded"),
            Written::Recorded { seq: 2 }
        );
        let records = records(&producer, &resource);
        assert_eq!(records[0].1["kind"], json!("marker"));
        assert_eq!(records[0].1["prev"], json!(GENESIS));
        assert_eq!(
            records[0].1["stream"]["instance"],
            json!(hex(&successor.run_id))
        );
        assert_eq!(records[1].1["id"], json!("d-2"));
        // A restart: the same Host resumes the same run, its first record a marker.
        drop(log);
        drop(producer);
        let producer = host.producer();
        let log = host.log(&producer, LOOSE);
        assert_eq!(
            log.record(&decided("d-3", false)).expect("recorded"),
            Written::Recorded { seq: 4 }
        );
        let records = super::host_log::records(&producer, &resource);
        assert_eq!(records.len(), 4);
        assert_eq!(records[2].1["kind"], json!("marker"));
        assert_eq!(
            records[3].1["stream"]["instance"],
            json!(hex(&successor.run_id))
        );
        assert_eq!(records[3].1["stream"]["id"], json!(host.host_hex()));
        permguard_decisions::chain::verify(
            &records
                .into_iter()
                .map(|(_, value)| value)
                .collect::<Vec<_>>(),
            None,
        )
        .expect("one chain across the restart");
    }

    /// WP-6.1: a stream holding past its bounds what its required subscription has not
    /// acknowledged refuses its decisions, writing nothing; with no subscription nothing is owed
    /// and no bound is ever reached; a denial is never sampled out.
    #[test]
    fn the_bounds_measure_only_what_a_required_subscription_owes() {
        let host = HostStream::new("host-log-pressure");
        let resource = ledger("zone-1", "ledger-1");
        let producer = host.producer();
        let tight = Bounds {
            max_bytes: 1,
            max_age_secs: 3600,
        };
        let log = host.log(&producer, tight);
        for n in 0..5 {
            assert!(matches!(
                log.record(&decided(&format!("free-{n}"), false))
                    .expect("recorded"),
                Written::Recorded { .. }
            ));
            log.measure();
        }
        // A coordinator's required subscription attaches: the run is fenced by it, and what it has
        // not acknowledged counts.
        let covering = Selector::under(Resource::plane("data"));
        permguard_host::composition::StreamShipping::due(producer.as_ref(), &shipping(&covering))
            .expect("due");
        assert!(matches!(
            log.record(&decided("owed", false)).expect("recorded"),
            Written::Recorded { .. }
        ));
        log.measure();
        let before = producer.state(&resource).expect("state").expect("a run");
        assert_eq!(
            log.record(&decided("refused", false)).expect("answered"),
            Written::Refused(permguard_core::codes::stream::SPOOL_FULL.to_owned())
        );
        let after = producer.state(&resource).expect("state").expect("a run");
        assert_eq!(after.next_seq, before.next_seq, "nothing written");
    }

    /// An engine whose stream cannot say its pressure, or cannot append: what a damaged volume
    /// answers.
    struct Failing {
        pressure: bool,
    }

    impl permguard_host::composition::StreamAppender for Failing {
        fn append(
            &self,
            _: &Resource,
            _: &[u8],
        ) -> Result<permguard_host::composition::StreamReceipt, String> {
            Err("the stream stopped".to_owned())
        }

        fn append_with(
            &self,
            _: &Resource,
            _: permguard_host::composition::BuildRecords<'_>,
        ) -> Result<permguard_host::composition::StreamReceipt, String> {
            Err("the stream stopped".to_owned())
        }

        fn pressure(&self, _: &Resource, _: u64, _: u64) -> Result<Option<&'static str>, String> {
            if self.pressure {
                Err("the journal does not read".to_owned())
            } else {
                Ok(None)
            }
        }
    }

    impl permguard_host::composition::StreamEngine for Failing {
        fn producer(
            &self,
            _: &str,
        ) -> Option<Arc<dyn permguard_host::composition::StreamAppender>> {
            Some(Arc::new(Failing {
                pressure: self.pressure,
            }))
        }
    }

    fn failing_log(pressure: bool) -> HostLog {
        let registration = Host::builder()
            .streams(Arc::new(Failing { pressure }))
            .build()
            .register(Declaration::new("data").produces_stream(STREAM))
            .expect("registers");
        HostLog::new(
            registration
                .stream_producer(STREAM)
                .expect("declared")
                .expect("composed"),
            [1; 16],
            Epoch {
                version: "0.1.0".to_owned(),
                build: None,
                engines: std::collections::BTreeMap::new(),
                sampling: "1.0".to_owned(),
            },
            permguard_decisions::Commitment::new(*b"a-key-of-at-least-32-bytes-long!!", "v1"),
            LOOSE,
            Metrics::none(),
        )
    }

    /// WP-6.1: fail closed: a stream whose pressure cannot be measured refuses its decisions, and
    /// an append the engine refuses is an error, never a decision recorded.
    #[test]
    fn a_stream_that_cannot_be_measured_or_written_records_nothing() {
        assert_eq!(
            failing_log(true)
                .record(&decided("unmeasured", false))
                .expect("answered"),
            Written::Refused(permguard_core::codes::stream::STORE_UNAVAILABLE.to_owned())
        );
        assert!(
            failing_log(false)
                .record(&decided("unwritten", false))
                .is_err()
        );
        // A permit sampled out writes nothing and says so; a denial is never sampled.
        let host = HostStream::new("host-log-sampling");
        let producer = host.producer();
        let registration = Host::builder()
            .streams(Arc::new(
                Served::default().with(STREAM, Arc::clone(&producer)),
            ))
            .build()
            .register(Declaration::new("data").produces_stream(STREAM))
            .expect("registers");
        let never = HostLog::new(
            registration
                .stream_producer(STREAM)
                .expect("declared")
                .expect("composed"),
            [1; 16],
            Epoch {
                version: "0.1.0".to_owned(),
                build: None,
                engines: std::collections::BTreeMap::new(),
                sampling: "0.0".to_owned(),
            },
            permguard_decisions::Commitment::new(*b"a-key-of-at-least-32-bytes-long!!", "v1"),
            LOOSE,
            Metrics::none(),
        );
        assert_eq!(
            never.record(&decided("p", true)).expect("answered"),
            Written::SampledOut
        );
        assert_eq!(
            never.record(&decided("d", false)).expect("answered"),
            Written::Recorded { seq: 2 }
        );
    }

    /// WP-6.1, after the review: a record past the stream's bound is refused before it takes a
    /// sequence, and leaves the run unmarked: the next record still follows its marker.
    #[test]
    fn a_refused_record_leaves_the_run_unmarked() {
        let host = HostStream::new("host-log-oversize");
        let producer = host.producer();
        let log = host.log(&producer, LOOSE);
        let mut oversize = decided("oversize", false);
        oversize.included_context = Some(serde_json::Map::from_iter([(
            "blob".to_owned(),
            json!("x".repeat(300 * 1024)),
        )]));
        assert!(log.record(&oversize).is_err(), "past the stream's bound");
        assert_eq!(
            log.record(&decided("next", false)).expect("recorded"),
            Written::Recorded { seq: 2 }
        );
        let records = records(&producer, &ledger("zone-1", "ledger-1"));
        assert_eq!(records[0].1["kind"], json!("marker"));
        assert_eq!(records[1].1["id"], json!("next"));
    }

    /// WP-6.1, F-12: under concurrent decisions, every one recorded is answered with its durable
    /// sequence, each sequence once, and each is on disk after the stream is reopened.
    #[test]
    fn every_recorded_decision_is_durable_at_its_sequence() {
        let host = HostStream::new("host-log-durable");
        let resource = ledger("zone-1", "ledger-1");
        let producer = host.producer();
        let log = Arc::new(host.log(&producer, LOOSE));
        let threads: Vec<_> = (0..8)
            .map(|thread| {
                let log = Arc::clone(&log);
                std::thread::spawn(move || {
                    (0..25)
                        .map(|n| {
                            let id = format!("{thread}-{n}");
                            match log.record(&decided(&id, false)).expect("recorded") {
                                Written::Recorded { seq } => (seq, id),
                                other => panic!("{other:?}"),
                            }
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let mut answered: Vec<(u64, String)> = threads
            .into_iter()
            .flat_map(|thread| thread.join().expect("the thread"))
            .collect();
        answered.sort();
        drop(log);
        drop(producer);
        let producer = host.producer();
        let records = records(&producer, &resource);
        assert_eq!(records.len(), 201, "the marker and 200 decisions");
        for (seq, id) in &answered {
            let (held, record) = &records[(*seq - 1) as usize];
            assert_eq!(held, seq);
            assert_eq!(record["id"], json!(id), "answered at the sequence it holds");
        }
    }
}

/// WP-6.1, F-12: saturating a `required` log refuses decisions `unavailable` with
/// `decision_unrecordable`, and every decision answered has its durable record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_saturated_required_log_refuses_with_unavailable_and_every_answer_is_recorded() {
    let root = scratch("host-log-saturated").join("mirrors");
    provision(
        &root,
        "acme",
        "main-ledger",
        &manifest(&[("app", "cedar", false)], ">=0.0.0"),
        &[("app", vec![&CEDAR_READ], None)],
    );
    let host = host_log::HostStream::new("host-log-saturated-volume");
    let producer = host.producer();
    // The coordinator's required subscription fences the stream once it holds a run.
    let covering =
        permguard_core::authz::Selector::under(permguard_core::authz::Resource::plane("data"));
    let log = Arc::new(host.log(
        &producer,
        permguard_data_plane::decisions::host::Bounds {
            max_bytes: 16 * 1024,
            max_age_secs: 3600,
        },
    ));
    let decider = Arc::new(
        Decider::new(
            root.clone(),
            Arc::new(Cache::new(64, 8 * 1024 * 1024)),
            Metrics::none(),
            None,
            256,
        )
        .with_journal(
            Some(Arc::clone(&log) as Arc<dyn permguard_data_plane::decisions::DecisionRecorder>),
            subjects(),
            permguard_core::decisions::IncludeSection::default(),
        ),
    );
    let resource = host_log::ledger(&uuid_of("acme"), &uuid_of("main-ledger"));
    producer.open_run(&resource, None).expect("a genesis run");
    permguard_host::composition::StreamShipping::due(
        producer.as_ref(),
        &host_log::shipping(&covering),
    )
    .expect("due");
    let mut answered = 0usize;
    let mut refused = 0usize;
    for _ in 0..40 {
        let calls: Vec<_> = (0..8)
            .map(|_| {
                let decider = Arc::clone(&decider);
                tokio::spawn(async move {
                    decider
                        .decide(&ask("acme", "main-ledger", "alice", "read"), None)
                        .await
                })
            })
            .collect();
        for call in calls {
            match call.await.expect("the call") {
                Ok(_) => answered += 1,
                Err(error) => {
                    assert_eq!(error.code(), "decision_unrecordable", "{error}");
                    assert_eq!(error.class(), permguard_core::ErrorClass::Unavailable);
                    refused += 1;
                }
            }
        }
        let measured = Arc::clone(&log);
        tokio::task::spawn_blocking(move || measured.measure())
            .await
            .expect("measured");
    }
    assert!(answered > 0, "answered before the bound");
    assert!(refused > 0, "refused past it");
    drop(decider);
    drop(log);
    drop(producer);
    let producer = host.producer();
    let recorded = host_log::records(&producer, &resource)
        .iter()
        .filter(|(_, record)| record["kind"] == json!("decision"))
        .count();
    assert_eq!(
        recorded, answered,
        "every answer has its record, and nothing more"
    );
}

/// WP-6.6a: every decision says what became of its record — `disabled` with no log, `durable`
/// with the record's id and its Host position with one, on each boxcarred evaluation and never on
/// the batch's own context — and a request for a signed response is refused before anything is
/// decided or recorded while nothing signs one, a nonce the contract does not define refused as
/// what it is.
#[tokio::test]
async fn every_decision_names_its_evidence_and_a_nonce_is_refused_until_something_signs() {
    use permguard_languages::attestation::{Evidence, EvidenceMode, EvidenceStatus};

    let root = scratch("evidence-object").join("mirrors");
    provision(
        &root,
        "acme",
        "main-ledger",
        &manifest(&[("app", "cedar", false)], ">=0.0.0"),
        &[("app", vec![&CEDAR_READ], None)],
    );

    // No log: nothing promised, and the answer says so.
    let unlogged = decider(&root)
        .decide(&ask("acme", "main-ledger", "alice", "read"), None)
        .await
        .expect("decided");
    let evidence = unlogged
        .context
        .as_ref()
        .and_then(|context| context.evidence.clone())
        .expect("the evidence");
    assert_eq!(evidence, Evidence::disabled());
    evidence
        .check(unlogged.decision)
        .expect("as the contract allows");

    // On the Host's log: the record's id, and where it sits.
    let host = host_log::HostStream::new("evidence-object-volume");
    let producer = host.producer();
    let log = Arc::new(host.log(&producer, host_log::LOOSE));
    let logged = Arc::new(
        Decider::new(
            root.clone(),
            Arc::new(Cache::new(64, 8 * 1024 * 1024)),
            Metrics::none(),
            None,
            256,
        )
        .with_journal(
            Some(Arc::clone(&log) as Arc<dyn permguard_data_plane::decisions::DecisionRecorder>),
            subjects(),
            permguard_core::decisions::IncludeSection::default(),
        ),
    );
    let answered = logged
        .decide(&ask("acme", "main-ledger", "alice", "read"), None)
        .await
        .expect("decided");
    let context = answered.context.expect("a context");
    let evidence = context.evidence.expect("the evidence");
    assert_eq!(
        (evidence.mode, evidence.status),
        (EvidenceMode::Required, EvidenceStatus::Durable)
    );
    assert_eq!(
        evidence.record_id, context.id,
        "one id, never a second authority"
    );
    evidence
        .check(answered.decision)
        .expect("as the contract allows");
    let position = evidence.position.expect("a durable position");
    let host_hex = host.host_hex();
    assert_eq!(position.host_id.replace('-', ""), host_hex);
    let resource = host_log::ledger(&uuid_of("acme"), &uuid_of("main-ledger"));
    let records = host_log::records(&producer, &resource);
    let (sequence, record) = records.last().expect("the record");
    assert_eq!(position.sequence, sequence.to_string());
    assert_eq!(
        record["id"],
        json!(context.id),
        "the position holds that record"
    );
    assert_eq!(record["stream"]["instance"], json!(position.run));

    // A batch: each evaluation its own record, the batch none.
    let batch: wire::CheckRequest = serde_json::from_value(json!({
        "zone": "acme", "ledger": "main-ledger",
        "subject": {"type": "user", "id": "alice"},
        "resource": {"type": "document", "id": "budget"},
        "action": {"name": "read"},
        "evaluations": [{"request_id": "one"}, {"request_id": "two"}],
    }))
    .expect("a batch");
    let answered = logged.decide(&batch, None).await.expect("decided");
    assert!(
        answered
            .context
            .as_ref()
            .is_some_and(|context| context.evidence.is_none()),
        "no record is of the batch"
    );
    let records = host_log::records(&producer, &resource);
    let evaluations = answered.evaluations.expect("each evaluation");
    assert_eq!(evaluations.len(), 2);
    for decision in evaluations {
        let evidence = decision
            .context
            .as_ref()
            .and_then(|context| context.evidence.clone())
            .expect("its evidence");
        evidence.check(decision.decision).expect("allowed");
        let sequence: u64 = evidence
            .position
            .expect("durable")
            .sequence
            .parse()
            .expect("decimal");
        let (_, record) = records
            .iter()
            .find(|(held, _)| *held == sequence)
            .expect("the record at that position");
        // Each evaluation's evidence names its own record, never its sibling's.
        assert_eq!(record["id"], json!(evidence.record_id), "{record}");
        assert_eq!(
            evidence.record_id,
            decision.context.and_then(|context| context.id)
        );
    }

    // A nonce: refused before anything is decided or recorded.
    let before = host_log::records(&producer, &resource).len();
    let mut signed = ask("acme", "main-ledger", "alice", "read");
    signed.request_nonce = Some("AAECAwQFBgcICQoLDA0ODw".to_owned());
    let refused = logged
        .decide(&signed, None)
        .await
        .expect_err("nothing signs");
    assert_eq!(refused.code(), "response_signing_unavailable");
    assert_eq!(refused.class(), permguard_core::ErrorClass::Unavailable);
    assert_eq!(
        host_log::records(&producer, &resource).len(),
        before,
        "nothing recorded for an answer that was never given"
    );
    // One the contract does not define is not a request for anything.
    signed.request_nonce = Some("AAECAwQFBgcICQoLDA0O".to_owned());
    let refused = logged.decide(&signed, None).await.expect_err("15 bytes");
    assert_eq!(refused.code(), "invalid_argument");
    assert_eq!(refused.class(), permguard_core::ErrorClass::Validation);

    // Over HTTP, the same refusal with its status.
    let (status, body, _) = surface::post(
        &root,
        "/access/v1/evaluation",
        json!({
            "zone": "acme", "ledger": "main-ledger",
            "subject": {"type": "user", "id": "alice"},
            "resource": {"type": "document", "id": "budget"},
            "action": {"name": "read"},
            "request_nonce": "AAECAwQFBgcICQoLDA0ODw",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["code"], "response_signing_unavailable", "{body}");
}

/// WP-6.6b: a signed native response, end to end, under a real `data.attest` ring.
mod signed_response {
    use super::*;

    use base64::Engine as _;
    use permguard_data_plane::authz::signing::{ResponseSigner, ResponseSigning};
    use permguard_languages::attestation::{Attestation, Payload};

    pub(super) const AUDIENCE: &str = "spiffe://acme/pep";
    pub(super) const NONCE: &str = "AAECAwQFBgcICQoLDA0ODw";
    pub(super) const NOW: i64 = 1_790_000_000;

    /// The Host's own signing of a response, at a fixed time so two transports sign alike.
    pub(super) struct RingSigner {
        pub(super) ring: Arc<permguard_host::keys::ring::Ring>,
        pub(super) refuses: bool,
    }

    impl ResponseSigner for RingSigner {
        fn sign(&self, payload: &[u8]) -> Result<Attestation, String> {
            if self.refuses {
                return Err("the ring is unavailable".to_owned());
            }
            let parts = permguard_host::composition::sign_jws::<
                permguard_host::composition::DecisionResponseV1,
            >(payload, self.ring.as_ref())
            .map_err(|error| error.to_string())?;
            Ok(Attestation {
                protected: parts.protected,
                payload: parts.payload,
                signature: parts.signature,
            })
        }

        fn now(&self) -> i64 {
            NOW
        }

        fn ready(&self) -> Result<(), String> {
            if self.refuses {
                return Err("the ring is unavailable".to_owned());
            }
            Ok(())
        }
    }

    pub(super) fn b64(part: &str) -> Vec<u8> {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(part)
            .expect("base64url")
    }

    /// Verifies `attestation` under `ring`'s published key, as a PEP would.
    pub(super) fn verified(
        attestation: &Attestation,
        ring: &permguard_host::keys::ring::Ring,
    ) -> Payload {
        use permguard_core::keys::PublicSet as _;
        let header: Value = serde_json::from_slice(&b64(&attestation.protected)).expect("JSON");
        let kid = header["kid"].as_str().expect("a kid").to_owned();
        assert_eq!(
            String::from_utf8(b64(&attestation.protected)).expect("UTF-8"),
            format!(r#"{{"alg":"EdDSA","kid":"{kid}","typ":"permguard.decision.response.v1"}}"#),
            "the closed JCS header"
        );
        let key = ring
            .public_keys()
            .expect("published")
            .into_iter()
            .find(|key| key.kid == kid)
            .expect("the key it names");
        permguard_objects::crypto::suite::Suite::Ed25519Sha256V1
            .verify(
                &b64(&key.x),
                format!("{}.{}", attestation.protected, attestation.payload).as_bytes(),
                &b64(&attestation.signature),
            )
            .expect("the signature verifies");
        let bytes = b64(&attestation.payload);
        permguard_stream::jcs::decode_canonical(&bytes).expect("the payload is JCS");
        let payload: Payload = serde_json::from_slice(&bytes).expect("the closed payload");
        payload.check().expect("every form exact");
        payload
    }

    pub(super) fn decider_signing(
        root: &Path,
        host: &host_log::HostStream,
        refuses: bool,
    ) -> Arc<Decider> {
        decider_signing_on(root, host, &host.producer(), refuses)
    }

    /// [`decider_signing`], its log appending to `producer`: the one a test counts records on.
    pub(super) fn decider_signing_on(
        root: &Path,
        host: &host_log::HostStream,
        producer: &Arc<permguard_stream::engine::Producer<permguard_decisions::stream::Codec>>,
        refuses: bool,
    ) -> Arc<Decider> {
        let log = Arc::new(host.log(producer, host_log::LOOSE));
        Arc::new(
            Decider::new(
                root.to_path_buf(),
                Arc::new(Cache::new(64, 8 * 1024 * 1024)),
                Metrics::none(),
                None,
                256,
            )
            .with_journal(
                Some(log as Arc<dyn permguard_data_plane::decisions::DecisionRecorder>),
                subjects(),
                permguard_core::decisions::IncludeSection::default(),
            )
            .with_response_signing(Some(ResponseSigning {
                signer: Arc::new(RingSigner {
                    ring: host.attest(),
                    refuses,
                }),
                validity: std::time::Duration::from_secs(300),
                clock_skew: std::time::Duration::from_secs(30),
            })),
        )
    }

    /// The asker a transport hands on: the authenticated caller, the digest of what it sent.
    fn asker(request: &wire::CheckRequest) -> permguard_data_plane::authz::decide::Asker {
        permguard_data_plane::authz::decide::Asker::of(Some(AUDIENCE.to_owned()), request)
    }

    fn signed_ask(body: Value) -> wire::CheckRequest {
        let mut body = body;
        body["request_nonce"] = json!(NONCE);
        serde_json::from_value(body).expect("a request")
    }

    #[tokio::test]
    async fn a_signed_response_binds_the_request_the_answer_and_the_policy_state() {
        let root = scratch("signed-response").join("mirrors");
        provision(
            &root,
            "acme",
            "main-ledger",
            &manifest(&[("app", "cedar", false)], ">=0.0.0"),
            &[("app", vec![&CEDAR_READ], None)],
        );
        let host = host_log::HostStream::new("signed-response-volume");
        let decider = decider_signing(&root, &host, false);
        let request = signed_ask(json!({
            "zone": "acme", "ledger": "main-ledger",
            "subject": {"type": "user", "id": "alice"},
            "resource": {"type": "document", "id": "budget"},
            "action": {"name": "read"},
            "request_id": "r-1",
        }));
        let response = decider
            .decide_signed(&request, None, None, asker(&request))
            .await
            .expect("decided and signed");
        let attestation = response.attestation.clone().expect("signed");
        let payload = verified(&attestation, &host.attest());

        assert_eq!(
            payload.audience, AUDIENCE,
            "the authenticated caller, exactly"
        );
        assert_eq!(payload.request_nonce, NONCE);
        assert_eq!(payload.request_ids, vec![Some("r-1".to_owned())]);
        assert_eq!(
            payload.request_digest,
            permguard_languages::attestation::request_digest(&request).expect("a digest")
        );
        assert_eq!(
            payload.response_digest,
            permguard_languages::attestation::response_digest(&response).expect("a digest"),
            "the answer as sent, its attestation aside"
        );
        assert_eq!(payload.decision, response.decision);
        assert_eq!(
            Some(&payload.evidence),
            response
                .context
                .as_ref()
                .and_then(|context| context.evidence.as_ref())
        );
        assert_eq!(payload.policy.authority_host_id, AUTHORITY);
        assert_eq!(payload.policy.zone_id, uuid_of("acme"));
        assert_eq!(payload.policy.ledger_id, uuid_of("main-ledger"));
        assert_eq!(payload.policy.reference, "main");
        assert_eq!(payload.policy.counter, "1");
        assert_eq!(payload.policy.profile, "default");
        assert!(payload.policy.commit.starts_with("sha256:"));
        assert_eq!(payload.issued_at, permguard_core::time::to_rfc3339(NOW));
        assert_eq!(
            payload.expires_at,
            permguard_core::time::to_rfc3339(NOW + 300)
        );

        // A batch: one id per evaluation, in order; its evidence the last evaluation's.
        let batch = signed_ask(json!({
            "zone": "acme", "ledger": "main-ledger",
            "subject": {"type": "user", "id": "alice"},
            "resource": {"type": "document", "id": "budget"},
            "action": {"name": "read"},
            "evaluations": [{"request_id": "one"}, {}],
        }));
        let answered = decider
            .decide_signed(&batch, None, None, asker(&batch))
            .await
            .expect("signed");
        let payload = verified(
            answered.attestation.as_ref().expect("signed"),
            &host.attest(),
        );
        assert_eq!(payload.request_ids, vec![Some("one".to_owned()), None]);
        assert_eq!(
            Some(&payload.evidence),
            answered
                .evaluations
                .as_ref()
                .and_then(|evaluations| evaluations
                    .last()
                    .and_then(|decision| decision.context.as_ref())
                    .and_then(|context| context.evidence.as_ref()))
        );

        // No nonce, no attestation.
        let mut plain = request.clone();
        plain.request_nonce = None;
        let answered = decider
            .decide_signed(&plain, None, None, asker(&plain))
            .await
            .expect("decided");
        assert!(answered.attestation.is_none());
    }

    #[tokio::test]
    async fn a_signature_that_cannot_be_made_refuses_the_answer_and_never_downgrades() {
        let root = scratch("signed-refusals").join("mirrors");
        provision(
            &root,
            "acme",
            "main-ledger",
            &manifest(&[("app", "cedar", false)], ">=0.0.0"),
            &[("app", vec![&CEDAR_READ], None)],
        );
        let host = host_log::HostStream::new("signed-refusals-volume");
        let resource = host_log::ledger(&uuid_of("acme"), &uuid_of("main-ledger"));
        let request = signed_ask(json!({
            "zone": "acme", "ledger": "main-ledger",
            "subject": {"type": "user", "id": "alice"},
            "resource": {"type": "document", "id": "budget"},
            "action": {"name": "read"},
        }));

        // Nobody authenticated to address it to: refused before anything is recorded.
        let producer = host.producer();
        let decider = decider_signing_on(&root, &host, &producer, false);
        // One decision recorded first, so a count that does not move means something.
        let mut plain = request.clone();
        plain.request_nonce = None;
        decider
            .decide_signed(&plain, None, None, Default::default())
            .await
            .expect("decided");
        assert!(!host_log::records(&producer, &resource).is_empty());
        let before = host_log::records(&producer, &resource).len();
        let refused = decider
            .decide_signed(
                &request,
                None,
                None,
                permguard_data_plane::authz::decide::Asker::default(),
            )
            .await
            .expect_err("no audience");
        assert_eq!(refused.code(), "response_signing_unavailable");
        assert_eq!(host_log::records(&producer, &resource).len(), before);

        // A ring that cannot sign now: refused before anything is recorded, never unsigned.
        let failing = decider_signing_on(&root, &host, &producer, true);
        let before = host_log::records(&producer, &resource).len();
        let refused = failing
            .decide_signed(&request, None, None, asker(&request))
            .await
            .expect_err("the ring refused");
        assert_eq!(refused.code(), "response_signing_unavailable");
        assert_eq!(refused.class(), permguard_core::ErrorClass::Unavailable);
        assert_eq!(host_log::records(&producer, &resource).len(), before);
        // No digest of what the caller sent: never recomputed from a body the transport touched.
        let refused = decider
            .decide_signed(
                &request,
                None,
                None,
                permguard_data_plane::authz::decide::Asker {
                    audience: Some(AUDIENCE.to_owned()),
                    request_digest: None,
                },
            )
            .await
            .expect_err("no digest");
        assert_eq!(refused.code(), "response_signing_unavailable");

        // A mirror pulled before it kept its head's authority signs nothing, refused unrecorded.
        let store = permguard_control_client::store::FsStore::new(
            permguard_data_plane::authz::store::find(&root, "acme", "main-ledger")
                .expect("located")
                .path,
        );
        let held = permguard_control_client::checkpoint::read(&store, "refs/main")
            .expect("reads")
            .expect("held");
        permguard_control_client::checkpoint::write(
            &store,
            "refs/main",
            &permguard_control_client::checkpoint::Checkpoint {
                authority_host_id: None,
                reference: None,
                ..held.clone()
            },
        )
        .expect("written");
        let older = decider_signing_on(&root, &host, &producer, false);
        let before = host_log::records(&producer, &resource).len();
        let refused = older
            .decide_signed(&request, None, None, asker(&request))
            .await
            .expect_err("no authority kept");
        assert_eq!(refused.code(), "response_signing_unavailable");
        assert_eq!(
            host_log::records(&producer, &resource).len(),
            before,
            "refused before anything is decided"
        );

        // An authority the payload could not name canonically: the payload is checked whole and
        // the answer refused rather than signed with a malformed state.
        permguard_control_client::checkpoint::write(
            &store,
            "refs/main",
            &permguard_control_client::checkpoint::Checkpoint {
                authority_host_id: Some("NOT-A-UUID".to_owned()),
                reference: Some("main".to_owned()),
                ..held.clone()
            },
        )
        .expect("written");
        let tampered = decider_signing_on(&root, &host, &producer, false);
        let refused = tampered
            .decide_signed(&request, None, None, asker(&request))
            .await
            .expect_err("not exact");
        assert_eq!(refused.code(), "response_signing_unavailable");
    }

    fn authenticated() -> Arc<permguard_core::authz::Actor> {
        Arc::new(permguard_core::authz::Actor::Authenticated(
            permguard_core::authz::ActorContext::new(
                permguard_core::authz::Principal::new(AUDIENCE).expect("a principal"),
                permguard_core::authz::Credential::Oidc,
                None,
            ),
        ))
    }

    fn authenticating(
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        request.extensions_mut().insert(authenticated());
        Ok(request)
    }

    /// Serves `decider` over gRPC on an ephemeral port, every caller authenticated as
    /// [`AUDIENCE`].
    fn serve_signed(decider: Arc<Decider>, boundary: Anonymising) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
        let address = listener.local_addr().expect("the address");
        listener.set_nonblocking(true).expect("non-blocking");
        let api = permguard_data_plane::authz::grpc::PdpApi {
            authorization: permissive(),
            decider,
            disclosure: Disclosure::Full,
            base_url: format!("http://{address}"),
            describer: permguard_core::stages::Describer::detached("data-plane"),
        };
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).expect("adopted");
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
                        permguard_data_plane::v1::policy_decision_point_server::PolicyDecisionPointServer::with_interceptor(
                            api, boundary,
                        ),
                    )
                    .serve_with_incoming(incoming)
                    .await;
            });
        });
        format!("grpc://{address}")
    }

    async fn rest(
        decider: Arc<Decider>,
        actor: Arc<permguard_core::authz::Actor>,
        body: Value,
    ) -> (StatusCode, Value) {
        // The bare routes: the actor is the one this request carries, as an authentication
        // boundary would have attached it.
        let router = permguard_data_plane::authz::http::routes(http::Surface {
            authorization: permissive(),
            decider,
            disclosure: Disclosure::Full,
            base_url: "http://127.0.0.1:7443".to_owned(),
            describer: permguard_core::stages::Describer::detached("data-plane"),
        });
        let request = Request::builder()
            .method("POST")
            .uri("/access/v1/evaluation")
            .header("content-type", "application/json")
            .header("x-request-id", "from-the-header")
            .extension(actor)
            .body(Body::from(body.to_string()))
            .expect("the request builds");
        let response = router.oneshot(request).await.expect("answers");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("the body")
            .to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// Over REST and gRPC alike: an authenticated caller gets an attestation a PEP recomputes from
    /// what it sent and what it received — the header's request id never part of the request
    /// digest — and an anonymous one is refused `401` where this plane signs.
    #[test]
    fn both_transports_sign_what_the_caller_can_recompute_and_refuse_nobody() {
        let root = scratch("signed-transports").join("mirrors");
        provision(
            &root,
            "acme",
            "main-ledger",
            &manifest(&[("app", "cedar", false)], ">=0.0.0"),
            &[("app", vec![&CEDAR_READ], None)],
        );
        let host = host_log::HostStream::new("signed-transports-volume");
        let decider = decider_signing(&root, &host, false);
        let body = json!({
            "zone": "acme", "ledger": "main-ledger",
            "subject": {"type": "user", "id": "alice"},
            "resource": {"type": "document", "id": "budget"},
            "action": {"name": "read"},
            "request_nonce": NONCE,
        });
        let sent: wire::CheckRequest = serde_json::from_value(body.clone()).expect("a request");
        let request_digest =
            permguard_languages::attestation::request_digest(&sent).expect("a digest");
        let recompute = |answer: &Value| {
            let mut unsigned = answer.clone();
            let attestation: Attestation =
                serde_json::from_value(unsigned["attestation"].clone()).expect("signed");
            unsigned
                .as_object_mut()
                .expect("an object")
                .remove("attestation");
            let payload = verified(&attestation, &host.attest());
            assert_eq!(
                payload.request_digest, request_digest,
                "what the caller sent"
            );
            assert_eq!(
                payload.response_digest,
                permguard_languages::attestation::response_value_digest(&unsigned)
                    .expect("a digest"),
                "what the caller received"
            );
            assert_eq!(payload.audience, AUDIENCE);
            payload
        };

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let (status, over_rest) =
            runtime.block_on(rest(Arc::clone(&decider), authenticated(), body.clone()));
        assert_eq!(status, StatusCode::OK, "{over_rest}");
        let payload = recompute(&over_rest);
        assert_eq!(
            payload.request_ids,
            vec![Some("from-the-header".to_owned())],
            "the id the answer echoes, even from the header"
        );

        let client = permguard_control_client::pdp::client(
            &serve_signed(Arc::clone(&decider), authenticating as Anonymising),
            &permguard_control_client::tls::TlsOptions::default(),
            Box::new(permguard_control_client::narrate::Silent),
        )
        .expect("the endpoint parses");
        let over_grpc = client.evaluate(&body).expect("signed");
        recompute(&over_grpc);

        // And the verifier a PEP runs, on what each transport actually delivered (WP-6.6c).
        let keys = {
            use permguard_core::keys::PublicSet as _;
            host.attest().public_keys().expect("published")
        };
        let pep_verifies = |answer: &Value| {
            let mut nonces = permguard_control_client::attestation::Outstanding::default();
            nonces.issue(NONCE);
            permguard_control_client::attestation::verify(
                &serde_json::to_vec(&body).unwrap(),
                &serde_json::to_vec(answer).unwrap(),
                &keys,
                &permguard_control_client::attestation::Expectation {
                    audience: AUDIENCE,
                    now: NOW + 10,
                    validity_seconds: 300,
                    clock_skew_seconds: 30,
                    policy: None,
                },
                &mut nonces,
            )
            .unwrap_or_else(|refusal| panic!("{refusal}: {answer}"))
        };
        assert_eq!(pep_verifies(&over_rest).policy.authority_host_id, AUTHORITY);
        assert_eq!(pep_verifies(&over_grpc).policy.authority_host_id, AUTHORITY);

        // A batch over gRPC, a deny and a permit: what the client rebuilds still digests as signed.
        let mut batch = body.clone();
        batch["evaluations"] = json!([
            {"request_id": "denied", "action": {"name": "purge"}},
            {}
        ]);
        let sent_batch: wire::CheckRequest =
            serde_json::from_value(batch.clone()).expect("a batch");
        let over_grpc = client.evaluate(&batch).expect("signed");
        let mut unsigned = over_grpc.clone();
        let attestation: Attestation =
            serde_json::from_value(unsigned["attestation"].clone()).expect("signed");
        unsigned
            .as_object_mut()
            .expect("an object")
            .remove("attestation");
        let payload = verified(&attestation, &host.attest());
        assert_eq!(
            payload.request_digest,
            permguard_languages::attestation::request_digest(&sent_batch).expect("a digest")
        );
        assert_eq!(
            payload.response_digest,
            permguard_languages::attestation::response_value_digest(&unsigned).expect("a digest")
        );
        assert_eq!(payload.request_ids, vec![Some("denied".to_owned()), None]);
        assert_eq!(
            over_grpc["evaluations"][0]["decision"],
            json!(false),
            "{over_grpc}"
        );

        // Nobody authenticated over gRPC: `UNAUTHENTICATED`, as REST answers `401`.
        let anonymous = permguard_control_client::pdp::client(
            &serve_signed(Arc::clone(&decider), anonymous_interceptor as Anonymising),
            &permguard_control_client::tls::TlsOptions::default(),
            Box::new(permguard_control_client::narrate::Silent),
        )
        .expect("the endpoint parses");
        let refused = anonymous
            .evaluate(&body)
            .expect_err("nobody to address it to");
        assert_eq!(refused.reason, "unauthenticated", "{refused}");

        let (status, refused) = runtime.block_on(rest(
            decider,
            Arc::new(permguard_core::authz::Actor::Anonymous),
            body,
        ));
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{refused}");
        assert_eq!(refused["code"], "unauthenticated", "{refused}");
    }
}
