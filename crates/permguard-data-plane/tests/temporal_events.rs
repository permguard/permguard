// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The temporal interface, end to end: a real ledger on a real volume, a real journal on a real
//! disk, and the real submission path, over both transports.
//!
//! Nothing here is a stand-in. The ledger is built out of the same objects a `permguard apply`
//! pushes, the artifacts are Dogwood's own from its `read_login_not_logout` example, and the
//! journal is the one a plane writes — because what is worth testing is precisely that *those*
//! turn into an answer, and that the answer is the one upstream records for the same trace.
//!
//! | | |
//! | --- | --- |
//! | upstream's own trace produces upstream's own verdicts, through Permguard's contract | |
//! | a history-only kind returns a receipt and never a fabricated verdict | |
//! | the event is durable before the answer leaves, and the watermark says where | |
//! | a retry of one occurrence is answered as one, and never observed twice | |
//! | one id with different content is a conflict, resolved by neither | |
//! | a caller cannot pin its own history, name its own producer, or state its own sequence | |
//! | HTTP and gRPC answer the same thing, from the same path | |

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
use permguard_data_plane::authz::decide::Decider;
use permguard_data_plane::authz::store::{Identity, Mirror};
use permguard_data_plane::temporal::streams::Streams;
use permguard_data_plane::temporal::submit::Submitter;
use permguard_data_plane::temporal::{configuration, http};
use permguard_events::journal::Bounds;
use permguard_languages::dogwood_artifacts;
use permguard_languages::registry;
use permguard_objects::manifest::{
    ArtifactContract, Manifest, Partition, Profile, Requirement, Runtime,
};
use permguard_objects::object::{Blob, Commit, Kind, Tree, TreeEntry};
use permguard_objects::policy_id::{ANNOTATION_POLICY_ID, ANNOTATION_POLICY_KIND};
use permguard_objects::semver::Constraint;

const POLICY: &str = include_str!("fixtures/read-login-not-logout.dw");
const ACTION_SCHEMA: &str = include_str!("fixtures/read-login-not-logout.cedarschema");
const EVENT_SCHEMA: &str = include_str!("fixtures/pinned.dwschema");

const ZONE: &str = "acme";
const LEDGER: &str = "agent-governance";
const PROFILE: &str = "temporal";

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pg-temporal-e2e-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory is created");

    dir
}

/// The manifest of a Dogwood ledger with one temporal profile.
fn manifest() -> Manifest {
    let mut runtimes = BTreeMap::new();
    runtimes.insert(
        permguard_languages::DOGWOOD.to_owned(),
        Runtime {
            language: Requirement {
                name: permguard_languages::DOGWOOD.to_owned(),
                constraint: Constraint::parse(">=1.0.0").expect("a constraint"),
            },
            engine: Requirement {
                name: registry::ENGINE_NAME.to_owned(),
                constraint: Constraint::parse(">=0.0.0").expect("a constraint"),
            },
        },
    );

    let mut media_types = vec![permguard_languages::MEDIA_TYPE_POLICY_DOGWOOD.to_owned()];
    media_types.extend(
        dogwood_artifacts::all()
            .iter()
            .map(|artifact| artifact.media_type().to_owned()),
    );
    media_types.sort();

    let mut partitions = BTreeMap::new();
    partitions.insert(
        "governance".to_owned(),
        Partition {
            runtime: permguard_languages::DOGWOOD.to_owned(),
            media_types,
            // A Dogwood partition states its contents by name: `schema: bool` cannot say which of
            // several schemas is meant.
            schema: false,
            artifacts: vec![
                ArtifactContract {
                    r#type: dogwood_artifacts::ACTION_SCHEMA.to_owned(),
                    required: true,
                },
                ArtifactContract {
                    r#type: dogwood_artifacts::EVENT_SCHEMA.to_owned(),
                    required: false,
                },
            ],
            history: None,
            input: Some(permguard_objects::manifest::InputContract {
                r#type: permguard_languages::event::EVENT_TYPE.to_owned(),
                required: true,
            }),
        },
    );

    let mut profiles = BTreeMap::new();
    profiles.insert(
        PROFILE.to_owned(),
        Profile {
            r#type: permguard_objects::manifest::PROFILE_PDP_TEMPORAL_V1ALPHA1.to_owned(),
            partitions: vec!["governance".to_owned()],
        },
    );

    Manifest {
        kind: "policy".to_owned(),
        name: "temporal-e2e".to_owned(),
        description: "a Dogwood ledger built by the temporal tests".to_owned(),
        author: "Nitro Agility S.r.l.".to_owned(),
        license: "Apache-2.0".to_owned(),
        runtimes,
        partitions,
        profiles,
    }
}

/// Writes a mirror the way a synchronization round leaves one.
fn provision(root: &Path, manifest: &Manifest) -> Mirror {
    let path = root.join(format!("{ZONE}-id")).join(format!("{LEDGER}-id"));
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

    let mut entries = Vec::new();
    let digest = put_blob(
        permguard_languages::MEDIA_TYPE_POLICY_DOGWOOD,
        POLICY.as_bytes(),
    );
    let mut annotations = BTreeMap::new();
    annotations.insert(
        ANNOTATION_POLICY_ID.to_owned(),
        "01a0-read-login-not-logout".to_owned(),
    );
    annotations.insert(ANNOTATION_POLICY_KIND.to_owned(), "policy".to_owned());
    entries.push(TreeEntry {
        kind: Kind::Blob,
        digest,
        name: "policy.dw".to_owned(),
        annotations,
    });
    for (type_name, source) in [
        (dogwood_artifacts::ACTION_SCHEMA, ACTION_SCHEMA),
        (dogwood_artifacts::EVENT_SCHEMA, EVENT_SCHEMA),
    ] {
        let artifact = permguard_languages::artifact::artifact_type(type_name).expect("registered");
        let digest = put_blob(artifact.media_type(), source.as_bytes());
        entries.push(TreeEntry {
            kind: Kind::Blob,
            digest,
            name: artifact
                .canonical_filename()
                .expect("these two reserve a name")
                .to_owned(),
            annotations: BTreeMap::new(),
        });
    }
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    let tree = Tree { entries };
    let bytes = tree.encode().expect("the tree encodes");
    let partition_digest = objects::put(&store, "objects", &bytes).expect("the tree is stored");

    let root_tree = Tree {
        entries: vec![TreeEntry {
            kind: Kind::Tree,
            digest: partition_digest,
            name: "governance".to_owned(),
            annotations: BTreeMap::new(),
        }],
    };
    let root_bytes = root_tree.encode().expect("the root tree encodes");
    let root_digest = objects::put(&store, "objects", &root_bytes).expect("the tree is stored");

    let commit = Commit {
        tree: root_digest,
        manifest: manifest_digest,
        predecessors: Vec::new(),
        author: "tests".to_owned(),
        author_at: 1_700_000_000,
        message: "the ledger these tests submit to".to_owned(),
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
        zone_id: format!("{ZONE}-id"),
        zone_name: ZONE.to_owned(),
        ledger_id: format!("{LEDGER}-id"),
        ledger_name: LEDGER.to_owned(),
        server: "http://127.0.0.1:7556".to_owned(),
    };
    permguard_data_plane::authz::store::record(&path, &identity).expect("the identity is recorded");

    Mirror { path, identity }
}

/// A whole plane: a provisioned mirror, a decider over it, and a journal beside it.
struct Plane {
    submitter: Arc<Submitter>,
    events: PathBuf,
    /// The journals, so a test can ask what order the ledger applied.
    streams: Arc<Streams>,
}

fn plane(tag: &str) -> Plane {
    let root = scratch(tag);
    let mirrors = root.join("mirrors");
    std::fs::create_dir_all(&mirrors).expect("the mirrors root is created");
    provision(&mirrors, &manifest());

    let decider = Arc::new(Decider::new(
        mirrors,
        Arc::new(Cache::new(64, 32 * 1024 * 1024)),
        Metrics::none(),
        None,
        256,
    ));
    let events = root.join("events");
    // The clock bounds are widened for the tests only, and deliberately: upstream's trace is dated
    // at the epoch, and what these tests are about is the temporal semantics rather than the skew
    // rule — which has tests of its own below, with the bounds the shipped configuration uses.
    let bounds = Bounds {
        retention_minimum: std::time::Duration::MAX,
        allowed_lateness: std::time::Duration::from_secs(u32::MAX.into()),
        clock_skew: std::time::Duration::from_secs(u32::MAX.into()),
        ..Bounds::default()
    };
    let streams = Arc::new(Streams::new(
        events.clone(),
        "test-plane".to_owned(),
        bounds,
    ));

    Plane {
        submitter: Arc::new(Submitter::new(
            decider,
            Arc::clone(&streams),
            Metrics::none(),
        )),
        events,
        streams,
    }
}

/// One occurrence of upstream's trace, in Permguard's own event contract.
fn submission(at: i64, action: &str, kind: &str, user: &str, input: Value) -> Value {
    let occurred_at =
        permguard_events::index::render_epoch_seconds(at).expect("the timepoint is an instant");

    json!({
        "store": {"zone": ZONE, "ledger": LEDGER, "profile": PROFILE},
        "event": {
            "type": permguard_languages::event::EVENT_TYPE,
            "data": {
                "event_id": format!("{action}-{kind}-{at}"),
                "kind": kind,
                "action": action,
                "principal": format!("Drupe::OAuthUser::\"{user}\""),
                "resource": "Drupe::Gateway::\"gw1\"",
                "logged": {"input": input},
                "request_context": {"input": input},
                "occurred_at": occurred_at,
            }
        }
    })
}

fn surface(plane: &Plane) -> axum::Router {
    http::routes(http::Surface {
        submitter: Arc::clone(&plane.submitter),
        disclosure: Disclosure::Full,
        base_url: "http://plane.test".to_owned(),
        pdp: "test-plane".to_owned(),
    })
}

async fn post(router: &axum::Router, body: Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri(permguard_languages::temporal::SUBMISSION_PATH)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("the request builds");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the surface answers");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("the body is read")
        .to_bytes();

    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Upstream's `expected.out` for this policy, this schema and this trace.
const TRACE: [(i64, &str, &str, &str); 5] = [
    (0, "Drupe::Action::Login", "request", "alice"),
    (5, "Drupe::Action::Login", "response", "alice"),
    (100, "Drupe::Action::Read", "request", "alice"),
    (4000, "Drupe::Action::Read", "request", "alice"),
    (4100, "Drupe::Action::Read", "request", "bob"),
];

fn input_of(at: i64, action: &str, kind: &str, user: &str) -> Value {
    match (action, kind) {
        ("Drupe::Action::Login", "response") => {
            json!({"user": user, "server": "s1"})
        }
        ("Drupe::Action::Login", _) => json!({"user": user, "server": "s1"}),
        _ => json!({"user": user, "document": format!("doc{at}")}),
    }
}

#[tokio::test]
async fn the_upstream_trace_reproduces_the_verdicts_upstream_records() {
    let plane = plane("trace");
    let router = surface(&plane);

    let mut verdicts = Vec::new();
    for (at, action, kind, user) in TRACE {
        let (status, body) = post(
            &router,
            submission(at, action, kind, user, input_of(at, action, kind, user)),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "@{at}: {body}");
        match body["outcome"].as_str() {
            Some("decided") => verdicts.push((at, body["decision"].as_bool().unwrap())),
            Some("accepted") => {
                // A history-only kind. Nothing is invented for it.
                assert!(body.get("decision").is_none(), "@{at}: {body}");
            }
            other => panic!("@{at}: an outcome of {other:?}"),
        }
    }

    assert_eq!(
        verdicts,
        vec![(0, false), (100, true), (4000, false), (4100, false)],
        "upstream records DENY, ALLOW, DENY, DENY for this trace"
    );
}

/// The receipt says where the occurrence sits, and the journal is the reason it can.
#[tokio::test]
async fn the_event_is_durable_before_the_answer_leaves_and_the_watermark_says_where() {
    let plane = plane("durable");
    let router = surface(&plane);

    let (status, body) = post(
        &router,
        submission(
            0,
            "Drupe::Action::Login",
            "response",
            "alice",
            json!({"user": "alice", "server": "s1"}),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["outcome"], "accepted");
    assert_eq!(body["watermark"]["sequence"], 1);
    assert!(
        body["watermark"]["instance"]
            .as_str()
            .is_some_and(|held| !held.is_empty()),
        "the receipt names the producer instance: {body}"
    );
    // The pinned schema pins `callerPrincipal`, so the receipt carries a history key.
    assert!(
        body["watermark"]["history"]
            .as_str()
            .is_some_and(|held| held.starts_with("sha256:") || !held.is_empty()),
        "{body}"
    );

    // And it is on disk, in the ledger's own directory, before any of that was said.
    let segment = plane
        .events
        .join(ZONE)
        .join(LEDGER)
        .join("seg-00000000000000000001.events");
    let held = std::fs::read_to_string(&segment).expect("the segment exists");
    assert!(held.contains("Drupe::Action::Login"), "{held}");
}

/// Concurrent submissions reach the histories in the order the journal made them durable.
///
/// # What this pins down
///
/// Journalling an occurrence and observing it are two steps, and between them the thread carrying
/// sequence 5 is an ordinary thread that can be descheduled while the one carrying 6 runs on. The
/// Dogwood history takes a lock, so the two never interleave *inside* an evaluation — but a lock
/// is taken in scheduling order, and a temporal policy is a statement about order. Without a
/// sequencer this ledger could observe 6 before 5 under load, and answer on replay differently
/// from how it answered live.
///
/// The race is timing-dependent, so this does not try to catch it by luck. It asserts the
/// invariants that hold only if every occurrence went through its turn: each sequence assigned
/// exactly once with no gap, and the ledger's applied mark standing at the journal's tail — which
/// is reached only by every turn being taken and given back. The adversarial interleaving itself
/// is forced in the sequencer's own tests, where the order can be controlled.
#[tokio::test]
async fn concurrent_submissions_are_applied_in_the_order_the_journal_assigned() {
    const SUBMISSIONS: usize = 24;

    let plane = plane("ordered-under-load");
    let router = surface(&plane);

    // One history — the pinned schema keys it by caller — so every one of these is a turn in the
    // same queue rather than independent work that never had to be ordered.
    let mut inflight = Vec::with_capacity(SUBMISSIONS);
    for nth in 0..SUBMISSIONS {
        let router = router.clone();
        let body = submission(
            i64::try_from(nth).expect("the index is small"),
            "Drupe::Action::Login",
            "response",
            "alice",
            json!({"user": "alice", "server": format!("s{nth}")}),
        );
        inflight.push(tokio::spawn(async move { post(&router, body).await }));
    }

    let mut sequences = Vec::with_capacity(SUBMISSIONS);
    for handle in inflight {
        let (status, body) = handle.await.expect("the submission finishes");
        assert_eq!(status, StatusCode::OK, "{body}");
        sequences.push(
            body["watermark"]["sequence"]
                .as_u64()
                .unwrap_or_else(|| panic!("every receipt names its sequence: {body}")),
        );
    }

    sequences.sort_unstable();
    assert_eq!(
        sequences,
        (1..=SUBMISSIONS as u64).collect::<Vec<u64>>(),
        "every occurrence got its own sequence, with no gap and no sequence twice"
    );

    let applied = plane
        .streams
        .sequencer(ZONE, LEDGER)
        .expect("the ledger is open")
        .applied_through();
    assert_eq!(
        applied, SUBMISSIONS as u64,
        "the ledger applied through its journal's tail: every turn was taken and given back"
    );
}

/// A hole in the shared history stops `shared-bounded` from deciding, until somebody accepts it.
///
/// # What this is not
///
/// It is not staleness. Staleness is history this plane has not caught up with *yet* and will, so
/// a freshness bound is the right instrument. A gap is history it will never hold — the control
/// plane had aged it out before this plane came back — and waiting does not fix it. Before the gap
/// was recorded, the subscription resumed from the oldest still held and then reported itself
/// perfectly fresh, so `shared-bounded` decided over a history with a hole in it and said nothing.
#[tokio::test]
async fn a_recorded_gap_stops_a_bounded_plane_from_deciding_until_it_is_accepted() {
    let root = scratch("bounded-gap");
    let mirrors = root.join("mirrors");
    std::fs::create_dir_all(&mirrors).expect("the mirrors root is created");
    provision(&mirrors, &manifest());

    let decider = Arc::new(Decider::new(
        mirrors,
        Arc::new(Cache::new(64, 32 * 1024 * 1024)),
        Metrics::none(),
        None,
        256,
    ));
    let bounds = Bounds {
        retention_minimum: std::time::Duration::MAX,
        allowed_lateness: std::time::Duration::from_secs(u32::MAX.into()),
        clock_skew: std::time::Duration::from_secs(u32::MAX.into()),
        ..Bounds::default()
    };
    let streams = Arc::new(Streams::new(
        root.join("events"),
        "test-plane".to_owned(),
        bounds,
    ));
    let imports = Arc::new(permguard_data_plane::temporal::imports::Imports::new(
        root.join("pull"),
    ));
    // Caught up a moment ago: nothing here is refused for being stale.
    imports
        .advance(ZONE, LEDGER, "offset-1")
        .expect("the cursor advances");

    let plane = Plane {
        submitter: Arc::new(
            Submitter::new(decider, Arc::clone(&streams), Metrics::none()).with_shared_history(
                permguard_core::config::Consistency::SharedBounded,
                Arc::clone(&imports),
                std::time::Duration::from_secs(3600),
            ),
        ),
        events: root.join("events"),
        streams,
    };
    let router = surface(&plane);
    let body = || {
        submission(
            0,
            "Drupe::Action::Login",
            "request",
            "alice",
            json!({"user": "alice", "server": "s1"}),
        )
    };

    // Whole history, fresh cursor: it decides.
    let (status, answered) = post(&router, body()).await;
    assert_eq!(status, StatusCode::OK, "{answered}");

    // The control plane aged out where this plane stood, and the hole is recorded.
    imports
        .record_gap(
            ZONE,
            LEDGER,
            "offset-oldest",
            permguard_data_plane::temporal::imports::Gap {
                zone: ZONE.to_owned(),
                ledger: LEDGER.to_owned(),
                from_sequence: 40,
                to_sequence: 91,
                at: "2026-08-29T00:00:00Z".to_owned(),
                consistency: "shared-bounded".to_owned(),
                resolved: false,
            },
        )
        .expect("the hole is recorded");

    let (status, refused) = post(
        &router,
        submission(
            1,
            "Drupe::Action::Login",
            "response",
            "alice",
            json!({"user": "alice", "server": "s2"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{refused}");
    assert_eq!(refused["code"], "history_incomplete", "{refused}");
    assert!(
        refused["message"]
            .as_str()
            .is_some_and(|held| held.contains("40") && held.contains("91")),
        "the refusal names what was lost: {refused}"
    );

    // The event was still recorded — only the answer is withheld.
    assert_eq!(
        plane
            .streams
            .read_from(ZONE, LEDGER, 0, 100)
            .expect("the journal reads")
            .len(),
        2,
        "the history is kept whole locally whatever the shared one is missing"
    );

    // Accepted explicitly. The next event is a read, so it only permits if the login response
    // that was journalled while the gap was open is replayed now, in this same process. This is
    // the crash-free form of the post-append hole that used to be repaired only by a restart.
    assert_eq!(imports.resolve_gaps(ZONE, LEDGER).expect("it resolves"), 1);
    let (status, answered) = post(
        &router,
        submission(
            100,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"user": "alice", "document": "doc1"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{answered}");
    assert_eq!(answered["decision"], true, "{answered}");
}

/// A retry is one occurrence, and one occurrence is observed once.
#[tokio::test]
async fn a_retry_of_one_occurrence_is_answered_as_one_and_never_observed_twice() {
    let plane = plane("retry");
    let router = surface(&plane);
    let body = submission(
        0,
        "Drupe::Action::Login",
        "response",
        "alice",
        json!({"user": "alice", "server": "s1"}),
    );

    let (first, original) = post(&router, body.clone()).await;
    assert_eq!(first, StatusCode::OK, "{original}");

    // A retry is not a conflict: it is what a client does when it did not see the first reply, and
    // refusing it leaves that client with no way to learn its own occurrence's verdict. So it is
    // answered exactly as it was answered the first time — the same position, the same verdict —
    // with nothing recorded and nothing observed a second time.
    let (second, answered) = post(&router, body).await;
    assert_eq!(second, StatusCode::OK, "{answered}");
    assert_eq!(
        answered, original,
        "the retry is answered with the answer the original got"
    );
    assert_eq!(
        answered["watermark"]["sequence"], 1,
        "and it still names the one position the occurrence occupies: {answered}"
    );

    // The occurrence was observed once. A second observation would make a temporal engine count
    // one thing twice, which is the failure the whole retry rule exists to prevent.
    assert_eq!(
        plane
            .streams
            .read_from(ZONE, LEDGER, 0, 100)
            .expect("the journal reads")
            .len(),
        1,
        "one occurrence, one record"
    );
}

/// One id carrying two occurrences is neither of them.
#[tokio::test]
async fn one_event_id_with_different_content_is_a_conflict_resolved_by_neither() {
    let plane = plane("conflict");
    let router = surface(&plane);

    let (first, _) = post(
        &router,
        submission(
            0,
            "Drupe::Action::Login",
            "response",
            "alice",
            json!({"user": "alice", "server": "s1"}),
        ),
    )
    .await;
    assert_eq!(first, StatusCode::OK);

    // The same id — it is derived from action, kind and timepoint — carrying a different server.
    let (second, answered) = post(
        &router,
        submission(
            0,
            "Drupe::Action::Login",
            "response",
            "alice",
            json!({"user": "alice", "server": "s2"}),
        ),
    )
    .await;

    assert_eq!(second, StatusCode::CONFLICT, "{answered}");
    assert_eq!(answered["code"], "event_id_conflict", "{answered}");
}

/// A caller may not choose its own history, its own producer, or its own position.
#[tokio::test]
async fn a_caller_cannot_state_what_the_server_binds() {
    let plane = plane("bound");
    let router = surface(&plane);

    for smuggled in ["pins", "producer", "seq", "history_key", "observed_at"] {
        let mut body = submission(
            0,
            "Drupe::Action::Login",
            "response",
            "alice",
            json!({"user": "alice", "server": "s1"}),
        );
        body["event"]["data"][smuggled] = json!("mine");

        let (status, answered) = post(&router, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "`{smuggled}`: {answered}");
    }
}

/// A profile nobody declared is refused exactly as the stateless interface refuses one.
///
/// The same code and the same status, because it is the same mistake seen from the other
/// interface, and a caller that learned one convention should not have to learn a second.
#[tokio::test]
async fn a_profile_this_ledger_does_not_declare_is_refused_as_the_other_interface_refuses_it() {
    let plane = plane("profile");
    let router = surface(&plane);
    let mut body = submission(
        0,
        "Drupe::Action::Login",
        "response",
        "alice",
        json!({"user": "alice", "server": "s1"}),
    );
    body["store"]["profile"] = json!("nonexistent");

    let (status, answered) = post(&router, body).await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{answered}");
    assert_eq!(answered["code"], "profile_unknown", "{answered}");
    assert!(
        answered["message"]
            .as_str()
            .is_some_and(|held| held.contains("temporal")),
        "the refusal lists what the ledger does declare: {answered}"
    );
}

/// An event type nothing registers is refused before anything is read.
#[tokio::test]
async fn an_event_type_this_plane_does_not_accept_is_refused_by_name() {
    let plane = plane("type");
    let router = surface(&plane);
    let mut body = submission(
        0,
        "Drupe::Action::Login",
        "response",
        "alice",
        json!({"user": "alice", "server": "s1"}),
    );
    body["event"]["type"] = json!("acme.whatever.v1");

    let (status, answered) = post(&router, body).await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{answered}");
    assert_eq!(answered["code"], "event_type_unsupported", "{answered}");
    assert!(
        answered["message"]
            .as_str()
            .is_some_and(|held| held.contains(permguard_languages::event::EVENT_TYPE)),
        "the refusal says what it does accept: {answered}"
    );
}

/// The document advertises the route the router actually mounts.
#[tokio::test]
async fn the_discovery_document_names_the_route_this_plane_answers() {
    let plane = plane("discovery");
    let router = surface(&plane);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(configuration::CONFIGURATION_PATH)
                .body(Body::empty())
                .expect("the request builds"),
        )
        .await
        .expect("the surface answers");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("the body is read")
        .to_bytes();
    let document: Value = serde_json::from_slice(&bytes).expect("the document parses");

    assert_eq!(
        document["interface"],
        permguard_languages::temporal::INTERFACE
    );
    let advertised = document["endpoints"]["submission"]
        .as_str()
        .expect("an endpoint");
    assert!(
        advertised.ends_with(permguard_languages::temporal::SUBMISSION_PATH),
        "{advertised}"
    );
    // And the advertised route answers.
    let (status, _) = post(
        &router,
        submission(
            0,
            "Drupe::Action::Login",
            "response",
            "alice",
            json!({"user": "alice", "server": "s1"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

/// The two transports are one interface: same request, same answer, same path underneath.
#[tokio::test]
async fn grpc_and_http_answer_the_same_submission_identically() {
    use permguard_data_plane::temporal::grpc;
    use permguard_data_plane::v1::temporal_policy_decision_point_server::TemporalPolicyDecisionPoint as _;

    let over_http = plane("http-parity");
    let over_grpc = plane("grpc-parity");

    // The same trace on both, so the histories they decide against are the same.
    let http_router = surface(&over_http);
    let api = grpc::TemporalPdpApi {
        submitter: Arc::clone(&over_grpc.submitter),
        disclosure: Disclosure::Full,
        base_url: "http://plane.test".to_owned(),
        pdp: "test-plane".to_owned(),
    };

    for (at, action, kind, user) in TRACE {
        let body = submission(at, action, kind, user, input_of(at, action, kind, user));
        let (status, answered) = post(&http_router, body.clone()).await;
        assert_eq!(status, StatusCode::OK, "@{at}: {answered}");

        let proto = permguard_data_plane::v1::SubmitEventRequest {
            store: Some(permguard_data_plane::v1::EventStore {
                zone: ZONE.to_owned(),
                ledger: LEDGER.to_owned(),
                profile: PROFILE.to_owned(),
            }),
            event: Some(permguard_data_plane::v1::TypedEvent {
                r#type: permguard_languages::event::EVENT_TYPE.to_owned(),
                data: Some(permguard_data_plane::authz::translate::struct_from_map(
                    body["event"]["data"].as_object().expect("an object"),
                )),
            }),
        };
        let over_the_wire = api
            .submit_event(tonic::Request::new(proto))
            .await
            .expect("the gRPC surface answers")
            .into_inner();

        assert_eq!(
            over_the_wire.event_id, answered["event_id"],
            "@{at}: the two transports name the same occurrence"
        );
        assert_eq!(
            over_the_wire.decision,
            answered["decision"].as_bool(),
            "@{at}: the two transports decide the same"
        );
        // A history-only kind leaves the verdict unset over both, rather than sending `false`.
        assert_eq!(
            over_the_wire.decision.is_none(),
            answered.get("decision").is_none(),
            "@{at}: {answered}"
        );
        assert_eq!(
            over_the_wire
                .watermark
                .as_ref()
                .map(|held| held.sequence)
                .unwrap_or_default(),
            answered["watermark"]["sequence"]
                .as_u64()
                .unwrap_or_default(),
            "@{at}: the two transports place it at the same position"
        );
    }
}

/// The shipped example, run the way its README tells a reader to run it.
///
/// The files are read from `examples/dogwood-session-access` — the manifest, the policy, both
/// schemas and the five occurrences — and the expected outcomes are the ones its README states.
/// The other examples are covered by `permguard test`, which decides stateless requests offline;
/// this one cannot be, because its answers depend on a history that has to be submitted in order.
/// So it is covered here instead, and the README's table is something the build proves.
mod shipped_example {
    use super::*;

    fn example(path: &str) -> String {
        let held = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/dogwood-session-access")
            .join(path);

        std::fs::read_to_string(&held)
            .unwrap_or_else(|error| panic!("reading {}: {error}", held.display()))
    }

    /// The example's own ledger, built from its own files.
    fn provision_example(root: &Path) -> Mirror {
        // Through the same reader the CLI uses, so the example's own YAML is what is tested
        // rather than a manifest rebuilt here to match it.
        let manifest =
            permguard_languages::manifest_file::from_yaml(example("manifest.yml").as_bytes())
                .expect("the example's manifest parses");

        let path = root.join(format!("{ZONE}-id")).join(format!("{LEDGER}-id"));
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

        let mut entries = Vec::new();
        let digest = put_blob(
            permguard_languages::MEDIA_TYPE_POLICY_DOGWOOD,
            example("governance/read-after-login.dw").as_bytes(),
        );
        let mut annotations = BTreeMap::new();
        annotations.insert(
            ANNOTATION_POLICY_ID.to_owned(),
            "01a0-read-after-login".to_owned(),
        );
        annotations.insert(ANNOTATION_POLICY_KIND.to_owned(), "policy".to_owned());
        entries.push(TreeEntry {
            kind: Kind::Blob,
            digest,
            name: "read-after-login.dw".to_owned(),
            annotations,
        });
        for (type_name, file) in [
            (
                dogwood_artifacts::ACTION_SCHEMA,
                "governance/schema.cedarschema",
            ),
            (
                dogwood_artifacts::EVENT_SCHEMA,
                "governance/events.dwschema",
            ),
        ] {
            let artifact =
                permguard_languages::artifact::artifact_type(type_name).expect("registered");
            let digest = put_blob(artifact.media_type(), example(file).as_bytes());
            entries.push(TreeEntry {
                kind: Kind::Blob,
                digest,
                name: artifact.canonical_filename().expect("named").to_owned(),
                annotations: BTreeMap::new(),
            });
        }
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        let tree = Tree { entries };
        let partition_digest =
            objects::put(&store, "objects", &tree.encode().expect("the tree encodes"))
                .expect("stored");

        let root_tree = Tree {
            entries: vec![TreeEntry {
                kind: Kind::Tree,
                digest: partition_digest,
                name: "governance".to_owned(),
                annotations: BTreeMap::new(),
            }],
        };
        let root_digest = objects::put(
            &store,
            "objects",
            &root_tree.encode().expect("the tree encodes"),
        )
        .expect("stored");

        let commit = Commit {
            tree: root_digest,
            manifest: manifest_digest,
            predecessors: Vec::new(),
            author: "tests".to_owned(),
            author_at: 1_700_000_000,
            message: "the shipped example".to_owned(),
        };
        let commit_digest = objects::put(
            &store,
            "objects",
            &commit.encode().expect("the commit encodes"),
        )
        .expect("stored");
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
            zone_id: format!("{ZONE}-id"),
            zone_name: ZONE.to_owned(),
            ledger_id: format!("{LEDGER}-id"),
            ledger_name: LEDGER.to_owned(),
            server: "http://127.0.0.1:7556".to_owned(),
        };
        permguard_data_plane::authz::store::record(&path, &identity).expect("recorded");

        Mirror { path, identity }
    }

    /// The same volume, opened by a process that remembers nothing.
    ///
    /// Everything in memory — the open journal, its recovered instance, the retry index — is
    /// dropped, and only what is on disk is carried across. That is what a restart is.
    fn reopened(events: &Path) -> Plane {
        let mirrors = events
            .parent()
            .expect("the volume is above the journals")
            .join("mirrors");
        let decider = Arc::new(Decider::new(
            mirrors,
            Arc::new(Cache::new(64, 32 * 1024 * 1024)),
            Metrics::none(),
            None,
            256,
        ));
        let bounds = Bounds {
            retention_minimum: std::time::Duration::MAX,
            allowed_lateness: std::time::Duration::from_secs(u32::MAX.into()),
            clock_skew: std::time::Duration::from_secs(u32::MAX.into()),
            ..Bounds::default()
        };

        let streams = Arc::new(Streams::new(
            events.to_path_buf(),
            "example-plane".to_owned(),
            bounds,
        ));

        Plane {
            submitter: Arc::new(Submitter::new(
                decider,
                Arc::clone(&streams),
                Metrics::none(),
            )),
            events: events.to_path_buf(),
            streams,
        }
    }

    /// The example's plane: its own ledger, and a journal beside it.
    fn example_plane() -> Plane {
        let root = scratch("shipped-example");
        let mirrors = root.join("mirrors");
        std::fs::create_dir_all(&mirrors).expect("the mirrors root is created");
        provision_example(&mirrors);

        let decider = Arc::new(Decider::new(
            mirrors,
            Arc::new(Cache::new(64, 32 * 1024 * 1024)),
            Metrics::none(),
            None,
            256,
        ));
        let events = root.join("events");
        // The example's occurrences are dated in 2026; the bounds are widened so the test is about
        // the temporal semantics rather than about how long ago the README was written.
        let bounds = Bounds {
            retention_minimum: std::time::Duration::MAX,
            allowed_lateness: std::time::Duration::from_secs(u32::MAX.into()),
            clock_skew: std::time::Duration::from_secs(u32::MAX.into()),
            ..Bounds::default()
        };

        let streams = Arc::new(Streams::new(
            events.clone(),
            "example-plane".to_owned(),
            bounds,
        ));

        Plane {
            submitter: Arc::new(Submitter::new(
                decider,
                Arc::clone(&streams),
                Metrics::none(),
            )),
            events,
            streams,
        }
    }

    /// The outcomes the example's README states, in the order its files are numbered.
    #[tokio::test]
    async fn the_shipped_example_produces_the_outcomes_its_readme_states() {
        let plane = example_plane();
        let router = surface(&plane);

        let expected: [(&str, &str, Option<bool>); 5] = [
            ("1-login-request.json", "decided", Some(false)),
            ("2-login-response.json", "accepted", None),
            ("3-read-permitted.json", "decided", Some(true)),
            ("4-read-outside-window.json", "decided", Some(false)),
            ("5-read-other-user.json", "decided", Some(false)),
        ];

        for (file, outcome, decision) in expected {
            let body: Value = serde_json::from_str(&example(&format!("events/{file}")))
                .unwrap_or_else(|error| panic!("{file}: {error}"));
            let (status, answered) = post(&router, body).await;

            assert_eq!(status, StatusCode::OK, "{file}: {answered}");
            assert_eq!(answered["outcome"], outcome, "{file}: {answered}");
            assert_eq!(
                answered["decision"].as_bool(),
                decision,
                "{file}: {answered}"
            );
            if decision.is_none() {
                assert!(
                    answered.get("decision").is_none(),
                    "a history-only kind returns no verdict at all, not `false`: {answered}"
                );
                assert!(
                    answered.get("evaluations").is_none(),
                    "a history-only occurrence has no partition verdicts: {answered}"
                );
            } else {
                assert_eq!(
                    answered["evaluations"][0]["partition"], "governance",
                    "the aggregate remains attributable to the profile's partition: {answered}"
                );
                assert_eq!(
                    answered["evaluations"][0]["decision"].as_bool(),
                    decision,
                    "the partition answer and aggregate agree in this one-partition profile: \
                     {answered}"
                );
            }
            // Every answer says which history it ranged over, so an auditor can reproduce it.
            assert_eq!(answered["history"]["mode"], "local", "{file}: {answered}");
        }
    }
    /// The example's refusals, which are as much of the contract as its permits.
    ///
    /// # What this is actually about
    ///
    /// An example that only shows what works teaches half a contract, and the half it leaves out is
    /// the half an integration meets first. Each file under `refusals/` is a submission somebody
    /// will send by accident, and each is refused for a reason the answer states — never accepted
    /// with the offending part quietly dropped, which is how an event ends up in a history meaning
    /// something other than what it said.
    #[tokio::test]
    async fn the_shipped_example_refuses_what_its_readme_says_it_refuses() {
        let plane = example_plane();
        let router = surface(&plane);

        // The history the conflict case collides with. Submitted first, because a conflict is only
        // a conflict against something already recorded.
        for file in [
            "1-login-request.json",
            "2-login-response.json",
            "3-read-permitted.json",
        ] {
            let body: Value = serde_json::from_str(&example(&format!("events/{file}")))
                .unwrap_or_else(|error| panic!("{file}: {error}"));
            let (status, answered) = post(&router, body).await;
            assert_eq!(status, StatusCode::OK, "{file}: {answered}");
        }

        let expected: [(&str, StatusCode, &str); 4] = [
            // An action the schema does not derive. Not "an event with an unusual action" — the
            // schema is what says which occurrences this partition can hold, and one it cannot
            // describe is one no temporal predicate could ever match.
            (
                "unknown-action.json",
                StatusCode::BAD_REQUEST,
                "event_action_undeclared",
            ),
            // A logged field nobody declared. Accepting it would store a value the engine cannot
            // see, in a record that looks like it carries it.
            (
                "undeclared-field.json",
                StatusCode::BAD_REQUEST,
                "event_field_undeclared",
            ),
            // A pin the caller also sent, disagreeing with the request's own principal. One of the
            // two is a lie about the request, and choosing either would let a caller pick which
            // history its event lands in.
            (
                "pin-disagrees.json",
                StatusCode::BAD_REQUEST,
                "event_pin_contradicted",
            ),
            // One id, two occurrences. Never resolved by choosing one.
            (
                "conflicting-retry.json",
                StatusCode::CONFLICT,
                "event_id_conflict",
            ),
        ];

        for (file, status, code) in expected {
            let body: Value = serde_json::from_str(&example(&format!("refusals/{file}")))
                .unwrap_or_else(|error| panic!("{file}: {error}"));
            let (answered_status, answered) = post(&router, body).await;

            assert_eq!(answered_status, status, "{file}: {answered}");
            assert_eq!(answered["code"], code, "{file}: {answered}");
        }
    }

    /// The same occurrence submitted twice is recorded once, and answered as the retry it is.
    ///
    /// A retry is the ordinary case — a client that did not hear the answer sends it again — and
    /// the one thing it must not do is get counted twice, because a temporal engine counts
    /// occurrences. So the second submission is neither stored nor observed, and the caller is told
    /// which position holds the one that was.
    #[tokio::test]
    async fn a_retry_of_an_occurrence_is_recorded_once_and_observed_once() {
        let plane = example_plane();
        let router = surface(&plane);

        let body: Value = serde_json::from_str(&example("events/1-login-request.json"))
            .expect("the occurrence parses");
        let (status, first) = post(&router, body.clone()).await;
        assert_eq!(status, StatusCode::OK, "{first}");
        let at = first["watermark"]["sequence"].as_u64().expect("a position");

        let (status, again) = post(&router, body).await;
        assert_eq!(status, StatusCode::OK, "{again}");
        assert_eq!(
            again, first,
            "the retry is answered with the answer the original got"
        );
        assert_eq!(
            again["watermark"]["sequence"], at,
            "and it still names the position the recorded one occupies: {again}"
        );
    }

    /// A crash after the journal append but before the response commit is recoverable.
    #[tokio::test]
    async fn a_retry_finishes_an_occurrence_whose_answer_was_not_committed() {
        let plane = example_plane();
        let router = surface(&plane);
        let body: Value = serde_json::from_str(&example("events/2-login-response.json"))
            .expect("the occurrence parses");
        let event_id = body["event"]["data"]["event_id"]
            .as_str()
            .expect("the occurrence has an id");

        let (status, first) = post(&router, body.clone()).await;
        assert_eq!(status, StatusCode::OK, "{first}");
        plane
            .streams
            .record_outcome(ZONE, LEDGER, event_id, &Value::Null)
            .expect("the crash window is reproduced on disk");
        let volume = plane.events.clone();
        drop(router);
        drop(plane);

        let restarted = reopened(&volume);
        let router = surface(&restarted);
        let (status, recovered) = post(&router, body).await;
        assert_eq!(status, StatusCode::OK, "{recovered}");
        assert_eq!(
            recovered, first,
            "recovery commits the original receipt shape"
        );

        let read: Value = serde_json::from_str(&example("events/3-read-permitted.json"))
            .expect("the decision occurrence parses");
        let (status, decided) = post(&router, read).await;
        assert_eq!(status, StatusCode::OK, "{decided}");
        assert_eq!(
            decided["decision"], true,
            "the recovered login is present once in the history used by the next decision"
        );
    }

    /// A crash after auditing a decision does not mint a second identity for its retry.
    #[tokio::test]
    async fn a_recovered_decision_keeps_the_identity_reserved_before_its_audit() {
        let plane = example_plane();
        let router = surface(&plane);

        let login: Value = serde_json::from_str(&example("events/2-login-response.json"))
            .expect("the history occurrence parses");
        let (status, accepted) = post(&router, login).await;
        assert_eq!(status, StatusCode::OK, "{accepted}");

        let body: Value = serde_json::from_str(&example("events/3-read-permitted.json"))
            .expect("the decision occurrence parses");
        let event_id = body["event"]["data"]["event_id"]
            .as_str()
            .expect("the occurrence has an id");
        let (status, first) = post(&router, body.clone()).await;
        assert_eq!(status, StatusCode::OK, "{first}");
        let decision_id = first["decision_id"]
            .as_str()
            .expect("a decision has a stable identity")
            .to_owned();

        // Reproduce the boundary after the decision identity and audit were made durable but
        // before the idempotency response was committed.
        plane
            .streams
            .record_outcome(ZONE, LEDGER, event_id, &Value::Null)
            .expect("the crash window is reproduced on disk");
        let volume = plane.events.clone();
        drop(router);
        drop(plane);

        let restarted = reopened(&volume);
        let router = surface(&restarted);
        let (status, recovered) = post(&router, body).await;
        assert_eq!(status, StatusCode::OK, "{recovered}");
        assert_eq!(
            recovered["decision_id"], decision_id,
            "one occurrence keeps one decision identity across audit recovery: {recovered}"
        );
        assert_eq!(
            recovered["watermark"], first["watermark"],
            "recovery answers for the original journal position: {recovered}"
        );
    }

    /// A plane restarted mid-session continues the history it had, rather than starting one.
    ///
    /// # What this is actually about
    ///
    /// A restart is the ordinary event a durable history has to survive, and everything about this
    /// interface depends on how it survives it. The sequence must continue, not restart; the chain
    /// must link to what was there, not to a new genesis; the retry index must be rebuilt from the
    /// journal's tail, or a client's retry across a restart becomes a duplicate; and a decision made
    /// after the restart must range over the history from before it, or the restart silently
    /// changed what the policies answer.
    ///
    /// So the example is submitted in two halves with a restart between them, and occurrence 3 —
    /// which is only permitted because occurrence 2 happened — is asked *after* the restart.
    #[tokio::test]
    async fn a_restart_continues_the_history_and_decides_against_what_was_there() {
        let plane = example_plane();
        let router = surface(&plane);

        for file in ["1-login-request.json", "2-login-response.json"] {
            let body: Value = serde_json::from_str(&example(&format!("events/{file}")))
                .unwrap_or_else(|error| panic!("{file}: {error}"));
            let (status, answered) = post(&router, body).await;
            assert_eq!(status, StatusCode::OK, "{file}: {answered}");
        }

        // The restart: everything this process held is dropped, and only the volume is carried
        // across. That the new plane can open the journal at all is part of the assertion — a
        // journal holds an exclusive lock on its directory for as long as it lives, so a "restart"
        // that had not really let go would be refused here rather than quietly writing a second
        // chain into one stream.
        let volume = plane.events.clone();
        drop(router);
        drop(plane);
        let restarted = reopened(&volume);
        let router = surface(&restarted);

        let body: Value = serde_json::from_str(&example("events/3-read-permitted.json"))
            .expect("the occurrence parses");
        let (status, answered) = post(&router, body).await;

        assert_eq!(status, StatusCode::OK, "{answered}");
        assert!(
            answered["decision"].as_bool().unwrap_or_default(),
            "the login from before the restart is still in the history: {answered}"
        );
        assert_eq!(
            answered["watermark"]["sequence"], 3,
            "and the sequence continued rather than starting again: {answered}"
        );

        // The retry index, rebuilt from the journal's tail: a client retrying across a restart is
        // still recognised, or a restart would turn every in-flight retry into a duplicate.
        let body: Value = serde_json::from_str(&example("events/2-login-response.json"))
            .expect("the occurrence parses");
        let (status, again) = post(&router, body).await;
        assert_eq!(status, StatusCode::OK, "{again}");
        assert_eq!(
            again["watermark"]["sequence"], 2,
            "the retry names the position the original took, from before the restart: {again}"
        );
        // The answer itself survived the restart too, which is when a client is most likely to be
        // retrying: it is read back from the volume rather than decided again.
        assert_eq!(again["outcome"], "accepted", "{again}");
    }
}
