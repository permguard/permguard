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
use permguard_data_plane::blocking::Blocking;
use permguard_data_plane::temporal::streams::Streams;
use permguard_data_plane::temporal::submit::Submitter;
use permguard_data_plane::temporal::{configuration, http};
use permguard_events::journal::Bounds;
use permguard_languages::dogwood_artifacts;
use permguard_languages::registry;

fn blocking() -> Blocking {
    Blocking::new(
        permguard_core::config::default_max_blocking(),
        Metrics::none(),
    )
}
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
/// What storage is keyed by: a request may name either, and one ledger keeps one journal.
const ZONE_ID: &str = "acme-id";
const LEDGER_ID: &str = "agent-governance-id";
const PROFILE: &str = "temporal";
/// The second profile of [`manifest_two_profiles`], over its own identical partition.
const AUDIT_PROFILE: &str = "audit";

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

/// The same ledger, with a second partition identical to the first behind its own profile.
///
/// Two profiles that range over one history is the shape the per-partition replay note exists for:
/// each profile's rebuild touches only its own partitions, and a note kept per history would let
/// one profile's rebuild mark the other's engine clean.
fn manifest_two_profiles() -> Manifest {
    let mut manifest = manifest();
    let audit = manifest
        .partitions
        .get("governance")
        .expect("the base manifest declares governance")
        .clone();
    manifest.partitions.insert("audit".to_owned(), audit);
    manifest.profiles.insert(
        AUDIT_PROFILE.to_owned(),
        Profile {
            r#type: permguard_objects::manifest::PROFILE_PDP_TEMPORAL_V1ALPHA1.to_owned(),
            partitions: vec!["audit".to_owned()],
        },
    );

    manifest
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

    // One entry per declared partition, all pointing at the same tree: the tests that need two
    // partitions need them to hold the same policy, not different ones.
    let root_tree = Tree {
        entries: manifest
            .partitions
            .keys()
            .map(|name| TreeEntry {
                kind: Kind::Tree,
                digest: partition_digest.clone(),
                name: name.clone(),
                annotations: BTreeMap::new(),
            })
            .collect(),
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
        server: "http://127.0.0.1:6443".to_owned(),
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
    /// The policy state the decider reads, so a test can take it away.
    mirrors: PathBuf,
}

fn plane(tag: &str) -> Plane {
    plane_of(tag, &manifest(), blocking())
}

/// The same plane, against a blocking budget the test chooses.
fn plane_with(tag: &str, blocking: Blocking) -> Plane {
    plane_of(tag, &manifest(), blocking)
}

/// The same plane, against a manifest the test chooses.
fn plane_of(tag: &str, manifest: &Manifest, blocking: Blocking) -> Plane {
    let root = scratch(tag);
    let mirrors = root.join("mirrors");
    std::fs::create_dir_all(&mirrors).expect("the mirrors root is created");
    provision(&mirrors, manifest);

    let decider = Arc::new(Decider::new(
        mirrors.clone(),
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
            blocking,
            Metrics::none(),
        )),
        events,
        streams,
        mirrors,
    }
}

/// One occurrence of upstream's trace, in Permguard's own event contract.
fn submission(at: i64, action: &str, kind: &str, user: &str, input: Value) -> Value {
    submission_to(PROFILE, at, action, kind, user, input)
}

/// The same occurrence, addressed to a stated profile.
fn submission_to(
    profile: &str,
    at: i64,
    action: &str,
    kind: &str,
    user: &str,
    input: Value,
) -> Value {
    let occurred_at =
        permguard_events::index::render_epoch_seconds(at).expect("the timepoint is an instant");

    json!({
        "store": {"zone": ZONE, "ledger": LEDGER, "profile": profile},
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
        .join(ZONE_ID)
        .join(LEDGER_ID)
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
    // One instant for all of them, and the identifiers made distinct on their own.
    //
    // They used to carry rising instants, which is a shape this plane cannot honour concurrently:
    // the journal assigns sequences in arrival order, so a submission whose instant is older than
    // one already recorded is refused rather than applied behind it — see
    // `an_occurrence_behind_what_the_history_holds_is_refused`. Racing rising instants therefore
    // made the outcome depend on the scheduler. What this test is about is the sequencer, and the
    // instants were only ever a convenient way to tell twenty-four occurrences apart.
    let mut inflight = Vec::with_capacity(SUBMISSIONS);
    for nth in 0..SUBMISSIONS {
        let router = router.clone();
        let mut body = submission(
            0,
            "Drupe::Action::Login",
            "response",
            "alice",
            json!({"user": "alice", "server": format!("s{nth}")}),
        );
        body["event"]["data"]["event_id"] = json!(format!("login-response-{nth}"));
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
        .sequencer(ZONE_ID, LEDGER_ID)
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
        mirrors.clone(),
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
        .advance(ZONE_ID, LEDGER_ID, "offset-1")
        .expect("the cursor advances");

    let plane = Plane {
        mirrors: mirrors.clone(),
        submitter: Arc::new(
            Submitter::new(decider, Arc::clone(&streams), blocking(), Metrics::none())
                .with_shared_history(
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
            ZONE_ID,
            LEDGER_ID,
            "offset-oldest",
            permguard_data_plane::temporal::imports::Gap {
                zone: ZONE_ID.to_owned(),
                ledger: LEDGER_ID.to_owned(),
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
            .read_from(ZONE_ID, LEDGER_ID, 0, 100)
            .expect("the journal reads")
            .len(),
        2,
        "the history is kept whole locally whatever the shared one is missing"
    );

    // Accepted explicitly. The next event is a read, so it only permits if the login response
    // that was journalled while the gap was open is replayed now, in this same process. This is
    // the crash-free form of the post-append hole that used to be repaired only by a restart.
    assert_eq!(
        imports
            .resolve_gaps(ZONE_ID, LEDGER_ID)
            .expect("it resolves"),
        1
    );
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
            .read_from(ZONE_ID, LEDGER_ID, 0, 100)
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
            server: "http://127.0.0.1:6443".to_owned(),
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
            mirrors.clone(),
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
                blocking(),
                Metrics::none(),
            )),
            events: events.to_path_buf(),
            streams,
            mirrors: mirrors.clone(),
        }
    }

    /// The example's plane: its own ledger, and a journal beside it.
    fn example_plane() -> Plane {
        let root = scratch("shipped-example");
        let mirrors = root.join("mirrors");
        std::fs::create_dir_all(&mirrors).expect("the mirrors root is created");
        provision_example(&mirrors);

        let decider = Arc::new(Decider::new(
            mirrors.clone(),
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
                blocking(),
                Metrics::none(),
            )),
            events,
            streams,
            mirrors: mirrors.clone(),
        }
    }

    /// The outcomes the example's README states, in the order its files are numbered.
    #[tokio::test]
    async fn the_shipped_example_produces_the_outcomes_its_readme_states() {
        let plane = example_plane();
        let router = surface(&plane);

        let expected: [(&str, &str, Option<bool>); 5] = [
            ("events/1-login-request.json", "decided", Some(false)),
            ("events/2-login-response.json", "accepted", None),
            ("requests/2-read-inside-window.json", "decided", Some(true)),
            (
                "requests/3-read-outside-window.json",
                "decided",
                Some(false),
            ),
            ("requests/4-read-other-user.json", "decided", Some(false)),
        ];

        for (fixture, outcome, decision) in expected {
            let body: Value = serde_json::from_str(&example(fixture))
                .unwrap_or_else(|error| panic!("{fixture}: {error}"));
            let (status, answered) = post(&router, body).await;

            assert_eq!(status, StatusCode::OK, "{fixture}: {answered}");
            assert_eq!(answered["outcome"], outcome, "{fixture}: {answered}");
            assert_eq!(
                answered["decision"].as_bool(),
                decision,
                "{fixture}: {answered}"
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
            assert_eq!(
                answered["history"]["mode"], "local",
                "{fixture}: {answered}"
            );
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
        for fixture in [
            "events/1-login-request.json",
            "events/2-login-response.json",
            "requests/2-read-inside-window.json",
        ] {
            let body: Value = serde_json::from_str(&example(fixture))
                .unwrap_or_else(|error| panic!("{fixture}: {error}"));
            let (status, answered) = post(&router, body).await;
            assert_eq!(status, StatusCode::OK, "{fixture}: {answered}");
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
            .record_outcome(
                ZONE_ID,
                LEDGER_ID,
                event_id,
                permguard_data_plane::temporal::streams::Routed {
                    profile: "default",
                    kind: "occurrence",
                },
                &Value::Null,
            )
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

        let read: Value = serde_json::from_str(&example("requests/2-read-inside-window.json"))
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

        let body: Value = serde_json::from_str(&example("requests/2-read-inside-window.json"))
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
            .record_outcome(
                ZONE_ID,
                LEDGER_ID,
                event_id,
                permguard_data_plane::temporal::streams::Routed {
                    profile: "default",
                    kind: "occurrence",
                },
                &Value::Null,
            )
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

        let body: Value = serde_json::from_str(&example("requests/2-read-inside-window.json"))
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

/// A settled answer survives the profile it was decided under being taken away.
///
/// # What this is actually about
///
/// A completed submission is a fact this plane already stated to a caller, and a retry is that
/// caller asking what it was told. Re-deriving the answer needs the profile, schema and commit it
/// was decided under, and none of those is guaranteed to still be here: a profile is updated, a
/// schema tightened, a partition removed.
///
/// If the retry loads them first, a settled answer starts failing for reasons that postdate it —
/// the caller is told the event is unknown, or invalid, when it is durable and was answered. So
/// the durable answer is read before any of that, and this asserts the order by removing the
/// profile entirely between the two calls: nothing that follows could compile it.
#[tokio::test]
async fn a_settled_answer_is_returned_after_its_profile_is_gone() {
    let plane = plane("settled-after-removal");
    let router = surface(&plane);
    let event = submission(
        0,
        "Drupe::Action::Login",
        "response",
        "alice",
        json!({"user": "alice", "server": "s1"}),
    );

    let (first, answered) = post(&router, event.clone()).await;
    assert_eq!(first, StatusCode::OK, "the first submission is answered");

    // The profile is gone. A re-derivation cannot happen from here.
    // The profile is taken away, not the mirror: the plane still serves this ledger — its
    // identity file is what resolves the canonical key — but nothing here can compile a profile
    // any more, so an answer that needed one could not be produced a second time.
    // A mirror lives at `<mirrors>/<zone>/<ledger>`, and its identity file beside its policy
    // state. Everything but that file goes.
    for zone in std::fs::read_dir(&plane.mirrors).expect("the mirrors root reads") {
        for ledger in std::fs::read_dir(zone.expect("a zone").path()).expect("the zone reads") {
            for held in std::fs::read_dir(ledger.expect("a ledger").path()).expect("it reads") {
                let held = held.expect("an entry").path();
                if held.file_name().and_then(|name| name.to_str())
                    == Some(permguard_data_plane::authz::store::IDENTITY_FILE)
                {
                    continue;
                }
                match held.is_dir() {
                    true => std::fs::remove_dir_all(&held).expect("the policy state goes"),
                    false => std::fs::remove_file(&held).expect("the policy state goes"),
                }
            }
        }
    }

    let (second, replayed) = post(&router, event).await;
    assert_eq!(
        second,
        StatusCode::OK,
        "a retry of a settled answer is not refused because its profile went away: {replayed}"
    );
    assert_eq!(
        replayed["event_id"], answered["event_id"],
        "and it is the same answer, read from the journal rather than decided again"
    );
    assert_eq!(replayed["outcome"], answered["outcome"]);
    assert_eq!(replayed["decision"], answered["decision"]);
    assert_eq!(
        replayed["decision_id"], answered["decision_id"],
        "a settled decision keeps its identity: a second one would be a second audit record"
    );
}

/// Naming a ledger by its identifier and by its name addresses one history.
///
/// # What this is actually about
///
/// A PEP configured with identifiers and a PEP configured with names are both configured
/// correctly — `Mirror::answers_to` accepts either. Keying storage by whichever string arrived
/// therefore let one ledger own *two* journals: two sequence spaces, two histories, two
/// idempotency indexes, each blind to the other. A retry that reached the other one would not be
/// recognised as a retry, and would be observed a second time by a temporal engine that counts
/// order.
///
/// So the assertion is not that both calls answer, but that the second is recognised as the
/// *same* occurrence: one record, one sequence, one answer.
#[tokio::test]
async fn a_ledger_named_two_ways_keeps_one_history() {
    let plane = plane("two-names");
    let router = surface(&plane);

    let by_name = submission(
        0,
        "Drupe::Action::Login",
        "response",
        "alice",
        json!({"user": "alice", "server": "s1"}),
    );
    // The same submission, addressed the other way a caller may address it.
    let mut by_id = by_name.clone();
    by_id["store"]["zone"] = json!(ZONE_ID);
    by_id["store"]["ledger"] = json!(LEDGER_ID);

    let (first, answered) = post(&router, by_name).await;
    assert_eq!(first, StatusCode::OK, "{answered}");

    let (second, replayed) = post(&router, by_id).await;
    assert_eq!(
        second,
        StatusCode::OK,
        "the same occurrence addressed by identifier is served by the same ledger: {replayed}"
    );
    assert_eq!(
        replayed["watermark"]["sequence"], answered["watermark"]["sequence"],
        "and it occupies the one position it already occupied, rather than a second one"
    );
    assert_eq!(replayed["event_id"], answered["event_id"]);
    assert_eq!(
        replayed["history"], answered["history"],
        "one ledger, one history"
    );

    // The decisive one: a second journal would hold this occurrence a second time.
    assert_eq!(
        plane
            .streams
            .read_from(ZONE_ID, LEDGER_ID, 0, 100)
            .expect("the journal reads")
            .len(),
        1,
        "one occurrence, one record, whichever way the ledger was named"
    );
    assert!(
        !plane.events.join(ZONE).join(LEDGER).exists(),
        "and nothing was written under the display names"
    );
}

/// A submission is bounded by the shared blocking pool, and the ceiling refuses rather than queues.
///
/// # What this is really asserting
///
/// Everything a submission does synchronously — validating the occurrence, appending it, taking its
/// turn, rebuilding the history and evaluating it — used to run on the runtime worker that carried
/// the request. Only the append had been moved to the pool. That meant an evaluation which stopped
/// returning, and upstream's providers are synchronous and cannot be interrupted, blocked a thread
/// the whole process shares: outside the deployment's configured bound, invisible to
/// `permguard_blocking_*`, and with health checks and unrelated ledgers queued behind it.
///
/// The permit here is taken by something that is *not* a submission, which is the point: the budget
/// is one budget. If the submission path had its own, or none, this test would pass with the bug in
/// place.
///
/// It also shows the runtime is still turning while the permit is held — the refusal is served, not
/// stalled — and that the capacity comes back when the work ends.
#[tokio::test]
async fn a_submission_spends_a_permit_of_the_shared_pool_and_the_ceiling_refuses() {
    let pool = Blocking::new(1, Metrics::none());
    let plane = plane_with("temporal-pool-bound", pool.clone());
    let router = surface(&plane);

    // Hold the only permit from outside the submission path. `recv` returns when the test drops the
    // sender, so nothing here depends on a sleep being long enough.
    let (release, wait) = std::sync::mpsc::channel::<()>();
    let occupying = {
        let pool = pool.clone();
        tokio::spawn(async move {
            pool.run(&[], move || {
                let _ = wait.recv();
            })
            .await
        })
    };
    while pool.in_flight() == 0 {
        tokio::task::yield_now().await;
    }

    let (status, refused) = post(
        &router,
        submission(
            1,
            "Drupe::Action::Login",
            "response",
            "alice",
            json!({"user": "alice", "server": "s1"}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "the budget is spent, so the submission is refused: {refused}"
    );
    assert_eq!(
        refused["code"], "event_submission_at_capacity",
        "and refused for the budget, not for anything about the occurrence: {refused}"
    );

    drop(release);
    occupying
        .await
        .expect("the occupying task finishes")
        .expect("it held a permit rather than being refused");
    while pool.in_flight() > 0 {
        tokio::task::yield_now().await;
    }

    let (status, body) = post(
        &router,
        submission(
            1,
            "Drupe::Action::Login",
            "response",
            "alice",
            json!({"user": "alice", "server": "s1"}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the capacity came back with the work that held it: {body}"
    );
}

/// An occurrence behind the history is refused, kept as evidence, and replayed into its place.
///
/// # What this is really asserting
///
/// `allowed_lateness` admits an event whose instant is behind the clock, and nothing used to
/// compare that instant with what the engine had already observed. So an occurrence at `t1`
/// submitted after one at `t2` was *observed* after it, and a temporal engine is fed in timestamp
/// order by contract — `Temporal::rebuild` says a late arrival is rebuilt, never inserted. Applied
/// out of order, `previous`, `since` and every window operator answer from a sequence that never
/// happened, and the ledger's own journal disagrees with the engine that decided from it.
///
/// The check runs under the ledger turn — after the append — so the refusal withholds only the
/// verdict: the record stays, the history is marked for replay, and the next decision is served
/// from a run rebuilt in order. The final permit is the proof of that last part: it is only
/// reachable if the refused login was actually fed to the engine, in its right place, by the
/// rebuild — a plane that merely refused and forgot would keep answering deny.
#[tokio::test]
async fn an_occurrence_behind_what_the_history_holds_is_refused() {
    let plane = plane("temporal-out-of-order");
    let router = surface(&plane);

    // A read first, with no login anywhere: denied, and now the history stands at t=4000.
    let (status, body) = post(
        &router,
        submission(
            4000,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"user": "alice", "document": "doc1"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["outcome"], "decided", "{body}");
    assert_eq!(body["decision"], false, "nothing has logged in yet: {body}");

    // The login that would have permitted it, arriving late: it happened at t=3900, before the
    // read the history already holds.
    let (status, refused) = post(
        &router,
        submission(
            3900,
            "Drupe::Action::Login",
            "response",
            "alice",
            json!({"user": "alice", "server": "s1"}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "an occurrence behind the history is a conflict with what is already there: {refused}"
    );
    assert_eq!(
        refused["code"], "event_out_of_order",
        "and it is refused for its order, not for its content: {refused}"
    );

    // The record is kept. An occurrence that happened is an input to every future decision in its
    // history, so discarding it because this one could not be answered would change what those
    // later decisions mean. Only the answer is withheld.
    assert_eq!(
        plane
            .streams
            .read_from(ZONE_ID, LEDGER_ID, 0, 100)
            .expect("the journal reads")
            .len(),
        2,
        "the occurrence is evidence and stays; what was refused is the verdict, not the record"
    );

    // The same question the first read asked, a hundred seconds later. The only login this ledger
    // has ever seen is the refused one at t=3900 — inside the policy's one-hour window of t=4100 —
    // so a permit here is possible only if the rebuild replayed it into its right place.
    let (status, body) = post(
        &router,
        submission(
            4100,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"user": "alice", "document": "doc1"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["outcome"], "decided",
        "the history healed on the next occurrence, not at the next restart: {body}"
    );
    assert_eq!(
        body["decision"], true,
        "the verdict is the proof: only the refused login at t=3900, replayed in order, permits \
         this read — a plane that refused and forgot would deny it: {body}"
    );
    assert_eq!(
        plane
            .streams
            .read_from(ZONE_ID, LEDGER_ID, 0, 100)
            .expect("the journal reads")
            .len(),
        3
    );
}

/// Two occurrences in timestamp order are both accepted, so the guard is not a blanket refusal.
#[tokio::test]
async fn occurrences_in_order_are_still_accepted() {
    let plane = plane("temporal-in-order");
    let router = surface(&plane);

    for at in [100i64, 4000] {
        let (status, body) = post(
            &router,
            submission(
                at,
                "Drupe::Action::Login",
                "response",
                "alice",
                json!({"user": "alice", "server": "s1"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "@{at}: {body}");
    }

    assert_eq!(
        plane
            .streams
            .read_from(ZONE_ID, LEDGER_ID, 0, 100)
            .expect("the journal reads")
            .len(),
        2,
        "order is what is refused, not lateness itself"
    );
}

/// Concurrent submissions with rising instants are ordered or refused — never applied out of order.
///
/// # The property this pins
///
/// The journal assigns sequences in arrival order, and arrival order is the scheduler's. So a set
/// of occurrences whose instants rise cannot be guaranteed to arrive in that order, and one of them
/// will find the history already past it. The guarantee is not that every submission is decided —
/// it cannot be — but that none is decided *out of order*, and that none is lost.
///
/// Checked under the ledger turn, where every lower sequence is durable, the answer is the same on
/// every run: whichever occurrence the journal placed behind a later instant is refused, and it is
/// refused for that reason rather than for anything about its content.
///
/// Every record survives either way. An occurrence that happened is an input to future decisions in
/// its history, so the refusal withholds the verdict and keeps the evidence — and because the
/// history is marked for replay, the rebuilt run sorts the refused arrival into its right place.
#[tokio::test]
async fn concurrent_rising_instants_are_never_applied_out_of_order() {
    const SUBMISSIONS: usize = 16;

    let plane = plane("temporal-concurrent-order");
    let router = surface(&plane);

    let mut inflight = Vec::with_capacity(SUBMISSIONS);
    for nth in 0..SUBMISSIONS {
        let router = router.clone();
        let body = submission(
            i64::try_from(nth).expect("the index is small") * 10,
            "Drupe::Action::Login",
            "response",
            "alice",
            json!({"user": "alice", "server": format!("s{nth}")}),
        );
        inflight.push(tokio::spawn(async move { post(&router, body).await }));
    }

    let mut decided = 0;
    for handle in inflight {
        let (status, body) = handle.await.expect("the submission finishes");
        match status {
            StatusCode::OK => decided += 1,
            StatusCode::CONFLICT => assert_eq!(
                body["code"], "event_out_of_order",
                "the only conflict this races into is the ordering one: {body}"
            ),
            other => panic!("neither decided nor refused for order: {other} {body}"),
        }
    }

    assert!(
        decided > 0,
        "an ordering guard that refuses everything is not a guard, it is an outage"
    );
    assert_eq!(
        plane
            .streams
            .read_from(ZONE_ID, LEDGER_ID, 0, 100)
            .expect("the journal reads")
            .len(),
        SUBMISSIONS,
        "every occurrence is durable, decided or not: the verdict is withheld, the evidence is not"
    );
}

/// A tie on event time is still an order, decided by the rest of the tuple.
///
/// # Why the tie break must be enforced and not just documented
///
/// The documented order is `(occurred_at, observed_at, producer, sequence)` — `order_of`, the one
/// every rebuilt run is sorted by. The guard used to scan from `occurred_at + 1`, which checks the
/// first component and leaves every tie undecided: two occurrences in the same second, journalled
/// opposite to the instants they were stamped with, were both applied — and the next rebuild would
/// sort them the other way round, so the engine's live view and its replayed view disagreed.
///
/// The record planted here has this occurrence's event time and an observed time far in its
/// future, so it sorts after anything submitted today: a submission tied on event time must be
/// refused, because the run it joins has already moved past it.
#[tokio::test]
async fn a_tie_on_event_time_is_still_an_order() {
    let plane = plane("temporal-tie-break");
    let router = surface(&plane);

    // An ordinary occurrence, to copy the shape of a durable record from.
    let (status, body) = post(
        &router,
        submission(
            1000,
            "Drupe::Action::Login",
            "response",
            "alice",
            json!({"user": "alice", "server": "s1"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The planted record: same event time, observed far in the future, so it outsorts on the
    // second component of the tuple exactly — the case a `occurred_at + 1` scan cannot see.
    let held = plane
        .streams
        .read_from(ZONE_ID, LEDGER_ID, 0, 100)
        .expect("the journal reads");
    let mut planted: permguard_events::record::Record =
        serde_json::from_value(held[0].clone()).expect("a durable record deserializes");
    planted.event_id = "tie-from-the-future".to_owned();
    planted.event["event_id"] = json!("tie-from-the-future");
    planted.occurrence_digest = permguard_events::record::occurrence_digest_of(&planted.event)
        .expect("the patched occurrence canonicalizes");
    planted.observed_at = "9999-01-01T00:00:00Z".to_owned();
    planted.seq = 0;
    planted.prev = String::new();
    let (written, _) = plane
        .streams
        .append(ZONE_ID, LEDGER_ID, planted)
        .expect("the planted record appends");
    // A direct append assigns a sequence nobody has taken a turn for, and the sequencer advances
    // only when a turn is dropped — the next submission would wait for it for ever. Take it and
    // give it back, the way an abandoned submission's drop does.
    let permguard_data_plane::temporal::streams::Written::Appended { seq, .. } = written else {
        panic!("the plant is a new record");
    };
    drop(
        plane
            .streams
            .sequencer(ZONE_ID, LEDGER_ID)
            .expect("the ledger is open")
            .turn(seq),
    );

    // Tied on event time, behind on observed time: refused, not applied behind the plant.
    let mut tied = submission(
        1000,
        "Drupe::Action::Login",
        "response",
        "alice",
        json!({"user": "alice", "server": "s2"}),
    );
    tied["event"]["data"]["event_id"] = json!("tie-submitted-today");
    let (status, refused) = post(&router, tied).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "equal event time is not equal order — the tuple decides: {refused}"
    );
    assert_eq!(refused["code"], "event_out_of_order", "{refused}");
}

/// A stale partition is rebuilt even after a sibling profile's rebuild came first.
///
/// # The leak this pins
///
/// The replay note used to be kept per history. An invalidation cleared it for everyone, but the
/// first profile to submit afterwards rebuilt only *its own* partitions and then wrote the note
/// back for the whole history — so the sibling profile's next request found its engine non-empty
/// and the note current, skipped the rebuild, and decided against a history still missing the
/// event. Two profiles over one history answered from two different pasts.
///
/// The final permit is the discriminating assertion: it is reachable only if the temporal
/// profile's partition was still considered stale after the audit profile's rebuild, and therefore
/// replayed the refused login into its place.
#[tokio::test]
async fn a_stale_partition_is_rebuilt_even_after_a_sibling_profile_was() {
    let plane = plane_of(
        "temporal-two-profiles",
        &manifest_two_profiles(),
        blocking(),
    );
    let router = surface(&plane);

    // The temporal profile's history moves to t=4000: a read, denied — no login anywhere.
    let (status, body) = post(
        &router,
        submission(
            4000,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"user": "alice", "document": "doc1"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["decision"], false, "{body}");

    // The login that would have permitted it arrives late, behind the read: refused for order,
    // kept as evidence, and every partition of this history is marked for replay.
    let (status, refused) = post(
        &router,
        submission(
            3900,
            "Drupe::Action::Login",
            "response",
            "alice",
            json!({"user": "alice", "server": "s1"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert_eq!(refused["code"], "event_out_of_order", "{refused}");

    // The sibling profile submits first. Its partition is rebuilt and marked clean — and with a
    // per-history note this is the step that used to mark the *temporal* partition clean too,
    // without having rebuilt it. At t=4050: the history is shared across partitions, so an audit
    // event ahead of the final read would make that read out of order for a different reason and
    // this test would stop testing the note.
    let (status, body) = post(
        &router,
        submission_to(
            AUDIT_PROFILE,
            4050,
            "Drupe::Action::Login",
            "response",
            "alice",
            json!({"user": "alice", "server": "s9"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Now the temporal profile asks. Its only login is the refused one at t=3900 — the audit
    // profile's login at t=5000 is addressed to the other partition and is never its input — so
    // this permit exists only if the temporal partition was still stale and rebuilt here.
    let (status, body) = post(
        &router,
        submission(
            4100,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"user": "alice", "document": "doc2"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["decision"], true,
        "the temporal partition stayed stale until it was itself rebuilt — a note kept per \
         history would have skipped this rebuild and denied: {body}"
    );
}
