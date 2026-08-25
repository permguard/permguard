// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The whole developer flow, end to end, against an in-process server
//! engine: init → author (Cedar + Rego) → plan → apply, then a second
//! workspace clones, pulls, edits, applies, and the first converges.

use std::path::PathBuf;

use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};

use permguard_cli::engine::remote::{RefAnswer, Remote};
use permguard_cli::engine::{FsStore, Store, Workspace};
use permguard_control_plane::engine::{Engine, EngineError, EngineLimits, LedgerIdentity};
use permguard_control_plane::store::FileObjectStore;
use permguard_notp::*;
use permguard_objects::statement::SignedHead;

/// An in-process remote: the very server engine, one signing key, a JWKS.
struct EngineRemote {
    store: FileObjectStore,
    key: Ed25519KeyPair,
}

impl EngineRemote {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("pg-ws-remote-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Self {
            store: FileObjectStore::new(dir),
            key: Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap(),
        }
    }

    fn engine(&self) -> Engine<'_> {
        Engine {
            store: &self.store,
            identity: LedgerIdentity {
                zone_id: "zone-guid".into(),
                ledger_id: "ledger-guid".into(),
            },
            limits: EngineLimits {
                max_batch_bytes: 8 * 1024 * 1024,
                max_batch_objects: 3, // deliberately tiny: exercise batching
                max_push_objects: 10_000,
                max_push_bytes: 64 * 1024 * 1024,
                ledger_quota_bytes: 256 * 1024 * 1024,
            },
        }
    }

    fn signer(
        &self,
    ) -> impl Fn(&permguard_objects::statement::HeadStatement) -> Result<Vec<u8>, EngineError> + '_
    {
        move |statement| {
            SignedHead::sign(statement, &self.key, b"test-key")
                .map(|signed| signed.encode())
                .map_err(|error| EngineError::Internal {
                    detail: error.to_string(),
                })
        }
    }
}

impl Remote for EngineRemote {
    fn resolve(&self, _zone: &str, _ledger: &str) -> Result<(String, String), String> {
        Ok(("zone-guid".into(), "ledger-guid".into()))
    }

    fn keyring(&self) -> Result<Vec<u8>, String> {
        let x =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.key.public_key().as_ref());
        Ok(format!(
            r#"{{"keys":[{{"kid":"test-key","kty":"OKP","crv":"Ed25519","x":"{x}","alg":"EdDSA","use":"sig"}}]}}"#
        )
        .into_bytes())
    }

    fn get_ref(&self, r#ref: &str) -> Result<Option<RefAnswer>, String> {
        let signer = self.signer();
        match self.engine().get_ref(r#ref, &signer) {
            Ok((state, statement)) => Ok(Some(RefAnswer {
                head: state.head.to_string(),
                counter: state.counter,
                statement,
            })),
            Err(EngineError::NotFound { .. }) => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }

    fn negotiate_push(
        &self,
        request: &NegotiatePushRequest,
    ) -> Result<NegotiatePushResponse, String> {
        self.engine()
            .negotiate_push(request)
            .map_err(|e| e.to_string())
    }

    fn upload(&self, request: &UploadObjectsRequest) -> Result<UploadObjectsResponse, String> {
        self.engine().upload(request).map_err(|e| e.to_string())
    }

    fn commit_push(&self, request: &CommitPushRequest) -> Result<CommitPushResponse, String> {
        let signer = self.signer();
        self.engine()
            .commit_push(request, &signer)
            .map_err(|e| e.to_string())
    }

    fn negotiate_pull(
        &self,
        request: &NegotiatePullRequest,
    ) -> Result<NegotiatePullResponse, String> {
        let signer = self.signer();
        self.engine()
            .negotiate_pull(request, &signer)
            .map_err(|e| e.to_string())
    }

    fn fetch(&self, request: &FetchObjectsRequest) -> Result<FetchObjectsResponse, String> {
        self.engine().fetch(request).map_err(|e| e.to_string())
    }
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pg-ws-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const CEDAR: &str = r#"@alias("billing-ro")
permit (
    principal in Group::"finance",
    action == Action::"read",
    resource
);
"#;

const REGO: &str = r#"# METADATA
# custom:
#   alias: gateway-routes
package gateway.routes

import rego.v1

default allow := false

allow if {
    input.subject.type == "user"
    input.action.name == "read"
}
"#;

#[test]
fn the_whole_developer_flow() {
    let remote = EngineRemote::new("flow");

    // ---- author one: init, write Cedar and Rego, checkout, apply ----
    let dir_a = scratch("author-a");
    let store_a = FsStore::new(&dir_a);
    let ws_a = Workspace::open(&store_a);
    ws_a.init("acme-authz", &["cedar", "rego"]).unwrap();

    // An unsupported language is an error, listing the built-ins.
    let bad = Workspace::open(&FsStore::new(scratch("bad-lang"))).init("x", &["prolog"]);
    assert!(bad.unwrap_err().to_string().contains("cedar"));

    store_a
        .write("cedar/billing.cedar", CEDAR.as_bytes())
        .unwrap();
    store_a.write("rego/routes.rego", REGO.as_bytes()).unwrap();

    let mut config = ws_a.config().unwrap();
    config.remotes.insert(
        "origin".into(),
        permguard_cli::engine::workspace::config::RemoteConfig {
            url: "test://".into(),
            tls_ca_file: None,
        },
    );
    ws_a.save_config(&config).unwrap();

    // Checkout binds the ledger (resolving names to GUIDs) — the ref does
    // not exist yet, so the pull inside reports it cleanly.
    let checkout = ws_a.checkout(&remote, "origin", "pharma", "main-ledger", "main");
    assert!(checkout.is_err(), "the ref does not exist yet");

    // Plan: two creates, one per language.
    let (_, plan) = ws_a.plan().unwrap();
    assert_eq!(plan.actions.len(), 2);

    // Apply: pushes, counter 1.
    let applied = ws_a
        .apply(&remote, "alice@acme.com", "first policies")
        .unwrap();
    assert_eq!(applied.counter, 1);
    assert!(
        applied.uploaded >= 5,
        "blobs, trees, manifest, commit travelled"
    );

    // Idempotent second apply: nothing to do.
    let again = ws_a.apply(&remote, "alice@acme.com", "noop").unwrap();
    assert_eq!(again.counter, 1);
    assert_eq!(again.uploaded, 0);

    // ---- author two: clone (checkout into an empty workspace), edit, apply ----
    let dir_b = scratch("author-b");
    let store_b = FsStore::new(&dir_b);
    let ws_b = Workspace::open(&store_b);
    ws_b.init("acme-authz", &["cedar", "rego"]).unwrap();
    // A clone materializes the manifest and every policy file.
    std::fs::remove_file(dir_b.join("manifest.yml")).unwrap();
    let pulled = ws_b
        .checkout(&remote, "origin", "pharma", "main-ledger", "main")
        .unwrap();
    assert_eq!(pulled.counter, 1);
    assert!(
        pulled
            .materialized
            .iter()
            .any(|path| path == "manifest.yml")
    );
    assert!(
        pulled
            .materialized
            .iter()
            .any(|path| path.starts_with("cedar/billing-ro"))
    );
    assert!(
        pulled
            .materialized
            .iter()
            .any(|path| path.starts_with("rego/gateway-routes"))
    );

    // Author two edits the Cedar policy (same alias → same identity).
    let edited = CEDAR.replace("Action::\"read\"", "Action::\"list\"");
    store_b
        .write("cedar/billing-ro.cedar", edited.as_bytes())
        .unwrap();
    let (_, plan_b) = ws_b.plan().unwrap();
    assert_eq!(plan_b.actions.len(), 1, "one update: {plan_b:?}");
    let applied_b = ws_b
        .apply(&remote, "bob@acme.com", "billing update")
        .unwrap();
    assert_eq!(applied_b.counter, 2);

    // ---- author one converges: pull, files untouched but content advanced ----
    let pulled_a = ws_a.pull(&remote).unwrap();
    assert_eq!(pulled_a.counter, 2);
    // The edited policy keeps its identity: same alias, same id, so nothing
    // new materializes as a file (the author's file stays the author's).
    assert!(
        pulled_a.materialized.is_empty(),
        "{:?}",
        pulled_a.materialized
    );

    // History shows both commits.
    let history = ws_a.history().unwrap();
    assert_eq!(history.len(), 2);

    // A second pull is a clean no-op at the same counter.
    let same = ws_a.pull(&remote).unwrap();
    assert_eq!(same.counter, 2);
    assert_eq!(same.fetched, 0);
}

#[test]
fn duplicates_are_ambiguity() {
    let dir = scratch("dups");
    let store = FsStore::new(&dir);
    let ws = Workspace::open(&store);
    ws.init("dups", &["cedar"]).unwrap();

    // The same alias in two files: rejected, both paths named.
    store.write("cedar/a.cedar", CEDAR.as_bytes()).unwrap();
    store.write("cedar/b.cedar", CEDAR.as_bytes()).unwrap();
    let refused = ws.refresh().unwrap_err().to_string();
    assert!(
        refused.contains("cedar/a.cedar") && refused.contains("cedar/b.cedar"),
        "{refused}"
    );
}

#[test]
fn both_manifest_extensions_reject() {
    let dir = scratch("two-manifests");
    let store = FsStore::new(&dir);
    let ws = Workspace::open(&store);
    ws.init("two", &["cedar"]).unwrap();
    let manifest = store.read("manifest.yml").unwrap().unwrap();
    store.write("manifest.yaml", &manifest).unwrap();
    assert!(ws.refresh().unwrap_err().to_string().contains("ambiguity"));
}

/// Nested folders round-trip: a Rego package tree three levels deep builds
/// into subtrees, pushes, and a fresh clone rebuilds the exact directories.
/// And a Cedar schema: exactly one per partition — two reject, both sides.
#[test]
fn nested_folders_and_schemas() {
    let remote = EngineRemote::new("nested");

    let dir = scratch("nested-author");
    let store = FsStore::new(&dir);
    let ws = Workspace::open(&store);
    ws.init("nested", &["cedar", "rego"]).unwrap();

    // Cedar with its schema (schema: true in the manifest).
    let manifest = String::from_utf8(store.read("manifest.yml").unwrap().unwrap()).unwrap();
    let manifest = manifest.replace(
        "cedar: { runtime: cedar, schema: false }",
        "cedar: { runtime: cedar, schema: true }",
    );
    store.write("manifest.yml", manifest.as_bytes()).unwrap();
    store
        .write("cedar/billing.cedar", CEDAR.as_bytes())
        .unwrap();
    // The schema has to cover what the policy says — `validate` runs the same
    // set-level check the server and the data plane run, so a policy naming an
    // entity the schema does not know fails right here.
    store
        .write(
            "cedar/model.cedarschema",
            b"entity Group;\nentity User in [Group];\nentity Document;\naction read appliesTo { principal: [User], resource: [Document] };\n",
        )
        .unwrap();

    // Rego, three folders deep — the package tree people actually keep.
    store
        .write("rego/gateway/http/routes.rego", REGO.as_bytes())
        .unwrap();

    let snapshot = ws.refresh().unwrap();
    assert_eq!(snapshot.policies.len(), 2);
    assert!(
        snapshot
            .policies
            .iter()
            .any(|p| p.source == "rego/gateway/http/routes.rego"),
        "{:?}",
        snapshot.policies
    );

    ws.checkout(&remote, "origin", "z", "l", "main")
        .unwrap_err(); // empty ref is fine at bind…
    let mut config = ws.config().unwrap();
    config.remotes.insert(
        "origin".into(),
        permguard_cli::engine::workspace::config::RemoteConfig {
            url: "test://".into(),
            tls_ca_file: None,
        },
    );
    ws.save_config(&config).unwrap();
    let applied = ws.apply(&remote, "a", "nested").unwrap();
    assert_eq!(applied.counter, 1);

    // A second schema in the same partition: refused client-side…
    store
        .write("cedar/second.cedarschema", b"entity Extra;\n")
        .unwrap();
    let refused = ws.refresh().unwrap_err().to_string();
    assert!(refused.contains("at most one"), "{refused}");
    std::fs::remove_file(dir.join("cedar/second.cedarschema")).unwrap();

    // …and schema: true on a language without schemas is refused too.
    let broken = manifest.replace(
        "rego: { runtime: rego, schema: false }",
        "rego: { runtime: rego, schema: true }",
    );
    store.write("manifest.yml", broken.as_bytes()).unwrap();
    let refused = ws.refresh().unwrap_err().to_string();
    assert!(refused.contains("has no schema"), "{refused}");
    store.write("manifest.yml", manifest.as_bytes()).unwrap();

    // A fresh clone rebuilds the folder structure exactly.
    let dir_b = scratch("nested-clone");
    let store_b = FsStore::new(&dir_b);
    let ws_b = Workspace::open(&store_b);
    let mut config = permguard_cli::engine::workspace::config::WorkspaceConfig::new();
    config.remotes.insert(
        "origin".into(),
        permguard_cli::engine::workspace::config::RemoteConfig {
            url: "test://".into(),
            tls_ca_file: None,
        },
    );
    ws_b.save_config(&config).unwrap();
    let pulled = ws_b.checkout(&remote, "origin", "z", "l", "main").unwrap();
    assert!(
        pulled
            .materialized
            .iter()
            .any(|path| path == "rego/gateway/http/gateway-routes.rego"),
        "{:?}",
        pulled.materialized
    );
    assert!(
        pulled
            .materialized
            .iter()
            .any(|path| path == "cedar/model.cedarschema")
    );
    // And the rebuilt clone refreshes to the same root.
    let snapshot_b = ws_b.refresh().unwrap();
    assert_eq!(
        snapshot_b.root, snapshot.root,
        "the clone rebuilds the same snapshot"
    );
}
