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
    /// What this simulated deployment has opted into, so a test can be a plane that has *not*.
    enabled: permguard_languages::registry::Enabled,
    /// The one ledger this remote serves — what `resolve` answers, whatever names it is asked.
    identity: LedgerIdentity,
    /// The mutation transaction its ref updates run in (WP-7.12).
    mutations: permguard_host::composition::MutationHandle,
}

impl EngineRemote {
    fn new(tag: &str) -> Self {
        Self::for_ledger(tag, "ledger-guid")
    }

    /// The same plane, serving a different ledger: two of these are two ledgers of one zone.
    fn for_ledger(tag: &str, ledger_id: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("pg-ws-remote-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Self {
            store: FileObjectStore::new(dir.join("ledger")),
            mutations: permguard_control_plane::store::testing::offline_ref_mutations(
                &dir.join("volume"),
            )
            .expect("a mutation transaction opens"),
            key: Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap(),
            enabled: permguard_languages::registry::Enabled::everything(),
            identity: LedgerIdentity {
                zone_id: "zone-guid".into(),
                ledger_id: ledger_id.into(),
            },
        }
    }

    /// The same plane, with the provisional runtimes it has not turned on.
    fn without_dogwood(tag: &str) -> Self {
        Self {
            enabled: permguard_languages::registry::Enabled::stable_only(),
            ..Self::new(tag)
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
            transfer: permguard_control_plane::engine::TransferPolicy {
                ttl: std::time::Duration::from_secs(900),
                grace: std::time::Duration::from_secs(3600),
            },
            identity: self.identity.clone(),
            limits: EngineLimits {
                max_batch_bytes: 8 * 1024 * 1024,
                max_batch_objects: 3, // deliberately tiny: exercise batching
                max_push_objects: 10_000,
                max_push_bytes: 64 * 1024 * 1024,
                ledger_quota_bytes: 256 * 1024 * 1024,
            },
            enabled: self.enabled.clone(),
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
                .map_err(|error| EngineError::Internal {
                    detail: error.to_string(),
                })
        }
    }
}

impl Remote for EngineRemote {
    fn resolve(&self, _zone: &str, _ledger: &str) -> Result<(String, String), String> {
        Ok((
            self.identity.zone_id.clone(),
            self.identity.ledger_id.clone(),
        ))
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
                ref_digest: state.ref_digest().map_err(|e| e.to_string())?.to_string(),
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

    // Checkout binds the ledger (resolving names to GUIDs) — the ref does not exist yet, so the
    // ledger is bound empty and there is nothing to pull.
    let checkout = ws_a.checkout(&remote, "origin", "delivery", "main-ledger", "main");
    assert_eq!(checkout.expect("an empty ledger is bound").counter, 0);

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
        .checkout(&remote, "origin", "delivery", "main-ledger", "main")
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
    let pulled_a = ws_a.pull(&remote, false).unwrap();
    assert_eq!(pulled_a.counter, 2);
    // The edited policy keeps its identity: same alias, same id, so nothing
    // new materializes as a file (the author's file stays the author's).
    assert!(
        pulled_a.materialized.is_empty(),
        "{:?}",
        pulled_a.materialized
    );
    // The author's file, though, now holds the other author's content. A
    // checkpoint at counter 2 over a tree still holding counter 1 is how the
    // next apply reverts a commit nobody asked it to touch.
    // It lands in *their* file, `billing.cedar` — the identity is the policy
    // id, not the name the other author happens to keep it under.
    assert_eq!(
        pulled_a.updated,
        vec!["cedar/billing.cedar".to_owned()],
        "the remote's change has to land in the file the author holds it in"
    );
    let landed = String::from_utf8(store_a.read("cedar/billing.cedar").unwrap().unwrap()).unwrap();
    assert!(
        landed.contains("Action::\"list\""),
        "author one's file did not advance: {landed}"
    );
    // And so the tree agrees with the checkpoint: nothing to apply.
    let (_, converged) = ws_a.plan().unwrap();
    assert!(
        converged.actions.is_empty(),
        "a converged workspace plans nothing: {converged:?}"
    );

    // History shows both commits.
    let history = ws_a.history().unwrap();
    assert_eq!(history.len(), 2);

    // A second pull is a clean no-op at the same counter.
    let same = ws_a.pull(&remote, false).unwrap();
    assert_eq!(same.counter, 2);
    assert_eq!(same.fetched, 0);
}

/// Checking out another ledger drops the checkpoint the previous one left behind.
///
/// The checkpoint is kept per ref and every ledger's default ref is `main`, so before this the two
/// ledgers shared one file. A workspace bound to a ledger at counter 1 and re-bound to an empty one
/// reported counter 1, planned nothing, and an `apply` returned the stale checkpoint as a success —
/// with nothing published.
#[test]
fn checking_out_another_ledger_does_not_keep_the_previous_ledgers_checkpoint() {
    let source = EngineRemote::new("rebind-source");
    let empty = EngineRemote::for_ledger("rebind-empty", "ledger-empty-guid");

    let dir = scratch("rebind");
    let store = FsStore::new(&dir);
    let ws = Workspace::open(&store);
    ws.init("acme-authz", &["cedar", "rego"]).unwrap();
    store
        .write("cedar/billing.cedar", CEDAR.as_bytes())
        .unwrap();
    store.write("rego/routes.rego", REGO.as_bytes()).unwrap();
    let mut config = ws.config().unwrap();
    config.remotes.insert(
        "origin".into(),
        permguard_cli::engine::workspace::config::RemoteConfig {
            url: "test://".into(),
            tls_ca_file: None,
        },
    );
    ws.save_config(&config).unwrap();

    // Bound to the first ledger and applied: counter 1, and a checkpoint that says so.
    let _ = ws.checkout(&source, "origin", "acme", "source", "main");
    assert_eq!(
        ws.apply(&source, "alice@acme.com", "first")
            .unwrap()
            .counter,
        1
    );
    assert_eq!(ws.status().unwrap().checkpoint.unwrap().counter, 1);

    // Re-bound to an empty ledger, from a clean tree. An empty ledger is an empty workspace: the
    // manifest and the partitions go, nothing of the first ledger's is carried over to be
    // published under the wrong name, and `init` gives the workspace a shape again without
    // touching the binding.
    let switched = ws
        .checkout(&empty, "origin", "acme", "empty", "main")
        .unwrap();
    assert!(
        switched
            .removed
            .iter()
            .any(|path| path == "cedar/billing.cedar"),
        "the switch says what it removed: {switched:?}"
    );
    assert!(!store.exists("cedar/billing.cedar"));
    assert!(!store.exists("rego/routes.rego"));
    assert!(!store.exists("manifest.yml"));
    assert!(!store.exists("cedar"));
    ws.init("acme-authz", &["cedar", "rego"]).unwrap();
    assert!(store.exists("manifest.yml"));
    let status = ws.status().unwrap();
    assert_eq!(
        status.ledger.as_ref().unwrap().ledger_id,
        "ledger-empty-guid"
    );
    assert!(
        status.checkpoint.is_none(),
        "the previous ledger's checkpoint must not survive the rebinding: {:?}",
        status.checkpoint
    );
    // No policy is pending on the empty ledger, and the manifest `init` wrote is: with no head
    // the base is empty, and the first `apply` publishes it (BUG-0009, DEC-0003).
    let (_, plan) = ws.plan().unwrap();
    assert!(
        plan.actions.is_empty() && plan.manifest_changed,
        "an emptied tree has only its new manifest pending on the empty ledger: {plan:?}"
    );

    // Written for the empty ledger, the apply publishes — for real, and only that.
    store
        .write("cedar/billing.cedar", CEDAR.as_bytes())
        .unwrap();
    let applied = ws
        .apply(&empty, "alice@acme.com", "first on the empty ledger")
        .unwrap();
    assert_eq!(applied.counter, 1);
    assert!(
        applied.uploaded > 0,
        "an apply to an empty ledger uploads its closure"
    );
    assert_eq!(
        empty.get_ref("main").unwrap().map(|answer| answer.counter),
        Some(1),
        "the empty ledger now has a head"
    );
    assert_eq!(
        source.get_ref("main").unwrap().map(|answer| answer.counter),
        Some(1),
        "and the ledger left behind was not touched"
    );
}

/// A checkout never carries work from one ledger into another: with a policy not yet applied to
/// the tracked ledger, checking out another one is refused, the binding does not move, and the
/// file is still there for the author to `apply` or remove.
#[test]
fn a_checkout_refuses_to_carry_unapplied_work_into_another_ledger() {
    let source = EngineRemote::new("carry-source");
    let other = EngineRemote::for_ledger("carry-other", "ledger-other-guid");
    let dir = scratch("carry");
    let store = FsStore::new(&dir);
    let ws = Workspace::open(&store);
    ws.init("acme-authz", &["cedar", "rego"]).unwrap();
    store
        .write("cedar/billing.cedar", CEDAR.as_bytes())
        .unwrap();
    store.write("rego/routes.rego", REGO.as_bytes()).unwrap();
    let mut config = ws.config().unwrap();
    config.remotes.insert(
        "origin".into(),
        permguard_cli::engine::workspace::config::RemoteConfig {
            url: "test://".into(),
            tls_ca_file: None,
        },
    );
    ws.save_config(&config).unwrap();
    let _ = ws.checkout(&source, "origin", "acme", "source", "main");
    ws.apply(&source, "alice@acme.com", "first").unwrap();

    // One more policy, not applied.
    store
        .write(
            "cedar/extra.cedar",
            "@alias(\"extra\")\npermit (principal, action == Action::\"write\", resource);\n"
                .as_bytes(),
        )
        .unwrap();
    let refused = ws
        .checkout(&other, "origin", "acme", "other", "main")
        .expect_err("unapplied work does not travel");
    assert!(
        refused.message.contains("not applied") && refused.message.contains("1 to create"),
        "{}",
        refused.message
    );
    assert!(
        refused.message.contains("origin/acme/source"),
        "the refusal names what the tree still tracks: {}",
        refused.message
    );
    let status = ws.status().unwrap();
    assert_eq!(
        status.ledger.as_ref().unwrap().ledger_id,
        "ledger-guid",
        "the binding did not move"
    );
    assert!(store.exists("cedar/extra.cedar"), "and nothing was lost");
    assert_eq!(status.checkpoint.unwrap().counter, 1);
}

/// On a clean tree, checking out another ledger replaces the tree with that ledger's — the
/// manifest and the partitions — and leaves what `.permguardignore` names alone.
#[test]
fn a_clean_checkout_replaces_the_tree_with_the_other_ledgers() {
    let source = EngineRemote::new("replace-source");
    let other = EngineRemote::for_ledger("replace-other", "ledger-other-guid");

    // The other ledger, published by another author.
    let dir_b = scratch("replace-author-b");
    let store_b = FsStore::new(&dir_b);
    let ws_b = Workspace::open(&store_b);
    ws_b.init("other-authz", &["cedar", "rego"]).unwrap();
    store_b
        .write(
            "cedar/other.cedar",
            "@alias(\"other-ro\")\npermit (principal, action == Action::\"read\", resource);\n"
                .as_bytes(),
        )
        .unwrap();
    store_b
        .write(
            "rego/other.rego",
            "# METADATA\n# custom:\n#   alias: other-routes\npackage other.routes\n\nimport \
             rego.v1\n\ndefault allow := false\n\nallow if input.action.name == \"list\"\n"
                .as_bytes(),
        )
        .unwrap();
    let mut config_b = ws_b.config().unwrap();
    config_b.remotes.insert(
        "origin".into(),
        permguard_cli::engine::workspace::config::RemoteConfig {
            url: "test://".into(),
            tls_ca_file: None,
        },
    );
    ws_b.save_config(&config_b).unwrap();
    let _ = ws_b.checkout(&other, "origin", "acme", "other", "main");
    assert_eq!(
        ws_b.apply(&other, "bob@acme.com", "first").unwrap().counter,
        1
    );

    // This author: on the source ledger, clean, with a folder the ledger never knew.
    let dir = scratch("replace");
    let store = FsStore::new(&dir);
    let ws = Workspace::open(&store);
    ws.init("acme-authz", &["cedar", "rego"]).unwrap();
    store
        .write("cedar/billing.cedar", CEDAR.as_bytes())
        .unwrap();
    store.write("rego/routes.rego", REGO.as_bytes()).unwrap();
    let ignores = String::from_utf8(store.read(".permguardignore").unwrap().unwrap()).unwrap();
    store
        .write(".permguardignore", format!("{ignores}notes/\n").as_bytes())
        .unwrap();
    store.write("notes/keep.md", b"mine\n").unwrap();
    // What the Finder left behind is not the ledger's either, and goes with the partition.
    store.write("cedar/.DS_Store", b"").unwrap();
    let mut config = ws.config().unwrap();
    config.remotes.insert(
        "origin".into(),
        permguard_cli::engine::workspace::config::RemoteConfig {
            url: "test://".into(),
            tls_ca_file: None,
        },
    );
    ws.save_config(&config).unwrap();
    let _ = ws.checkout(&source, "origin", "acme", "source", "main");
    ws.apply(&source, "alice@acme.com", "first").unwrap();

    let switched = ws
        .checkout(&other, "origin", "acme", "other", "main")
        .unwrap();
    assert_eq!(switched.counter, 1, "the other ledger's head: {switched:?}");
    assert!(
        !store.exists("cedar/billing.cedar"),
        "the source's policy is gone"
    );
    assert!(!store.exists("rego/routes.rego"));
    // Materialised under their canonical names, whatever the other author called the files.
    let holds = |partition: &str, alias: &str| {
        store.list(partition).unwrap().iter().any(|(name, _)| {
            let bytes = store
                .read(&format!("{partition}/{name}"))
                .unwrap()
                .unwrap_or_default();
            String::from_utf8_lossy(&bytes).contains(alias)
        })
    };
    assert!(
        holds("cedar", "other-ro"),
        "the other ledger's Cedar policy is here"
    );
    assert!(holds("rego", "other-routes"), "and its Rego module");
    assert!(
        store.exists("manifest.yml"),
        "the manifest is the other ledger's"
    );
    assert!(
        store.exists("notes/keep.md"),
        "what is ignored is not the ledger's to remove"
    );
    assert!(
        !store.exists("cedar/.DS_Store"),
        "what the operating system dropped goes with the partition"
    );
    let status = ws.status().unwrap();
    assert_eq!(
        status.ledger.as_ref().unwrap().ledger_id,
        "ledger-other-guid"
    );
    assert_eq!(status.checkpoint.unwrap().counter, 1);
    let (_, plan) = ws.plan().unwrap();
    assert!(
        plan.is_empty(),
        "the tree is exactly the other ledger: {plan:?}"
    );
}

/// Both authors change the same policy: the pull refuses instead of
/// advancing the checkpoint over content the tree does not hold, and names
/// the object so the author can read the version they have to reconcile with.
#[test]
fn a_pull_does_not_advance_over_a_conflict() {
    let remote = EngineRemote::new("conflict");

    // Author one publishes the base.
    let store_a = FsStore::new(scratch("conflict-a"));
    let ws_a = bind(&store_a);
    store_a
        .write("cedar/billing.cedar", CEDAR.as_bytes())
        .unwrap();
    store_a.write("rego/routes.rego", REGO.as_bytes()).unwrap();
    let _ = ws_a.checkout(&remote, "origin", "delivery", "main-ledger", "main");
    assert_eq!(
        ws_a.apply(&remote, "a@acme.com", "base").unwrap().counter,
        1
    );

    // Author two clones it.
    let store_b = FsStore::new(scratch("conflict-b"));
    let ws_b = bind(&store_b);
    std::fs::remove_file(store_b.root().join("manifest.yml")).unwrap();
    ws_b.checkout(&remote, "origin", "delivery", "main-ledger", "main")
        .unwrap();

    // Both edit the same policy, differently. Author one gets there first.
    store_a
        .write(
            "cedar/billing.cedar",
            CEDAR
                .replace("Action::\"read\"", "Action::\"list\"")
                .as_bytes(),
        )
        .unwrap();
    assert_eq!(
        ws_a.apply(&remote, "a@acme.com", "list").unwrap().counter,
        2
    );
    store_b
        .write(
            "cedar/billing-ro.cedar",
            CEDAR
                .replace("Action::\"read\"", "Action::\"purge\"")
                .as_bytes(),
        )
        .unwrap();

    // Author two is refused the push, told to pull — and the pull refuses
    // too, rather than quietly making the next apply a revert.
    assert!(ws_b.apply(&remote, "b@acme.com", "purge").is_err());
    let refused = ws_b.pull(&remote, false).unwrap_err().to_string();
    assert!(
        refused.contains("cedar/billing-ro.cedar") && refused.contains("objects cat"),
        "the refusal has to name the file and how to read theirs: {refused}"
    );

    // Nothing moved: the checkpoint still says 1, so the apply still refuses
    // and author one's commit cannot be lost.
    assert_eq!(ws_b.status().unwrap().checkpoint.unwrap().counter, 1);
    assert!(ws_b.apply(&remote, "b@acme.com", "purge").is_err());
    let held = String::from_utf8(store_b.read("cedar/billing-ro.cedar").unwrap().unwrap()).unwrap();
    assert!(
        held.contains("Action::\"purge\""),
        "the tree was not touched"
    );

    // Reconciled by hand, `--resolved` lets it through, and the apply lands
    // on top of author one's commit instead of replacing it.
    ws_b.pull(&remote, true).unwrap();
    assert_eq!(ws_b.status().unwrap().checkpoint.unwrap().counter, 2);
    assert_eq!(
        ws_b.apply(&remote, "b@acme.com", "purge").unwrap().counter,
        3
    );
}

/// One Cedar file, two policies.
const DOCUMENTS: &str = r#"// Who may do what on documents.

@alias("document-readers")
permit (
    principal in Group::"finance",
    action == Action::"read",
    resource
);

@alias("document-owners")
permit (
    principal,
    action == Action::"write",
    resource
) when { resource.owner == principal };
"#;

/// A workspace bound to the test remote. The store outlives the borrow.
fn bind(store: &FsStore) -> Workspace<'_> {
    let ws = Workspace::open(store);
    ws.init("acme-authz", &["cedar", "rego"]).unwrap();
    let mut config = ws.config().unwrap();
    config.remotes.insert(
        "origin".into(),
        permguard_cli::engine::workspace::config::RemoteConfig {
            url: "test://".into(),
            tls_ca_file: None,
        },
    );
    ws.save_config(&config).unwrap();
    ws
}

/// The file on disk, as text.
fn text(store: &FsStore, path: &str) -> String {
    String::from_utf8(store.read(path).unwrap().unwrap()).unwrap()
}

/// One file, two policies, and the remote moves one of them: the pull
/// advances that policy inside the file and keeps the other, instead of
/// rewriting the file as the one policy the remote sent — which is how the
/// next apply would delete the other policy from the ledger.
#[test]
fn a_pull_advances_one_policy_of_a_file_and_keeps_the_rest() {
    let remote = EngineRemote::new("two-in-one");

    // Author one publishes both policies from one file.
    let store_a = FsStore::new(scratch("two-in-one-a"));
    let ws_a = bind(&store_a);
    store_a
        .write("cedar/documents.cedar", DOCUMENTS.as_bytes())
        .unwrap();
    store_a.write("rego/routes.rego", REGO.as_bytes()).unwrap();
    let _ = ws_a.checkout(&remote, "origin", "delivery", "main-ledger", "main");
    assert_eq!(
        ws_a.apply(&remote, "a@acme.com", "base").unwrap().counter,
        1
    );

    // Author two clones: a clone writes one file per policy.
    let store_b = FsStore::new(scratch("two-in-one-b"));
    let ws_b = bind(&store_b);
    std::fs::remove_file(store_b.root().join("manifest.yml")).unwrap();
    let cloned = ws_b
        .checkout(&remote, "origin", "delivery", "main-ledger", "main")
        .unwrap();
    for file in [
        "cedar/document-readers.cedar",
        "cedar/document-owners.cedar",
    ] {
        assert!(
            cloned.materialized.iter().any(|path| path == file),
            "{file} not cloned: {:?}",
            cloned.materialized
        );
    }

    // Author two changes the readers and commits.
    let readers = text(&store_b, "cedar/document-readers.cedar");
    store_b
        .write(
            "cedar/document-readers.cedar",
            readers
                .replace("Action::\"read\"", "Action::\"list\"")
                .as_bytes(),
        )
        .unwrap();
    assert_eq!(
        ws_b.apply(&remote, "b@acme.com", "readers may list")
            .unwrap()
            .counter,
        2
    );

    // Author one pulls: the readers advance inside the file, the owners and
    // the file's own text stay.
    let pulled = ws_a.pull(&remote, false).unwrap();
    assert_eq!(pulled.counter, 2);
    assert!(pulled.materialized.is_empty(), "{:?}", pulled.materialized);
    assert_eq!(pulled.updated, vec!["cedar/documents.cedar".to_owned()]);
    assert!(pulled.removed.is_empty(), "{:?}", pulled.removed);
    let documents = text(&store_a, "cedar/documents.cedar");
    assert!(
        documents.contains("Action::\"list\""),
        "the readers did not advance: {documents}"
    );
    assert!(
        documents.contains("document-owners") && documents.contains("resource.owner == principal"),
        "the owners were lost: {documents}"
    );
    assert!(
        documents.starts_with("// Who may do what on documents."),
        "the file's own text was lost: {documents}"
    );
    let (_, plan) = ws_a.plan().unwrap();
    assert!(
        plan.actions.is_empty(),
        "a converged workspace plans nothing: {plan:?}"
    );

    // Author two drops the owners: the file keeps the readers.
    std::fs::remove_file(store_b.root().join("cedar/document-owners.cedar")).unwrap();
    assert_eq!(
        ws_b.apply(&remote, "b@acme.com", "no more owners")
            .unwrap()
            .counter,
        3
    );
    let pulled = ws_a.pull(&remote, false).unwrap();
    assert_eq!(pulled.updated, vec!["cedar/documents.cedar".to_owned()]);
    assert!(pulled.removed.is_empty(), "{:?}", pulled.removed);
    let documents = text(&store_a, "cedar/documents.cedar");
    assert!(
        documents.contains("Action::\"list\"") && !documents.contains("document-owners"),
        "{documents}"
    );
    let (_, plan) = ws_a.plan().unwrap();
    assert!(plan.actions.is_empty(), "{plan:?}");

    // And the readers: nothing left in the file, so the file goes.
    std::fs::remove_file(store_b.root().join("cedar/document-readers.cedar")).unwrap();
    assert_eq!(
        ws_b.apply(&remote, "b@acme.com", "no more documents")
            .unwrap()
            .counter,
        4
    );
    let pulled = ws_a.pull(&remote, false).unwrap();
    assert!(pulled.updated.is_empty(), "{:?}", pulled.updated);
    assert_eq!(pulled.removed, vec!["cedar/documents.cedar".to_owned()]);
    assert!(!store_a.exists("cedar/documents.cedar"));
    let (_, plan) = ws_a.plan().unwrap();
    assert!(plan.actions.is_empty(), "{plan:?}");
}

/// A tree that does not build cannot say what the author changed, so the pull
/// refuses rather than advance the checkpoint over it: once the tree builds
/// again, an apply against that checkpoint would revert the remote's commit.
#[test]
fn a_pull_refuses_a_tree_it_cannot_read() {
    let remote = EngineRemote::new("unbuildable");

    let store_a = FsStore::new(scratch("unbuildable-a"));
    let ws_a = bind(&store_a);
    store_a
        .write("cedar/billing.cedar", CEDAR.as_bytes())
        .unwrap();
    store_a.write("rego/routes.rego", REGO.as_bytes()).unwrap();
    let _ = ws_a.checkout(&remote, "origin", "delivery", "main-ledger", "main");
    assert_eq!(
        ws_a.apply(&remote, "a@acme.com", "base").unwrap().counter,
        1
    );

    let store_b = FsStore::new(scratch("unbuildable-b"));
    let ws_b = bind(&store_b);
    std::fs::remove_file(store_b.root().join("manifest.yml")).unwrap();
    ws_b.checkout(&remote, "origin", "delivery", "main-ledger", "main")
        .unwrap();
    store_b
        .write(
            "cedar/billing-ro.cedar",
            CEDAR
                .replace("Action::\"read\"", "Action::\"list\"")
                .as_bytes(),
        )
        .unwrap();
    assert_eq!(
        ws_b.apply(&remote, "b@acme.com", "list").unwrap().counter,
        2
    );

    // Author one is mid-edit, and the file does not parse.
    store_a
        .write(
            "cedar/billing.cedar",
            b"@alias(\"billing-ro\")\npermit (principal, action, resource) when { 1 + };\n",
        )
        .unwrap();
    let refused = ws_a.pull(&remote, false).unwrap_err().to_string();
    assert!(refused.contains("does not build"), "{refused}");
    assert_eq!(ws_a.status().unwrap().checkpoint.unwrap().counter, 1);
    // Nor does `--resolved` get past it: there is nothing reconciled to accept.
    assert!(ws_a.pull(&remote, true).is_err());
    assert_eq!(ws_a.status().unwrap().checkpoint.unwrap().counter, 1);

    // The file fixed, the pull lands the remote's change in it.
    store_a
        .write("cedar/billing.cedar", CEDAR.as_bytes())
        .unwrap();
    let pulled = ws_a.pull(&remote, false).unwrap();
    assert_eq!(pulled.counter, 2);
    assert_eq!(pulled.updated, vec!["cedar/billing.cedar".to_owned()]);
    assert!(text(&store_a, "cedar/billing.cedar").contains("Action::\"list\""));
}

/// The remote adds a policy whose file name this workspace already uses for
/// another policy: the pull refuses, because writing would clobber the
/// author's file, and skipping would let the next apply delete the remote's
/// policy from the ledger.
#[test]
fn a_pull_does_not_advance_over_a_name_it_cannot_write() {
    let remote = EngineRemote::new("name-taken");

    let store_a = FsStore::new(scratch("name-taken-a"));
    let ws_a = bind(&store_a);
    store_a
        .write("cedar/billing.cedar", CEDAR.as_bytes())
        .unwrap();
    store_a.write("rego/routes.rego", REGO.as_bytes()).unwrap();
    let _ = ws_a.checkout(&remote, "origin", "delivery", "main-ledger", "main");
    assert_eq!(
        ws_a.apply(&remote, "a@acme.com", "base").unwrap().counter,
        1
    );

    // Author two adds `audit`, whose file is cedar/audit.cedar.
    let store_b = FsStore::new(scratch("name-taken-b"));
    let ws_b = bind(&store_b);
    std::fs::remove_file(store_b.root().join("manifest.yml")).unwrap();
    ws_b.checkout(&remote, "origin", "delivery", "main-ledger", "main")
        .unwrap();
    store_b
        .write(
            "cedar/audit.cedar",
            CEDAR.replace("billing-ro", "audit").as_bytes(),
        )
        .unwrap();
    assert_eq!(
        ws_b.apply(&remote, "b@acme.com", "audit").unwrap().counter,
        2
    );

    // Author one already keeps a different policy under that name, unapplied.
    let local = CEDAR
        .replace("billing-ro", "audit-local")
        .replace("Action::\"read\"", "Action::\"write\"");
    store_a
        .write("cedar/audit.cedar", local.as_bytes())
        .unwrap();
    let refused = ws_a.pull(&remote, false).unwrap_err().to_string();
    assert!(
        refused.contains("cedar/audit.cedar") && refused.contains("objects cat"),
        "the refusal has to name the file and how to read theirs: {refused}"
    );
    assert_eq!(ws_a.status().unwrap().checkpoint.unwrap().counter, 1);
    assert_eq!(
        text(&store_a, "cedar/audit.cedar"),
        local,
        "the author's file was touched"
    );

    // Moved aside, the remote's policy lands under its own name, and the
    // author's is what is left to apply.
    store_a
        .write("cedar/audit-local.cedar", local.as_bytes())
        .unwrap();
    store_a.remove("cedar/audit.cedar").unwrap();
    let pulled = ws_a.pull(&remote, false).unwrap();
    assert_eq!(pulled.counter, 2);
    assert_eq!(pulled.materialized, vec!["cedar/audit.cedar".to_owned()]);
    let (_, plan) = ws_a.plan().unwrap();
    assert_eq!(plan.actions.len(), 1, "{plan:?}");
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

/// A Windows checkout writes CRLF where git stores LF (6-contract-ledger-notp, Policy identity):
/// the same policies and schema with either line ending build the same snapshot, ids, digests and
/// root, so a team on Linux, macOS and Windows shares one identity per policy.
#[test]
fn a_windows_checkout_builds_the_snapshot_a_linux_one_does() {
    let build = |tag: &str, crlf: bool| {
        let dir = scratch(tag);
        let store = FsStore::new(&dir);
        let ws = Workspace::open(&store);
        ws.init("eol", &["cedar", "rego"]).unwrap();
        let manifest = String::from_utf8(store.read("manifest.yml").unwrap().unwrap()).unwrap();
        let manifest = manifest.replace(
            "cedar: { runtime: cedar, schema: false }",
            "cedar: { runtime: cedar, schema: true }",
        );
        store.write("manifest.yml", manifest.as_bytes()).unwrap();
        let written = |text: &str| {
            if crlf {
                text.replace('\n', "\r\n")
            } else {
                text.to_owned()
            }
        };
        // No alias: the id is derived from the bytes, which is what the line endings could change.
        let unnamed = "permit (\n    principal in Group::\"finance\",\n    action == Action::\"read\",\n    resource\n);\n";
        store
            .write("cedar/billing.cedar", written(unnamed).as_bytes())
            .unwrap();
        store
            .write(
                "cedar/model.cedarschema",
                written("entity Group;\nentity User in [Group];\nentity Document;\naction read appliesTo { principal: [User], resource: [Document] };\n").as_bytes(),
            )
            .unwrap();
        store
            .write("rego/routes.rego", written(REGO).as_bytes())
            .unwrap();
        ws.refresh().unwrap()
    };
    let linux = build("eol-lf", false);
    let windows = build("eol-crlf", true);
    let identities = |snapshot: &permguard_cli::engine::workspace::Snapshot| {
        let mut ids: Vec<(String, String, String)> = snapshot
            .policies
            .iter()
            .map(|p| (p.source.clone(), p.id.clone(), p.digest.to_string()))
            .collect();
        ids.sort();
        ids
    };
    assert_eq!(identities(&windows), identities(&linux));
    assert_eq!(windows.root, linux.root);
    assert_eq!(windows.manifest, linux.manifest);
    assert!(
        windows
            .objects
            .values()
            .all(|bytes| !bytes.windows(2).any(|pair| pair == b"\r\n")),
        "no stored object carries a CRLF"
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

    // An empty ref is fine at bind: the ledger is bound, with nothing to pull.
    ws.checkout(&remote, "origin", "z", "l", "main")
        .expect("an empty ledger is bound");
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

    // Rego has a schema of its own now — JSON Schema, describing the document a request hands the
    // partition — and the same three rules hold for it as for Cedar's.
    let with_schema = manifest.replace(
        "rego: { runtime: rego, schema: false }",
        "rego: { runtime: rego, schema: true }",
    );
    store.write("manifest.yml", with_schema.as_bytes()).unwrap();
    // Declared and absent: refused.
    let refused = ws.refresh().unwrap_err().to_string();
    assert!(refused.contains("hold none"), "{refused}");
    // Declared and present, exactly one: accepted.
    store
        .write(
            "rego/gateway/model.regoschema",
            br#"{"type": "object", "properties": {"teams": {"type": "array"}}}"#,
        )
        .unwrap();
    let with_rego_schema = ws.refresh().unwrap();
    assert_eq!(
        with_rego_schema.policies.len(),
        2,
        "the schema is not a policy"
    );
    // Two: refused, the same ambiguity rule Cedar's schema has.
    store
        .write("rego/other.regoschema", br#"{"type": "object"}"#)
        .unwrap();
    let refused = ws.refresh().unwrap_err().to_string();
    assert!(refused.contains("at most one"), "{refused}");
    std::fs::remove_file(dir.join("rego/other.regoschema")).unwrap();
    // Present while the manifest declares none: refused.
    store.write("manifest.yml", manifest.as_bytes()).unwrap();
    let refused = ws.refresh().unwrap_err().to_string();
    assert!(
        refused.contains("does not declare") || refused.contains("declares"),
        "{refused}"
    );
    std::fs::remove_file(dir.join("rego/gateway/model.regoschema")).unwrap();
    // Back to what was applied, so the clone below has something to match.
    assert_eq!(ws.refresh().unwrap().root, snapshot.root);

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

/// The shipped Dogwood example, applied to a control plane.
///
/// # Why this test and not another unit check
///
/// A Dogwood partition is a *bundle*: a policy, a required action schema and an optional event
/// schema, each stored under its own registered media type. Three places have to agree about what
/// that bundle is — the CLI that builds it, the control plane that accepts the push, the data
/// plane that loads it — and they used to agree in only two. The control plane judged a
/// partition's contents by the legacy pair (`policy_media_type`, `schema_media_type`), and
/// `schema_media_type` is `None` for a runtime with several artifacts by its own contract, so
/// every Dogwood artifact read as content belonging to no language.
///
/// The failure was not a wrong error message: it was a commit the CLI validates, builds and signs,
/// refused by the only server that could store it. So the test is the whole path rather than a
/// call to the gate.
#[test]
fn a_dogwood_bundle_the_cli_builds_is_accepted_by_the_control_plane() {
    let example = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/dogwood-session-access")
        .canonicalize()
        .expect("the shipped example is where the repository keeps it");

    let remote = EngineRemote::new("dogwood");
    let dir = scratch("dogwood-author");
    let store = FsStore::new(&dir);
    let workspace = Workspace::open(&store);
    workspace.init("session-access", &["dogwood"]).unwrap();

    // The example's own manifest and its own bundle: a test that authored a smaller one would be
    // proving something about the test rather than about what ships.
    for file in [
        "manifest.yml",
        "governance/read-after-login.dw",
        "governance/schema.cedarschema",
        "governance/events.dwschema",
    ] {
        let bytes = std::fs::read(example.join(file)).expect("the example carries it");
        store.write(file, &bytes).unwrap();
    }
    // `init` named its partition after the language; the example's manifest declares
    // `governance` instead, and a partition folder nobody declares is dirt, not decoration.
    store.remove("dogwood").unwrap();

    let mut config = workspace.config().unwrap();
    config.remotes.insert(
        "origin".into(),
        permguard_cli::engine::workspace::config::RemoteConfig {
            url: "test://".into(),
            tls_ca_file: None,
        },
    );
    workspace.save_config(&config).unwrap();
    let checkout = workspace.checkout(&remote, "origin", "delivery", "session-ledger", "main");
    assert_eq!(checkout.expect("an empty ledger is bound").counter, 0);

    // The CLI validates the bundle locally...
    let (_, plan) = workspace.plan().expect("the Dogwood workspace validates");
    assert_eq!(plan.actions.len(), 1, "one policy: {:?}", plan.actions);

    // ...and the control plane accepts exactly what it built.
    let applied = workspace
        .apply(&remote, "alice@acme.com", "session access")
        .expect("the control plane accepts the Dogwood bundle the CLI signed");
    assert_eq!(applied.counter, 1);
    assert!(
        applied.uploaded >= 5,
        "the policy, both schemas, the trees, the manifest and the commit travelled: {}",
        applied.uploaded
    );

    // And it is the same snapshot on both sides: a re-apply has nothing to say.
    let again = workspace.apply(&remote, "alice@acme.com", "noop").unwrap();
    assert_eq!(again.counter, 1);
    assert_eq!(again.uploaded, 0);
}

/// A plane that has not enabled Dogwood refuses the push, rather than storing it.
///
/// Refusing at ingest is the whole point of the gate: a ledger accepted here would be mirrored to
/// every data plane and refused at each of their load gates instead — fail-closed, but the error
/// would belong to planes that did nothing wrong, long after the push that caused it succeeded.
#[test]
fn a_plane_that_has_not_enabled_dogwood_refuses_the_push() {
    let example = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/dogwood-session-access")
        .canonicalize()
        .expect("the shipped example is where the repository keeps it");

    let remote = EngineRemote::without_dogwood("dogwood-off");
    let dir = scratch("dogwood-off-author");
    let store = FsStore::new(&dir);
    let workspace = Workspace::open(&store);
    workspace.init("session-access", &["dogwood"]).unwrap();

    for file in [
        "manifest.yml",
        "governance/read-after-login.dw",
        "governance/schema.cedarschema",
        "governance/events.dwschema",
    ] {
        let bytes = std::fs::read(example.join(file)).expect("the example carries it");
        store.write(file, &bytes).unwrap();
    }
    // `init` named its partition after the language; the example's manifest declares
    // `governance` instead, and a partition folder nobody declares is dirt, not decoration.
    store.remove("dogwood").unwrap();

    let mut config = workspace.config().unwrap();
    config.remotes.insert(
        "origin".into(),
        permguard_cli::engine::workspace::config::RemoteConfig {
            url: "test://".into(),
            tls_ca_file: None,
        },
    );
    workspace.save_config(&config).unwrap();
    let _ = workspace.checkout(&remote, "origin", "delivery", "session-ledger", "main");

    // The CLI still validates it: the build carries the language either way. What differs is
    // whether *this deployment* will serve it.
    workspace.plan().expect("the workspace itself is valid");

    let refused = workspace
        .apply(&remote, "alice@acme.com", "session access")
        .expect_err("a plane that has not enabled Dogwood must refuse the push");
    let message = refused.to_string();
    assert!(
        message.contains("experimental.dogwood.enabled"),
        "the refusal names the setting that would allow it: {message}"
    );
}

/// `clone` is a new workspace bound to the ledger and pulled whole: the remote named `origin` at
/// the URL given, the ignore file `init` writes, every policy materialised, and a binding a later
/// pull finds through `tracked`.
#[test]
fn a_clone_is_a_workspace_bound_to_its_ledger_and_pulled() {
    use permguard_cli::engine::workspace::clone::{ORIGIN, clone};

    let remote = EngineRemote::new("clone");
    let dir_a = scratch("clone-author");
    let store_a = FsStore::new(&dir_a);
    let ws_a = Workspace::open(&store_a);
    ws_a.init("acme-authz", &["cedar"]).unwrap();
    store_a
        .write("cedar/billing.cedar", CEDAR.as_bytes())
        .unwrap();
    let mut config = ws_a.config().unwrap();
    config.remotes.insert(
        "origin".into(),
        permguard_cli::engine::workspace::config::RemoteConfig {
            url: "test://".into(),
            tls_ca_file: None,
        },
    );
    ws_a.save_config(&config).unwrap();
    let _ = ws_a.checkout(&remote, "origin", "delivery", "main-ledger", "main");
    assert_eq!(
        ws_a.apply(&remote, "alice@acme.com", "first")
            .unwrap()
            .counter,
        1
    );

    let target = scratch("clone-target").join("main-ledger");
    let pulled = clone(&target, "test://", "delivery", "main-ledger", &remote).unwrap();
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
    assert!(target.join(".permguardignore").is_file());

    let store_b = FsStore::new(&target);
    let tracked = Workspace::open(&store_b).tracked().unwrap();
    assert_eq!(tracked.remote, ORIGIN);
    assert_eq!(tracked.url.as_deref(), Some("test://"));
    assert!(!tracked.zone_id.is_empty() && !tracked.ledger_id.is_empty());

    // A second clone into the same folder is refused, and the first is left as it was.
    let refused = clone(&target, "test://", "delivery", "main-ledger", &remote).unwrap_err();
    assert!(refused.to_string().contains("is not empty"), "{refused}");
    assert!(target.join("manifest.yml").is_file());
}

/// A remote nothing answers at: every call fails as a closed port does.
struct Unreachable;

impl Remote for Unreachable {
    fn resolve(&self, _zone: &str, _ledger: &str) -> Result<(String, String), String> {
        Err("nothing is listening".into())
    }
    fn keyring(&self) -> Result<Vec<u8>, String> {
        Err("nothing is listening".into())
    }
    fn get_ref(&self, _ref: &str) -> Result<Option<RefAnswer>, String> {
        Err("nothing is listening".into())
    }
    fn negotiate_push(
        &self,
        _request: &NegotiatePushRequest,
    ) -> Result<NegotiatePushResponse, String> {
        Err("nothing is listening".into())
    }
    fn upload(&self, _request: &UploadObjectsRequest) -> Result<UploadObjectsResponse, String> {
        Err("nothing is listening".into())
    }
    fn commit_push(&self, _request: &CommitPushRequest) -> Result<CommitPushResponse, String> {
        Err("nothing is listening".into())
    }
    fn negotiate_pull(
        &self,
        _request: &NegotiatePullRequest,
    ) -> Result<NegotiatePullResponse, String> {
        Err("nothing is listening".into())
    }
    fn fetch(&self, _request: &FetchObjectsRequest) -> Result<FetchObjectsResponse, String> {
        Err("nothing is listening".into())
    }
}

/// BUG-0068: a clone that fails leaves the destination as it found it, so the same clone runs
/// again; a destination that is not empty is refused and nothing in it is touched.
#[test]
fn a_failed_clone_leaves_its_destination_as_it_found_it() {
    use permguard_cli::engine::workspace::clone::clone;

    // A folder the clone would create is not left behind.
    let root = scratch("clone-failed");
    let target = root.join("main-ledger");
    clone(&target, "test://", "delivery", "main-ledger", &Unreachable).unwrap_err();
    assert!(!target.exists(), "the folder it created is removed");

    // An empty folder that was there stays, empty.
    std::fs::create_dir_all(&target).unwrap();
    clone(&target, "test://", "delivery", "main-ledger", &Unreachable).unwrap_err();
    assert!(target.is_dir());
    assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0, "left empty");

    // A folder holding the author's files is refused, and they stay.
    let held = root.join("held");
    std::fs::create_dir_all(&held).unwrap();
    std::fs::write(held.join("notes.txt"), "mine").unwrap();
    let refused = clone(&held, "test://", "delivery", "main-ledger", &Unreachable).unwrap_err();
    assert!(refused.to_string().contains("is not empty"), "{refused}");
    assert_eq!(
        std::fs::read_to_string(held.join("notes.txt")).unwrap(),
        "mine"
    );

    // Once the remote answers, the same clone succeeds into the same folder.
    let remote = EngineRemote::new("clone-retry");
    let pulled = clone(&target, "test://", "delivery", "main-ledger", &remote).unwrap();
    assert_eq!(pulled.counter, 0);
}

/// BUG-0213: a clone of a ledger with no history holds the manifest `init` writes, so its first
/// `apply` creates that history, with no `init` in between.
#[test]
fn a_clone_of_an_empty_ledger_applies_its_first_policy() {
    use permguard_cli::engine::workspace::clone::clone;

    let remote = EngineRemote::new("clone-empty");
    let target = scratch("clone-empty").join("main-ledger");
    let pulled = clone(&target, "test://", "delivery", "main-ledger", &remote).unwrap();
    assert_eq!(pulled.counter, 0);
    assert!(
        target.join("manifest.yml").is_file(),
        "the manifest `init` writes"
    );
    let store = FsStore::new(&target);
    store
        .write("cedar/billing.cedar", CEDAR.as_bytes())
        .unwrap();
    let workspace = Workspace::open(&store);
    assert_eq!(
        workspace
            .apply(&remote, "alice@acme.com", "first")
            .unwrap()
            .counter,
        1
    );
}

/// The policy files of `partition`, as the tree holds them.
fn files_of(store: &FsStore, partition: &str) -> Vec<String> {
    store
        .list(partition)
        .unwrap()
        .into_iter()
        .filter(|(name, is_dir)| !is_dir && name.ends_with(".cedar"))
        .map(|(name, _)| format!("{partition}/{name}"))
        .collect()
}

/// BUG-0026, DEC-0003: a policy deleted here is a pending deletion a pull keeps, whatever else
/// it brings; deleted here and changed there is a conflict that writes nothing.
#[test]
fn a_pull_keeps_a_local_deletion_and_refuses_one_the_remote_changed() {
    let remote = EngineRemote::new("local-delete");
    let store_a = FsStore::new(scratch("local-delete-a"));
    let ws_a = bind(&store_a);
    store_a
        .write("cedar/billing.cedar", CEDAR.as_bytes())
        .unwrap();
    store_a.write("rego/routes.rego", REGO.as_bytes()).unwrap();
    let _ = ws_a.checkout(&remote, "origin", "delivery", "main-ledger", "main");
    assert_eq!(
        ws_a.apply(&remote, "a@acme.com", "base").unwrap().counter,
        1
    );

    let store_b = FsStore::new(scratch("local-delete-b"));
    let ws_b = bind(&store_b);
    std::fs::remove_file(store_b.root().join("manifest.yml")).unwrap();
    ws_b.checkout(&remote, "origin", "delivery", "main-ledger", "main")
        .unwrap();
    let deleted = files_of(&store_b, "cedar");
    assert_eq!(deleted.len(), 1, "{deleted:?}");
    store_b.remove(&deleted[0]).unwrap();

    // An unrelated remote change: the pull lands it and keeps the deletion pending.
    store_a
        .write(
            "rego/routes.rego",
            REGO.replace("allow", "allowed").as_bytes(),
        )
        .unwrap();
    assert_eq!(
        ws_a.apply(&remote, "a@acme.com", "rego").unwrap().counter,
        2
    );
    ws_b.pull(&remote, false).unwrap();
    assert!(files_of(&store_b, "cedar").is_empty(), "never written back");
    let (_, plan) = ws_b.plan().unwrap();
    let deletes = plan
        .actions
        .iter()
        .filter(|action| {
            matches!(
                action,
                permguard_cli::engine::workspace::PlanAction::Delete { .. }
            )
        })
        .count();
    assert_eq!(deletes, 1, "the deletion is still what apply sends");

    // The remote changes the policy this workspace deleted: a conflict, and nothing moves.
    store_a
        .write(
            "cedar/billing.cedar",
            CEDAR
                .replace("Action::\"read\"", "Action::\"list\"")
                .as_bytes(),
        )
        .unwrap();
    assert_eq!(
        ws_a.apply(&remote, "a@acme.com", "list").unwrap().counter,
        3
    );
    let refused = ws_b.pull(&remote, false).unwrap_err().to_string();
    assert!(refused.contains("deleted here"), "{refused}");
    assert_eq!(ws_b.status().unwrap().checkpoint.unwrap().counter, 2);
    assert!(files_of(&store_b, "cedar").is_empty());
}

/// BUG-0017, DEC-0003: a manifest unchanged here takes the remote's change, and a plan is then
/// empty; one changed on both sides is a conflict naming it, and the checkpoint stays.
#[test]
fn a_pull_lands_a_remote_manifest_change_and_refuses_one_changed_on_both_sides() {
    let remote = EngineRemote::new("manifest-merge");
    let store_a = FsStore::new(scratch("manifest-merge-a"));
    let ws_a = bind(&store_a);
    store_a
        .write("cedar/billing.cedar", CEDAR.as_bytes())
        .unwrap();
    store_a.write("rego/routes.rego", REGO.as_bytes()).unwrap();
    let _ = ws_a.checkout(&remote, "origin", "delivery", "main-ledger", "main");
    assert_eq!(
        ws_a.apply(&remote, "a@acme.com", "base").unwrap().counter,
        1
    );

    let store_b = FsStore::new(scratch("manifest-merge-b"));
    let ws_b = bind(&store_b);
    std::fs::remove_file(store_b.root().join("manifest.yml")).unwrap();
    ws_b.checkout(&remote, "origin", "delivery", "main-ledger", "main")
        .unwrap();

    let add_profile = |store: &FsStore, name: &str| {
        let manifest = text(store, "manifest.yml");
        let added = manifest.replacen(
            "profiles:\n",
            &format!(
                "profiles:\n  {name}: {{ type: permguard.api.pdp.native.v1, partitions: [cedar] }}\n"
            ),
            1,
        );
        assert_ne!(added, manifest, "the profile is added");
        store.write("manifest.yml", added.as_bytes()).unwrap();
    };
    add_profile(&store_a, "readonly");
    assert_eq!(
        ws_a.apply(&remote, "a@acme.com", "readonly")
            .unwrap()
            .counter,
        2
    );

    ws_b.pull(&remote, false).unwrap();
    assert!(text(&store_b, "manifest.yml").contains("readonly"));
    assert!(ws_b.plan().unwrap().1.is_empty(), "nothing to publish back");

    add_profile(&store_a, "auditors");
    assert_eq!(
        ws_a.apply(&remote, "a@acme.com", "auditors")
            .unwrap()
            .counter,
        3
    );
    add_profile(&store_b, "operators");
    let refused = ws_b.pull(&remote, false).unwrap_err().to_string();
    assert!(refused.contains("manifest.yml"), "{refused}");
    assert_eq!(ws_b.status().unwrap().checkpoint.unwrap().counter, 2);
    assert!(text(&store_b, "manifest.yml").contains("operators"));
}

/// BUG-0009, BUG-0049, DEC-0003: with no tracked head the manifest is pending; an empty folder is
/// no part of the snapshot, so a workspace with one publishes what one without it does, and a
/// clone of it plans nothing.
#[test]
fn the_manifest_is_pending_before_the_first_head_and_an_empty_folder_is_nothing() {
    let remote = EngineRemote::new("empty-folder");
    let store_a = FsStore::new(scratch("empty-folder-a"));
    let ws_a = bind(&store_a);
    store_a
        .write("cedar/billing.cedar", CEDAR.as_bytes())
        .unwrap();
    store_a.write("rego/routes.rego", REGO.as_bytes()).unwrap();
    assert!(
        ws_a.plan().unwrap().1.manifest_changed,
        "nothing tracked: the manifest is pending"
    );
    let without = ws_a.refresh().unwrap().root;
    std::fs::create_dir_all(store_a.root().join("cedar/drafts")).unwrap();
    assert_eq!(
        ws_a.refresh().unwrap().root,
        without,
        "an empty folder is nothing"
    );

    let _ = ws_a.checkout(&remote, "origin", "delivery", "main-ledger", "main");
    assert_eq!(
        ws_a.apply(&remote, "a@acme.com", "base").unwrap().counter,
        1
    );
    assert!(ws_a.plan().unwrap().1.is_empty());

    let store_b = FsStore::new(scratch("empty-folder-b"));
    let ws_b = bind(&store_b);
    std::fs::remove_file(store_b.root().join("manifest.yml")).unwrap();
    ws_b.checkout(&remote, "origin", "delivery", "main-ledger", "main")
        .unwrap();
    assert!(ws_b.plan().unwrap().1.is_empty(), "a clone plans nothing");
}

/// BUG-0204: a checkout of a ref the ledger does not hold yet says so, not that the ledger is
/// empty, and an apply from it reports the ref it moved.
#[test]
fn a_new_ref_is_not_an_empty_ledger_and_apply_reports_the_ref_it_moved() {
    let remote = EngineRemote::new("new-ref");
    let store_a = FsStore::new(scratch("new-ref-a"));
    let ws_a = bind(&store_a);
    store_a
        .write("cedar/billing.cedar", CEDAR.as_bytes())
        .unwrap();
    store_a.write("rego/routes.rego", REGO.as_bytes()).unwrap();
    let _ = ws_a.checkout(&remote, "origin", "delivery", "main-ledger", "main");
    let applied = ws_a.apply(&remote, "a@acme.com", "base").unwrap();
    assert_eq!((applied.r#ref.as_str(), applied.counter), ("main", 1));

    let store_b = FsStore::new(scratch("new-ref-b"));
    let ws_b = bind(&store_b);
    let bound = ws_b
        .checkout(&remote, "origin", "delivery", "main-ledger", "dev")
        .unwrap();
    assert_eq!(bound.counter, 0);
    assert_eq!(bound.missing_ref.as_deref(), Some("dev"));
    store_b
        .write("cedar/billing.cedar", CEDAR.as_bytes())
        .unwrap();
    let applied = ws_b.apply(&remote, "b@acme.com", "dev").unwrap();
    assert_eq!(applied.r#ref, "dev");
}

/// BUG-0006: `verify` tells a ledger that is gone from a ref that is missing. A ledger recreated
/// under the tracked names is another ledger, and says so; the tracked ledger without the ref says
/// the ref is missing.
#[test]
fn verify_tells_a_ledger_that_is_gone_from_a_missing_ref() {
    let remote = EngineRemote::new("verify-gone");
    let store = FsStore::new(scratch("verify-gone"));
    let ws = bind(&store);
    store
        .write("cedar/billing.cedar", CEDAR.as_bytes())
        .unwrap();
    let _ = ws.checkout(&remote, "origin", "delivery", "main-ledger", "main");
    assert_eq!(ws.apply(&remote, "a@acme.com", "base").unwrap().counter, 1);
    ws.verify(&remote).unwrap();

    // The ledger deleted, and a new one created under the same names: another id.
    let recreated = EngineRemote::for_ledger("verify-recreated", "ledger-recreated-guid");
    let refused = ws.verify(&recreated).unwrap_err().to_string();
    assert!(
        refused.contains("no longer exists") && refused.contains("ledger-recreated-guid"),
        "{refused}"
    );

    // The tracked ledger itself, without the ref: the ref is what is missing.
    let unpushed = EngineRemote::new("verify-unpushed");
    let refused = ws.verify(&unpushed).unwrap_err().to_string();
    assert!(refused.contains("has no ref `main`"), "{refused}");
}
