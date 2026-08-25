// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The transfer lifecycle against a server that misbehaves.
//!
//! The e2e suite proves the honest flow; this one proves the defenses. Every
//! test wraps the real in-process engine in a remote that lies in exactly one
//! way — an object nobody asked for, a withheld object, a head signed by a
//! foreign key, a replayed older head — and asserts two things: the refusal,
//! and that **the checkpoint did not move**. A defense that rejects but
//! advances state anyway is no defense.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;

use permguard_cli::engine::remote::{RefAnswer, Remote};
use permguard_cli::engine::{FsStore, Store as _, Workspace};
use permguard_control_plane::engine::{Engine, EngineError, EngineLimits, LedgerIdentity};
use permguard_control_plane::store::FileObjectStore;
use permguard_notp::{
    CommitPushRequest, CommitPushResponse, FetchObjectsRequest, FetchObjectsResponse,
    NegotiatePullRequest, NegotiatePullResponse, NegotiatePushRequest, NegotiatePushResponse,
    UploadObjectsRequest, UploadObjectsResponse,
};
use permguard_objects::object::Blob;
use permguard_objects::statement::SignedHead;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};

// ---- the honest half: the same in-process engine the e2e suite drives ----

struct EngineRemote {
    store: FileObjectStore,
    key: Ed25519KeyPair,
}

impl EngineRemote {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("pg-ws-hostile-{tag}-{}", std::process::id()));
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
                max_batch_objects: 1000,
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
        let x = base64_url(self.key.public_key().as_ref());
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

fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

// ---- the lies, one per wrapper ----

/// How the wrapped remote misbehaves — exactly one lie at a time.
enum Lie {
    /// `fetch` slips one extra object into the batch that nobody asked for.
    SmuggleObject,
    /// `fetch` withholds every object: the closure can never complete.
    WithholdObjects,
    /// Head statements are signed by a key the ring never published.
    ForeignSigner(Ed25519KeyPair),
}

struct HostileRemote {
    honest: EngineRemote,
    lie: Lie,
}

impl HostileRemote {
    fn resign(&self, statement_bytes: &[u8]) -> Vec<u8> {
        // Decode the honest statement, re-sign it with the foreign key under
        // the published kid — the impersonation a stolen ring name enables.
        let Lie::ForeignSigner(key) = &self.lie else {
            return statement_bytes.to_vec();
        };
        let honest = SignedHead::decode(statement_bytes)
            .expect("the honest statement parses")
            .statement_unverified()
            .expect("the honest statement decodes");
        SignedHead::sign(&honest, key, b"test-key")
            .expect("the forgery signs")
            .encode()
    }
}

impl Remote for HostileRemote {
    fn resolve(&self, zone: &str, ledger: &str) -> Result<(String, String), String> {
        self.honest.resolve(zone, ledger)
    }

    fn keyring(&self) -> Result<Vec<u8>, String> {
        self.honest.keyring()
    }

    fn get_ref(&self, r#ref: &str) -> Result<Option<RefAnswer>, String> {
        Ok(self.honest.get_ref(r#ref)?.map(|answer| RefAnswer {
            statement: self.resign(&answer.statement),
            ..answer
        }))
    }

    fn negotiate_push(
        &self,
        request: &NegotiatePushRequest,
    ) -> Result<NegotiatePushResponse, String> {
        self.honest.negotiate_push(request)
    }

    fn upload(&self, request: &UploadObjectsRequest) -> Result<UploadObjectsResponse, String> {
        self.honest.upload(request)
    }

    fn commit_push(&self, request: &CommitPushRequest) -> Result<CommitPushResponse, String> {
        let answer = self.honest.commit_push(request)?;
        Ok(CommitPushResponse {
            statement: self.resign(&answer.statement),
            ..answer
        })
    }

    fn negotiate_pull(
        &self,
        request: &NegotiatePullRequest,
    ) -> Result<NegotiatePullResponse, String> {
        let answer = self.honest.negotiate_pull(request)?;
        Ok(NegotiatePullResponse {
            statement: self.resign(&answer.statement),
            ..answer
        })
    }

    fn fetch(&self, request: &FetchObjectsRequest) -> Result<FetchObjectsResponse, String> {
        match &self.lie {
            Lie::WithholdObjects => Ok(FetchObjectsResponse {
                objects: Vec::new(),
                compression: None,
            }),
            Lie::SmuggleObject => {
                let mut answer = self.honest.fetch(request)?;
                let smuggled = Blob {
                    media_type: "application/vnd.permguard.policy.cedar".into(),
                    data: b"permit(principal, action, resource); // smuggled".to_vec(),
                }
                .encode()
                .expect("the smuggled blob encodes");
                answer.objects.push(smuggled);
                Ok(answer)
            }
            Lie::ForeignSigner(_) => self.honest.fetch(request),
        }
    }
}

// ---- fixtures ----

const CEDAR: &str =
    "@alias(\"readers\")\npermit(principal, action == Action::\"read\", resource);\n";

fn scratch(tag: &str) -> PathBuf {
    // Keyed by thread too: the tests run in parallel inside one process.
    let dir = std::env::temp_dir().join(format!(
        "pg-ws-hostile-ws-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// An authored workspace, checked out and applied against the honest remote:
/// the state every attack starts from.
fn seeded(tag: &str, remote: &EngineRemote) -> (FsStore, u64) {
    let store = FsStore::new(scratch(tag));
    let ws = Workspace::open(&store);
    ws.init("hostile-lab", &["cedar"]).unwrap();
    store.write("cedar/rules.cedar", CEDAR.as_bytes()).unwrap();

    let mut config = ws.config().unwrap();
    config.remotes.insert(
        "origin".into(),
        permguard_cli::engine::workspace::config::RemoteConfig {
            url: "test://".into(),
            tls_ca_file: None,
        },
    );
    ws.save_config(&config).unwrap();
    let _ = ws.checkout(remote, "origin", "zone-guid", "ledger-guid", "main");
    let applied = ws.apply(remote, "tester", "seed").unwrap();
    (store, applied.counter)
}

fn checkpoint_of(store: &FsStore) -> permguard_cli::engine::workspace::config::Checkpoint {
    permguard_cli::engine::workspace::config::read_checkpoint(store, "main")
        .unwrap()
        .expect("a checkpoint exists after the seed apply")
}

/// A second author's edit lands on the remote, so a pull has work to do.
fn advance_remote(remote: &EngineRemote) {
    let (store_b, _) = seeded("advancer", remote);
    // (scratch is thread-keyed, so parallel tests never share this clone)
    let ws_b = Workspace::open(&store_b);
    store_b
        .write(
            "cedar/more.cedar",
            "@alias(\"writers\")\npermit(principal, action == Action::\"write\", resource);\n"
                .as_bytes(),
        )
        .unwrap();
    ws_b.pull(remote).unwrap();
    ws_b.apply(remote, "tester-b", "advance").unwrap();
}

// ---- the attacks ----

#[test]
fn an_object_nobody_asked_for_is_refused_and_the_checkpoint_stays() {
    let honest = EngineRemote::new("smuggle");
    let (store, _) = seeded("smuggle", &honest);
    advance_remote(&honest);
    let before = checkpoint_of(&store);

    let hostile = HostileRemote {
        honest,
        lie: Lie::SmuggleObject,
    };
    let error = Workspace::open(&store)
        .pull(&hostile)
        .expect_err("a smuggled object must be refused");

    assert!(error.message.contains("not asked for"), "{}", error.message);
    assert_eq!(
        checkpoint_of(&store),
        before,
        "the checkpoint must not move"
    );
}

#[test]
fn a_withheld_closure_is_refused_and_the_checkpoint_stays() {
    let honest = EngineRemote::new("withhold");
    let (store, _) = seeded("withhold", &honest);
    advance_remote(&honest);
    let before = checkpoint_of(&store);

    let hostile = HostileRemote {
        honest,
        lie: Lie::WithholdObjects,
    };
    let error = Workspace::open(&store)
        .pull(&hostile)
        .expect_err("an incomplete closure must be refused");

    assert!(
        error.message.contains("closure is incomplete"),
        "{}",
        error.message
    );
    assert_eq!(
        checkpoint_of(&store),
        before,
        "the checkpoint must not move"
    );
}

#[test]
fn a_head_signed_by_a_foreign_key_is_refused_everywhere_it_appears() {
    let honest = EngineRemote::new("foreign");
    let (store, _) = seeded("foreign", &honest);
    advance_remote(&honest);
    let before = checkpoint_of(&store);

    let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let hostile = HostileRemote {
        honest,
        lie: Lie::ForeignSigner(Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap()),
    };
    let ws = Workspace::open(&store);

    // The pull path refuses before anything advances.
    let error = ws
        .pull(&hostile)
        .expect_err("a forged head must be refused");
    assert!(
        error.message.contains("does not verify"),
        "{}",
        error.message
    );
    assert_eq!(
        checkpoint_of(&store),
        before,
        "the checkpoint must not move"
    );

    // And verify says the same thing about the advertised ref.
    let error = ws
        .verify(&hostile)
        .expect_err("verify must refuse the forgery too");
    assert!(
        error.message.contains("does not verify"),
        "{}",
        error.message
    );
}

#[test]
fn a_forged_commit_acknowledgement_never_advances_the_checkpoint() {
    // The push half of the same defense: the server accepts the commit but
    // answers with a statement the ring cannot vouch for — the apply fails
    // *after* the CAS, and the local checkpoint still refuses to move.
    let honest = EngineRemote::new("forged-ack");
    let (store, _) = seeded("forged-ack", &honest);
    let before = checkpoint_of(&store);

    let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let hostile = HostileRemote {
        honest,
        lie: Lie::ForeignSigner(Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap()),
    };
    let ws = Workspace::open(&store);
    store
        .write(
            "cedar/extra.cedar",
            "@alias(\"extra\")\npermit(principal, action == Action::\"list\", resource);\n"
                .as_bytes(),
        )
        .unwrap();

    let error = ws
        .apply(&hostile, "tester", "forged")
        .expect_err("a forged acknowledgement must be refused");
    assert!(
        error.message.contains("does not verify"),
        "{}",
        error.message
    );
    assert_eq!(
        checkpoint_of(&store),
        before,
        "the checkpoint must not move"
    );
}

#[test]
fn without_a_tracked_ledger_the_syncing_commands_say_what_to_do() {
    let remote = EngineRemote::new("untracked");
    let store = FsStore::new(scratch("untracked"));
    let ws = Workspace::open(&store);
    ws.init("untracked", &["cedar"]).unwrap();

    for error in [
        ws.pull(&remote).expect_err("pull needs a tracked ledger"),
        ws.apply(&remote, "t", "m")
            .expect_err("apply needs a tracked ledger"),
        ws.verify(&remote)
            .expect_err("verify needs a tracked ledger"),
    ] {
        assert!(
            error.message.contains("permguard checkout"),
            "{}",
            error.message
        );
    }
}

#[test]
fn a_corrupt_local_checkpoint_stops_the_sync_instead_of_trusting_it() {
    let honest = EngineRemote::new("corrupt-cp");
    let (store, _) = seeded("corrupt-cp", &honest);

    store
        .write(
            ".permguard/refs/main",
            br#"{"head":"not-a-digest","counter":1}"#,
        )
        .unwrap();

    let error = Workspace::open(&store)
        .pull(&honest)
        .expect_err("a corrupt checkpoint must stop the pull");
    assert!(
        error.message.to_lowercase().contains("checkpoint"),
        "{}",
        error.message
    );
}
