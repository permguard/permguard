// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A mirror's remote over a `policy.mirror` task session (WP-7.2a).
//!
//! ```text
//! round ─▶ MirrorTasks::open_mirror(task)        the member opens; the lease is verified and kept
//!       ─▶ list_ledgers                          what the task's resource covers, by id
//!       ─▶ per ledger: TaskRemote                the same pull, verification and checkpoint as
//!            negotiate_pull, key_ring, fetch      over a URL, its reads carried on the session
//! ```
//!
//! The session is authenticated by the membership: the coordinator its pin verified, the lease
//! bound to the connection. Nothing here names a URL, a TLS root or a statement key.

use std::sync::Arc;

use permguard_control_client::remote::{RefAnswer, Remote};
use permguard_host::composition::{MirrorSession, MirrorTask};
use permguard_notp::{
    CommitPushRequest, CommitPushResponse, FetchObjectsRequest, FetchObjectsResponse,
    GetRefRequest, GetRefResponse, ListLedgersAnswer, MirrorOperation, MirrorRequest,
    NegotiatePullRequest, NegotiatePullResponse, NegotiatePushRequest, NegotiatePushResponse,
    UploadObjectsRequest, UploadObjectsResponse,
};

/// One open session, shared by the ledgers a round mirrors over it: one message, one answer, in
/// order.
pub type Shared = Arc<tokio::sync::Mutex<Box<dyn MirrorSession>>>;

/// The ledgers `task`'s resource covers, as the coordinator lists them over `session`.
pub async fn list(session: &Shared, task: &MirrorTask) -> Result<ListLedgersAnswer, String> {
    let message = MirrorRequest {
        operation: MirrorOperation::ListLedgers,
        zone: String::new(),
        ledger: String::new(),
        body: Vec::new(),
    }
    .encode()
    .map_err(|error| format!("encoding the listing: {error}"))?;
    let answer = session
        .lock()
        .await
        .call(message)
        .await
        .map_err(|refusal| format!("listing the ledgers of task `{}`: {refusal}", task.task_id))?;
    ListLedgersAnswer::decode(&answer).map_err(|error| format!("the listing: {error}"))
}

/// Where a task mirror keeps the identity-signed binding of the `control.attest` set its
/// statements verified under (WP-7.2b).
pub const RING_BINDING: &str = "RING-BINDING.cose";

/// Pulls one ledger over its task session (WP-7.2b), the same pull a URL mirror runs bound to
/// the membership: the ring never goes back nor forks at one epoch, checked before anything is
/// fetched; the statement verifies under the pinned `control.attest` keys only, names the task's
/// coordinator as its authority and the pin's epoch and key-set digest. The switch, the binding
/// with it, is the caller's, through the mirror's journal (WP-7.2c).
pub fn verified_pull(
    store: &dyn permguard_control_client::store::Store,
    tracked: &permguard_control_client::pull::TrackedRef,
    remote: &TaskRemote,
    ring: &permguard_host::composition::PinnedRing,
    coordinator: [u8; 16],
) -> Result<permguard_control_client::pull::VerifiedHead, String> {
    use permguard_control_client::pull;

    let expected = pull::Expected {
        authority_host_id: coordinator,
        ring_epoch: ring.epoch,
        key_set_digest: permguard_objects::digest::Digest::from_raw(ring.key_set_digest),
    };
    let verified = pull::fetch_closure_expecting(
        store,
        "objects",
        "refs/main",
        remote,
        tracked,
        Some(&expected),
    )?;
    Ok(verified)
}

/// The reads of one ledger over a task session, for the pull a URL mirror runs.
pub struct TaskRemote {
    session: Shared,
    runtime: tokio::runtime::Handle,
    zone_id: String,
    ledger_id: String,
    /// The signed task's bound on a message: a read larger than it is never sent.
    max_body_bytes: u64,
    /// The JWKS document of the membership's pinned `control.attest` set (WP-7.2b).
    keys: Vec<u8>,
}

impl TaskRemote {
    /// The reads of `zone_id`/`ledger_id` over `session`, from a blocking thread of `runtime`.
    ///
    /// Each read blocks on `runtime` from the thread the pull runs on: a `spawn_blocking` thread
    /// of the multi-threaded runtime every binary runs, never a runtime worker.
    pub fn new(
        session: Shared,
        runtime: tokio::runtime::Handle,
        zone_id: &str,
        ledger_id: &str,
        max_body_bytes: u64,
        ring: &permguard_host::composition::PinnedRing,
    ) -> Self {
        // The pinned keys as the JWKS document the statement verification reads; a key that is not
        // JSON is left out, and what it signed does not verify.
        let keys: Vec<serde_json::Value> = ring
            .keys
            .iter()
            .filter_map(|key| serde_json::from_str(key).ok())
            .collect();
        Self {
            session,
            runtime,
            zone_id: zone_id.to_owned(),
            ledger_id: ledger_id.to_owned(),
            max_body_bytes,
            keys: serde_json::to_vec(&serde_json::json!({ "keys": keys })).unwrap_or_default(),
        }
    }

    fn call(&self, operation: MirrorOperation, body: Vec<u8>) -> Result<Vec<u8>, Refused> {
        let message = MirrorRequest {
            operation,
            zone: self.zone_id.clone(),
            ledger: self.ledger_id.clone(),
            body,
        }
        .encode()
        .map_err(|error| Refused::other(format!("encoding the read: {error}")))?;
        if u64::try_from(message.len()).unwrap_or(u64::MAX) > self.max_body_bytes {
            return Err(Refused::other(format!(
                "a read of {} bytes is beyond the {} bytes the task allows a message",
                message.len(),
                self.max_body_bytes
            )));
        }
        let session = Arc::clone(&self.session);
        self.runtime
            .block_on(async move { session.lock().await.call(message).await })
            .map_err(|refusal| Refused {
                code: refusal.code.clone(),
                detail: refusal.to_string(),
            })
    }
}

/// A read the session refused, with the coordinator's code when it gave one.
struct Refused {
    code: String,
    detail: String,
}

impl Refused {
    fn other(detail: String) -> Self {
        Self {
            code: String::new(),
            detail,
        }
    }
}

impl Remote for TaskRemote {
    /// The session names ledgers by id only: a name is never resolved here.
    fn resolve(&self, zone: &str, ledger: &str) -> Result<(String, String), String> {
        if (zone, ledger) == (self.zone_id.as_str(), self.ledger_id.as_str()) {
            Ok((self.zone_id.clone(), self.ledger_id.clone()))
        } else {
            Err("a task session names its ledger by id, and only the one it was opened for".into())
        }
    }

    /// The membership's pinned `control.attest` keys (WP-7.2b): never a ring the coordinator
    /// hands over the session, which could name any key it likes.
    fn keyring(&self) -> Result<Vec<u8>, String> {
        Ok(self.keys.clone())
    }

    fn get_ref(&self, r#ref: &str) -> Result<Option<RefAnswer>, String> {
        let body = GetRefRequest {
            r#ref: r#ref.to_owned(),
        }
        .encode()
        .map_err(|error| error.to_string())?;
        match self.call(MirrorOperation::GetRef, body) {
            Ok(answer) => {
                let answer = GetRefResponse::decode(&answer).map_err(|error| error.to_string())?;
                Ok(Some(RefAnswer {
                    head: answer.head.to_string(),
                    counter: answer.counter,
                    statement: answer.statement,
                    ref_digest: answer.ref_digest.to_string(),
                }))
            }
            Err(refused) if refused.code == permguard_core::codes::common::NOT_FOUND => Ok(None),
            Err(refused) => Err(refused.detail),
        }
    }

    fn negotiate_push(&self, _: &NegotiatePushRequest) -> Result<NegotiatePushResponse, String> {
        Err(PULL_ONLY.to_owned())
    }

    fn upload(&self, _: &UploadObjectsRequest) -> Result<UploadObjectsResponse, String> {
        Err(PULL_ONLY.to_owned())
    }

    fn commit_push(&self, _: &CommitPushRequest) -> Result<CommitPushResponse, String> {
        Err(PULL_ONLY.to_owned())
    }

    fn negotiate_pull(
        &self,
        request: &NegotiatePullRequest,
    ) -> Result<NegotiatePullResponse, String> {
        let body = request.encode().map_err(|error| error.to_string())?;
        let answer = self
            .call(MirrorOperation::NegotiatePull, body)
            .map_err(|refused| refused.detail)?;
        NegotiatePullResponse::decode(&answer).map_err(|error| error.to_string())
    }

    fn fetch(&self, request: &FetchObjectsRequest) -> Result<FetchObjectsResponse, String> {
        let body = request.encode().map_err(|error| error.to_string())?;
        let answer = self
            .call(MirrorOperation::FetchObjects, body)
            .map_err(|refused| refused.detail)?;
        FetchObjectsResponse::decode(&answer).map_err(|error| error.to_string())
    }
}

/// What a push over a mirror's session is refused with: `policy.mirror` reads.
const PULL_ONLY: &str = "a policy.mirror task session only reads";

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::Mutex;

    use base64::Engine as _;
    use permguard_control_client::pull::TrackedRef;
    use permguard_control_client::store::Store as _;
    use permguard_host::composition::{MirrorRefusal, PinnedRing};
    use permguard_objects::digest::Digest;
    use permguard_objects::object::{Blob, Commit, Tree};
    use permguard_objects::statement::{HeadStatement, SignedHead};
    use ring::signature::{Ed25519KeyPair, KeyPair as _};

    use super::*;

    type Answer = Box<dyn Fn(&MirrorRequest) -> Result<Vec<u8>, MirrorRefusal> + Send>;

    /// A session answering from a script, keeping every message it carried.
    struct Scripted {
        carried: Arc<Mutex<Vec<MirrorRequest>>>,
        answer: Answer,
    }

    impl MirrorSession for Scripted {
        fn ring(&self) -> Option<PinnedRing> {
            None
        }

        fn call(
            &mut self,
            body: Vec<u8>,
        ) -> permguard_core::BoxFuture<'_, Result<Vec<u8>, MirrorRefusal>> {
            let request = MirrorRequest::decode(&body).expect("a mirror message");
            let answered = (self.answer)(&request);
            self.carried.lock().expect("the log").push(request);
            Box::pin(std::future::ready(answered))
        }
    }

    fn keypair(seed: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).expect("a key")
    }

    fn jwk(kid: &str, key: &Ed25519KeyPair) -> String {
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.public_key().as_ref());
        format!(
            r#"{{"kid":"{kid}","kty":"OKP","crv":"Ed25519","x":"{x}","alg":"EdDSA","use":"sig"}}"#
        )
    }

    const COORDINATOR: [u8; 16] = [0x11; 16];

    /// The membership's pin: `key` at epoch 2.
    fn pinned(key: &Ed25519KeyPair) -> PinnedRing {
        PinnedRing {
            epoch: 2,
            key_set_digest: *Digest::compute(b"the pinned set").raw(),
            binding: b"the binding".to_vec(),
            keys: vec![jwk("pinned", key)],
        }
    }

    /// A one-commit closure: its objects and its head.
    fn closure() -> (Vec<Vec<u8>>, Digest) {
        let manifest = Blob {
            media_type: "application/vnd.permguard.policy.cedar".into(),
            data: b"permit(principal, action, resource);".to_vec(),
        }
        .encode()
        .expect("a blob");
        let tree = Tree {
            entries: Vec::new(),
        }
        .encode()
        .expect("a tree");
        let commit = Commit {
            tree: Digest::compute(&tree),
            manifest: Digest::compute(&manifest),
            predecessors: Vec::new(),
            author: "test".into(),
            author_at: 1_700_000_000,
            message: "first".into(),
        }
        .encode()
        .expect("a commit");
        let head = Digest::compute(&commit);
        (vec![commit, tree, manifest], head)
    }

    /// The statement of `head` as the coordinator would sign it, every binding field given.
    fn statement(head: &Digest, authority: [u8; 16], epoch: u64, set: &Digest) -> HeadStatement {
        HeadStatement {
            zone: "zone-id".into(),
            ledger: "ledger-id".into(),
            r#ref: "main".into(),
            digest: head.clone(),
            counter: 1,
            signed_at: 1_700_000_000,
            authority_host_id: authority,
            ref_digest: Digest::compute(b"ref state"),
            ring_epoch: epoch,
            key_set_digest: set.clone(),
        }
    }

    /// A session that negotiates `signed` and serves `objects`, never anything else.
    fn serving(signed: Vec<u8>, statement: HeadStatement, objects: Vec<Vec<u8>>) -> Answer {
        Box::new(move |request: &MirrorRequest| {
            let encoded = match request.operation {
                MirrorOperation::NegotiatePull => NegotiatePullResponse {
                    head: statement.digest.clone(),
                    counter: statement.counter,
                    statement: signed.clone(),
                    missing: objects.iter().map(|bytes| Digest::compute(bytes)).collect(),
                    max_batch_bytes: 1 << 20,
                    max_batch_objects: 64,
                    compression: None,
                    transfer_id: [7; 16],
                    ref_digest: statement.ref_digest.clone(),
                    expiry: 60,
                }
                .encode(),
                MirrorOperation::FetchObjects => {
                    let asked = FetchObjectsRequest::decode(&request.body).expect("a fetch");
                    FetchObjectsResponse {
                        objects: objects
                            .iter()
                            .filter(|bytes| asked.digests.contains(&Digest::compute(bytes)))
                            .cloned()
                            .collect(),
                        compression: None,
                        expiry: 60,
                    }
                    .encode()
                }
                other => panic!("a task pull never asks {other:?}"),
            };
            Ok(encoded.expect("it encodes"))
        })
    }

    fn answer_basic(request: &MirrorRequest) -> Result<Vec<u8>, MirrorRefusal> {
        let encoded = match request.operation {
            MirrorOperation::GetRef => {
                let asked = GetRefRequest::decode(&request.body).expect("a ref read");
                if asked.r#ref != "main" {
                    return Err(MirrorRefusal {
                        code: permguard_core::codes::common::NOT_FOUND.to_owned(),
                        reason: "no such ref".to_owned(),
                    });
                }
                GetRefResponse {
                    head: Digest::compute(b"head"),
                    counter: 3,
                    statement: vec![1, 2, 3],
                    ref_digest: Digest::compute(b"ref"),
                }
                .encode()
            }
            MirrorOperation::NegotiatePull => NegotiatePullResponse {
                head: Digest::compute(b"head"),
                counter: 3,
                statement: vec![1, 2, 3],
                missing: vec![Digest::compute(b"head")],
                max_batch_bytes: 1024,
                max_batch_objects: 8,
                compression: None,
                transfer_id: [7; 16],
                ref_digest: Digest::compute(b"ref"),
                expiry: 60,
            }
            .encode(),
            MirrorOperation::FetchObjects => FetchObjectsResponse {
                objects: vec![b"object".to_vec()],
                compression: None,
                expiry: 60,
            }
            .encode(),
            MirrorOperation::KeyRing => panic!("a task mirror never asks the session for keys"),
            MirrorOperation::ListLedgers => ListLedgersAnswer {
                ledgers: Vec::new(),
                complete: true,
            }
            .encode(),
        };
        Ok(encoded.expect("it encodes"))
    }

    fn remote_with(
        max_body_bytes: u64,
        ring: &PinnedRing,
        answer: Answer,
    ) -> (TaskRemote, Arc<Mutex<Vec<MirrorRequest>>>) {
        let carried = Arc::new(Mutex::new(Vec::new()));
        let session: Shared = Arc::new(tokio::sync::Mutex::new(Box::new(Scripted {
            carried: Arc::clone(&carried),
            answer,
        })));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a runtime");
        let handle = runtime.handle().clone();
        // The runtime outlives the remote: this test drives it from its own thread.
        std::mem::forget(runtime);
        (
            TaskRemote::new(
                session,
                handle,
                "zone-id",
                "ledger-id",
                max_body_bytes,
                ring,
            ),
            carried,
        )
    }

    fn remote(max_body_bytes: u64) -> (TaskRemote, Arc<Mutex<Vec<MirrorRequest>>>) {
        remote_with(max_body_bytes, &pinned(&keypair(1)), Box::new(answer_basic))
    }

    /// WP-7.2a: every read names its ledger by id and travels as its own operation; an absent ref
    /// is an absent ref, and a mirror's session never pushes. WP-7.2b: the keys are the pinned
    /// set, never asked of the session.
    #[test]
    fn each_read_travels_as_its_operation_and_names_its_ledger() {
        let (remote, carried) = remote(1 << 20);

        let advertised = remote.get_ref("main").expect("read").expect("a ref");
        assert_eq!(advertised.counter, 3);
        assert!(
            remote.get_ref("other").expect("read").is_none(),
            "not found is absent"
        );
        let negotiated = remote
            .negotiate_pull(&NegotiatePullRequest {
                r#ref: "main".into(),
                at: None,
                have: Vec::new(),
                checkpoint: None,
            })
            .expect("negotiated");
        assert_eq!(negotiated.missing, vec![Digest::compute(b"head")]);
        let fetched = remote
            .fetch(&FetchObjectsRequest {
                digests: vec![Digest::compute(b"head")],
                accept_compression: None,
                transfer_id: [7; 16],
            })
            .expect("fetched");
        assert_eq!(fetched.objects, vec![b"object".to_vec()]);
        let keys: serde_json::Value =
            serde_json::from_slice(&remote.keyring().expect("the ring")).expect("a JWKS");
        assert_eq!(keys["keys"][0]["kid"], serde_json::json!("pinned"));

        let carried = carried.lock().expect("the log").clone();
        assert_eq!(
            carried
                .iter()
                .map(|request| request.operation)
                .collect::<Vec<_>>(),
            vec![
                MirrorOperation::GetRef,
                MirrorOperation::GetRef,
                MirrorOperation::NegotiatePull,
                MirrorOperation::FetchObjects,
            ],
            "the keys never travelled"
        );
        assert!(
            carried
                .iter()
                .all(|request| (request.zone.as_str(), request.ledger.as_str())
                    == ("zone-id", "ledger-id")),
            "{carried:?}"
        );

        assert!(remote.resolve("zone-id", "ledger-id").is_ok());
        assert!(
            remote.resolve("acme", "main").is_err(),
            "names are not resolved"
        );
        assert!(
            remote
                .commit_push(&CommitPushRequest {
                    r#ref: "main".to_owned(),
                    transfer_id: [1; 16],
                    new_head: Digest::compute(b"head"),
                    expected_ref: None,
                    request_id: "r".to_owned(),
                })
                .is_err(),
            "a mirror never pushes"
        );
    }

    /// WP-7.2a: a read exactly as large as the signed task allows a message is sent; one byte
    /// more is never sent.
    #[test]
    fn a_read_is_sent_up_to_the_task_bound_and_never_past_it() {
        let exact = MirrorRequest {
            operation: MirrorOperation::GetRef,
            zone: "zone-id".to_owned(),
            ledger: "ledger-id".to_owned(),
            body: GetRefRequest {
                r#ref: "main".into(),
            }
            .encode()
            .expect("it encodes"),
        }
        .encode()
        .expect("it encodes")
        .len() as u64;
        let (at, carried) = remote(exact);
        at.get_ref("main").expect("at the bound").expect("a ref");
        assert_eq!(carried.lock().expect("the log").len(), 1);
        let (below, carried) = remote(exact - 1);
        let refused = below.get_ref("main").expect_err("one byte past the bound");
        assert!(refused.contains("the task allows"), "{refused}");
        assert!(
            carried.lock().expect("the log").is_empty(),
            "nothing went out"
        );
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pg-task-pull-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory");
        dir
    }

    fn tracked() -> TrackedRef {
        TrackedRef {
            zone_id: "zone-id".into(),
            ledger_id: "ledger-id".into(),
            r#ref: "main".into(),
        }
    }

    /// WP-7.2b: a statement signed under the pinned set, naming the task's coordinator and the
    /// pin's epoch and set, pulls the closure and keeps the binding.
    #[test]
    fn a_statement_under_the_pinned_set_and_its_coordinator_pulls() {
        let key = keypair(1);
        let ring = pinned(&key);
        let (objects, head) = closure();
        let set = Digest::from_raw(ring.key_set_digest);
        let statement = statement(&head, COORDINATOR, ring.epoch, &set);
        let signed = SignedHead::sign(&statement, &key, b"pinned")
            .expect("signed")
            .encode()
            .expect("encoded");
        let signed_bytes = signed.clone();
        let (remote, _) = remote_with(1 << 20, &ring, serving(signed, statement, objects.clone()));
        let root = scratch("pinned");
        let store = permguard_control_client::FsStore::new(&root);

        let verified =
            verified_pull(&store, &tracked(), &remote, &ring, COORDINATOR).expect("verified");
        assert_eq!(verified.head, head);
        assert_eq!(
            verified.statement, signed_bytes,
            "the exact statement it verified"
        );
        let mut closure: Vec<Digest> = objects.iter().map(|bytes| Digest::compute(bytes)).collect();
        closure.sort();
        assert_eq!(
            verified.closure, closure,
            "every object of the closure, sorted"
        );
    }

    /// WP-7.2b: whatever the session would say of keys, a statement is refused when it is signed
    /// by a key the membership does not pin, names another authority, or names another epoch or
    /// set than the pin; nothing is kept of it.
    #[test]
    fn a_statement_outside_the_pin_or_its_coordinator_is_refused() {
        let key = keypair(1);
        let stranger = keypair(9);
        let ring = pinned(&key);
        let (objects, head) = closure();
        let set = Digest::from_raw(ring.key_set_digest);
        let cases: [(&str, &Ed25519KeyPair, HeadStatement, &str); 4] = [
            (
                "a key the membership does not pin",
                &stranger,
                statement(&head, COORDINATOR, ring.epoch, &set),
                "",
            ),
            (
                "another authority",
                &key,
                statement(&head, [0x22; 16], ring.epoch, &set),
                "another authority",
            ),
            (
                "another epoch",
                &key,
                statement(&head, COORDINATOR, ring.epoch + 1, &set),
                "another `control.attest` set",
            ),
            (
                "another set",
                &key,
                statement(&head, COORDINATOR, ring.epoch, &Digest::compute(b"other")),
                "another `control.attest` set",
            ),
        ];
        for (case, signer, statement, says) in cases {
            let signed = SignedHead::sign(&statement, signer, b"pinned")
                .expect("signed")
                .encode()
                .expect("encoded");
            let (remote, carried) =
                remote_with(1 << 20, &ring, serving(signed, statement, objects.clone()));
            let root = scratch(&case.replace(' ', "-"));
            let store = permguard_control_client::FsStore::new(&root);
            let refused =
                verified_pull(&store, &tracked(), &remote, &ring, COORDINATOR).expect_err(case);
            assert!(refused.contains(says), "{case}: {refused}");
            // Refused before a byte of policy crossed: no fetch, no object, no binding.
            assert!(
                carried
                    .lock()
                    .expect("the log")
                    .iter()
                    .all(|request| request.operation != MirrorOperation::FetchObjects),
                "{case}: nothing was fetched"
            );
            assert!(!root.join("objects").exists(), "{case}: no object landed");
            assert!(
                store.read(RING_BINDING).expect("reads").is_none(),
                "{case}: nothing is kept"
            );
        }
    }

    /// WP-7.2b: a pin below the epoch a mirror was verified under, or another set at that epoch,
    /// is refused before anything is asked of the session.
    #[test]
    fn a_ring_rollback_or_fork_is_refused_before_anything_is_fetched() {
        let key = keypair(1);
        let ring = pinned(&key);
        for (case, epoch, set) in [
            (
                "rollback",
                ring.epoch + 1,
                Digest::from_raw(ring.key_set_digest),
            ),
            ("equivocation", ring.epoch, Digest::compute(b"another set")),
        ] {
            let root = scratch(case);
            let store = permguard_control_client::FsStore::new(&root);
            permguard_control_client::checkpoint::write(
                &store,
                "refs/main",
                &permguard_control_client::checkpoint::Checkpoint {
                    head: Digest::compute(b"held").to_string(),
                    counter: 1,
                    ring_epoch: Some(epoch),
                    key_set_digest: Some(set.to_string()),
                    ..Default::default()
                },
            )
            .expect("held");
            let (remote, carried) = remote_with(
                1 << 20,
                &ring,
                Box::new(|_: &MirrorRequest| panic!("nothing is asked")),
            );
            let refused =
                verified_pull(&store, &tracked(), &remote, &ring, COORDINATOR).expect_err(case);
            assert!(refused.contains(case), "{case}: {refused}");
            assert!(carried.lock().expect("the log").is_empty(), "{case}");
        }
    }

    /// The member side of one `policy.mirror` task whose session lists `ledger-id` and serves
    /// `answer`, under `ring`.
    struct OneTask {
        ring: PinnedRing,
        answer: std::sync::Arc<Mutex<Answer>>,
    }

    struct Answering {
        ring: PinnedRing,
        answer: std::sync::Arc<Mutex<Answer>>,
    }

    impl MirrorSession for Answering {
        fn ring(&self) -> Option<PinnedRing> {
            Some(self.ring.clone())
        }

        fn call(
            &mut self,
            body: Vec<u8>,
        ) -> permguard_core::BoxFuture<'_, Result<Vec<u8>, MirrorRefusal>> {
            let request = MirrorRequest::decode(&body).expect("a mirror message");
            let answered = if request.operation == MirrorOperation::ListLedgers {
                Ok(ListLedgersAnswer {
                    ledgers: vec![permguard_notp::ListedLedger {
                        zone_id: "zone-id".into(),
                        zone_name: "acme".into(),
                        ledger_id: "ledger-id".into(),
                        ledger_name: "main-ledger".into(),
                    }],
                    complete: true,
                }
                .encode()
                .expect("it encodes"))
            } else {
                (self.answer.lock().expect("the script"))(&request)
            };
            Box::pin(std::future::ready(answered))
        }
    }

    impl permguard_host::composition::MirrorTasks for OneTask {
        fn watch_mirror<'a>(
            &'a self,
            _task: &'a permguard_host::composition::MirrorTask,
            _positions: Vec<(String, u64)>,
        ) -> permguard_core::BoxFuture<
            'a,
            Result<
                Box<dyn permguard_host::composition::MirrorWatch>,
                permguard_host::composition::MirrorRefusal,
            >,
        > {
            Box::pin(std::future::ready(Err(
                permguard_host::composition::MirrorRefusal {
                    code: "unavailable".to_owned(),
                    reason: "this stand-in watches nothing".to_owned(),
                },
            )))
        }

        fn mirror_tasks(&self) -> Vec<permguard_host::composition::MirrorTask> {
            vec![permguard_host::composition::MirrorTask {
                membership_id: [1; 16],
                task_id: "mirror".into(),
                coordinator: COORDINATOR,
                revision: 5,
                resource: "plane/control".into(),
                required: true,
                max_body_bytes: 1 << 20,
            }]
        }

        fn open_mirror<'a>(
            &'a self,
            _task: &'a permguard_host::composition::MirrorTask,
        ) -> permguard_core::BoxFuture<'a, Result<Box<dyn MirrorSession>, MirrorRefusal>> {
            Box::pin(std::future::ready(Ok(Box::new(Answering {
                ring: self.ring.clone(),
                answer: std::sync::Arc::clone(&self.answer),
            })
                as Box<dyn MirrorSession>)))
        }
    }

    /// WP-7.2c: a round over a task pulls a verified head and switches the mirror through its
    /// journal: one item naming the task's revision, the coordinator, the head, the ring and the
    /// closure, with the exact statement and binding as its views; a second round over the same
    /// head appends nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_round_over_a_task_switches_the_mirror_through_its_journal() {
        let key = keypair(1);
        let ring = pinned(&key);
        let (objects, head) = closure();
        let set = Digest::from_raw(ring.key_set_digest);
        let statement = statement(&head, COORDINATOR, ring.epoch, &set);
        let signed = SignedHead::sign(&statement, &key, b"pinned")
            .expect("signed")
            .encode()
            .expect("encoded");
        let answer = std::sync::Arc::new(Mutex::new(serving(
            signed.clone(),
            statement,
            objects.clone(),
        )));
        let root = scratch("round-journal");
        let context = std::sync::Arc::new(super::super::round::Context {
            sources: Vec::new(),
            tasks: Some(std::sync::Arc::new(OneTask {
                ring: ring.clone(),
                answer: std::sync::Arc::clone(&answer),
            })),
            selections: Default::default(),
            root: root.clone(),
            decider: None,
            deadline: std::time::Duration::from_secs(30),
            parallelism: 1,
            stale_after: None,
            permits: std::sync::Arc::new(tokio::sync::Semaphore::new(2)),
            metrics: permguard_core::Metrics::none(),
        });

        let outcome = super::super::round::run(std::sync::Arc::clone(&context)).await;
        assert_eq!((outcome.failed, outcome.unreachable), (0, 0), "{outcome:?}");
        let mirror = root
            .join(super::super::layout::authority_name(&COORDINATOR))
            .join("zone-id")
            .join("ledger-id");
        let state = super::super::state::recover(&mirror)
            .expect("reads")
            .expect("switched");
        assert_eq!(state.revision, 5);
        assert_eq!(state.authority, COORDINATOR);
        assert_eq!(state.head, head);
        assert_eq!(state.ring_epoch, ring.epoch);
        assert_eq!(state.verified, signed);
        assert_eq!(state.ring_binding, ring.binding);
        let mut digests: Vec<Digest> = objects.iter().map(|bytes| Digest::compute(bytes)).collect();
        digests.sort();
        assert_eq!(
            state.closure_digest,
            super::super::state::closure_digest(&digests)
        );
        assert_eq!(
            std::fs::read(mirror.join(super::super::state::VERIFIED)).expect("a view"),
            signed
        );
        assert_eq!(
            std::fs::read(mirror.join(RING_BINDING)).expect("a view"),
            ring.binding
        );
        assert_eq!(
            std::fs::read(mirror.join(super::super::state::CHECKPOINT)).expect("a view"),
            state.checkpoint().expect("encodes")
        );
        let json = permguard_control_client::checkpoint::read(
            &permguard_control_client::store::FsStore::new(&mirror),
            "refs/main",
        )
        .expect("reads")
        .expect("a view");
        assert_eq!(
            (json.counter, json.head),
            (state.counter, state.head.to_string())
        );

        super::super::round::run(context).await;
        let items = permguard_host::storage::sequence::read(
            &permguard_host::storage::Dir::open(&mirror).expect("opens"),
            super::super::state::JOURNAL,
            1 << 20,
        )
        .expect("reads")
        .items;
        assert_eq!(items.len(), 1, "the same head again appends nothing");
    }
}
