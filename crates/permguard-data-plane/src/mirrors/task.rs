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

/// The reads of one ledger over a task session, for the pull a URL mirror runs.
pub struct TaskRemote {
    session: Shared,
    runtime: tokio::runtime::Handle,
    zone_id: String,
    ledger_id: String,
    /// The signed task's bound on a message: a read larger than it is never sent.
    max_body_bytes: u64,
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
    ) -> Self {
        Self {
            session,
            runtime,
            zone_id: zone_id.to_owned(),
            ledger_id: ledger_id.to_owned(),
            max_body_bytes,
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

    fn keyring(&self) -> Result<Vec<u8>, String> {
        self.call(MirrorOperation::KeyRing, Vec::new())
            .map_err(|refused| refused.detail)
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

    use permguard_host::composition::MirrorRefusal;
    use permguard_objects::digest::Digest;

    use super::*;

    /// A session answering from a script, keeping every message it carried.
    struct Scripted {
        carried: Arc<Mutex<Vec<MirrorRequest>>>,
        answer: fn(&MirrorRequest) -> Result<Vec<u8>, MirrorRefusal>,
    }

    impl MirrorSession for Scripted {
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

    fn head() -> Digest {
        Digest::compute(b"head")
    }

    fn answer(request: &MirrorRequest) -> Result<Vec<u8>, MirrorRefusal> {
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
                    head: head(),
                    counter: 3,
                    statement: vec![1, 2, 3],
                    ref_digest: Digest::compute(b"ref"),
                }
                .encode()
            }
            MirrorOperation::NegotiatePull => NegotiatePullResponse {
                head: head(),
                counter: 3,
                statement: vec![1, 2, 3],
                missing: vec![head()],
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
            MirrorOperation::KeyRing => return Ok(br#"{"keys":[]}"#.to_vec()),
            MirrorOperation::ListLedgers => ListLedgersAnswer {
                ledgers: Vec::new(),
                complete: true,
            }
            .encode(),
        };
        Ok(encoded.expect("it encodes"))
    }

    fn remote(max_body_bytes: u64) -> (TaskRemote, Arc<Mutex<Vec<MirrorRequest>>>) {
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
            TaskRemote::new(session, handle, "zone-id", "ledger-id", max_body_bytes),
            carried,
        )
    }

    /// WP-7.2a: every read names its ledger by id and travels as its own operation; an absent ref
    /// is an absent ref, and a mirror's session never pushes.
    #[test]
    fn each_read_travels_as_its_operation_and_names_its_ledger() {
        let (remote, carried) = remote(1 << 20);

        let advertised = remote.get_ref("main").expect("read").expect("a ref");
        assert_eq!(
            (advertised.head, advertised.counter),
            (head().to_string(), 3)
        );
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
        assert_eq!(negotiated.missing, vec![head()]);
        let fetched = remote
            .fetch(&FetchObjectsRequest {
                digests: vec![head()],
                accept_compression: None,
                transfer_id: [7; 16],
            })
            .expect("fetched");
        assert_eq!(fetched.objects, vec![b"object".to_vec()]);
        assert_eq!(
            remote.keyring().expect("the ring"),
            br#"{"keys":[]}"#.to_vec()
        );

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
                MirrorOperation::KeyRing,
            ]
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
                    new_head: head(),
                    expected_ref: None,
                    request_id: "r".to_owned(),
                })
                .is_err(),
            "a mirror never pushes"
        );
    }

    /// WP-7.2a: a read exactly as large as the signed task allows a message is sent.
    #[test]
    fn a_read_at_the_task_bound_is_sent() {
        let exact = MirrorRequest {
            operation: MirrorOperation::KeyRing,
            zone: "zone-id".to_owned(),
            ledger: "ledger-id".to_owned(),
            body: Vec::new(),
        }
        .encode()
        .expect("it encodes")
        .len() as u64;
        let (at, carried) = remote(exact);
        at.keyring().expect("at the bound");
        assert_eq!(carried.lock().expect("the log").len(), 1);
        let (below, carried) = remote(exact - 1);
        assert!(below.keyring().is_err(), "one byte past the bound");
        assert!(carried.lock().expect("the log").is_empty());
    }

    /// WP-7.2a: a read larger than the signed task allows a message is never sent.
    #[test]
    fn a_read_beyond_the_task_bound_is_never_sent() {
        let (remote, carried) = remote(16);
        let refused = remote
            .negotiate_pull(&NegotiatePullRequest {
                r#ref: "main".into(),
                at: None,
                have: vec![head(); 4],
                checkpoint: None,
            })
            .expect_err("beyond the bound");
        assert!(refused.contains("the task allows"), "{refused}");
        assert!(
            carried.lock().expect("the log").is_empty(),
            "nothing went out"
        );
    }
}
