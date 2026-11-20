// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! WP-7.2a: a `policy.mirror` task stand-in. Its session decodes each real `MirrorRequest` and
//! answers it from the control plane at `url`, so what this suite drives is the round, the
//! listing, the authority-qualified layout and the pull over a task session; the provider's own
//! handler has its tests in the control plane.

use std::sync::{Arc, Mutex};

use permguard_client::{AnyRemote, TlsOptions};
use permguard_core::BoxFuture;
use permguard_host::composition::{MirrorRefusal, MirrorSession, MirrorTask, MirrorTasks};
pub use permguard_host::membership::record::ProgressResource;
use permguard_mirror::remote::Remote as _;

/// Every progress report a session carried, by task id (WP-7.2d).
pub type Reported = Arc<Mutex<Vec<(String, Vec<ProgressResource>)>>>;
use permguard_notp::{
    FetchObjectsRequest, GetRefRequest, GetRefResponse, ListLedgersAnswer, ListLedgersRequest,
    ListedLedger, MirrorOperation, MirrorRequest, NegotiatePullRequest,
};

/// The tasks a Host holds, the URL that answers each coordinator, and what was asked.
#[derive(Clone)]
pub struct Held {
    pub tasks: Vec<MirrorTask>,
    pub url: String,
    /// The coordinators that refuse every session.
    pub silent: Vec<[u8; 16]>,
    /// Every operation a session carried, by task id.
    pub asked: Arc<Mutex<Vec<(String, MirrorOperation)>>>,
    /// The ledger names a task's listing is cut to, by task id; a task absent lists every one.
    pub only: Vec<(String, Vec<String>)>,
    /// Whether listings say they are not complete.
    pub incomplete: bool,
    /// The tasks whose listings alone say they are not complete.
    pub partial: Vec<String>,
    /// The tasks whose sessions name no pinned ring.
    pub unpinned: Vec<String>,
    /// Every progress report a session carried, by task id (WP-7.2d).
    pub reported: Reported,
    /// How long every read (not a listing) stalls before it is answered.
    pub slow: Option<std::time::Duration>,
}

impl MirrorTasks for Held {
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

    fn mirror_tasks(&self) -> Vec<MirrorTask> {
        self.tasks.clone()
    }

    fn open_mirror<'a>(
        &'a self,
        task: &'a MirrorTask,
    ) -> BoxFuture<'a, Result<Box<dyn MirrorSession>, MirrorRefusal>> {
        let opened: Result<Box<dyn MirrorSession>, MirrorRefusal> =
            if self.silent.contains(&task.coordinator) {
                Err(MirrorRefusal {
                    code: permguard_core::codes::common::UNAVAILABLE.to_owned(),
                    reason: "the coordinator did not answer".to_owned(),
                })
            } else {
                Ok(Box::new(Session {
                    url: self.url.clone(),
                    task: task.task_id.clone(),
                    asked: Arc::clone(&self.asked),
                    only: self
                        .only
                        .iter()
                        .find(|(id, _)| *id == task.task_id)
                        .map(|(_, names)| names.clone()),
                    incomplete: self.incomplete || self.partial.contains(&task.task_id),
                    unpinned: self.unpinned.contains(&task.task_id),
                    reported: Arc::clone(&self.reported),
                    slow: self.slow,
                }))
            };
        Box::pin(std::future::ready(opened))
    }
}

struct Session {
    url: String,
    task: String,
    asked: Arc<Mutex<Vec<(String, MirrorOperation)>>>,
    only: Option<Vec<String>>,
    incomplete: bool,
    unpinned: bool,
    reported: Reported,
    slow: Option<std::time::Duration>,
}

impl MirrorSession for Session {
    fn report(
        &mut self,
        resources: Vec<ProgressResource>,
    ) -> BoxFuture<'_, Result<(), MirrorRefusal>> {
        self.reported
            .lock()
            .expect("the log")
            .push((self.task.clone(), resources));
        Box::pin(std::future::ready(Ok(())))
    }

    fn ring(&self) -> Option<permguard_host::composition::PinnedRing> {
        // The ledgers of these tests hold no history yet: nothing is verified under it.
        (!self.unpinned).then(|| permguard_host::composition::PinnedRing {
            epoch: 1,
            key_set_digest: [3; 32],
            binding: b"binding".to_vec(),
            keys: Vec::new(),
        })
    }

    fn call(&mut self, body: Vec<u8>) -> BoxFuture<'_, Result<Vec<u8>, MirrorRefusal>> {
        let url = self.url.clone();
        let task = self.task.clone();
        let asked = Arc::clone(&self.asked);
        let only = self.only.clone();
        let incomplete = self.incomplete;
        let stall = self.slow.filter(|_| {
            MirrorRequest::decode(&body)
                .is_ok_and(|request| request.operation != MirrorOperation::ListLedgers)
        });
        Box::pin(async move {
            if let Some(stall) = stall {
                tokio::time::sleep(stall).await;
            }
            tokio::task::spawn_blocking(move || {
                answer(&url, &task, &asked, &body, only.as_deref(), incomplete)
            })
            .await
            .expect("the answer is computed")
        })
    }
}

fn refused(code: &str, reason: String) -> MirrorRefusal {
    MirrorRefusal {
        code: code.to_owned(),
        reason,
    }
}

fn answer(
    url: &str,
    task: &str,
    asked: &Mutex<Vec<(String, MirrorOperation)>>,
    body: &[u8],
    only: Option<&[String]>,
    incomplete: bool,
) -> Result<Vec<u8>, MirrorRefusal> {
    let request =
        MirrorRequest::decode(body).map_err(|error| refused("body_rejected", error.to_string()))?;
    asked
        .lock()
        .expect("the log")
        .push((task.to_owned(), request.operation));
    let failed = |error: String| refused("notp_failed", error);
    if request.operation == MirrorOperation::ListLedgers {
        let catalog = permguard_client::catalog::client(
            url,
            &TlsOptions::default(),
            Box::new(permguard_client::narrate::Silent),
        )
        .map_err(failed)?;
        let mut ledgers = Vec::new();
        // Every ledger the catalog holds, by ids, whatever the cut: a mirrored ledger it no
        // longer holds was deleted (BUG-0192).
        let mut existing = std::collections::BTreeSet::new();
        for zone in catalog
            .list_zones(None, None)
            .map_err(|f| failed(f.detail))?
        {
            for ledger in catalog
                .list_ledgers(&zone.id, None, None)
                .map_err(|f| failed(f.detail))?
            {
                existing.insert((zone.id.clone(), ledger.id.clone()));
                if only.is_some_and(|names| !names.contains(&ledger.name)) {
                    continue;
                }
                ledgers.push(ListedLedger {
                    zone_id: zone.id.clone(),
                    zone_name: zone.name.clone(),
                    ledger_id: ledger.id,
                    ledger_name: ledger.name,
                });
            }
        }
        ledgers.sort_by(|left, right| {
            (&left.zone_id, &left.ledger_id).cmp(&(&right.zone_id, &right.ledger_id))
        });
        let deleted = (!request.body.is_empty())
            .then(|| ListLedgersRequest::decode(&request.body))
            .transpose()
            .map_err(|error| refused("body_rejected", error.to_string()))?
            .map(|asked| {
                asked
                    .held
                    .into_iter()
                    .filter(|ids| !existing.contains(&(ids.zone_id.clone(), ids.ledger_id.clone())))
                    .collect()
            });
        return ListLedgersAnswer {
            ledgers,
            complete: !incomplete,
            deleted,
        }
        .encode()
        .map_err(|error| failed(error.to_string()));
    }
    let remote = AnyRemote::connect(
        url,
        &TlsOptions::default(),
        Box::new(permguard_client::narrate::Silent),
    )
    .map_err(failed)?;
    remote.bind(&request.zone, &request.ledger);
    // Told by the class the remote met, not by the wording of its sentence: the coordinator's
    // provider answers a ledger with no history `not_found`.
    let not_found = |error: String| match remote.take_failure() {
        Some(failure) if failure.class == "not_found" => {
            refused(permguard_core::codes::common::NOT_FOUND, error)
        }
        _ => failed(error),
    };
    match request.operation {
        MirrorOperation::KeyRing => remote.keyring().map_err(failed),
        MirrorOperation::GetRef => {
            let asked =
                GetRefRequest::decode(&request.body).map_err(|error| failed(error.to_string()))?;
            let held = remote
                .get_ref(&asked.r#ref)
                .map_err(failed)?
                .ok_or_else(|| {
                    refused(permguard_core::codes::common::NOT_FOUND, "no ref".into())
                })?;
            GetRefResponse {
                head: permguard_objects::digest::Digest::parse(&held.head)
                    .map_err(|_| failed("a head".into()))?,
                counter: held.counter,
                statement: held.statement,
                ref_digest: permguard_objects::digest::Digest::parse(&held.ref_digest)
                    .map_err(|_| failed("a digest".into()))?,
            }
            .encode()
            .map_err(|error| failed(error.to_string()))
        }
        MirrorOperation::NegotiatePull => {
            let asked = NegotiatePullRequest::decode(&request.body)
                .map_err(|error| failed(error.to_string()))?;
            remote
                .negotiate_pull(&asked)
                .map_err(not_found)?
                .encode()
                .map_err(|error| failed(error.to_string()))
        }
        MirrorOperation::FetchObjects => {
            let asked = FetchObjectsRequest::decode(&request.body)
                .map_err(|error| failed(error.to_string()))?;
            remote
                .fetch(&asked)
                .map_err(failed)?
                .encode()
                .map_err(|error| failed(error.to_string()))
        }
        MirrorOperation::ListLedgers => unreachable!("answered above"),
    }
}

/// One `policy.mirror` task of `coordinator`.
pub fn task(coordinator: [u8; 16], membership: u8, id: &str, required: bool) -> MirrorTask {
    MirrorTask {
        membership_id: [membership; 16],
        task_id: id.to_owned(),
        coordinator,
        revision: 1,
        resource: "plane/control".to_owned(),
        required,
        max_body_bytes: 1 << 24,
    }
}
