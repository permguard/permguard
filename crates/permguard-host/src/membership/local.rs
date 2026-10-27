// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The local `policy.mirror` task (WP-7.7): how a Host that runs both Planes mirrors its own
//! Control Plane once configured URLs are gone.
//!
//! ```text
//! mirror_tasks ─▶ the membership tasks, and one local task
//!                   coordinator and authority: this Host; resource: `plane/control`, read whole
//! open_mirror(local) ─▶ a session that calls the Control Plane's `policy.mirror` handler
//!                       in-process: no network, no URL, no TLS
//! ring() ─▶ this Host's own `control.attest` statement and its identity-signed binding
//! ```
//!
//! Everything after the session is the membership task's path: the same pull, the head statements
//! verified under the pinned set and naming their authority, the same journal and readiness. The
//! local task has no watch: the round polls it. A membership task is passed through untouched.

use std::sync::Arc;

use permguard_core::BoxFuture;
use permguard_core::authz::{Resource, Selector};

use crate::composition::{
    MirrorRefusal, MirrorSession, MirrorTask, MirrorTasks, MirrorWatch, PinnedRing,
};
use crate::keys::ring::Ring;
use crate::membership::record::{Limits, ProgressResource, TaskType};
use crate::membership::task::{TaskContext, TaskHandler};

/// The membership id the local task carries: the nil UUID, which no membership is ever minted
/// with.
pub const LOCAL_MEMBERSHIP: [u8; 16] = [0; 16];
/// The local task's id.
pub const LOCAL_TASK: &str = "local";
/// The largest message a local session carries: the bound a membership's `policy.mirror` task
/// is usually signed with.
pub const LOCAL_MAX_BODY_BYTES: u64 = 1024 * 1024;

/// Whether `task` is the local task.
pub fn is_local(task: &MirrorTask) -> bool {
    task.membership_id == LOCAL_MEMBERSHIP && task.task_id == LOCAL_TASK
}

/// The membership tasks, when this Host holds any, and the local task of its own Control Plane.
pub struct LocalMirrors {
    members: Option<Arc<dyn MirrorTasks>>,
    host_id: [u8; 16],
    handler: Arc<dyn TaskHandler>,
    control_attest: Arc<Ring>,
}

impl LocalMirrors {
    /// The local task of the Host `host_id`, served by `handler` (the Control Plane's
    /// `policy.mirror` handler, or the slot it fills) and verified under `control_attest`, beside
    /// `members`' tasks.
    pub fn new(
        members: Option<Arc<dyn MirrorTasks>>,
        host_id: [u8; 16],
        handler: Arc<dyn TaskHandler>,
        control_attest: Arc<Ring>,
    ) -> Self {
        Self {
            members,
            host_id,
            handler,
            control_attest,
        }
    }

    fn task(&self) -> MirrorTask {
        MirrorTask {
            membership_id: LOCAL_MEMBERSHIP,
            task_id: LOCAL_TASK.to_owned(),
            coordinator: self.host_id,
            revision: 0,
            resource: Resource::plane("control").to_string(),
            required: true,
            max_body_bytes: LOCAL_MAX_BODY_BYTES,
        }
    }

    /// This Host's `control.attest` set as a pin: its epoch, the digest of its keys, its binding
    /// and its keys. `None` while the ring holds no key or no binding of its epoch.
    fn pinned(&self) -> Option<PinnedRing> {
        let statement = super::statement_of(&self.control_attest).ok()?;
        Some(PinnedRing {
            epoch: statement.epoch,
            key_set_digest: super::keys_digest(&statement).ok()?,
            binding: statement.binding.clone(),
            keys: statement.keys,
        })
    }
}

impl MirrorTasks for LocalMirrors {
    fn mirror_tasks(&self) -> Vec<MirrorTask> {
        // A membership task carrying the local task's identity is dropped, whatever the membership
        // side handed over: only this Host's own task is ever routed in-process.
        let mut tasks: Vec<MirrorTask> = self
            .members
            .as_ref()
            .map(|members| members.mirror_tasks())
            .unwrap_or_default()
            .into_iter()
            .filter(|task| task.membership_id != LOCAL_MEMBERSHIP)
            .collect();
        tasks.push(self.task());
        tasks
    }

    fn open_mirror<'a>(
        &'a self,
        task: &'a MirrorTask,
    ) -> BoxFuture<'a, Result<Box<dyn MirrorSession>, MirrorRefusal>> {
        if is_local(task) {
            let session: Box<dyn MirrorSession> = Box::new(LocalSession {
                host_id: self.host_id,
                handler: Arc::clone(&self.handler),
                ring: self.pinned(),
                calls: 0,
            });
            return Box::pin(async move { Ok(session) });
        }
        match &self.members {
            Some(members) => members.open_mirror(task),
            None => Box::pin(async move { Err(no_membership(task)) }),
        }
    }

    fn watch_mirror<'a>(
        &'a self,
        task: &'a MirrorTask,
        positions: Vec<(String, u64)>,
    ) -> BoxFuture<'a, Result<Box<dyn MirrorWatch>, MirrorRefusal>> {
        if is_local(task) {
            return Box::pin(async move {
                Err(MirrorRefusal {
                    code: permguard_core::codes::host::NOT_SERVED_YET.to_owned(),
                    reason: "the local task has no watch: its round polls".to_owned(),
                })
            });
        }
        match &self.members {
            Some(members) => members.watch_mirror(task, positions),
            None => Box::pin(async move { Err(no_membership(task)) }),
        }
    }
}

fn no_membership(task: &MirrorTask) -> MirrorRefusal {
    MirrorRefusal {
        code: permguard_core::codes::host::MEMBERSHIP_UNKNOWN.to_owned(),
        reason: format!(
            "this Host holds no membership for the task `{}`",
            task.task_id
        ),
    }
}

/// A session of the local task: each message handed to the Control Plane's handler in-process,
/// under the task's context.
struct LocalSession {
    host_id: [u8; 16],
    handler: Arc<dyn TaskHandler>,
    ring: Option<PinnedRing>,
    calls: u64,
}

impl MirrorSession for LocalSession {
    fn call(&mut self, body: Vec<u8>) -> BoxFuture<'_, Result<Vec<u8>, MirrorRefusal>> {
        self.calls += 1;
        let context = TaskContext {
            membership_id: LOCAL_MEMBERSHIP,
            task_id: LOCAL_TASK.to_owned(),
            task_type: TaskType::PolicyMirror,
            version: 1,
            epoch: 0,
            resource: Resource::plane("control").to_string(),
            selector: Selector::under(Resource::plane("control")),
            member: self.host_id,
            request_id: format!("local-{}", self.calls),
            limits: Limits {
                max_body_bytes: LOCAL_MAX_BODY_BYTES,
                max_concurrency: 1,
                max_rate_per_minute: u64::MAX,
                max_batch_records: 1000,
                retention_seconds: 0,
            },
            channel_binding: [0; 32],
        };
        // The handler reads the catalog where it is called: a ledger's reads from the round's
        // blocking pool (`TaskRemote`), the listing on the round's task — one bounded read, at
        // most `MAX_LISTED_LEDGERS` entries, as a membership's listing is.
        let answer = self
            .handler
            .handle(&context, &body)
            .map_err(|refusal| MirrorRefusal {
                code: refusal.code.to_owned(),
                reason: refusal.reason,
            });
        Box::pin(async move { answer })
    }

    fn ring(&self) -> Option<PinnedRing> {
        self.ring.clone()
    }

    /// The local task's progress is this Host's own: nobody to report it to.
    fn report(
        &mut self,
        _resources: Vec<ProgressResource>,
    ) -> BoxFuture<'_, Result<(), MirrorRefusal>> {
        Box::pin(async { Ok(()) })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::Mutex;
    use std::time::Duration;

    use permguard_core::assurance::AssuranceProfile;

    use super::*;
    use crate::identity::{self, Identity, Suite};
    use crate::keys::ring::{CONTROL_ATTEST, Policy};
    use crate::session::Refusal;
    use crate::storage::volume::Volume;
    use crate::time::TimeGuard;

    /// A handler that records the context of every call and answers with the body it got.
    #[derive(Default)]
    struct Echo {
        seen: Mutex<Vec<TaskContext>>,
    }

    impl TaskHandler for Echo {
        fn handle(&self, context: &TaskContext, body: &[u8]) -> Result<Vec<u8>, Refusal> {
            self.seen.lock().expect("the log").push(context.clone());
            if body == b"refuse" {
                return Err(Refusal {
                    code: permguard_core::codes::common::NOT_FOUND,
                    reason: "asked to".to_owned(),
                });
            }
            Ok(body.to_vec())
        }
    }

    /// A membership side holding one task, whose sessions this suite never opens.
    struct Members(MirrorTask);

    impl MirrorTasks for Members {
        fn mirror_tasks(&self) -> Vec<MirrorTask> {
            vec![self.0.clone()]
        }

        fn open_mirror<'a>(
            &'a self,
            _task: &'a MirrorTask,
        ) -> BoxFuture<'a, Result<Box<dyn MirrorSession>, MirrorRefusal>> {
            Box::pin(async {
                Err(MirrorRefusal {
                    code: "membership".to_owned(),
                    reason: "the membership's own session".to_owned(),
                })
            })
        }

        fn watch_mirror<'a>(
            &'a self,
            _task: &'a MirrorTask,
            _positions: Vec<(String, u64)>,
        ) -> BoxFuture<'a, Result<Box<dyn MirrorWatch>, MirrorRefusal>> {
            Box::pin(async {
                Err(MirrorRefusal {
                    code: "membership".to_owned(),
                    reason: "the membership's own watch".to_owned(),
                })
            })
        }
    }

    /// A Host's identity and its `control.attest` ring, bound and holding its first key.
    fn host(tag: &str) -> (Volume, Arc<Identity>, Arc<Ring>) {
        let root = std::env::temp_dir().join(format!(
            "permguard-host-local-mirror-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let time = Arc::new(TimeGuard::system(Duration::from_secs(30)));
        let identity = Arc::new(
            Identity::provision(
                &volume,
                Arc::new(crate::keys::FileKeyProvider::new(
                    identity::directories(&volume).expect("the identity").1,
                )),
                Suite::Ed25519Sha256V1,
                crate::authz::store::now(),
                crate::authz::store::now() * 1000,
            )
            .expect("provisioned"),
        );
        let ring = Arc::new(
            Ring::open(
                &volume,
                CONTROL_ATTEST,
                Suite::Ed25519Sha256V1,
                Policy {
                    publish_ahead: Duration::from_secs(600),
                    rotate_every: Duration::from_secs(3600),
                    retain: Duration::from_secs(7200),
                },
                time,
            )
            .expect("the ring opens")
            .with_binder(identity.clone()),
        );
        ring.maintain_now().expect("the first key");
        (volume, identity, ring)
    }

    fn local_of(tasks: &[MirrorTask]) -> MirrorTask {
        tasks
            .iter()
            .find(|task| is_local(task))
            .expect("the local task")
            .clone()
    }

    /// WP-7.7: the local task stands beside the membership tasks, coordinated and authorized by
    /// this Host, reading its whole Control Plane; a membership task is passed through untouched.
    #[tokio::test]
    async fn the_local_task_stands_beside_the_membership_tasks() {
        let (_volume, identity, ring) = host("tasks");
        let membership = MirrorTask {
            membership_id: [7; 16],
            task_id: "policy-mirror".to_owned(),
            coordinator: [9; 16],
            revision: 3,
            resource: "plane/control/zone/acme/*".to_owned(),
            required: false,
            max_body_bytes: 1024,
        };
        let mirrors = LocalMirrors::new(
            Some(Arc::new(Members(membership.clone()))),
            identity.host_id(),
            Arc::new(Echo::default()),
            ring,
        );
        let tasks = mirrors.mirror_tasks();
        assert_eq!(tasks.len(), 2);
        assert!(tasks.contains(&membership));
        let local = local_of(&tasks);
        assert_eq!(local.coordinator, identity.host_id());
        assert_eq!(local.resource, "plane/control");
        assert!(local.required, "a Host waits for its own Control Plane");
        assert!(!is_local(&membership));

        // The membership's task opens and watches on the membership side.
        let refused = mirrors
            .open_mirror(&membership)
            .await
            .err()
            .expect("the membership side answers");
        assert_eq!(refused.code, "membership");
        let refused = mirrors
            .watch_mirror(&membership, Vec::new())
            .await
            .err()
            .expect("the membership side answers");
        assert_eq!(refused.code, "membership");

        // A membership task carrying the local task's identity is never passed off as local.
        let forged = MirrorTask {
            membership_id: LOCAL_MEMBERSHIP,
            task_id: LOCAL_TASK.to_owned(),
            coordinator: [9; 16],
            revision: 1,
            resource: "plane/control".to_owned(),
            required: true,
            max_body_bytes: 1024,
        };
        let guarded = LocalMirrors::new(
            Some(Arc::new(Members(forged))),
            identity.host_id(),
            Arc::new(Echo::default()),
            {
                let (_, _, ring) = host("tasks-forged");
                ring
            },
        );
        let tasks = guarded.mirror_tasks();
        assert_eq!(tasks.len(), 1, "only this Host's own local task");
        assert_eq!(tasks[0].coordinator, identity.host_id());

        // Without memberships the local task is the only one, and no other opens.
        let alone = LocalMirrors::new(None, identity.host_id(), Arc::new(Echo::default()), {
            let (_, _, ring) = host("tasks-alone");
            ring
        });
        assert_eq!(alone.mirror_tasks().len(), 1);
        let refused = alone
            .open_mirror(&membership)
            .await
            .err()
            .expect("no membership answers it");
        assert_eq!(
            refused.code,
            permguard_core::codes::host::MEMBERSHIP_UNKNOWN
        );
    }

    /// WP-7.7: a local session hands each message to the Control Plane's handler in-process, under
    /// the local task's context reading the whole Control Plane, and passes its refusal back; it
    /// pins this Host's own `control.attest` set, binding included; it reports to nobody and has
    /// no watch.
    #[tokio::test]
    async fn a_local_session_calls_the_handler_in_process_under_the_hosts_own_ring() {
        let (_volume, identity, ring) = host("session");
        let echo = Arc::new(Echo::default());
        let mirrors = LocalMirrors::new(
            None,
            identity.host_id(),
            Arc::clone(&echo) as Arc<dyn TaskHandler>,
            Arc::clone(&ring),
        );
        let task = local_of(&mirrors.mirror_tasks());
        let mut session = mirrors.open_mirror(&task).await.expect("opens");

        assert_eq!(
            session.call(b"hello".to_vec()).await.expect("answered"),
            b"hello"
        );
        let refused = session.call(b"refuse".to_vec()).await.expect_err("refused");
        assert_eq!(refused.code, permguard_core::codes::common::NOT_FOUND);
        let seen = echo.seen.lock().expect("the log").clone();
        assert_eq!(seen.len(), 2);
        let context = &seen[0];
        assert_eq!(context.membership_id, LOCAL_MEMBERSHIP);
        assert_eq!(context.task_id, LOCAL_TASK);
        assert_eq!(context.task_type, TaskType::PolicyMirror);
        assert_eq!(context.member, identity.host_id());
        assert_eq!(context.resource, "plane/control");
        assert!(
            context.selector.covers_descendants(),
            "the whole Control Plane"
        );
        assert_ne!(seen[0].request_id, seen[1].request_id);

        let statement = crate::membership::statement_of(&ring).expect("the statement");
        let pinned = session.ring().expect("the Host's own set");
        assert_eq!(pinned.epoch, statement.epoch);
        assert_eq!(pinned.binding, statement.binding);
        assert_eq!(pinned.keys, statement.keys);
        assert_eq!(
            pinned.key_set_digest,
            crate::membership::keys_digest(&statement).expect("digested")
        );

        session
            .report(Vec::new())
            .await
            .expect("nobody to report to");
        let refused = mirrors
            .watch_mirror(&task, Vec::new())
            .await
            .err()
            .expect("no watch");
        assert_eq!(refused.code, permguard_core::codes::host::NOT_SERVED_YET);
    }
}
