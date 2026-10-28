// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `WatchRefs` on the member side (WP-7.2c, F-19, `3-data-plane/3-data-plane-mirrors-notp.md`,
//! change signal).
//!
//! ```text
//! every task this plane follows ─▶ a watch the member opens, from the counter each mirror holds
//!   hint      ─▶ wake the round now: the ordinary negotiate, verify, checkpoint runs
//!   heartbeat ─▶ nothing
//!   lost, overflowed, fenced, silent past its bound ─▶ wake the round now, then watch again
//! ```
//!
//! A hint carries no policy and grants nothing: it only schedules the ordinary round, which
//! verifies what it pulls as it always does. With a watch, revocation reaches this plane in the
//! time a round takes to verify and checkpoint; without one, in the interval plus its jitter.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use permguard_host::composition::{MirrorTask, MirrorTasks};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use super::layout;
use super::source::TaskSelections;

const COMPONENT: &str = "data-plane";

/// What every task's watch reads: the tasks, the narrowing, where the mirrors are, what to wake.
pub struct Watching {
    pub tasks: Arc<dyn MirrorTasks>,
    pub selections: TaskSelections,
    pub root: PathBuf,
    pub wake: Arc<Notify>,
    /// How long a watch that could not be opened, or that ended, waits before it opens again.
    pub retry: Duration,
}

/// The counter each mirror of `task` holds, by `zone_id/ledger_id/ref`: where the task's watch
/// starts from.
pub fn positions(root: &std::path::Path, task: &MirrorTask) -> Vec<(String, u64)> {
    let authority = layout::authority_name(&task.coordinator);
    let label = super::round::task_label(task);
    let Ok(held) = layout::on_disk(root) else {
        return Vec::new();
    };
    held.into_iter()
        .filter(|mirror| mirror.authority.as_deref() == Some(authority.as_str()))
        .filter_map(|mirror| {
            let path = mirror.path(root);
            let identity = crate::authz::store::identity_of(&path)?;
            if identity.task.as_deref() != Some(label.as_str()) {
                return None;
            }
            let store = permguard_control_client::FsStore::new(&path);
            let checkpoint =
                permguard_control_client::checkpoint::read(&store, "refs/main").ok()??;
            Some((
                format!("{}/{}/main", mirror.zone_id, mirror.ledger_id),
                checkpoint.counter,
            ))
        })
        .collect()
}

/// Watches one task until aborted: each hint wakes the round; a watch that ends wakes it too, then
/// opens again after `retry`.
async fn watch_one(watching: Arc<Watching>, task: MirrorTask) {
    loop {
        let positions = positions(&watching.root, &task);
        match watching.tasks.watch_mirror(&task, positions).await {
            Ok(mut watch) => loop {
                match watch.next().await {
                    Ok(hints) if hints.is_empty() => {}
                    Ok(hints) => {
                        debug!(
                            event.name = "sync.hinted",
                            component = COMPONENT,
                            task = task.task_id.as_str(),
                            refs = hints.len(),
                            "a ref moved: the round runs now"
                        );
                        watching.wake.notify_one();
                    }
                    Err(refusal) => {
                        // Lost, overflowed, fenced or silent: what moved meanwhile is unknown, so
                        // the ordinary round runs now, and polling covers the gap until the watch
                        // is open again.
                        warn!(
                            event.name = "sync.watch_lost",
                            component = COMPONENT,
                            task = task.task_id.as_str(),
                            error = %refusal,
                            "the task's watch ended: the round runs now, then the watch reopens"
                        );
                        watching.wake.notify_one();
                        break;
                    }
                }
            },
            Err(refusal) => debug!(
                event.name = "sync.watch_unopened",
                component = COMPONENT,
                task = task.task_id.as_str(),
                error = %refusal,
                "the task's watch did not open: polling covers it"
            ),
        }
        tokio::time::sleep(watching.retry).await;
    }
}

/// Keeps one watch per followed task, reconciled every `retry`: a task that appears is watched,
/// one that goes is no longer. Ends when `stop` is dropped or set.
pub async fn run(watching: Arc<Watching>, mut stop: tokio::sync::watch::Receiver<bool>) {
    let mut running: BTreeMap<String, JoinHandle<()>> = BTreeMap::new();
    loop {
        let followed: BTreeMap<String, MirrorTask> = watching
            .tasks
            .mirror_tasks()
            .into_iter()
            .filter(|task| {
                watching
                    .selections
                    .follows_task(&task.membership_id, &task.task_id)
            })
            .map(|task| (super::round::task_label(&task), task))
            .collect();
        running.retain(|label, handle| {
            let keep = followed.contains_key(label) && !handle.is_finished();
            if !keep {
                handle.abort();
            }
            keep
        });
        for (label, task) in followed {
            running
                .entry(label)
                .or_insert_with(|| tokio::spawn(watch_one(Arc::clone(&watching), task)));
        }
        tokio::select! {
            _ = tokio::time::sleep(watching.retry) => {}
            _ = stop.changed() => break,
        }
    }
    for handle in running.into_values() {
        handle.abort();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use permguard_core::BoxFuture;
    use permguard_host::composition::{MirrorRefusal, MirrorSession, MirrorWatch};

    use super::*;

    /// What a scripted watch says, one step per `next`.
    #[derive(Debug, Clone)]
    enum Step {
        Hint,
        Heartbeat,
        Lost,
        /// Waits until the test opens the gate.
        Gate(Arc<Notify>),
    }

    struct Scripted {
        steps: VecDeque<Step>,
        dropped: Arc<AtomicBool>,
    }

    /// A watch that is let go says so, for a test that it was.
    impl Drop for Scripted {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl MirrorWatch for Scripted {
        fn next(&mut self) -> BoxFuture<'_, Result<Vec<(String, u64)>, MirrorRefusal>> {
            let mut step = self.steps.pop_front();
            Box::pin(async move {
                if let Some(Step::Gate(gate)) = &step {
                    gate.notified().await;
                    step = Some(Step::Heartbeat);
                }
                match step {
                    Some(Step::Hint) => Ok(vec![("zone/ledger/main".to_owned(), 9)]),
                    Some(Step::Heartbeat) => Ok(Vec::new()),
                    Some(Step::Lost) => Err(MirrorRefusal {
                        code: "watch_overflow".to_owned(),
                        reason: "too many keys".to_owned(),
                    }),
                    // The script is over: the watch waits, as a quiet one does.
                    None | Some(Step::Gate(_)) => std::future::pending().await,
                }
            })
        }
    }

    /// One task whose watches follow `scripts`, one script per opening, the positions each
    /// opening was given kept.
    struct Tasks {
        task: Mutex<Option<MirrorTask>>,
        scripts: Mutex<VecDeque<Vec<Step>>>,
        opened: Mutex<Vec<Vec<(String, u64)>>>,
        dropped: Arc<AtomicBool>,
    }

    impl MirrorTasks for Tasks {
        fn mirror_tasks(&self) -> Vec<MirrorTask> {
            self.task
                .lock()
                .expect("the task")
                .iter()
                .cloned()
                .collect()
        }

        fn open_mirror<'a>(
            &'a self,
            _task: &'a MirrorTask,
        ) -> BoxFuture<'a, Result<Box<dyn MirrorSession>, MirrorRefusal>> {
            Box::pin(std::future::ready(Err(MirrorRefusal {
                code: "unavailable".to_owned(),
                reason: "a watch test opens no session".to_owned(),
            })))
        }

        fn watch_mirror<'a>(
            &'a self,
            _task: &'a MirrorTask,
            positions: Vec<(String, u64)>,
        ) -> BoxFuture<'a, Result<Box<dyn MirrorWatch>, MirrorRefusal>> {
            self.opened.lock().expect("the log").push(positions);
            let script = self.scripts.lock().expect("the scripts").pop_front();
            Box::pin(std::future::ready(Ok(Box::new(Scripted {
                steps: script.unwrap_or_default().into(),
                dropped: Arc::clone(&self.dropped),
            })
                as Box<dyn MirrorWatch>)))
        }
    }

    fn task() -> MirrorTask {
        MirrorTask {
            membership_id: [1; 16],
            task_id: "mirror".into(),
            coordinator: [0x11; 16],
            revision: 1,
            resource: "plane/control".into(),
            required: true,
            max_body_bytes: 1 << 20,
        }
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pg-mirror-hints-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory");
        dir
    }

    /// A mirror of `task` at `counter`, one of another task beside it, and one under another
    /// authority that names the same task.
    fn held(root: &std::path::Path, counter: u64) {
        let own = layout::authority_name(&task().coordinator);
        for (authority, ledger, label) in [
            (
                own.clone(),
                "ledger-a",
                super::super::round::task_label(&task()),
            ),
            (own.clone(), "ledger-b", "another/task".to_owned()),
            (
                layout::authority_name(&[0x22; 16]),
                "ledger-c",
                super::super::round::task_label(&task()),
            ),
        ] {
            let path = root.join(&authority).join("zone-z").join(ledger);
            std::fs::create_dir_all(&path).expect("the mirror");
            crate::authz::store::record(
                &path,
                &crate::authz::store::Identity {
                    zone_id: "zone-z".into(),
                    zone_name: "acme".into(),
                    ledger_id: ledger.into(),
                    ledger_name: ledger.into(),
                    server: format!("host:{authority}"),
                    authority: Some(authority.clone()),
                    task: Some(label),
                },
            )
            .expect("the identity");
            permguard_control_client::checkpoint::write(
                &permguard_control_client::FsStore::new(&path),
                "refs/main",
                &permguard_control_client::checkpoint::Checkpoint {
                    head: permguard_objects::digest::Digest::compute(b"head").to_string(),
                    counter,
                    ..Default::default()
                },
            )
            .expect("the checkpoint");
        }
    }

    /// F-19: a task's watch starts from the counter each of its own mirrors holds; a hint wakes
    /// the round, a heartbeat does not; a watch that ends wakes the round and opens again from
    /// where the mirrors are then.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_hint_or_a_lost_watch_wakes_the_round_and_a_heartbeat_does_not() {
        let root = scratch("wake");
        held(&root, 4);
        // The loss waits for the test, so each wake is observed apart: a `Notify` keeps one
        // permit, and two wakes before the test waits would be one.
        let gate = Arc::new(Notify::new());
        let tasks = Arc::new(Tasks {
            task: Mutex::new(Some(task())),
            scripts: Mutex::new(VecDeque::from([
                vec![
                    Step::Heartbeat,
                    Step::Hint,
                    Step::Heartbeat,
                    Step::Gate(Arc::clone(&gate)),
                    Step::Lost,
                ],
                Vec::new(),
            ])),
            opened: Mutex::new(Vec::new()),
            dropped: Arc::new(AtomicBool::new(false)),
        });
        let wake = Arc::new(Notify::new());
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let watching = tokio::spawn(run(
            Arc::new(Watching {
                tasks: Arc::clone(&tasks) as Arc<dyn MirrorTasks>,
                selections: TaskSelections::default(),
                root: root.clone(),
                wake: Arc::clone(&wake),
                retry: Duration::from_millis(50),
            }),
            stopped,
        ));

        let woken = |what: &'static str| {
            let wake = Arc::clone(&wake);
            async move {
                tokio::time::timeout(Duration::from_secs(5), wake.notified())
                    .await
                    .unwrap_or_else(|_| panic!("{what} wakes the round"));
            }
        };
        woken("the hint").await;
        // The watch opens again after its loss, from the mirrors as they are then.
        held(&root, 9);
        gate.notify_one();
        woken("the lost watch").await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while tasks.opened.lock().expect("the log").len() < 2 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the watch reopens");
        let opened = tasks.opened.lock().expect("the log").clone();
        assert_eq!(
            opened[0],
            vec![("zone-z/ledger-a/main".to_owned(), 4)],
            "its own mirror's position, not another task's nor another authority's"
        );
        assert_eq!(opened[1], vec![("zone-z/ledger-a/main".to_owned(), 9)]);
        // Two wakes, never more: the heartbeats woke nothing.
        assert!(
            tokio::time::timeout(Duration::from_millis(200), wake.notified())
                .await
                .is_err(),
            "a heartbeat wakes nothing"
        );

        let _ = stop.send(true);
        watching.await.expect("the watching ends");
    }

    /// A task no longer held is no longer watched.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_task_that_goes_is_no_longer_watched() {
        let root = scratch("gone");
        let tasks = Arc::new(Tasks {
            task: Mutex::new(Some(task())),
            scripts: Mutex::new(VecDeque::new()),
            opened: Mutex::new(Vec::new()),
            dropped: Arc::new(AtomicBool::new(false)),
        });
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let watching = tokio::spawn(run(
            Arc::new(Watching {
                tasks: Arc::clone(&tasks) as Arc<dyn MirrorTasks>,
                selections: TaskSelections::default(),
                root,
                wake: Arc::new(Notify::new()),
                retry: Duration::from_millis(20),
            }),
            stopped,
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            tasks.opened.lock().expect("the log").len(),
            1,
            "watched once"
        );
        assert!(
            !tasks.dropped.load(Ordering::SeqCst),
            "a quiet watch is held"
        );
        *tasks.task.lock().expect("the task") = None;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            tasks.dropped.load(Ordering::SeqCst),
            "the watch of a task that went is let go"
        );
        let opened = tasks.opened.lock().expect("the log").len();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            tasks.opened.lock().expect("the log").len(),
            opened,
            "a task that went is never watched again"
        );
        let _ = stop.send(true);
        watching.await.expect("the watching ends");
    }
}
