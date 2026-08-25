// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Retention: how long decision records are kept, and what leaving looks like.
//!
//! # Why this is not garbage collection
//!
//! The object collector reclaims what nothing references — a storage
//! optimisation. This removes records that are still perfectly referenced,
//! because keeping them any longer is the wrong answer to a different
//! question. A decision log that never forgets is a data-protection liability,
//! and one that forgets quietly makes a consumer report a clean run it did not
//! have. So records leave on a schedule, and a reader that had fallen behind
//! is told exactly that when it comes back — `offset_expired`, with the oldest
//! offset still available.
//!
//! # What is removed, and what is never
//!
//! Whole **segments**, once every record in them is older than the retention
//! window. Never part of one: a segment is the unit an offset names and a seal
//! attests, and removing records from inside one would leave a file whose seal
//! no longer describes it — indistinguishable, to a later auditor, from
//! tampering.
//!
//! The stream's `STATE`, its `EPOCHS.jsonl`, the batch envelopes and the
//! archived verification keys are **never** removed by retention. They are
//! small, and they are what lets whoever holds an exported segment still check
//! it years later.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context as _, Result};

/// What one sweep did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Swept {
    /// How many segments left.
    pub removed: usize,
    /// How many bytes that freed.
    pub reclaimed: u64,
    /// How many segments are still held.
    pub retained: usize,
}

/// Removes every segment whose records are all older than `keep`.
///
/// The modification time of a segment is the moment its **last** record was
/// appended, so a segment is only old when everything in it is.
pub fn sweep_once(root: &Path, keep: Duration) -> Result<Swept> {
    let mut swept = Swept::default();
    let now = SystemTime::now();

    for scope in scopes(root)? {
        for entry in fs::read_dir(&scope).into_iter().flatten().flatten() {
            let path = entry.path();
            if !is_segment(&path) {
                continue;
            }
            let metadata = fs::metadata(&path).context("measuring a segment")?;
            let age = metadata
                .modified()
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .unwrap_or_default();
            if age < keep {
                swept.retained += 1;
                continue;
            }
            let bytes = metadata.len();
            fs::remove_file(&path).context("removing a segment")?;
            swept.removed += 1;
            swept.reclaimed += bytes;
        }
    }

    Ok(swept)
}

/// The periodic sweep, beside the store it keeps in bounds.
pub struct RetentionService {
    /// A cadence override, for a test that cannot wait for a configured day.
    every: Option<Duration>,
    running: std::sync::Mutex<Option<Running>>,
}

struct Running {
    task: tokio::task::JoinHandle<()>,
    stop: tokio::sync::watch::Sender<bool>,
}

impl Default for RetentionService {
    fn default() -> Self {
        Self::new()
    }
}

impl RetentionService {
    /// Builds the service that keeps the decision store inside its retention.
    pub fn new() -> Self {
        Self {
            every: None,
            running: std::sync::Mutex::new(None),
        }
    }

    /// Sweeps at a fixed cadence regardless of configuration.
    pub fn every(mut self, tick: Duration) -> Self {
        self.every = Some(tick);

        self
    }
}

impl permguard_core::Service for RetentionService {
    fn name(&self) -> &'static str {
        "decision-retention"
    }

    fn start<'a>(
        &'a self,
        context: &'a permguard_core::ServerContext<'a>,
    ) -> permguard_core::BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let config = context.config();
            if !config.decision_store_enabled() {
                return Ok(());
            }
            let root = config.working_dir().join(config.decision_store_directory());
            let keep = config.decision_store_retention();
            // A twelfth of the window, bounded: often enough that "records
            // leave on a schedule" is true rather than approximately true,
            // rarely enough that a ninety-day store is not walked hourly.
            let every = self.every.unwrap_or_else(|| {
                (keep / 12).clamp(Duration::from_secs(300), Duration::from_secs(6 * 3600))
            });
            tracing::info!(
                event.name = "decisions.retaining",
                component = "control-plane",
                retention.seconds = keep.as_secs(),
                interval.seconds = every.as_secs(),
                "decision records older than the retention window will leave"
            );

            let (stop, mut stopped) = tokio::sync::watch::channel(false);
            let task = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        // One interval away, not at start: a plane that has
                        // just come up is the worst moment to walk a store.
                        _ = tokio::time::sleep(every) => {
                            let root = root.clone();
                            let swept = tokio::task::spawn_blocking(move || sweep_once(&root, keep)).await;
                            match swept {
                                Ok(Ok(swept)) if swept.removed > 0 => tracing::info!(
                                    event.name = "decisions.swept",
                                    component = "control-plane",
                                    removed = swept.removed,
                                    reclaimed = swept.reclaimed,
                                    retained = swept.retained,
                                    "decision segments left on the retention schedule"
                                ),
                                Ok(Err(error)) => tracing::warn!(
                                    event.name = "decisions.sweep_failed",
                                    component = "control-plane",
                                    error = %error,
                                    "a retention sweep did not complete"
                                ),
                                _ => {}
                            }
                        }
                        _ = stopped.changed() => break,
                    }
                }
            });

            if let Ok(mut running) = self.running.lock() {
                *running = Some(Running { task, stop });
            }

            Ok(())
        })
    }

    fn stop<'a>(
        &'a self,
        _context: &'a permguard_core::ServerContext<'a>,
    ) -> permguard_core::BoxFuture<'a, Result<()>> {
        let running = self.running.lock().ok().and_then(|mut held| held.take());

        Box::pin(async move {
            let Some(running) = running else {
                return Ok(());
            };
            let _ = running.stop.send(true);
            let _ = running.task.await;

            Ok(())
        })
    }
}

/// Every directory that holds segments: each stream, and each tenant view.
fn scopes(root: &Path) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    // streams/<pdp>/<instance> and views/<zone>/<ledger> are both two deep.
    for top in ["streams", "views"] {
        let directory = root.join(top);
        for outer in fs::read_dir(&directory).into_iter().flatten().flatten() {
            if !outer.path().is_dir() {
                continue;
            }
            for inner in fs::read_dir(outer.path()).into_iter().flatten().flatten() {
                if inner.path().is_dir() {
                    found.push(inner.path());
                }
            }
        }
    }

    Ok(found)
}

fn is_segment(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("seg-") && name.ends_with(".jsonl"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("permguard-retention-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("views/acme/main-ledger")).expect("it is created");

        root
    }

    #[test]
    fn a_segment_younger_than_the_window_stays() {
        let root = scratch("young");
        fs::write(
            root.join("views/acme/main-ledger/seg-00000000000000000001.jsonl"),
            b"{}\n",
        )
        .expect("it writes");

        let swept = sweep_once(&root, Duration::from_secs(3600)).expect("it sweeps");
        assert_eq!(swept.removed, 0);
        assert_eq!(swept.retained, 1);
    }

    #[test]
    fn a_segment_past_the_window_leaves_whole() {
        let root = scratch("old");
        let path = root.join("views/acme/main-ledger/seg-00000000000000000001.jsonl");
        fs::write(&path, b"{}\n").expect("it writes");

        let swept = sweep_once(&root, Duration::from_secs(0)).expect("it sweeps");
        assert_eq!(swept.removed, 1);
        assert!(swept.reclaimed > 0);
        assert!(!path.exists());
    }

    #[test]
    fn nothing_but_segments_is_ever_removed() {
        let root = scratch("evidence");
        let scope = root.join("views/acme/main-ledger");
        for name in ["STATE", "EPOCHS.jsonl", "batch-00000000000000000001.jws"] {
            fs::write(scope.join(name), b"{}\n").expect("it writes");
        }

        sweep_once(&root, Duration::from_secs(0)).expect("it sweeps");
        for name in ["STATE", "EPOCHS.jsonl", "batch-00000000000000000001.jws"] {
            assert!(
                scope.join(name).exists(),
                "{name} is what lets an exported segment still be checked years later"
            );
        }
    }
}
