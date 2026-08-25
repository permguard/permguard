// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Reclaiming what nothing references.
//!
//! # The leak this closes
//!
//! A content-addressed store only ever adds. A push uploads its objects first
//! and commits second, so between the two they are legitimately unreachable —
//! and if the commit never comes (a connection lost, a conflict nobody
//! retried, a client that crashed) they stay unreachable forever. The same is
//! true of a history that moved: the objects only the abandoned side of it
//! reached are dead the moment the ref does not name them.
//!
//! Nothing else in this server ever deletes an object, so without this the
//! disk of every long-lived deployment climbs in one direction.
//!
//! # The rule, and why it is safe
//!
//! ```text
//! keep  =  reachable from ANY ref   ∪   younger than the grace period
//! ```
//!
//! Reachability is computed from **every ref of the ledger**, not the default
//! one, walking commits to their predecessors, their manifest and their tree,
//! and trees to their entries. Everything else is a candidate — and a
//! candidate is only removed once it is **older than `storage.gc.grace`**,
//! which is what keeps a push in flight safe: its uploads are unreachable and
//! new, so they are never candidates. The server refuses a grace period short
//! enough to make that untrue.
//!
//! Two more properties this relies on, both already true of the store:
//! objects are **immutable and content-addressed**, so an object removed by
//! mistake can be re-uploaded byte-identically by any client that has it; and
//! ref updates are atomic, so a sweep either sees a ref before or after a
//! commit, never halfway.
//!
//! # What it never does
//!
//! It never reads an object to decide its fate — only the reachability walk
//! decodes, and only what a ref reaches. It never removes a ref, a signature
//! or anything outside the object fanout: the paths it touches are built from
//! digests it just listed. And it never runs on the request path.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Result, anyhow};
use permguard_core::catalog::{Catalog, Selector};
use permguard_core::metrics::{Metric, SECONDS};
use permguard_core::{AuditRecorder, BoxFuture, Metrics, ServerContext, Service, Subject, ready};
use permguard_objects::digest::Digest;
use permguard_objects::object::{self, Object};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::store::FileObjectStore;

const COMPONENT: &str = "control-plane";

/// Objects removed, by zone and ledger.
pub const REMOVED: Metric = Metric::counter(
    "permguard_gc_objects_removed_total",
    "Objects removed because nothing referenced them, by zone and ledger.",
);

/// Bytes reclaimed.
pub const RECLAIMED: Metric = Metric::counter(
    "permguard_gc_bytes_reclaimed_total",
    "Bytes reclaimed by removing unreferenced objects, by zone and ledger.",
);

/// Objects that are unreachable and still inside the grace period — the ones
/// a sweep deliberately left alone. A number that keeps climbing is a client
/// abandoning pushes.
pub const RETAINED: Metric = Metric::gauge(
    "permguard_gc_objects_retained",
    "Unreachable objects held back because they are younger than the grace period.",
);

/// Sweeps, by outcome: `ok`, `partial` (a ledger could not be swept).
pub const SWEEPS: Metric = Metric::counter(
    "permguard_gc_sweeps_total",
    "Garbage-collection sweeps, by outcome.",
);

/// How long a whole sweep took.
pub const SWEEP_SECONDS: Metric = Metric::histogram(
    "permguard_gc_sweep_seconds",
    "How long a garbage-collection sweep took.",
    SECONDS,
);

/// The service the control plane mounts.
pub struct GcService {
    /// A cadence override, for a test that cannot wait six hours.
    every: Option<Duration>,
    running: Mutex<Option<Running>>,
}

struct Running {
    task: JoinHandle<()>,
    stop: watch::Sender<bool>,
}

impl Default for GcService {
    fn default() -> Self {
        Self::new()
    }
}

impl GcService {
    /// The service; what it does comes from the configuration.
    pub fn new() -> Self {
        Self {
            every: None,
            running: Mutex::new(None),
        }
    }

    /// Runs on a fixed cadence regardless of configuration — what a test asks
    /// for.
    #[cfg(test)]
    pub fn every(mut self, every: Duration) -> Self {
        self.every = Some(every);

        self
    }
}

impl Service for GcService {
    fn name(&self) -> &'static str {
        "gc"
    }

    fn start<'a>(&'a self, context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let config = context.config();
            if !config.gc_enabled() {
                info!(
                    event.name = "gc.disabled",
                    component = COMPONENT,
                    "unreferenced objects are kept: this store only grows"
                );

                return Ok(());
            }
            let Some(catalog) = context.catalog().cloned() else {
                debug!(
                    event.name = "gc.disabled",
                    component = COMPONENT,
                    "no catalog is composed: there is nothing to sweep"
                );

                return Ok(());
            };

            let sweep = Sweep {
                catalog,
                root: config.zones_directory(),
                grace: config.gc_grace(),
                metrics: context.metrics().clone(),
                recorder: context.recorder().cloned(),
            };
            let every = self.every.unwrap_or_else(|| config.gc_interval());
            info!(
                event.name = "gc.following",
                component = COMPONENT,
                interval.seconds = every.as_secs(),
                grace.seconds = sweep.grace.as_secs(),
                "unreferenced objects older than the grace period will be reclaimed"
            );

            let (stop, mut stopped) = watch::channel(false);
            let task = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        // The first sweep is one interval away, not at start:
                        // a plane that has just come up is the worst moment to
                        // spend a directory walk, and nothing is urgent here.
                        _ = tokio::time::sleep(every) => {
                            let sweep = sweep.clone();
                            let outcome = tokio::task::spawn_blocking(move || {
                                let outcome = sweep.run();
                                (sweep, outcome)
                            })
                            .await;
                            if let Ok((sweep, outcome)) = outcome {
                                sweep.report(&outcome).await;
                            }
                        }
                        _ = stopped.changed() => break,
                    }
                }
            });

            *self
                .running
                .lock()
                .map_err(|_| anyhow!("the gc service lock is poisoned"))? =
                Some(Running { task, stop });

            Ok(())
        })
    }

    fn stop<'a>(&'a self, _context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        let running = match self.running.lock() {
            Ok(mut running) => running.take(),
            Err(_) => return ready(Err(anyhow!("the gc service lock is poisoned"))),
        };

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

/// Everything one sweep needs, resolved once.
#[derive(Clone)]
struct Sweep {
    catalog: Arc<dyn Catalog>,
    root: std::path::PathBuf,
    grace: Duration,
    metrics: Metrics,
    recorder: Option<AuditRecorder>,
}

/// What a sweep did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub ledgers: usize,
    pub removed: usize,
    pub reclaimed: u64,
    /// Unreachable, and left alone because they are still young.
    pub retained: usize,
    /// Ledgers that could not be swept — a store that would not list, a ref
    /// that would not read. Nothing was removed for those.
    pub skipped: usize,
}

impl Outcome {
    /// How the sweep ended, in one word.
    pub fn label(&self) -> &'static str {
        if self.skipped == 0 { "ok" } else { "partial" }
    }
}

impl Sweep {
    /// One pass over every ledger of every zone.
    fn run(&self) -> Outcome {
        let started = Instant::now();
        let mut outcome = Outcome::default();
        let zones = match self.catalog.list_zones() {
            Ok(zones) => zones,
            Err(error) => {
                warn!(
                    event.name = "gc.failed",
                    component = COMPONENT,
                    error = %error,
                    "the catalog could not be listed: nothing is swept this round"
                );
                outcome.skipped += 1;

                return outcome;
            }
        };

        for zone in &zones {
            let ledgers = match self.catalog.list_ledgers(&Selector::Id(zone.id.clone())) {
                Ok(ledgers) => ledgers,
                Err(error) => {
                    warn!(
                        event.name = "gc.zone_failed",
                        component = COMPONENT,
                        zone = zone.name.as_str(),
                        error = %error,
                        "a zone's ledgers could not be listed"
                    );
                    outcome.skipped += 1;
                    continue;
                }
            };
            for ledger in &ledgers {
                outcome.ledgers += 1;
                let directory = self.root.join(&zone.id).join("ledgers").join(&ledger.id);
                let store = FileObjectStore::new(&directory);
                match self.sweep_ledger(&store, &zone.name, &ledger.name) {
                    Ok(swept) => {
                        outcome.removed += swept.removed;
                        outcome.reclaimed += swept.reclaimed;
                        outcome.retained += swept.retained;
                    }
                    Err(error) => {
                        outcome.skipped += 1;
                        warn!(
                            event.name = "gc.ledger_failed",
                            component = COMPONENT,
                            zone = zone.name.as_str(),
                            ledger = ledger.name.as_str(),
                            error = %error,
                            "this ledger was left exactly as it was"
                        );
                    }
                }
            }
        }

        self.metrics.count(&SWEEPS, &[("outcome", outcome.label())]);
        self.metrics
            .observe(&SWEEP_SECONDS, &[], started.elapsed().as_secs_f64());

        outcome
    }

    /// One ledger, with what a service adds around the sweep: labels, metrics
    /// and a line in the log.
    fn sweep_ledger(&self, store: &FileObjectStore, zone: &str, ledger: &str) -> Result<Swept> {
        let labels = [("zone", zone), ("ledger", ledger)];
        let swept = sweep_once(store, self.grace)?;

        if swept.removed > 0 {
            self.metrics.add(&REMOVED, &labels, swept.removed as f64);
            self.metrics
                .add(&RECLAIMED, &labels, swept.reclaimed as f64);
            info!(
                event.name = "gc.ledger_swept",
                component = COMPONENT,
                zone = zone,
                ledger = ledger,
                removed = swept.removed,
                bytes = swept.reclaimed,
                "unreferenced objects were reclaimed"
            );
        }
        self.metrics.set(&RETAINED, &labels, swept.retained as f64);

        Ok(swept)
    }

    /// Puts the sweep on the trail.
    ///
    /// Recorded whether or not anything was removed: "nothing was deleted at
    /// 03:00" is what lets an auditor account for a store's contents over
    /// time, and a trail that only carried deletions could not.
    async fn report(&self, outcome: &Outcome) {
        info!(
            event.name = "gc.sweep",
            component = COMPONENT,
            outcome = outcome.label(),
            ledgers = outcome.ledgers,
            removed = outcome.removed,
            bytes = outcome.reclaimed,
            retained = outcome.retained,
            skipped = outcome.skipped,
            "a garbage-collection sweep finished"
        );
        let Some(recorder) = &self.recorder else {
            return;
        };
        let target = format!(
            "{} ledgers swept, {} objects removed, {} bytes reclaimed, {} retained, {} skipped",
            outcome.ledgers, outcome.removed, outcome.reclaimed, outcome.retained, outcome.skipped
        );
        if let Err(error) = recorder
            .record_on("store.swept", Subject::System(COMPONENT), &target)
            .await
        {
            warn!(
                event.name = "gc.audit_failed",
                component = COMPONENT,
                error = %error,
                "objects were reclaimed and the audit record was not written"
            );
        }
    }
}

/// What one ledger's sweep did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Swept {
    /// Objects removed.
    pub removed: usize,
    /// Bytes reclaimed by removing them.
    pub reclaimed: u64,
    /// Unreachable, and left alone because they are still young — what a push
    /// in flight looks like from here.
    pub retained: usize,
}

/// Sweeps one ledger's store: what its refs reach stays, the rest goes once it
/// is older than `grace`.
///
/// The unit the service is built from, and the one a test can drive: no
/// catalog, no clock but the filesystem's, no metrics. It answers what it did,
/// or refuses — a store whose closure has a hole is left exactly as it was.
pub fn sweep_once(store: &FileObjectStore, grace: Duration) -> Result<Swept> {
    let held = store.list_objects().map_err(|error| anyhow!("{error}"))?;
    if held.is_empty() {
        return Ok(Swept::default());
    }
    let reachable = reachable(store)?;
    let now = SystemTime::now();
    let mut swept = Swept::default();

    for object in held {
        if reachable.contains(&object.digest) {
            continue;
        }
        // Young and unreachable is what a push in flight looks like.
        let age = now
            .duration_since(object.modified)
            .unwrap_or(Duration::ZERO);
        if age < grace {
            swept.retained += 1;
            continue;
        }
        let reclaimed = store
            .remove_object(&object.digest)
            .map_err(|error| anyhow!("{error}"))?;
        swept.removed += 1;
        swept.reclaimed += reclaimed;
    }

    Ok(swept)
}

/// Everything every ref of this ledger reaches.
///
/// Every ref, not the default one: a ledger may serve several, and a sweep
/// that knew about one would delete the others. A hole in the closure — an
/// object a ref names and the store does not hold — stops the sweep for this
/// ledger rather than being walked around: a store that cannot be fully read
/// is not a store to delete from.
fn reachable(store: &FileObjectStore) -> Result<BTreeSet<Digest>> {
    let refs = store.list_refs().map_err(|error| anyhow!("{error}"))?;
    let mut reached = BTreeSet::new();
    let mut queue: Vec<Digest> = refs.into_iter().map(|(_, state)| state.head).collect();

    while let Some(digest) = queue.pop() {
        if !reached.insert(digest.clone()) {
            continue;
        }
        let bytes = store
            .get_object(&digest)
            .map_err(|error| anyhow!("{error}"))?
            .ok_or_else(|| {
                anyhow!("the object {digest} is referenced and missing: refusing to sweep")
            })?;
        match object::decode(&bytes).map_err(|error| anyhow!("{digest}: {error}"))? {
            Object::Commit(commit) => {
                queue.push(commit.tree);
                queue.push(commit.manifest);
                queue.extend(commit.predecessors);
            }
            Object::Tree(tree) => {
                queue.extend(tree.entries.into_iter().map(|entry| entry.digest));
            }
            Object::Blob(_) => {}
        }
    }

    Ok(reached)
}
