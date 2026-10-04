// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What this control plane holds, as numbers an operator can page on: objects and bytes, in total.
//!
//! # Why a loop rather than a counter
//!
//! The obvious design is to add up bytes as objects arrive. It is also wrong
//! in the way that matters: a process that restarts would report nothing until
//! the next push, a store trimmed by hand would never be noticed, and the one
//! number an operator actually wants — *how much disk is this deployment
//! using* — would be a running total nobody could reconcile with `du`.
//!
//! So it is measured, not accumulated: a walk of the store on a slow cadence,
//! publishing gauges that are true when they are read. The walk costs one
//! `stat` per object file and no reads; on a store of a hundred thousand
//! objects it is milliseconds, and it happens once a minute, off every request
//! path.
//!
//! # What it answers
//!
//! | Question                               | Metric                    |
//! | -------------------------------------- | ------------------------- |
//! | how much disk is this deployment using | `permguard_store_bytes`   |
//! | how many objects it holds              | `permguard_store_objects` |
//!
//! Totals only, with no label. Which zone or ledger is growing is a question for the catalog,
//! asked by an authorized caller: a series per zone or per ledger would be a tenant identifier
//! in the telemetry, which P10 forbids.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use permguard_core::catalog::{Catalog, Selector};
use permguard_core::metrics::{Metric, SECONDS};
use permguard_core::{BoxFuture, Metrics, ServerContext, Service, ready};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

const COMPONENT: &str = "control-plane";

/// How often the store is measured. Not configurable on purpose: it is cheap,
/// and a knob whose only effect is the freshness of a gauge is a knob nobody
/// should have to reason about.
const EVERY: Duration = Duration::from_secs(60);

/// Objects every ledger of this control plane holds. Totals only: a ledger's or a zone's own
/// size would be a series per tenant, which P10 forbids; per-ledger figures are an authorized
/// question for the catalog, not a label.
pub const STORE_OBJECTS: Metric = Metric::gauge(
    "permguard_store_objects",
    "Objects every ledger of this control plane holds.",
);

/// The whole deployment, in bytes.
pub const STORE_BYTES: Metric = Metric::gauge(
    "permguard_store_bytes",
    "Bytes every ledger of this control plane occupies on disk.",
);

/// How long a measurement took, so a store that has grown past this design
/// says so rather than quietly slowing something down.
pub const WALK_SECONDS: Metric = Metric::histogram(
    "permguard_inventory_walk_seconds",
    "How long measuring the whole store took.",
    SECONDS,
);

/// The service the plane mounts.
pub struct InventoryService {
    every: Duration,
    running: Mutex<Option<Running>>,
}

struct Running {
    task: JoinHandle<()>,
    stop: watch::Sender<bool>,
}

impl Default for InventoryService {
    fn default() -> Self {
        Self::new()
    }
}

impl InventoryService {
    /// The service, on its ordinary cadence.
    pub fn new() -> Self {
        Self {
            every: EVERY,
            running: Mutex::new(None),
        }
    }

    /// A faster cadence, for a test that cannot wait a minute.
    #[cfg(test)]
    pub fn every(mut self, every: Duration) -> Self {
        self.every = every;

        self
    }
}

impl Service for InventoryService {
    fn name(&self) -> &'static str {
        "inventory"
    }

    fn start<'a>(&'a self, context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let Some(catalog) = context.catalog().cloned() else {
                debug!(
                    event.name = "inventory.disabled",
                    component = COMPONENT,
                    "no catalog is composed: there is nothing to measure"
                );

                return Ok(());
            };
            let root = context.config().zones_directory();
            let metrics = context.metrics().clone();
            let every = self.every;

            // Once at start, so a plane that has just come up already reports
            // what it holds rather than waiting out the first interval.
            measure(&catalog, &root, &metrics);

            let (stop, mut stopped) = watch::channel(false);
            let task = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(every) => {
                            let catalog = Arc::clone(&catalog);
                            let root = root.clone();
                            let metrics = metrics.clone();
                            // A directory walk is blocking work; it does not
                            // belong on a runtime thread that answers requests.
                            let _ = tokio::task::spawn_blocking(move || {
                                measure(&catalog, &root, &metrics);
                            })
                            .await;
                        }
                        _ = stopped.changed() => break,
                    }
                }
            });

            *self
                .running
                .lock()
                .map_err(|_| anyhow!("the inventory service lock is poisoned"))? =
                Some(Running { task, stop });

            Ok(())
        })
    }

    fn stop<'a>(&'a self, _context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        let running = match self.running.lock() {
            Ok(mut running) => running.take(),
            Err(_) => return ready(Err(anyhow!("the inventory service lock is poisoned"))),
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

/// One pass: every zone, every ledger, published as gauges.
fn measure(catalog: &Arc<dyn Catalog>, root: &Path, metrics: &Metrics) {
    let started = Instant::now();
    let zones = match catalog.list_zones() {
        Ok(zones) => zones,
        Err(error) => {
            warn!(
                event.name = "inventory.failed",
                component = COMPONENT,
                error = %error,
                "the catalog could not be listed: what this plane holds is not reported this round"
            );

            return;
        }
    };

    let mut total = 0u64;
    let mut objects = 0u64;
    for zone in &zones {
        let ledgers = match catalog.list_ledgers(&Selector::Id(zone.id.clone())) {
            Ok(ledgers) => ledgers,
            Err(error) => {
                warn!(
                    event.name = "inventory.zone_failed",
                    component = COMPONENT,
                    zone = zone.id.as_str(),
                    error = %error,
                    "a zone's ledgers could not be listed"
                );
                continue;
            }
        };
        let mut zone_bytes = 0u64;
        for ledger in &ledgers {
            let directory = root.join(&zone.id).join("ledgers").join(&ledger.id);
            let held = held_by(&directory);
            zone_bytes += held.bytes;
            objects += held.objects;
        }
        total += zone_bytes;
    }

    metrics.set(&STORE_BYTES, &[], total as f64);
    metrics.set(&STORE_OBJECTS, &[], objects as f64);
    metrics.observe(&WALK_SECONDS, &[], started.elapsed().as_secs_f64());
    debug!(
        event.name = "inventory.measured",
        component = COMPONENT,
        zones = zones.len(),
        bytes = total,
        "what this plane holds was measured"
    );
}

/// What one ledger's directory holds.
#[derive(Debug, Default, PartialEq, Eq)]
struct Held {
    bytes: u64,
    objects: u64,
}

/// Walks one ledger's objects, counting files and bytes. `stat` only: nothing
/// is read, and nothing is decompressed.
fn held_by(ledger: &Path) -> Held {
    let mut held = Held::default();
    let objects = ledger.join("objects");
    let Ok(fans) = std::fs::read_dir(&objects) else {
        return held;
    };
    for fan in fans.flatten() {
        let Ok(entries) = std::fs::read_dir(fan.path()) else {
            continue;
        };
        for entry in entries.flatten() {
            // A temporary is a write in flight or one a crash interrupted, not an object.
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(permguard_host::storage::dir::TEMP_PREFIX)
            {
                continue;
            }
            if let Ok(metadata) = entry.metadata()
                && metadata.is_file()
            {
                held.objects += 1;
                held.bytes += metadata.len();
            }
        }
    }

    held
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use std::path::PathBuf;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pg-inventory-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory is created");

        dir
    }

    #[test]
    fn a_ledger_that_is_not_there_holds_nothing() {
        assert_eq!(held_by(Path::new("/nonexistent/ledger")), Held::default());
    }

    #[test]
    fn what_is_on_disk_is_what_is_counted() {
        let ledger = scratch("counted");
        let fan = ledger.join("objects").join("ab");
        std::fs::create_dir_all(&fan).expect("the fanout exists");
        std::fs::write(fan.join("cdef"), b"twelve bytes").expect("an object");
        std::fs::write(fan.join("0123"), b"four").expect("another");
        // A directory inside the fanout is not an object.
        std::fs::create_dir_all(fan.join("nested")).expect("a directory");
        // Nor is a temporary a write left behind.
        std::fs::write(fan.join(".tmp-0123456789abcdef"), b"partial").expect("a temporary");

        assert_eq!(
            held_by(&ledger),
            Held {
                bytes: 16,
                objects: 2
            }
        );
    }
}
