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
//! keep  =  reachable from ANY ref   ∪   pinned by a kept transfer session   ∪   younger than the grace period
//!       ∪  everything of a ledger a hold keeps
//! ```
//!
//! A hold (WP-7.3c) names a ledger, or a zone and so every ledger of it, and keeps all it holds,
//! unreachable objects included, until it expires or is released. The holds are read once per
//! pass, before any ledger: holds that cannot be read sweep nothing that pass.
//!
//! Reachability is computed from **every ref of the ledger**, not the default
//! one, walking commits to their predecessors, their manifest and their tree,
//! and trees to their entries. Everything else is a candidate — and a
//! candidate is only removed once it is **older than `storage.gc.grace`**,
//! which keeps an object a crash left behind safe for a while. What keeps a
//! push in flight safe is its transfer session (WP-7.12): every object its
//! closure declared is pinned while the session is open, and for the grace
//! after it ends, however long the push takes. An open session past its expiry
//! is closed first, and a pull session pins what its negotiation answered
//! missing until it expires. The server refuses a grace period shorter than any
//! write lasts.
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
use permguard_core::{BoxFuture, Metrics, PlaneContext, PlaneTask, Subject, ready};
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
    "Objects removed because nothing referenced them.",
);

/// Bytes reclaimed.
pub const RECLAIMED: Metric = Metric::counter(
    "permguard_gc_bytes_reclaimed_total",
    "Bytes reclaimed by removing unreferenced objects.",
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

impl PlaneTask for GcService {
    fn name(&self) -> &'static str {
        "gc"
    }

    fn start<'a>(&'a self, context: &'a PlaneContext<'a>) -> BoxFuture<'a, Result<()>> {
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
                recorder: crate::handles::audit(context),
                holds: crate::handles::holds(context),
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

    fn stop<'a>(&'a self, _context: &'a PlaneContext<'a>) -> BoxFuture<'a, Result<()>> {
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
    recorder: Option<crate::handles::Audit>,
    /// The Host's holds (WP-7.3c): `Ok(None)` without a Host; an error when a Host registered the
    /// plane and handed it none, which sweeps nothing (after the review).
    holds: std::result::Result<Option<Arc<permguard_host::holds::HoldStore>>, ()>,
}

/// What a sweep did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub ledgers: usize,
    pub removed: usize,
    pub reclaimed: u64,
    /// Unreachable, and left alone because they are still young.
    pub retained: usize,
    /// Temporary files of interrupted writes, removed.
    pub temporaries: usize,
    /// Ledgers that could not be swept — a store that would not list, a ref
    /// that would not read. Nothing was removed for those.
    pub skipped: usize,
    /// Ledgers a hold keeps, left whole (WP-7.3c).
    pub held: usize,
    /// The holds could not be read: nothing was swept (after the review).
    pub holds_unreadable: bool,
}

impl Outcome {
    /// How the sweep ended, in one word.
    pub fn label(&self) -> &'static str {
        if self.skipped == 0 && !self.holds_unreadable {
            "ok"
        } else {
            "partial"
        }
    }
}

impl Sweep {
    /// One pass over every ledger of every zone.
    fn run(&self) -> Outcome {
        let started = Instant::now();
        let mut outcome = Outcome::default();
        let now = permguard_host::authz::store::now();
        // The holds first, once: a pass that cannot know what is held removes nothing.
        let listed = match &self.holds {
            Ok(None) => Ok(Vec::new()),
            Ok(Some(store)) => store.list().map_err(|error| error.to_string()),
            Err(()) => Err("the Host handed this plane no holds".to_owned()),
        };
        let holds = match listed {
            Ok(holds) => holds,
            Err(error) => {
                warn!(
                    event.name = "gc.holds_unreadable",
                    component = COMPONENT,
                    error = %error,
                    "the holds could not be read: nothing is swept this round"
                );
                outcome.holds_unreadable = true;

                return outcome;
            }
        };
        for hold in &holds {
            if hold.status(now) == permguard_host::holds::Status::ReviewDue {
                warn!(
                    event.name = "gc.hold_review_due",
                    component = COMPONENT,
                    hold = hold.id.as_str(),
                    "a hold is past its review date: it still keeps what it names"
                );
            }
        }
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

        let mut listed = std::collections::BTreeSet::new();
        for zone in &zones {
            let ledgers = match self.catalog.list_ledgers(&Selector::Id(zone.id.clone())) {
                Ok(ledgers) => ledgers,
                Err(error) => {
                    warn!(
                        event.name = "gc.zone_failed",
                        component = COMPONENT,
                        zone = zone.id.as_str(),
                        error = %error,
                        "a zone's ledgers could not be listed"
                    );
                    outcome.skipped += 1;
                    continue;
                }
            };
            for ledger in &ledgers {
                outcome.ledgers += 1;
                listed.insert(format!("{}/{}", zone.id, ledger.id));
                if holds
                    .iter()
                    .any(|hold| hold.keeps(&zone.id, &ledger.id, now))
                {
                    outcome.held += 1;
                    continue;
                }
                let directory = self.root.join(&zone.id).join("ledgers").join(&ledger.id);
                let store = FileObjectStore::new(&directory);
                match self.sweep_ledger(&store, &zone.id, &ledger.id) {
                    Ok(swept) => {
                        outcome.removed += swept.removed;
                        outcome.reclaimed += swept.reclaimed;
                        outcome.retained += swept.retained;
                        outcome.temporaries += swept.temporaries;
                    }
                    Err(error) => {
                        outcome.skipped += 1;
                        warn!(
                            event.name = "gc.ledger_failed",
                            component = COMPONENT,
                            zone = zone.id.as_str(),
                            ledger = ledger.id.as_str(),
                            error = %error,
                            "this ledger was left exactly as it was"
                        );
                    }
                }
            }
        }

        // A ledger the catalog no longer lists stops counting toward what is retained. Only after a
        // listing that reached every zone: a zone that could not be listed is not evidence that its
        // ledgers are gone.
        if outcome.skipped == 0 {
            self.metrics
                .retain_aggregated(&RETAINED, permguard_core::Aggregate::Sum, |resource| {
                    listed.contains(resource)
                });
        }

        self.metrics.count(
            &SWEEPS,
            &[(permguard_core::metrics::labels::OUTCOME, outcome.label())],
        );
        self.metrics
            .observe(&SWEEP_SECONDS, &[], started.elapsed().as_secs_f64());

        outcome
    }

    /// One ledger, with what a service adds around the sweep: labels, metrics
    /// and a line in the log.
    /// `zone` and `ledger` are ids: they key the retained-objects aggregate and name the ledger in the
    /// log, where a name would be a tenant identifier.
    fn sweep_ledger(&self, store: &FileObjectStore, zone: &str, ledger: &str) -> Result<Swept> {
        let swept = sweep_once(store, self.grace)?;

        if swept.removed > 0 {
            self.metrics.add(&REMOVED, &[], swept.removed as f64);
            self.metrics.add(&RECLAIMED, &[], swept.reclaimed as f64);
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
        self.metrics.set_aggregated(
            &RETAINED,
            permguard_core::Aggregate::Sum,
            &format!("{zone}/{ledger}"),
            swept.retained as f64,
        );

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
            temporaries = outcome.temporaries,
            skipped = outcome.skipped,
            held = outcome.held,
            holds_unreadable = outcome.holds_unreadable,
            "a garbage-collection sweep finished"
        );
        let Some(recorder) = &self.recorder else {
            return;
        };
        let target = trail_target(outcome);
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

/// What the `store.swept` record names: every count of the pass, the held ledgers included
/// (WP-7.3c).
fn trail_target(outcome: &Outcome) -> String {
    if outcome.holds_unreadable {
        return "nothing swept: the holds could not be read".to_owned();
    }
    format!(
        "{} ledgers swept, {} objects removed, {} bytes reclaimed, {} retained, {} skipped, {} held",
        outcome.ledgers,
        outcome.removed,
        outcome.reclaimed,
        outcome.retained,
        outcome.skipped,
        outcome.held
    )
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
    /// Temporary files of writes a crash interrupted, removed once older than
    /// the grace period.
    pub temporaries: usize,
}

/// Sweeps one ledger's store: what its refs reach stays, the rest goes once it
/// is older than `grace`.
///
/// The unit the service is built from, and the one a test can drive: no
/// catalog, no clock but the filesystem's, no metrics. It answers what it did,
/// or refuses — a store whose closure has a hole is left exactly as it was.
pub fn sweep_once(store: &FileObjectStore, grace: Duration) -> Result<Swept> {
    // A temporary is a write that never finished, unless it is younger than any write lasts: the
    // grace period that keeps a push in flight safe keeps its temporaries safe too.
    // A temporary that cannot be swept costs disk, not correctness: it never stops the
    // collection of the objects.
    let temporaries = match store.sweep_temporaries(grace) {
        Ok(swept) => swept,
        Err(error) => {
            warn!(
                event.name = "gc.temporaries_not_swept",
                component = COMPONENT,
                ledger = %store.root().display(),
                error = %error,
                "the temporaries of interrupted writes could not be swept"
            );
            0
        }
    };
    // The transfer sessions first (WP-7.12): one past its expiry is closed before it stops
    // counting, and every session still kept pins what its transfer may touch. A session that
    // does not read stops the sweep of this ledger: what it pins is not known.
    let now = SystemTime::now();
    // Held to the end of the sweep: a negotiation that pins an object waits until the sweep has
    // decided, so nothing it was told is present is removed after it was told.
    let transfers = store.transfers().map_err(|error| anyhow!("{error}"))?;
    let pinned = {
        let unix = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        transfers
            .sweep(unix, grace)
            .map_err(|error| anyhow!("{error}"))?;
        transfers.pins().map_err(|error| anyhow!("{error}"))?
    };
    let held = store.list_objects().map_err(|error| anyhow!("{error}"))?;
    if held.is_empty() {
        return Ok(Swept {
            temporaries,
            ..Swept::default()
        });
    }
    let mut reachable = reachable(store)?;
    reachable.extend(pinned);
    let mut swept = Swept {
        temporaries,
        ..Swept::default()
    };

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
    drop(transfers);

    Ok(swept)
}

/// Everything every ref of this ledger reaches.
///
/// Every ref, not the default one: a ledger may serve several, and a sweep
/// that knew about one would delete the others. A hole in the closure — an
/// object a ref names and the store does not hold — stops the sweep for this
/// ledger rather than being walked around: a store that cannot be fully read
/// is not a store to delete from.
pub(crate) fn reachable(store: &FileObjectStore) -> Result<BTreeSet<Digest>> {
    let refs = store.list_refs().map_err(|error| anyhow!("{error}"))?;
    reachable_from(store, refs.into_iter().map(|(_, state)| state.head))
}

/// Everything `heads` reach in `store`; a hole in the closure is an error, as for [`reachable`].
pub(crate) fn reachable_from(
    store: &FileObjectStore,
    heads: impl IntoIterator<Item = Digest>,
) -> Result<BTreeSet<Digest>> {
    let mut reached = BTreeSet::new();
    let mut queue: Vec<Digest> = heads.into_iter().collect();

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

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use permguard_core::assurance::AssuranceProfile;
    use permguard_host::holds::{Deadline, HoldStore, NewHold};
    use permguard_host::operations::journal::Initiator;
    use permguard_host::operations::mutation::Mutations;
    use permguard_host::storage::volume::Volume;
    use permguard_objects::object::Blob;
    use permguard_std::catalog::FileCatalog;

    use super::*;

    /// Two ledgers of one zone, each holding one orphan old enough to go, and the volume's holds.
    struct Fixture {
        sweep: Sweep,
        holds: Arc<HoldStore>,
        mutations: Mutations,
        zone: String,
        ledgers: Vec<(String, FileObjectStore, permguard_objects::Digest)>,
    }

    fn fixture(tag: &str) -> Fixture {
        let root = std::env::temp_dir().join(format!(
            "permguard-gc-holds-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let catalog = Arc::new(FileCatalog::new(root.join("zones")));
        let zone = catalog.create_zone("delivery").expect("a zone");
        let mut ledgers = Vec::new();
        for name in ["policies", "rules"] {
            let ledger = catalog
                .create_ledger(&Selector::Id(zone.id.clone()), name)
                .expect("a ledger");
            let store = FileObjectStore::new(
                root.join("zones")
                    .join(&zone.id)
                    .join("ledgers")
                    .join(&ledger.id),
            );
            let bytes = Blob {
                media_type: "application/vnd.permguard.policy.cedar".to_owned(),
                data: format!("permit (principal, action, resource); // {name}").into_bytes(),
            }
            .encode()
            .expect("a blob");
            let digest = store.put_object(&bytes).expect("stored").0;
            let hex = digest.to_string();
            let hex = &hex["sha256:".len()..];
            std::fs::File::options()
                .write(true)
                .open(store.root().join("objects").join(&hex[..2]).join(&hex[2..]))
                .expect("the object")
                .set_modified(std::time::SystemTime::now() - Duration::from_secs(30 * 86_400))
                .expect("aged");
            ledgers.push((ledger.id, store, digest));
        }
        let volume =
            Volume::claim(&root.join("volume"), AssuranceProfile::Development).expect("a volume");
        let holds = Arc::new(HoldStore::open(&volume).expect("the holds"));
        let mutations = Mutations::open_offline(&volume, "test").expect("the transaction");
        Fixture {
            sweep: Sweep {
                catalog,
                root: root.join("zones"),
                grace: Duration::from_secs(60),
                metrics: Metrics::none(),
                recorder: None,
                holds: Ok(Some(Arc::clone(&holds))),
            },
            holds,
            mutations,
            zone: zone.id,
            ledgers,
        }
    }

    fn hold(fixture: &Fixture, resource: String) -> String {
        permguard_host::holds::add(
            &fixture.mutations,
            &fixture.holds,
            Initiator::System("test".to_owned()),
            NewHold {
                resource,
                owner: "legal".to_owned(),
                reason: "litigation".to_owned(),
                deadline: Deadline::Review(permguard_host::authz::store::now() + 3_600),
            },
            permguard_host::authz::store::now(),
        )
        .expect("held")
        .id
    }

    fn present(fixture: &Fixture) -> Vec<bool> {
        fixture
            .ledgers
            .iter()
            .map(|(_, store, digest)| store.has_object(digest))
            .collect()
    }

    /// WP-7.3c, owner decision of 2026-10-21: a held ledger is not swept at all, its unreachable
    /// objects included; the ledger beside it is swept as before, and a released hold keeps
    /// nothing.
    #[test]
    fn a_held_ledger_is_not_swept() {
        let fixture = fixture("ledger");
        let id = hold(
            &fixture,
            format!(
                "plane/control/zone/{}/ledger/{}",
                fixture.zone, fixture.ledgers[0].0
            ),
        );

        let outcome = fixture.sweep.run();
        assert_eq!((outcome.held, outcome.removed, outcome.skipped), (1, 1, 0));
        assert_eq!(present(&fixture), vec![true, false]);

        permguard_host::holds::release(
            &fixture.mutations,
            &fixture.holds,
            Initiator::System("test".to_owned()),
            &id,
        )
        .expect("released");
        let outcome = fixture.sweep.run();
        assert_eq!((outcome.held, outcome.removed), (0, 1));
        assert_eq!(present(&fixture), vec![false, false]);
    }

    /// WP-7.3c, owner decision of 2026-10-21: a zone's hold keeps every ledger of the zone.
    #[test]
    fn a_zone_hold_keeps_every_ledger_of_the_zone() {
        let fixture = fixture("zone");
        hold(&fixture, format!("plane/control/zone/{}", fixture.zone));

        let outcome = fixture.sweep.run();
        assert_eq!((outcome.held, outcome.removed), (2, 0));
        assert_eq!(present(&fixture), vec![true, true]);
    }

    /// WP-7.3c, owner decision of 2026-10-21: holds that cannot be read sweep nothing that pass.
    #[test]
    fn unreadable_holds_sweep_nothing() {
        let fixture = fixture("unreadable");
        let volume = fixture
            .sweep
            .root
            .parent()
            .expect("the root")
            .join("volume");
        std::fs::write(
            volume
                .join("host")
                .join(permguard_host::holds::DIRECTORY)
                .join("01a00000-0000-7000-8000-00000000000c.json"),
            b"{ not a hold",
        )
        .expect("a broken hold");

        let outcome = fixture.sweep.run();
        assert!(outcome.holds_unreadable);
        assert_eq!(
            (outcome.removed, outcome.ledgers, outcome.label()),
            (0, 0, "partial")
        );
        assert_eq!(present(&fixture), vec![true, true]);
        assert_eq!(
            trail_target(&outcome),
            "nothing swept: the holds could not be read"
        );
    }

    /// WP-7.3c, after the review: a plane a Host registered, declaring it reads the holds and
    /// handed none, sweeps nothing: it cannot know what is held.
    #[test]
    fn a_plane_handed_no_holds_sweeps_nothing() {
        let mut fixture = fixture("missing");
        fixture.sweep.holds = Err(());

        let outcome = fixture.sweep.run();
        assert!(outcome.holds_unreadable);
        assert_eq!(present(&fixture), vec![true, true]);
    }

    /// WP-7.3c, owner decision of 2026-10-21: an expired hold keeps nothing; its ledger is swept.
    #[test]
    fn an_expired_hold_keeps_nothing_from_the_sweep() {
        let fixture = fixture("expired");
        let id = hold(
            &fixture,
            format!(
                "plane/control/zone/{}/ledger/{}",
                fixture.zone, fixture.ledgers[0].0
            ),
        );
        // Its deadline moved into the past, as the clock would move it.
        let path = fixture
            .sweep
            .root
            .parent()
            .expect("the root")
            .join("volume")
            .join("host")
            .join(permguard_host::holds::DIRECTORY)
            .join(format!("{id}.json"));
        let mut written: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("the hold")).expect("JSON");
        written
            .as_object_mut()
            .expect("an object")
            .remove("review_at");
        written["expires_at"] = serde_json::json!(1);
        std::fs::write(&path, written.to_string()).expect("rewritten");

        let outcome = fixture.sweep.run();
        assert_eq!((outcome.held, outcome.removed), (0, 2));
        assert_eq!(present(&fixture), vec![false, false]);
    }

    /// WP-7.3c, owner decision of 2026-10-21: the `store.swept` record counts the held ledgers.
    #[test]
    fn the_sweep_record_counts_the_held_ledgers() {
        let target = trail_target(&Outcome {
            ledgers: 3,
            removed: 4,
            reclaimed: 5,
            retained: 6,
            temporaries: 0,
            skipped: 0,
            held: 2,
            holds_unreadable: false,
        });
        assert_eq!(
            target,
            "3 ledgers swept, 4 objects removed, 5 bytes reclaimed, 6 retained, 0 skipped, 2 held"
        );
    }
}
