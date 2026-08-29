// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Dropping what is old enough to drop, and nothing that proves what stays.
//!
//! # Whole sealed segments, never records
//!
//! Retention removes segments, not rows. A row removed from the middle of a segment would leave a
//! chain with a hole in it and an index naming a position that no longer exists; a whole segment
//! that has left is a *gap a reader is told about*, which is a different and honest thing.
//!
//! # What must survive what it proves
//!
//! Two things are kept regardless of age: the envelope covering any retained record, because
//! without it that record cannot be verified at all; and the archived public key that envelope
//! names, because a producer rotates and its published set only carries what is current. Dropping
//! either would leave records that are present and unverifiable, which is worse than absent.
//!
//! # The absolute sequence keeps climbing
//!
//! Removing old segments never renumbers a surviving position, and a newly appended record never
//! reuses one. A consumer that falls behind the oldest retained position is told so explicitly —
//! with where to resume and how large the gap is — rather than silently restarted at the
//! beginning, which would turn a gap it could have recorded into a duplicate run it cannot.

use std::fs;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};

use super::store::{EventStore, Scope, lines_in, segments_in};

/// What one sweep removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Swept {
    /// How many segments were removed.
    pub segments: u64,
    /// How many records went with them.
    pub records: u64,
}

/// Removes sealed segments of `scope` that end at or below `through`.
///
/// `through` is the caller's decision, and it is a sequence rather than an age because the two
/// stores that call this compute it differently: a tenant view drops what a retention window no
/// longer covers, and a producer stream drops what the tenant views have all absorbed. What is
/// common — whole segments only, never the newest, never the envelopes — is here.
pub fn sweep(store: &EventStore, scope: &Scope, through: u64) -> Result<Swept> {
    let directory = store.scope_path(scope)?;
    let segments = segments_in(&directory)?;
    let mut swept = Swept::default();

    for (index, (first, path)) in segments.iter().enumerate() {
        // Never the newest: it is the one being appended to, and a segment that is still growing
        // has no settled end to compare against.
        if index + 1 == segments.len() {
            break;
        }
        let Some((next_first, _)) = segments.get(index + 1) else {
            break;
        };
        // A segment ends where the next begins. Removing it is only safe when everything it holds
        // is at or below the boundary the caller named.
        if next_first.saturating_sub(1) > through {
            break;
        }
        let held = lines_in(path)?;
        fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
        swept.segments += 1;
        swept.records += held;
        let _ = first;
    }

    if swept.segments > 0 {
        // The index names positions inside the segments that are gone. Rebuilt rather than edited,
        // so an entry can never point past a file that no longer exists.
        super::store::rebuild_index(&directory)?;
    }

    Ok(swept)
}

/// Every tenant view this store holds, as `(zone, ledger)`.
///
/// Read off the filesystem rather than from what this process has served: a sweep has to reach a
/// ledger nothing has asked about since the plane came up, which is exactly the ledger most likely
/// to be over its window.
fn tenants(store: &EventStore) -> Result<Vec<(String, String)>> {
    let mut found = Vec::new();
    let views = store.root().join("views");
    let Ok(zones) = fs::read_dir(&views) else {
        return Ok(found);
    };
    for zone in zones {
        let zone = zone.with_context(|| format!("listing {}", views.display()))?;
        if !zone.path().is_dir() {
            continue;
        }
        let Ok(name) = zone.file_name().into_string() else {
            continue;
        };
        let Ok(ledgers) = fs::read_dir(zone.path()) else {
            continue;
        };
        for ledger in ledgers {
            let ledger = ledger.with_context(|| format!("listing {}", zone.path().display()))?;
            if !ledger.path().is_dir() {
                continue;
            }
            if let Ok(held) = ledger.file_name().into_string() {
                found.push((name.clone(), held));
            }
        }
    }

    Ok(found)
}

/// The highest sequence in `scope` whose segment is older than `keep`.
///
/// Age is a property of the file and sequence is what [`sweep`] takes, so this is where the two
/// meet. Deliberately conservative: a segment is only past the window when the one after it starts,
/// because a segment still being appended to has no settled end.
fn sequence_older_than(store: &EventStore, scope: &Scope, keep: Duration) -> Result<u64> {
    let directory = store.scope_path(scope)?;
    let segments = segments_in(&directory)?;
    let now = SystemTime::now();
    let mut through = 0;

    for (index, (_, path)) in segments.iter().enumerate() {
        let Some((next_first, _)) = segments.get(index + 1) else {
            break;
        };
        let metadata = fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
        let age = metadata
            .modified()
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .unwrap_or_default();
        if age < keep {
            break;
        }
        through = next_first.saturating_sub(1);
    }

    Ok(through)
}

/// One pass over every tenant view this store holds.
pub fn sweep_once(store: &EventStore, keep: Duration) -> Result<Swept> {
    let mut swept = Swept::default();
    for (zone, ledger) in tenants(store)? {
        let scope = Scope::Tenant { zone, ledger };
        let through = sequence_older_than(store, &scope, keep)?;
        if through == 0 {
            continue;
        }
        let held = sweep(store, &scope, through)?;
        swept.segments += held.segments;
        swept.records += held.records;
    }

    Ok(swept)
}

/// The periodic sweep, beside the store it keeps in bounds.
///
/// # Why this exists
///
/// [`sweep`] was written and nothing ever called it. A retention window that no schedule enforces
/// is a number in a configuration file: the store grew without bound, and the setting that claimed
/// to bound it was read at startup and never used again. A deployment would discover the gap when
/// the volume filled.
pub struct EventRetentionService {
    /// A cadence override, for a test that cannot wait for a configured day.
    every: Option<Duration>,
    running: std::sync::Mutex<Option<Running>>,
}

struct Running {
    task: tokio::task::JoinHandle<()>,
    stop: tokio::sync::watch::Sender<bool>,
}

impl Default for EventRetentionService {
    fn default() -> Self {
        Self::new()
    }
}

impl EventRetentionService {
    /// Builds the service that keeps the event store inside its retention.
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

impl permguard_core::Service for EventRetentionService {
    fn name(&self) -> &'static str {
        "event-retention"
    }

    fn start<'a>(
        &'a self,
        context: &'a permguard_core::ServerContext<'a>,
    ) -> permguard_core::BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let config = context.config();
            if !config.event_store_enabled() || !config.experimental_dogwood() {
                return Ok(());
            }
            let directory = config.event_store_directory();
            let keep = config.event_store_retention();
            // The same cadence rule the decision store uses: a twelfth of the window, bounded, so
            // "records leave on a schedule" is true rather than approximately true, without
            // walking a ninety-day store hourly.
            let every = self.every.unwrap_or_else(|| {
                (keep / 12).clamp(Duration::from_secs(300), Duration::from_secs(6 * 3600))
            });
            tracing::info!(
                event.name = "events.retaining",
                component = "control-plane",
                retention.seconds = keep.as_secs(),
                interval.seconds = every.as_secs(),
                "event segments older than the retention window will leave"
            );

            let (stop, mut stopped) = tokio::sync::watch::channel(false);
            let task = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        // One interval away, not at start: a plane that has just come up is the
                        // worst moment to walk a store.
                        _ = tokio::time::sleep(every) => {
                            let directory = directory.clone();
                            let swept = tokio::task::spawn_blocking(move || {
                                let store = EventStore::open(&directory)?;
                                sweep_once(&store, keep)
                            })
                            .await;
                            match swept {
                                Ok(Ok(swept)) if swept.segments > 0 => tracing::info!(
                                    event.name = "events.swept",
                                    component = "control-plane",
                                    segments = swept.segments,
                                    records = swept.records,
                                    "event segments left on the retention schedule"
                                ),
                                Ok(Err(error)) => tracing::warn!(
                                    event.name = "events.sweep_failed",
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
