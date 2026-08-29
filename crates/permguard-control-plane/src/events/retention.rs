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

use std::collections::BTreeMap;
use std::fs;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use base64::Engine as _;

use super::store::{EventStore, Scope, lines_in, segments_in};

/// The highest removed sequence for every producer stream represented in a tenant-view prefix.
type ProducerFrontiers = BTreeMap<String, (permguard_events::Stream, u64)>;

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
    sweep_prefix(store, scope, through).map(|(swept, _)| swept)
}

/// Removes a prefix and, for a merged view, remembers the producer frontier that disappeared.
///
/// The producer copies may leave only after the tenant copy has left. Returning the exact streams
/// found in the removed view prefix makes that ordering explicit and avoids an independent
/// age-based sweep racing ahead of the view it is meant to back.
fn sweep_prefix(
    store: &EventStore,
    scope: &Scope,
    through: u64,
) -> Result<(Swept, ProducerFrontiers)> {
    let directory = store.scope_path(scope)?;
    let segments = segments_in(&directory)?;
    let mut swept = Swept::default();
    let mut producers = ProducerFrontiers::new();

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
        if matches!(scope, Scope::Tenant { .. }) {
            let text = fs::read_to_string(path)
                .with_context(|| format!("reading {} before retention", path.display()))?;
            for (number, line) in text.lines().filter(|line| !line.is_empty()).enumerate() {
                let record: serde_json::Value = serde_json::from_str(line).with_context(|| {
                    format!(
                        "reading retained record {} of {}",
                        number + 1,
                        path.display()
                    )
                })?;
                let stream: permguard_events::Stream = serde_json::from_value(
                    record
                        .get("stream")
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("an event record has no stream"))?,
                )
                .with_context(|| format!("reading a stream from {}", path.display()))?;
                let sequence = record
                    .get("seq")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| anyhow::anyhow!("an event record has no sequence"))?;
                let key = Scope::for_stream(&stream).key();
                producers
                    .entry(key)
                    .and_modify(|(_, held)| *held = (*held).max(sequence))
                    .or_insert((stream, sequence));
            }
        }
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

    Ok((swept, producers))
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
        let gate = store.scope_gate(&scope);
        let (held, producers) = {
            let _maintenance = match gate.lock() {
                Ok(held) => held,
                Err(poisoned) => poisoned.into_inner(),
            };
            let through = sequence_older_than(store, &scope, keep)?;
            if through == 0 {
                continue;
            }
            sweep_prefix(store, &scope, through)?
        };
        swept.segments += held.segments;
        swept.records += held.records;

        // Lock ordering matters: ingest holds stream then view. The view guard above is released
        // before any stream guard is taken, so retention cannot deadlock an ingest. A new append
        // between the two is harmless because every boundary below names only the old prefix.
        for (_, (stream, through)) in producers {
            let stream_scope = Scope::for_stream(&stream);
            let stream_gate = store.scope_gate(&stream_scope);
            let _maintenance = match stream_gate.lock() {
                Ok(held) => held,
                Err(poisoned) => poisoned.into_inner(),
            };
            let through = proof_safe_through(store, &stream, through)?;
            let removed = sweep(store, &stream_scope, through)?;
            swept.segments += removed.segments;
            swept.records += removed.records;
        }
    }

    Ok(swept)
}

/// A retained record's Merkle path needs every leaf of the signed batch that covers it.
///
/// Producer records are therefore kept back to the first sequence of the batch containing the
/// first retained sequence, even when the tenant view has already dropped those earlier leaves.
/// Once the whole batch leaves the view, its producer prefix becomes eligible on a later sweep.
fn proof_safe_through(
    store: &EventStore,
    stream: &permguard_events::Stream,
    proposed: u64,
) -> Result<u64> {
    let next = proposed.saturating_add(1);
    let Some(signed) = store.envelope_covering(stream, next)? else {
        return Ok(proposed);
    };
    let payload = signed
        .get("payload")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("a retained event batch has no payload"))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .context("decoding a retained event batch")?;
    let envelope: permguard_events::envelope::Envelope =
        serde_json::from_slice(&bytes).context("reading a retained event batch")?;
    if envelope.stream != *stream || !(envelope.first_seq..=envelope.last_seq).contains(&next) {
        anyhow::bail!(
            "the retained envelope selected for sequence {next} does not cover that producer"
        );
    }

    Ok(proposed.min(envelope.first_seq.saturating_sub(1)))
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
    store: Option<std::sync::Arc<std::sync::Mutex<Option<std::sync::Arc<EventStore>>>>>,
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
            store: None,
            running: std::sync::Mutex::new(None),
        }
    }

    /// Sweeps at a fixed cadence regardless of configuration.
    pub fn every(mut self, tick: Duration) -> Self {
        self.every = Some(tick);

        self
    }

    /// Uses the store already composed for HTTP and gRPC. Opening the directory again would fail
    /// its exclusive writer lock, so retention is a peer of the surfaces, not a second owner.
    pub fn with_store(
        mut self,
        store: std::sync::Arc<std::sync::Mutex<Option<std::sync::Arc<EventStore>>>>,
    ) -> Self {
        self.store = Some(store);

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
            let shared = self.store.clone();
            let task = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        // One interval away, not at start: a plane that has just come up is the
                        // worst moment to walk a store.
                        _ = tokio::time::sleep(every) => {
                            let store = shared.as_ref().and_then(|shared| {
                                shared.lock().ok().and_then(|held| held.clone())
                            });
                            let swept = tokio::task::spawn_blocking(move || {
                                let Some(store) = store else {
                                    anyhow::bail!(
                                        "the event store has not been composed for its serving \
                                         surfaces"
                                    );
                                };
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
