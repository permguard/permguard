// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The origins' history the member Host imported (WP-6.2c2b1, owner decisions of 2026-10-19).
//!
//! ```text
//! the Host's consumer of data/events      the origins' runs, verbatim, and the import's state
//!   ─▶ planes/data/temporal/<zone>/<ledger>/imported/<origin>/<run>/indexes
//!        the positions by type, history, action, kind and time: rebuildable, caught up from
//!        the consumer before a shared decision reads its window
//! ```
//!
//! The plane keeps no imported record: every read goes to the consumer. It keeps where each record
//! is, per origin and run, as it does for its own stream since WP-6.2a, so a decision reads its
//! window and never the whole imported history. What freshness and completeness are measured from
//! is the Host's: the checkpoint it last verified, when, and the gaps it keeps.
//!
//! The floor registered on the consumer is the last sequence of each imported run no loaded window
//! reads any more; a run not measured is kept whole.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use permguard_core::authz::Resource;
use permguard_events::index::{Index, JournalError, Located, Query};
use permguard_host::composition::{StreamConsumer, StreamFloor};
use permguard_host::membership::import::{Checkpoint, State};
use serde_json::Value;

/// The most records one read of the consumer takes.
const READ_PAGE: usize = 1024;

/// The widest gap between two wanted sequences a scan reads across rather than skipping.
const SCAN_GAP: u64 = 64;

/// Below a ledger's plane-side directory, where the imported runs are indexed.
const IMPORTED_DIR: &str = "imported";

fn io(error: impl std::fmt::Display) -> JournalError {
    JournalError::Io(error.to_string())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The floor this plane registers on the consumer of `data/events`: per resource and run, the
/// last sequence no loaded window reads any more, as the plane last measured it.
#[derive(Debug, Default)]
pub struct ImportFloors(Mutex<BTreeMap<(String, [u8; 16]), u64>>);

impl StreamFloor for ImportFloors {
    fn retention_safe(&self, resource: &str, run: &[u8; 16]) -> Option<u64> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(resource.to_owned(), *run))
            .copied()
    }
}

/// One imported run's index, and what it covers, kept so a decision does not walk it.
struct Run {
    index: Index,
    /// The last sequence indexed.
    covered: u64,
    /// The first sequence the index still names: what the consumer pruned below is forgotten.
    forgotten_below: u64,
}

/// One ledger's imported runs, by `(origin, run)`.
struct Ledger {
    resource: Resource,
    directory: PathBuf,
    runs: BTreeMap<([u8; 16], [u8; 16]), Run>,
}

/// One ledger's imported runs, shared by the reads and the floor's measure.
type OpenLedger = Arc<Mutex<Ledger>>;

/// What a shared decision knows of a ledger's imported history.
#[derive(Debug, Clone, Default)]
pub struct Shared {
    /// The Host's import state: the checkpoint it last verified, when, and its gaps.
    pub state: Option<State>,
    /// That checkpoint's claims, read again from what the Host kept.
    pub checkpoint: Option<Checkpoint>,
    /// Each run the checkpoint names past what the consumer holds:
    /// `(origin, run, held, checkpointed)`.
    pub behind: Vec<([u8; 16], [u8; 16], u64, u64)>,
    /// What the plane has indexed of every imported run: a rebuild's invalidation mark.
    pub watermark: String,
    /// Every imported run the consumer holds, other than this Host's own, with the gaps the Host
    /// recorded for it: the exact vector frontier a decision cites (WP-6.4a), sorted.
    pub frontier: Vec<permguard_core::frontier::FrontierRun>,
    /// The required origins: those the verified checkpoint names, other than this Host, in hex,
    /// sorted.
    pub required: Vec<String>,
}

/// The imported history this plane reads.
pub struct Imported {
    consumer: StreamConsumer,
    host_id: [u8; 16],
    /// `planes/data/temporal`.
    root: PathBuf,
    floors: Arc<ImportFloors>,
    ledgers: Mutex<BTreeMap<(String, String), OpenLedger>>,
}

impl Imported {
    /// The imported history of `consumer`, this Host's own runs excluded, indexed under `root`;
    /// the floor is registered on the consumer, so a consumer that keeps none refuses.
    pub fn new(
        consumer: StreamConsumer,
        host_id: [u8; 16],
        root: PathBuf,
    ) -> Result<Self, JournalError> {
        let floors = Arc::new(ImportFloors::default());
        consumer
            .retain_above(Arc::clone(&floors) as Arc<dyn StreamFloor>)
            .map_err(|error| {
                JournalError::Io(format!(
                    "the Host's event consumer keeps no floor, so it would delete imported history \
                     a loaded window still reads: {error}"
                ))
            })?;
        Ok(Self {
            consumer,
            host_id,
            root,
            floors,
            ledgers: Mutex::new(BTreeMap::new()),
        })
    }

    fn ledger(&self, zone: &str, ledger: &str) -> Arc<Mutex<Ledger>> {
        let mut held = self.ledgers.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(
            held.entry((zone.to_owned(), ledger.to_owned()))
                .or_insert_with(|| {
                    Arc::new(Mutex::new(Ledger {
                        resource: Resource::ledger("data", zone, ledger),
                        directory: super::host::directory(&self.root, zone, ledger)
                            .join(IMPORTED_DIR),
                        runs: BTreeMap::new(),
                    }))
                }),
        )
    }

    /// Indexes what the consumer holds of every imported run of the ledger past what is indexed,
    /// and forgets what it no longer holds.
    fn catch_up(&self, ledger: &mut Ledger) -> Result<(), JournalError> {
        let held: Vec<_> = self
            .consumer
            .runs(&ledger.resource)
            .map_err(io)?
            .into_iter()
            .filter(|run| run.producer != self.host_id)
            .collect();
        // A run the consumer no longer holds names nothing readable (after the review).
        ledger.runs.retain(|(origin, run), _| {
            held.iter()
                .any(|kept| kept.producer == *origin && kept.run == *run)
        });
        for run in held {
            let key = (run.producer, run.run);
            // An index ahead of what the consumer holds, a consumer restored to an older state,
            // describes records that are not there: rebuilt from the consumer, the authority.
            if ledger
                .runs
                .get(&key)
                .is_some_and(|indexed| indexed.covered > run.acked)
                && let Some(mut stale) = ledger.runs.remove(&key)
            {
                stale.index.reset()?;
            }
            if !ledger.runs.contains_key(&key) {
                let directory = ledger
                    .directory
                    .join(hex(&run.producer))
                    .join(hex(&run.run));
                std::fs::create_dir_all(&directory).map_err(io)?;
                // A missing or damaged index is rebuilt from the consumer, the authority.
                let (mut index, loaded) = Index::detached(&directory)?;
                if !loaded {
                    index.reset()?;
                }
                let mut covered = index.covered_through();
                if covered > run.acked {
                    index.reset()?;
                    covered = 0;
                }
                ledger.runs.insert(
                    key,
                    Run {
                        index,
                        covered,
                        forgotten_below: 1,
                    },
                );
            }
            let Some(indexed) = ledger.runs.get_mut(&key) else {
                continue;
            };
            if run.oldest_retained > indexed.forgotten_below {
                indexed.index.forget_below(run.oldest_retained)?;
                indexed.forgotten_below = run.oldest_retained;
            }
            let mut next = indexed.covered.max(run.oldest_retained.saturating_sub(1)) + 1;
            let mut staged = false;
            while next <= run.acked {
                let page = self
                    .consumer
                    .records(&ledger.resource, &run.producer, &run.run, next, READ_PAGE)
                    .map_err(io)?;
                if page.records.is_empty() {
                    break;
                }
                for (seq, bytes) in &page.records {
                    let value: Value = serde_json::from_slice(bytes).map_err(|error| {
                        JournalError::Corrupt(format!("an imported event record: {error}"))
                    })?;
                    let Some((mut entry, _)) = permguard_events::index::entry_of(&value, 0, 0, 0)
                    else {
                        return Err(JournalError::Corrupt(
                            "an imported event record the index cannot place".to_owned(),
                        ));
                    };
                    // The run's own sequence: one index per run.
                    entry.seq = *seq;
                    indexed.index.stage(
                        entry,
                        Located {
                            seq: *seq,
                            segment: 0,
                            offset: 0,
                            length: 0,
                        },
                    )?;
                    staged = true;
                    next = seq + 1;
                }
            }
            if staged {
                indexed.index.sync()?;
                indexed.covered = next - 1;
            }
        }
        Ok(())
    }

    /// The imported records a temporal question needs, every imported run's index scanned.
    ///
    /// With `bound`, no further than the frontier a decision captured (WP-6.4a, after the review):
    /// a run it does not name is not read, and a run it names is read through its
    /// `covered_through`, so the replay ranges over exactly what the decision cites.
    pub fn window(
        &self,
        zone: &str,
        ledger: &str,
        query: &Query,
        bound: Option<&[permguard_core::frontier::FrontierRun]>,
    ) -> Result<Vec<Value>, JournalError> {
        let held = self.ledger(zone, ledger);
        let mut held = held.lock().unwrap_or_else(PoisonError::into_inner);
        self.catch_up(&mut held)?;
        let mut found = Vec::new();
        for ((origin, run), indexed) in &held.runs {
            let through = match bound {
                None => u64::MAX,
                Some(bound) => match bound
                    .iter()
                    .find(|named| named.origin == hex(origin) && named.run == hex(run))
                {
                    Some(named) => named.covered_through,
                    None => continue,
                },
            };
            let mut seqs: Vec<u64> = indexed
                .index
                .scan(query)
                .into_iter()
                .map(|located| located.seq)
                .filter(|seq| *seq <= through)
                .collect();
            seqs.sort_unstable();
            let mut at = 0;
            while at < seqs.len() {
                // Sequences close enough together are read in one page; what lies between two far
                // apart is not read.
                let first = seqs[at];
                let mut last = first;
                for next in &seqs[at + 1..] {
                    if next - last > SCAN_GAP || next - first >= READ_PAGE as u64 {
                        break;
                    }
                    last = *next;
                }
                let limit = usize::try_from(last - first + 1).unwrap_or(READ_PAGE);
                let page = self
                    .consumer
                    .records(&held.resource, origin, run, first, limit)
                    .map_err(io)?;
                // A record the index names and the consumer does not answer is history this
                // decision would run without: refused rather than read short (after the review).
                let returned: Vec<u64> = page.records.iter().map(|(seq, _)| *seq).collect();
                if let Some(missing) = seqs[at..]
                    .iter()
                    .take_while(|seq| **seq <= last)
                    .find(|seq| returned.binary_search(seq).is_err())
                {
                    return Err(JournalError::Corrupt(format!(
                        "the imported run {} of {} does not hold sequence {missing}, which its \
                         index names",
                        hex(run),
                        hex(origin)
                    )));
                }
                let read_through = last;
                for (seq, bytes) in page.records {
                    if seqs.binary_search(&seq).is_ok() {
                        found.push(serde_json::from_slice(&bytes).map_err(|error| {
                            JournalError::Corrupt(format!("an imported event record: {error}"))
                        })?);
                    }
                }
                while at < seqs.len() && seqs[at] <= read_through {
                    at += 1;
                }
            }
        }
        Ok(found)
    }

    /// What a shared decision knows of the ledger's imported history now.
    pub fn shared(&self, zone: &str, ledger: &str) -> Result<Shared, JournalError> {
        let held = self.ledger(zone, ledger);
        let mut held = held.lock().unwrap_or_else(PoisonError::into_inner);
        self.catch_up(&mut held)?;
        let state = self.consumer.import_state(&held.resource).map_err(io)?;
        // The checkpoint as the Host kept it after verifying it: read for its claims. One that
        // does not read, or names another ledger or origin set, vouches for nothing (after the
        // review): refused, never read as no run behind.
        let checkpoint = match &state {
            None => None,
            Some(state) => {
                let read = permguard_objects::cose::Sign1::decode(&state.checkpoint)
                    .ok()
                    .and_then(|sign1| Checkpoint::decode(sign1.payload_unverified()).ok())
                    .ok_or_else(|| {
                        JournalError::Corrupt(
                            "the Host's import state holds a checkpoint that does not read"
                                .to_owned(),
                        )
                    })?;
                if read.resource != held.resource.to_string() || read.revision != state.revision {
                    return Err(JournalError::Corrupt(
                        "the Host's import state holds a checkpoint of another ledger or origin \
                         set"
                        .to_owned(),
                    ));
                }
                Some(read)
            }
        };
        let runs = self.consumer.runs(&held.resource).map_err(io)?;
        // The frontier is what the plane indexed — what a decision can read — of every imported
        // run, and of every run the checkpoint names or a gap cites that it holds nothing of, at
        // zero (WP-6.4a, after the review). Sorted by origin and run.
        // `catch_up` never indexes this Host's own runs, so the index holds imported runs only.
        let mut named: BTreeMap<([u8; 16], [u8; 16]), (u64, u64)> = held
            .runs
            .iter()
            .map(|(key, indexed)| {
                // Caught up through what it indexed, or through the last sequence below what the
                // run still retains, which there is nothing left to read of.
                let through = indexed
                    .covered
                    .max(indexed.forgotten_below.saturating_sub(1));
                (*key, (through, indexed.forgotten_below))
            })
            .collect();
        if let Some(checkpoint) = &checkpoint {
            for origin in checkpoint
                .origins
                .iter()
                .filter(|origin| origin.host_id != self.host_id)
            {
                for run in &origin.runs {
                    named.entry((origin.host_id, run.run)).or_insert((0, 0));
                }
            }
        }
        if let Some(state) = &state {
            for gap in state.gaps.iter().filter(|gap| gap.origin != self.host_id) {
                named.entry((gap.origin, gap.run)).or_insert((0, 0));
            }
        }
        let frontier: Vec<permguard_core::frontier::FrontierRun> = named
            .into_iter()
            .map(|((origin, run), (covered_through, low_watermark))| {
                permguard_core::frontier::FrontierRun {
                    origin: hex(&origin),
                    run: hex(&run),
                    covered_through,
                    low_watermark,
                    gaps: state
                        .as_ref()
                        .map(|state| {
                            state
                                .gaps
                                .iter()
                                .filter(|gap| gap.origin == origin && gap.run == run)
                                .map(|gap| permguard_core::frontier::FrontierGap {
                                    from: gap.from,
                                    through: gap.through,
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                }
            })
            .collect();
        let mut required: Vec<String> = checkpoint
            .as_ref()
            .map(|checkpoint| {
                checkpoint
                    .origins
                    .iter()
                    .filter(|origin| origin.host_id != self.host_id)
                    .map(|origin| hex(&origin.host_id))
                    .collect()
            })
            .unwrap_or_default();
        required.sort();
        required.dedup();
        let mut behind = Vec::new();
        if let Some(checkpoint) = &checkpoint {
            for origin in checkpoint
                .origins
                .iter()
                .filter(|origin| origin.host_id != self.host_id)
            {
                for named in &origin.runs {
                    let have = runs
                        .iter()
                        .find(|run| run.producer == origin.host_id && run.run == named.run)
                        .map_or(0, |run| run.acked);
                    if have < named.acked {
                        behind.push((origin.host_id, named.run, have, named.acked));
                    }
                }
            }
        }
        let watermark = held
            .runs
            .iter()
            .map(|((origin, run), indexed)| {
                format!("{}:{}:{}", hex(origin), hex(run), indexed.covered)
            })
            .collect::<Vec<_>>()
            .join(",");
        Ok(Shared {
            state,
            checkpoint,
            behind,
            watermark,
            frontier,
            required,
        })
    }

    /// Measures, for every imported run of every ledger read so far, the last sequence observed
    /// before `horizon` (epoch seconds), counted contiguously from what the run still holds: what a
    /// loaded window no longer reads, which the consumer may delete.
    pub fn refresh_floors(&self, horizon: i64) -> Result<(), JournalError> {
        // Every ledger the consumer holds, whether a decision read it or not (after the review):
        // one nobody reads still gets its floor from the horizon.
        for resource in self.consumer.resources().map_err(io)? {
            if let Resource::Ledger {
                plane,
                zone_id,
                ledger_id,
            } = &resource
                && plane == "data"
            {
                self.ledger(zone_id, ledger_id);
            }
        }
        let ledgers: Vec<Arc<Mutex<Ledger>>> = self
            .ledgers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect();
        for held in ledgers {
            let mut held = held.lock().unwrap_or_else(PoisonError::into_inner);
            self.catch_up(&mut held)?;
            let runs = self.consumer.runs(&held.resource).map_err(io)?;
            let resource = held.resource.to_string();
            for run in runs.iter().filter(|run| run.producer != self.host_id) {
                let Some(indexed) = held.runs.get(&(run.producer, run.run)) else {
                    continue;
                };
                let mut occurred: BTreeMap<u64, i64> = BTreeMap::new();
                for (key, located) in indexed.index.entries() {
                    occurred.insert(located.seq, key.occurred_at);
                }
                let mut through = run.oldest_retained.saturating_sub(1);
                for seq in run.oldest_retained.max(1)..=run.acked {
                    match occurred.get(&seq) {
                        Some(at) if *at < horizon => through = seq,
                        _ => break,
                    }
                }
                self.floors
                    .0
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert((resource.clone(), run.run), through);
            }
        }
        Ok(())
    }
}

/// The logical occurrences of `records`, merged from this plane's own stream and the imported
/// origins, in the deterministic order (owner decision of 2026-10-18, `5-data-plane-temporal.md`):
/// one key is a trusted source and the `event_id`. Equal digests apply once, the first in order
/// kept; different digests are a conflict, and the occurrence is quarantined from shared
/// decisions: every copy of it is left out. A record with no `source`, or the anonymous one,
/// keys by its origin instead (owner decision of 2026-10-19): an identity nobody vouched for
/// never collapses nor quarantines another origin's occurrence. Answers the records kept and how
/// many were quarantined.
pub fn deduplicated(mut records: Vec<Value>) -> (Vec<Value>, usize) {
    records.sort_by_key(super::imports::order_of);
    let key_of = |record: &Value| {
        let event_id = record
            .get("event_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        match record.get("source").and_then(Value::as_str) {
            Some(source)
                if !source.is_empty()
                    && source != permguard_core::authz::Principal::anonymous().as_str() =>
            {
                (format!("source:{source}"), event_id)
            }
            _ => (
                format!(
                    "origin:{}",
                    record
                        .get("stream")
                        .and_then(|stream| stream.get("producer"))
                        .and_then(|producer| producer.get("id"))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                ),
                event_id,
            ),
        }
    };
    let digest_of = |record: &Value| {
        record
            .get("occurrence_digest")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let mut seen: BTreeMap<(String, String), String> = BTreeMap::new();
    let mut conflicting: std::collections::BTreeSet<(String, String)> =
        std::collections::BTreeSet::new();
    for record in &records {
        let key = key_of(record);
        let digest = digest_of(record);
        match seen.get(&key) {
            Some(held) if *held != digest => {
                conflicting.insert(key);
            }
            Some(_) => {}
            None => {
                seen.insert(key, digest);
            }
        }
    }
    let mut kept = Vec::with_capacity(records.len());
    let mut applied: std::collections::BTreeSet<(String, String)> =
        std::collections::BTreeSet::new();
    for record in records {
        let key = key_of(&record);
        if conflicting.contains(&key) || !applied.insert(key) {
            continue;
        }
        kept.push(record);
    }
    (kept, conflicting.len())
}

#[cfg(test)]
mod tests;
