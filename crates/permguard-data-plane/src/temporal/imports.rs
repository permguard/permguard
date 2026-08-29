// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Where imported history lives, and why it is not the journal.
//!
//! # Two stores, on purpose
//!
//! ```text
//! data/events/<zone>/<ledger>/          what this plane recorded — its own signed chain
//! data/events/pull/<zone>/<ledger>/     what it imported — somebody else's, kept as theirs
//! ```
//!
//! An imported record is evidence another producer created. Putting it in this plane's journal
//! would place it inside this plane's own sequence and hash chain, which would be a claim that this
//! plane recorded it — and the next batch this plane signed would attest that claim. So imports
//! live beside the journal, keep their origin identity, and are never shipped.
//!
//! # Deduplication, twice, because there are two kinds of duplicate
//!
//! By **origin position** `(class, producer, instance, sequence)`: the same record arriving twice,
//! because a cursor was replayed or a page overlapped. Cheap, exact, and it is what makes the pull
//! loop safe to retry.
//!
//! By **logical occurrence** `(zone, ledger, event_id, occurrence_digest)`: the *same* client
//! request that reached two data planes, each of which recorded it in its own stream. Those are two
//! legitimate records of one thing, and a temporal policy counting occurrences must count it once.
//! Neither record is deleted — both are evidence — but only the first is observed.
//!
//! The two are separate because collapsing them would be wrong in both directions: two records at
//! one origin position is a fork, and one occurrence at two origin positions is normal.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The file a subscription's cursor lives in.
pub const STATE_FILE: &str = "STATE";
/// The file imported records are appended to.
pub const RECORDS_FILE: &str = "imported.events";

/// Where one subscription stands.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    /// The opaque offset the control plane last returned.
    ///
    /// Opaque here too: this plane echoes it and never parses it, because the frontier it stands
    /// for spans several producers and has no single number to compare.
    #[serde(default)]
    pub offset: String,
    /// When the last successful read completed, as a canonical instant.
    ///
    /// What `shared-bounded` measures staleness against. Written on every advance, including one
    /// that imported nothing — a plane that is caught up is fresh, not stale.
    #[serde(default)]
    pub read_at: String,
    /// How many records have been imported here in total.
    #[serde(default)]
    pub imported: u64,
    /// How many origin positions were skipped as already held.
    #[serde(default)]
    pub duplicates: u64,
    /// How many were skipped as the same logical occurrence recorded by another plane.
    #[serde(default)]
    pub logical_duplicates: u64,
    /// The holes in this imported history, oldest first.
    ///
    /// Persisted, and persisted *here*, because a gap is a property of the history and not of the
    /// process that noticed it: a restart that forgot its gaps would present an incomplete history
    /// as a complete one, which is the single thing a temporal store must never do.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gaps: Vec<Gap>,
}

/// A stretch of another plane's history this one will never hold.
///
/// # Why it is kept rather than logged
///
/// When the control plane no longer holds the position a subscription stood at, the records in
/// between are gone for this plane for good. Resuming from the oldest still held keeps the
/// subscription working — and leaves it looking exactly like one that never missed anything. A
/// decision made against that history would be made against fewer occurrences than actually
/// happened, and nothing in the answer would say so.
///
/// So the hole is a durable fact with a shape: what was lost, whose it was, when it was noticed,
/// and under which consistency mode. `shared-bounded` refuses to decide until it is resolved
/// explicitly; `shared-eventual` decides and says it is degraded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gap {
    /// The zone whose history has the hole.
    pub zone: String,
    /// The ledger whose history has the hole.
    pub ledger: String,
    /// The origin sequence this plane stood at, which is the first thing it lost.
    pub from_sequence: u64,
    /// The oldest sequence the control plane still held: everything below it is lost.
    pub to_sequence: u64,
    /// When the hole was noticed, as a canonical instant.
    pub at: String,
    /// The consistency mode in force when it was noticed.
    pub consistency: String,
    /// Whether an operator has accepted it.
    ///
    /// Never set by the plane itself. A hole does not stop being a hole because time passed, and a
    /// history that healed itself by waiting is one nobody can reason about.
    #[serde(default)]
    pub resolved: bool,
}

/// Rebuilds an import index from the records file it is derived from.
fn rebuild_index(index: &mut permguard_events::index::Index, path: &Path) -> Result<()> {
    index
        .reset()
        .map_err(|error| anyhow!("clearing the import index: {error}"))?;
    let Some(text) = read_records(path)? else {
        return Ok(());
    };
    let mut offset = 0u64;
    for line in text.split_inclusive('\n') {
        let length = line.len() as u64;
        let trimmed = line.strip_suffix('\n').unwrap_or(line);
        if !trimmed.trim().is_empty() {
            let imported: Imported = serde_json::from_str(trimmed).with_context(|| {
                format!(
                    "rebuilding the import index at byte {offset} of {}",
                    path.display()
                )
            })?;
            if let Some((key, located)) =
                permguard_events::index::entry_of(&imported.record, 0, offset, length)
            {
                index
                    .stage(key, located)
                    .map_err(|error| anyhow!("rebuilding the import index: {error}"))?;
            }
        }
        offset += length;
    }
    index
        .sync()
        .map_err(|error| anyhow!("flushing the import index: {error}"))?;

    Ok(())
}

/// Reads the record file, or says it is not there.
///
/// `None` means the subscription has imported nothing yet, which is a legitimate empty history.
/// Every *other* failure — a permission, a bad disk, a truncated read — is an error and not an
/// empty history. Collapsing them was the dangerous shape: a plane that could not read what it had
/// imported would decide against an empty history and answer as though the events had never
/// happened.
fn read_records(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("reading the imported history {}", path.display()))
        }
    }
}

/// One subscription's write gate, held for the whole of a round.
type Gate = std::sync::Arc<Mutex<()>>;

/// Every subscription's gate, by `(zone, ledger)`.
type Gates = Mutex<BTreeMap<(String, String), Gate>>;

/// The imported histories this plane holds.
pub struct Imports {
    root: PathBuf,
    /// The deduplication sets of each subscription, built once and kept in step.
    ///
    /// Rebuilding them from the file on every `absorb` made importing `n` records read the file
    /// `n` times — quadratic in exactly the case that matters, a plane catching up after being
    /// away. Held under the same per-subscription gate as the write, so the set and the file
    /// cannot disagree.
    known: Mutex<BTreeMap<(String, String), Held>>,
    /// The time-and-history index of each subscription's imported records.
    ///
    /// The same index the journal keeps, over this store's own file. Without it an evaluation read
    /// *every* imported record and filtered in memory: the local half was already a bounded range
    /// scan, so a plane in a shared mode paid the whole retained import history on every decision
    /// while its own journal cost one window. What the index buys is the same bound on both halves
    /// — one history partition, one window — rather than a filter over everything.
    indexes: Mutex<BTreeMap<(String, String), permguard_events::index::Index>>,
    /// One gate per subscription: a round reads a cursor, writes records and writes the cursor
    /// back, and two rounds interleaving that would import a page twice.
    gates: Gates,
}

impl Imports {
    /// Opens the import store under `directory`.
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            root: directory.into(),
            known: Mutex::new(BTreeMap::new()),
            indexes: Mutex::new(BTreeMap::new()),
            gates: Mutex::new(BTreeMap::new()),
        }
    }

    /// Where this store keeps everything.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn gate(&self, zone: &str, ledger: &str) -> Gate {
        let mut gates = match self.gates.lock() {
            Ok(gates) => gates,
            Err(poisoned) => poisoned.into_inner(),
        };

        std::sync::Arc::clone(
            gates
                .entry((zone.to_owned(), ledger.to_owned()))
                .or_default(),
        )
    }

    fn path(&self, zone: &str, ledger: &str) -> Result<PathBuf> {
        for segment in [zone, ledger] {
            if segment.is_empty() || segment.contains('/') || segment.contains("..") {
                return Err(anyhow!("`{segment}` is not a name this store can hold"));
            }
        }

        Ok(self.root.join(zone).join(ledger))
    }

    /// Where one subscription stands.
    pub fn state(&self, zone: &str, ledger: &str) -> Result<Cursor> {
        let path = self.path(zone, ledger)?.join(STATE_FILE);
        match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).context("reading an import cursor"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Cursor::default()),
            Err(error) => Err(error).context("reading an import cursor"),
        }
    }

    /// The offset to present next, or `None` for a subscription that has never read.
    pub fn cursor(&self, zone: &str, ledger: &str) -> Result<Option<String>> {
        let state = self.state(zone, ledger)?;

        Ok((!state.offset.is_empty()).then_some(state.offset))
    }

    /// Records that the subscription has read through `offset`.
    pub fn advance(&self, zone: &str, ledger: &str, offset: &str) -> Result<()> {
        let gate = self.gate(zone, ledger);
        let _held = match gate.lock() {
            Ok(held) => held,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut state = self.state(zone, ledger)?;
        state.offset = offset.to_owned();
        state.read_at = now();

        self.write_state(zone, ledger, &state)
    }

    /// Records a hole in this imported history, and moves the cursor past it.
    ///
    /// The two are one step on purpose: advancing without recording is what made an incomplete
    /// history indistinguishable from a complete one, and recording without advancing would leave
    /// the subscription asking for a position that will never come back.
    pub fn record_gap(&self, zone: &str, ledger: &str, offset: &str, gap: Gap) -> Result<()> {
        let gate = self.gate(zone, ledger);
        let _held = match gate.lock() {
            Ok(held) => held,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut state = self.state(zone, ledger)?;
        // One entry per hole. A round that retries the same expired offset must not turn one hole
        // into a list of them.
        let known = state.gaps.iter().any(|held| {
            held.from_sequence == gap.from_sequence && held.to_sequence == gap.to_sequence
        });
        if !known {
            state.gaps.push(gap);
        }
        state.offset = offset.to_owned();
        state.read_at = now();

        self.write_state(zone, ledger, &state)
    }

    /// The holes in one imported history that nobody has accepted yet.
    pub fn unresolved_gaps(&self, zone: &str, ledger: &str) -> Result<Vec<Gap>> {
        Ok(self
            .state(zone, ledger)?
            .gaps
            .into_iter()
            .filter(|gap| !gap.resolved)
            .collect())
    }

    /// Marks every hole in one imported history as accepted.
    ///
    /// The explicit resolution `shared-bounded` waits for. An operator states that the missing
    /// occurrences are known and the ledger may decide again; nothing about the history changes,
    /// and the gaps stay on the record.
    pub fn resolve_gaps(&self, zone: &str, ledger: &str) -> Result<usize> {
        let gate = self.gate(zone, ledger);
        let _held = match gate.lock() {
            Ok(held) => held,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut state = self.state(zone, ledger)?;
        let mut resolved = 0;
        for gap in &mut state.gaps {
            if !gap.resolved {
                gap.resolved = true;
                resolved += 1;
            }
        }
        if resolved > 0 {
            self.write_state(zone, ledger, &state)?;
        }

        Ok(resolved)
    }

    /// Absorbs one verified record, and says whether it was new here.
    ///
    /// `false` is not a failure: it is the ordinary answer for a replayed page, and for the same
    /// client request that two planes each recorded. Both are duplicates and neither is an error.
    pub fn absorb(&self, zone: &str, ledger: &str, record: &Value) -> Result<bool> {
        let gate = self.gate(zone, ledger);
        let _held = match gate.lock() {
            Ok(held) => held,
            Err(poisoned) => poisoned.into_inner(),
        };

        let origin = origin_of(record).ok_or_else(|| anyhow!("a record with no origin"))?;
        let occurrence = occurrence_of(record).ok_or_else(|| anyhow!("a record with no id"))?;
        let held = self.held(zone, ledger)?;
        let mut state = self.state(zone, ledger)?;

        if held.origins.contains(&origin) {
            state.duplicates = state.duplicates.saturating_add(1);
            self.write_state(zone, ledger, &state)?;

            return Ok(false);
        }
        if held.occurrences.contains(&occurrence) {
            // Kept as evidence, not observed twice: two planes recorded one client request, and a
            // temporal policy counting occurrences must count it once.
            state.logical_duplicates = state.logical_duplicates.saturating_add(1);
            let imported = self.append(zone, ledger, record, false)?;
            self.remember(zone, ledger, &imported);
            self.write_state(zone, ledger, &state)?;

            return Ok(false);
        }

        let imported = self.append(zone, ledger, record, true)?;
        self.remember(zone, ledger, &imported);
        state.imported = state.imported.saturating_add(1);
        self.write_state(zone, ledger, &state)?;

        Ok(true)
    }

    /// Every imported record that should be observed, oldest first.
    ///
    /// Ordered by `(occurred_at, observed_at, class, producer, instance, sequence)` — event time
    /// first, and a documented deterministic tie break after it, because there is no truthful total
    /// order across producers and inventing one would make two planes disagree about what a policy
    /// saw.
    pub fn observable(&self, zone: &str, ledger: &str) -> Result<Vec<Value>> {
        let path = self.path(zone, ledger)?.join(RECORDS_FILE);
        let Some(text) = read_records(&path)? else {
            return Ok(Vec::new());
        };
        let mut held = Vec::new();
        for (number, line) in text
            .lines()
            .enumerate()
            .filter(|(_, line)| !line.is_empty())
        {
            // Parsed, not `filter_map`ped. A line this build cannot read is a damaged history, and
            // skipping it would hand a temporal policy a history with a hole in it that nothing
            // recorded and nobody could see — the same failure the gap machinery exists to make
            // impossible, arriving through the back door.
            let imported: Imported = serde_json::from_str(line).with_context(|| {
                format!(
                    "reading the imported record at line {} of {}",
                    number + 1,
                    path.display()
                )
            })?;
            if imported.observe {
                held.push(imported.record);
            }
        }
        held.sort_by_key(order_of);

        Ok(held)
    }

    /// The one line an imported record is stored as.
    fn append(&self, zone: &str, ledger: &str, record: &Value, observe: bool) -> Result<Imported> {
        let directory = self.path(zone, ledger)?;
        fs::create_dir_all(&directory).context("creating an import directory")?;
        let imported = Imported {
            observe,
            record: record.clone(),
        };
        let line = serde_json::to_string(&imported).context("rendering an imported record")?;
        let path = directory.join(RECORDS_FILE);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .context("opening the import store")?;
        // Where this record starts, taken before it is written: the index addresses records by
        // byte offset, and an offset read afterwards would be the offset of the record after it.
        let offset = file.metadata().context("measuring the import store")?.len();
        let length = line.len() as u64 + 1;
        writeln!(file, "{line}").context("writing an imported record")?;
        // Durable before the cursor moves past it: a crash the other way round would lose a record
        // the cursor claimed to have passed.
        file.sync_all().context("flushing the import store")?;
        // And the index after the record, never before: an entry durable ahead of what it points
        // at would survive a crash the record did not, and a scan would then read a hole.
        self.index_one(zone, ledger, record, offset, length)?;

        Ok(imported)
    }

    /// Files one imported record's coordinates, so a windowed read can find it without a scan.
    fn index_one(
        &self,
        zone: &str,
        ledger: &str,
        record: &Value,
        offset: u64,
        length: u64,
    ) -> Result<()> {
        // Segment zero: this store keeps one file per subscription rather than rolling segments,
        // and the index addresses `(segment, offset)`. One file is segment zero of one.
        let Some((key, located)) = permguard_events::index::entry_of(record, 0, offset, length)
        else {
            // A record without the coordinates an index is built from is still stored — it is
            // another producer's evidence and this plane does not edit it — but it cannot be found
            // by a windowed read. Said rather than silently dropped from the index.
            anyhow::bail!(
                "an imported record carries no indexable coordinates: it has no sequence, event \
                 type, kind or occurrence time"
            );
        };
        let mut indexes = match self.indexes.lock() {
            Ok(indexes) => indexes,
            Err(poisoned) => poisoned.into_inner(),
        };
        let index = self.index_for(&mut indexes, zone, ledger)?;
        index
            .insert(key, located)
            .map_err(|error| anyhow!("indexing an imported record: {error}"))?;

        Ok(())
    }

    /// This subscription's index, loaded or rebuilt from the records it holds.
    fn index_for<'a>(
        &self,
        indexes: &'a mut BTreeMap<(String, String), permguard_events::index::Index>,
        zone: &str,
        ledger: &str,
    ) -> Result<&'a mut permguard_events::index::Index> {
        let key = (zone.to_owned(), ledger.to_owned());
        if !indexes.contains_key(&key) {
            let directory = self.path(zone, ledger)?;
            fs::create_dir_all(&directory).context("creating an import directory")?;
            let (mut index, loaded) = permguard_events::index::Index::detached(&directory)
                .map_err(|error| anyhow!("opening the import index: {error}"))?;
            if !loaded {
                // The records file is the authority; the index is derived from it. Rebuilt rather
                // than started empty, because an empty index over a non-empty store is a history
                // that reads as though nothing had been imported.
                rebuild_index(&mut index, &directory.join(RECORDS_FILE))?;
            }
            indexes.insert(key.clone(), index);
        }

        indexes
            .get_mut(&key)
            .ok_or_else(|| anyhow!("the import index vanished between insert and read"))
    }

    /// The imported records of one history inside one window, read by their coordinates.
    ///
    /// The bounded half of what an evaluation reads. The local journal was already a range scan
    /// over an index; this one used to be "load every imported record and filter", so a plane in a
    /// shared mode paid its whole retained import history on every decision.
    pub fn window(
        &self,
        zone: &str,
        ledger: &str,
        query: &permguard_events::index::Query,
    ) -> Result<Vec<Value>> {
        let path = self.path(zone, ledger)?.join(RECORDS_FILE);
        let Some(text) = read_records(&path)? else {
            return Ok(Vec::new());
        };
        let located: Vec<(u64, u64)> = {
            let mut indexes = match self.indexes.lock() {
                Ok(indexes) => indexes,
                Err(poisoned) => poisoned.into_inner(),
            };
            let index = self.index_for(&mut indexes, zone, ledger)?;

            index
                .scan(query)
                .into_iter()
                .map(|held| (held.offset, held.length))
                .collect()
        };

        let bytes = text.as_bytes();
        let mut held = Vec::with_capacity(located.len());
        for (offset, length) in located {
            let start = usize::try_from(offset).unwrap_or(usize::MAX);
            let end = start.saturating_add(usize::try_from(length).unwrap_or(0));
            let Some(line) = bytes.get(start..end.min(bytes.len())) else {
                anyhow::bail!(
                    "the import index of {} names a position the store does not hold: rebuild it",
                    path.display()
                );
            };
            let imported: Imported = serde_json::from_slice(
                line.strip_suffix(b"\n").unwrap_or(line),
            )
            .with_context(|| {
                format!(
                    "reading the imported record at byte {offset} of {}",
                    path.display()
                )
            })?;
            if imported.observe {
                held.push(imported.record);
            }
        }
        held.sort_by_key(order_of);

        Ok(held)
    }

    /// What this subscription already holds.
    fn held(&self, zone: &str, ledger: &str) -> Result<Held> {
        let key = (zone.to_owned(), ledger.to_owned());
        {
            let known = match self.known.lock() {
                Ok(known) => known,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some(held) = known.get(&key) {
                return Ok(held.clone());
            }
        }

        let path = self.path(zone, ledger)?.join(RECORDS_FILE);
        let mut held = Held::default();
        if let Some(text) = read_records(&path)? {
            for (number, line) in text
                .lines()
                .enumerate()
                .filter(|(_, line)| !line.is_empty())
            {
                let imported: Imported = serde_json::from_str(line).with_context(|| {
                    format!(
                        "reading the imported record at line {} of {}",
                        number + 1,
                        path.display()
                    )
                })?;
                held.remember(&imported);
            }
        }

        let mut known = match self.known.lock() {
            Ok(known) => known,
            Err(poisoned) => poisoned.into_inner(),
        };
        known.insert(key, held.clone());

        Ok(held)
    }

    /// Records what one newly appended import adds to the deduplication sets.
    ///
    /// Kept in step with the file rather than re-derived from it. Rebuilding the sets on every
    /// `absorb` made importing `n` records cost `n²` reads of a file that only grows — a pull loop
    /// catching up after an outage was the exact case that made it slowest.
    fn remember(&self, zone: &str, ledger: &str, imported: &Imported) {
        let mut known = match self.known.lock() {
            Ok(known) => known,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(held) = known.get_mut(&(zone.to_owned(), ledger.to_owned())) {
            held.remember(imported);
        }
    }

    fn write_state(&self, zone: &str, ledger: &str, state: &Cursor) -> Result<()> {
        let directory = self.path(zone, ledger)?;
        fs::create_dir_all(&directory).context("creating an import directory")?;
        let bytes = serde_json::to_vec_pretty(state).context("rendering an import cursor")?;
        let temporary = directory.join("STATE.writing");
        fs::write(&temporary, bytes).context("writing an import cursor")?;
        fs::rename(&temporary, directory.join(STATE_FILE)).context("writing an import cursor")?;

        Ok(())
    }
}

/// One imported record, and whether it is the one to observe.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Imported {
    /// `false` for the second copy of one logical occurrence: kept as evidence, observed once.
    observe: bool,
    record: Value,
}

/// What a subscription already holds, by both kinds of identity.
#[derive(Debug, Default, Clone)]
struct Held {
    origins: std::collections::BTreeSet<(String, String, String, u64)>,
    occurrences: std::collections::BTreeSet<(String, String)>,
}

impl Held {
    /// Files one imported record into the sets a later duplicate is recognised by.
    fn remember(&mut self, imported: &Imported) {
        if let Some(origin) = origin_of(&imported.record) {
            self.origins.insert(origin);
        }
        // Only an observed record contributes a logical occurrence: one kept purely as another
        // plane's evidence was already counted through the record that *was* observed.
        if imported.observe
            && let Some(occurrence) = occurrence_of(&imported.record)
        {
            self.occurrences.insert(occurrence);
        }
    }
}

/// The origin position of a record: which producer wrote it, and where.
fn origin_of(record: &Value) -> Option<(String, String, String, u64)> {
    let producer = record.get("stream")?.get("producer")?;

    Some((
        producer.get("class")?.as_str()?.to_owned(),
        producer.get("id")?.as_str()?.to_owned(),
        producer.get("instance")?.as_str()?.to_owned(),
        record.get("seq")?.as_u64()?,
    ))
}

/// The logical occurrence a record is of: the caller's id, and what it actually sent.
///
/// Both, because an id alone is the caller's claim and the digest is what was claimed: the same id
/// with different content is a conflict rather than a duplicate, and treating it as one would
/// silently drop the second.
fn occurrence_of(record: &Value) -> Option<(String, String)> {
    Some((
        record.get("event_id")?.as_str()?.to_owned(),
        record.get("occurrence_digest")?.as_str()?.to_owned(),
    ))
}

/// The documented deterministic order records are observed in.
///
/// Event time first, then a deterministic tie break, because there is no truthful total order
/// across producers and inventing one would make two planes disagree about what a policy saw.
///
/// Public because it is not the import path's order — it is *the* order, and the local journal's
/// records are merged into the same run by it. Two functions deciding this separately would be two
/// answers to "what did this policy see".
pub fn order_of(record: &Value) -> (String, String, String, String, String, u64) {
    let text = |path: &[&str]| -> String {
        let mut held = record;
        for segment in path {
            let Some(next) = held.get(*segment) else {
                return String::new();
            };
            held = next;
        }

        held.as_str().unwrap_or_default().to_owned()
    };

    (
        text(&["occurred_at"]),
        text(&["observed_at"]),
        text(&["stream", "producer", "class"]),
        text(&["stream", "producer", "id"]),
        text(&["stream", "producer", "instance"]),
        record
            .get("seq")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
    )
}

/// This moment, as the canonical instant a cursor records.
fn now() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| i64::try_from(since.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or_default();

    permguard_events::index::render_epoch_seconds(seconds)
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_owned())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use serde_json::json;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pg-imports-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);

        dir
    }

    fn record(producer: &str, seq: u64, event_id: &str, digest: &str, at: &str) -> Value {
        json!({
            "stream": {
                "producer": {
                    "class": "permguard.event.producer.data-plane.v1",
                    "id": producer,
                    "instance": "i-1"
                },
                "zone": "acme",
                "ledger": "main"
            },
            "seq": seq,
            "event_id": event_id,
            "occurrence_digest": digest,
            "occurred_at": at,
            "observed_at": at,
            // The coordinates a windowed read finds a record by. Real records always carry them —
            // the journal refuses one that does not — and a fixture without them would be testing
            // a record no producer can ship.
            "event_type": permguard_languages::event::EVENT_TYPE,
            "kind": "response",
            "event": {"action": "Drupe::Action::Login"}
        })
    }

    #[test]
    fn the_same_origin_position_arriving_twice_is_imported_once() {
        let imports = Imports::new(scratch("origin"));
        let held = record("plane-a", 1, "e1", "sha256:aa", "2026-08-28T10:00:00Z");

        assert!(imports.absorb("acme", "main", &held).expect("it absorbs"));
        assert!(
            !imports.absorb("acme", "main", &held).expect("it absorbs"),
            "a replayed page is not new history"
        );
        assert_eq!(
            imports.observable("acme", "main").expect("it reads").len(),
            1
        );
    }

    /// One client request that reached two planes is two records and one occurrence.
    #[test]
    fn one_occurrence_recorded_by_two_planes_is_observed_once_and_kept_twice() {
        let imports = Imports::new(scratch("logical"));
        let first = record("plane-a", 1, "e1", "sha256:aa", "2026-08-28T10:00:00Z");
        let second = record("plane-b", 7, "e1", "sha256:aa", "2026-08-28T10:00:00Z");

        assert!(imports.absorb("acme", "main", &first).expect("absorbs"));
        assert!(
            !imports.absorb("acme", "main", &second).expect("absorbs"),
            "the same occurrence must be counted once"
        );

        // Observed once…
        assert_eq!(imports.observable("acme", "main").expect("reads").len(), 1);
        // …and both kept, because both are evidence.
        let state = imports.state("acme", "main").expect("reads");
        assert_eq!(state.imported, 1);
        assert_eq!(state.logical_duplicates, 1);
    }

    /// The same id with different content is not a duplicate — it is two different things.
    #[test]
    fn one_id_with_different_content_is_two_occurrences_and_both_are_kept() {
        let imports = Imports::new(scratch("conflict"));
        let first = record("plane-a", 1, "e1", "sha256:aa", "2026-08-28T10:00:00Z");
        let second = record("plane-b", 7, "e1", "sha256:bb", "2026-08-28T10:00:01Z");

        assert!(imports.absorb("acme", "main", &first).expect("absorbs"));
        assert!(
            imports.absorb("acme", "main", &second).expect("absorbs"),
            "an id alone is a claim; the digest is what was claimed"
        );
        assert_eq!(imports.observable("acme", "main").expect("reads").len(), 2);
    }

    /// Event time first, then a documented tie break — never an invented global sequence.
    #[test]
    fn records_are_observed_in_event_time_with_a_deterministic_tie_break() {
        let imports = Imports::new(scratch("order"));
        // Arrives second, happened first.
        let later = record("plane-a", 9, "e-late", "sha256:cc", "2026-08-28T10:00:05Z");
        let earlier = record("plane-b", 1, "e-early", "sha256:dd", "2026-08-28T10:00:01Z");
        imports.absorb("acme", "main", &later).expect("absorbs");
        imports.absorb("acme", "main", &earlier).expect("absorbs");

        let observed = imports.observable("acme", "main").expect("reads");
        let ids: Vec<&str> = observed
            .iter()
            .filter_map(|held| held.get("event_id")?.as_str())
            .collect();
        assert_eq!(ids, ["e-early", "e-late"]);

        // The tie break, when the times are identical: producer class, id, instance, sequence.
        let imports = Imports::new(scratch("tie"));
        for producer in ["plane-c", "plane-a", "plane-b"] {
            imports
                .absorb(
                    "acme",
                    "main",
                    &record(
                        producer,
                        1,
                        producer,
                        &format!("sha256:{producer}"),
                        "2026-08-28T10:00:00Z",
                    ),
                )
                .expect("absorbs");
        }
        let observed = imports.observable("acme", "main").expect("reads");
        let producers: Vec<&str> = observed
            .iter()
            .filter_map(|held| held.get("stream")?.get("producer")?.get("id")?.as_str())
            .collect();
        assert_eq!(producers, ["plane-a", "plane-b", "plane-c"]);
    }

    #[test]
    fn a_cursor_survives_a_restart() {
        let directory = scratch("cursor");
        {
            let imports = Imports::new(&directory);
            imports
                .advance("acme", "main", "offset-1")
                .expect("advances");
        }
        let reopened = Imports::new(&directory);

        assert_eq!(
            reopened.cursor("acme", "main").expect("reads"),
            Some("offset-1".to_owned())
        );
        assert!(
            !reopened
                .state("acme", "main")
                .expect("reads")
                .read_at
                .is_empty(),
            "a plane that is caught up is fresh, and the time it last read says so"
        );
    }

    #[test]
    fn a_name_that_is_not_a_directory_name_is_refused() {
        let imports = Imports::new(scratch("escape"));

        assert!(imports.state("../etc", "main").is_err());
        assert!(imports.state("acme", "").is_err());
    }

    /// A hole is a durable fact, and it does not heal by itself.
    ///
    /// Resuming from the oldest still held is what keeps a subscription working after the control
    /// plane has aged out where it stood. Doing only that made the result indistinguishable from a
    /// subscription that never missed anything: it caught up, reported itself fresh, and every
    /// decision afterwards ranged over fewer occurrences than had actually happened.
    #[test]
    fn a_gap_survives_the_restart_and_is_only_closed_deliberately() {
        let root = scratch("gap");
        let imports = Imports::new(&root);

        assert!(
            imports
                .unresolved_gaps("z", "l")
                .expect("it reads")
                .is_empty(),
            "a history nothing was lost from has no holes"
        );

        imports
            .record_gap(
                "z",
                "l",
                "offset-oldest",
                Gap {
                    zone: "z".to_owned(),
                    ledger: "l".to_owned(),
                    from_sequence: 40,
                    to_sequence: 91,
                    at: "2026-08-29T00:00:00Z".to_owned(),
                    consistency: "shared-bounded".to_owned(),
                    resolved: false,
                },
            )
            .expect("the hole is recorded");

        // The cursor moved, which is what keeps the subscription alive...
        assert_eq!(
            imports.state("z", "l").expect("it reads").offset,
            "offset-oldest"
        );
        // ...and the hole moved with it, which is what stops the history lying about itself.
        let held = imports.unresolved_gaps("z", "l").expect("it reads");
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].from_sequence, 40);
        assert_eq!(held[0].to_sequence, 91);
        assert_eq!(held[0].consistency, "shared-bounded");

        // A retried round over the same expired offset is one hole, not a list of them.
        imports
            .record_gap(
                "z",
                "l",
                "offset-oldest",
                Gap {
                    zone: "z".to_owned(),
                    ledger: "l".to_owned(),
                    from_sequence: 40,
                    to_sequence: 91,
                    at: "2026-08-29T00:05:00Z".to_owned(),
                    consistency: "shared-bounded".to_owned(),
                    resolved: false,
                },
            )
            .expect("the same hole again");
        assert_eq!(
            imports.unresolved_gaps("z", "l").expect("it reads").len(),
            1
        );

        // It is on the volume, so a restart does not present an incomplete history as a whole one.
        let reopened = Imports::new(&root);
        assert_eq!(
            reopened.unresolved_gaps("z", "l").expect("it reads").len(),
            1
        );

        // Closed only because somebody said so — and still on the record afterwards.
        assert_eq!(reopened.resolve_gaps("z", "l").expect("it resolves"), 1);
        assert!(
            reopened
                .unresolved_gaps("z", "l")
                .expect("it reads")
                .is_empty()
        );
        assert_eq!(
            reopened.state("z", "l").expect("it reads").gaps.len(),
            1,
            "resolving accepts the hole; it does not erase it"
        );
    }

    /// A history this plane cannot read is an error, never an empty history.
    ///
    /// The dangerous shape it replaces: every read failure — a permission, a bad disk, a truncated
    /// file — collapsed into "no records". A temporal policy handed that decides as though the
    /// events never happened, and answers a request it should have refused. Absence and failure
    /// are different facts and only one of them is safe to act on.
    #[test]
    fn an_unreadable_history_fails_closed_rather_than_reading_as_empty() {
        let root = scratch("unreadable");
        let imports = Imports::new(&root);

        // Nothing imported yet is a legitimate empty history.
        assert!(
            imports
                .observable("acme", "main")
                .expect("it reads")
                .is_empty(),
            "a subscription that has imported nothing has an empty history, not an error"
        );

        // A line this build cannot read is a damaged history, and skipping it would hand a policy
        // a hole nothing recorded.
        let directory = imports.path("acme", "main").expect("a directory");
        fs::create_dir_all(&directory).expect("it is created");
        fs::write(directory.join(RECORDS_FILE), b"{ this is not a record }\n")
            .expect("it is written");

        let refused = imports
            .observable("acme", "main")
            .expect_err("a damaged history is an error");
        let message = format!("{refused:#}");
        assert!(
            message.contains("line 1"),
            "the refusal names where the damage is: {message}"
        );
    }

    /// Importing does not re-read everything it has already imported.
    ///
    /// Rebuilding the deduplication sets from the file on every record made importing `n` records
    /// read the file `n` times — quadratic exactly when it hurts, a plane catching up after an
    /// outage. What this pins down is that the answers stay the same now that they are cached.
    #[test]
    fn importing_many_records_does_not_re_read_what_it_already_holds() {
        let root = scratch("catch-up");
        let imports = Imports::new(&root);

        for seq in 1..=200u64 {
            let record = json!({
                "stream": {
                    "producer": {"class": "data-plane", "id": "plane-a", "instance": "i-1"},
                    "zone": "acme",
                    "ledger": "main",
                },
                "seq": seq,
                "event_id": format!("evt-{seq}"),
                "occurrence_digest": format!("sha256:{seq}"),
                "occurred_at": "2026-08-29T00:00:00Z",
                "observed_at": "2026-08-29T00:00:00Z",
                "event_type": permguard_languages::event::EVENT_TYPE,
                "kind": "response",
                "event": {"action": "Drupe::Action::Login"},
            });
            assert!(
                imports.absorb("acme", "main", &record).expect("it absorbs"),
                "record {seq} is new"
            );
        }

        assert_eq!(
            imports.observable("acme", "main").expect("it reads").len(),
            200
        );

        // And a replayed page is still recognised, from the cache rather than from a re-read.
        let replay = json!({
            "stream": {
                "producer": {"class": "data-plane", "id": "plane-a", "instance": "i-1"},
                "zone": "acme",
                "ledger": "main",
            },
            "seq": 7,
            "event_id": "evt-7",
            "occurrence_digest": "sha256:7",
            "occurred_at": "2026-08-29T00:00:00Z",
            "observed_at": "2026-08-29T00:00:00Z",
            "event_type": permguard_languages::event::EVENT_TYPE,
            "kind": "response",
            "event": {"action": "Drupe::Action::Login"},
        });
        assert!(
            !imports.absorb("acme", "main", &replay).expect("it absorbs"),
            "an origin position already held is imported once"
        );
        assert_eq!(
            imports.observable("acme", "main").expect("it reads").len(),
            200,
            "and nothing was added"
        );
    }

    /// A windowed read reads a window, not the retained history.
    ///
    /// The shortfall this closes: the local journal was already a range scan over an index, while
    /// the imported half loaded *every* record it held and filtered in memory. A plane in a shared
    /// mode therefore paid its whole retained import history on every decision — the cost grew
    /// with how long the plane had been running, which is the one thing an evaluation's cost must
    /// not depend on.
    #[test]
    fn a_windowed_read_returns_the_window_and_not_the_history() {
        let root = scratch("windowed");
        let imports = Imports::new(&root);

        // One record a minute for two hours, all in one history.
        for minute in 0..120u64 {
            let at =
                permguard_events::index::render_epoch_seconds(1_800_000_000 + (minute as i64) * 60)
                    .expect("an instant");
            let held = record(
                "plane-a",
                minute + 1,
                &format!("e{minute}"),
                "sha256:aa",
                &at,
            );
            imports.absorb("acme", "main", &held).expect("it absorbs");
        }
        assert_eq!(
            imports.observable("acme", "main").expect("it reads").len(),
            120,
            "the store holds two hours"
        );

        // A ten-minute window over the same store.
        let until = 1_800_000_000 + 119 * 60;
        let query = permguard_events::index::Query {
            event_type: permguard_languages::event::EVENT_TYPE.to_owned(),
            history: String::new(),
            action: None,
            kind: None,
            from: until - 10 * 60,
            until,
        };
        let held = imports.window("acme", "main", &query).expect("it reads");
        assert_eq!(
            held.len(),
            11,
            "eleven minutes inclusive, not the hundred and twenty retained"
        );

        // The index is on the volume, so a restart does not go back to reading everything.
        let reopened = Imports::new(&root);
        let after = reopened.window("acme", "main", &query).expect("it reads");
        assert_eq!(after.len(), 11);

        // And a lost index is rebuilt from the records rather than read as an empty history.
        let directory = imports.path("acme", "main").expect("a directory");
        for entry in fs::read_dir(&directory).expect("it lists").flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name != RECORDS_FILE && name != STATE_FILE {
                let _ = fs::remove_file(entry.path());
            }
        }
        let rebuilt = Imports::new(&root);
        assert_eq!(
            rebuilt
                .window("acme", "main", &query)
                .expect("it reads")
                .len(),
            11,
            "the records are the authority and the index is derived from them"
        );
    }
}
