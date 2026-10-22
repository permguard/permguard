// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The durable logical index of a ledger's occurrences across origins (WP-6.4b, owner decision of
//! 2026-10-21).
//!
//! ```text
//! key   = (authenticated source, or the origin when nobody vouched for one; event_id)
//! entry = history key, occurred_at, digest, every position (origin, run, sequence), conflicts
//! ```
//!
//! The physical records stay in their own streams, whichever plane recorded them: this index
//! never deletes provenance, it records every position that contributed to one logical
//! occurrence. After convergence an equal occurrence applies once to future history; a key seen
//! with two digests is a conflict, and the occurrence is quarantined from shared decisions.
//!
//! Kept at the import catch-up: each imported record is indexed, and a new key's copy on this
//! plane's own journal is looked up; this plane's own records past `local_through` are read in
//! local order and indexed when another origin holds their key. Pruned below the horizon the
//! import floors use, written whole and atomically through the storage library, and rebuilt from
//! the consumer and the local journal when it does not read: derived state, never an authority.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use permguard_events::index::JournalError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Where a ledger's logical index lives, under its temporal directory.
pub const DIRECTORY: &str = "indexes";

/// The index's file.
pub const FILE: &str = "logical.json";

/// One logical occurrence's key: the source that vouched for it, or its origin, and its id.
pub type Key = (String, String);

/// One position a physical record holds: origin, run and sequence.
pub type Position = (String, String, u64);

/// One logical occurrence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// The history key's digest, empty for global history.
    pub history: String,
    /// Its event time, in epoch seconds: what the horizon prunes by.
    pub occurred_at: i64,
    /// The first digest seen.
    pub digest: String,
    /// Every position that recorded it.
    pub positions: BTreeSet<Position>,
    /// Every other digest seen under the same key: a conflict when not empty.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub conflicts: BTreeSet<String>,
}

impl Entry {
    /// Whether the occurrence is quarantined: its key was seen with two digests.
    pub fn conflicted(&self) -> bool {
        !self.conflicts.is_empty()
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Body {
    entries: Vec<(Key, Entry)>,
    /// The local position this plane's own journal was read through.
    #[serde(default)]
    local_through: u64,
    /// Per imported run, `<origin>/<run>` in hex, the sequence observed through.
    #[serde(default)]
    runs: BTreeMap<String, u64>,
}

/// One ledger's logical index.
#[derive(Debug, Default)]
pub struct Logical {
    directory: PathBuf,
    entries: BTreeMap<Key, Entry>,
    local_through: u64,
    runs: BTreeMap<String, u64>,
    changed: bool,
}

/// The key a record is indexed under: a trusted source and the `event_id`; a record with no
/// `source`, or the anonymous one, keys by its origin instead, so an identity nobody vouched for
/// never collapses nor quarantines another origin's occurrence (owner decision of 2026-10-19).
pub fn key_of(record: &Value) -> Key {
    key(
        record.get("source").and_then(Value::as_str),
        &text(record, &["stream", "producer", "id"]),
        &text(record, &["event_id"]),
    )
}

/// The key of an occurrence `source` vouched for, or nobody did, recorded by `origin`.
pub fn key(source: Option<&str>, origin: &str, event_id: &str) -> Key {
    match source {
        Some(source)
            if !source.is_empty()
                && source != permguard_core::authz::Principal::anonymous().as_str() =>
        {
            (format!("source:{source}"), event_id.to_owned())
        }
        _ => (format!("origin:{origin}"), event_id.to_owned()),
    }
}

fn text(record: &Value, path: &[&str]) -> String {
    let mut held = record;
    for segment in path {
        match held.get(segment) {
            Some(next) => held = next,
            None => return String::new(),
        }
    }
    held.as_str().unwrap_or_default().to_owned()
}

fn io(error: impl std::fmt::Display) -> JournalError {
    JournalError::Io(error.to_string())
}

impl Logical {
    /// The index under `ledger_directory`, and whether it read: one that is absent or does not
    /// read starts empty, and its caller rebuilds it from the consumer.
    pub fn open(ledger_directory: &Path) -> (Self, bool) {
        let directory = ledger_directory.join(DIRECTORY);
        let read = std::fs::read(directory.join(FILE))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Body>(&bytes).ok());
        let loaded = read.is_some();
        let body = read.unwrap_or_default();
        (
            Self {
                directory,
                entries: body.entries.into_iter().collect(),
                local_through: body.local_through,
                runs: body.runs,
                changed: !loaded,
            },
            loaded,
        )
    }

    /// Whether a record's key is one a trusted source vouched for: the only kind this plane's own
    /// journal and another origin's can share.
    pub fn vouched(key: &Key) -> bool {
        key.0.starts_with("source:")
    }

    /// Whether the index holds `key`.
    pub fn holds(&self, key: &Key) -> bool {
        self.entries.contains_key(key)
    }

    /// The local position this plane's own journal was read through.
    pub fn local_through(&self) -> u64 {
        self.local_through
    }

    /// Moves the local mark. Not a change by itself: a mark saved late is read again, and reading
    /// a record twice records nothing new.
    pub fn read_local_through(&mut self, through: u64) {
        self.local_through = self.local_through.max(through);
    }

    /// The sequence of an imported run the index observed through: a run index covering more was
    /// written by a process that stopped before this index was, and the run is read again.
    pub fn run_through(&self, origin: &str, run: &str) -> u64 {
        self.runs
            .get(&format!("{origin}/{run}"))
            .copied()
            .unwrap_or_default()
    }

    /// Records that an imported run is observed through `seq`.
    pub fn read_run_through(&mut self, origin: &str, run: &str, seq: u64) {
        let held = self.runs.entry(format!("{origin}/{run}")).or_default();
        if seq != *held {
            *held = seq;
            self.changed = true;
        }
    }

    /// Forgets the marks of every run but `runs`, `(origin, run)` in hex.
    pub fn keep_runs(&mut self, runs: &BTreeSet<(String, String)>) {
        let before = self.runs.len();
        self.runs.retain(|name, _| {
            name.split_once('/')
                .is_some_and(|(origin, run)| runs.contains(&(origin.to_owned(), run.to_owned())))
        });
        self.changed |= self.runs.len() != before;
    }

    /// Records one physical record's position under its key; a second digest is a conflict.
    pub fn observe(&mut self, record: &Value) {
        let key = key_of(record);
        let digest = text(record, &["occurrence_digest"]);
        let position = (
            text(record, &["stream", "producer", "id"]),
            text(record, &["stream", "producer", "instance"]),
            record
                .get("seq")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
        );
        let entry = self.entries.entry(key).or_insert_with(|| Entry {
            history: text(record, &["history_key", "digest"]),
            occurred_at: permguard_events::index::epoch_seconds(&text(record, &["occurred_at"]))
                .unwrap_or_default(),
            digest: digest.clone(),
            positions: BTreeSet::new(),
            conflicts: BTreeSet::new(),
        });
        let mut changed = entry.positions.insert(position);
        if digest != entry.digest {
            changed |= entry.conflicts.insert(digest);
        }
        self.changed |= changed;
    }

    /// Forgets every entry older than `horizon`, which no loaded window reads any more.
    pub fn forget_older(&mut self, horizon: i64) {
        let before = self.entries.len();
        self.entries.retain(|_, entry| entry.occurred_at >= horizon);
        self.changed |= self.entries.len() != before;
    }

    /// Writes the index if it changed, whole and atomically.
    pub fn save(&mut self) -> Result<(), JournalError> {
        if !self.changed {
            return Ok(());
        }
        self.flush()
    }

    /// Writes the index whole and atomically, its local mark with it.
    pub fn flush(&mut self) -> Result<(), JournalError> {
        let body = Body {
            entries: self
                .entries
                .iter()
                .map(|(key, entry)| (key.clone(), entry.clone()))
                .collect(),
            local_through: self.local_through,
            runs: self.runs.clone(),
        };
        let bytes = serde_json::to_vec(&body)
            .map_err(|error| JournalError::Malformed(format!("the logical index: {error}")))?;
        let dir = permguard_host::storage::Dir::create_root(&self.directory).map_err(io)?;
        permguard_host::storage::write::replace_bytes(&dir, FILE, &bytes).map_err(io)?;
        self.changed = false;
        Ok(())
    }

    /// The entry of `key`, when the index holds one.
    pub fn get(&self, key: &Key) -> Option<&Entry> {
        self.entries.get(key)
    }

    /// Every quarantined occurrence of `history` whose event time is in `[from, until]`: what a
    /// decision over that window would have read.
    pub fn quarantined(&self, history: &str, from: i64, until: i64) -> Vec<&Entry> {
        self.entries
            .values()
            .filter(|entry| {
                entry.conflicted()
                    && entry.history == history
                    && (from..=until).contains(&entry.occurred_at)
            })
            .collect()
    }

    /// Every key the index holds as conflicted.
    pub fn conflicting(&self) -> BTreeSet<Key> {
        self.entries
            .iter()
            .filter(|(_, entry)| entry.conflicted())
            .map(|(key, _)| key.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use serde_json::json;

    fn record(origin: &str, run: &str, seq: u64, event_id: &str, digest: &str, at: &str) -> Value {
        json!({
            "seq": seq,
            "event_id": event_id,
            "source": "spiffe://acme/gateway",
            "occurrence_digest": digest,
            "occurred_at": at,
            "history_key": {"digest": "sha256:h"},
            "stream": {"producer": {"id": origin, "instance": run}},
        })
    }

    fn scratch(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "permguard-logical-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        path
    }

    #[test]
    fn every_position_is_recorded_and_a_second_digest_is_a_conflict() {
        let (mut index, loaded) = Logical::open(&scratch("positions"));
        assert!(!loaded, "nothing to read yet");
        let at = "2026-10-22T10:00:00Z";
        index.observe(&record("aa", "r1", 1, "e1", "sha256:d", at));
        index.observe(&record("bb", "r2", 7, "e1", "sha256:d", at));
        index.observe(&record("bb", "r2", 7, "e1", "sha256:d", at));
        let key = ("source:spiffe://acme/gateway".to_owned(), "e1".to_owned());
        let entry = index.get(&key).expect("indexed");
        assert_eq!(entry.positions.len(), 2, "each position once");
        assert!(!entry.conflicted());
        assert!(index.quarantined("sha256:h", i64::MIN, i64::MAX).is_empty());

        index.observe(&record("cc", "r3", 2, "e1", "sha256:other", at));
        let entry = index.get(&key).expect("indexed");
        assert!(entry.conflicted());
        assert_eq!(entry.positions.len(), 3, "provenance is never dropped");
        let instant = permguard_events::index::epoch_seconds(at).expect("an instant");
        assert_eq!(index.quarantined("sha256:h", instant, instant).len(), 1);
        assert!(
            index
                .quarantined("sha256:else", i64::MIN, i64::MAX)
                .is_empty()
        );
        // Outside the window a decision reads, the occurrence quarantines nothing.
        assert!(
            index
                .quarantined("sha256:h", instant + 1, i64::MAX)
                .is_empty()
        );
        assert!(
            index
                .quarantined("sha256:h", i64::MIN, instant - 1)
                .is_empty()
        );
        assert_eq!(index.conflicting(), [key].into());
    }

    #[test]
    fn the_index_persists_prunes_below_the_horizon_and_a_damaged_one_starts_empty() {
        let directory = scratch("persist");
        let (mut index, _) = Logical::open(&directory);
        index.observe(&record(
            "aa",
            "r1",
            1,
            "old",
            "sha256:o",
            "2026-10-01T00:00:00Z",
        ));
        index.observe(&record(
            "aa",
            "r1",
            2,
            "new",
            "sha256:n",
            "2026-10-22T00:00:00Z",
        ));
        index.read_local_through(7);
        index.read_local_through(3);
        index.save().expect("written");
        let (mut reread, loaded) = Logical::open(&directory);
        assert!(loaded);
        assert_eq!(reread.entries.len(), 2);
        assert_eq!(reread.local_through(), 7, "the mark never moves back");

        reread.forget_older(
            permguard_events::index::epoch_seconds("2026-10-10T00:00:00Z").expect("an instant"),
        );
        reread.save().expect("written");
        let (reread, _) = Logical::open(&directory);
        assert_eq!(
            reread
                .entries
                .keys()
                .map(|key| key.1.clone())
                .collect::<Vec<_>>(),
            ["new"]
        );

        std::fs::write(directory.join(DIRECTORY).join(FILE), b"not json").expect("damaged");
        let (damaged, loaded) = Logical::open(&directory);
        assert!(!loaded, "a damaged index is rebuilt by its caller");
        assert!(damaged.entries.is_empty());
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn an_identity_nobody_vouched_for_keys_by_its_origin() {
        let mut anonymous = record("aa", "r1", 1, "e1", "sha256:d", "2026-10-22T00:00:00Z");
        anonymous["source"] = json!(permguard_core::authz::Principal::anonymous().as_str());
        assert_eq!(key_of(&anonymous).0, "origin:aa");
        anonymous.as_object_mut().expect("a map").remove("source");
        assert_eq!(key_of(&anonymous).0, "origin:aa");
    }
}
