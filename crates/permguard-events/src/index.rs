// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The persistent index that keeps a temporal evaluation bounded.
//!
//! # Why an index is not an optimisation here
//!
//! A temporal policy asks a question of the form *did this principal do X in the last hour*. The
//! obvious implementation reads the ledger's history and filters it, and that implementation is
//! wrong in a way that only shows up in production: its cost grows with everything ever retained,
//! so a deployment that is fast on day one is unusable on day ninety, with no code change in
//! between. Worse, the growth is invisible in a test suite whose fixtures hold ten events.
//!
//! So the index is part of the contract, not a later optimisation. A decision reads only the
//! records matching its pin, action, kind and time range, and `max_window` bounds how far that
//! range can reach — it is a ceiling on the *question*, never a licence to read everything under
//! the ceiling when a leaf asks for a smaller interval.
//!
//! # What it maps
//!
//! ```text
//! (event_type, history key, action, kind, occurred_at, seq) -> (segment, offset, length)
//! ```
//!
//! The key is ordered so a range scan answers the query shape directly: fix the type and the
//! history key, fix the action and kind if the leaf names them, and the remainder is a contiguous
//! run ordered by time. Nothing is scanned that could not have matched.
//!
//! # Why it may be thrown away
//!
//! The segments are authoritative; the index is derived. It is persisted so a restart does not pay
//! to rebuild, and it is *rebuildable* so a corrupt or absent index is an inconvenience rather than
//! data loss. That asymmetry is deliberate: an index that could disagree with the segments and win
//! would be a second source of truth about history, and there can only be one.
//!
//! An append becomes visible to evaluation only after its index entry is durable. A record that is
//! in a segment but not in the index would be invisible to the policy that needed it — which is a
//! wrong answer, not a slow one.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::journal::JournalError;

/// Where the index is kept, beside the segments it is derived from.
pub(crate) const INDEX_FILE: &str = "INDEX";

/// Where one record lives, and what it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Located {
    /// The stream sequence — what the record is called.
    pub seq: u64,
    /// The first sequence of the segment holding it, which is that segment's name.
    pub segment: u64,
    /// Its byte offset inside that segment.
    pub offset: u64,
    /// Its length in bytes, so a reader takes exactly one record.
    pub length: u64,
}

/// The ordered part of an index entry.
///
/// Field order is the scan order, and it is chosen to match the question a temporal leaf asks:
/// everything a query fixes comes before everything it ranges over.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Key {
    /// The registered event type. Fixed by every query: a subscription reads the types it asked
    /// for, and reading one must not decode the others retained beside it.
    pub event_type: String,
    /// The derived history key's digest, or an empty string for a partition with global history.
    pub history: String,
    /// The qualified action.
    pub action: String,
    /// The runtime's own kind — `request`, `response`, `error`.
    pub kind: String,
    /// When the occurrence happened, as epoch seconds. The dimension a window ranges over.
    pub occurred_at: i64,
    /// The sequence, last, so entries with identical coordinates still order deterministically.
    pub seq: u64,
}

/// What a query fixes and what it ranges over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub event_type: String,
    /// The history key to scan. Empty scans the global partition.
    pub history: String,
    /// The action, when the leaf names one.
    pub action: Option<String>,
    /// The kind, when the leaf names one.
    pub kind: Option<String>,
    /// The inclusive lower bound of the window.
    pub from: i64,
    /// The inclusive upper bound of the window.
    pub until: i64,
}

/// A local, rebuildable index over one stream's segments.
pub struct Index {
    directory: PathBuf,
    entries: BTreeMap<Key, Located>,
}

impl Index {
    /// Opens the index beside its journal, loading what was persisted.
    ///
    /// A missing or damaged index is not an error: it is rebuilt from the segments, because the
    /// segments are the authority and this is derived from them.
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, JournalError> {
        let directory = directory.as_ref().to_path_buf();
        let mut index = Self {
            directory,
            entries: BTreeMap::new(),
        };
        index.load().or_else(|_| {
            index.entries.clear();

            index.rebuild()
        })?;

        Ok(index)
    }

    /// Opens an index over records this crate's segments do not hold.
    ///
    /// [`Index::open`] rebuilds from `seg-*.events` when the persisted index is missing, because
    /// for a journal the segments are the authority. A store that keeps its records some other way
    /// — the imported history, which is another producer's evidence and deliberately not in this
    /// plane's chain — has no such segments, and that rebuild would quietly yield an *empty* index
    /// and make every imported record invisible.
    ///
    /// So the fallback is the caller's. `false` means nothing was loaded and the caller must
    /// rebuild from whatever it does keep; `true` means the index is what was persisted.
    pub fn detached(directory: impl AsRef<Path>) -> Result<(Self, bool), JournalError> {
        let mut index = Self {
            directory: directory.as_ref().to_path_buf(),
            entries: BTreeMap::new(),
        };
        match index.load() {
            Ok(()) => Ok((index, true)),
            Err(_) => {
                index.entries.clear();

                Ok((index, false))
            }
        }
    }

    /// Forgets everything indexed and removes the persisted file, before a rebuild.
    pub fn reset(&mut self) -> Result<(), JournalError> {
        self.entries.clear();
        let path = self.directory.join(INDEX_FILE);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(JournalError::Io(error.to_string())),
        }
    }

    /// How many records are indexed.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is indexed.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The highest sequence this index covers.
    ///
    /// Recovery replays the durable segment tail beyond this, so a crash between an append and its
    /// index entry loses neither the record nor its visibility.
    pub fn covered_through(&self) -> u64 {
        self.entries
            .values()
            .map(|located| located.seq)
            .max()
            .unwrap_or(0)
    }

    /// Records one record's coordinates and persists the entry.
    ///
    /// Durable before the caller may treat the record as observable: an entry that is only in
    /// memory would vanish on a restart and take the record's visibility with it.
    pub fn insert(&mut self, key: Key, located: Located) -> Result<(), JournalError> {
        self.stage(key, located)?;

        self.sync()
    }

    /// Records one record's coordinates **without** flushing.
    ///
    /// The half of [`Index::insert`] that a group commit needs: the entry is written and visible in
    /// memory, and [`Index::sync`] is what makes it durable. A journal that flushed the index per
    /// record would pay a second disk barrier per append and give the batch back what group commit
    /// just saved.
    pub fn stage(&mut self, key: Key, located: Located) -> Result<(), JournalError> {
        let line = serde_json::to_vec(&(&key, &located))
            .map_err(|error| JournalError::Malformed(error.to_string()))?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.directory.join(INDEX_FILE))
            .map_err(|error| JournalError::Io(error.to_string()))?;
        file.write_all(&line)
            .map_err(|error| JournalError::Io(error.to_string()))?;
        file.write_all(b"\n")
            .map_err(|error| JournalError::Io(error.to_string()))?;

        self.entries.insert(key, located);

        Ok(())
    }

    /// Flushes whatever [`Index::stage`] wrote.
    ///
    /// Called with — and never after — the segment's own flush: an index entry durable before its
    /// record would make a record visible that a crash then took away, which for a temporal engine
    /// is a history that answers differently before and after the restart.
    pub fn sync(&mut self) -> Result<(), JournalError> {
        let path = self.directory.join(INDEX_FILE);
        if !path.exists() {
            return Ok(());
        }
        let file = OpenOptions::new()
            .append(true)
            .open(&path)
            .map_err(|error| JournalError::Io(error.to_string()))?;
        file.sync_all()
            .map_err(|error| JournalError::Io(error.to_string()))?;

        Ok(())
    }

    /// The records matching a query, in key order.
    ///
    /// A range scan over the ordered key, not a filter over everything. Precisely what that buys:
    /// the walk is bounded by the **history partition** — the two most significant fields of the
    /// key are the event type and the history, so entries belonging to any other are never
    /// examined — and what is *returned*, and therefore read off disk, is bounded by the window as
    /// well. For a schema that pins the caller, that is one caller's entries walked and one
    /// window's records read, rather than a ledger.
    ///
    /// `action` and `kind` narrow the range further when a leaf names them. When it does not they
    /// range with the rest, and the time bound is applied as the entries are walked: the entries of
    /// one history partition are small and the records are not, so bounding the read is where the
    /// cost is.
    pub fn scan(&self, query: &Query) -> Vec<&Located> {
        let low = Key {
            event_type: query.event_type.clone(),
            history: query.history.clone(),
            action: query.action.clone().unwrap_or_default(),
            kind: query.kind.clone().unwrap_or_default(),
            occurred_at: query.from,
            seq: 0,
        };

        self.entries
            .range(low..)
            .take_while(|(key, _)| {
                key.event_type == query.event_type && key.history == query.history
            })
            .filter(|(key, _)| {
                query
                    .action
                    .as_ref()
                    .is_none_or(|action| &key.action == action)
                    && query.kind.as_ref().is_none_or(|kind| &key.kind == kind)
                    && key.occurred_at >= query.from
                    && key.occurred_at <= query.until
            })
            .map(|(_, located)| located)
            .collect()
    }

    /// Drops entries for records that no longer exist, after eviction.
    pub fn forget_below(&mut self, oldest_retained: u64) -> Result<usize, JournalError> {
        let before = self.entries.len();
        self.entries
            .retain(|_, located| located.seq >= oldest_retained);
        let dropped = before - self.entries.len();
        if dropped > 0 {
            // Rewritten rather than appended to: an append-only index cannot express a deletion,
            // and a compaction that left tombstones would grow without bound.
            self.persist()?;
        }

        Ok(dropped)
    }

    fn load(&mut self) -> Result<(), JournalError> {
        let path = self.directory.join(INDEX_FILE);
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(JournalError::Corrupt("no index yet".to_owned()));
            }
            Err(error) => return Err(JournalError::Io(error.to_string())),
        };
        for line in BufReader::new(file).lines() {
            let line = line.map_err(|error| JournalError::Io(error.to_string()))?;
            if line.trim().is_empty() {
                continue;
            }
            let (key, located): (Key, Located) = serde_json::from_str(&line)
                .map_err(|error| JournalError::Corrupt(error.to_string()))?;
            self.entries.insert(key, located);
        }

        Ok(())
    }

    fn persist(&self) -> Result<(), JournalError> {
        let path = self.directory.join(INDEX_FILE);
        let temporary = self.directory.join(format!("{INDEX_FILE}.tmp"));
        {
            let mut file =
                File::create(&temporary).map_err(|error| JournalError::Io(error.to_string()))?;
            for (key, located) in &self.entries {
                let line = serde_json::to_vec(&(key, located))
                    .map_err(|error| JournalError::Malformed(error.to_string()))?;
                file.write_all(&line)
                    .map_err(|error| JournalError::Io(error.to_string()))?;
                file.write_all(b"\n")
                    .map_err(|error| JournalError::Io(error.to_string()))?;
            }
            file.sync_all()
                .map_err(|error| JournalError::Io(error.to_string()))?;
        }
        fs::rename(&temporary, &path).map_err(|error| JournalError::Io(error.to_string()))?;

        Ok(())
    }

    /// Rebuilds the whole index by reading the segments.
    ///
    /// The recovery path, and the reason a damaged index is survivable: everything here is derived
    /// from records that are still on disk.
    pub fn rebuild(&mut self) -> Result<(), JournalError> {
        self.entries.clear();
        let mut segments: Vec<(u64, PathBuf)> = Vec::new();
        let entries =
            fs::read_dir(&self.directory).map_err(|error| JournalError::Io(error.to_string()))?;
        for entry in entries {
            let entry = entry.map_err(|error| JournalError::Io(error.to_string()))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(rest) = name.strip_prefix("seg-") else {
                continue;
            };
            let Some(number) = rest.strip_suffix(".events") else {
                continue;
            };
            let Ok(first) = number.parse::<u64>() else {
                continue;
            };
            segments.push((first, entry.path()));
        }
        segments.sort_by_key(|(first, _)| *first);

        for (first, path) in segments {
            let bytes = fs::read(&path).map_err(|error| JournalError::Io(error.to_string()))?;
            let mut offset = 0u64;
            for line in bytes.split_inclusive(|byte| *byte == b'\n') {
                if !line.ends_with(b"\n") {
                    break;
                }
                let length = line.len() as u64;
                let value: Value = serde_json::from_slice(&line[..line.len() - 1])
                    .map_err(|error| JournalError::Corrupt(error.to_string()))?;
                if let Some((key, located)) = entry_of(&value, first, offset, length) {
                    self.entries.insert(key, located);
                }
                offset += length;
            }
        }
        self.persist()?;

        Ok(())
    }
}

/// The index entry one record produces, or `None` for a record this build cannot place.
///
/// A record missing the fields an index is built from is not silently bucketed somewhere: it is
/// left unindexed, and the journal's own validation is what stops such a record being written in
/// the first place.
pub fn entry_of(record: &Value, segment: u64, offset: u64, length: u64) -> Option<(Key, Located)> {
    let seq = record.get("seq")?.as_u64()?;
    let event_type = record.get("event_type")?.as_str()?.to_owned();
    let kind = record.get("kind")?.as_str()?.to_owned();
    let history = record
        .get("history_key")
        .and_then(|key| key.get("digest"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let action = record
        .get("event")
        .and_then(|event| event.get("action"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let occurred_at = record
        .get("occurred_at")
        .and_then(Value::as_str)
        .and_then(epoch_seconds)?;

    Some((
        Key {
            event_type,
            history,
            action,
            kind,
            occurred_at,
            seq,
        },
        Located {
            seq,
            segment,
            offset,
            length,
        },
    ))
}

/// A canonical RFC 3339 UTC instant at whole-second precision, as epoch seconds.
///
/// Deliberately strict. Dogwood's windows are closed intervals over signed epoch seconds, so a
/// fractional second or a non-UTC offset has no exact representation and would land on one side or
/// the other of a boundary depending on how it was rounded. Refused rather than rounded.
pub fn epoch_seconds(instant: &str) -> Option<i64> {
    // `YYYY-MM-DDTHH:MM:SSZ`, and nothing else.
    let bytes = instant.as_bytes();
    if bytes.len() != 20 || bytes[10] != b'T' || bytes[19] != b'Z' {
        return None;
    }
    let number = |from: usize, to: usize| instant.get(from..to)?.parse::<i64>().ok();
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        // Leap seconds have no epoch-second of their own, so `:60` is refused rather than
        // silently folded onto the following second.
        || second > 59
    {
        return None;
    }

    // Days from the civil epoch — Howard Hinnant's algorithm, which is exact for the whole range
    // and needs no calendar table.
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_adjusted = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_adjusted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;

    let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second;

    // The round trip is what "canonical" means here, so it is what is checked.
    //
    // Every field above is in range on its own, and that is not enough: `1..=31` admits a day the
    // month does not have, and the civil-days arithmetic has no notion of a date that does not
    // exist — it converts `2025-02-29` into the instant three lines of algebra say it is, which is
    // `2025-03-01`. Accepting that puts two spellings on one instant, and leaves a record holding a
    // date the calendar never had while the index and the engine use a different one. A February
    // 29th in a year that has none is an ordinary client bug, not an exotic input.
    //
    // Rendering the result and requiring it back is exact, and needs no second table of month
    // lengths and no second leap rule to disagree with this one: the only strings that survive are
    // the ones this system also writes.
    (render_epoch_seconds(seconds)? == instant).then_some(seconds)
}

/// The canonical instant of an epoch second — the exact inverse of [`epoch_seconds`].
///
/// One spelling of an instant, produced here and parsed there, so a record read back is the record
/// that was written. `None` for a second whose civil date does not fit the four-digit year form
/// the canonical spelling has: a range no clock in this system reaches, refused rather than
/// rendered as something [`epoch_seconds`] would then read as a different time.
pub fn render_epoch_seconds(seconds: i64) -> Option<String> {
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);

    // Hinnant's civil-from-days, the inverse of the days computation in `epoch_seconds`.
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_adjusted = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_adjusted + 2) / 5 + 1;
    let month = if month_adjusted < 10 {
        month_adjusted + 3
    } else {
        month_adjusted - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    if !(0..=9999).contains(&year) {
        return None;
    }

    Some(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3_600,
        (rest % 3_600) / 60,
        rest % 60
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use serde_json::json;

    fn located(seq: u64) -> Located {
        Located {
            seq,
            segment: 1,
            offset: seq * 100,
            length: 100,
        }
    }

    fn key(history: &str, action: &str, kind: &str, at: i64, seq: u64) -> Key {
        Key {
            event_type: "permguard.dogwood.event.v1".to_owned(),
            history: history.to_owned(),
            action: action.to_owned(),
            kind: kind.to_owned(),
            occurred_at: at,
            seq,
        }
    }

    fn scratch(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "permguard-index-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("the directory is created");

        path
    }

    /// A date the calendar does not have is refused, not moved to one that exists.
    ///
    /// # Why this needs a test of its own
    ///
    /// Each field passes on its own: `02` is a month and `29` is inside `1..=31`. What fails is the
    /// combination, and the civil-days arithmetic has no opinion about it — it converts
    /// `2025-02-29` into the instant the algebra says, which is `2025-03-01`. That put two
    /// spellings on one instant: the audit record kept the date the caller sent while the index and
    /// the engine used another, three days apart at the extreme. A leap year off by one is an
    /// ordinary client bug, so this is an input that really arrives.
    #[test]
    fn a_date_the_calendar_does_not_have_is_refused_rather_than_moved() {
        for absent in [
            // February, in years that have no twenty-ninth.
            "2025-02-29T00:00:00Z",
            "2026-02-29T00:00:00Z",
            "2100-02-29T00:00:00Z",
            // February never has these at all.
            "2024-02-30T00:00:00Z",
            "2026-02-31T00:00:00Z",
            // The thirty-day months have no thirty-first.
            "2026-04-31T00:00:00Z",
            "2026-06-31T00:00:00Z",
            "2026-09-31T00:00:00Z",
            "2026-11-31T00:00:00Z",
        ] {
            assert_eq!(
                epoch_seconds(absent),
                None,
                "`{absent}` is not a date, and accepting it would record an instant days from the \
                 one it spells"
            );
        }
    }

    /// The dates that do exist still convert, including the awkward ones.
    #[test]
    fn the_calendar_dates_that_do_exist_are_accepted() {
        for present in [
            // Leap days, by each of the rules that decide them.
            "2024-02-29T00:00:00Z",
            "2000-02-29T00:00:00Z",
            // The last day of each length of month.
            "2026-01-31T00:00:00Z",
            "2026-02-28T00:00:00Z",
            "2026-04-30T00:00:00Z",
            // Either side of a year boundary.
            "2026-12-31T23:59:59Z",
            "2027-01-01T00:00:00Z",
        ] {
            assert!(
                epoch_seconds(present).is_some(),
                "`{present}` is a date this system must keep accepting"
            );
        }
    }

    /// Parsing and rendering are inverse, which is what makes the spelling one.
    #[test]
    fn an_instant_survives_a_round_trip() {
        let mut at = 0i64;
        // Steps of a second, a minute, an hour, a day, a year and a leap cycle: the walk crosses
        // month ends, leap days and the epoch without enumerating a century.
        for step in [1i64, 59, 3_600, 86_400, 86_400 * 365, 86_400 * 1_461] {
            for _ in 0..64 {
                let text = render_epoch_seconds(at).expect("the instant renders");
                assert_eq!(
                    epoch_seconds(&text),
                    Some(at),
                    "`{text}` must read back as the second it was written from"
                );
                at = at.saturating_add(step);
            }
        }
    }

    #[test]
    fn a_canonical_instant_converts_exactly_and_anything_else_is_refused() {
        assert_eq!(epoch_seconds("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(epoch_seconds("2026-08-28T10:15:30Z"), Some(1_787_912_130));

        for refused in [
            "2026-08-28T10:15:30.500Z",  // a fraction has no exact epoch second
            "2026-08-28T10:15:30+02:00", // a non-UTC offset is not canonical here
            "2026-08-28T10:15:60Z",      // a leap second has no epoch second of its own
            "2026-08-28 10:15:30Z",      // not RFC 3339
            "2026-13-01T00:00:00Z",      // not a month
            "",
        ] {
            assert_eq!(epoch_seconds(refused), None, "{refused}");
        }
    }

    /// The scan reads a range, not everything: entries outside the pin are never examined.
    #[test]
    fn a_scan_returns_only_the_pin_action_kind_and_window_it_asked_for() {
        let directory = scratch("scan");
        let mut index = Index::open(&directory).expect("it opens");

        // Two history partitions, so the wrong one being returned would be visible.
        index
            .insert(key("alice", "Read", "request", 100, 1), located(1))
            .expect("it inserts");
        index
            .insert(key("alice", "Login", "response", 50, 2), located(2))
            .expect("it inserts");
        index
            .insert(key("alice", "Read", "request", 5_000, 3), located(3))
            .expect("it inserts");
        index
            .insert(key("bob", "Read", "request", 100, 4), located(4))
            .expect("it inserts");

        let found = index.scan(&Query {
            event_type: "permguard.dogwood.event.v1".to_owned(),
            history: "alice".to_owned(),
            action: Some("Read".to_owned()),
            kind: Some("request".to_owned()),
            from: 0,
            until: 1_000,
        });

        assert_eq!(
            found.len(),
            1,
            "one record matches the pin, action, kind and window"
        );
        assert_eq!(found[0].seq, 1);
    }

    /// A leaf that names no action ranges over them, still inside its pin and window.
    #[test]
    fn a_query_that_fixes_less_still_never_leaves_its_history_partition() {
        let directory = scratch("unfixed");
        let mut index = Index::open(&directory).expect("it opens");
        index
            .insert(key("alice", "Read", "request", 100, 1), located(1))
            .expect("it inserts");
        index
            .insert(key("alice", "Login", "response", 50, 2), located(2))
            .expect("it inserts");
        index
            .insert(key("bob", "Read", "request", 100, 3), located(3))
            .expect("it inserts");

        let found = index.scan(&Query {
            event_type: "permguard.dogwood.event.v1".to_owned(),
            history: "alice".to_owned(),
            action: None,
            kind: None,
            from: 0,
            until: 1_000,
        });

        assert_eq!(found.len(), 2, "both of alice's, neither of bob's");
    }

    /// Reading one registered type must not return another retained beside it.
    #[test]
    fn a_scan_of_one_event_type_returns_no_other() {
        let directory = scratch("types");
        let mut index = Index::open(&directory).expect("it opens");
        index
            .insert(key("alice", "Read", "request", 100, 1), located(1))
            .expect("it inserts");
        let mut other = key("alice", "Read", "request", 100, 2);
        other.event_type = "permguard.future.event.v1".to_owned();
        index.insert(other, located(2)).expect("it inserts");

        let found = index.scan(&Query {
            event_type: "permguard.dogwood.event.v1".to_owned(),
            history: "alice".to_owned(),
            action: None,
            kind: None,
            from: 0,
            until: 1_000,
        });

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].seq, 1);
    }

    #[test]
    fn an_index_survives_a_restart() {
        let directory = scratch("restart");
        {
            let mut index = Index::open(&directory).expect("it opens");
            index
                .insert(key("alice", "Read", "request", 100, 1), located(1))
                .expect("it inserts");
        }
        let reopened = Index::open(&directory).expect("it reopens");

        assert_eq!(reopened.len(), 1);
        assert_eq!(reopened.covered_through(), 1);
    }

    /// A damaged index is an inconvenience, not data loss: the segments are the authority.
    #[test]
    fn a_damaged_index_is_rebuilt_from_the_segments() {
        let directory = scratch("rebuild");
        // One segment holding two records, written the way the journal writes them.
        let mut segment = Vec::new();
        for seq in 1u64..=2 {
            let record = json!({
                "seq": seq,
                "event_type": "permguard.dogwood.event.v1",
                "kind": "request",
                "history_key": {"pins": ["callerPrincipal"], "values": ["alice"], "digest": "h-alice"},
                "occurred_at": "2026-08-28T10:15:30Z",
                "event": {"action": "Drupe::Action::Read"},
            });
            segment.extend_from_slice(&serde_json::to_vec(&record).expect("it serializes"));
            segment.push(b'\n');
        }
        fs::write(directory.join("seg-00000000000000000001.events"), &segment)
            .expect("the segment is written");
        fs::write(directory.join(INDEX_FILE), b"this index is rubbish\n").expect("it writes");

        let index = Index::open(&directory).expect("a damaged index is rebuilt, not fatal");

        assert_eq!(
            index.len(),
            2,
            "both records were recovered from the segment"
        );
        let found = index.scan(&Query {
            event_type: "permguard.dogwood.event.v1".to_owned(),
            history: "h-alice".to_owned(),
            action: Some("Drupe::Action::Read".to_owned()),
            kind: Some("request".to_owned()),
            from: 0,
            until: i64::MAX,
        });
        assert_eq!(found.len(), 2);
        // And the offsets point at the right bytes: the second record starts where the first ends.
        assert_eq!(found[0].offset, 0);
        assert_eq!(found[1].offset, found[0].length);
    }

    #[test]
    fn entries_below_the_retained_beginning_are_forgotten_after_eviction() {
        let directory = scratch("forget");
        let mut index = Index::open(&directory).expect("it opens");
        for seq in 1..=4 {
            index
                .insert(
                    key("alice", "Read", "request", seq as i64, seq),
                    located(seq),
                )
                .expect("it inserts");
        }

        assert_eq!(index.forget_below(3).expect("it forgets"), 2);
        assert_eq!(index.len(), 2);
        assert_eq!(
            Index::open(&directory).expect("it reopens").len(),
            2,
            "and the forgetting is durable"
        );
    }
}
