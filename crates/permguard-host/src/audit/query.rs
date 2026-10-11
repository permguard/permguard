// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Reads and exports of one trail (WP-3.7, owner decisions of 2026-10-11).
//!
//! | Rule     | Here                                                                                  |
//! | -------- | ------------------------------------------------------------------------------------- |
//! | gaps     | every page states what it cannot show: the prefix retention deleted, the records an   |
//! |          | `access` queue dropped and any sequence missing from the day files                    |
//! | frontier | the first page fixes the trail's next sequence; later pages never pass it             |
//! | bounds   | a page stops at its record limit, its byte budget or its deadline                      |
//! | cursor   | the position, the frontier and the query, under an HMAC keyed by this process         |
//! | indexing | none: a read walks the day files from the cursor's day                                |
//!
//! A record goes to the day file of its `at` or a later one, never an earlier one, so a read
//! from `from` starts at that day's file; it walks on to the frontier, since a record whose
//! clock stepped back sits in a day file after its `at`.
//!
//! Authorization is the caller's: the Host API admits `audit.read` on the resource before any of
//! this runs.

use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hmac::{Hmac, KeyInit, Mac as _};
use sha2::Sha256;

use permguard_core::domains::digest::AUDIT_CURSOR;
use permguard_objects::cbor::{self, Value};

use crate::storage::Dir;

use super::Class;
use super::checkpoint::{self, Anchor, CHECKPOINT_SUFFIX};
use super::record::{AuditRecord, FactValue};
use super::trail::{self, CHECKPOINTS, DAY_SUFFIX};

/// The records a page answers when the caller names no limit.
pub const DEFAULT_LIMIT: usize = 100;
/// The most records one page answers.
pub const MAX_LIMIT: usize = 1000;
/// The most record bytes one page answers.
pub const MAX_PAGE_BYTES: usize = 1024 * 1024;
/// How long one page may walk the day files.
pub const PAGE_DEADLINE: Duration = Duration::from_secs(2);
/// The most checkpoints one answer lists, the newest kept.
pub const MAX_CHECKPOINTS: usize = 1000;

/// What a read asks for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Query {
    /// The earliest `at`, in seconds, inclusive.
    pub from: Option<u64>,
    /// The latest `at`, in seconds, inclusive.
    pub to: Option<u64>,
    /// How many records at most, `1..=MAX_LIMIT`.
    pub limit: Option<usize>,
    /// An export's frontier, below the trail's next sequence: fixed by the first page, and on a
    /// later page, when given, the one its cursor carries.
    pub frontier: Option<u64>,
    /// Where the previous page stopped.
    pub cursor: Option<String>,
}

/// Something a page cannot show, stated rather than left out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gap {
    /// Retention deleted every record below `below`, through the day `through`.
    Retention { below: u64, through: String },
    /// The `access` queue dropped `count` records before the record `seq`, which marks it.
    Dropped { seq: u64, count: u64 },
    /// The records `from..=to` are missing from the day files.
    Missing { from: u64, to: u64 },
}

/// One page of a read or an export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub records: Vec<AuditRecord>,
    pub gaps: Vec<Gap>,
    /// The trail's next sequence when the first page was read: no page passes it.
    pub frontier: u64,
    /// Where the next page starts; `None` when this one reached the frontier.
    pub next: Option<String>,
    /// What retention deleted, when it deleted anything.
    pub anchor: Option<Anchor>,
}

/// The checkpoints an answer carries, and how many older ones it leaves out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckpointList {
    pub files: Vec<CheckpointFile>,
    /// The older checkpoints beyond [`MAX_CHECKPOINTS`], left out and counted.
    pub omitted: usize,
}

/// One checkpoint as an answer carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointFile {
    /// Its file name below `checkpoints/`.
    pub name: String,
    /// The COSE_Sign1 envelope.
    pub envelope: Vec<u8>,
    /// The witness's co-signature, when one was kept.
    pub witness: Option<Vec<u8>>,
}

/// Why a read was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryError {
    /// The cursor is not one this process issued for this query.
    Cursor(String),
    /// A bound of the query is out of range.
    Invalid(String),
    /// The trail could not be read.
    Storage(String),
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cursor(detail) | Self::Invalid(detail) => f.write_str(detail),
            Self::Storage(detail) => write!(f, "the audit trail could not be read: {detail}"),
        }
    }
}

impl std::error::Error for QueryError {}

/// The position a cursor carries, and what it was issued for.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Position {
    export: bool,
    class: String,
    resource: String,
    from: Option<u64>,
    to: Option<u64>,
    frontier: u64,
    next_seq: u64,
    day: String,
}

/// The HMAC key cursors are issued under: drawn per process, so a cursor dies with the process.
pub struct CursorKey([u8; 32]);

impl std::fmt::Debug for CursorKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CursorKey(..)")
    }
}

impl CursorKey {
    /// A key drawn from the system's randomness.
    pub fn draw() -> Option<Self> {
        use ring::rand::SecureRandom as _;
        let mut key = [0u8; 32];
        ring::rand::SystemRandom::new().fill(&mut key).ok()?;
        Some(Self(key))
    }

    fn mac(&self, body: &[u8]) -> Hmac<Sha256> {
        #[allow(clippy::expect_used)]
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.0)
            .expect("HMAC takes a key of any length");
        mac.update(AUDIT_CURSOR.as_bytes());
        mac.update(body);
        mac
    }

    fn issue(&self, position: &Position) -> String {
        // An absent bound is the empty array, a present one the array of it.
        let opt = |value: Option<u64>| {
            Value::Array(value.map(|v| Value::Int(v as i64)).into_iter().collect())
        };
        let body = cbor::encode(&Value::Array(vec![
            Value::Bool(position.export),
            Value::Text(position.class.clone()),
            Value::Text(position.resource.clone()),
            opt(position.from),
            opt(position.to),
            Value::Int(position.frontier as i64),
            Value::Int(position.next_seq as i64),
            Value::Text(position.day.clone()),
        ]))
        .unwrap_or_default();
        let tag = self.mac(&body).finalize().into_bytes();
        format!("{}.{}", B64.encode(&body), B64.encode(tag))
    }

    fn open(&self, cursor: &str) -> Result<Position, QueryError> {
        let refused = || QueryError::Cursor("the cursor is not one this Host issued".to_owned());
        let (body, tag) = cursor.split_once('.').ok_or_else(refused)?;
        let body = B64.decode(body).map_err(|_| refused())?;
        let tag = B64.decode(tag).map_err(|_| refused())?;
        self.mac(&body).verify_slice(&tag).map_err(|_| refused())?;
        let Ok(Value::Array(items)) = cbor::decode_canonical(&body) else {
            return Err(refused());
        };
        let uint = |value: &Value| match value {
            Value::Int(v) if *v >= 0 => Some(*v as u64),
            _ => None,
        };
        let opt = |value: &Value| match value {
            Value::Array(items) if items.is_empty() => Some(None),
            Value::Array(items) if items.len() == 1 => uint(&items[0]).map(Some),
            _ => None,
        };
        let text = |value: &Value| match value {
            Value::Text(text) => Some(text.clone()),
            _ => None,
        };
        let read = || match items.as_slice() {
            [
                Value::Bool(export),
                class,
                resource,
                from,
                to,
                frontier,
                next_seq,
                day,
            ] => Some(Position {
                export: *export,
                class: text(class)?,
                resource: text(resource)?,
                from: opt(from)?,
                to: opt(to)?,
                frontier: uint(frontier)?,
                next_seq: uint(next_seq)?,
                day: text(day)?,
            }),
            _ => None,
        };
        read().ok_or_else(refused)
    }
}

/// Reads one page of the trail in `dir`, whose next sequence is `next_seq` now.
pub(crate) fn page(
    key: &CursorKey,
    dir: &Dir,
    class: Class,
    resource: &str,
    next_seq: u64,
    query: &Query,
    export: bool,
) -> Result<Page, QueryError> {
    let storage = |error: crate::storage::StorageError| QueryError::Storage(error.to_string());
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    if limit == 0 || limit > MAX_LIMIT {
        return Err(QueryError::Invalid(format!(
            "a page answers 1 to {MAX_LIMIT} records"
        )));
    }
    if let (Some(from), Some(to)) = (query.from, query.to)
        && from > to
    {
        return Err(QueryError::Invalid("`from` comes after `to`".to_owned()));
    }
    let days = trail::days(dir).map_err(storage)?;
    let position = match &query.cursor {
        Some(cursor) => {
            let position = key.open(cursor)?;
            let (from, to) = if export {
                (None, None)
            } else {
                (query.from, query.to)
            };
            if position.export != export
                || position.class != class.as_str()
                || position.resource != resource
                || position.from != from
                || position.to != to
                || query
                    .frontier
                    .is_some_and(|frontier| frontier != position.frontier)
            {
                return Err(QueryError::Cursor(
                    "the cursor was issued for another query".to_owned(),
                ));
            }
            position
        }
        None => Position {
            export,
            class: class.as_str().to_owned(),
            resource: resource.to_owned(),
            from: if export { None } else { query.from },
            to: if export { None } else { query.to },
            frontier: query
                .frontier
                .filter(|_| export)
                .map_or(next_seq, |frontier| frontier.min(next_seq)),
            next_seq: 0,
            day: String::new(),
        },
    };
    let anchor = trail::anchor(dir).map_err(storage)?;
    let mut gaps = Vec::new();
    if let Some(anchor) = &anchor
        && position.next_seq < anchor.low_watermark
        && position
            .from
            .is_none_or(|from| day_period(from) <= anchor.through)
    {
        gaps.push(Gap::Retention {
            below: anchor.low_watermark,
            through: anchor.through.clone(),
        });
    }
    let first_day = position
        .from
        .map(|from| format!("{}{DAY_SUFFIX}", day_period(from)));
    let started = Instant::now();
    let mut records = Vec::new();
    let mut bytes = 0usize;
    let mut expected: Option<u64> = None;
    let mut next: Option<(u64, String)> = None;
    // Records walked from the cursor on: the deadline stops a page only past the first, so the
    // next cursor always moves.
    let mut walked = 0u64;
    'days: for day in days.iter().filter(|day| {
        day.as_str() >= position.day.as_str()
            && first_day.as_ref().is_none_or(|first| *day >= first)
    }) {
        for record in trail::read_written(dir, day).map_err(storage)? {
            if record.seq >= position.frontier {
                break 'days;
            }
            if record.seq < position.next_seq {
                expected = Some(record.seq + 1);
                continue;
            }
            if walked > 0 && started.elapsed() > PAGE_DEADLINE {
                next = Some((record.seq, day.clone()));
                break 'days;
            }
            walked += 1;
            match expected {
                Some(seq) if record.seq > seq => gaps.push(Gap::Missing {
                    from: seq,
                    to: record.seq - 1,
                }),
                None if record.seq > position.next_seq
                    && anchor
                        .as_ref()
                        .is_none_or(|anchor| record.seq > anchor.low_watermark)
                    && position.from.is_none() =>
                {
                    let from = anchor.as_ref().map_or(position.next_seq, |anchor| {
                        anchor.low_watermark.max(position.next_seq)
                    });
                    gaps.push(Gap::Missing {
                        from,
                        to: record.seq - 1,
                    });
                }
                _ => {}
            }
            expected = Some(record.seq + 1);
            if position.from.is_some_and(|from| record.at < from)
                || position.to.is_some_and(|to| record.at > to)
            {
                continue;
            }
            let size = record.encode().map(|b| b.len()).unwrap_or_default();
            if records.len() == limit || (bytes + size > MAX_PAGE_BYTES && !records.is_empty()) {
                next = Some((record.seq, day.clone()));
                break 'days;
            }
            bytes += size;
            if record.action == "audit.access_dropped"
                && let Some(FactValue::Uint(count)) = record.facts.get("dropped")
            {
                gaps.push(Gap::Dropped {
                    seq: record.seq,
                    count: *count,
                });
            }
            records.push(record);
        }
    }
    let next = next.map(|(next_seq, day)| {
        key.issue(&Position {
            next_seq,
            day,
            ..position.clone()
        })
    });
    Ok(Page {
        records,
        gaps,
        frontier: position.frontier,
        next,
        anchor,
    })
}

/// The checkpoints of the trail in `dir`, in the order they were sealed, of the day `period`
/// alone when it names one, the newest [`MAX_CHECKPOINTS`] kept and the rest counted; with each,
/// its co-signature. A trail never opened since checkpoints exist has none.
pub(crate) fn checkpoints(dir: &Dir, period: Option<&str>) -> Result<CheckpointList, QueryError> {
    let storage = |error: crate::storage::StorageError| QueryError::Storage(error.to_string());
    if let Some(period) = period
        && permguard_core::time::Date::from_iso(period).is_none()
    {
        return Err(QueryError::Invalid(format!("`{period}` is not a day")));
    }
    let held = match dir.subdir(CHECKPOINTS, false) {
        Ok(held) => held,
        Err(crate::storage::StorageError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(CheckpointList::default());
        }
        Err(error) => return Err(storage(error)),
    };
    let names = held.names().map_err(storage)?;
    let mut ordered: Vec<String> = checkpoint::ordered(names.iter().cloned())
        .into_iter()
        .filter(|name| {
            period.is_none_or(|period| {
                checkpoint::parse_name(name).is_some_and(|(day, _)| day == period)
            })
        })
        .collect();
    let omitted = ordered.len().saturating_sub(MAX_CHECKPOINTS);
    ordered.drain(..omitted);
    let files = ordered
        .into_iter()
        .map(|name| {
            let envelope = held.read(&name).map_err(storage)?.unwrap_or_default();
            let witness_name = checkpoint::witness_name(&name);
            let witness = if names.contains(&witness_name) {
                held.read(&witness_name).map_err(storage)?
            } else {
                None
            };
            debug_assert!(name.ends_with(CHECKPOINT_SUFFIX));
            Ok(CheckpointFile {
                name,
                envelope,
                witness,
            })
        })
        .collect::<Result<Vec<_>, QueryError>>()?;
    Ok(CheckpointList { files, omitted })
}

/// The day `at` falls in, `YYYY-MM-DD`.
fn day_period(at: u64) -> String {
    trail::period_of(&trail::day_name(at))
}
