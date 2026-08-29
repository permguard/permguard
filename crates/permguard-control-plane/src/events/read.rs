// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Reading events back: bounded, filtered, and honest about what it proves.
//!
//! # Filtering does not stall pagination
//!
//! A page may legitimately match nothing while still advancing over the positions it examined —
//! and a consumer that stopped on "empty" would stop in the middle of a ledger whose next segment
//! is full of what it asked for. So `next` advances over non-matching positions, the scan work is
//! bounded separately from the records returned, and a consumer stops from `next`, `more` and its
//! own `until`. Never from emptiness.
//!
//! # `event_type` is a first-class filter, not a predicate over everything
//!
//! Listing one type must not scan and decode every other type retained for the ledger. When the
//! filter names types, the read walks the store's per-type index and reads only the positions it
//! names; when it names none, it walks the segments. The two are the same contract with different
//! costs, and the difference is visible in `coverage.examined`.
//!
//! # What a filtered block does not claim
//!
//! Chain completeness. The chain links adjacent records of one producer, and a filtered view is a
//! subsequence — so `coverage.contiguous` is false and the inclusion paths are what a reader
//! verifies with. Claiming otherwise for a view that cannot prove it is the one thing a store
//! holding evidence must not do.

use std::collections::BTreeMap;

use permguard_stream::cursor::{Cursor, CursorError, CursorKey, Position, filter_digest};
use permguard_stream::{Block, Coverage, Frontier, Window};
use serde_json::Value;

use super::store::{EventStore, Scope, read_segment};

/// The API family an event-log offset belongs to.
pub const API: &str = "permguard.api.events.native.v1alpha1";

/// What a reader is narrowing to.
///
/// Every field is optional and every one that is set narrows: there is no filter here that widens
/// what a scope may return, because the scope is the authorization boundary and a filter is not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filters {
    /// The registered event types, exact. Empty means every type the scope holds.
    pub event_types: Vec<String>,
    /// One producer's records inside a tenant view.
    pub producer: Option<String>,
    /// One incarnation of that producer.
    pub instance: Option<String>,
    /// The profile the submission selected.
    pub profile: Option<String>,
    /// One addressed policy partition.
    pub policy_partition: Option<String>,
    /// The runtime's own word for what happened.
    pub kind: Option<String>,
    /// One occurrence, by the identifier its caller stated.
    pub event_id: Option<String>,
    /// The earliest occurrence time, inclusive, as a canonical instant.
    pub since: Option<String>,
    /// The latest occurrence time, inclusive.
    pub until_time: Option<String>,
    /// One Dogwood history key, by its digest.
    pub history: Option<String>,
}

impl Filters {
    /// The canonical form a cursor binds.
    ///
    /// Normalized here and nowhere else: two spellings of one filter set must produce one digest,
    /// or a consumer would find its own cursor refused because it listed two types in the other
    /// order. Sorted, deduplicated, and with absent fields absent rather than null.
    pub fn canonical(&self) -> Value {
        let mut types = self.event_types.clone();
        types.sort();
        types.dedup();

        let mut held = serde_json::Map::new();
        held.insert("event_types".to_owned(), serde_json::json!(types));
        for (name, value) in [
            ("producer", &self.producer),
            ("instance", &self.instance),
            ("profile", &self.profile),
            ("policy_partition", &self.policy_partition),
            ("kind", &self.kind),
            ("event_id", &self.event_id),
            ("since", &self.since),
            ("until_time", &self.until_time),
            ("history", &self.history),
        ] {
            if let Some(held_value) = value {
                held.insert(name.to_owned(), serde_json::json!(held_value));
            }
        }

        Value::Object(held)
    }

    /// The digest a cursor is bound to.
    pub fn digest(&self) -> String {
        filter_digest(&self.canonical())
    }

    /// Whether anything narrows at all.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Whether one record matches.
    fn matches(&self, record: &Value) -> bool {
        let text = |path: &[&str]| -> Option<&str> {
            let mut held = record;
            for segment in path {
                held = held.get(*segment)?;
            }

            held.as_str()
        };
        let same = |asked: &Option<String>, path: &[&str]| match asked {
            Some(asked) => text(path) == Some(asked.as_str()),
            None => true,
        };

        if !self.event_types.is_empty() {
            let held = text(&["event_type"]).unwrap_or_default();
            if !self.event_types.iter().any(|asked| asked == held) {
                return false;
            }
        }
        if !same(&self.producer, &["stream", "producer", "id"])
            || !same(&self.instance, &["stream", "producer", "instance"])
            || !same(&self.profile, &["profile"])
            || !same(&self.kind, &["kind"])
            || !same(&self.event_id, &["event_id"])
            || !same(&self.history, &["history_key", "digest"])
        {
            return false;
        }
        if let Some(partition) = &self.policy_partition {
            let held = record
                .get("policy_partitions")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .any(|held| held == partition)
                })
                .unwrap_or(false);
            if !held {
                return false;
            }
        }
        // Compared as text, which is exact because the instants are canonical: one spelling, fixed
        // width, UTC. Parsing them to compare would be the same comparison with a failure mode.
        let occurred = text(&["occurred_at"]).unwrap_or_default();
        if let Some(since) = &self.since
            && occurred < since.as_str()
        {
            return false;
        }
        if let Some(until) = &self.until_time
            && occurred > until.as_str()
        {
            return false;
        }

        true
    }
}

/// Why a read was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    /// The offset is not usable here.
    Offset(CursorError),
    /// The offset is older than what is held; here is where to resume, and how much was lost.
    Expired {
        oldest: String,
        oldest_sequence: u64,
        requested_sequence: u64,
    },
    /// The store could not answer.
    Unavailable(String),
    /// The search gave up before reaching the end of its snapshot.
    ///
    /// Distinct from "not found", and it has to be: a lookup that walked its bound and stopped has
    /// established nothing about whether the record is there. Returning `None` for it would turn a
    /// bound this code chose into a statement about the caller's data.
    SearchExhausted {
        /// How many pages were walked before giving up.
        pages: usize,
        /// Where a caller may resume the search from.
        resume: String,
    },
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Offset(error) => write!(formatter, "{error}"),
            Self::Expired {
                oldest,
                oldest_sequence,
                requested_sequence,
            } => write!(
                formatter,
                "this offset stands at {requested_sequence} and the oldest still held is \
                 {oldest_sequence}: the records in between left on the retention schedule. Resume \
                 from `{oldest}`, knowing that {} positions are gone",
                oldest_sequence.saturating_sub(*requested_sequence)
            ),
            Self::Unavailable(detail) => write!(formatter, "{detail}"),
            Self::SearchExhausted { pages, resume } => write!(
                formatter,
                "this lookup walked {pages} pages without reaching the end of the store and \
                 stopped: whether the record is here is not established. Resume from `{resume}`"
            ),
        }
    }
}

impl std::error::Error for ReadError {}

/// One page of events.
pub type Page = Block<Value>;

/// Reads one bounded, filtered block of `scope`.
pub fn read(
    store: &EventStore,
    scope: &Scope,
    filters: &Filters,
    key: &CursorKey,
    window: &Window,
) -> Result<Page, ReadError> {
    let segments = store
        .segments(scope)
        .map_err(|error| ReadError::Unavailable(error.to_string()))?;
    let oldest_segment = segments.first().map(|(first, _)| *first).unwrap_or(0);
    let stream = scope.key();
    let bound = filters.digest();

    let beginning = |until: Option<Frontier>| {
        let mut cursor = Cursor::beginning(API, &stream, &bound, until);
        cursor.advance(
            &stream,
            Position {
                segment: oldest_segment,
                offset: 0,
            },
        );

        cursor
    };
    let oldest_available = beginning(window.until.clone())
        .seal(key)
        .map_err(ReadError::Offset)?;

    let mut cursor = match &window.from {
        Some(token) => Cursor::open(token, key, API, &stream, &bound).map_err(ReadError::Offset)?,
        None => beginning(window.until.clone()),
    };
    // An export declares its bound on its second page — the first could not have, because the
    // bound is that page's own watermark. Once declared it cannot be changed or dropped.
    match (&cursor.until, &window.until) {
        (Some(held), Some(asked)) if held != asked => {
            return Err(ReadError::Offset(CursorError::WrongFilters));
        }
        (Some(_), None) => return Err(ReadError::Offset(CursorError::WrongFilters)),
        _ => cursor.until.clone_from(&window.until),
    }

    let mut position = cursor.position(&stream);
    if position.segment == 0 {
        position.segment = oldest_segment;
    }
    if position.segment < oldest_segment {
        return Err(ReadError::Expired {
            oldest: oldest_available,
            oldest_sequence: oldest_segment,
            requested_sequence: position.segment,
        });
    }

    let by_index = !filters.event_types.is_empty();
    let walked = if by_index {
        // The index names exactly the positions of the requested types, so the other types
        // retained for this ledger are never opened.
        indexed(store, scope, filters, &segments, position, window)?
    } else {
        scanned(&segments, filters, position, window)?
    };

    cursor.advance(&stream, walked.position);
    if let Some(observed) = walked.observed {
        cursor.frontier.cover(&stream, observed);
    }
    let observed_frontier = cursor.frontier.clone();
    let end = Frontier::of(
        &stream,
        end_of(store, scope).unwrap_or_else(|| observed_frontier.covered_through(&stream)),
    );
    let more = permguard_stream::more(window, &observed_frontier, &end) || walked.stopped_early;

    let (proof, inclusion) = if window.proof {
        proofs(store, scope, &walked.records)
    } else {
        (Vec::new(), Vec::new())
    };

    Ok(Page {
        records: walked.records,
        next: cursor.seal(key).map_err(ReadError::Offset)?,
        oldest_available,
        high_watermark: observed_frontier.encode(),
        more,
        proof,
        inclusion,
        coverage: Coverage {
            // A contiguous run of one producer, and only when nothing narrowed it: anything else
            // is a subsequence whose chain does not link across the gaps.
            contiguous: matches!(scope, Scope::Stream { .. }) && filters.is_empty(),
            examined: walked.examined,
            scan_bounded: walked.scan_bounded,
        },
    })
}

/// One occurrence, by the identifier its caller stated.
///
/// Bounded like any other read: the search walks a finite snapshot and stops, so "no such event"
/// is an answer rather than a command that never returns on a ledger that keeps growing.
pub fn get(
    store: &EventStore,
    scope: &Scope,
    event_id: &str,
    key: &CursorKey,
) -> Result<Option<Value>, ReadError> {
    let filters = Filters {
        event_id: Some(event_id.to_owned()),
        ..Filters::default()
    };
    let mut window = Window {
        limit_records: permguard_stream::window::MAX_RECORDS,
        ..Window::default()
    };
    // The bound this search is of. Records written after it are not in it, which is the correct
    // answer for a question asked at a moment.
    let mut snapshot = None;
    let mut resume = String::new();
    for _ in 0..SEARCH_PAGES {
        let page = read(store, scope, &filters, key, &window)?;
        if let Some(found) = page.records.into_iter().next() {
            return Ok(Some(found));
        }
        if snapshot.is_none() {
            snapshot = Frontier::decode(&page.high_watermark);
            window.until.clone_from(&snapshot);
        }
        if !page.more {
            // Reached the end of the snapshot without a match. *This* is "not here".
            return Ok(None);
        }
        resume.clone_from(&page.next);
        window.from = Some(page.next);
    }

    // The bound ran out first. Saying `None` here would report a limit this code chose as an
    // absence in the caller's data — the one answer a lookup must never invent.
    Err(ReadError::SearchExhausted {
        pages: SEARCH_PAGES,
        resume,
    })
}

/// How many pages a single-record lookup walks before it stops and says so.
const SEARCH_PAGES: usize = 10_000;

/// What one walk of the store produced.
struct Walked {
    records: Vec<Value>,
    position: Position,
    observed: Option<u64>,
    examined: usize,
    scan_bounded: bool,
    /// Whether the walk stopped with matching positions still ahead of it.
    stopped_early: bool,
}

/// Walks the segments, matching as it goes.
fn scanned(
    segments: &[(u64, std::path::PathBuf)],
    filters: &Filters,
    mut position: Position,
    window: &Window,
) -> Result<Walked, ReadError> {
    let limit = window.records();
    let budget = window.bytes();
    let mut records = Vec::new();
    let mut bytes = 0u64;
    let mut examined = 0usize;
    let mut stopped = false;

    for (first, path) in segments {
        if *first < position.segment {
            continue;
        }
        if *first > position.segment {
            position.segment = *first;
            position.offset = 0;
        }
        loop {
            let (found, next_offset) = read_segment(path, position.offset, 64)
                .map_err(|error| ReadError::Unavailable(error.to_string()))?;
            if found.is_empty() {
                break;
            }
            for record in found {
                examined += 1;
                position.offset += 1;
                if !filters.matches(&record) {
                    continue;
                }
                let size = serde_json::to_vec(&record)
                    .map(|held| held.len() as u64)
                    .unwrap_or(0);
                if !records.is_empty() && bytes + size > budget {
                    // Step back: this record has not been returned, so the next page must start at
                    // it rather than past it.
                    position.offset -= 1;
                    stopped = true;
                    break;
                }
                bytes += size;
                records.push(record);
                if records.len() >= limit {
                    stopped = true;
                    break;
                }
            }
            if stopped || examined >= permguard_stream::window::MAX_EXAMINED {
                break;
            }
            position.offset = next_offset;
        }
        if stopped || examined >= permguard_stream::window::MAX_EXAMINED {
            break;
        }
    }

    let observed = records
        .last()
        .and_then(|record| record.get("seq").and_then(Value::as_u64))
        .map(|seq| seq + 1);

    Ok(Walked {
        records,
        position,
        observed,
        examined,
        scan_bounded: examined >= permguard_stream::window::MAX_EXAMINED,
        stopped_early: stopped,
    })
}

/// Walks only the positions the type index names.
fn indexed(
    store: &EventStore,
    scope: &Scope,
    filters: &Filters,
    segments: &[(u64, std::path::PathBuf)],
    mut position: Position,
    window: &Window,
) -> Result<Walked, ReadError> {
    let limit = window.records();
    let budget = window.bytes();
    let paths: BTreeMap<u64, &std::path::PathBuf> = segments
        .iter()
        .map(|(first, path)| (*first, path))
        .collect();

    // Every requested type's positions, merged into one order. Sorted rather than interleaved by
    // hand, so the block comes back in the scope's own order whatever order the types were asked
    // in.
    let mut positions: Vec<(u64, u64)> = Vec::new();
    for event_type in &filters.event_types {
        positions.extend(
            store
                .positions_of(scope, event_type)
                .map_err(|error| ReadError::Unavailable(error.to_string()))?,
        );
    }
    positions.sort_unstable();
    positions.dedup();

    let mut records = Vec::new();
    let mut bytes = 0u64;
    let mut examined = 0usize;
    let mut stopped = false;
    let mut last = position;

    for (segment, line) in positions {
        if (segment, line) < (position.segment, position.offset) {
            continue;
        }
        let Some(path) = paths.get(&segment) else {
            continue;
        };
        examined += 1;
        let held = super::store::read_line(path, line)
            .map_err(|error| ReadError::Unavailable(error.to_string()))?;
        let Some(record) = held else {
            continue;
        };
        last = Position {
            segment,
            offset: line + 1,
        };
        if !filters.matches(&record) {
            continue;
        }
        let size = serde_json::to_vec(&record)
            .map(|held| held.len() as u64)
            .unwrap_or(0);
        if !records.is_empty() && bytes + size > budget {
            last = Position {
                segment,
                offset: line,
            };
            stopped = true;
            break;
        }
        bytes += size;
        records.push(record);
        if records.len() >= limit {
            stopped = true;
            break;
        }
        if examined >= permguard_stream::window::MAX_EXAMINED {
            break;
        }
    }
    position = last;

    let observed = records
        .last()
        .and_then(|record| record.get("seq").and_then(Value::as_u64))
        .map(|seq| seq + 1);

    Ok(Walked {
        records,
        position,
        observed,
        examined,
        scan_bounded: examined >= permguard_stream::window::MAX_EXAMINED,
        stopped_early: stopped,
    })
}

/// The envelopes covering a page's records, and one inclusion path per record.
fn proofs(store: &EventStore, scope: &Scope, records: &[Value]) -> (Vec<Value>, Vec<Value>) {
    // Read from the records themselves rather than from the request, so a tenant asking for a
    // proof cannot name a stream it has no records of.
    let mut streams: Vec<permguard_events::Stream> = records
        .iter()
        .filter_map(|record| serde_json::from_value(record.get("stream")?.clone()).ok())
        .collect();
    streams.dedup_by(|left, right| left == right);

    let mut envelopes = Vec::new();
    for stream in &streams {
        if let Ok(held) = store.envelopes(stream) {
            envelopes.extend(held);
        }
    }

    let mut inclusion = Vec::new();
    for record in records {
        let Some(path) = inclusion_path(store, scope, record, &envelopes) else {
            continue;
        };
        inclusion.push(path);
    }

    (envelopes, inclusion)
}

/// One record's place in the tree its batch was signed with.
///
/// Rebuilt from the **producer stream**, not from the page: the leaves of a batch include records
/// of every tenant it touched, and the point is that the tenant never sees those and still gets a
/// path that reaches the root its signed envelope attests.
fn inclusion_path(
    store: &EventStore,
    scope: &Scope,
    record: &Value,
    envelopes: &[Value],
) -> Option<Value> {
    use base64::Engine as _;

    let seq = record.get("seq").and_then(Value::as_u64)?;
    let stream: permguard_events::Stream =
        serde_json::from_value(record.get("stream")?.clone()).ok()?;

    let (first, last, root) = envelopes.iter().find_map(|signed| {
        let payload = signed.get("payload").and_then(Value::as_str)?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .ok()?;
        let envelope: permguard_events::envelope::Envelope = serde_json::from_slice(&bytes).ok()?;
        if envelope.stream != stream || !(envelope.first_seq..=envelope.last_seq).contains(&seq) {
            return None;
        }

        Some((envelope.first_seq, envelope.last_seq, envelope.merkle_root))
    })?;

    let _ = scope;
    let producer = Scope::Stream {
        zone: stream.zone.clone(),
        ledger: stream.ledger.clone(),
        class: stream.producer.class.clone(),
        producer: stream.producer.id.clone(),
        instance: stream.producer.instance.clone(),
    };
    let mut leaves: Vec<(u64, String)> = Vec::new();
    for (_, path) in store.segments(&producer).ok()? {
        let (held, _) = read_segment(&path, 0, usize::MAX).ok()?;
        for value in held {
            let Some(held_seq) = value.get("seq").and_then(Value::as_u64) else {
                continue;
            };
            if !(first..=last).contains(&held_seq) {
                continue;
            }
            if let Ok(digest) = permguard_events::digest_of(&value) {
                leaves.push((held_seq, digest));
            }
        }
    }
    leaves.sort_by_key(|(held_seq, _)| *held_seq);
    let index = leaves.iter().position(|(held_seq, _)| *held_seq == seq)?;
    let digests: Vec<String> = leaves.into_iter().map(|(_, digest)| digest).collect();
    let path = permguard_decisions::merkle::path(&digests, index)?;

    serde_json::to_value(serde_json::json!({
        "seq": seq,
        "leaf": digests.get(index)?,
        "root": root,
        "path": path,
    }))
    .ok()
}

/// The exclusive end of a scope right now: one past its highest sequence.
fn end_of(store: &EventStore, scope: &Scope) -> Option<u64> {
    let segments = store.segments(scope).ok()?;
    let (_, last) = segments.last()?;
    let (records, _) = read_segment(last, 0, usize::MAX).ok()?;

    records
        .last()
        .and_then(|record| record.get("seq").and_then(Value::as_u64))
        .map(|seq| seq + 1)
}
