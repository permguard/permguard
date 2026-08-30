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
    /// The scope named does not resolve to a ledger this plane holds.
    ///
    /// Distinct from an empty page, and the distinction is the point: a page with no records says
    /// this ledger recorded nothing, and that is a statement about the data. A scope that does not
    /// resolve is a statement about the request, and answering it with an empty page would let a
    /// mistyped or wrongly-shaped scope read as an audit trail with nothing in it.
    Unknown(String),
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
            Self::Unknown(detail) => write!(formatter, "{detail}"),
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
    let gate = store.scope_gate(scope);
    let _reading = match gate.lock() {
        Ok(held) => held,
        Err(poisoned) => poisoned.into_inner(),
    };
    let end = store
        .frontier(scope)
        .map_err(|error| ReadError::Unavailable(error.to_string()))?;
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
        indexed(
            store,
            scope,
            filters,
            &segments,
            position,
            window,
            cursor.frontier.clone(),
        )?
    } else {
        scanned(
            scope,
            &segments,
            filters,
            position,
            window,
            cursor.frontier.clone(),
        )?
    };

    cursor.advance(&stream, walked.position);
    cursor.frontier = walked.frontier;
    let target = window.until.as_ref().unwrap_or(&end);
    if !walked.stopped_early && !walked.scan_bounded {
        let through = target.covered_through(&stream);
        cursor.frontier.cover(&stream, through);
        cursor.advance(&stream, position_of(through));
    }
    if cursor.frontier.covered_through(&stream) >= target.covered_through(&stream) {
        for (producer, sequence) in &target.covered {
            cursor.frontier.cover(producer, *sequence);
        }
    }
    let observed_frontier = cursor.frontier.clone();
    let more = permguard_stream::more(window, &observed_frontier, &end) || walked.stopped_early;

    let (proof, inclusion) = if window.proof {
        proofs(store, &walked.records)?
    } else {
        (Vec::new(), Vec::new())
    };

    Ok(Page {
        records: walked.records,
        next: cursor.seal(key).map_err(ReadError::Offset)?,
        oldest_available,
        // A finite export keeps echoing the snapshot it is bounded by. Returning the moving
        // current end on later pages invites a client to replace its bound and create an export
        // that never finishes on a busy ledger.
        high_watermark: target.encode(),
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

fn progress(position: Position) -> u64 {
    position
        .segment
        .saturating_sub(1)
        .saturating_add(position.offset)
}

fn position_of(progress: u64) -> Position {
    if progress == 0 {
        return Position {
            segment: 1,
            offset: 0,
        };
    }
    let next = progress.saturating_add(1);
    let segment =
        next.saturating_sub(1) / super::store::SEGMENT_RECORDS * super::store::SEGMENT_RECORDS + 1;

    Position {
        segment,
        offset: next.saturating_sub(segment),
    }
}

fn at_bound(scope: &Scope, position: Position, window: &Window) -> bool {
    window
        .until
        .as_ref()
        .is_some_and(|bound| progress(position) >= bound.covered_through(&scope.key()))
}

fn observe(scope: &Scope, frontier: &mut Frontier, position: Position, record: &Value) {
    frontier.cover(&scope.key(), progress(position));
    if matches!(scope, Scope::Tenant { .. })
        && let Some(stream) = record
            .get("stream")
            .cloned()
            .and_then(|value| serde_json::from_value::<permguard_events::Stream>(value).ok())
        && let Some(sequence) = record.get("seq").and_then(Value::as_u64)
    {
        frontier.cover(
            &Scope::for_stream(&stream).key(),
            sequence.saturating_add(1),
        );
    }
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
    frontier: Frontier,
    examined: usize,
    scan_bounded: bool,
    /// Whether the walk stopped with matching positions still ahead of it.
    stopped_early: bool,
}

/// Walks the segments, matching as it goes.
fn scanned(
    scope: &Scope,
    segments: &[(u64, std::path::PathBuf)],
    filters: &Filters,
    mut position: Position,
    window: &Window,
    mut frontier: Frontier,
) -> Result<Walked, ReadError> {
    let limit = window.records();
    let budget = window.bytes();
    let mut records = Vec::new();
    let mut bytes = 0u64;
    let mut examined = 0usize;
    let mut stopped = false;

    'segments: for (first, path) in segments {
        if *first < position.segment {
            continue;
        }
        if *first > position.segment {
            position.segment = *first;
            position.offset = 0;
        }
        loop {
            if at_bound(scope, position, window) {
                break 'segments;
            }
            let (found, next_offset) = read_segment(path, position.offset, 64)
                .map_err(|error| ReadError::Unavailable(error.to_string()))?;
            if found.is_empty() {
                break;
            }
            for record in found {
                if at_bound(scope, position, window) {
                    break 'segments;
                }
                examined += 1;
                position.offset += 1;
                if !filters.matches(&record) {
                    observe(scope, &mut frontier, position, &record);
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
                observe(scope, &mut frontier, position, &record);
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

    Ok(Walked {
        records,
        position,
        frontier,
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
    mut frontier: Frontier,
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
        if at_bound(
            scope,
            Position {
                segment,
                offset: line,
            },
            window,
        ) {
            break;
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
            observe(scope, &mut frontier, last, &record);
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
        observe(scope, &mut frontier, last, &record);
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

    Ok(Walked {
        records,
        position,
        frontier,
        examined,
        scan_bounded: examined >= permguard_stream::window::MAX_EXAMINED,
        stopped_early: stopped,
    })
}

/// The envelopes covering a page's records, and one inclusion path per record.
fn proofs(store: &EventStore, records: &[Value]) -> Result<(Vec<Value>, Vec<Value>), ReadError> {
    use base64::Engine as _;

    struct BatchProof {
        envelope: permguard_events::envelope::Envelope,
        digests: Vec<String>,
    }

    let unavailable = |detail: String| ReadError::Unavailable(detail);
    let mut batches: Vec<BatchProof> = Vec::new();
    let mut proof = Vec::new();
    let mut inclusion = Vec::with_capacity(records.len());

    for record in records {
        // Read identity from the returned record itself. A tenant cannot use a proof request to
        // name a producer stream it was not already entitled to read.
        let sequence = record
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| unavailable("an event record has no sequence".to_owned()))?;
        let stream: permguard_events::Stream = serde_json::from_value(
            record
                .get("stream")
                .cloned()
                .ok_or_else(|| unavailable("an event record has no stream".to_owned()))?,
        )
        .map_err(|error| unavailable(format!("an event record has an invalid stream: {error}")))?;

        let found = batches.iter().position(|batch| {
            batch.envelope.stream == stream
                && (batch.envelope.first_seq..=batch.envelope.last_seq).contains(&sequence)
        });
        let batch_index = match found {
            Some(index) => index,
            None => {
                let signed = store
                    .envelope_covering(&stream, sequence)
                    .map_err(|error| unavailable(error.to_string()))?
                    .ok_or_else(|| {
                        unavailable(format!(
                            "no signed batch covers sequence {sequence} of {}",
                            Scope::for_stream(&stream).key()
                        ))
                    })?;
                let payload = signed
                    .get("payload")
                    .and_then(Value::as_str)
                    .ok_or_else(|| unavailable("a signed batch has no payload".to_owned()))?;
                let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(payload)
                    .map_err(|error| {
                        unavailable(format!("a batch payload is not base64: {error}"))
                    })?;
                let envelope: permguard_events::envelope::Envelope = serde_json::from_slice(&bytes)
                    .map_err(|error| {
                        unavailable(format!("a batch payload is not an event envelope: {error}"))
                    })?;
                if envelope.stream != stream
                    || !(envelope.first_seq..=envelope.last_seq).contains(&sequence)
                {
                    return Err(unavailable(format!(
                        "the selected signed batch does not cover sequence {sequence} of {}",
                        Scope::for_stream(&stream).key()
                    )));
                }
                let held = store
                    .records_between(&stream, envelope.first_seq, envelope.last_seq)
                    .map_err(|error| unavailable(error.to_string()))?;
                let digests: Vec<String> = held
                    .iter()
                    .map(permguard_events::digest_of)
                    .collect::<Result<_, _>>()
                    .map_err(|error| unavailable(error.to_string()))?;
                let root = permguard_decisions::merkle::root(&digests)
                    .ok_or_else(|| unavailable("a signed batch has no Merkle leaves".to_owned()))?;
                if root != envelope.merkle_root {
                    return Err(unavailable(format!(
                        "the retained producer records do not reproduce the Merkle root of batch \
                         {}..={}",
                        envelope.first_seq, envelope.last_seq
                    )));
                }
                proof.push(signed);
                batches.push(BatchProof { envelope, digests });
                batches.len() - 1
            }
        };

        let batch = &batches[batch_index];
        let index = usize::try_from(sequence.saturating_sub(batch.envelope.first_seq))
            .map_err(|_| unavailable("a Merkle leaf position is too large".to_owned()))?;
        let leaf = batch
            .digests
            .get(index)
            .ok_or_else(|| unavailable("a Merkle leaf is missing".to_owned()))?;
        let returned =
            permguard_events::digest_of(record).map_err(|error| unavailable(error.to_string()))?;
        if returned != *leaf {
            return Err(unavailable(format!(
                "the returned record at sequence {sequence} differs from its producer copy"
            )));
        }
        let path = permguard_decisions::merkle::path(&batch.digests, index)
            .ok_or_else(|| unavailable("a Merkle inclusion path cannot be built".to_owned()))?;
        inclusion.push(serde_json::json!({
            "seq": sequence,
            "leaf": leaf,
            "root": batch.envelope.merkle_root,
            "path": path,
        }));
    }

    Ok((proof, inclusion))
}

/// Turns the scope a reader named into the one the records are keyed by.
///
/// # Why a read has to do this at all
///
/// A record is written under the zone and ledger **identities**, because those are what a rename
/// cannot move. A reader names whichever of the two they have — a name from the catalog listing, an
/// identity from a previous answer — and `Selector` already reads either, everywhere else in this
/// product. Here it did not: a name went to the store verbatim, matched nothing, and came back as
/// an empty page.
///
/// An empty page is the dangerous answer. It is indistinguishable from a ledger that recorded
/// nothing, so somebody auditing a trail concludes nothing happened when what actually happened is
/// that they typed the form this path did not accept. A scope that does not resolve is a refusal,
/// and an unknown one says so.
///
/// # Why an identity is not looked up
///
/// An identity is already the key the records carry, so resolving it would only be asking the
/// catalog to agree — and the catalog is the wrong authority for that question. A ledger deleted
/// from the catalog keeps its records in this store until retention removes them, and that is
/// deliberate: deleting a configuration must not destroy evidence early. Requiring the lookup made
/// the deletion do exactly that — the records were still here, and nothing could name them any
/// more. So an identity addresses the store directly, and only a *name* needs the catalog to say
/// what it stands for.
fn identify(
    catalog: &std::sync::Arc<dyn permguard_core::catalog::Catalog>,
    zone: &str,
    ledger: &str,
) -> Result<(String, String), ReadError> {
    use permguard_core::catalog::Selector;

    let (selected_zone, selected_ledger) = (Selector::parse(zone), Selector::parse(ledger));
    // Both already identities: nothing to resolve, and nothing to ask.
    if let (Selector::Id(zone), Selector::Id(ledger)) = (&selected_zone, &selected_ledger) {
        return Ok((zone.clone(), ledger.clone()));
    }

    let found = catalog.get_zone(&selected_zone).and_then(|found| {
        let held = catalog.get_ledger(&Selector::Id(found.id.clone()), &selected_ledger)?;

        Ok((found.id, held.id))
    });

    found.map_err(|_| {
        ReadError::Unknown(format!(
            "`{zone}/{ledger}` is not a ledger this plane holds. A zone and a ledger may be named \
             by name or by identity, and neither form matched"
        ))
    })
}

/// The scope a read is served from, with its zone and ledger canonicalized.
///
/// Both shapes carry a zone and a ledger, and both are keyed by identity in the store, so both are
/// resolved. `Stream` used to be returned untouched, which meant the privileged deployment-wide
/// read — the one an auditor reaches for — answered a named scope with an empty page while the
/// records sat under their identities.
pub(crate) fn canonical(
    catalog: Option<&std::sync::Arc<dyn permguard_core::catalog::Catalog>>,
    scope: crate::events::store::Scope,
) -> Result<crate::events::store::Scope, ReadError> {
    use crate::events::store::Scope;

    let Some(catalog) = catalog else {
        return Ok(scope);
    };

    match scope {
        Scope::Tenant { zone, ledger } => {
            let (zone, ledger) = identify(catalog, &zone, &ledger)?;

            Ok(Scope::Tenant { zone, ledger })
        }
        Scope::Stream {
            zone,
            ledger,
            class,
            producer,
            instance,
        } => {
            let (zone, ledger) = identify(catalog, &zone, &ledger)?;

            Ok(Scope::Stream {
                zone,
                ledger,
                class,
                producer,
                instance,
            })
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::events::store::Scope;
    use permguard_core::catalog::{Catalog, Selector};
    use permguard_std::catalog::FileCatalog;

    /// A catalog holding one zone and one ledger, so a test can ask for either form.
    pub(super) fn catalog(tag: &str) -> (std::sync::Arc<dyn Catalog>, String, String) {
        let root = std::env::temp_dir().join(format!("permguard-scope-{tag}"));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("the catalog root is created");

        let catalog = FileCatalog::new(&root);
        let zone = catalog.create_zone("acme").expect("the zone is created");
        let ledger = catalog
            .create_ledger(&Selector::Id(zone.id.clone()), "agent-governance")
            .expect("the ledger is created");

        (std::sync::Arc::new(catalog), zone.id, ledger.id)
    }

    /// A scope named by name reads the same records as one named by identity.
    ///
    /// # Why this is worth pinning
    ///
    /// Records are keyed by identity, because that is what a rename cannot move. Readers name
    /// whichever of the two they have, and `Selector` reads either everywhere else in this product.
    /// Here it did not: a name went to the store verbatim and matched nothing, and the answer was
    /// an empty page — indistinguishable from a ledger that recorded nothing. Somebody auditing a
    /// trail would have concluded that nothing happened.
    #[test]
    fn a_scope_named_by_name_resolves_to_the_one_records_are_keyed_by() {
        let (catalog, zone_id, ledger_id) = catalog("by-name");

        let by_name = canonical(
            Some(&catalog),
            Scope::Tenant {
                zone: "acme".to_owned(),
                ledger: "agent-governance".to_owned(),
            },
        )
        .expect("a ledger the catalog holds resolves");
        let by_id = canonical(
            Some(&catalog),
            Scope::Tenant {
                zone: zone_id.clone(),
                ledger: ledger_id.clone(),
            },
        )
        .expect("an identity resolves to itself");

        assert_eq!(
            by_name, by_id,
            "the two forms must address one ledger, or a reader's choice of spelling changes the \
             answer"
        );
        assert_eq!(
            by_name,
            Scope::Tenant {
                zone: zone_id,
                ledger: ledger_id
            },
            "and both resolve to the identity, which is what the records carry"
        );
    }

    /// A scope nobody holds is refused, never answered with an empty page.
    #[test]
    fn a_scope_that_does_not_resolve_is_refused_rather_than_empty() {
        let (catalog, zone_id, _) = catalog("unknown");

        for (zone, ledger) in [
            ("acme", "no-such-ledger"),
            ("no-such-zone", "agent-governance"),
            (zone_id.as_str(), "no-such-ledger"),
        ] {
            let refused = canonical(
                Some(&catalog),
                Scope::Tenant {
                    zone: zone.to_owned(),
                    ledger: ledger.to_owned(),
                },
            );
            assert!(
                matches!(refused, Err(ReadError::Unknown(_))),
                "`{zone}/{ledger}` is not held, and an empty page would read as an empty ledger"
            );
        }
    }

    /// A build with no catalog has no names to resolve, and passes the scope through.
    #[test]
    fn without_a_catalog_the_scope_is_left_as_it_was_given() {
        let scope = Scope::Tenant {
            zone: "acme".to_owned(),
            ledger: "agent-governance".to_owned(),
        };
        assert_eq!(
            canonical(None, scope.clone()).expect("no catalog is not a refusal"),
            scope
        );
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod scope_tests {
    use super::tests::catalog;
    use super::*;
    use crate::events::store::Scope;
    use permguard_core::catalog::Selector;

    /// The privileged stream read is resolved too, not returned as it was named.
    ///
    /// # Why this needed its own case
    ///
    /// Only `Tenant` used to be resolved, and `Stream` fell through untouched. `Stream` is the
    /// deployment-wide read — the one an auditor reaches for to verify a producer's chain end to
    /// end — so the shape that mattered most was the one that answered a named scope with an empty
    /// page while the records sat under their identities.
    #[test]
    fn a_stream_scope_is_resolved_like_a_tenant_scope() {
        let (catalog, zone_id, ledger_id) = catalog("stream-by-name");

        let resolved = canonical(
            Some(&catalog),
            Scope::Stream {
                zone: "acme".to_owned(),
                ledger: "agent-governance".to_owned(),
                class: "data-plane".to_owned(),
                producer: "plane-a".to_owned(),
                instance: "01a0".to_owned(),
            },
        )
        .expect("a ledger the catalog holds resolves");

        assert_eq!(
            resolved,
            Scope::Stream {
                zone: zone_id,
                ledger: ledger_id,
                class: "data-plane".to_owned(),
                producer: "plane-a".to_owned(),
                instance: "01a0".to_owned(),
            },
            "the producer half is untouched; only the tenant half is keyed by identity"
        );
    }

    /// Records outlive the catalog entry that named them, and stay readable by identity.
    ///
    /// # Why this matters more than it looks
    ///
    /// Deleting a ledger removes it from the catalog; it does not remove what this store recorded,
    /// which stays until retention takes it. That is deliberate — configuration is not evidence,
    /// and deleting the first must not destroy the second early. Resolving an identity through the
    /// catalog made the deletion do exactly that: the records were still on disk and nothing could
    /// name them any more.
    #[test]
    fn an_identity_still_reads_after_the_ledger_is_deleted_from_the_catalog() {
        let (catalog, zone_id, ledger_id) = catalog("deleted-ledger");
        catalog
            .delete_ledger(
                &Selector::Id(zone_id.clone()),
                &Selector::Id(ledger_id.clone()),
            )
            .expect("the ledger is deleted");

        let resolved = canonical(
            Some(&catalog),
            Scope::Tenant {
                zone: zone_id.clone(),
                ledger: ledger_id.clone(),
            },
        )
        .expect("evidence outlives the configuration that named it");
        assert_eq!(
            resolved,
            Scope::Tenant {
                zone: zone_id,
                ledger: ledger_id
            }
        );

        assert!(
            matches!(
                canonical(
                    Some(&catalog),
                    Scope::Tenant {
                        zone: "acme".to_owned(),
                        ledger: "agent-governance".to_owned(),
                    },
                ),
                Err(ReadError::Unknown(_))
            ),
            "the name, however, no longer stands for anything: nothing is there to resolve it"
        );
    }
}
