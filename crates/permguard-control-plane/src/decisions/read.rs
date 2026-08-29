// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Serving a page of records, and the proof that goes with it.
//!
//! # Falling off retention is answered, not discovered
//!
//! An offset older than what the scope still holds is refused explicitly, with
//! the oldest offset now available. A consumer returning from a long outage
//! therefore learns three things at once — that it lost records, where the
//! remaining ones begin, and that its run was not clean — instead of resuming
//! from the wrong place and reporting success.
//!
//! # What a tenant can verify, and how
//!
//! A tenant-scoped reader sees a subsequence of a producer's stream, so the
//! chain does not verify for it: the records in between belong to other
//! tenants and must not be disclosed. The inclusion path is what closes that
//! gap — it proves *this record was in a batch signed by that producer, and
//! has not been altered* without handing over anything of anybody else's.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use permguard_decisions::{merkle, record};
use permguard_stream::cursor::{Cursor, CursorError, CursorKey, Position, filter_digest};
use permguard_stream::{Block, Coverage, Frontier, Window};

use super::store::{DecisionStore, Scope, read_segment};

/// The API family a decision-log offset belongs to.
///
/// Inside every offset's signature, so a position in the decision log presented against the event
/// log is a stable refusal rather than a read of the wrong evidence.
pub const API: &str = "permguard.api.decisions.native.v1";

/// The decision log declares no filters, and says so explicitly.
///
/// An empty *declared* filter set rather than no filter binding at all: the binding is what a
/// later filter would be added to, and a cursor issued today keeps meaning the same read when one
/// is. The digest of `{}` is a constant, computed once.
pub fn filters() -> String {
    filter_digest(&serde_json::json!({}))
}

/// One page of records, and where to continue.
///
/// The shared stream block, with decision records in it. What used to be a type of this module is
/// now [`permguard_stream::Block`]: the decision log and the event log answer the same shape,
/// because a consumer reading one should not have to learn a second contract to read the other.
pub type Page = Block<Value>;

/// One record's place in the tree its batch was signed with.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inclusion {
    /// Which record this proves.
    pub seq: u64,
    /// The digest of the record, which is the leaf.
    pub leaf: String,
    /// The root the path reaches — the one the signed envelope attests.
    pub root: String,
    /// The siblings, from the leaf upwards.
    pub path: Vec<permguard_decisions::merkle::Step>,
}

/// Why a read was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    /// The offset is not usable here.
    Offset(CursorError),
    /// The offset is older than what is held; here is where to resume, and how much was lost.
    ///
    /// Expected retention behaviour, not corruption. The consumer learns three things at once —
    /// that it lost records, where the remaining ones begin, and how many positions are gone —
    /// instead of resuming from the wrong place and reporting success.
    Expired {
        /// The oldest offset the scope still holds.
        oldest: String,
        /// The first position still held.
        oldest_sequence: u64,
        /// Where the consumer stood.
        requested_sequence: u64,
    },
    /// The store could not answer.
    Unavailable(String),
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
        }
    }
}

/// Reads one bounded block of `scope`.
///
/// # What changed, and why it had to
///
/// This used to take a record limit and a base64 JSON offset a consumer could edit. Both were
/// wrong in ways that only show up in production: a record limit alone does not bound a response,
/// and an unauthenticated offset is a position a consumer can move itself to — including one
/// issued for another tenant. Both are now the shared contract's, so the decision log and the
/// event log cannot answer them differently.
pub fn read(
    store: &DecisionStore,
    scope: &Scope,
    key: &CursorKey,
    window: &Window,
) -> Result<Page, ReadError> {
    let segments = store
        .segments(scope)
        .map_err(|error| ReadError::Unavailable(error.to_string()))?;
    let oldest_segment = segments.first().map(|(first, _)| *first).unwrap_or(0);
    let stream = scope.key();
    let filters = filters();

    let oldest_available = {
        let mut beginning = Cursor::beginning(API, &stream, &filters, window.until.clone());
        beginning.advance(
            &stream,
            Position {
                segment: oldest_segment,
                offset: 0,
            },
        );

        beginning.seal(key).map_err(ReadError::Offset)?
    };

    let mut cursor = match &window.from {
        Some(token) => {
            Cursor::open(token, key, API, &stream, &filters).map_err(ReadError::Offset)?
        }
        None => {
            let mut beginning = Cursor::beginning(API, &stream, &filters, window.until.clone());
            beginning.advance(
                &stream,
                Position {
                    segment: oldest_segment,
                    offset: 0,
                },
            );

            beginning
        }
    };
    // The export bound travels *inside* the offset, so a caller cannot drop it on a later page and
    // turn a finite export into an endless one.
    //
    // It is *adopted* rather than required, because an export cannot state its bound on its first
    // page: the bound is that page's own watermark, which the caller does not have until it has
    // been answered. So a cursor carrying no bound may take one — that is the second page of an
    // export declaring what it is — and a cursor already carrying one must be presented with the
    // same one. Changing it afterwards, or dropping it, is a different read.
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
    // A position naming a segment that has left on the retention schedule. Answered, never
    // silently restarted at the beginning: a consumer that lost records must learn so.
    if position.segment < oldest_segment {
        return Err(ReadError::Expired {
            oldest: oldest_available,
            oldest_sequence: oldest_segment,
            requested_sequence: position.segment,
        });
    }

    let limit = window.records();
    let byte_budget = window.bytes();
    let mut records: Vec<Value> = Vec::new();
    let mut bytes = 0u64;
    let mut examined = 0usize;
    let mut bound_by_bytes = false;

    for (first, path) in &segments {
        if *first < position.segment {
            continue;
        }
        if *first > position.segment {
            position.segment = *first;
            position.offset = 0;
        }
        let (found, next_offset) = read_segment(path, position.offset, limit - records.len())
            .map_err(|error| ReadError::Unavailable(error.to_string()))?;
        // The byte bound is applied record by record, so a block never exceeds it — and a single
        // record larger than the whole budget is still returned, because refusing it would stall
        // the consumer forever at that position.
        let mut consumed = 0u64;
        for record in found {
            let size = serde_json::to_vec(&record)
                .map(|held| held.len() as u64)
                .unwrap_or(0);
            if !records.is_empty() && bytes + size > byte_budget {
                bound_by_bytes = true;
                break;
            }
            bytes += size;
            consumed += 1;
            examined += 1;
            records.push(record);
        }
        position.offset = if bound_by_bytes {
            position.offset + consumed
        } else {
            next_offset
        };
        if records.len() >= limit || bound_by_bytes {
            break;
        }
    }
    cursor.advance(&stream, position);

    // The exclusive end this read observed: the sequence after the last record it returned, or
    // wherever it already stood when it returned none.
    let observed = records
        .last()
        .and_then(|record| record.get("seq").and_then(Value::as_u64))
        .map(|seq| seq + 1);
    if let Some(observed) = observed {
        cursor.frontier.cover(&stream, observed);
    }
    let observed_frontier = cursor.frontier.clone();
    let end = Frontier::of(
        &stream,
        end_of(store, scope).unwrap_or_else(|| observed_frontier.covered_through(&stream)),
    );
    let more = permguard_stream::more(window, &observed_frontier, &end);

    // The envelopes of whichever streams these records came from. Read from the record itself
    // rather than from the request, so a tenant asking for a proof cannot name a stream it has no
    // records of.
    let proof = if window.proof {
        let mut streams: Vec<(String, String)> = records
            .iter()
            .filter_map(|record| {
                let stream = record.get("stream")?;
                Some((
                    stream.get("id")?.as_str()?.to_owned(),
                    stream.get("instance")?.as_str()?.to_owned(),
                ))
            })
            .collect();
        streams.sort();
        streams.dedup();
        streams
            .into_iter()
            .filter_map(|(pdp_id, instance)| store.envelopes(&pdp_id, &instance).ok())
            .flatten()
            .collect()
    } else {
        Vec::new()
    };

    let inclusion: Vec<Value> = if proof.is_empty() {
        Vec::new()
    } else {
        inclusion_paths(store, &records, &proof)
            .into_iter()
            .filter_map(|held| serde_json::to_value(held).ok())
            .collect()
    };

    Ok(Page {
        records,
        next: cursor.seal(key).map_err(ReadError::Offset)?,
        oldest_available,
        high_watermark: observed_frontier.encode(),
        more,
        proof,
        inclusion,
        coverage: Coverage {
            // A producer stream is a contiguous run and its chain verifies across the block. A
            // tenant view is a subsequence — the records in between belong to other tenants and
            // are not disclosed — so the chain does not, and the inclusion paths are what there is.
            contiguous: matches!(scope, Scope::Stream { .. }),
            examined,
            // Nothing filters here yet, so the scan bound is never what stopped a block. The field
            // is reported rather than omitted because the contract is shared, and a consumer that
            // reads both stores reads one shape.
            scan_bounded: false,
        },
    })
}

/// The exclusive end of a scope right now: one past its highest sequence.
fn end_of(store: &DecisionStore, scope: &Scope) -> Option<u64> {
    let segments = store.segments(scope).ok()?;
    let (_, last) = segments.last()?;
    let (records, _) = read_segment(last, 0, usize::MAX).ok()?;

    records
        .last()
        .and_then(|record| record.get("seq").and_then(Value::as_u64))
        .map(|seq| seq + 1)
}

/// Builds the inclusion path of every record, against the batch that carried it.
///
/// The leaves of a batch include records of every tenant it touched, so the
/// tree is rebuilt from the **producer stream**, not from the page. That is the
/// point: the tenant never sees those records, and still gets a path that
/// reaches the root its signed envelope attests.
fn inclusion_paths(store: &DecisionStore, records: &[Value], proof: &[Value]) -> Vec<Inclusion> {
    let mut built = Vec::new();
    for record in records {
        let Some(seq) = record.get("seq").and_then(Value::as_u64) else {
            continue;
        };
        let Some(stream) = record.get("stream") else {
            continue;
        };
        let (Some(pdp_id), Some(instance)) = (
            stream.get("id").and_then(Value::as_str),
            stream.get("instance").and_then(Value::as_str),
        ) else {
            continue;
        };

        // Which batch carried it, and what that batch attested.
        let Some((first_seq, last_seq, root)) = covering(proof, seq, pdp_id, instance) else {
            continue;
        };
        let leaves = leaves_of(store, pdp_id, instance, first_seq, last_seq);
        let Some(index) = leaves.iter().position(|(leaf_seq, _)| *leaf_seq == seq) else {
            continue;
        };
        let digests: Vec<String> = leaves.into_iter().map(|(_, digest)| digest).collect();
        let Some(path) = merkle::path(&digests, index) else {
            continue;
        };

        built.push(Inclusion {
            seq,
            leaf: digests[index].clone(),
            root,
            path,
        });
    }

    built
}

/// The batch that covers `seq`, as its envelope attests it.
fn covering(proof: &[Value], seq: u64, pdp_id: &str, instance: &str) -> Option<(u64, u64, String)> {
    use base64::Engine as _;

    for signed in proof {
        let payload = signed.get("payload").and_then(Value::as_str)?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .ok()?;
        let envelope: Value = serde_json::from_slice(&bytes).ok()?;
        let stream = envelope.get("stream")?;
        if stream.get("id").and_then(Value::as_str) != Some(pdp_id)
            || stream.get("instance").and_then(Value::as_str) != Some(instance)
        {
            continue;
        }
        let first = envelope.get("first_seq").and_then(Value::as_u64)?;
        let last = envelope.get("last_seq").and_then(Value::as_u64)?;
        if (first..=last).contains(&seq) {
            let root = envelope
                .get("merkle_root")
                .and_then(Value::as_str)?
                .to_owned();

            return Some((first, last, root));
        }
    }

    None
}

/// The digests of one batch's records, in the order they were hashed.
fn leaves_of(
    store: &DecisionStore,
    pdp_id: &str,
    instance: &str,
    first_seq: u64,
    last_seq: u64,
) -> Vec<(u64, String)> {
    let scope = Scope::Stream {
        pdp_id: pdp_id.to_owned(),
        instance: instance.to_owned(),
    };
    let mut leaves = Vec::new();
    for (_, path) in store.segments(&scope).unwrap_or_default() {
        let Ok((records, _)) = read_segment(&path, 0, usize::MAX) else {
            continue;
        };
        for value in records {
            let Some(seq) = value.get("seq").and_then(Value::as_u64) else {
                continue;
            };
            if (first_seq..=last_seq).contains(&seq)
                && let Ok(digest) = record::digest_of(&value)
            {
                leaves.push((seq, digest));
            }
        }
    }
    leaves.sort_by_key(|(seq, _)| *seq);

    leaves
}
