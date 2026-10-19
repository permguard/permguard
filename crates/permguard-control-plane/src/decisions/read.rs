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

use permguard_core::authz::Resource;
use permguard_decisions::{merkle, record};
use permguard_host::composition::{ConsumedRun, StreamConsumer};
use permguard_stream::cursor::{Cursor, CursorError, Position, filter_digest};
use permguard_stream::engine::batch::{SealedBatch, digest_string};

use crate::decisions::cursorkey::CursorKeys;
use permguard_stream::{Block, Coverage, Frontier, Window};

use super::store::{DecisionStore, Scope, read_segment};

/// The API family a decision-log offset belongs to.
///
/// Inside every offset's signature, so a position in the decision log presented against the event
/// log is a stable refusal rather than a read of the wrong evidence.
pub const API: &str = permguard_core::domains::interface::DECISIONS_NATIVE_V1;

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

/// The code a read refused with this error answers (WP-5.5): a cursor's own, `offset_invalid`
/// otherwise as before.
pub fn refusal_code(error: &ReadError) -> &'static str {
    match error {
        ReadError::Offset(error) => error.code(),
        _ => permguard_core::codes::stream::OFFSET_INVALID,
    }
}

/// The class and code a refused read answers: a store or consumer that could not answer is
/// `unavailable`, never taken for a bad offset (WP-6.1b, after the review); anything else is the
/// offset's own refusal.
pub fn refusal(error: &ReadError) -> (permguard_core::ErrorClass, &'static str) {
    match error {
        ReadError::Unavailable(_) => (
            permguard_core::ErrorClass::Unavailable,
            permguard_core::codes::stream::STORE_UNAVAILABLE,
        ),
        _ => (permguard_core::ErrorClass::Validation, refusal_code(error)),
    }
}

/// Where a read finds its records: the legacy store, and the Host's consumer of the decision
/// stream when one is composed (WP-6.1b).
#[derive(Clone, Copy)]
pub struct Sources<'a> {
    pub store: &'a DecisionStore,
    pub host: Option<&'a StreamConsumer>,
    /// What turns a tenant route's names into the ids the consumer's streams are keyed by.
    pub catalog: Option<&'a std::sync::Arc<dyn permguard_core::catalog::Catalog>>,
}

/// One run of the Host's consumer a read covers, and the name its position is kept under.
pub(crate) struct HostRun {
    pub(crate) resource: Resource,
    pub(crate) run: ConsumedRun,
    pub(crate) key: String,
}

/// The cursor stream a consumer run's position is kept under.
pub(crate) fn host_key(run: &ConsumedRun) -> String {
    format!("host:{}:{}", hex(&run.producer), hex(&run.run))
}

/// Whether `scope` reads the legacy store, and the consumer runs it covers: a stream scope
/// naming a run the consumer holds reads that run alone; a tenant scope reads the legacy store,
/// then every run of its ledger by producer and opening order (owner decision of 2026-10-18).
fn sources_of(sources: &Sources<'_>, scope: &Scope) -> Result<(bool, Vec<HostRun>), ReadError> {
    let unavailable = |error: String| ReadError::Unavailable(error);
    let Some(host) = sources.host else {
        return Ok((true, Vec::new()));
    };
    match scope {
        Scope::Stream { pdp_id, instance } => {
            let (Some(producer), Some(run)) = (unhex16(pdp_id), unhex16(instance)) else {
                return Ok((true, Vec::new()));
            };
            let Some(resource) = host.locate(&producer, &run).map_err(unavailable)? else {
                return Ok((true, Vec::new()));
            };
            let runs = host
                .runs(&resource)
                .map_err(unavailable)?
                .into_iter()
                .filter(|held| held.producer == producer && held.run == run)
                .map(|held| HostRun {
                    key: host_key(&held),
                    resource: resource.clone(),
                    run: held,
                })
                .collect();
            Ok((false, runs))
        }
        Scope::Tenant { zone, ledger } => {
            let Some(resource) = ledger_resource(sources.catalog, zone, ledger)? else {
                return Ok((true, Vec::new()));
            };
            let runs = host
                .runs(&resource)
                .map_err(unavailable)?
                .into_iter()
                .map(|held| HostRun {
                    key: host_key(&held),
                    resource: resource.clone(),
                    run: held,
                })
                .collect();
            Ok((true, runs))
        }
    }
}

/// The ledger the catalog names `zone`/`ledger` by, as the Host's stream resource: `None` with
/// no catalog, or for a ledger it does not hold.
fn ledger_resource(
    catalog: Option<&std::sync::Arc<dyn permguard_core::catalog::Catalog>>,
    zone: &str,
    ledger: &str,
) -> Result<Option<Resource>, ReadError> {
    use permguard_core::catalog::{CatalogError, Selector};

    let Some(catalog) = catalog else {
        return Ok(None);
    };
    let found = catalog.get_zone(&Selector::parse(zone)).and_then(|found| {
        let held = catalog.get_ledger(&Selector::Id(found.id.clone()), &Selector::parse(ledger))?;
        Ok((found.id, held.id))
    });
    match found {
        Ok((zone_id, ledger_id)) => Ok(Some(Resource::ledger("data", zone_id, ledger_id))),
        Err(CatalogError::NotFound { .. }) => Ok(None),
        Err(error) => Err(ReadError::Unavailable(format!(
            "the catalog could not name this ledger: {error}"
        ))),
    }
}

pub(crate) fn unhex16(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (at, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(at * 2..at * 2 + 2)?, 16).ok()?;
    }
    Some(bytes)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Reads one bounded block of `scope` from the legacy store alone.
pub fn read(
    store: &DecisionStore,
    scope: &Scope,
    keys: &CursorKeys,
    window: &Window,
) -> Result<Page, ReadError> {
    read_with(
        &Sources {
            store,
            host: None,
            catalog: None,
        },
        scope,
        keys,
        window,
    )
}

/// Reads one bounded block of `scope` from `sources`.
///
/// # What changed, and why it had to
///
/// This used to take a record limit and a base64 JSON offset a consumer could edit. Both were
/// wrong in ways that only show up in production: a record limit alone does not bound a response,
/// and an unauthenticated offset is a position a consumer can move itself to — including one
/// issued for another tenant. Both are now the shared contract's, so the decision log and the
/// event log cannot answer them differently.
///
/// Since WP-6.1b the records come from the legacy store and from the Host's consumer: the legacy
/// store first, then each consumer run, each from the position the cursor keeps for it.
pub fn read_with(
    sources: &Sources<'_>,
    scope: &Scope,
    keys: &CursorKeys,
    window: &Window,
) -> Result<Page, ReadError> {
    let store = sources.store;
    let (legacy, host_runs) = sources_of(sources, scope)?;
    let segments = if legacy {
        store
            .segments(scope)
            .map_err(|error| ReadError::Unavailable(error.to_string()))?
    } else {
        Vec::new()
    };
    let oldest_segment = segments.first().map(|(first, _)| *first).unwrap_or(0);
    let stream = scope.key();
    // The resource's own key (WP-3.3): an offset of one resource never opens under another's.
    let key = &keys
        .for_resource(&stream)
        .map_err(|error| ReadError::Unavailable(error.to_string()))?;
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

        beginning
            .seal_v2(key, keys.now(), keys.lifetime())
            .map_err(ReadError::Offset)?
    };

    let mut cursor = match &window.from {
        Some(token) => Cursor::open_any(token, key, API, &stream, &filters, keys.now())
            .map_err(ReadError::Offset)?,
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

    let limit = window.records();
    let byte_budget = window.bytes();
    let mut records: Vec<Value> = Vec::new();
    // Where each record came from: `None` the legacy store, else the consumer run it was read of.
    let mut origins: Vec<Option<usize>> = Vec::new();
    let mut bytes = 0u64;
    let mut examined = 0usize;
    let mut bound_by_bytes = false;
    let mut end = Frontier::empty();

    if legacy {
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

        for (first, path) in &segments {
            if *first < position.segment {
                continue;
            }
            if *first > position.segment {
                position.segment = *first;
                position.offset = 0;
            }
            let (found, next_offset) =
                read_segment(path, position.offset, limit - records.len())
                    .map_err(|error| ReadError::Unavailable(error.to_string()))?;
            // The byte bound is applied record by record, so a block never exceeds it — and a
            // single record larger than the whole budget is still returned, because refusing it
            // would stall the consumer forever at that position.
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
                origins.push(None);
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

        // The exclusive end this read observed: the sequence after the last record it returned,
        // or wherever it already stood when it returned none.
        let observed = records
            .last()
            .and_then(|record| record.get("seq").and_then(Value::as_u64))
            .map(|seq| seq + 1);
        if let Some(observed) = observed {
            cursor.frontier.cover(&stream, observed);
        }
        let held_through = cursor.frontier.covered_through(&stream);
        end.cover(&stream, end_of(store, scope)?.unwrap_or(held_through));
    }

    // Then each consumer run, from where the cursor stands in it.
    for (index, held) in host_runs.iter().enumerate() {
        let run = &held.run;
        end.cover(&held.key, run.acked + 1);
        let at = cursor.position(&held.key).segment;
        // A run whose prefix left on the retention schedule while this reader stood in it.
        if at != 0 && at < run.oldest_retained {
            return Err(ReadError::Expired {
                oldest: oldest_available,
                oldest_sequence: run.oldest_retained,
                requested_sequence: at,
            });
        }
        let from = at.max(run.oldest_retained).max(1);
        // Nothing readable left in the run (read to its end, or its whole prefix pruned): the
        // reader has observed all of it, so `more` does not stay true for it (after the review).
        if from > run.acked {
            cursor.frontier.cover(&held.key, run.acked + 1);
            continue;
        }
        if records.len() >= limit || bound_by_bytes {
            continue;
        }
        let host = sources
            .host
            .ok_or_else(|| ReadError::Unavailable("no consumer is composed".to_owned()))?;
        let page = host
            .records(
                &held.resource,
                &run.producer,
                &run.run,
                from,
                limit - records.len(),
            )
            .map_err(ReadError::Unavailable)?;
        let mut next = from;
        for (seq, record) in page.records {
            let value: Value = serde_json::from_slice(&record).map_err(|error| {
                ReadError::Unavailable(format!("a record of the Host's stream: {error}"))
            })?;
            let size = record.len() as u64;
            if !records.is_empty() && bytes + size > byte_budget {
                bound_by_bytes = true;
                break;
            }
            bytes += size;
            examined += 1;
            records.push(value);
            origins.push(Some(index));
            next = seq + 1;
        }
        cursor.advance(
            &held.key,
            Position {
                segment: next,
                offset: 0,
            },
        );
        if next > from {
            cursor.frontier.cover(&held.key, next);
        }
    }

    let observed_frontier = cursor.frontier.clone();
    let more = permguard_stream::more(window, &observed_frontier, &end);

    let (proof, inclusion) = if window.proof {
        let (mut proof, mut inclusion) = legacy_proof(store, &records, &origins)?;
        // A path names only its sequence, so a page holding both sources pairs paths with
        // records by position: a legacy record left without its path would shift every Host path
        // onto the wrong record. Refused rather than answered short (after the review).
        let legacy_count = origins.iter().filter(|origin| origin.is_none()).count();
        if inclusion.len() != legacy_count && origins.iter().any(Option::is_some) {
            return Err(ReadError::Unavailable(
                "a legacy record of this page has no envelope to prove it by, and a proof \
                 missing part of itself must not be returned as one"
                    .to_owned(),
            ));
        }
        let (host_proof, host_inclusion) = host_proof(
            sources.host,
            &host_runs,
            &records,
            &origins,
            permguard_core::domains::digest::DECISION_RECORD,
        )?;
        proof.extend(host_proof);
        inclusion.extend(host_inclusion);
        (proof, inclusion)
    } else {
        (Vec::new(), Vec::new())
    };

    Ok(Page {
        records,
        next: cursor
            .seal_v2(key, keys.now(), keys.lifetime())
            .map_err(ReadError::Offset)?,
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

/// The legacy envelopes of the streams the legacy records came from, each naming its format,
/// and the records' inclusion paths.
fn legacy_proof(
    store: &DecisionStore,
    records: &[Value],
    origins: &[Option<usize>],
) -> Result<(Vec<Value>, Vec<Value>), ReadError> {
    let legacy: Vec<Value> = records
        .iter()
        .zip(origins)
        .filter(|(_, origin)| origin.is_none())
        .map(|(record, _)| record.clone())
        .collect();
    // The envelopes of whichever streams these records came from. Read from the record itself
    // rather than from the request, so a tenant asking for a proof cannot name a stream it has no
    // records of.
    let mut streams: Vec<(String, String)> = legacy
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
    // A proof that is quietly short is worse than no proof: the caller asked for evidence, got
    // a successful answer, and has fewer envelopes than records without being told which are
    // missing or why. A store it could not read is a refusal.
    let mut held = Vec::new();
    for (pdp_id, instance) in streams {
        held.extend(store.envelopes(&pdp_id, &instance).map_err(|error| {
            ReadError::Unavailable(format!(
                "the evidence for `{pdp_id}/{instance}` could not be read, and a proof missing \
                 part of itself must not be returned as one: {error}"
            ))
        })?);
    }
    if held.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    // Same rule for the paths themselves: one that will not render is one the caller cannot
    // check, and dropping it silently leaves a page whose proof covers fewer records than it
    // appears to.
    let mut rendered = Vec::with_capacity(legacy.len());
    for path in inclusion_paths(store, &legacy, &held) {
        rendered.push(serde_json::to_value(path).map_err(|error| {
            ReadError::Unavailable(format!("an inclusion path could not be rendered: {error}"))
        })?);
    }
    // Each entry names its format (owner decision of 2026-10-18): the JWS members unchanged.
    for envelope in &mut held {
        if let Some(object) = envelope.as_object_mut() {
            object.insert("format".to_owned(), Value::from(LEGACY_FORMAT));
        }
    }
    Ok((held, rendered))
}

/// The format of a legacy `proof[]` entry: the store's batch JWS.
pub const LEGACY_FORMAT: &str = "legacy-jws-v1";
/// The format of a `proof[]` entry the Host's engine sealed: its batch's JWS.
pub const HOST_FORMAT: &str = "host-batch-v1";

/// The sealed batch of every consumer run's records in the page, each once, and each record's
/// RFC 6962 path to the root its batch's envelope signs, its leaves digested under `domain`: what
/// the decision and the event reads both prove a Host record with (WP-6.2b).
pub(crate) fn host_proof(
    host: Option<&StreamConsumer>,
    runs: &[HostRun],
    records: &[Value],
    origins: &[Option<usize>],
    domain: &str,
) -> Result<(Vec<Value>, Vec<Value>), ReadError> {
    let mut proof = Vec::new();
    let mut inclusion = Vec::new();
    // `(run index, first, last)` of each batch already in the proof, with its leaves and root.
    let mut batches: Vec<(usize, u64, u64, Vec<String>, String)> = Vec::new();
    for (record, origin) in records.iter().zip(origins) {
        let Some(index) = origin else {
            continue;
        };
        let held = &runs[*index];
        let seq = record
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| ReadError::Unavailable("a record names no sequence".to_owned()))?;
        let known = batches
            .iter()
            .position(|(run, first, last, ..)| run == index && (*first..=*last).contains(&seq));
        let at = match known {
            Some(at) => at,
            None => {
                let host = host
                    .ok_or_else(|| ReadError::Unavailable("no consumer is composed".to_owned()))?;
                let bytes = host
                    .batch(&held.resource, &held.run.producer, &held.run.run, seq)
                    .map_err(ReadError::Unavailable)?
                    .ok_or_else(|| {
                        ReadError::Unavailable(format!(
                            "no batch covers sequence {seq} of run {}: a proof missing part of \
                             itself must not be returned as one",
                            hex(&held.run.run)
                        ))
                    })?;
                let sealed = SealedBatch::decode(&bytes)
                    .map_err(|error| ReadError::Unavailable(error.to_string()))?;
                let envelope = sealed
                    .envelope_unverified()
                    .map_err(|error| ReadError::Unavailable(error.to_string()))?;
                let mut leaves = Vec::with_capacity(sealed.records.len());
                for encoded in &sealed.records {
                    use base64::Engine as _;
                    let record = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(encoded)
                        .map_err(|error| ReadError::Unavailable(error.to_string()))?;
                    leaves.push(digest_string(domain, &record));
                }
                proof.push(serde_json::json!({
                    "format": HOST_FORMAT,
                    "signature": sealed.signature,
                }));
                batches.push((
                    *index,
                    envelope.first_seq,
                    envelope.last_seq,
                    leaves,
                    envelope.merkle_root,
                ));
                batches.len() - 1
            }
        };
        let (_, first, _, leaves, root) = &batches[at];
        let position = (seq - first) as usize;
        let path = merkle::path(leaves, position).ok_or_else(|| {
            ReadError::Unavailable(format!("no inclusion path for sequence {seq}"))
        })?;
        inclusion.push(
            serde_json::to_value(Inclusion {
                seq,
                leaf: leaves[position].clone(),
                root: root.clone(),
                path,
            })
            .map_err(|error| ReadError::Unavailable(error.to_string()))?,
        );
    }
    Ok((proof, inclusion))
}

/// The exclusive end of a scope right now: one past its highest sequence.
///
/// `Ok(None)` is a scope with no segments — a legitimate answer, and the only one that may be read
/// as "there is nothing beyond here". A store that could not be read is an error, because the
/// caller turns this into `more`: a failure reported as absence tells a consumer it is caught up
/// when the truth is that nobody looked, and a consumer that believes it is caught up stops.
fn end_of(store: &DecisionStore, scope: &Scope) -> Result<Option<u64>, ReadError> {
    let segments = store.segments(scope).map_err(|error| {
        ReadError::Unavailable(format!(
            "the segments of this scope could not be listed: {error}"
        ))
    })?;
    let Some((_, last)) = segments.last() else {
        return Ok(None);
    };
    let (records, _) = read_segment(last, 0, usize::MAX).map_err(|error| {
        ReadError::Unavailable(format!(
            "the last segment of this scope could not be read: {error}"
        ))
    })?;

    Ok(records
        .last()
        .and_then(|record| record.get("seq").and_then(Value::as_u64))
        .map(|seq| seq + 1))
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod host_reads {
    //! WP-6.1b: the public reads over the legacy store and the Host's consumer.

    use std::sync::{Arc, Mutex};

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use permguard_core::catalog::{Catalog, Selector};
    use permguard_host::composition::{ConsumedPage, StreamConsumerReads};
    use permguard_std::catalog::FileCatalog;
    use permguard_stream::engine::batch::{Envelope, Jws, KeyView};
    use serde_json::json;

    use super::*;

    const ROOT: &[u8] = b"a-test-cursor-key-of-32-bytes!!!!";

    fn scratch(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "permguard-decision-host-reads-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("a directory");
        root
    }

    /// One consumer run the fake holds: its records, batched two at a time.
    struct Run {
        resource: Resource,
        run: ConsumedRun,
        records: Vec<Vec<u8>>,
    }

    /// The Host's consumer, as a Plane reads it.
    struct Held {
        runs: Mutex<Vec<Run>>,
    }

    impl Held {
        fn batch_of(run: &Run, seq: u64) -> Option<Vec<u8>> {
            let first = (seq - 1) / 2 * 2 + 1;
            let last = (first + 1).min(run.records.len() as u64);
            if seq > last {
                return None;
            }
            let records: Vec<&Vec<u8>> = (first..=last)
                .map(|at| &run.records[(at - 1) as usize])
                .collect();
            let leaves: Vec<String> = records
                .iter()
                .map(|record| {
                    digest_string(permguard_core::domains::digest::DECISION_RECORD, record)
                })
                .collect();
            let envelope = Envelope {
                descriptor_version: 1,
                stream_key: KeyView {
                    plane: "data".to_owned(),
                    stream_type: "decisions".to_owned(),
                    resource: run.resource.to_string(),
                    producer_host_id: hex(&run.run.producer),
                },
                run: hex(&run.run.run),
                membership_id: None,
                epoch: None,
                first_seq: first,
                last_seq: last,
                count: last - first + 1,
                previous_head: "sha256:00".to_owned(),
                head: leaves.last().cloned().unwrap_or_default(),
                merkle_root: merkle::root(&leaves).expect("a root"),
                batch_id: format!("{}-{first}", hex(&run.run.run)),
                created_at: "2026-10-18T10:00:00Z".to_owned(),
                key_set_epoch: 1,
            };
            SealedBatch {
                signature: Jws {
                    protected: "e30".to_owned(),
                    payload: B64.encode(envelope.signed_bytes().expect("signed bytes")),
                    signature: "c2ln".to_owned(),
                },
                records: records.iter().map(|record| B64.encode(record)).collect(),
            }
            .encode()
            .ok()
        }
    }

    impl StreamConsumerReads for Held {
        fn runs(&self, resource: &Resource) -> Result<Vec<ConsumedRun>, String> {
            Ok(self
                .runs
                .lock()
                .unwrap()
                .iter()
                .filter(|held| &held.resource == resource)
                .map(|held| held.run.clone())
                .collect())
        }

        fn locate(&self, producer: &[u8; 16], run: &[u8; 16]) -> Result<Option<Resource>, String> {
            Ok(self
                .runs
                .lock()
                .unwrap()
                .iter()
                .find(|held| held.run.producer == *producer && held.run.run == *run)
                .map(|held| held.resource.clone()))
        }

        fn records(
            &self,
            _: &Resource,
            producer: &[u8; 16],
            run: &[u8; 16],
            from: u64,
            limit: usize,
        ) -> Result<ConsumedPage, String> {
            let runs = self.runs.lock().unwrap();
            let held = runs
                .iter()
                .find(|held| held.run.producer == *producer && held.run.run == *run)
                .ok_or("no such run")?;
            let from = from.max(held.run.oldest_retained);
            Ok(ConsumedPage {
                records: (from..=held.run.acked)
                    .take(limit)
                    .map(|seq| (seq, held.records[(seq - 1) as usize].clone()))
                    .collect(),
                low_watermark: None,
            })
        }

        fn batch(
            &self,
            _: &Resource,
            producer: &[u8; 16],
            run: &[u8; 16],
            seq: u64,
        ) -> Result<Option<Vec<u8>>, String> {
            let runs = self.runs.lock().unwrap();
            Ok(runs
                .iter()
                .find(|held| held.run.producer == *producer && held.run.run == *run)
                .and_then(|held| Self::batch_of(held, seq)))
        }
    }

    /// A Host record of `producer`'s run `run` at `seq`, for the tenant `acme/governance`, in
    /// its canonical encoding as the engine keeps it.
    fn host_record(producer: u8, run: u8, seq: u64) -> Vec<u8> {
        permguard_stream::jcs::canonicalize(&json!({
            "v": 1,
            "kind": "decision",
            "seq": seq,
            "stream": {"id": hex(&[producer; 16]), "instance": hex(&[run; 16])},
            "store": {"zone": "acme", "ledger": "governance"},
        }))
        .expect("canonical JSON")
    }

    fn run(resource: &Resource, producer: u8, run: u8, count: u64) -> Run {
        Run {
            resource: resource.clone(),
            run: ConsumedRun {
                producer: [producer; 16],
                run: [run; 16],
                acked: count,
                oldest_retained: 1,
            },
            records: (1..=count)
                .map(|seq| host_record(producer, run, seq))
                .collect(),
        }
    }

    struct Fixture {
        store: DecisionStore,
        catalog: Arc<dyn Catalog>,
        consumer: StreamConsumer,
        held: Arc<Held>,
        keys: CursorKeys,
        resource: Resource,
    }

    impl Fixture {
        /// Two legacy records of `acme/governance`; two producers holding runs of its ledger.
        fn new(tag: &str) -> Self {
            let root = scratch(tag);
            let store = DecisionStore::open(root.join("store")).expect("a store");
            for seq in 1..=2 {
                store
                    .append(
                        "plane-a",
                        "i-1",
                        &json!({
                            "v": 1,
                            "kind": "decision",
                            "seq": seq,
                            "stream": {"id": "plane-a", "instance": "i-1"},
                            "store": {"zone": "acme", "ledger": "governance"},
                        }),
                    )
                    .expect("appended");
            }
            let catalog = FileCatalog::new(root.join("catalog"));
            let zone = catalog.create_zone("acme").expect("a zone");
            let ledger = catalog
                .create_ledger(&Selector::Id(zone.id.clone()), "governance")
                .expect("a ledger");
            let resource = Resource::ledger("data", zone.id, ledger.id);
            let held = Arc::new(Held {
                runs: Mutex::new(vec![
                    run(&resource, 0xa1, 0x01, 3),
                    run(&resource, 0xb2, 0x02, 2),
                    // Another ledger's run, which no read of this one sees.
                    run(&Resource::ledger("data", "z", "l"), 0xc3, 0x03, 4),
                ]),
            });
            Self {
                store,
                catalog: Arc::new(catalog),
                consumer: StreamConsumer::over(Arc::clone(&held) as Arc<dyn StreamConsumerReads>),
                held,
                keys: CursorKeys::from_root(ROOT, [1; 16], "decisions").expect("a cursor key"),
                resource,
            }
        }

        fn read(&self, scope: &Scope, window: &Window) -> Result<Page, ReadError> {
            read_with(
                &Sources {
                    store: &self.store,
                    host: Some(&self.consumer),
                    catalog: Some(&self.catalog),
                },
                scope,
                &self.keys,
                window,
            )
        }
    }

    fn tenant() -> Scope {
        Scope::Tenant {
            zone: "acme".to_owned(),
            ledger: "governance".to_owned(),
        }
    }

    fn named(page: &Page) -> Vec<(String, u64)> {
        page.records
            .iter()
            .map(|record| {
                (
                    record["stream"]["id"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                    record["seq"].as_u64().unwrap_or_default(),
                )
            })
            .collect()
    }

    /// WP-6.1b, owner decisions and F-06: the tenant view reads the legacy store, then each
    /// producer's runs of the ledger, from the position the cursor keeps for each, and every Host
    /// record names its `host_id` and run.
    #[test]
    fn the_tenant_view_reads_the_legacy_store_then_the_host_runs() {
        let fixture = Fixture::new("tenant");
        let (a, b) = (hex(&[0xa1; 16]), hex(&[0xb2; 16]));
        let first = fixture
            .read(
                &tenant(),
                &Window {
                    limit_records: 4,
                    ..Window::default()
                },
            )
            .expect("a page");
        assert_eq!(
            named(&first),
            vec![
                ("plane-a".to_owned(), 1),
                ("plane-a".to_owned(), 2),
                (a.clone(), 1),
                (a.clone(), 2)
            ]
        );
        assert!(first.more, "the rest is held");
        assert!(!first.coverage.contiguous);
        let second = fixture
            .read(
                &tenant(),
                &Window {
                    from: Some(first.next.clone()),
                    limit_records: 4,
                    ..Window::default()
                },
            )
            .expect("a page");
        assert_eq!(
            named(&second),
            vec![(a.clone(), 3), (b.clone(), 1), (b.clone(), 2)],
            "two producers on one ledger, both named"
        );
        assert!(!second.more, "read to the end");
        for record in first.records.iter().chain(&second.records).skip(2) {
            assert_eq!(
                record["stream"]["instance"].as_str().map(str::len),
                Some(32)
            );
        }
        // Named by its ids, the ledger reads the same.
        let by_id = Scope::Tenant {
            zone: match &fixture.resource {
                Resource::Ledger { zone_id, .. } => zone_id.clone(),
                _ => unreachable!(),
            },
            ledger: match &fixture.resource {
                Resource::Ledger { ledger_id, .. } => ledger_id.clone(),
                _ => unreachable!(),
            },
        };
        let page = fixture.read(&by_id, &Window::default()).expect("a page");
        assert_eq!(
            named(&page)
                .into_iter()
                .filter(|(id, _)| id != "plane-a")
                .count(),
            5
        );
        // A ledger the catalog does not hold reads the legacy store alone.
        let unknown = fixture
            .read(
                &Scope::Tenant {
                    zone: "acme".to_owned(),
                    ledger: "nowhere".to_owned(),
                },
                &Window::default(),
            )
            .expect("a page");
        assert!(unknown.records.is_empty());
    }

    /// WP-6.1b: `pdp` and `instance` naming a run the consumer holds read that run alone; any
    /// other pair reads the legacy store as before.
    #[test]
    fn a_stream_read_names_a_host_run() {
        let fixture = Fixture::new("stream");
        // Another run of the same producer, and a legacy stream under the run's very name: the
        // read takes neither.
        let resource = fixture.resource.clone();
        fixture
            .held
            .runs
            .lock()
            .unwrap()
            .push(run(&resource, 0xb2, 0x04, 1));
        fixture
            .store
            .append(
                &hex(&[0xb2; 16]),
                &hex(&[0x02; 16]),
                &json!({"v": 1, "kind": "decision", "seq": 9, "stream": {"id": "x", "instance": "y"}}),
            )
            .expect("appended");
        let page = fixture
            .read(
                &Scope::Stream {
                    pdp_id: hex(&[0xb2; 16]),
                    instance: hex(&[0x02; 16]),
                },
                &Window::default(),
            )
            .expect("a page");
        assert_eq!(
            named(&page),
            vec![(hex(&[0xb2; 16]), 1), (hex(&[0xb2; 16]), 2)]
        );
        assert!(page.coverage.contiguous);
        let legacy = fixture
            .read(
                &Scope::Stream {
                    pdp_id: "plane-a".to_owned(),
                    instance: "i-1".to_owned(),
                },
                &Window::default(),
            )
            .expect("a page");
        assert_eq!(
            named(&legacy),
            vec![("plane-a".to_owned(), 1), ("plane-a".to_owned(), 2)]
        );
        let neither = fixture
            .read(
                &Scope::Stream {
                    pdp_id: hex(&[0xb2; 16]),
                    instance: hex(&[0x09; 16]),
                },
                &Window::default(),
            )
            .expect("a page");
        assert!(
            neither.records.is_empty(),
            "no such run, and no such legacy stream"
        );
    }

    /// WP-6.1b, owner decision: a Host record's proof is its sealed batch's JWS, named
    /// `host-batch-v1`, each batch once, and its path reaches the root that batch signs.
    #[test]
    fn a_host_proof_carries_the_sealed_batch_and_its_paths() {
        let fixture = Fixture::new("proof");
        let page = fixture
            .read(
                &Scope::Stream {
                    pdp_id: hex(&[0xa1; 16]),
                    instance: hex(&[0x01; 16]),
                },
                &Window {
                    proof: true,
                    ..Window::default()
                },
            )
            .expect("a page");
        assert_eq!(page.records.len(), 3);
        assert_eq!(page.proof.len(), 2, "records 1-2 and 3, each batch once");
        for entry in &page.proof {
            assert_eq!(entry["format"], json!(HOST_FORMAT));
            assert!(entry["signature"]["payload"].is_string());
        }
        assert_eq!(page.inclusion.len(), 3);
        for (record, path) in page.records.iter().zip(&page.inclusion) {
            let path: Inclusion = serde_json::from_value(path.clone()).expect("a path");
            assert_eq!(Some(path.seq), record["seq"].as_u64());
            assert_eq!(
                path.leaf,
                record::digest_of(record).expect("a digest"),
                "the leaf is the record's digest"
            );
            assert_eq!(merkle::recompute(&path.leaf, &path.path), path.root);
        }
        let roots: Vec<String> = page
            .proof
            .iter()
            .map(|entry| {
                let payload = B64
                    .decode(entry["signature"]["payload"].as_str().unwrap_or_default())
                    .expect("base64url");
                serde_json::from_slice::<Envelope>(&payload)
                    .expect("an envelope")
                    .merkle_root
            })
            .collect();
        assert!(
            page.inclusion
                .iter()
                .all(|path| roots.contains(&path["root"].as_str().unwrap_or_default().to_owned())),
            "each path reaches a root a batch in the proof signs"
        );
    }

    /// WP-6.1b, owner decision: a legacy entry of a merged proof keeps its JWS members and names
    /// its format beside them; the stored envelope is not changed.
    #[test]
    fn a_legacy_proof_entry_names_its_format() {
        let fixture = Fixture::new("legacy-proof");
        // The envelope of the two legacy records: their stream, range and Merkle root.
        let leaves: Vec<String> = fixture
            .store
            .segments(&Scope::Stream {
                pdp_id: "plane-a".to_owned(),
                instance: "i-1".to_owned(),
            })
            .expect("segments")
            .iter()
            .flat_map(|(_, path)| read_segment(path, 0, usize::MAX).expect("read").0)
            .map(|record| record::digest_of(&record).expect("a digest"))
            .collect();
        let envelope = json!({
            "stream": {"id": "plane-a", "instance": "i-1"},
            "first_seq": 1,
            "last_seq": 2,
            "merkle_root": merkle::root(&leaves).expect("a root"),
        });
        let signed = json!({
            "protected": "e30",
            "payload": B64.encode(serde_json::to_vec(&envelope).expect("JSON")),
            "signature": "c2ln",
        });
        fixture
            .store
            .keep_envelope("plane-a", "i-1", 1, &signed)
            .expect("kept");
        let page = fixture
            .read(
                &tenant(),
                &Window {
                    proof: true,
                    ..Window::default()
                },
            )
            .expect("a page");
        let legacy: Vec<&Value> = page
            .proof
            .iter()
            .filter(|entry| entry["format"] == json!(LEGACY_FORMAT))
            .collect();
        assert_eq!(legacy.len(), 1);
        for member in ["protected", "payload", "signature"] {
            assert_eq!(legacy[0][member], signed[member], "{member} unchanged");
        }
        assert_eq!(
            page.proof
                .iter()
                .filter(|entry| entry["format"] == json!(HOST_FORMAT))
                .count(),
            3,
            "the Host batches beside it: 1-2 and 3 of one producer, 1-2 of the other"
        );
        assert_eq!(
            fixture
                .store
                .envelopes("plane-a", "i-1")
                .expect("read")
                .first()
                .and_then(|entry| entry.get("format")),
            None,
            "the stored envelope is unchanged"
        );
    }

    /// WP-6.1b, after the review: a run holding nothing readable (its whole prefix pruned) is
    /// observed to its end, so a tail does not answer `more` for it forever.
    #[test]
    fn a_run_with_nothing_left_to_read_is_not_more() {
        let fixture = Fixture::new("pruned-run");
        {
            let mut runs = fixture.held.runs.lock().unwrap();
            let pruned = &mut runs[1];
            pruned.run.oldest_retained = pruned.run.acked + 1;
        }
        let page = fixture.read(&tenant(), &Window::default()).expect("a page");
        assert_eq!(
            named(&page).len(),
            5,
            "the legacy records and the first producer's"
        );
        assert!(!page.more, "nothing is left to read");
    }

    /// WP-6.1b, after the review: pages bounded by bytes or filled by the legacy store resume
    /// where they stopped, across the runs, never skipping or repeating a record.
    #[test]
    fn pages_resume_across_sources_without_a_gap_or_a_repeat() {
        let fixture = Fixture::new("resume");
        let all = named(&fixture.read(&tenant(), &Window::default()).expect("a page"));
        assert_eq!(all.len(), 7);
        for window in [
            Window {
                limit_records: 2,
                ..Window::default()
            },
            Window {
                limit_bytes: 1,
                ..Window::default()
            },
        ] {
            let mut seen = Vec::new();
            let mut from = None;
            for _ in 0..20 {
                let page = fixture
                    .read(
                        &tenant(),
                        &Window {
                            from: from.clone(),
                            ..window.clone()
                        },
                    )
                    .expect("a page");
                seen.extend(named(&page));
                from = Some(page.next.clone());
                if !page.more {
                    break;
                }
            }
            assert_eq!(seen, all, "every record once, in order");
        }
        // A first page the legacy store fills leaves every run at its start.
        let first = fixture
            .read(
                &tenant(),
                &Window {
                    limit_records: 2,
                    ..Window::default()
                },
            )
            .expect("a page");
        assert!(named(&first).iter().all(|(id, _)| id == "plane-a"));
        assert!(first.more);
    }

    /// WP-6.1b, after the review: a page mixing both sources whose legacy record has no envelope
    /// is refused `unavailable`, since its paths pair with records by position; a legacy page
    /// alone keeps answering as before.
    #[test]
    fn a_mixed_page_missing_a_legacy_envelope_is_refused() {
        let fixture = Fixture::new("short-proof");
        let refused = fixture
            .read(
                &tenant(),
                &Window {
                    proof: true,
                    ..Window::default()
                },
            )
            .expect_err("a legacy record without its envelope");
        assert!(matches!(refused, ReadError::Unavailable(_)), "{refused:?}");
        assert_eq!(
            refusal(&refused),
            (
                permguard_core::ErrorClass::Unavailable,
                permguard_core::codes::stream::STORE_UNAVAILABLE
            )
        );
        let legacy = fixture
            .read(
                &Scope::Stream {
                    pdp_id: "plane-a".to_owned(),
                    instance: "i-1".to_owned(),
                },
                &Window {
                    proof: true,
                    ..Window::default()
                },
            )
            .expect("a legacy page alone");
        assert_eq!(legacy.records.len(), 2);
        assert_eq!(
            refusal(&ReadError::Offset(CursorError::Malformed)).0,
            permguard_core::ErrorClass::Validation
        );
    }

    /// WP-6.1b: a cursor standing in a run behind what the consumer still holds is answered,
    /// never silently moved past the records it lost.
    #[test]
    fn a_host_position_behind_retention_is_answered() {
        let fixture = Fixture::new("expired");
        let scope = Scope::Stream {
            pdp_id: hex(&[0xa1; 16]),
            instance: hex(&[0x01; 16]),
        };
        let first = fixture
            .read(
                &scope,
                &Window {
                    limit_records: 1,
                    ..Window::default()
                },
            )
            .expect("a page");
        assert_eq!(named(&first), vec![(hex(&[0xa1; 16]), 1)]);
        fixture.held.runs.lock().unwrap()[0].run.oldest_retained = 3;
        let refused = fixture
            .read(
                &scope,
                &Window {
                    from: Some(first.next),
                    ..Window::default()
                },
            )
            .expect_err("records 2 left");
        assert!(
            matches!(
                refused,
                ReadError::Expired {
                    oldest_sequence: 3,
                    requested_sequence: 2,
                    ..
                }
            ),
            "{refused:?}"
        );
        // A fresh reader starts at what is held.
        let fresh = fixture.read(&scope, &Window::default()).expect("a page");
        assert_eq!(named(&fresh), vec![(hex(&[0xa1; 16]), 3)]);
    }
}
