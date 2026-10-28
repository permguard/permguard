// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Sealing a producer stream's records into signed batches (WP-5.2; owner decisions of
//! 2026-10-13).
//!
//! ```text
//! producer/<sha256(resource)>/<producer-host>/
//! ├── batches/<run>/<first>-<last>.jws     immutable, published before a seal answers
//! ├── signers.cbor                         {1: [{1 run, 2: [{1 from_seq, 2 kid, 3 jwk}]}]}
//! └── CUTOVER                              {1 stream, 2 membership_id, 3 ring, 4 kid,
//!                                           5 from_seq, 6 confirmed}
//! ```
//!
//! The batch files are the authority on what is sealed: a run's sealed watermark is the last
//! sequence its contiguous files cover, and STATE's `signed_seq` follows them. A batch is
//! published first, its signer span after it, STATE last; a crash between them leaves a batch
//! the next seal counts as sealed, its span appended then, and it is never signed again. A span
//! is only ever appended. Under a fence, a key other than the stream's last one seals nothing
//! until the cutover naming the stream's next sequence is journaled by the coordinator (WP-4.5).

use permguard_core::keys::Jwk;
use permguard_host::keys::ring::Ring;
use permguard_host::storage::write::{publish_immutable, read_view, replace_view};
use permguard_host::storage::{Dir, format};
use permguard_objects::cbor::Value;

use super::super::batch::{Envelope, GENESIS_HEAD, KeyView, SealedBatch, digest_string};
use super::super::codec::{Map, encode, uint};
use super::super::run::{Fence, RunStatement, statement_digest};
use super::super::{Descriptor, StreamError, hex};
use super::{Context, Physical, RECORDS, RUN_OPEN, decode_group};

const BATCHES: &str = "batches";
/// The most bytes a batch's encoded records take: its file's bound less room for the envelope
/// and the signature.
#[cfg(not(test))]
const BATCH_RECORD_BYTES: usize = super::super::batch::MAX_BATCH_FILE_BYTES - 64 * 1024;
/// Small enough that the unit tests reach it.
#[cfg(test)]
const BATCH_RECORD_BYTES: usize = 8 * 1024;
const SIGNERS: &str = "signers.cbor";
const CUTOVER: &str = "CUTOVER";
/// The most bytes `signers.cbor` takes.
pub const MAX_SIGNERS_BYTES: usize = 1 << 20;
/// The most bytes CUTOVER takes.
pub const MAX_CUTOVER_BYTES: usize = 4096;

/// What a seal did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sealing {
    /// Every durable record is sealed already.
    Nothing,
    /// The batch of `first..=last` of `run`, its exact bytes.
    Sealed {
        run: [u8; 16],
        first: u64,
        last: u64,
        bytes: Vec<u8>,
    },
    /// The signing key changed under a fence: nothing is sealed until the coordinator journals
    /// the cutover of `stream` at `from_seq`.
    AwaitingCutover { stream: String, from_seq: u64 },
}

/// One signer span: the key that signs a run's batches from `from_seq` on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    pub from_seq: u64,
    pub kid: String,
    /// The public key's JWK, as JSON: a batch stays verifiable after its key left the ring.
    pub jwk: String,
}

/// The spans of every run of a stream, in run order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Spans {
    pub runs: Vec<([u8; 16], Vec<Span>)>,
}

impl Spans {
    pub fn encode(&self) -> Result<Vec<u8>, StreamError> {
        let mut runs = Vec::new();
        for (run, spans) in &self.runs {
            let mut entries = Vec::new();
            for span in spans {
                entries.push(Value::Map(vec![
                    (Value::Int(1), uint(span.from_seq)?),
                    (Value::Int(2), Value::Text(span.kid.clone())),
                    (Value::Int(3), Value::Text(span.jwk.clone())),
                ]));
            }
            runs.push(Value::Map(vec![
                (Value::Int(1), Value::Bytes(run.to_vec())),
                (Value::Int(2), Value::Array(entries)),
            ]));
        }
        encode(vec![(1, Value::Array(runs))])
    }

    // conformance: boundary
    pub fn decode(bytes: &[u8]) -> Result<Self, StreamError> {
        if bytes.len() > MAX_SIGNERS_BYTES {
            return Err(StreamError::Invalid(
                "a stream's signers are out of their bound".to_owned(),
            ));
        }
        let mut map = Map::read(bytes, "a stream's signers")?;
        let mut runs: Vec<([u8; 16], Vec<Span>)> = Vec::new();
        for value in map.array(1)? {
            let mut run = Map::of(value, "a run's signers")?;
            let run_id: [u8; 16] = run.fixed(1)?;
            let mut spans: Vec<Span> = Vec::new();
            for value in run.array(2)? {
                let mut span = Map::of(value, "a signer span")?;
                let read = Span {
                    from_seq: span.uint(1)?,
                    kid: span.text(2)?,
                    jwk: span.text(3)?,
                };
                span.finish()?;
                span_jwk(&read.jwk, &read.kid)?;
                if read.from_seq == 0
                    || spans
                        .last()
                        .is_some_and(|last| last.from_seq >= read.from_seq)
                {
                    return Err(StreamError::Invalid(
                        "a signer span starts after the one before it, at 1 or later".to_owned(),
                    ));
                }
                spans.push(read);
            }
            run.finish()?;
            if spans.is_empty() || runs.iter().any(|(held, _)| *held == run_id) {
                return Err(StreamError::Invalid(
                    "a run's signers name it once, with a span".to_owned(),
                ));
            }
            runs.push((run_id, spans));
        }
        map.finish()?;
        Ok(Self { runs })
    }

    /// The span of `run` that signs `seq`.
    pub fn signing(&self, run: &[u8; 16], seq: u64) -> Option<&Span> {
        self.runs
            .iter()
            .find(|(held, _)| held == run)
            .and_then(|(_, spans)| spans.iter().rev().find(|span| span.from_seq <= seq))
    }

    /// The last span the stream recorded, whatever its run.
    fn last(&self) -> Option<&Span> {
        self.runs.iter().rev().find_map(|(_, spans)| spans.last())
    }

    /// Appends `span` to `run`; refuses one that does not start after the run's last span.
    pub(crate) fn append(&mut self, run: [u8; 16], span: Span) -> Result<(), StreamError> {
        let at = match self.runs.iter().position(|(held, _)| *held == run) {
            Some(at) => at,
            None => {
                self.runs.push((run, Vec::new()));
                self.runs.len() - 1
            }
        };
        let spans = &mut self.runs[at].1;
        if spans
            .last()
            .is_some_and(|last| last.from_seq >= span.from_seq)
        {
            return Err(StreamError::Corruption(
                "a signer span is appended after the last one, never before".to_owned(),
            ));
        }
        spans.push(span);
        Ok(())
    }
}

/// A stream's cutover to a new signing key, pending or journaled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cutover {
    /// `<plane>/<type>/<sha256(resource)>/<run>`.
    pub stream: String,
    pub membership_id: [u8; 16],
    pub ring: String,
    pub kid: String,
    pub from_seq: u64,
    pub confirmed: bool,
}

impl Cutover {
    pub fn encode(&self) -> Result<Vec<u8>, StreamError> {
        encode(vec![
            (1, Value::Text(self.stream.clone())),
            (2, Value::Bytes(self.membership_id.to_vec())),
            (3, Value::Text(self.ring.clone())),
            (4, Value::Text(self.kid.clone())),
            (5, uint(self.from_seq)?),
            (6, Value::Bool(self.confirmed)),
        ])
    }

    // conformance: boundary
    pub fn decode(bytes: &[u8]) -> Result<Self, StreamError> {
        if bytes.len() > MAX_CUTOVER_BYTES {
            return Err(StreamError::Invalid(
                "a stream's cutover is out of its bound".to_owned(),
            ));
        }
        let mut map = Map::read(bytes, "a stream's cutover")?;
        let stream = map.text(1)?;
        let membership_id = map.fixed(2)?;
        let ring = map.text(3)?;
        let kid = map.text(4)?;
        let from_seq = map.uint(5)?;
        let Value::Bool(confirmed) = map.value(6)? else {
            return Err(StreamError::Invalid(
                "a cutover's confirmation is a boolean".to_owned(),
            ));
        };
        map.finish()?;
        Ok(Self {
            stream,
            membership_id,
            ring,
            kid,
            from_seq,
            confirmed,
        })
    }
}

pub(super) fn spans_of(dir: &Dir) -> Result<Spans, StreamError> {
    Ok(match read_view(dir, SIGNERS, format::VIEW)? {
        Some(bytes) => Spans::decode(&bytes)?,
        None => Spans::default(),
    })
}

pub(super) fn cutover_of(dir: &Dir) -> Result<Option<Cutover>, StreamError> {
    read_view(dir, CUTOVER, format::VIEW)?
        .map(|bytes| Cutover::decode(&bytes))
        .transpose()
}

pub(super) fn keep_cutover(dir: &Dir, cutover: &Cutover) -> Result<(), StreamError> {
    replace_view(dir, CUTOVER, format::VIEW, &cutover.encode()?)?;
    Ok(())
}

/// The view naming the last sequence of a run's batch files deleted because every required
/// subscription acknowledged them (WP-5.4).
pub(super) const PRUNED: &str = "PRUNED";

/// The last sequence of `dir`'s batch files deleted, 0 when none was.
pub(super) fn pruned_of(dir: &Dir) -> Result<u64, StreamError> {
    let Some(bytes) = read_view(dir, PRUNED, format::VIEW)? else {
        return Ok(0);
    };
    if bytes.len() > 16 {
        return Err(StreamError::Invalid(
            "a pruned mark is out of its bound".to_owned(),
        ));
    }
    let mut map = Map::read(&bytes, "a pruned mark")?;
    let through = map.uint(1)?;
    map.finish()?;
    Ok(through)
}

/// Every batch file of `dir`: `(first, last, name)`, unordered.
fn batch_files(dir: &Dir) -> Result<Vec<(u64, u64, String)>, StreamError> {
    let mut found = Vec::new();
    for name in dir.names()? {
        let Some(range) = name.strip_suffix(".jws") else {
            continue;
        };
        let parsed = range
            .split_once('-')
            .and_then(|(first, last)| Some((first.parse::<u64>().ok()?, last.parse::<u64>().ok()?)))
            .filter(|(first, last)| {
                *first >= 1 && first <= last && name == format!("{first}-{last}.jws")
            });
        let Some((first, last)) = parsed else {
            return Err(StreamError::Corruption(format!(
                "`{name}` names no range of a run"
            )));
        };
        found.push((first, last, name));
    }
    Ok(found)
}

/// The batch files at or below the pruned mark a crash left before deleting them: what the next
/// truncation deletes (after the review).
pub(super) fn below_mark(dir: &Dir) -> Result<Vec<String>, StreamError> {
    let pruned = pruned_of(dir)?;
    Ok(batch_files(dir)?
        .into_iter()
        .filter(|(_, last, _)| *last <= pruned)
        .map(|(_, _, name)| name)
        .collect())
}

/// The batch files of one run: `(first, last, name)`, in order and contiguous from the sequence
/// after the last pruned, 1 when none was. A file wholly at or below the pruned mark is one a
/// crash left before its deletion, skipped; one straddling the mark is refused (after the
/// review).
pub(super) fn batches_of(dir: &Dir) -> Result<Vec<(u64, u64, String)>, StreamError> {
    let pruned = pruned_of(dir)?;
    let mut found: Vec<(u64, u64, String)> = batch_files(dir)?
        .into_iter()
        .filter(|(_, last, _)| *last > pruned)
        .collect();
    found.sort();
    let mut sealed = pruned;
    for (first, last, name) in &found {
        if *first != sealed + 1 {
            return Err(StreamError::Corruption(format!(
                "the batch `{name}` does not follow sequence {sealed}"
            )));
        }
        sealed = *last;
    }
    Ok(found)
}

/// Where the next seal starts, kept by the writer while the run it was computed under is current:
/// a seal reads the journal from the frame its records start at, not from the beginning. A
/// rollover, a reopening or any failure computes it again from the segments and the batch files.
pub(crate) struct Next {
    /// The digest of the current run it was computed under.
    current: [u8; 32],
    runs: Vec<Held>,
    /// Each run's sealed watermark, as its batch files cover it.
    sealed: Vec<u64>,
    spans: Spans,
    /// The run the next batch seals: the oldest with unsealed records, else the last.
    at: usize,
    /// The head before the next batch: the last sealed record's digest, or genesis.
    head: String,
    /// The journal frame the next batch's records are read from.
    from_frame: u64,
}

/// One run as the segments hold it, for sealing.
struct Held {
    statement: RunStatement,
    digest: [u8; 32],
    /// The index of its RUN_OPEN frame.
    open_frame: u64,
    last_seq: u64,
}

/// A run as the shipper reads it: its id, its fence's membership, its last sequence, its sealed
/// watermark.
pub(super) type RunView = ([u8; 16], Option<[u8; 16]>, u64, u64);

/// The name a cutover gives a stream: its plane, type, resource digest and run.
pub(super) fn stream_name(physical: &Physical, run: &[u8; 16]) -> String {
    format!(
        "{}/{}/{}/{}",
        physical.key.plane,
        physical.key.stream_type,
        physical.key.resource_component(),
        hex(run)
    )
}

/// `jwk` as RFC 8785 canonical JSON: what a span keeps.
pub fn canonical_jwk(jwk: &Jwk) -> Result<String, StreamError> {
    let value =
        serde_json::to_value(jwk).map_err(|error| StreamError::Invalid(error.to_string()))?;
    String::from_utf8(
        crate::jcs::canonicalize(&value)
            .map_err(|error| StreamError::Invalid(error.to_string()))?,
    )
    .map_err(|error| StreamError::Invalid(error.to_string()))
}

/// The JWK a span keeps, refused unless canonical and naming the span's key.
fn span_jwk(text: &str, kid: &str) -> Result<Jwk, StreamError> {
    let invalid = |detail: String| StreamError::Invalid(format!("a signer span's key: {detail}"));
    let jwk: Jwk = serde_json::from_value(
        crate::jcs::decode_canonical(text.as_bytes())
            .map_err(|error| invalid(error.to_string()))?,
    )
    .map_err(|error| invalid(error.to_string()))?;
    if jwk.kid != kid {
        return Err(invalid(format!("it names `{}`, not `{kid}`", jwk.kid)));
    }
    Ok(jwk)
}

/// The JWK of `kid` in `signer`, whatever its state: a span names a key that may have left the
/// published set since it signed (after the review).
fn known(signer: &Ring, kid: &str) -> Result<Jwk, StreamError> {
    let view = signer
        .view()
        .map_err(|error| StreamError::Sign(error.to_string()))?;
    let key = view
        .keys
        .iter()
        .find(|key| key.kid == kid)
        .ok_or_else(|| StreamError::Sign(format!("the ring holds no key `{kid}`")))?;
    serde_json::from_str(&key.jwk).map_err(|error| StreamError::Sign(error.to_string()))
}

/// The active key of `signer` and the ring epoch, read together (after the review).
fn active(signer: &Ring) -> Result<(Jwk, u64), StreamError> {
    let view = signer
        .view()
        .map_err(|error| StreamError::Sign(error.to_string()))?;
    let key = view
        .keys
        .iter()
        .find(|key| key.state == permguard_host::keys::record::State::Active)
        .ok_or_else(|| StreamError::Sign("no key of the ring is active yet".to_owned()))?;
    let jwk =
        serde_json::from_str(&key.jwk).map_err(|error| StreamError::Sign(error.to_string()))?;
    Ok((jwk, view.epoch))
}

fn pending(
    fence: &Fence,
    descriptor: &Descriptor,
    stream: String,
    kid: &str,
    from_seq: u64,
) -> Cutover {
    Cutover {
        stream,
        membership_id: fence.membership_id,
        ring: descriptor.ring.to_owned(),
        kid: kid.to_owned(),
        from_seq,
        confirmed: false,
    }
}

impl Physical {
    /// Seals the next batch of the stream, at most `max_records`, under `signer`: the oldest
    /// run with durable records no batch covers comes first.
    pub(super) fn seal(
        &self,
        context: &Context,
        descriptor: &Descriptor,
        signer: &Ring,
        max_records: u64,
        max_record_bytes: usize,
    ) -> Result<Sealing, StreamError> {
        let budget = BATCH_RECORD_BYTES.min(max_record_bytes);
        let mut writer = self.writer();
        // Taken out: it goes back only when everything below succeeded.
        let Some(mut next) = self.next(&mut writer, signer, descriptor)? else {
            return Ok(Sealing::Nothing);
        };
        let run = &next.runs[next.at];
        let sealed = next.sealed[next.at];
        if sealed >= run.last_seq {
            writer.next = Some(next);
            return Ok(Sealing::Nothing);
        }
        let run_id = run.statement.run_id;
        let (jwk, key_set_epoch) = active(signer)?;
        if let Some(waiting) =
            self.cutover_gate(&writer.dir, &next.spans, run, &jwk.kid, sealed, descriptor)?
        {
            writer.next = Some(next);
            return Ok(waiting);
        }
        let first = sealed + 1;
        let last = run.last_seq.min(sealed + max_records.max(1));
        let mut last = last;
        let mut in_run = next.from_frame > run.open_frame;
        let mut records: Vec<Vec<u8>> = Vec::new();
        let mut size = 0usize;
        let mut from_frame = None;
        'frames: for frame in writer.journal.frames_from(next.from_frame)? {
            match frame.kind {
                RUN_OPEN if frame.index == run.open_frame => in_run = true,
                RUN_OPEN if in_run => break,
                RECORDS if in_run => {
                    let (from, group) = decode_group(&frame.payload)?;
                    let end = from + group.len() as u64 - 1;
                    for (offset, bytes) in group.into_iter().enumerate() {
                        let seq = from + offset as u64;
                        if !(first..=last).contains(&seq) {
                            continue;
                        }
                        // A batch file stays within the bound its readers hold it to: the
                        // records it carries, base64url and quoted, beside the envelope (after
                        // the review).
                        let grown = size + bytes.len().div_ceil(3) * 4 + 3;
                        if !records.is_empty() && grown > budget {
                            last = seq - 1;
                            from_frame = Some(frame.index);
                            break 'frames;
                        }
                        size = grown;
                        records.push(bytes);
                    }
                    if (from..=end).contains(&last) {
                        // The frame the record after `last` is in: this one, or the one after.
                        from_frame = Some(if end > last {
                            frame.index
                        } else {
                            frame.index + 1
                        });
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(from_frame) = from_frame.filter(|_| records.len() as u64 == last - sealed) else {
            return Err(StreamError::Corruption(
                "the run does not hold the records its frames number".to_owned(),
            ));
        };
        let digests: Vec<String> = records
            .iter()
            .map(|record| digest_string(descriptor.record_domain, record))
            .collect();
        let fence = run.statement.fence.as_ref();
        let envelope = Envelope {
            descriptor_version: descriptor.version,
            stream_key: KeyView::of(&self.key),
            run: hex(&run_id),
            membership_id: fence
                .map(|fence| permguard_host::identity::record::uuid_text(&fence.membership_id)),
            epoch: fence.map(|fence| fence.epoch),
            first_seq: first,
            last_seq: last,
            count: last - sealed,
            previous_head: next.head.clone(),
            head: digests.last().cloned().unwrap_or_default(),
            merkle_root: crate::merkle::root(&digests).unwrap_or_default(),
            batch_id: format!("{}-{first}", hex(&run_id)),
            created_at: permguard_host::api::grants::rfc3339(context.time.now_secs()),
            key_set_epoch,
        };
        let bytes =
            SealedBatch::seal(signer, &jwk, descriptor.batch_typ, &envelope, &records)?.encode()?;
        // The batch first, immutable; its span after it; STATE last.
        let dir = writer
            .dir
            .subdir(BATCHES, true)?
            .subdir(&hex(&run_id), true)?;
        publish_immutable(
            &dir,
            &format!("{first}-{last}.jws"),
            &bytes,
            &|_| true,
            &|held| held == bytes.as_slice(),
        )?;
        if next
            .spans
            .signing(&run_id, first)
            .is_none_or(|span| span.kid != jwk.kid)
        {
            Self::append_span(&writer.dir, &mut next.spans, run_id, first, &jwk)?;
        }
        let current = writer.run.clone();
        if let Some(current) = current.filter(|current| current.digest == next.runs[next.at].digest)
        {
            writer.keep_signed(&current, last)?;
        }
        next.sealed[next.at] = last;
        next.head = envelope.head;
        next.from_frame = from_frame;
        // A run sealed through moves the next seal to the run after it, from genesis.
        if last == next.runs[next.at].last_seq && next.at + 1 < next.runs.len() {
            next.at += 1;
            if next.sealed[next.at] == 0 {
                next.head = GENESIS_HEAD.to_owned();
                next.from_frame = next.runs[next.at].open_frame;
                writer.next = Some(next);
            }
        } else {
            writer.next = Some(next);
        }
        Ok(Sealing::Sealed {
            run: run_id,
            first,
            last,
            bytes,
        })
    }

    /// Every run of the stream: its id, its fence's membership, its last sequence (WP-5.4).
    pub(super) fn runs(
        &self,
        signer: &Ring,
        descriptor: &Descriptor,
    ) -> Result<Vec<RunView>, StreamError> {
        let mut writer = self.writer();
        let Some(next) = self.next(&mut writer, signer, descriptor)? else {
            return Ok(Vec::new());
        };
        let runs = next
            .runs
            .iter()
            .zip(&next.sealed)
            .map(|(run, sealed)| {
                (
                    run.statement.run_id,
                    run.statement
                        .fence
                        .as_ref()
                        .map(|fence| fence.membership_id),
                    run.last_seq,
                    *sealed,
                )
            })
            .collect();
        writer.next = Some(next);
        Ok(runs)
    }

    /// Where the next seal starts, taken from the writer: the one kept while its run is current,
    /// or computed again. `None` when the stream holds no run.
    fn next(
        &self,
        writer: &mut super::Writer,
        signer: &Ring,
        descriptor: &Descriptor,
    ) -> Result<Option<Next>, StreamError> {
        if let Some(at_seq) = writer.state.as_ref().and_then(|state| state.forked_at_seq) {
            return Err(StreamError::Forked { at_seq });
        }
        let Some(current) = writer.run.clone() else {
            return Ok(None);
        };
        if let Some(mut next) = writer
            .next
            .take()
            .filter(|next| next.current == current.digest)
        {
            if let Some(last) = next.runs.last_mut() {
                last.last_seq = current.last_seq;
            }
            return Ok(Some(next));
        }
        self.survey(writer, signer, descriptor, &current).map(Some)
    }

    /// Computes where the next seal starts from the segments and the batch files. A batch a crash
    /// left before its span gets the span here; STATE's `signed_seq` follows the current run's
    /// files.
    fn survey(
        &self,
        writer: &mut super::Writer,
        signer: &Ring,
        descriptor: &Descriptor,
        current: &super::Run,
    ) -> Result<Next, StreamError> {
        let frames = writer.journal.frames()?;
        let mut runs: Vec<Held> = Vec::new();
        // Below the journal's first frame the first run opened earlier (WP-5.6): its records
        // start at the first frame, and its head below them is STATE's base.
        let base = writer.base().cloned();
        if let Some(base) = &base {
            runs.push(Held {
                statement: RunStatement::decode(
                    permguard_objects::cose::Sign1::decode(&base.statement)
                        .map_err(|error| StreamError::Invalid(error.to_string()))?
                        .payload_unverified(),
                )?,
                digest: statement_digest(&base.statement),
                // The frame before the first kept, which no frame has: the seal reads the run's
                // records from the first kept frame on (after the review).
                open_frame: base.first_index - 1,
                last_seq: base.last_seq,
            });
        }
        for frame in &frames {
            match frame.kind {
                RUN_OPEN => runs.push(Held {
                    statement: RunStatement::decode(
                        permguard_objects::cose::Sign1::decode(&frame.payload)
                            .map_err(|error| StreamError::Invalid(error.to_string()))?
                            .payload_unverified(),
                    )?,
                    digest: statement_digest(&frame.payload),
                    open_frame: frame.index,
                    last_seq: 0,
                }),
                RECORDS => {
                    let (first, group) = decode_group(&frame.payload)?;
                    if let Some(run) = runs.last_mut() {
                        run.last_seq = first + group.len() as u64 - 1;
                    }
                }
                _ => {}
            }
        }
        if runs.last().map(|run| run.digest) != Some(current.digest) {
            return Err(StreamError::Corruption(
                "the segments do not end with the run the stream writes".to_owned(),
            ));
        }
        let root = writer.dir.subdir(BATCHES, true)?;
        let mut spans = spans_of(&writer.dir)?;
        let mut watermarks = Vec::with_capacity(runs.len());
        for run in &runs {
            let dir = root.subdir(&hex(&run.statement.run_id), true)?;
            // A publish a crash interrupted before its link leaves a temporary: swept.
            dir.sweep_temps()?;
            let batches = batches_of(&dir)?;
            // The last batch a crash left before its span: its span now, whether the run had none
            // or the batch's key is not the one its covering span names (after the review).
            if let Some((first, _, name)) = batches.last() {
                let bytes = dir.read(name)?.unwrap_or_default();
                let kid = SealedBatch::decode(&bytes)?.kid()?;
                if spans
                    .signing(&run.statement.run_id, *first)
                    .is_none_or(|span| span.kid != kid)
                {
                    Self::append_span(
                        &writer.dir,
                        &mut spans,
                        run.statement.run_id,
                        *first,
                        &known(signer, &kid)?,
                    )?;
                }
            }
            let sealed = match batches.last() {
                Some((_, last, _)) => *last,
                None => pruned_of(&dir)?,
            };
            if sealed > run.last_seq {
                return Err(StreamError::Corruption(format!(
                    "a batch of run {} seals sequence {sealed}, past its records",
                    hex(&run.statement.run_id)
                )));
            }
            if run.digest == current.digest {
                writer.keep_signed(current, sealed)?;
            }
            watermarks.push(sealed);
        }
        let at = runs
            .iter()
            .zip(&watermarks)
            .position(|(run, sealed)| *sealed < run.last_seq)
            .unwrap_or(runs.len() - 1);
        let (run, sealed) = (&runs[at], watermarks[at]);
        // The head before the next batch, and the frame its first record is in.
        let mut head = GENESIS_HEAD.to_owned();
        let mut from_frame = if sealed == run.last_seq {
            writer.journal.next_index()
        } else {
            run.open_frame
        };
        // The run STATE's base names has no RUN_OPEN frame left: its records start at the
        // journal's first frame, and the record at its base's last sequence went with the prefix.
        let mut in_run = false;
        if let Some(base) = base
            .as_ref()
            .filter(|base| statement_digest(&base.statement) == run.digest)
        {
            in_run = true;
            if sealed > 0 && sealed == base.last_seq {
                head = format!("sha256:{}", hex(&base.last_digest));
            } else if sealed < base.last_seq {
                return Err(StreamError::Corruption(format!(
                    "run {} sealed through {sealed}, below the prefix that went",
                    hex(&run.statement.run_id)
                )));
            }
        }
        for frame in &frames {
            match frame.kind {
                RUN_OPEN => in_run = frame.index == run.open_frame,
                RECORDS if in_run => {
                    let (first, group) = decode_group(&frame.payload)?;
                    let end = first + group.len() as u64 - 1;
                    if sealed >= first && sealed <= end {
                        head = digest_string(
                            descriptor.record_domain,
                            &group[(sealed - first) as usize],
                        );
                    }
                    if sealed < run.last_seq && (first..=end).contains(&(sealed + 1)) {
                        from_frame = frame.index;
                    }
                }
                _ => {}
            }
        }
        Ok(Next {
            current: current.digest,
            runs,
            sealed: watermarks,
            spans,
            at,
            head,
            from_frame,
        })
    }

    /// The cutover this stream needs before `kid` of `signer` seals for `membership_id`:
    /// `(stream, from_seq)`, recorded pending; `None` when its run is not that membership's,
    /// it sealed nothing yet, or it seals under `kid` already.
    pub(super) fn due(
        &self,
        descriptor: &Descriptor,
        signer: &Ring,
        membership_id: &[u8; 16],
        kid: &str,
    ) -> Result<Option<(String, u64)>, StreamError> {
        let mut writer = self.writer();
        let Some(next) = self.next(&mut writer, signer, descriptor)? else {
            return Ok(None);
        };
        let (run, sealed) = (&next.runs[next.at], next.sealed[next.at]);
        let due = if run
            .statement
            .fence
            .as_ref()
            .is_none_or(|fence| fence.membership_id != *membership_id)
        {
            None
        } else {
            match self.cutover_gate(&writer.dir, &next.spans, run, kid, sealed, descriptor)? {
                Some(Sealing::AwaitingCutover { stream, from_seq }) => Some((stream, from_seq)),
                // Confirmed already: what was journaled, sent again.
                None => cutover_of(&writer.dir)?
                    .filter(|cutover| {
                        cutover.kid == kid
                            && cutover.stream == stream_name(self, &run.statement.run_id)
                    })
                    .map(|cutover| (cutover.stream, cutover.from_seq)),
                Some(_) => None,
            }
        };
        writer.next = Some(next);
        Ok(due)
    }

    /// Under a fence, a key other than the stream's last span's seals only once the cutover
    /// naming the next sequence is journaled: answers the wait, recording the cutover pending.
    fn cutover_gate(
        &self,
        dir: &Dir,
        spans: &Spans,
        run: &Held,
        kid: &str,
        sealed: u64,
        descriptor: &Descriptor,
    ) -> Result<Option<Sealing>, StreamError> {
        let (Some(fence), Some(last)) = (&run.statement.fence, spans.last()) else {
            return Ok(None);
        };
        if last.kid == kid {
            return Ok(None);
        }
        let stream = stream_name(self, &run.statement.run_id);
        let cutover = match cutover_of(dir)? {
            Some(cutover) if cutover.kid == kid && cutover.stream == stream => {
                if cutover.confirmed {
                    return Ok(None);
                }
                cutover
            }
            _ => {
                let cutover = pending(fence, descriptor, stream, kid, sealed + 1);
                keep_cutover(dir, &cutover)?;
                cutover
            }
        };
        Ok(Some(Sealing::AwaitingCutover {
            stream: cutover.stream,
            from_seq: cutover.from_seq,
        }))
    }

    /// Appends the span of `jwk` from `from_seq` to `run`, and keeps it.
    fn append_span(
        dir: &Dir,
        spans: &mut Spans,
        run: [u8; 16],
        from_seq: u64,
        jwk: &Jwk,
    ) -> Result<(), StreamError> {
        let mut grown = spans.clone();
        grown.append(
            run,
            Span {
                from_seq,
                kid: jwk.kid.clone(),
                jwk: canonical_jwk(jwk)?,
            },
        )?;
        // Refused once past the bound a reader holds them to, the spans left as they were.
        let bytes = grown.encode()?;
        if bytes.len() > MAX_SIGNERS_BYTES {
            return Err(StreamError::Invalid(format!(
                "the stream's signer spans would pass their bound of {MAX_SIGNERS_BYTES} bytes"
            )));
        }
        replace_view(dir, SIGNERS, format::VIEW, &bytes)?;
        *spans = grown;
        Ok(())
    }
}
