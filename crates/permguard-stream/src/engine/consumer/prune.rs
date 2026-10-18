// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A consumer's retention (WP-5.6b): the batches admitted longer ago than the retention of the
//! task that ships them, and for `history` no loaded temporal contract reads, go once the run's
//! anchor and the audit record are written.
//!
//! ```text
//! per run   bound = the last batch admitted at least `retention_seconds` ago, min `acked`, min
//!           the `history` floor; through = the last whole batch file below it
//!           ANCHOR (cumulative) ─▶ the audit record ─▶ STATE oldest_retained = through + 1
//!           ─▶ Journal::drop_prefix below the first RECORDS frame past `through`
//!           ─▶ the batch files at or below `through`, unlinked and flushed
//! ```
//!
//! The producer directory's `RESERVE` is released before anything is written and allocated
//! again after.

use permguard_core::authz::Resource;
use permguard_host::storage::Dir;
use permguard_host::storage::format;
use permguard_host::storage::write::{allocate, read_view, release, replace_view};

use super::super::anchor::{ANCHOR, Anchor, envelope_digest};
use super::super::batch::SealedBatch;
use super::super::producer::{RECORDS, Spans, decode_group};
use super::super::retention::{Audit, MAX_PRUNE_BATCHES, Pruned};
use super::super::{RecordCodec, Retention, StreamError, StreamKey, hex};
use super::{
    ADMITTED, BATCHES, Consumer, ConsumerState, Held, SIGNERS, STATE, child, encode_admitted,
    unhex16,
};

/// The name the job and the audit record give a consumer stream: plane, type, resource digest,
/// producer and run.
pub(super) fn pruned_name(key: &StreamKey, run: &[u8; 16]) -> String {
    format!(
        "{}/{}/{}/{}/{}",
        key.plane,
        key.stream_type,
        key.resource_component(),
        hex(&key.producer_host_id),
        hex(run)
    )
}

/// The reserve a consumer keeps beside its runs, released for a deletion's writes.
pub(super) const RESERVE_FILE: &str = "RESERVE";
pub(super) const RESERVE_BYTES: u64 = 64 * 1024;

/// The batch files of a run, `(first, last, name)`, in order.
fn batch_files(dir: &Dir) -> Result<Vec<(u64, u64, String)>, StreamError> {
    let Some(batches) = child(dir, BATCHES, false)? else {
        return Ok(Vec::new());
    };
    let mut found = Vec::new();
    for name in batches.names()? {
        let Some((first, last)) = name
            .strip_suffix(".jws")
            .and_then(|range| range.split_once('-'))
            .and_then(|(first, last)| Some((first.parse().ok()?, last.parse().ok()?)))
        else {
            continue;
        };
        found.push((first, last, name));
    }
    found.sort();
    Ok(found)
}

/// The resource a run's records are of: from a batch file it holds, or its anchor.
fn resource_of(dir: &Dir) -> Result<Option<String>, StreamError> {
    if let Some((_, _, name)) = batch_files(dir)?.first()
        && let Some(batches) = child(dir, BATCHES, false)?
        && let Some(bytes) = batches.read(name)?
    {
        return Ok(Some(
            SealedBatch::decode(&bytes)?
                .envelope_unverified()?
                .stream_key
                .resource,
        ));
    }
    Ok(read_view(dir, ANCHOR, format::VIEW)?
        .map(|bytes| Anchor::decode(&bytes))
        .transpose()?
        .map(|anchor| anchor.resource))
}

impl<C: RecordCodec> Consumer<C> {
    /// Every run this consumer holds: `(key, run)`.
    pub(super) fn runs(&self) -> Result<Vec<(StreamKey, [u8; 16])>, StreamError> {
        self.runs_under(None)
    }

    /// The runs this consumer holds of `resource`, reading its directory alone (WP-6.1b).
    pub(super) fn runs_of(
        &self,
        resource: &Resource,
    ) -> Result<Vec<(StreamKey, [u8; 16])>, StreamError> {
        let component = self.descriptor.key(resource, [0; 16])?.resource_component();
        self.runs_under(Some(&component))
    }

    fn runs_under(&self, only: Option<&str>) -> Result<Vec<(StreamKey, [u8; 16])>, StreamError> {
        let mut found = Vec::new();
        for component in self.dir.subdirs()? {
            if only.is_some_and(|only| only != component) {
                continue;
            }
            let resource_dir = self.dir.subdir(&component, false)?;
            for producer in resource_dir.subdirs()? {
                let Some(producer_id) = unhex16(&producer) else {
                    continue;
                };
                let producer_dir = resource_dir.subdir(&producer, false)?;
                for run in producer_dir.subdirs()? {
                    let Some(run_id) = unhex16(&run) else {
                        continue;
                    };
                    let Some(resource) = resource_of(&producer_dir.subdir(&run, false)?)? else {
                        continue;
                    };
                    let resource = Resource::parse(&resource)
                        .map_err(|error| StreamError::Corruption(error.to_string()))?;
                    let key = self.descriptor.key(&resource, producer_id)?;
                    if key.resource_component() != component {
                        return Err(StreamError::Corruption(format!(
                            "the run at `{component}/{producer}/{run}` holds another resource"
                        )));
                    }
                    found.push((key, run_id));
                }
            }
        }
        Ok(found)
    }

    /// What one pass would delete of `key`'s run `run`, or deletes when `audit` is given.
    pub(super) fn prune_run(
        &self,
        key: &StreamKey,
        run: [u8; 16],
        now: u64,
        audit: Option<Audit<'_>>,
    ) -> Result<Pruned, StreamError> {
        let name = pruned_name(key, &run);
        let nothing = || Pruned::nothing(name.clone(), "consumer");
        let retention = self
            .source
            .as_ref()
            .and_then(|source| source.retention_seconds(&key.resource, &key.producer_host_id));
        let pruned = self.with_held(key, run, false, |held| {
            let Some(retention) = retention else {
                return Ok(nothing());
            };
            if audit.is_some() {
                // Batch files a crash left below what is retained: decided, and finished.
                let stale: Vec<String> = batch_files(&held.dir)?
                    .into_iter()
                    .filter(|(_, last, _)| *last < held.oldest_retained)
                    .map(|(_, _, name)| name)
                    .collect();
                if let Some(batches) = child(&held.dir, BATCHES, false)?
                    && !stale.is_empty()
                {
                    for name in &stale {
                        batches.unlink(name)?;
                    }
                    batches.sync()?;
                }
            }
            if audit.is_some()
                && let Some((through, at)) = held.undated.take()
            {
                // Dated by the open that found them; written here, off any read path.
                held.journal
                    .append(ADMITTED, &encode_admitted(through, at)?)?;
                held.admitted.push((through, at));
            }
            // A batch file straddling what the run retains is not one this run wrote: refused,
            // as a producer refuses one straddling its mark (after the review).
            if let Some((_, _, name)) = batch_files(&held.dir)?.iter().find(|(first, last, _)| {
                *first < held.oldest_retained && *last >= held.oldest_retained
            }) {
                return Err(StreamError::Corruption(format!(
                    "the batch `{name}` straddles what run {} retains",
                    hex(&run)
                )));
            }
            // The admissions in order, up to the first not yet past retention: a later batch dated
            // earlier never carries an unexpired one along (after the review).
            let Some(mut bound) = held
                .admitted
                .iter()
                .take_while(|(_, at)| at.saturating_add(retention) <= now)
                .map(|(through, _)| *through)
                .last()
            else {
                return Ok(nothing());
            };
            bound = bound.min(held.acked);
            if self.descriptor.retention == Retention::History
                && let Some(floor) = &self.floor
            {
                bound = bound.min(floor.retention_safe(&key.resource, &run).unwrap_or(0));
            }
            let mut expected = held.oldest_retained;
            let mut files = Vec::new();
            for (first, last, name) in batch_files(&held.dir)? {
                if last < held.oldest_retained {
                    continue;
                }
                if first != expected || last > bound || files.len() == MAX_PRUNE_BATCHES {
                    break;
                }
                expected = last + 1;
                files.push((first, last, name));
            }
            let Some(&(_, through, _)) = files.last() else {
                return Ok(nothing());
            };
            let pruned = Pruned {
                stream: name.clone(),
                role: "consumer",
                run: Some(run),
                through,
                batches: files.len() as u64,
            };
            if let Some(audit) = audit {
                self.delete(held, key, run, &files, &pruned, audit)?;
            }
            Ok(pruned)
        })?;
        let pruned = pruned.unwrap_or_else(nothing);
        if pruned.run.is_none()
            && let Some(audit) = audit
        {
            audit(&pruned).map_err(StreamError::Invalid)?;
        }
        Ok(pruned)
    }

    /// The writes of a pass over one run: the anchor, the record, STATE, the journal prefix,
    /// the batch files.
    fn delete(
        &self,
        held: &mut Held,
        key: &StreamKey,
        run: [u8; 16],
        files: &[(u64, u64, String)],
        pruned: &Pruned,
        audit: Audit<'_>,
    ) -> Result<(), StreamError> {
        let producer = self.producer_dir(key, false)?.ok_or_else(|| {
            StreamError::Corruption("a run held has no producer directory".to_owned())
        })?;
        if producer.exists(RESERVE_FILE)? {
            release(&producer, RESERVE_FILE)?;
        }
        let deleted = self.delete_reserved(held, key, run, files, pruned, audit);
        let _ = allocate(&producer, RESERVE_FILE, RESERVE_BYTES);
        deleted
    }

    fn delete_reserved(
        &self,
        held: &mut Held,
        key: &StreamKey,
        run: [u8; 16],
        files: &[(u64, u64, String)],
        pruned: &Pruned,
        audit: Audit<'_>,
    ) -> Result<(), StreamError> {
        let batches = child(&held.dir, BATCHES, false)?.ok_or_else(|| {
            StreamError::Corruption("a run with batch files to delete has none".to_owned())
        })?;
        let retained_below = held.oldest_retained - 1;
        let anchor = read_view(&held.dir, ANCHOR, format::VIEW)?
            .map(|bytes| Anchor::decode(&bytes))
            .transpose()?;
        let anchored = anchor.as_ref().map_or(0, |anchor| anchor.through);
        let mut covering = anchor.map(|anchor| anchor.covering).unwrap_or_default();
        if anchored < retained_below {
            return Err(StreamError::Corruption(format!(
                "run {}'s records were deleted past its anchor",
                hex(&run)
            )));
        }
        if anchored > retained_below {
            // A pass a crash stopped after its anchor and before STATE: covered again below.
            let again = batch_files(&held.dir)?
                .iter()
                .filter(|(first, last, _)| *first > retained_below && *last <= anchored)
                .count();
            let kept = covering.len().checked_sub(again).ok_or_else(|| {
                StreamError::Corruption(format!(
                    "run {}'s anchor covers fewer batches than it names",
                    hex(&run)
                ))
            })?;
            covering.truncate(kept);
        }
        let mut last = None;
        for (_, _, name) in files {
            let bytes = batches.read(name)?.ok_or_else(|| {
                StreamError::Corruption(format!("the batch `{name}` went before its anchor"))
            })?;
            let envelope = SealedBatch::decode(&bytes)?.envelope_unverified()?;
            covering.push(envelope_digest(&envelope)?);
            last = Some((envelope, bytes));
        }
        let Some((envelope, checkpoint)) = last else {
            return Ok(());
        };
        let spans = match read_view(&held.dir, SIGNERS, format::VIEW)? {
            Some(bytes) => Spans::decode(&bytes)?,
            None => Spans::default(),
        };
        let signers = spans
            .runs
            .iter()
            .find(|(held_run, _)| *held_run == run)
            .map(|(_, spans)| {
                spans
                    .iter()
                    .filter(|span| span.from_seq <= pruned.through)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let anchor = Anchor {
            resource: key.resource.clone(),
            run,
            low_watermark: pruned.through + 1,
            through: pruned.through,
            terminal_head: envelope.head,
            covering,
            signers,
            checkpoint,
        };
        replace_view(&held.dir, ANCHOR, format::VIEW, &anchor.encode()?)?;
        audit(pruned).map_err(|error| {
            StreamError::Invalid(format!(
                "the deletion could not be audited, and nothing was deleted: {error}"
            ))
        })?;
        replace_view(
            &held.dir,
            STATE,
            format::VIEW,
            &ConsumerState {
                acked: held.acked,
                oldest_retained: pruned.through + 1,
                opened: held.opened,
            }
            .encode()?,
        )?;
        held.oldest_retained = pruned.through + 1;

        // The journal: below the segment of the first RECORDS frame past `through`.
        let mut keep_from = held.journal.next_index();
        for frame in held.journal.frames()? {
            if frame.kind != RECORDS {
                continue;
            }
            let (start, group) = decode_group(&frame.payload)?;
            if start + group.len() as u64 - 1 > pruned.through {
                keep_from = frame.index;
                break;
            }
        }
        if let Some(at) = held
            .journal
            .segment_starts()
            .into_iter()
            .filter(|start| *start <= keep_from)
            .max()
            && at > held.journal.first_index()
        {
            let reached = held.journal.drop_prefix(at, None)?;
            if reached != at {
                return Err(StreamError::Corruption(format!(
                    "the journal's prefix was to end at frame {at}, and ends at {reached}"
                )));
            }
            held.groups.retain(|(_, index)| *index >= at);
        }
        held.admitted
            .retain(|(through, _)| *through > pruned.through);

        for (_, _, name) in files {
            batches.unlink(name)?;
        }
        batches.sync()?;
        Ok(())
    }
}
