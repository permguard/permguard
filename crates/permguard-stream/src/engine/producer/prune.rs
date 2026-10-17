// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A producer's retention (WP-5.6b): the batch files and the journal prefix every required
//! subscription acknowledged, and for `history` no loaded temporal contract reads, go once the
//! run's anchor and the audit record are written.
//!
//! ```text
//! per run   bound = truncate_safe, min the `history` floor; through = the last whole batch below
//!           ANCHOR (cumulative, from sequence 1) ─▶ the audit record ─▶ PRUNED {1 through}
//! journal   the first frame still kept: the first RECORDS frame past its run's `through`
//!           base = what the frames before that frame's segment gave the open ─▶ STATE 11
//!           ─▶ Journal::drop_prefix: BASE, then the segments below it
//! then      the batch files at or below `through`, unlinked and flushed
//! ```
//!
//! The stream's `RESERVE` is released before anything is written and allocated again after, as
//! a rollover does: the anchor and the record that make a deletion accountable are never refused
//! for space the deletion is about to return.

use permguard_host::storage::format;
use permguard_host::storage::write::{allocate, read_view, release, replace_view};

use super::super::anchor::{ANCHOR, Anchor, envelope_digest};
use super::super::batch::SealedBatch;
use super::super::codec::{encode, uint};
use super::super::retention::{Audit, MAX_PRUNE_BATCHES, Pruned};
use super::super::run::RunStatement;
use super::super::state::Base;
use super::super::{RecordCodec, Retention, StreamError, hex, record_digest};
use super::seal::{PRUNED, batches_of, below_mark, pruned_of, spans_of};
use super::ship::{subscriptions_of, truncate_safe_of};
use super::{
    Physical, Producer, RECORDS, RESERVE_BYTES, RESERVE_FILE, RUN_OPEN, TERMINAL, Writer,
    decode_group,
};

const BATCHES: &str = "batches";

/// One run's share of a pass: the batch files that go, `(first, last, name)`.
struct Planned {
    run: [u8; 16],
    files: Vec<(u64, u64, String)>,
}

impl<C: RecordCodec> Producer<C> {
    /// The name the job and the audit record give a producer stream.
    pub(super) fn pruned_name(physical: &Physical) -> String {
        format!(
            "{}/{}/{}/{}",
            physical.key.plane,
            physical.key.stream_type,
            physical.key.resource_component(),
            hex(&physical.key.producer_host_id)
        )
    }

    /// What one pass would delete of `physical`, or deletes when `audit` is given.
    pub(super) fn prune_stream(
        &self,
        physical: &Physical,
        audit: Option<Audit<'_>>,
    ) -> Result<Vec<Pruned>, StreamError> {
        let name = Self::pruned_name(physical);
        // A producer that seals nothing has no batch to delete, nor a run acknowledged.
        let Ok(signer) = self.signer_ring() else {
            let nothing = Pruned::nothing(name, "producer");
            if let Some(audit) = audit {
                audit(&nothing).map_err(StreamError::Invalid)?;
            }
            return Ok(vec![nothing]);
        };
        let runs = physical.runs(signer, &self.descriptor)?;
        let mut writer = physical.writer();
        let subscriptions = subscriptions_of(&writer.dir)?;
        let root = writer.dir.subdir(BATCHES, true)?;
        if audit.is_some() {
            // What a crash left below a run's mark before its deletion: decided, and finished.
            for (run, ..) in &runs {
                let dir = root.subdir(&hex(run), true)?;
                let stale = below_mark(&dir)?;
                for name in &stale {
                    dir.unlink(name)?;
                }
                if !stale.is_empty() {
                    dir.sync()?;
                }
            }
        }
        let mut budget = MAX_PRUNE_BATCHES;
        let mut planned = Vec::new();
        for (run, fence, last_seq, _) in &runs {
            let Some(safe) = truncate_safe_of(&subscriptions, run, *fence) else {
                continue;
            };
            let mut bound = safe.min(*last_seq);
            if self.descriptor.retention == Retention::History
                && let Some(floor) = &self.floor
            {
                bound = bound.min(
                    floor
                        .retention_safe(&physical.key.resource, run)
                        .unwrap_or(0),
                );
            }
            let dir = root.subdir(&hex(run), true)?;
            let files: Vec<(u64, u64, String)> = batches_of(&dir)?
                .into_iter()
                .filter(|(_, last, _)| *last <= bound)
                .take(budget)
                .collect();
            if files.is_empty() {
                continue;
            }
            budget -= files.len();
            planned.push(Planned { run: *run, files });
        }
        let pruned: Vec<Pruned> = planned
            .iter()
            .map(|plan| Pruned {
                stream: name.clone(),
                role: "producer",
                run: Some(plan.run),
                through: plan.files.last().map_or(0, |(_, last, _)| *last),
                batches: plan.files.len() as u64,
            })
            .collect();
        let Some(audit) = audit else {
            return Ok(if pruned.is_empty() {
                vec![Pruned::nothing(name, "producer")]
            } else {
                pruned
            });
        };
        if planned.is_empty() {
            let nothing = Pruned::nothing(name, "producer");
            audit(&nothing).map_err(StreamError::Invalid)?;
            // A pass stopped after its marks and before the journal: caught up now.
            self.drop_journal_prefix(&mut writer, &root)?;
            return Ok(vec![nothing]);
        }

        // The anchor and the record are never refused for the space the deletion returns.
        if writer.reserved {
            release(&writer.dir, RESERVE_FILE)?;
            writer.reserved = false;
        }
        let deleted = self.delete(&mut writer, &root, physical, &planned, &pruned, audit);
        writer.reserved = allocate(&writer.dir, RESERVE_FILE, RESERVE_BYTES).unwrap_or(false);
        deleted?;
        Ok(pruned)
    }

    /// The writes of a pass: each run's anchor, record and mark, then the journal prefix and the
    /// batch files.
    fn delete(
        &self,
        writer: &mut Writer,
        root: &permguard_host::storage::Dir,
        physical: &Physical,
        planned: &[Planned],
        pruned: &[Pruned],
        audit: Audit<'_>,
    ) -> Result<(), StreamError> {
        let spans = spans_of(&writer.dir)?;
        for (plan, record) in planned.iter().zip(pruned) {
            let dir = root.subdir(&hex(&plan.run), true)?;
            let held = pruned_of(&dir)?;
            let anchor = match read_view(&dir, ANCHOR, format::VIEW)? {
                Some(bytes) => Some(Anchor::decode(&bytes)?),
                None => None,
            };
            let anchored = anchor.as_ref().map_or(0, |anchor| anchor.through);
            let mut covering = anchor.map(|anchor| anchor.covering).unwrap_or_default();
            // A run truncated before anchors existed (WP-5.4) has a mark and no anchor: what went
            // then has no digest left to keep, and its anchor covers from the mark on (after the
            // review). A mark past an anchor is corruption.
            if anchored < held && anchored > 0 {
                return Err(StreamError::Corruption(format!(
                    "run {}'s batch files were deleted past its anchor",
                    hex(&plan.run)
                )));
            }
            if anchored > held {
                // A pass a crash stopped after its anchor and before its mark: the batches it
                // covered past the mark are still here, and are covered again below.
                let again = batches_of(&dir)?
                    .iter()
                    .filter(|(_, last, _)| *last <= anchored)
                    .count();
                let kept = covering.len().checked_sub(again).ok_or_else(|| {
                    StreamError::Corruption(format!(
                        "run {}'s anchor covers fewer batches than it names",
                        hex(&plan.run)
                    ))
                })?;
                covering.truncate(kept);
            }
            let mut last = None;
            for (_, _, name) in &plan.files {
                let bytes = dir.read(name)?.ok_or_else(|| {
                    StreamError::Corruption(format!("the batch `{name}` went before its anchor"))
                })?;
                let envelope = SealedBatch::decode(&bytes)?.envelope_unverified()?;
                covering.push(envelope_digest(&envelope)?);
                last = Some((envelope, bytes));
            }
            let Some((envelope, checkpoint)) = last else {
                continue;
            };
            let signers = spans
                .runs
                .iter()
                .find(|(run, _)| *run == plan.run)
                .map(|(_, spans)| {
                    spans
                        .iter()
                        .filter(|span| span.from_seq <= record.through)
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            let anchor = Anchor {
                resource: physical.key.resource.clone(),
                run: plan.run,
                low_watermark: record.through + 1,
                through: record.through,
                terminal_head: envelope.head,
                covering,
                signers,
                checkpoint,
            };
            replace_view(&dir, ANCHOR, format::VIEW, &anchor.encode()?)?;
            audit(record).map_err(|error| {
                StreamError::Invalid(format!(
                    "the deletion could not be audited, and nothing was deleted: {error}"
                ))
            })?;
            replace_view(
                &dir,
                PRUNED,
                format::VIEW,
                &encode(vec![(1, uint(record.through)?)])?,
            )?;
        }

        self.drop_journal_prefix(writer, root)?;

        for plan in planned {
            let dir = root.subdir(&hex(&plan.run), true)?;
            for (_, _, name) in &plan.files {
                dir.unlink(name)?;
            }
            dir.sync()?;
        }
        Ok(())
    }

    /// Deletes the journal segments whose every frame is a run's opening or ending, or records
    /// at or below their run's mark, after writing what they gave the open as STATE's base.
    fn drop_journal_prefix(
        &self,
        writer: &mut Writer,
        root: &permguard_host::storage::Dir,
    ) -> Result<(), StreamError> {
        let first = writer.journal.first_index();
        let mut marks: std::collections::BTreeMap<[u8; 16], u64> =
            std::collections::BTreeMap::new();
        let mut through = |run: &[u8; 16]| -> Result<u64, StreamError> {
            if let Some(mark) = marks.get(run) {
                return Ok(*mark);
            }
            let mark = pruned_of(&root.subdir(&hex(run), true)?)?;
            marks.insert(*run, mark);
            Ok(mark)
        };
        let frames = writer.journal.frames()?;
        let mut current: Option<[u8; 16]> = match writer.base() {
            Some(base) => Some(run_id(&base.statement)?),
            None => None,
        };
        let mut keep_from = writer.journal.next_index();
        for frame in &frames {
            match frame.kind {
                RUN_OPEN => current = Some(run_id(&frame.payload)?),
                RECORDS => {
                    let (start, group) = decode_group(&frame.payload)?;
                    let end = start + group.len() as u64 - 1;
                    let Some(run) = current else {
                        return Err(StreamError::Corruption(format!(
                            "frame {} holds records outside a run",
                            frame.index
                        )));
                    };
                    if end > through(&run)? {
                        keep_from = frame.index;
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(at) = writer
            .journal
            .segment_starts()
            .into_iter()
            .filter(|start| *start <= keep_from)
            .max()
        else {
            return Ok(());
        };
        if at <= first {
            return Ok(());
        }

        // What the frames below `at` give the open: the run open there, how far it reached.
        let mut base = writer.base().cloned();
        for frame in frames.iter().take_while(|frame| frame.index < at) {
            match frame.kind {
                RUN_OPEN => {
                    base = Some(Base {
                        first_index: at,
                        statement: frame.payload.clone(),
                        last_seq: 0,
                        last_digest: [0; 32],
                        ended: false,
                    });
                }
                RECORDS => {
                    let (start, group) = decode_group(&frame.payload)?;
                    if let (Some(base), Some(record)) = (base.as_mut(), group.last()) {
                        base.last_seq = start + group.len() as u64 - 1;
                        base.last_digest = record_digest(self.descriptor.record_domain, record);
                    }
                }
                TERMINAL => {
                    if let Some(base) = base.as_mut() {
                        base.ended = true;
                    }
                }
                _ => {}
            }
        }
        let Some(mut base) = base else {
            return Err(StreamError::Corruption(
                "the journal's prefix opens no run".to_owned(),
            ));
        };
        base.first_index = at;
        let previous = writer.state.as_ref().and_then(|state| state.base.clone());
        writer.keep_base(base)?;
        // A failure before `BASE` leaves the journal where it was: STATE goes back with it, so
        // the handle reads on as before (after the review); a restart finishes either way.
        let reached = match writer.journal.drop_prefix(at, None) {
            Ok(reached) => reached,
            Err(error) => {
                if writer.journal.first_index() < at {
                    let _ = writer.restore_base(previous);
                }
                return Err(error.into());
            }
        };
        if reached != at {
            return Err(StreamError::Corruption(format!(
                "the journal's prefix was to end at frame {at}, and ends at {reached}"
            )));
        }
        Ok(())
    }
}

/// The run a signed statement opens, read without verifying it: the frames were verified when
/// the stream opened.
fn run_id(envelope: &[u8]) -> Result<[u8; 16], StreamError> {
    Ok(RunStatement::decode(
        permguard_objects::cose::Sign1::decode(envelope)
            .map_err(|error| StreamError::Invalid(error.to_string()))?
            .payload_unverified(),
    )?
    .run_id)
}
