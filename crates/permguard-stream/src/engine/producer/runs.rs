// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a Plane reads back of a stream it produces (WP-6.2a, owner decision of 2026-10-18): the
//! runs of a resource and a run's records by sequence, what a Plane deciding against its own
//! history replays and scans.
//!
//! A read starts at the record group holding its first sequence rather than at the journal's
//! first frame: each physical stream remembers, as far as a read has looked, where every run's
//! groups sit, so a read opens the segment that holds them and not the ones before.

use std::collections::BTreeMap;

use super::super::anchor::{Anchor, Gap, Page, anchor_in};
use super::super::run::RunStatement;
use super::super::{RecordCodec, StreamError, hex};
use super::{Physical, Producer, RECORDS, RUN_OPEN, Writer, decode_group};
use permguard_core::authz::Resource;

/// Where each run's record groups sit in the journal, as far as a read has looked.
#[derive(Debug, Default)]
pub(super) struct Groups {
    /// The first journal frame not looked at yet.
    through: u64,
    /// The run the frames looked at so far end in.
    current: Option<[u8; 16]>,
    /// Each run's record groups: `(first sequence, frame index)`, in journal order.
    runs: BTreeMap<[u8; 16], Vec<(u64, u64)>>,
}

impl Groups {
    /// Looks at the frames written since the last look; what a deleted prefix took is forgotten.
    fn refresh(&mut self, writer: &Writer) -> Result<(), StreamError> {
        let first = writer.journal.first_index();
        if self.through <= first {
            // Nothing looked at survives, or nothing was looked at: start where the journal does,
            // in the run STATE's base names when a prefix went.
            self.through = first;
            self.runs.clear();
            self.current = match writer.base() {
                Some(base) => Some(statement(&base.statement)?.run_id),
                None => None,
            };
        } else {
            for groups in self.runs.values_mut() {
                groups.retain(|(_, index)| *index >= first);
            }
        }
        for frame in writer.journal.frames_from(self.through)? {
            match frame.kind {
                RUN_OPEN => self.current = Some(statement(&frame.payload)?.run_id),
                RECORDS => {
                    let (first_seq, _) = decode_group(&frame.payload)?;
                    if let Some(run) = self.current {
                        self.runs
                            .entry(run)
                            .or_default()
                            .push((first_seq, frame.index));
                    }
                }
                _ => {}
            }
            self.through = frame.index + 1;
        }
        Ok(())
    }
}

/// The run statement a RUN_OPEN frame or STATE's base carries, read without verifying it: the
/// stream's own journal, which this producer wrote.
fn statement(envelope: &[u8]) -> Result<RunStatement, StreamError> {
    RunStatement::decode(
        permguard_objects::cose::Sign1::decode(envelope)
            .map_err(|error| StreamError::Invalid(error.to_string()))?
            .payload_unverified(),
    )
}

/// The anchor of `run`'s deleted prefix, read without creating its directory.
fn anchor_of(writer: &Writer, run: &[u8; 16]) -> Result<Option<Anchor>, StreamError> {
    if !writer.dir.subdirs()?.iter().any(|name| name == "batches") {
        return Ok(None);
    }
    let batches = writer.dir.subdir("batches", false)?;
    let name = hex(run);
    if !batches.subdirs()?.contains(&name) {
        return Ok(None);
    }
    anchor_in(&batches.subdir(&name, false)?)
}

impl<C: RecordCodec> Producer<C> {
    /// The runs of `resource`'s stream, in the order its journal opened them, each with its low
    /// watermark; none for a stream this producer never opened.
    pub fn produced_runs(
        &self,
        resource: &Resource,
    ) -> Result<Vec<permguard_host::composition::ProducedRun>, StreamError> {
        let Some(physical) = self.held(&resource.to_string())? else {
            return Ok(Vec::new());
        };
        let runs = Self::journal_runs(&physical)?;
        let writer = physical.writer();
        runs.into_iter()
            .map(|(run, _, last_seq, ended)| {
                Ok(permguard_host::composition::ProducedRun {
                    run,
                    last_seq,
                    low_watermark: anchor_of(&writer, &run)?
                        .map_or(1, |anchor| anchor.low_watermark),
                    ended,
                })
            })
            .collect()
    }

    /// The records of `run` in `resource`'s stream from `from_seq`, at most `limit`, as their
    /// bytes; a read starting below what the run deleted answers from its low watermark with the
    /// gap, never as complete.
    pub fn produced_records(
        &self,
        resource: &Resource,
        run: &[u8; 16],
        from_seq: u64,
        limit: usize,
    ) -> Result<Page<Vec<u8>>, StreamError> {
        let empty = |gap| Page {
            records: Vec::new(),
            gap,
        };
        let Some(physical) = self.held(&resource.to_string())? else {
            return Ok(empty(None));
        };
        Self::run_page(&physical, run, from_seq, limit)
    }

    /// [`Self::produced_records`] of `physical`.
    fn run_page(
        physical: &Physical,
        run: &[u8; 16],
        from_seq: u64,
        limit: usize,
    ) -> Result<Page<Vec<u8>>, StreamError> {
        let writer = physical.writer();
        let mut groups = physical
            .groups
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        groups.refresh(&writer)?;
        let anchor = anchor_of(&writer, run)?;
        let low_watermark = anchor.as_ref().map_or(1, |anchor| anchor.low_watermark);
        let gap = match anchor {
            Some(anchor) if from_seq < anchor.low_watermark => Some(Gap {
                low_watermark: anchor.low_watermark,
                anchor,
            }),
            _ => None,
        };
        let from_seq = from_seq.max(low_watermark).max(1);
        let Some(held) = groups.runs.get(run).filter(|held| !held.is_empty()) else {
            return Ok(Page {
                records: Vec::new(),
                gap,
            });
        };
        // The last group starting at or before the first sequence asked for.
        let at = held.partition_point(|(first, _)| *first <= from_seq);
        let start = held[at.saturating_sub(1)].1;
        let last = held[held.len() - 1].1;
        let mine: std::collections::BTreeSet<u64> = held.iter().map(|(_, index)| *index).collect();
        let mut found = Vec::new();
        for frame in writer.journal.frames_from(start)? {
            if frame.index > last || found.len() >= limit {
                break;
            }
            if frame.kind != RECORDS || !mine.contains(&frame.index) {
                continue;
            }
            let (first, records) = decode_group(&frame.payload)?;
            for (offset, bytes) in records.into_iter().enumerate() {
                let seq = first + offset as u64;
                if seq >= from_seq && found.len() < limit {
                    found.push((seq, bytes));
                }
            }
        }
        Ok(Page {
            records: found,
            gap,
        })
    }
}
