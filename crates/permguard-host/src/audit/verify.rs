// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `audit verify --directory <dir> [--keys <file>] [--checkpoint <file>]` over the Host's trails
//! (WP-3.7, owner decisions of 2026-10-11).
//!
//! | Check       | What fails                                                                        |
//! | ----------- | --------------------------------------------------------------------------------- |
//! | chain       | a record out of sequence, one that does not chain to the record before it         |
//! | start       | a first record kept that neither starts the chain nor follows an anchored seal     |
//! | checkpoints | a signature by no key of the set, a broken `previous_checkpoint` chain, a range or |
//! |             | head that is not the records', a sealed day that changed, a checkpoint signed by  |
//! |             | a revoked key that no later checkpoint by a key not revoked chains over           |
//! | anchor      | a checkpoint it names that the trail lacks or that is not the seal of `through`    |
//! | coverage    | an ended day left unsealed, a sealed day whose file is gone                       |
//! | held        | a checkpoint kept outside the volume that the trail no longer leads to and from    |
//!
//! The keys are the `host.operations` public keys kept apart from the volume (`--keys`, the
//! output of `keys export`); without them the keys the volume publishes are used, and the report
//! says it is not independent. A checkpoint signed by a key revoked since stands, as a warning,
//! when a later checkpoint by a key that is not revoked chains over it (owner decision of
//! 2026-10-11, after the review). Every day before a trail's last day file has ended, and the
//! Host seals it before it writes the next one, so one left unsealed fails; only the last day is
//! reported as unsealed. Nothing here writes to the volume; a witness's co-signature is reported
//! present or absent, never verified, since no witness key is kept here.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use permguard_objects::digest::Digest;

use crate::storage::{Dir, StorageError};

use super::checkpoint::{
    Anchor, Checkpoint, Keys, envelope_digest, no_checkpoint, ordered, parse_name, read_unverified,
    witness_name,
};
use super::record::{TrailMeta, genesis};
use super::trail::{self, CHECKPOINTS, META};
use super::{Class, DIRECTORY, TRAILS};

/// The most problems, or warnings, one trail's report lists; the rest are counted.
const MAX_PROBLEMS: usize = 20;
/// The most checkpoints without a co-signature a report names.
const MAX_UNWITNESSED: usize = 10;

/// What verifying one trail found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrailReport {
    pub class: String,
    pub resource: String,
    pub records: u64,
    pub first_seq: Option<u64>,
    pub last_seq: Option<u64>,
    pub checkpoints: usize,
    /// How many checkpoints carry a witness's co-signature, present and not verified.
    pub witnessed: usize,
    /// The checkpoints without one, when a witness co-signed any.
    pub unwitnessed: Vec<String>,
    /// The newest day a seal closed.
    pub sealed_through: Option<String>,
    /// The trail's last day, when no seal covers it yet.
    pub unsealed: Vec<String>,
    pub anchor: Option<Anchor>,
    /// The checkpoint kept outside the volume the trail was verified from, and up to which
    /// record.
    pub held: Option<String>,
    pub warnings: Vec<String>,
    pub problems: Vec<String>,
    /// Problems beyond [`MAX_PROBLEMS`], counted.
    pub more_problems: usize,
}

impl TrailReport {
    fn problem(&mut self, problem: impl Into<String>) {
        if self.problems.len() < MAX_PROBLEMS {
            self.problems.push(problem.into());
        } else {
            self.more_problems += 1;
        }
    }

    fn warning(&mut self, warning: impl Into<String>) {
        if self.warnings.len() < MAX_PROBLEMS {
            self.warnings.push(warning.into());
        }
    }
}

/// What verifying every trail found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Whether the keys came from outside the volume.
    pub independent: bool,
    pub trails: Vec<TrailReport>,
}

impl Report {
    /// Whether every trail verified.
    pub fn sound(&self) -> bool {
        self.trails.iter().all(|trail| trail.problems.is_empty())
    }

    /// The report as `audit verify` prints it.
    pub fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "keys: {}",
            if self.independent {
                "independent (--keys)"
            } else {
                "the volume's own: not independent; pass --keys with the `host.operations` keys \
                 kept apart"
            }
        );
        for trail in &self.trails {
            let range = match (trail.first_seq, trail.last_seq) {
                (Some(first), Some(last)) => format!("records {first}..={last}"),
                _ => "no records".to_owned(),
            };
            let _ = writeln!(
                out,
                "{}:{} {}: {range} ({}), {} checkpoints, sealed through {}{}{}{}",
                trail.class,
                trail.resource,
                if trail.problems.is_empty() {
                    "ok"
                } else {
                    "FAILED"
                },
                trail.records,
                trail.checkpoints,
                trail.sealed_through.as_deref().unwrap_or("nothing"),
                trail
                    .anchor
                    .as_ref()
                    .map(|anchor| format!(
                        ", records below {} deleted through {}",
                        anchor.low_watermark, anchor.through
                    ))
                    .unwrap_or_default(),
                if trail.unsealed.is_empty() {
                    String::new()
                } else {
                    format!(", unsealed: {}", trail.unsealed.join(" "))
                },
                trail
                    .held
                    .as_ref()
                    .map(|held| format!(", verified from the checkpoint held: {held}"))
                    .unwrap_or_default()
            );
            if trail.witnessed > 0 {
                let _ = writeln!(
                    out,
                    "  witness: {} of {} checkpoints co-signed (present, not verified){}",
                    trail.witnessed,
                    trail.checkpoints,
                    if trail.unwitnessed.is_empty() {
                        String::new()
                    } else {
                        format!("; not co-signed: {}", trail.unwitnessed.join(" "))
                    }
                );
            }
            for warning in &trail.warnings {
                let _ = writeln!(out, "  ! {warning}");
            }
            for problem in &trail.problems {
                let _ = writeln!(out, "  - {problem}");
            }
            if trail.more_problems > 0 {
                let _ = writeln!(out, "  - and {} more", trail.more_problems);
            }
        }
        let failed = self
            .trails
            .iter()
            .filter(|trail| !trail.problems.is_empty())
            .count();
        let _ = write!(
            out,
            "{} trails verified, {failed} failed",
            self.trails.len()
        );
        out
    }
}

/// Verifies the trails below `directory`, a Host volume or its `host/audit/trails`, with the
/// key document at `keys` or, without it, the volume's `host.operations` keys; the trail the
/// checkpoint envelope at `held` names is verified from it as well. A directory holding no
/// trail is refused.
pub fn verify_directory(
    directory: &Path,
    keys: Option<&Path>,
    held: Option<&Path>,
) -> Result<Report, String> {
    let volume_trails = directory.join("host").join(DIRECTORY).join(TRAILS);
    let (trails, host) = if volume_trails.is_dir() {
        (volume_trails, directory.join("host"))
    } else {
        let host = directory
            .parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        (directory.to_path_buf(), host)
    };
    let (keys, independent) = match keys {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|error| format!("reading {}: {error}", path.display()))?;
            (Keys::from_document(&text)?, true)
        }
        None => {
            let ring = host
                .join(crate::keys::ring::DIRECTORY)
                .join(crate::keys::ring::HOST_OPERATIONS);
            let text = crate::keys::ring::export(&ring).map_err(|error| {
                format!(
                    "the volume publishes no `host.operations` keys ({error}); pass --keys with \
                     the keys kept apart"
                )
            })?;
            (Keys::from_document(&text)?, false)
        }
    };
    let dir = Dir::open(&trails).map_err(|error| error.to_string())?;
    let mut reports = verify_trails(&dir, &keys).map_err(|error| error.to_string())?;
    if reports.is_empty() {
        return Err(format!(
            "{} holds no audit trail: name a Host volume or its `host/audit/trails`",
            directory.display()
        ));
    }
    if let Some(path) = held {
        let envelope =
            std::fs::read(path).map_err(|error| format!("reading {}: {error}", path.display()))?;
        let checkpoint = read_unverified(&envelope)
            .map_err(|error| format!("{} is not a checkpoint: {error}", path.display()))?;
        let (class, resource) = checkpoint
            .trail
            .split_once(':')
            .ok_or_else(|| format!("the checkpoint held names the trail `{}`", checkpoint.trail))?;
        let report = reports
            .iter_mut()
            .find(|report| report.class == class && report.resource == resource)
            .ok_or_else(|| {
                format!(
                    "the checkpoint held names the trail `{}`, which {} does not hold",
                    checkpoint.trail,
                    directory.display()
                )
            })?;
        let trail_dir = dir
            .subdir(class, false)
            .and_then(|class_dir| class_dir.subdir(&trail::resource_digest(resource), false))
            .map_err(|error| error.to_string())?;
        match verify_from(&trail_dir, &envelope) {
            Ok(last) => {
                report.held = Some(format!(
                    "{} up to record {}, chained to record {last}",
                    checkpoint.period, checkpoint.last_seq
                ));
            }
            Err(error) => report.problem(format!("from the checkpoint held: {error}")),
        }
    }
    Ok(Report {
        independent,
        trails: reports,
    })
}

/// Verifies every trail below `trails`.
pub fn verify_trails(trails: &Dir, keys: &Keys) -> Result<Vec<TrailReport>, StorageError> {
    let mut reports = Vec::new();
    let mut classes = trails.subdirs()?;
    classes.sort();
    for class_name in classes {
        let Some(class) = Class::parse(&class_name) else {
            reports.push(TrailReport {
                class: class_name.clone(),
                problems: vec![format!("`{class_name}` is not an audit class")],
                ..TrailReport::default()
            });
            continue;
        };
        let class_dir = trails.subdir(&class_name, false)?;
        let mut digests = class_dir.subdirs()?;
        digests.sort();
        for digest in digests {
            let dir = class_dir.subdir(&digest, false)?;
            reports.push(verify_trail(&dir, class, &digest, keys));
        }
    }
    Ok(reports)
}

/// Verifies the trail in `dir`, of `class`, kept under the resource digest `digest`.
pub fn verify_trail(dir: &Dir, class: Class, digest: &str, keys: &Keys) -> TrailReport {
    let mut report = TrailReport {
        class: class.as_str().to_owned(),
        ..TrailReport::default()
    };
    if let Err(problem) = check(dir, class, digest, keys, &mut report) {
        report.problem(problem);
    }
    report
}

/// One checkpoint whose signature verified.
struct Verified {
    file: String,
    checkpoint: Checkpoint,
    digest: Digest,
    kid: String,
    revoked: bool,
}

fn check(
    dir: &Dir,
    class: Class,
    digest: &str,
    keys: &Keys,
    report: &mut TrailReport,
) -> Result<(), String> {
    let storage = |error: StorageError| error.to_string();
    let meta = dir
        .read(META)
        .map_err(storage)?
        .ok_or_else(|| format!("{} holds no {META}", dir.path().display()))?;
    let meta = TrailMeta::decode(&meta).map_err(|error| format!("{META}: {error}"))?;
    report.resource = meta.resource.clone();
    if meta.class != class.as_str() {
        report.problem(format!("{META} names the class `{}`", meta.class));
    }
    if trail::resource_digest(&meta.resource) != digest {
        report.problem(format!(
            "{META} names a resource that is not kept under `{digest}`"
        ));
    }
    let name = format!("{}:{}", class.as_str(), meta.resource);

    // The checkpoints, in the order they were sealed, each chained to the one before.
    let held = match dir.subdir(CHECKPOINTS, false) {
        Ok(held) => Some(held),
        Err(StorageError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            None
        }
        Err(error) => return Err(error.to_string()),
    };
    let names: BTreeSet<String> = match &held {
        Some(held) => held.names().map_err(storage)?.into_iter().collect(),
        None => BTreeSet::new(),
    };
    let mut verified: Vec<Verified> = Vec::new();
    let mut previous = no_checkpoint();
    for file in ordered(names.iter().cloned()) {
        let Some(held) = &held else { break };
        let envelope = held.read(&file).map_err(storage)?.unwrap_or_default();
        let signed = match keys.verify(&envelope) {
            Ok(signed) => signed,
            Err(error) => {
                report.problem(format!(
                    "checkpoint {file}: {error}; the checkpoints after it are not checked"
                ));
                break;
            }
        };
        let checkpoint = signed.checkpoint;
        let Some((period, on_demand)) = parse_name(&file) else {
            continue;
        };
        if checkpoint.trail != name {
            report.problem(format!(
                "checkpoint {file} names the trail `{}`",
                checkpoint.trail
            ));
        }
        if checkpoint.period != period || on_demand.is_some_and(|seq| seq != checkpoint.last_seq) {
            report.problem(format!("checkpoint {file} is not the one its name says"));
        }
        if checkpoint.previous_checkpoint != previous {
            report.problem(format!(
                "checkpoint {file} does not chain to the checkpoint before it"
            ));
        }
        if verified
            .last()
            .is_some_and(|before| checkpoint.last_seq < before.checkpoint.last_seq)
        {
            report.problem(format!(
                "checkpoint {file} covers less than the checkpoint before it"
            ));
        }
        previous = envelope_digest(&envelope);
        if names.contains(&witness_name(&file)) {
            report.witnessed += 1;
        } else {
            report.unwitnessed.push(file.clone());
        }
        if on_demand.is_none() {
            report.sealed_through = Some(period);
        }
        verified.push(Verified {
            file,
            checkpoint,
            digest: previous.clone(),
            kid: signed.kid,
            revoked: signed.revoked,
        });
    }
    report.checkpoints = verified.len();
    if report.witnessed == 0 {
        report.unwitnessed.clear();
    } else if report.unwitnessed.len() > MAX_UNWITNESSED {
        let more = report.unwitnessed.len() - MAX_UNWITNESSED;
        report.unwitnessed.truncate(MAX_UNWITNESSED);
        report.unwitnessed.push(format!("and {more} more"));
    }

    // A signature by a key revoked since stands where a later one by a key that is not revoked
    // chains over it.
    for (index, entry) in verified.iter().enumerate() {
        if !entry.revoked {
            continue;
        }
        if verified[index + 1..].iter().any(|later| !later.revoked) {
            report.warning(format!(
                "checkpoint {} is signed by `{}`, revoked since; a later checkpoint by a key \
                 that is not revoked chains over it",
                entry.file, entry.kid
            ));
        } else {
            report.problem(format!(
                "checkpoint {} is signed by `{}`, revoked since, and no checkpoint by a key \
                 that is not revoked chains over it",
                entry.file, entry.kid
            ));
        }
    }

    // The anchor names the seal of the last day retention deleted.
    let anchor = trail::anchor(dir).map_err(storage)?;
    if let Some(anchor) = &anchor {
        if anchor.trail != name {
            report.problem(format!("the anchor names the trail `{}`", anchor.trail));
        }
        match verified
            .iter()
            .find(|entry| entry.digest == anchor.checkpoint)
        {
            None => report.problem("the anchor names a checkpoint the trail does not hold"),
            Some(entry) => {
                if parse_name(&entry.file).is_none_or(|(_, seq)| seq.is_some())
                    || entry.checkpoint.period != anchor.through
                {
                    report.problem(format!(
                        "the anchor names {}, which is not the seal of {}",
                        entry.file, anchor.through
                    ));
                }
                if entry.checkpoint.last_seq + 1 != anchor.low_watermark {
                    report.problem(format!(
                        "the anchor keeps records from {}, and its seal ends at {}",
                        anchor.low_watermark, entry.checkpoint.last_seq
                    ));
                }
            }
        }
    }
    report.anchor = anchor.clone();

    // The records: one chain, starting where the anchor or the chain's genesis says.
    let wanted: BTreeSet<u64> = verified
        .iter()
        .map(|entry| entry.checkpoint.last_seq)
        .collect();
    let mut heads: BTreeMap<u64, Digest> = BTreeMap::new();
    let mut ranges: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut expected: Option<(u64, Digest)> = None;
    let mut foreign = false;
    for day in trail::days(dir).map_err(storage)? {
        let records = trail::read_day(dir, &day).map_err(storage)?;
        for record in records {
            if record.trail != name && !foreign {
                foreign = true;
                report.problem(format!(
                    "record {} names the trail `{}`",
                    record.seq, record.trail
                ));
            }
            match &expected {
                None if record.seq == 0 => {
                    if record.previous != genesis() {
                        report.problem("the first record does not start the chain");
                    }
                }
                None => {
                    match &anchor {
                        None => report.problem(format!(
                            "records 0..{} are missing and no anchor states their deletion",
                            record.seq
                        )),
                        Some(anchor) if anchor.low_watermark < record.seq => {
                            report.problem(format!(
                                "records {}..{} are missing below the first record kept",
                                anchor.low_watermark, record.seq
                            ));
                        }
                        Some(_) => {}
                    }
                    match verified
                        .iter()
                        .rev()
                        .find(|entry| entry.checkpoint.last_seq + 1 == record.seq)
                    {
                        Some(entry) if entry.checkpoint.head_digest == record.previous => {}
                        Some(entry) => report.problem(format!(
                            "the first record kept, {}, does not chain to {}",
                            record.seq, entry.file
                        )),
                        None => report.problem(format!(
                            "no checkpoint seals the record before the first one kept, {}",
                            record.seq
                        )),
                    }
                }
                Some((seq, previous)) => {
                    if record.seq != *seq {
                        report.problem(format!(
                            "record {} follows record {}",
                            record.seq,
                            seq.saturating_sub(1)
                        ));
                    }
                    if record.previous != *previous {
                        report.problem(format!(
                            "record {} does not chain to the record before it",
                            record.seq
                        ));
                    }
                }
            }
            let digest = record.digest().map_err(|error| error.to_string())?;
            if wanted.contains(&record.seq) {
                heads.insert(record.seq, digest.clone());
            }
            ranges
                .entry(trail::period_of(&day))
                .and_modify(|range| range.1 = record.seq)
                .or_insert((record.seq, record.seq));
            report.first_seq.get_or_insert(record.seq);
            report.last_seq = Some(record.seq);
            report.records += 1;
            expected = Some((record.seq + 1, digest));
        }
    }

    // Each checkpoint against the records it covers.
    for entry in &verified {
        let (file, checkpoint) = (&entry.file, &entry.checkpoint);
        let seal = parse_name(file).is_some_and(|(_, seq)| seq.is_none());
        match ranges.get(&checkpoint.period) {
            None if anchor
                .as_ref()
                .is_some_and(|anchor| checkpoint.period <= anchor.through) => {}
            None => report.problem(format!(
                "checkpoint {file} covers records of {}, whose day file is gone",
                checkpoint.period
            )),
            Some((first, last)) => {
                if checkpoint.first_seq != *first {
                    report.problem(format!(
                        "checkpoint {file} starts at record {}, the day at {first}",
                        checkpoint.first_seq
                    ));
                }
                if checkpoint.last_seq > *last {
                    report.problem(format!(
                        "checkpoint {file} covers records up to {}, and the day ends at {last}",
                        checkpoint.last_seq
                    ));
                } else if heads.get(&checkpoint.last_seq) != Some(&checkpoint.head_digest) {
                    report.problem(format!(
                        "record {} is not the one checkpoint {file} sealed",
                        checkpoint.last_seq
                    ));
                }
                if seal && checkpoint.last_seq < *last {
                    report.problem(format!(
                        "the day {} holds records after its seal",
                        checkpoint.period
                    ));
                }
            }
        }
    }

    // Coverage: every day before the last one ended, and the Host sealed it before it wrote the
    // next one.
    let sealed_days: BTreeSet<&str> = verified
        .iter()
        .filter(|entry| parse_name(&entry.file).is_some_and(|(_, seq)| seq.is_none()))
        .map(|entry| entry.checkpoint.period.as_str())
        .collect();
    let last_day = ranges.keys().next_back().cloned();
    for period in ranges.keys() {
        if sealed_days.contains(period.as_str()) {
            continue;
        }
        if Some(period) == last_day.as_ref() {
            report.unsealed.push(period.clone());
        } else {
            report.problem(format!(
                "the day {period} ended and is not sealed: its seal is gone or was never written"
            ));
        }
    }
    Ok(())
}

/// Verifies the trail in `dir` from a checkpoint envelope `held` kept outside the volume. The
/// trail's checkpoints still hold it, every checkpoint before it chains back from it to the
/// first and every checkpoint after it chains on to the newest; the records kept form one chain,
/// starting at the genesis or at an anchored seal, and each record a checkpoint of that chain
/// sealed is the one it sealed. Answers the newest sequence verified. A rewritten history, a
/// prefix below the held head included, is found without trusting anything the volume holds
/// now, its keys included.
pub fn verify_from(dir: &Dir, held: &[u8]) -> Result<u64, String> {
    let storage = |error: StorageError| error.to_string();
    let start = read_unverified(held).map_err(|error| error.to_string())?;
    let held_digest = envelope_digest(held);
    let checkpoints = dir.subdir(CHECKPOINTS, false).map_err(storage)?;
    let mut chain = Vec::new();
    for name in ordered(checkpoints.names().map_err(storage)?) {
        let envelope = checkpoints
            .read(&name)
            .map_err(storage)?
            .unwrap_or_default();
        let checkpoint = read_unverified(&envelope)
            .map_err(|error| format!("checkpoint {name} does not read: {error}"))?;
        chain.push((checkpoint, envelope_digest(&envelope)));
    }
    let position = chain
        .iter()
        .position(|(_, digest)| *digest == held_digest)
        .ok_or_else(|| {
            "the trail no longer holds the checkpoint held: its history was rewritten".to_owned()
        })?;
    let mut previous = no_checkpoint();
    for (index, (checkpoint, digest)) in chain.iter().enumerate() {
        if checkpoint.previous_checkpoint != previous {
            return Err(if index <= position {
                format!(
                    "the checkpoint of {} before the one held was rewritten",
                    checkpoint.period
                )
            } else {
                format!(
                    "the checkpoint of {} does not chain to the one before it",
                    checkpoint.period
                )
            });
        }
        previous = digest.clone();
    }
    let mut heads: BTreeMap<u64, Digest> = BTreeMap::new();
    for (checkpoint, _) in &chain {
        if let Some(head) = heads.insert(checkpoint.last_seq, checkpoint.head_digest.clone())
            && head != checkpoint.head_digest
        {
            return Err(format!(
                "two checkpoints seal different records as record {}",
                checkpoint.last_seq
            ));
        }
    }
    let newest = chain
        .last()
        .map_or_else(|| start.clone(), |(checkpoint, _)| checkpoint.clone());
    let anchor = trail::anchor(dir).map_err(storage)?;
    let mut expected: Option<(u64, Digest)> = None;
    let mut first_kept = None;
    let mut seen_start = false;
    let mut last = None;
    for day in trail::days(dir).map_err(storage)? {
        for record in trail::read_day(dir, &day).map_err(storage)? {
            match &expected {
                None if record.seq == 0 => {
                    if record.previous != genesis() {
                        return Err("the first record does not start the chain".to_owned());
                    }
                }
                None => {
                    // Records below went with retention: the first one kept chains to the seal
                    // the anchor names, through the checkpoints the held one authenticates.
                    let anchored = anchor
                        .as_ref()
                        .is_some_and(|anchor| record.seq <= anchor.low_watermark);
                    let chained = heads
                        .get(&(record.seq - 1))
                        .is_some_and(|head| *head == record.previous);
                    if !anchored || !chained {
                        return Err(format!(
                            "records below {} are missing and no anchored seal accounts for them",
                            record.seq
                        ));
                    }
                }
                Some((seq, previous)) => {
                    if record.seq != *seq || record.previous != *previous {
                        return Err(format!(
                            "record {} does not follow the record before it: the history was \
                             rewritten",
                            record.seq
                        ));
                    }
                }
            }
            let digest = record.digest().map_err(|error| error.to_string())?;
            if let Some(head) = heads.get(&record.seq)
                && *head != digest
            {
                return Err(format!(
                    "record {} is not the one its checkpoint sealed: the history was rewritten",
                    record.seq
                ));
            }
            first_kept.get_or_insert(record.seq);
            seen_start |= record.seq == start.last_seq;
            expected = Some((record.seq + 1, digest));
            last = Some(record.seq);
        }
    }
    let last = last.ok_or_else(|| "the trail holds no record".to_owned())?;
    if !seen_start && first_kept.is_none_or(|first| start.last_seq >= first) {
        return Err(format!(
            "record {} the checkpoint held sealed is missing",
            start.last_seq
        ));
    }
    if last < newest.last_seq {
        return Err(format!(
            "the records end at {last}, and the newest checkpoint covers up to {}",
            newest.last_seq
        ));
    }
    Ok(last)
}
