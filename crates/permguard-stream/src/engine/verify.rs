// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The offline check of a stream's directory (WP-5.7c, owner decisions of 2026-10-17): what
//! `streams verify <dir> --keys <file>` runs over a producer's `<resource>/<host>` directory or a
//! consumer's run, copied off a volume, reading it and changing nothing.
//!
//! | Check                     | A finding                                                        |
//! | ------------------------- | ---------------------------------------------------------------- |
//! | each batch file           | a signature, envelope or Merkle root that does not verify        |
//! | each run's batches        | a gap or an overlap between them, or a run they do not name      |
//! | the chain                 | a `previous_head` that is not genesis, the anchor's head or the  |
//! |                           | batch before                                                     |
//! | the anchor                | its checkpoint not verifying, not ending at `through`, not       |
//! |                           | carrying `terminal_head`, or not its last `covering` digest      |
//! | the records               | a record the journal holds at a sealed sequence that is not the  |
//! |                           | batch's                                                          |
//!
//! Records past the last batch are unsealed, and noted; a batch signed by a key the document
//! revoked is noted too, since a retained key's old signatures still verify.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use permguard_core::keys::Jwk;
use permguard_host::storage::Dir;
use permguard_host::storage::format;
use permguard_host::storage::write::read_view;

use super::anchor::{ANCHOR, Anchor, envelope_digest};
use super::batch::{GENESIS_HEAD, KeyView, SealedBatch};
use super::producer::{RECORDS, RUN_OPEN};
use super::{Descriptor, StreamError, decode_group, hex};

/// The keys a stream's batches are verified with: what `keys export` prints for their ring.
#[derive(Debug, Clone, Default)]
pub struct Keys {
    pub keys: Vec<Jwk>,
    pub revoked: BTreeSet<String>,
}

impl Keys {
    /// Reads a key document: `keys export` of the ring `ring` (its published and retained keys,
    /// and the kids it revoked), or a plain JWKS; a document of another ring, or with no key, is
    /// refused.
    pub fn from_document(text: &str, ring: &str) -> Result<Self, String> {
        let document: serde_json::Value =
            serde_json::from_str(text).map_err(|error| format!("not a key document: {error}"))?;
        if let Some(named) = document.get("ring")
            && named.as_str() != Some(ring)
        {
            return Err(format!(
                "the key document is of the ring {named}, and the batches are signed under `{ring}`"
            ));
        }
        let mut keys: Vec<Jwk> = Vec::new();
        for value in document
            .get("keys")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            keys.push(
                serde_json::from_value(value.clone())
                    .map_err(|error| format!("a published key: {error}"))?,
            );
        }
        for value in document
            .get("retained")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            let jwk = value.get("jwk").cloned().unwrap_or_else(|| value.clone());
            keys.push(
                serde_json::from_value(jwk).map_err(|error| format!("a retained key: {error}"))?,
            );
        }
        if keys.is_empty() {
            return Err("the key document holds no key".to_owned());
        }
        let revoked = document
            .get("revoked")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.get("kid").and_then(serde_json::Value::as_str))
            .map(str::to_owned)
            .collect();
        Ok(Self { keys, revoked })
    }
}

/// What the check found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// `producer` or `consumer`.
    pub role: String,
    /// The stream the batches name: plane, type and resource.
    pub stream: String,
    pub runs: u64,
    pub batches: u64,
    pub records: u64,
    /// Alterations: any makes the check fail.
    pub findings: Vec<String>,
    /// What holds and is worth saying: unsealed records, revoked keys, a pre-anchor prefix.
    pub notes: Vec<String>,
}

impl Report {
    /// Whether every check held.
    pub fn sound(&self) -> bool {
        self.findings.is_empty()
    }

    /// The report as text, one line per check and finding.
    pub fn render(&self) -> String {
        let mut lines = vec![format!(
            "{} {}: {} run(s), {} batch(es), {} record(s) checked",
            self.role, self.stream, self.runs, self.batches, self.records
        )];
        lines.extend(self.notes.iter().map(|note| format!("note: {note}")));
        lines.extend(
            self.findings
                .iter()
                .map(|finding| format!("finding: {finding}")),
        );
        lines.push(if self.sound() {
            "verified: every batch, chain, anchor and record holds".to_owned()
        } else {
            format!("NOT verified: {} finding(s)", self.findings.len())
        });
        lines.join("\n")
    }
}

/// What one run's check is given.
struct Run<'a> {
    role: &'static str,
    id: [u8; 16],
    /// The stream the run's statement names, when the journal holds it: every batch and the
    /// anchor must name the same.
    key: Option<KeyView>,
    /// The run's batch directory, absent when it never sealed.
    batches: Option<&'a Dir>,
    /// Where its `ANCHOR` lies.
    anchor_dir: Option<&'a Dir>,
    /// The records its journal holds, by sequence.
    records: &'a BTreeMap<u64, Vec<u8>>,
}

/// One run as the producer's journal holds it: its id, the stream its statement names and its
/// records by sequence.
type JournalRun = ([u8; 16], KeyView, BTreeMap<u64, Vec<u8>>);

/// How far one run's batches reached.
struct Checked {
    sealed: u64,
}

fn unhex16(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32 {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..32)
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect();
    bytes?.try_into().ok()
}

/// The batch files of `dir`, `(first, last, name)`, in order.
fn batch_files(dir: &Dir) -> Result<Vec<(u64, u64, String)>, StreamError> {
    let mut found = Vec::new();
    for name in dir.names()? {
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

fn statement_of(envelope: &[u8]) -> Result<super::run::RunStatement, StreamError> {
    super::run::RunStatement::decode(
        permguard_objects::cose::Sign1::decode(envelope)
            .map_err(|error| StreamError::Invalid(error.to_string()))?
            .payload_unverified(),
    )
}

/// Checks the stream directory `path`, a producer's or a consumer run's, its batches verified
/// under `keys` and the descriptor among `descriptors` they name. An error is a directory or file
/// that cannot be read; anything damaged or altered inside it is a finding (after the review).
pub fn verify_directory(
    path: &Path,
    keys: &Keys,
    descriptors: &[Descriptor],
) -> Result<Report, StreamError> {
    let dir = Dir::open(path)?;
    let subdirs = dir.subdirs()?;
    if !subdirs.iter().any(|name| name == "records") {
        return Err(StreamError::Invalid(format!(
            "{} is neither a producer stream nor a consumer run: it holds no `records`",
            path.display()
        )));
    }
    let batches = if subdirs.iter().any(|name| name == "batches") {
        Some(dir.subdir("batches", false)?)
    } else {
        None
    };
    let mut report = Report::default();
    let (frames, torn) = match permguard_host::storage::journal::read_frames_and_tail(
        &dir.subdir("records", false)?,
    ) {
        Ok(read) => read,
        Err(permguard_host::storage::StorageError::Corruption(detail)) => {
            report.role = "stream".to_owned();
            report
                .findings
                .push(format!("the journal does not read: {detail}"));
            return Ok(report);
        }
        Err(error) => return Err(error.into()),
    };
    if torn {
        report.notes.push(
            "the journal's last segment ends in a torn frame: an append under way, or damage"
                .to_owned(),
        );
    }
    let state_bytes = read_view(&dir, "STATE", format::VIEW)?;
    let producer_state = state_bytes
        .as_ref()
        .and_then(|bytes| super::state::State::decode(bytes).ok());
    let is_producer = producer_state.is_some() || frames.iter().any(|frame| frame.kind == RUN_OPEN);
    if is_producer {
        verify_producer(
            path,
            &dir,
            batches.as_ref(),
            &frames,
            producer_state,
            state_bytes.is_some(),
            keys,
            descriptors,
            &mut report,
        )?;
    } else {
        verify_consumer(
            path,
            &dir,
            batches.as_ref(),
            &frames,
            state_bytes,
            keys,
            descriptors,
            &mut report,
        )?;
    }
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn verify_producer(
    path: &Path,
    dir: &Dir,
    batches: Option<&Dir>,
    frames: &[permguard_host::storage::journal::Frame],
    state: Option<super::state::State>,
    state_held: bool,
    keys: &Keys,
    descriptors: &[Descriptor],
    report: &mut Report,
) -> Result<(), StreamError> {
    report.role = "producer".to_owned();
    if state_held && state.is_none() {
        report.findings.push("its STATE does not decode".to_owned());
    }
    // The runs the journal holds, from STATE's base on, each with the stream its statement names.
    let mut runs: Vec<JournalRun> = Vec::new();
    if let Some(base) = state.as_ref().and_then(|state| state.base.as_ref()) {
        match statement_of(&base.statement) {
            Ok(statement) => runs.push((
                statement.run_id,
                KeyView::of(&statement.key),
                BTreeMap::new(),
            )),
            Err(error) => report
                .findings
                .push(format!("STATE's base names no run: {error}")),
        }
    }
    for frame in frames {
        match frame.kind {
            RUN_OPEN => match statement_of(&frame.payload) {
                Ok(statement) => {
                    runs.push((
                        statement.run_id,
                        KeyView::of(&statement.key),
                        BTreeMap::new(),
                    ));
                }
                Err(error) => {
                    report
                        .findings
                        .push(format!("frame {} opens no run: {error}", frame.index));
                    return Ok(());
                }
            },
            RECORDS => {
                let Some((_, _, records)) = runs.last_mut() else {
                    report
                        .findings
                        .push(format!("frame {} holds records outside a run", frame.index));
                    return Ok(());
                };
                match decode_group(&frame.payload) {
                    Ok((first, group)) => {
                        for (offset, record) in group.into_iter().enumerate() {
                            records.insert(first + offset as u64, record);
                        }
                    }
                    Err(error) => {
                        report
                            .findings
                            .push(format!("frame {} does not decode: {error}", frame.index));
                        return Ok(());
                    }
                }
            }
            _ => {}
        }
    }
    // One stream: every run's, and the directory's producer.
    if let Some((_, key, _)) = runs.first() {
        report.stream = format!("{}/{}/{}", key.plane, key.stream_type, key.resource);
        if runs.iter().any(|(_, other, _)| other != key) {
            report
                .findings
                .push("the journal's runs name more than one stream".to_owned());
        }
        if let Some(name) = path.file_name().and_then(|name| name.to_str())
            && let Some(producer) = unhex16(name)
            && permguard_host::identity::record::uuid_text(&producer) != key.producer_host_id
        {
            report.findings.push(format!(
                "the directory is producer {name}'s, and its runs name {}",
                key.producer_host_id
            ));
        }
    }
    let run_dirs: Vec<String> = match batches {
        Some(batches) => batches.subdirs()?,
        None => Vec::new(),
    };
    let signed = state.as_ref().map(|state| (state.run_id, state.signed_seq));
    for (id, key, records) in &runs {
        let name = hex(id);
        let run_dir = match batches {
            Some(batches) if run_dirs.contains(&name) => Some(batches.subdir(&name, false)?),
            _ => None,
        };
        let checked = check_run(
            &Run {
                role: "producer",
                id: *id,
                key: Some(key.clone()),
                batches: run_dir.as_ref(),
                anchor_dir: run_dir.as_ref(),
                records,
            },
            keys,
            descriptors,
            report,
        )?;
        if let Some((run, signed_seq)) = signed
            && run == *id
            && checked.sealed < signed_seq
        {
            report.findings.push(format!(
                "run {name}: STATE says it was sealed through {signed_seq}, and its batches reach \
                 {}",
                checked.sealed
            ));
        }
        report.runs += 1;
    }
    // A batch directory of a run the journal no longer holds: only a run every batch of which its
    // anchor covers, its frames all gone with the prefix.
    for name in run_dirs {
        let Some(id) = unhex16(&name) else {
            report
                .findings
                .push(format!("`batches/{name}` names no run"));
            continue;
        };
        if runs.iter().any(|(held, _, _)| *held == id) {
            continue;
        }
        let run_dir = batches
            .map(|batches| batches.subdir(&name, false))
            .transpose()?;
        let Some(run_dir) = run_dir else { continue };
        let anchor =
            match read_view(&run_dir, ANCHOR, format::VIEW)?.map(|bytes| Anchor::decode(&bytes)) {
                Some(Ok(anchor)) => Some(anchor),
                Some(Err(error)) => {
                    report
                        .findings
                        .push(format!("run {name}: its anchor does not decode: {error}"));
                    continue;
                }
                None => None,
            };
        let covered = anchor.as_ref().is_some_and(|anchor| {
            batch_files(&run_dir)
                .is_ok_and(|files| files.iter().all(|(_, last, _)| *last <= anchor.through))
        });
        if !covered {
            report.findings.push(format!(
                "run {name}: batches of a run the journal does not hold"
            ));
            continue;
        }
        let empty = BTreeMap::new();
        check_run(
            &Run {
                role: "producer",
                id,
                key: runs.first().map(|(_, key, _)| key.clone()),
                batches: Some(&run_dir),
                anchor_dir: Some(&run_dir),
                records: &empty,
            },
            keys,
            descriptors,
            report,
        )?;
        report.runs += 1;
    }
    let _ = dir;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_consumer(
    path: &Path,
    dir: &Dir,
    batches: Option<&Dir>,
    frames: &[permguard_host::storage::journal::Frame],
    state_bytes: Option<Vec<u8>>,
    keys: &Keys,
    descriptors: &[Descriptor],
    report: &mut Report,
) -> Result<(), StreamError> {
    report.role = "consumer".to_owned();
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let id = unhex16(name).ok_or_else(|| {
        StreamError::Invalid(format!(
            "a consumer run's directory is named by its run, and `{name}` is not one"
        ))
    })?;
    let state = match state_bytes.map(|bytes| super::consumer::ConsumerState::decode(&bytes)) {
        Some(Ok(state)) => Some(state),
        Some(Err(error)) => {
            report
                .findings
                .push(format!("its STATE does not decode: {error}"));
            None
        }
        None => None,
    };
    let mut records = BTreeMap::new();
    for frame in frames {
        if frame.kind == RECORDS {
            match decode_group(&frame.payload) {
                Ok((first, group)) => {
                    for (offset, record) in group.into_iter().enumerate() {
                        records.insert(first + offset as u64, record);
                    }
                }
                Err(error) => {
                    report
                        .findings
                        .push(format!("frame {} does not decode: {error}", frame.index));
                    return Ok(());
                }
            }
        }
    }
    let checked = check_run(
        &Run {
            role: "consumer",
            id,
            key: None,
            batches,
            anchor_dir: Some(dir),
            records: &records,
        },
        keys,
        descriptors,
        report,
    )?;
    report.runs += 1;
    if let Some(state) = state
        && state.acked > checked.sealed
    {
        report.findings.push(format!(
            "its STATE says {} was acknowledged, and its batches reach {}",
            state.acked, checked.sealed
        ));
    }
    Ok(())
}

/// The descriptor a batch names, among `descriptors`.
fn descriptor_of<'a>(
    descriptors: &'a [Descriptor],
    batch: &SealedBatch,
) -> Result<&'a Descriptor, String> {
    let envelope = batch
        .envelope_unverified()
        .map_err(|error| error.to_string())?;
    descriptors
        .iter()
        .find(|descriptor| {
            descriptor.plane == envelope.stream_key.plane
                && descriptor.stream_type == envelope.stream_key.stream_type
                && descriptor.version == envelope.descriptor_version
        })
        .ok_or_else(|| {
            format!(
                "a batch of `{}/{}` version {}, a stream this build does not describe",
                envelope.stream_key.plane,
                envelope.stream_key.stream_type,
                envelope.descriptor_version
            )
        })
}

fn check_run(
    run: &Run<'_>,
    keys: &Keys,
    descriptors: &[Descriptor],
    report: &mut Report,
) -> Result<Checked, StreamError> {
    let run_hex = hex(&run.id);
    let mut stream = run.key.clone();
    let verify = |bytes: &[u8], what: &str, report: &mut Report, stream: &mut Option<KeyView>| {
        let batch = match SealedBatch::decode(bytes) {
            Ok(batch) => batch,
            Err(error) => {
                report
                    .findings
                    .push(format!("run {run_hex}: {what} does not decode: {error}"));
                return None;
            }
        };
        let descriptor = match descriptor_of(descriptors, &batch) {
            Ok(descriptor) => descriptor,
            Err(detail) => {
                report
                    .findings
                    .push(format!("run {run_hex}: {what}: {detail}"));
                return None;
            }
        };
        if let Ok(kid) = batch.kid()
            && keys.revoked.contains(&kid)
        {
            report.notes.push(format!(
                "run {run_hex}: {what} is signed by `{kid}`, revoked since"
            ));
        }
        match batch.verify(&keys.keys, descriptor.batch_typ, descriptor.record_domain) {
            Ok((envelope, records)) => {
                match stream {
                    Some(key) if *key != envelope.stream_key => {
                        report.findings.push(format!(
                            "run {run_hex}: {what} is of another stream, `{}/{}/{}`",
                            envelope.stream_key.plane,
                            envelope.stream_key.stream_type,
                            envelope.stream_key.resource
                        ));
                        return None;
                    }
                    Some(_) => {}
                    None => *stream = Some(envelope.stream_key.clone()),
                }
                if report.stream.is_empty() {
                    report.stream = format!(
                        "{}/{}/{}",
                        envelope.stream_key.plane,
                        envelope.stream_key.stream_type,
                        envelope.stream_key.resource
                    );
                }
                if envelope.run != run_hex {
                    report
                        .findings
                        .push(format!("run {run_hex}: {what} names run {}", envelope.run));
                    return None;
                }
                Some((envelope, records))
            }
            Err(error) => {
                report
                    .findings
                    .push(format!("run {run_hex}: {what} does not verify: {error}"));
                None
            }
        }
    };

    // The anchor, then where the batches start: after it, after a pre-anchor mark, or at 1.
    let anchor = match run.anchor_dir {
        Some(dir) => {
            match read_view(dir, ANCHOR, format::VIEW)?.map(|bytes| Anchor::decode(&bytes)) {
                Some(Ok(anchor)) => Some(anchor),
                Some(Err(error)) => {
                    report.findings.push(format!(
                        "run {run_hex}: its anchor does not decode: {error}"
                    ));
                    return Ok(Checked { sealed: 0 });
                }
                None => None,
            }
        }
        None => None,
    };
    let (mut expected, mut previous) = (1u64, Some(GENESIS_HEAD.to_owned()));
    let mut below = 0u64;
    if let Some(anchor) = &anchor {
        if anchor.run != run.id {
            report.findings.push(format!(
                "run {run_hex}: its anchor names run {}",
                hex(&anchor.run)
            ));
        }
        if let Some(key) = &stream
            && anchor.resource != key.resource
        {
            report.findings.push(format!(
                "run {run_hex}: its anchor is of resource `{}`",
                anchor.resource
            ));
        }
        if let Some((envelope, _)) = verify(
            &anchor.checkpoint,
            "the anchor's checkpoint",
            report,
            &mut stream,
        ) {
            if envelope.last_seq != anchor.through || envelope.head != anchor.terminal_head {
                report.findings.push(format!(
                    "run {run_hex}: the anchor's checkpoint ends at {} with another head than \
                     the anchor's `through` {}",
                    envelope.last_seq, anchor.through
                ));
            }
            if envelope_digest(&envelope).ok().as_ref() != anchor.covering.last() {
                report.findings.push(format!(
                    "run {run_hex}: the anchor's checkpoint is not the last batch it covers"
                ));
            }
        }
        expected = anchor.through + 1;
        below = anchor.through;
        previous = Some(anchor.terminal_head.clone());
    } else if run.role == "producer"
        && let Some(batches) = run.batches
        && let Some(bytes) = read_view(batches, "PRUNED", format::VIEW)?
    {
        // A run the WP-5.4 shipping loop truncated before anchors existed: its mark says where
        // the batches start, and the head below them is not kept.
        let mark = super::codec::Map::read(&bytes, "a pruned mark").and_then(|mut map| map.uint(1));
        match mark {
            Ok(mark) if mark > 0 => {
                report.notes.push(format!(
                    "run {run_hex}: deleted through {mark} before anchors existed; the head below \
                     is not kept"
                ));
                expected = mark + 1;
                below = mark;
                previous = None;
            }
            Ok(_) => {}
            Err(error) => report
                .findings
                .push(format!("run {run_hex}: its pruned mark: {error}")),
        }
    }

    let mut sealed = below;
    let files = match run.batches {
        Some(batches) => batch_files(batches)?,
        None => Vec::new(),
    };
    let first_held = run.records.keys().next().copied();
    let count = files.iter().filter(|(_, last, _)| *last > below).count();
    let mut seen = 0usize;
    for (first, last, name) in files {
        if last <= below {
            // Below the anchor: a file a crash left before its deletion.
            continue;
        }
        seen += 1;
        let Some(batches) = run.batches else { break };
        let bytes = match batches.read(&name) {
            Ok(bytes) => bytes.unwrap_or_default(),
            Err(error @ permguard_host::storage::StorageError::Corruption(_)) => {
                let _ = error;
                report
                    .findings
                    .push(format!("run {run_hex}: batch `{name}` does not read"));
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let Some((envelope, records)) =
            verify(&bytes, &format!("batch `{name}`"), report, &mut stream)
        else {
            continue;
        };
        report.batches += 1;
        if envelope.first_seq != first || envelope.last_seq != last {
            report.findings.push(format!(
                "run {run_hex}: batch `{name}` holds {}-{}",
                envelope.first_seq, envelope.last_seq
            ));
        }
        if envelope.first_seq != expected {
            report.findings.push(format!(
                "run {run_hex}: batch `{name}` starts at {}, and {expected} was next",
                envelope.first_seq
            ));
        }
        if let Some(previous) = &previous
            && &envelope.previous_head != previous
        {
            report.findings.push(format!(
                "run {run_hex}: batch `{name}` does not continue the chain"
            ));
        }
        let last_batch = seen == count;
        for (offset, record) in records.iter().enumerate() {
            let seq = envelope.first_seq + offset as u64;
            report.records += 1;
            match run.records.get(&seq) {
                Some(held) if held != record => report.findings.push(format!(
                    "run {run_hex}: the journal's record {seq} is not the one batch `{name}` signed"
                )),
                Some(_) => {}
                // Held from `first_held` on, every sealed record is in the journal; a consumer's
                // last batch may lack its records, a crash between its file and them.
                None if first_held.is_some_and(|held| seq >= held)
                    || (first_held.is_none() && run.role == "producer" && seq > below) =>
                {
                    if run.role == "consumer" && last_batch {
                        report.notes.push(format!(
                            "run {run_hex}: batch `{name}`'s record {seq} is not in the journal yet"
                        ));
                    } else {
                        report.findings.push(format!(
                            "run {run_hex}: the journal lacks record {seq}, which batch `{name}` \
                             signed"
                        ));
                    }
                }
                None => {}
            }
        }
        previous = Some(envelope.head.clone());
        expected = envelope.last_seq + 1;
        sealed = envelope.last_seq;
    }
    let unsealed = run.records.keys().filter(|seq| **seq > sealed).count();
    if unsealed > 0 {
        if run.role == "consumer" {
            report.findings.push(format!(
                "run {run_hex}: {unsealed} record(s) no batch signed"
            ));
        } else {
            report.notes.push(format!(
                "run {run_hex}: {unsealed} record(s) past the last batch, not yet sealed"
            ));
        }
    }
    Ok(Checked { sealed })
}
