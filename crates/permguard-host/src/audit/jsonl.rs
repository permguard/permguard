// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The daily JSON-lines audit chain and its seals, as the deleted file sink wrote them (WP-3.8,
//! owner decisions of 2026-10-11): read for verification through every release of iteration 01,
//! and migrated byte for byte into the Host through the WP-1.9 framework.
//!
//! | Layout `audit-legacy` | Where                                                | What                         |
//! | --------------------- | ---------------------------------------------------- | ---------------------------- |
//! | version 1             | the legacy directory as it is (`audit.directory`)    | `audit-YYYY-MM-DD.jsonl` and |
//! |                       |                                                      | `audit-YYYY-MM-DD.seal`      |
//! | version 2             | `host/audit/legacy/`                                 | the same files, unchanged    |
//!
//! No record is converted: the records written since WP-3.5 are in the Host trails, and evidence
//! is never rewritten or re-signed. A file of the legacy directory that is not a day or a seal
//! stops the migration, since `migrate finalize` removes the old directory whole.
//!
//! | Format | What the digest or the signature covers                                              |
//! | ------ | ------------------------------------------------------------------------------------ |
//! | record | SHA-256 over the JSON of its `body`, fields in the writer's order, absent ones left out |
//! | seal   | the signature, by a `host.operations` key named by its bare thumbprint, over the JSON |
//! |        | of its `body`                                                                        |
//!
//! [`verify`] checks the digests, the chain and the sequence across days, each seal's head and
//! count, and, with keys, each seal's signature: a key the set lacks or a wrong signature fails, an
//! unsigned seal is a warning, a seal by a key revoked since stands only where a later seal by a
//! key that is not revoked covers it. A trail whose oldest days the old sink removed for retention
//! opens at the first record kept, the absent prefix stated as a warning; a gap in the middle fails
//! (owner decisions of 2026-10-11).

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use permguard_core::assurance::AssuranceProfile;
use permguard_core::time::{self as civil, Date};

use super::checkpoint::Keys;
use crate::storage::migrate::{Built, Layout, Preflight, Reads};
use crate::storage::volume::Volume;
use crate::storage::write::publish_immutable;
use crate::storage::{Dir, Result, StorageError};

/// The layout subsystem of the legacy chain.
pub const SUBSYSTEM: &str = "audit-legacy";
/// The layout version of the legacy directory, as it is.
pub const SOURCE_VERSION: u16 = 1;
/// The layout version of `host/audit/legacy/`.
pub const TARGET_VERSION: u16 = 2;
/// The directory below `host/audit/` the migrated chain lives in.
pub const DIRECTORY: &str = "legacy";

/// What a file of records is called, either side of the date.
const PREFIX: &str = "audit-";
const SUFFIX: &str = ".jsonl";
/// What a seal is called, beside the day it closes.
const SEAL_SUFFIX: &str = ".seal";
/// The most bytes one day file may take: refused before it is read.
pub const MAX_DAY_BYTES: u64 = 64 * 1024 * 1024;
/// The most bytes one seal may take: refused before it is read.
pub const MAX_SEAL_BYTES: u64 = 64 * 1024;
/// The digest the first record of the chain names as its predecessor.
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The layout the legacy chain is declared under, and the versions this build reads: version 1
/// only to migrate it.
pub fn layouts() -> Vec<(&'static str, Reads)> {
    vec![(SUBSYSTEM, Reads::from(SOURCE_VERSION, TARGET_VERSION))]
}

/// Where the chain lives once migrated, relative to the volume root.
pub fn target() -> String {
    format!(
        "{}/{}/{DIRECTORY}",
        crate::storage::volume::HOST,
        super::DIRECTORY
    )
}

/// Everything a record says, and the only thing its digest covers: the writer's fields in the
/// writer's order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Body {
    pub seq: u64,
    pub at: String,
    pub prev: String,
    pub action: String,
    pub subject: String,
    pub subject_kind: String,
    pub subject_sensitivity: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub continuity_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub continuity_position: Option<u64>,
    pub service: String,
    pub version: String,
}

/// One line of a day file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub body: Body,
    /// SHA-256 of the JSON of `body`, lowercase hex.
    pub digest: String,
}

impl Record {
    /// The digest `body` has.
    pub fn expected_digest(body: &Body) -> std::result::Result<String, String> {
        let canonical =
            serde_json::to_vec(body).map_err(|error| format!("describing a record: {error}"))?;
        Ok(hex(Sha256::digest(&canonical).as_slice()))
    }
}

/// What a seal attests to: the chain up to its `records`-th record, whose digest is `head`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealBody {
    pub day: String,
    pub at: String,
    pub records: u64,
    pub head: String,
}

/// A seal beside a day file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seal {
    pub body: SealBody,
    /// The bare thumbprint of the key that signed it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kid: Option<String>,
    /// `EdDSA` or `ES256`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub algorithm: Option<String>,
    /// The signature over the JSON of `body`, lowercase hex.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub signature: Option<String>,
}

impl Seal {
    /// The bytes its signature covers.
    pub fn signed_bytes(&self) -> std::result::Result<Vec<u8>, String> {
        serde_json::to_vec(&self.body).map_err(|error| format!("describing a seal: {error}"))
    }
}

/// What one seal's signature came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealSignature {
    /// Signed by `kid`, verified; `revoked` when that key was revoked since.
    Verified { kid: String, revoked: bool },
    /// Written without a signature.
    Unsigned,
    /// Not checked: no keys were given.
    NotChecked,
}

/// One seal, checked against the records it attests to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealCheck {
    pub day: String,
    pub records: u64,
    pub signature: SealSignature,
}

/// What verifying the legacy chain found.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Verification {
    pub records: u64,
    pub days: usize,
    /// The first record kept, when the chain holds any.
    pub first_seq: Option<u64>,
    /// The digest of the last record.
    pub head: String,
    pub seals: Vec<SealCheck>,
    pub warnings: Vec<String>,
}

/// The day a file of records is for, or `None` when it is not one.
pub fn day_of_file(name: &str) -> Option<i64> {
    let date = name.strip_prefix(PREFIX)?.strip_suffix(SUFFIX)?;
    Date::from_iso(date).map(civil::days_of)
}

/// The day a seal closes, or `None` when the file is not one.
fn day_of_seal(name: &str) -> Option<i64> {
    let date = name.strip_prefix(PREFIX)?.strip_suffix(SEAL_SUFFIX)?;
    Date::from_iso(date).map(civil::days_of)
}

/// Whether `dir` holds a day of the legacy chain: a regular file named as one, as [`verify`]
/// reads them.
pub fn holds_chain(dir: &Path) -> bool {
    Dir::open(dir)
        .and_then(|held| held.names())
        .is_ok_and(|names| names.iter().any(|name| day_of_file(name).is_some()))
}

/// Reads the legacy chain in `dir` and checks that nothing in it was altered; with `keys`, each
/// seal's signature too. Answers the first problem found as an error.
pub fn verify(dir: &Path, keys: Option<&Keys>) -> std::result::Result<Verification, String> {
    let held = Dir::open(dir).map_err(|error| error.to_string())?;
    let names = held.names().map_err(|error| error.to_string())?;
    // Each file bounded before it is read: the directory may be a stopped volume or one an
    // operator named.
    let bounded = |name: &str, most: u64| -> std::result::Result<Vec<u8>, String> {
        let size = std::fs::metadata(dir.join(name))
            .map_err(|error| format!("measuring {name}: {error}"))?
            .len();
        if size > most {
            return Err(format!("{name} takes {size} bytes, more than {most}"));
        }
        held.read(name)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("{name} vanished while it was read"))
    };
    // Each day by the name it is listed under; two names for one day, as a spelling the writer
    // never used could give, are refused rather than one of them skipped.
    let mut days: Vec<(i64, String)> = names
        .iter()
        .filter_map(|name| day_of_file(name).map(|day| (day, name.clone())))
        .collect();
    days.sort();
    if let Some(pair) = days.windows(2).find(|pair| pair[0].0 == pair[1].0) {
        return Err(format!(
            "{} and {} are records of the same day",
            pair[0].1, pair[1].1
        ));
    }
    let mut seals = std::collections::BTreeMap::new();
    for name in names.iter() {
        let Some(day) = day_of_seal(name) else {
            continue;
        };
        let bytes = bounded(name, MAX_SEAL_BYTES)?;
        let seal: Seal =
            serde_json::from_slice(&bytes).map_err(|error| format!("parsing {name}: {error}"))?;
        if seal.body.day != civil::date_of(day).to_iso() {
            return Err(format!(
                "{name} closes the day {}, and is named for another",
                seal.body.day
            ));
        }
        if let Some((other, _)) = seals.insert(seal.body.records, (name.clone(), seal)) {
            return Err(format!(
                "{other} and {name} attest to the same record: one of them is not the writer's"
            ));
        }
    }

    let mut verification = Verification {
        days: days.len(),
        head: GENESIS.to_owned(),
        ..Verification::default()
    };
    let mut expected: Option<(u64, String)> = None;
    let mut checked = std::collections::BTreeSet::new();
    for (_, name) in &days {
        let bytes = bounded(name, MAX_DAY_BYTES)?;
        for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let at = format!("{name}:{}", index + 1);
            let record: Record =
                serde_json::from_slice(line).map_err(|error| format!("parsing {at}: {error}"))?;
            if Record::expected_digest(&record.body)? != record.digest {
                return Err(format!(
                    "{at} has been altered: it does not match its own digest"
                ));
            }
            match &expected {
                None if record.body.seq == 1 => {
                    if record.body.prev != GENESIS {
                        return Err(format!("{at} is the first record and names a predecessor"));
                    }
                }
                None if record.body.seq == 0 => {
                    return Err(format!("{at} is numbered 0; the chain starts at 1"));
                }
                None => verification.warnings.push(format!(
                    "records 1..{} are absent, removed by the old sink's retention: they cannot \
                     be verified",
                    record.body.seq - 1
                )),
                Some((seq, previous)) => {
                    if record.body.prev != *previous {
                        return Err(format!(
                            "{at} does not follow the record before it: the chain is broken, \
                             something between them was changed or removed"
                        ));
                    }
                    if record.body.seq != *seq {
                        return Err(format!(
                            "{at} is numbered {} where {seq} was expected: {} record(s) are \
                             missing",
                            record.body.seq,
                            record.body.seq.saturating_sub(*seq)
                        ));
                    }
                }
            }
            verification.first_seq.get_or_insert(record.body.seq);
            verification.records += 1;
            // The moment the chain reaches the point a seal attests to, the head is the one it
            // names: the check a chain rewritten from the start cannot pass.
            if let Some((file, seal)) = seals.get(&record.body.seq) {
                if seal.body.head != record.digest {
                    return Err(format!(
                        "{file} attests that record {} was {}, and the chain now has {}: the \
                         records have been rewritten since they were sealed",
                        record.body.seq, seal.body.head, record.digest
                    ));
                }
                checked.insert(record.body.seq);
            }
            let next = record.body.seq.checked_add(1).ok_or_else(|| {
                format!(
                    "{at} is numbered {}, past the last a chain can hold",
                    record.body.seq
                )
            })?;
            expected = Some((next, record.digest.clone()));
            verification.head = record.digest;
        }
    }
    let last = expected.as_ref().map_or(0, |(seq, _)| seq - 1);
    let first = verification.first_seq.unwrap_or(1);
    for (point, (file, seal)) in &seals {
        if *point > last {
            return Err(format!(
                "{file} attests to {} record(s) and the chain ends at {last}: {} record(s) have \
                 been removed from the end",
                seal.body.records,
                seal.body.records - last
            ));
        }
        if *point < first {
            verification.warnings.push(format!(
                "{file} attests to records the old sink's retention removed: it cannot be checked"
            ));
        }
    }

    // The seals' signatures, in the chain's order.
    let ordered: Vec<&(String, Seal)> = seals
        .iter()
        .filter(|(point, _)| checked.contains(point))
        .map(|(_, held)| held)
        .collect();
    let mut signatures = Vec::new();
    for (file, seal) in &ordered {
        let signature = match (&seal.kid, &seal.algorithm, &seal.signature) {
            (None, None, None) => SealSignature::Unsigned,
            (Some(kid), Some(algorithm), Some(signature)) => match keys {
                None => SealSignature::NotChecked,
                Some(keys) => {
                    let message = seal.signed_bytes()?;
                    let signature = unhex(signature)
                        .ok_or_else(|| format!("{file}: the signature is not hex"))?;
                    let (kid, revoked) = keys
                        .verify_by_thumbprint(kid, algorithm, &message, &signature)
                        .map_err(|error| format!("{file}: {error}"))?;
                    SealSignature::Verified { kid, revoked }
                }
            },
            _ => {
                return Err(format!(
                    "{file} names a part of a signature and not the rest of it"
                ));
            }
        };
        signatures.push(signature);
    }
    for (index, signature) in signatures.iter().enumerate() {
        let (file, _) = ordered[index];
        match signature {
            SealSignature::Unsigned => verification
                .warnings
                .push(format!("{file} was written without a signature")),
            SealSignature::Verified { kid, revoked: true } => {
                let covered = signatures[index + 1..]
                    .iter()
                    .any(|later| matches!(later, SealSignature::Verified { revoked: false, .. }));
                if !covered {
                    return Err(format!(
                        "{file} is signed by `{kid}`, revoked since, and no later seal by a key \
                         that is not revoked covers it"
                    ));
                }
                verification.warnings.push(format!(
                    "{file} is signed by `{kid}`, revoked since; a later seal by a key that is \
                     not revoked covers it"
                ));
            }
            _ => {}
        }
    }
    verification.seals = ordered
        .iter()
        .zip(signatures)
        .map(|((_, seal), signature)| SealCheck {
            day: seal.body.day.clone(),
            records: seal.body.records,
            signature,
        })
        .collect();
    Ok(verification)
}

/// The migration of the legacy chain to `host/audit/legacy/`: every day and seal carried byte
/// for byte, anything else refused.
#[derive(Debug, Clone, Copy, Default)]
pub struct Migration;

impl crate::storage::migrate::Migration for Migration {
    fn subsystem(&self) -> &str {
        SUBSYSTEM
    }

    fn source_version(&self) -> u16 {
        SOURCE_VERSION
    }

    fn target_version(&self) -> u16 {
        TARGET_VERSION
    }

    fn build(&self, old: &Dir, new: &Dir) -> Result<Built> {
        let names = old.names()?;
        let mut foreign: Vec<String> = names
            .iter()
            .filter(|name| day_of_file(name).is_none() && day_of_seal(name).is_none())
            .cloned()
            .collect();
        foreign.extend(old.subdirs()?.into_iter().map(|name| format!("{name}/")));
        // A link, or anything else neither a file nor a directory, is listed by neither; it would
        // go with the directory too.
        let listed: std::collections::BTreeSet<String> = names.iter().cloned().collect();
        let entries = std::fs::read_dir(old.path()).map_err(|source| StorageError::Io {
            what: format!("listing {}", old.path().display()),
            source,
        })?;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let directory = entry.file_type().is_ok_and(|kind| kind.is_dir());
            if !listed.contains(&name) && !directory {
                foreign.push(name);
            }
        }
        if !foreign.is_empty() {
            return Err(StorageError::Refused(format!(
                "{} holds {} beside the audit chain; `migrate finalize` would remove them with \
                 the directory: move them out of it, then migrate again",
                old.path().display(),
                foreign.join(", ")
            )));
        }
        let mut carried = Vec::new();
        for name in names {
            let bytes = old.read(&name)?.unwrap_or_default();
            let same = |held: &[u8]| held == bytes.as_slice();
            publish_immutable(new, &name, &bytes, &same, &same)?;
            carried.push((name.clone(), name));
        }
        Ok(Built {
            files: carried.len(),
            carried,
            dropped: Vec::new(),
        })
    }
}

/// What [`lay_out`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Laid {
    /// No legacy chain: version 2 declared, empty.
    Fresh,
    /// The legacy chain was migrated now.
    Migrated,
    /// Laid out already.
    Current,
}

/// The legacy directory relative to the volume root, when it holds a day of the chain; one
/// outside the volume is refused, as a legacy ring is.
fn legacy_relative(volume: &Volume, legacy: Option<&Path>) -> Result<Option<String>> {
    let Some(legacy) = legacy else {
        return Ok(None);
    };
    match legacy.try_exists() {
        Ok(true) => {}
        Ok(false) => return Ok(None),
        Err(error) => {
            return Err(StorageError::Refused(format!(
                "reading {}: {error}",
                legacy.display()
            )));
        }
    }
    if !holds_chain(legacy) {
        return Ok(None);
    }
    let resolved = |path: &Path| {
        path.canonicalize().map_err(|error| {
            StorageError::Refused(format!("resolving {}: {error}", path.display()))
        })
    };
    let directory = resolved(legacy)?;
    let root = resolved(volume.root())?;
    let relative = directory
        .strip_prefix(&root)
        .ok()
        .and_then(Path::to_str)
        .filter(|relative| !relative.is_empty())
        .ok_or_else(|| {
            StorageError::Refused(format!(
                "the legacy audit chain at {} is outside the volume {}: move it into the volume, \
                 then start again",
                directory.display(),
                root.display()
            ))
        })?;
    Ok(Some(relative.replace(std::path::MAIN_SEPARATOR, "/")))
}

/// Refuses a chain found at `legacy` once the subsystem is at version 2, unless it is the old
/// generation a migration keeps until `migrate finalize`: a chain copied in, or `audit.directory`
/// changed, after the layout would otherwise never be read again.
fn refuse_orphan(
    volume: &Volume,
    manifest: &crate::storage::migrate::LayoutManifest,
    legacy: Option<&Path>,
) -> Result<()> {
    let Some(relative) = legacy_relative(volume, legacy)? else {
        return Ok(());
    };
    let kept = manifest
        .previous
        .as_ref()
        .is_some_and(|previous| previous.directory == relative);
    if kept {
        return Ok(());
    }
    Err(StorageError::Refused(format!(
        "a legacy audit chain is in `{relative}`, and the volume laid out `{SUBSYSTEM}` at \
         `{}` already: it is not migrated twice; verify it with `audit verify --directory`, then \
         move it out of `audit.directory`",
        manifest.active.directory
    )))
}

/// The directory a declared version 1 names: where the chain waits for its migration.
pub fn pending_directory(volume: &Volume) -> Result<Option<String>> {
    let layout = Layout::open(volume, SUBSYSTEM)?;
    Ok(layout
        .manifest()?
        .filter(|manifest| manifest.active.version == SOURCE_VERSION)
        .map(|manifest| manifest.active.directory))
}

/// Whether a legacy chain at `legacy` is still to migrate; a chain found once the subsystem is at
/// version 2, and not the old generation it keeps, is refused.
pub fn needs_migration(volume: &Volume, legacy: Option<&Path>) -> Result<bool> {
    let layout = Layout::open(volume, SUBSYSTEM)?;
    Ok(match layout.manifest()? {
        Some(manifest) if manifest.active.version == TARGET_VERSION => {
            refuse_orphan(volume, &manifest, legacy)?;
            false
        }
        Some(_) => true,
        None => legacy_relative(volume, legacy)?.is_some(),
    })
}

/// Lays the legacy chain out at version 2: a chain at `legacy` is migrated through the framework
/// under `profile`'s preflight with `backup` declared; otherwise version 2 is declared, empty.
pub fn lay_out(
    volume: &Volume,
    legacy: Option<&Path>,
    profile: AssuranceProfile,
    backup: Option<String>,
    now: u64,
) -> Result<Laid> {
    let layout = Layout::open(volume, SUBSYSTEM)?;
    match layout.manifest()? {
        Some(manifest) if manifest.active.version == TARGET_VERSION => {
            refuse_orphan(volume, &manifest, legacy)?;
            return Ok(Laid::Current);
        }
        Some(_) => {}
        None => match legacy_relative(volume, legacy)? {
            None => {
                layout.declare(TARGET_VERSION, &target(), now)?;
                return Ok(Laid::Fresh);
            }
            Some(relative) => {
                layout.declare(SOURCE_VERSION, &relative, now)?;
            }
        },
    }
    layout.migrate(&Migration, Preflight::new(profile, &target(), backup, now))?;
    Ok(Laid::Migrated)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests;
