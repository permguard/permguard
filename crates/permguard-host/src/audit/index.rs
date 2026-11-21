// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The trails a volume ever held, kept beside them in `host/audit/index` (BUG-0156).
//!
//! A trail's directory holds its records, its checkpoints and its `META.cbor`: removing it removed
//! every trace that the trail existed, and `audit verify`, which walks the directories present,
//! reported the rest of the volume sound. The index names every trail before its first record is
//! written, so a trail deleted whole is a trail the index names and the volume lacks. The
//! directory is created first and named second: a Host that stops between the two leaves a
//! directory that holds no record, which the next start names, and never a name without its
//! directory, which would be recorded lost for good though nothing was ever in it.
//!
//! | File                    | Written                                     | Says                     |
//! | ----------------------- | ------------------------------------------- | ------------------------ |
//! | `<class>-<digest>.cbor` | before the trail's first record, once       | the trail's `META.cbor`  |
//! | `<class>-<digest>.lost` | when a Host starts and finds the trail gone | the day it was found     |
//!
//! Both are immutable. A `.lost` entry stays: the trail the Host recreates at seq 0 afterwards
//! does not bring back what was deleted, and `audit verify` fails on it for good. A volume written
//! before the index existed has its trails adopted at the next start. Someone able to rewrite the
//! volume can remove the index as well; what this answers is the deletion of a trail that leaves
//! its index behind, and the verifier says when a volume keeps no index at all.

use crate::storage::write::{Published, publish_immutable};
use crate::storage::{Dir, Result as StorageResult, StorageError};

use super::Class;
use super::record::TrailMeta;
use super::trail::{self, META};

/// The index's directory, beside `trails/` under `host/audit/`.
pub const DIRECTORY: &str = "index";
/// The suffix of the entry naming a trail.
const KNOWN: &str = ".cbor";
/// The suffix of the entry recording that a Host found the trail gone.
const LOST: &str = ".lost";

/// One trail the index names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub class: Class,
    pub digest: String,
    /// The resource its entry names, or why the entry does not read.
    pub resource: Result<String, String>,
    /// The day a Host found the trail gone, when one did.
    pub lost: Option<String>,
}

impl Entry {
    /// `<class>:<resource>`, or `<class>:<digest>` when the entry does not read.
    pub fn name(&self) -> String {
        match &self.resource {
            Ok(resource) => format!("{}:{resource}", self.class.as_str()),
            Err(_) => format!("{}:{}", self.class.as_str(), self.digest),
        }
    }
}

fn stem(class: Class, digest: &str) -> String {
    format!("{}-{digest}", class.as_str())
}

/// Names the trail of `(class, resource)` in `index`; a trail already named is left as it is.
pub fn record(index: &Dir, class: Class, resource: &str) -> StorageResult<()> {
    let meta = TrailMeta {
        class: class.as_str().to_owned(),
        resource: resource.to_owned(),
    }
    .encode()
    .map_err(|error| StorageError::Corruption(error.to_string()))?;
    let name = format!("{}{KNOWN}", stem(class, &trail::resource_digest(resource)));
    let same = |held: &[u8]| held == meta.as_slice();
    match publish_immutable(index, &name, &meta, &same, &same)? {
        Published::Written | Published::AlreadyThere => Ok(()),
    }
}

/// Every trail `index` names, in the order of their entries' names.
pub fn entries(index: &Dir) -> StorageResult<Vec<Entry>> {
    let mut names = index.names()?;
    names.sort();
    let mut entries = Vec::new();
    for name in &names {
        let Some(stem) = name.strip_suffix(KNOWN) else {
            continue;
        };
        let Some((class, digest)) = stem
            .split_once('-')
            .and_then(|(class, digest)| Some((Class::parse(class)?, digest)))
        else {
            continue;
        };
        let resource = match index.read(name)? {
            None => Err("its entry vanished while it was read".to_owned()),
            Some(bytes) => TrailMeta::decode(&bytes)
                .map_err(|error| format!("its entry does not read: {error}"))
                .and_then(|meta| {
                    if meta.class == class.as_str()
                        && trail::resource_digest(&meta.resource) == digest
                    {
                        Ok(meta.resource)
                    } else {
                        Err("its entry names another trail".to_owned())
                    }
                }),
        };
        let lost = index
            .read(&format!("{stem}{LOST}"))?
            .map(|bytes| String::from_utf8_lossy(&bytes).trim().to_owned());
        entries.push(Entry {
            class,
            digest: digest.to_owned(),
            resource,
            lost,
        });
    }
    Ok(entries)
}

/// Records in `index` that the trail of `entry` was found gone on `day`; a trail already
/// recorded lost keeps the first day.
fn mark_lost(index: &Dir, entry: &Entry, day: &str) -> StorageResult<()> {
    let name = format!("{}{LOST}", stem(entry.class, &entry.digest));
    let bytes = day.as_bytes();
    let any = |_: &[u8]| true;
    match publish_immutable(index, &name, bytes, &any, &any)? {
        Published::Written | Published::AlreadyThere => Ok(()),
    }
}

/// Whether `trails` holds a directory for the trail of `class` under `digest`.
fn held(trails: &Dir, class: Class, digest: &str) -> StorageResult<bool> {
    if !trails.subdirs()?.iter().any(|name| name == class.as_str()) {
        return Ok(false);
    }
    Ok(trails
        .subdir(class.as_str(), false)?
        .subdirs()?
        .iter()
        .any(|name| name == digest))
}

/// Brings `index` in line with `trails` as a Host starts on `day`: a trail on the volume that
/// the index does not name yet is named, and a trail the index names that the volume lacks is
/// recorded lost. Answers the trails found lost now, by `<class>:<resource>`.
pub fn reconcile(index: &Dir, trails: &Dir, day: &str) -> StorageResult<Vec<String>> {
    let mut known = entries(index)?;
    for class_name in trails.subdirs()? {
        let Some(class) = Class::parse(&class_name) else {
            continue;
        };
        let class_dir = trails.subdir(&class_name, false)?;
        for digest in class_dir.subdirs()? {
            if known
                .iter()
                .any(|entry| entry.class == class && entry.digest == digest)
            {
                continue;
            }
            // A trail without a readable `META.cbor` names no resource to index; the sweep and
            // the verifier report it.
            let Some(meta) = class_dir.subdir(&digest, false)?.read(META)? else {
                continue;
            };
            let Ok(meta) = TrailMeta::decode(&meta) else {
                continue;
            };
            if trail::resource_digest(&meta.resource) == digest {
                record(index, class, &meta.resource)?;
            }
        }
    }
    known.retain(|entry| entry.lost.is_none());
    let mut lost = Vec::new();
    for entry in known {
        if !held(trails, entry.class, &entry.digest)? {
            mark_lost(index, &entry, day)?;
            lost.push(entry.name());
        }
    }
    Ok(lost)
}
