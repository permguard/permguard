// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The holds on the file backend: one file a hold and an index beside them.
//!
//! ```text
//! host/holds/
//! ├── <hold-id>.json    one hold, read whole or refused
//! └── INDEX.json        the SHA-256 of every hold's file
//! ```
//!
//! The index is written by the same operation that writes or removes a hold's file (BUG-0172):
//! an add writes its file and then the index, a release removes its entry and then the file. A
//! hold the index records whose file is gone, or whose file no longer has the recorded digest,
//! makes the holds unreadable, so a listing refuses naming it and the garbage collection sweeps
//! nothing: a hold is never lost by removing or editing its file outside an operation. A file
//! the index lacks still keeps what it names, the direction that can only keep more; an
//! operation records it, and [`HoldStore::verify`] names it until one does. An index that is
//! missing beside hold files makes the holds unreadable too; a volume written before the index
//! existed is indexed by the first writable open.

use permguard_core::catalog::is_guid_shaped;
use serde::{Deserialize, Serialize};

use super::{
    Hold, HoldError, HoldStore, MAX_HOLD_BYTES, MAX_TIME, is_catalog_id, is_text, resource_ids,
};
use crate::operations::mutation::Applying;
use crate::storage::volume::Volume;
use crate::storage::write::replace_bytes;
use crate::storage::{Dir, StorageError};

impl From<StorageError> for HoldError {
    fn from(error: StorageError) -> Self {
        Self::Unavailable(Box::new(error))
    }
}

/// The directory under `host/` the holds live in.
pub const DIRECTORY: &str = "holds";

/// The index of the holds' files, beside them.
pub const INDEX: &str = "INDEX.json";

/// The largest index read, in bytes: room for many thousands of holds.
const MAX_INDEX_BYTES: u64 = 4 * 1024 * 1024;

/// What `INDEX.json` holds: every hold's id and the digest of its file, `sha256:<hex>`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    version: u32,
    holds: std::collections::BTreeMap<String, String>,
}

/// The digest an index records of a hold's file.
fn digest(bytes: &[u8]) -> String {
    use sha2::Digest as _;

    permguard_objects::digest::Digest::from_raw(sha2::Sha256::digest(bytes).into()).to_string()
}

/// The holds of a volume, under `host/holds/`.
pub struct FileHolds {
    dir: Dir,
    /// Held while a hold is added or released: the read of a hold and its removal, a file and
    /// its index entry, are one step for any other change of the holds.
    changing: std::sync::Mutex<()>,
}

/// A hold's file name, from an id that is one.
fn file(id: &str) -> Option<String> {
    is_catalog_id(id).then(|| format!("{id}.json"))
}

impl FileHolds {
    /// The holds of `volume`, the directory created when absent.
    ///
    /// A store without an index is indexed here, its files as they are: a volume written before
    /// the index existed, or one whose index was removed, said at WARN when it holds any hold,
    /// since only then can the files have changed unrecorded.
    pub fn open(volume: &Volume) -> Result<Self, StorageError> {
        let store = Self {
            dir: volume.host().subdir(DIRECTORY, true)?,
            changing: std::sync::Mutex::new(()),
        };
        store.index_unindexed()?;
        Ok(store)
    }

    /// Indexes a store that has no index, its files as they are: a volume written before the
    /// index existed, or one whose index was removed, said at WARN when it holds any hold, since
    /// only then can the files have changed unrecorded. A file that does not read is left to the
    /// listing to refuse, as before the index: nothing is indexed, and the garbage collection
    /// sweeps nothing meanwhile.
    fn index_unindexed(&self) -> Result<(), StorageError> {
        if self.dir.exists(INDEX)? {
            return Ok(());
        }
        let files = match self.files() {
            Ok(files) => files,
            // What the directory refused, as it said it.
            Err(HoldError::Unavailable(error)) => {
                return Err(match error.downcast::<StorageError>() {
                    Ok(storage) => *storage,
                    Err(other) => StorageError::Refused(other.to_string()),
                });
            }
            Err(_) => return Ok(()),
        };
        let index = Index {
            version: 1,
            holds: files
                .iter()
                .map(|(hold, digest)| (hold.id.clone(), digest.clone()))
                .collect(),
        };
        let bytes = serde_json::to_vec_pretty(&index)
            .map_err(|error| StorageError::Corruption(error.to_string()))?;
        replace_bytes(&self.dir, INDEX, &bytes)?;
        if !index.holds.is_empty() {
            tracing::warn!(
                event.name = "host.holds_indexed",
                holds = index.holds.len(),
                "the holds carried no index and are indexed as their files are now: a volume \
                 written before the index, or one whose index was removed"
            );
        }
        Ok(())
    }

    /// The holds of `volume` to read, creating nothing: `None` when it has never held one. What a
    /// reader of a volume that is never written opens, one restored for forensics (BUG-0188).
    pub fn open_to_read(volume: &Volume) -> Result<Option<Self>, StorageError> {
        if !volume
            .host()
            .subdirs()?
            .iter()
            .any(|name| name == DIRECTORY)
        {
            return Ok(None);
        }
        Ok(Some(Self {
            dir: volume.host().subdir(DIRECTORY, false)?,
            changing: std::sync::Mutex::new(()),
        }))
    }

    /// The names of the hold files, by the id they are named for.
    fn names(&self) -> Result<Vec<String>, HoldError> {
        let mut names: Vec<String> = self
            .dir
            .names()?
            .into_iter()
            .filter(|name| name.strip_suffix(".json").is_some_and(is_guid_shaped))
            .collect();
        names.sort();
        Ok(names)
    }

    /// Every hold file, read, with the digest of its bytes, by id.
    fn files(&self) -> Result<Vec<(Hold, String)>, HoldError> {
        self.names()?
            .iter()
            .map(|name| self.read_bytes(name))
            .collect()
    }

    /// The index, `None` when there is none.
    fn read_index(&self) -> Result<Option<Index>, HoldError> {
        use std::io::Read as _;

        let Some(file_handle) = self.dir.open_read(INDEX)? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file_handle
            .take(MAX_INDEX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| HoldError::Record(format!("{INDEX}: {error}")))?;
        if bytes.len() as u64 > MAX_INDEX_BYTES {
            return Err(HoldError::Record(format!(
                "{INDEX} is larger than {MAX_INDEX_BYTES} bytes"
            )));
        }
        let index: Index = serde_json::from_slice(&bytes)
            .map_err(|error| HoldError::Record(format!("{INDEX}: {error}")))?;
        if index.version != 1
            || index
                .holds
                .iter()
                .any(|(id, digest)| !is_catalog_id(id) || !digest.starts_with("sha256:"))
        {
            return Err(HoldError::Record(format!(
                "{INDEX} is not an index of holds"
            )));
        }
        Ok(Some(index))
    }

    /// Writes `index` whole, replacing the one before, inside the operation `applying`.
    fn write_index(&self, applying: &Applying<'_>, index: &Index) -> Result<(), HoldError> {
        let _ = applying;
        let bytes = serde_json::to_vec_pretty(index)
            .map_err(|error| HoldError::Record(error.to_string()))?;
        replace_bytes(&self.dir, INDEX, &bytes)?;
        Ok(())
    }

    /// The index after an operation on `id`: the one before, entries it records kept as they are,
    /// never repaired, so a file changed outside an operation stays named; files it lacks
    /// recorded; then `id` set to `digest`, or dropped when `None`.
    fn indexed(&self, id: &str, digest: Option<String>) -> Result<Index, HoldError> {
        let mut index = self.read_index()?.unwrap_or(Index {
            version: 1,
            holds: std::collections::BTreeMap::new(),
        });
        for name in self.names()? {
            if let Ok((hold, held)) = self.read_bytes(&name) {
                index.holds.entry(hold.id).or_insert(held);
            }
        }
        match digest {
            Some(digest) => {
                index.holds.insert(id.to_owned(), digest);
            }
            None => {
                index.holds.remove(id);
            }
        }
        Ok(index)
    }

    fn read(&self, name: &str) -> Result<Hold, HoldError> {
        self.read_bytes(name).map(|(hold, _)| hold)
    }

    /// The hold in the file `name`, and the digest of its bytes.
    fn read_bytes(&self, name: &str) -> Result<(Hold, String), HoldError> {
        use std::io::Read as _;

        let file_handle = self
            .dir
            .open_read(name)?
            .ok_or_else(|| HoldError::Record(format!("{name} vanished while it was read")))?;
        let mut bytes = Vec::new();
        file_handle
            .take(MAX_HOLD_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| HoldError::Record(format!("{name}: {error}")))?;
        if bytes.len() as u64 > MAX_HOLD_BYTES {
            return Err(HoldError::Record(format!(
                "{name} is larger than {MAX_HOLD_BYTES} bytes"
            )));
        }
        let hold: Hold = serde_json::from_slice(&bytes)
            .map_err(|error| HoldError::Record(format!("{name}: {error}")))?;
        let refused = |why: &str| Err(HoldError::Record(format!("{name}: {why}")));
        if file(&hold.id).as_deref() != Some(name) || !is_catalog_id(&hold.id) {
            return refused("it names another hold");
        }
        if resource_ids(&hold.resource).is_none() {
            return refused("its resource is not a Control Plane zone or ledger by ids");
        }
        if !is_text(&hold.owner) || !is_text(&hold.reason) {
            return refused("its owner or reason is not one a hold carries");
        }
        let deadline = match (hold.expires_at, hold.review_at) {
            (Some(at), None) | (None, Some(at)) => at,
            _ => return refused("it carries both deadlines, or neither"),
        };
        if deadline > MAX_TIME || hold.created_at > MAX_TIME {
            return refused("a time past the year 9999");
        }
        let held = digest(&bytes);
        Ok((hold, held))
    }
}

#[cfg(any(test, feature = "test-support"))]
impl FileHolds {
    /// Rewrites a hold and its index entry together, as an operation would: what a test of a
    /// hold's deadline does in place of the clock moving. Tests only, never a release build.
    pub fn rewrite_for_tests(&self, hold: &Hold) -> Result<(), HoldError> {
        let name = file(&hold.id).ok_or_else(|| HoldError::Invalid("an id".to_owned()))?;
        let bytes = serde_json::to_vec_pretty(hold)
            .map_err(|error| HoldError::Record(error.to_string()))?;
        let index = self.indexed(&hold.id, Some(digest(&bytes)))?;
        let indexed = serde_json::to_vec_pretty(&index)
            .map_err(|error| HoldError::Record(error.to_string()))?;
        replace_bytes(&self.dir, &name, &bytes)?;
        replace_bytes(&self.dir, INDEX, &indexed)?;
        Ok(())
    }
}

impl HoldStore for FileHolds {
    fn list(&self) -> Result<Vec<Hold>, HoldError> {
        // The files and the index are read as one step for an add or a release: a listing never
        // meets a file without its entry, or an entry without its file, that a change is making.
        let _changing = self
            .changing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let files = self.files()?;
        match self.read_index()? {
            Some(index) => {
                for (id, recorded) in &index.holds {
                    match files.iter().find(|(hold, _)| hold.id == *id) {
                        None => {
                            return Err(HoldError::Record(format!(
                                "the hold {id} is recorded and its file is gone: removed without \
                                 a release"
                            )));
                        }
                        Some((_, held)) if held != recorded => {
                            return Err(HoldError::Record(format!(
                                "the hold {id}'s file changed outside a hold operation"
                            )));
                        }
                        Some(_) => {}
                    }
                }
            }
            None if !files.is_empty() => {
                return Err(HoldError::Record(format!(
                    "{INDEX} is missing beside {} hold file(s): what they keep cannot be told \
                     from what was recorded",
                    files.len()
                )));
            }
            None => {}
        }
        Ok(files.into_iter().map(|(hold, _)| hold).collect())
    }

    fn get(&self, id: &str) -> Result<Option<Hold>, HoldError> {
        let Some(name) = file(id) else {
            return Ok(None);
        };
        if !self.dir.exists(&name)? {
            return Ok(None);
        }
        self.read(&name).map(Some)
    }

    fn verify(&self) -> Result<Vec<String>, HoldError> {
        let _changing = self
            .changing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut findings = Vec::new();
        let mut files = Vec::new();
        for name in self.names()? {
            match self.read_bytes(&name) {
                Ok((hold, digest)) => files.push((hold, digest)),
                Err(HoldError::Record(why)) => findings.push(format!("does not read: {why}")),
                Err(other) => return Err(other),
            }
        }
        let index = match self.read_index() {
            Ok(index) => index,
            Err(HoldError::Record(why)) => {
                findings.push(why);
                return Ok(findings);
            }
            Err(other) => return Err(other),
        };
        let Some(index) = index else {
            if !files.is_empty() {
                findings.push(format!(
                    "{INDEX} is missing beside {} hold file(s)",
                    files.len()
                ));
            }
            return Ok(findings);
        };
        for (id, recorded) in &index.holds {
            match files.iter().find(|(hold, _)| hold.id == *id) {
                None => findings.push(format!(
                    "the hold {id} is recorded and its file is gone: removed without a release"
                )),
                Some((_, held)) if held != recorded => findings.push(format!(
                    "the hold {id}'s file changed outside a hold operation"
                )),
                Some(_) => {}
            }
        }
        for (hold, _) in &files {
            if !index.holds.contains_key(&hold.id) {
                findings.push(format!(
                    "the hold {} has a file the index does not record: it keeps what it names \
                     until an operation records it, or it is released",
                    hold.id
                ));
            }
        }
        Ok(findings)
    }

    fn add(&self, applying: &Applying<'_>, hold: &Hold) -> Result<(), HoldError> {
        let _changing = self
            .changing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let name = file(&hold.id).ok_or_else(|| HoldError::Invalid("an id".to_owned()))?;
        if self.dir.exists(&name)? {
            return Err(HoldError::Invalid(format!(
                "a hold has the id `{}` already",
                hold.id
            )));
        }
        let bytes = serde_json::to_vec_pretty(hold)
            .map_err(|error| HoldError::Record(error.to_string()))?;
        // The file, then its entry: a crash between the two leaves a file the index lacks, which
        // keeps what it names, never an entry without its file.
        let index = self.indexed(&hold.id, Some(digest(&bytes)))?;
        replace_bytes(&self.dir, &name, &bytes)?;
        crate::storage::crash::point("holds.file_written");
        self.write_index(applying, &index)?;
        Ok(())
    }

    fn release(&self, applying: &Applying<'_>, id: &str) -> Result<Hold, HoldError> {
        let _changing = self
            .changing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let name = file(id).ok_or_else(|| HoldError::NotFound(id.to_owned()))?;
        if !self.dir.exists(&name)? {
            return Err(HoldError::NotFound(id.to_owned()));
        }
        let hold = self.read(&name)?;
        // The entry, then the file: a crash between the two leaves a file the index lacks, which
        // keeps what it names until the release is run again.
        let index = self.indexed(id, None)?;
        self.write_index(applying, &index)?;
        crate::storage::crash::point("holds.entry_removed");
        self.dir.unlink(&name)?;
        self.dir.sync()?;
        Ok(hold)
    }
}
