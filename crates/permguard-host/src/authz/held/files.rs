// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The file backend of [`HeldStore`]: `host/authority/`.
//!
//! ```text
//! host/authority/
//! ├── keys.json        the last good key set, with the issuer it was taken for
//! └── lists/           every status list held, a signed statuslist+jwt each
//! ```
//!
//! A list's file is named by the SHA-256 of its issuer and `uri`, so no `uri` names a path and
//! no issuer's list takes another's place.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use sha2::{Digest as _, Sha256};

use super::{HeldError, HeldStore, KeptKeys, Named};
use crate::storage::dir::Dir;
use crate::storage::volume::Volume;
use crate::storage::{StorageError, write};

/// The directory below `host/`.
pub const DIRECTORY: &str = "authority";
const KEYS: &str = "keys.json";
const LISTS: &str = "lists";

impl From<StorageError> for HeldError {
    fn from(error: StorageError) -> Self {
        Self(Box::new(error))
    }
}

/// The name a list is kept under.
fn file_of(issuer: &str, uri: &str) -> String {
    let digest = Sha256::digest(format!("{issuer}\n{uri}").as_bytes());
    format!(
        "{}.jwt",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

/// What one volume holds of the Authority Plane.
pub struct FileHeld {
    dir: Dir,
    lists: Dir,
    /// The `iat` of every list kept, by its file: read at [`HeldStore::restore`], and held from
    /// the comparison of a list to the write that keeps it.
    kept: Mutex<BTreeMap<String, u64>>,
}

impl std::fmt::Debug for FileHeld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileHeld").finish_non_exhaustive()
    }
}

impl FileHeld {
    /// `host/authority/` of `volume`, created when absent.
    pub fn open(volume: &Volume) -> Result<Self, StorageError> {
        let dir = volume.host().subdir(DIRECTORY, true)?;
        let lists = dir.subdir(LISTS, true)?;
        Ok(Self {
            dir,
            lists,
            kept: Mutex::default(),
        })
    }

    fn kept(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, u64>> {
        self.kept.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl HeldStore for FileHeld {
    fn keys(&self) -> Result<Option<KeptKeys>, HeldError> {
        Ok(self
            .dir
            .read(KEYS)?
            .and_then(|bytes| serde_json::from_slice(&bytes).ok()))
    }

    fn keep_keys(&self, keys: &KeptKeys) -> Result<(), HeldError> {
        let bytes = serde_json::to_vec(keys).map_err(|error| HeldError(Box::new(error)))?;
        write::replace_bytes(&self.dir, KEYS, &bytes)?;
        Ok(())
    }

    fn restore(&self, verify: &dyn Fn(&str) -> Option<Named>) -> Result<Vec<String>, HeldError> {
        let mut kept = self.kept();
        kept.clear();
        let mut restored = Vec::new();
        for name in self.lists.names()? {
            if !name.ends_with(".jwt") {
                continue;
            }
            let token = self
                .lists
                .read(&name)
                .ok()
                .flatten()
                .and_then(|bytes| String::from_utf8(bytes).ok());
            match token
                .as_deref()
                .and_then(|token| Some((token, verify(token)?)))
            {
                Some((token, named)) if file_of(&named.issuer, &named.uri) == name => {
                    kept.insert(name, named.iat);
                    restored.push(token.to_owned());
                }
                _ => {
                    let _ = self.lists.unlink(&name);
                }
            }
        }
        Ok(restored)
    }

    fn keep_list(&self, named: &Named, token: &str) -> Result<bool, HeldError> {
        let file = file_of(&named.issuer, &named.uri);
        let mut kept = self.kept();
        if kept.get(&file).is_some_and(|held| *held >= named.iat) {
            return Ok(false);
        }
        write::replace_bytes(&self.lists, &file, token.as_bytes())?;
        kept.insert(file, named.iat);
        Ok(true)
    }

    fn drop_list(&self, issuer: &str, uri: &str) -> Result<(), HeldError> {
        let file = file_of(issuer, uri);
        let mut kept = self.kept();
        kept.remove(&file);
        self.lists.unlink(&file)?;
        Ok(())
    }
}
