// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The file backend of [`SlotStore`]: `<slot>.key` and `<slot>.ref` below one directory, a ring's
//! `private/` or the identity's `keys/`.
//!
//! A slot is filled by a publication without replacement, so of two that arrive together the
//! filesystem keeps one; it is emptied through a tombstone, so a deletion that stopped is
//! completed.

use std::sync::Arc;

use super::{Kind, SlotStore, check};
use crate::keys::{FileKeyProvider, KeyError};
use crate::storage::write::{Published, publish_immutable, replace_bytes};
use crate::storage::{Dir, StorageError, crash, tombstone};

impl From<StorageError> for KeyError {
    fn from(error: StorageError) -> Self {
        Self::Unavailable(Box::new(error))
    }
}

fn extension(kind: Kind) -> &'static str {
    match kind {
        Kind::Key => ".key",
        Kind::Reference => ".ref",
    }
}

fn file(kind: Kind, slot: &str) -> Result<String, KeyError> {
    check(slot)?;
    Ok(format!("{slot}{}", extension(kind)))
}

/// The slots of one directory, which the caller created `0700`.
pub struct FileSlots {
    dir: Dir,
}

impl std::fmt::Debug for FileSlots {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileSlots")
            .field("dir", &self.dir.path())
            .finish()
    }
}

impl FileSlots {
    /// Over `dir`.
    pub fn new(dir: Dir) -> Self {
        Self { dir }
    }
}

impl SlotStore for FileSlots {
    fn read(&self, kind: Kind, slot: &str) -> Result<Option<Vec<u8>>, KeyError> {
        Ok(self.dir.read(&file(kind, slot)?)?)
    }

    fn fill(&self, kind: Kind, slot: &str, bytes: &[u8]) -> Result<(), KeyError> {
        let name = file(kind, slot)?;
        if self.dir.read(&name)?.is_some() {
            return Err(KeyError::Exists(slot.to_owned()));
        }
        // Anything there by now fills the slot, whatever it is: this key is refused.
        match publish_immutable(
            &self.dir,
            &name,
            bytes,
            &|written| written == bytes,
            &|_| false,
        ) {
            Ok(Published::Written) => {
                crash::point("slots.filled");
                Ok(())
            }
            Ok(Published::AlreadyThere) => Err(KeyError::Exists(slot.to_owned())),
            // Refused because another key took the slot meanwhile; anything else, a write that
            // did not read back among them, published nothing and is said as it is.
            Err(StorageError::Corruption(_)) if self.dir.read(&name)?.is_some() => {
                Err(KeyError::Exists(slot.to_owned()))
            }
            Err(error) => Err(error.into()),
        }
    }

    fn replace(&self, kind: Kind, slot: &str, bytes: &[u8]) -> Result<(), KeyError> {
        replace_bytes(&self.dir, &file(kind, slot)?, bytes)?;
        crash::point("slots.replaced");
        Ok(())
    }

    fn slots(&self, kind: Kind) -> Result<Vec<String>, KeyError> {
        Ok(self
            .dir
            .names()?
            .into_iter()
            .filter_map(|name| name.strip_suffix(extension(kind)).map(str::to_owned))
            .filter(|slot| check(slot).is_ok())
            .collect())
    }

    fn empty(&self, kind: Kind, slot: &str) -> Result<(), KeyError> {
        tombstone::delete(&self.dir, &file(kind, slot)?)?;
        crash::point("slots.emptied");
        Ok(())
    }

    fn place(&self, kind: Kind, slot: &str) -> String {
        self.dir
            .child_path(&format!("{slot}{}", extension(kind)))
            .display()
            .to_string()
    }
}

impl FileKeyProvider {
    /// Over `dir`, which the caller created `0700`: the plaintext custody of the file backend.
    pub fn new(dir: Dir) -> Self {
        Self::over(Arc::new(FileSlots::new(dir)))
    }
}
