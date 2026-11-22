// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The file backend of [`RingStore`]: `host/keys/<ring>/` on the volume.
//!
//! ```text
//! host/keys/<ring>/
//! ├── journal.cborseq          lifecycle and epoch transitions; authoritative
//! ├── ring.cbor                the materialized public view, rebuilt from the journal
//! ├── binding.cose             the identity-signed binding of the current set
//! ├── bindings/<seq>.cose      every binding issued, by its `bound` journal entry (WP-3.4)
//! ├── public/<thumbprint>.jwk  every key the ring ever published, kept for good
//! └── private/<thumbprint>.key through the key provider, 0600; destroyed at retirement
//! host/keys/retired/<old host_id>/<ring>/   a retired ring's public records
//! ```
//!
//! What takes a [`Volume`] or a directory here is the file backend's way in: a ring of a volume
//! opened, or a ring directory of a stopped volume read.

use std::sync::{Arc, Mutex, PoisonError};

use permguard_objects::cbor::Value;
use permguard_objects::crypto::suite::Suite;

use super::store::RingStore;
use super::{Policy, Ring, RingError};
use crate::keys::record::{Entry, MAX_ENTRY_BYTES};
use crate::keys::registry::Stores;
use crate::keys::slots::files::FileSlots;
use crate::keys::{FileKeyProvider, KeyProvider};
use crate::operations::mutation::Applying;
use crate::storage::volume::Volume;
use crate::storage::write::{Published, publish_immutable, read_view, replace_bytes, replace_view};
use crate::storage::{Dir, StorageError, crash, format, sequence, tombstone};
use crate::time::TimeGuard;

/// The directory below `host/`.
pub const DIRECTORY: &str = "keys";
/// The ring's journal.
pub const JOURNAL: &str = "journal.cborseq";
/// The materialized view.
pub const VIEW: &str = "ring.cbor";
/// The identity-signed binding.
pub const BINDING: &str = "binding.cose";
/// Every binding issued, by the sequence of its `bound` journal entry, kept for the verification
/// bundle (WP-3.4, owner decisions of 2026-10-09).
pub const BINDINGS: &str = "bindings";
/// The public halves.
pub const PUBLIC: &str = "public";
/// The private halves, through the key provider.
pub const PRIVATE: &str = "private";
/// The directory a reset keeps a retired ring's public records in, below `host/keys/`.
pub const RETIRED: &str = "retired";

impl From<StorageError> for RingError {
    fn from(error: StorageError) -> Self {
        Self::Unavailable(Box::new(error))
    }
}

/// The directory of `ring` below `volume`, created when absent.
pub fn directory(volume: &Volume, ring: &str) -> Result<Dir, StorageError> {
    volume.host().subdir(DIRECTORY, true)?.subdir(ring, true)
}

/// The records of one ring's directory.
pub struct FileRing {
    dir: Dir,
    /// The ring's own name: the directory its retired records are kept under.
    ring: String,
    /// How many entries are held, from the read that counted them to the write that adds one;
    /// `None` when the records were opened to read, and take no entry.
    held: Option<Mutex<u64>>,
}

impl std::fmt::Debug for FileRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileRing")
            .field("dir", &self.dir.path())
            .finish()
    }
}

impl FileRing {
    /// The records of `ring` in `dir`, its directory on a claimed volume: an entry a process that
    /// stopped left half written is cut.
    pub fn open(dir: Dir, ring: &str) -> Result<Self, StorageError> {
        let held = sequence::recover(&dir, JOURNAL, MAX_ENTRY_BYTES)?
            .items
            .len() as u64;
        Ok(Self {
            dir,
            ring: ring.to_owned(),
            held: Some(Mutex::new(held)),
        })
    }

    /// The records of the ring directory `dir`, to read: nothing is written, not even to cut a
    /// torn entry. What an export of a stopped volume reads.
    pub fn to_read(dir: Dir) -> Self {
        Self {
            dir,
            ring: String::new(),
            held: None,
        }
    }

    /// The directory `name` of the ring, made when absent: what a write goes to. A ring's
    /// records opened to read take no write.
    fn sub(&self, name: &str) -> Result<Dir, RingError> {
        self.writable()?;
        Ok(self.dir.subdir(name, true)?)
    }

    /// The directory `name` of the ring, when it exists: what a read looks in, creating nothing.
    fn existing(&self, name: &str) -> Result<Option<Dir>, RingError> {
        if !self.dir.subdirs()?.iter().any(|held| held == name) {
            return Ok(None);
        }
        Ok(Some(self.dir.subdir(name, false)?))
    }

    fn writable(&self) -> Result<(), RingError> {
        if self.held.is_none() {
            return Err(RingError::Refused(
                "a ring's records opened to read take no write".to_owned(),
            ));
        }
        Ok(())
    }
}

impl RingStore for FileRing {
    fn entries(&self) -> Result<Vec<Value>, RingError> {
        // Counted under the same hold as an entry is added: a ring that reads its entries again
        // adds the next one after what it read.
        let mut held = self
            .held
            .as_ref()
            .map(|held| held.lock().unwrap_or_else(PoisonError::into_inner));
        let items = sequence::read(&self.dir, JOURNAL, MAX_ENTRY_BYTES)?.items;
        if let Some(held) = held.as_mut() {
            **held = items.len() as u64;
        }
        Ok(items)
    }

    fn append(&self, seq: u64, entry: &[u8]) -> Result<(), RingError> {
        self.writable()?;
        let Some(held) = &self.held else {
            return Ok(());
        };
        let mut held = held.lock().unwrap_or_else(PoisonError::into_inner);
        if seq != held.saturating_add(1) {
            return Err(RingError::Refused(format!(
                "the entry {seq} does not follow the {} the ring holds: the ring moved",
                *held
            )));
        }
        sequence::append(&self.dir, JOURNAL, entry)?;
        *held = seq;
        crash::point("ring.entry_added");
        Ok(())
    }

    fn view(&self) -> Result<Option<Vec<u8>>, RingError> {
        Ok(read_view(&self.dir, VIEW, format::VIEW)?)
    }

    fn replace_view(&self, view: &[u8]) -> Result<(), RingError> {
        self.writable()?;
        Ok(replace_view(&self.dir, VIEW, format::VIEW, view)?)
    }

    fn binding(&self) -> Result<Option<Vec<u8>>, RingError> {
        Ok(read_view(&self.dir, BINDING, format::VIEW)?)
    }

    fn replace_binding(&self, envelope: &[u8]) -> Result<(), RingError> {
        self.writable()?;
        Ok(replace_view(&self.dir, BINDING, format::VIEW, envelope)?)
    }

    fn keep_binding(&self, seq: u64, envelope: &[u8]) -> Result<(), RingError> {
        Ok(replace_view(
            &self.sub(BINDINGS)?,
            &format!("{seq}.cose"),
            format::VIEW,
            envelope,
        )?)
    }

    fn kept_binding(&self, seq: u64) -> Result<Option<Vec<u8>>, RingError> {
        let Some(dir) = self.existing(BINDINGS)? else {
            return Ok(None);
        };
        Ok(read_view(&dir, &format!("{seq}.cose"), format::VIEW)?)
    }

    fn kept_bindings(&self) -> Result<Vec<Vec<u8>>, RingError> {
        let Some(dir) = self.existing(BINDINGS)? else {
            return Ok(Vec::new());
        };
        let mut kept = Vec::new();
        for name in dir.names()? {
            // What does not read as a kept binding is none: a temporary file a write that
            // stopped left, a file damaged at rest. It never makes the others unreadable.
            if let Ok(Some(bytes)) = read_view(&dir, &name, format::VIEW) {
                kept.push(bytes);
            }
        }
        Ok(kept)
    }

    fn public(&self, thumbprint: &str) -> Result<Option<Vec<u8>>, RingError> {
        let Some(dir) = self.existing(PUBLIC)? else {
            return Ok(None);
        };
        Ok(dir.read(&format!("{thumbprint}.jwk"))?)
    }

    fn publish_public(&self, thumbprint: &str, jwk: &[u8]) -> Result<(), RingError> {
        let same = |bytes: &[u8]| bytes == jwk;
        match publish_immutable(
            &self.sub(PUBLIC)?,
            &format!("{thumbprint}.jwk"),
            jwk,
            &same,
            &same,
        )? {
            Published::Written => crash::point("ring.public_published"),
            Published::AlreadyThere => {}
        }
        Ok(())
    }

    fn retire(&self, _applying: &Applying<'_>, old_host_id: &[u8; 16]) -> Result<(), RingError> {
        self.writable()?;
        let keys = Dir::open(
            self.dir
                .path()
                .parent()
                .ok_or_else(|| RingError::Corrupt("a ring directory has no parent".to_owned()))?,
        )?;
        let kept = keys
            .subdir(RETIRED, true)?
            .subdir(&crate::identity::record::uuid_text(old_host_id), true)?
            .subdir(&self.ring, true)?;
        for name in [JOURNAL, VIEW, BINDING] {
            if let Some(bytes) = self.dir.read(name)? {
                replace_bytes(&kept, name, &bytes)?;
            }
        }
        for sub in [BINDINGS, PUBLIC] {
            let from = self.sub(sub)?;
            let to = kept.subdir(sub, true)?;
            for name in from.names()? {
                if let Some(bytes) = from.read(&name)? {
                    replace_bytes(&to, &name, &bytes)?;
                }
            }
        }
        Ok(())
    }

    fn forget_entries(&self) -> Result<(), RingError> {
        self.writable()?;
        // Held across the removal: an entry is not added to a journal that is going.
        let mut held = self
            .held
            .as_ref()
            .map(|held| held.lock().unwrap_or_else(PoisonError::into_inner));
        if self.dir.read(JOURNAL)?.is_some() {
            tombstone::delete(&self.dir, JOURNAL)?;
        }
        if let Some(held) = held.as_mut() {
            **held = 0;
        }
        crash::point("ring.entries_forgotten");
        Ok(())
    }

    fn clear(&self) -> Result<(), RingError> {
        self.writable()?;
        for name in [VIEW, BINDING] {
            if self.dir.read(name)?.is_some() {
                tombstone::delete(&self.dir, name)?;
            }
        }
        for sub in [BINDINGS, PUBLIC] {
            let dir = self.sub(sub)?;
            for name in dir.names()? {
                tombstone::delete(&dir, &name)?;
            }
        }
        Ok(())
    }
}

/// The stores of `ring` on `volume`: its records and the slots of its private keys.
pub fn stores(volume: &Volume, ring: &str) -> Result<Stores, StorageError> {
    let dir = directory(volume, ring)?;
    dir.subdir(PUBLIC, true)?;
    let private = dir.subdir(PRIVATE, true)?;
    Ok(Stores {
        ring: Arc::new(FileRing::open(dir, ring)?),
        slots: Arc::new(FileSlots::new(private)),
    })
}

impl Ring {
    /// Opens `ring` on `volume`, its private keys in the clear below its own directory: the
    /// plaintext custody of the file backend.
    pub fn open(
        volume: &Volume,
        ring: &'static str,
        suite: Suite,
        policy: Policy,
        time: Arc<TimeGuard>,
    ) -> Result<Self, RingError> {
        Self::registered(ring)?;
        let Stores { ring: store, slots } = stores(volume, ring)?;
        let provider: Arc<dyn KeyProvider> = Arc::new(FileKeyProvider::over(slots));
        Self::open_with(store, provider, ring, suite, policy, time)
    }
}

/// What `keys export --directory` prints for a ring directory on a stopped volume (WP-3.4, owner
/// decisions of 2026-10-09), from its journal alone, no private half read.
pub fn export(directory: &std::path::Path) -> Result<String, RingError> {
    super::export_of(
        &FileRing::to_read(Dir::open(directory)?),
        &directory.display().to_string(),
    )
}

/// Decodes `journal.cborseq`'s entries, for the tests and an offline reader.
pub fn journal_entries(dir: &Dir) -> Result<Vec<Entry>, RingError> {
    sequence::read(dir, JOURNAL, MAX_ENTRY_BYTES)?
        .items
        .into_iter()
        .map(|item| Entry::decode(item).map_err(RingError::Record))
        .collect()
}
