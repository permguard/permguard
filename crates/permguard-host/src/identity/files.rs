// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The file backend of [`IdentityStore`]: `host/identity/` on the volume.
//!
//! ```text
//! host/identity/
//! ├── INIT                 immutable provisioning marker, written last
//! ├── identity.cose        the signed document of the current epoch; atomic replace
//! ├── succession.cborseq   the succession records, appended
//! ├── BOOT                 this start's boot id and the volume's claim generation
//! ├── RESETTING            the old host_id, while a reset is under way
//! ├── keys/
//! │   ├── <epoch>.key      the private key, through the key provider (0600)
//! │   └── <epoch>.pub      the public key, kept for good (owner decision of 2026-10-08)
//! └── retired/<old host_id>/
//!     ├── INIT, identity.cose, succession.cborseq, keys-<epoch>.pub
//!     └── RESET            {1 old host_id, 2 at, 3? operation id}
//! ```
//!
//! What takes a [`Volume`] here is the file backend's way in: the identity of a volume, opened,
//! provisioned or read before it is opened. Each makes the store and hands it to what
//! [`Identity`] does on any backend.

use std::sync::Arc;

use permguard_objects::cbor::Value;

use super::record::{self, Init};
use super::reset::{self, Provisioner, Reset};
use super::store::{HeldEpoch, IdentityStore, Public, Records, Retired};
use super::{Home, Identity, IdentityError, Suite};
use crate::keys::KeyProvider;
use crate::keys::ring::Ring;
use crate::operations::mutation::Applying;
use crate::storage::volume::Volume;
use crate::storage::write::{self, Published, publish_immutable};
use crate::storage::{Dir, StorageError, crash, sequence, tombstone};

/// The directory below `host/`.
pub const DIRECTORY: &str = "identity";
pub const INIT: &str = "INIT";
pub const DOCUMENT: &str = "identity.cose";
pub const SUCCESSION: &str = "succession.cborseq";
pub const BOOT: &str = "BOOT";
pub const KEYS: &str = "keys";
/// The marker of a reset under way, beside `INIT`.
pub const RESETTING: &str = "RESETTING";
/// The directory of the retired identities, below `host/identity/`.
pub const RETIRED: &str = "retired";
/// The record of a reset, in its retired identity's directory.
pub const RESET: &str = "RESET";
/// The most bytes one succession record takes.
const MAX_RECORD_BYTES: usize = 16 * 1024;

impl From<StorageError> for IdentityError {
    fn from(error: StorageError) -> Self {
        Self::Unavailable(Box::new(error))
    }
}

fn public_name(epoch: u64) -> String {
    format!("{epoch}.pub")
}

/// The identity directory of `volume`, and its `keys/` below, created `0700`.
pub fn directories(volume: &Volume) -> Result<(Dir, Dir), StorageError> {
    let dir = volume.host().subdir(DIRECTORY, true)?;
    let keys = dir.subdir(KEYS, true)?;
    Ok((dir, keys))
}

/// The stored public keys of the identity, `<epoch>.pub` below `keys`: what a sealed identity
/// key must open as (WP-3.2).
pub fn stored_public(keys: Dir) -> crate::keys::custody::StoredPublic {
    Box::new(move |slot, _suite| Ok(keys.read(&format!("{slot}.pub"))?))
}

/// The identity records of one volume.
pub struct FileIdentity {
    dir: Dir,
    keys: Dir,
}

impl std::fmt::Debug for FileIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileIdentity").finish_non_exhaustive()
    }
}

impl FileIdentity {
    /// The identity records of `volume`: its directories created when absent, and what a
    /// process that stopped left of a write or a deletion completed.
    pub fn open(volume: &Volume) -> Result<Self, StorageError> {
        let (dir, keys) = directories(volume)?;
        dir.sweep_temps()?;
        tombstone::complete(&dir)?;
        keys.sweep_temps()?;
        tombstone::complete(&keys)?;
        Ok(Self { dir, keys })
    }

    /// The directory of the retired `host_id`'s evidence, when it exists.
    fn evidence(&self, host_id: &str) -> Result<Option<Dir>, StorageError> {
        if !self.dir.subdirs()?.iter().any(|name| name == RETIRED) {
            return Ok(None);
        }
        let retired = self.dir.subdir(RETIRED, false)?;
        if !retired.subdirs()?.iter().any(|name| name == host_id) {
            return Ok(None);
        }
        Ok(Some(retired.subdir(host_id, false)?))
    }
}

/// The public records below `dir`, the evidence of a retired identity when `keys` is `None`:
/// its public keys are then `keys-<epoch>.pub` beside the records.
fn public_records(dir: &Dir, keys: Option<&Dir>) -> Result<Public, IdentityError> {
    let successions = sequence::read(dir, SUCCESSION, MAX_RECORD_BYTES)?
        .items
        .iter()
        .map(|item| {
            permguard_objects::cbor::encode(item).map_err(|error| {
                IdentityError::Corrupt(format!("a succession does not encode: {error:?}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (keys_dir, prefix) = match keys {
        Some(keys) => (keys, ""),
        None => (dir, "keys-"),
    };
    let mut public = Vec::new();
    for name in keys_dir.names()? {
        let Some(epoch) = name
            .strip_prefix(prefix)
            .and_then(|name| name.strip_suffix(".pub"))
            .and_then(|stem| stem.parse::<u64>().ok())
            .filter(|epoch| name == format!("{prefix}{}", public_name(*epoch)))
        else {
            continue;
        };
        if let Some(key) = keys_dir.read(&name)? {
            public.push((epoch, key));
        }
    }
    public.sort();
    Ok(Public {
        init: dir.read(INIT)?,
        document: dir.read(DOCUMENT)?,
        successions,
        keys: public,
    })
}

impl FileIdentity {
    /// Every record held but the keys the custody keeps, read without writing: what an import
    /// carries to another backend (iteration 03, WP-27.6).
    ///
    /// A reset under way, or a retired identity whose reset is not recorded, refuses: the next
    /// start on files completes it, and an import carries a volume at rest.
    pub fn export(&self) -> Result<Records, IdentityError> {
        let unsettled = || {
            IdentityError::Unavailable(
                "a reset is under way: start the server on files once, so it completes, then \
                 import"
                    .into(),
            )
        };
        if self.dir.read(RESETTING)?.is_some() {
            return Err(unsettled());
        }
        let mut retired = Vec::new();
        for held in self.retired()? {
            let evidence = self.evidence(&held.host_id)?.ok_or_else(unsettled)?;
            let reset = held.reset.ok_or_else(unsettled)?;
            retired.push((held.host_id, reset, public_records(&evidence, None)?));
        }
        Ok(Records {
            current: public_records(&self.dir, Some(&self.keys))?,
            start: self.dir.read(BOOT)?,
            retired,
        })
    }
}

impl IdentityStore for FileIdentity {
    fn init(&self) -> Result<Option<Vec<u8>>, IdentityError> {
        Ok(self.dir.read(INIT)?)
    }

    fn publish_init(&self, record: &[u8]) -> Result<(), IdentityError> {
        let same = |held: &[u8]| held == record;
        match publish_immutable(&self.dir, INIT, record, &same, &same)? {
            Published::Written | Published::AlreadyThere => {}
        }
        crash::point("identity.init_published");
        Ok(())
    }

    fn remove_init(&self) -> Result<(), IdentityError> {
        if self.dir.read(INIT)?.is_some() {
            tombstone::delete(&self.dir, INIT)?;
        }
        crash::point("identity.init_removed");
        Ok(())
    }

    fn document(&self) -> Result<Option<Vec<u8>>, IdentityError> {
        Ok(self.dir.read(DOCUMENT)?)
    }

    fn replace_document(&self, envelope: &[u8]) -> Result<(), IdentityError> {
        write::replace_bytes(&self.dir, DOCUMENT, envelope)?;
        crash::point("identity.document_replaced");
        Ok(())
    }

    fn successions(&self) -> Result<Vec<Value>, IdentityError> {
        Ok(sequence::recover(&self.dir, SUCCESSION, MAX_RECORD_BYTES)?.items)
    }

    fn append_succession(&self, envelope: &[u8]) -> Result<(), IdentityError> {
        sequence::append(&self.dir, SUCCESSION, envelope)?;
        crash::point("identity.succession_added");
        Ok(())
    }

    fn public(&self, epoch: u64) -> Result<Option<Vec<u8>>, IdentityError> {
        Ok(self.keys.read(&public_name(epoch))?)
    }

    fn publish_public(&self, epoch: u64, key: &[u8]) -> Result<(), IdentityError> {
        let same = |held: &[u8]| held == key;
        match publish_immutable(&self.keys, &public_name(epoch), key, &same, &same)? {
            Published::Written | Published::AlreadyThere => {}
        }
        crash::point("identity.public_published");
        Ok(())
    }

    fn remove_public(&self, epoch: u64) -> Result<(), IdentityError> {
        if self.keys.read(&public_name(epoch))?.is_some() {
            tombstone::delete(&self.keys, &public_name(epoch))?;
        }
        Ok(())
    }

    fn held_epochs(&self) -> Result<Vec<HeldEpoch>, IdentityError> {
        let mut held = std::collections::BTreeMap::<u64, HeldEpoch>::new();
        for name in self.keys.names()? {
            let mut parts = name.splitn(2, '.');
            let Some(epoch) = parts.next().and_then(|stem| stem.parse::<u64>().ok()) else {
                continue;
            };
            let entry = held.entry(epoch).or_insert(HeldEpoch {
                epoch,
                public: false,
                private: false,
            });
            match parts.next() {
                Some("pub") if name == public_name(epoch) => entry.public = true,
                Some("key") if name == format!("{epoch}.key") => entry.private = true,
                // Any other file named for an epoch is key material of it all the same.
                _ => {}
            }
        }
        Ok(held.into_values().collect())
    }

    fn started(&self) -> Result<bool, IdentityError> {
        Ok(self.dir.read(BOOT)?.is_some())
    }

    fn record_start(&self, record: &[u8]) -> Result<(), IdentityError> {
        Ok(write::replace_bytes(&self.dir, BOOT, record)?)
    }

    fn clear(&self) -> Result<(), IdentityError> {
        for name in [DOCUMENT, SUCCESSION, BOOT] {
            if self.dir.read(name)?.is_some() {
                tombstone::delete(&self.dir, name)?;
            }
        }
        self.keys.sweep_temps()?;
        tombstone::complete(&self.keys)?;
        for name in self.keys.names()? {
            tombstone::delete(&self.keys, &name)?;
        }
        Ok(())
    }

    fn resetting(&self) -> Result<Option<Vec<u8>>, IdentityError> {
        Ok(self.dir.read(RESETTING)?)
    }

    fn mark_resetting(
        &self,
        _applying: &Applying<'_>,
        host_id: &[u8; 16],
    ) -> Result<(), IdentityError> {
        write::replace_bytes(&self.dir, RESETTING, host_id)?;
        crash::point("identity.reset_marked");
        Ok(())
    }

    fn clear_resetting(&self) -> Result<(), IdentityError> {
        if self.dir.read(RESETTING)?.is_some() {
            tombstone::delete(&self.dir, RESETTING)?;
        }
        Ok(())
    }

    fn retire(
        &self,
        _applying: &Applying<'_>,
        host_id: &[u8; 16],
        reset: &[u8],
    ) -> Result<(), IdentityError> {
        let retired = self
            .dir
            .subdir(RETIRED, true)?
            .subdir(&record::uuid_text(host_id), true)?;
        for name in [INIT, DOCUMENT, SUCCESSION] {
            if let Some(bytes) = self.dir.read(name)? {
                write::replace_bytes(&retired, name, &bytes)?;
            }
        }
        for name in self.keys.names()? {
            if name.ends_with(".pub")
                && let Some(bytes) = self.keys.read(&name)?
            {
                write::replace_bytes(&retired, &format!("{KEYS}-{name}"), &bytes)?;
            }
        }
        write::replace_bytes(&retired, RESET, reset)?;
        crash::point("identity.retired");
        Ok(())
    }

    fn retired(&self) -> Result<Vec<Retired>, IdentityError> {
        if !self.dir.subdirs()?.iter().any(|name| name == RETIRED) {
            return Ok(Vec::new());
        }
        let mut found = Vec::new();
        for host_id in self.dir.subdir(RETIRED, false)?.subdirs()? {
            let Some(evidence) = self.evidence(&host_id)? else {
                continue;
            };
            found.push(Retired {
                reset: evidence.read(RESET)?,
                init: evidence.read(INIT)?.is_some(),
                host_id,
            });
        }
        Ok(found)
    }
}

fn store_of(volume: &Volume) -> Result<Arc<dyn IdentityStore>, IdentityError> {
    Ok(Arc::new(FileIdentity::open(volume)?))
}

fn home_of(volume: &Volume) -> Home {
    Home {
        id: volume.id(),
        generation: volume.generation(),
    }
}

/// Whether `volume` holds a provisioned identity.
pub fn is_provisioned(volume: &Volume) -> Result<bool, StorageError> {
    Ok(directories(volume)?.0.read(INIT)?.is_some())
}

/// The external witness of `volume`'s identity, read from its provisioning record alone and
/// without writing anything: what a start compares before it opens the identity. `None` when the
/// identity is not provisioned.
pub fn witness_of(volume: &Volume) -> Result<Option<String>, IdentityError> {
    let Some(bytes) = directories(volume)?.0.read(INIT)? else {
        return Ok(None);
    };
    let init = Init::decode(&bytes)?;
    Ok(Some(record::witness(
        &bytes,
        &volume.id(),
        &init.fingerprint,
    )))
}

/// The `host_id` the provisioning record names, when the identity is provisioned: what the
/// provider of its keys binds them to before the identity opens (WP-3.2).
pub fn host_id_of(volume: &Volume) -> Result<Option<[u8; 16]>, IdentityError> {
    let Some(bytes) = directories(volume)?.0.read(INIT)? else {
        return Ok(None);
    };
    Ok(Some(Init::decode(&bytes)?.host_id))
}

/// The suite of the current identity document, read without verifying it: which suite the keys
/// on the volume are, before a provider seals them (WP-3.2). The open verifies the document.
pub fn suite_of(volume: &Volume) -> Result<Option<Suite>, IdentityError> {
    let Some(bytes) = directories(volume)?.0.read(DOCUMENT)? else {
        return Ok(None);
    };
    super::suite_of_document(&bytes).map(Some)
}

/// Whether an identity was ever retired on the volume at `root`: what a Host on the file backend
/// that holds no identity store asks, a Data Plane's check of its key versions.
pub fn was_reset_at(root: &std::path::Path) -> bool {
    let retired = root
        .join(crate::storage::volume::HOST)
        .join(DIRECTORY)
        .join(RETIRED);
    std::fs::read_dir(retired)
        .map(|mut entries| entries.any(|entry| entry.is_ok()))
        .unwrap_or(false)
}

impl Identity {
    /// Provisions the identity of `volume`: refused when it is provisioned. Answers the open
    /// identity, its first `boot_id` minted.
    pub fn provision(
        volume: &Volume,
        provider: Arc<dyn KeyProvider>,
        suite: Suite,
        now: u64,
        now_millis: u64,
    ) -> Result<Self, IdentityError> {
        Self::provision_with(volume, |_| Ok(provider), suite, now, now_millis)
    }

    /// [`Identity::provision`] with the provider made for the `host_id` just minted: a sealing
    /// provider binds every key to its Host (WP-3.2).
    pub fn provision_with(
        volume: &Volume,
        provider: impl FnOnce(&[u8; 16]) -> Result<Arc<dyn KeyProvider>, IdentityError>,
        suite: Suite,
        now: u64,
        now_millis: u64,
    ) -> Result<Self, IdentityError> {
        Self::provision_in(
            store_of(volume)?,
            home_of(volume),
            provider,
            suite,
            now,
            now_millis,
        )
    }

    /// Opens the identity of `volume`, verifying it whole, and mints this start's `boot_id`.
    pub fn open(volume: &Volume, provider: Arc<dyn KeyProvider>) -> Result<Self, IdentityError> {
        Self::open_in(store_of(volume)?, home_of(volume), provider)
    }
}

/// The identity a reset under way on `volume` retires, when one is: the start refuses until it
/// is completed.
pub fn marked(volume: &Volume) -> Result<Option<[u8; 16]>, IdentityError> {
    // Read alone: a start that refuses writes nothing.
    directories(volume)?
        .0
        .read(RESETTING)?
        .map(|marker| reset::marked_host(&marker))
        .transpose()
}

/// Completes the reset marked on `volume`: what a reset run again does after a crash (the
/// offline CLI). Answers `None` when no reset is under way.
pub fn resume(
    applying: &Applying<'_>,
    volume: &Volume,
    provisioner: &Provisioner,
    rings: &[Arc<Ring>],
    suite: Suite,
    now: u64,
    now_millis: u64,
) -> Result<Option<Reset>, IdentityError> {
    reset::resume_in(
        applying,
        &FileIdentity::open(volume)?,
        volume.id(),
        provisioner,
        rings,
        suite,
        now,
        now_millis,
    )
}

/// Completes an interrupted reset of `volume` as `initiator`, one operation of the mutation
/// engine (the offline CLI): `None` when no reset is under way.
pub fn resume_run(
    mutations: &crate::operations::mutation::Mutations,
    volume: &Volume,
    provisioner: &Provisioner,
    rings: &[Arc<Ring>],
    suite: Suite,
    initiator: crate::operations::journal::Initiator,
    now: u64,
) -> Result<Option<Reset>, crate::operations::mutation::MutationError<IdentityError>> {
    let store = FileIdentity::open(volume)
        .map_err(|error| crate::operations::mutation::MutationError::Refused(error.into()))?;
    reset::resume_run_in(
        mutations,
        &store,
        volume.id(),
        provisioner,
        rings,
        suite,
        initiator,
        now,
    )
}
