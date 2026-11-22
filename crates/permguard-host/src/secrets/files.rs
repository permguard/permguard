// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The file backends of [`WitnessStore`] and [`DeliveredKeys`].
//!
//! ```text
//! host/state/witness/<reference>/<version>                              a root's witness
//! host/state/witness/zone-use/<authority>/<zone>/<purpose>/<scope>/<v>  a delivered key's witness
//! host/zone-use/<authority>/<zone>/<purpose>/<scope>/<version>          a delivered key (0600)
//! ```
//!
//! Every file is published without replacement: of two that arrive together under one name the
//! filesystem keeps one, and the other reads it.

use std::sync::Arc;

use zeroize::Zeroizing;

use permguard_objects::crypto::kdf::KEY_LEN;

use super::{
    DeliveredKeys, KeyVersion, SecretsError, WitnessStore, Witnesses, ZONE_USE, ZoneKeys,
    ZonePurpose, ZoneTuple, parse_uuid,
};
use crate::identity::record::uuid_text;
use crate::storage::volume::Volume;
use crate::storage::{Dir, StorageError, write};

/// The witnesses' directory below `host/state/`.
pub const WITNESS: &str = "witness";

/// The directory `path` names below `dir`, each part created when absent.
fn below(dir: &Dir, path: &[String]) -> Result<Option<Dir>, SecretsError> {
    let mut found: Option<Dir> = None;
    for part in path {
        found = Some(found.as_ref().unwrap_or(dir).subdir(part, true)?);
    }
    Ok(found)
}

/// The subdirectory `name` of `dir`, when it exists.
fn existing(dir: &Dir, name: &str) -> Result<Option<Dir>, SecretsError> {
    if dir.subdirs()?.iter().any(|held| held == name) {
        Ok(Some(dir.subdir(name, false)?))
    } else {
        Ok(None)
    }
}

/// The witnesses of one volume.
#[derive(Debug)]
pub struct FileWitnesses {
    dir: Dir,
}

impl FileWitnesses {
    /// `host/state/witness/` of `volume`, created `0700`.
    pub fn open(volume: &Volume) -> Result<Self, SecretsError> {
        let dir = volume.host().subdir("state", true)?.subdir(WITNESS, true)?;
        dir.sweep_temps()?;
        Ok(Self { dir })
    }
}

impl WitnessStore for FileWitnesses {
    fn first(&self, name: &[String], witness: &[u8; 32]) -> Result<Vec<u8>, SecretsError> {
        let (file, parents) = name
            .split_last()
            .ok_or_else(|| SecretsError::Storage("an empty witness path".to_owned()))?;
        let dir = below(&self.dir, parents)?;
        let dir = dir.as_ref().unwrap_or(&self.dir);
        if let Some(held) = dir.read(file)? {
            return Ok(held);
        }
        // Whatever is there by now is the first: the caller compares.
        write::publish_immutable(dir, file, witness, &|_| true, &|_| true)?;
        dir.read(file)?
            .ok_or_else(|| SecretsError::Storage(format!("the witness {file} vanished")))
    }
}

impl Witnesses {
    /// The witnesses `volume` keeps: the file backend's.
    pub fn open(volume: &Volume) -> Result<Self, SecretsError> {
        Ok(Self::new(Arc::new(FileWitnesses::open(volume)?)))
    }
}

/// The delivered zone keys of one volume.
#[derive(Debug)]
pub struct FileDeliveredKeys {
    dir: Dir,
}

impl FileDeliveredKeys {
    /// `host/zone-use/` of `volume`, created `0700`.
    pub fn open(volume: &Volume) -> Result<Self, SecretsError> {
        let dir = volume.host().subdir(ZONE_USE, true)?;
        dir.sweep_temps()?;
        Ok(Self { dir })
    }

    /// The directory of `tuple`'s key, when it exists.
    fn directory(&self, tuple: &ZoneTuple) -> Result<Option<Dir>, SecretsError> {
        let path = tuple.path();
        let mut dir: Option<Dir> = None;
        for part in &path[..path.len() - 1] {
            match existing(dir.as_ref().unwrap_or(&self.dir), part)? {
                Some(next) => dir = Some(next),
                None => return Ok(None),
            }
        }
        Ok(dir)
    }

    fn read(
        dir: &Dir,
        tuple: &ZoneTuple,
    ) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>, SecretsError> {
        let Some(held) = dir.read(&tuple.version.to_string())? else {
            return Ok(None);
        };
        let held = Zeroizing::new(held);
        let key: [u8; KEY_LEN] = held.as_slice().try_into().map_err(|_| {
            SecretsError::Storage(format!("{} is not a key", tuple.path().join("/")))
        })?;
        Ok(Some(Zeroizing::new(key)))
    }
}

impl DeliveredKeys for FileDeliveredKeys {
    fn keep(
        &self,
        tuple: &ZoneTuple,
        key: &[u8; KEY_LEN],
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, SecretsError> {
        let path = tuple.path();
        let dir = below(&self.dir, &path[..path.len() - 1])?
            .ok_or_else(|| SecretsError::Storage("the zone key directory".to_owned()))?;
        if let Some(held) = Self::read(&dir, tuple)? {
            return Ok(held);
        }
        // Whatever is there by now is the first: the caller compares.
        write::publish_immutable(&dir, &tuple.version.to_string(), key, &|_| true, &|_| true)?;
        Self::read(&dir, tuple)?
            .ok_or_else(|| SecretsError::Storage(format!("the key {} vanished", path.join("/"))))
    }

    fn key(&self, tuple: &ZoneTuple) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>, SecretsError> {
        let Some(dir) = self.directory(tuple)? else {
            return Ok(None);
        };
        Self::read(&dir, tuple)
    }

    fn delivered(
        &self,
        authority: &[u8; 16],
        purpose: ZonePurpose,
        version: KeyVersion,
    ) -> Result<Vec<ZoneTuple>, SecretsError> {
        let mut found = Vec::new();
        let Some(authority_dir) = existing(&self.dir, &uuid_text(authority))? else {
            return Ok(found);
        };
        for zone in authority_dir.subdirs()? {
            let Some(zone_id) = parse_uuid(&zone) else {
                continue;
            };
            let zone_dir = authority_dir.subdir(&zone, false)?;
            if !zone_dir
                .subdirs()?
                .iter()
                .any(|name| ZonePurpose::parse(name) == Some(purpose))
            {
                continue;
            }
            let purpose_dir = zone_dir.subdir(purpose.as_str(), false)?;
            for scope in purpose_dir.subdirs()? {
                let Some(scope_id) = parse_uuid(&scope) else {
                    continue;
                };
                let tuple = ZoneTuple {
                    authority: *authority,
                    zone: zone_id,
                    purpose,
                    scope: scope_id,
                    version,
                };
                if purpose_dir
                    .subdir(&scope, false)?
                    .read(&version.to_string())?
                    .is_some()
                {
                    found.push(tuple);
                }
            }
        }
        Ok(found)
    }
}

impl ZoneKeys {
    /// The delivered keys `volume` keeps, with its witnesses: the file backend's.
    pub fn open(volume: &Volume) -> Result<Self, SecretsError> {
        Ok(Self::new(
            Arc::new(FileDeliveredKeys::open(volume)?),
            Witnesses::new(Arc::new(FileWitnesses::open(volume)?)),
        ))
    }
}

impl From<StorageError> for SecretsError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error.to_string())
    }
}
