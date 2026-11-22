// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The file backend of [`SeenStore`]: `host/peers/`.
//!
//! ```text
//! host/peers/
//! └── <host_id>.cbor   {1 host_id, 2 epoch, 3 fingerprint of that epoch's key, 4 at}
//! ```

use std::sync::{Mutex, PoisonError};

use super::{PeerRefusal, Seen, SeenStore, check};
use crate::identity::Verified;
use crate::identity::record::uuid_text;
use crate::storage::volume::Volume;
use crate::storage::{Dir, StorageError, write};

/// The directory below `host/`.
pub const DIRECTORY: &str = "peers";

/// The seen epochs of one volume.
pub struct FileSeen {
    dir: Dir,
    /// Serializes the seen-epoch updates, so two sessions never move one backwards.
    advancing: Mutex<()>,
}

impl std::fmt::Debug for FileSeen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileSeen").finish_non_exhaustive()
    }
}

fn file(host_id: &[u8; 16]) -> String {
    format!("{}.cbor", uuid_text(host_id))
}

impl FileSeen {
    /// The seen epochs `volume` keeps, their directory created when absent.
    pub fn open(volume: &Volume) -> Result<Self, StorageError> {
        let dir = volume.host().subdir(DIRECTORY, true)?;
        dir.sweep_temps()?;
        Ok(Self {
            dir,
            advancing: Mutex::new(()),
        })
    }
}

impl SeenStore for FileSeen {
    fn seen(&self, host_id: &[u8; 16]) -> Result<Option<Seen>, PeerRefusal> {
        let Some(bytes) = self.dir.read(&file(host_id))? else {
            return Ok(None);
        };
        let seen = Seen::decode(&bytes)?;
        if &seen.host_id != host_id {
            return Err(PeerRefusal::Storage(format!(
                "{} names another Host",
                file(host_id)
            )));
        }
        Ok(Some(seen))
    }

    fn advance(&self, verified: &Verified, at: u64) -> Result<(), PeerRefusal> {
        let _advancing = self
            .advancing
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(seen) = self.seen(&verified.host_id)? {
            check(&seen, verified)?;
            if seen.epoch == verified.epoch {
                return Ok(());
            }
        }
        let seen = Seen {
            host_id: verified.host_id,
            epoch: verified.epoch,
            fingerprint: verified.fingerprint().to_owned(),
            at,
        };
        write::replace_bytes(&self.dir, &file(&verified.host_id), &seen.encode()?)?;
        Ok(())
    }
}

impl From<StorageError> for PeerRefusal {
    fn from(error: StorageError) -> Self {
        Self::Storage(error.to_string())
    }
}
