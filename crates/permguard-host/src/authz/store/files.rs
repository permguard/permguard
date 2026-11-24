// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The file backend of [`BootstrapStore`]: `host/authz/bootstrap.cbor`.
//!
//! ```text
//! host/authz/
//! └── bootstrap.cbor    immutable commitment to the recovery principal's certificate
//! ```
//!
//! The file is published without replacement: of two commitments that arrive together the
//! filesystem keeps one, and the other reads it.

use super::{AuthzError, Bootstrap, BootstrapStore, bootstrap_principal};
use crate::operations::mutation::Applying;
use crate::storage::dir::Dir;
use crate::storage::volume::Volume;
use crate::storage::write::{Published, publish_immutable};
use crate::storage::{Rebuildable, StorageError};

/// The directory below `host/`.
pub const DIRECTORY: &str = "authz";
const BOOTSTRAP: &str = "bootstrap.cbor";

/// The recovery principal's commitment on one volume.
pub struct FileBootstrap {
    dir: Rebuildable<Dir>,
}

impl std::fmt::Debug for FileBootstrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileBootstrap").finish_non_exhaustive()
    }
}

impl FileBootstrap {
    /// The commitment of `volume`, its directory created when absent. A commitment that does not
    /// read refuses the open.
    pub fn open(volume: &Volume) -> Result<Self, AuthzError> {
        let store = Self {
            dir: Rebuildable::new(volume.host().subdir(DIRECTORY, true)?),
        };
        store.bootstrap()?;
        Ok(store)
    }
}

impl BootstrapStore for FileBootstrap {
    fn bootstrap(&self) -> Result<Option<Bootstrap>, AuthzError> {
        let Some(bytes) = self.dir.get().read(BOOTSTRAP)? else {
            return Ok(None);
        };
        Bootstrap::decode(&bytes).map(Some).ok_or_else(|| {
            AuthzError::Record(format!(
                "{} does not read as a bootstrap commitment",
                self.dir.get().child_path(BOOTSTRAP).display()
            ))
        })
    }

    fn commit(
        &self,
        _applying: &Applying<'_>,
        fingerprint: &str,
        now: u64,
    ) -> Result<(Bootstrap, bool), AuthzError> {
        let principal = bootstrap_principal(fingerprint)?;
        let commitment = Bootstrap {
            principal: principal.clone(),
            fingerprint: fingerprint.trim().to_ascii_lowercase(),
            created_at: now,
        };
        let bytes = commitment.encode()?;
        let same_principal = |existing: &[u8]| {
            Bootstrap::decode(existing).is_some_and(|held| held.principal == principal)
        };
        let published = publish_immutable(
            self.dir.get(),
            BOOTSTRAP,
            &bytes,
            &|content| Bootstrap::decode(content).is_some(),
            &same_principal,
        )
        .map_err(|error| match error {
            StorageError::Corruption(_) => AuthzError::Invalid(format!(
                "{} already commits to another recovery principal; a bootstrap is written once",
                self.dir.get().child_path(BOOTSTRAP).display()
            )),
            other => AuthzError::from(other),
        })?;
        let held = self.bootstrap()?.unwrap_or(commitment);
        Ok((held, matches!(published, Published::Written)))
    }
}

impl From<StorageError> for AuthzError {
    fn from(error: StorageError) -> Self {
        Self::Unavailable(Box::new(error))
    }
}
