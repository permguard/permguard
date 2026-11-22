// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The file backend of [`VersionWitnesses`]: one text file a scope, a line an entry, the label
//! and the witness parted by a tab.
//!
//! ```text
//! <working dir>/operations/state/audit-pseudonym-versions                  the server's
//! <working dir>/realms/<name>/operations/state/audit-pseudonym-versions    a realm's
//! ```
//!
//! The file is `0600` in a directory `0700`, and replaced whole through the storage library, so
//! a crash never leaves a half-written witness that the next start would read as a key change.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use super::{Change, VersionWitnesses, VersionsError};

/// Where the witnesses are kept below the working directory, and below a realm's.
const WITNESS_FILE: &str = "operations/state/audit-pseudonym-versions";

/// The versions' witnesses below one working directory.
#[derive(Debug)]
pub struct FileVersionWitnesses {
    working_dir: PathBuf,
    /// Held from the read of a file to the write that replaces it.
    updating: Mutex<()>,
}

impl FileVersionWitnesses {
    /// The witnesses kept below `working_dir`; nothing is created before the first is kept.
    pub fn new(working_dir: impl Into<PathBuf>) -> Self {
        Self {
            working_dir: working_dir.into(),
            updating: Mutex::new(()),
        }
    }

    /// The file of `realm`'s witnesses, the server's own when `None`.
    pub fn path(&self, realm: Option<&str>) -> PathBuf {
        Self::path_below(&self.working_dir, realm)
    }

    /// The file of `realm`'s witnesses below `working_dir`, the server's own when `None`.
    pub fn path_below(working_dir: &Path, realm: Option<&str>) -> PathBuf {
        match realm {
            None => working_dir.join(WITNESS_FILE),
            Some(realm) => working_dir.join("realms").join(realm).join(WITNESS_FILE),
        }
    }
}

fn failed(doing: &str, path: &Path, error: impl std::fmt::Display) -> VersionsError {
    VersionsError(format!("{doing} {}: {error}", path.display()))
}

fn read(path: &Path) -> Result<Vec<(String, String)>, VersionsError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(failed("reading", path, error)),
    };
    Ok(text
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .map(|(version, witness)| (version.to_owned(), witness.to_owned()))
        .collect())
}

fn write(path: &Path, entries: &[(String, String)]) -> Result<(), VersionsError> {
    let (parent, name) = path
        .parent()
        .zip(path.file_name().and_then(|name| name.to_str()))
        .ok_or_else(|| VersionsError(format!("{} names no file", path.display())))?;
    std::fs::create_dir_all(parent).map_err(|error| failed("creating", parent, error))?;
    restrict(parent, 0o700)?;
    let text: String = entries
        .iter()
        .map(|(version, witness)| format!("{version}\t{witness}\n"))
        .collect();
    let dir = crate::storage::Dir::create_root(parent)
        .map_err(|error| failed("opening", parent, error))?;
    crate::storage::write::replace_bytes(&dir, name, text.as_bytes())
        .map_err(|error| failed("writing", path, error))?;
    restrict(path, 0o600)
}

/// Narrows permissions where the platform has them.
#[cfg(unix)]
fn restrict(path: &Path, mode: u32) -> Result<(), VersionsError> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|error| failed("restricting", path, error))
}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) -> Result<(), VersionsError> {
    Ok(())
}

impl VersionWitnesses for FileVersionWitnesses {
    fn update(&self, realm: Option<&str>, change: Change<'_>) -> Result<(), VersionsError> {
        let _updating = self.updating.lock().unwrap_or_else(PoisonError::into_inner);
        let path = self.path(realm);
        let mut entries = read(&path)?;
        if change(&mut entries) {
            write(&path, &entries)?;
        }
        Ok(())
    }

    fn place(&self, realm: Option<&str>) -> String {
        self.path(realm).display().to_string()
    }
}
