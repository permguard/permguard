// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Where the local half lives — the seam both layers of the engine speak.
//!
//! The CLI passes the filesystem implementation rooted at a workspace; a
//! browser would pass one over its own storage; a mirror on a volume would
//! pass one rooted there. Same logic, different shelves — which is why
//! neither layer ever names `std::fs` outside this file.

use std::fs;
use std::path::PathBuf;

/// One consumer's storage. Paths are relative, `/`-separated, and never
/// interpreted by the engine beyond joining segments it validated itself.
pub trait Store: Send + Sync {
    /// Reads a file, `None` when it does not exist.
    fn read(&self, path: &str) -> Result<Option<Vec<u8>>, String>;
    /// Writes a file, creating parents.
    fn write(&self, path: &str, bytes: &[u8]) -> Result<(), String>;
    /// Whether a file exists.
    fn exists(&self, path: &str) -> bool;
    /// Lists the entries of a directory: `(name, is_directory)`. An absent
    /// directory lists empty.
    fn list(&self, path: &str) -> Result<Vec<(String, bool)>, String>;
    /// Creates a file only if it does not exist — atomically, the primitive
    /// the lock is built on. `false` means someone else holds it.
    fn create_exclusive(&self, path: &str, bytes: &[u8]) -> Result<bool, String>;
    /// Removes a file; removing an absent file succeeds.
    fn remove(&self, path: &str) -> Result<(), String>;
}

/// The filesystem implementation.
pub struct FsStore {
    root: PathBuf,
}

impl FsStore {
    /// A store rooted at a directory.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The directory this store lives in.
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }

    fn resolve(&self, path: &str) -> PathBuf {
        let mut resolved = self.root.clone();
        for segment in path.split('/') {
            resolved.push(segment);
        }
        resolved
    }
}

impl Store for FsStore {
    fn read(&self, path: &str) -> Result<Option<Vec<u8>>, String> {
        match fs::read(self.resolve(path)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("reading {path}: {error}")),
        }
    }

    fn write(&self, path: &str, bytes: &[u8]) -> Result<(), String> {
        let resolved = self.resolve(path);
        if let Some(parent) = resolved.parent() {
            fs::create_dir_all(parent).map_err(|error| format!("creating {path}: {error}"))?;
        }
        fs::write(&resolved, bytes).map_err(|error| format!("writing {path}: {error}"))
    }

    fn exists(&self, path: &str) -> bool {
        self.resolve(path).exists()
    }

    fn list(&self, path: &str) -> Result<Vec<(String, bool)>, String> {
        let resolved = self.resolve(path);
        let entries = match fs::read_dir(&resolved) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(format!("listing {path}: {error}")),
        };
        let mut listed = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| format!("listing {path}: {error}"))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let is_dir = entry.path().is_dir();
            listed.push((name, is_dir));
        }
        listed.sort();
        Ok(listed)
    }

    fn create_exclusive(&self, path: &str, bytes: &[u8]) -> Result<bool, String> {
        let resolved = self.resolve(path);
        if let Some(parent) = resolved.parent() {
            fs::create_dir_all(parent).map_err(|error| format!("creating {path}: {error}"))?;
        }
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&resolved)
        {
            Ok(mut file) => {
                use std::io::Write as _;
                file.write_all(bytes)
                    .map_err(|error| format!("writing {path}: {error}"))?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(format!("creating {path}: {error}")),
        }
    }

    fn remove(&self, path: &str) -> Result<(), String> {
        match fs::remove_file(self.resolve(path)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("removing {path}: {error}")),
        }
    }
}
