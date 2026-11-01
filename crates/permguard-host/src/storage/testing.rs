// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The storage contract, as tests other crates run against their own stores.
//!
//! A store that publishes immutable content implements [`ImmutableStore`] in its tests and calls
//! [`immutable_contract`]; a subsystem that keeps a journal of this library runs
//! [`torn_tail_contract`] in the directory it keeps it in. The same assertions, run against every
//! store, are what keeps "the store follows the storage contract" a fact rather than a claim each
//! store makes about itself.

use std::path::{Path, PathBuf};

use super::journal::{Journal, Options, encode_frame};
use super::{Dir, StorageError};

/// Why a store refused to publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// The name holds other content: the corruption H-06 requires.
    Corruption(String),
    /// Anything else.
    Other(String),
}

/// A store that publishes immutable content under a name derived from it.
pub trait ImmutableStore {
    /// Publishes `content`: `Ok(true)` when it was written, `Ok(false)` when it was already there,
    /// and the store's refusal, classified, otherwise.
    fn publish(&self, content: &[u8]) -> Result<bool, Refused>;
    /// The file `content` is published under.
    fn path_of(&self, content: &[u8]) -> PathBuf;
    /// The content held under `content`'s name, as the store reads it back.
    fn read(&self, content: &[u8]) -> Option<Vec<u8>>;
}

/// Republishing is idempotent and rewrites nothing; a name holding different content is refused
/// as corruption and left byte-for-byte as it was (H-06).
///
/// `content` is any content the store accepts; `forged` is a file that is *not* `content`'s stored
/// form, planted under `content`'s name before it is published.
pub fn immutable_contract(store: &dyn ImmutableStore, content: &[u8], forged: &[u8]) {
    assert_eq!(store.publish(content), Ok(true), "the first publish writes");
    let path = store.path_of(content);
    let read = |what: &str| match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("{what}: {} cannot be read: {error}", path.display()),
    };
    let stored = read("after the first publish");
    let inode = identity(&path);
    assert_eq!(
        store.publish(content),
        Ok(false),
        "a republish is idempotent"
    );
    assert_eq!(
        read("after a republish"),
        stored,
        "a republish rewrites nothing"
    );
    assert_eq!(
        identity(&path),
        inode,
        "a republish keeps the original inode"
    );
    assert_eq!(store.read(content).as_deref(), Some(content));

    // The same name, other content: corruption, and the planted file is left exactly as it was.
    if let Err(error) = std::fs::remove_file(&path) {
        panic!("{} cannot be removed: {error}", path.display());
    }
    if let Err(error) = std::fs::write(&path, forged) {
        panic!("{} cannot be planted: {error}", path.display());
    }
    let planted = identity(&path);
    let refused = store.publish(content);
    assert!(
        matches!(refused, Err(Refused::Corruption(_))),
        "a name holding other content is refused as corruption: {refused:?}"
    );
    assert_eq!(
        read("after the refusal"),
        forged,
        "the existing file is left byte-for-byte as it was"
    );
    assert_eq!(identity(&path), planted, "and is the same file");
}

/// The inode a file is, where the platform has one.
fn identity(path: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        match std::fs::metadata(path) {
            Ok(metadata) => Some(metadata.ino()),
            Err(error) => panic!("{} cannot be read: {error}", path.display()),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// A torn final frame is truncated on open and nothing before it moves: run in `path`, the
/// directory a subsystem keeps its journal in, so the filesystem under it is the one checked.
pub fn torn_tail_contract(path: &Path) {
    let open = || {
        Journal::open(
            Dir::open(path).map_err(|error| error.to_string())?,
            Options::default(),
        )
        .map_err(|error| error.to_string())
    };
    let Ok((mut journal, _)) = open() else {
        panic!("the journal at {} opens", path.display());
    };
    let appended = journal.append(1, b"durable");
    assert!(appended.is_ok(), "{appended:?}");
    let segments = journal.segments();
    drop(journal);
    let Some(last) = segments.last() else {
        panic!("a journal has a segment");
    };
    let segment = path.join(last);
    let before = std::fs::read(&segment).unwrap_or_default();
    let mut torn = before.clone();
    let Ok(frame) = encode_frame(1, 0, b"torn") else {
        panic!("a four-byte frame encodes");
    };
    torn.extend_from_slice(&frame[..7]);
    if let Err(error) = std::fs::write(&segment, &torn) {
        panic!("{} cannot be written: {error}", segment.display());
    }

    let reopened = open();
    let Ok((journal, recovery)) = reopened else {
        panic!("a torn tail is repaired, not refused: {reopened:?}");
    };
    assert_eq!(recovery.truncated_bytes, 7);
    assert_eq!(std::fs::read(&segment).unwrap_or_default(), before);
    assert_eq!(journal.frames().map(|frames| frames.len()).ok(), Some(1));
}

/// Whether `error` is the corruption a same-name different-content publish must be.
pub fn is_corruption(error: &StorageError) -> bool {
    matches!(error, StorageError::Corruption(_))
}

/// Every regular file below `root`, at any depth.
pub fn files_below(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("listed").flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// The bytes of `path`, read as a test reads a volume its Host is holding.
///
/// A `LOCK` file (the volume's, a journal's, a spool's) is empty by construction, and on Windows,
/// where locks are mandatory, the process holding it cannot read it either. Its length, which the
/// metadata gives without reading, proves it holds nothing, so a held empty `LOCK` reads as empty.
/// Every other failure is the failure it is.
pub fn read_held(path: &Path) -> std::io::Result<Vec<u8>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(_)
            if path
                .file_name()
                .is_some_and(|name| name == super::volume::LOCK)
                && std::fs::metadata(path).is_ok_and(|metadata| metadata.len() == 0) =>
        {
            Ok(Vec::new())
        }
        Err(error) => Err(error),
    }
}

/// Copies the directory `from` as `cp -Rp from to` does: into `to/<name of from>` when `to` is a
/// directory already, to `to` otherwise, with every directory's permissions. A `LOCK` file is
/// created empty rather than read: it is empty by construction, and a Windows process cannot read
/// one that is held.
pub fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    let to = if to.is_dir() {
        to.join(from.file_name().unwrap_or_default())
    } else {
        to.to_path_buf()
    };
    copy_into(from, &to)
}

fn copy_into(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let source = entry.path();
        let target = to.join(entry.file_name());
        let metadata = std::fs::symlink_metadata(&source)?;
        if metadata.is_dir() {
            copy_into(&source, &target)?;
        } else if entry.file_name() == super::volume::LOCK && metadata.len() == 0 {
            std::fs::File::create(&target)?;
        } else if metadata.is_file() {
            std::fs::copy(&source, &target)?;
        }
    }
    std::fs::set_permissions(to, std::fs::metadata(from)?.permissions())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tree_is_copied_with_its_locks_empty_and_its_files_whole() {
        let root = std::env::temp_dir().join(format!("pg-copy-tree-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let from = root.join("volume");
        std::fs::create_dir_all(from.join("host/keys")).expect("folders");
        std::fs::write(from.join("host/LOCK"), b"").expect("a lock");
        std::fs::write(from.join("host/keys/1.key"), b"key bytes").expect("a key");
        std::fs::create_dir_all(root.join("into")).expect("a target");

        copy_tree(&from, &root.join("into")).expect("copied");
        let copied = root.join("into/volume");
        assert_eq!(read_held(&copied.join("host/LOCK")).expect("read"), b"");
        assert_eq!(
            read_held(&copied.join("host/keys/1.key")).expect("read"),
            b"key bytes"
        );
        assert_eq!(files_below(&copied).len(), 2);
        assert!(read_held(&copied.join("absent")).is_err());
        let _ = std::fs::remove_dir_all(root);
    }
}
