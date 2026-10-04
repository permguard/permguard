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
