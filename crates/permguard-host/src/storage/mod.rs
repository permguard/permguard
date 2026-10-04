// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The storage library: the write patterns of the storage contract, implemented once.
//!
//! | State shape              | Module        | Protocol                                                                                     |
//! | ------------------------ | ------------- | -------------------------------------------------------------------------------------------- |
//! | immutable content object | [`write`]     | temp `O_EXCL` → write → flush → verify → hard link (no replace) → unlink temp → flush parent |
//! | replaceable view         | [`write`]     | sibling temp → flush → rename over → flush parent                                            |
//! | append-only journal      | [`journal`]   | framed, checksummed append → `fdatasync`; only a torn last frame is truncated                |
//! | segment roll             | [`journal`]   | flush old segment → create and flush new header → flush directory                            |
//! | deletion                 | [`tombstone`] | durable tombstone first → unlink → flush parent → remove tombstone → flush parent            |
//! | snapshot cache           | [`snapshot`]  | built from the authoritative journal → atomic replace; revision and digest inside            |
//!
//! Every open below a [`Dir`] is relative to that directory and never follows a symbolic link (on
//! Unix); every format begins with the header of [`format`]; every write and flush goes through
//! [`permguard_core::fault`], so the fault shim of the conformance crate reaches all of them; and
//! every protocol names its crash points ([`crash`]), which the crash-point tests abort at one by
//! one.
//!
//! # Failed flushes are final
//!
//! A failed `fsync` or `fdatasync` is final for the data it covered: the kernel may have dropped the
//! dirty pages, and a later successful call proves nothing about them. Every operation here reports
//! it as [`StorageError::Durability`] and never retries. A [`journal::Journal`] that saw one
//! refuses every later append, turns not ready and records the failure, so the frame whose flush
//! failed is cut when the journal is opened again (WP-1.2). An object's or a ref's bytes are
//! flushed before its name is linked or renamed, so a failed directory flush leaves only the entry
//! unflushed, and a later idempotent answer flushes it again before it succeeds.

pub mod authority;
pub mod crash;
pub mod dir;
pub mod format;
pub mod journal;
pub mod snapshot;
pub mod testing;
pub mod tombstone;
pub mod write;

pub use authority::{Authoritative, Authority, Rebuildable};
pub use dir::Dir;

/// Why a storage operation did not complete.
#[derive(Debug)]
pub enum StorageError {
    /// The operating system refused an operation.
    Io {
        what: String,
        source: std::io::Error,
    },
    /// A flush failed: final for the data it covered, and never retried.
    Durability {
        what: String,
        source: std::io::Error,
    },
    /// A name that is not exactly one path component.
    Name(String),
    /// Content that contradicts what is already durable: an existing name with different content,
    /// a checksum that does not match, a length that runs past the file.
    Corruption(String),
    /// A format this build does not read: another magic, a newer version, an unknown mandatory
    /// flag or a non-zero reserved field.
    Unsupported(String),
    /// A frame over the journal's bound.
    TooLarge(String),
    /// A journal that saw a failed flush, which refuses every later append.
    Poisoned,
    /// A journal this process does not open again: a failed write or flush could not be recorded,
    /// or a repair made while opening it could not be flushed.
    NotRecoverable(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { what, source } => write!(f, "{what}: {source}"),
            Self::Durability { what, source } => {
                write!(f, "{what}: the flush failed and is final: {source}")
            }
            Self::Name(name) => write!(f, "`{name}` is not one path component"),
            Self::Corruption(what) => write!(f, "corruption: {what}"),
            Self::Unsupported(what) => write!(f, "unsupported format: {what}"),
            Self::TooLarge(what) => write!(f, "too large: {what}"),
            Self::Poisoned => f.write_str(
                "this journal saw a failed flush and accepts nothing more until it is recovered",
            ),
            Self::NotRecoverable(what) => write!(f, "not recoverable in this process: {what}"),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } | Self::Durability { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// The library's result.
pub type Result<T> = std::result::Result<T, StorageError>;

pub(crate) fn io(what: impl Into<String>) -> impl FnOnce(std::io::Error) -> StorageError {
    let what = what.into();
    move |source| StorageError::Io { what, source }
}

pub(crate) fn durability(what: impl Into<String>) -> impl FnOnce(std::io::Error) -> StorageError {
    let what = what.into();
    move |source| StorageError::Durability { what, source }
}

/// How this platform meets the storage contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformMode {
    /// Directory flushes and directory-relative no-follow opens: the contract in full.
    Full,
    /// Neither (Windows): a published compatibility mode below the `production` floor.
    Compatibility,
}

/// How this build meets the storage contract on this platform.
pub fn platform_mode() -> PlatformMode {
    if cfg!(unix) {
        PlatformMode::Full
    } else {
        PlatformMode::Compatibility
    }
}
