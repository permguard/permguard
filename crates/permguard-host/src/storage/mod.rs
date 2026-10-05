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
pub mod probe;
pub mod qualify;
pub mod quota;
pub mod snapshot;
pub mod testing;
pub mod tombstone;
pub mod verify;
pub mod volume;
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
    /// A journal handle given up after a failed write or flush: it refuses every later append and
    /// read for good, and the journal is recovered by opening it again, as a new handle.
    Poisoned,
    /// A journal this process does not open again: a failed write or flush could not be recorded,
    /// or a repair made while opening it could not be flushed.
    NotRecoverable(String),
    /// A write would pass the quota of a scope of its path; nothing was written.
    QuotaExceeded(String),
    /// A write would take free space below what its writer must leave: the emergency floor for an
    /// ordinary writer, the maintenance reserve for garbage collection and retention; nothing was
    /// written.
    BelowFloor(String),
    /// The volume's `LOCK` is held by another process on this mount.
    Held(String),
    /// A volume operation the volume's state does not permit: serving without a claim where the
    /// profile requires one, or a claim that does not increase.
    Refused(String),
    /// A frame carries a lower claim generation than a frame before it: a writer whose claim was
    /// superseded appended after the takeover (H-05).
    StaleWriter {
        journal: String,
        index: u64,
        generation: u64,
        after: u64,
    },
    /// A frame carries a claim generation above the volume's current claim: the claim is stale,
    /// rolled back or inconsistent with the data.
    ClaimBehindData {
        journal: String,
        index: u64,
        generation: u64,
        claim: u64,
    },
}

impl StorageError {
    /// The registered code of a fencing incident, the evidence an operator's runbook branches on.
    pub fn code(&self) -> Option<&'static str> {
        match self {
            Self::StaleWriter { .. } => Some(permguard_core::codes::storage::STALE_WRITER),
            Self::ClaimBehindData { .. } => Some(permguard_core::codes::storage::CLAIM_BEHIND_DATA),
            _ => None,
        }
    }
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
                "this journal handle saw a failed write or flush and accepts nothing more; open the \
                 journal again to recover it",
            ),
            Self::NotRecoverable(what) => write!(f, "not recoverable in this process: {what}"),
            Self::QuotaExceeded(what) => write!(f, "over quota: {what}"),
            Self::BelowFloor(what) => write!(f, "below the emergency floor: {what}"),
            Self::Held(what) => write!(f, "the volume is held: {what}"),
            Self::Refused(what) => write!(f, "refused: {what}"),
            Self::StaleWriter {
                journal,
                index,
                generation,
                after,
            } => write!(
                f,
                "stale writer in {journal}: frame {index} carries claim generation {generation} \
                 after a frame of generation {after}; a writer whose claim was superseded wrote \
                 after the takeover, and nothing is replayed until the fence is re-established"
            ),
            Self::ClaimBehindData {
                journal,
                index,
                generation,
                claim,
            } => write!(
                f,
                "claim behind the data in {journal}: frame {index} carries claim generation \
                 {generation}, above the volume's claim {claim}; the claim is stale or rolled \
                 back, and nothing is replayed"
            ),
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
