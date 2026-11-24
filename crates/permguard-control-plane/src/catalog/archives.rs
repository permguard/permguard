// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The contract of the store that keeps the archives a zone imported as foreign evidence
//! (`3-control-plane/1` Stores).
//!
//! An archive is kept verbatim, once, with the request that kept it and the record of what it
//! holds. It is never a ledger and never served. The store keeps the two rules that make a kept
//! archive one import: a zone keeps one archive a name, and one archive a request id.
//!
//! | Backend            | Keeps a zone's archives in                                         |
//! | ------------------ | ------------------------------------------------------------------ |
//! | [`files`], default | `<zones>/<zone>/archives/<id>/{ARCHIVE, REQUEST.json, RECORD.json}` |
//! | `permguard-s3`     | the bytes on S3, the record and the request in PostgreSQL         |

pub mod files;
#[cfg(any(test, feature = "test-support"))]
pub mod suite;

use serde::{Deserialize, Serialize};

pub use files::FileArchives;

use super::imports::ArchiveRecord;

/// What an archive keeps of the request that imported it: its id, and what the request asked,
/// the name and the manifest. A retry naming the same id and asking the same is answered with the
/// archive; the same id asking anything else is `request_id_reused`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Requested {
    pub request_id: String,
    pub name: String,
    pub manifest_digest: String,
}

/// What keeping an archive did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Keeping {
    /// The archive is kept.
    Kept,
    /// The zone already keeps an archive under this request id: its record, and what that
    /// request asked. Nothing was written.
    Requested(Box<ArchiveRecord>, Requested),
    /// The zone already keeps an archive of this name, under another request. Nothing was
    /// written.
    Named,
}

/// Why the store of the archives could not answer.
#[derive(Debug)]
pub enum ArchiveError {
    /// A kept archive's record or request does not read.
    Record(String),
    /// The store could not be read or written.
    Unavailable(Box<dyn std::error::Error + Send + Sync>),
}

impl std::fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Record(detail) => write!(f, "a kept archive does not read: {detail}"),
            Self::Unavailable(error) => write!(f, "the archives are not available: {error}"),
        }
    }
}

impl std::error::Error for ArchiveError {}

/// The archives the zones keep. `zone` is a catalog id.
pub trait ArchiveStore: Send + Sync {
    /// The record of every archive `zone` keeps. An archive whose record does not read is an
    /// error, never an archive that is not there.
    fn archived(&self, zone: &str) -> Result<Vec<ArchiveRecord>, ArchiveError>;

    /// The archive the request `request_id` kept in `zone`, with what that request asked.
    fn kept_by(
        &self,
        zone: &str,
        request_id: &str,
    ) -> Result<Option<(ArchiveRecord, Requested)>, ArchiveError>;

    /// Keeps `archive` in `zone` under `record.id`, with the request that asks it, unless the
    /// zone already keeps one under `asked.request_id` or under `record.name`. The whole rule
    /// is this call: of the requests that arrive together with one id or one name, one keeps
    /// its archive and the others are answered what is kept. An archive is listed and answered
    /// to a retry once all of it is kept, never part of it.
    fn keep(
        &self,
        zone: &str,
        archive: &[u8],
        asked: &Requested,
        record: &ArchiveRecord,
    ) -> Result<Keeping, ArchiveError>;

    /// Removes what a keeping that stopped between publishing an archive's bytes and writing its
    /// record left in `zone`, older than `older_than`: bytes no record names. Answers how many
    /// archives' bytes it removed. A backend that keeps the bytes and the record together has
    /// none to remove (iteration 03, WP-28.2).
    fn sweep_unnamed(
        &self,
        _zone: &str,
        _older_than: std::time::Duration,
    ) -> Result<usize, ArchiveError> {
        Ok(0)
    }
}
