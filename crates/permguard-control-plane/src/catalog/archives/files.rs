// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The file backend of [`ArchiveStore`]: `<zones>/<zone>/archives/<id>/`, three files written
//! once each, the record last.
//!
//! ```text
//! <zones>/<zone>/archives/<id>/
//! ├── ARCHIVE        the archive, verbatim
//! ├── REQUEST.json   the request that kept it
//! └── RECORD.json    what it holds; an archive without one keeps nothing yet
//! ```

use std::path::PathBuf;
use std::sync::Mutex;

use permguard_host::storage::write::publish_immutable;
use permguard_host::storage::{Dir, StorageError};

use super::{ArchiveError, ArchiveStore, Keeping, Requested};
use crate::catalog::imports::ArchiveRecord;

/// The directory of a zone's archives.
pub const ARCHIVES: &str = "archives";
/// The archive file of an archive kept as foreign evidence.
pub const ARCHIVE: &str = "ARCHIVE";
/// Its record.
pub const RECORD: &str = "RECORD.json";
/// The request that kept it, so a retry is answered with it (BUG-0187).
pub const REQUEST: &str = "REQUEST.json";

impl From<StorageError> for ArchiveError {
    fn from(error: StorageError) -> Self {
        Self::Unavailable(Box::new(error))
    }
}

/// The archives below a zones root.
pub struct FileArchives {
    zones_root: PathBuf,
    /// One archive kept at a time: the name and the request id checked free stay free until the
    /// archive is kept.
    keeping: Mutex<()>,
}

impl FileArchives {
    /// The archives below `zones_root`; nothing is created until an archive is kept or asked for.
    pub fn new(zones_root: impl Into<PathBuf>) -> Self {
        Self {
            zones_root: zones_root.into(),
            keeping: Mutex::new(()),
        }
    }

    /// The zone's archives directory, created on first use.
    fn directory(&self, zone: &str) -> Result<Dir, ArchiveError> {
        Ok(Dir::create_root(&self.zones_root.join(zone))?.subdir(ARCHIVES, true)?)
    }

    /// Every archive of `zone` that has its record, with what its request asked when it reads
    /// one.
    fn kept(&self, zone: &str) -> Result<Vec<(ArchiveRecord, Option<Requested>)>, ArchiveError> {
        let dir = self.directory(zone)?;
        let mut kept = Vec::new();
        for id in dir.subdirs()? {
            let archive = dir.subdir(&id, false)?;
            // An archive a crash left without its record holds nothing yet.
            let Some(record) = archive.read(RECORD)? else {
                continue;
            };
            let record = serde_json::from_slice(&record).map_err(|error| {
                ArchiveError::Record(format!("the archive {id}'s record: {error}"))
            })?;
            let asked = archive
                .read(REQUEST)?
                .map(|asked| {
                    serde_json::from_slice(&asked).map_err(|error| {
                        ArchiveError::Record(format!("the archive {id}'s request: {error}"))
                    })
                })
                .transpose()?;
            kept.push((record, asked));
        }
        Ok(kept)
    }
}

impl ArchiveStore for FileArchives {
    fn archived(&self, zone: &str) -> Result<Vec<ArchiveRecord>, ArchiveError> {
        Ok(self
            .kept(zone)?
            .into_iter()
            .map(|(record, _)| record)
            .collect())
    }

    fn kept_by(
        &self,
        zone: &str,
        request_id: &str,
    ) -> Result<Option<(ArchiveRecord, Requested)>, ArchiveError> {
        Ok(self.kept(zone)?.into_iter().find_map(|(record, asked)| {
            asked
                .filter(|asked| asked.request_id == request_id)
                .map(|asked| (record, asked))
        }))
    }

    fn keep(
        &self,
        zone: &str,
        archive: &[u8],
        asked: &Requested,
        record: &ArchiveRecord,
    ) -> Result<Keeping, ArchiveError> {
        let _keeping = self
            .keeping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut named = false;
        for (held, held_asked) in self.kept(zone)? {
            if let Some(held_asked) = held_asked
                && held_asked.request_id == asked.request_id
            {
                return Ok(Keeping::Requested(Box::new(held), held_asked));
            }
            named |= held.name == record.name;
        }
        if named {
            return Ok(Keeping::Named);
        }
        let dir = self.directory(zone)?.subdir(&record.id, true)?;
        let encoded = |what: &str, error: serde_json::Error| {
            ArchiveError::Record(format!("the archive {}'s {what}: {error}", record.id))
        };
        let request = serde_json::to_vec(asked).map_err(|error| encoded("request", error))?;
        let body = serde_json::to_vec(record).map_err(|error| encoded("record", error))?;
        // The record last: an archive without one is not listed, nor answered to a retry.
        for (name, bytes) in [
            (ARCHIVE, archive),
            (REQUEST, request.as_slice()),
            (RECORD, body.as_slice()),
        ] {
            publish_immutable(&dir, name, bytes, &|read| read == bytes, &|held| {
                held == bytes
            })?;
        }
        Ok(Keeping::Kept)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::path::PathBuf;
    use std::sync::Arc;

    use super::*;
    use crate::catalog::archives::suite;

    const ZONE: &str = "01a00000-0000-7000-8000-00000000000a";

    fn scratch(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "permguard-archives-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    fn record(id: &str, name: &str) -> ArchiveRecord {
        ArchiveRecord {
            id: id.to_owned(),
            name: name.to_owned(),
            imported_at: 1_800_000_000,
            manifest_digest: format!("sha256:{}", "ab".repeat(32)),
            source_host_id: "11".repeat(16),
            source_zone_id: "source-zone".to_owned(),
            source_zone_name: "delivery".to_owned(),
            ledgers: Vec::new(),
        }
    }

    fn asked(request_id: &str, record: &ArchiveRecord) -> Requested {
        Requested {
            request_id: request_id.to_owned(),
            name: record.name.clone(),
            manifest_digest: record.manifest_digest.clone(),
        }
    }

    /// The file backend passes the contract's suite, each case below a zones root of its own.
    #[test]
    fn the_file_backend_keeps_the_contract() {
        let made = std::sync::atomic::AtomicUsize::new(0);
        suite::run(&|| {
            let case = made.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Arc::new(FileArchives::new(scratch(&format!("suite-{case}"))))
        });
    }

    /// The archive is kept verbatim, with its request and its record, where the layout says, and
    /// a store opened again reads it.
    #[test]
    fn an_archive_is_kept_verbatim_on_disk() {
        let root = scratch("verbatim");
        let record = record("archive-1", "backup");
        let store = FileArchives::new(&root);
        assert_eq!(
            store
                .keep(ZONE, b"the archive", &asked("import-1", &record), &record)
                .expect("kept"),
            Keeping::Kept
        );
        let directory = root.join(ZONE).join(ARCHIVES).join("archive-1");
        assert_eq!(
            std::fs::read(directory.join(ARCHIVE)).expect("the archive"),
            b"the archive"
        );
        assert_eq!(
            serde_json::from_slice::<ArchiveRecord>(
                &std::fs::read(directory.join(RECORD)).expect("the record")
            )
            .expect("a record"),
            record
        );
        let again = FileArchives::new(&root);
        assert_eq!(
            again.archived(ZONE).expect("listed"),
            std::slice::from_ref(&record)
        );
        assert_eq!(
            again.kept_by(ZONE, "import-1").expect("read"),
            Some((record.clone(), asked("import-1", &record)))
        );
    }

    /// An archive a crash left without its record keeps nothing yet: it is not listed, not
    /// answered to a retry, and neither its name nor its request id is taken.
    #[test]
    fn an_archive_without_its_record_keeps_nothing() {
        let root = scratch("cut");
        let record = record("archive-2", "backup");
        let cut = root.join(ZONE).join(ARCHIVES).join("archive-1");
        std::fs::create_dir_all(&cut).expect("the directory");
        std::fs::write(cut.join(ARCHIVE), b"the archive").expect("the archive");
        std::fs::write(
            cut.join(REQUEST),
            serde_json::to_vec(&asked("import-1", &record)).expect("a request"),
        )
        .expect("the request");
        let store = FileArchives::new(&root);
        assert!(store.archived(ZONE).expect("listed").is_empty());
        assert_eq!(store.kept_by(ZONE, "import-1").expect("read"), None);
        assert_eq!(
            store
                .keep(ZONE, b"the archive", &asked("import-1", &record), &record)
                .expect("kept"),
            Keeping::Kept
        );
        assert_eq!(store.archived(ZONE).expect("listed"), [record]);
    }

    /// A record or a request that does not read is an error, never an archive that is not there.
    #[test]
    fn a_record_that_does_not_read_is_an_error() {
        let root = scratch("damaged");
        let record = record("archive-1", "backup");
        let store = FileArchives::new(&root);
        store
            .keep(ZONE, b"the archive", &asked("import-1", &record), &record)
            .expect("kept");
        let directory = root.join(ZONE).join(ARCHIVES).join("archive-1");
        let request = std::fs::read(directory.join(REQUEST)).expect("the request");
        std::fs::write(directory.join(REQUEST), b"rot").expect("damaged");
        assert!(matches!(
            store.kept_by(ZONE, "import-1"),
            Err(ArchiveError::Record(_))
        ));
        std::fs::write(directory.join(REQUEST), request).expect("repaired");
        std::fs::write(directory.join(RECORD), b"rot").expect("damaged");
        assert!(matches!(store.archived(ZONE), Err(ArchiveError::Record(_))));
        let other = self::record("archive-2", "other");
        assert!(matches!(
            store.keep(ZONE, b"another", &asked("import-2", &other), &other),
            Err(ArchiveError::Record(_))
        ));
    }
}
