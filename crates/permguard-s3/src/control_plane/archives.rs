// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL and S3 backend of [`ArchiveStore`]: an archive's bytes in the bucket, under
//! `zones/<zone>/archives/<id>`, and its record and its request in `permguard_archives`.
//!
//! | Rule of the contract                      | Kept by                                         |
//! | ----------------------------------------- | ----------------------------------------------- |
//! | a zone keeps one archive a name           | the table's key over the zone and the name      |
//! | a zone keeps one archive a request id     | the table's key over the zone and the request   |
//! | an archive is listed once all of it is kept | the bytes are published first, the row after  |
//!
//! The bytes are an effect outside the database, so the row is their confirmation: an archive
//! has a row only once the bucket holds it. A request that is answered what the zone already
//! keeps removes the bytes it published; a process stopped between the two leaves bytes no row
//! names, which nothing reads as an archive.

use permguard_control_plane::catalog::archives::{ArchiveError, ArchiveStore, Keeping, Requested};
use permguard_control_plane::catalog::imports::ArchiveRecord;
use permguard_postgres::{Database, Failure, Unit};

use crate::{Bucket, Put};

/// The archives of the zones of one database and one bucket.
#[derive(Debug, Clone)]
pub struct PostgresArchives {
    database: Database,
    bucket: Bucket,
}

type Step<T> = Result<T, Failure<ArchiveError>>;

fn unavailable(error: impl std::error::Error + Send + Sync + 'static) -> ArchiveError {
    ArchiveError::Unavailable(Box::new(error))
}

fn read<T: serde::de::DeserializeOwned>(text: &str, what: &str) -> Result<T, ArchiveError> {
    serde_json::from_str(text)
        .map_err(|error| ArchiveError::Record(format!("{what} does not read: {error}")))
}

fn written<T: serde::Serialize>(value: &T, what: &str) -> Result<String, ArchiveError> {
    serde_json::to_string(value)
        .map_err(|error| ArchiveError::Record(format!("{what} does not encode: {error}")))
}

/// The archives `condition` selects in `zone`, each with what its request asked.
fn kept(
    unit: &Unit,
    zone: &str,
    request_id: Option<&str>,
) -> Step<Vec<(ArchiveRecord, Requested)>> {
    unit.query(
        "SELECT record, requested FROM permguard_archives
         WHERE zone = $1 AND ($2::text IS NULL OR request_id = $2) ORDER BY id",
        &[&zone, &request_id],
    )?
    .iter()
    .map(|row| {
        Ok((
            read(row.get(0), "an archive's record").map_err(Failure::Refused)?,
            read(row.get(1), "an archive's request").map_err(Failure::Refused)?,
        ))
    })
    .collect()
}

impl PostgresArchives {
    /// The archives kept in `database`, whose schema is this build's, and in `bucket`.
    pub fn new(database: Database, bucket: Bucket) -> Self {
        Self { database, bucket }
    }

    fn unit<T>(&self, work: impl Fn(&Unit) -> Step<T>) -> Result<T, ArchiveError> {
        self.database.transaction(work).map_err(unavailable)?
    }
}

impl ArchiveStore for PostgresArchives {
    fn sweep_unnamed(
        &self,
        zone: &str,
        older_than: std::time::Duration,
    ) -> Result<usize, ArchiveError> {
        let prefix = format!("zones/{zone}/archives/");
        let named: std::collections::BTreeSet<String> = self.unit(|unit| {
            Ok(unit
                .query(
                    "SELECT id FROM permguard_archives WHERE zone = $1",
                    &[&zone],
                )?
                .into_iter()
                .map(|row| row.get::<_, String>(0))
                .collect())
        })?;
        let before = permguard_core::time::unix_now().saturating_sub(older_than.as_secs());
        let mut removed = 0;
        for listed in self.bucket.list(&prefix).map_err(unavailable)? {
            let Some(id) = listed.key.strip_prefix(&prefix) else {
                continue;
            };
            // A keeping under way publishes its bytes, then writes its record: bytes younger
            // than the grace may be one, and stay.
            if named.contains(id) || listed.modified >= before {
                continue;
            }
            self.bucket.delete(&listed.key).map_err(unavailable)?;
            removed += 1;
        }
        Ok(removed)
    }

    fn archived(&self, zone: &str) -> Result<Vec<ArchiveRecord>, ArchiveError> {
        self.unit(|unit| {
            Ok(kept(unit, zone, None)?
                .into_iter()
                .map(|(record, _)| record)
                .collect())
        })
    }

    fn kept_by(
        &self,
        zone: &str,
        request_id: &str,
    ) -> Result<Option<(ArchiveRecord, Requested)>, ArchiveError> {
        self.unit(|unit| Ok(kept(unit, zone, Some(request_id))?.pop()))
    }

    fn keep(
        &self,
        zone: &str,
        archive: &[u8],
        asked: &Requested,
        record: &ArchiveRecord,
    ) -> Result<Keeping, ArchiveError> {
        let (record_text, asked_text) = (
            written(record, "an archive's record")?,
            written(asked, "an archive's request")?,
        );
        // What the zone already keeps is answered before anything is published.
        let held = |unit: &Unit| -> Step<Option<Keeping>> {
            if let Some((record, asked)) = kept(unit, zone, Some(&asked.request_id))?.pop() {
                return Ok(Some(Keeping::Requested(Box::new(record), asked)));
            }
            let named = unit.query_opt(
                "SELECT 1 FROM permguard_archives WHERE zone = $1 AND name = $2",
                &[&zone, &record.name],
            )?;
            Ok(named.map(|_| Keeping::Named))
        };
        if let Some(keeping) = self.unit(held)? {
            return Ok(keeping);
        }
        // The bytes first: the row that makes them an archive is written only over bytes the
        // bucket holds.
        let key = format!("zones/{zone}/archives/{}", record.id);
        if self.bucket.put_new(&key, archive).map_err(unavailable)? == Put::Exists {
            // The key holds bytes already. Those of an archive that is kept stay as they are;
            // those no row names are what a keeping that stopped left, and give way.
            let named = self.unit(|unit| {
                Ok(unit
                    .query_opt(
                        "SELECT 1 FROM permguard_archives WHERE zone = $1 AND id = $2",
                        &[&zone, &record.id],
                    )?
                    .is_some())
            })?;
            if named {
                return Err(ArchiveError::Record(format!(
                    "the zone already keeps an archive under the id {}",
                    record.id
                )));
            }
            self.bucket.delete(&key).map_err(unavailable)?;
            if self.bucket.put_new(&key, archive).map_err(unavailable)? == Put::Exists {
                return Err(ArchiveError::Unavailable(
                    "another keeping holds the archive's key".into(),
                ));
            }
        }
        let keeping = self.unit(|unit| {
            // Decided again with the write: of the requests that arrive together with one id
            // or one name, on any instance, one writes its row.
            if let Some(keeping) = held(unit)? {
                return Ok(keeping);
            }
            unit.execute(
                "INSERT INTO permguard_archives (zone, id, name, request_id, record, requested)
                 VALUES ($1, $2, $3, $4, $5, $6)",
                &[
                    &zone,
                    &record.id,
                    &record.name,
                    &asked.request_id,
                    &record_text,
                    &asked_text,
                ],
            )?;
            Ok(Keeping::Kept)
        });
        if !matches!(keeping, Ok(Keeping::Kept)) {
            // The bytes are no archive: another request's was kept, or the row was not
            // written. Left behind they would be read by nothing; they are removed, and a
            // removal that fails changes no answer.
            let _ = self.bucket.delete(&key);
        }
        keeping
    }
}
