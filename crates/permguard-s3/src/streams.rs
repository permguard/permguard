// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A stream consumer's runs on PostgreSQL and S3 (iteration 03, WP-27.4): the batches and the
//! ring statements, the signed evidence exactly as its producer sent it, in the bucket; each
//! run's journal, its views and its place in the listing, in the database.
//!
//! | Kept                                   | In                                                   |
//! | -------------------------------------- | ---------------------------------------------------- |
//! | a run, where its journal starts and ends | `permguard_stream_runs`, a row a run               |
//! | a frame of a run's journal             | `permguard_stream_frames`, a row a frame             |
//! | a view of a run, a producer, a resource | `permguard_stream_views`                            |
//! | a batch, a ring statement              | S3, named in `permguard_stream_shelves`              |
//!
//! A run is opened for one holder at a time, on any instance: the holder takes the run's scope
//! on a connection of its own and every statement of the hold runs on that connection, so a
//! holder that lost its connection lost the scope and writes nothing. A file of a shelf is
//! published to the bucket first and named in its row after, and a file is unlinked from its
//! row first and from the bucket after: a row never names bytes the bucket lacks, and bytes no
//! row names are read by nothing.

use permguard_host::storage::StorageError;
use permguard_host::storage::journal::Frame;
use permguard_postgres::{Database, Hold, Row, ToSql};
use permguard_stream::engine::StreamError;
use permguard_stream::engine::consumer::store::{RunFiles, RunStore, Runs};

use crate::{Bucket, Put};

/// The most bytes a batch or a statement read back may hold.
const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;

type Parameters<'a> = &'a [&'a (dyn ToSql + Sync)];

fn failed(what: &str, error: impl std::fmt::Display) -> StreamError {
    StreamError::Storage(StorageError::Io {
        what: what.to_owned(),
        source: std::io::Error::other(error.to_string()),
    })
}

fn index(value: i64) -> Result<u64, StreamError> {
    u64::try_from(value)
        .map_err(|_| StreamError::Corruption("a frame index held is no index".to_owned()))
}

fn stored(value: u64) -> Result<i64, StreamError> {
    i64::try_from(value)
        .map_err(|_| StreamError::Corruption("an index past what the store keeps".to_owned()))
}

/// Where a run's statements run: the holder's own connection, or the pool for a read that takes
/// no hold.
enum Connection {
    Held(Box<Hold>),
    Pool(Database),
}

impl Connection {
    fn query(
        &self,
        what: &str,
        statement: &str,
        parameters: Parameters<'_>,
    ) -> Result<Vec<Row>, StreamError> {
        match self {
            Self::Held(hold) => hold
                .query(statement, parameters)
                .map_err(|error| failed(what, error)),
            Self::Pool(database) => database
                .write(|unit| unit.query(statement, parameters))
                .map_err(|error| failed(what, error)),
        }
    }

    fn execute(
        &self,
        what: &str,
        statement: &str,
        parameters: Parameters<'_>,
    ) -> Result<u64, StreamError> {
        match self {
            Self::Held(hold) => hold
                .execute(statement, parameters)
                .map_err(|error| failed(what, error)),
            Self::Pool(database) => database
                .write(|unit| unit.execute(statement, parameters))
                .map_err(|error| failed(what, error)),
        }
    }
}

/// The runs of one consumer, named `plane/type/version`, in one database and one bucket.
#[derive(Debug, Clone)]
pub struct PostgresRuns {
    database: Database,
    bucket: Bucket,
    consumer: String,
}

impl PostgresRuns {
    /// The runs of the consumer `consumer` kept in `database`, whose schema is this build's,
    /// and in `bucket`.
    pub fn new(database: Database, bucket: Bucket, consumer: &str) -> Self {
        Self {
            database,
            bucket,
            consumer: consumer.to_owned(),
        }
    }

    fn run(
        &self,
        connection: Connection,
        component: &str,
        producer: &str,
        run: &str,
    ) -> PostgresRun {
        PostgresRun {
            connection,
            bucket: self.bucket.clone(),
            consumer: self.consumer.clone(),
            component: component.to_owned(),
            producer: producer.to_owned(),
            run: run.to_owned(),
            first: 0,
            next: 0,
        }
    }

    fn view_at(
        &self,
        component: &str,
        producer: &str,
        name: &str,
    ) -> Result<Option<Vec<u8>>, StreamError> {
        let pool = Connection::Pool(self.database.clone());
        Ok(pool
            .query(
                "reading a view",
                "SELECT bytes FROM permguard_stream_views
                 WHERE consumer = $1 AND component = $2 AND producer = $3 AND run = '' AND name = $4",
                &[&self.consumer, &component, &producer, &name],
            )?
            .pop()
            .map(|row| row.get(0)))
    }

    fn replace_view_at(
        &self,
        component: &str,
        producer: &str,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), StreamError> {
        Connection::Pool(self.database.clone()).execute(
            "replacing a view",
            "INSERT INTO permguard_stream_views (consumer, component, producer, run, name, bytes)
             VALUES ($1, $2, $3, '', $4, $5)
             ON CONFLICT (consumer, component, producer, run, name) DO UPDATE SET bytes = EXCLUDED.bytes",
            &[&self.consumer, &component, &producer, &name, &bytes],
        )?;
        Ok(())
    }

    fn list(
        &self,
        statement: &str,
        parameters: Parameters<'_>,
    ) -> Result<Vec<String>, StreamError> {
        Ok(Connection::Pool(self.database.clone())
            .query("listing the runs", statement, parameters)?
            .into_iter()
            .map(|row| row.get(0))
            .collect())
    }
}

impl Runs for PostgresRuns {
    fn kept_open(&self) -> bool {
        false
    }

    fn open(
        &self,
        component: &str,
        producer: &str,
        run: &str,
        create: bool,
    ) -> Result<Option<Box<dyn RunStore>>, StreamError> {
        let hold = self
            .database
            .hold(&format!(
                "stream-run/{}/{component}/{producer}/{run}",
                self.consumer
            ))
            .map_err(|error| failed("holding a run", error))?;
        let mut held = self.run(Connection::Held(Box::new(hold)), component, producer, run);
        if create {
            held.connection.execute(
                "opening a run",
                "INSERT INTO permguard_stream_runs (consumer, component, producer, run, first_index, next_index)
                 VALUES ($1, $2, $3, $4, 0, 0) ON CONFLICT DO NOTHING",
                &[&self.consumer, &component, &producer, &run],
            )?;
        }
        let Some(row) = held
            .connection
            .query(
                "opening a run",
                "SELECT first_index, next_index FROM permguard_stream_runs
                 WHERE consumer = $1 AND component = $2 AND producer = $3 AND run = $4",
                &[&self.consumer, &component, &producer, &run],
            )?
            .pop()
        else {
            return Ok(None);
        };
        held.first = index(row.get(0))?;
        held.next = index(row.get(1))?;
        Ok(Some(Box::new(held)))
    }

    fn peek(
        &self,
        component: &str,
        producer: &str,
        run: &str,
    ) -> Result<Option<Box<dyn RunFiles>>, StreamError> {
        let exists = !self
            .list(
                "SELECT run FROM permguard_stream_runs
                 WHERE consumer = $1 AND component = $2 AND producer = $3 AND run = $4",
                &[&self.consumer, &component, &producer, &run],
            )?
            .is_empty();
        Ok(exists.then(|| {
            Box::new(self.run(
                Connection::Pool(self.database.clone()),
                component,
                producer,
                run,
            )) as Box<dyn RunFiles>
        }))
    }

    fn producer_view(
        &self,
        component: &str,
        producer: &str,
        name: &str,
    ) -> Result<Option<Vec<u8>>, StreamError> {
        self.view_at(component, producer, name)
    }

    fn replace_producer_view(
        &self,
        component: &str,
        producer: &str,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), StreamError> {
        self.replace_view_at(component, producer, name, bytes)
    }

    fn resource_view(&self, component: &str, name: &str) -> Result<Option<Vec<u8>>, StreamError> {
        self.view_at(component, "", name)
    }

    fn replace_resource_view(
        &self,
        component: &str,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), StreamError> {
        self.replace_view_at(component, "", name, bytes)
    }

    fn components(&self) -> Result<Vec<String>, StreamError> {
        self.list(
            "SELECT DISTINCT component FROM permguard_stream_runs WHERE consumer = $1
             ORDER BY component",
            &[&self.consumer],
        )
    }

    fn producers(&self, component: &str) -> Result<Vec<String>, StreamError> {
        self.list(
            "SELECT DISTINCT producer FROM permguard_stream_runs
             WHERE consumer = $1 AND component = $2 ORDER BY producer",
            &[&self.consumer, &component],
        )
    }

    fn runs(&self, component: &str, producer: &str) -> Result<Vec<String>, StreamError> {
        self.list(
            "SELECT run FROM permguard_stream_runs
             WHERE consumer = $1 AND component = $2 AND producer = $3 ORDER BY run",
            &[&self.consumer, &component, &producer],
        )
    }

    /// The database keeps no room aside: a write it cannot make is refused, whole.
    fn release_reserve(&self, _component: &str, _producer: &str) -> Result<(), StreamError> {
        Ok(())
    }

    fn keep_reserve(&self, _component: &str, _producer: &str) {}
}

/// One run: its journal and views in rows, its shelves in the bucket.
struct PostgresRun {
    connection: Connection,
    bucket: Bucket,
    consumer: String,
    component: String,
    producer: String,
    run: String,
    first: u64,
    next: u64,
}

impl PostgresRun {
    fn key(&self, shelf: &str, name: &str) -> String {
        format!(
            "streams/{}/{}/{}/{}/{shelf}/{name}",
            self.consumer, self.component, self.producer, self.run
        )
    }

    fn named(&self, shelf: &str, name: &str) -> Result<bool, StreamError> {
        Ok(!self
            .connection
            .query(
                "reading a shelf",
                "SELECT 1 FROM permguard_stream_shelves
                 WHERE consumer = $1 AND component = $2 AND producer = $3 AND run = $4
                   AND shelf = $5 AND name = $6",
                &[
                    &self.consumer,
                    &self.component,
                    &self.producer,
                    &self.run,
                    &shelf,
                    &name,
                ],
            )?
            .is_empty())
    }
}

impl RunFiles for PostgresRun {
    fn view(&self, name: &str) -> Result<Option<Vec<u8>>, StreamError> {
        Ok(self
            .connection
            .query(
                "reading a view",
                "SELECT bytes FROM permguard_stream_views
                 WHERE consumer = $1 AND component = $2 AND producer = $3 AND run = $4
                   AND name = $5",
                &[
                    &self.consumer,
                    &self.component,
                    &self.producer,
                    &self.run,
                    &name,
                ],
            )?
            .pop()
            .map(|row| row.get(0)))
    }

    fn read(&self, shelf: &str, name: &str) -> Result<Option<Vec<u8>>, StreamError> {
        // Bytes no row names are no file.
        if !self.named(shelf, name)? {
            return Ok(None);
        }
        let key = self.key(shelf, name);
        self.bucket
            .get(&key, MAX_FILE_BYTES)
            .map_err(|error| failed("reading a file of a shelf", error))?
            .map(Some)
            .ok_or_else(|| StreamError::Corruption(format!("{key} is named and gone")))
    }

    fn names(&self, shelf: &str) -> Result<Vec<String>, StreamError> {
        Ok(self
            .connection
            .query(
                "listing a shelf",
                "SELECT name FROM permguard_stream_shelves
                 WHERE consumer = $1 AND component = $2 AND producer = $3 AND run = $4
                   AND shelf = $5 ORDER BY name",
                &[
                    &self.consumer,
                    &self.component,
                    &self.producer,
                    &self.run,
                    &shelf,
                ],
            )?
            .into_iter()
            .map(|row| row.get(0))
            .collect())
    }
}

impl RunStore for PostgresRun {
    fn frames(&self) -> Result<Vec<Frame>, StreamError> {
        self.frames_from(self.first)
    }

    fn frames_from(&self, from: u64) -> Result<Vec<Frame>, StreamError> {
        let from = stored(from.max(self.first))?;
        self.connection
            .query(
                "reading the journal",
                "SELECT idx, kind, payload FROM permguard_stream_frames
                 WHERE consumer = $1 AND component = $2 AND producer = $3 AND run = $4
                   AND idx >= $5 ORDER BY idx",
                &[
                    &self.consumer,
                    &self.component,
                    &self.producer,
                    &self.run,
                    &from,
                ],
            )?
            .into_iter()
            .map(|row| {
                Ok(Frame {
                    index: index(row.get(0))?,
                    kind: u16::try_from(row.get::<_, i32>(1)).map_err(|_| {
                        StreamError::Corruption("a frame kind held is none".to_owned())
                    })?,
                    claim: 0,
                    payload: row.get(2),
                })
            })
            .collect()
    }

    fn first_index(&self) -> u64 {
        self.first
    }

    fn next_index(&self) -> u64 {
        self.next
    }

    /// Every frame is a place a prefix deletion may end.
    fn segment_starts(&self) -> Vec<u64> {
        (self.first..self.next).collect()
    }

    fn append(&mut self, kind: u16, payload: &[u8]) -> Result<u64, StreamError> {
        // The index and the frame in one statement: the run's next index rises with the frame
        // it gave, or neither.
        let row = self
            .connection
            .query(
                "appending to the journal",
                "WITH given AS (
                     UPDATE permguard_stream_runs SET next_index = next_index + 1
                     WHERE consumer = $1 AND component = $2 AND producer = $3 AND run = $4
                     RETURNING next_index - 1 AS idx
                 )
                 INSERT INTO permguard_stream_frames
                     (consumer, component, producer, run, idx, kind, payload)
                 SELECT $1, $2, $3, $4, given.idx, $5, $6 FROM given
                 RETURNING idx",
                &[
                    &self.consumer,
                    &self.component,
                    &self.producer,
                    &self.run,
                    &i32::from(kind),
                    &payload,
                ],
            )?
            .pop()
            .ok_or_else(|| StreamError::Corruption("a run held has no row".to_owned()))?;
        let given = index(row.get(0))?;
        self.next = given + 1;
        Ok(given)
    }

    fn drop_prefix(&mut self, below: u64) -> Result<u64, StreamError> {
        if below <= self.first {
            return Ok(self.first);
        }
        let below = below.min(self.next);
        // Where the journal starts first: frames left below it are read by nothing, and the
        // next deletion removes them.
        self.connection.execute(
            "dropping a prefix",
            "UPDATE permguard_stream_runs SET first_index = $5
             WHERE consumer = $1 AND component = $2 AND producer = $3 AND run = $4",
            &[
                &self.consumer,
                &self.component,
                &self.producer,
                &self.run,
                &stored(below)?,
            ],
        )?;
        self.first = below;
        self.connection.execute(
            "dropping a prefix",
            "DELETE FROM permguard_stream_frames
             WHERE consumer = $1 AND component = $2 AND producer = $3 AND run = $4 AND idx < $5",
            &[
                &self.consumer,
                &self.component,
                &self.producer,
                &self.run,
                &stored(below)?,
            ],
        )?;
        Ok(below)
    }

    fn replace_view(&self, name: &str, bytes: &[u8]) -> Result<(), StreamError> {
        self.connection.execute(
            "replacing a view",
            "INSERT INTO permguard_stream_views (consumer, component, producer, run, name, bytes)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (consumer, component, producer, run, name) DO UPDATE SET bytes = EXCLUDED.bytes",
            &[&self.consumer, &self.component, &self.producer, &self.run, &name, &bytes],
        )?;
        Ok(())
    }

    fn publish(&self, shelf: &str, name: &str, bytes: &[u8]) -> Result<(), StreamError> {
        let key = self.key(shelf, name);
        // The bytes first: a row never names bytes the bucket lacks.
        let put = self
            .bucket
            .put_new(&key, bytes)
            .map_err(|error| failed("publishing a file of a shelf", error))?;
        if put == Put::Exists {
            let held = self
                .bucket
                .get(&key, MAX_FILE_BYTES)
                .map_err(|error| failed("reading a file of a shelf", error))?;
            if held.as_deref() != Some(bytes) {
                return Err(StreamError::Corruption(format!(
                    "{key} already holds different content under the same name; it is left as it was"
                )));
            }
        }
        self.connection.execute(
            "naming a file of a shelf",
            "INSERT INTO permguard_stream_shelves (consumer, component, producer, run, shelf, name)
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
            &[
                &self.consumer,
                &self.component,
                &self.producer,
                &self.run,
                &shelf,
                &name,
            ],
        )?;
        Ok(())
    }

    fn unlink(&self, shelf: &str, names: &[String]) -> Result<(), StreamError> {
        for name in names {
            // The row first: bytes no row names are read by nothing.
            self.connection.execute(
                "unlinking a file of a shelf",
                "DELETE FROM permguard_stream_shelves
                 WHERE consumer = $1 AND component = $2 AND producer = $3 AND run = $4
                   AND shelf = $5 AND name = $6",
                &[
                    &self.consumer,
                    &self.component,
                    &self.producer,
                    &self.run,
                    &shelf,
                    name,
                ],
            )?;
            self.bucket
                .delete(&self.key(shelf, name))
                .map_err(|error| failed("removing a file of a shelf", error))?;
        }
        Ok(())
    }
}
