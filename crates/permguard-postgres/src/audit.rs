// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL backend of the audit engine's storage: [`Trails`] and the [`TrailStore`] of
//! each trail (`1-architecture/5` Stores).
//!
//! | Kept                    | In                                                             |
//! | ----------------------- | -------------------------------------------------------------- |
//! | where a trail continues | `permguard_audit_trails`, a row a trail                        |
//! | a record                | `permguard_audit_records`, a row a record, by its sequence     |
//! | a day                   | `permguard_audit_days`, a row a day file of the trail          |
//! | a checkpoint            | `permguard_audit_checkpoints`, with the co-signatures          |
//! | the anchor              | the trail's row                                                |
//!
//! | Rule of the contract                         | Kept by                                          |
//! | -------------------------------------------- | ------------------------------------------------ |
//! | one holder of a trail at a time              | the trail's row, locked for the holder's transaction |
//! | a sequence is given once                     | the key of the records' table                    |
//! | a record and where the trail continues agree | written in one transaction                       |
//! | a checkpoint is published once               | the key of the checkpoints' table                |
//!
//! A trail is held inside the transaction of whoever holds it. Held from inside a mutation, it
//! is held in the mutation's own transaction: the change and its audit record are kept
//! together or not at all (iteration 03, decision E24). Nothing of a trail is kept in the
//! process: every instance continues a trail from its row.
//!
//! A record is the canonical bytes the file backend writes, and a day read from here is the
//! bytes of the day file it would be.

use std::time::Duration;

use permguard_host::audit::Class;
use permguard_host::audit::record::{TrailMeta, genesis};
use permguard_host::audit::store::{Listed, Trails};
use permguard_host::audit::trail::{self, Sealed, State, Trail, TrailStore};
use permguard_host::storage::{Result as StorageResult, StorageError};
use permguard_objects::digest::Digest;

use crate::database::{Database, DbError, Failure, Unit};

/// The audit trails of the Host of one database.
#[derive(Debug, Clone)]
pub struct PostgresTrails {
    database: Database,
}

fn failed(what: &str, error: impl std::fmt::Display) -> StorageError {
    StorageError::Io {
        what: what.to_owned(),
        source: std::io::Error::other(error.to_string()),
    }
}

fn corrupt(detail: &str) -> Failure<StorageError> {
    Failure::Refused(StorageError::Corruption(detail.to_owned()))
}

fn digest(bytes: Option<Vec<u8>>, what: &str) -> Result<Option<Digest>, Failure<StorageError>> {
    bytes
        .map(|bytes| {
            <[u8; 32]>::try_from(bytes)
                .map(Digest::from_raw)
                .map_err(|_| corrupt(&format!("{what} held is no digest")))
        })
        .transpose()
}

fn sequence(seq: u64) -> Result<i64, Failure<StorageError>> {
    i64::try_from(seq).map_err(|_| corrupt("a sequence past what the store keeps"))
}

impl PostgresTrails {
    /// The trails kept in `database`, whose schema is this build's.
    pub fn new(database: Database) -> Self {
        Self { database }
    }

    fn of(&self, class: Class, resource: &str) -> PostgresTrail {
        PostgresTrail {
            database: self.database.clone(),
            class: class.as_str(),
            digest: trail::resource_digest(resource),
        }
    }
}

/// Where the trail of `row` continues.
fn state_of(row: &postgres::Row) -> Result<State, Failure<StorageError>> {
    let last_checkpoint = match row.get::<_, Option<String>>(4) {
        None => None,
        Some(name) => Some(Sealed {
            name,
            digest: digest(row.get(5), "a checkpoint's digest")?
                .ok_or_else(|| corrupt("a checkpoint held has no digest"))?,
            last_seq: u64::try_from(row.get::<_, Option<i64>>(6).unwrap_or(-1))
                .map_err(|_| corrupt("a checkpoint held covers no sequence"))?,
            head: digest(row.get(7), "a checkpoint's head")?
                .ok_or_else(|| corrupt("a checkpoint held has no head"))?,
        }),
    };
    Ok(State {
        next_seq: u64::try_from(row.get::<_, i64>(0))
            .map_err(|_| corrupt("a trail's next sequence held is none"))?,
        previous: digest(Some(row.get(1)), "a trail's head")?
            .ok_or_else(|| corrupt("a trail held has no head"))?,
        last_day: row.get(2),
        last_checkpoint,
        sealed: row.get(3),
    })
}

impl Trails for PostgresTrails {
    fn hold(
        &self,
        class: Class,
        resource: &str,
        retention: Option<Duration>,
        work: &mut dyn FnMut(&mut Trail) -> bool,
    ) -> Result<(), String> {
        let store = self.of(class, resource);
        let meta = TrailMeta {
            class: class.as_str().to_owned(),
            resource: resource.to_owned(),
        }
        .encode()
        .map_err(|error| error.to_string())?;
        // Run again when the database could not serialize the transaction with another's: the
        // work is then given the trail as that one left it.
        let work = std::cell::RefCell::new(work);
        let held = self.database.transaction(|unit| {
            // The trail's row is its name in the listing, written before any record of it.
            unit.execute(
                "INSERT INTO permguard_audit_trails
                     (class, digest, resource, meta, next_seq, previous)
                 VALUES ($1, $2, $3, $4, 0, $5)
                 ON CONFLICT (class, digest) DO NOTHING",
                &[
                    &store.class,
                    &store.digest,
                    &resource,
                    &meta,
                    &genesis().raw().as_slice(),
                ],
            )?;
            // Locked until the holder's transaction ends: the next holder, on any instance,
            // reads the trail as this one left it.
            let row = unit.query_one(
                "SELECT next_seq, previous, last_day, sealed, checkpoint_name,
                        checkpoint_digest, checkpoint_last_seq, checkpoint_head, resource
                 FROM permguard_audit_trails WHERE class = $1 AND digest = $2 FOR UPDATE",
                &[&store.class, &store.digest],
            )?;
            if row.get::<_, &str>(8) != resource {
                return Err(corrupt(
                    "the trail kept under this digest is of another resource",
                ));
            }
            let before = state_of(&row)?;
            let mut trail = Trail::resume(
                Box::new(store.clone()),
                class,
                resource,
                retention,
                before.clone(),
            );
            if !(*work.borrow_mut())(&mut trail) {
                // What the work did is not kept: the trail stays as it was held.
                return Err(Failure::Refused(StorageError::Corruption(String::new())));
            }
            let after = trail.state();
            if after != before {
                let sealed = after.last_checkpoint.as_ref();
                unit.execute(
                    "UPDATE permguard_audit_trails
                     SET next_seq = $3, previous = $4, last_day = $5, sealed = $6,
                         checkpoint_name = $7, checkpoint_digest = $8,
                         checkpoint_last_seq = $9, checkpoint_head = $10
                     WHERE class = $1 AND digest = $2",
                    &[
                        &store.class,
                        &store.digest,
                        &sequence(after.next_seq)?,
                        &after.previous.raw().as_slice(),
                        &after.last_day,
                        &after.sealed,
                        &sealed.map(|sealed| sealed.name.as_str()),
                        &sealed.map(|sealed| sealed.digest.raw().as_slice()),
                        &sealed.map(|sealed| sequence(sealed.last_seq)).transpose()?,
                        &sealed.map(|sealed| sealed.head.raw().as_slice()),
                    ],
                )?;
            }
            Ok(())
        });
        match held {
            Ok(Ok(())) => Ok(()),
            // The work said the trail is not as it says: nothing of it was kept.
            Ok(Err(StorageError::Corruption(detail))) if detail.is_empty() => Ok(()),
            Ok(Err(error)) => Err(error.to_string()),
            Err(error) => Err(error.to_string()),
        }
    }

    fn view(&self, class: Class, resource: &str) -> Result<Option<Box<dyn TrailStore>>, String> {
        let store = self.of(class, resource);
        let held = self
            .database
            .write(|unit| {
                unit.query_opt(
                    "SELECT 1 FROM permguard_audit_trails WHERE class = $1 AND digest = $2",
                    &[&store.class, &store.digest],
                )
            })
            .map_err(|error| error.to_string())?;
        Ok(held.map(|_| Box::new(store) as Box<dyn TrailStore>))
    }

    fn held(&self) -> Result<Vec<Listed>, String> {
        let rows = self
            .database
            .write(|unit| {
                unit.query(
                    "SELECT class, digest, resource FROM permguard_audit_trails
                     ORDER BY class, digest",
                    &[],
                )
            })
            .map_err(|error| error.to_string())?;
        Ok(rows
            .into_iter()
            .filter_map(|row| {
                let class = Class::parse(row.get(0))?;
                let digest: String = row.get(1);
                let resource: String = row.get(2);
                // A row naming a resource kept under another digest would open another trail.
                let resource = if trail::resource_digest(&resource) == digest {
                    Ok(resource)
                } else {
                    Err("its row names a resource kept under another digest".to_owned())
                };
                Some((class, digest, resource))
            })
            .collect())
    }
}

/// One trail: its records, its days, its checkpoints and its anchor, as rows.
#[derive(Debug, Clone)]
struct PostgresTrail {
    database: Database,
    class: &'static str,
    digest: String,
}

impl PostgresTrail {
    fn unit<T>(
        &self,
        what: &str,
        work: impl Fn(&Unit) -> Result<T, Failure<StorageError>>,
    ) -> StorageResult<T> {
        self.database
            .transaction(work)
            .map_err(|error: DbError| failed(what, error))?
    }
}

impl TrailStore for PostgresTrail {
    fn place(&self, name: &str) -> String {
        if name.is_empty() {
            format!("the audit trail {}/{}", self.class, self.digest)
        } else {
            format!("{name} of the audit trail {}/{}", self.class, self.digest)
        }
    }

    /// A trail's row is written when it is first held, with its class and resource: there is
    /// nothing an interrupted write leaves here.
    fn prepare(&self, _meta: &[u8]) -> StorageResult<()> {
        Ok(())
    }

    fn days(&self) -> StorageResult<Vec<String>> {
        self.unit("listing the days", |unit| {
            Ok(unit
                .query(
                    "SELECT day FROM permguard_audit_days
                     WHERE class = $1 AND digest = $2 ORDER BY day COLLATE \"C\"",
                    &[&self.class, &self.digest],
                )?
                .into_iter()
                .map(|row| row.get(0))
                .collect())
        })
    }

    fn day(&self, name: &str) -> StorageResult<Vec<u8>> {
        self.unit("reading a day", |unit| {
            let mut bytes = Vec::new();
            for row in unit.query(
                "SELECT record FROM permguard_audit_records
                 WHERE class = $1 AND digest = $2 AND day = $3 ORDER BY seq",
                &[&self.class, &self.digest, &name],
            )? {
                bytes.extend_from_slice(row.get(0));
            }
            Ok(bytes)
        })
    }

    fn append(&self, name: &str, seq: u64, record: &[u8]) -> StorageResult<()> {
        self.unit("appending a record", |unit| {
            unit.execute(
                "INSERT INTO permguard_audit_days (class, digest, day) VALUES ($1, $2, $3)
                 ON CONFLICT (class, digest, day) DO NOTHING",
                &[&self.class, &self.digest, &name],
            )?;
            // A sequence is given once: a second record under it is refused by the key.
            unit.execute(
                "INSERT INTO permguard_audit_records (class, digest, seq, day, record)
                 VALUES ($1, $2, $3, $4, $5)",
                &[&self.class, &self.digest, &sequence(seq)?, &name, &record],
            )?;
            Ok(())
        })
    }

    /// A record is a row, whole or absent: there is never a torn one to cut.
    fn cut(&self, _name: &str, _to: u64) -> StorageResult<()> {
        Ok(())
    }

    fn remove_day(&self, name: &str) -> StorageResult<()> {
        self.unit("removing a day", |unit| {
            unit.execute(
                "DELETE FROM permguard_audit_records
                 WHERE class = $1 AND digest = $2 AND day = $3",
                &[&self.class, &self.digest, &name],
            )?;
            unit.execute(
                "DELETE FROM permguard_audit_days WHERE class = $1 AND digest = $2 AND day = $3",
                &[&self.class, &self.digest, &name],
            )?;
            Ok(())
        })
    }

    fn checkpoint_names(&self) -> StorageResult<Vec<String>> {
        self.unit("listing the checkpoints", |unit| {
            Ok(unit
                .query(
                    "SELECT name FROM permguard_audit_checkpoints
                     WHERE class = $1 AND digest = $2 ORDER BY name COLLATE \"C\"",
                    &[&self.class, &self.digest],
                )?
                .into_iter()
                .map(|row| row.get(0))
                .collect())
        })
    }

    fn checkpoint(&self, name: &str) -> StorageResult<Option<Vec<u8>>> {
        self.unit("reading a checkpoint", |unit| {
            Ok(unit
                .query_opt(
                    "SELECT envelope FROM permguard_audit_checkpoints
                     WHERE class = $1 AND digest = $2 AND name = $3",
                    &[&self.class, &self.digest, &name],
                )?
                .map(|row| row.get(0)))
        })
    }

    fn publish_checkpoint(&self, name: &str, envelope: &[u8]) -> StorageResult<()> {
        self.unit("publishing a checkpoint", |unit| {
            // Published once: of the envelopes that arrive together under a name one is kept,
            // and every other caller is judged against it.
            unit.execute(
                "INSERT INTO permguard_audit_checkpoints (class, digest, name, envelope)
                 VALUES ($1, $2, $3, $4) ON CONFLICT (class, digest, name) DO NOTHING",
                &[&self.class, &self.digest, &name, &envelope],
            )?;
            let held: Vec<u8> = unit
                .query_one(
                    "SELECT envelope FROM permguard_audit_checkpoints
                     WHERE class = $1 AND digest = $2 AND name = $3",
                    &[&self.class, &self.digest, &name],
                )?
                .get(0);
            if held == envelope {
                Ok(())
            } else {
                Err(corrupt(&format!(
                    "{} already holds another envelope; it is left as it was",
                    self.place(name)
                )))
            }
        })
    }

    fn anchor(&self) -> StorageResult<Option<Vec<u8>>> {
        self.unit("reading the anchor", |unit| {
            Ok(unit
                .query_opt(
                    "SELECT anchor FROM permguard_audit_trails WHERE class = $1 AND digest = $2",
                    &[&self.class, &self.digest],
                )?
                .and_then(|row| row.get(0)))
        })
    }

    fn replace_anchor(&self, anchor: &[u8]) -> StorageResult<()> {
        self.unit("replacing the anchor", |unit| {
            unit.execute(
                "UPDATE permguard_audit_trails SET anchor = $3 WHERE class = $1 AND digest = $2",
                &[&self.class, &self.digest, &anchor],
            )?;
            Ok(())
        })
    }
}
