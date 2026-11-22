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
//!
//! A sealed day takes no record again, and is settled: its bytes are published to the object
//! store under `audit/trails/<class>/<resource digest>/<day>`, the bytes of its day file, and
//! only then are its rows removed and the day marked kept there. The object is the confirmation's
//! precondition, so a settlement that stops anywhere leaves the day readable, from its rows or
//! from its object. A day retention deletes once it is settled is removed with its trail's hold,
//! and its object is named for removal; the object goes after, so a hold that is not kept never
//! loses one. Settling runs at the engine's sweeps, outside every trail's hold and every
//! mutation's transaction.

use std::sync::Arc;
use std::time::Duration;

use permguard_host::audit::Class;
use permguard_host::audit::record::{TrailMeta, genesis};
use permguard_host::audit::store::{Listed, Trails};
use permguard_host::audit::trail::{self, Sealed, State, Trail, TrailStore};
use permguard_host::storage::{Result as StorageResult, StorageError};
use permguard_objects::digest::Digest;

use crate::database::{Database, DbError, Failure, Unit};

/// Where the sealed days of the trails rest once they are settled: an object store, reached
/// through this and nothing else. This package reaches no network client itself, so what
/// implements it is the bucket's own package's (`permguard-s3`).
pub trait Objects: Send + Sync + std::fmt::Debug {
    /// Publishes `bytes` under `key` where the key holds nothing; answers whether it wrote.
    fn put_new(&self, key: &str, bytes: &[u8]) -> Result<bool, String>;
    /// The object under `key`, whole; `None` when the key holds none.
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String>;
    /// Removes the object under `key`; nothing when the key holds none.
    fn delete(&self, key: &str) -> Result<(), String>;
}

/// The audit trails of the Host of one database.
#[derive(Debug, Clone)]
pub struct PostgresTrails {
    database: Database,
    /// Where the sealed days are settled; none, and they stay in their rows.
    objects: Option<Arc<dyn Objects>>,
}

/// The key a settled day is kept under.
fn day_key(class: &str, digest: &str, day: &str) -> String {
    format!("audit/trails/{class}/{digest}/{day}")
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
    /// The trails kept in `database`, whose schema is this build's, every day in its rows.
    pub fn new(database: Database) -> Self {
        Self {
            database,
            objects: None,
        }
    }

    /// These trails, their sealed days settled to `objects`.
    #[must_use]
    pub fn with_objects(mut self, objects: Arc<dyn Objects>) -> Self {
        self.objects = Some(objects);
        self
    }

    fn of(&self, class: Class, resource: &str) -> PostgresTrail {
        PostgresTrail {
            database: self.database.clone(),
            objects: self.objects.clone(),
            class: class.as_str(),
            digest: trail::resource_digest(resource),
        }
    }

    /// Settles the sealed day `day` of the trail `(class, digest)`: its bytes published, then
    /// its rows removed and the day marked settled.
    fn settle_day(
        &self,
        objects: &dyn Objects,
        class: &str,
        digest: &str,
        day: &str,
    ) -> Result<(), String> {
        let trail = PostgresTrail {
            database: self.database.clone(),
            objects: None,
            class: Class::parse(class)
                .ok_or_else(|| format!("`{class}` names no class"))?
                .as_str(),
            digest: digest.to_owned(),
        };
        let bytes = trail.day(day).map_err(|error| error.to_string())?;
        let key = day_key(class, digest, day);
        if !objects.put_new(&key, &bytes)? {
            // A settlement that stopped before its rows went: the object must be these bytes.
            if objects.get(&key)?.as_deref() != Some(bytes.as_slice()) {
                return Err(format!(
                    "{key} holds other bytes than the sealed day; it is left as it was"
                ));
            }
        }
        self.database
            .write(|unit| {
                let marked = unit.execute(
                    "UPDATE permguard_audit_days SET archived = true
                     WHERE class = $1 AND digest = $2 AND day = $3 AND NOT archived",
                    &[&class, &digest, &day],
                )?;
                if marked == 1 {
                    unit.execute(
                        "DELETE FROM permguard_audit_records
                         WHERE class = $1 AND digest = $2 AND day = $3",
                        &[&class, &digest, &day],
                    )?;
                }
                Ok(())
            })
            .map_err(|error| error.to_string())
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

    fn settle(&self) -> Result<usize, String> {
        let Some(objects) = self.objects.as_deref() else {
            return Ok(0);
        };
        // The days no record goes to again: those a seal closed.
        let sealed = self
            .database
            .write(|unit| {
                unit.query(
                    "SELECT day.class, day.digest, day.day
                     FROM permguard_audit_days AS day
                     JOIN permguard_audit_trails AS trail USING (class, digest)
                     WHERE NOT day.archived AND trail.sealed IS NOT NULL
                       AND day.day COLLATE \"C\" <= (trail.sealed || '.cborseq') COLLATE \"C\"
                     ORDER BY day.class, day.digest, day.day",
                    &[],
                )
            })
            .map_err(|error| error.to_string())?;
        let mut settled = 0;
        for row in &sealed {
            self.settle_day(objects, row.get(0), row.get(1), row.get(2))?;
            settled += 1;
        }
        // The objects of the days retention deleted, now that no hold keeps their rows.
        let doomed = self
            .database
            .write(|unit| unit.query("SELECT key FROM permguard_audit_doomed ORDER BY key", &[]))
            .map_err(|error| error.to_string())?;
        for row in &doomed {
            let key: &str = row.get(0);
            objects.delete(key)?;
            self.database
                .write(|unit| {
                    unit.execute("DELETE FROM permguard_audit_doomed WHERE key = $1", &[&key])
                })
                .map_err(|error| error.to_string())?;
            settled += 1;
        }
        Ok(settled)
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

/// One trail: its records, its days, its checkpoints and its anchor, as rows; its settled days
/// as objects.
#[derive(Debug, Clone)]
struct PostgresTrail {
    database: Database,
    objects: Option<Arc<dyn Objects>>,
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
        let settled = self.unit("reading a day", |unit| {
            Ok(unit
                .query_opt(
                    "SELECT archived FROM permguard_audit_days
                     WHERE class = $1 AND digest = $2 AND day = $3",
                    &[&self.class, &self.digest, &name],
                )?
                .is_some_and(|row| row.get::<_, bool>(0)))
        })?;
        if settled {
            let key = day_key(self.class, &self.digest, name);
            let objects = self.objects.as_deref().ok_or_else(|| {
                failed(
                    "reading a settled day",
                    "no object store is composed to read it from",
                )
            })?;
            return objects
                .get(&key)
                .map_err(|error| failed("reading a settled day", error))?
                .ok_or_else(|| {
                    StorageError::Corruption(format!("{} is settled and its object is gone", key))
                });
        }
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
            // A settled day's object goes after the hold that removes the day is kept.
            unit.execute(
                "INSERT INTO permguard_audit_doomed (key)
                 SELECT $4 FROM permguard_audit_days
                 WHERE class = $1 AND digest = $2 AND day = $3 AND archived
                 ON CONFLICT (key) DO NOTHING",
                &[
                    &self.class,
                    &self.digest,
                    &name,
                    &day_key(self.class, &self.digest, name),
                ],
            )?;
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
