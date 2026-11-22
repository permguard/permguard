// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL and S3 backend of [`LedgerStore`]: a ledger's objects in a bucket, everything
//! else in the database.
//!
//! | Record           | Kept in                                                              |
//! | ---------------- | -------------------------------------------------------------------- |
//! | object           | S3, under `zones/<zone>/ledgers/<ledger>/objects/<2 hex>/<62 hex>`   |
//! | ref              | `permguard_ledger_refs`, a row a ref, with the operation that moved it |
//! | head statement   | `permguard_ledger_statements`                                        |
//! | root             | `permguard_ledger_roots`                                             |
//! | transfer session | `permguard_ledger_transfers`                                         |
//!
//! | Rule of the contract                      | Kept by                                              |
//! | ----------------------------------------- | ---------------------------------------------------- |
//! | an object lands once                      | the bucket publishes a key only where it holds none  |
//! | an object is served while it hashes right | hashed again at every read                           |
//! | a ref moves from the state that was read  | written only where the row still is that state       |
//! | the sessions are one holder's at a time   | a scope of the ledger, held on the holder's connection |
//!
//! An object is the canonical bytes its digest names, as they are: the bucket holds what a
//! digest can be checked against with no tool of this product. Nothing of a ledger is kept in
//! the process: every instance reads the same rows and the same bucket.

use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use permguard_control_plane::store::{
    Landed, LedgerStore, Ledgers, RefState, RefUpdate, StoreError, StoredObject, TransferSessions,
    ref_digest,
};
use permguard_control_plane::transfer::Transfers;
use permguard_host::operations::mutation::Applying;
use permguard_notp::ExpectedRef;
use permguard_objects::digest::Digest;
use permguard_objects::grammar;
use permguard_objects::limits;
use permguard_objects::object::{self, Object, ObjectError};
use permguard_postgres::{Database, DbError, Failure, Hold, SqlError, Unit};

use crate::{Bucket, Put, S3Error};

type Result<T> = std::result::Result<T, StoreError>;

fn backend(context: &str, error: impl std::fmt::Display) -> StoreError {
    StoreError::Backend {
        detail: format!("{context}: {error}"),
    }
}

fn database(error: DbError) -> StoreError {
    backend("the database", error)
}

fn statement(error: SqlError) -> StoreError {
    backend("the database", error)
}

fn bucket(error: S3Error) -> StoreError {
    backend("the object store", error)
}

/// The ledgers of one database and one bucket.
#[derive(Debug, Clone)]
pub struct PostgresLedgers {
    database: Database,
    bucket: Bucket,
}

impl PostgresLedgers {
    /// The ledgers kept in `database`, whose schema is this build's, and in `bucket`.
    pub fn new(database: Database, bucket: Bucket) -> Self {
        Self { database, bucket }
    }
}

impl Ledgers for PostgresLedgers {
    fn ledger(&self, zone: &str, ledger: &str) -> Arc<dyn LedgerStore> {
        Arc::new(PostgresLedger {
            database: self.database.clone(),
            bucket: self.bucket.clone(),
            zone: zone.to_owned(),
            ledger: ledger.to_owned(),
        })
    }
}

/// One ledger. It holds nothing of its own: two of one ledger, in one process or in two, are
/// the same store.
#[derive(Debug, Clone)]
struct PostgresLedger {
    database: Database,
    bucket: Bucket,
    zone: String,
    ledger: String,
}

fn hex(digest: &Digest) -> String {
    permguard_core::encoding::hex(digest.raw())
}

fn digest_of(text: &str, what: &str) -> std::result::Result<Digest, StoreError> {
    Digest::parse(text).map_err(|_| StoreError::Backend {
        detail: format!("{what} held is no digest"),
    })
}

/// A ref's row: its state and the operation that wrote it.
fn state_of(row: &permguard_postgres::Row) -> std::result::Result<RefState, StoreError> {
    Ok(RefState {
        head: digest_of(row.get(0), "a ref's head")?,
        counter: u64::try_from(row.get::<_, i64>(1)).map_err(|_| StoreError::Backend {
            detail: "a ref's counter held is no counter".to_owned(),
        })?,
        previous_ref_digest: row
            .get::<_, Option<&str>>(2)
            .map(|previous| digest_of(previous, "a ref's previous digest"))
            .transpose()?,
    })
}

impl PostgresLedger {
    /// Where the objects of this ledger are, in the bucket.
    fn objects(&self) -> String {
        format!("zones/{}/ledgers/{}/objects/", self.zone, self.ledger)
    }

    fn key(&self, digest: &Digest) -> String {
        let hex = hex(digest);
        let (fan, rest) = hex.split_at(2);
        format!("{}{fan}/{rest}", self.objects())
    }

    fn unit<T>(
        &self,
        work: impl Fn(&Unit) -> std::result::Result<T, Failure<StoreError>>,
    ) -> Result<T> {
        self.database.transaction(work).map_err(database)?
    }

    fn current(
        &self,
        unit: &Unit,
        name: &str,
    ) -> std::result::Result<Option<RefState>, Failure<StoreError>> {
        unit.query_opt(
            "SELECT head, counter, previous FROM permguard_ledger_refs
             WHERE zone = $1 AND ledger = $2 AND name = $3",
            &[&self.zone, &self.ledger, &name],
        )?
        .as_ref()
        .map(state_of)
        .transpose()
        .map_err(Failure::Refused)
    }
}

impl LedgerStore for PostgresLedger {
    fn has_object(&self, digest: &Digest) -> bool {
        // A bucket that does not answer holds nothing a negotiation can count on.
        matches!(self.bucket.head(&self.key(digest)), Ok(Some(_)))
    }

    fn publish_object(&self, bytes: &[u8]) -> Result<(Digest, Object, Landed)> {
        if bytes.len() > limits::MAX_OBJECT_BYTES {
            return Err(ObjectError::Limit("object bytes").into());
        }
        let decoded = object::decode(bytes)?;
        let digest = Digest::compute(bytes);
        let key = self.key(&digest);
        let landed = match self.bucket.put_new(&key, bytes).map_err(bucket)? {
            Put::Written => Landed::Written,
            Put::Exists => {
                // The key holds an object already: this one, or the name is corrupt.
                let held = self
                    .bucket
                    .get(&key, limits::MAX_OBJECT_BYTES)
                    .map_err(bucket)?;
                if held.as_deref() != Some(bytes) {
                    return Err(StoreError::Corrupt { digest });
                }
                Landed::AlreadyThere
            }
        };
        Ok((digest, decoded, landed))
    }

    fn get_object(&self, digest: &Digest) -> Result<Option<Vec<u8>>> {
        let Some(bytes) = self
            .bucket
            .get(&self.key(digest), limits::MAX_OBJECT_BYTES)
            .map_err(bucket)?
        else {
            return Ok(None);
        };
        if Digest::compute(&bytes) != *digest {
            return Err(StoreError::Corrupt {
                digest: digest.clone(),
            });
        }
        Ok(Some(bytes))
    }

    fn list_objects(&self) -> Result<Vec<StoredObject>> {
        let mut held = Vec::new();
        for object in self.bucket.list(&self.objects()).map_err(bucket)? {
            // A key that is no digest is not this store's: it is no object, and nothing here
            // has an opinion about it.
            let Some(digest) = object
                .key
                .strip_prefix(&self.objects())
                .and_then(|name| name.split_once('/'))
                .filter(|(fan, rest)| fan.len() == 2 && rest.len() == 62)
                .and_then(|(fan, rest)| Digest::parse(&format!("sha256:{fan}{rest}")).ok())
            else {
                continue;
            };
            held.push(StoredObject {
                digest,
                bytes: object.bytes,
                modified: UNIX_EPOCH + Duration::from_secs(object.modified),
            });
        }
        Ok(held)
    }

    fn remove_object(&self, digest: &Digest) -> Result<u64> {
        let key = self.key(digest);
        let Some(bytes) = self.bucket.head(&key).map_err(bucket)? else {
            return Ok(0);
        };
        self.bucket.delete(&key).map_err(bucket)?;
        Ok(bytes)
    }

    fn keep_roots(&self, heads: &[Digest]) -> Result<()> {
        self.unit(|unit| {
            for head in heads {
                unit.execute(
                    "INSERT INTO permguard_ledger_roots (zone, ledger, head) VALUES ($1, $2, $3)
                     ON CONFLICT (zone, ledger, head) DO NOTHING",
                    &[&self.zone, &self.ledger, &head.to_string()],
                )?;
            }
            Ok(())
        })
    }

    fn roots(&self) -> Result<Vec<Digest>> {
        let mut roots = self.unit(|unit| {
            unit.query(
                "SELECT head FROM permguard_ledger_roots WHERE zone = $1 AND ledger = $2",
                &[&self.zone, &self.ledger],
            )?
            .iter()
            .map(|row| digest_of(row.get(0), "a root").map_err(Failure::Refused))
            .collect::<std::result::Result<Vec<_>, _>>()
        })?;
        roots.sort();
        Ok(roots)
    }

    fn read_ref(&self, name: &str) -> Result<Option<RefState>> {
        grammar::validate_ref_name(name)?;
        self.unit(|unit| self.current(unit, name))
    }

    fn ref_operation(&self, name: &str) -> Result<Option<String>> {
        grammar::validate_ref_name(name)?;
        self.unit(|unit| {
            Ok(unit
                .query_opt(
                    "SELECT operation FROM permguard_ledger_refs
                     WHERE zone = $1 AND ledger = $2 AND name = $3",
                    &[&self.zone, &self.ledger, &name],
                )?
                .map(|row| row.get(0)))
        })
    }

    fn list_refs(&self) -> Result<Vec<(String, RefState)>> {
        self.unit(|unit| {
            unit.query(
                "SELECT head, counter, previous, name FROM permguard_ledger_refs
                 WHERE zone = $1 AND ledger = $2 ORDER BY name COLLATE \"C\"",
                &[&self.zone, &self.ledger],
            )?
            .iter()
            .map(|row| Ok((row.get(3), state_of(row).map_err(Failure::Refused)?)))
            .collect()
        })
    }

    fn update_ref(
        &self,
        applying: &Applying<'_>,
        name: &str,
        expected: Option<&ExpectedRef>,
        new: &Digest,
    ) -> Result<RefUpdate> {
        grammar::validate_ref_name(name)?;
        let operation = applying.operation_id().to_string();
        self.unit(|unit| {
            let current = self.current(unit, name)?;
            if let Some(state) = &current
                && state.head == *new
            {
                return Ok(RefUpdate::AlreadyCurrent(state.clone()));
            }
            let conflict = |current| Failure::Refused(StoreError::Conflict { current });
            let refused = |error: StoreError| Failure::Refused(error);
            // The row is written only where it still is the state that was read: of the
            // updates that read one state and arrive together, on any instance and in
            // whatever unit of work, one writes it and the others are told what is current.
            let (state, written) = match (expected, &current) {
                (None, None) => {
                    let state = RefState::first(new.clone());
                    let written = unit.execute(
                        "INSERT INTO permguard_ledger_refs
                             (zone, ledger, name, head, counter, previous, operation)
                         VALUES ($1, $2, $3, $4, 1, NULL, $5)
                         ON CONFLICT (zone, ledger, name) DO NOTHING",
                        &[
                            &self.zone,
                            &self.ledger,
                            &name,
                            &new.to_string(),
                            &operation,
                        ],
                    )?;
                    (state, written)
                }
                (Some(expected), Some(held))
                    if expected.counter == held.counter
                        && expected.digest == ref_digest(held).map_err(refused)? =>
                {
                    let state = held
                        .successor(new.clone())
                        .map_err(|error| refused(backend("the next ref state", error)))?;
                    let counter = |counter: u64| {
                        i64::try_from(counter)
                            .map_err(|_| refused(backend("a ref's counter", "past its range")))
                    };
                    let written = unit.execute(
                        "UPDATE permguard_ledger_refs
                         SET head = $4, counter = $5, previous = $6, operation = $7
                         WHERE zone = $1 AND ledger = $2 AND name = $3
                           AND head = $8 AND counter = $9",
                        &[
                            &self.zone,
                            &self.ledger,
                            &name,
                            &state.head.to_string(),
                            &counter(state.counter)?,
                            &state.previous_ref_digest.as_ref().map(ToString::to_string),
                            &operation,
                            &held.head.to_string(),
                            &counter(held.counter)?,
                        ],
                    )?;
                    (state, written)
                }
                _ => return Err(conflict(current)),
            };
            if written == 1 {
                Ok(RefUpdate::Updated(state))
            } else {
                Err(conflict(self.current(unit, name)?))
            }
        })
    }

    /// A ref is durable when its transaction is committed: there is nothing left to do.
    fn make_ref_durable(&self, _name: &str) -> Result<()> {
        Ok(())
    }

    /// An object is durable when the bucket answered its publication.
    fn make_durable(&self, _digests: &std::collections::BTreeSet<Digest>) -> Result<()> {
        Ok(())
    }

    /// Nothing is written in two steps here: a publication is one request, whole or absent.
    fn sweep_temporaries(&self, _older_than: Duration) -> Result<usize> {
        Ok(0)
    }

    fn verify_at_load(&self) -> Result<usize> {
        let refs = self.list_refs()?;
        for (name, state) in &refs {
            let held = self.bucket.head(&self.key(&state.head)).map_err(bucket)?;
            if held.is_none() {
                return Err(StoreError::Backend {
                    detail: format!(
                        "the ref {name} names the head {} the store does not hold",
                        state.head
                    ),
                });
            }
        }
        Ok(refs.len())
    }

    fn write_signature(&self, name: &str, envelope: &[u8]) -> Result<()> {
        grammar::validate_ref_name(name)?;
        self.unit(|unit| {
            unit.execute(
                "INSERT INTO permguard_ledger_statements (zone, ledger, name, envelope)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (zone, ledger, name) DO UPDATE SET envelope = EXCLUDED.envelope",
                &[&self.zone, &self.ledger, &name, &envelope],
            )?;
            Ok(())
        })
    }

    fn read_signature(&self, name: &str) -> Result<Option<Vec<u8>>> {
        grammar::validate_ref_name(name)?;
        self.unit(|unit| {
            Ok(unit
                .query_opt(
                    "SELECT envelope FROM permguard_ledger_statements
                     WHERE zone = $1 AND ledger = $2 AND name = $3",
                    &[&self.zone, &self.ledger, &name],
                )?
                .map(|row| row.get(0)))
        })
    }

    fn transfers(&self) -> Result<Transfers<'_>> {
        let hold = self
            .database
            .hold(&format!("ledger-transfers/{}/{}", self.zone, self.ledger))
            .map_err(database)?;
        Ok(Transfers::new(
            self,
            Box::new(Sessions {
                hold,
                zone: &self.zone,
                ledger: &self.ledger,
            }),
        ))
    }

    fn stored_bytes(&self) -> Result<u64> {
        Ok(self
            .bucket
            .list(&self.objects())
            .map_err(bucket)?
            .iter()
            .map(|object| object.bytes)
            .sum())
    }
}

/// A ledger's sessions, under the scope its holder holds: read and written on the holder's
/// connection, so a holder that lost the scope writes nothing.
struct Sessions<'a> {
    hold: Hold,
    zone: &'a str,
    ledger: &'a str,
}

impl TransferSessions for Sessions<'_> {
    fn get(&self, transfer_id: &[u8; 16]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .hold
            .query_opt(
                "SELECT record FROM permguard_ledger_transfers
                 WHERE zone = $1 AND ledger = $2 AND transfer_id = $3",
                &[&self.zone, &self.ledger, &transfer_id.as_slice()],
            )
            .map_err(statement)?
            .map(|row| row.get(0)))
    }

    fn list(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self
            .hold
            .query(
                "SELECT record FROM permguard_ledger_transfers
                 WHERE zone = $1 AND ledger = $2 ORDER BY transfer_id",
                &[&self.zone, &self.ledger],
            )
            .map_err(statement)?
            .iter()
            .map(|row| row.get(0))
            .collect())
    }

    fn put(&self, transfer_id: &[u8; 16], record: &[u8]) -> Result<()> {
        self.hold
            .execute(
                "INSERT INTO permguard_ledger_transfers (zone, ledger, transfer_id, record)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (zone, ledger, transfer_id) DO UPDATE SET record = EXCLUDED.record",
                &[&self.zone, &self.ledger, &transfer_id.as_slice(), &record],
            )
            .map_err(statement)?;
        Ok(())
    }

    fn remove(&self, transfer_id: &[u8; 16]) -> Result<()> {
        self.hold
            .execute(
                "DELETE FROM permguard_ledger_transfers
                 WHERE zone = $1 AND ledger = $2 AND transfer_id = $3",
                &[&self.zone, &self.ledger, &transfer_id.as_slice()],
            )
            .map_err(statement)?;
        Ok(())
    }
}
