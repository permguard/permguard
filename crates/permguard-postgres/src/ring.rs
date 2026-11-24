// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL backend of [`RingStore`]: the records of one ring of one database, each table
//! keyed by the ring's name.
//!
//! | Record       | Kept in                                                     |
//! | ------------ | ----------------------------------------------------------- |
//! | entry        | `permguard_ring_entries`, a row a sequence                  |
//! | view         | `permguard_ring_records`, the row `view`                    |
//! | binding      | `permguard_ring_records`, the row `binding`                 |
//! | kept binding | `permguard_ring_kept_bindings`, a row a `bound` entry       |
//! | public key   | `permguard_ring_public_keys`, a row a thumbprint            |
//! | retired ring | `permguard_ring_evidence`, the rows of a retired Host       |
//!
//! An entry is the one after the last by the table's key: of the transitions that arrive
//! together, on any instance, one row is written and the others learn the ring moved.

use permguard_host::identity::record::uuid_text;
use permguard_host::keys::ring::RingError;
use permguard_host::keys::ring::store::{Exported, Records, RingStore};
use permguard_host::operations::mutation::Applying;
use permguard_objects::cbor::{self, Value};

use crate::database::{Database, DbError, Failure, Unit};

impl From<DbError> for RingError {
    fn from(error: DbError) -> Self {
        Self::Unavailable(Box::new(error))
    }
}

const VIEW: &str = "view";
const BINDING: &str = "binding";

type Step<T> = Result<T, Failure<RingError>>;

/// The records of one ring of one database.
#[derive(Debug, Clone)]
pub struct PostgresRing {
    database: Database,
    ring: String,
}

fn sequence(seq: u64) -> Step<i64> {
    i64::try_from(seq).map_err(|_| {
        Failure::Refused(RingError::Refused(
            "a sequence past what the store keeps".to_owned(),
        ))
    })
}

impl PostgresRing {
    /// The records of the ring `ring` in `database`, whose schema is this build's.
    pub fn new(database: Database, ring: &str) -> Self {
        Self {
            database,
            ring: ring.to_owned(),
        }
    }

    fn unit<T>(&self, work: impl Fn(&Unit) -> Step<T>) -> Result<T, RingError> {
        self.database.transaction(work)?
    }

    fn record(&self, name: &str) -> Result<Option<Vec<u8>>, RingError> {
        self.unit(|unit| {
            Ok(unit
                .query_opt(
                    "SELECT record FROM permguard_ring_records WHERE ring = $1 AND name = $2",
                    &[&self.ring, &name],
                )?
                .map(|row| row.get(0)))
        })
    }

    fn replace(&self, name: &str, bytes: &[u8]) -> Result<(), RingError> {
        self.unit(|unit| {
            unit.execute(
                "INSERT INTO permguard_ring_records (ring, name, record) VALUES ($1, $2, $3)
                 ON CONFLICT (ring, name) DO UPDATE SET record = EXCLUDED.record",
                &[&self.ring, &name, &bytes],
            )?;
            Ok(())
        })
    }
}

impl PostgresRing {
    /// Writes `exported`, as another backend held it, in one transaction: the import of a volume
    /// (iteration 03, WP-27.6), into a database no server is using. A record already held
    /// refuses.
    pub fn import(&self, exported: &Exported) -> Result<(), RingError> {
        self.unit(|unit| {
            let Records {
                entries,
                view,
                binding,
                kept_bindings,
                public_keys,
            } = &exported.current;
            for (seq, entry) in (1_i64..).zip(entries) {
                unit.execute(
                    "INSERT INTO permguard_ring_entries (ring, seq, entry) VALUES ($1, $2, $3)",
                    &[&self.ring, &seq, entry],
                )?;
            }
            for (name, record) in [(VIEW, view), (BINDING, binding)] {
                if let Some(record) = record {
                    unit.execute(
                        "INSERT INTO permguard_ring_records (ring, name, record)
                         VALUES ($1, $2, $3)",
                        &[&self.ring, &name, record],
                    )?;
                }
            }
            for (seq, envelope) in kept_bindings {
                unit.execute(
                    "INSERT INTO permguard_ring_kept_bindings (ring, seq, envelope)
                     VALUES ($1, $2, $3)",
                    &[&self.ring, &sequence(*seq)?, envelope],
                )?;
            }
            for (thumbprint, jwk) in public_keys {
                unit.execute(
                    "INSERT INTO permguard_ring_public_keys (ring, thumbprint, jwk)
                     VALUES ($1, $2, $3)",
                    &[&self.ring, thumbprint, jwk],
                )?;
            }
            for (host_id, kept) in &exported.retired {
                let mut evidence: Vec<(&str, String, &[u8])> = Vec::new();
                for (seq, entry) in (1_u64..).zip(&kept.entries) {
                    evidence.push(("entry", seq.to_string(), entry));
                }
                for (name, record) in [(VIEW, &kept.view), (BINDING, &kept.binding)] {
                    if let Some(record) = record {
                        evidence.push(("record", name.to_owned(), record));
                    }
                }
                for (seq, envelope) in &kept.kept_bindings {
                    evidence.push(("kept binding", seq.to_string(), envelope));
                }
                for (thumbprint, jwk) in &kept.public_keys {
                    evidence.push(("public key", thumbprint.clone(), jwk));
                }
                for (kind, name, record) in evidence {
                    unit.execute(
                        "INSERT INTO permguard_ring_evidence (ring, host_id, kind, name, record)
                         VALUES ($1, $2, $3, $4, $5)",
                        &[&self.ring, host_id, &kind, &name, &record],
                    )?;
                }
            }
            Ok(())
        })
    }
}

impl RingStore for PostgresRing {
    fn shared(&self) -> bool {
        true
    }

    fn entries(&self) -> Result<Vec<Value>, RingError> {
        self.unit(|unit| {
            unit.query(
                "SELECT entry FROM permguard_ring_entries WHERE ring = $1 ORDER BY seq",
                &[&self.ring],
            )?
            .into_iter()
            .map(|row| {
                cbor::decode_canonical(&row.get::<_, Vec<u8>>(0)).map_err(|error| {
                    Failure::Refused(RingError::Corrupt(format!(
                        "an entry held does not read: {error:?}"
                    )))
                })
            })
            .collect()
        })
    }

    fn append(&self, seq: u64, entry: &[u8]) -> Result<(), RingError> {
        self.unit(|unit| {
            let moved = || {
                Failure::Refused(RingError::Refused(format!(
                    "the entry {seq} does not follow the last one held"
                )))
            };
            let last: i64 = unit
                .query_one(
                    "SELECT COALESCE(MAX(seq), 0) FROM permguard_ring_entries WHERE ring = $1",
                    &[&self.ring],
                )?
                .get(0);
            if sequence(seq)? != last + 1 {
                return Err(moved());
            }
            // Another instance that read the same last entry writes the same key: one row is
            // written, and this unit of work, run again, reads the ring as it then stands.
            let added = unit.execute(
                "INSERT INTO permguard_ring_entries (ring, seq, entry) VALUES ($1, $2, $3)
                 ON CONFLICT (ring, seq) DO NOTHING",
                &[&self.ring, &(last + 1), &entry],
            )?;
            if added == 1 { Ok(()) } else { Err(moved()) }
        })
    }

    fn view(&self) -> Result<Option<Vec<u8>>, RingError> {
        self.record(VIEW)
    }

    fn replace_view(&self, view: &[u8]) -> Result<(), RingError> {
        self.replace(VIEW, view)
    }

    fn binding(&self) -> Result<Option<Vec<u8>>, RingError> {
        self.record(BINDING)
    }

    fn replace_binding(&self, envelope: &[u8]) -> Result<(), RingError> {
        self.replace(BINDING, envelope)
    }

    fn keep_binding(&self, seq: u64, envelope: &[u8]) -> Result<(), RingError> {
        self.unit(|unit| {
            unit.execute(
                "INSERT INTO permguard_ring_kept_bindings (ring, seq, envelope)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (ring, seq) DO UPDATE SET envelope = EXCLUDED.envelope",
                &[&self.ring, &sequence(seq)?, &envelope],
            )?;
            Ok(())
        })
    }

    fn kept_binding(&self, seq: u64) -> Result<Option<Vec<u8>>, RingError> {
        self.unit(|unit| {
            Ok(unit
                .query_opt(
                    "SELECT envelope FROM permguard_ring_kept_bindings
                     WHERE ring = $1 AND seq = $2",
                    &[&self.ring, &sequence(seq)?],
                )?
                .map(|row| row.get(0)))
        })
    }

    fn kept_bindings(&self) -> Result<Vec<Vec<u8>>, RingError> {
        self.unit(|unit| {
            Ok(unit
                .query(
                    "SELECT envelope FROM permguard_ring_kept_bindings
                     WHERE ring = $1 ORDER BY seq",
                    &[&self.ring],
                )?
                .into_iter()
                .map(|row| row.get(0))
                .collect())
        })
    }

    fn public(&self, thumbprint: &str) -> Result<Option<Vec<u8>>, RingError> {
        self.unit(|unit| {
            Ok(unit
                .query_opt(
                    "SELECT jwk FROM permguard_ring_public_keys
                     WHERE ring = $1 AND thumbprint = $2",
                    &[&self.ring, &thumbprint],
                )?
                .map(|row| row.get(0)))
        })
    }

    fn publish_public(&self, thumbprint: &str, jwk: &[u8]) -> Result<(), RingError> {
        self.unit(|unit| {
            // Published once: of the keys that arrive together under a thumbprint one is kept,
            // and every other caller is judged against it.
            unit.execute(
                "INSERT INTO permguard_ring_public_keys (ring, thumbprint, jwk)
                 VALUES ($1, $2, $3) ON CONFLICT (ring, thumbprint) DO NOTHING",
                &[&self.ring, &thumbprint, &jwk],
            )?;
            let held: Vec<u8> = unit
                .query_one(
                    "SELECT jwk FROM permguard_ring_public_keys
                     WHERE ring = $1 AND thumbprint = $2",
                    &[&self.ring, &thumbprint],
                )?
                .get(0);
            if held == jwk {
                Ok(())
            } else {
                Err(Failure::Refused(RingError::Refused(format!(
                    "another key is published under {thumbprint}; it is left as it was"
                ))))
            }
        })
    }

    fn retire(&self, _applying: &Applying<'_>, old_host_id: &[u8; 16]) -> Result<(), RingError> {
        let host_id = uuid_text(old_host_id);
        self.unit(|unit| {
            unit.execute(
                "DELETE FROM permguard_ring_evidence WHERE ring = $1 AND host_id = $2",
                &[&self.ring, &host_id],
            )?;
            for (kind, name, record, table) in [
                ("entry", "seq::text", "entry", "permguard_ring_entries"),
                ("record", "name", "record", "permguard_ring_records"),
                (
                    "kept binding",
                    "seq::text",
                    "envelope",
                    "permguard_ring_kept_bindings",
                ),
                (
                    "public key",
                    "thumbprint",
                    "jwk",
                    "permguard_ring_public_keys",
                ),
            ] {
                unit.execute(
                    &format!(
                        "INSERT INTO permguard_ring_evidence (ring, host_id, kind, name, record)
                         SELECT ring, $2, '{kind}', {name}, {record} FROM {table} WHERE ring = $1"
                    ),
                    &[&self.ring, &host_id],
                )?;
            }
            Ok(())
        })
    }

    fn forget_entries(&self) -> Result<(), RingError> {
        self.unit(|unit| {
            unit.execute(
                "DELETE FROM permguard_ring_entries WHERE ring = $1",
                &[&self.ring],
            )?;
            Ok(())
        })
    }

    fn clear(&self) -> Result<(), RingError> {
        self.unit(|unit| {
            for table in [
                "permguard_ring_records",
                "permguard_ring_kept_bindings",
                "permguard_ring_public_keys",
            ] {
                unit.execute(
                    &format!("DELETE FROM {table} WHERE ring = $1"),
                    &[&self.ring],
                )?;
            }
            Ok(())
        })
    }
}
