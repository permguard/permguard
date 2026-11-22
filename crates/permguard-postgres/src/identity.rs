// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL backend of [`IdentityStore`]: the records of the Host identity of one
//! database.
//!
//! | Record              | Kept in                                                   |
//! | ------------------- | --------------------------------------------------------- |
//! | provisioning record | `permguard_identity_records`, the row `init`              |
//! | document            | `permguard_identity_records`, the row `document`          |
//! | start               | `permguard_identity_records`, the row `start`             |
//! | reset under way     | `permguard_identity_records`, the row `resetting`         |
//! | successions         | `permguard_identity_successions`, a row each, by position |
//! | public key          | `permguard_identity_public_keys`, a row an epoch          |
//! | retired identity    | `permguard_identity_retired` and its evidence             |
//!
//! No private key rests here: the keys of an identity kept on this backend are its custody's,
//! which every instance reaches, so no epoch is ever answered as holding one.

use permguard_host::identity::IdentityError;
use permguard_host::identity::record::uuid_text;
use permguard_host::identity::store::{HeldEpoch, IdentityStore, Retired};
use permguard_host::operations::mutation::Applying;
use permguard_objects::cbor::{self, Value};

use crate::database::{Database, DbError, Failure, Unit};

impl From<DbError> for IdentityError {
    fn from(error: DbError) -> Self {
        Self::Unavailable(Box::new(error))
    }
}

const INIT: &str = "init";
const DOCUMENT: &str = "document";
const START: &str = "start";
const RESETTING: &str = "resetting";

type Step<T> = Result<T, Failure<IdentityError>>;

/// The records of the Host identity of one database.
#[derive(Debug, Clone)]
pub struct PostgresIdentity {
    database: Database,
}

fn refused(detail: &str) -> Failure<IdentityError> {
    Failure::Refused(IdentityError::Unavailable(detail.into()))
}

fn epoch_of(epoch: u64) -> Step<i64> {
    i64::try_from(epoch).map_err(|_| refused("an epoch past what the store keeps"))
}

fn record(unit: &Unit, name: &str) -> Step<Option<Vec<u8>>> {
    Ok(unit
        .query_opt(
            "SELECT record FROM permguard_identity_records WHERE name = $1",
            &[&name],
        )?
        .map(|row| row.get(0)))
}

fn replace(unit: &Unit, name: &str, bytes: &[u8]) -> Step<()> {
    unit.execute(
        "INSERT INTO permguard_identity_records (name, record) VALUES ($1, $2)
         ON CONFLICT (name) DO UPDATE SET record = EXCLUDED.record",
        &[&name, &bytes],
    )?;
    Ok(())
}

fn remove(unit: &Unit, name: &str) -> Step<()> {
    unit.execute(
        "DELETE FROM permguard_identity_records WHERE name = $1",
        &[&name],
    )?;
    Ok(())
}

fn keep(unit: &Unit, host_id: &str, kind: &str, position: i64, bytes: &[u8]) -> Step<()> {
    unit.execute(
        "INSERT INTO permguard_identity_evidence (host_id, kind, position, record)
         VALUES ($1, $2, $3, $4)",
        &[&host_id, &kind, &position, &bytes],
    )?;
    Ok(())
}

impl PostgresIdentity {
    /// The identity's records in `database`, whose schema is this build's.
    pub fn new(database: Database) -> Self {
        Self { database }
    }

    fn unit<T>(&self, work: impl Fn(&Unit) -> Step<T>) -> Result<T, IdentityError> {
        self.database.transaction(work)?
    }
}

impl IdentityStore for PostgresIdentity {
    fn init(&self) -> Result<Option<Vec<u8>>, IdentityError> {
        self.unit(|unit| record(unit, INIT))
    }

    fn publish_init(&self, bytes: &[u8]) -> Result<(), IdentityError> {
        self.unit(|unit| {
            // Written once: of the records that arrive together, on any instance, one is kept,
            // and every other caller is judged against it.
            unit.execute(
                "INSERT INTO permguard_identity_records (name, record) VALUES ($1, $2)
                 ON CONFLICT (name) DO NOTHING",
                &[&INIT, &bytes],
            )?;
            if record(unit, INIT)?.as_deref() == Some(bytes) {
                Ok(())
            } else {
                Err(refused(
                    "another provisioning record is held; it is left as it was",
                ))
            }
        })
    }

    fn remove_init(&self) -> Result<(), IdentityError> {
        self.unit(|unit| remove(unit, INIT))
    }

    fn document(&self) -> Result<Option<Vec<u8>>, IdentityError> {
        self.unit(|unit| record(unit, DOCUMENT))
    }

    fn replace_document(&self, envelope: &[u8]) -> Result<(), IdentityError> {
        self.unit(|unit| replace(unit, DOCUMENT, envelope))
    }

    fn successions(&self) -> Result<Vec<Value>, IdentityError> {
        self.unit(|unit| {
            unit.query(
                "SELECT envelope FROM permguard_identity_successions ORDER BY position",
                &[],
            )?
            .into_iter()
            .map(|row| {
                cbor::decode_canonical(&row.get::<_, Vec<u8>>(0)).map_err(|error| {
                    Failure::Refused(IdentityError::Corrupt(format!(
                        "a succession held does not read: {error:?}"
                    )))
                })
            })
            .collect()
        })
    }

    fn append_succession(&self, envelope: &[u8]) -> Result<(), IdentityError> {
        self.unit(|unit| {
            // The position is the one after the last held: two that arrive together cannot both
            // take it, and the one the database refuses is run again after the other.
            unit.execute(
                "INSERT INTO permguard_identity_successions (position, envelope)
                 SELECT COALESCE(MAX(position), 0) + 1, $1 FROM permguard_identity_successions",
                &[&envelope],
            )?;
            Ok(())
        })
    }

    fn public(&self, epoch: u64) -> Result<Option<Vec<u8>>, IdentityError> {
        self.unit(|unit| {
            Ok(unit
                .query_opt(
                    "SELECT key FROM permguard_identity_public_keys WHERE epoch = $1",
                    &[&epoch_of(epoch)?],
                )?
                .map(|row| row.get(0)))
        })
    }

    fn publish_public(&self, epoch: u64, key: &[u8]) -> Result<(), IdentityError> {
        self.unit(|unit| {
            let epoch = epoch_of(epoch)?;
            unit.execute(
                "INSERT INTO permguard_identity_public_keys (epoch, key) VALUES ($1, $2)
                 ON CONFLICT (epoch) DO NOTHING",
                &[&epoch, &key],
            )?;
            let held: Vec<u8> = unit
                .query_one(
                    "SELECT key FROM permguard_identity_public_keys WHERE epoch = $1",
                    &[&epoch],
                )?
                .get(0);
            if held == key {
                Ok(())
            } else {
                Err(refused(
                    "another public key is published for the epoch; it is left as it was",
                ))
            }
        })
    }

    fn remove_public(&self, epoch: u64) -> Result<(), IdentityError> {
        self.unit(|unit| {
            unit.execute(
                "DELETE FROM permguard_identity_public_keys WHERE epoch = $1",
                &[&epoch_of(epoch)?],
            )?;
            Ok(())
        })
    }

    fn held_epochs(&self) -> Result<Vec<HeldEpoch>, IdentityError> {
        self.unit(|unit| {
            Ok(unit
                .query(
                    "SELECT epoch FROM permguard_identity_public_keys ORDER BY epoch",
                    &[],
                )?
                .into_iter()
                .map(|row| HeldEpoch {
                    epoch: row.get::<_, i64>(0).unsigned_abs(),
                    public: true,
                    private: false,
                })
                .collect())
        })
    }

    fn started(&self) -> Result<bool, IdentityError> {
        self.unit(|unit| Ok(record(unit, START)?.is_some()))
    }

    fn record_start(&self, bytes: &[u8]) -> Result<(), IdentityError> {
        self.unit(|unit| replace(unit, START, bytes))
    }

    fn clear(&self) -> Result<(), IdentityError> {
        self.unit(|unit| {
            unit.execute(
                "DELETE FROM permguard_identity_records WHERE name IN ($1, $2)",
                &[&DOCUMENT, &START],
            )?;
            unit.execute("DELETE FROM permguard_identity_successions", &[])?;
            unit.execute("DELETE FROM permguard_identity_public_keys", &[])?;
            Ok(())
        })
    }

    fn resetting(&self) -> Result<Option<Vec<u8>>, IdentityError> {
        self.unit(|unit| record(unit, RESETTING))
    }

    fn mark_resetting(
        &self,
        _applying: &Applying<'_>,
        host_id: &[u8; 16],
    ) -> Result<(), IdentityError> {
        self.unit(|unit| replace(unit, RESETTING, host_id))
    }

    fn clear_resetting(&self) -> Result<(), IdentityError> {
        self.unit(|unit| remove(unit, RESETTING))
    }

    fn retire(
        &self,
        _applying: &Applying<'_>,
        host_id: &[u8; 16],
        reset: &[u8],
    ) -> Result<(), IdentityError> {
        let host_id = uuid_text(host_id);
        self.unit(|unit| {
            // The evidence and the record of the reset are one write: a retired identity is
            // never held with one and not the other.
            unit.execute(
                "INSERT INTO permguard_identity_retired (host_id, reset) VALUES ($1, $2)
                 ON CONFLICT (host_id) DO UPDATE SET reset = EXCLUDED.reset",
                &[&host_id, &reset],
            )?;
            unit.execute(
                "DELETE FROM permguard_identity_evidence WHERE host_id = $1",
                &[&host_id],
            )?;
            for name in [INIT, DOCUMENT] {
                if let Some(bytes) = record(unit, name)? {
                    keep(unit, &host_id, name, 0, &bytes)?;
                }
            }
            unit.execute(
                "INSERT INTO permguard_identity_evidence (host_id, kind, position, record)
                 SELECT $1, 'succession', position, envelope FROM permguard_identity_successions",
                &[&host_id],
            )?;
            unit.execute(
                "INSERT INTO permguard_identity_evidence (host_id, kind, position, record)
                 SELECT $1, 'public', epoch, key FROM permguard_identity_public_keys",
                &[&host_id],
            )?;
            Ok(())
        })
    }

    fn retired(&self) -> Result<Vec<Retired>, IdentityError> {
        self.unit(|unit| {
            Ok(unit
                .query(
                    "SELECT retired.host_id, retired.reset, EXISTS (
                         SELECT 1 FROM permguard_identity_evidence AS evidence
                         WHERE evidence.host_id = retired.host_id AND evidence.kind = 'init')
                     FROM permguard_identity_retired AS retired ORDER BY retired.host_id",
                    &[],
                )?
                .into_iter()
                .map(|row| Retired {
                    host_id: row.get(0),
                    reset: Some(row.get(1)),
                    init: row.get(2),
                })
                .collect())
        })
    }
}
