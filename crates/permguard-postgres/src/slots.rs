// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL backend of [`SlotStore`]: what a custody keeps of each key, a row a slot of
//! one scope, a ring's or the identity's (`1-architecture/4` Stores).
//!
//! A slot holds what its custody puts there: a key sealed under a key-encryption key held
//! outside the database (`permguard.sealed-key.v1`), or a reference to a key a token or a KMS
//! holds. No key is kept here in the clear: the configuration refuses the `development` custody
//! on this backend. Every instance reads the same rows, so every instance signs with the same
//! keys, unsealed under the same key-encryption key or asked of the same KMS.

use permguard_host::keys::KeyError;
use permguard_host::keys::slots::{Kind, SlotStore, check};

use crate::database::{Database, DbError, Failure};

impl From<DbError> for KeyError {
    fn from(error: DbError) -> Self {
        Self::Unavailable(Box::new(error))
    }
}

/// The slots of one scope, a ring's or the identity's, in one database.
#[derive(Debug, Clone)]
pub struct PostgresSlots {
    database: Database,
    scope: String,
}

fn kind_of(kind: Kind) -> &'static str {
    match kind {
        Kind::Key => "key",
        Kind::Reference => "reference",
    }
}

impl PostgresSlots {
    /// The slots of `scope` kept in `database`, whose schema is this build's.
    pub fn new(database: Database, scope: &str) -> Self {
        Self {
            database,
            scope: scope.to_owned(),
        }
    }
}

impl SlotStore for PostgresSlots {
    fn read(&self, kind: Kind, slot: &str) -> Result<Option<Vec<u8>>, KeyError> {
        check(slot)?;
        Ok(self.database.write(|unit| {
            Ok(unit
                .query_opt(
                    "SELECT bytes FROM permguard_key_slots
                     WHERE scope = $1 AND kind = $2 AND slot = $3",
                    &[&self.scope, &kind_of(kind), &slot],
                )?
                .map(|row| row.get(0)))
        })?)
    }

    fn fill(&self, kind: Kind, slot: &str, bytes: &[u8]) -> Result<(), KeyError> {
        check(slot)?;
        // Filled once: of the keys that arrive together for one slot, on any instance, the key
        // of the table keeps one, and the others are refused.
        self.database.transaction(|unit| {
            let written = unit.execute(
                "INSERT INTO permguard_key_slots (scope, kind, slot, bytes) VALUES ($1, $2, $3, $4)
                 ON CONFLICT (scope, kind, slot) DO NOTHING",
                &[&self.scope, &kind_of(kind), &slot, &bytes],
            )?;
            if written == 1 {
                Ok(())
            } else {
                Err(Failure::Refused(KeyError::Exists(slot.to_owned())))
            }
        })?
    }

    fn replace(&self, kind: Kind, slot: &str, bytes: &[u8]) -> Result<(), KeyError> {
        check(slot)?;
        self.database.write(|unit| {
            unit.execute(
                "INSERT INTO permguard_key_slots (scope, kind, slot, bytes) VALUES ($1, $2, $3, $4)
                 ON CONFLICT (scope, kind, slot) DO UPDATE SET bytes = EXCLUDED.bytes",
                &[&self.scope, &kind_of(kind), &slot, &bytes],
            )
        })?;
        Ok(())
    }

    fn slots(&self, kind: Kind) -> Result<Vec<String>, KeyError> {
        Ok(self.database.write(|unit| {
            Ok(unit
                .query(
                    "SELECT slot FROM permguard_key_slots WHERE scope = $1 AND kind = $2
                     ORDER BY slot",
                    &[&self.scope, &kind_of(kind)],
                )?
                .into_iter()
                .map(|row| row.get(0))
                .collect())
        })?)
    }

    fn empty(&self, kind: Kind, slot: &str) -> Result<(), KeyError> {
        check(slot)?;
        self.database.write(|unit| {
            unit.execute(
                "DELETE FROM permguard_key_slots WHERE scope = $1 AND kind = $2 AND slot = $3",
                &[&self.scope, &kind_of(kind), &slot],
            )
        })?;
        Ok(())
    }

    fn place(&self, kind: Kind, slot: &str) -> String {
        format!(
            "the {} slot {slot} of {} in the database",
            kind_of(kind),
            self.scope
        )
    }
}
