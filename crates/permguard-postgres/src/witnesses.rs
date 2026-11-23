// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL backends of the Host's witnesses: what a root or a delivered key was first
//! seen as ([`WitnessStore`]), and the witnesses of the pseudonym key versions
//! ([`VersionWitnesses`]).
//!
//! A witness is no secret: it is what a secret is checked against. The secrets themselves, the
//! delivered keys and the keys of the rings, are kept here only sealed, with the custody every
//! instance reaches.

use std::cell::RefCell;

use permguard_host::identity::witness::{Change, VersionWitnesses, VersionsError};
use permguard_host::secrets::files::Witness;
use permguard_host::secrets::{SecretsError, WitnessStore};

use crate::database::{Database, DbError};

/// The witnesses of one database: a row a name, the first witness kept under it.
#[derive(Debug, Clone)]
pub struct PostgresWitnesses {
    database: Database,
}

fn secrets(error: DbError) -> SecretsError {
    SecretsError::Storage(error.to_string())
}

impl PostgresWitnesses {
    /// The witnesses of `database`, whose schema is this build's.
    pub fn new(database: Database) -> Self {
        Self { database }
    }
}

impl WitnessStore for PostgresWitnesses {
    fn first(&self, name: &[String], witness: &[u8; 32]) -> Result<Vec<u8>, SecretsError> {
        if name.is_empty() {
            return Err(SecretsError::Storage("an empty witness path".to_owned()));
        }
        // The parts are plain names, so the separator names one witness and no other.
        let name = name.join("/");
        self.database
            .write(|unit| {
                // The first witness under a name stays: a later one writes nothing, and every
                // caller is answered the one kept.
                unit.execute(
                    "INSERT INTO permguard_witnesses (name, witness) VALUES ($1, $2)
                     ON CONFLICT (name) DO NOTHING",
                    &[&name, &witness.as_slice()],
                )?;
                Ok(unit
                    .query_one(
                        "SELECT witness FROM permguard_witnesses WHERE name = $1",
                        &[&name],
                    )?
                    .get(0))
            })
            .map_err(secrets)
    }
}

/// The witnesses of the pseudonym key versions of one database: the entries of the server and
/// of each realm, in their order.
#[derive(Debug, Clone)]
pub struct PostgresVersionWitnesses {
    database: Database,
}

impl PostgresVersionWitnesses {
    /// The version witnesses of `database`, whose schema is this build's.
    pub fn new(database: Database) -> Self {
        Self { database }
    }
}

impl PostgresWitnesses {
    /// Writes `witnesses`, as another backend held them, in one transaction: the import of a
    /// volume (iteration 03, WP-27.6), into a database no server is using. A name already held
    /// refuses.
    pub fn import(&self, witnesses: &[Witness]) -> Result<usize, SecretsError> {
        self.database
            .write(|unit| {
                for (name, witness) in witnesses {
                    unit.execute(
                        "INSERT INTO permguard_witnesses (name, witness) VALUES ($1, $2)",
                        &[&name.join("/"), &witness.as_slice()],
                    )?;
                }
                Ok(witnesses.len())
            })
            .map_err(secrets)
    }
}

impl PostgresVersionWitnesses {
    /// Writes the entries of `realm`, the server's own when `None`, as another backend held them:
    /// the import of a volume (iteration 03, WP-27.6), into a database no server is using. A
    /// scope already held refuses.
    pub fn import(
        &self,
        realm: Option<&str>,
        entries: &[(String, String)],
    ) -> Result<usize, VersionsError> {
        let scope = scope(realm);
        self.database
            .write(|unit| {
                for (position, (label, witness)) in entries.iter().enumerate() {
                    unit.execute(
                        "INSERT INTO permguard_version_witnesses (scope, position, label, witness)
                         VALUES ($1, $2, $3, $4)",
                        &[&scope, &(position as i32), label, witness],
                    )?;
                }
                Ok(entries.len())
            })
            .map_err(|error| VersionsError(error.to_string()))
    }
}

/// The key a scope's entries are kept under: the server's own, or a realm's.
fn scope(realm: Option<&str>) -> String {
    match realm {
        None => "server".to_owned(),
        Some(realm) => format!("realm/{realm}"),
    }
}

impl VersionWitnesses for PostgresVersionWitnesses {
    fn update(&self, realm: Option<&str>, change: Change<'_>) -> Result<(), VersionsError> {
        let scope = scope(realm);
        // Asked again when the database could not serialize the update with another: it is then
        // given what that one kept.
        let change = RefCell::new(change);
        self.database
            .write(|unit| {
                let mut entries: Vec<(String, String)> = unit
                    .query(
                        "SELECT label, witness FROM permguard_version_witnesses
                         WHERE scope = $1 ORDER BY position",
                        &[&scope],
                    )?
                    .into_iter()
                    .map(|row| (row.get(0), row.get(1)))
                    .collect();
                if !(*change.borrow_mut())(&mut entries) {
                    return Ok(());
                }
                unit.execute(
                    "DELETE FROM permguard_version_witnesses WHERE scope = $1",
                    &[&scope],
                )?;
                for (position, (label, witness)) in entries.iter().enumerate() {
                    unit.execute(
                        "INSERT INTO permguard_version_witnesses (scope, position, label, witness)
                         VALUES ($1, $2, $3, $4)",
                        &[&scope, &(position as i32), label, witness],
                    )?;
                }
                Ok(())
            })
            .map_err(|error| VersionsError(error.to_string()))
    }

    fn place(&self, realm: Option<&str>) -> String {
        format!(
            "the rows of `{}` in `permguard_version_witnesses`",
            scope(realm)
        )
    }
}
