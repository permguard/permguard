// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The schema: versioned, forward only, checked at start (iteration 03, decision E29).
//!
//! A migration is a number, a name and the statements that take the schema from the version
//! before it. Migrations are applied in order, each recorded in `permguard_schema` in the
//! transaction that applies it, by whichever instance starts first: the others wait for it and
//! find nothing left to apply. A migration is never edited once released and none goes back.
//! A database whose schema is newer than this build knows is not served by it.

use crate::database::{Database, DbError, Failure, Unit};

/// One step of the schema.
pub struct Migration {
    pub version: i32,
    pub name: &'static str,
    pub statements: &'static str,
}

/// Every migration, oldest first, their versions counting from 1 with no gap.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "foundations",
        statements: "
        CREATE TABLE permguard_leases (
            name text PRIMARY KEY,
            holder text NOT NULL,
            generation bigint NOT NULL CHECK (generation > 0),
            expires_at timestamptz NOT NULL
        );
        CREATE TABLE permguard_clock_marks (
            scope text PRIMARY KEY,
            mark bigint NOT NULL
        );
    ",
    },
    Migration {
        version: 2,
        name: "mutations",
        statements: "
        CREATE TABLE permguard_mutations (
            operation_id bytea PRIMARY KEY CHECK (octet_length(operation_id) = 16),
            domain text NOT NULL,
            operation text NOT NULL,
            action text NOT NULL,
            initiator_kind text NOT NULL CHECK (initiator_kind IN ('principal', 'system')),
            initiator text NOT NULL,
            request_id text,
            request_digest text,
            target text,
            state text NOT NULL CHECK (state IN ('applied', 'failed')),
            revision bigint CHECK (revision >= 0),
            result bytea,
            at timestamptz NOT NULL DEFAULT now(),
            CHECK ((request_id IS NULL) = (request_digest IS NULL))
        );
        CREATE UNIQUE INDEX permguard_mutations_request
            ON permguard_mutations (initiator, request_id)
            WHERE request_id IS NOT NULL AND initiator_kind = 'principal' AND state = 'applied';
        CREATE TABLE permguard_mutation_audit (
            sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            operation_id bytea NOT NULL REFERENCES permguard_mutations (operation_id),
            phase text NOT NULL CHECK (phase IN ('intent', 'applied', 'failed')),
            action text NOT NULL,
            subject_kind text NOT NULL CHECK (subject_kind IN ('principal', 'system')),
            subject text NOT NULL,
            target text,
            at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (operation_id, phase)
        );
    ",
    },
];

/// The version this build's schema is at.
pub fn known() -> i32 {
    MIGRATIONS.last().map_or(0, |migration| migration.version)
}

/// The version the database's schema is at; 0 for a database that holds none yet.
fn version(unit: &Unit) -> Result<i32, crate::database::SqlError> {
    unit.batch_execute(
        "CREATE TABLE IF NOT EXISTS permguard_schema (
            version integer PRIMARY KEY CHECK (version > 0),
            name text NOT NULL,
            applied_at timestamptz NOT NULL DEFAULT now()
        )",
    )?;
    Ok(unit
        .query_one(
            "SELECT COALESCE(MAX(version), 0) FROM permguard_schema",
            &[],
        )?
        .get(0))
}

/// Brings the database's schema to this build's, applying what is missing, and answers the
/// version it is at. One instance applies at a time. A schema newer than this build knows is
/// [`DbError::SchemaNewer`] and nothing is changed.
pub fn migrate(database: &Database) -> Result<i32, DbError> {
    database.under_scope("schema migrations", |transaction| {
        let found = version(transaction)?;
        if found > known() {
            return Err(Failure::Refused(DbError::SchemaNewer {
                found,
                known: known(),
            }));
        }
        for migration in MIGRATIONS.iter().filter(|step| step.version > found) {
            transaction.batch_execute(migration.statements)?;
            transaction.execute(
                "INSERT INTO permguard_schema (version, name) VALUES ($1, $2)",
                &[&migration.version, &migration.name],
            )?;
        }
        Ok(known())
    })?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A migration released is never renumbered: versions count from 1 with no gap, so the
    /// highest version is how many were applied.
    #[test]
    fn the_migrations_are_numbered_from_1_with_no_gap() {
        for (index, migration) in MIGRATIONS.iter().enumerate() {
            assert_eq!(migration.version, index as i32 + 1, "{}", migration.name);
            assert!(!migration.name.is_empty() && !migration.statements.trim().is_empty());
        }
        assert_eq!(known(), MIGRATIONS.len() as i32);
    }
}
