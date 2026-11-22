// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL backend of [`HoldStore`]: a row a hold, `permguard_holds`.
//!
//! | Rule of the contract                         | Kept by                                 |
//! | -------------------------------------------- | --------------------------------------- |
//! | an id that is held is not kept twice         | the hold's primary key                  |
//! | a release reads and removes as one step      | one statement that deletes and answers  |
//!
//! A hold is one row, so there is no file without its entry and no entry without its file to
//! find: [`HoldStore::verify`] finds nothing wrong with holds that read.

use permguard_host::holds::{Hold, HoldError, HoldStore};
use permguard_host::operations::mutation::Applying;
use postgres::Row;
use postgres::error::SqlState;

use crate::database::{Database, DbError, Failure, SqlError};

impl From<DbError> for HoldError {
    fn from(error: DbError) -> Self {
        Self::Unavailable(Box::new(error))
    }
}

/// The holds of one database.
#[derive(Debug, Clone)]
pub struct PostgresHolds {
    database: Database,
}

const COLUMNS: &str = "id, resource, owner, reason, created_at, expires_at, review_at, operation";

fn hold(row: &Row) -> Result<Hold, HoldError> {
    let time = |value: i64| {
        u64::try_from(value).map_err(|_| HoldError::Record("a time before the epoch".to_owned()))
    };
    Ok(Hold {
        id: row.get(0),
        resource: row.get(1),
        owner: row.get(2),
        reason: row.get(3),
        created_at: time(row.get(4))?,
        expires_at: row.get::<_, Option<i64>>(5).map(time).transpose()?,
        review_at: row.get::<_, Option<i64>>(6).map(time).transpose()?,
        operation: row.get(7),
    })
}

fn kept(value: u64) -> Result<i64, HoldError> {
    i64::try_from(value)
        .map_err(|_| HoldError::Invalid("a time past what the store keeps".to_owned()))
}

impl PostgresHolds {
    /// The holds of `database`, whose schema is this build's.
    pub fn new(database: Database) -> Self {
        Self { database }
    }

    fn rows(
        &self,
        ask: impl Fn(&crate::Unit) -> Result<Vec<Row>, SqlError>,
    ) -> Result<Vec<Hold>, HoldError> {
        self.database.write(ask)?.iter().map(hold).collect()
    }
}

impl HoldStore for PostgresHolds {
    fn list(&self) -> Result<Vec<Hold>, HoldError> {
        self.rows(|unit| {
            unit.query(
                &format!("SELECT {COLUMNS} FROM permguard_holds ORDER BY id"),
                &[],
            )
        })
    }

    fn get(&self, id: &str) -> Result<Option<Hold>, HoldError> {
        Ok(self
            .rows(|unit| {
                unit.query(
                    &format!("SELECT {COLUMNS} FROM permguard_holds WHERE id = $1"),
                    &[&id],
                )
            })?
            .pop())
    }

    fn verify(&self) -> Result<Vec<String>, HoldError> {
        // Every hold reads, or the listing says which does not.
        match self.list() {
            Ok(_) => Ok(Vec::new()),
            Err(HoldError::Record(why)) => Ok(vec![format!("does not read: {why}")]),
            Err(other) => Err(other),
        }
    }

    fn add(&self, _applying: &Applying<'_>, hold: &Hold) -> Result<(), HoldError> {
        let (created_at, expires_at, review_at) = (
            kept(hold.created_at)?,
            hold.expires_at.map(kept).transpose()?,
            hold.review_at.map(kept).transpose()?,
        );
        self.database.transaction(|unit| {
            if unit
                .query_opt("SELECT 1 FROM permguard_holds WHERE id = $1", &[&hold.id])?
                .is_some()
            {
                return Err(Failure::Refused(HoldError::Invalid(format!(
                    "a hold has the id `{}` already",
                    hold.id
                ))));
            }
            match unit.execute(
                "INSERT INTO permguard_holds
                         (id, resource, owner, reason, created_at, expires_at, review_at, operation)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                &[
                    &hold.id,
                    &hold.resource,
                    &hold.owner,
                    &hold.reason,
                    &created_at,
                    &expires_at,
                    &review_at,
                    &hold.operation,
                ],
            ) {
                Ok(_) => Ok(()),
                // Another instance kept the id between the read and the write.
                Err(error) if error.code() == Some(&SqlState::UNIQUE_VIOLATION) => {
                    Err(Failure::Refused(HoldError::Invalid(format!(
                        "a hold has the id `{}` already",
                        hold.id
                    ))))
                }
                Err(error) => Err(error.into()),
            }
        })?
    }

    fn release(&self, _applying: &Applying<'_>, id: &str) -> Result<Hold, HoldError> {
        self.database.transaction(|unit| {
            let removed = unit.query_opt(
                &format!("DELETE FROM permguard_holds WHERE id = $1 RETURNING {COLUMNS}"),
                &[&id],
            )?;
            match removed {
                Some(row) => hold(&row).map_err(Failure::Refused),
                None => Err(Failure::Refused(HoldError::NotFound(id.to_owned()))),
            }
        })?
    }
}
