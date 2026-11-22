// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL backend of [`ClockMark`]: one row a Host, `permguard_clock_marks`.
//!
//! The mark only rises, and the statement that raises it says so: it writes only where the mark
//! held is lower, whichever instance raised that one.

use std::sync::Arc;

use permguard_host::time::{ClockMark, MarkError};

use crate::database::{Database, DbError};

impl From<DbError> for MarkError {
    fn from(error: DbError) -> Self {
        Self::Unavailable(Box::new(error))
    }
}

/// The clock's high-water mark of the Host `scope` names, in the database.
pub struct PostgresClockMark {
    database: Arc<Database>,
    scope: String,
}

impl PostgresClockMark {
    /// The mark kept under `scope`: the Host's, one for all its instances.
    pub fn new(database: Arc<Database>, scope: impl Into<String>) -> Self {
        Self {
            database,
            scope: scope.into(),
        }
    }
}

impl ClockMark for PostgresClockMark {
    fn read(&self) -> Result<Option<i64>, MarkError> {
        Ok(self.database.write(|transaction| {
            Ok(transaction
                .query_opt(
                    "SELECT mark FROM permguard_clock_marks WHERE scope = $1",
                    &[&self.scope],
                )?
                .map(|row| row.get(0)))
        })?)
    }

    fn raise(&self, mark: i64) -> Result<(), MarkError> {
        self.database.write(|transaction| {
            transaction.execute(
                "INSERT INTO permguard_clock_marks AS held (scope, mark) VALUES ($1, $2)
                 ON CONFLICT (scope) DO UPDATE SET mark = EXCLUDED.mark
                 WHERE held.mark < EXCLUDED.mark",
                &[&self.scope, &mark],
            )
        })?;
        Ok(())
    }

    fn remedy(&self) -> String {
        format!(
            "with every instance stopped, delete the row of `{}` in `permguard_clock_marks`",
            self.scope
        )
    }
}
