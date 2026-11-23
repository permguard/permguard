// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL backend of [`BootstrapStore`]: the one row of `permguard_bootstrap`.
//!
//! The commitment is written once: the table holds one row, by its key, so of the commitments
//! that arrive together, on any instance, one is written whatever each names.

use permguard_core::authz::Principal;
use permguard_host::authz::store::{AuthzError, Bootstrap, BootstrapStore, bootstrap_principal};
use permguard_host::operations::mutation::Applying;
use postgres::error::SqlState;

use crate::database::{Database, DbError, Failure, Unit};

impl From<DbError> for AuthzError {
    fn from(error: DbError) -> Self {
        Self::Unavailable(Box::new(error))
    }
}

/// The recovery principal's commitment in one database.
#[derive(Debug, Clone)]
pub struct PostgresBootstrap {
    database: Database,
}

fn held(unit: &Unit) -> Result<Option<Bootstrap>, Failure<AuthzError>> {
    let Some(row) = unit.query_opt(
        "SELECT principal, fingerprint, created_at FROM permguard_bootstrap",
        &[],
    )?
    else {
        return Ok(None);
    };
    let unread = || {
        Failure::Refused(AuthzError::Record(
            "the bootstrap commitment held does not read as one".to_owned(),
        ))
    };
    Ok(Some(Bootstrap {
        principal: Principal::new(row.get::<_, String>(0)).map_err(|_| unread())?,
        fingerprint: row.get(1),
        created_at: u64::try_from(row.get::<_, i64>(2)).map_err(|_| unread())?,
    }))
}

impl PostgresBootstrap {
    /// The commitment of `database`, whose schema is this build's.
    pub fn new(database: Database) -> Self {
        Self { database }
    }
}

impl PostgresBootstrap {
    /// Writes the commitment a volume kept, as it is: what the import of a volume does.
    pub fn import(&self, commitment: &Bootstrap) -> Result<(), AuthzError> {
        let created_at = i64::try_from(commitment.created_at)
            .map_err(|_| AuthzError::Invalid("a time past what the store keeps".to_owned()))?;
        self.database.write(|unit| {
            unit.execute(
                "INSERT INTO permguard_bootstrap (principal, fingerprint, created_at)
                 VALUES ($1, $2, $3)",
                &[
                    &commitment.principal.as_str(),
                    &commitment.fingerprint,
                    &created_at,
                ],
            )
        })?;
        Ok(())
    }
}

impl BootstrapStore for PostgresBootstrap {
    fn bootstrap(&self) -> Result<Option<Bootstrap>, AuthzError> {
        self.database.transaction(held)?
    }

    fn commit(
        &self,
        _applying: &Applying<'_>,
        fingerprint: &str,
        now: u64,
    ) -> Result<(Bootstrap, bool), AuthzError> {
        let principal = bootstrap_principal(fingerprint)?;
        let commitment = Bootstrap {
            principal: principal.clone(),
            fingerprint: fingerprint.trim().to_ascii_lowercase(),
            created_at: now,
        };
        let created_at = i64::try_from(now)
            .map_err(|_| AuthzError::Invalid("a time past what the store keeps".to_owned()))?;
        let another = || {
            Failure::Refused(AuthzError::Invalid(
                "the Host already commits to another recovery principal; a bootstrap is written \
                 once"
                    .to_owned(),
            ))
        };
        self.database.transaction(|unit| {
            if let Some(existing) = held(unit)? {
                return if existing.principal == principal {
                    Ok((existing, false))
                } else {
                    Err(another())
                };
            }
            match unit.execute(
                "INSERT INTO permguard_bootstrap (principal, fingerprint, created_at)
                 VALUES ($1, $2, $3)",
                &[&principal.as_str(), &commitment.fingerprint, &created_at],
            ) {
                Ok(_) => Ok((commitment.clone(), true)),
                // Another instance committed between the read and the write: the database could
                // not serialize the two, or the row was there.
                Err(error) if error.code() == Some(&SqlState::UNIQUE_VIOLATION) => Err(another()),
                Err(error) => Err(error.into()),
            }
        })?
    }
}
