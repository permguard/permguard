// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL backend of [`HeldStore`]: what a Host holds of the Authority Plane, the key
//! set and the status list tokens it verified.
//!
//! A list is kept only when it is newer than the one held, by the statement that keeps it:
//! whichever instance fetched it, a list fetched late never puts an older one back.

use permguard_host::authz::held::{HeldError, HeldStore, KeptKeys, Named};

use crate::database::{Database, DbError};

impl From<DbError> for HeldError {
    fn from(error: DbError) -> Self {
        Self(Box::new(error))
    }
}

/// What one database holds of the Authority Plane.
#[derive(Debug, Clone)]
pub struct PostgresHeld {
    database: Database,
}

impl PostgresHeld {
    /// The held store of `database`, whose schema is this build's.
    pub fn new(database: Database) -> Self {
        Self { database }
    }
}

fn kept(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

impl HeldStore for PostgresHeld {
    fn keys(&self) -> Result<Option<KeptKeys>, HeldError> {
        let held: Option<String> = self
            .database
            .write(|unit| unit.query_opt("SELECT key_set FROM permguard_held_keys", &[]))?
            .map(|row| row.get(0));
        // What does not read as a key set is fetched again.
        Ok(held.and_then(|text| serde_json::from_str(&text).ok()))
    }

    fn keep_keys(&self, keys: &KeptKeys) -> Result<(), HeldError> {
        let text = serde_json::to_string(keys).map_err(|error| HeldError(Box::new(error)))?;
        self.database.write(|unit| {
            unit.execute(
                "INSERT INTO permguard_held_keys (key_set) VALUES ($1)
                 ON CONFLICT (only_one) DO UPDATE SET key_set = EXCLUDED.key_set",
                &[&text],
            )
        })?;
        Ok(())
    }

    fn restore(&self, verify: &dyn Fn(&str) -> Option<Named>) -> Result<Vec<String>, HeldError> {
        Ok(self.database.write(|unit| {
            let mut restored = Vec::new();
            for row in unit.query(
                "SELECT issuer, uri, token FROM permguard_held_lists ORDER BY issuer, uri",
                &[],
            )? {
                let (issuer, uri, token): (String, String, String) =
                    (row.get(0), row.get(1), row.get(2));
                match verify(&token) {
                    Some(named) if named.issuer == issuer && named.uri == uri => {
                        unit.execute(
                            "UPDATE permguard_held_lists SET iat = $3
                             WHERE issuer = $1 AND uri = $2",
                            &[&issuer, &uri, &kept(named.iat)],
                        )?;
                        restored.push(token);
                    }
                    // Not a list any more, or another list than the one it is kept as.
                    _ => {
                        unit.execute(
                            "DELETE FROM permguard_held_lists WHERE issuer = $1 AND uri = $2",
                            &[&issuer, &uri],
                        )?;
                    }
                }
            }
            Ok(restored)
        })?)
    }

    fn keep_list(&self, named: &Named, token: &str) -> Result<bool, HeldError> {
        let written = self.database.write(|unit| {
            unit.execute(
                "INSERT INTO permguard_held_lists AS held (issuer, uri, iat, token)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (issuer, uri) DO UPDATE SET iat = EXCLUDED.iat, token = EXCLUDED.token
                 WHERE held.iat < EXCLUDED.iat",
                &[&named.issuer, &named.uri, &kept(named.iat), &token],
            )
        })?;
        Ok(written == 1)
    }

    fn drop_list(&self, issuer: &str, uri: &str) -> Result<(), HeldError> {
        self.database.write(|unit| {
            unit.execute(
                "DELETE FROM permguard_held_lists WHERE issuer = $1 AND uri = $2",
                &[&issuer, &uri],
            )
        })?;
        Ok(())
    }
}
