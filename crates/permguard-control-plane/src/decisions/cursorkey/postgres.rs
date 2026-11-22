// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL backend of [`CursorRoots`]: the root of one evidence store's cursor keys,
//! sealed, a row a store (iteration 03, WP-27.5).
//!
//! The root is a secret every instance shares, so an offset one instance issued verifies at
//! another: a row holds it sealed by the key-encryption key of the `file` custody, held outside
//! the database, bound to this Host and to the store, so a row copied to another store, or
//! edited, does not open. A rotation moves the issuing root to the previous one, in one
//! statement: the next ask mints a new root, and the previous is still accepted while the row
//! keeps it.

use std::sync::Arc;

use anyhow::{Result, anyhow};
use permguard_host::secrets::sealed::{Sealed, Sealer};
use permguard_postgres::{Database, Failure, Row, Unit};
use zeroize::Zeroizing;

use super::{CursorRoots, KEY_BYTES, Roots};

/// What the seal of a cursor root names it for.
const PURPOSE: &str = permguard_core::domains::kdf::STREAM_CURSOR;

/// The cursor roots of the evidence stores of one database.
#[derive(Debug, Clone)]
pub struct PostgresCursorRoots {
    database: Database,
    sealer: Arc<Sealer>,
    store: String,
}

/// The root sealed in the columns from `at` of `row`, when there is one.
fn sealed_at(row: &Row, at: usize) -> Result<Option<Sealed>> {
    let Some(kek_ref) = row.get::<_, Option<String>>(at) else {
        return Ok(None);
    };
    Ok(Some(Sealed {
        kek_ref,
        kek_version: u64::try_from(row.get::<_, i64>(at + 1))
            .map_err(|_| anyhow!("a key-encryption key version held is none"))?,
        wrap_algorithm: row.get(at + 2),
        wrapped: row.get(at + 3),
    }))
}

impl PostgresCursorRoots {
    /// The root of the evidence store `store`, kept in `database`, whose schema is this build's,
    /// sealed by `sealer`.
    pub fn new(database: Database, sealer: Arc<Sealer>, store: &str) -> Self {
        Self {
            database,
            sealer,
            store: store.to_owned(),
        }
    }

    /// Rotates the root: the one issuing becomes the previous, accepted while it is kept, and
    /// the next ask mints a new one. A root already moved to the previous is replaced by the
    /// one issuing: offsets issued under the oldest are refused from then on.
    pub fn rotate(&self) -> Result<()> {
        self.database
            .write(|unit| {
                unit.execute(
                    "UPDATE permguard_cursor_roots
                     SET previous_kek_ref = kek_ref, previous_kek_version = kek_version,
                         previous_wrap_algorithm = wrap_algorithm, previous_wrapped = wrapped,
                         kek_ref = NULL, kek_version = NULL, wrap_algorithm = NULL, wrapped = NULL
                     WHERE store = $1 AND wrapped IS NOT NULL",
                    &[&self.store],
                )
            })
            .map_err(|error| anyhow!("rotating the cursor root of `{}`: {error}", self.store))?;
        Ok(())
    }

    /// A root is bound to its store, not to where in its row it is: a rotation moves the sealed
    /// bytes from the issuing root to the previous one as they are.
    fn open(&self, sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>, String> {
        let opened = self.sealer.open(PURPOSE, &self.store, sealed)?;
        Ok(Zeroizing::new(opened.secret.to_vec()))
    }

    fn seal(&self, root: &[u8; KEY_BYTES]) -> Result<Sealed, String> {
        self.sealer.seal(PURPOSE, &self.store, root)
    }

    /// The roots held, the issuing one minted in `unit` when none is.
    fn roots_in(&self, unit: &Unit) -> std::result::Result<Roots, Failure<String>> {
        let refused = |error: String| Failure::Refused(error);
        unit.execute(
            "INSERT INTO permguard_cursor_roots (store) VALUES ($1) ON CONFLICT DO NOTHING",
            &[&self.store],
        )?;
        let row = unit.query_one(
            "SELECT kek_ref, kek_version, wrap_algorithm, wrapped,
                    previous_kek_ref, previous_kek_version, previous_wrap_algorithm,
                    previous_wrapped
             FROM permguard_cursor_roots WHERE store = $1 FOR UPDATE",
            &[&self.store],
        )?;
        let previous = sealed_at(&row, 4)
            .map_err(|error| refused(error.to_string()))?
            .map(|sealed| self.open(&sealed))
            .transpose()
            .map_err(refused)?;
        let issuing = match sealed_at(&row, 0).map_err(|error| refused(error.to_string()))? {
            Some(sealed) => self.open(&sealed).map_err(refused)?,
            None => {
                // Minted once: the row is locked, so of the callers that find none together,
                // on any instance, one mints and the others read what it kept.
                let root: Zeroizing<[u8; KEY_BYTES]> = permguard_objects::crypto::random::bytes(
                    &permguard_objects::crypto::random::SystemEntropy,
                )
                .map_err(|error| refused(format!("minting a cursor root: {error}")))?;
                let sealed = self.seal(&root).map_err(refused)?;
                unit.execute(
                    "UPDATE permguard_cursor_roots
                     SET kek_ref = $2, kek_version = $3, wrap_algorithm = $4, wrapped = $5
                     WHERE store = $1",
                    &[
                        &self.store,
                        &sealed.kek_ref,
                        &i64::try_from(sealed.kek_version).unwrap_or(i64::MAX),
                        &sealed.wrap_algorithm,
                        &sealed.wrapped,
                    ],
                )?;
                Zeroizing::new(root.to_vec())
            }
        };
        Ok(Roots { issuing, previous })
    }
}

impl CursorRoots for PostgresCursorRoots {
    fn roots(&self) -> Result<Roots> {
        self.database
            .transaction(|unit| self.roots_in(unit))
            .map_err(|error| anyhow!("the cursor root of `{}`: {error}", self.store))?
            .map_err(|error| anyhow!("the cursor root of `{}`: {error}", self.store))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use permguard_postgres::testing::{Cases, sealer, server};

    use super::*;

    /// The PostgreSQL backend passes the contract's suite, each case in a database of its own.
    #[test]
    fn the_cursor_roots_keep_their_contract_sealed_on_postgresql() {
        let Some(server) = server("the_cursor_roots_keep_their_contract_sealed_on_postgresql")
        else {
            return;
        };
        let cases = Cases::new(server);
        super::super::suite::run(&|| {
            Arc::new(PostgresCursorRoots::new(
                cases.next(),
                sealer(),
                "decisions",
            ))
        });
    }

    /// A rotation moves the issuing root to the previous, accepted while it is kept, and the
    /// next ask mints another; no root is ever in the clear.
    #[test]
    fn a_cursor_root_rotates_on_postgresql() {
        let Some(server) = server("a_cursor_root_rotates_on_postgresql") else {
            return;
        };
        let cases = Cases::new(server);
        let database = cases.next();
        let store = PostgresCursorRoots::new(database.clone(), sealer(), "decisions");
        let first = store.roots().expect("minted");
        assert!(first.previous.is_none());
        store.rotate().expect("rotated");
        let second = store.roots().expect("minted again");
        assert_ne!(second.issuing.as_slice(), first.issuing.as_slice());
        assert_eq!(
            second.previous.as_deref().map(Vec::as_slice),
            Some(first.issuing.as_slice()),
            "the root before is still accepted"
        );
        // Another store of the same database has its own.
        let other = PostgresCursorRoots::new(database.clone(), sealer(), "events");
        assert_ne!(
            other.roots().expect("minted").issuing.as_slice(),
            second.issuing.as_slice()
        );
        let rows: Vec<Vec<u8>> = database
            .write(|unit| {
                Ok(unit
                    .query(
                        "SELECT wrapped FROM permguard_cursor_roots
                         UNION ALL SELECT previous_wrapped FROM permguard_cursor_roots
                         WHERE previous_wrapped IS NOT NULL",
                        &[],
                    )?
                    .into_iter()
                    .map(|row| row.get(0))
                    .collect())
            })
            .expect("read");
        for row in rows {
            for root in [first.issuing.as_slice(), second.issuing.as_slice()] {
                assert!(
                    !row.windows(root.len()).any(|window| window == root),
                    "a root in the clear"
                );
            }
        }
    }
}
