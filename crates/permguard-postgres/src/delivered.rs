// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL backend of [`DeliveredKeys`]: the zone keys delivered to this Host, each
//! sealed (iteration 03, WP-27.5).
//!
//! A delivered key is a secret: a row holds it sealed by the key-encryption key of the `file`
//! custody, held outside the database, bound to this Host and to the key's coordinates, so a row
//! copied under other coordinates, or edited, does not open. A key sealed under the
//! key-encryption key a rotation left behind is opened and sealed again under the current one.

use std::sync::Arc;

use zeroize::Zeroizing;

use permguard_host::secrets::sealed::{Sealed, Sealer};
use permguard_host::secrets::{DeliveredKeys, KeyVersion, SecretsError, ZonePurpose, ZoneTuple};
use permguard_objects::crypto::kdf::KEY_LEN;

use crate::database::{Database, Failure, Unit};

/// What the seal of a delivered key names it for.
const PURPOSE: &str = permguard_core::domains::kdf::ZONE_USE;

/// The delivered zone keys of the Host of one database.
#[derive(Debug, Clone)]
pub struct PostgresDeliveredKeys {
    database: Database,
    sealer: Arc<Sealer>,
}

fn storage(error: impl std::fmt::Display) -> SecretsError {
    SecretsError::Storage(error.to_string())
}

/// The name a key's seal binds it to: its coordinates.
fn name(tuple: &ZoneTuple) -> String {
    let hex = permguard_core::encoding::hex;
    format!(
        "{}/{}/{}/{}/v{}",
        hex(&tuple.authority),
        hex(&tuple.zone),
        tuple.purpose.as_str(),
        hex(&tuple.scope),
        tuple.version.get()
    )
}

type Step<T> = Result<T, Failure<SecretsError>>;

fn version(value: u64) -> Step<i64> {
    i64::try_from(value).map_err(|_| Failure::Refused(storage("a version past its range")))
}

impl PostgresDeliveredKeys {
    /// The delivered keys kept in `database`, whose schema is this build's, sealed by `sealer`.
    pub fn new(database: Database, sealer: Arc<Sealer>) -> Self {
        Self { database, sealer }
    }

    /// The key held under `tuple`, opened, and sealed again in `unit` when its key-encryption
    /// key is the one a rotation left behind.
    fn held(&self, unit: &Unit, tuple: &ZoneTuple) -> Step<Option<Zeroizing<[u8; KEY_LEN]>>> {
        let Some(row) = unit.query_opt(
            "SELECT kek_ref, kek_version, wrap_algorithm, wrapped FROM permguard_delivered_keys
             WHERE authority = $1 AND zone = $2 AND purpose = $3 AND scope = $4 AND version = $5",
            &[
                &tuple.authority.as_slice(),
                &tuple.zone.as_slice(),
                &tuple.purpose.as_str(),
                &tuple.scope.as_slice(),
                &version(tuple.version.get())?,
            ],
        )?
        else {
            return Ok(None);
        };
        let sealed = Sealed {
            kek_ref: row.get(0),
            kek_version: u64::try_from(row.get::<_, i64>(1)).map_err(|_| {
                Failure::Refused(storage("a key-encryption key version held is none"))
            })?,
            wrap_algorithm: row.get(2),
            wrapped: row.get(3),
        };
        let name = name(tuple);
        let opened = self
            .sealer
            .open(PURPOSE, &name, &sealed)
            .map_err(|error| Failure::Refused(storage(error)))?;
        if opened.stale {
            self.write(unit, tuple, &opened.secret, true)?;
        }
        Ok(Some(opened.secret))
    }

    /// Seals `key` and writes it under `tuple`: in place of the row held when `replace`, only
    /// where none is held otherwise.
    fn write(
        &self,
        unit: &Unit,
        tuple: &ZoneTuple,
        key: &[u8; KEY_LEN],
        replace: bool,
    ) -> Step<u64> {
        let sealed = self
            .sealer
            .seal(PURPOSE, &name(tuple), key)
            .map_err(|error| Failure::Refused(storage(error)))?;
        let conflict = if replace {
            "DO UPDATE SET kek_ref = EXCLUDED.kek_ref, kek_version = EXCLUDED.kek_version,
                 wrap_algorithm = EXCLUDED.wrap_algorithm, wrapped = EXCLUDED.wrapped"
        } else {
            "DO NOTHING"
        };
        Ok(unit.execute(
            &format!(
                "INSERT INTO permguard_delivered_keys
                     (authority, zone, purpose, scope, version, kek_ref, kek_version,
                      wrap_algorithm, wrapped)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                 ON CONFLICT (authority, zone, purpose, scope, version) {conflict}"
            ),
            &[
                &tuple.authority.as_slice(),
                &tuple.zone.as_slice(),
                &tuple.purpose.as_str(),
                &tuple.scope.as_slice(),
                &version(tuple.version.get())?,
                &sealed.kek_ref,
                &version(sealed.kek_version)?,
                &sealed.wrap_algorithm,
                &sealed.wrapped,
            ],
        )?)
    }
}

impl DeliveredKeys for PostgresDeliveredKeys {
    fn keep(
        &self,
        tuple: &ZoneTuple,
        key: &[u8; KEY_LEN],
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, SecretsError> {
        self.database
            .transaction(|unit| {
                // Kept once: of the keys that arrive together under one tuple, on any instance,
                // the key of the table keeps one, and every caller is answered that one.
                self.write(unit, tuple, key, false)?;
                self.held(unit, tuple)?
                    .ok_or_else(|| Failure::Refused(storage("a key kept vanished")))
            })
            .map_err(storage)?
    }

    fn key(&self, tuple: &ZoneTuple) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>, SecretsError> {
        self.database
            .transaction(|unit| self.held(unit, tuple))
            .map_err(storage)?
    }

    fn delivered(
        &self,
        authority: &[u8; 16],
        purpose: ZonePurpose,
        version_of: KeyVersion,
    ) -> Result<Vec<ZoneTuple>, SecretsError> {
        let rows = self
            .database
            .write(|unit| {
                unit.query(
                    "SELECT zone, scope FROM permguard_delivered_keys
                     WHERE authority = $1 AND purpose = $2 AND version = $3
                     ORDER BY zone, scope",
                    &[
                        &authority.as_slice(),
                        &purpose.as_str(),
                        &i64::try_from(version_of.get()).unwrap_or(i64::MAX),
                    ],
                )
            })
            .map_err(storage)?;
        rows.into_iter()
            .map(|row| {
                let id = |at: usize| {
                    <[u8; 16]>::try_from(row.get::<_, Vec<u8>>(at))
                        .map_err(|_| storage("an id held is not 16 bytes"))
                };
                Ok(ZoneTuple {
                    authority: *authority,
                    zone: id(0)?,
                    purpose,
                    scope: id(1)?,
                    version: version_of,
                })
            })
            .collect()
    }
}
