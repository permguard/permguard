// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL backend of [`Catalog`]: the zones and the ledgers of one database.
//!
//! | Rule of the contract                              | Kept by                                     |
//! | ------------------------------------------------- | ------------------------------------------- |
//! | a zone's name is one in the deployment            | the unique key of `permguard_zones`         |
//! | a ledger's name is one in its zone                | the unique key of `permguard_ledgers`       |
//! | a zone that holds ledgers is not deleted          | the count and the delete in one transaction |
//! | a change held to a revision applies once          | the read and the write in one transaction   |
//! | an id that is gone is never minted again          | `permguard_catalog_tombstones`, by its key  |
//! | a name taken again starts above what it reached   | `permguard_catalog_marks`                   |
//!
//! Every call is one serializable unit of work: what it checked is what it wrote on, on any
//! instance.

use permguard_core::catalog::{
    Catalog, CatalogError, FIRST_REVISION, Ledger, LedgerState, Provenance, Selector, Tombstone,
    Write, validate_name,
};
use permguard_host::identity::record::{uuid_text, uuid_v7};
use postgres::Row;

use crate::database::{Database, Failure, Unit};

type Step<T> = Result<T, Failure<CatalogError>>;

/// The marks of the names the zones held.
const ZONE_NAMES: &str = "zones";
/// The marks of the paths `<zone name>/<ledger name>` the ledgers held.
const LEDGER_PATHS: &str = "paths";
/// How many ids are minted before a source that keeps minting buried ones is a failure.
const MINT_ATTEMPTS: usize = 8;

const ZONE: &str = "id, name, created_at, updated_at, revision, operation";
const LEDGER: &str = "id, zone_id, name, default_ref, created_at, updated_at, revision, \
                      operation, state, provenance";

/// The catalog of one database.
#[derive(Debug, Clone)]
pub struct PostgresCatalog {
    database: Database,
}

fn refused<T>(error: CatalogError) -> Step<T> {
    Err(Failure::Refused(error))
}

fn unread(what: &str) -> Failure<CatalogError> {
    Failure::Refused(CatalogError::backend(format!(
        "{what} held does not read as one"
    )))
}

fn number(row: &Row, column: usize) -> Step<u64> {
    u64::try_from(row.get::<_, i64>(column)).map_err(|_| unread("a number"))
}

fn stored(value: u64) -> Step<i64> {
    i64::try_from(value)
        .map_err(|_| Failure::Refused(CatalogError::backend("a number past what the store keeps")))
}

fn zone_of(row: &Row) -> Step<permguard_core::catalog::Zone> {
    Ok(permguard_core::catalog::Zone {
        id: row.get(0),
        name: row.get(1),
        created_at: number(row, 2)?,
        updated_at: number(row, 3)?,
        revision: number(row, 4)?,
        operation: row.get(5),
    })
}

fn ledger_of(row: &Row) -> Step<Ledger> {
    let provenance = row
        .get::<_, Option<String>>(9)
        .map(|text| serde_json::from_str::<Provenance>(&text))
        .transpose()
        .map_err(|_| unread("a provenance"))?;
    Ok(Ledger {
        id: row.get(0),
        zone_id: row.get(1),
        name: row.get(2),
        default_ref: row.get(3),
        created_at: number(row, 4)?,
        updated_at: number(row, 5)?,
        revision: number(row, 6)?,
        operation: row.get(7),
        state: match row.get::<_, &str>(8) {
            "active" => LedgerState::Active,
            "archived" => LedgerState::Archived,
            _ => return Err(unread("a ledger's state")),
        },
        provenance,
    })
}

fn column(selector: &Selector) -> &'static str {
    match selector {
        Selector::Id(_) => "id",
        Selector::Name(_) => "name",
    }
}

fn find_zone(unit: &Unit, zone: &Selector) -> Step<Option<permguard_core::catalog::Zone>> {
    unit.query_opt(
        &format!(
            "SELECT {ZONE} FROM permguard_zones WHERE {} = $1",
            column(zone)
        ),
        &[&zone.as_str()],
    )?
    .as_ref()
    .map(zone_of)
    .transpose()
}

fn require_zone(unit: &Unit, zone: &Selector) -> Step<permguard_core::catalog::Zone> {
    find_zone(unit, zone)?.map_or_else(|| refused(missing("zone", zone)), Ok)
}

fn find_ledger(unit: &Unit, zone_id: &str, ledger: &Selector) -> Step<Option<Ledger>> {
    unit.query_opt(
        &format!(
            "SELECT {LEDGER} FROM permguard_ledgers WHERE zone_id = $1 AND {} = $2",
            column(ledger)
        ),
        &[&zone_id, &ledger.as_str()],
    )?
    .as_ref()
    .map(ledger_of)
    .transpose()
}

fn missing(kind: &'static str, selector: &Selector) -> CatalogError {
    CatalogError::NotFound {
        kind,
        selector: selector.to_string(),
    }
}

fn stale(kind: &'static str, selector: &Selector, current: u64) -> CatalogError {
    CatalogError::RevisionConflict {
        kind,
        selector: selector.to_string(),
        current,
    }
}

fn ledger_names(zone_id: &str) -> String {
    format!("ledgers/{zone_id}")
}

fn path(zone_name: &str, ledger_name: &str) -> String {
    format!("{zone_name}/{ledger_name}")
}

/// The revision a record created under `name` starts at: one above the highest any record
/// reached under it, [`FIRST_REVISION`] for a name never held.
fn first_revision_for(unit: &Unit, scope: &str, name: &str) -> Step<u64> {
    match unit.query_opt(
        "SELECT reached FROM permguard_catalog_marks WHERE scope = $1 AND name = $2",
        &[&scope, &name],
    )? {
        Some(row) => Ok(number(&row, 0)?.saturating_add(1)),
        None => Ok(FIRST_REVISION),
    }
}

/// Records that a record leaves `name` at `revision`, in the unit of work that moves it.
fn mark_name(unit: &Unit, scope: &str, name: &str, revision: u64) -> Step<()> {
    unit.execute(
        "INSERT INTO permguard_catalog_marks (scope, name, reached) VALUES ($1, $2, $3)
         ON CONFLICT (scope, name) DO UPDATE
         SET reached = GREATEST(permguard_catalog_marks.reached, EXCLUDED.reached)",
        &[&scope, &name, &stored(revision)?],
    )?;
    Ok(())
}

/// An id no zone or ledger ever had: a UUIDv7 whose moment and random bits are the database's.
fn fresh(unit: &Unit) -> Step<String> {
    for _ in 0..MINT_ATTEMPTS {
        let row = unit.query_one(
            "SELECT uuid_send(gen_random_uuid()),
                    (extract(epoch FROM clock_timestamp()) * 1000)::bigint",
            &[],
        )?;
        let random: [u8; 10] = row
            .get::<_, Vec<u8>>(0)
            .get(6..)
            .and_then(|bits| bits.try_into().ok())
            .ok_or_else(|| unread("a random id"))?;
        let id = uuid_text(&uuid_v7(number(&row, 1)?, random));
        let buried = unit
            .query_opt(
                "SELECT 1 FROM permguard_catalog_tombstones WHERE id = $1",
                &[&id],
            )?
            .is_some();
        if !buried {
            return Ok(id);
        }
    }
    refused(CatalogError::backend(
        "every id minted has a tombstone: the random source is not random",
    ))
}

fn bury(
    unit: &Unit,
    id: &str,
    zone_id: Option<&str>,
    name: &str,
    revision: u64,
    write: &Write<'_>,
) -> Step<()> {
    unit.execute(
        "INSERT INTO permguard_catalog_tombstones
             (id, zone_id, name, deleted_at, revision, operation)
         VALUES ($1, $2, $3, $4, $5, $6)",
        &[
            &id,
            &zone_id,
            &name,
            &stored(permguard_core::time::unix_now())?,
            &stored(revision)?,
            &write.operation,
        ],
    )?;
    Ok(())
}

fn tombstone(unit: &Unit, id: &str, zone_id: Option<&str>) -> Step<Option<Tombstone>> {
    unit.query_opt(
        "SELECT id, zone_id, name, deleted_at, revision, operation
         FROM permguard_catalog_tombstones
         WHERE id = $1 AND zone_id IS NOT DISTINCT FROM $2",
        &[&id, &zone_id],
    )?
    .map(|row| {
        Ok(Tombstone {
            id: row.get(0),
            zone_id: row.get(1),
            name: row.get(2),
            deleted_at: number(&row, 3)?,
            revision: number(&row, 4)?,
            operation: row.get(5),
        })
    })
    .transpose()
}

impl PostgresCatalog {
    /// The catalog of `database`, whose schema is this build's.
    pub fn new(database: Database) -> Self {
        Self { database }
    }

    fn unit<T>(&self, work: impl Fn(&Unit) -> Step<T>) -> Result<T, CatalogError> {
        self.database
            .transaction(work)
            .map_err(CatalogError::backend)?
    }

    /// Writes `ledger` over the row of its id and answers it.
    fn rewrite(unit: &Unit, ledger: Ledger) -> Step<Ledger> {
        unit.execute(
            "UPDATE permguard_ledgers
             SET name = $2, updated_at = $3, revision = $4, operation = $5, state = $6
             WHERE id = $1",
            &[
                &ledger.id,
                &ledger.name,
                &stored(ledger.updated_at)?,
                &stored(ledger.revision)?,
                &ledger.operation,
                &ledger.state.as_str(),
            ],
        )?;
        Ok(ledger)
    }
}

impl Catalog for PostgresCatalog {
    fn name(&self) -> &'static str {
        "postgresql"
    }

    fn create_zone_with(
        &self,
        name: &str,
        write: &Write<'_>,
    ) -> Result<permguard_core::catalog::Zone, CatalogError> {
        validate_name(name)?;
        self.unit(|unit| {
            if find_zone(unit, &Selector::Name(name.to_owned()))?.is_some() {
                return refused(CatalogError::NameTaken {
                    name: name.to_owned(),
                    scope: "this deployment's zones".to_owned(),
                });
            }
            let at = permguard_core::time::unix_now();
            let zone = permguard_core::catalog::Zone {
                id: fresh(unit)?,
                name: name.to_owned(),
                created_at: at,
                updated_at: at,
                revision: first_revision_for(unit, ZONE_NAMES, name)?,
                operation: write.operation.map(str::to_owned),
            };
            unit.execute(
                "INSERT INTO permguard_zones (id, name, created_at, updated_at, revision, operation)
                 VALUES ($1, $2, $3, $3, $4, $5)",
                &[
                    &zone.id,
                    &zone.name,
                    &stored(at)?,
                    &stored(zone.revision)?,
                    &zone.operation,
                ],
            )?;
            Ok(zone)
        })
    }

    fn list_zones(&self) -> Result<Vec<permguard_core::catalog::Zone>, CatalogError> {
        self.unit(|unit| {
            unit.query(
                &format!("SELECT {ZONE} FROM permguard_zones ORDER BY position"),
                &[],
            )?
            .iter()
            .map(zone_of)
            .collect()
        })
    }

    fn get_zone(&self, zone: &Selector) -> Result<permguard_core::catalog::Zone, CatalogError> {
        self.unit(|unit| require_zone(unit, zone))
    }

    fn rename_zone_with(
        &self,
        zone: &Selector,
        name: &str,
        write: &Write<'_>,
    ) -> Result<permguard_core::catalog::Zone, CatalogError> {
        validate_name(name)?;
        self.unit(|unit| {
            let found = find_zone(unit, zone)?;
            // The revision first: a change that expected another one applies nothing.
            if let Some(found) = &found
                && !write.admits(found.revision)
            {
                return refused(stale("zone", zone, found.revision));
            }
            let holder = find_zone(unit, &Selector::Name(name.to_owned()))?;
            if holder
                .as_ref()
                .is_some_and(|holder| found.as_ref().is_none_or(|found| found.id != holder.id))
            {
                return refused(CatalogError::NameTaken {
                    name: name.to_owned(),
                    scope: "this deployment's zones".to_owned(),
                });
            }
            let Some(mut found) = found else {
                return refused(missing("zone", zone));
            };
            // A rename to the name it has changes nothing: no revision, no write.
            if found.name == name {
                return Ok(found);
            }
            mark_name(unit, ZONE_NAMES, &found.name, found.revision)?;
            // Its ledgers leave their paths under the old name with it: a zone that takes that
            // name later creates its ledgers above them.
            for row in unit.query(
                "SELECT name, revision FROM permguard_ledgers WHERE zone_id = $1",
                &[&found.id],
            )? {
                let ledger: String = row.get(0);
                mark_name(
                    unit,
                    LEDGER_PATHS,
                    &path(&found.name, &ledger),
                    number(&row, 1)?,
                )?;
            }
            found.name = name.to_owned();
            found.updated_at = permguard_core::time::unix_now();
            found.revision = found
                .revision
                .max(first_revision_for(unit, ZONE_NAMES, name)?.saturating_sub(1))
                + 1;
            found.operation = write.operation.map(str::to_owned);
            unit.execute(
                "UPDATE permguard_zones
                 SET name = $2, updated_at = $3, revision = $4, operation = $5 WHERE id = $1",
                &[
                    &found.id,
                    &found.name,
                    &stored(found.updated_at)?,
                    &stored(found.revision)?,
                    &found.operation,
                ],
            )?;
            Ok(found)
        })
    }

    fn delete_zone_with(
        &self,
        zone: &Selector,
        write: &Write<'_>,
    ) -> Result<permguard_core::catalog::Zone, CatalogError> {
        self.unit(|unit| {
            let found = require_zone(unit, zone)?;
            if !write.admits(found.revision) {
                return refused(stale("zone", zone, found.revision));
            }
            let ledgers: i64 = unit
                .query_one(
                    "SELECT COUNT(*) FROM permguard_ledgers WHERE zone_id = $1",
                    &[&found.id],
                )?
                .get(0);
            if ledgers > 0 {
                return refused(CatalogError::NotEmpty {
                    zone: found.name.clone(),
                    ledgers: usize::try_from(ledgers).unwrap_or(usize::MAX),
                });
            }
            mark_name(unit, ZONE_NAMES, &found.name, found.revision)?;
            bury(unit, &found.id, None, &found.name, found.revision, write)?;
            unit.execute("DELETE FROM permguard_zones WHERE id = $1", &[&found.id])?;
            Ok(found)
        })
    }

    fn create_ledger_with(
        &self,
        zone: &Selector,
        name: &str,
        write: &Write<'_>,
    ) -> Result<Ledger, CatalogError> {
        validate_name(name)?;
        self.unit(|unit| {
            let owner = require_zone(unit, zone)?;
            if find_ledger(unit, &owner.id, &Selector::Name(name.to_owned()))?.is_some() {
                return refused(CatalogError::NameTaken {
                    name: name.to_owned(),
                    scope: format!("the zone `{}`", owner.name),
                });
            }
            let at = permguard_core::time::unix_now();
            let ledger = Ledger {
                id: fresh(unit)?,
                zone_id: owner.id.clone(),
                name: name.to_owned(),
                default_ref: "main".to_owned(),
                created_at: at,
                updated_at: at,
                revision: first_revision_for(unit, &ledger_names(&owner.id), name)?.max(
                    first_revision_for(unit, LEDGER_PATHS, &path(&owner.name, name))?,
                ),
                operation: write.operation.map(str::to_owned),
                state: LedgerState::Active,
                provenance: write.provenance.cloned(),
            };
            let provenance = ledger
                .provenance
                .as_ref()
                .map(serde_json::to_string)
                .transpose()
                .map_err(|error| {
                    Failure::Refused(CatalogError::backend(format!(
                        "a provenance does not encode: {error}"
                    )))
                })?;
            unit.execute(
                "INSERT INTO permguard_ledgers
                     (id, zone_id, name, default_ref, created_at, updated_at, revision,
                      operation, state, provenance)
                 VALUES ($1, $2, $3, $4, $5, $5, $6, $7, $8, $9)",
                &[
                    &ledger.id,
                    &ledger.zone_id,
                    &ledger.name,
                    &ledger.default_ref,
                    &stored(at)?,
                    &stored(ledger.revision)?,
                    &ledger.operation,
                    &ledger.state.as_str(),
                    &provenance,
                ],
            )?;
            Ok(ledger)
        })
    }

    fn list_ledgers(&self, zone: &Selector) -> Result<Vec<Ledger>, CatalogError> {
        self.unit(|unit| {
            let owner = require_zone(unit, zone)?;
            unit.query(
                &format!(
                    "SELECT {LEDGER} FROM permguard_ledgers WHERE zone_id = $1 ORDER BY position"
                ),
                &[&owner.id],
            )?
            .iter()
            .map(ledger_of)
            .collect()
        })
    }

    fn get_ledger(&self, zone: &Selector, ledger: &Selector) -> Result<Ledger, CatalogError> {
        self.unit(|unit| {
            let owner = require_zone(unit, zone)?;
            find_ledger(unit, &owner.id, ledger)?
                .map_or_else(|| refused(missing("ledger", ledger)), Ok)
        })
    }

    fn rename_ledger_with(
        &self,
        zone: &Selector,
        ledger: &Selector,
        name: &str,
        write: &Write<'_>,
    ) -> Result<Ledger, CatalogError> {
        validate_name(name)?;
        self.unit(|unit| {
            let owner = require_zone(unit, zone)?;
            let found = find_ledger(unit, &owner.id, ledger)?;
            if let Some(found) = &found
                && !write.admits(found.revision)
            {
                return refused(stale("ledger", ledger, found.revision));
            }
            let holder = find_ledger(unit, &owner.id, &Selector::Name(name.to_owned()))?;
            if holder
                .as_ref()
                .is_some_and(|holder| found.as_ref().is_none_or(|found| found.id != holder.id))
            {
                return refused(CatalogError::NameTaken {
                    name: name.to_owned(),
                    scope: format!("the zone `{}`", owner.name),
                });
            }
            let Some(mut found) = found else {
                return refused(missing("ledger", ledger));
            };
            // A rename to the name it has changes nothing: no revision, no write.
            if found.name == name {
                return Ok(found);
            }
            let names = ledger_names(&owner.id);
            mark_name(unit, &names, &found.name, found.revision)?;
            mark_name(
                unit,
                LEDGER_PATHS,
                &path(&owner.name, &found.name),
                found.revision,
            )?;
            found.revision = found
                .revision
                .max(first_revision_for(unit, &names, name)?.saturating_sub(1))
                .max(
                    first_revision_for(unit, LEDGER_PATHS, &path(&owner.name, name))?
                        .saturating_sub(1),
                )
                + 1;
            found.name = name.to_owned();
            found.updated_at = permguard_core::time::unix_now();
            found.operation = write.operation.map(str::to_owned);
            Self::rewrite(unit, found)
        })
    }

    fn delete_ledger_with(
        &self,
        zone: &Selector,
        ledger: &Selector,
        write: &Write<'_>,
    ) -> Result<Ledger, CatalogError> {
        self.unit(|unit| {
            let owner = require_zone(unit, zone)?;
            let Some(found) = find_ledger(unit, &owner.id, ledger)? else {
                return refused(missing("ledger", ledger));
            };
            if !write.admits(found.revision) {
                return refused(stale("ledger", ledger, found.revision));
            }
            mark_name(unit, &ledger_names(&owner.id), &found.name, found.revision)?;
            mark_name(
                unit,
                LEDGER_PATHS,
                &path(&owner.name, &found.name),
                found.revision,
            )?;
            bury(
                unit,
                &found.id,
                Some(&owner.id),
                &found.name,
                found.revision,
                write,
            )?;
            unit.execute("DELETE FROM permguard_ledgers WHERE id = $1", &[&found.id])?;
            Ok(found)
        })
    }

    fn zone_tombstone(&self, zone_id: &str) -> Result<Option<Tombstone>, CatalogError> {
        self.unit(|unit| tombstone(unit, zone_id, None))
    }

    fn ledger_tombstone(
        &self,
        zone_id: &str,
        ledger_id: &str,
    ) -> Result<Option<Tombstone>, CatalogError> {
        self.unit(|unit| tombstone(unit, ledger_id, Some(zone_id)))
    }

    fn set_ledger_state_with(
        &self,
        zone: &Selector,
        ledger: &Selector,
        state: LedgerState,
        write: &Write<'_>,
    ) -> Result<Ledger, CatalogError> {
        self.unit(|unit| {
            let owner = require_zone(unit, zone)?;
            let Some(mut found) = find_ledger(unit, &owner.id, ledger)? else {
                return refused(missing("ledger", ledger));
            };
            if !write.admits(found.revision) {
                return refused(stale("ledger", ledger, found.revision));
            }
            // A state it is already in changes nothing: no revision, no write.
            if found.state == state {
                return Ok(found);
            }
            found.state = state;
            found.updated_at = permguard_core::time::unix_now();
            found.revision += 1;
            found.operation = write.operation.map(str::to_owned);
            Self::rewrite(unit, found)
        })
    }
}
