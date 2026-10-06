// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What each ledger operation *means* — the ledger twin of [`super::zones`], same rules:
//! one implementation, both transports, no wire in sight, authorization before lookup.

use permguard_core::Ledger;
use permguard_core::authz::{Actor, operations};
use permguard_core::catalog::Selector;

use super::{CatalogFacade, ledger_resource};
use crate::wire::Refusal;

#[tracing::instrument(name = "ledger.create", skip_all)]
pub(crate) async fn create(
    facade: &CatalogFacade,
    actor: &Actor,
    zone: &str,
    name: &str,
) -> Result<Ledger, Refusal> {
    // Creating in a zone is writing the zone.
    let resolved = facade.resolve_zone(actor, operations::CATALOG_WRITE, zone)?;
    let ledger = match facade
        .catalog
        .create_ledger(&Selector::Id(resolved.id), name)
    {
        Ok(ledger) => ledger,
        Err(error) => return Err(facade.refused("ledger.create.refused", error).await.into()),
    };

    facade.record("ledger.created", &ledger.id).await;

    Ok(ledger)
}

/// The ledgers of a zone the caller may read, windowed: a grant on one ledger is enough to name
/// the zone and see that ledger, and no other.
pub(crate) fn list(
    facade: &CatalogFacade,
    actor: &Actor,
    zone: &str,
    window: super::ListWindow,
) -> Result<Vec<Ledger>, Refusal> {
    let resolved = facade.resolve_zone_for_children(actor, operations::CATALOG_READ, zone)?;
    let ledgers = facade
        .catalog
        .list_ledgers(&Selector::Id(resolved.id.clone()))
        .map_err(super::api_error)?
        .into_iter()
        .filter(|ledger| {
            facade
                .authorize(
                    actor,
                    operations::CATALOG_READ,
                    &ledger_resource(&resolved.id, &ledger.id),
                )
                .is_ok()
        })
        .collect();

    Ok(window.apply(ledgers))
}

pub(crate) fn get(
    facade: &CatalogFacade,
    actor: &Actor,
    zone: &str,
    ledger: &str,
) -> Result<Ledger, Refusal> {
    facade
        .resolve_ledger(actor, operations::CATALOG_READ, zone, ledger)
        .map(|(_, ledger)| ledger)
}

#[tracing::instrument(name = "ledger.rename", skip_all)]
pub(crate) async fn rename(
    facade: &CatalogFacade,
    actor: &Actor,
    zone: &str,
    ledger: &str,
    name: &str,
) -> Result<Ledger, Refusal> {
    let (zone, resolved) = facade.resolve_ledger(actor, operations::CATALOG_WRITE, zone, ledger)?;
    let ledger =
        match facade
            .catalog
            .rename_ledger(&Selector::Id(zone.id), &Selector::Id(resolved.id), name)
        {
            Ok(ledger) => ledger,
            Err(error) => return Err(facade.refused("ledger.rename.refused", error).await.into()),
        };

    facade.record("ledger.renamed", &ledger.id).await;

    Ok(ledger)
}

#[tracing::instrument(name = "ledger.delete", skip_all)]
pub(crate) async fn delete(
    facade: &CatalogFacade,
    actor: &Actor,
    zone: &str,
    ledger: &str,
) -> Result<Ledger, Refusal> {
    let (zone, resolved) = facade.resolve_ledger(actor, operations::CATALOG_WRITE, zone, ledger)?;
    let ledger = match facade
        .catalog
        .delete_ledger(&Selector::Id(zone.id), &Selector::Id(resolved.id))
    {
        Ok(ledger) => ledger,
        Err(error) => return Err(facade.refused("ledger.delete.refused", error).await.into()),
    };

    facade.record("ledger.deleted", &ledger.id).await;

    Ok(ledger)
}
