// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What each ledger operation *means* — the ledger twin of [`super::zones`], same rules:
//! one implementation, both transports, no wire in sight.

use permguard_core::catalog::Selector;
use permguard_core::{ApiError, Ledger};

use super::{CatalogFacade, api_error};

#[tracing::instrument(name = "ledger.create", skip_all)]
pub(crate) async fn create(
    facade: &CatalogFacade,
    zone: &str,
    name: &str,
) -> Result<Ledger, ApiError> {
    let ledger = match facade.catalog.create_ledger(&Selector::parse(zone), name) {
        Ok(ledger) => ledger,
        Err(error) => return Err(facade.refused("ledger.create.refused", error).await),
    };

    facade.record("ledger.created", &ledger.id).await;

    Ok(ledger)
}

pub(crate) fn list(
    facade: &CatalogFacade,
    zone: &str,
    window: super::ListWindow,
) -> Result<Vec<Ledger>, ApiError> {
    facade
        .catalog
        .list_ledgers(&Selector::parse(zone))
        .map(|ledgers| window.apply(ledgers))
        .map_err(api_error)
}

pub(crate) fn get(facade: &CatalogFacade, zone: &str, ledger: &str) -> Result<Ledger, ApiError> {
    facade
        .catalog
        .get_ledger(&Selector::parse(zone), &Selector::parse(ledger))
        .map_err(api_error)
}

#[tracing::instrument(name = "ledger.rename", skip_all)]
pub(crate) async fn rename(
    facade: &CatalogFacade,
    zone: &str,
    ledger: &str,
    name: &str,
) -> Result<Ledger, ApiError> {
    let ledger =
        match facade
            .catalog
            .rename_ledger(&Selector::parse(zone), &Selector::parse(ledger), name)
        {
            Ok(ledger) => ledger,
            Err(error) => return Err(facade.refused("ledger.rename.refused", error).await),
        };

    facade.record("ledger.renamed", &ledger.id).await;

    Ok(ledger)
}

#[tracing::instrument(name = "ledger.delete", skip_all)]
pub(crate) async fn delete(
    facade: &CatalogFacade,
    zone: &str,
    ledger: &str,
) -> Result<Ledger, ApiError> {
    let ledger = match facade
        .catalog
        .delete_ledger(&Selector::parse(zone), &Selector::parse(ledger))
    {
        Ok(ledger) => ledger,
        Err(error) => return Err(facade.refused("ledger.delete.refused", error).await),
    };

    facade.record("ledger.deleted", &ledger.id).await;

    Ok(ledger)
}
