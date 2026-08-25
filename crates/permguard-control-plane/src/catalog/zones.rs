// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What each zone operation *means*: the domain, with no wire in sight.
//!
//! Every function here is the single implementation both transports call, so HTTP and gRPC cannot
//! drift apart on semantics, auditing or errors. Anything a transport needs beyond `Result` — a
//! status code, a metadata key — is [`crate::wire`]'s business.

use permguard_core::catalog::Selector;
use permguard_core::{ApiError, Zone};

use super::{CatalogFacade, api_error};

#[tracing::instrument(name = "zone.create", skip_all)]
pub(crate) async fn create(facade: &CatalogFacade, name: &str) -> Result<Zone, ApiError> {
    let zone = match facade.catalog.create_zone(name) {
        Ok(zone) => zone,
        Err(error) => return Err(facade.refused("zone.create.refused", error).await),
    };

    facade.record("zone.created", &zone.id).await;

    Ok(zone)
}

pub(crate) fn list(
    facade: &CatalogFacade,
    window: super::ListWindow,
) -> Result<Vec<Zone>, ApiError> {
    facade
        .catalog
        .list_zones()
        .map(|zones| window.apply(zones))
        .map_err(api_error)
}

pub(crate) fn get(facade: &CatalogFacade, zone: &str) -> Result<Zone, ApiError> {
    facade
        .catalog
        .get_zone(&Selector::parse(zone))
        .map_err(api_error)
}

#[tracing::instrument(name = "zone.rename", skip_all)]
pub(crate) async fn rename(
    facade: &CatalogFacade,
    zone: &str,
    name: &str,
) -> Result<Zone, ApiError> {
    let zone = match facade.catalog.rename_zone(&Selector::parse(zone), name) {
        Ok(zone) => zone,
        Err(error) => return Err(facade.refused("zone.rename.refused", error).await),
    };

    facade.record("zone.renamed", &zone.id).await;

    Ok(zone)
}

#[tracing::instrument(name = "zone.delete", skip_all)]
pub(crate) async fn delete(facade: &CatalogFacade, zone: &str) -> Result<Zone, ApiError> {
    let zone = match facade.catalog.delete_zone(&Selector::parse(zone)) {
        Ok(zone) => zone,
        Err(error) => return Err(facade.refused("zone.delete.refused", error).await),
    };

    facade.record("zone.deleted", &zone.id).await;

    Ok(zone)
}
