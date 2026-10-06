// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What each zone operation *means*: the domain, with no wire in sight.
//!
//! Every function here is the single implementation both transports call, so HTTP and gRPC cannot
//! drift apart on semantics, auditing or errors. Anything a transport needs beyond `Result` — a
//! status code, a metadata key — is [`crate::wire`]'s business.
//!
//! Authorization comes first (WP-2.4): `catalog.read` or `catalog.write` on the plane for what
//! creates or lists, on the exact zone for what names one; the facade resolves a name only after
//! the caller is known to hold something here, and never discloses what lies outside its grants.

use permguard_core::Zone;
use permguard_core::authz::{Actor, operations};
use permguard_core::catalog::Selector;

use super::{CatalogFacade, plane_resource, zone_resource};
use crate::wire::Refusal;

#[tracing::instrument(name = "zone.create", skip_all)]
pub(crate) async fn create(
    facade: &CatalogFacade,
    actor: &Actor,
    name: &str,
) -> Result<Zone, Refusal> {
    facade.authorize(actor, operations::CATALOG_WRITE, &plane_resource())?;
    let zone = match facade.catalog.create_zone(name) {
        Ok(zone) => zone,
        Err(error) => return Err(facade.refused("zone.create.refused", error).await.into()),
    };

    facade.record("zone.created", &zone.id).await;

    Ok(zone)
}

/// The zones the caller may read, windowed. A caller with no `catalog.read` anywhere under the
/// plane is refused; one with grants on some zones sees those and no other.
pub(crate) fn list(
    facade: &CatalogFacade,
    actor: &Actor,
    window: super::ListWindow,
) -> Result<Vec<Zone>, Refusal> {
    facade
        .authorization
        .may_act_under(actor, operations::CATALOG_READ, &plane_resource())?;
    let zones = facade
        .catalog
        .list_zones()
        .map_err(super::api_error)?
        .into_iter()
        .filter(|zone| {
            facade
                .authorize(actor, operations::CATALOG_READ, &zone_resource(&zone.id))
                .is_ok()
        })
        .collect();

    Ok(window.apply(zones))
}

pub(crate) fn get(facade: &CatalogFacade, actor: &Actor, zone: &str) -> Result<Zone, Refusal> {
    facade.resolve_zone(actor, operations::CATALOG_READ, zone)
}

#[tracing::instrument(name = "zone.rename", skip_all)]
pub(crate) async fn rename(
    facade: &CatalogFacade,
    actor: &Actor,
    zone: &str,
    name: &str,
) -> Result<Zone, Refusal> {
    let resolved = facade.resolve_zone(actor, operations::CATALOG_WRITE, zone)?;
    let zone = match facade.catalog.rename_zone(&Selector::Id(resolved.id), name) {
        Ok(zone) => zone,
        Err(error) => return Err(facade.refused("zone.rename.refused", error).await.into()),
    };

    facade.record("zone.renamed", &zone.id).await;

    Ok(zone)
}

#[tracing::instrument(name = "zone.delete", skip_all)]
pub(crate) async fn delete(
    facade: &CatalogFacade,
    actor: &Actor,
    zone: &str,
) -> Result<Zone, Refusal> {
    let resolved = facade.resolve_zone(actor, operations::CATALOG_WRITE, zone)?;
    let zone = match facade.catalog.delete_zone(&Selector::Id(resolved.id)) {
        Ok(zone) => zone,
        Err(error) => return Err(facade.refused("zone.delete.refused", error).await.into()),
    };

    facade.record("zone.deleted", &zone.id).await;

    Ok(zone)
}
