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
use permguard_core::catalog::{Selector, Write};

use super::{CatalogFacade, plane_resource, zone_resource};
use crate::wire::Refusal;

#[tracing::instrument(name = "zone.create", skip_all)]
pub(crate) async fn create(
    facade: &CatalogFacade,
    actor: &Actor,
    name: &str,
    request_id: &str,
) -> Result<Zone, Refusal> {
    facade.authorize(actor, operations::CATALOG_WRITE, &plane_resource())?;
    let change = super::Change {
        request_id,
        request: serde_json::json!({ "name": name }),
        name: Some(name),
    };
    facade
        .mutate(
            actor,
            super::ZONE_CREATE,
            change,
            super::target::NEW_ZONE.to_owned(),
            |write| facade.catalog.create_zone_with(name, write),
        )
        .await
        .map(Zone::public)
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
        .map(Zone::public)
        .collect();

    Ok(window.apply(zones))
}

pub(crate) fn get(facade: &CatalogFacade, actor: &Actor, zone: &str) -> Result<Zone, Refusal> {
    facade
        .resolve_zone(actor, operations::CATALOG_READ, zone)
        .map(Zone::public)
}

#[tracing::instrument(name = "zone.rename", skip_all)]
pub(crate) async fn rename(
    facade: &CatalogFacade,
    actor: &Actor,
    zone: &str,
    name: &str,
    expected_revision: u64,
    request_id: &str,
) -> Result<Zone, Refusal> {
    let change = super::Change {
        request_id,
        request: serde_json::json!({
            "zone": zone,
            "name": name,
            "expected_revision": expected_revision,
        }),
        name: Some(name),
    };
    // A retry learns the first answer before the zone is resolved, which that answer may have
    // renamed (after the review); the admission check comes first, as it does for a lookup.
    facade
        .authorization
        .may_act_under(actor, operations::CATALOG_WRITE, &plane_resource())?;
    if let Some(done) = facade.replayed(actor, super::ZONE_RENAME, &change).await? {
        return Ok(Zone::public(done));
    }
    let resolved = facade.resolve_zone(actor, operations::CATALOG_WRITE, zone)?;
    let id = Selector::Id(resolved.id.clone());
    facade
        .mutate(
            actor,
            super::ZONE_RENAME,
            change,
            super::target::zone(&resolved.id),
            |write| {
                facade.catalog.rename_zone_with(
                    &id,
                    name,
                    &Write {
                        expected_revision: Some(expected_revision),
                        ..*write
                    },
                )
            },
        )
        .await
        .map(Zone::public)
}

#[tracing::instrument(name = "zone.delete", skip_all)]
pub(crate) async fn delete(
    facade: &CatalogFacade,
    actor: &Actor,
    zone: &str,
    expected_revision: u64,
    request_id: &str,
) -> Result<Zone, Refusal> {
    let change = super::Change {
        request_id,
        request: serde_json::json!({ "zone": zone, "expected_revision": expected_revision }),
        name: None,
    };
    // A retry learns the first answer before the zone, which that answer deleted, is resolved.
    facade
        .authorization
        .may_act_under(actor, operations::CATALOG_WRITE, &plane_resource())?;
    if let Some(done) = facade.replayed(actor, super::ZONE_DELETE, &change).await? {
        return Ok(Zone::public(done));
    }
    let resolved = facade.resolve_zone(actor, operations::CATALOG_WRITE, zone)?;
    let id = Selector::Id(resolved.id.clone());
    facade
        .mutate(
            actor,
            super::ZONE_DELETE,
            change,
            super::target::zone(&resolved.id),
            |write| {
                facade.catalog.delete_zone_with(
                    &id,
                    &Write {
                        expected_revision: Some(expected_revision),
                        ..*write
                    },
                )
            },
        )
        .await
        .map(Zone::public)
}
