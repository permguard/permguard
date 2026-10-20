// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What each ledger operation *means* — the ledger twin of [`super::zones`], same rules:
//! one implementation, both transports, no wire in sight, authorization before lookup.

use permguard_core::Ledger;
use permguard_core::authz::{Actor, operations};
use permguard_core::catalog::{Selector, Write};

use super::{CatalogFacade, ledger_resource};
use crate::wire::Refusal;

/// A retry learns the first answer before anything is resolved, which that answer may have
/// renamed or deleted (after the review); the admission check comes first, as it does for a
/// lookup.
async fn replayed(
    facade: &CatalogFacade,
    actor: &Actor,
    mutation: super::Mutation,
    change: &super::Change<'_>,
) -> Result<Option<Ledger>, Refusal> {
    facade.authorization.may_act_under(
        actor,
        operations::CATALOG_WRITE,
        &super::plane_resource(),
    )?;
    facade.replayed(actor, mutation, change).await
}

#[tracing::instrument(name = "ledger.create", skip_all)]
pub(crate) async fn create(
    facade: &CatalogFacade,
    actor: &Actor,
    zone: &str,
    name: &str,
    request_id: &str,
) -> Result<Ledger, Refusal> {
    let change = super::Change {
        request_id,
        request: serde_json::json!({ "zone": zone, "name": name }),
        name: Some(name),
    };
    if let Some(done) = replayed(facade, actor, super::LEDGER_CREATE, &change).await? {
        return Ok(Ledger::public(done));
    }
    // Creating in a zone is writing the zone.
    let resolved = facade.resolve_zone(actor, operations::CATALOG_WRITE, zone)?;
    let zone_id = Selector::Id(resolved.id.clone());
    facade
        .mutate(
            actor,
            super::LEDGER_CREATE,
            change,
            super::target::new_ledger(&resolved.id),
            |write| facade.catalog.create_ledger_with(&zone_id, name, write),
        )
        .await
        .map(Ledger::public)
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
        .map(Ledger::public)
        .collect();

    Ok(window.apply(ledgers))
}

/// The ledger with the members this Host coordinates whose `policy.mirror` task covers it
/// (WP-4.4): `GetLedger`'s answer, authorized as `get` is.
pub(crate) fn get_served(
    facade: &CatalogFacade,
    actor: &Actor,
    zone: &str,
    ledger: &str,
) -> Result<super::serving::LedgerServed, Refusal> {
    let (zone, ledger) = facade.resolve_ledger(actor, operations::CATALOG_READ, zone, ledger)?;
    let serving_members = facade
        .host
        .as_ref()
        .map(|host| {
            host.serving_members(&super::ledger_resource(&zone.id, &ledger.id))
                .into_iter()
                .map(super::serving::ServingMember::from)
                .collect()
        })
        .unwrap_or_default();
    Ok(super::serving::LedgerServed {
        ledger: ledger.public(),
        serving_members,
    })
}

#[tracing::instrument(name = "ledger.rename", skip_all)]
pub(crate) async fn rename(
    facade: &CatalogFacade,
    actor: &Actor,
    zone: &str,
    ledger: &str,
    name: &str,
    expected_revision: u64,
    request_id: &str,
) -> Result<Ledger, Refusal> {
    let change = super::Change {
        request_id,
        request: serde_json::json!({
            "zone": zone,
            "ledger": ledger,
            "name": name,
            "expected_revision": expected_revision,
        }),
        name: Some(name),
    };
    if let Some(done) = replayed(facade, actor, super::LEDGER_RENAME, &change).await? {
        return Ok(Ledger::public(done));
    }
    let (zone, resolved) = facade.resolve_ledger(actor, operations::CATALOG_WRITE, zone, ledger)?;
    let (zone_id, id) = (
        Selector::Id(zone.id.clone()),
        Selector::Id(resolved.id.clone()),
    );
    facade
        .mutate(
            actor,
            super::LEDGER_RENAME,
            change,
            super::target::ledger(&zone.id, &resolved.id),
            |write| {
                facade.catalog.rename_ledger_with(
                    &zone_id,
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
        .map(Ledger::public)
}

#[tracing::instrument(name = "ledger.delete", skip_all)]
pub(crate) async fn delete(
    facade: &CatalogFacade,
    actor: &Actor,
    zone: &str,
    ledger: &str,
    expected_revision: u64,
    request_id: &str,
) -> Result<Ledger, Refusal> {
    let change = super::Change {
        request_id,
        request: serde_json::json!({
            "zone": zone,
            "ledger": ledger,
            "expected_revision": expected_revision,
        }),
        name: None,
    };
    if let Some(done) = replayed(facade, actor, super::LEDGER_DELETE, &change).await? {
        return Ok(Ledger::public(done));
    }
    let (zone, resolved) = facade.resolve_ledger(actor, operations::CATALOG_WRITE, zone, ledger)?;
    let (zone_id, id) = (
        Selector::Id(zone.id.clone()),
        Selector::Id(resolved.id.clone()),
    );
    facade
        .mutate(
            actor,
            super::LEDGER_DELETE,
            change,
            super::target::ledger(&zone.id, &resolved.id),
            |write| {
                facade.catalog.delete_ledger_with(
                    &zone_id,
                    &id,
                    &Write {
                        expected_revision: Some(expected_revision),
                        ..*write
                    },
                )
            },
        )
        .await
        .map(Ledger::public)
}
