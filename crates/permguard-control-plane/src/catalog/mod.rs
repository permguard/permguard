// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The catalog domain: zones and ledgers, one file each, two transports around them.
//!
//! The layering is the point of the layout, and every future domain should copy it:
//!
//! | file | owns | knows about |
//! | --- | --- | --- |
//! | [`zones`] / [`ledgers`] | the domain: what an operation *means*, auditing it, its errors | the [`Catalog`] contract — no axum, no tonic |
//! | [`http`] | routes and extraction | the domain modules and [`crate::wire`] |
//! | [`grpc`] | the tonic service impl | the same two |
//!
//! Both transports are deliberately too thin to be wrong: extract, call the domain, shape the
//! answer. Everything that could disagree between HTTP and gRPC — semantics, uniqueness, audit,
//! error taxonomy — lives below them, written once.

/// How much of a listing one answer carries.
///
/// `None` for both is the whole listing — the shape a synchronizing mirror
/// needs, and what every caller asked for before pagination existed. Naming
/// either narrows it: a page is 0-based, a size is clamped to
/// [`MAX_PAGE_SIZE`] so no caller can turn a listing into a memory test.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ListWindow {
    pub page: Option<u32>,
    pub size: Option<u32>,
}

/// The most entries one page may carry, whatever a caller asks for.
pub(crate) const MAX_PAGE_SIZE: u32 = 1_000;

/// The default page size, when a caller asked for a page and said nothing
/// about its size.
pub(crate) const DEFAULT_PAGE_SIZE: u32 = 100;

impl ListWindow {
    /// A window from wire inputs: an absent field is "not asked". Page 0 is
    /// the first page, so it is kept; a size of 0 is no size, so it is not.
    pub(crate) fn of(page: Option<u32>, size: Option<u32>) -> Self {
        Self {
            page,
            size: size.filter(|size| *size > 0),
        }
    }

    /// Applies the window to an already deterministically ordered listing.
    ///
    /// One function, used by HTTP and gRPC both, so the two transports cannot
    /// come to disagree about what page 3 holds.
    pub(crate) fn apply<T>(self, items: Vec<T>) -> Vec<T> {
        if self.page.is_none() && self.size.is_none() {
            return items;
        }
        let size = self
            .size
            .unwrap_or(DEFAULT_PAGE_SIZE)
            .clamp(1, MAX_PAGE_SIZE) as usize;
        let page = self.page.unwrap_or(0) as usize;

        items
            .into_iter()
            .skip(page.saturating_mul(size))
            .take(size)
            .collect()
    }
}

#[cfg(test)]
mod window_tests {
    use super::ListWindow;

    #[test]
    fn no_window_is_the_whole_listing() {
        assert_eq!(
            ListWindow::of(None, None).apply(vec![1, 2, 3]),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn pages_count_from_zero_and_partition_the_listing_without_overlap() {
        let items: Vec<u32> = (1..=7).collect();
        let page = |page: u32| ListWindow::of(Some(page), Some(3)).apply(items.clone());
        assert_eq!(page(0), vec![1, 2, 3]);
        assert_eq!(page(1), vec![4, 5, 6]);
        assert_eq!(page(2), vec![7]);
        assert_eq!(page(3), Vec::<u32>::new());
    }

    #[test]
    fn a_size_alone_is_the_first_page_and_a_page_alone_gets_the_default_size() {
        assert_eq!(
            ListWindow::of(None, Some(2)).apply(vec![1, 2, 3]),
            vec![1, 2]
        );
        let many: Vec<u32> = (0..250).collect();
        assert_eq!(
            ListWindow::of(Some(1), None).apply(many)[0],
            100,
            "page 1 of the default size is the second hundred"
        );
    }

    #[test]
    fn a_size_of_zero_is_no_size() {
        // The wire cannot refuse it, so it reads as "not asked": the default size applies.
        let many: Vec<u32> = (0..250).collect();
        assert_eq!(ListWindow::of(Some(1), Some(0)).apply(many)[0], 100);
    }
}

pub(crate) mod exports;
pub(crate) mod grpc;
pub(crate) mod http;
pub(crate) mod imports;
pub(crate) mod ledgers;
mod parity;
pub(crate) mod serving;
pub(crate) mod zones;

use std::sync::Arc;

use permguard_core::catalog::{Catalog, CatalogError, Selector};
use permguard_core::metrics::labels;
use permguard_core::metrics::{Metric, Metrics};
use permguard_core::{ApiError, Disclosure, ErrorClass, Ledger, Subject, Zone, codes};

/// Administrative operations answered — `action` is the audit action name
/// (a fixed set of compile-time literals), `outcome` `ok` or `refused`.
const OPERATIONS: Metric = Metric::counter(
    "permguard_catalog_operations_total",
    "Catalog operations answered, by action and outcome.",
);

/// How many zones the catalog currently holds.
const ZONES: Metric = Metric::gauge("permguard_catalog_zones", "Zones the catalog holds.");

/// How many ledgers it holds, across every zone.
const LEDGERS: Metric = Metric::gauge(
    "permguard_catalog_ledgers",
    "Ledgers the catalog holds, across every zone.",
);

/// What every catalog operation runs with: the store, the trail, and the disclosure posture.
#[derive(Clone)]
pub(crate) struct CatalogFacade {
    pub(crate) catalog: Arc<dyn Catalog>,
    pub(crate) recorder: Option<crate::handles::Audit>,
    pub(crate) disclosure: Disclosure,
    /// Whether refused operations go on the trail too — `audit.refusals`, off by default.
    pub(crate) audit_refusals: bool,
    /// Where the numbers go; a handle that may hold nothing, costing a branch.
    pub(crate) metrics: Metrics,
    /// The Host's authorization, which every catalog operation decides with before it looks
    /// anything up (WP-2.4).
    pub(crate) authorization: Arc<permguard_host::composition::Authorization>,
    /// This plane's handles, through which the Host tells the members serving a ledger
    /// (WP-4.4); `None` when no Host registered the plane.
    pub(crate) host: Option<Arc<permguard_host::composition::Registration>>,
    /// The Host's security-mutation transaction every catalog mutation runs in (WP-7.3a); `None`
    /// when the Host composes none, and then every mutation is refused `unavailable`.
    pub(crate) mutations: Option<permguard_host::composition::MutationHandle>,
    /// What exports a zone or a ledger (WP-7.10); `None` when the Host composes no
    /// `host.operations` signer, and then every export is refused `unavailable`.
    pub(crate) exports: Option<Arc<exports::Exports>>,
}

/// The domain of the catalog's mutations (WP-7.3a): what recovery asks of zones and ledgers.
pub const CATALOG_DOMAIN: &str = "catalog";

/// One catalog mutation: its operation, the phased audit action the transaction writes, and the
/// plain action its refusal is recorded under.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Mutation {
    pub(crate) operation: &'static str,
    pub(crate) action: &'static str,
    pub(crate) refused: &'static str,
}

pub(crate) const ZONE_CREATE: Mutation = Mutation {
    operation: "catalog.zone.create",
    action: "catalog.zone.created",
    refused: "zone.create.refused",
};
pub(crate) const ZONE_RENAME: Mutation = Mutation {
    operation: "catalog.zone.rename",
    action: "catalog.zone.renamed",
    refused: "zone.rename.refused",
};
pub(crate) const ZONE_DELETE: Mutation = Mutation {
    operation: "catalog.zone.delete",
    action: "catalog.zone.deleted",
    refused: "zone.delete.refused",
};
pub(crate) const LEDGER_CREATE: Mutation = Mutation {
    operation: "catalog.ledger.create",
    action: "catalog.ledger.created",
    refused: "ledger.create.refused",
};
pub(crate) const LEDGER_RENAME: Mutation = Mutation {
    operation: "catalog.ledger.rename",
    action: "catalog.ledger.renamed",
    refused: "ledger.rename.refused",
};
pub(crate) const LEDGER_DELETE: Mutation = Mutation {
    operation: "catalog.ledger.delete",
    action: "catalog.ledger.deleted",
    refused: "ledger.delete.refused",
};
pub(crate) const LEDGER_ARCHIVE: Mutation = Mutation {
    operation: "catalog.ledger.archive",
    action: "catalog.ledger.archived",
    refused: "ledger.archive.refused",
};
pub(crate) const LEDGER_RESTORE: Mutation = Mutation {
    operation: "catalog.ledger.restore",
    action: "catalog.ledger.restored",
    refused: "ledger.restore.refused",
};

/// What a caller asks of one catalog mutation (WP-7.3a): its request id, and the request as it
/// was sent, the selectors as given and the body, which a retry repeats byte for byte; the name a
/// create or a rename gives, validated before any intent.
pub(crate) struct Change<'a> {
    pub(crate) request_id: &'a str,
    pub(crate) request: serde_json::Value,
    pub(crate) name: Option<&'a str>,
}

/// The intent target of a catalog operation (WP-7.3a): a record by its ids, or, for a create
/// whose id the store mints inside the operation, the place it is created in, so no tenant name
/// reaches the trail (after the review).
pub(crate) mod target {
    pub(crate) const NEW_ZONE: &str = "zone-new";

    pub(crate) fn zone(id: &str) -> String {
        format!("zone/{id}")
    }
    pub(crate) fn ledger(zone_id: &str, id: &str) -> String {
        format!("ledger/{zone_id}/{id}")
    }
    pub(crate) fn new_ledger(zone_id: &str) -> String {
        format!("ledger-new/{zone_id}")
    }
}

/// A record a catalog mutation answers: its revision, the target that names it, and how to read
/// it again by that target.
pub(crate) trait Record: Sized {
    fn revision(&self) -> u64;
    fn target(&self) -> String;
    fn at(catalog: &dyn Catalog, target: &str) -> Result<Self, CatalogError>;
}

/// The record a target names that `target` does not: a malformed or foreign one.
fn unnamed(target: &str) -> CatalogError {
    CatalogError::backend(format!("the operation's target `{target}` names no record"))
}

impl Record for permguard_core::Zone {
    fn revision(&self) -> u64 {
        self.revision
    }
    fn target(&self) -> String {
        target::zone(&self.id)
    }
    fn at(catalog: &dyn Catalog, at: &str) -> Result<Self, CatalogError> {
        match at.split('/').collect::<Vec<_>>().as_slice() {
            ["zone", id] => catalog.get_zone(&Selector::Id((*id).to_owned())),
            _ => Err(unnamed(at)),
        }
    }
}

impl Record for permguard_core::Ledger {
    fn revision(&self) -> u64 {
        self.revision
    }
    fn target(&self) -> String {
        target::ledger(&self.zone_id, &self.id)
    }
    fn at(catalog: &dyn Catalog, at: &str) -> Result<Self, CatalogError> {
        match at.split('/').collect::<Vec<_>>().as_slice() {
            ["ledger", zone, id] => catalog.get_ledger(
                &Selector::Id((*zone).to_owned()),
                &Selector::Id((*id).to_owned()),
            ),
            _ => Err(unnamed(at)),
        }
    }
}

/// The catalog as the mutation transaction's domain: an operation shows when the record its
/// target names was last written by it, at the record's revision; a create's, when a record of
/// the place it names was; a delete's, when the record is gone and its tombstone names the
/// operation (WP-7.3b).
///
/// Only the last writer is kept: a create whose answer was lost and whose record another change
/// wrote before the next start reads as failed there, although it applied, and its retry is
/// refused as the name being taken (after the review, a recorded limit).
pub struct CatalogDomain {
    pub catalog: Arc<dyn Catalog>,
}

impl permguard_host::operations::mutation::Domain for CatalogDomain {
    fn name(&self) -> &'static str {
        CATALOG_DOMAIN
    }

    fn observe(
        &self,
        operation_id: &permguard_host::operations::journal::OperationId,
        target: Option<&str>,
    ) -> Option<permguard_host::operations::mutation::Observed> {
        let target = target?;
        let operation = operation_id.to_string();
        let written = |revision: u64, by: Option<&str>, at: String| {
            (by == Some(operation.as_str())).then_some(
                permguard_host::operations::mutation::Observed {
                    revision,
                    target: Some(at),
                },
            )
        };
        match target.split('/').collect::<Vec<_>>().as_slice() {
            ["zone", id] => match permguard_core::Zone::at(self.catalog.as_ref(), target) {
                Ok(zone) => written(zone.revision, zone.operation.as_deref(), zone.target()),
                Err(CatalogError::NotFound { .. }) => {
                    let gone = self.catalog.zone_tombstone(id).ok()??;
                    written(gone.revision, gone.operation.as_deref(), target.to_owned())
                }
                Err(_) => None,
            },
            ["zone-new"] => self
                .catalog
                .list_zones()
                .ok()?
                .into_iter()
                .find_map(|zone| written(zone.revision, zone.operation.as_deref(), zone.target())),
            ["ledger", zone, id] => match permguard_core::Ledger::at(self.catalog.as_ref(), target)
            {
                Ok(ledger) => written(
                    ledger.revision,
                    ledger.operation.as_deref(),
                    ledger.target(),
                ),
                Err(CatalogError::NotFound { .. }) => {
                    let gone = self.catalog.ledger_tombstone(zone, id).ok()??;
                    written(gone.revision, gone.operation.as_deref(), target.to_owned())
                }
                Err(_) => None,
            },
            ["ledger-new", zone] => self
                .catalog
                .list_ledgers(&Selector::Id((*zone).to_owned()))
                .ok()?
                .into_iter()
                .find_map(|ledger| {
                    written(
                        ledger.revision,
                        ledger.operation.as_deref(),
                        ledger.target(),
                    )
                }),
            _ => None,
        }
    }
}

/// `mutations` once the catalog operations a crash left open are resolved against `catalog`,
/// before the catalog takes a change; `None`, and every change refused `unavailable`, when the
/// recovery fails.
pub(crate) fn recovered(
    mutations: permguard_host::composition::MutationHandle,
    catalog: &Arc<dyn Catalog>,
) -> Option<permguard_host::composition::MutationHandle> {
    let domain = CatalogDomain {
        catalog: Arc::clone(catalog),
    };
    match mutations.recover(&domain) {
        Ok(_) => Some(mutations),
        Err(error) => {
            tracing::error!(
                event.name = "catalog.mutations_unrecovered",
                component = crate::service::COMPONENT,
                error = %error,
                "the catalog takes no change: the mutations a crash left open could not be resolved"
            );
            None
        }
    }
}

/// The resource of this plane, and of its zones and ledgers, in the Host's tree.
pub(crate) fn plane_resource() -> permguard_core::authz::Resource {
    permguard_core::authz::Resource::plane(crate::service::PLANE)
}

pub(crate) fn zone_resource(zone_id: &str) -> permguard_core::authz::Resource {
    permguard_core::authz::Resource::zone(crate::service::PLANE, zone_id)
}

pub(crate) fn ledger_resource(zone_id: &str, ledger_id: &str) -> permguard_core::authz::Resource {
    permguard_core::authz::Resource::ledger(crate::service::PLANE, zone_id, ledger_id)
}

impl CatalogFacade {
    /// The transaction and the start of one catalog mutation: refused before anything when the
    /// request id is empty or the Host composes no transaction. The request is bound to the
    /// operation and to the request as sent, so a retry is recognised before anything is
    /// resolved.
    fn begin(
        &self,
        actor: &permguard_core::authz::Actor,
        mutation: Mutation,
        change: &Change<'_>,
        target: Option<String>,
    ) -> Result<
        (
            &permguard_host::composition::MutationHandle,
            permguard_host::operations::mutation::Begin,
        ),
        crate::wire::Refusal,
    > {
        use permguard_host::operations::journal::{Initiator, RequestKey};

        if change.request_id.trim().is_empty() {
            return Err(ApiError::new(
                ErrorClass::Validation,
                codes::common::INVALID_ARGUMENT,
                "a catalog change names its `request_id`, which a retry repeats",
            )
            .into());
        }
        let Some(mutations) = &self.mutations else {
            return Err(ApiError::new(
                ErrorClass::Unavailable,
                codes::common::UNAVAILABLE,
                "the Host composes no mutation transaction, so the catalog takes no change",
            )
            .into());
        };
        let principal = actor.principal()?;
        let digest = permguard_objects::digest::Digest::compute(
            &serde_json::to_vec(&serde_json::json!({
                "operation": mutation.operation,
                "request": change.request,
            }))
            .unwrap_or_default(),
        )
        .to_string();
        Ok((
            mutations,
            permguard_host::operations::mutation::Begin {
                domain: CATALOG_DOMAIN,
                operation: mutation.operation,
                action: mutation.action,
                initiator: Initiator::Principal(principal.to_string()),
                request: Some(RequestKey {
                    request_id: change.request_id.to_owned(),
                    digest,
                }),
                target,
            },
        ))
    }

    /// The answer a retry of `change` learns, before the caller resolves anything a first
    /// attempt may have renamed or deleted (after the review): `None` when the window holds
    /// none. The caller has passed the admission check on the plane, and the window is keyed by
    /// its own principal, so only its own earlier answer is ever handed back.
    pub(crate) async fn replayed<T>(
        &self,
        actor: &permguard_core::authz::Actor,
        mutation: Mutation,
        change: &Change<'_>,
    ) -> Result<Option<T>, crate::wire::Refusal>
    where
        T: Record + serde::de::DeserializeOwned,
    {
        use permguard_host::operations::mutation::Outcome;

        let (mutations, begin) = self.begin(actor, mutation, change, None)?;
        match mutations.replayed::<T, CatalogError>(&begin) {
            Ok(None) => Ok(None),
            Ok(Some(Outcome::Applied(value) | Outcome::Replayed(value))) => Ok(Some(value)),
            Ok(Some(Outcome::Reconciled { target, .. })) => {
                T::at(self.catalog.as_ref(), target.as_deref().unwrap_or_default())
                    .map(Some)
                    .map_err(|error| api_error(error).into())
            }
            Err(error) => Err(self.failed(mutation, error).await),
        }
    }

    /// Runs one catalog mutation in the Host's security-mutation transaction (WP-7.3a): its
    /// intent, the store's write carrying the operation id, its commit and phased audit records.
    /// A retry of the same `request_id` with the same request learns the first answer; the same
    /// id with another request is `request_id_reused`. A name is validated before the intent;
    /// `apply` writes, held to the revision the caller expects.
    pub(crate) async fn mutate<T>(
        &self,
        actor: &permguard_core::authz::Actor,
        mutation: Mutation,
        change: Change<'_>,
        target: String,
        apply: impl FnOnce(&permguard_core::catalog::Write<'_>) -> Result<T, CatalogError>,
    ) -> Result<T, crate::wire::Refusal>
    where
        T: Record + serde::Serialize + serde::de::DeserializeOwned,
    {
        use permguard_host::operations::mutation::{Applied, Failure, Outcome};

        let (mutations, begin) = self.begin(actor, mutation, &change, Some(target))?;
        let outcome = mutations.run_checked(
            begin,
            || {
                change
                    .name
                    .map_or(Ok(()), permguard_core::catalog::validate_name)
            },
            |applying| {
                let operation_id = applying.operation_id().to_string();
                match apply(&permguard_core::catalog::Write {
                    expected_revision: None,
                    operation: Some(&operation_id),
                    provenance: None,
                }) {
                    Ok(value) => Ok(Applied {
                        revision: value.revision(),
                        target: Some(value.target()),
                        value,
                    }),
                    // A write that failed may have landed: recovery asks the record.
                    Err(error @ CatalogError::Backend { .. }) => Err(Failure::Indeterminate(error)),
                    Err(error) => Err(Failure::Refused(error)),
                }
            },
        );
        match outcome {
            Ok(Outcome::Applied(value) | Outcome::Replayed(value)) => {
                self.metrics.count(
                    &OPERATIONS,
                    &[(labels::ACTION, mutation.action), (labels::OUTCOME, "ok")],
                );
                self.refresh_holdings();
                Ok(value)
            }
            Ok(Outcome::Reconciled { target, .. }) => {
                T::at(self.catalog.as_ref(), target.as_deref().unwrap_or_default())
                    .map_err(|error| api_error(error).into())
            }
            Err(error) => Err(self.failed(mutation, error).await),
        }
    }

    /// The refusal a transaction's error answers.
    async fn failed(
        &self,
        mutation: Mutation,
        error: permguard_host::operations::mutation::MutationError<CatalogError>,
    ) -> crate::wire::Refusal {
        use permguard_host::operations::mutation::MutationError;

        match error {
            MutationError::Refused(error) => self.refused(mutation.refused, error).await.into(),
            MutationError::RequestIdReused(detail) => {
                ApiError::new(ErrorClass::Conflict, codes::host::REQUEST_ID_REUSED, detail).into()
            }
            MutationError::AuditUnavailable(detail) => ApiError::new(
                ErrorClass::Unavailable,
                codes::host::AUDIT_UNAVAILABLE,
                "the change was not made: its audit record could not be written",
            )
            .with_internal(detail)
            .into(),
            MutationError::Unrecorded(detail) => crate::unrecorded(detail).into(),
            MutationError::Indeterminate(error) => crate::unrecorded(error).into(),
            MutationError::Unavailable(detail) => ApiError::new(
                ErrorClass::Unavailable,
                codes::common::UNAVAILABLE,
                "the catalog's mutation journal could not be written: nothing was changed",
            )
            .with_internal(detail)
            .into(),
            // A backup barrier (WP-7.8): the same request succeeds once the backup ends.
            MutationError::Quiesced(detail) => ApiError::new(
                ErrorClass::Unavailable,
                codes::common::UNAVAILABLE,
                format!("{detail}; nothing was changed"),
            )
            .into(),
        }
    }

    /// Whether `actor` may do `operation` on exactly `resource`.
    pub(crate) fn authorize(
        &self,
        actor: &permguard_core::authz::Actor,
        operation: &str,
        resource: &permguard_core::authz::Resource,
    ) -> Result<(), crate::wire::Refusal> {
        self.authorization
            .authorize(actor, operation, resource)
            .map_err(Into::into)
    }

    /// Resolves a zone named by id or name, authorization first (owner decision, 2026-10-06):
    /// a caller with nothing for `operation` under this plane is refused before any lookup; the
    /// resolved zone is then authorized exactly, and a name that resolves to nothing is answered
    /// as out of scope unless the caller's grants cover the whole plane.
    pub(crate) fn resolve_zone(
        &self,
        actor: &permguard_core::authz::Actor,
        operation: &str,
        zone: &str,
    ) -> Result<Zone, crate::wire::Refusal> {
        let plane = plane_resource();
        self.authorization.may_act_under(actor, operation, &plane)?;
        match self.catalog.get_zone(&Selector::parse(zone)) {
            Ok(found) => {
                self.authorize(actor, operation, &zone_resource(&found.id))?;
                Ok(found)
            }
            Err(error @ CatalogError::NotFound { .. }) => {
                self.authorization
                    .not_found_or_forbidden(actor, operation, &plane)?;
                Err(api_error(error).into())
            }
            Err(error) => Err(api_error(error).into()),
        }
    }

    /// Resolves a zone whose children `actor` may reach for `operation`: the zone itself need
    /// not be granted, a grant on one of its ledgers is enough to name it.
    pub(crate) fn resolve_zone_for_children(
        &self,
        actor: &permguard_core::authz::Actor,
        operation: &str,
        zone: &str,
    ) -> Result<Zone, crate::wire::Refusal> {
        let plane = plane_resource();
        self.authorization.may_act_under(actor, operation, &plane)?;
        match self.catalog.get_zone(&Selector::parse(zone)) {
            Ok(found) => {
                self.authorization
                    .may_act_under(actor, operation, &zone_resource(&found.id))?;
                Ok(found)
            }
            Err(error @ CatalogError::NotFound { .. }) => {
                self.authorization
                    .not_found_or_forbidden(actor, operation, &plane)?;
                Err(api_error(error).into())
            }
            Err(error) => Err(api_error(error).into()),
        }
    }

    /// Resolves a ledger of a zone, both by id or name, the same way: the exact ledger is
    /// authorized, and a ledger name that resolves to nothing is out of scope unless the caller
    /// covers the whole zone.
    pub(crate) fn resolve_ledger(
        &self,
        actor: &permguard_core::authz::Actor,
        operation: &str,
        zone: &str,
        ledger: &str,
    ) -> Result<(Zone, Ledger), crate::wire::Refusal> {
        let zone = self.resolve_zone_for_children(actor, operation, zone)?;
        let scope = zone_resource(&zone.id);
        match self
            .catalog
            .get_ledger(&Selector::Id(zone.id.clone()), &Selector::parse(ledger))
        {
            Ok(found) => {
                self.authorize(actor, operation, &ledger_resource(&zone.id, &found.id))?;
                Ok((zone, found))
            }
            Err(error @ CatalogError::NotFound { .. }) => {
                self.authorization
                    .not_found_or_forbidden(actor, operation, &scope)?;
                Err(api_error(error).into())
            }
            Err(error) => Err(api_error(error).into()),
        }
    }
}

impl CatalogFacade {
    /// Sets the holdings gauges from what the catalog actually holds — read
    /// back rather than incremented, so the gauges cannot drift from disk.
    /// Called at composition and after every mutation; the catalog is local
    /// and the counts are a directory listing.
    pub(crate) fn refresh_holdings(&self) {
        if !self.metrics.is_recording() {
            return;
        }
        let Ok(zones) = self.catalog.list_zones() else {
            return;
        };
        let ledgers = zones
            .iter()
            .map(|zone| {
                self.catalog
                    .list_ledgers(&Selector::Id(zone.id.clone()))
                    .map(|list| list.len())
                    .unwrap_or(0)
            })
            .sum::<usize>();
        self.metrics.set(&ZONES, &[], zones.len() as f64);
        self.metrics.set(&LEDGERS, &[], ledgers as f64);
    }

    /// Records one administrative action against the trail, when the build keeps one.
    ///
    /// A failed record does not undo the mutation, which is already the fact, and is not answered
    /// as a success either: the caller is told `mutation_unrecorded` and reads the state before it
    /// retries (owner decision of 2026-10-07). `TODO(WP-17)`: the catalog's mutations become
    /// operations of the Host's security-mutation transaction (WP-3.6).
    pub(crate) async fn record(&self, action: &'static str, target: &str) -> Result<(), ApiError> {
        // Every record is a mutation that happened: count it and refresh the
        // holdings gauges here, the one place all mutations pass through.
        // A refusal put on the trail (`audit.refusals`) arrives here too,
        // already counted by `refused` — skip it or it counts twice.
        if !action.ends_with(".refused") {
            self.metrics.count(
                &OPERATIONS,
                &[(labels::ACTION, action), (labels::OUTCOME, "ok")],
            );
            self.refresh_holdings();
        }

        let Some(recorder) = &self.recorder else {
            return Ok(());
        };

        recorder
            .record_on(action, Subject::System("control-plane"), target)
            .await
            .map_err(|error| {
                tracing::error!(
                    event.name = "catalog.audit_failed",
                    component = "control-plane",
                    action = action,
                    error = %error,
                    "the catalog change was made and its audit record was not"
                );
                crate::unrecorded(error)
            })
    }
}

impl CatalogFacade {
    /// Settles one refused operation: maps the error, and — when the deployment asked for denied
    /// attempts on the record — writes `<operation>.refused` to the trail first.
    ///
    /// Only the caller-caused classes are trail material even then: an `internal` failure is a
    /// fault of ours, already in the operational log at full fidelity, and a trail entry saying
    /// "we broke" attests to nothing about anybody's conduct.
    pub(crate) async fn refused(&self, operation: &'static str, error: CatalogError) -> ApiError {
        self.metrics.count(
            &OPERATIONS,
            &[(labels::ACTION, operation), (labels::OUTCOME, "refused")],
        );
        let error = api_error(error);

        if self.audit_refusals
            && matches!(
                error.class(),
                ErrorClass::Validation | ErrorClass::Conflict | ErrorClass::NotFound
            )
        {
            // A refusal changed nothing: its record failing is said in the log, not answered.
            let _ = self.record(operation, error.code()).await;
        }

        error
    }
}

/// Translates the catalog's vocabulary into the API's — the one place the two meet.
///
/// The safe sentence and the internal detail are separated here: what the store said about paths
/// and files is operator material, attached as internal detail and disclosed only where the
/// deployment allows it.
pub(crate) fn api_error(error: CatalogError) -> ApiError {
    match &error {
        CatalogError::NotFound { kind, selector } => ApiError::new(
            ErrorClass::NotFound,
            codes::common::NOT_FOUND,
            format!("no {kind} answers to `{selector}`"),
        ),
        CatalogError::NameTaken { name, scope } => ApiError::new(
            ErrorClass::Conflict,
            codes::catalog::NAME_TAKEN,
            format!("the name `{name}` is already taken in {scope}"),
        ),
        CatalogError::NotEmpty { zone, ledgers } => ApiError::new(
            ErrorClass::Conflict,
            codes::catalog::ZONE_NOT_EMPTY,
            format!("the zone `{zone}` still holds {ledgers} ledger(s): delete them first"),
        ),
        CatalogError::InvalidName { name, detail } => ApiError::new(
            ErrorClass::Validation,
            codes::catalog::INVALID_NAME,
            format!("`{name}` is not a name this catalog accepts: {detail}"),
        ),
        CatalogError::RevisionConflict {
            kind,
            selector,
            current,
        } => ApiError::new(
            ErrorClass::Conflict,
            codes::catalog::REVISION_CONFLICT,
            format!(
                "the {kind} `{selector}` is at revision {current}, not the one this change \
                 expected: read it again and retry"
            ),
        ),
        CatalogError::Backend { detail } => {
            // The generic sentence is the wire's; the detail — which may name paths — is the log's.
            ApiError::new(
                ErrorClass::Internal,
                codes::catalog::CATALOG_FAILED,
                "the catalog store failed",
            )
            .with_internal(detail.clone())
        }
    }
}
