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
/// either narrows it: a page is 1-based, a size is clamped to
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
    /// A window from wire inputs, where zero means "not asked".
    pub(crate) fn of(page: u32, size: u32) -> Self {
        Self {
            page: (page > 0).then_some(page),
            size: (size > 0).then_some(size),
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
        let page = self.page.unwrap_or(1).max(1) as usize;

        items
            .into_iter()
            .skip((page - 1).saturating_mul(size))
            .take(size)
            .collect()
    }
}

#[cfg(test)]
mod window_tests {
    use super::ListWindow;

    #[test]
    fn no_window_is_the_whole_listing() {
        assert_eq!(ListWindow::of(0, 0).apply(vec![1, 2, 3]), vec![1, 2, 3]);
    }

    #[test]
    fn pages_partition_the_listing_without_overlap() {
        let items: Vec<u32> = (1..=7).collect();
        assert_eq!(ListWindow::of(1, 3).apply(items.clone()), vec![1, 2, 3]);
        assert_eq!(ListWindow::of(2, 3).apply(items.clone()), vec![4, 5, 6]);
        assert_eq!(ListWindow::of(3, 3).apply(items.clone()), vec![7]);
        assert_eq!(ListWindow::of(4, 3).apply(items), Vec::<u32>::new());
    }

    #[test]
    fn a_size_alone_is_the_first_page_and_a_page_alone_gets_the_default_size() {
        assert_eq!(ListWindow::of(0, 2).apply(vec![1, 2, 3]), vec![1, 2]);
        let many: Vec<u32> = (0..250).collect();
        assert_eq!(
            ListWindow::of(2, 0).apply(many)[0],
            100,
            "page 2 of the default size"
        );
    }
}

pub(crate) mod grpc;
pub(crate) mod http;
pub(crate) mod ledgers;
pub(crate) mod zones;

use std::sync::Arc;

use permguard_core::catalog::{Catalog, CatalogError, Selector};
use permguard_core::metrics::{Metric, Metrics};
use permguard_core::{ApiError, AuditRecorder, Disclosure, ErrorClass, Subject};

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
    pub(crate) recorder: Option<AuditRecorder>,
    pub(crate) disclosure: Disclosure,
    /// Whether refused operations go on the trail too — `audit.refusals`, off by default.
    pub(crate) audit_refusals: bool,
    /// Where the numbers go; a handle that may hold nothing, costing a branch.
    pub(crate) metrics: Metrics,
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
    /// A failed record is reported and does not undo the mutation: the catalog write is the fact,
    /// and refusing to have done what was already done helps nobody. The trail's own chain makes a
    /// gap detectable.
    pub(crate) async fn record(&self, action: &'static str, target: &str) {
        // Every record is a mutation that happened: count it and refresh the
        // holdings gauges here, the one place all mutations pass through.
        // A refusal put on the trail (`audit.refusals`) arrives here too,
        // already counted by `refused` — skip it or it counts twice.
        if !action.ends_with(".refused") {
            self.metrics
                .count(&OPERATIONS, &[("action", action), ("outcome", "ok")]);
            self.refresh_holdings();
        }

        let Some(recorder) = &self.recorder else {
            return;
        };

        if let Err(error) = recorder
            .record_on(action, Subject::System("control-plane"), target)
            .await
        {
            tracing::warn!(
                event.name = "catalog.audit_failed",
                component = "control-plane",
                action = action,
                error = %error,
                "the catalog change was made and its audit record was not"
            );
        }
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
            &[("action", operation), ("outcome", "refused")],
        );
        let error = api_error(error);

        if self.audit_refusals
            && matches!(
                error.class(),
                ErrorClass::Validation | ErrorClass::Conflict | ErrorClass::NotFound
            )
        {
            self.record(operation, error.code()).await;
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
            "not_found",
            format!("no {kind} answers to `{selector}`"),
        ),
        CatalogError::NameTaken { name, scope } => ApiError::new(
            ErrorClass::Conflict,
            "name_taken",
            format!("the name `{name}` is already taken in {scope}"),
        ),
        CatalogError::NotEmpty { zone, ledgers } => ApiError::new(
            ErrorClass::Conflict,
            "zone_not_empty",
            format!("the zone `{zone}` still holds {ledgers} ledger(s): delete them first"),
        ),
        CatalogError::InvalidName { name, detail } => ApiError::new(
            ErrorClass::Validation,
            "invalid_name",
            format!("`{name}` is not a name this catalog accepts: {detail}"),
        ),
        CatalogError::Backend { detail } => {
            // The generic sentence is the wire's; the detail — which may name paths — is the log's.
            ApiError::new(
                ErrorClass::Internal,
                "catalog_failed",
                "the catalog store failed",
            )
            .with_internal(detail.clone())
        }
    }
}
