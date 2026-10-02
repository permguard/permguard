// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The catalog answers the same over REST and gRPC: one script of operations, run once per
//! transport through the production client, with the same outcome at every step.

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use permguard_conformance::parity::{Outcome, Served, assert_parity, outcome, serve};
    use permguard_control_client::catalog::{Catalog, client};
    use permguard_core::Disclosure;
    use permguard_core::metrics::Metrics;
    use permguard_std::catalog::FileCatalog;

    use crate::catalog::CatalogFacade;

    /// Identifiers and timestamps a mutation mints: two planes cannot share them.
    const MINTED: &[&str] = &["id", "zone_id", "created_at", "updated_at"];

    fn plane(name: &str) -> Served {
        let root = std::env::temp_dir().join(format!(
            "permguard-catalog-parity-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("the catalog volume exists");
        let facade = CatalogFacade {
            catalog: Arc::new(FileCatalog::new(&root)),
            recorder: None,
            disclosure: Disclosure::Full,
            audit_refusals: false,
            metrics: Metrics::none(),
        };

        serve(
            crate::catalog::http::routes(facade.clone()),
            tonic::service::Routes::new(crate::v1::zone_catalog_server::ZoneCatalogServer::new(
                facade,
            )),
        )
    }

    fn connect(url: &str) -> Box<dyn Catalog> {
        client(
            url,
            &permguard_control_client::tls::TlsOptions::default(),
            Box::new(permguard_control_client::narrate::Silent),
        )
        .expect("the endpoint parses")
    }

    /// Every step of the script, named, with what this transport answered.
    fn script(catalog: &dyn Catalog) -> Vec<(&'static str, Outcome)> {
        vec![
            ("create a zone", outcome(catalog.create_zone("billing"))),
            (
                "create a taken name",
                outcome(catalog.create_zone("billing")),
            ),
            (
                "create an invalid name",
                outcome(catalog.create_zone("Not A Name!")),
            ),
            ("get a zone by name", outcome(catalog.get_zone("billing"))),
            ("get an unknown zone", outcome(catalog.get_zone("missing"))),
            (
                "create a ledger",
                outcome(catalog.create_ledger("billing", "invoices")),
            ),
            (
                "create a second ledger",
                outcome(catalog.create_ledger("billing", "refunds")),
            ),
            (
                "create a ledger in an unknown zone",
                outcome(catalog.create_ledger("missing", "x")),
            ),
            (
                "create a taken ledger name",
                outcome(catalog.create_ledger("billing", "invoices")),
            ),
            ("list the zones", outcome(catalog.list_zones(None, None))),
            (
                "list the second page of one",
                outcome(catalog.list_ledgers("billing", Some(1), Some(1))),
            ),
            (
                "list the ledgers",
                outcome(catalog.list_ledgers("billing", None, None)),
            ),
            (
                "list the ledgers of an unknown zone",
                outcome(catalog.list_ledgers("missing", None, None)),
            ),
            (
                "get an unknown ledger",
                outcome(catalog.get_ledger("billing", "missing")),
            ),
            (
                "rename a zone",
                outcome(catalog.rename_zone("billing", "finance")),
            ),
            (
                "rename to an invalid name",
                outcome(catalog.rename_zone("finance", "Bad Name")),
            ),
            (
                "delete a zone that holds ledgers",
                outcome(catalog.delete_zone("finance")),
            ),
            (
                "rename a ledger",
                outcome(catalog.rename_ledger("finance", "refunds", "returns")),
            ),
            (
                "delete a ledger",
                outcome(catalog.delete_ledger("finance", "invoices")),
            ),
            (
                "delete an unknown ledger",
                outcome(catalog.delete_ledger("finance", "invoices")),
            ),
            (
                "delete the last ledger",
                outcome(catalog.delete_ledger("finance", "returns")),
            ),
            (
                "delete the empty zone",
                outcome(catalog.delete_zone("finance")),
            ),
            ("get the deleted zone", outcome(catalog.get_zone("finance"))),
        ]
    }

    #[test]
    fn test_one_script_gets_the_same_outcome_at_every_step_over_rest_and_grpc() {
        let over_http = script(connect(&plane("rest").http).as_ref());
        let over_grpc = script(connect(&plane("grpc").grpc).as_ref());

        assert_eq!(over_http.len(), over_grpc.len());
        let mut refusals = 0;
        for ((case, http), (_, grpc)) in over_http.into_iter().zip(over_grpc) {
            if matches!(http, Outcome::Refused { .. }) {
                refusals += 1;
            }
            assert_parity(case, http.masked(MINTED), grpc.masked(MINTED));
        }
        assert!(
            refusals >= 8,
            "the script exercises the refusals, not only the happy path ({refusals})"
        );
    }

    #[test]
    fn test_both_transports_read_the_same_state_identically() {
        let served = plane("shared");
        let over_http = connect(&served.http);
        let over_grpc = connect(&served.grpc);
        over_http
            .create_zone("billing")
            .expect("the zone is created");
        over_grpc
            .create_ledger("billing", "invoices")
            .expect("the ledger is created");

        for (case, http, grpc) in [
            (
                "the zone",
                outcome(over_http.get_zone("billing")),
                outcome(over_grpc.get_zone("billing")),
            ),
            (
                "the zones",
                outcome(over_http.list_zones(None, None)),
                outcome(over_grpc.list_zones(None, None)),
            ),
            (
                "the ledger",
                outcome(over_http.get_ledger("billing", "invoices")),
                outcome(over_grpc.get_ledger("billing", "invoices")),
            ),
        ] {
            assert!(matches!(http, Outcome::Answered(_)), "{case}: {http:?}");
            assert_parity(case, http, grpc);
        }
    }
}
