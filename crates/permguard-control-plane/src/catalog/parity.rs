// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The catalog answers the same over REST and gRPC: one script of operations, run once per
//! transport through the production client, with the same outcome at every step.

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use permguard_conformance::parity::{
        Outcome, Served, assert_parity, assert_statuses, outcome, serve,
    };
    use permguard_control_client::catalog::{Catalog, client};
    use permguard_core::Disclosure;
    use permguard_core::metrics::Metrics;
    use permguard_std::catalog::FileCatalog;

    use crate::catalog::CatalogFacade;

    /// Identifiers and timestamps a mutation mints: two planes cannot share them.
    const MINTED: &[&str] = &["id", "zone_id", "created_at", "updated_at"];

    fn facade(name: &str) -> CatalogFacade {
        let root = std::env::temp_dir().join(format!(
            "permguard-catalog-parity-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("the catalog volume exists");
        CatalogFacade {
            catalog: Arc::new(FileCatalog::new(&root)),
            recorder: None,
            disclosure: Disclosure::Full,
            audit_refusals: false,
            metrics: Metrics::none(),
        }
    }

    fn plane(name: &str) -> Served {
        let facade = facade(name);

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

    /// The raw answers, below any client: the HTTP status and body, the gRPC code and metadata.
    mod raw {
        use axum::body::Body;
        use axum::http::Request;
        use http_body_util::BodyExt as _;
        use tower::ServiceExt as _;

        use crate::catalog::CatalogFacade;
        use crate::v1;
        use crate::v1::zone_catalog_server::ZoneCatalog as _;
        use crate::wire::{GRPC_ERROR_CLASS, GRPC_ERROR_CODE};

        /// `(status, class, code)` of one REST call.
        pub(super) async fn rest(
            facade: &CatalogFacade,
            method: &str,
            uri: &str,
            body: Option<&str>,
        ) -> (u16, String, String) {
            let request = Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .body(body.map_or_else(Body::empty, |body| Body::from(body.to_owned())))
                .expect("the request builds");
            let answer = crate::catalog::http::routes(facade.clone())
                .oneshot(request)
                .await
                .expect("the router answers");
            let status = answer.status().as_u16();
            let bytes = answer
                .into_body()
                .collect()
                .await
                .expect("the body reads")
                .to_bytes();
            let body: serde_json::Value =
                serde_json::from_slice(&bytes).expect("a refusal body is JSON");
            let field = |name: &str| body[name].as_str().unwrap_or_default().to_owned();

            (status, field("class"), field("code"))
        }

        /// `(code, class, code)` of one gRPC refusal.
        pub(super) fn grpc(status: tonic::Status) -> (i32, String, String) {
            let metadata = |key: &str| {
                status
                    .metadata()
                    .get(key)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_owned()
            };

            (
                status.code() as i32,
                metadata(GRPC_ERROR_CLASS),
                metadata(GRPC_ERROR_CODE),
            )
        }

        pub(super) async fn create_zone(facade: &CatalogFacade, name: &str) -> tonic::Status {
            facade
                .create_zone(tonic::Request::new(v1::CreateZoneRequest {
                    name: name.to_owned(),
                }))
                .await
                .expect_err("the case is a refusal")
        }

        pub(super) async fn get_zone(facade: &CatalogFacade, zone: &str) -> tonic::Status {
            facade
                .get_zone(tonic::Request::new(v1::GetZoneRequest {
                    zone: zone.to_owned(),
                }))
                .await
                .expect_err("the case is a refusal")
        }

        pub(super) async fn delete_zone(facade: &CatalogFacade, zone: &str) -> tonic::Status {
            facade
                .delete_zone(tonic::Request::new(v1::DeleteZoneRequest {
                    zone: zone.to_owned(),
                }))
                .await
                .expect_err("the case is a refusal")
        }

        pub(super) async fn create_ledger(
            facade: &CatalogFacade,
            zone: &str,
            name: &str,
        ) -> tonic::Status {
            facade
                .create_ledger(tonic::Request::new(v1::CreateLedgerRequest {
                    zone: zone.to_owned(),
                    name: name.to_owned(),
                }))
                .await
                .expect_err("the case is a refusal")
        }
    }

    #[tokio::test]
    async fn test_every_refusal_answers_the_status_its_class_maps_to_on_both_transports() {
        let facade = facade("raw");
        raw::rest(&facade, "POST", "/v1/zones", Some(r#"{"name":"billing"}"#)).await;
        raw::rest(
            &facade,
            "POST",
            "/v1/zones/billing/ledgers",
            Some(r#"{"name":"invoices"}"#),
        )
        .await;

        let cases = [
            (
                "a taken name",
                raw::rest(&facade, "POST", "/v1/zones", Some(r#"{"name":"billing"}"#)).await,
                raw::grpc(raw::create_zone(&facade, "billing").await),
            ),
            (
                "an invalid name",
                raw::rest(&facade, "POST", "/v1/zones", Some(r#"{"name":"Bad Name"}"#)).await,
                raw::grpc(raw::create_zone(&facade, "Bad Name").await),
            ),
            (
                "an unknown zone",
                raw::rest(&facade, "GET", "/v1/zones/missing", None).await,
                raw::grpc(raw::get_zone(&facade, "missing").await),
            ),
            (
                "a zone that holds ledgers",
                raw::rest(&facade, "DELETE", "/v1/zones/billing", None).await,
                raw::grpc(raw::delete_zone(&facade, "billing").await),
            ),
            (
                "a ledger in an unknown zone",
                raw::rest(
                    &facade,
                    "POST",
                    "/v1/zones/missing/ledgers",
                    Some(r#"{"name":"x"}"#),
                )
                .await,
                raw::grpc(raw::create_ledger(&facade, "missing", "x").await),
            ),
        ];
        for (case, (http_status, http_class, http_code), (grpc_code, grpc_class, grpc_code_name)) in
            cases
        {
            assert_eq!(
                (&http_class, &http_code),
                (&grpc_class, &grpc_code_name),
                "`{case}`: the body and the metadata name the same refusal"
            );
            assert_statuses(case, &http_class, &http_code, http_status, grpc_code);
        }
    }
}
