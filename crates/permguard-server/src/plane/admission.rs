// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The routes each surface admits, read from the contracts the binary carries: every operation
//! of `contracts/openapi` names the Plane that serves it, the credential it takes, the operation
//! it requires and the resource it applies to (`x-permguard-endpoint`), and the transport refuses
//! a caller holding that operation nowhere under the resource's plane before the route runs
//! ([`permguard_transport::AdmissionLayer`]). One table for every surface, from the one source
//! the conformance tests check the code against: a route cannot be served without the standing
//! its contract states, and a contract cannot drift from what is served.

use std::sync::{Arc, OnceLock};

use axum::Router;
use http::Method;
use permguard_core::authz::{Admission, Resource};
use permguard_transport::{AdmissionLayer, AdmittedRoute, Requirement};

/// The contracts carried, each a document of `contracts/openapi` with paths; the test below
/// holds the list to the directory.
pub const CONTRACTS: &[(&str, &str)] = &[
    (
        "authority.json",
        include_str!("../../../../contracts/openapi/authority.json"),
    ),
    (
        "catalog.json",
        include_str!("../../../../contracts/openapi/catalog.json"),
    ),
    (
        "discovery.json",
        include_str!("../../../../contracts/openapi/discovery.json"),
    ),
    (
        "evidence-decisions.json",
        include_str!("../../../../contracts/openapi/evidence-decisions.json"),
    ),
    (
        "evidence-events-v1alpha1.json",
        include_str!("../../../../contracts/openapi/evidence-events-v1alpha1.json"),
    ),
    (
        "health.json",
        include_str!("../../../../contracts/openapi/health.json"),
    ),
    (
        "host.json",
        include_str!("../../../../contracts/openapi/host.json"),
    ),
    (
        "notp.json",
        include_str!("../../../../contracts/openapi/notp.json"),
    ),
    (
        "pdp-native-v1.json",
        include_str!("../../../../contracts/openapi/pdp-native-v1.json"),
    ),
    (
        "pdp-temporal-v1alpha1.json",
        include_str!("../../../../contracts/openapi/pdp-temporal-v1alpha1.json"),
    ),
];

/// The credential of a route the transport admits by a token's standing: the other credentials
/// are open routes, the token endpoint's own proof, and peer sessions, each decided elsewhere.
const ACCESS_TOKEN: &str = "access token";

/// One contract row: the Plane serving it, and the route it admits.
struct Row {
    plane: String,
    route: AdmittedRoute,
}

fn rows() -> &'static [Row] {
    static ROWS: OnceLock<Vec<Row>> = OnceLock::new();
    ROWS.get_or_init(|| {
        CONTRACTS
            .iter()
            .flat_map(|(name, text)| {
                let document: serde_json::Value = serde_json::from_str(text)
                    .unwrap_or_else(|error| panic!("{name} is not JSON: {error}"));
                rows_of(&document)
            })
            .collect()
    })
}

/// The rows of one contract document: for each operation taking an access token, its HTTP route
/// and, when it has one, its gRPC twin.
fn rows_of(document: &serde_json::Value) -> Vec<Row> {
    let mut rows = Vec::new();
    let Some(paths) = document["paths"].as_object() else {
        return rows;
    };
    for (path, operations) in paths {
        let Some(operations) = operations.as_object() else {
            continue;
        };
        for (method, operation) in operations {
            let Ok(method) = Method::from_bytes(method.to_uppercase().as_bytes()) else {
                continue;
            };
            let endpoint = &operation["x-permguard-endpoint"];
            if endpoint["credential"].as_str() != Some(ACCESS_TOKEN) {
                continue;
            }
            let text = |field: &str| endpoint[field].as_str().unwrap_or_default().to_owned();
            let scopes = scopes_of(&text("target"));
            assert!(
                !text("operation").is_empty() && !scopes.is_empty(),
                "{method} {path} takes a token but names no operation or target"
            );
            let plane = text("plane");
            let requires = Requirement::of(&text("operation"));
            rows.push(Row {
                plane: plane.clone(),
                route: AdmittedRoute {
                    method: Some(method),
                    path: path.clone(),
                    requires: requires.clone(),
                    scopes: scopes.clone(),
                },
            });
            if let Some(rpc) = operation["x-grpc-rpc"].as_str() {
                rows.push(Row {
                    plane,
                    route: AdmittedRoute {
                        method: None,
                        path: format!("/{rpc}"),
                        requires,
                        scopes,
                    },
                });
            }
        }
    }
    rows
}

/// The scopes a contract's `target` names: `host`, and each `plane/<name>`, an alternation
/// `plane/<data|control>` being each of them. A resource below a plane is the plane's: the
/// handler resolves it, this only asks whether the caller holds anything there.
fn scopes_of(target: &str) -> Vec<Resource> {
    let mut scopes = Vec::new();
    for part in target.split('|').map(str::trim) {
        if part.starts_with("host") {
            scopes.push(Resource::host());
        }
    }
    let mut rest = target;
    while let Some(at) = rest.find("plane/") {
        rest = &rest[at + "plane/".len()..];
        let planes: Vec<&str> = match rest.strip_prefix('<') {
            Some(inner) => inner
                .split_once('>')
                .map(|(names, _)| names.split('|').collect())
                .unwrap_or_default(),
            None => vec![
                rest.split(|c: char| !c.is_ascii_alphabetic())
                    .next()
                    .unwrap_or(""),
            ],
        };
        for plane in planes {
            let plane = plane.trim();
            if !plane.is_empty() && !plane.starts_with('<') {
                scopes.push(Resource::plane(plane));
            }
        }
    }
    scopes.sort_by_key(ToString::to_string);
    scopes.dedup();
    scopes
}

/// The routes a surface serving `plane` admits by a token's standing.
pub fn routes_of(plane: &str) -> Vec<AdmittedRoute> {
    rows()
        .iter()
        .filter(|row| row.plane == plane)
        .map(|row| row.route.clone())
        .collect()
}

/// `router`, every closed route of `plane` asked only by a caller with standing under it.
pub fn admitted(router: Router, plane: &str, admission: Arc<dyn Admission>) -> Router {
    router.route_layer(AdmissionLayer::new(admission, routes_of(plane)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    /// The contracts carried are the contracts checked in: one with paths left out would leave
    /// its routes without the transport's admission.
    #[test]
    fn every_contract_with_paths_is_carried() {
        let directory =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/openapi");
        let mut on_disk: Vec<String> = std::fs::read_dir(&directory)
            .expect("the contracts directory")
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                let document: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).ok()?).ok()?;
                document["paths"]
                    .as_object()
                    .is_some_and(|paths| !paths.is_empty())
                    .then(|| path.file_name()?.to_str().map(str::to_owned))?
            })
            .collect();
        on_disk.sort();
        let carried: Vec<&str> = CONTRACTS.iter().map(|(name, _)| *name).collect();
        assert_eq!(carried, on_disk);
        for (name, text) in CONTRACTS {
            let checked_in = std::fs::read_to_string(directory.join(name)).expect(name);
            assert_eq!(text, &checked_in, "{name} is carried as checked in");
        }
    }

    /// Every Plane admits what its contract says, by the operation and the plane of the target;
    /// the Host API's routes on a Plane's resources admit under that plane too.
    #[test]
    fn the_routes_are_the_contracts() {
        let authority = routes_of("authority");
        assert_eq!(
            authority.len(),
            14 * 2,
            "14 routes, each with its gRPC twin"
        );
        let create = authority
            .iter()
            .find(|route| {
                route.method == Some(Method::POST) && route.path == "/authority/v1/service-accounts"
            })
            .expect("the create route");
        assert_eq!(create.requires, Requirement::of("accounts.write"));
        assert_eq!(create.scopes, vec![Resource::plane("authority")]);
        assert!(authority.iter().any(|route| route.method.is_none()
            && route.path == "/permguard.authority.v1.ServiceAccountService/CreateServiceAccount"));
        let host = routes_of("host");
        let streams = host
            .iter()
            .find(|route| route.path == "/host/v1/streams/{plane}/{stream_type}/records")
            .expect("a route on a plane's resource");
        assert_eq!(streams.requires, Requirement::of("streams.read"));
        assert_eq!(
            streams.scopes,
            vec![
                Resource::host(),
                Resource::plane("control"),
                Resource::plane("data")
            ]
        );
        let import = routes_of("control")
            .into_iter()
            .find(|route| route.path == "/catalog/v1/zones/{zone}/import")
            .expect("the import route");
        assert_eq!(
            import.requires,
            Requirement::All(vec!["catalog.write".to_owned(), "policy.push".to_owned()])
        );
        assert!(
            routes_of("every surface").is_empty(),
            "open routes are not admitted here"
        );
        assert!(
            routes_of("control")
                .iter()
                .all(|route| { route.scopes == vec![Resource::plane("control")] })
        );
        assert_eq!(
            scopes_of("host | plane/<data|control>[/zone/<zone_id>[/ledger/<ledger_id>]]"),
            vec![
                Resource::host(),
                Resource::plane("control"),
                Resource::plane("data")
            ]
        );
        assert_eq!(
            scopes_of(
                "plane/control/zone/<zone_id>/ledger/<ledger_id> | plane/control (a legacy stream)"
            ),
            vec![Resource::plane("control")]
        );
    }
}
