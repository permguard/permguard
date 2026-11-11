// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The API layout of iteration 02 (D13, WP-13.3, `7-contracts/0` Path layout): every REST path is
//! `/<interface>/<version>/<resource>`, the interface a name the registry knows and the tenant part
//! of the resource, never of the prefix; a short list of exceptions is named here. Checked on what
//! the contracts publish and on what the source mounts, so a route added off the layout fails
//! here whichever of the two it reached first.
//!
//! `contracts/endpoints.csv` is generated from the contracts' `x-permguard-endpoint` and checked:
//! `PERMGUARD_WRITE_ENDPOINTS=1` writes it again after a contract changed.

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

/// The interfaces the registry knows, and the three surfaces' own key sets.
const INTERFACES: &[&str] = &[
    "catalog",
    "notp",
    "decisions",
    "events",
    "temporal",
    "streams",
    "host",
    "authority",
    "control-plane",
    "data-plane",
    "server-host",
];

/// Paths outside the rule, each with its reason in `7-contracts/0` Path layout.
const EXCEPTIONS: &[&str] = &[
    // The paths of the OpenID AuthZEN standard.
    "/access/v1/evaluation",
    "/access/v1/evaluations",
    // Operations endpoints probes and scrapers address by fixed paths.
    "/",
    "/version",
    "/health",
    "/healthz",
    "/readyz",
    "/metrics",
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Whether one segment is a version: `v1`, `v1alpha1`, `v2beta3`.
fn is_version(segment: &str) -> bool {
    let Some(rest) = segment.strip_prefix('v') else {
        return false;
    };
    let digits = rest.chars().take_while(char::is_ascii_digit).count();
    if digits == 0 {
        return false;
    }
    let stage = &rest[digits..];
    stage.is_empty()
        || ["alpha", "beta"].iter().any(|name| {
            stage.strip_prefix(name).is_some_and(|number| {
                !number.is_empty() && number.chars().all(|c| c.is_ascii_digit())
            })
        })
}

/// Whether `path` is at its place in the layout, or one of the named exceptions.
fn on_layout(path: &str) -> bool {
    if EXCEPTIONS.contains(&path) || path.starts_with("/.well-known/") {
        return true;
    }
    let mut segments = path.trim_start_matches('/').split('/');
    let (Some(interface), Some(version)) = (segments.next(), segments.next()) else {
        return false;
    };
    INTERFACES.contains(&interface) && is_version(version)
}

#[test]
fn the_layout_rule_reads_paths_as_the_contract_says() {
    for held in [
        "/catalog/v1/zones",
        "/notp/v1/zones/{zone}/ledgers/{ledger}/refs/{name}",
        "/events/v1alpha1/zones/{zone}/ledgers/{ledger}/records",
        "/control-plane/v1/keys",
        "/access/v1/evaluation",
        "/.well-known/server-configuration",
        "/health",
    ] {
        assert!(on_layout(held), "{held}");
    }
    for held in [
        "/v1/zones",
        "/zones/{zone}/ledgers/{ledger}/decisions/v1/records",
        "/decisions/records",
        "/events/latest/records",
        "/control-plane/keys",
        "/v1/streams",
        "/access/v2/evaluation",
        "/unknown/v1/things",
    ] {
        assert!(!on_layout(held), "{held}");
    }
}

/// Every OpenAPI document under `contracts/openapi`.
fn documents() -> Vec<(String, serde_json::Value)> {
    let mut found: Vec<(String, serde_json::Value)> =
        std::fs::read_dir(root().join("contracts/openapi"))
            .expect("contracts/openapi lists")
            .map(|entry| entry.expect("an entry").path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .map(|path| {
                let name = path
                    .file_name()
                    .expect("a name")
                    .to_string_lossy()
                    .into_owned();
                let document = serde_json::from_slice(&std::fs::read(&path).expect("reads"))
                    .expect("a JSON document");
                (name, document)
            })
            .collect();
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found
}

const METHODS: &[&str] = &["get", "post", "put", "patch", "delete"];

#[test]
fn every_published_path_is_on_the_layout() {
    let mut offences = Vec::new();
    for (name, document) in documents() {
        let Some(paths) = document["paths"].as_object() else {
            continue;
        };
        for path in paths.keys() {
            if !on_layout(path) {
                offences.push(format!("{name}: {path}"));
            }
        }
    }
    assert!(
        offences.is_empty(),
        "paths off `/<interface>/<version>/<resource>` (7-contracts/0 Path layout):\n{}",
        offences.join("\n")
    );
}

/// The roots of a file path, never of a route: a constant naming one is not a route.
const FILESYSTEM: &[&str] = &[
    "/var/", "/etc/", "/tmp/", "/dev/", "/proc/", "/run/", "/usr/", "/sys/", "/opt/", "/home/",
];

/// Every `.rs` file under `dir`, tests excluded: what a server mounts.
fn sources(dir: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("lists") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "tests") {
                continue;
            }
            sources(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

/// The first string literal after `marker` on each line it is found: a mounted path.
fn literals_after<'a>(text: &'a str, marker: &str) -> Vec<&'a str> {
    let mut held = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find(marker) {
        rest = &rest[at + marker.len()..];
        let trimmed = rest.trim_start();
        if let Some(open) = trimmed.strip_prefix('"')
            && let Some(close) = open.find('"')
        {
            held.push(&open[..close]);
        }
    }
    held
}

#[test]
fn every_mounted_route_is_on_the_layout() {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(root().join("crates")).expect("crates lists") {
        let src = entry.expect("an entry").path().join("src");
        if src.is_dir() {
            sources(&src, &mut files);
        }
    }
    let mut offences = Vec::new();
    let mut mounted = 0;
    for file in files {
        let whole = std::fs::read_to_string(&file).expect("reads");
        // What the crate builds, not its unit tests: a test router mounts what it likes.
        let text = whole.split("\n#[cfg(test)]").next().unwrap_or_default();
        // Only the server side: a route a router mounts, or the constant a router mounts.
        let mut paths = literals_after(text, ".route(");
        // Every string constant, of any visibility and name, whose value is a path: what a router
        // mounts by name, its value on the line or, rustfmt having split it, on the next.
        let lines: Vec<&str> = text.lines().collect();
        for (at, line) in lines.iter().enumerate() {
            let line = line.trim_start();
            let declares = line.contains("const ") && line.contains(": &str =");
            if !declares {
                continue;
            }
            let value = line
                .split_once(": &str =")
                .map(|(_, value)| value.trim())
                .filter(|value| !value.is_empty())
                .or_else(|| lines.get(at + 1).map(|next| next.trim()));
            if let Some(held) = value.and_then(|value| value.strip_prefix('"'))
                && let Some(held) = held.split('"').next()
                && held.starts_with('/')
                && !held.contains(' ')
                && !FILESYSTEM.iter().any(|root| held.starts_with(root))
            {
                paths.push(held);
            }
        }
        // A router built another way is one this scan cannot read: refused, so it is never
        // silently skipped.
        for unread in [".nest(", ".route_service(", ".nest_service("] {
            if text.contains(unread) {
                offences.push(format!(
                    "{}: mounts with `{unread}`, which this check does not follow",
                    file.display()
                ));
            }
        }
        for path in paths.into_iter().filter(|path| path.starts_with('/')) {
            mounted += 1;
            if !on_layout(path) {
                offences.push(format!("{}: {path}", file.display()));
            }
        }
    }
    assert!(
        mounted > 50,
        "the scan found {mounted} mounted paths: it reads nothing"
    );
    assert!(
        offences.is_empty(),
        "routes off `/<interface>/<version>/<resource>` (7-contracts/0 Path layout):\n{}",
        offences.join("\n")
    );
}

/// The CSV the contracts imply: one row per operation, in a fixed order.
fn endpoints_csv() -> String {
    const PLANES: &[&str] = &["data", "control", "authority", "host", "every surface"];
    let mut rows: Vec<(usize, String, String, usize, String)> = Vec::new();
    let mut missing = Vec::new();
    for (name, document) in documents() {
        let Some(paths) = document["paths"].as_object() else {
            continue;
        };
        for (path, operations) in paths {
            for (rank, method) in METHODS.iter().enumerate() {
                let Some(operation) = operations.get(*method) else {
                    continue;
                };
                let endpoint = &operation["x-permguard-endpoint"];
                let text = |field: &str| endpoint[field].as_str().unwrap_or_default().to_owned();
                let plane = text("plane");
                let Some(order) = PLANES.iter().position(|held| *held == plane) else {
                    missing.push(format!("{name}: {} {path}", method.to_uppercase()));
                    continue;
                };
                let row = [
                    plane,
                    text("category"),
                    method.to_uppercase(),
                    path.clone(),
                    text("credential"),
                    text("operation"),
                    text("target"),
                ]
                .iter()
                .map(|cell| {
                    if cell.contains([',', '"']) {
                        format!("\"{}\"", cell.replace('"', "\"\""))
                    } else {
                        cell.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(",");
                rows.push((order, text("category"), path.clone(), rank, row));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "operations without an `x-permguard-endpoint` naming one of {PLANES:?}:\n{}",
        missing.join("\n")
    );
    rows.sort();
    let mut csv = String::from("PLANE,CATEGORY,HTTP VERB,ENDPOINT,AUTH,AZ SCOPE,AZ TARGET\n");
    for (.., row) in rows {
        csv.push_str(&row);
        csv.push('\n');
    }
    csv
}

#[test]
fn endpoints_csv_is_what_the_contracts_say() {
    let generated = endpoints_csv();
    let path = root().join("contracts/endpoints.csv");
    if std::env::var_os("PERMGUARD_WRITE_ENDPOINTS").is_some() {
        std::fs::write(&path, &generated).expect("contracts/endpoints.csv writes");
    }
    let held = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        held == generated,
        "contracts/endpoints.csv is not what the contracts say: write it again with \
         `PERMGUARD_WRITE_ENDPOINTS=1 cargo test -p permguard-conformance --test api_layout`"
    );
}
