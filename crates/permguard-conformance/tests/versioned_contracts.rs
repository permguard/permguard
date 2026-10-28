// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! P8, the API boundary (`9-architecture-patterns.md`): contracts are versioned. Every resource
//! path of every OpenAPI document, every protobuf package, and every record type, protected type,
//! digest domain, interface, artifact and input contract carries its version, so a change is a
//! new version beside the old one, never an edit under the same name. The unversioned paths are
//! the operational entry points a client reaches before it knows any version, and are named here.

#![allow(clippy::expect_used)]

use std::path::Path;

/// The paths a client reaches before it has chosen a contract: discovery, health, metrics and the
/// published key sets. Each discovery document is itself named after the version it describes.
const ENTRY_POINTS: &[&str] = &[
    "/",
    "/.well-known/server-configuration",
    "/health",
    "/healthz",
    "/readyz",
    "/version",
    "/metrics",
    "/server-host/keys",
    "/control-plane/keys",
    "/data-plane/keys",
];

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
    if stage.is_empty() {
        return true;
    }
    ["alpha", "beta"].iter().any(|name| {
        stage
            .strip_prefix(name)
            .is_some_and(|number| !number.is_empty() && number.chars().all(|c| c.is_ascii_digit()))
    })
}

/// Whether `name` carries a version among its segments.
fn versioned(name: &str) -> bool {
    name.split(['.', '/', '-', '+', ':', '\n', '_'])
        .any(is_version)
}

#[test]
fn the_version_reader_tells_a_version_from_a_word() {
    for held in ["v1", "v12", "v1alpha1", "v2beta3"] {
        assert!(is_version(held), "{held}");
    }
    for held in ["v", "va", "version", "v1alpha", "v1gamma1", "1", "values"] {
        assert!(!is_version(held), "{held}");
    }
}

#[test]
fn every_record_type_protected_type_and_contract_carries_its_version() {
    let unversioned: Vec<String> = permguard_core::domains::all()
        .into_iter()
        .filter(|(name, _)| {
            [
                "digest.",
                "protected.",
                "record.",
                "interface.",
                "artifact.",
                "input.",
            ]
            .iter()
            .any(|kind| name.starts_with(kind))
        })
        .filter(|(_, value)| !versioned(value))
        .map(|(name, value)| format!("{name} = {value:?}"))
        .collect();
    assert!(
        unversioned.is_empty(),
        "every contract name carries its version:\n  {}",
        unversioned.join("\n  ")
    );
}

#[test]
fn every_resource_path_of_every_openapi_document_carries_its_version() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/openapi");
    let mut paths = 0;
    let mut unversioned = Vec::new();
    for entry in std::fs::read_dir(&root).expect("the OpenAPI documents are listed") {
        let path = entry.expect("an entry").path();
        if path.extension().and_then(|held| held.to_str()) != Some("json") {
            continue;
        }
        let document: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&path).expect("the document is readable"),
        )
        .expect("the document is JSON");
        for route in document["paths"]
            .as_object()
            .into_iter()
            .flat_map(|held| held.keys())
        {
            paths += 1;
            if !versioned(route) && !ENTRY_POINTS.contains(&route.as_str()) {
                unversioned.push(format!(
                    "{}: {route}",
                    path.file_name()
                        .and_then(|held| held.to_str())
                        .unwrap_or("?")
                ));
            }
        }
    }
    assert!(paths > 50, "the documents were read ({paths} paths)");
    assert!(
        unversioned.is_empty(),
        "a resource path carries its version, or is an entry point named in this test:\n  {}",
        unversioned.join("\n  ")
    );
}

#[test]
fn every_protobuf_package_carries_its_version() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/proto");
    let mut pending = vec![root];
    let mut packages = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).expect("listed") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().and_then(|held| held.to_str()) == Some("proto") {
                let text = std::fs::read_to_string(&path).expect("readable");
                let package = text
                    .lines()
                    .find_map(|line| line.trim().strip_prefix("package "))
                    .map(|held| held.trim_end_matches(';').trim().to_owned())
                    .unwrap_or_else(|| panic!("{} declares a package", path.display()));
                packages.push((path, package));
            }
        }
    }
    assert!(packages.len() >= 5, "the protobuf files were read");
    for (path, package) in packages {
        assert!(
            package.rsplit('.').next().is_some_and(is_version),
            "{}: package {package} ends with its version",
            path.display()
        );
    }
}
