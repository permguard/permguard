// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The dependency direction of the composition (`1-architecture-server.md`): a Plane depends on the
//! Host, never the reverse. The Host, and every workspace crate it reaches, reaches no concrete Plane
//! and no binary that composes one, through any path of the resolved graph, normal or build.
//! `task check:core-deps` and `task check:seams` hold the narrower rules; this one reads the
//! graph cargo itself resolved, so a Plane reached transitively is caught too.

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

/// The crates a Plane is, or that compose one.
const ABOVE_THE_HOST: &[&str] = &[
    "permguard-authority-plane",
    "permguard-authority-plane-server",
    "permguard-control-plane",
    "permguard-data-plane",
    "permguard-data-plane-server",
    "permguard-all-in-one",
    "permguard-cli",
];

/// Every workspace package name, and the names it reaches through normal and build dependencies.
fn reached() -> BTreeMap<String, BTreeSet<String>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = Command::new(cargo)
        // Every feature: a Plane reached only through one that is off by default still counts.
        // Not offline: with every feature, cargo reads the manifests of dependencies for other
        // platforms too, which a runner's cache may not hold; the lockfile still pins them all.
        .args([
            "metadata",
            "--format-version",
            "1",
            "--all-features",
            "--locked",
        ])
        .current_dir(&root)
        .output()
        .expect("cargo metadata runs");
    assert!(
        output.status.success(),
        "cargo metadata: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata is JSON");
    let names: BTreeMap<&str, &str> = metadata["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .map(|package| {
            (
                package["id"].as_str().expect("an id"),
                package["name"].as_str().expect("a name"),
            )
        })
        .collect();
    // Each node's direct edges, dev-dependencies left out: a test may compose anything.
    let edges: BTreeMap<&str, Vec<&str>> = metadata["resolve"]["nodes"]
        .as_array()
        .expect("the resolved graph")
        .iter()
        .map(|node| {
            let to = node["deps"]
                .as_array()
                .expect("deps")
                .iter()
                .filter(|dep| {
                    dep["dep_kinds"]
                        .as_array()
                        .expect("dep kinds")
                        .iter()
                        .any(|kind| kind["kind"].as_str() != Some("dev"))
                })
                .map(|dep| dep["pkg"].as_str().expect("a package id"))
                .collect();
            (node["id"].as_str().expect("a node id"), to)
        })
        .collect();
    let mut closures = BTreeMap::new();
    for member in metadata["workspace_members"]
        .as_array()
        .expect("members")
        .iter()
        .map(|member| member.as_str().expect("a member id"))
    {
        let mut seen = BTreeSet::new();
        let mut pending = vec![member];
        while let Some(id) = pending.pop() {
            for next in edges.get(id).into_iter().flatten() {
                if seen.insert(*next) {
                    pending.push(next);
                }
            }
        }
        closures.insert(
            names[member].to_owned(),
            seen.into_iter().map(|id| names[id].to_owned()).collect(),
        );
    }
    closures
}

#[test]
fn the_host_and_the_crates_beneath_it_reach_no_plane() {
    let closures = reached();
    // Beneath the Host: itself and every workspace crate it reaches, whatever they are named.
    let mut beneath: Vec<&str> = closures["permguard-host"]
        .iter()
        .filter(|name| closures.contains_key(name.as_str()))
        .map(String::as_str)
        .collect();
    beneath.push("permguard-host");
    for shared in ["permguard-core", "permguard-objects"] {
        assert!(beneath.contains(&shared), "{shared} is beneath the Host");
    }
    let mut problems = Vec::new();
    for crate_name in &beneath {
        for plane in ABOVE_THE_HOST {
            if closures[*crate_name].contains(*plane) {
                problems.push(format!("{crate_name} reaches {plane}"));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "a Plane depends on the Host, never the reverse:\n  {}",
        problems.join("\n  ")
    );
    // The check reads a real graph: the Planes do reach the Host.
    for plane in [
        "permguard-authority-plane",
        "permguard-control-plane",
        "permguard-data-plane",
    ] {
        assert!(
            closures[plane].contains("permguard-host"),
            "{plane} composes on the Host"
        );
    }
}

/// The network and server stack: what only a server adapter, a listener or a network client links
/// (`11-refactoring/1-dependencies.md`, Target dependency layers).
const SERVER_STACK: &[&str] = &[
    "permguard-server",
    "permguard-transport",
    "permguard-telemetry",
    "axum",
    "tonic",
    "hyper",
    "tower-http",
    "opentelemetry",
];

/// What only a server links: a listener, the server composition, telemetry endpoints and exporters.
const SERVER_ONLY: &[&str] = &[
    "permguard-server",
    "permguard-transport",
    "permguard-telemetry",
    "tower-http",
    "opentelemetry",
];

/// What each layer may not reach, through any normal or build dependency, with every feature on.
/// A phase of the crate boundaries refactoring adds its rows when its split lands, so a boundary
/// once drawn cannot be crossed again unnoticed.
const LAYERS: &[(&str, &[&str])] = &[
    // The headless protocol, Host and evidence crates: no listener, no network stack.
    ("permguard-core", SERVER_STACK),
    ("permguard-objects", SERVER_STACK),
    ("permguard-notp", SERVER_STACK),
    ("permguard-host", SERVER_STACK),
    ("permguard-std", SERVER_STACK),
    ("permguard-stream", SERVER_STACK),
    ("permguard-decisions", SERVER_STACK),
    ("permguard-events", SERVER_STACK),
    // The policy languages validate and evaluate; they serve nothing and call nobody.
    ("permguard-languages", SERVER_STACK),
    // A Plane's domain serves nothing (RD-1): its routes, module and binary are its server
    // package's.
    ("permguard-authority-plane", SERVER_STACK),
    // The Data Plane's domain listens nowhere and composes no server (RD-2); the network client it
    // synchronizes and ships through still links tonic until the client surfaces split (phase 3).
    ("permguard-data-plane", SERVER_ONLY),
];

#[test]
fn each_layer_reaches_only_what_it_allows() {
    let closures = reached();
    let mut problems = Vec::new();
    for (package, forbidden) in LAYERS {
        let reached = closures
            .get(*package)
            .unwrap_or_else(|| panic!("{package} is a workspace member"));
        for name in *forbidden {
            if reached.contains(*name) {
                problems.push(format!("{package} reaches {name}"));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "a layer reaches what it may not (11-refactoring, Target dependency layers):\n  {}",
        problems.join("\n  ")
    );
    // The check reads a real graph: a server composition does reach the stack it forbids.
    for name in SERVER_STACK {
        assert!(
            closures["permguard-all-in-one"].contains(*name),
            "the all-in-one reaches {name}"
        );
    }
}
