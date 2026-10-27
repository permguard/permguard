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
    "permguard-control-plane",
    "permguard-data-plane",
    "permguard-all-in-one",
    "permguard-cli",
];

/// Every workspace package name, and the names it reaches through normal and build dependencies.
fn reached() -> BTreeMap<String, BTreeSet<String>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = Command::new(cargo)
        // Every feature: a Plane reached only through one that is off by default still counts.
        .args([
            "metadata",
            "--format-version",
            "1",
            "--all-features",
            "--locked",
            "--offline",
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
    for plane in ["permguard-control-plane", "permguard-data-plane"] {
        assert!(
            closures[plane].contains("permguard-host"),
            "{plane} composes on the Host"
        );
    }
}
