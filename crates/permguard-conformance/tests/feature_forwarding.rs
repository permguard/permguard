// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A feature turns on what a build links: every `dependency/feature` a workspace package's feature
//! names is a dependency that build links, normal or build, never a dev-dependency alone.
//!
//! A feature forwarded to a dev-dependency compiles and does nothing: resolver 3 unifies no
//! dev-dependency's features into a binary, so the binary built with it lacks what the feature
//! promised and says so only at run time (BUG-0342: the command line's `pkcs11` named the server
//! after the server became a dev-dependency, and the custody was refused as "built without it").

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

/// One workspace package: its features, and its dependencies by the name its manifest gives them.
struct Package {
    name: String,
    features: BTreeMap<String, Vec<String>>,
    /// What its builds link: normal and build dependencies.
    linked: BTreeSet<String>,
    /// What its tests alone link.
    dev: BTreeSet<String>,
}

/// Every workspace package, read from the manifests cargo resolves.
fn packages() -> Vec<Package> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--no-deps", "--locked"])
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
    metadata["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .map(|package| {
            let features = package["features"]
                .as_object()
                .expect("features")
                .iter()
                .map(|(name, entries)| {
                    (
                        name.clone(),
                        entries
                            .as_array()
                            .expect("a feature's entries")
                            .iter()
                            .map(|entry| entry.as_str().expect("an entry").to_owned())
                            .collect(),
                    )
                })
                .collect();
            let (mut linked, mut dev) = (BTreeSet::new(), BTreeSet::new());
            for dependency in package["dependencies"].as_array().expect("dependencies") {
                let name = dependency["rename"]
                    .as_str()
                    .or_else(|| dependency["name"].as_str())
                    .expect("a dependency's name")
                    .to_owned();
                if dependency["kind"].as_str() == Some("dev") {
                    dev.insert(name);
                } else {
                    linked.insert(name);
                }
            }
            Package {
                name: package["name"].as_str().expect("a name").to_owned(),
                features,
                linked,
                dev,
            }
        })
        .collect()
}

/// The dependency a feature entry turns a feature of, if it names one: `dep/feature` and
/// `dep?/feature`; `dep:name` and a plain feature name turn on no feature of a dependency.
fn forwarded(entry: &str) -> Option<&str> {
    if entry.starts_with("dep:") {
        return None;
    }
    entry
        .split_once('/')
        .map(|(dependency, _)| dependency.trim_end_matches('?'))
}

#[test]
fn test_no_feature_turns_on_a_dev_dependency_alone() {
    let packages = packages();
    assert!(
        packages.len() > 20,
        "the workspace is read: {} packages",
        packages.len()
    );
    let mut problems = Vec::new();
    let mut seen = 0;
    for Package {
        name: package,
        features,
        linked,
        dev,
    } in &packages
    {
        for (feature, entries) in features {
            for entry in entries {
                let Some(dependency) = forwarded(entry) else {
                    continue;
                };
                seen += 1;
                if !linked.contains(dependency) {
                    let why = if dev.contains(dependency) {
                        "a dev-dependency only, which no build of the package links"
                    } else {
                        "no dependency of the package"
                    };
                    problems.push(format!("{package}: `{feature}` names `{entry}`, {why}"));
                }
            }
        }
    }
    assert!(seen > 10, "the check reads real features: {seen} entries");
    assert!(
        problems.is_empty(),
        "features that turn on nothing a build links:\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn test_the_forms_of_a_feature_entry_are_read() {
    assert_eq!(
        forwarded("permguard-offline/pkcs11"),
        Some("permguard-offline")
    );
    assert_eq!(
        forwarded("permguard-offline?/pkcs11"),
        Some("permguard-offline")
    );
    assert_eq!(forwarded("dep:cryptoki"), None);
    assert_eq!(forwarded("cli-bin"), None);
}
