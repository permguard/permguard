// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Every engine dependency is pinned exactly, compiles without its defaults, and names the
//! features its descriptor lists — so a feature or version change is visible as a descriptor
//! change in the same diff.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use permguard_languages::registry::engine_features;

/// The text of one dependency declaration, which may span several lines.
fn declaration<'a>(manifest: &'a str, name: &str) -> &'a str {
    let start = manifest
        .find(&format!("\n{name} = "))
        .unwrap_or_else(|| panic!("`{name}` is declared in Cargo.toml"))
        + 1;
    let rest = &manifest[start..];
    let end = if rest[name.len() + 3..].trim_start().starts_with('{') {
        // A table: it ends at the first `}` that closes it.
        rest.find('}').expect("the table closes") + 1
    } else {
        rest.find('\n').unwrap_or(rest.len())
    };
    &rest[..end]
}

fn features(declaration: &str) -> Vec<String> {
    let Some(start) = declaration.find("features = [") else {
        return Vec::new();
    };
    let list = &declaration[start + "features = [".len()..];
    let list = &list[..list.find(']').expect("the feature list closes")];
    list.split(',')
        .map(|item| item.trim().trim_matches('"').to_owned())
        .filter(|item| !item.is_empty())
        .collect()
}

#[test]
fn test_every_engine_is_pinned_without_defaults_and_names_its_descriptor_features() {
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("the manifest is readable");

    for (name, expected) in [
        ("cedar-policy", engine_features::CEDAR),
        ("regorus", engine_features::REGO),
        ("amzn-dogwood-language", engine_features::DOGWOOD),
    ] {
        let declared = declaration(&manifest, name);
        assert!(
            declared.contains("default-features = false"),
            "`{name}` must not take its defaults: {declared}"
        );
        assert!(
            declared.contains("version = \"=") || declared.contains("rev = \""),
            "`{name}` must be pinned to an exact version or revision: {declared}"
        );
        let mut listed = features(declared);
        let sorted = {
            let mut copy = listed.clone();
            copy.sort();
            copy
        };
        assert_eq!(listed, sorted, "`{name}` lists its features sorted");
        listed.dedup();
        assert_eq!(
            listed,
            expected.iter().map(|f| (*f).to_owned()).collect::<Vec<_>>(),
            "`{name}`'s features in Cargo.toml and registry::engine_features differ: change both"
        );
    }
}

#[test]
fn test_the_feature_parser_reads_one_line_and_multi_line_declarations() {
    let manifest = "\nx = { version = \"=1.0.0\", default-features = false, features = [\"b\", \"a\"] }\n\
                    y = { version = \"=2\", default-features = false, features = [\n    \"c\",\n] }\nz = \"1\"\n";
    assert_eq!(features(declaration(manifest, "x")), ["b", "a"]);
    assert_eq!(features(declaration(manifest, "y")), ["c"]);
    assert!(features(declaration(manifest, "z")).is_empty());
}

/// Every feature `roots` turn on, `roots` included, followed through the package's feature table
/// the way Cargo follows it: `a` turns on the feature `a`; `x/y` turns on the dependency `x`, and
/// with it the feature `x` when the package has one; `x?/y` and `dep:x` turn on no feature of the
/// package.
fn closure(
    table: &serde_json::Map<String, serde_json::Value>,
    roots: &[&str],
) -> std::collections::BTreeSet<String> {
    let mut on = std::collections::BTreeSet::new();
    let mut pending: Vec<String> = roots.iter().map(|root| (*root).to_owned()).collect();
    while let Some(feature) = pending.pop() {
        if !on.insert(feature.clone()) {
            continue;
        }
        for implied in table
            .get(&feature)
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
        {
            if implied.starts_with("dep:") {
                continue;
            }
            match implied.split_once('/') {
                None => pending.push(implied.to_owned()),
                Some((dependency, _))
                    if !dependency.ends_with('?') && table.contains_key(dependency) =>
                {
                    pending.push(dependency.to_owned());
                }
                Some(_) => {}
            }
        }
    }

    on
}

/// The declarations are one manifest; what is compiled is what Cargo resolves for the whole
/// workspace, after unifying every crate that depends on an engine — a Dogwood revision that asks
/// Cedar for another feature, a second declaration under a target table, a local feature that
/// forwards to the engine. Every one of them shows here, as a resolved feature the descriptor does
/// not list.
///
/// Resolved twice: with the default features, and with every feature of every crate, which is how
/// the tests and the release build — a local feature that forwards to an engine shows only there.
#[test]
fn test_the_resolved_engine_features_are_the_descriptor_features() {
    for selection in [&[][..], &["--all-features"][..]] {
        resolved_engine_features_are_the_descriptor_features(selection);
    }
}

fn resolved_engine_features_are_the_descriptor_features(selection: &[&str]) {
    let output = std::process::Command::new(env!("CARGO"))
        .args(["metadata", "--locked", "--format-version", "1"])
        .args(selection)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo metadata runs");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata is JSON");
    let packages = metadata["packages"].as_array().expect("packages");
    let nodes = metadata["resolve"]["nodes"]
        .as_array()
        .expect("the resolve graph");

    for (name, expected) in [
        ("cedar-policy", engine_features::CEDAR),
        ("regorus", engine_features::REGO),
        ("amzn-dogwood-language", engine_features::DOGWOOD),
    ] {
        let matching: Vec<_> = packages
            .iter()
            .filter(|package| package["name"] == name)
            .collect();
        assert_eq!(matching.len(), 1, "one version of `{name}` is compiled");
        let package = matching[0];
        let table = package["features"].as_object().expect("a feature table");
        let node = nodes
            .iter()
            .find(|node| node["id"] == package["id"])
            .unwrap_or_else(|| panic!("`{name}` is in the resolve graph"));
        let resolved: std::collections::BTreeSet<String> = node["features"]
            .as_array()
            .expect("resolved features")
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_owned)
            .collect();

        let mut allowed = closure(table, expected);
        // `default` may arrive through another dependent — Dogwood depends on Cedar with its
        // defaults — and is admitted only while it turns on nothing the descriptor does not list.
        if resolved.contains("default") {
            let defaults = closure(table, &["default"]);
            let beyond: Vec<_> = defaults
                .iter()
                .filter(|feature| *feature != "default" && !allowed.contains(*feature))
                .collect();
            assert!(
                beyond.is_empty(),
                "`{name}` is compiled with its defaults, which turn on {beyond:?} beyond its descriptor"
            );
            allowed.insert("default".to_owned());
        }
        assert_eq!(
            resolved, allowed,
            "`{name}` is compiled ({selection:?}) with features its descriptor does not list, or without ones it does"
        );
    }
}
