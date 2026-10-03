// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The registries against their checked fixture, `tests/fixtures/registry.json`.
//!
//! The fixture names every public domain and stable code with its exact bytes. It is written from
//! the blueprint's registries and checked in; a registry that loses, duplicates or changes an entry
//! fails here, and so does a fixture edited without the registry following it.

use std::collections::BTreeMap;

use permguard_core::{codes, domains};

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/registry.json")).expect("the fixture is JSON")
}

fn expected(section: &str) -> BTreeMap<String, String> {
    fixture()[section]
        .as_object()
        .expect("a section is an object")
        .iter()
        .map(|(name, value)| {
            (
                name.clone(),
                value.as_str().expect("a value is a string").to_owned(),
            )
        })
        .collect()
}

/// The inventory as a map, failing on a name listed twice.
fn inventory(entries: Vec<(&'static str, &'static str)>) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for (name, value) in entries {
        assert!(
            map.insert(name.to_owned(), value.to_owned()).is_none(),
            "`{name}` is listed twice in the inventory"
        );
    }

    map
}

/// Every `pub const` a registry source declares, as `module.NAME`.
fn declared(source: &str) -> Vec<String> {
    let mut module = String::new();
    let mut names = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("pub mod ") {
            module = rest.trim_end_matches(" {").to_owned();
        } else if let Some((name, _)) = trimmed
            .strip_prefix("pub const ")
            .and_then(|rest| rest.split_once(':'))
        {
            names.push(format!("{module}.{name}"));
        }
    }

    names
}

#[test]
fn test_the_domain_inventory_is_the_checked_fixture() {
    assert_eq!(inventory(domains::all()), expected("domains"));
}

#[test]
fn test_the_code_inventory_is_the_checked_fixture() {
    assert_eq!(inventory(codes::all()), expected("codes"));
}

#[test]
fn test_every_declared_constant_is_in_its_inventory() {
    for (source, listed) in [
        (include_str!("../src/domains.rs"), inventory(domains::all())),
        (include_str!("../src/codes.rs"), inventory(codes::all())),
    ] {
        for name in declared(source) {
            assert!(
                listed.contains_key(&name),
                "`{name}` is declared but missing from its inventory"
            );
        }
    }
}
