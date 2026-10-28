// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The release configuration names what it packages by id, and an id that names nothing is not an
//! error to GoReleaser until the release runs: a build renamed while its archives, packages and
//! images still name the old id ships no Linux or Windows archive, and fails at `linux packages`
//! with `no linux binaries found`, after the tag is public (v0.1.10).
//!
//! The configuration is read as data: every id an archive, a package, an image or the notarisation
//! names is a build, every id the Homebrew cask names is an archive, and every build is in some
//! archive, so nothing that is built is left out of the release.

#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_norway::Value;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn config(name: &str) -> Value {
    let path = repository().join(name);
    serde_norway::from_str(&std::fs::read_to_string(&path).expect("the configuration is readable"))
        .expect("the configuration is YAML")
}

/// The `id` of every entry of `section`.
fn ids_of(config: &Value, section: &str) -> BTreeSet<String> {
    config[section]
        .as_sequence()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("id").and_then(Value::as_str))
        .map(str::to_owned)
        .collect()
}

/// Every id the entries of `entries` name in their `ids`, each with where it was named.
fn named(entries: Option<&Value>, at: &str) -> Vec<(String, String)> {
    entries
        .and_then(Value::as_sequence)
        .into_iter()
        .flatten()
        .enumerate()
        .flat_map(|(index, entry)| {
            let place = format!(
                "{at}[{index}]{}",
                entry
                    .get("id")
                    .and_then(Value::as_str)
                    .map(|id| format!(" ({id})"))
                    .unwrap_or_default()
            );
            entry
                .get("ids")
                .and_then(Value::as_sequence)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(move |id| (id.to_owned(), place.clone()))
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn every_id_the_release_names_is_one_it_builds_or_archives() {
    let base = config(".goreleaser.yaml");
    let pro = config(".goreleaser-pro.yaml");
    let builds = ids_of(&base, "builds");
    let archives = ids_of(&base, "archives");
    assert!(builds.len() >= 8, "the builds were read: {builds:?}");

    let mut problems = Vec::new();
    let mut referencing_builds = named(base.get("archives"), "archives");
    referencing_builds.extend(named(base.get("nfpms"), "nfpms"));
    referencing_builds.extend(named(base.get("dockers_v2"), "dockers_v2"));
    referencing_builds.extend(named(
        pro.get("notarize")
            .and_then(|notarize| notarize.get("macos")),
        "notarize.macos",
    ));
    for (id, place) in &referencing_builds {
        if !builds.contains(id) {
            problems.push(format!("{place} names `{id}`, which no build declares"));
        }
    }
    for (id, place) in named(pro.get("homebrew_casks"), "homebrew_casks") {
        if !archives.contains(&id) {
            problems.push(format!("{place} names `{id}`, which no archive declares"));
        }
    }
    let archived: BTreeSet<String> = named(base.get("archives"), "archives")
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    for build in &builds {
        if !archived.contains(build) {
            problems.push(format!(
                "the build `{build}` is in no archive: it would not ship"
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "the release configuration names what it does not build:\n  {}",
        problems.join("\n  ")
    );
}
