// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Every configuration file this workspace ships, read the way the binaries
//! read it.
//!
//! A shipped configuration is documentation that runs: an operator copies it
//! and expects it to start. Nothing checked these before, which is how a
//! `sync` block came to sit at the top level — parsed by nobody, silently
//! never read. So each file is parsed here, its plane sections are turned into
//! settings exactly as a plane does at startup, and what it declares about
//! mirroring is checked for shape.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use permguard_core::ConfigFile;
use permguard_core::mirrors::check_source;
use permguard_server::plane::settings::{PlaneSettingKeys, mirror_sources, plane_settings};

/// Every `config.*.yml` beside the three server crates.
fn shipped() -> Vec<PathBuf> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crates directory is above this one")
        .to_path_buf();
    let mut files = Vec::new();
    for crate_name in [
        "permguard-control-plane",
        "permguard-data-plane",
        "permguard-all-in-one",
    ] {
        let directory = crates.join(crate_name);
        for entry in std::fs::read_dir(&directory).expect("the crate directory is readable") {
            let path = entry.expect("the entry is readable").path();
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .to_owned();
            if name.starts_with("config.") && name.ends_with(".yml") {
                files.push(path);
            }
        }
    }
    files.sort();
    assert!(
        files.len() >= 24,
        "the three crates ship eight configurations each: {files:?}"
    );

    files
}

#[test]
fn every_shipped_configuration_parses() {
    for path in shipped() {
        let file = ConfigFile::load(&path).unwrap_or_else(|error| {
            panic!("{} does not parse: {error:#}", path.display());
        });
        // The typed settings are what the file layer contributes; a value of the
        // wrong shape is refused here rather than at the first request.
        let _ = file.settings();
    }
}

#[test]
fn every_plane_section_turns_into_the_settings_a_plane_reads() {
    for path in shipped() {
        let file = ConfigFile::load(&path).expect("the file parses");
        for (section, keys) in [
            ("controlPlane", PlaneSettingKeys::CONTROL),
            ("dataPlane", PlaneSettingKeys::DATA),
        ] {
            let Some(value) = file.section(section) else {
                continue;
            };
            let settings = plane_settings(value, keys).unwrap_or_else(|error| {
                panic!(
                    "the `{section}` section of {} is not what a plane reads: {error:#}",
                    path.display()
                );
            });
            assert!(
                !settings.is_empty(),
                "the `{section}` section of {} contributes nothing",
                path.display()
            );
        }
    }
}

#[test]
fn what_a_configuration_says_about_mirroring_is_well_shaped_and_in_the_right_place() {
    for path in shipped() {
        let file = ConfigFile::load(&path).expect("the file parses");

        // Mirroring is the data plane's own business, so it is declared inside
        // `dataPlane`. At the top level it would be read by nothing.
        assert!(
            file.section("mirrors").is_none(),
            "{} declares `mirrors` at the top level: it belongs under `dataPlane`",
            path.display()
        );

        let Some(value) = file.section("dataPlane") else {
            continue;
        };
        for source in mirror_sources(value).unwrap_or_else(|error| {
            panic!(
                "the sync block of {} does not parse: {error:#}",
                path.display()
            );
        }) {
            check_source(&source).unwrap_or_else(|error| {
                panic!(
                    "{} follows a server it could never reach: {error:#}",
                    path.display()
                );
            });
        }
    }
}

#[test]
fn a_data_plane_configuration_that_mirrors_names_the_server_it_mirrors_from() {
    // Every environment answers the same question — "where do the policies come
    // from here?" — so every data-plane configuration states it, whether the
    // block is on or waiting for its trust material.
    let mut examined = 0;
    for path in shipped() {
        let name = path.to_string_lossy();
        if !name.contains("permguard-data-plane") || name.ends_with("config.template.yml") {
            continue;
        }
        let file = ConfigFile::load(&path).expect("the file parses");
        let value = file
            .section("dataPlane")
            .expect("a data plane configures its plane");
        let sources = mirror_sources(value).expect("the sync block parses");
        assert!(
            !sources.is_empty(),
            "{} says nothing about where its policies come from",
            path.display()
        );
        examined += 1;
    }
    assert_eq!(examined, 7, "seven environments beside the template");
}
