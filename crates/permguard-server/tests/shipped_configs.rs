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
        files.len() >= 27,
        "the three crates ship every environment, plus the Dogwood variant: {files:?}"
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
    assert_eq!(examined, 8, "every environment beside the template");
}

/// One commented example, uncommented: the lines it would contribute if an operator used it.
///
/// A shipped configuration is mostly examples, and an example is documentation that *claims* to
/// run. Stripping one `# ` from a block's YAML lines is exactly what an operator does to it, so
/// that is what is done here — prose keeps its own `#` and stays a comment.
fn uncommented(lines: &[&str], from: usize, to: usize) -> Vec<String> {
    let mut out: Vec<String> = lines.iter().map(|line| (*line).to_owned()).collect();
    let mut written = Vec::new();
    for line in &lines[from..to] {
        let indent = line.len() - line.trim_start().len();
        let body = line.trim_start();
        let Some(rest) = body.strip_prefix('#') else {
            written.push((*line).to_owned());
            continue;
        };
        let rest = rest.strip_prefix(' ').unwrap_or(rest);
        let trimmed = rest.trim_start();
        // A YAML line, an inner comment, or a blank keeps its place; prose is dropped, because an
        // operator uncommenting a block does not uncomment the paragraph explaining it.
        let is_yaml = trimmed.starts_with('#')
            || trimmed.starts_with("- ")
            || trimmed.split_once(':').is_some_and(|(key, after)| {
                !key.is_empty()
                    && key
                        .chars()
                        .all(|held| held.is_ascii_alphanumeric() || held == '_' || held == '-')
                    && (after.is_empty() || after.starts_with(' '))
            });
        if trimmed.is_empty() || is_yaml {
            written.push(format!("{}{rest}", " ".repeat(indent)));
        }
    }
    out.splice(from..to, written);

    out
}

/// Whether a comment run is an example rather than a paragraph.
///
/// An example opens a block: somewhere in it is a line that is nothing but a key and a colon —
/// `events:`, `retention:`, `pull:`. Prose does not do that, and the distinction matters because
/// half of what is in these files is prose *about* the examples.
fn introduces_a_block(run: &[&str]) -> bool {
    run.iter().any(|line| {
        let body = line.trim_start().trim_start_matches('#').trim();

        body.strip_suffix(':').is_some_and(|key| {
            !key.is_empty()
                && key.starts_with(|held: char| held.is_ascii_lowercase())
                && key
                    .chars()
                    .all(|held| held.is_ascii_alphanumeric() || held == '_' || held == '-')
        })
    })
}

/// Every commented example in a shipped configuration would parse if an operator used it.
///
/// # What this is actually about
///
/// These files are read far more often than they are run, and most of what is in them is commented
/// out. An example indented under the wrong section is invisible to every check that only parses
/// what is *active*: it reads correctly, it is copied by an operator, and it fails at a startup
/// that happens somewhere else — or, worse, it lands somewhere that accepts it and is read by
/// nobody.
///
/// So each block is uncommented, one at a time, and the result is put through the same loader a
/// binary uses. An example that would not start is not documentation; it is a trap.
#[test]
fn every_commented_example_would_start_if_an_operator_used_it() {
    let mut examined = 0;
    for path in shipped() {
        let text = std::fs::read_to_string(&path).expect("the file is readable");
        let lines: Vec<&str> = text.lines().collect();

        let mut at = 0;
        while at < lines.len() {
            if !lines[at].trim_start().starts_with('#') || lines[at].starts_with('#') {
                at += 1;
                continue;
            }
            // An indented comment run: a block nested inside a section, which is where an example
            // lives. A run at the left margin is the file's own prose.
            let mut end = at;
            while end < lines.len()
                && (lines[end].trim().is_empty() || lines[end].trim_start().starts_with('#'))
            {
                end += 1;
            }
            if !introduces_a_block(&lines[at..end]) {
                // Prose, not an example. A paragraph explaining a setting is not a setting, and
                // uncommenting one would be asserting that English parses as YAML.
                at = end;
                continue;
            }
            let variant = uncommented(&lines, at, end).join("\n");
            let scratch = std::env::temp_dir().join(format!(
                "permguard-example-{}-{at}.yml",
                path.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("config")
            ));
            std::fs::write(&scratch, &variant).expect("the variant is written");

            let file = ConfigFile::load(&scratch).unwrap_or_else(|error| {
                panic!(
                    "the example at {}:{} does not parse when it is used: {error:#}\n{variant}",
                    path.display(),
                    at + 1
                );
            });
            let _ = file.settings();
            for (section, keys) in [
                ("controlPlane", PlaneSettingKeys::CONTROL),
                ("dataPlane", PlaneSettingKeys::DATA),
            ] {
                let Some(value) = file.section(section) else {
                    continue;
                };
                plane_settings(value, keys).unwrap_or_else(|error| {
                    panic!(
                        "the example at {}:{} is not what a plane reads once used: {error:#}",
                        path.display(),
                        at + 1
                    );
                });
            }
            let _ = std::fs::remove_file(&scratch);
            examined += 1;
            at = end;
        }
    }
    assert!(
        examined > 24,
        "the shipped configurations carry more examples than this: {examined}"
    );
}

/// One setting's value in a shipped file, as the loader produces it.
fn setting(path: &Path, name: &str) -> Option<String> {
    let file = ConfigFile::load(path).expect("the file parses");
    let mut found = file
        .settings()
        .into_iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value);
    if found.is_none() {
        for (section, keys) in [
            ("controlPlane", PlaneSettingKeys::CONTROL),
            ("dataPlane", PlaneSettingKeys::DATA),
        ] {
            let Some(value) = file.section(section) else {
                continue;
            };
            if let Some(held) = plane_settings(value, keys)
                .expect("the section is what a plane reads")
                .into_iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value)
            {
                found = Some(held);
            }
        }
    }

    found
}

/// A configuration named `-dogwood` turns the interfaces on, and every other one leaves them off.
///
/// # What this is actually about
///
/// The provisional interfaces are off everywhere by default, which is right and which also means
/// nothing in the shipped set exercises them. So one variant per crate turns them on, and it is
/// worth exactly as much as it is actually different from the file it was copied from: a variant
/// that quietly reverted to the defaults would still parse, still ship, and still be recommended in
/// the documentation as the way to see the interface work.
///
/// The other half of the assertion matters just as much. An experimental contract that crept into
/// an ordinary environment's file would be a deployment accepting an unstable shape because a
/// default moved, which is the thing the switch exists to prevent.
#[test]
fn the_dogwood_variants_are_the_only_shipped_configurations_that_turn_it_on() {
    use permguard_core::config::{
        SETTING_EVENT_STORE_ENABLED, SETTING_EVENTS_ENABLED, SETTING_EXPERIMENTAL_DOGWOOD,
    };

    let mut variants = 0;
    for path in shipped() {
        let name = path.to_string_lossy().into_owned();
        let dogwood = setting(&path, SETTING_EXPERIMENTAL_DOGWOOD);
        let is_variant = name.ends_with("config.local-experimental.yml");

        assert_eq!(
            dogwood.as_deref(),
            Some(if is_variant { "true" } else { "false" }),
            "{} says `experimental.dogwood.enabled: {dogwood:?}`",
            path.display()
        );
        if !is_variant {
            continue;
        }
        variants += 1;

        // And the plane's own half of the gate, for whichever planes this file configures. Both
        // are needed: one without the other is refused at startup.
        let has_data = ConfigFile::load(&path)
            .expect("the file parses")
            .section("dataPlane")
            .is_some();
        if has_data {
            assert_eq!(
                setting(&path, SETTING_EVENTS_ENABLED).as_deref(),
                Some("true"),
                "{} accepts the contract and keeps no history",
                path.display()
            );
        }
        let has_control = ConfigFile::load(&path)
            .expect("the file parses")
            .section("controlPlane")
            .is_some();
        if has_control {
            assert_eq!(
                setting(&path, SETTING_EVENT_STORE_ENABLED).as_deref(),
                Some("true"),
                "{} accepts the contract and receives nothing",
                path.display()
            );
        }
    }
    assert_eq!(variants, 3, "one variant per server crate");
}
