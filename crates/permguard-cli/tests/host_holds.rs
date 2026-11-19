// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `permguard host holds` (WP-7.3c, owner decisions of 2026-10-21): offline, on the volume of a
//! stopped server, a hold is added, listed and released through the Host's mutation transaction.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// An id no catalog holds.
const UNKNOWN: &str = "01a00000-0000-7000-8000-00000000000c";

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "permguard-cli-holds-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory is created");
    dir
}

fn run(workdir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_permguard"))
        .arg("-w")
        .arg(workdir)
        .args(args)
        .env("PERMGUARD_CONFIG", workdir.join("cli-config.yml"))
        .env("NO_COLOR", "1")
        .output()
        .expect("the binary runs")
}

fn json(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("the JSON output parses")
}

/// A volume as a server's first start leaves it, the server stopped.
fn volume(dir: &Path) -> PathBuf {
    let volume = dir.join("volume");
    drop(
        permguard_host::storage::volume::Volume::claim(
            &volume,
            permguard_core::assurance::AssuranceProfile::Development,
        )
        .expect("a volume"),
    );
    volume
}

/// A zone of the volume's catalog and a ledger of it, by ids, where the server keeps them.
fn catalogued(volume: &Path, zone: &str) -> (String, String) {
    use permguard_core::Catalog as _;

    let catalog = permguard_std::catalog::FileCatalog::new(volume.join("data").join("zones"));
    let zone = catalog.create_zone(zone).expect("a zone");
    let ledger = catalog
        .create_ledger(
            &permguard_core::catalog::Selector::Id(zone.id.clone()),
            "policies",
        )
        .expect("a ledger");
    (zone.id, ledger.id)
}

/// WP-7.3c, owner decision of 2026-10-21: `add` writes the hold, `list` shows where it stands,
/// `release` removes it; a hold that names a name, or both deadlines, is a usage error.
#[test]
fn the_cli_adds_lists_and_releases_a_hold_offline() {
    let dir = scratch("lifecycle");
    let volume = volume(&dir);
    let (zone, ledger) = catalogued(&volume, "delivery");
    let volume = volume.to_str().expect("a path");
    let resource = format!("plane/control/zone/{zone}/ledger/{ledger}");

    let added = json(&run(
        &dir,
        &[
            "-o",
            "json",
            "host",
            "holds",
            "add",
            "--volume",
            volume,
            "--resource",
            &resource,
            "--owner",
            "legal@acme",
            "--reason",
            "litigation 2026-17",
            "--review-at",
            "2099-01-01T00:00:00Z",
        ],
    ));
    assert_eq!(added["action"], "added");
    assert_eq!(added["resource"], resource.as_str());
    assert_eq!(added["status"], "active");
    assert_eq!(added["review_at"], "2099-01-01T00:00:00Z");
    assert!(added.get("expires_at").is_none());
    let id = added["id"].as_str().expect("an id").to_owned();
    assert!(
        Path::new(volume)
            .join("host")
            .join("holds")
            .join(format!("{id}.json"))
            .is_file()
    );

    let listed = json(&run(
        &dir,
        &["-o", "json", "host", "holds", "list", "--volume", volume],
    ));
    assert_eq!(listed["holds"][0]["id"], id.as_str());
    assert_eq!(listed["holds"][0]["owner"], "legal@acme");
    // The same listing as text and as YAML.
    let text = run(&dir, &["host", "holds", "list", "--volume", volume]);
    let text = String::from_utf8_lossy(&text.stdout).into_owned();
    assert!(
        text.contains(&id) && text.contains("status:   active"),
        "{text}"
    );
    assert!(text.contains("1 hold(s)."), "{text}");
    let yaml = run(
        &dir,
        &["-o", "yaml", "host", "holds", "list", "--volume", volume],
    );
    let yaml = String::from_utf8_lossy(&yaml.stdout).into_owned();
    assert!(
        yaml.contains("status: active") && yaml.contains(&id),
        "{yaml}"
    );

    for refused in [
        vec![
            "--resource",
            "plane/control/zone/delivery",
            "--review-at",
            "2099-01-01T00:00:00Z",
        ],
        vec![
            "--resource",
            &resource,
            "--review-at",
            "2099-01-01T00:00:00Z",
            "--expires-at",
            "2099-01-01T00:00:00Z",
        ],
        vec!["--resource", &resource],
        vec![
            "--resource",
            &resource,
            "--expires-at",
            "2001-01-01T00:00:00Z",
        ],
    ] {
        let mut args = vec![
            "host", "holds", "add", "--volume", volume, "--owner", "o", "--reason", "r",
        ];
        args.extend(refused.iter().copied());
        let output = run(&dir, &args);
        assert!(!output.status.success(), "{refused:?}");
        assert_eq!(output.status.code(), Some(64), "{refused:?}: a usage error");
    }

    let released = json(&run(
        &dir,
        &[
            "-o", "json", "host", "holds", "release", "--volume", volume, &id,
        ],
    ));
    assert_eq!(released["action"], "released");
    let listed = json(&run(
        &dir,
        &["-o", "json", "host", "holds", "list", "--volume", volume],
    ));
    assert_eq!(listed["holds"], serde_json::json!([]));
    let again = run(&dir, &["host", "holds", "release", "--volume", volume, &id]);
    assert_eq!(
        again.status.code(),
        Some(64),
        "no hold has that id any more"
    );
}

/// Adds a hold on `resource` to `volume`, answering the command's output.
fn add(dir: &Path, volume: &str, resource: &str) -> Output {
    run(
        dir,
        &[
            "-o",
            "json",
            "host",
            "holds",
            "add",
            "--volume",
            volume,
            "--resource",
            resource,
            "--owner",
            "legal@acme",
            "--reason",
            "litigation 2026-17",
            "--expires-at",
            "2099-01-01T00:00:00Z",
        ],
    )
}

/// BUG-0171: a hold names a zone the catalog holds, and a ledger of that zone. An unknown zone,
/// an unknown ledger, and a real ledger under another real zone are refused, exit 64, naming the
/// id, with no hold file written; a hold on a real zone, and on a real ledger of it, is added.
#[test]
fn a_hold_on_ids_the_catalog_does_not_hold_is_refused() {
    let dir = scratch("catalog");
    let volume = volume(&dir);
    let (zone, ledger) = catalogued(&volume, "delivery");
    let (other_zone, other_ledger) = catalogued(&volume, "billing");
    let holds = volume.join("host").join("holds");
    let volume = volume.to_str().expect("a path");

    for (resource, named) in [
        (format!("plane/control/zone/{UNKNOWN}"), UNKNOWN),
        (
            format!("plane/control/zone/{UNKNOWN}/ledger/{ledger}"),
            UNKNOWN,
        ),
        (
            format!("plane/control/zone/{zone}/ledger/{UNKNOWN}"),
            UNKNOWN,
        ),
        (
            format!("plane/control/zone/{zone}/ledger/{other_ledger}"),
            other_ledger.as_str(),
        ),
    ] {
        let output = add(&dir, volume, &resource);
        assert_eq!(output.status.code(), Some(64), "{resource}");
        let said = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(said.contains(named), "{resource}: {said}");
        let written = std::fs::read_dir(&holds)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter(|entry| entry.file_name() != "INDEX.json")
                    .count()
            })
            .unwrap_or(0);
        assert_eq!(written, 0, "{resource}: nothing written");
    }

    json(&add(
        &dir,
        volume,
        &format!("plane/control/zone/{other_zone}"),
    ));
    json(&add(
        &dir,
        volume,
        &format!("plane/control/zone/{zone}/ledger/{ledger}"),
    ));
    let listed = json(&run(
        &dir,
        &["-o", "json", "host", "holds", "list", "--volume", volume],
    ));
    assert_eq!(listed["holds"].as_array().map(Vec::len), Some(2));
}

/// BUG-0172: a hold file removed without a release is named by `list`, exit 65, and by
/// `verify`, exit 2; with the files as the operations left them `verify` passes.
#[test]
fn a_hold_removed_outside_a_release_is_named_by_list_and_verify() {
    let dir = scratch("tampered");
    let volume = volume(&dir);
    let (zone, ledger) = catalogued(&volume, "delivery");
    let holds = volume.join("host").join("holds");
    let volume = volume.to_str().expect("a path");
    let added = json(&add(
        &dir,
        volume,
        &format!("plane/control/zone/{zone}/ledger/{ledger}"),
    ));
    let id = added["id"].as_str().expect("an id").to_owned();

    let verified = json(&run(
        &dir,
        &["-o", "json", "host", "holds", "verify", "--volume", volume],
    ));
    assert_eq!(verified["findings"], serde_json::json!([]));

    std::fs::remove_file(holds.join(format!("{id}.json"))).expect("removed");
    let listed = run(&dir, &["host", "holds", "list", "--volume", volume]);
    assert_eq!(listed.status.code(), Some(65));
    let said = String::from_utf8_lossy(&listed.stderr).into_owned();
    assert!(said.contains(&id) && said.contains("gone"), "{said}");

    let verified = run(
        &dir,
        &["-o", "json", "host", "holds", "verify", "--volume", volume],
    );
    assert_eq!(verified.status.code(), Some(2));
    let report: serde_json::Value =
        serde_json::from_slice(&verified.stdout).expect("the report parses");
    assert!(
        report["findings"]
            .as_array()
            .is_some_and(|findings| findings
                .iter()
                .any(|finding| finding.as_str().is_some_and(|text| text.contains(&id)))),
        "{report}"
    );
}
