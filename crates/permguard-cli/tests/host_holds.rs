// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `permguard host holds` (WP-7.3c, owner decisions of 2026-10-21): offline, on the volume of a
//! stopped server, a hold is added, listed and released through the Host's mutation transaction.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const ZONE: &str = "01a00000-0000-7000-8000-00000000000a";
const LEDGER: &str = "01a00000-0000-7000-8000-00000000000b";

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

/// WP-7.3c, owner decision of 2026-10-21: `add` writes the hold, `list` shows where it stands,
/// `release` removes it; a hold that names a name, or both deadlines, is a usage error.
#[test]
fn the_cli_adds_lists_and_releases_a_hold_offline() {
    let dir = scratch("lifecycle");
    let volume = volume(&dir);
    let volume = volume.to_str().expect("a path");
    let resource = format!("plane/control/zone/{ZONE}/ledger/{LEDGER}");

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
