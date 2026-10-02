// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A workspace as this release's `init` and `status` write it, kept so that every later layout can
//! prove the command line still reads one.
//!
//! `tests/fixtures/legacy/v1/workspace` is a workspace written by the current binary: `init`, one
//! Cedar policy, then `status`, which fills the workspace mirror with the policy's objects. Its
//! `.permguard` directory is stored as `dot-permguard`, because the repository ignores the real
//! name, and renamed back when the fixture is restored. In CI the fixture is copied aside and
//! read by the current binary, whose `status` must report the captured workspace and need no
//! object the mirror does not already hold. Setting
//! `PERMGUARD_CAPTURE_LEGACY_FIXTURES=1` rewrites the fixture from the current binary instead;
//! that is done once per layout version and reviewed, never to make a failing test pass.
//!
//! The fixture is the v1 compatibility baseline: every later migration of this store must read it.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/legacy/v1/workspace"
);
const MIRROR: &str = ".permguard";
const STORED_MIRROR: &str = "dot-permguard";
const POLICY: &str = r#"@alias("billing-ro")
permit (
    principal in Group::"finance",
    action == Action::"read",
    resource
);
"#;

fn scratch() -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("permguard-legacy-workspace-{}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("the scratch directory is created");
    path
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("the target directory is created");
    for entry in fs::read_dir(from).expect("the source directory is listed") {
        let entry = entry.expect("an entry is read");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("a file type").is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("a file is copied");
        }
    }
}

fn run(workdir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_permguard"))
        .arg("-w")
        .arg(workdir)
        .args(args)
        .env("PERMGUARD_CONFIG", workdir.join("cli-config.yml"))
        .env_remove("PERMGUARD_TLS_CA_FILE")
        .env("NO_COLOR", "1")
        .output()
        .expect("the binary runs")
}

#[test]
fn test_the_v1_workspace_fixture_is_read_by_the_current_binary() {
    let work = scratch();
    let fixture = Path::new(FIXTURE);
    if std::env::var_os("PERMGUARD_CAPTURE_LEGACY_FIXTURES").is_some() {
        let init = run(&work, &["init", "legacy-workspace"]);
        assert!(
            init.status.success(),
            "{}",
            String::from_utf8_lossy(&init.stderr)
        );
        // One policy, and a `status` over it, so that the mirror holds objects as well as `HEAD`.
        fs::write(work.join("cedar").join("billing.cedar"), POLICY).expect("the policy is written");
        let status = run(&work, &["-o", "json", "status"]);
        assert!(
            status.status.success(),
            "{}",
            String::from_utf8_lossy(&status.stderr)
        );
        let _ = fs::remove_dir_all(fixture);
        copy_dir(&work, fixture);
        fs::rename(fixture.join(MIRROR), fixture.join(STORED_MIRROR))
            .expect("the mirror directory is stored under its visible name");
        let _ = fs::remove_file(fixture.join(STORED_MIRROR).join("lock"));
    } else {
        copy_dir(fixture, &work);
        fs::rename(work.join(STORED_MIRROR), work.join(MIRROR))
            .expect("the mirror directory takes its real name back");
    }

    // Listed before `status` runs, which writes objects itself: these are the captured ones.
    let captured = files_under(&work.join(MIRROR).join("objects"));
    assert!(!captured.is_empty(), "the captured mirror holds objects");
    assert!(work.join(MIRROR).join("HEAD").exists());

    let status = run(&work, &["-o", "json", "status"]);
    assert!(
        status.status.success(),
        "status refused the fixture: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&status.stdout).expect("the report is JSON");
    assert_eq!(report["workspace"], "legacy-workspace", "{report}");
    assert_eq!(
        report["languages"],
        serde_json::json!(["cedar"]),
        "{report}"
    );
    assert_eq!(report["ref"], "main", "{report}");
    assert_eq!(report["remote_configured"], false, "{report}");
    assert_eq!(report["sources_valid"], true, "{report}");
    assert_eq!(report["pending_create"], 1, "{report}");
    assert_eq!(
        files_under(&work.join(MIRROR).join("objects")),
        captured,
        "the current binary needs no object the fixture does not already hold"
    );
}

/// Every file below `directory`, as sorted paths relative to it.
fn files_under(directory: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(next) = pending.pop() {
        let Ok(entries) = fs::read_dir(&next) else {
            continue;
        };
        for entry in entries {
            let path = entry.expect("an entry is read").path();
            if path.is_dir() {
                pending.push(path);
            } else {
                found.push(path.strip_prefix(directory).expect("below").to_path_buf());
            }
        }
    }
    found.sort();
    found
}
