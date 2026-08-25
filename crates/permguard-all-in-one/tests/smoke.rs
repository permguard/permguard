// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The composition root, run as the binary it ships as. Nothing here starts
//! a server: `--help` and a bad invocation both exercise the entry path —
//! identity, argument parsing, the composed plane set — and exit.

#![allow(clippy::expect_used)]

use std::process::Command;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_permguard-all-in-one"))
}

#[test]
fn help_names_the_product_and_exits_cleanly() {
    let output = binary().arg("--help").output().expect("the binary runs");

    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("permguard"), "{text}");
}

#[test]
fn version_reports_the_workspace_version() {
    let output = binary().arg("--version").output().expect("the binary runs");

    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains(env!("CARGO_PKG_VERSION")), "{text}");
}

#[test]
fn a_missing_configuration_file_is_a_clean_refusal_not_a_panic() {
    let output = binary()
        .arg("/nonexistent/permguard-config.yml")
        .output()
        .expect("the binary runs");

    assert!(!output.status.success());
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(!text.contains("panicked"), "{text}");
}

#[test]
fn the_composed_runtime_starts_serves_and_stops() {
    use std::io::Read as _;

    let dir =
        std::env::temp_dir().join(format!("permguard-all-in-one-smoke-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory is created");

    // Ephemeral ports everywhere: the test owns no number and collides with nobody.
    std::fs::write(
        dir.join("config.yml"),
        concat!(
            "development_mode: true\nautogenerate: true\n",
            "log:\n  level: info\n  format: json\n",
            "telemetry:\n  addr: 127.0.0.1:0\n",
            "controlPlane:\n  public:\n    http: 127.0.0.1:0\n",
            "dataPlane:\n  public:\n    http: 127.0.0.1:0\n",
        ),
    )
    .expect("the config writes");

    let mut child = binary()
        .arg(dir.join("config.yml"))
        .env("PERMGUARD_WORKING_DIR", &dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the runtime starts");

    // The runtime says it started; that record is the assertion.
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let mut seen = String::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut buffer = [0u8; 4096];
    while std::time::Instant::now() < deadline && !seen.contains("server.started") {
        match stdout.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => seen.push_str(&String::from_utf8_lossy(&buffer[..read])),
            Err(_) => break,
        }
    }

    let _ = child.kill();
    let _ = child.wait();

    assert!(seen.contains("server.started"), "{seen}");
    assert!(
        seen.contains("control-plane") && seen.contains("data-plane"),
        "both planes compose: {seen}"
    );
}

#[test]
fn the_underscore_alias_binary_is_the_same_program() {
    // The Go-compatible name ships too; it must answer exactly like the canonical one.
    let output = Command::new(env!("CARGO_BIN_EXE_permguard_all_in_one"))
        .arg("--version")
        .output()
        .expect("the alias binary runs");

    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(env!("CARGO_PKG_VERSION")),
        "{output:?}"
    );
}
