// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A recovery drain run of the composed binary (TD-2): with `shutdown.recover_drain` the server
//! stops as soon as it has started, drains, and prints one JSON line holding its signed drain
//! receipt and verification bundle; the receipt verifies under the identity pin the volume's `INIT`
//! names, and names that volume and its claim. The Host listener is configured: without it a Host
//! composes no Host API, holds no membership and issues no receipt, so no claim of it is reclaimed.

#![cfg(unix)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "permguard-data-plane-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory is created");
    dir
}

#[test]
fn a_recover_drain_run_stops_after_start_and_prints_a_receipt() {
    let dir = scratch("recover-drain");
    let volume = dir.join("volume");
    std::fs::create_dir_all(&volume).expect("the volume directory");
    let config = dir.join("config.yml");
    std::fs::write(
        &config,
        format!(
            "\
working_dir: {}
development_mode: true
autogenerate: true
assurance: {{ profile: development }}
telemetry: {{ addr: 127.0.0.1:0 }}
admin:
  addr: 127.0.0.1:0
  tls: {{ cert: tls/server.pem, key: tls/server.key }}
operations: {{ keys: {{ enabled: \"true\", publish_ahead: 5m, rotate_every: 1h, retain: 1d }} }}
shutdown: {{ recover_drain: \"true\" }}
dataPlane:
  public:
    http: {{ addr: 127.0.0.1:0 }}
    grpc: {{ addr: 127.0.0.1:0 }}
",
            volume.display()
        ),
    )
    .expect("the configuration is written");
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_permguard-data-plane"));
    for (variable, _) in std::env::vars_os() {
        if variable.to_string_lossy().starts_with("PERMGUARD_") {
            command.env_remove(variable);
        }
    }
    let mut child = command
        .arg(&config)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the binary runs");
    // A run that did not stop by itself would serve until stopped: bounded, then failed.
    let started = Instant::now();
    while child.try_wait().expect("waitable").is_none() {
        if started.elapsed() > Duration::from_secs(60) {
            let _ = child.kill();
            panic!("a recovery drain run did not stop after starting");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let output = child.wait_with_output().expect("its output");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stdout}\n{stderr}");

    let line = stdout
        .lines()
        .find(|line| line.starts_with("{\"drain_receipt\""))
        .unwrap_or_else(|| panic!("no receipt line:\n{stdout}\n{stderr}"));
    let printed: serde_json::Value = serde_json::from_str(line).expect("one JSON line");
    let export = &printed["drain_receipt"];
    let receipt = B64
        .decode(export["receipt"].as_str().unwrap())
        .expect("base64url");
    let manifest = B64
        .decode(export["bundle"]["manifest"].as_str().unwrap())
        .expect("base64url");
    let items: Vec<Vec<u8>> = export["bundle"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| B64.decode(item.as_str().unwrap()).expect("base64url"))
        .collect();

    // The pin, read independently from the volume: the fingerprint `INIT` names.
    let held = permguard_host::storage::volume::Volume::claim(
        &volume,
        permguard_core::assurance::AssuranceProfile::Development,
    )
    .expect("the volume is free once the run ended");
    let (identity, _) = permguard_host::identity::directories(&held).expect("the identity");
    let init = identity
        .read("INIT")
        .expect("readable")
        .expect("provisioned");
    let pin = permguard_host::identity::record::Init::decode(&init)
        .expect("an INIT")
        .fingerprint;

    let verified = permguard_host::operations::drain::verify(&receipt, &manifest, &items, &pin)
        .expect("the receipt verifies under the volume's own pin");
    assert_eq!(verified.volume_id, held.id());
    assert_eq!(verified.generation, held.generation());
    assert!(verified.drained_at > 1_700_000_000);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_host_without_its_listener_issues_no_receipt() {
    let dir = scratch("recover-drain-no-listener");
    let volume = dir.join("volume");
    std::fs::create_dir_all(&volume).expect("the volume directory");
    let config = dir.join("config.yml");
    std::fs::write(
        &config,
        format!(
            "\
working_dir: {}
development_mode: true
autogenerate: true
assurance: {{ profile: development }}
telemetry: {{ addr: 127.0.0.1:0 }}
shutdown: {{ recover_drain: \"true\" }}
dataPlane:
  public:
    http: {{ addr: 127.0.0.1:0 }}
    grpc: {{ addr: 127.0.0.1:0 }}
",
            volume.display()
        ),
    )
    .expect("the configuration is written");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_permguard-data-plane"))
        .arg(&config)
        .env_remove("PERMGUARD_LOG_LEVEL")
        .output()
        .expect("the binary runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout
            .lines()
            .any(|line| line.starts_with("{\"drain_receipt\"")),
        "{stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
