// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The offline `host identity` commands open the identity's keys where the server keeps them
//! (WP-3.2, owner decision of 2026-10-08): with `--server-config`, read with the environment as
//! the server reads them, a `file` custody provisions and resets sealed keys. Online identity
//! inspection and rotation refuse an offline volume.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "permguard-cli-custody-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory is created");
    dir
}

fn run(workdir: &Path, kek: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_permguard"))
        .arg("-w")
        .arg(workdir)
        .args(args)
        .env("PERMGUARD_CONFIG", workdir.join("cli-config.yml"))
        .env("KEKCLI_HOST_KEK", kek)
        .env("NO_COLOR", "1")
        .output()
        .expect("the binary runs")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn json(output: &Output) -> serde_json::Value {
    assert!(output.status.success(), "{}", stderr(output));
    serde_json::from_slice(&output.stdout).expect("the JSON output parses")
}

/// A `file` custody whose key-encryption key `kek` is a file of a `directory` secret store, so
/// this process opens the same keys the command does; `assurance` is appended as given.
fn file_custody(dir: &Path, kek: &str, assurance: &str) -> PathBuf {
    let secrets = dir.join("secrets");
    std::fs::create_dir_all(&secrets).expect("the secrets directory");
    std::fs::write(secrets.join("host-kek"), kek).expect("the key-encryption key");
    let config = dir.join("server.yml");
    std::fs::write(
        &config,
        format!(
            "public:\n  http: 0.0.0.0:5556\n{assurance}operations:\n  secrets:\n    provider: \
             directory\n    directory: {}\n  keys:\n    custody: file\n    kek_ref: host-kek\n",
            secrets.display()
        ),
    )
    .expect("the configuration writes");
    config
}

/// What the server's first start does to every ring of `volume`: its first key signs at once.
/// The offline commands never activate a key themselves.
fn first_start(volume: &Path, config: &Path) {
    use permguard_server::offline;
    let config = offline::config(env!("CARGO_PKG_VERSION"), Some(config)).expect("the config");
    let held = permguard_host::storage::volume::Volume::claim(
        volume,
        permguard_core::assurance::AssuranceProfile::Development,
    )
    .expect("the volume");
    let custodian = offline::custodian(&config, &held).expect("the custody");
    let host_id = permguard_host::identity::host_id_of(&held)
        .expect("read")
        .expect("provisioned");
    let time = std::sync::Arc::new(permguard_host::time::TimeGuard::system(
        config.time_max_clock_skew(),
    ));
    for ring in offline::rings(&config, &held, host_id, None, &custodian, time).expect("rings") {
        ring.maintain_now().expect("maintained");
    }
}

#[test]
fn the_identity_is_provisioned_sealed_and_online_operations_refuse_the_volume() {
    const KEK: &str = "0123456789abcdef0123456789abcdef";
    let dir = scratch("file");
    let volume = dir.join("volume");
    let config = dir.join("server.yml");
    std::fs::write(
        &config,
        "public:\n  http: 0.0.0.0:5556\noperations:\n  secrets:\n    provider: environment\n    \
         env_prefix: KEKCLI\n  keys:\n    custody: file\n    kek_ref: host-kek\n",
    )
    .expect("the configuration writes");
    let volume_arg = volume.to_str().expect("utf-8");
    let config_arg = config.to_str().expect("utf-8");
    let key = || std::fs::read(volume.join("host/identity/keys/1.key")).expect("held");

    let _provisioned = json(&run(
        &dir,
        KEK,
        &[
            "-o",
            "json",
            "host",
            "identity",
            "provision",
            "--volume",
            volume_arg,
            "--server-config",
            config_arg,
        ],
    ));
    assert_ne!(key().first(), Some(&0x30), "never PKCS#8 at rest");

    for online in [vec!["show"], vec!["rotate", "--expected-epoch", "1"]] {
        let mut args = vec!["host", "identity"];
        args.extend(online);
        args.extend(["--volume", volume_arg]);
        let refused = run(&dir, KEK, &args);
        assert!(!refused.status.success());
        assert!(
            stderr(&refused).contains("Host listener"),
            "{}",
            stderr(&refused)
        );
    }

    // A volume provisioned without the server's configuration holds a plaintext key: offline, the
    // server's `file` custody refuses to seal it, which is the start's to do and record.
    let plain = dir.join("plain");
    let plain_arg = plain.to_str().expect("utf-8");
    let provisioned = json(&run(
        &dir,
        KEK,
        &[
            "-o",
            "json",
            "host",
            "identity",
            "provision",
            "--volume",
            plain_arg,
        ],
    ));
    assert_eq!(provisioned["custody"], "development");
    assert_eq!(
        std::fs::read(plain.join("host/identity/keys/1.key"))
            .expect("held")
            .first(),
        Some(&0x30),
        "left as it was"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// The offline emergency reset (WP-4.1, WP-3.9): its COSE plan receipt written to a file only its
/// owner reads, run against it once, a new identity under the same custody; the receipt confirms
/// one state of the volume and no other.
#[test]
fn the_offline_reset_writes_a_receipt_readable_by_its_owner_only_and_runs_it() {
    const KEK: &str = "0123456789abcdef0123456789abcdef";
    let dir = scratch("reset");
    let volume = dir.join("volume");
    let config = file_custody(&dir, KEK, "");
    let volume_arg = volume.to_str().expect("utf-8");
    let config_arg = config.to_str().expect("utf-8");
    let plan = dir.join("reset.plan");
    let plan_arg = plan.to_str().expect("utf-8");
    let host = |args: &[&str]| {
        let mut all = vec!["-o", "json", "host", "identity"];
        all.extend_from_slice(args);
        all.extend_from_slice(&["--volume", volume_arg, "--server-config", config_arg]);
        run(&dir, KEK, &all)
    };

    let provisioned = json(&host(&["provision"]));
    // `host.operations` signs the receipt, and has no key before the server's first start.
    let early = host(&["reset", "plan", "--reason", "a drill", "--out", plan_arg]);
    assert!(!early.status.success());
    assert!(
        stderr(&early).contains("start the server once"),
        "{}",
        stderr(&early)
    );
    assert!(!plan.exists(), "nothing written");
    first_start(&volume, &config);
    let planned = json(&host(&[
        "reset", "plan", "--reason", "a drill", "--out", plan_arg,
    ]));
    assert_eq!(planned["host_id"], provisioned["host_id"]);
    assert_eq!(planned["mode"], "emergency");
    assert_eq!(planned["approvals_required"], 0);
    assert!(
        planned["plan_digest"]
            .as_str()
            .expect("a digest")
            .starts_with("sha256:")
    );
    // The file is the COSE_Sign1 receipt itself: an array of four.
    let receipt = std::fs::read(&plan).expect("the receipt");
    assert_eq!(receipt.first(), Some(&0x84), "a COSE_Sign1");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&plan)
            .expect("written")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the plan is its owner's alone");
    }
    // A second plan does not overwrite the first.
    assert!(
        !host(&["reset", "plan", "--reason", "again", "--out", plan_arg])
            .status
            .success()
    );

    // An edited receipt is refused: it is not the one the plan step wrote.
    let edited = dir.join("edited.plan");
    let mut altered = receipt.clone();
    let last = altered.len() - 1;
    altered[last] ^= 0x01;
    std::fs::write(&edited, &altered).expect("written");
    let refused = host(&[
        "reset",
        "run",
        "--confirm-file",
        edited.to_str().expect("utf-8"),
    ]);
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("not the one the plan step answered"),
        "{}",
        stderr(&refused)
    );

    let sealed = checkpoint_files(&volume);
    let reset = json(&host(&["reset", "run", "--confirm-file", plan_arg]));
    assert_eq!(reset["old_host_id"], provisioned["host_id"]);
    // The trails were checkpointed under the operations ring before it retired (WP-4.9).
    assert!(
        checkpoint_files(&volume) > sealed,
        "the reset sealed its evidence"
    );
    assert_ne!(reset["host_id"], provisioned["host_id"]);
    assert_ne!(reset["witness"], provisioned["witness"]);
    let key = std::fs::read(volume.join("host/identity/keys/1.key")).expect("the new key");
    assert_ne!(key.first(), Some(&0x30), "the new key is sealed too");
    let retired = volume.join(format!(
        "host/identity/retired/{}",
        provisioned["host_id"].as_str().expect("a host id")
    ));
    for kept in ["INIT", "identity.cose", "RESET", "keys-1.pub"] {
        assert!(retired.join(kept).is_file(), "{kept}");
    }

    // The receipt was spent by the run: it confirms nothing now.
    let stale = host(&["reset", "run", "--confirm-file", plan_arg]);
    assert!(!stale.status.success());
    assert!(stderr(&stale).contains("already run"), "{}", stderr(&stale));
}

/// How many checkpoint files the audit trails of `volume` hold.
fn checkpoint_files(volume: &std::path::Path) -> usize {
    fn walk(dir: &std::path::Path, under_checkpoints: bool) -> usize {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return 0;
        };
        entries
            .flatten()
            .map(|entry| {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, entry.file_name() == "checkpoints")
                } else {
                    usize::from(under_checkpoints)
                }
            })
            .sum()
    }
    walk(&volume.join("host/audit/trails"), false)
}

/// Under `operations.dual_control` the offline reset's receipt requires an approval the Host API
/// records (WP-3.9): without it the run is refused and the receipt stays unspent.
#[test]
fn under_dual_control_the_offline_reset_is_refused_until_approved() {
    const KEK: &str = "0123456789abcdef0123456789abcdef";
    let dir = scratch("reset-dual");
    let volume = dir.join("volume");
    let config = file_custody(
        &dir,
        KEK,
        "assurance:\n  added_controls: [operations.dual_control]\n",
    );
    let volume_arg = volume.to_str().expect("utf-8");
    let config_arg = config.to_str().expect("utf-8");
    let plan = dir.join("reset.plan");
    let plan_arg = plan.to_str().expect("utf-8");
    let host = |args: &[&str]| {
        let mut all = vec!["-o", "json", "host", "identity"];
        all.extend_from_slice(args);
        all.extend_from_slice(&["--volume", volume_arg, "--server-config", config_arg]);
        run(&dir, KEK, &all)
    };

    let provisioned = json(&host(&["provision"]));
    first_start(&volume, &config);
    let planned = json(&host(&[
        "reset", "plan", "--reason", "a drill", "--out", plan_arg,
    ]));
    assert_eq!(planned["approvals_required"], 1);
    for _ in 0..2 {
        let refused = host(&["reset", "run", "--confirm-file", plan_arg]);
        assert!(!refused.status.success());
        assert!(
            stderr(&refused).contains("requires 1 approval(s) and holds 0"),
            "{}",
            stderr(&refused)
        );
    }
    let held = permguard_host::storage::volume::Volume::claim(
        &volume,
        permguard_core::assurance::AssuranceProfile::Development,
    )
    .expect("the volume reopens");
    assert_eq!(
        permguard_host::identity::record::uuid_text(
            &permguard_host::identity::host_id_of(&held)
                .expect("the identity reads")
                .expect("the identity exists"),
        ),
        provisioned["host_id"].as_str().expect("a host id"),
        "nothing was reset"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// A reset a crash interrupted after its marker (WP-4.1): the identity refuses to open, and
/// `reset run`, with no plan, completes it.
#[test]
fn an_interrupted_reset_is_completed_by_reset_run_without_a_plan() {
    const KEK: &str = "0123456789abcdef0123456789abcdef";
    let dir = scratch("resume");
    let volume = dir.join("volume");
    let config = dir.join("server.yml");
    std::fs::write(
        &config,
        "public:\n  http: 0.0.0.0:5556\noperations:\n  secrets:\n    provider: environment\n    \
         env_prefix: KEKCLI\n  keys:\n    custody: file\n    kek_ref: host-kek\n",
    )
    .expect("the configuration writes");
    let volume_arg = volume.to_str().expect("utf-8");
    let config_arg = config.to_str().expect("utf-8");
    let host = |args: &[&str]| {
        let mut all = vec!["-o", "json", "host", "identity"];
        all.extend_from_slice(args);
        all.extend_from_slice(&["--volume", volume_arg, "--server-config", config_arg]);
        run(&dir, KEK, &all)
    };
    let provisioned = json(&host(&["provision"]));
    let old = provisioned["host_id"]
        .as_str()
        .expect("a host id")
        .to_owned();

    // What a reset leaves when it stops after its marker: the evidence kept, the marker written.
    let identity = volume.join("host/identity");
    let retired = identity.join(format!("retired/{old}"));
    std::fs::create_dir_all(&retired).expect("created");
    std::fs::copy(identity.join("INIT"), retired.join("INIT")).expect("kept");
    std::fs::write(retired.join("RESET"), [0xA0]).expect("recorded");
    let raw: Vec<u8> = (0..16)
        .map(|at| {
            let hex = old.replace('-', "");
            u8::from_str_radix(&hex[at * 2..at * 2 + 2], 16).expect("hex")
        })
        .collect();
    std::fs::write(identity.join("RESETTING"), raw).expect("marked");

    // No plan is needed to complete it.
    let resumed = json(&host(&["reset", "run"]));
    assert_eq!(resumed["old_host_id"], old.as_str());
    assert_ne!(resumed["host_id"], old.as_str());
    let held = permguard_host::storage::volume::Volume::claim(
        &volume,
        permguard_core::assurance::AssuranceProfile::Development,
    )
    .expect("the volume reopens");
    assert_eq!(
        permguard_host::identity::record::uuid_text(
            &permguard_host::identity::host_id_of(&held)
                .expect("the identity reads")
                .expect("the identity exists"),
        ),
        resumed["host_id"].as_str().expect("a host id")
    );
    assert!(!identity.join("RESETTING").exists(), "the marker is gone");
    // And with nothing under way, a run without a plan is a usage error.
    assert!(!host(&["reset", "run"]).status.success());
}
