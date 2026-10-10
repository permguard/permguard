// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The offline `host identity` commands open the identity's keys where the server keeps them
//! (WP-3.2, owner decision of 2026-10-08): with `--server-config`, read with the environment as
//! the server reads them, a `file` custody provisions, opens and rotates sealed keys.

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

#[test]
fn the_identity_is_provisioned_opened_and_rotated_sealed_under_the_servers_custody() {
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
    let key = |epoch: u32| {
        std::fs::read(volume.join(format!("host/identity/keys/{epoch}.key"))).expect("held")
    };

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
            volume_arg,
            "--server-config",
            config_arg,
        ],
    ));
    assert_ne!(key(1).first(), Some(&0x30), "never PKCS#8 at rest");

    // Without the server's configuration the sealed key does not open, and the refusal names the
    // option.
    let refused = run(
        &dir,
        KEK,
        &["host", "identity", "show", "--volume", volume_arg],
    );
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("--server-config"),
        "{}",
        stderr(&refused)
    );

    let shown = json(&run(
        &dir,
        KEK,
        &[
            "-o",
            "json",
            "host",
            "identity",
            "show",
            "--volume",
            volume_arg,
            "--server-config",
            config_arg,
        ],
    ));
    assert_eq!(shown["host_id"], provisioned["host_id"]);

    let rotated = json(&run(
        &dir,
        KEK,
        &[
            "-o",
            "json",
            "host",
            "identity",
            "rotate",
            "--volume",
            volume_arg,
            "--expected-epoch",
            "1",
            "--server-config",
            config_arg,
        ],
    ));
    assert_eq!(rotated["epoch"], 2);
    assert_ne!(
        key(2).first(),
        Some(&0x30),
        "the next epoch's key is sealed too"
    );

    // Another KEK under the same version is refused, and nothing is replaced.
    let before = key(2);
    let other = run(
        &dir,
        "fedcba9876543210fedcba9876543210",
        &[
            "host",
            "identity",
            "show",
            "--volume",
            volume_arg,
            "--server-config",
            config_arg,
        ],
    );
    assert!(!other.status.success());
    assert_eq!(key(2), before);

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
    let refused = run(
        &dir,
        KEK,
        &[
            "host",
            "identity",
            "show",
            "--volume",
            plain_arg,
            "--server-config",
            config_arg,
        ],
    );
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("still to be sealed"),
        "{}",
        stderr(&refused)
    );
    assert_eq!(
        std::fs::read(plain.join("host/identity/keys/1.key"))
            .expect("held")
            .first(),
        Some(&0x30),
        "left as it was"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// The offline emergency reset (WP-4.1): planned to a file, run against it, a new identity under
/// the same custody; the plan confirms one state of the volume and no other.
#[test]
fn the_offline_reset_retires_the_identity_and_provisions_another_under_the_same_custody() {
    const KEK: &str = "0123456789abcdef0123456789abcdef";
    let dir = scratch("reset");
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
    let plan = dir.join("reset.plan");
    let plan_arg = plan.to_str().expect("utf-8");
    let host = |args: &[&str]| {
        let mut all = vec!["-o", "json", "host", "identity"];
        all.extend_from_slice(args);
        all.extend_from_slice(&["--volume", volume_arg, "--server-config", config_arg]);
        run(&dir, KEK, &all)
    };

    let provisioned = json(&host(&["provision"]));
    let planned = json(&host(&[
        "reset", "plan", "--reason", "a drill", "--out", plan_arg,
    ]));
    assert_eq!(planned["host_id"], provisioned["host_id"]);
    assert_eq!(planned["mode"], "emergency");
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

    // An edited plan is refused.
    let edited = dir.join("edited.plan");
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&plan).expect("the plan")).expect("JSON");
    value["reason"] = serde_json::json!("another reason");
    std::fs::write(&edited, serde_json::to_vec(&value).expect("JSON")).expect("written");
    let refused = host(&[
        "reset",
        "run",
        "--confirm-file",
        edited.to_str().expect("utf-8"),
    ]);
    assert!(!refused.status.success());
    assert!(stderr(&refused).contains("edited"), "{}", stderr(&refused));

    let reset = json(&host(&["reset", "run", "--confirm-file", plan_arg]));
    assert_eq!(reset["old_host_id"], provisioned["host_id"]);
    assert_ne!(reset["host_id"], provisioned["host_id"]);
    assert_ne!(reset["witness"], provisioned["witness"]);
    let shown = json(&host(&["show"]));
    assert_eq!(shown["host_id"], reset["host_id"]);
    assert_eq!(shown["epoch"], 1);
    let key = std::fs::read(volume.join("host/identity/keys/1.key")).expect("the new key");
    assert_ne!(key.first(), Some(&0x30), "the new key is sealed too");
    let retired = volume.join(format!(
        "host/identity/retired/{}",
        provisioned["host_id"].as_str().expect("a host id")
    ));
    for kept in ["INIT", "identity.cose", "RESET", "keys-1.pub"] {
        assert!(retired.join(kept).is_file(), "{kept}");
    }

    // The plan named the identity that is gone: it confirms nothing now.
    let stale = host(&["reset", "run", "--confirm-file", plan_arg]);
    assert!(!stale.status.success());
    assert!(
        stderr(&stale).contains("changed since the plan"),
        "{}",
        stderr(&stale)
    );
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

    let refused = host(&["show"]);
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("reset run"),
        "{}",
        stderr(&refused)
    );
    // No plan is needed to complete it.
    let resumed = json(&host(&["reset", "run"]));
    assert_eq!(resumed["old_host_id"], old.as_str());
    assert_ne!(resumed["host_id"], old.as_str());
    let shown = json(&host(&["show"]));
    assert_eq!(shown["host_id"], resumed["host_id"]);
    assert!(!identity.join("RESETTING").exists(), "the marker is gone");
    // And with nothing under way, a run without a plan is a usage error.
    assert!(!host(&["reset", "run"]).status.success());
}
