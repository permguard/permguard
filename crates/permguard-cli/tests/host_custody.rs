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
