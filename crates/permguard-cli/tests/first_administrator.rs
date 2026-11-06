// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The first administrator offline, and recovery (WP-8.2): a bootstrap makes the first one and
//! runs again for it changing nothing, refuses a second one, and `host recovery start` makes a
//! setup code instead, private to the volume's owner, never printed.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const KEK: &str = "0123456789abcdef0123456789abcdef";

struct Volume {
    dir: PathBuf,
    volume: PathBuf,
    config: PathBuf,
}

impl Volume {
    fn provisioned(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "permguard-cli-first-admin-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let secrets = dir.join("secrets");
        std::fs::create_dir_all(&secrets).expect("the secrets directory");
        std::fs::write(secrets.join("host-kek"), KEK).expect("the key-encryption key");
        let config = dir.join("server.yml");
        std::fs::write(
            &config,
            format!(
                "public:\n  http: 0.0.0.0:5556\nassurance:\n  profile: development\noperations:\n  \
                 secrets:\n    provider: directory\n    directory: {}\n  keys:\n    custody: file\n    \
                 kek_ref: host-kek\n",
                secrets.display()
            ),
        )
        .expect("the configuration writes");
        let volume = Self {
            volume: dir.join("volume"),
            dir,
            config,
        };
        let provisioned = volume.run(&["host", "identity", "provision"], None);
        assert!(provisioned.status.success(), "{}", stderr(&provisioned));
        volume
    }

    fn run(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_permguard"))
            .arg("-w")
            .arg(&self.dir)
            .arg("-o")
            .arg("json")
            .args(args)
            .arg("--volume")
            .arg(&self.volume)
            .arg("--server-config")
            .arg(&self.config)
            .env("PERMGUARD_CONFIG", self.dir.join("cli-config.yml"))
            .env("NO_COLOR", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the binary runs");
        if let Some(text) = stdin {
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(text.as_bytes())
                .expect("written");
        } else {
            drop(child.stdin.take());
        }
        child.wait_with_output().expect("it ends")
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn json(output: &Output) -> serde_json::Value {
    assert!(output.status.success(), "{}", stderr(output));
    serde_json::from_slice(&output.stdout).expect("the JSON output parses")
}

#[test]
fn a_bootstrap_makes_only_the_first_administrator_and_recovery_makes_a_code() {
    let volume = Volume::provisioned("bootstrap");

    let first = json(&volume.run(
        &[
            "host",
            "users",
            "bootstrap",
            "--name",
            "alice",
            "--password-stdin",
        ],
        Some("alice's first password"),
    ));
    assert_eq!(first["principal"], "user:alice");
    assert!(first["grant"].is_string(), "{first}");

    // Again for the same administrator: nothing changes.
    let again = json(&volume.run(
        &[
            "host",
            "users",
            "bootstrap",
            "--name",
            "alice",
            "--email",
            "alice@acme.example",
        ],
        None,
    ));
    assert_eq!(again["already_administrator"], true, "{again}");

    // A second administrator is not a bootstrap.
    for refused in [
        volume.run(
            &[
                "host",
                "users",
                "bootstrap",
                "--name",
                "mallory",
                "--email",
                "m@evil.example",
            ],
            None,
        ),
        volume.run(
            &[
                "host",
                "grants",
                "bootstrap",
                "--fingerprint",
                &"ab".repeat(32),
            ],
            None,
        ),
    ] {
        assert!(!refused.status.success(), "a second administrator was made");
        assert!(
            stderr(&refused).contains("host recovery start"),
            "{}",
            stderr(&refused)
        );
    }

    // Recovery: a reason, then a code in a private file, never in the output.
    let unexplained = volume.run(&["host", "recovery", "start", "--reason", " "], None);
    assert!(!unexplained.status.success());
    let started = volume.run(
        &[
            "host",
            "recovery",
            "start",
            "--reason",
            "every administrator left",
            "--expires",
            "2h",
        ],
        None,
    );
    let report = json(&started);
    let code_file = PathBuf::from(report["code_file"].as_str().expect("the code's file"));
    let code = std::fs::read_to_string(&code_file)
        .expect("the code")
        .trim()
        .to_owned();
    assert!(code.starts_with("pgsetup_"), "{code}");
    assert!(
        !String::from_utf8_lossy(&started.stdout).contains(&code)
            && !stderr(&started).contains(&code),
        "never printed"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&code_file)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "private to the volume's owner");
    }
    let recovery = volume
        .volume
        .join("host")
        .join("setup")
        .join("recovery.json");
    assert!(
        std::fs::read_to_string(recovery)
            .expect("the recovery record")
            .contains("every administrator left")
    );
}
