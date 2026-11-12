// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The administrator's key offline: when every key of `admin` is lost, `authority admin-key` makes
//! a new one on the stopped server's volume, its secret written to a new file only its owner reads
//! and never printed, and leaves the mark the next start records in the audit trail.

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

    /// The command line on this volume, without the server's configuration: what the `authority`
    /// commands take.
    fn run_on_volume(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_permguard"))
            .arg("-w")
            .arg(&self.dir)
            .arg("-o")
            .arg("json")
            .args(args)
            .arg("--volume")
            .arg(&self.volume)
            .env("PERMGUARD_CONFIG", self.dir.join("cli-config.yml"))
            .env("NO_COLOR", "1")
            .output()
            .expect("the binary runs")
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
fn the_offline_admin_key_needs_the_authority_plane_and_never_prints_its_secret() {
    use permguard_authority_plane::{accounts, admin};

    let volume = Volume::provisioned("admin-key");
    let out = volume.dir.join("admin.key");
    let out_text = out.to_str().expect("a UTF-8 path");
    let refused = volume.run_on_volume(&["authority", "admin-key", "--secret-out", out_text]);
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("holds no Authority Plane"),
        "{}",
        stderr(&refused)
    );
    assert!(!out.exists(), "nothing is written for a refusal");

    // The Authority Plane's first start, as the server makes it: `admin` and its first key.
    let plane_dir = volume.volume.join("planes/authority");
    std::fs::create_dir_all(&plane_dir).expect("the plane's directory");
    let first = {
        let dir = permguard_host::storage::Dir::open(&plane_dir).expect("opens");
        let (held, _) =
            accounts::Accounts::open(&dir, permguard_host::storage::journal::Options::default())
                .expect("the accounts open");
        admin::ensure(&held, &plane_dir, permguard_core::time::unix_now())
            .expect("made")
            .expect("the first start makes it")
    };

    let made = volume.run_on_volume(&["authority", "admin-key", "--secret-out", out_text]);
    let printed = String::from_utf8_lossy(&made.stdout).into_owned() + &stderr(&made);
    assert!(!printed.contains("pgsk_"), "never printed: {printed}");
    let answer = json(&made);
    let access_key = answer["access_key"]
        .as_str()
        .expect("the new key")
        .to_owned();
    assert!(
        access_key.starts_with("pgak_") && access_key != first,
        "{answer}"
    );
    let text = std::fs::read_to_string(&out).expect("the key file");
    assert!(
        text.contains(&format!("access_key: {access_key}")),
        "the file names its key"
    );
    assert!(admin::secret_of(&text).is_some(), "and holds its secret");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&out)
            .expect("written")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "the key file is its owner's alone");
    }
    assert_eq!(
        admin::take_offline_mark(&plane_dir).as_deref(),
        Some(access_key.as_str()),
        "the next start records it"
    );
    {
        let dir = permguard_host::storage::Dir::open(&plane_dir).expect("opens");
        let (held, _) =
            accounts::Accounts::open(&dir, permguard_host::storage::journal::Options::default())
                .expect("the accounts open");
        let keys: Vec<String> = held
            .get(accounts::ADMIN)
            .expect("admin")
            .keys
            .into_iter()
            .map(|key| key.access_key)
            .collect();
        assert!(keys.contains(&access_key), "{keys:?}");
    }

    // The file is new or nothing is written: a second run never overwrites a secret.
    let again = volume.run_on_volume(&["authority", "admin-key", "--secret-out", out_text]);
    assert!(!again.status.success(), "{}", stderr(&again));
    assert_eq!(std::fs::read_to_string(&out).expect("kept"), text);
}
