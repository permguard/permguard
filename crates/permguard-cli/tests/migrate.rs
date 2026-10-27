// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `permguard migrate plan|run|status|rollback` (TC-3): a subsystem's layout migration of a
//! stopped server's volume, planned with the backup taken before it, run from the plan's receipt
//! once, through the server binary's own migration, into a new generation it never builds over
//! anything that exists.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const KEK: &str = "0123456789abcdef0123456789abcdef";
/// The backups' recovery key (TS-5).
const RECOVERY_KEY: &[u8] = b"the right recovery key";

const LEGACY_TRAIL: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../permguard-std/tests/fixtures/legacy/v1/audit/trail"
);

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "permguard-cli-migrate-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory is created");
    dir
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn json(output: &Output) -> serde_json::Value {
    assert!(output.status.success(), "{}", stderr(output));
    serde_json::from_slice(&output.stdout).expect("the JSON output parses")
}

/// Runs `claim` until the volume's lock is not reported held, for at most five seconds.
///
/// A child process another test thread spawns holds a copy of every descriptor of this process
/// between its fork and its exec — the volume's `LOCK` among them, close-on-exec or not — so a lock
/// this thread has just released can read as held by another process for that instant. Waited
/// out, and bounded: a lock really held elsewhere is still refused.
fn waiting_out_a_spawn<T>(
    mut claim: impl FnMut() -> Result<T, permguard_host::storage::StorageError>,
) -> Result<T, permguard_host::storage::StorageError> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match claim() {
            Err(permguard_host::storage::StorageError::Held(_))
                if std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            claimed => return claimed,
        }
    }
}

/// A provisioned volume under a `file` custody, its rings given their first keys, and the legacy
/// audit chain of a version-1 server where the server kept it.
struct Volume {
    dir: PathBuf,
    volume: PathBuf,
    config: PathBuf,
}

impl Volume {
    fn new(name: &str, assurance: &str) -> Self {
        let dir = scratch(name);
        let volume = dir.join("volume");
        let secrets = dir.join("secrets");
        std::fs::create_dir_all(&secrets).expect("the secrets directory");
        std::fs::write(secrets.join("host-kek"), KEK).expect("the key-encryption key");
        // From `production` every restore resolves the backups' recovery key (TS-5).
        std::fs::write(secrets.join("recovery"), RECOVERY_KEY).expect("the recovery key");
        let config = dir.join("server.yml");
        std::fs::write(
            &config,
            format!(
                "public:\n  http: 0.0.0.0:5556\n{assurance}operations:\n  secrets:\n    \
                 provider: directory\n    directory: {}\n  keys:\n    custody: file\n    \
                 kek_ref: host-kek\n  backup:\n    recovery_key: recovery\n",
                secrets.display()
            ),
        )
        .expect("the configuration writes");
        let held = Self {
            dir,
            volume,
            config,
        };
        json(&held.run(&["host", "identity", "provision"]));
        held.first_start();
        let legacy = held.legacy();
        std::fs::create_dir_all(&legacy).expect("the legacy directory");
        for entry in std::fs::read_dir(LEGACY_TRAIL).expect("the fixture") {
            let entry = entry.expect("an entry");
            std::fs::copy(entry.path(), legacy.join(entry.file_name())).expect("copied");
        }
        held
    }

    fn legacy(&self) -> PathBuf {
        self.volume.join("operations/audit")
    }

    fn migrated(&self) -> PathBuf {
        self.volume.join("host/audit/legacy")
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_permguard"))
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
            .output()
            .expect("the binary runs")
    }

    fn plan(&self, out: &Path) -> Output {
        self.run(&[
            "migrate",
            "plan",
            "--subsystem",
            "audit",
            "--backup",
            "snap-2026-10-25",
            "--out",
            out.to_str().expect("utf-8"),
        ])
    }

    fn migrate(&self, plan: &Path) -> Output {
        self.run(&[
            "migrate",
            "run",
            "--confirm-file",
            plan.to_str().expect("utf-8"),
        ])
    }

    fn status(&self) -> Vec<String> {
        json(&self.run(&["migrate", "status"]))["lines"]
            .as_array()
            .expect("lines")
            .iter()
            .map(|line| line.as_str().expect("a line").to_owned())
            .collect()
    }

    /// What the server's first start does to every ring: its first key signs at once.
    fn first_start(&self) {
        use permguard_server::offline;
        let config =
            offline::config(env!("CARGO_PKG_VERSION"), Some(&self.config)).expect("the config");
        let held = waiting_out_a_spawn(|| {
            permguard_host::storage::volume::Volume::claim(
                &self.volume,
                permguard_core::assurance::AssuranceProfile::Development,
            )
        })
        .expect("the volume");
        let custodian = offline::custodian(&config, &held).expect("the custody");
        let host_id = permguard_host::identity::host_id_of(&held)
            .expect("read")
            .expect("provisioned");
        let time = std::sync::Arc::new(permguard_host::time::TimeGuard::system(
            config.time_max_clock_skew(),
        ));
        for ring in offline::rings(&config, &held, host_id, None, &custodian, time).expect("rings")
        {
            ring.maintain_now().expect("maintained");
        }
    }

    fn files(directory: &Path) -> Vec<(String, Vec<u8>)> {
        let mut files: Vec<(String, Vec<u8>)> = std::fs::read_dir(directory)
            .expect("listed")
            .map(|entry| {
                let entry = entry.expect("an entry");
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    std::fs::read(entry.path()).expect("read"),
                )
            })
            .collect();
        files.sort();
        files
    }
}

impl Drop for Volume {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// TC-3: the legacy audit chain is migrated from a plan: the plan's receipt is a new owner-only
/// file, the run carries every day byte for byte into the new generation and spends the plan,
/// the status names the subsystem at version 2, and the rollback returns it to version 1.
#[test]
fn a_planned_migration_runs_once_and_rolls_back() {
    let volume = Volume::new("audit", "");
    let before = Volume::files(&volume.legacy());
    let plan = volume.dir.join("migrate.plan");
    let planned = json(&volume.plan(&plan));
    assert_eq!(planned["subsystem"], "audit");
    assert_eq!(planned["backup"], "snap-2026-10-25");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&plan)
            .expect("written")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // A plan file is never overwritten.
    let again = volume.plan(&plan);
    assert_eq!(again.status.code(), Some(64), "{}", stderr(&again));

    let ran = json(&volume.migrate(&plan));
    assert_eq!(ran["subsystem"], "audit");
    assert_eq!(ran["plan_id"], planned["plan_id"]);
    assert_eq!(
        Volume::files(&volume.migrated()),
        before,
        "every day carried byte for byte"
    );
    let status = volume.status();
    assert!(
        status
            .iter()
            .any(|line| line.starts_with("audit-legacy: version 2")),
        "{status:?}"
    );
    // The receipt is spent.
    let spent = volume.migrate(&plan);
    assert_eq!(spent.status.code(), Some(64), "{}", stderr(&spent));

    let rolled = json(&volume.run(&["migrate", "rollback", "--subsystem", "audit-legacy"]));
    assert_eq!(rolled["subsystem"], "audit-legacy");
    let status = volume.status();
    assert!(
        status
            .iter()
            .any(|line| line.starts_with("audit-legacy: version 1")),
        "{status:?}"
    );
}

/// TC-3, a full migration targets a virgin generation: a run whose new generation's directory
/// exists builds nothing over it, and the chain stays where it was, whole.
#[test]
fn a_migration_never_builds_over_what_exists() {
    let volume = Volume::new("occupied", "");
    let before = Volume::files(&volume.legacy());
    let plan = volume.dir.join("migrate.plan");
    json(&volume.plan(&plan));
    std::fs::create_dir_all(volume.migrated()).expect("occupied");
    std::fs::write(volume.migrated().join("KEEP"), b"already here").expect("written");
    let refused = volume.migrate(&plan);
    assert_eq!(refused.status.code(), Some(69), "{}", stderr(&refused));
    // The plan is spent, and the refusal says so: a run again is refused, the cause fixed and
    // planned again. The layout is declared at version 1 before the framework refuses the build;
    // nothing else of the volume changes.
    assert!(
        stderr(&refused).contains("is spent"),
        "{}",
        stderr(&refused)
    );
    assert_eq!(
        Volume::files(&volume.migrated()),
        vec![("KEEP".to_owned(), b"already here".to_vec())],
        "nothing built over it"
    );
    assert_eq!(
        Volume::files(&volume.legacy()),
        before,
        "the chain untouched"
    );
}

/// TC-3: a receipt is bound to its volume's claim and to a migration: a raised claim, or a
/// restore's receipt, is refused before anything changes.
#[test]
fn a_receipt_of_another_claim_or_operation_is_refused() {
    let volume = Volume::new("bound", "");
    let plan = volume.dir.join("migrate.plan");
    json(&volume.plan(&plan));
    waiting_out_a_spawn(|| permguard_host::storage::volume::set_claim(&volume.volume, 9))
        .expect("claimed");
    let refused = volume.migrate(&plan);
    assert_eq!(refused.status.code(), Some(64), "{}", stderr(&refused));
    assert!(
        stderr(&refused).contains("claim generation"),
        "{}",
        stderr(&refused)
    );

    // A restore proves a fence above every claim recorded, the refused run's included.
    waiting_out_a_spawn(|| permguard_host::storage::volume::set_claim(&volume.volume, 10))
        .expect("claimed");
    let restore = volume.dir.join("restore.plan");
    json(&volume.run(&[
        "restore",
        "plan",
        "--mode",
        "dr",
        "--reason",
        "a drill",
        "--out",
        restore.to_str().expect("utf-8"),
    ]));
    let refused = volume.migrate(&restore);
    assert_eq!(refused.status.code(), Some(64), "{}", stderr(&refused));
    assert!(
        !volume.migrated().exists(),
        "nothing was migrated: {}",
        stderr(&refused)
    );
}

/// TC-3: under dual control a migration plan needs an approval no offline volume can collect:
/// refused, nothing written.
#[test]
fn under_dual_control_a_migration_is_refused() {
    let volume = Volume::new(
        "dual",
        "assurance:\n  added_controls: [operations.dual_control]\n",
    );
    let plan = volume.dir.join("migrate.plan");
    let refused = volume.plan(&plan);
    assert_eq!(refused.status.code(), Some(64), "{}", stderr(&refused));
    assert!(
        stderr(&refused).contains("dual control"),
        "{}",
        stderr(&refused)
    );
    assert!(!plan.exists());
}

/// TC-3, after the review: a `--legacy` the migration would refuse is refused before any plan is
/// signed, so no plan is spent on it.
#[test]
fn a_legacy_location_the_migration_refuses_is_refused_at_plan() {
    let volume = Volume::new("legacy", "");
    let plan = volume.dir.join("migrate.plan");
    for args in [
        vec!["--subsystem", "audit", "--legacy", "a", "--legacy", "b"],
        vec!["--subsystem", "events", "--legacy", "a"],
        vec!["--subsystem", "keys", "--legacy", "contorl.attest=/dir"],
        vec!["--subsystem", "keys", "--legacy", "no-equals"],
        vec![
            "--subsystem",
            "keys",
            "--legacy",
            "data.attest=/a",
            "--legacy",
            "data.attest=/b",
        ],
    ] {
        let mut all = vec!["migrate", "plan", "--backup", "snap-1"];
        all.extend(args.iter().copied());
        all.extend(["--out", plan.to_str().expect("utf-8")]);
        let refused = volume.run(&all);
        assert_eq!(
            refused.status.code(),
            Some(64),
            "{args:?}: {}",
            stderr(&refused)
        );
        assert!(!plan.exists(), "{args:?}");
    }
}

/// TC-3, after the review: a volume restored for forensics is never written: no migration is
/// planned on it, and none is rolled back.
#[test]
fn a_forensic_volume_is_never_migrated() {
    let volume = Volume::new("forensic", "");
    waiting_out_a_spawn(|| permguard_host::storage::volume::set_claim(&volume.volume, 9))
        .expect("claimed");
    let restore = volume.dir.join("restore.plan");
    json(&volume.run(&[
        "restore",
        "plan",
        "--mode",
        "forensic",
        "--reason",
        "an inquiry",
        "--out",
        restore.to_str().expect("utf-8"),
    ]));
    json(&volume.run(&[
        "restore",
        "run",
        "--mode",
        "forensic",
        "--confirm-file",
        restore.to_str().expect("utf-8"),
    ]));
    let plan = volume.dir.join("migrate.plan");
    let refused = volume.plan(&plan);
    assert_eq!(refused.status.code(), Some(64), "{}", stderr(&refused));
    assert!(!plan.exists());
    let refused = volume.run(&["migrate", "rollback", "--subsystem", "audit-legacy"]);
    assert_eq!(refused.status.code(), Some(64), "{}", stderr(&refused));
    // A read still works.
    volume.status();
}
