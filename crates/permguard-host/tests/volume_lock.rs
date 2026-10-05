// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Two processes on one mount: the second fails on `host/LOCK` while the first holds the volume,
//! and claims it once the first is gone (WP-1.4).

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use permguard_core::assurance::AssuranceProfile;
use permguard_host::storage::StorageError;
use permguard_host::storage::volume::{self, Volume};

const ROOT: &str = "PERMGUARD_VOLUME_ROOT";
/// The file the holder writes once it holds the volume.
const HELD: &str = "held";
/// The file the parent writes to let the holder go.
const RELEASE: &str = "release";

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-host-volume-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("a scratch directory");
    path
}

fn wait_for(path: &Path) {
    let started = Instant::now();
    while !path.exists() {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "{} never appeared",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[ignore = "started by its parent"]
fn child_holds_the_volume() {
    let root = PathBuf::from(std::env::var(ROOT).expect("the parent names the root"));
    let held = Volume::claim(&root.join("volume"), AssuranceProfile::Development).expect("claims");
    std::fs::write(root.join(HELD), held.id_hex()).expect("says so");
    wait_for(&root.join(RELEASE));
}

#[test]
fn a_second_process_on_the_same_mount_fails_on_the_lock() {
    let root = scratch("two-processes");
    let mut holder = Command::new(std::env::current_exe().expect("this binary names itself"))
        .args([
            "--ignored",
            "--exact",
            "child_holds_the_volume",
            "--nocapture",
        ])
        .env(ROOT, &root)
        .stdout(Stdio::null())
        // The holder's own failure, should it fail, is what explains a parent waiting in vain.
        .stderr(Stdio::inherit())
        .spawn()
        .expect("the holder starts");
    wait_for(&root.join(HELD));

    let volume_root = root.join("volume");
    let refused = Volume::claim(&volume_root, AssuranceProfile::Development)
        .expect_err("the other process holds it");
    assert!(matches!(refused, StorageError::Held(_)), "{refused}");
    let refused = volume::set_claim(&volume_root, 1).expect_err("nor can the claim move");
    assert!(matches!(refused, StorageError::Held(_)), "{refused}");

    std::fs::write(root.join(RELEASE), b"").expect("released");
    assert!(holder.wait().expect("the holder exits").success());

    let claimed = Volume::claim(&volume_root, AssuranceProfile::Development)
        .expect("free once the holder is gone");
    assert_eq!(
        claimed.id_hex(),
        std::fs::read_to_string(root.join(HELD)).expect("the holder's view"),
        "one volume, one identity"
    );
}
