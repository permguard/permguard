// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A policy mirror as this release writes it, kept so that every later layout can prove it still
//! reads one.
//!
//! `tests/fixtures/legacy/v1/mirrors` is a mirrors root written by the current code: one
//! `<zone>/<ledger>` directory with its `FORMAT` pin, one content-addressed object and the
//! `refs/main` checkpoint. In CI the fixture is copied aside and read by the current layout and
//! client code, which must list the mirror and read its checkpoint. Setting
//! `PERMGUARD_CAPTURE_LEGACY_FIXTURES=1` rewrites the fixture from the current code instead; that
//! is done once per layout version and reviewed, never to make a failing test pass.
//!
//! The fixture is the v1 compatibility baseline: every later migration of this store must read it.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};

use permguard_control_client::checkpoint::{self, Checkpoint};
use permguard_control_client::objects;
use permguard_control_client::store::FsStore;
use permguard_core::domains;
use permguard_data_plane::mirrors::layout::{Mirror, on_disk};
use permguard_objects::object::Blob;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/legacy/v1/mirrors"
);

fn scratch() -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("permguard-legacy-mirrors-{}", std::process::id()));
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

fn mirror() -> Mirror {
    Mirror {
        zone_id: "zone-a".to_owned(),
        ledger_id: "ledger-a".to_owned(),
    }
}

fn blob() -> Vec<u8> {
    Blob {
        media_type: domains::media::POLICY_CEDAR.to_owned(),
        data: b"forbid(principal, action, resource);\n".to_vec(),
    }
    .encode()
    .expect("the blob encodes")
}

fn build(root: &Path) {
    let directory = mirror().path(root);
    fs::create_dir_all(&directory).expect("the mirror directory is created");
    fs::write(directory.join("FORMAT"), b"1\n").expect("the pin is written");
    let store = FsStore::new(&directory);
    let digest = objects::put(&store, "objects", &blob()).expect("the object lands");
    checkpoint::write(
        &store,
        "refs/main",
        &Checkpoint {
            head: digest.to_string(),
            counter: 1,
        },
    )
    .expect("the checkpoint is written");
}

fn verify(root: &Path) {
    assert_eq!(
        on_disk(root).expect("the mirrors are listed"),
        vec![mirror()]
    );
    let directory = mirror().path(root);
    let store = FsStore::new(&directory);
    let bytes = blob();
    let digest = permguard_objects::Digest::compute(&bytes);
    assert_eq!(
        objects::get(&store, "objects", &digest).expect("the object reads"),
        Some(bytes)
    );
    let found = checkpoint::read(&store, "refs/main")
        .expect("the checkpoint reads")
        .expect("the checkpoint exists");
    assert_eq!(found.head, digest.to_string());
    assert_eq!(found.counter, 1);
}

#[test]
fn test_the_v1_mirror_fixture_is_read_by_the_current_code() {
    let work = scratch();
    if std::env::var_os("PERMGUARD_CAPTURE_LEGACY_FIXTURES").is_some() {
        build(&work);
        let _ = fs::remove_dir_all(FIXTURE);
        copy_dir(&work, Path::new(FIXTURE));
    } else {
        copy_dir(Path::new(FIXTURE), &work);
    }
    verify(&work);
}
