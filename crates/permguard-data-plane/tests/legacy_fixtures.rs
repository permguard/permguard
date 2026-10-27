// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A policy mirror of a configured URL, as releases up to v0.1.6 wrote it: the fixture of the
//! retired path (WP-7.7).
//!
//! `tests/fixtures/legacy/v1/mirrors` is a mirrors root in the first shape: one `<zone>/<ledger>`
//! directory with its `FORMAT` pin, one content-addressed object and the `refs/main` checkpoint,
//! no authority above it. The current code still recognizes it — the layout lists it, the client
//! reads its checkpoint — and that is the whole of the dual reader left: the decision path never
//! serves it, and the first round removes it, a re-pullable cache whose authority a URL never
//! proved. Setting `PERMGUARD_CAPTURE_LEGACY_FIXTURES=1` rewrites the fixture instead; that is
//! done once per layout version and reviewed, never to make a failing test pass.

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
        authority: None,
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
            ref_digest: None,
            ..Checkpoint::default()
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

/// WP-7.7: the retired path's fixture is never served, and the first round removes it, whatever
/// task this Host follows, recorded.
#[tokio::test(flavor = "multi_thread")]
async fn test_the_v1_mirror_fixture_is_never_served_and_the_first_round_removes_it() {
    let work = std::env::temp_dir().join(format!(
        "permguard-legacy-mirrors-retired-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&work);
    copy_dir(Path::new(FIXTURE), &work);
    assert!(
        permguard_data_plane::authz::store::mirrors(&work).is_empty(),
        "never served"
    );
    let outcome = permguard_data_plane::mirrors::round::run(std::sync::Arc::new(
        permguard_data_plane::mirrors::round::Context {
            tasks: None,
            selections: Default::default(),
            decider: None,
            root: work.clone(),
            deadline: std::time::Duration::from_secs(30),
            stale_after: None,
            reap_grace: std::time::Duration::ZERO,
            holds: Default::default(),
            parallelism: 1,
            permits: std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
            metrics: permguard_core::Metrics::none(),
        },
    ))
    .await;
    assert_eq!(outcome.reaped, 1);
    assert_eq!(
        outcome.candidacy,
        vec![("mirror.reaped", "zone-a/ledger-a".to_owned())]
    );
    assert!(on_disk(&work).expect("listed").is_empty());
}
