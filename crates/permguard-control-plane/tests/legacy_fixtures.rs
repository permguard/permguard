// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A Control Plane zones root as this release writes it, kept so that every later layout can prove
//! it still reads one.
//!
//! `tests/fixtures/legacy/v1/zones` is a zones root written by the current code: the catalog
//! (`zones.json`, `<zone-id>/ledgers.json`) and, nested under it exactly where the Control Plane
//! opens it, one ledger store at `<zone-id>/ledgers/<ledger-id>` with `FORMAT`, one
//! content-addressed blob and one ref. In CI the fixture is copied aside, the ledger is found
//! through the catalog and its store opened, which must find the same object and ref. Setting
//! `PERMGUARD_CAPTURE_LEGACY_FIXTURES=1` rewrites the fixture from the current code instead; that
//! is done once per layout version and reviewed, never to make a failing test pass.
//!
//! The fixture is the v1 compatibility baseline: every later migration of this store must read it.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};

use permguard_control_plane::store::FileObjectStore;
use permguard_core::{Catalog, Selector, domains};
use permguard_objects::object::Blob;
use permguard_std::catalog::FileCatalog;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/legacy/v1/zones"
);

fn scratch() -> PathBuf {
    let path = std::env::temp_dir().join(format!("permguard-legacy-zones-{}", std::process::id()));
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

fn blob() -> Vec<u8> {
    Blob {
        media_type: domains::media::POLICY_CEDAR.to_owned(),
        data: b"permit(principal, action, resource);\n".to_vec(),
    }
    .encode()
    .expect("the blob encodes")
}

/// The ledger directory, found through the catalog the way the Control Plane finds it.
fn ledger_directory(root: &Path) -> PathBuf {
    let catalog = FileCatalog::new(root);
    let zones = catalog.list_zones().expect("the zones list");
    assert_eq!(
        zones
            .iter()
            .map(|zone| zone.name.as_str())
            .collect::<Vec<_>>(),
        ["billing"]
    );
    let ledger = catalog
        .get_ledger(
            &Selector::Id(zones[0].id.clone()),
            &Selector::parse("invoices"),
        )
        .expect("the ledger is in the catalog");
    root.join(&zones[0].id).join("ledgers").join(&ledger.id)
}

fn build(root: &Path) {
    let catalog = FileCatalog::new(root);
    catalog.create_zone("billing").expect("the zone is created");
    catalog
        .create_ledger(&Selector::parse("billing"), "invoices")
        .expect("the ledger is created");
    let store = FileObjectStore::new(ledger_directory(root));
    let (digest, _) = store.put_object(&blob()).expect("the object lands");
    store
        .update_ref("refs/main", None, &digest)
        .expect("the ref is created");
}

fn verify(root: &Path) {
    let directory = ledger_directory(root);
    let store = FileObjectStore::new(&directory);
    let bytes = blob();
    let digest = permguard_objects::Digest::compute(&bytes);
    assert_eq!(
        fs::read_to_string(directory.join("FORMAT"))
            .expect("FORMAT is present")
            .trim(),
        "1"
    );
    assert_eq!(
        store.get_object(&digest).expect("the object reads"),
        Some(bytes),
        "the blob is found by its digest"
    );
    let state = store
        .read_ref("refs/main")
        .expect("the ref reads")
        .expect("the ref exists");
    assert_eq!(state.head, digest);
    assert_eq!(state.counter, 1);
}

#[test]
fn test_the_v1_zones_root_fixture_is_read_by_the_current_code() {
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
