// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The sweep, against a real store.
//!
//! A garbage collector is only as good as what it refuses to touch, so that is
//! what this suite is about: a reachable object is never removed, a push in
//! flight is never removed, a second ref keeps its own history alive, and a
//! store that cannot be read completely is left exactly as it was.
//!
//! Everything here goes through the shipped [`FileObjectStore`] — the same
//! writes a push performs — because a fake store would prove nothing about the
//! layout the sweep walks.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use permguard_control_plane::gc;
use permguard_control_plane::store::FileObjectStore;
use permguard_objects::digest::Digest;
use permguard_objects::object::{Blob, Commit, Kind, Tree, TreeEntry};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pg-gc-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory is created");

    dir
}

/// A blob, stored the way a push stores one.
fn blob(store: &FileObjectStore, text: &str) -> Digest {
    let bytes = Blob {
        media_type: "application/vnd.permguard.policy.cedar".to_owned(),
        data: format!("permit (principal, action, resource); // {text}").into_bytes(),
    }
    .encode()
    .expect("the blob encodes");

    store.put_object(&bytes).expect("the blob is stored").0
}

/// A commit over one blob, and the ref that names it.
fn commit_over(store: &FileObjectStore, r#ref: &str, blobs: &[(&str, Digest)]) -> Digest {
    let manifest = store
        .put_object(
            &Blob {
                media_type: permguard_objects::manifest::MEDIA_TYPE.to_owned(),
                data: manifest_bytes(),
            }
            .encode()
            .expect("the manifest blob encodes"),
        )
        .expect("the manifest is stored")
        .0;

    let mut entries: Vec<TreeEntry> = blobs
        .iter()
        .map(|(name, digest)| TreeEntry {
            kind: Kind::Blob,
            digest: digest.clone(),
            name: (*name).to_owned(),
            annotations: std::collections::BTreeMap::new(),
        })
        .collect();
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    let partition = store
        .put_object(&Tree { entries }.encode().expect("the tree encodes"))
        .expect("the tree is stored")
        .0;
    let root = store
        .put_object(
            &Tree {
                entries: vec![TreeEntry {
                    kind: Kind::Tree,
                    digest: partition,
                    name: "cedar".to_owned(),
                    annotations: std::collections::BTreeMap::new(),
                }],
            }
            .encode()
            .expect("the root tree encodes"),
        )
        .expect("the tree is stored")
        .0;
    let commit = store
        .put_object(
            &Commit {
                tree: root,
                manifest,
                predecessors: Vec::new(),
                author: "tests".to_owned(),
                author_at: 1_700_000_000,
                message: format!("the commit `{ref}` names", r#ref = r#ref),
            }
            .encode()
            .expect("the commit encodes"),
        )
        .expect("the commit is stored")
        .0;
    store
        .update_ref(r#ref, None, &commit)
        .expect("the ref is created");

    commit
}

fn manifest_bytes() -> Vec<u8> {
    use permguard_objects::manifest::{Manifest, Partition, Profile, Requirement, Runtime};
    use permguard_objects::semver::Constraint;

    let mut runtimes = std::collections::BTreeMap::new();
    runtimes.insert(
        "cedar".to_owned(),
        Runtime {
            language: Requirement {
                name: "cedar".to_owned(),
                constraint: Constraint::parse(">=4.0.0").expect("a constraint"),
            },
            engine: Requirement {
                name: "permguard".to_owned(),
                constraint: Constraint::parse(">=0.0.0").expect("a constraint"),
            },
        },
    );
    let mut partitions = std::collections::BTreeMap::new();
    partitions.insert(
        "cedar".to_owned(),
        Partition {
            runtime: "cedar".to_owned(),
            media_types: vec!["application/vnd.permguard.policy.cedar".to_owned()],
            schema: false,
            artifacts: Vec::new(),
            history: None,
            input: None,
        },
    );
    let mut profiles = std::collections::BTreeMap::new();
    profiles.insert(
        "default".to_owned(),
        Profile {
            r#type: "permguard.pdp.v1".to_owned(),
            partitions: vec!["cedar".to_owned()],
        },
    );

    Manifest {
        kind: "policy".to_owned(),
        name: "gc-tests".to_owned(),
        description: "a ledger the sweep tests walk".to_owned(),
        author: "Nitro Agility S.r.l.".to_owned(),
        license: "Apache-2.0".to_owned(),
        runtimes,
        partitions,
        profiles,
    }
    .encode()
}

/// Makes an object look old enough to be a candidate.
fn age(store: &FileObjectStore, digest: &Digest, by: Duration) {
    let hex = digest.to_string();
    let hex = &hex["sha256:".len()..];
    let path = store.root().join("objects").join(&hex[..2]).join(&hex[2..]);
    let when = SystemTime::now() - by;
    let file = std::fs::File::options()
        .write(true)
        .open(&path)
        .expect("the object is there");
    file.set_modified(when).expect("the clock is set back");
}

fn present(store: &FileObjectStore, digest: &Digest) -> bool {
    store.has_object(digest)
}

#[test]
fn what_a_ref_reaches_is_never_removed() {
    let store = FileObjectStore::new(scratch("reachable"));
    let policy = blob(&store, "kept");
    let head = commit_over(&store, "main", &[("policy.cedar", policy.clone())]);
    // Old enough to be a candidate, if reachability did not protect it.
    for digest in [&policy, &head] {
        age(&store, digest, Duration::from_secs(30 * 24 * 60 * 60));
    }

    let swept = gc::sweep_once(&store, Duration::from_secs(60)).expect("the sweep runs");

    assert_eq!(swept.removed, 0, "everything here is reachable");
    assert!(present(&store, &policy));
    assert!(present(&store, &head));
}

#[test]
fn an_orphan_past_the_grace_period_goes_and_its_bytes_are_reported() {
    let store = FileObjectStore::new(scratch("orphan"));
    let kept = blob(&store, "kept");
    commit_over(&store, "main", &[("policy.cedar", kept.clone())]);
    // The upload of a push that never committed.
    let orphan = blob(&store, "abandoned");
    age(&store, &orphan, Duration::from_secs(2 * 60 * 60));

    let swept = gc::sweep_once(&store, Duration::from_secs(60 * 60)).expect("the sweep runs");

    assert_eq!(swept.removed, 1);
    assert!(swept.reclaimed > 0, "the bytes it freed are reported");
    assert!(!present(&store, &orphan), "the orphan is gone");
    assert!(present(&store, &kept), "and nothing else moved");
}

#[test]
fn a_push_in_flight_is_never_swept() {
    let store = FileObjectStore::new(scratch("in-flight"));
    commit_over(&store, "main", &[("policy.cedar", blob(&store, "kept"))]);
    // Uploaded seconds ago, commit still to come: unreachable and young.
    let uploading = blob(&store, "uploading");

    let swept = gc::sweep_once(&store, Duration::from_secs(24 * 60 * 60)).expect("the sweep runs");

    assert_eq!(swept.removed, 0, "a transfer in flight is not garbage");
    assert_eq!(
        swept.retained, 1,
        "it is counted, so an operator can see it"
    );
    assert!(present(&store, &uploading));
}

#[test]
fn every_ref_protects_its_own_history() {
    let store = FileObjectStore::new(scratch("two-refs"));
    let on_main = blob(&store, "main");
    commit_over(&store, "main", &[("policy.cedar", on_main.clone())]);
    let on_other = blob(&store, "release");
    commit_over(&store, "release", &[("policy.cedar", on_other.clone())]);
    for digest in [&on_main, &on_other] {
        age(&store, digest, Duration::from_secs(30 * 24 * 60 * 60));
    }

    let swept = gc::sweep_once(&store, Duration::from_secs(60)).expect("the sweep runs");

    assert_eq!(swept.removed, 0);
    assert!(
        present(&store, &on_other),
        "a sweep that knew only about `main` would have deleted this"
    );
}

#[test]
fn a_store_with_a_hole_in_its_closure_is_left_exactly_as_it_was() {
    let store = FileObjectStore::new(scratch("hole"));
    let policy = blob(&store, "kept");
    commit_over(&store, "main", &[("policy.cedar", policy.clone())]);
    let orphan = blob(&store, "abandoned");
    age(&store, &orphan, Duration::from_secs(2 * 60 * 60));
    // Something a ref reaches is missing: the store cannot be read completely.
    store.remove_object(&policy).expect("removed by hand");

    let refused = gc::sweep_once(&store, Duration::from_secs(60 * 60))
        .expect_err("a store that cannot be fully read is not one to delete from");

    assert!(
        refused.to_string().contains("refusing to sweep"),
        "{refused}"
    );
    assert!(
        present(&store, &orphan),
        "and the orphan it would have taken is still there"
    );
}

#[test]
fn an_empty_store_is_a_sweep_that_does_nothing() {
    let store = FileObjectStore::new(scratch("empty"));

    let swept = gc::sweep_once(&store, Duration::from_secs(60)).expect("the sweep runs");

    assert_eq!(swept, gc::Swept::default());
}
