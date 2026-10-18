// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! WP-3.3 (owner decision of 2026-10-08): a zone key version never names two keys in a decision
//! spool. A spool whose markers already name the version under the commitment key of before is
//! refused until the version is raised; a version witnessed under one key is refused under another.
//! The witness lives beside the spool since WP-6.1c, seeded once from the copy in the spool or in
//! its archive.

#![allow(clippy::expect_used)]

use std::path::PathBuf;

use permguard_data_plane::decisions::{ZONE_KEYS_FILE, check_zone_key_version, zone_keys_path};
use permguard_host::secrets::{Coordinator, KeyVersion, Root, ZoneHandle, ZonePurpose};

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-zone-key-version-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("created");
    path
}

fn tags(root: u8, version: u64) -> ZoneHandle {
    ZoneHandle::coordinated(
        ZonePurpose::DecisionCommitment,
        Coordinator::new(
            Root::from_material(&[root; 32], KeyVersion::new(version).expect("a version"))
                .expect("a root"),
            [1; 16],
        ),
    )
}

/// A spool directory below a fresh scratch, and the archive beside it.
fn spool_and_archive(tag: &str) -> (PathBuf, PathBuf) {
    let root = scratch(tag);
    let spool = root.join("spool");
    std::fs::create_dir_all(&spool).expect("created");
    (spool, root.join("legacy"))
}

#[test]
fn a_spool_written_under_the_commitment_key_of_before_refuses_its_version() {
    let (spool, archive) = spool_and_archive("before");
    std::fs::write(
        spool.join("seg-00000000000000000001.jsonl"),
        "{\"v\":1,\"seq\":1,\"kind\":\"marker\",\"commitments\":{\"alg\":\"HMAC-SHA256\",\"key_version\":\"v1\"}}\n",
    )
    .expect("an old segment");

    let refused =
        check_zone_key_version(&spool, &archive, &tags(7, 1)).expect_err("v1 named another key");
    assert!(
        format!("{refused:#}").contains("zone_key_version"),
        "{refused:#}"
    );
    assert!(
        !zone_keys_path(&spool).exists(),
        "nothing recorded on a refusal"
    );

    check_zone_key_version(&spool, &archive, &tags(7, 2)).expect("a raised version starts");
    check_zone_key_version(&spool, &archive, &tags(7, 2)).expect("and starts again");
}

#[test]
fn a_version_witnessed_under_one_key_is_refused_under_another() {
    let (spool, archive) = spool_and_archive("witnessed");
    check_zone_key_version(&spool, &archive, &tags(7, 1)).expect("first seen");
    check_zone_key_version(&spool, &archive, &tags(7, 1)).expect("the same key");
    let refused =
        check_zone_key_version(&spool, &archive, &tags(8, 1)).expect_err("another key under v1");
    assert!(
        format!("{refused:#}").contains("another key"),
        "{refused:#}"
    );
    let held = std::fs::read_to_string(zone_keys_path(&spool)).expect("recorded");
    assert_eq!(
        zone_keys_path(&spool),
        spool.parent().expect("a parent").join(ZONE_KEYS_FILE),
        "beside the spool"
    );
    assert!(!spool.join(ZONE_KEYS_FILE).exists(), "never in the spool");
    assert!(
        held.starts_with("v1\t") && !held.contains(&"07".repeat(8)),
        "{held}"
    );
}

/// The witness `ZONE_KEYS` of what `version` and `root` tag, as `check_zone_key_version` writes it.
fn witnessed(root: u8, version: u64) -> String {
    let (spool, archive) = spool_and_archive(&format!("witness-{root}-{version}"));
    check_zone_key_version(&spool, &archive, &tags(root, version)).expect("witnessed");
    std::fs::read_to_string(zone_keys_path(&spool)).expect("recorded")
}

#[test]
fn the_zone_key_witness_lives_beside_the_spool_seeded_once_from_its_copy() {
    // A release before WP-6.1c kept the witness in the spool: copied beside it on first use, and
    // its key still holds the version.
    let (spool, archive) = spool_and_archive("seeded-spool");
    std::fs::write(spool.join(ZONE_KEYS_FILE), witnessed(7, 1)).expect("an old witness");
    let refused = check_zone_key_version(&spool, &archive, &tags(8, 1))
        .expect_err("another key under the seeded v1");
    assert!(
        format!("{refused:#}").contains("another key"),
        "{refused:#}"
    );
    assert!(
        !zone_keys_path(&spool).exists(),
        "nothing recorded on a refusal"
    );
    check_zone_key_version(&spool, &archive, &tags(7, 1)).expect("the same key");
    assert_eq!(
        std::fs::read_to_string(zone_keys_path(&spool)).expect("seeded"),
        witnessed(7, 1)
    );
    // Once seeded, the copy in the spool is no longer read.
    std::fs::remove_file(spool.join(ZONE_KEYS_FILE)).expect("archived away");
    check_zone_key_version(&spool, &archive, &tags(8, 1))
        .expect_err("still refused from the live witness");

    // The spool archived and gone: seeded from the archive's copy.
    let (spool, archive) = spool_and_archive("seeded-archive");
    std::fs::remove_dir(&spool).expect("finalized");
    std::fs::create_dir_all(&archive).expect("archived");
    std::fs::write(archive.join(ZONE_KEYS_FILE), witnessed(7, 1)).expect("the archived witness");
    check_zone_key_version(&spool, &archive, &tags(8, 1))
        .expect_err("another key under the archived v1");
    check_zone_key_version(&spool, &archive, &tags(7, 1)).expect("the same key");
    assert!(zone_keys_path(&spool).exists(), "seeded beside the spool");
}

#[test]
fn an_archived_spool_still_refuses_a_version_its_markers_named() {
    let (spool, archive) = spool_and_archive("archived-markers");
    std::fs::remove_dir(&spool).expect("finalized");
    std::fs::create_dir_all(&archive).expect("archived");
    std::fs::write(
        archive.join("seg-00000000000000000001.jsonl"),
        "{\"v\":1,\"seq\":1,\"kind\":\"marker\",\"commitments\":{\"alg\":\"HMAC-SHA256\",\"key_version\":\"v1\"}}\n",
    )
    .expect("an archived segment");
    let refused =
        check_zone_key_version(&spool, &archive, &tags(7, 1)).expect_err("v1 named another key");
    assert!(
        format!("{refused:#}").contains("zone_key_version"),
        "{refused:#}"
    );
    check_zone_key_version(&spool, &archive, &tags(7, 2)).expect("a raised version starts");
}
