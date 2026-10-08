// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! WP-3.3 (owner decision of 2026-10-08): a zone key version never names two keys in a decision
//! spool. A spool whose markers already name the version under the commitment key of before is
//! refused until the version is raised; a version witnessed under one key is refused under another.

#![allow(clippy::expect_used)]

use std::path::PathBuf;

use permguard_data_plane::decisions::{ZONE_KEYS_FILE, check_zone_key_version};
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

#[test]
fn a_spool_written_under_the_commitment_key_of_before_refuses_its_version() {
    let spool = scratch("before");
    std::fs::write(
        spool.join("seg-00000000000000000001.jsonl"),
        "{\"v\":1,\"seq\":1,\"kind\":\"marker\",\"commitments\":{\"alg\":\"HMAC-SHA256\",\"key_version\":\"v1\"}}\n",
    )
    .expect("an old segment");

    let refused = check_zone_key_version(&spool, &tags(7, 1)).expect_err("v1 named another key");
    assert!(
        format!("{refused:#}").contains("zone_key_version"),
        "{refused:#}"
    );
    assert!(
        !spool.join(ZONE_KEYS_FILE).exists(),
        "nothing recorded on a refusal"
    );

    check_zone_key_version(&spool, &tags(7, 2)).expect("a raised version starts");
    check_zone_key_version(&spool, &tags(7, 2)).expect("and starts again");
}

#[test]
fn a_version_witnessed_under_one_key_is_refused_under_another() {
    let spool = scratch("witnessed");
    check_zone_key_version(&spool, &tags(7, 1)).expect("first seen");
    check_zone_key_version(&spool, &tags(7, 1)).expect("the same key");
    let refused = check_zone_key_version(&spool, &tags(8, 1)).expect_err("another key under v1");
    assert!(
        format!("{refused:#}").contains("another key"),
        "{refused:#}"
    );
    let held = std::fs::read_to_string(spool.join(ZONE_KEYS_FILE)).expect("recorded");
    assert!(
        held.starts_with("v1\t") && !held.contains(&"07".repeat(8)),
        "{held}"
    );
}
