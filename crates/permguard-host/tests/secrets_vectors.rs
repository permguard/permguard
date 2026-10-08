// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The secrets' golden vectors (`contracts/vectors/secrets.json`, WP-3.3), computed by an
//! independent generator and reproduced here by `permguard-host::secrets`.

#![allow(clippy::expect_used)]

use permguard_host::secrets::{
    Coordinator, HostLocal, HostPurpose, KeyVersion, Root, ZoneHandle, ZonePurpose, host_pseudonym,
    witness_of,
};
use permguard_objects::crypto::kdf;
use serde_json::Value;

fn vectors() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/vectors/secrets.json"
    ))
    .expect("the vectors read");
    serde_json::from_str(&text).expect("the vectors parse")
}

fn hex(value: &Value) -> Vec<u8> {
    let text = value.as_str().expect("hex text");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn id(value: &Value) -> [u8; 16] {
    hex(value).try_into().expect("16 bytes")
}

fn text(value: &Value) -> &str {
    value.as_str().expect("text")
}

fn v1() -> KeyVersion {
    KeyVersion::new(1).expect("v1")
}

#[test]
fn the_witness_and_the_host_local_keys_are_the_generators() {
    let v = vectors();
    let root = hex(&v["root"]);
    assert_eq!(witness_of(&root).to_vec(), hex(&v["witness"]));

    let owner = id(&v["host"]);
    assert_eq!(
        kdf::host_local_info("audit.pseudonym", &owner, "host", 1).expect("encoded"),
        hex(&v["host_local"]["info"])
    );
    let local = HostLocal::new(Root::from_material(&root, v1()).expect("a root"), owner);
    let key = local
        .key(HostPurpose::AuditPseudonym, "host")
        .expect("derived");
    assert_eq!(key.to_vec(), hex(&v["host_local"]["key"]));
    assert_eq!(
        host_pseudonym(&key, v1(), "principal", " alice ").expect("a pseudonym"),
        text(&v["host_local"]["pseudonym"])
    );
    let other = HostLocal::new(
        Root::from_material(&root, v1()).expect("a root"),
        id(&v["other_host"]),
    );
    assert_eq!(
        host_pseudonym(
            &other
                .key(HostPurpose::AuditPseudonym, "host")
                .expect("derived"),
            v1(),
            "principal",
            "alice"
        )
        .expect("a pseudonym"),
        text(&v["host_local"]["other_host_pseudonym"])
    );
    assert_eq!(
        local
            .key(HostPurpose::StreamCursor, "decisions/acme/main")
            .expect("derived")
            .to_vec(),
        hex(&v["cursor"]["key"])
    );
}

#[test]
fn the_zone_root_the_distributed_keys_and_what_they_compute_are_the_generators() {
    let v = vectors();
    let (authority, zone, ledger) = (id(&v["host"]), id(&v["zone"]), id(&v["ledger"]));
    let coordinator_root = hex(&v["coordinator_root"]);
    assert_eq!(
        kdf::derive_zone_root(&coordinator_root, &authority, &zone, 1)
            .expect("derived")
            .to_vec(),
        hex(&v["zone_root"]["key"])
    );
    let coordinator = || {
        Coordinator::new(
            Root::from_material(&coordinator_root, v1()).expect("a root"),
            authority,
        )
    };
    assert_eq!(
        coordinator()
            .distributed(ZonePurpose::AuditPseudonym, &zone, &zone)
            .expect("derived")
            .to_vec(),
        hex(&v["zone_pseudonym"]["key"])
    );
    let pseudonyms = ZoneHandle::coordinated(ZonePurpose::AuditPseudonym, coordinator());
    assert_eq!(
        pseudonyms
            .pseudonym(&zone, "subject", "alice")
            .expect("a pseudonym"),
        text(&v["zone_pseudonym"]["pseudonym"])
    );
    assert_eq!(
        coordinator()
            .distributed(ZonePurpose::DecisionCommitment, &zone, &ledger)
            .expect("derived")
            .to_vec(),
        hex(&v["input_tag"]["key"])
    );
    let tags = ZoneHandle::coordinated(ZonePurpose::DecisionCommitment, coordinator());
    assert_eq!(
        tags.mac(
            &zone,
            &ledger,
            &[
                permguard_core::domains::digest::INPUT_TAG.as_bytes(),
                text(&v["input_tag"]["value"]).as_bytes()
            ]
        )
        .expect("a tag")
        .to_vec(),
        hex(&v["input_tag"]["tag"])
    );
}
