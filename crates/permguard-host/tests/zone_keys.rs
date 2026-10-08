// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! F-23 and H-02 (WP-3.3): replicas of one zone compute the same shared user pseudonyms and
//! decision input tags without holding the zone root, while Host-local pseudonyms differ across
//! Hosts by design; a member cannot derive a sibling purpose, scope or version.

#![allow(clippy::expect_used)]

use std::path::PathBuf;

use permguard_core::assurance::AssuranceProfile;
use permguard_host::secrets::{
    Coordinator, HostLocal, HostPurpose, KeyVersion, Root, ZoneHandle, ZoneKeys, ZonePurpose,
    host_pseudonym,
};
use permguard_host::storage::volume::Volume;

const COORDINATOR: [u8; 16] = [0xc0; 16];
const ZONE: [u8; 16] = [0x20; 16];
const LEDGER: [u8; 16] = [0x30; 16];
const OTHER_LEDGER: [u8; 16] = [0x31; 16];

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-zone-keys-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    path
}

fn v(n: u64) -> KeyVersion {
    KeyVersion::new(n).expect("a version")
}

fn coordinator() -> Coordinator {
    Coordinator::new(
        Root::from_material(&[0x5a; 32], v(1)).expect("the coordinator root"),
        COORDINATOR,
    )
}

/// A member Host: its volume and the keys the coordinator delivered to it.
struct Member {
    _volume: Volume,
    keys: ZoneKeys,
}

fn member(root: &std::path::Path) -> Member {
    let volume = Volume::claim(root, AssuranceProfile::Development).expect("claimed");
    let keys = ZoneKeys::open(&volume).expect("the zone keys");
    let coordinator = coordinator();
    coordinator
        .deliver(&keys, ZonePurpose::AuditPseudonym, &ZONE, &ZONE)
        .expect("the zone's pseudonym key");
    coordinator
        .deliver(&keys, ZonePurpose::DecisionCommitment, &ZONE, &LEDGER)
        .expect("the ledger's commitment key");
    Member {
        _volume: volume,
        keys,
    }
}

fn handle(member: &Member, purpose: ZonePurpose) -> ZoneHandle {
    ZoneHandle::delivered(purpose, &COORDINATOR, v(1), &member.keys).expect("the delivered keys")
}

#[test]
fn replicas_of_a_zone_agree_without_the_zone_root_and_host_local_pseudonyms_differ() {
    let root = scratch("f23");
    let (a, b) = (member(&root.join("a")), member(&root.join("b")));

    // F-23: the same user pseudonym and the same input tag on both replicas.
    let pseudonyms = (
        handle(&a, ZonePurpose::AuditPseudonym),
        handle(&b, ZonePurpose::AuditPseudonym),
    );
    let alice = |handle: &ZoneHandle| handle.pseudonym(&ZONE, "principal", "alice").expect("held");
    assert_eq!(alice(&pseudonyms.0), alice(&pseudonyms.1));
    let tags = (
        handle(&a, ZonePurpose::DecisionCommitment),
        handle(&b, ZonePurpose::DecisionCommitment),
    );
    let tag = |handle: &ZoneHandle| {
        handle
            .mac(&ZONE, &LEDGER, &[b"permguard.input.v1\n", b"\"HR\""])
            .expect("held")
    };
    assert_eq!(tag(&tags.0), tag(&tags.1));
    // And the coordinator, deriving in memory, computes the same.
    let coordinated = ZoneHandle::coordinated(ZonePurpose::DecisionCommitment, coordinator());
    assert_eq!(tag(&coordinated), tag(&tags.0));

    // Neither member holds the zone root: their volumes carry only the exact delivered keys.
    for member in ["a", "b"] {
        let mut files = Vec::new();
        collect(&root.join(member).join("host/zone-use"), &mut files);
        assert_eq!(files.len(), 2, "{files:?}");
        for file in &files {
            let held = std::fs::read(file).expect("read");
            assert_ne!(
                held,
                vec![0x5a; 32],
                "the coordinator root is never delivered"
            );
        }
    }

    // H-02: Host-local pseudonyms of the same root and identifier differ from Host to Host.
    let local = |owner: u8| {
        let host = HostLocal::new(
            Root::from_material(&[0x77; 32], v(1)).expect("a root"),
            [owner; 16],
        );
        host_pseudonym(
            &host
                .key(HostPurpose::AuditPseudonym, "host")
                .expect("derived"),
            v(1),
            "principal",
            "alice",
        )
        .expect("a pseudonym")
    };
    assert_ne!(local(1), local(2));
    assert_ne!(
        local(1),
        alice(&pseudonyms.0),
        "Host-local and zone-shared never coincide"
    );
}

#[test]
fn a_member_cannot_derive_a_sibling_purpose_scope_or_version() {
    let root = scratch("siblings");
    let a = member(&root.join("a"));
    let tags = handle(&a, ZonePurpose::DecisionCommitment);
    assert!(tags.mac(&ZONE, &LEDGER, &[b"x"]).is_some());
    assert!(
        tags.mac(&ZONE, &OTHER_LEDGER, &[b"x"]).is_none(),
        "a ledger never delivered"
    );
    let at_two =
        ZoneHandle::delivered(ZonePurpose::DecisionCommitment, &COORDINATOR, v(2), &a.keys)
            .expect("read");
    assert!(
        at_two.mac(&ZONE, &LEDGER, &[b"x"]).is_none(),
        "a future version"
    );
    let pseudonyms = handle(&a, ZonePurpose::AuditPseudonym);
    assert!(
        pseudonyms.mac(&ZONE, &LEDGER, &[b"x"]).is_none(),
        "the pseudonym key does not stand in for the ledger's"
    );
    // The keys themselves are unrelated: the delivered pseudonym key is not the commitment key
    // of the zone's own scope, and neither is the coordinator's for another ledger.
    let coordinator = coordinator();
    let delivered = coordinator
        .distributed(ZonePurpose::DecisionCommitment, &ZONE, &LEDGER)
        .expect("derived");
    for sibling in [
        coordinator
            .distributed(ZonePurpose::DecisionCommitment, &ZONE, &OTHER_LEDGER)
            .expect("derived"),
        coordinator
            .distributed(ZonePurpose::AuditPseudonym, &ZONE, &ZONE)
            .expect("derived"),
        Coordinator::new(
            Root::from_material(&[0x5a; 32], v(2)).expect("a root"),
            COORDINATOR,
        )
        .distributed(ZonePurpose::DecisionCommitment, &ZONE, &LEDGER)
        .expect("derived"),
    ] {
        assert_ne!(*sibling, *delivered);
    }
}

fn collect(dir: &std::path::Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("listed") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            collect(&path, files);
        } else {
            files.push(path);
        }
    }
}
