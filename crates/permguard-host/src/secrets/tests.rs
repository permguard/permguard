// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use permguard_core::assurance::AssuranceProfile;
use permguard_core::{Secret, SecretError};

use super::*;

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-host-secrets-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    path
}

/// A store over a map, its material replaceable between resolutions.
#[derive(Default)]
struct Store(Mutex<BTreeMap<String, Vec<u8>>>);

impl Store {
    fn with(name: &str, material: &[u8]) -> Self {
        let store = Self::default();
        store.set(name, material);
        store
    }

    fn set(&self, name: &str, material: &[u8]) {
        self.0
            .lock()
            .expect("the map")
            .insert(name.to_owned(), material.to_vec());
    }
}

impl SecretStore for Store {
    fn name(&self) -> &'static str {
        "map"
    }

    fn resolve(&self, reference: &SecretRef) -> Result<Secret, SecretError> {
        self.0
            .lock()
            .expect("the map")
            .get(reference.name())
            .map(|material| Secret::new(material.clone()))
            .ok_or_else(|| SecretError::NotFound {
                reference: reference.name().to_owned(),
            })
    }
}

fn v(n: u64) -> KeyVersion {
    KeyVersion::new(n).expect("a version")
}

#[test]
fn a_key_version_is_v_and_an_integer_of_at_least_one() {
    assert_eq!("v1".parse::<KeyVersion>().expect("v1").get(), 1);
    assert_eq!("v42".parse::<KeyVersion>().expect("v42").to_string(), "v42");
    for refused in [
        "1",
        "v0",
        "v01",
        "v",
        "V1",
        "v1a",
        "2024a",
        "v-1",
        "v9223372036854775808",
    ] {
        assert!(refused.parse::<KeyVersion>().is_err(), "`{refused}`");
    }
}

#[test]
fn a_root_is_at_least_256_bits_and_its_material_is_witnessed_per_version() {
    let root = scratch("witness");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let witnesses = Witnesses::open(&volume).expect("the witnesses");
    let reference = SecretRef::new("audit-pseudonym");

    let short = Store::with("audit-pseudonym", &[7; 31]);
    assert!(matches!(
        resolve(&short, &witnesses, &reference, v(1), "audit-pseudonym"),
        Err(SecretsError::TooShort { length: 31, .. })
    ));

    let store = Store::with("audit-pseudonym", &[7; 32]);
    resolve(&store, &witnesses, &reference, v(1), "audit-pseudonym").expect("first seen");
    resolve(&store, &witnesses, &reference, v(1), "audit-pseudonym")
        .expect("the same material again");
    assert!(
        root.join("host/state/witness/audit-pseudonym/v1").exists(),
        "the witness sits at host/state/witness/<reference>/<version>"
    );

    // Another key under the same version: refused. Under a new version: accepted.
    store.set("audit-pseudonym", &[8; 32]);
    assert!(matches!(
        resolve(&store, &witnesses, &reference, v(1), "audit-pseudonym"),
        Err(SecretsError::Changed { .. })
    ));
    resolve(&store, &witnesses, &reference, v(2), "audit-pseudonym").expect("a new version");

    // The witness discloses nothing of the material.
    let held = std::fs::read(root.join("host/state/witness/audit-pseudonym/v2")).expect("read");
    assert_eq!(held, witness_of(&[8; 32]));
    assert!(!held.windows(8).any(|window| window == [8; 8]));
}

#[test]
fn a_reference_that_is_no_plain_name_is_witnessed_under_its_digest() {
    let root = scratch("witness-names");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let witnesses = Witnesses::open(&volume).expect("the witnesses");
    let store = Store::with("../../etc/passwd", &[1; 32]);
    resolve(
        &store,
        &witnesses,
        &SecretRef::new("../../etc/passwd"),
        v(1),
        "audit-pseudonym",
    )
    .expect("resolved");
    let names: Vec<String> = std::fs::read_dir(root.join("host/state/witness"))
        .expect("listed")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .into_string()
                .expect("text")
        })
        .filter(|name| name != BY_ROLE)
        .collect();
    assert_eq!(names.len(), 1);
    assert!(names[0].starts_with("sha256-"), "{names:?}");
}

#[test]
fn host_local_keys_differ_by_purpose_resource_version_and_owner() {
    let local = |owner: u8, version: u64| {
        HostLocal::new(
            Root::from_material(&[5; 32], v(version)).expect("a root"),
            [owner; 16],
        )
    };
    let a = local(1, 1);
    let key =
        |host: &HostLocal, purpose, resource: &str| *host.key(purpose, resource).expect("derived");
    let base = key(&a, HostPurpose::AuditPseudonym, "host");
    assert_eq!(
        base,
        key(&a, HostPurpose::AuditPseudonym, "host"),
        "deterministic"
    );
    for other in [
        key(&a, HostPurpose::StreamCursor, "host"),
        key(&a, HostPurpose::AuditPseudonym, "realm/acme"),
        key(&local(1, 2), HostPurpose::AuditPseudonym, "host"),
        key(&local(2, 1), HostPurpose::AuditPseudonym, "host"),
    ] {
        assert_ne!(base, other);
    }
    // Exactly the blueprint's derivation, owner as salt and as authority.
    let expected = permguard_objects::crypto::kdf::derive_host_local(
        &[5; 32],
        &[1; 16],
        permguard_core::domains::kdf::AUDIT_PSEUDONYM,
        &[1; 16],
        "host",
        1,
    )
    .expect("derived");
    assert_eq!(base, *expected);
    assert!(Root::from_material(&[5; 31], v(1)).is_err());
}

#[test]
fn a_host_pseudonym_separates_the_type_from_the_identifier_and_names_its_version() {
    let key = [3u8; 32];
    let one = host_pseudonym(&key, v(1), "principal", "alice").expect("a pseudonym");
    assert!(one.starts_with("v1:") && one.len() == 3 + 32, "{one}");
    assert_eq!(
        one,
        host_pseudonym(&key, v(1), "principal", "  alice ").expect("a pseudonym"),
        "surrounding white space is not part of the identifier"
    );
    assert_ne!(
        one,
        host_pseudonym(&key, v(1), "subject", "alice").expect("p")
    );
    assert_ne!(
        host_pseudonym(&key, v(1), "a", "bc").expect("p"),
        host_pseudonym(&key, v(1), "ab", "c").expect("p"),
        "the type and the identifier never run into each other"
    );
    assert!(
        host_pseudonym(&key, v(2), "principal", "alice")
            .expect("p")
            .starts_with("v2:")
    );
}

#[test]
fn a_delivered_key_is_stored_once_witnessed_and_read_back() {
    let root = scratch("delivered");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let keys = ZoneKeys::open(&volume).expect("the zone keys");
    let coordinator = Coordinator::new(
        Root::from_material(&[9; 32], v(1)).expect("a root"),
        [1; 16],
    );
    let (zone, ledger) = ([2u8; 16], [3u8; 16]);
    let tuple = coordinator
        .deliver(&keys, ZonePurpose::DecisionCommitment, &zone, &ledger)
        .expect("delivered");
    coordinator
        .deliver(&keys, ZonePurpose::DecisionCommitment, &zone, &ledger)
        .expect("delivered again, the same key");
    let held = keys.load(&tuple).expect("readable").expect("delivered");
    assert_eq!(
        *held,
        *coordinator
            .distributed(ZonePurpose::DecisionCommitment, &zone, &ledger)
            .expect("derived")
    );
    let path = root.join(format!(
        "host/{ZONE_USE}/{}/{}/{}/{}/v1",
        uuid_text(&[1; 16]),
        uuid_text(&zone),
        ZonePurpose::DecisionCommitment.as_str(),
        uuid_text(&ledger)
    ));
    assert!(path.exists(), "{}", path.display());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o077, 0, "owner only: {mode:o}");
    }
    // Another key under the same tuple is refused.
    assert!(matches!(
        keys.store(&tuple, &[0; 32]),
        Err(SecretsError::Changed { .. })
    ));
    // The witness lost, another key under the tuple is still refused by the key on disk.
    let witness = root.join(format!(
        "host/state/witness/{ZONE_USE}/{}/{}/{}/{}/v1",
        uuid_text(&[1; 16]),
        uuid_text(&zone),
        ZonePurpose::DecisionCommitment.as_str(),
        uuid_text(&ledger)
    ));
    std::fs::remove_file(&witness).expect("the witness removed");
    assert!(matches!(
        keys.store(&tuple, &[0; 32]),
        Err(SecretsError::Changed { .. })
    ));
    assert!(!witness.exists(), "a refused key leaves no witness behind");
    keys.store(&tuple, &held)
        .expect("the same key is witnessed again");
    assert!(witness.exists());
    // A key swapped on disk is refused by its witness.
    std::fs::write(&path, [0u8; 32]).expect("swapped");
    assert!(matches!(
        keys.load(&tuple),
        Err(SecretsError::Changed { .. })
    ));
    // A tuple never delivered is no key.
    let other = ZoneTuple {
        scope: [4; 16],
        ..tuple
    };
    assert!(keys.load(&other).expect("readable").is_none());
}

#[test]
fn a_zone_handle_answers_no_mac_for_a_tuple_it_holds_no_key_for() {
    let root = scratch("handle");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let keys = ZoneKeys::open(&volume).expect("the zone keys");
    let coordinator = Coordinator::new(
        Root::from_material(&[9; 32], v(1)).expect("a root"),
        [1; 16],
    );
    coordinator
        .deliver(&keys, ZonePurpose::DecisionCommitment, &[2; 16], &[3; 16])
        .expect("delivered");
    let handle = ZoneHandle::delivered(ZonePurpose::DecisionCommitment, &[1; 16], v(1), &keys)
        .expect("read");
    assert!(handle.mac(&[2; 16], &[3; 16], &[b"x"]).is_some());
    assert!(
        handle.mac(&[2; 16], &[4; 16], &[b"x"]).is_none(),
        "another ledger"
    );
    assert!(
        handle.mac(&[5; 16], &[3; 16], &[b"x"]).is_none(),
        "another zone"
    );
    let at_two = ZoneHandle::delivered(ZonePurpose::DecisionCommitment, &[1; 16], v(2), &keys)
        .expect("read");
    assert!(
        at_two.mac(&[2; 16], &[3; 16], &[b"x"]).is_none(),
        "another version"
    );
    let pseudonyms =
        ZoneHandle::delivered(ZonePurpose::AuditPseudonym, &[1; 16], v(1), &keys).expect("read");
    assert!(
        pseudonyms.mac(&[2; 16], &[3; 16], &[b"x"]).is_none(),
        "another purpose"
    );
    assert_eq!(
        format!("{handle:?}"),
        "ZoneHandle(decision.commitment, v1, redacted)"
    );
}

#[test]
fn a_role_keeps_its_version_honest_whatever_reference_names_it() {
    let root = scratch("by-role");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let witnesses = Witnesses::open(&volume).expect("the witnesses");
    let store = Store::with("coordinator-a", &[1; 32]);
    store.set("coordinator-b", &[2; 32]);
    resolve(
        &store,
        &witnesses,
        &SecretRef::new("coordinator-a"),
        v(1),
        "coordinator",
    )
    .expect("first seen");
    // Another reference, other material, the same role and version: refused.
    assert!(matches!(
        resolve(
            &store,
            &witnesses,
            &SecretRef::new("coordinator-b"),
            v(1),
            "coordinator"
        ),
        Err(SecretsError::Changed { .. })
    ));
    resolve(
        &store,
        &witnesses,
        &SecretRef::new("coordinator-b"),
        v(2),
        "coordinator",
    )
    .expect("a new version");
    // Names the directory uses itself are hashed, never taken as they are.
    for reserved in [ZONE_USE, BY_ROLE, "sha256-abc"] {
        let store = Store::with(reserved, &[3; 32]);
        resolve(
            &store,
            &witnesses,
            &SecretRef::new(reserved),
            v(1),
            reserved,
        )
        .expect("resolved");
        assert!(component(reserved).starts_with("sha256-") && component(reserved) != reserved);
    }
}

#[test]
fn the_zones_shared_pseudonyms_take_the_zone_as_their_only_scope() {
    let coordinator = Coordinator::new(
        Root::from_material(&[9; 32], v(1)).expect("a root"),
        [1; 16],
    );
    let (zone, ledger) = ([2u8; 16], [3u8; 16]);
    assert!(
        coordinator
            .distributed(ZonePurpose::AuditPseudonym, &zone, &zone)
            .is_ok()
    );
    assert!(matches!(
        coordinator.distributed(ZonePurpose::AuditPseudonym, &zone, &ledger),
        Err(SecretsError::Scope)
    ));
    let handle = ZoneHandle::coordinated(ZonePurpose::AuditPseudonym, coordinator.clone());
    assert!(handle.mac(&zone, &zone, &[b"x"]).is_some());
    assert!(handle.mac(&zone, &ledger, &[b"x"]).is_none());
    let root = scratch("scope");
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let keys = ZoneKeys::open(&volume).expect("the zone keys");
    assert!(matches!(
        coordinator.deliver(&keys, ZonePurpose::AuditPseudonym, &zone, &ledger),
        Err(SecretsError::Scope)
    ));
    assert_eq!(
        format!("{handle:?}"),
        "ZoneHandle(audit.pseudonym, v1, redacted)",
        "Debug names the purpose and version, never a key"
    );
}
