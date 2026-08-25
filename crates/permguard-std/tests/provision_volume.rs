#![cfg(feature = "provision")]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a run creates, what it refuses to touch, and what it refuses to do without permission.

use std::fs;
use std::path::{Path, PathBuf};

use permguard_core::{BuildSettings, Config, Layers};
use permguard_std::provision::{Volume, prepare};

/// A volume location nothing else is using.
fn volume(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("permguard-volume-{name}"));
    let _ = fs::remove_dir_all(&path);

    path
}

/// Builds a configuration out of settings, as the file layer would supply them.
fn config(pairs: &[(&str, &str)]) -> Config {
    Config::from_layers(
        BuildSettings::new("9.9.9", "2026", "Test Holder"),
        Vec::<String>::new(),
        Layers::new().with_file(
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<Vec<_>>(),
        ),
    )
    .expect("the config builds")
}

/// The settings a local run uses: everything relative to the volume, generation allowed.
fn generating(root: &Path, extra: &[(&str, &str)]) -> Config {
    let mut pairs = vec![
        (
            "PERMGUARD_WORKING_DIR",
            root.to_str().expect("a UTF-8 path"),
        ),
        ("PERMGUARD_AUTOGENERATE", "true"),
        ("PERMGUARD_SECRETS_PROVIDER", "directory"),
        ("PERMGUARD_AUDIT_PSEUDONYM_ENABLED", "true"),
        ("PERMGUARD_AUDIT_PSEUDONYM_KEY_REF", "audit-pseudonym"),
    ];
    pairs.extend_from_slice(extra);

    config(&pairs)
}

#[test]
fn test_the_volume_is_created_even_when_nothing_may_be_generated() {
    let root = volume("bare");
    let config = config(&[(
        "PERMGUARD_WORKING_DIR",
        root.to_str().expect("a UTF-8 path"),
    )]);

    prepare(&config).expect("the volume is prepared");

    // The directory is where the server keeps what it keeps; creating it grants no trust.
    assert!(root.is_dir());
    assert!(root.join("data").is_dir());
    assert!(!root.join("tls").exists(), "nothing was generated");
}

#[test]
fn test_a_secret_is_generated_when_generation_is_allowed() {
    let root = volume("secret");
    let config = generating(&root, &[]);

    prepare(&config).expect("the volume is prepared");

    let secret = root.join("operations/secrets").join("audit-pseudonym");
    let material = fs::read_to_string(&secret).expect("the secret is there");

    // 32 bytes, hex encoded, and not something a person typed.
    assert_eq!(material.len(), 64, "{material}");
    assert!(material.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_two_runs_never_produce_the_same_secret() {
    let first = volume("random-a");
    let second = volume("random-b");

    prepare(&generating(&first, &[])).expect("the first volume");
    prepare(&generating(&second, &[])).expect("the second volume");

    assert_ne!(
        fs::read_to_string(first.join("operations/secrets/audit-pseudonym"))
            .expect("the first secret"),
        fs::read_to_string(second.join("operations/secrets/audit-pseudonym"))
            .expect("the second secret"),
        "a generated key that repeats is not a key"
    );
}

#[test]
fn test_what_is_already_there_is_never_overwritten() {
    let root = volume("existing");
    fs::create_dir_all(root.join("operations/secrets")).expect("creating the directory");
    fs::write(
        root.join("operations/secrets/audit-pseudonym"),
        "supplied-by-somebody-else",
    )
    .expect("writing the secret");

    prepare(&generating(&root, &[])).expect("the volume is prepared");

    assert_eq!(
        fs::read_to_string(root.join("operations/secrets/audit-pseudonym"))
            .expect("the secret is there"),
        "supplied-by-somebody-else",
        "a file that exists is a file somebody meant to put there"
    );
}

#[test]
fn test_certificates_are_generated_only_when_the_configuration_wants_tls() {
    let without = volume("no-tls");
    prepare(&generating(&without, &[])).expect("the volume is prepared");
    assert!(
        !without.join("tls/server.pem").exists(),
        "nothing asked for TLS"
    );

    let with = volume("tls");
    prepare(&generating(
        &with,
        &[
            ("PERMGUARD_PUBLIC_TLS_CERT", "tls/server.pem"),
            ("PERMGUARD_PUBLIC_TLS_KEY", "tls/server.key"),
        ],
    ))
    .expect("the volume is prepared");

    for file in [
        "tls/ca.pem",
        "tls/server.pem",
        "tls/server.key",
        "tls/client.pem",
    ] {
        assert!(with.join(file).is_file(), "{file} was not generated");
    }
}

#[test]
fn test_half_a_set_of_certificates_is_refused_rather_than_completed() {
    let root = volume("half");
    fs::create_dir_all(root.join("tls")).expect("creating the directory");
    fs::write(root.join("tls/server.pem"), "-----BEGIN CERTIFICATE-----\n").expect("writing");
    fs::write(root.join("tls/server.key"), "-----BEGIN PRIVATE KEY-----\n").expect("writing");

    let error = prepare(&generating(
        &root,
        &[
            ("PERMGUARD_PUBLIC_TLS_CERT", "tls/server.pem"),
            ("PERMGUARD_PUBLIC_TLS_KEY", "tls/server.key"),
        ],
    ))
    .expect_err("the set is incomplete");

    // Signing a server certificate with an authority that is no longer there verifies against
    // nothing, so it says so instead of quietly making one.
    assert!(format!("{error:#}").contains("incomplete"), "{error:#}");
}

#[test]
fn test_nothing_is_generated_without_permission() {
    let root = volume("forbidden");
    let config = config(&[
        (
            "PERMGUARD_WORKING_DIR",
            root.to_str().expect("a UTF-8 path"),
        ),
        ("PERMGUARD_AUDIT_PSEUDONYM_ENABLED", "true"),
        ("PERMGUARD_AUDIT_PSEUDONYM_KEY_REF", "audit-pseudonym"),
        ("PERMGUARD_SECRETS_PROVIDER", "directory"),
    ]);

    prepare(&config).expect("the volume is prepared");

    assert!(
        !root.join("operations/secrets/audit-pseudonym").exists(),
        "generation must take saying so"
    );
}

#[test]
fn test_the_volume_is_the_working_directory() {
    let root = volume("where");
    let config = config(&[(
        "PERMGUARD_WORKING_DIR",
        root.to_str().expect("a UTF-8 path"),
    )]);

    assert_eq!(Volume::of(&config).root(), root);
}

#[cfg(unix)]
#[test]
fn test_generated_material_is_readable_by_nobody_else() {
    use std::os::unix::fs::PermissionsExt;

    let root = volume("modes");
    prepare(&generating(
        &root,
        &[
            ("PERMGUARD_PUBLIC_TLS_CERT", "tls/server.pem"),
            ("PERMGUARD_PUBLIC_TLS_KEY", "tls/server.key"),
        ],
    ))
    .expect("the volume is prepared");

    for private in [
        "operations/secrets/audit-pseudonym",
        "tls/server.key",
        "tls/ca.key",
    ] {
        let mode = fs::metadata(root.join(private))
            .expect("the file is there")
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(mode, 0o600, "{private} is {mode:o}");
    }
}
