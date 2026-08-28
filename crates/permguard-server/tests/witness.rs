// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The check that catches a pseudonymisation key changing without its version changing.
//!
//! This is the mistake worth a test: it produces no error, no warning and no visible symptom, and it
//! ruins the audit trail slowly. By the time anyone asks "are these two records about the same
//! person", the answer has been unknowable for months.

use std::fs;
use std::path::{Path, PathBuf};

use permguard_core::{BuildSettings, Config, Layers, Pseudonymizer, config::*};
use permguard_server::witness;

/// A pseudonymiser that behaves like the real one for the purposes of this check: the same key
/// yields the same tokens, a different key yields different ones.
struct Keyed {
    key: &'static str,
    version: &'static str,
}

impl Pseudonymizer for Keyed {
    fn key_version(&self) -> &str {
        self.version
    }

    fn pseudonymize(&self, value: &str) -> String {
        format!("{}:{}-{}", self.version, self.key, value.len())
    }
}

/// A volume nothing else is using.
fn volume(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-witness-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = fs::remove_dir_all(&path);

    path
}

fn config(root: &Path) -> Config {
    Config::from_layers(
        BuildSettings::new("9.9.9", "2026", "Test Holder"),
        Vec::<String>::new(),
        Layers::new().with_file(vec![(
            SETTING_WORKING_DIR.to_owned(),
            root.to_str().expect("a UTF-8 path").to_owned(),
        )]),
    )
    .expect("the config builds")
}

#[test]
fn test_the_first_start_records_the_version_and_says_nothing() {
    let root = volume("first");
    let config = config(&root);

    witness::check(
        &config,
        Some(&Keyed {
            key: "alpha",
            version: "v1",
        }),
    )
    .expect("a version nobody has seen before is recorded");

    assert!(witness::witness_path(&config).exists());
}

#[test]
fn test_starting_again_with_the_same_key_is_fine() {
    let root = volume("same");
    let config = config(&root);
    let key = Keyed {
        key: "alpha",
        version: "v1",
    };

    witness::check(&config, Some(&key)).expect("the first start records it");
    witness::check(&config, Some(&key)).expect("the second start recognises it");
    witness::check(&config, Some(&key)).expect("and so does the third");
}

#[test]
fn test_a_key_that_changed_without_its_version_stops_the_start() {
    let root = volume("silent-rotation");
    let config = config(&root);

    witness::check(
        &config,
        Some(&Keyed {
            key: "alpha",
            version: "v1",
        }),
    )
    .expect("the first start records it");

    // The mistake: new key material behind the same reference, and nobody bumped the version.
    let error = witness::check(
        &config,
        Some(&Keyed {
            key: "beta",
            version: "v1",
        }),
    )
    .expect_err("the same version now means a different key");

    let why = format!("{error:#}");
    assert!(why.contains("changed but its version did not"), "{why}");
    // The message has to say what to do, because the person reading it is the person who has to
    // decide whether the old key is coming back.
    assert!(why.contains("key_version"), "{why}");
}

#[test]
fn test_rotating_properly_is_accepted() {
    let root = volume("proper-rotation");
    let config = config(&root);

    witness::check(
        &config,
        Some(&Keyed {
            key: "alpha",
            version: "v1",
        }),
    )
    .expect("the first start records it");

    // A new key *and* a new version, which is what rotating means.
    witness::check(
        &config,
        Some(&Keyed {
            key: "beta",
            version: "v2",
        }),
    )
    .expect("a new key under a new version is a rotation");

    // And the old version is still remembered, so going back to the old key by mistake is caught.
    let error = witness::check(
        &config,
        Some(&Keyed {
            key: "gamma",
            version: "v1",
        }),
    )
    .expect_err("v1 has a meaning already");

    assert!(format!("{error:#}").contains("changed but its version did not"));
}

#[test]
fn test_a_deployment_that_does_not_pseudonymise_is_not_asked_about_keys() {
    let root = volume("disabled");
    let config = config(&root);

    witness::check(&config, None).expect("there is nothing to check");

    assert!(
        !witness::witness_path(&config).exists(),
        "a deployment that pseudonymises nothing wrote a file about its keys"
    );
}

#[test]
fn test_the_file_holds_no_key_and_is_readable_only_by_this_user() {
    let root = volume("contents");
    let config = config(&root);

    witness::check(
        &config,
        Some(&Keyed {
            key: "a-very-secret-key",
            version: "v1",
        }),
    )
    .expect("it records");

    let path = witness::witness_path(&config);
    let text = fs::read_to_string(&path).expect("the file reads");

    // What is written is the pseudonymiser's own output for a constant — producing it needs the key,
    // having it does not reveal the key. Exactly as sensitive as the trail it protects.
    assert!(text.starts_with("v1\t"), "{text}");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = fs::metadata(&path)
            .expect("it is there")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn test_a_real_keyed_pseudonymiser_leaves_no_key_material_on_disk() {
    use permguard_std::pseudonym::HmacPseudonymizer;

    let root = volume("real-key");
    let config = config(&root);
    let key = b"a key long enough to derive pseudonyms from";

    witness::check(&config, Some(&HmacPseudonymizer::new(key, "v1")))
        .expect("the first start records it");

    let text = fs::read_to_string(witness::witness_path(&config)).expect("the file reads");

    assert!(text.starts_with("v1\t"), "{text}");
    assert!(
        !text.contains("a key long enough"),
        "the key reached the disk: {text}"
    );

    // The same key still verifies, and a different one under the same version does not.
    witness::check(&config, Some(&HmacPseudonymizer::new(key, "v1")))
        .expect("the same key is recognised");
    witness::check(
        &config,
        Some(&HmacPseudonymizer::new(b"an entirely different key", "v1")),
    )
    .expect_err("a different key under the same version is caught");
}
