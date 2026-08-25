#![cfg(feature = "secrets")]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What each store answers, and — more importantly — how it distinguishes the ways it can fail.
//!
//! Here rather than beside the code because the cases that matter touch a real filesystem: a file
//! that is not there, a file that cannot be read, and a name that is trying to leave the directory.

use std::fs;
use std::path::PathBuf;

use permguard_core::{Secret, SecretError, SecretRef, SecretStore};
use permguard_std::secrets::{DirectorySecretStore, EnvironmentSecretStore, InMemorySecretStore};

/// Unwraps the failure of a resolution.
///
/// Written out rather than `expect_err` because `Secret` implements no `Debug` — which is the type
/// doing its job: not even a test can print secret material by accident.
fn failure(resolved: Result<Secret, SecretError>, what: &str) -> SecretError {
    match resolved {
        Err(error) => error,
        Ok(_) => panic!("{what}"),
    }
}

/// A directory of secrets, of the shape a mounted Kubernetes secret has.
fn directory(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("permguard-secrets-{name}"));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("creating the fixture directory");

    path
}

#[test]
fn test_a_secret_on_disk_resolves_to_its_contents() {
    let path = directory("present");
    fs::write(path.join("audit-pseudonym"), "0123456789abcdef").expect("writing the secret");

    let secret = DirectorySecretStore::new(&path)
        .resolve(&SecretRef::new("audit-pseudonym"))
        .expect("the reference resolves");

    assert_eq!(secret.expose(), b"0123456789abcdef");
}

#[test]
fn test_the_newline_an_editor_adds_is_not_part_of_the_key() {
    let path = directory("newline");
    fs::write(path.join("key"), "0123456789abcdef\n").expect("writing the secret");

    let secret = DirectorySecretStore::new(&path)
        .resolve(&SecretRef::new("key"))
        .expect("the reference resolves");

    assert_eq!(
        secret.expose(),
        b"0123456789abcdef",
        "a trailing newline would silently change every derived value"
    );
}

#[test]
fn test_absence_and_refusal_are_different_answers() {
    let path = directory("absent");
    let store = DirectorySecretStore::new(&path);

    // Nothing written: the reference names a secret that does not exist.
    let missing = failure(
        store.resolve(&SecretRef::new("audit-pseudonym")),
        "nothing is there",
    );
    assert!(matches!(missing, SecretError::NotFound { .. }));
    assert!(
        !missing.is_retryable(),
        "a wrong reference never becomes right"
    );

    // A reference trying to leave the directory is an attempt, not an absence.
    let escape = failure(
        store.resolve(&SecretRef::new("../../etc/shadow")),
        "the reference is malformed",
    );
    assert!(matches!(escape, SecretError::Denied { .. }));
}

#[test]
fn test_a_secret_from_the_environment_resolves_by_its_variable() {
    // SAFETY: the variable is unique to this test and removed before it returns.
    unsafe { std::env::set_var("PERMGUARD_TEST_AUDIT_PSEUDONYM", "from-the-environment") };

    let resolved =
        EnvironmentSecretStore::new("PERMGUARD_TEST").resolve(&SecretRef::new("audit-pseudonym"));

    unsafe { std::env::remove_var("PERMGUARD_TEST_AUDIT_PSEUDONYM") };

    assert_eq!(
        resolved.expect("the reference resolves").expose(),
        b"from-the-environment"
    );
}

#[test]
fn test_an_unset_variable_is_an_absence_not_a_failure() {
    let error = failure(
        EnvironmentSecretStore::new("PERMGUARD_TEST_NOTHING").resolve(&SecretRef::new("nowhere")),
        "nothing is set",
    );

    assert!(matches!(error, SecretError::NotFound { .. }));
}

#[test]
fn test_the_in_memory_store_answers_what_it_was_given() {
    let store = InMemorySecretStore::new().with("audit-pseudonym", "0123456789abcdef");

    assert_eq!(
        store
            .resolve(&SecretRef::new("audit-pseudonym"))
            .expect("the reference resolves")
            .expose(),
        b"0123456789abcdef"
    );
    assert!(matches!(
        failure(store.resolve(&SecretRef::new("other")), "not there"),
        SecretError::NotFound { .. }
    ));
}

#[cfg(unix)]
#[test]
fn test_a_secret_anyone_could_rewrite_is_refused() {
    use std::os::unix::fs::PermissionsExt;

    let path = directory("writable");
    let secret = path.join("audit-pseudonym");
    fs::write(&secret, "0123456789abcdef").expect("writing the secret");
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o666)).expect("loosening it");

    // Writable by others means an attacker chooses the key, and every value derived from it.
    let error = failure(
        DirectorySecretStore::new(&path).resolve(&SecretRef::new("audit-pseudonym")),
        "the file is world-writable",
    );

    assert!(matches!(error, SecretError::Denied { .. }));
}

#[cfg(unix)]
#[test]
fn test_a_secret_others_can_only_read_is_still_served() {
    use std::os::unix::fs::PermissionsExt;

    let path = directory("readable");
    let secret = path.join("audit-pseudonym");
    fs::write(&secret, "0123456789abcdef").expect("writing the secret");
    // 0644 is what a Kubernetes secret volume mounts by default: refusing it would refuse the most
    // common correct deployment. It is reported, not rejected.
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o644)).expect("loosening it");

    assert_eq!(
        DirectorySecretStore::new(&path)
            .resolve(&SecretRef::new("audit-pseudonym"))
            .expect("the reference resolves")
            .expose(),
        b"0123456789abcdef"
    );
}

#[test]
fn test_every_store_names_itself() {
    assert_eq!(DirectorySecretStore::new("/tmp").name(), "directory");
    assert_eq!(
        EnvironmentSecretStore::new("PERMGUARD").name(),
        "environment"
    );
    assert_eq!(InMemorySecretStore::new().name(), "in-memory");
}
