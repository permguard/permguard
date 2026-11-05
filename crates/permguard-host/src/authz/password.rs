// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Local users' passwords (WP-8.1, `1-architecture/1` Local users and authentication methods):
//! kept only as Argon2id PHC strings, 19 MiB, 2 passes, 1 lane, a 16-byte salt from the system's
//! generator; checked against a policy before they are hashed; never logged, never returned.

use std::sync::OnceLock;

use argon2::{Algorithm, Argon2, Params, PasswordHasher as _, PasswordVerifier as _, Version};
use ring::rand::{SecureRandom as _, SystemRandom};

/// Argon2id's memory, in KiB.
pub const MEMORY_KIB: u32 = 19_456;
/// Argon2id's passes.
pub const PASSES: u32 = 2;
/// Argon2id's lanes.
pub const LANES: u32 = 1;
/// The salt's length.
pub const SALT_BYTES: usize = 16;
/// The longest password accepted, in bytes: a bound on the work an unauthenticated request asks.
pub const MAX_PASSWORD_BYTES: usize = 1_024;
/// The shortest `min_length` a deployment may set.
pub const MIN_LENGTH_FLOOR: usize = 8;
/// The default `min_length`.
pub const DEFAULT_MIN_LENGTH: usize = 12;

fn hasher() -> Result<Argon2<'static>, String> {
    let params = Params::new(MEMORY_KIB, PASSES, LANES, None)
        .map_err(|error| format!("the Argon2id parameters: {error}"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Why `password` is refused for the user `name`, if it is: shorter than `min_length` characters,
/// longer than [`MAX_PASSWORD_BYTES`], the user name itself, or blank.
pub fn check_policy(name: &str, password: &str, min_length: usize) -> Result<(), String> {
    let min_length = min_length.max(MIN_LENGTH_FLOOR);
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(format!("a password is at most {MAX_PASSWORD_BYTES} bytes"));
    }
    if password.chars().count() < min_length {
        return Err(format!("a password is at least {min_length} characters"));
    }
    if password.trim().is_empty() {
        return Err("a password is not blank".to_owned());
    }
    if password.eq_ignore_ascii_case(name) {
        return Err("a password is not the user name".to_owned());
    }
    Ok(())
}

/// The PHC string of `password` under a fresh salt.
pub fn hash(password: &str) -> Result<String, String> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(format!("a password is at most {MAX_PASSWORD_BYTES} bytes"));
    }
    let mut salt = [0u8; SALT_BYTES];
    SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| "the system's random generator failed".to_owned())?;
    hasher()?
        .hash_password_with_salt(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| format!("hashing a password: {error}"))
}

/// Whether `password` is the one `phc` was made from. Only an Argon2id string is accepted, and
/// a password over [`MAX_PASSWORD_BYTES`] is refused without the work.
pub fn verify(password: &str, phc: &str) -> bool {
    if password.len() > MAX_PASSWORD_BYTES || !phc.starts_with("$argon2id$") {
        return false;
    }
    hasher().is_ok_and(|hasher| hasher.verify_password(password.as_bytes(), phc).is_ok())
}

/// The same work as a verification, for a name that has no password or does not exist, so the
/// answer takes the same time whatever failed.
pub fn burn(password: &str) {
    static DUMMY: OnceLock<Option<String>> = OnceLock::new();
    if let Some(phc) = DUMMY.get_or_init(|| hash("permguard-burn-a-verification").ok()) {
        let _ = verify(password, phc);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn a_password_is_kept_as_argon2id_and_verifies_only_itself() {
        let phc = hash("correct horse battery").expect("hashed");
        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{phc}");
        assert!(verify("correct horse battery", &phc));
        assert!(!verify("correct horse batterY", &phc));
        assert_ne!(
            phc,
            hash("correct horse battery").expect("hashed"),
            "a fresh salt each time"
        );
        assert!(
            !verify("anything", "$argon2i$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA"),
            "Argon2id only"
        );
        assert!(!verify(&"x".repeat(MAX_PASSWORD_BYTES + 1), &phc));
        burn("whatever");
    }

    #[test]
    fn the_policy_refuses_short_long_blank_and_the_name() {
        assert!(check_policy("alice", "a long enough one", 12).is_ok());
        assert!(
            check_policy("alice", "short", 12)
                .unwrap_err()
                .contains("at least 12")
        );
        assert!(
            check_policy("alice", "short1", 4)
                .unwrap_err()
                .contains("at least 8"),
            "never under the floor"
        );
        assert!(
            check_policy("alice", &"x".repeat(1_025), 12)
                .unwrap_err()
                .contains("at most")
        );
        assert!(
            check_policy("alice", "            ", 12)
                .unwrap_err()
                .contains("blank")
        );
        assert!(
            check_policy("verylongname@acme.com", "VeryLongName@acme.com", 12)
                .unwrap_err()
                .contains("user name")
        );
        assert!(
            check_policy("alice", "àèìòùàèìòùàè", 12).is_ok(),
            "characters, not bytes"
        );
    }
}
