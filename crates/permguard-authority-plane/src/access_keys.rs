// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Access keys (`2-security/8` Access keys): an id a log may name, and a secret only its holder
//! knows, kept by the Authority Plane as an Argon2id hash.
//!
//! | Part       | Form                                                         |
//! | ---------- | ------------------------------------------------------------ |
//! | access key | `pgak_` and 20 uppercase base32 characters (100 random bits) |
//! | secret key | `pgsk_` and 43 base64url characters (32 random bytes)        |

use std::sync::OnceLock;

use argon2::{Algorithm, Argon2, Params, PasswordHasher as _, PasswordVerifier as _, Version};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom as _, SystemRandom};
use zeroize::Zeroizing;

/// What every access key starts with.
pub const ACCESS_KEY_PREFIX: &str = "pgak_";
/// What every secret key starts with.
pub const SECRET_KEY_PREFIX: &str = "pgsk_";
/// The base32 characters after the access key's prefix.
pub const ACCESS_KEY_CHARS: usize = 20;
/// The random bytes a secret key carries.
pub const SECRET_BYTES: usize = 32;
/// The Argon2id cost: OWASP's second configuration, the same everywhere a secret is kept.
pub const MEMORY_KIB: u32 = 19_456;
pub const PASSES: u32 = 2;
pub const LANES: u32 = 1;
/// The salt of every hash.
pub const SALT_BYTES: usize = 16;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn hasher() -> Result<Argon2<'static>, String> {
    let params = Params::new(MEMORY_KIB, PASSES, LANES, None)
        .map_err(|error| format!("the Argon2id parameters: {error}"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0u8; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "the system's random generator failed".to_owned())?;
    Ok(bytes)
}

/// A new access key: `pgak_` and 20 base32 characters, each from a byte modulo 32, which 256
/// divides, so every character is uniform.
pub fn draw_access_key() -> Result<String, String> {
    let bytes: [u8; ACCESS_KEY_CHARS] = random()?;
    let mut key = String::with_capacity(ACCESS_KEY_PREFIX.len() + ACCESS_KEY_CHARS);
    key.push_str(ACCESS_KEY_PREFIX);
    key.extend(
        bytes
            .iter()
            .map(|byte| char::from(BASE32[usize::from(byte % 32)])),
    );
    Ok(key)
}

/// A new secret key, wiped from memory when dropped.
pub fn draw_secret_key() -> Result<Zeroizing<String>, String> {
    let bytes = Zeroizing::new(random::<SECRET_BYTES>()?);
    Ok(Zeroizing::new(format!(
        "{SECRET_KEY_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(bytes.as_slice())
    )))
}

/// Whether `text` has the form of an access key.
pub fn is_access_key(text: &str) -> bool {
    text.strip_prefix(ACCESS_KEY_PREFIX).is_some_and(|rest| {
        rest.len() == ACCESS_KEY_CHARS && rest.bytes().all(|byte| BASE32.contains(&byte))
    })
}

/// Whether `text` has the form of a secret key: what is refused before any hash is computed.
pub fn is_secret_key(text: &str) -> bool {
    text.strip_prefix(SECRET_KEY_PREFIX).is_some_and(|rest| {
        rest.len() == 43
            && rest
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    })
}

/// The Argon2id PHC string of `secret`, under a fresh salt.
pub fn hash(secret: &str) -> Result<String, String> {
    if !is_secret_key(secret) {
        return Err("not a secret key".to_owned());
    }
    let salt: [u8; SALT_BYTES] = random()?;
    hasher()?
        .hash_password_with_salt(secret.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| format!("hashing a secret key: {error}"))
}

/// Whether `secret` is the one `phc` was made from.
pub fn verify(secret: &str, phc: &str) -> bool {
    if !is_secret_key(secret) || !phc.starts_with("$argon2id$") {
        return false;
    }
    hasher().is_ok_and(|hasher| hasher.verify_password(secret.as_bytes(), phc).is_ok())
}

/// Spends what a verification spends, against nothing: an unknown access key takes as long as a
/// known one with the wrong secret, so the time of a refusal says nothing of which it was.
pub fn burn(secret: &str) {
    static DUMMY: OnceLock<Option<String>> = OnceLock::new();
    let dummy = DUMMY.get_or_init(|| {
        draw_secret_key()
            .ok()
            .and_then(|secret| hash(secret.as_str()).ok())
    });
    if let Some(phc) = dummy {
        let _ = verify(secret, phc);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn keys_have_their_form_and_never_repeat() {
        let key = draw_access_key().expect("drawn");
        assert!(is_access_key(&key), "{key}");
        assert_eq!(key.len(), 25);
        assert_ne!(key, draw_access_key().expect("drawn"));
        let secret = draw_secret_key().expect("drawn");
        assert!(is_secret_key(&secret), "the secret has its form");
        assert_eq!(secret.len(), 48);
        assert!(!is_access_key("pgak_short"));
        assert!(!is_access_key("pgak_aaaaaaaaaaaaaaaaaaaa"), "uppercase");
        assert!(!is_secret_key("pgsk_"));
        assert!(!is_secret_key(&format!("pgsk_{}", "a".repeat(42))));
    }

    #[test]
    fn a_secret_is_kept_as_argon2id_and_verifies_only_itself() {
        let secret = draw_secret_key().expect("drawn");
        let phc = hash(&secret).expect("hashed");
        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{phc}");
        assert!(verify(&secret, &phc));
        let other = draw_secret_key().expect("drawn");
        assert!(!verify(&other, &phc));
        assert_ne!(
            phc,
            hash(&secret).expect("hashed"),
            "a fresh salt each time"
        );
        assert!(!verify("not a secret", &phc));
        assert!(hash("not a secret").is_err());
        burn(&other);
    }
}
