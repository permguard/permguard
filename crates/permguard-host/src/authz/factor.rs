// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A local user's second factor (WP-8.1): TOTP (RFC 6238), SHA-1, 6 digits, 30 s steps, one step
//! either way, each code accepted once. The secret is kept sealed with AES-256-GCM under the key
//! the Host-local root derives for `mfa.seal` and the user, the associated data binding it to the
//! user: a sealed secret copied to another user, or another Host, does not open.

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom as _, SystemRandom};
use zeroize::Zeroizing;

/// The secret's length: 160 bits, as RFC 4226 recommends.
pub const SECRET_BYTES: usize = 20;
/// The step, in seconds.
pub const STEP: u64 = 30;
/// The digits of a code.
pub const DIGITS: u32 = 6;
/// The version byte a sealed secret starts with.
const SEAL_V1: u8 = 1;

/// A fresh secret.
pub fn new_secret() -> Result<Zeroizing<Vec<u8>>, String> {
    let mut secret = Zeroizing::new(vec![0u8; SECRET_BYTES]);
    SystemRandom::new()
        .fill(&mut secret)
        .map_err(|_| "the system's random generator failed".to_owned())?;
    Ok(secret)
}

/// The HOTP code of `secret` at `counter` (RFC 4226).
pub fn code_at(secret: &[u8], counter: u64) -> u32 {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = ring::hmac::sign(&key, &counter.to_be_bytes());
    let digest = tag.as_ref();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let binary = (u32::from(digest[offset]) & 0x7f) << 24
        | u32::from(digest[offset + 1]) << 16
        | u32::from(digest[offset + 2]) << 8
        | u32::from(digest[offset + 3]);
    binary % 10u32.pow(DIGITS)
}

/// The step `code` matches at `now`, one step either way, when it is later than `last`: each
/// code is accepted once. A code that is not six digits matches nothing.
pub fn check(secret: &[u8], code: &str, now: u64, last: Option<u64>) -> Option<u64> {
    let code = code.trim();
    if code.len() != DIGITS as usize || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let wanted: u32 = code.parse().ok()?;
    let current = now / STEP;
    let mut found = None;
    // Every candidate is computed, so the time does not say which step matched.
    for step in [current.saturating_sub(1), current, current + 1] {
        // One 32-bit comparison: no early exit on the first digit that differs.
        let matches = (code_at(secret, step) ^ wanted) == 0;
        if matches && last.is_none_or(|last| step > last) && found.is_none() {
            found = Some(step);
        }
    }
    found
}

/// RFC 4648 base32, no padding: how authenticator applications read a secret.
pub fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u64 = 0;
    let mut bits = 0;
    for byte in bytes {
        buffer = (buffer << 8) | u64::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

/// The `otpauth://` URI an authenticator application scans, naming the user and the Host.
pub fn uri(issuer: &str, user: &str, secret: &[u8]) -> String {
    let escape = |text: &str| -> String {
        text.bytes()
            .map(|byte| match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'@' => {
                    char::from(byte).to_string()
                }
                other => format!("%{other:02X}"),
            })
            .collect()
    };
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP}",
        escape(issuer),
        escape(user),
        base32(secret),
        escape(issuer)
    )
}

fn aad(user: &str) -> Vec<u8> {
    let mut aad = permguard_core::domains::digest::FACTOR_SEAL
        .as_bytes()
        .to_vec();
    aad.extend_from_slice(user.as_bytes());
    aad
}

/// `secret`, sealed for `user` under `key`: version, nonce, ciphertext and tag.
pub fn seal(key: &[u8; 32], user: &str, secret: &[u8]) -> Result<Vec<u8>, String> {
    let sealing = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| "the sealing key".to_owned())?,
    );
    let mut nonce = [0u8; 12];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| "the system's random generator failed".to_owned())?;
    let mut sealed = secret.to_vec();
    sealing
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad(user)),
            &mut sealed,
        )
        .map_err(|_| "sealing the factor".to_owned())?;
    let mut out = Vec::with_capacity(1 + nonce.len() + sealed.len());
    out.push(SEAL_V1);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// The secret `sealed` holds for `user` under `key`; `None` when it does not open: another key,
/// another user, or damaged.
pub fn unseal(key: &[u8; 32], user: &str, sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let (&version, rest) = sealed.split_first()?;
    if version != SEAL_V1 || rest.len() < 12 + 16 {
        return None;
    }
    let (nonce, body) = rest.split_at(12);
    let opening = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).ok()?);
    let mut buffer = Zeroizing::new(body.to_vec());
    let plain = opening
        .open_in_place(
            Nonce::try_assume_unique_for_key(nonce).ok()?,
            Aad::from(aad(user)),
            &mut buffer,
        )
        .ok()?;
    Some(Zeroizing::new(plain.to_vec()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    /// RFC 6238 appendix B, SHA-1, its 20-byte secret, the last six digits.
    #[test]
    fn the_codes_are_rfc_6238s() {
        let secret = b"12345678901234567890";
        for (time, eight) in [
            (59u64, 94_287_082u32),
            (1_111_111_109, 7_081_804),
            (1_111_111_111, 14_050_471),
            (1_234_567_890, 89_005_924),
            (2_000_000_000, 69_279_037),
        ] {
            assert_eq!(code_at(secret, time / STEP), eight % 1_000_000, "at {time}");
        }
        assert_eq!(
            base32(b"12345678901234567890"),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
    }

    #[test]
    fn a_code_matches_one_step_either_way_and_once() {
        let secret = new_secret().expect("a secret");
        let now = 1_800_000_000;
        let code = |step: u64| format!("{:06}", code_at(&secret, step));
        let current = now / STEP;
        assert_eq!(check(&secret, &code(current), now, None), Some(current));
        assert_eq!(
            check(&secret, &code(current - 1), now, None),
            Some(current - 1)
        );
        assert_eq!(
            check(&secret, &code(current + 1), now, None),
            Some(current + 1)
        );
        assert_eq!(check(&secret, &code(current - 2), now, None), None);
        assert_eq!(
            check(&secret, &code(current), now, Some(current)),
            None,
            "used once"
        );
        assert_eq!(check(&secret, "12345", now, None), None);
        assert_eq!(check(&secret, "abcdef", now, None), None);
        let uri = uri("Permguard acme", "alice@acme.com", &secret);
        assert!(
            uri.starts_with("otpauth://totp/Permguard%20acme:alice@acme.com?secret="),
            "{uri}"
        );
    }

    #[test]
    fn a_sealed_secret_opens_only_for_its_user_and_key() {
        let key = [7u8; 32];
        let secret = new_secret().expect("a secret");
        let sealed = seal(&key, "user:alice", &secret).expect("sealed");
        assert_eq!(
            unseal(&key, "user:alice", &sealed)
                .expect("opens")
                .as_slice(),
            secret.as_slice()
        );
        assert!(
            unseal(&key, "user:mallory", &sealed).is_none(),
            "bound to its user"
        );
        assert!(
            unseal(&[8u8; 32], "user:alice", &sealed).is_none(),
            "bound to its key"
        );
        let mut damaged = sealed.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        assert!(unseal(&key, "user:alice", &damaged).is_none());
        assert_ne!(
            sealed,
            seal(&key, "user:alice", &secret).expect("sealed"),
            "a fresh nonce"
        );
    }
}
