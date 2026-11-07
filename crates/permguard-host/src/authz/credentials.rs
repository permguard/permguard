// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A service account's credentials (iteration 02, WP-11.2, `2-security/8` Service accounts): what
//! a request gives becomes what the directory keeps, and a secret leaves the IAM Host once, in the
//! answer that made it.
//!
//! | Kind              | The request gives                    | The directory keeps                         |
//! | ----------------- | ------------------------------------ | ------------------------------------------- |
//! | `client_secret`   | nothing: the Host draws it           | its Argon2id PHC string                     |
//! | `private_key_jwt` | a public JWK, Ed25519 or P-256       | the key, its algorithm, its RFC 7638 `kid`  |
//! | `tls_client_auth` | `spki:sha256:<hex>` or a SAN URI     | the binding                                 |

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SecureRandom as _;
use sha2::{Digest as _, Sha256};

use permguard_core::authz::Principal;

/// A secret the IAM Host drew, presented with HTTP Basic at the token endpoint.
pub const CLIENT_SECRET: &str = "client_secret";
/// A client assertion signed with the account's key (RFC 7523).
pub const PRIVATE_KEY_JWT: &str = "private_key_jwt";
/// The TLS client certificate of the connection (RFC 8705).
pub const TLS_CLIENT_AUTH: &str = "tls_client_auth";
/// Every kind, as the directory spells it.
pub const KINDS: &[&str] = &[CLIENT_SECRET, PRIVATE_KEY_JWT, TLS_CLIENT_AUTH];

/// What every drawn secret starts with, so a leaked one is recognised by a scanner.
pub const SECRET_PREFIX: &str = "pgc_";
/// The random bytes behind a secret.
const SECRET_BYTES: usize = 32;

/// The algorithm of an Ed25519 key.
pub const EDDSA: &str = "EdDSA";
/// The algorithm of a P-256 key.
pub const ES256: &str = "ES256";

/// A JWK member only a private key carries: a public key never holds one.
const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// A secret drawn from the OS CSPRNG: `pgc_` and 43 base64url characters.
pub fn draw_secret() -> Result<String, String> {
    let mut bytes = [0u8; SECRET_BYTES];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "the OS random source failed".to_owned())?;
    Ok(format!("{SECRET_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes)))
}

/// Whether `secret` reads as one the IAM Host draws: checked before it is hashed, so a malformed
/// one costs no Argon2id.
pub fn is_secret(secret: &str) -> bool {
    secret
        .strip_prefix(SECRET_PREFIX)
        .is_some_and(|rest| rest.len() == 43 && URL_SAFE_NO_PAD.decode(rest).is_ok())
}

/// A public key as the directory keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// `EdDSA` or `ES256`.
    pub algorithm: &'static str,
    /// 32 bytes for Ed25519; the 65-byte uncompressed point for P-256.
    pub key: Vec<u8>,
    /// The RFC 7638 thumbprint, base64url.
    pub key_id: String,
}

/// Reads a public JWK, its members as text: `OKP` `Ed25519` or `EC` `P-256`, no private member,
/// `use` `sig` and an `alg` matching the key when they are present.
pub fn public_key(jwk: &BTreeMap<String, String>) -> Result<PublicKey, String> {
    if let Some(member) = PRIVATE_MEMBERS
        .iter()
        .find(|member| jwk.contains_key(**member))
    {
        return Err(format!(
            "the JWK holds `{member}`, a private key's member: give the public key only"
        ));
    }
    let text = |name: &str| jwk.get(name).map(String::as_str);
    let coordinate = |name: &str| -> Result<(String, Vec<u8>), String> {
        let value = text(name).ok_or_else(|| format!("the JWK has no `{name}`"))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| format!("the JWK's `{name}` is not base64url"))?;
        Ok((value.to_owned(), bytes))
    };
    if let Some(usage) = text("use")
        && usage != "sig"
    {
        return Err(format!("the JWK is for `{usage}`, not signatures"));
    }
    let (algorithm, key) = match (text("kty"), text("crv")) {
        (Some("OKP"), Some("Ed25519")) => {
            let (_, key) = coordinate("x")?;
            if key.len() != 32 {
                return Err("an Ed25519 key is 32 bytes".to_owned());
            }
            if has_small_order(&key) {
                return Err(
                    "the Ed25519 key is a point of small order, which verifies forged signatures"
                        .to_owned(),
                );
            }
            (EDDSA, key)
        }
        (Some("EC"), Some("P-256")) => {
            let (_, x_bytes) = coordinate("x")?;
            let (_, y_bytes) = coordinate("y")?;
            if x_bytes.len() != 32 || y_bytes.len() != 32 {
                return Err("a P-256 key's coordinates are 32 bytes each".to_owned());
            }
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend(x_bytes);
            point.extend(y_bytes);
            (ES256, point)
        }
        (kty, crv) => {
            return Err(format!(
                "a key of `{}` `{}`: only `OKP` `Ed25519` and `EC` `P-256` are accepted",
                kty.unwrap_or(""),
                crv.unwrap_or("")
            ));
        }
    };
    if let Some(declared) = text("alg")
        && declared != algorithm
    {
        return Err(format!(
            "the JWK declares `{declared}`, and its key is for `{algorithm}`"
        ));
    }
    let key_id = thumbprint(algorithm, &key).ok_or("the key has no thumbprint")?;
    Ok(PublicKey {
        algorithm,
        key,
        key_id,
    })
}

/// The RFC 7638 thumbprint of a key as the directory keeps it: the required members in
/// lexicographic order, no whitespace, SHA-256, base64url. `None` for a key of another size.
pub fn thumbprint(algorithm: &str, key: &[u8]) -> Option<String> {
    let canonical = match (algorithm, key.len()) {
        (EDDSA, 32) => serde_json::json!({
            "crv": "Ed25519", "kty": "OKP", "x": URL_SAFE_NO_PAD.encode(key)
        }),
        (ES256, 65) if key[0] == 0x04 => serde_json::json!({
            "crv": "P-256",
            "kty": "EC",
            "x": URL_SAFE_NO_PAD.encode(&key[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&key[33..]),
        }),
        _ => return None,
    };
    // serde_json orders a map's keys and writes it compact.
    Some(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.to_string().as_bytes())))
}

/// The encodings of the Ed25519 points of small order, the sign bit cleared (libsodium's
/// blocklist): such a public key verifies a signature it never made, so none is ever kept.
const SMALL_ORDER: [[u8; 32]; 7] = [
    // 0, order 4.
    [0; 32],
    // 1, order 1.
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    // Order 8.
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
    // Order 8.
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
    // p - 1, order 2.
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // p, the non-canonical 0.
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // p + 1, the non-canonical 1.
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

/// Whether `key` encodes an Ed25519 point of small order, whatever its sign bit.
pub fn has_small_order(key: &[u8]) -> bool {
    let Ok(mut point) = <[u8; 32]>::try_from(key) else {
        return false;
    };
    point[31] &= 0x7f;
    SMALL_ORDER.contains(&point)
}

/// Reads a `tls_client_auth` binding: `spki:sha256:` and 64 lowercase hex characters, one key; or
/// a SAN URI, every certificate the client CA issues with it. A URI never begins with a prefix the
/// Host reserves, in any case: `spki:` is a digest in its one canonical spelling or nothing, so one
/// key is never bound twice under two spellings.
pub fn binding(certificate: &str) -> Result<String, String> {
    if let Some(hex) = certificate.strip_prefix("spki:sha256:")
        && hex.len() == 64
        && hex
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Ok(certificate.to_owned());
    }
    if certificate
        .get(..5)
        .is_some_and(|head| head.eq_ignore_ascii_case("spki:"))
    {
        return Err("an SPKI binding is `spki:sha256:` and 64 lowercase hex characters".to_owned());
    }
    if super::directory::is_reserved(certificate) {
        return Err(format!(
            "`{certificate}` names a principal the Host reserves, not a certificate"
        ));
    }
    let uri = certificate.split_once(':').is_some_and(|(scheme, rest)| {
        !scheme.is_empty()
            && scheme
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphabetic())
            && scheme
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
            && !rest.is_empty()
    });
    if !uri || certificate.len() > 512 || Principal::new(certificate).is_err() {
        return Err(format!(
            "`{certificate}` is neither `spki:sha256:<64 hex>` nor a SAN URI"
        ));
    }
    Ok(certificate.to_owned())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn jwk(members: &[(&str, &str)]) -> BTreeMap<String, String> {
        members
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    /// RFC 8037 appendix A.2 and A.3: the Ed25519 key and its RFC 7638 thumbprint.
    #[test]
    fn an_ed25519_key_reads_with_its_rfc_8037_thumbprint() {
        let key = public_key(&jwk(&[
            ("kty", "OKP"),
            ("crv", "Ed25519"),
            ("x", "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"),
        ]))
        .expect("the key reads");
        assert_eq!(key.algorithm, EDDSA);
        assert_eq!(key.key.len(), 32);
        assert_eq!(key.key_id, "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
    }

    /// The thumbprint is over the required members only: `kid`, `alg` and `use` change nothing.
    #[test]
    fn a_p256_key_reads_and_its_thumbprint_ignores_optional_members() {
        let x = URL_SAFE_NO_PAD.encode([1u8; 32]);
        let y = URL_SAFE_NO_PAD.encode([2u8; 32]);
        let bare = public_key(&jwk(&[
            ("kty", "EC"),
            ("crv", "P-256"),
            ("x", &x),
            ("y", &y),
        ]))
        .expect("the key reads");
        let decorated = public_key(&jwk(&[
            ("kty", "EC"),
            ("crv", "P-256"),
            ("x", &x),
            ("y", &y),
            ("kid", "mine"),
            ("alg", "ES256"),
            ("use", "sig"),
        ]))
        .expect("the key reads");
        assert_eq!(bare.algorithm, ES256);
        assert_eq!(bare.key.len(), 65);
        assert_eq!(bare.key[0], 0x04);
        assert_eq!(bare.key_id, decorated.key_id);
    }

    #[test]
    fn a_private_key_another_curve_a_wrong_size_or_a_mismatched_alg_is_refused() {
        let x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
        for (members, why) in [
            (
                vec![("kty", "OKP"), ("crv", "Ed25519"), ("x", x), ("d", x)],
                "private",
            ),
            (vec![("kty", "OKP"), ("crv", "X25519"), ("x", x)], "only"),
            (vec![("kty", "RSA"), ("n", x), ("e", "AQAB")], "only"),
            (
                vec![("kty", "OKP"), ("crv", "Ed25519"), ("x", "AAAA")],
                "32 bytes",
            ),
            (
                vec![
                    ("kty", "OKP"),
                    ("crv", "Ed25519"),
                    ("x", x),
                    ("alg", "ES256"),
                ],
                "declares",
            ),
            (
                vec![("kty", "OKP"), ("crv", "Ed25519"), ("x", x), ("use", "enc")],
                "signatures",
            ),
            (
                vec![("kty", "OKP"), ("crv", "Ed25519"), ("x", "not base64!")],
                "base64url",
            ),
        ] {
            let refused = public_key(&jwk(&members)).expect_err(why);
            assert!(refused.contains(why), "{members:?}: {refused}");
        }
    }

    /// A small-order Ed25519 point, under either sign bit, would verify a forged signature.
    #[test]
    fn a_small_order_ed25519_key_is_refused() {
        for point in SMALL_ORDER {
            for sign in [0u8, 0x80] {
                let mut key = point;
                key[31] |= sign;
                let refused = public_key(&jwk(&[
                    ("kty", "OKP"),
                    ("crv", "Ed25519"),
                    ("x", &URL_SAFE_NO_PAD.encode(key)),
                ]))
                .expect_err("small order");
                assert!(refused.contains("small order"), "{refused}");
            }
        }
        // The RFC 8037 key is not one of them.
        assert!(!has_small_order(
            &URL_SAFE_NO_PAD
                .decode("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
                .expect("base64url")
        ));
    }

    #[test]
    fn the_thumbprint_reads_back_from_the_kept_key() {
        let x = URL_SAFE_NO_PAD.encode([1u8; 32]);
        let y = URL_SAFE_NO_PAD.encode([2u8; 32]);
        let read = public_key(&jwk(&[
            ("kty", "EC"),
            ("crv", "P-256"),
            ("x", &x),
            ("y", &y),
        ]))
        .expect("the key reads");
        assert_eq!(thumbprint(ES256, &read.key), Some(read.key_id));
        assert_eq!(thumbprint(ES256, &[4; 32]), None);
        assert_eq!(thumbprint("RS256", &[4; 32]), None);
    }

    #[test]
    fn a_drawn_secret_has_the_prefix_and_never_repeats() {
        let first = draw_secret().expect("drawn");
        let second = draw_secret().expect("drawn");
        assert!(is_secret(&first) && is_secret(&second));
        assert_ne!(first, second);
        assert!(first.starts_with(SECRET_PREFIX));
        assert_eq!(first.len(), SECRET_PREFIX.len() + 43);
        assert!(!is_secret("pgc_short"));
        assert!(!is_secret(&first.replacen(SECRET_PREFIX, "pgs_", 1)));
    }

    #[test]
    fn a_binding_is_an_spki_digest_or_a_san_uri() {
        let digest = format!("spki:sha256:{}", "ab".repeat(32));
        assert_eq!(binding(&digest).expect("a digest"), digest);
        assert_eq!(
            binding("spiffe://acme/billing").expect("a URI"),
            "spiffe://acme/billing"
        );
        for refused in [
            format!("spki:sha256:{}", "AB".repeat(32)),
            format!("SPKI:SHA256:{}", "ab".repeat(32)),
            "spki:sha256:abc".to_owned(),
            "sa:billing".to_owned(),
            "User:alice".to_owned(),
            "oidc:https://login.example#1".to_owned(),
            "billing".to_owned(),
            String::new(),
            format!("spiffe://acme/{}", "a".repeat(600)),
        ] {
            assert!(binding(&refused).is_err(), "{refused}");
        }
    }
}
