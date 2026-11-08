// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A service account's credential material as the IAM Host takes it (TC-6, `2-security/7`
//! Service accounts): the readers `iam credentials create` and Permguard Admin share. Each takes
//! the file's bytes and says why it refuses them, so its caller names the file its own way. A
//! private key is refused before anything leaves its holder.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The most a key or certificate file may hold.
const MAX_BYTES: usize = 64 * 1024;

/// A public key as the IAM Host takes it, its JWK members: an Ed25519 or P-256 JWK, or the same
/// key in a PEM `PUBLIC KEY` (SubjectPublicKeyInfo). A JWK carrying `d` is a private key, refused.
pub fn public_key(bytes: &[u8]) -> Result<BTreeMap<String, String>, String> {
    use rustls::pki_types::pem::PemObject as _;

    if bytes.len() > MAX_BYTES {
        return Err("larger than a public key".to_owned());
    }
    if let Ok(jwk) = serde_json::from_slice::<BTreeMap<String, serde_json::Value>>(bytes) {
        // The public members only: a JWK carrying `d` is a private key, refused.
        if jwk.contains_key("d") {
            return Err(
                "is a private key: give the public key, the private one never leaves its holder"
                    .to_owned(),
            );
        }
        return Ok(jwk
            .into_iter()
            .filter(|(name, _)| matches!(name.as_str(), "kty" | "crv" | "x" | "y"))
            .filter_map(|(name, value)| value.as_str().map(|text| (name, text.to_owned())))
            .collect());
    }
    let der = rustls::pki_types::SubjectPublicKeyInfoDer::from_pem_slice(bytes)
        .map_err(|_| "is neither a JWK nor a PEM public key".to_owned())?;
    let der = der.as_ref();
    // The two encodings RFC 8410 and RFC 5480 give, their fixed prefixes before the key.
    const ED25519: &[u8] = &[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    const P256: &[u8] = &[
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    if let Some(key) = der.strip_prefix(ED25519).filter(|key| key.len() == 32) {
        return Ok(BTreeMap::from([
            ("kty".to_owned(), "OKP".to_owned()),
            ("crv".to_owned(), "Ed25519".to_owned()),
            ("x".to_owned(), URL_SAFE_NO_PAD.encode(key)),
        ]));
    }
    if let Some(point) = der
        .strip_prefix(P256)
        .filter(|point| point.len() == 65 && point[0] == 0x04)
    {
        return Ok(BTreeMap::from([
            ("kty".to_owned(), "EC".to_owned()),
            ("crv".to_owned(), "P-256".to_owned()),
            ("x".to_owned(), URL_SAFE_NO_PAD.encode(&point[1..33])),
            ("y".to_owned(), URL_SAFE_NO_PAD.encode(&point[33..])),
        ]));
    }
    Err("is neither an Ed25519 nor a P-256 public key".to_owned())
}

/// The `spki:sha256:` binding of a PEM certificate's public key, as the IAM Host matches a
/// connection's certificate.
pub fn certificate_binding(bytes: &[u8]) -> Result<String, String> {
    use rustls::pki_types::pem::PemObject as _;

    if bytes.len() > MAX_BYTES {
        return Err("larger than a certificate".to_owned());
    }
    let certificate = rustls::pki_types::CertificateDer::from_pem_slice(bytes)
        .map_err(|_| "is not a PEM certificate".to_owned())?;
    let identity = permguard_transport::identity_of(&certificate)
        .ok_or_else(|| "does not parse as an X.509 certificate".to_owned())?;
    let digest = identity
        .spki_sha256()
        .ok_or_else(|| "carries no public key".to_owned())?;
    Ok(format!("spki:sha256:{digest}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn a_public_key_reads_from_a_jwk_or_a_pem_and_a_private_key_is_refused() {
        let jwk = br#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"ignored"}"#;
        let read = public_key(jwk).expect("a JWK");
        assert_eq!(read.get("crv").map(String::as_str), Some("Ed25519"));
        assert!(!read.contains_key("kid"), "only the public members");
        let private = br#"{"kty":"OKP","crv":"Ed25519","x":"AAAA","d":"BBBB"}"#;
        assert!(public_key(private).is_err_and(|why| why.contains("private key")));
        let pkcs8 =
            ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                .expect("a key");
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("a pair");
        let mut spki = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        spki.extend_from_slice(ring::signature::KeyPair::public_key(&pair).as_ref());
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(&spki)
        );
        let read = public_key(pem.as_bytes()).expect("a PEM public key");
        assert_eq!(
            read.get("x").map(String::as_str),
            Some(
                URL_SAFE_NO_PAD
                    .encode(ring::signature::KeyPair::public_key(&pair).as_ref())
                    .as_str()
            )
        );
        assert!(public_key(b"not a key").is_err());
        assert!(public_key(&vec![b' '; MAX_BYTES + 1]).is_err());
    }

    #[test]
    fn a_certificate_binds_by_its_public_keys_digest() {
        let key = rcgen::KeyPair::generate().expect("a key");
        let certificate = rcgen::CertificateParams::new(vec!["client.example".to_owned()])
            .expect("parameters")
            .self_signed(&key)
            .expect("a certificate");
        let binding = certificate_binding(certificate.pem().as_bytes()).expect("a binding");
        assert!(binding.starts_with("spki:sha256:") && binding.len() == "spki:sha256:".len() + 64);
        assert!(
            certificate_binding(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
                .is_err()
        );
        assert!(certificate_binding(key.serialize_pem().as_bytes()).is_err());
    }
}
