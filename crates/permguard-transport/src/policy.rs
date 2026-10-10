// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The algorithms every Permguard TLS endpoint negotiates, named here rather than inherited
//! (WP-2.11, owner decision of 2026-10-10).
//!
//! | Kind            | Allowed                                                                          |
//! | --------------- | -------------------------------------------------------------------------------- |
//! | TLS 1.3 suites  | `AES_256_GCM_SHA384`, `AES_128_GCM_SHA256`, `CHACHA20_POLY1305_SHA256`           |
//! | TLS 1.2 suites  | ECDHE with ECDSA or RSA, and AES-GCM or CHACHA20-POLY1305: forward secret, AEAD  |
//! | key exchange    | X25519, P-256, P-384                                                             |
//!
//! It is the set the `ring` provider offers today. Listing it is what keeps it: a provider that
//! gains a suite in a later release does not widen what a listener or the peer client accepts,
//! and a test fails instead. TLS 1.2 is still offered only where a listener's `min_version` asks
//! for it, which is the `tls.1_2_compat` relaxation.

use std::sync::Arc;

use rustls::SupportedCipherSuite;
use rustls::crypto::CryptoProvider;
use rustls::crypto::ring::{cipher_suite, default_provider, kx_group};

/// The cipher suites, TLS 1.3 first, each version strongest first.
pub const CIPHER_SUITES: [SupportedCipherSuite; 9] = [
    cipher_suite::TLS13_AES_256_GCM_SHA384,
    cipher_suite::TLS13_AES_128_GCM_SHA256,
    cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// The provider every listener and the peer client build their configuration on: the `ring`
/// primitives, restricted to [`CIPHER_SUITES`] and the three key-exchange groups.
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider {
        cipher_suites: CIPHER_SUITES.to_vec(),
        kx_groups: vec![kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1],
        ..default_provider()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_provider_offers_only_the_pinned_suites_and_groups() {
        let provider = provider();
        let suites: Vec<String> = provider
            .cipher_suites
            .iter()
            .map(|suite| format!("{:?}", suite.suite()))
            .collect();
        assert_eq!(
            suites,
            [
                "TLS13_AES_256_GCM_SHA384",
                "TLS13_AES_128_GCM_SHA256",
                "TLS13_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            ]
        );
        let groups: Vec<String> = provider
            .kx_groups
            .iter()
            .map(|group| format!("{:?}", group.name()))
            .collect();
        assert_eq!(groups, ["X25519", "secp256r1", "secp384r1"]);
        // Nothing the default provider offers differs silently either: when it gains, drops or
        // swaps a suite or a group, this list is reviewed rather than followed.
        let mut offered: Vec<String> = default_provider()
            .cipher_suites
            .iter()
            .map(|suite| format!("{:?}", suite.suite()))
            .collect();
        let mut pinned = suites.clone();
        offered.sort();
        pinned.sort();
        assert_eq!(offered, pinned, "the provider offers {offered:?}");
        let mut offered_groups: Vec<String> = default_provider()
            .kx_groups
            .iter()
            .map(|group| format!("{:?}", group.name()))
            .collect();
        let mut pinned_groups = groups.clone();
        offered_groups.sort();
        pinned_groups.sort();
        assert_eq!(offered_groups, pinned_groups);
    }
}
