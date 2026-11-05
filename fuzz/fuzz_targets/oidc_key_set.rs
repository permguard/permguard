// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A provider's key set as the refresh task hands it over: whatever arrives is parsed, filtered
//! and either held or refused, never a panic.

#![no_main]

use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;
use permguard_host::authz::oidc::{KeySource, OidcRule, Verifier};
use permguard_host::time::TimeGuard;

fn verifier() -> &'static Verifier {
    static VERIFIER: OnceLock<Verifier> = OnceLock::new();
    VERIFIER.get_or_init(|| {
        Verifier::new(
            OidcRule {
                name: "fuzz".to_owned(),
                issuer: "https://login.example".to_owned(),
                audience: "permguard".to_owned(),
                algorithms: vec!["RS256".to_owned(), "ES256".to_owned(), "EdDSA".to_owned()],
                claim: "sub".to_owned(),
                keys: KeySource::Discovery,
                ca_file: None,
                refresh: std::time::Duration::from_secs(3_600),
                max_stale: std::time::Duration::from_secs(86_400),
                clients: Vec::new(),
                token_types: vec!["JWT".to_owned()],
                link_email: false,
            },
            0,
            Arc::new(TimeGuard::system(std::time::Duration::from_secs(30))),
        )
        .expect("the verifier builds")
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = verifier().install(data);
});
