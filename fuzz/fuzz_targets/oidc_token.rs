// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;

use permguard_host::authz::oidc::{OidcRule, Verifier};
use permguard_host::time::TimeGuard;

/// One verifier over a fixed Ed25519 key set, built once: the token is the input under test.
fn verifier() -> &'static Verifier {
    static VERIFIER: OnceLock<Verifier> = OnceLock::new();
    VERIFIER.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("permguard-fuzz-oidc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("the scratch directory is created");
        let file = dir.join("jwks.json");
        // RFC 8037 appendix A.2's public key, as a JWKS.
        std::fs::write(
            &file,
            r#"{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","alg":"EdDSA","use":"sig","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}"#,
        )
        .expect("the key set is written");
        Verifier::new(
            OidcRule {
                issuer: "https://login.example".to_owned(),
                audience: "permguard".to_owned(),
                algorithms: vec!["EdDSA".to_owned()],
                claim: "sub".to_owned(),
                jwks_file: file,
                max_stale: std::time::Duration::from_secs(86_400),
            },
            0,
            Arc::new(TimeGuard::system(std::time::Duration::from_secs(30))),
        )
        .expect("the verifier builds")
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(token) = std::str::from_utf8(data) else {
        return;
    };
    let _ = Verifier::verify(verifier(), token);
});
