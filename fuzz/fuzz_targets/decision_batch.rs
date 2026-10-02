// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use permguard_core::Jwk;
use permguard_decisions::{Batch, Signed, chain};

/// The one key the verifier trusts: RFC 8037's, so no input can carry a key the verifier accepts.
fn keys() -> Vec<Jwk> {
    vec![
        serde_json::from_value(serde_json::json!({
            "kid": "data.attest:fuzz", "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        }))
        .expect("the key is a JWK"),
    ]
}

// A decision batch as a peer sends it: decoded, its JWS signature verified, its chain walked.
fuzz_target!(|data: &[u8]| {
    if let Ok(batch) = Batch::decode(data) {
        let _ = Signed::verify(&batch.signature, &keys());
        let _ = chain::verify(&batch.records, None);
    }
});
