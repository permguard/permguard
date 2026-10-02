// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use permguard_core::Jwk;
use permguard_events::{Batch, Signed, chain};

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

fn exercise(batch: &Batch) {
    let _ = Signed::verify(&batch.signature, &keys());
    let _ = chain::verify(&batch.records, None);
}

// The two wire forms of one batch: one JSON body over HTTP, and the envelope with one byte string
// per record over gRPC. The first byte splits the input into parts for the second.
fuzz_target!(|data: &[u8]| {
    if let Ok(batch) = Batch::decode(data) {
        exercise(&batch);
    }

    let Some((&count, rest)) = data.split_first() else {
        return;
    };
    let mut parts = rest.chunks(rest.len() / (usize::from(count % 8) + 1) + 1);
    let envelope = parts.next().unwrap_or_default();
    let records: Vec<Vec<u8>> = parts.map(<[u8]>::to_vec).collect();
    if let Ok(batch) = Batch::from_wire_parts(envelope, &records) {
        exercise(&batch);
    }
});
