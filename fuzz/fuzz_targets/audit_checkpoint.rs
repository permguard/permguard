// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;

use permguard_host::audit::checkpoint::{Anchor, Checkpoint, Keys};

/// The RFC 8032 section 7.1 test 2 key as a `host.operations` JWK: a set no fuzzed envelope is
/// signed by.
const KEYS: &str = r#"{"keys":[{"kid":"host.operations:FtIu-VbGrfe_KB6CH7GNwODB72MNxj_ml11dEvO-7kk","kty":"OKP","crv":"Ed25519","x":"PUAXw-hDiVqStwqnTRt-vJyYLM8uxJaMwM1V8Sr0Zgw","alg":"EdDSA","use":"sig"}]}"#;

fuzz_target!(|data: &[u8]| {
    if let Ok(checkpoint) = Checkpoint::decode(data) {
        // Whatever decodes re-encodes to the same bytes: the format has one encoding.
        assert_eq!(checkpoint.encode().ok().as_deref(), Some(data));
    }
    if let Ok(anchor) = Anchor::decode(data) {
        assert_eq!(anchor.encode().ok().as_deref(), Some(data));
    }
    // An envelope from a volume or an export, under a key it was not signed by: refused, never a
    // panic.
    if let Ok(keys) = Keys::from_document(KEYS) {
        assert!(Keys::verify(&keys, data).is_err());
    }
});
