// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;

use permguard_host::audit::checkpoint::Keys;

/// The RFC 8032 section 7.1 test 2 key as a `host.operations` JWK: a set no fuzzed seal is
/// signed by.
const KEYS: &str = r#"{"keys":[{"kid":"host.operations:FtIu-VbGrfe_KB6CH7GNwODB72MNxj_ml11dEvO-7kk","kty":"OKP","crv":"Ed25519","x":"PUAXw-hDiVqStwqnTRt-vJyYLM8uxJaMwM1V8Sr0Zgw","alg":"EdDSA","use":"sig"}]}"#;

fuzz_target!(|data: &[u8]| {
    // A legacy chain directory holding one day and one seal of the fuzzed bytes: refused or read,
    // never a panic.
    let dir = std::env::temp_dir().join(format!("permguard-fuzz-audit-legacy-{}", std::process::id()));
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let (day, seal) = data.split_at(data.len() / 2);
    if std::fs::write(dir.join("audit-2026-01-01.jsonl"), day).is_err()
        || std::fs::write(dir.join("audit-2026-01-01.seal"), seal).is_err()
    {
        return;
    }
    let _ = permguard_host::audit::jsonl::verify(&dir, None);
    // With keys, a signed seal reaches the signature check: refused, never a panic.
    if let Ok(keys) = Keys::from_document(KEYS) {
        let _ = permguard_host::audit::jsonl::verify(&dir, Some(&keys));
    }
});
