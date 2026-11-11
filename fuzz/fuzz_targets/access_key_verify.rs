// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

use permguard_authority_plane::access_keys;

/// One Argon2id hash of a secret drawn once: what a presented secret is checked against.
fn held() -> &'static str {
    static HELD: OnceLock<String> = OnceLock::new();
    HELD.get_or_init(|| {
        let secret = access_keys::draw_secret_key().expect("a secret");
        access_keys::hash(secret.as_str()).expect("a hash")
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = access_keys::is_access_key(text);
    // A secret presented at the token endpoint never verifies against another's hash.
    assert!(!access_keys::verify(text, held()));
});
