// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

use permguard_host::authz::access_tokens::{self, Anchor};
use permguard_host::authz::status_lists::{self, HeldLists, PinnedKey};

const ISSUER: &str = "https://authority.example:8443";

fn anchor() -> &'static Anchor {
    static ANCHOR: OnceLock<Anchor> = OnceLock::new();
    ANCHOR.get_or_init(|| Anchor {
        issuer: ISSUER.to_owned(),
        audience: "permguard".to_owned(),
        keys: vec![PinnedKey {
            kid: "authority.tokens:k1".to_owned(),
            algorithm: "EdDSA",
            public_key: vec![
                0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
                0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
                0xf7, 0x07, 0x51, 0x1a,
            ],
        }],
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(token) = std::str::from_utf8(data) else {
        return;
    };
    let _ = access_tokens::is_access_token(token);
    let _ = access_tokens::key_id_of(token);
    let lists = HeldLists::in_memory();
    assert!(
        access_tokens::verify(token, anchor(), &lists, 1_800_000_000).is_err(),
        "nothing verifies without the list it names"
    );
    // A status list token comes over the same network, from the same Authority Plane.
    let _ = status_lists::verify_list(token, &anchor().keys, ISSUER, None, 1_800_000_000);
});
