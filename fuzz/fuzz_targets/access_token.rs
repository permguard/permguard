// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

use permguard_host::authz::access_tokens::{self, Anchor};
use permguard_host::membership::token_status::{HeldLists, PinnedKey};

/// One anchor over RFC 8037 appendix A.2's public key, and no list held: the token is the input
/// under test, and whatever it claims it is refused by step 7 at the latest.
fn anchors() -> &'static [Anchor] {
    static ANCHORS: OnceLock<Vec<Anchor>> = OnceLock::new();
    ANCHORS.get_or_init(|| {
        vec![Anchor {
            issuer: "urn:permguard:iam:0198f2aa-0000-7000-8000-000000000001".to_owned(),
            tenant: "default".to_owned(),
            keys: vec![PinnedKey {
                kid: "iam.tokens:k1".to_owned(),
                algorithm: "EdDSA",
                public_key: vec![
                    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9,
                    0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02,
                    0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
                ],
            }],
            member: "member:0198f2aa-0000-7000-8000-000000000002".to_owned(),
            groups: vec!["group:eu".to_owned()],
        }]
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(token) = std::str::from_utf8(data) else {
        return;
    };
    let _ = access_tokens::is_access_token(token);
    let lists = HeldLists::in_memory();
    assert!(
        access_tokens::verify(token, anchors(), &lists, Some("00"), 1_800_000_000).is_err(),
        "nothing verifies without the list it names"
    );
});
