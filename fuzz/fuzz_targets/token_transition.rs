// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;

use permguard_authority_plane::tokens::{TokenTransition, status};

fuzz_target!(|data: &[u8]| {
    // A status a caller names to filter the tokens listed.
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = status::parse(text);
    }
    if let Ok(transition) = TokenTransition::decode(data) {
        // Whatever decodes re-encodes to the same bytes: the format has one encoding.
        assert_eq!(transition.encode().ok().as_deref(), Some(data));
    }
});
