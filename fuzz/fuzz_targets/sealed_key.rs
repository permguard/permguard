// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;

use permguard_objects::crypto::seal::SealedKey;

fuzz_target!(|data: &[u8]| {
    if let Ok(sealed) = SealedKey::decode(data) {
        // Whatever decodes re-encodes to the same bytes: the format has one encoding.
        assert_eq!(sealed.encode().ok().as_deref(), Some(data));
    }
});
