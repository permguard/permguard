// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // A decoded value encodes back to exactly the bytes it came from.
    if let Ok(value) = permguard_objects::cbor::decode_canonical(data) {
        assert_eq!(
            permguard_objects::cbor::encode(&value).ok().as_deref(),
            Some(data)
        );
    }
});
