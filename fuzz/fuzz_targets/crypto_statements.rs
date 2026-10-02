// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use permguard_objects::crypto::kdf::Info;
use permguard_objects::crypto::thumbprint::KeySet;

// The closed CBOR forms of the cryptographic profile: a key-set statement and a KDF info tuple.
// Whatever decodes re-encodes to the same bytes.
fuzz_target!(|data: &[u8]| {
    if let Ok(set) = KeySet::decode(data) {
        assert_eq!(set.encode(), data);
    }
    if let Ok(info) = Info::decode(data) {
        assert_eq!(info.encode().ok().as_deref(), Some(data));
    }
});
