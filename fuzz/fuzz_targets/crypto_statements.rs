// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use permguard_objects::crypto::kdf::Info;
use permguard_objects::crypto::mac;
use permguard_objects::crypto::thumbprint::KeySet;

// The closed CBOR forms of the cryptographic profile, a key-set statement and a KDF info tuple,
// whatever decodes re-encoding to the same bytes; and a MAC tag presented by a caller.
fuzz_target!(|data: &[u8]| {
    if let Ok(set) = KeySet::decode(data) {
        assert_eq!(set.encode(), data);
    }
    if let Ok(info) = Info::decode(data) {
        assert_eq!(info.encode().ok().as_deref(), Some(data));
    }
    let (tag, message) = data.split_at(data.len().min(32));
    assert!(!mac::verify(&[7u8; 32], "permguard.fuzz.v1\n", message, tag) || tag.len() == 32);
});
