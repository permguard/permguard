// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use permguard_objects::crypto::suite::{Suite, is_low_s};

// One byte picks the suite, then the public key, the 64-byte signature and the message.
fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let suite = Suite::ALL[usize::from(selector) % Suite::ALL.len()];
    let key_len = suite.public_key_len();
    if rest.len() < key_len + Suite::SIGNATURE_LEN {
        return;
    }
    let (public_key, rest) = rest.split_at(key_len);
    let (signature, message) = rest.split_at(Suite::SIGNATURE_LEN);
    if Suite::verify(suite, public_key, message, signature).is_ok() && suite == Suite::P256Sha256V1
    {
        assert!(is_low_s(&signature[32..]), "a high-s signature verified");
    }
});
