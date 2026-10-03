// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;

use permguard_stream::jcs;

fuzz_target!(|data: &[u8]| {
    // What the strict reader accepts, the canonicaliser writes, and the canonical bytes read back
    // to the same value and are a fixed point: no input makes the profile disagree with itself.
    if let Ok(value) = jcs::parse_strict(data) {
        let canonical = jcs::canonicalize(&value).expect("an accepted value canonicalises");
        let again = jcs::decode_canonical(&canonical).expect("canonical bytes decode");
        assert_eq!(
            jcs::canonicalize(&again).expect("a decoded value canonicalises"),
            canonical
        );
    }
    if let Ok(value) = jcs::decode_canonical(data) {
        assert_eq!(jcs::canonicalize(&value).ok().as_deref(), Some(data));
    }
});
