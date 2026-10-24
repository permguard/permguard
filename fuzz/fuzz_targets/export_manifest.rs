// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;

use permguard_host::exports::{self, Manifest};

fuzz_target!(|data: &[u8]| {
    if let Ok(manifest) = Manifest::decode(data) {
        // Whatever decodes re-encodes to the same bytes: the format has one encoding.
        assert_eq!(manifest.encode().ok().as_deref(), Some(data));
    }
    // A manifest and a bundle an import is handed, under a pin nothing matches: refused, never a
    // panic.
    assert!(exports::verify(data, data, &[data.to_vec()], "pin").is_err());
});
