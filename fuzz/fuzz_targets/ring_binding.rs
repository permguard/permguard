// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;

use permguard_host::keys::record::Binding;
use permguard_host::keys::ring::verify_binding;
use permguard_objects::crypto::suite::Suite;

fuzz_target!(|data: &[u8]| {
    if let Ok(binding) = Binding::decode(data) {
        // Whatever decodes re-encodes to the same bytes: the format has one encoding.
        assert_eq!(binding.encode().ok().as_deref(), Some(data));
    }
    // A peer's envelope, under a key it was not signed by: refused, never a panic.
    assert!(
        verify_binding(
            data,
            Suite::Ed25519Sha256V1,
            &[0; 32],
            &[0; 16],
            "data.attest",
            0
        )
        .is_err()
    );
});
