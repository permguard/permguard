// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(head) = permguard_objects::statement::SignedHead::decode(data) {
        let _ = head.kid();
        let _ = head.statement_unverified();
        let _ = head.verify(&[0u8; 32]);
    }
});
