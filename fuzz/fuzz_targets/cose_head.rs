// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use permguard_objects::statement::SignedHead;

fuzz_target!(|data: &[u8]| {
    if let Ok(head) = SignedHead::decode(data) {
        let _ = head.kid();
        let _ = head.statement_unverified();
        let _ = SignedHead::verify(&head, &[0u8; 32]);
    }
});
