// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = permguard_stream::jcs::parse_strict(data);
    let _ = permguard_stream::jcs::decode_canonical(data);
});
