// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;

use permguard_host::authz::record::GrantRecord;

fuzz_target!(|data: &[u8]| {
    if let Ok(record) = GrantRecord::decode(data) {
        // Whatever decodes re-encodes to the same bytes: the format has one encoding.
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
});
