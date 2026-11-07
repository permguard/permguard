// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;

use permguard_objects::status_list::{ENTRIES, StatusList};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for bits in [1, 2, 4, 8] {
        if let Ok(list) = StatusList::decode(bits, text, 1 << 20, ENTRIES) {
            // Never past the bound it was read under, and what it holds reads back.
            assert!(list.len() <= ENTRIES);
            let encoded = list.encode().expect("a decoded list encodes");
            let again = StatusList::decode(bits, &encoded, usize::MAX, ENTRIES)
                .expect("an encoded list decodes");
            assert_eq!(again, list);
        }
    }
});
