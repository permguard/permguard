// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use permguard_stream::cursor::{Cursor, CursorKey};

// A read cursor arrives as text from any caller; it must be refused, never trusted, unless this
// server sealed it for exactly this read.
fuzz_target!(|data: &[u8]| {
    let Ok(token) = std::str::from_utf8(data) else {
        return;
    };
    let key = CursorKey::new(&[7u8; 32], &[]).expect("a 32-byte key is accepted");
    let _ = Cursor::open(
        token,
        &key,
        "permguard.fuzz.v1",
        "zone-a/ledger-a",
        "filters",
    );
    // Either version (WP-5.5): a version 2 token is opened by its own rules, at any time.
    for now in [0, 1_800_000_000, u64::MAX] {
        let _ = Cursor::open_any(
            token,
            &key,
            "permguard.fuzz.v1",
            "zone-a/ledger-a",
            "filters",
            now,
        );
    }
});
