// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A sign-in's password against a held PHC string, and any PHC string: refused or checked,
//! never a panic, and never the work of a password over its bound.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use permguard_host::authz::password;

fn held() -> &'static str {
    static HELD: OnceLock<String> = OnceLock::new();
    HELD.get_or_init(|| password::hash("a long enough secret").expect("hashed"))
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = password::verify(text, held());
    let _ = password::verify("a long enough secret", text);
});
