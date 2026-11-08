// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;

use permguard_host::membership::token_status::{Request, decode_index, decode_list};

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = Request::decode(data) {
        // Whatever decodes re-encodes to the same bytes: the format has one encoding.
        assert_eq!(request.encode().ok().as_deref(), Some(data));
    }
    // The answers a member reads come from its coordinator over the same channel.
    let _ = decode_index(data);
    let _ = decode_list(data);
});
