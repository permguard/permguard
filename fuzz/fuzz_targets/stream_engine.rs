// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;

use permguard_stream::engine::{self, RunEnd, RunStatement, State, encode_group};

fuzz_target!(|data: &[u8]| {
    // Whatever decodes re-encodes to the same bytes: each record of the engine has one encoding.
    if let Ok(statement) = RunStatement::decode(data) {
        assert_eq!(statement.encode().ok().as_deref(), Some(data));
    }
    if let Ok(end) = RunEnd::decode(data) {
        assert_eq!(end.encode().ok().as_deref(), Some(data));
    }
    if let Ok(state) = State::decode(data) {
        assert_eq!(state.encode().ok().as_deref(), Some(data));
    }
    if let Ok((first, records)) = engine::decode_group(data) {
        let encoded = encode_group(first, records.iter().map(Vec::as_slice)).ok();
        assert_eq!(encoded.as_deref(), Some(data));
    }
});
