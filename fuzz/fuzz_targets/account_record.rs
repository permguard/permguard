// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;

use permguard_authority_plane::accounts::AccountRecord;
use permguard_authority_plane::cbor;

fuzz_target!(|data: &[u8]| {
    // The labelled map every record of the Authority Plane is read through.
    let _ = cbor::decode(data, 16);
    if let Ok(record) = AccountRecord::decode(data) {
        // Whatever decodes re-encodes to the same bytes: the format has one encoding.
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
});
