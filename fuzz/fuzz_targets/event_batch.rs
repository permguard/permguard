// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;

// The two wire forms of one batch: one JSON body over HTTP, and the envelope with one byte string
// per record over gRPC. The first byte splits the input into parts for the second.
fuzz_target!(|data: &[u8]| {
    let _ = permguard_events::Batch::decode(data);

    let Some((&count, rest)) = data.split_first() else {
        return;
    };
    let mut parts = rest.chunks(rest.len() / (usize::from(count % 8) + 1) + 1);
    let envelope = parts.next().unwrap_or_default();
    let records: Vec<Vec<u8>> = parts.map(<[u8]>::to_vec).collect();
    let _ = permguard_events::Batch::from_wire_parts(envelope, &records);
});
