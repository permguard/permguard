// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;

use permguard_host::operations::drain::{self, DrainReceipt};

fuzz_target!(|data: &[u8]| {
    if let Ok(receipt) = DrainReceipt::decode(data) {
        // Whatever decodes re-encodes to the same bytes: the format has one encoding.
        assert_eq!(receipt.encode().ok().as_deref(), Some(data));
    }
    // A receipt and a bundle a drain Job printed, as the drain controller reads them from its log:
    // refused under any pin, never a panic.
    assert!(drain::verify(data, data, &[data.to_vec()], "pin").is_err());
});
