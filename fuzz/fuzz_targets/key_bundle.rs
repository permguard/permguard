// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;

use permguard_host::keys::bundle::{self, Frontier, Item, Manifest};

fuzz_target!(|data: &[u8]| {
    // Whatever decodes re-encodes to the same bytes: each record has one encoding.
    if let Ok(item) = Item::decode(data) {
        assert_eq!(item.encode().ok().as_deref(), Some(data));
    }
    if let Ok(frontier) = Frontier::decode(data) {
        assert_eq!(frontier.encode().ok().as_deref(), Some(data));
    }
    if let Ok(manifest) = Manifest::decode(data) {
        assert_eq!(manifest.encode().ok().as_deref(), Some(data));
    }
    // A bundle split anywhere into a manifest and one item: never a panic, never verified
    // without the identity it pins.
    let cut = data.first().map_or(0, |first| usize::from(*first)).min(data.len());
    let (manifest, item) = data.split_at(cut);
    assert!(bundle::verify(manifest, &[item.to_vec()], "pin", "host").is_err());
});
