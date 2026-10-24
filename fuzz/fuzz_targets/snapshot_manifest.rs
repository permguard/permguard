// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;

use permguard_host::operations::backup::{self, SnapshotManifest};

fuzz_target!(|data: &[u8]| {
    if let Ok(manifest) = SnapshotManifest::decode(data) {
        // Whatever decodes re-encodes to the same bytes: the format has one encoding.
        assert_eq!(manifest.encode().ok().as_deref(), Some(data));
    }
    // A manifest and a bundle an operator hands an offline verification, over no snapshot at all:
    // refused, never a panic, and never a label.
    let missing = std::path::Path::new("/nonexistent/permguard-fuzz-snapshot");
    assert!(backup::verify(missing, data, data, &[data.to_vec()], "pin").is_err());
});
