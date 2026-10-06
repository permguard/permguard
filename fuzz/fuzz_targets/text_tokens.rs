// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::str::FromStr as _;

use permguard_core::ErrorClass;
use permguard_core::authz;
use permguard_core::catalog::Selector;
use permguard_objects::Digest;
use permguard_objects::manifest::HistoryScope;
use permguard_objects::semver::{Constraint, Version};
use permguard_stream::frontier::Frontier;
use permguard_stream::name::StreamPosition;

// Every short text token a request can carry: a digest, a version or a range, a history scope,
// a frontier, a stream position, a zone or ledger selector, and the error class an answer names.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = Digest::parse(text);
    let _ = Version::parse(text);
    let _ = Constraint::parse(text);
    let _ = HistoryScope::parse(text);
    let _ = Frontier::decode(text);
    let _ = StreamPosition::parse(text);
    let _ = Selector::parse(text);
    let _ = authz::Resource::parse(text);
    let _ = authz::Selector::parse(text);
    let _ = ErrorClass::from_str(text);
});
