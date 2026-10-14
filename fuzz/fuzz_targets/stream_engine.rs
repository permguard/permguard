// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;

use permguard_stream::engine::batch::SealedBatch;
use permguard_stream::engine::ingest::{Answer, Ship};
use permguard_stream::engine::{
    self, ConsumerState, Cutover, ForkMark, RunEnd, RunStatement, Spans, State, encode_group,
};

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
    if let Ok(spans) = Spans::decode(data) {
        assert_eq!(spans.encode().ok().as_deref(), Some(data));
    }
    if let Ok(cutover) = Cutover::decode(data) {
        assert_eq!(cutover.encode().ok().as_deref(), Some(data));
    }
    // A batch file is canonical JSON: what decodes re-encodes to the same bytes (WP-5.2).
    if let Ok(batch) = SealedBatch::decode(data) {
        assert_eq!(batch.encode().ok().as_deref(), Some(data));
    }
    // The ingest's message and answer, a consumer's STATE and fork mark (WP-5.3).
    if let Ok(ship) = Ship::decode(data) {
        assert_eq!(ship.encode().ok().as_deref(), Some(data));
    }
    if let Ok(answer) = Answer::decode(data) {
        assert_eq!(answer.encode().ok().as_deref(), Some(data));
    }
    if let Ok(state) = ConsumerState::decode(data) {
        assert_eq!(state.encode().ok().as_deref(), Some(data));
    }
    if let Ok(mark) = ForkMark::decode(data) {
        assert_eq!(mark.encode().ok().as_deref(), Some(data));
    }
});
