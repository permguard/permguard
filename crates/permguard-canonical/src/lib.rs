#![forbid(unsafe_code)]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The canonical primitives independent protocols share (the crate boundaries refactoring,
//! RD-16): what a signature, a digest or a history key is computed over, with no storage, no
//! stream and no runtime in it.
//!
//! | Module     | What it is                                                                       |
//! | ---------- | -------------------------------------------------------------------------------- |
//! | [`jcs`]    | RFC 8785 canonical JSON, strict parsing and the decoding of canonical bytes      |
//! | [`merkle`] | the Merkle tree over a batch, its inclusion paths and their verification         |
//! | [`time`]   | the canonical instant of the temporal protocol, as epoch seconds and back        |
//!
//! Decision evidence, event evidence, the policy languages' descriptors and attestations and the
//! streams all compute over these, and none owns them: here a wire-model consumer reaches them
//! without linking a store or a stream engine.

pub mod jcs;
pub mod merkle;
pub mod time;
