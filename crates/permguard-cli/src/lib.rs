// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The library half of the CLI: the workspace engine, exposed so the
//! integration tests can drive it in-process. The binary in `main.rs` is
//! the product; this exists for the tests and for nothing else.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

pub mod engine;
