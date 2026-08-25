// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! How an exchange is told, without deciding where it is told to.
//!
//! The CLI prints `[verbose] POST … -> 200` on stderr when `-v` is given; a
//! server logs the same fact through `tracing`, inside whatever span is
//! current. Both are the same event described differently, so the transports
//! raise it and the caller decides what it means.

/// Told once per exchange, by whichever transport made it.
pub trait Narrator: Send + Sync {
    /// One finished exchange: the verb (`POST`, or an RPC name), what it
    /// addressed, how many bytes went each way, and how it ended.
    fn exchange(&self, verb: &str, target: &str, sent: usize, outcome: &str, received: usize);
}

/// A narrator that says nothing — the default, so a caller that does not
/// care pays a branch and no allocation.
#[derive(Debug, Clone, Copy, Default)]
pub struct Silent;

impl Narrator for Silent {
    fn exchange(&self, _verb: &str, _target: &str, _sent: usize, _outcome: &str, _received: usize) {
    }
}
