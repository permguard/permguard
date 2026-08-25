// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! How this CLI tells an operator what went over the wire: dim `[verbose]`
//! lines on stderr, one per exchange, and nothing at all without `-v`.
//!
//! The transports raise the event; deciding it is worth printing — and in
//! which colour — is the CLI's business, which is why this lives here and
//! not in the client crate.

use permguard_control_client::narrate::{Narrator, Silent};

use crate::style;

/// Prints one dim line per exchange, on stderr so it never pollutes a report
/// a script is parsing.
pub struct Verbose;

impl Narrator for Verbose {
    fn exchange(&self, verb: &str, target: &str, sent: usize, outcome: &str, received: usize) {
        let line = if verb == "rpc" {
            format!("[verbose] rpc {target} -> {outcome}")
        } else {
            format!("[verbose] {verb} {target} ({sent}b) -> {outcome} ({received}b)")
        };
        eprintln!("{}", style::dim(&line));
    }
}

/// The narrator a run asks for: verbose or silent.
pub fn for_run(verbose: bool) -> Box<dyn Narrator> {
    if verbose {
        Box::new(Verbose)
    } else {
        Box::new(Silent)
    }
}
