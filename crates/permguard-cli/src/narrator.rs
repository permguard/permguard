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

/// Prints one dim line per exchange, on the diagnostics so it never pollutes
/// a report a script is parsing. It keeps the capture of the run that made it:
/// the transports may narrate from another thread.
pub struct Verbose {
    capture: Option<crate::streams::Capture>,
}

impl Narrator for Verbose {
    fn exchange(&self, verb: &str, target: &str, sent: usize, outcome: &str, received: usize) {
        let line = if verb == "rpc" {
            format!("[verbose] rpc {target} -> {outcome}")
        } else {
            format!("[verbose] {verb} {target} ({sent}b) -> {outcome} ({received}b)")
        };
        let line = format!("{}\n", style::dim(&line));
        let _ = match &self.capture {
            Some(capture) => capture.err(|out| out.write_all(line.as_bytes())),
            None => crate::streams::err(|out| out.write_all(line.as_bytes())),
        };
    }
}

/// The narrator a run asks for: verbose or silent.
pub fn for_run(verbose: bool) -> Box<dyn Narrator> {
    if verbose {
        Box::new(Verbose {
            capture: crate::streams::current(),
        })
    } else {
        Box::new(Silent)
    }
}
