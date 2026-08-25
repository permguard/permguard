// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the CLI says about what it is doing, and where it says it.
//!
//! Diagnostics go to **stderr**, always. Stdout carries the report and nothing else, so that
//! `permguard inspect -o json | jq` keeps working with `--verbose` on — a tool that mixes its
//! narration into its output is a tool that cannot be piped, and being pipeable is most of what a
//! CLI is for.

use std::fmt::Display;
use std::io::Write;

/// Whether the CLI narrates what it does.
#[derive(Copy, Clone, Debug)]
pub struct Trace {
    enabled: bool,
}

impl Trace {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Narrates one step, when asked to.
    pub fn say(&self, message: impl Display) {
        if !self.enabled {
            return;
        }

        let mut err = std::io::stderr().lock();
        let _ = writeln!(err, "· {message}");
    }
}

/// Says something the operator needs to see whether they asked for narration or not.
pub fn warn(message: impl Display) {
    let mut err = std::io::stderr().lock();
    let _ = writeln!(err, "warning: {message}");
}
