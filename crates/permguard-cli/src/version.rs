// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What this binary is.

use std::io::{self, Write};

use permguard_core::brand;
use serde::Serialize;

use crate::output::Report;

/// The build this CLI came from.
#[derive(Debug, Serialize)]
pub struct VersionReport {
    /// The name this binary is invoked as.
    pub binary: &'static str,
    /// The version it was compiled at.
    pub version: &'static str,
    /// The commit it was built from, or `unknown` for a build nothing stamped.
    pub commit: &'static str,
    /// The copyright year.
    pub copyright_year: &'static str,
    /// Who holds the copyright.
    pub copyright_holder: &'static str,
}

/// Reports what this binary is.
pub fn version() -> VersionReport {
    VersionReport {
        binary: "permguard",
        version: env!("CARGO_PKG_VERSION"),
        // The same environment variable the planes read, so every Permguard binary in a release
        // reports the same commit, and an unstamped local build says so instead of guessing.
        commit: option_env!("PERMGUARD_BUILD_COMMIT").unwrap_or("unknown"),
        copyright_year: brand::PERMGUARD_COPYRIGHT_YEAR,
        copyright_holder: brand::PERMGUARD_COPYRIGHT_HOLDER,
    }
}

impl Report for VersionReport {
    /// The one answer that is about the product rather than about a resource:
    /// the banner is its context, everywhere else it is noise.
    fn wants_banner(&self) -> bool {
        true
    }

    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(out, "{} {}", self.binary, self.version)?;
        writeln!(out, "  commit:    {}", self.commit)?;
        writeln!(
            out,
            "  copyright: © {} {}",
            self.copyright_year, self.copyright_holder
        )
    }
}
