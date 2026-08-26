// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The one place a command's answer becomes output.

use std::io::{self, Write};

use anyhow::Result;
use clap::ValueEnum;
use serde::Serialize;

/// How an answer is rendered.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    /// For a person: a banner, then a laid-out report.
    Terminal,
    /// For a program: JSON.
    Json,
    /// For a program, or a configuration file: YAML.
    #[value(alias = "yml")]
    Yaml,
}

/// What a command answers with, in a form every output format can render.
///
/// A command builds one of these and hands it to [`emit`]. It never decides how the answer is
/// rendered and never writes to stdout itself — so a new format is added once, here, rather than
/// once per command, and a command cannot support one format and quietly not another.
///
/// `Serialize` covers the machine-readable formats: they are the same data with a different
/// encoding, and neither wants a hand-written implementation. The terminal is the only format that
/// is a *presentation* rather than an encoding — field order, alignment, what to leave out when a
/// value would be meaningless — so it is the only one a report writes itself.
pub trait Report: Serialize {
    /// Writes the human-facing rendering of this answer.
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()>;

    /// Whether the terminal rendering opens with the product banner.
    ///
    /// It does **not**, by default: a command's output is the command's
    /// answer, and eleven lines of ASCII art before every `zones list` push
    /// the answer off the screen. The banner is identity, and identity has
    /// its moments — `--help`, the bare `permguard`, and `version` — not
    /// every invocation. The one report that is *about* the product opts in.
    fn wants_banner(&self) -> bool {
        false
    }
}

/// Renders a report in the requested format, to stdout.
pub fn emit<R: Report>(report: &R, format: OutputFormat) -> Result<()> {
    let mut out = io::stdout().lock();

    render(report, format, &mut out)?;
    out.flush()?;

    Ok(())
}

/// Renders a report to any sink, which is what makes the rendering testable without a process.
pub fn render<R: Report>(report: &R, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    match format {
        OutputFormat::Terminal => {
            // The banner belongs to the terminal rendering and to nothing else: it is decoration,
            // and decoration in a JSON document is a parse error waiting to happen.
            if report.wants_banner() {
                writeln!(out, "{}", crate::banner::banner())?;
                writeln!(out)?;
            }

            report.render_terminal(out)?;
        }
        OutputFormat::Json => writeln!(out, "{}", serde_json::to_string_pretty(report)?)?,
        OutputFormat::Yaml => write!(out, "{}", serde_norway::to_string(report)?)?,
    }

    Ok(())
}
