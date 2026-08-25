// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! How much a build says, and in what shape it says it.
//!
//! Both are contracts rather than implementation: the types live here so configuration can carry
//! them and any build can honour them, while installing an actual subscriber is somebody else's job.
//!
//! The defaults are the production ones — [`LogLevel::Info`] and [`LogFormat::Json`] — because the
//! deployment that gets the defaults is the one nobody configured, and that is far more often a
//! container than a terminal.

use std::fmt;
use std::str::FromStr;

use anyhow::{Result, bail};

/// How much a build says.
///
/// The server lifecycle is deliberately split across two of these: `started` and `stopped` are
/// [`Info`](LogLevel::Info), while `starting` and `stopping` are [`Debug`](LogLevel::Debug). A
/// default deployment therefore records that the server came up and went down, and asking for
/// `debug` is what shows the transitions in between.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum LogLevel {
    /// Only failures that stopped something.
    Error,
    /// Failures something recovered from.
    Warn,
    /// The default: what a running server did, not how it did it.
    #[default]
    Info,
    /// The transitions between the states `info` reports.
    Debug,
    /// Everything, including per-request detail.
    Trace,
}

impl LogLevel {
    /// Returns the lowercase name this level is written as.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }

    /// Every level a configuration may name, for diagnostics.
    pub const ALL: [Self; 5] = [
        Self::Error,
        Self::Warn,
        Self::Info,
        Self::Debug,
        Self::Trace,
    ];
}

impl FromStr for LogLevel {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "error" => Ok(Self::Error),
            "warn" | "warning" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            other => bail!(
                "`{other}` is not a log level: expected one of {}",
                Self::ALL.map(|level| level.as_str()).join(", ")
            ),
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The shape a build writes its records in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    /// One JSON object per record: the default, and what a log pipeline can read.
    #[default]
    Json,
    /// Human-readable lines, for a terminal someone is actually looking at.
    Terminal,
}

impl LogFormat {
    /// Returns the lowercase name this format is written as.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Terminal => "terminal",
        }
    }

    /// Every format a configuration may name, for diagnostics.
    pub const ALL: [Self; 2] = [Self::Json, Self::Terminal];
}

impl FromStr for LogFormat {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "terminal" | "text" | "pretty" => Ok(Self::Terminal),
            other => bail!(
                "`{other}` is not a log format: expected one of {}",
                Self::ALL.map(|format| format.as_str()).join(", ")
            ),
        }
    }
}

impl fmt::Display for LogFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn test_the_defaults_are_the_production_ones() {
        assert_eq!(LogLevel::default(), LogLevel::Info);
        assert_eq!(LogFormat::default(), LogFormat::Json);
    }

    #[test]
    fn test_every_level_round_trips_through_its_name() {
        for level in LogLevel::ALL {
            assert_eq!(
                level.as_str().parse::<LogLevel>().expect("the name parses"),
                level
            );
            assert_eq!(level.to_string(), level.as_str());
        }
    }

    #[test]
    fn test_every_format_round_trips_through_its_name() {
        for format in LogFormat::ALL {
            assert_eq!(
                format
                    .as_str()
                    .parse::<LogFormat>()
                    .expect("the name parses"),
                format
            );
            assert_eq!(format.to_string(), format.as_str());
        }
    }

    #[test]
    fn test_names_are_read_regardless_of_case_and_padding() {
        assert_eq!(
            "  DEBUG ".parse::<LogLevel>().expect("the name parses"),
            LogLevel::Debug
        );
        assert_eq!(
            "Terminal".parse::<LogFormat>().expect("the name parses"),
            LogFormat::Terminal
        );
    }

    #[test]
    fn test_accepted_spellings_map_to_the_same_value() {
        assert_eq!(
            "warning".parse::<LogLevel>().expect("the name parses"),
            LogLevel::Warn
        );
        assert_eq!(
            "text".parse::<LogFormat>().expect("the name parses"),
            LogFormat::Terminal
        );
    }

    #[test]
    fn test_an_unknown_name_lists_what_was_expected() {
        let level = "verbose"
            .parse::<LogLevel>()
            .expect_err("`verbose` is not a level");
        assert!(format!("{level}").contains("error, warn, info, debug, trace"));

        let format = "xml"
            .parse::<LogFormat>()
            .expect_err("`xml` is not a format");
        assert!(format!("{format}").contains("json, terminal"));
    }

    #[test]
    fn test_levels_order_from_quietest_to_loudest() {
        assert!(LogLevel::Error < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Trace);
    }
}
