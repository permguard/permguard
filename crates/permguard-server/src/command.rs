// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The command set every Permguard build understands.
//!
//! Serving is what the binary does. It is not a command you name, it is what happens when you do not
//! name one: `permguard <config file>` starts the server, and a named command is how you ask for
//! something else instead.
//!
//! [`Command`] is a plain `clap` subcommand enum, so a build that adds commands of its own flattens
//! it into a larger enum and hands the shared variants back to [`App::dispatch`](crate::App::dispatch)
//! through [`Action`]:
//!
//! ```ignore
//! #[derive(Subcommand)]
//! enum MyCommand {
//!     #[command(flatten)]
//!     Shared(permguard_server::Command),
//!     License(LicenseArgs),
//! }
//! ```
//!
//! Neither the executable name nor the description lives here: [`App`](crate::App) stamps those onto
//! the parser from the product identity the binary supplied.

use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand};

use clap::builder::TypedValueParser as _;
use permguard_core::config::{
    SETTING_ADMIN_ADDR, SETTING_LOG_FORMAT, SETTING_LOG_LEVEL, SETTING_PUBLIC_GRPC_ADDR,
    SETTING_PUBLIC_HTTP_ADDR, SETTING_TELEMETRY_ADDR,
};
use permguard_core::{LogFormat, LogLevel};

/// The spellings `--log-level` accepts, and which of them the help lists.
///
/// `LogLevel::ALL` is the canonical set and is what a reader is shown; `from_str` also takes
/// `warning`, which stays accepted and stays out of the listing — an alias in a `[possible values:]`
/// reads as a sixth level rather than a second name for one. A test below asserts that every
/// spelling here parses and that no canonical one is missing, so the two cannot drift.
const LOG_LEVEL_ALIASES: &[&str] = &["warning"];

/// The same, for `--log-format`: `text` and `pretty` are `terminal`.
const LOG_FORMAT_ALIASES: &[&str] = &["text", "pretty"];

/// Declares the accepted values so that `--help` lists them the way every other enumerated flag in
/// this product lists them — `[possible values: …]`, not a sentence in the description that no
/// completion script and no `-o json` consumer can read.
fn spellings(
    canonical: &[&'static str],
    aliases: &[&'static str],
) -> Vec<clap::builder::PossibleValue> {
    canonical
        .iter()
        .map(|name| clap::builder::PossibleValue::new(*name))
        .chain(
            aliases
                .iter()
                .map(|name| clap::builder::PossibleValue::new(*name).hide(true)),
        )
        .collect()
}

/// Reads a log level, reporting an unknown name as `clap` reports any other bad value.
fn parse_log_level(value: &str) -> Result<LogLevel, String> {
    value
        .parse()
        .map_err(|error: anyhow::Error| error.to_string())
}

/// Reads a log format, reporting an unknown name as `clap` reports any other bad value.
fn parse_log_format(value: &str) -> Result<LogFormat, String> {
    value
        .parse()
        .map_err(|error: anyhow::Error| error.to_string())
}

/// The argument parser for a build that adds no command of its own.
///
/// `args_conflicts_with_subcommands` keeps the two forms from being mixed, and
/// `subcommand_negates_reqs` is what lets the configuration file stay a required argument of the
/// default action while a named command needs none.
///
/// `long_about = None` keeps this explanation in the API docs and out of `--help`, where the text
/// belongs to the product identity the binary supplied.
#[derive(Parser, Debug)]
#[command(
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true,
    arg_required_else_help = true,
    long_about = None
)]
pub struct Cli {
    /// Arguments of the default action, absent when a command is named instead.
    ///
    /// The group is optional because `clap` builds it from the parsed arguments, and a named command
    /// supplies none of them: leaving it required would reintroduce the requirement that
    /// `subcommand_negates_reqs` just removed.
    #[command(flatten)]
    pub serve: Option<ServeArgs>,

    /// The named command, when the invocation asks for one instead of serving.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// The commands that ask for something other than serving.
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Report the product version.
    Version,
    /// Work with the audit trail.
    Audit {
        /// What to do with it.
        #[command(subcommand)]
        what: AuditCommand,
    },
    /// Work with a key ring.
    Keys {
        /// What to do with it.
        #[command(subcommand)]
        what: KeysCommand,
    },
}

/// What can be asked of a key ring from the command line.
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum KeysCommand {
    /// Print a ring's public keys as a JWKS document.
    ///
    /// The *offline* way to obtain the public half of an operations ring — the keys that seal a
    /// trail. The running server also publishes them at `/server-host/keys` on the Host port, and
    /// the two answer different needs: the endpoint serves the routine case — a dashboard, a
    /// rotation check — while this command reads the ring on disk, so it works with the server
    /// stopped, which is exactly when a restore needs it. Export from the volume before backing it
    /// up, keep the file off the host, and check restored seals against it: a forensic
    /// verification takes its keys from a snapshot made *before* the incident, never from the
    /// machine under suspicion, whose endpoint the same attacker could be answering.
    Export {
        /// Directory the ring lives in, e.g. `<volume>/operations/keys`.
        #[arg(long, value_name = "DIRECTORY")]
        directory: PathBuf,
    },
}

/// What can be asked of an audit trail from the command line.
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum AuditCommand {
    /// Check that nothing in a trail has been altered.
    ///
    /// Named here and implemented by the binary, like every other collaborator: this crate knows
    /// that a trail can be verified, and the composition root knows what a trail is.
    Verify {
        /// Directory the trail was written to.
        #[arg(long, value_name = "DIRECTORY")]
        directory: PathBuf,

        /// Key set to check the seals' signatures against, as a JWKS document.
        ///
        /// Optional, and pointedly not defaulted to the local key ring: verifying a seal against
        /// keys taken from the machine under suspicion checks a signature against a key the same
        /// attacker could have replaced. Point it at a copy you trust.
        #[arg(long, value_name = "JWKS")]
        keys: Option<PathBuf>,
    },
}

/// What an invocation resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Start the server: the default when no command is named.
    Serve(ServeArgs),
    /// Run the named command.
    Named(Command),
}

/// Arguments of the default action.
///
/// The configuration file is a required positional argument, and exactly one is accepted.
#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct ServeArgs {
    /// Path to the configuration file.
    #[arg(value_name = "CONFIG_FILE")]
    config_file: PathBuf,

    /// Override the public HTTP listen address from the configuration file.
    #[arg(long, value_name = "ADDR")]
    public_http_addr: Option<String>,

    /// Override the public gRPC listen address from the configuration file.
    #[arg(long, value_name = "ADDR")]
    public_grpc_addr: Option<String>,

    /// Override the telemetry listen address from the configuration file.
    #[arg(long, value_name = "ADDR")]
    telemetry_addr: Option<String>,

    /// Override the admin listen address from the configuration file.
    #[arg(long, value_name = "ADDR")]
    admin_addr: Option<String>,

    /// Override how much the server says.
    #[arg(
        long,
        value_name = "LEVEL",
        // The listed spellings are exactly the ones `parse_log_level` takes, so `try_map`
        // never actually refuses — and if somebody adds one to only half of that, it
        // refuses rather than guessing.
        value_parser = clap::builder::PossibleValuesParser::new(spellings(
            &LogLevel::ALL.map(|level| level.as_str()),
            LOG_LEVEL_ALIASES,
        )).try_map(|value| parse_log_level(&value)),
    )]
    log_level: Option<LogLevel>,

    /// Override the shape records are written in.
    #[arg(
        long,
        value_name = "FORMAT",
        value_parser = clap::builder::PossibleValuesParser::new(spellings(
            &LogFormat::ALL.map(|format| format.as_str()),
            LOG_FORMAT_ALIASES,
        )).try_map(|value| parse_log_format(&value)),
    )]
    log_format: Option<LogFormat>,
}

impl Cli {
    /// Resolves the invocation to what it actually asked for.
    ///
    /// Returns `None` for an invocation that names neither a command nor a configuration file.
    /// `arg_required_else_help` turns that into help before parsing ever completes, so it is the
    /// caller's business only because a total function beats a panic on user input.
    pub fn action(self) -> Option<Action> {
        match (self.command, self.serve) {
            (Some(command), _) => Some(Action::Named(command)),
            (None, Some(args)) => Some(Action::Serve(args)),
            (None, None) => None,
        }
    }
}

impl Action {
    /// The command-line override layer this action contributes.
    pub fn setting_inputs(&self) -> Vec<(String, String)> {
        match self {
            Self::Serve(args) => args.setting_inputs(),
            Self::Named(_) => Vec::new(),
        }
    }
}

impl ServeArgs {
    /// Returns the configuration file this invocation named.
    pub fn config_file(&self) -> &Path {
        &self.config_file
    }

    /// The command-line overrides that feed the config, as the last precedence layer.
    ///
    /// Only flags the invocation actually passed appear here, so an absent flag never overwrites a
    /// value the configuration file supplied.
    pub fn setting_inputs(&self) -> Vec<(String, String)> {
        let addresses = [
            (SETTING_PUBLIC_HTTP_ADDR, self.public_http_addr.as_ref()),
            (SETTING_PUBLIC_GRPC_ADDR, self.public_grpc_addr.as_ref()),
            (SETTING_TELEMETRY_ADDR, self.telemetry_addr.as_ref()),
            (SETTING_ADMIN_ADDR, self.admin_addr.as_ref()),
        ];

        let logging = [
            (
                SETTING_LOG_LEVEL,
                self.log_level.map(|level| level.as_str().to_owned()),
            ),
            (
                SETTING_LOG_FORMAT,
                self.log_format.map(|format| format.as_str().to_owned()),
            ),
        ];

        addresses
            .into_iter()
            .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.clone())))
            .chain(
                logging
                    .into_iter()
                    .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value))),
            )
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every spelling the help offers is a spelling the parser takes, and every canonical one is
    /// offered.
    ///
    /// The two live apart on purpose — the parser is `permguard-core`'s, which may not depend on
    /// `clap`, and the listing is this crate's — so this is what keeps them one contract. Add a
    /// level to the enum, or an alias to `from_str`, and this fails until the listing follows.
    #[test]
    fn every_listed_spelling_parses_and_every_level_is_listed() {
        let levels = spellings(
            &LogLevel::ALL.map(|level| level.as_str()),
            LOG_LEVEL_ALIASES,
        );
        for value in &levels {
            let name = value.get_name();
            assert!(
                parse_log_level(name).is_ok(),
                "`{name}` is offered and not accepted"
            );
        }
        for level in LogLevel::ALL {
            assert!(
                levels
                    .iter()
                    .any(|value| value.get_name() == level.as_str() && !value.is_hide_set()),
                "`{}` is a level and is not listed",
                level.as_str()
            );
        }

        let formats = spellings(
            &LogFormat::ALL.map(|format| format.as_str()),
            LOG_FORMAT_ALIASES,
        );
        for value in &formats {
            let name = value.get_name();
            assert!(
                parse_log_format(name).is_ok(),
                "`{name}` is offered and not accepted"
            );
        }
        for format in LogFormat::ALL {
            assert!(
                formats
                    .iter()
                    .any(|value| value.get_name() == format.as_str() && !value.is_hide_set()),
                "`{}` is a format and is not listed",
                format.as_str()
            );
        }
    }

    /// An alias is accepted and not advertised: a `[possible values:]` that listed `warning` beside
    /// `warn` would read as a sixth level rather than a second name for one.
    #[test]
    fn an_alias_is_accepted_and_stays_out_of_the_listing() {
        let levels = spellings(
            &LogLevel::ALL.map(|level| level.as_str()),
            LOG_LEVEL_ALIASES,
        );

        for alias in LOG_LEVEL_ALIASES {
            let listed = levels
                .iter()
                .find(|value| &value.get_name() == alias)
                .unwrap_or_else(|| panic!("`{alias}` is not offered at all"));

            assert!(listed.is_hide_set(), "`{alias}` is advertised as a level");
            assert!(parse_log_level(alias).is_ok(), "`{alias}` is not accepted");
        }
    }
}
