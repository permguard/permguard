// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Permguard command-line interface.
//!
//! # How a setting is decided
//!
//! A flag beats the environment, the environment beats the configuration file in
//! `~/.permguard/config.yml`, and the file beats the default compiled in. `permguard config show`
//! reports which of those four each value came from, which is the question an operator asks when a
//! command talks to the wrong server.
//!
//! # Exit statuses
//!
//! They are an interface, and scripts depend on them, so they are documented here and tested:
//!
//! | Status | Meaning |
//! | -----: | ------- |
//! | `0` | the command succeeded, and every plane it asked about is ready |
//! | `1` | no plane answered — there was nothing to inspect |
//! | `2` | planes answered, and not all of them are ready |
//! | `64` | the command line, or something it named, was wrong (`EX_USAGE`) |
//! | `70` | the command failed for an internal reason (`EX_SOFTWARE`) |
//!
//! The distinction between `1` and `2` is what makes `permguard inspect` usable as a gate: a
//! deployment that waits for `0` waits for a runtime that is actually serving, and can tell "not up
//! yet" apart from "up, still draining" while it waits.

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used, clippy::expect_used)]

mod args;
mod banner;
mod commands;
mod config;
mod decision_out;
mod failure;
mod inspect;
mod narrator;
mod output;
mod reference;
mod session;
mod settings;
mod style;
mod target;
mod trace;
mod version;
mod workspace_out;

use std::process::ExitCode;

use crate::args::{Cli, Command};
use crate::commands::catalog::{CatalogAction, catalog_command};
use crate::commands::config::config_command;
use crate::commands::inspect::inspect_command;
use crate::commands::workspace::{WorkspaceOp, workspace_command};
use crate::failure::Failure;
use crate::session::render;
use crate::trace::Trace;

pub use crate::failure::{EXIT_NOT_READY, EXIT_READY, EXIT_SOFTWARE, EXIT_UNREACHABLE, EXIT_USAGE};

fn main() -> ExitCode {
    // Parsed by hand so that a wrong command line exits `EX_USAGE` rather than clap's default of
    // 2 — which is a status this CLI has already given a meaning of its own.
    let cli = match args::command().try_get_matches().and_then(|matches| {
        // `permguard help zones create` asks what `permguard zones create -h` asks, and is answered
        // the same way — before the matches are derived, because the stand-in that parsed it has no
        // variant in `Command` to be derived into.
        if let Some(path) = args::help_request(&matches) {
            return Err(help_error(&path));
        }

        <Cli as clap::FromArgMatches>::from_arg_matches(&matches)
    }) {
        Ok(cli) => cli,
        Err(error) => {
            let requested = !error.use_stderr();
            let _ = error.print();

            // `--help` and `--version` are errors only in clap's plumbing: the user asked, and got
            // what they asked for.
            return ExitCode::from(if requested { EXIT_READY } else { EXIT_USAGE });
        }
    };

    let format = cli.globals.output;

    match run(cli) {
        Ok(code) => code,
        Err(failure) => failure.report(format),
    }
}

/// The one help, for a `permguard help [COMMAND]...`, dressed as the error kind clap uses to mean
/// "the user asked, and this is the answer": printed on stdout, and a zero status.
///
/// The tree is built before it is walked so that each command already knows its own name in full —
/// otherwise `permguard help zones create` answers with a usage line reading `create`.
fn help_error(path: &[String]) -> clap::Error {
    let mut root = args::command();
    root.build();

    let mut current = &root;

    for name in path {
        match current.find_subcommand(name) {
            Some(found) => current = found,
            None => {
                return clap::Error::raw(
                    clap::error::ErrorKind::InvalidSubcommand,
                    format!(
                        "error: '{name}' is not a {} command\n",
                        current.get_display_name().unwrap_or(current.get_name())
                    ),
                );
            }
        }
    }

    clap::Error::raw(
        clap::error::ErrorKind::DisplayHelp,
        current.clone().render_help(),
    )
}

fn run(cli: Cli) -> Result<ExitCode, Failure> {
    let globals = cli.globals;
    let trace = Trace::new(globals.verbose);
    let format = globals.output;

    // `--version` is answered by the command that answers `version`, so the two spellings cannot
    // drift apart and `-o json` works for both. A command named alongside it is not a conflict
    // worth an error: the question was asked, and it is answered.
    let command = match (cli.version, cli.command) {
        (true, _) => Command::Version,
        (false, Some(command)) => command,
        // A bare `permguard`, or global flags with no command. Neither is a usage error — the
        // question is "and now what?", and the help is its answer: stdout, status zero.
        (false, None) => {
            let mut out = std::io::stdout();
            crate::args::command()
                .write_help(&mut out)
                .map_err(Failure::internal)?;

            return Ok(ExitCode::from(EXIT_READY));
        }
    };

    match command {
        Command::Version => {
            render(&version::version(), format, &trace)?;

            Ok(ExitCode::from(EXIT_READY))
        }
        Command::Completion { shell } => {
            // Raw generator source, straight to stdout: a shell evaluates this, so a banner or a
            // report wrapper would be syntax errors in someone's rc file.
            clap_complete::generate(
                shell,
                &mut args::command(),
                "permguard",
                &mut std::io::stdout(),
            );

            Ok(ExitCode::from(EXIT_READY))
        }
        Command::Config { action } => config_command(&globals, action, &trace),
        Command::Inspect { timeout } => inspect_command(&globals, timeout, &trace),
        Command::Init { name, language } => {
            let languages: Vec<&str> = language.iter().map(String::as_str).collect();
            workspace_command(
                &globals,
                WorkspaceOp::Init {
                    name,
                    languages: languages.iter().map(|s| s.to_string()).collect(),
                },
                &trace,
            )
        }
        Command::Remote { action } => {
            workspace_command(&globals, WorkspaceOp::Remote(action), &trace)
        }
        Command::Clone { url, directory } => {
            workspace_command(&globals, WorkspaceOp::Clone { url, directory }, &trace)
        }
        Command::Checkout { reference } => {
            workspace_command(&globals, WorkspaceOp::Checkout { reference }, &trace)
        }
        Command::Pull => workspace_command(&globals, WorkspaceOp::Pull, &trace),
        Command::Refresh => workspace_command(&globals, WorkspaceOp::Refresh, &trace),
        Command::Validate => workspace_command(&globals, WorkspaceOp::Validate, &trace),
        Command::Plan => workspace_command(&globals, WorkspaceOp::Plan, &trace),
        Command::Apply { message } => {
            workspace_command(&globals, WorkspaceOp::Apply { message }, &trace)
        }
        Command::History => workspace_command(&globals, WorkspaceOp::History, &trace),
        Command::Status => workspace_command(&globals, WorkspaceOp::Status, &trace),
        Command::Objects { action } => {
            workspace_command(&globals, WorkspaceOp::Objects(action), &trace)
        }
        Command::Verify => workspace_command(&globals, WorkspaceOp::Verify, &trace),
        Command::Check(args) => commands::check::check(&globals, &args),
        Command::Decisions { action } => commands::decisions::decisions(&globals, &action),
        Command::Zones { action } => {
            catalog_command(&globals, CatalogAction::Zones(action), &trace)
        }
        Command::Ledgers { action } => {
            catalog_command(&globals, CatalogAction::Ledgers(action), &trace)
        }
    }
}
