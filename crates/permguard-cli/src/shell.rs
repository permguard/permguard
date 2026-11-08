// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A whole command line: parsed, its target resolved, run and rendered, with its exit status. The
//! binary is [`run`] given the process's arguments and its standard streams; a program that
//! embeds the CLI calls [`run_captured`] and reads what a person would have read, byte for byte.
//!
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
//! | `2` | the command ran and its subject did not pass: planes answered and not all are ready, or cases failed |
//! | `64` | the command line, or something it named, was wrong (`EX_USAGE`) |
//! | `69` | the plane could not answer right now — unreachable, or a ledger with no history yet — and retrying is reasonable (`EX_UNAVAILABLE`) |
//! | `70` | the command failed for an internal reason (`EX_SOFTWARE`) |
//!
//! `69` and `70` are the line between "wait" and "page somebody": a data plane that has not
//! mirrored a ledger's first commit yet answers `ledger_empty`, which is nothing the operator
//! typed and nothing in this CLI, and used to exit `70` beside a decode failure.
//!
//! The distinction between `1` and `2` is what makes `permguard inspect` usable as a gate: a
//! deployment that waits for `0` waits for a runtime that is actually serving, and can tell "not up
//! yet" apart from "up, still draining" while it waits. `permguard test` draws the same line from
//! the other side: `2` is a workspace whose cases did not all pass, which is not the CLI failing —
//! it did exactly what it was asked, and the answer is no.

use std::process::ExitCode;

use crate::args::{Cli, Command, HostAction, IdentityAction};
use crate::commands::catalog::{CatalogAction, catalog_command};
use crate::commands::config::config_command;
use crate::commands::inspect::inspect_command;
use crate::commands::workspace::{WorkspaceOp, workspace_command};
use crate::failure::Failure;
use crate::output::OutputFormat;
use crate::session::render;
use crate::trace::Trace;

pub use crate::failure::{
    EXIT_NOT_READY, EXIT_READY, EXIT_SOFTWARE, EXIT_UNAVAILABLE, EXIT_UNREACHABLE, EXIT_USAGE,
};
use crate::{args, commands, version};

/// What a captured command line wrote, and the status the binary would have exited with.
#[derive(Debug, Default)]
pub struct Captured {
    /// What the command answered: its report, its help, its version.
    pub stdout: Vec<u8>,
    /// What it said beside: a failure, a warning, the narration of `--verbose`.
    pub stderr: Vec<u8>,
    /// The exit status, as the table of this module documents it.
    pub status: u8,
}

/// Runs one command line on this process's standard streams, colour as the terminal allows, and
/// answers with its exit status. `args` is the whole command line, the program's name first.
pub fn run<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let args: Vec<std::ffi::OsString> = args.into_iter().map(Into::into).collect();
    with_headroom(move || run_command(args))
}

/// Runs one command line into two buffers instead of the process's streams, `color` deciding
/// whether the output carries ANSI colours. Never prints, prompts, reads stdin or exits: what the
/// binary would have printed is in [`Captured`], with its status.
pub fn run_captured<I, T>(args: I, color: bool) -> Captured
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let args: Vec<std::ffi::OsString> = args.into_iter().map(Into::into).collect();
    let capture = crate::streams::Capture::new(color);
    let buffers = capture.clone();
    let code =
        crate::streams::with_capture(capture, move || with_headroom(move || run_command(args)));
    let (stdout, stderr) = buffers.take();

    Captured {
        stdout,
        stderr,
        status: status_of(code),
    }
}

/// The number an exit code carries: `ExitCode` hides it, and a captured run reports it.
fn status_of(code: ExitCode) -> u8 {
    (0..=u8::MAX)
        .find(|status| ExitCode::from(*status) == code)
        .unwrap_or(EXIT_SOFTWARE)
}

fn with_headroom(command: impl FnOnce() -> ExitCode) -> ExitCode {
    // Claimed once, for the whole command: a policy engine guards its own recursion by asking how
    // much stack is left, and on a musl build — which every Linux release is — the answer for the
    // process's first thread is the pages that happen to be mapped rather than the stack it has.
    // An engine that believes it has 128 KiB declines to parse, deserialize or evaluate anything
    // at all, so `permguard test` answered "recursion limit reached" on Linux for policies that
    // passed everywhere else. Claiming the room here covers every call this command makes; the
    // engine boundaries in `permguard-languages` cover the threads it hands work to.
    permguard_languages::headroom::with(command)
}

fn run_command(args: Vec<std::ffi::OsString>) -> ExitCode {
    // Parsed by hand so that a wrong command line exits `EX_USAGE` rather than clap's default of
    // 2 — which is a status this CLI has already given a meaning of its own.
    let matches = match args::command().try_get_matches_from(args) {
        Ok(matches) => matches,
        Err(error) => {
            let requested = !error.use_stderr();
            print_clap(&error);

            // `--help` and `--version` are errors only in clap's plumbing: the user asked, and got
            // what they asked for.
            return ExitCode::from(if requested { EXIT_READY } else { EXIT_USAGE });
        }
    };

    // `permguard help zones create` asks what `permguard zones create -h` asks, and is answered the
    // same way — here rather than in `run`, because the stand-in that parsed it deliberately has no
    // variant in `Command` to be derived into.
    if let Some(path) = args::help_request(&matches) {
        return print_help(&path);
    }

    let cli = match <Cli as clap::FromArgMatches>::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(error) => {
            let requested = !error.use_stderr();
            print_clap(&error);

            // `--help` and `--version` are errors only in clap's plumbing: the user asked, and got
            // what they asked for.
            return ExitCode::from(if requested { EXIT_READY } else { EXIT_USAGE });
        }
    };

    let format = cli.globals.output;

    // The catalogue of languages this binary carries, checked before any command reads policy: a
    // build whose registries collide would classify a workspace's files by whichever language a
    // lookup happened to reach first (LANG-12).
    if let Err(collision) = permguard_languages::registry::check_registry() {
        return ExitCode::from(
            Failure::internal(format!(
                "this build's language catalogue is inconsistent: {collision}"
            ))
            .report(format),
        );
    }

    match dispatch(cli) {
        Ok(code) => code,
        Err(failure) => ExitCode::from(failure.report(format)),
    }
}

/// What clap says, where the binary would have said it: help and version on the output, a wrong
/// command line on the diagnostics, coloured when the output may carry colour.
fn print_clap(error: &clap::Error) {
    let rendered = error.render();
    let text = if crate::style::coloured() {
        rendered.ansi().to_string()
    } else {
        rendered.to_string()
    };
    let _ = if error.use_stderr() {
        crate::streams::err(|out| std::io::Write::write_all(out, text.as_bytes()))
    } else {
        crate::streams::out(|out| std::io::Write::write_all(out, text.as_bytes()))
    };
}

/// A command's help, on the output, coloured as clap colours `--help`.
fn print_command_help(command: &mut clap::Command) -> std::io::Result<()> {
    let rendered = command.render_help();
    let text = if crate::style::coloured() {
        rendered.ansi().to_string()
    } else {
        rendered.to_string()
    };
    crate::streams::out(|out| std::io::Write::write_all(out, text.as_bytes()))
}

/// Answers `permguard help [COMMAND]...` with the help the named command answers `-h` with: the
/// same bytes, on stdout, and a zero status. A name that is not a command is a usage error, told
/// the way clap tells it for a name typed without `help` in front.
///
/// The tree is built before it is walked so that each command already knows its own name in full —
/// otherwise `permguard help zones create` answers with a usage line reading `create`.
fn print_help(path: &[String]) -> ExitCode {
    let mut root = args::command();
    root.build();

    let mut current = &root;

    for name in path {
        let Some(found) = current.find_subcommand(name) else {
            print_clap(&current.clone().error(
                clap::error::ErrorKind::InvalidSubcommand,
                format!("unrecognized subcommand '{name}'"),
            ));

            return ExitCode::from(EXIT_USAGE);
        };

        current = found;
    }

    match print_command_help(&mut current.clone()) {
        Ok(()) => ExitCode::from(EXIT_READY),
        Err(error) => ExitCode::from(Failure::internal(error).report(OutputFormat::Terminal)),
    }
}

fn dispatch(cli: Cli) -> Result<ExitCode, Failure> {
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
        // `print_help`, not `write_help`: clap styles the former like `--help` and renders the
        // latter plain, and the bare command must not be the one place the banner goes white.
        (false, None) => {
            print_command_help(&mut crate::args::command()).map_err(Failure::internal)?;

            return Ok(ExitCode::from(EXIT_READY));
        }
    };

    let (name, class) = target_of(&command);
    crate::target::check_class(name, class, &globals)?;

    match command {
        Command::Version => {
            render(&version::version(), format, &trace)?;

            Ok(ExitCode::from(EXIT_READY))
        }
        Command::Completion { shell } => {
            // Raw generator source, straight to stdout: a shell evaluates this, so a banner or a
            // report wrapper would be syntax errors in someone's rc file.
            let mut script = Vec::new();
            clap_complete::generate(shell, &mut args::command(), "permguard", &mut script);
            crate::streams::out(|out| std::io::Write::write_all(out, &script))
                .map_err(Failure::internal)?;

            Ok(ExitCode::from(EXIT_READY))
        }
        Command::Config { action } => config_command(&globals, action, &trace),
        Command::Host {
            server_config,
            action,
        } => commands::host::host_command(&globals, server_config.as_deref(), action, &trace),
        Command::Iam { action } => commands::iam::iam_command(&globals, action, &trace),
        Command::Restore {
            server_config,
            action,
        } => commands::restore::restore_command(&globals, server_config.as_deref(), action, &trace),
        Command::Gc { action } => commands::host_ops::gc_command(&globals, action, &trace),
        Command::Reclaim {
            action: crate::args::ReclaimAction::Run(args),
        } => commands::reclaim::run(&globals, &trace, args),
        Command::Evidence { action } => {
            commands::host_ops::evidence_command(&globals, action, &trace)
        }
        Command::Backup { action } => {
            commands::offline_ops::backup_command(&globals, action, &trace)
        }
        Command::Migrate {
            server_config,
            action,
        } => commands::offline_ops::migrate_command(
            &globals,
            server_config.as_deref(),
            action,
            &trace,
        ),
        Command::Inspect { timeout } => inspect_command(&globals, timeout, &trace),
        Command::Discover { url, timeout } => {
            commands::discover::discover_command(&globals, &url, timeout, &trace)
        }
        Command::Login { url, user, code } => {
            commands::directory::login(&globals, &url, &user, code.as_deref(), &trace)
        }
        Command::Logout { url } => commands::directory::logout(&globals, &url, &trace),
        Command::Password { url } => commands::directory::password(&globals, &url, &trace),
        Command::Factor { url, action } => {
            commands::directory::factor(&globals, &url, action, &trace)
        }
        Command::Setup {
            url,
            check,
            code_file,
            name,
            email,
            password_stdin,
        } => commands::directory::setup(
            &globals,
            &url,
            check,
            code_file.as_deref(),
            name.as_deref(),
            email,
            password_stdin,
            &trace,
        ),
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
        Command::Pull { resolved } => {
            workspace_command(&globals, WorkspaceOp::Pull { resolved }, &trace)
        }
        Command::Refresh => workspace_command(&globals, WorkspaceOp::Refresh, &trace),
        Command::Validate => workspace_command(&globals, WorkspaceOp::Validate, &trace),
        Command::Test {
            path,
            name,
            profile,
            list,
            remote,
            zone,
            ledger,
        } => workspace_command(
            &globals,
            WorkspaceOp::Test {
                paths: path,
                name,
                profile,
                list,
                remote,
                zone,
                ledger,
            },
            &trace,
        ),
        Command::Plan => workspace_command(&globals, WorkspaceOp::Plan, &trace),
        Command::Apply { message } => {
            workspace_command(&globals, WorkspaceOp::Apply { message }, &trace)
        }
        Command::History { limit } => {
            workspace_command(&globals, WorkspaceOp::History { limit }, &trace)
        }
        Command::Status => workspace_command(&globals, WorkspaceOp::Status, &trace),
        Command::Objects { action } => {
            workspace_command(&globals, WorkspaceOp::Objects(action), &trace)
        }
        Command::Verify => workspace_command(&globals, WorkspaceOp::Verify, &trace),
        Command::Check(args) => commands::check::check(&globals, &args),
        Command::Decisions { action } => commands::decisions::decisions(&globals, &action),
        Command::Events { action } => commands::events::events(&globals, &action),
        Command::Zones { action } => {
            catalog_command(&globals, CatalogAction::Zones(action), &trace)
        }
        Command::Ledgers { action } => {
            catalog_command(&globals, CatalogAction::Ledgers(action), &trace)
        }
    }
}

/// The command's name, as a refusal quotes it, and the one target class it reaches (TC-1).
fn target_of(command: &Command) -> (&'static str, crate::target::Class) {
    use crate::target::Class;

    match command {
        Command::Version => ("version", Class::Local),
        Command::Completion { .. } => ("completion", Class::Local),
        Command::Config { .. } => ("config", Class::Local),
        Command::Init { .. } => ("init", Class::Local),
        Command::Refresh => ("refresh", Class::Local),
        Command::Validate => ("validate", Class::Local),
        Command::Plan => ("plan", Class::Local),
        Command::Status => ("status", Class::Local),
        Command::History { .. } => ("history", Class::Local),
        Command::Objects { .. } => ("objects", Class::Local),
        Command::Test { remote, .. } => ("test", if *remote { Class::Data } else { Class::Local }),
        Command::Check(_) => ("check", Class::Data),
        Command::Zones { .. } => ("zones", Class::Control),
        Command::Ledgers { .. } => ("ledgers", Class::Control),
        Command::Decisions { .. } => ("decisions", Class::Control),
        Command::Events { .. } => ("events", Class::Control),
        Command::Remote { .. } => ("remote", Class::Control),
        Command::Clone { .. } => ("clone", Class::Control),
        Command::Checkout { .. } => ("checkout", Class::Control),
        Command::Pull { .. } => ("pull", Class::Control),
        Command::Apply { .. } => ("apply", Class::Control),
        Command::Verify => ("verify", Class::Control),
        Command::Inspect { .. } => ("inspect", Class::Planes),
        Command::Restore { .. } => ("restore", Class::Volume),
        Command::Backup { .. } => ("backup", Class::Volume),
        Command::Gc { .. } => ("gc", Class::Host),
        Command::Reclaim { .. } => ("reclaim", Class::Host),
        Command::Evidence { .. } => ("evidence", Class::Host),
        Command::Migrate { .. } => ("migrate", Class::Volume),
        Command::Discover { .. } => ("discover", Class::Local),
        Command::Login { .. } => ("login", Class::Local),
        Command::Logout { .. } => ("logout", Class::Local),
        Command::Password { .. } => ("password", Class::Local),
        Command::Factor { .. } => ("factor", Class::Local),
        Command::Setup { .. } => ("setup", Class::Local),
        Command::Iam { .. } => ("iam", Class::Host),
        Command::Host { action, .. } => {
            let class = match action {
                HostAction::Identity {
                    action: IdentityAction::Provision { .. } | IdentityAction::Reset { .. },
                }
                | HostAction::Grants { .. }
                | HostAction::Users { .. }
                | HostAction::Recovery { .. }
                | HostAction::Holds { .. } => Class::Volume,
                HostAction::Identity {
                    action: IdentityAction::Pin { .. },
                } => Class::Local,
                HostAction::Identity { .. }
                | HostAction::Members { .. }
                | HostAction::Streams { .. }
                | HostAction::Keys { .. }
                | HostAction::Audit { .. }
                | HostAction::Config { .. }
                | HostAction::Status
                | HostAction::Plans { .. }
                | HostAction::Backup { .. } => Class::Host,
            };
            ("host", class)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    #[test]
    fn a_captured_run_answers_what_the_binary_prints_and_its_status() {
        let captured = run_captured(["permguard", "version"], false);

        assert_eq!(captured.status, EXIT_READY);
        assert!(text(&captured.stdout).contains("permguard"));
        assert!(captured.stderr.is_empty());
    }

    #[test]
    fn a_wrong_command_line_is_a_usage_error_on_the_diagnostics() {
        let captured = run_captured(["permguard", "nosuch"], false);

        assert_eq!(captured.status, EXIT_USAGE);
        assert!(captured.stdout.is_empty());
        assert!(text(&captured.stderr).contains("unrecognized subcommand"));
    }

    #[test]
    fn the_json_output_is_the_contract_in_a_capture_too() {
        let captured = run_captured(["permguard", "-o", "json", "version"], true);
        let answer: serde_json::Value =
            serde_json::from_slice(&captured.stdout).unwrap_or_default();

        assert_eq!(captured.status, EXIT_READY);
        assert_eq!(answer["binary"], "permguard");
    }

    #[test]
    fn a_capture_without_colour_carries_no_escape_and_with_it_carries_some() {
        let plain = run_captured(["permguard", "--help"], false);
        let coloured = run_captured(["permguard", "--help"], true);

        assert_eq!(plain.status, EXIT_READY);
        assert!(!plain.stdout.contains(&0x1b));
        assert!(coloured.stdout.contains(&0x1b));
    }

    #[test]
    fn a_failure_in_a_workspace_is_reported_into_the_capture() {
        let missing = std::env::temp_dir().join("permguard-shell-no-such-workspace");
        let captured = run_captured(
            [
                std::ffi::OsString::from("permguard"),
                "-w".into(),
                missing.into_os_string(),
                "validate".into(),
            ],
            false,
        );

        assert_eq!(captured.status, EXIT_USAGE);
        assert!(text(&captured.stderr).starts_with("error: "));
    }
}
