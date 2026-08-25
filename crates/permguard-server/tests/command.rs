// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What each invocation resolves to.
//!
//! Here rather than beside the code because the table of cases is the point: which spellings parse,
//! which are refused, and what a build outside this workspace sees when it flattens the shared
//! commands into a parser of its own.

use std::path::Path;

use clap::{Parser, Subcommand};

use permguard_core::config::{
    SETTING_ADMIN_ADDR, SETTING_PUBLIC_GRPC_ADDR, SETTING_PUBLIC_HTTP_ADDR, SETTING_TELEMETRY_ADDR,
};
use permguard_server::{Action, Cli, Command, ServeArgs};

fn action(argv: &[&str]) -> Action {
    Cli::try_parse_from(argv)
        .expect("the invocation parses")
        .action()
        .expect("the invocation resolves to an action")
}

fn serve_args(argv: &[&str]) -> ServeArgs {
    match action(argv) {
        Action::Serve(args) => args,
        other => panic!("expected the default action, resolved {other:?}"),
    }
}

#[test]
fn test_a_configuration_file_alone_resolves_to_serving() {
    let args = serve_args(&["permguard", "config.yml"]);

    assert_eq!(args.config_file(), Path::new("config.yml"));
}

#[test]
fn test_serving_takes_exactly_one_configuration_file() {
    assert!(Cli::try_parse_from(["permguard", "a.yml", "b.yml"]).is_err());
}

#[test]
fn test_serving_without_a_configuration_file_fails_to_parse() {
    assert!(Cli::try_parse_from(["permguard", "--admin-addr", "127.0.0.1:4"]).is_err());
}

#[test]
fn test_serve_is_no_longer_a_command_name() {
    // `serve` now reads as a configuration file path, so naming it and a file is two positionals.
    assert!(Cli::try_parse_from(["permguard", "serve", "config.yml"]).is_err());
}

#[test]
fn test_no_config_flag_exists() {
    assert!(Cli::try_parse_from(["permguard", "--config", "config.yml"]).is_err());
    assert!(Cli::try_parse_from(["permguard", "--config=config.yml"]).is_err());
}

#[test]
fn test_address_flags_are_optional_overrides() {
    let bare = serve_args(&["permguard", "config.yml"]);
    assert!(bare.setting_inputs().is_empty());

    let overridden = serve_args(&[
        "permguard",
        "config.yml",
        "--public-http-addr",
        "127.0.0.1:1",
        "--public-grpc-addr",
        "127.0.0.1:2",
        "--telemetry-addr",
        "127.0.0.1:3",
        "--admin-addr",
        "127.0.0.1:4",
    ]);

    assert_eq!(
        overridden.setting_inputs(),
        vec![
            (
                SETTING_PUBLIC_HTTP_ADDR.to_owned(),
                "127.0.0.1:1".to_owned()
            ),
            (
                SETTING_PUBLIC_GRPC_ADDR.to_owned(),
                "127.0.0.1:2".to_owned()
            ),
            (SETTING_TELEMETRY_ADDR.to_owned(), "127.0.0.1:3".to_owned()),
            (SETTING_ADMIN_ADDR.to_owned(), "127.0.0.1:4".to_owned()),
        ]
    );
}

#[test]
fn test_address_flags_come_before_or_after_the_configuration_file() {
    let before = serve_args(&["permguard", "--admin-addr", "127.0.0.1:4", "config.yml"]);
    let after = serve_args(&["permguard", "config.yml", "--admin-addr", "127.0.0.1:4"]);

    assert_eq!(before, after);
}

#[test]
fn test_version_is_a_named_command_that_needs_no_configuration_file() {
    let resolved = action(&["permguard", "version"]);

    assert_eq!(resolved, Action::Named(Command::Version));
    assert!(resolved.setting_inputs().is_empty());
}

#[test]
fn test_a_named_command_refuses_the_arguments_of_the_default_action() {
    assert!(Cli::try_parse_from(["permguard", "version", "config.yml"]).is_err());
    assert!(Cli::try_parse_from(["permguard", "version", "--admin-addr", "127.0.0.1:4"]).is_err());
}

#[test]
fn test_serving_contributes_its_flags_as_the_command_line_layer() {
    let resolved = action(&["permguard", "config.yml", "--admin-addr", "127.0.0.1:4"]);

    assert_eq!(
        resolved.setting_inputs(),
        vec![(SETTING_ADMIN_ADDR.to_owned(), "127.0.0.1:4".to_owned())]
    );
}

#[test]
fn test_no_argument_at_all_fails_to_parse() {
    assert!(Cli::try_parse_from(["permguard"]).is_err());
}

#[test]
fn test_an_invocation_that_asks_for_nothing_resolves_to_no_action() {
    let empty = Cli {
        serve: None,
        command: None,
    };

    assert_eq!(empty.action(), None);
}

#[test]
fn test_an_unknown_flag_fails_to_parse() {
    assert!(Cli::try_parse_from(["permguard", "config.yml", "--unknown"]).is_err());
}

/// The parser a downstream build writes when it adds a command of its own.
///
/// This exists to prove the shared command set composes: if flattening ever stopped working, a
/// binary outside this workspace could no longer extend the CLI without forking it.
#[derive(Parser, Debug)]
#[command(
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true,
    arg_required_else_help = true
)]
struct DownstreamCli {
    #[command(flatten)]
    serve: Option<ServeArgs>,

    #[command(subcommand)]
    command: Option<DownstreamCommand>,
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
enum DownstreamCommand {
    #[command(flatten)]
    Shared(Command),
    /// A command only the downstream build has.
    License,
}

#[test]
fn test_a_downstream_build_can_flatten_the_shared_commands() {
    let shared =
        DownstreamCli::try_parse_from(["other-x", "version"]).expect("the shared command parses");
    assert_eq!(
        shared.command,
        Some(DownstreamCommand::Shared(Command::Version))
    );

    let own =
        DownstreamCli::try_parse_from(["other-x", "license"]).expect("the own command parses");
    assert_eq!(own.command, Some(DownstreamCommand::License));
}

#[test]
fn test_a_downstream_build_keeps_the_default_action() {
    let parsed =
        DownstreamCli::try_parse_from(["other-x", "config.yml", "--admin-addr", "127.0.0.1:4"])
            .expect("the default action parses");

    assert_eq!(parsed.command, None);
    assert_eq!(
        parsed
            .serve
            .expect("the default action carries its arguments")
            .setting_inputs(),
        vec![(SETTING_ADMIN_ADDR.to_owned(), "127.0.0.1:4".to_owned())]
    );
}
