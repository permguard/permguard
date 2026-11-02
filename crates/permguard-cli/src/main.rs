// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Permguard command-line interface: the library's [`permguard_cli::shell::run`] given this
//! process's arguments and its standard streams. The command line, its settings and its exit
//! statuses are documented in that module.

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used, clippy::expect_used)]

use std::process::ExitCode;

fn main() -> ExitCode {
    // A process started as a supervised evaluation worker answers frames and exits.
    permguard_languages::worker::serve_if_worker();

    permguard_cli::shell::run(std::env::args_os())
}
