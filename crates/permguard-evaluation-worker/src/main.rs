#![forbid(unsafe_code)]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The dedicated supervised evaluation worker (`11-refactoring/1-dependencies.md`, Supervised
//! evaluators assume ownership of the process entry point).
//!
//! A standalone Data Plane starts itself again as its worker. An application that embeds the Data
//! Plane keeps its entry point to itself: it names this executable instead, and the supervisor
//! starts it with the worker argument, bounds it with the OS limits and kills it at the deadline,
//! exactly as it does the same-binary worker.
//!
//! It does one thing. Started by a supervisor, it answers frames on the private descriptor and
//! exits; started any other way, it says what it is on standard error and refuses, without
//! reading an argument, a file or the environment.

use std::process::ExitCode;

use permguard_languages::guard::report_panics_without_their_words;
use permguard_languages::worker::{WORKER_ARGUMENT, serve_if_worker};

/// The exit code of a command used wrongly, as `sysexits` names it.
const USAGE: u8 = 64;

fn main() -> ExitCode {
    report_panics_without_their_words();
    // Never returns for a process a supervisor started.
    serve_if_worker();

    eprintln!(
        "permguard-evaluation-worker evaluates policies for a Permguard Data Plane, which starts \
         it with `{WORKER_ARGUMENT}` as its first argument and speaks to it over a private \
         descriptor. It is not started by hand, and does nothing when it is."
    );
    ExitCode::from(USAGE)
}
