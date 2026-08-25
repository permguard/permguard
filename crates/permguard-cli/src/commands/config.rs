// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The CLI's own configuration: read it, write it, and say which layer each
//! value came from — the question an operator asks when a command talks to
//! the wrong server.

use std::process::ExitCode;

use crate::args::{ConfigAction, Globals};
use crate::config;
use crate::failure::{EXIT_READY, Failure};
use crate::session::{open_store, render};
use crate::trace::Trace;

pub fn config_command(
    globals: &Globals,
    action: ConfigAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    let mut store = open_store(globals, trace)?;

    // A first `config` command leaves a file to look at and edit, which is what makes the settings
    // discoverable at all. Reading a setting does not need one, so `get` does not create it.
    if !matches!(action, ConfigAction::Get { .. })
        && config::ensure(&store).map_err(Failure::usage)?
    {
        trace.say(format!("created {}", store.path().display()));
    }

    match action {
        ConfigAction::Show => render(&config::show(&store), globals.output, trace)?,
        ConfigAction::Get { key } => {
            let report = config::get(&store, &key).map_err(Failure::usage)?;

            render(&report, globals.output, trace)?;
        }
        ConfigAction::Set { key, value } => {
            let report = config::set(&mut store, &key, &value).map_err(Failure::usage)?;

            render(&report, globals.output, trace)?;
        }
        ConfigAction::Reset { key } => {
            let report = config::reset(&mut store, key.as_deref()).map_err(Failure::usage)?;

            render(&report, globals.output, trace)?;
        }
    }

    Ok(ExitCode::from(EXIT_READY))
}
