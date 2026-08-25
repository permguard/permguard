// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What every command needs before it can do anything: where the operator's
//! configuration is, which endpoint a flag or a file or a default resolved
//! to, and how a report reaches standard output.
//!
//! Shared plumbing, not a command — which is why it is here and not in
//! `commands/`, and why `main.rs` holds nothing but the dispatch.

use crate::args::Globals;
use crate::failure::Failure;
use crate::output::{OutputFormat, Report, emit};
use crate::settings::{self, Origin, Store};
use crate::trace::Trace;
use permguard_control_client::Endpoint;

pub fn resolve_endpoint_url(
    key: &str,
    flag: Option<&str>,
    store: &Store,
    trace: &Trace,
) -> Result<String, Failure> {
    let setting = settings::setting(key).ok_or_else(|| {
        // Unreachable: the keys are compiled in.
        Failure::internal(format!("`{key}` is not a setting"))
    })?;
    let resolved = settings::resolve(setting, store.file(), flag, &settings::environment);
    trace.say(format!("{key} = {} [{}]", resolved.value, resolved.origin));
    Ok(resolved.value)
}

pub fn open_store(globals: &Globals, trace: &Trace) -> Result<Store, Failure> {
    let path = settings::config_path(globals.config.as_deref()).map_err(Failure::usage)?;

    trace.say(format!("configuration file: {}", path.display()));

    Store::open(path).map_err(Failure::usage)
}

pub fn resolve_endpoint(
    key: &str,
    flag: Option<&str>,
    store: &Store,
    trace: &Trace,
) -> Result<Endpoint, Failure> {
    let setting = settings::setting(key).ok_or_else(|| {
        // Unreachable: the keys are compiled in, and this one is written above.
        Failure::internal(format!("`{key}` is not a setting"))
    })?;
    let resolved = settings::resolve(setting, store.file(), flag, &settings::environment);

    trace.say(format!("{key} = {} [{}]", resolved.value, resolved.origin));

    Endpoint::parse(&resolved.value).map_err(|error| {
        Failure::usage(match resolved.origin {
            Origin::Default => format!("{error}"),
            origin => format!("{error} (from the {origin})"),
        })
    })
}

pub fn render<R: Report>(report: &R, format: OutputFormat, trace: &Trace) -> Result<(), Failure> {
    match emit(report, format) {
        Ok(()) => Ok(()),
        Err(error) => {
            // `permguard inspect | head -1` closes the pipe, and a CLI that reports that as a
            // failure is a CLI that cannot be piped.
            if let Some(io) = error.downcast_ref::<std::io::Error>()
                && io.kind() == std::io::ErrorKind::BrokenPipe
            {
                trace.say("output closed early");

                return Ok(());
            }

            Err(Failure::internal(format!("{error:#}")))
        }
    }
}
