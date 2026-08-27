// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What every command needs before it can do anything: where the operator's
//! configuration is, which endpoint a flag or a file or a default resolved
//! to, and how a report reaches standard output.
//!
//! Shared plumbing, not a command — which is why it is here and not in
//! `commands/`, and why `main.rs` holds nothing but the dispatch.

use std::path::{Path, PathBuf};

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

/// A path a flag named, resolved the way `-w` says every relative path is.
///
/// `-w` is documented as "the directory relative paths are resolved against", and a flag that
/// resolved its own against the process's current directory instead would make that sentence false
/// for exactly the arguments a person passes by hand. An absolute path is already an answer and is
/// left alone; `-` is standard input and never reaches here.
///
/// The default `-w` is `.`, so a command that names no working directory behaves as it always did.
pub fn rooted(globals: &Globals, path: &str) -> PathBuf {
    let named = Path::new(path);
    if named.is_absolute() {
        return named.to_path_buf();
    }

    globals.workdir.join(named)
}

pub fn open_store(globals: &Globals, trace: &Trace) -> Result<Store, Failure> {
    let path = match globals.config.as_deref() {
        Some(named) => rooted(globals, named),
        None => settings::config_path(None).map_err(Failure::usage)?,
    };

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
