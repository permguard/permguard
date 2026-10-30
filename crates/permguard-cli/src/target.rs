// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Which server a command talks to, and which policy store it acts on.
//!
//! One function, used by every command that needs the answer, because an
//! operator should not have to learn a different precedence per command — and
//! because a rule written twice is a rule that will disagree with itself.
//!
//! # The precedence, once
//!
//! ```text
//! endpoint:    flag  >  environment  >  configuration file  >  compiled default
//! zone/ledger: flag  >  workspace  >  whatever the request states
//! ```
//!
//! The endpoint follows the layered pipeline every setting in this CLI
//! follows. The store follows the workspace, because a person standing in a
//! checked-out ledger means *this* ledger: `permguard check` there asks about
//! what they are looking at, whatever a hand-written payload happens to say.
//!
//! # Escaping the workspace
//!
//! `--ignore-workspace` sends the document exactly as written — the escape
//! hatch for trying another ledger's payload from inside a checkout, and for a
//! script that keeps its requests in files. It never affects the endpoint:
//! where to send a request and what to ask about are two different questions,
//! and the flags that answer them are separate.

use permguard_control_client::TlsOptions;

use crate::args::Globals;
use crate::failure::Failure;
use crate::session;
use crate::settings::Store;
use crate::trace::Trace;
use permguard_cli::engine::{FsStore, Workspace};

/// What a command was told, before the workspace and the settings are read.
#[derive(Debug, Default, Clone)]
pub struct Asked {
    /// `--zone`, when the caller named one.
    pub zone: Option<String>,
    /// `--ledger`, when the caller named one.
    pub ledger: Option<String>,
    /// `--ignore-workspace`: leave the document's own store alone.
    pub ignore_workspace: bool,
}

/// Where a command sends its request, and what it acts on.
#[derive(Debug, Clone)]
pub struct Target {
    /// The endpoint, resolved through the layers.
    pub endpoint: String,
    /// The zone to act on, when anything named one.
    pub zone: Option<String>,
    /// The ledger to act on, when anything named one.
    pub ledger: Option<String>,
    /// Where the store came from, for `-v` and for a report that has to
    /// explain itself: `flag`, `workspace`, or `payload`.
    pub origin: &'static str,
}

impl Target {
    /// Whether this target names a store to override a document with.
    pub fn names_store(&self) -> bool {
        self.zone.is_some() && self.ledger.is_some()
    }
}

/// Resolves the endpoint a command sends to, and the store it is about.
///
/// `setting` is the settings key whose layers name the endpoint — the data
/// plane's for a decision, the control plane's for an administrative command —
/// so this stays one function rather than one per surface.
pub fn resolve(
    setting: &str,
    flag: Option<&str>,
    asked: &Asked,
    globals: &Globals,
    store: &Store,
    trace: &Trace,
) -> Result<Target, Failure> {
    let endpoint = session::resolve_endpoint_url(setting, flag, store, trace)?;

    // The flags win, always: they are the most specific thing anybody said.
    if let (Some(zone), Some(ledger)) = (&asked.zone, &asked.ledger) {
        trace.say(format!("store = {zone}/{ledger} [flags]"));

        return Ok(Target {
            endpoint,
            zone: Some(zone.clone()),
            ledger: Some(ledger.clone()),
            origin: "flag",
        });
    }
    if asked.zone.is_some() != asked.ledger.is_some() {
        return Err(Failure::usage(
            "--zone and --ledger name one store together: state both, or neither",
        ));
    }

    if asked.ignore_workspace {
        trace.say("store = whatever the request states [--ignore-workspace]");

        return Ok(Target {
            endpoint,
            zone: None,
            ledger: None,
            origin: "payload",
        });
    }

    // A person standing in a checked-out ledger means this ledger.
    let workspace_store = FsStore::new(&globals.workdir);
    let workspace = Workspace::open(&workspace_store);
    if let Ok(config) = workspace.config()
        && let Some(tracked) = config.ledger
    {
        trace.say(format!(
            "store = {}/{} [workspace]",
            tracked.zone, tracked.ledger
        ));

        return Ok(Target {
            endpoint,
            zone: Some(tracked.zone),
            ledger: Some(tracked.ledger),
            origin: "workspace",
        });
    }

    trace.say("store = whatever the request states [no workspace]");

    Ok(Target {
        endpoint,
        zone: None,
        ledger: None,
        origin: "payload",
    })
}

/// The operator's material for every network command (TC-1): the TLS paths a flag states, or
/// the configuration; the key by `tls.key_ref` (`env:NAME` or `file:PATH`) instead of a file; and
/// the bearer token from `--token-file` or `auth.token_file`. A relative path from a flag or the
/// environment is resolved against the working directory, one from the configuration file
/// against that file's directory (owner decision of 2026-10-10), so no file planted where a
/// command runs becomes a trust anchor. Nothing secret is ever traced: `-v` names the files,
/// never what they hold.
pub fn tls(globals: &Globals, store: &Store, trace: &Trace) -> Result<TlsOptions, Failure> {
    let path = |flag: &Option<std::path::PathBuf>, key: &str| -> Option<std::path::PathBuf> {
        match flag {
            Some(flag) => Some(rooted_at(&globals.workdir, flag)),
            None => configured(key, store, globals),
        }
    };
    let mut options = TlsOptions {
        ca_file: path(&globals.tls_ca_file, "tls.ca_file"),
        cert_file: path(&globals.tls_cert_file, "tls.cert_file"),
        key_file: None,
        server_name: globals
            .tls_server_name
            .clone()
            .or_else(|| setting_value("tls.server_name", store).map(|(value, _)| value)),
        skip_verify: globals.tls_skip_verify,
        key_pem: None,
        token: None,
    };
    // The client key, the most specific statement winning: a flag (or its variable), then a
    // reference in the environment, then the configuration file, where naming it twice is a
    // mistake rather than a precedence.
    let key_file = setting_value("tls.key_file", store);
    let key_ref = setting_value("tls.key_ref", store);
    if let Some(flag) = &globals.tls_key_file {
        options.key_file = Some(rooted_at(&globals.workdir, flag));
    } else {
        match (key_ref, key_file) {
            (
                Some((_, crate::settings::Origin::File)),
                Some((_, crate::settings::Origin::File)),
            ) => {
                return Err(Failure::usage(
                    "the client key is named twice in the configuration, by `tls.key_file` and \
                     by `tls.key_ref`: keep one",
                ));
            }
            (Some((reference, origin)), _) => {
                key_by_reference(&mut options, &reference, origin, store, globals, trace)?;
            }
            (None, Some(_)) => options.key_file = configured("tls.key_file", store, globals),
            (None, None) => {}
        }
    }
    let token_file = match &globals.token_file {
        Some(flag) => Some(rooted_at(&globals.workdir, flag)),
        None => configured("auth.token_file", store, globals),
    };
    if let Some(named) = token_file {
        trace.say(format!("bearer token: {}", named.display()));
        options.token = Some(read_token(&named)?);
    }
    Ok(options)
}

/// The key a `tls.key_ref` names: a variable's PEM, or a file resolved as its origin resolves.
fn key_by_reference(
    options: &mut TlsOptions,
    reference: &str,
    origin: crate::settings::Origin,
    store: &Store,
    globals: &Globals,
    trace: &Trace,
) -> Result<(), Failure> {
    match reference.split_once(':') {
        Some(("env", name)) if !name.is_empty() => {
            trace.say(format!("client key: the variable {name} [tls.key_ref]"));
            let pem = std::env::var_os(name).ok_or_else(|| {
                Failure::usage(format!(
                    "`tls.key_ref` names the variable {name}, which is not set"
                ))
            })?;
            let pem = pem.into_string().map_err(|_| {
                Failure::usage(format!(
                    "`tls.key_ref` names the variable {name}, which does not hold text"
                ))
            })?;
            if pem.trim().is_empty() {
                return Err(Failure::usage(format!(
                    "`tls.key_ref` names the variable {name}, which is empty"
                )));
            }
            options.key_pem = Some(permguard_control_client::tls::Credential::new(pem));
        }
        Some(("file", named)) if !named.is_empty() => {
            trace.say(format!("client key: {named} [tls.key_ref]"));
            let named = std::path::Path::new(named);
            options.key_file = Some(match origin {
                crate::settings::Origin::File => rooted_at(&config_dir(store), named),
                _ => rooted_at(&globals.workdir, named),
            });
        }
        _ => {
            return Err(Failure::usage(
                "`tls.key_ref` is a reference: env:NAME or file:PATH",
            ));
        }
    }
    Ok(())
}

/// A setting the environment or the file states, with where it came from; never a compiled
/// default, none of these having one.
fn setting_value(key: &str, store: &Store) -> Option<(String, crate::settings::Origin)> {
    let setting = crate::settings::setting(key)?;
    let resolved =
        crate::settings::resolve(setting, store.file(), None, &crate::settings::environment);
    (!resolved.value.trim().is_empty()).then_some((resolved.value, resolved.origin))
}

/// A path setting, resolved as its origin says: the configuration file's directory for the file,
/// the working directory for the environment.
fn configured(key: &str, store: &Store, globals: &Globals) -> Option<std::path::PathBuf> {
    let (value, origin) = setting_value(key, store)?;
    let named = std::path::Path::new(&value);
    Some(match origin {
        crate::settings::Origin::File => rooted_at(&config_dir(store), named),
        _ => rooted_at(&globals.workdir, named),
    })
}

/// The directory of the configuration file.
fn config_dir(store: &Store) -> std::path::PathBuf {
    store
        .path()
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_default()
}

/// `path` as is when absolute, below `base` otherwise.
fn rooted_at(base: &std::path::Path, path: &std::path::Path) -> std::path::PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

/// Reads the bearer token from `path`, by the library's rule (TC-1): a refusal is a usage error.
pub fn read_token(
    path: &std::path::Path,
) -> Result<permguard_control_client::tls::Credential, Failure> {
    permguard_cli::token::read(path).map_err(Failure::usage)
}

/// The one target class a command reaches (TC-1): a command names exactly one, and a flag naming
/// another is a usage error, never a fallback from one plane or Host to another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// The workspace and nothing else.
    Local,
    /// The Control Plane public API.
    Control,
    /// The Data Plane public API.
    Data,
    /// The Host listener.
    Host,
    /// A Server Host's volume, offline.
    Volume,
    /// Both plane endpoints: a multi-target probe such as `inspect`.
    Planes,
}

impl Class {
    fn reaches(self) -> &'static str {
        match self {
            Self::Local => "the workspace alone",
            Self::Control => "the control plane",
            Self::Data => "the data plane",
            Self::Host => "the Host listener",
            Self::Volume => "a Server Host's volume",
            Self::Planes => "both planes",
        }
    }
}

/// Refuses a flag that names a target `class` does not reach.
pub fn check_class(command: &str, class: Class, globals: &Globals) -> Result<(), Failure> {
    let named = [
        (
            "--control-endpoint",
            globals.control_endpoint.is_some(),
            matches!(class, Class::Control | Class::Planes),
        ),
        (
            "--data-endpoint",
            globals.data_endpoint.is_some(),
            matches!(class, Class::Data | Class::Planes),
        ),
        (
            "--host-endpoint",
            globals.host_endpoint.is_some(),
            class == Class::Host,
        ),
        ("--volume", globals.volume.is_some(), class == Class::Volume),
    ];
    match named.iter().find(|(_, given, allowed)| *given && !allowed) {
        Some((flag, _, _)) => Err(Failure::usage(format!(
            "`{command}` reaches {}; {flag} names another target, and a command never falls \
             back from one to another",
            class.reaches()
        ))),
        None => Ok(()),
    }
}
