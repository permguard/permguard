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

/// The TLS material the globals carry, resolved against the working
/// directory — the same material every other command presents.
pub fn tls(globals: &Globals) -> TlsOptions {
    TlsOptions {
        ca_file: globals.tls_ca_file.clone(),
        cert_file: globals.tls_cert_file.clone(),
        key_file: globals.tls_key_file.clone(),
        server_name: globals.tls_server_name.clone(),
        skip_verify: globals.tls_skip_verify,
    }
    .rooted_at(&globals.workdir)
}
