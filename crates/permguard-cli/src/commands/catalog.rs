// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Zones and ledgers: the administrative commands, over whichever transport
//! the endpoint's scheme names.
//!
//! The transport is the client crate's business — `http`/`https` ride the
//! HTTP surface, `grpc`/`grpcs` the gRPC one — and the semantics are the
//! server's. What is left here is what a command *is*: which question to ask,
//! and how the answer reads.

use std::process::ExitCode;

use permguard_control_client::TlsOptions;
use permguard_control_client::catalog;

use crate::args::{Globals, LedgersAction, ZonesAction};
use crate::failure::{EXIT_READY, Failure};
use crate::session::{open_store, render, resolve_endpoint_url};
use crate::trace::{self, Trace};
use crate::workspace_out;

/// The two command families that speak to the catalog, joined so they share one setup.
pub enum CatalogAction {
    Zones(ZonesAction),
    Ledgers(LedgersAction),
}

/// Runs one catalog command against the control plane — over HTTP or gRPC,
/// whichever the endpoint's scheme names; the semantics live on the server.
/// A refusal the operator can fix — a taken name, a zone that is not empty —
/// exits as a usage error; a transport failure exits as one.
pub fn catalog_command(
    globals: &Globals,
    action: CatalogAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    let store = open_store(globals, trace)?;
    let url = resolve_endpoint_url(
        "control-plane.endpoint",
        globals.control_endpoint.as_deref(),
        &store,
        trace,
    )?;
    let tls = TlsOptions {
        ca_file: globals.tls_ca_file.clone(),
        cert_file: globals.tls_cert_file.clone(),
        key_file: globals.tls_key_file.clone(),
        server_name: globals.tls_server_name.clone(),
        skip_verify: globals.tls_skip_verify,
    }
    .rooted_at(&globals.workdir);

    // One catalog, whichever transport the scheme named: the client crate owns
    // that choice, so this file is about commands and nothing else.
    if url.starts_with("https://") && tls.skip_verify {
        trace::warn("TLS certificate verification is disabled: the endpoint is not authenticated");
    }
    let backend = catalog::client(&url, &tls, crate::narrator::for_run(globals.verbose))
        .map_err(Failure::usage)?;
    // The message stays clean: the code is its own field, and only the terminal rendering appends
    // it in parentheses — a structured error that repeats its code inside its sentence is a field
    // nobody can trust to be prose.
    let failed = |failure: catalog::Failure| {
        if failure.usage {
            Failure::usage(&failure.detail).named(failure.class, failure.reason)
        } else {
            Failure::internal(&failure.detail).named(failure.class, failure.reason)
        }
    };

    match action {
        CatalogAction::Zones(action) => match action {
            ZonesAction::Create { name } => {
                let zone = backend.create_zone(&name).map_err(failed)?;

                render(
                    &workspace_out::ZoneReport {
                        action: "created",
                        zone,
                    },
                    globals.output,
                    trace,
                )?;
            }
            ZonesAction::List { page, size } => {
                let listed = backend.list_zones(page, size).map_err(failed)?;

                render(
                    &workspace_out::ZoneListReport {
                        zones: listed,
                        page,
                    },
                    globals.output,
                    trace,
                )?;
            }
            ZonesAction::Get { zone } => {
                let zone = backend.get_zone(&zone).map_err(failed)?;

                render(
                    &workspace_out::ZoneReport {
                        action: "found",
                        zone,
                    },
                    globals.output,
                    trace,
                )?;
            }
            ZonesAction::Update { zone, name } => {
                let zone = backend.rename_zone(&zone, &name).map_err(failed)?;

                render(
                    &workspace_out::ZoneReport {
                        action: "renamed",
                        zone,
                    },
                    globals.output,
                    trace,
                )?;
            }
            ZonesAction::Delete { zone } => {
                let zone = backend.delete_zone(&zone).map_err(failed)?;

                render(
                    &workspace_out::ZoneReport {
                        action: "deleted",
                        zone,
                    },
                    globals.output,
                    trace,
                )?;
            }
        },
        CatalogAction::Ledgers(action) => match action {
            LedgersAction::Create { zone, name } => {
                let ledger = backend.create_ledger(&zone, &name).map_err(failed)?;

                render(
                    &workspace_out::LedgerReport {
                        action: "created",
                        ledger,
                    },
                    globals.output,
                    trace,
                )?;
            }
            LedgersAction::List { zone, page, size } => {
                let listed = backend.list_ledgers(&zone, page, size).map_err(failed)?;

                render(
                    &workspace_out::LedgerListReport {
                        zone,
                        ledgers: listed,
                        page,
                    },
                    globals.output,
                    trace,
                )?;
            }
            LedgersAction::Get { zone, ledger } => {
                let ledger = backend.get_ledger(&zone, &ledger).map_err(failed)?;

                render(
                    &workspace_out::LedgerReport {
                        action: "found",
                        ledger,
                    },
                    globals.output,
                    trace,
                )?;
            }
            LedgersAction::Update { zone, ledger, name } => {
                let ledger = backend
                    .rename_ledger(&zone, &ledger, &name)
                    .map_err(failed)?;

                render(
                    &workspace_out::LedgerReport {
                        action: "renamed",
                        ledger,
                    },
                    globals.output,
                    trace,
                )?;
            }
            LedgersAction::Delete { zone, ledger } => {
                let ledger = backend.delete_ledger(&zone, &ledger).map_err(failed)?;

                render(
                    &workspace_out::LedgerReport {
                        action: "deleted",
                        ledger,
                    },
                    globals.output,
                    trace,
                )?;
            }
        },
    }

    Ok(ExitCode::from(EXIT_READY))
}
