// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Zones and ledgers: the administrative commands, over whichever transport
//! the endpoint's scheme names.
//!
//! The transport is the client crate's business — `http`/`https` ride the
//! HTTP surface, `grpc`/`grpcs` the gRPC one — and the semantics are the
//! server's. What is left here is what a command *is*: which question to ask,
//! and how the answer reads.
//!
//! A rename or a delete names the revision it was made against (WP-7.3a): the one the operator
//! gave with `--expected-revision`, or else the one a read just before answers.

use std::process::ExitCode;

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
/// exits as a usage error; a plane that does not answer exits as unavailable.
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
    let tls = crate::target::tls(globals, &store, trace)?;

    // One catalog, whichever transport the scheme named: the client crate owns
    // that choice, so this file is about commands and nothing else.
    if url.starts_with("https://") && tls.skip_verify {
        trace::warn("TLS certificate verification is disabled: the endpoint is not authenticated");
    }
    let backend = catalog::client(&url, &tls, crate::narrator::for_run(globals.verbose))
        .map_err(Failure::usage)?;
    // The one conversion every command that talks to a plane uses, so a refusal the operator can
    // fix, a plane that is not answering and a failure inside one exit as three different
    // statuses here exactly as they do from `check`. The message stays clean: the code is its own
    // field, and only the terminal rendering appends it in parentheses.
    let failed = |failure: catalog::Failure| Failure::from_client(&failure);

    match action {
        CatalogAction::Zones(action) => match action {
            ZonesAction::Create { name } => {
                let zone = backend.create_zone(&name).map_err(failed)?;

                render(
                    &workspace_out::ZoneReport {
                        action: "created",
                        zone: zone.into(),
                    },
                    globals.output,
                    trace,
                )?;
            }
            ZonesAction::List { page, size } => {
                let listed = backend.list_zones(page, size).map_err(failed)?;

                render(
                    &workspace_out::ZoneListReport {
                        zones: listed.into_iter().map(Into::into).collect(),
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
                        zone: zone.into(),
                    },
                    globals.output,
                    trace,
                )?;
            }
            ZonesAction::Update {
                zone,
                name,
                expected_revision,
            } => {
                let revision = match expected_revision {
                    Some(revision) => revision,
                    None => backend.get_zone(&zone).map_err(failed)?.revision,
                };
                let zone = backend
                    .rename_zone(&zone, &name, revision)
                    .map_err(failed)?;

                render(
                    &workspace_out::ZoneReport {
                        action: "renamed",
                        zone: zone.into(),
                    },
                    globals.output,
                    trace,
                )?;
            }
            ZonesAction::Delete {
                zone,
                expected_revision,
            } => {
                let revision = match expected_revision {
                    Some(revision) => revision,
                    None => backend.get_zone(&zone).map_err(failed)?.revision,
                };
                let zone = backend.delete_zone(&zone, revision).map_err(failed)?;

                render(
                    &workspace_out::ZoneReport {
                        action: "deleted",
                        zone: zone.into(),
                    },
                    globals.output,
                    trace,
                )?;
            }
            ZonesAction::Import {
                file,
                target,
                mode,
                bundle,
                pin,
            } => {
                let request = import_request(&file, mode, None, &bundle, pin)?;
                let imported = backend.import(&target, &request).map_err(failed)?;
                render(&ImportReport(&imported), globals.output, trace)?;
            }
            ZonesAction::Export { zone, out } => {
                let export = backend.export_zone(&zone).map_err(failed)?;
                written(&out, &export, globals, trace)?;
            }
        },
        CatalogAction::Ledgers(action) => match action {
            LedgersAction::Import {
                file,
                target,
                mode,
                bundle,
                pin,
            } => {
                let Some((zone, name)) = target.split_once('/') else {
                    return Err(Failure::usage(format!(
                        "--as {target}: name the zone and the ledger, `<zone>/<name>`"
                    )));
                };
                let request = import_request(&file, mode, Some(name.to_owned()), &bundle, pin)?;
                let imported = backend.import(zone, &request).map_err(failed)?;
                render(&ImportReport(&imported), globals.output, trace)?;
            }
            LedgersAction::Export { zone, ledger, out } => {
                let export = backend.export_ledger(&zone, &ledger).map_err(failed)?;
                written(&out, &export, globals, trace)?;
            }
            LedgersAction::Create { zone, name } => {
                let ledger = backend.create_ledger(&zone, &name).map_err(failed)?;

                render(
                    &workspace_out::LedgerReport {
                        action: "created",
                        ledger: ledger.into(),
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
                        ledgers: listed.into_iter().map(Into::into).collect(),
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
                        ledger: ledger.into(),
                    },
                    globals.output,
                    trace,
                )?;
            }
            LedgersAction::Update {
                zone,
                ledger,
                name,
                expected_revision,
            } => {
                let revision = match expected_revision {
                    Some(revision) => revision,
                    None => backend.get_ledger(&zone, &ledger).map_err(failed)?.revision,
                };
                let ledger = backend
                    .rename_ledger(&zone, &ledger, &name, revision)
                    .map_err(failed)?;

                render(
                    &workspace_out::LedgerReport {
                        action: "renamed",
                        ledger: ledger.into(),
                    },
                    globals.output,
                    trace,
                )?;
            }
            LedgersAction::Archive {
                zone,
                ledger,
                expected_revision,
            } => {
                let revision = match expected_revision {
                    Some(revision) => revision,
                    None => backend.get_ledger(&zone, &ledger).map_err(failed)?.revision,
                };
                let ledger = backend
                    .archive_ledger(&zone, &ledger, revision)
                    .map_err(failed)?;

                render(
                    &workspace_out::LedgerReport {
                        action: "archived",
                        ledger: ledger.into(),
                    },
                    globals.output,
                    trace,
                )?;
            }
            LedgersAction::Restore {
                zone,
                ledger,
                expected_revision,
            } => {
                let revision = match expected_revision {
                    Some(revision) => revision,
                    None => backend.get_ledger(&zone, &ledger).map_err(failed)?.revision,
                };
                let ledger = backend
                    .restore_ledger(&zone, &ledger, revision)
                    .map_err(failed)?;

                render(
                    &workspace_out::LedgerReport {
                        action: "restored",
                        ledger: ledger.into(),
                    },
                    globals.output,
                    trace,
                )?;
            }
            LedgersAction::Delete {
                zone,
                ledger,
                expected_revision,
            } => {
                let revision = match expected_revision {
                    Some(revision) => revision,
                    None => backend.get_ledger(&zone, &ledger).map_err(failed)?.revision,
                };
                let ledger = backend
                    .delete_ledger(&zone, &ledger, revision)
                    .map_err(failed)?;

                render(
                    &workspace_out::LedgerReport {
                        action: "deleted",
                        ledger: ledger.into(),
                    },
                    globals.output,
                    trace,
                )?;
            }
        },
    }

    Ok(ExitCode::from(EXIT_READY))
}

/// What an export reports: where the archive went and what it binds.
#[derive(serde::Serialize)]
struct ExportReport<'a> {
    path: String,
    #[serde(flatten)]
    export: &'a catalog::Export,
}

impl crate::output::Report for ExportReport<'_> {
    fn render_terminal(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(out, "Exported to {}", self.path)?;
        writeln!(out, "zone_id        {}", self.export.zone_id)?;
        writeln!(out, "bundle digest  {}", self.export.bundle_digest)?;
        writeln!(out, "bundle bytes   {}", self.export.bundle_bytes)?;
        for ledger in &self.export.ledgers {
            writeln!(
                out,
                "  {} {:<24} {} ref(s), {} object(s), {} statement(s)",
                ledger.id, ledger.name, ledger.refs, ledger.objects, ledger.statements
            )?;
        }
        Ok(())
    }
}

/// Writes `export`'s archive to the new file `output`, readable by its owner only, and reports
/// it (WP-7.10).
fn written(
    output: &std::path::Path,
    export: &catalog::Export,
    globals: &Globals,
    trace: &Trace,
) -> Result<(), Failure> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(output)
        .map_err(|error| Failure::usage(format!("--out {}: {error}", output.display())))?;
    if let Err(error) = file.write_all(&export.archive) {
        // A partial archive is not left where a retry would be refused for it.
        drop(file);
        let _ = std::fs::remove_file(output);
        return Err(Failure::unavailable(format!(
            "writing {}: {error}",
            output.display()
        )));
    }
    render(
        &ExportReport {
            path: output.display().to_string(),
            export,
        },
        globals.output,
        trace,
    )?;
    Ok(())
}

/// The keys bundle file an import reads (WP-7.10): the source Host's bundle, base64url.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleFile {
    manifest: String,
    items: Vec<String>,
}

/// What `import` hands the plane: the archive file, the bundle file decoded, the pin.
fn import_request(
    file: &std::path::Path,
    mode: String,
    name: Option<String>,
    bundle: &std::path::Path,
    pin: String,
) -> Result<catalog::ImportRequest, Failure> {
    use base64::Engine as _;
    let read = |path: &std::path::Path| {
        std::fs::read(path).map_err(|error| Failure::usage(format!("{}: {error}", path.display())))
    };
    let archive = read(file)?;
    let held: BundleFile = serde_json::from_slice(&read(bundle)?).map_err(|error| {
        Failure::usage(format!(
            "--bundle {}: not a keys bundle file: {error}",
            bundle.display()
        ))
    })?;
    let decode = |value: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|error| {
                Failure::usage(format!(
                    "--bundle {}: a value is not base64url: {error}",
                    bundle.display()
                ))
            })
    };
    Ok(catalog::ImportRequest {
        mode,
        name,
        archive,
        bundle_manifest: decode(&held.manifest)?,
        bundle_items: held
            .items
            .iter()
            .map(|item| decode(item))
            .collect::<Result<_, _>>()?,
        pin,
    })
}

/// What an import reports.
#[derive(serde::Serialize)]
#[serde(transparent)]
struct ImportReport<'a>(&'a catalog::Imported);

impl crate::output::Report for ImportReport<'_> {
    fn render_terminal(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        let imported = self.0;
        writeln!(out, "Imported ({})", imported.mode)?;
        writeln!(out, "manifest digest  {}", imported.manifest_digest)?;
        writeln!(out, "source host      {}", imported.source_host_id)?;
        writeln!(out, "source zone      {}", imported.source_zone_id)?;
        if let Some(archive) = &imported.archive {
            writeln!(out, "archive          {} ({})", archive.name, archive.id)?;
            writeln!(
                out,
                "Kept as foreign evidence: never a ledger of this Host, never served."
            )?;
        }
        for ledger in &imported.ledgers {
            writeln!(out, "  ledger {} {}", ledger.id, ledger.name)?;
        }
        if !imported.ledgers.is_empty() {
            writeln!(
                out,
                "Re-homed: each ledger serves once you push its head (`permguard apply`)."
            )?;
        }
        Ok(())
    }
}
