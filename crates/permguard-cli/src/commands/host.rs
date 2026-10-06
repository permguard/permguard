// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `permguard host grants`: the grant store of a volume, offline (WP-2.4, owner decision of
//! 2026-10-06).
//!
//! The Host API that lists, issues and revokes grants arrives with the dedicated Host listener
//! (WP-2.5); until then an operator works on the volume itself, with the server stopped: the
//! process lock refuses a volume another process holds. `bootstrap` writes the one recovery
//! administrator's commitment, once; `issue`, `revoke` and `list` append to and read the journal.
//!
//! `TODO(WP-3.6)`: issue and revoke become the Host security-mutation transaction.

use std::collections::BTreeMap;
use std::process::ExitCode;

use serde::Serialize;

use permguard_core::assurance::AssuranceProfile;
use permguard_core::authz::{Principal, Selector};
use permguard_host::authz::{AuthzError, GrantId, GrantRecord, GrantStore, Issue};
use permguard_host::storage::volume::Volume;

use crate::args::{Globals, GrantsAction, HostAction};
use crate::failure::{EXIT_READY, Failure};
use crate::output::Report;
use crate::session::render;
use crate::trace::Trace;

/// Runs one `host …` command.
pub fn host_command(
    globals: &Globals,
    action: HostAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    match action {
        HostAction::Grants { action } => grants(globals, action, trace),
    }
}

fn grants(globals: &Globals, action: GrantsAction, trace: &Trace) -> Result<ExitCode, Failure> {
    let now = permguard_host::authz::store::now();
    match action {
        GrantsAction::Bootstrap {
            volume,
            fingerprint,
        } => {
            let store = open(&volume, trace)?;
            let (commitment, grant) = store
                .bootstrap_recovery_administrator(&fingerprint, now)
                .map_err(failure)?;
            render(
                &BootstrapReport {
                    principal: commitment.principal.to_string(),
                    fingerprint: commitment.fingerprint,
                    created_at: permguard_core::time::to_rfc3339(
                        i64::try_from(commitment.created_at).unwrap_or(i64::MAX),
                    ),
                    grant: grant.as_ref().map(grant_report),
                    already_there: grant.is_none(),
                },
                globals.output,
                trace,
            )?;
        }
        GrantsAction::Issue {
            volume,
            principal,
            operations,
            selector,
            types,
            expires,
            issued_by,
        } => {
            let store = open(&volume, trace)?;
            let expires_at = match expires {
                Some(text) => Some(
                    permguard_core::time::from_rfc3339(&text)
                        .and_then(|seconds| u64::try_from(seconds).ok())
                        .ok_or_else(|| {
                            Failure::usage(format!("`{text}` is not an RFC 3339 instant"))
                        })?,
                ),
                None => None,
            };
            let record = store
                .issue(
                    Issue {
                        principal: Principal::new(principal)
                            .map_err(|error| Failure::usage(format!("--principal: {error}")))?,
                        operations,
                        selector: Selector::parse(&selector)
                            .map_err(|error| Failure::usage(format!("--selector: {error}")))?,
                        resource_types: if types.is_empty() {
                            vec!["*".to_owned()]
                        } else {
                            types
                        },
                        constraints: BTreeMap::new(),
                        issued_by,
                        expires_at,
                    },
                    now,
                )
                .map_err(failure)?;
            render(&grant_report(&record), globals.output, trace)?;
        }
        GrantsAction::Revoke {
            volume,
            grant_id,
            by,
        } => {
            let store = open(&volume, trace)?;
            let id =
                GrantId::parse(&grant_id).map_err(|error| Failure::usage(error.to_string()))?;
            let record = store.revoke(id, &by, now).map_err(failure)?;
            render(&grant_report(&record), globals.output, trace)?;
        }
        GrantsAction::List {
            volume,
            principal,
            selector,
        } => {
            let store = open(&volume, trace)?;
            let grants: Vec<GrantReportBody> = store
                .records()
                .iter()
                .filter(|record| {
                    principal
                        .as_deref()
                        .is_none_or(|wanted| record.principal_id.as_str() == wanted)
                })
                .filter(|record| {
                    selector
                        .as_deref()
                        .is_none_or(|wanted| record.selector.to_string() == wanted)
                })
                .map(grant_report)
                .collect();
            render(
                &GrantsReport {
                    revision: store.revision(),
                    grants,
                },
                globals.output,
                trace,
            )?;
        }
    }
    Ok(ExitCode::from(EXIT_READY))
}

fn open(volume: &std::path::Path, trace: &Trace) -> Result<std::sync::Arc<GrantStore>, Failure> {
    trace.say(format!("volume: {}", volume.display()));
    // An existing volume only: a mistyped path must not become a fresh volume holding grants the
    // server never sees. The volume's own layout marker is what says it is one.
    if !volume.join("host").join("FORMAT").is_file() {
        return Err(Failure::usage(format!(
            "{} is not a Server Host volume: no host/FORMAT; start the server once, or check the path",
            volume.display()
        )));
    }
    // Offline: the claim takes the process lock, so a volume a running server holds is refused
    // here with the lock's own message rather than written under it. The development profile is
    // the one that serves an unclaimed volume; the profile the server runs under is its own.
    let held = Volume::claim(volume, AssuranceProfile::Development)
        .map_err(|error| Failure::unavailable(format!("claiming the volume: {error}")))?;
    let (store, recovery) = GrantStore::open(&held).map_err(failure)?;
    if recovery.truncated_bytes > 0 {
        trace.say(format!(
            "the grant journal recovered, truncating {} byte(s)",
            recovery.truncated_bytes
        ));
    }
    // The lock lives as long as the volume; it is held until the process exits.
    std::mem::forget(held);
    Ok(store)
}

fn failure(error: AuthzError) -> Failure {
    match error {
        AuthzError::Invalid(_) | AuthzError::Unknown(_) | AuthzError::Terminal(..) => {
            Failure::usage(error)
        }
        AuthzError::Storage(_) => Failure::unavailable(error),
        AuthzError::Record(_) => Failure::internal(error),
    }
}

#[derive(Serialize)]
struct GrantReportBody {
    grant_id: String,
    principal: String,
    operations: Vec<String>,
    selector: String,
    resource_types: Vec<String>,
    status: &'static str,
    revision: u64,
    issued_by: String,
    issued_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
}

fn grant_report(record: &GrantRecord) -> GrantReportBody {
    let instant =
        |seconds: u64| permguard_core::time::to_rfc3339(i64::try_from(seconds).unwrap_or(i64::MAX));
    GrantReportBody {
        grant_id: record.grant_id.to_string(),
        principal: record.principal_id.to_string(),
        operations: record.operations.clone(),
        selector: record.selector.to_string(),
        resource_types: record.resource_types.clone(),
        status: record.status.as_str(),
        revision: record.revision,
        issued_by: record.issued_by.clone(),
        issued_at: instant(record.issued_at),
        expires_at: record.expires_at.map(instant),
    }
}

impl Report for GrantReportBody {
    fn render_terminal(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(out, "grant      {}", self.grant_id)?;
        writeln!(out, "principal  {}", self.principal)?;
        writeln!(out, "operations {}", self.operations.join(", "))?;
        writeln!(out, "selector   {}", self.selector)?;
        writeln!(out, "types      {}", self.resource_types.join(", "))?;
        writeln!(
            out,
            "status     {} (revision {})",
            self.status, self.revision
        )?;
        writeln!(out, "issued     {} by {}", self.issued_at, self.issued_by)?;
        if let Some(expires) = &self.expires_at {
            writeln!(out, "expires    {expires}")?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct GrantsReport {
    revision: u64,
    grants: Vec<GrantReportBody>,
}

impl Report for GrantsReport {
    fn render_terminal(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(
            out,
            "{} grant(s) at revision {}",
            self.grants.len(),
            self.revision
        )?;
        for grant in &self.grants {
            writeln!(
                out,
                "{}  {:<8} {}  {}  {}",
                grant.grant_id,
                grant.status,
                grant.principal,
                grant.operations.join(","),
                grant.selector
            )?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct BootstrapReport {
    principal: String,
    fingerprint: String,
    created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant: Option<GrantReportBody>,
    already_there: bool,
}

impl Report for BootstrapReport {
    fn render_terminal(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        if self.already_there {
            writeln!(
                out,
                "the volume already commits to this recovery administrator"
            )?;
        } else {
            writeln!(out, "recovery administrator committed")?;
        }
        writeln!(out, "principal   {}", self.principal)?;
        writeln!(out, "fingerprint {}", self.fingerprint)?;
        writeln!(out, "created     {}", self.created_at)?;
        if let Some(grant) = &self.grant {
            writeln!(out)?;
            grant.render_terminal(out)?;
        }
        Ok(())
    }
}
