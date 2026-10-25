// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `permguard host keys`, `host audit`, `host config`, `host status` and `host plans` (TC-2):
//! the Host listener's key rings, audit trails, configuration, lifecycle and plans, each one
//! call of the Host facade over REST or gRPC, printed as the Host answers it.
//!
//! A two-step change writes its plan to a new owner-only file and runs from it, as
//! `host grants revoke` does. A bundle or an export walks every page at the frontier its first
//! page fixed and writes them to a new owner-only file, never one that exists.

use std::process::ExitCode;

use permguard_control_client::host::Operations;
use permguard_host::api::audit::{AuditCheckpointQuery, AuditExportQuery, AuditQuery};
use permguard_host::api::keys::{KeyBundleQuery, PlanKeyRevoke, RotateRing, RunKeyRevoke};
use permguard_host::api::plans::ApprovePlan;
use serde::Serialize;

use super::host::{Reserved, online_host, read_json, render_json, request_id, rooted_file};
use crate::args::{
    AuditAction, BundleAction, Globals, HostConfigAction, KeyRevokeAction, KeysAction, PlansAction,
};
use crate::failure::Failure;
use crate::trace::Trace;

/// The most pages one bundle or export walks: far past any bundle or trail page count, so a
/// Host that never stops answering a cursor cannot keep the command running.
const MAX_PAGES: usize = 100_000;

fn failed(failure: permguard_control_client::catalog::Failure) -> Failure {
    Failure::from_client(&failure)
}

/// Seconds since the epoch of an instant the argument parser already read as RFC 3339.
fn seconds(instant: Option<String>) -> Result<Option<u64>, Failure> {
    instant
        .map(|text| {
            permguard_core::time::from_rfc3339(&text)
                .and_then(|seconds| u64::try_from(seconds).ok())
                .ok_or_else(|| Failure::usage(format!("`{text}` is before the epoch")))
        })
        .transpose()
}

/// Claims the new owner-only `out`, rooted at the workdir, before the Host is asked.
fn reserve(globals: &Globals, out: &std::path::Path) -> Result<Reserved, Failure> {
    Reserved::claim(&rooted_file(globals, out))
}

/// Fills `reserved` with `value` as pretty JSON.
fn fill(reserved: Reserved, value: &impl Serialize) -> Result<(), Failure> {
    reserved.fill(&serde_json::to_vec_pretty(value).map_err(Failure::internal)?)
}

/// `permguard host keys …`.
pub(super) fn keys(
    globals: &Globals,
    action: KeysAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    let host = online_host(globals, trace, false)?;
    match action {
        KeysAction::List => render_json(&host.rings().map_err(failed)?, globals, trace)?,
        KeysAction::Show { ring } => {
            render_json(&host.ring(&ring).map_err(failed)?, globals, trace)?
        }
        KeysAction::Rotate {
            ring,
            expected_epoch,
        } => {
            let rotated = host
                .rotate_ring(
                    &ring,
                    &RotateRing {
                        request_id: request_id(),
                        expected_epoch,
                    },
                )
                .map_err(failed)?;
            render_json(&rotated, globals, trace)?;
        }
        KeysAction::Revoke { action } => match action {
            KeyRevokeAction::Plan {
                ring,
                kid,
                reason,
                compromised_at,
                expected_epoch,
                out,
            } => {
                let reserved = reserve(globals, &out)?;
                let planned = host
                    .plan_key_revoke(
                        &ring,
                        &PlanKeyRevoke {
                            request_id: request_id(),
                            kid,
                            reason,
                            compromised_at,
                            expected_epoch,
                        },
                    )
                    .map_err(failed)?;
                fill(reserved, &planned)?;
                render_json(&planned, globals, trace)?;
            }
            KeyRevokeAction::Run { ring, confirm_file } => {
                let plan: permguard_host::api::Planned =
                    read_json(&rooted_file(globals, &confirm_file), "key revocation plan")?;
                let revoked = host
                    .run_key_revoke(
                        &ring,
                        &RunKeyRevoke {
                            request_id: request_id(),
                            receipt: plan.receipt,
                        },
                    )
                    .map_err(failed)?;
                render_json(&revoked, globals, trace)?;
            }
        },
        KeysAction::Bundle {
            action: BundleAction::Export { resource, out },
        } => {
            let reserved = reserve(globals, &out)?;
            let bundle = bundle(host.as_ref(), &resource)?;
            fill(reserved, &bundle)?;
            render_json(
                &BundleWritten {
                    resource: bundle.resource,
                    bundle_digest: bundle.bundle_digest,
                    items: bundle.items.len(),
                    out: rooted_file(globals, &out).display().to_string(),
                },
                globals,
                trace,
            )?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// A verification bundle as a file holds it: what `bundle export` writes and `ledgers import
/// --bundle` reads, one shape for both (after the TC-2 review). A file of the manifest and the
/// items alone, as WP-7.10 documented it, still reads.
#[derive(Debug, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BundleFile {
    #[serde(default)]
    pub resource: String,
    pub manifest: String,
    #[serde(default)]
    pub bundle_digest: String,
    pub items: Vec<String>,
}

/// What `bundle export` prints once the file is written.
#[derive(Debug, Serialize)]
struct BundleWritten {
    resource: String,
    bundle_digest: String,
    items: usize,
    out: String,
}

/// Every page of `resource`'s bundle at the frontier its first page fixed.
fn bundle(host: &dyn Operations, resource: &str) -> Result<BundleFile, Failure> {
    let first = host
        .key_bundle(&KeyBundleQuery {
            resource: resource.to_owned(),
            limit: Some(500),
            ..KeyBundleQuery::default()
        })
        .map_err(failed)?;
    let mut items = first.items;
    let mut cursor = first.next_cursor;
    let mut pages = 1;
    while let Some(next) = cursor {
        pages += 1;
        if pages > MAX_PAGES {
            return Err(Failure::unavailable(
                "the Host kept answering the bundle's cursor: nothing was written",
            ));
        }
        let page = host
            .key_bundle(&KeyBundleQuery {
                resource: resource.to_owned(),
                frontier: Some(first.manifest.clone()),
                cursor: Some(next),
                limit: Some(500),
            })
            .map_err(failed)?;
        if page.manifest != first.manifest || page.bundle_digest != first.bundle_digest {
            return Err(Failure::unavailable(
                "a later page of the bundle answered another frontier: nothing was written",
            ));
        }
        items.extend(page.items);
        cursor = page.next_cursor;
    }
    if u64::try_from(items.len()).ok() != Some(first.total) {
        return Err(Failure::unavailable(format!(
            "the bundle counts {} items and its pages carried {}: nothing was written",
            first.total,
            items.len()
        )));
    }
    Ok(BundleFile {
        resource: first.resource,
        manifest: first.manifest,
        bundle_digest: first.bundle_digest,
        items,
    })
}

/// An audit export as a file holds it: every page at one frontier, as the Host answered them.
#[derive(Debug, Serialize)]
struct AuditExportFile {
    class: String,
    resource: String,
    frontier: u64,
    pages: Vec<permguard_host::api::audit::AuditExportPage>,
}

/// What `audit export` prints once the file is written.
#[derive(Debug, Serialize)]
struct ExportWritten {
    class: String,
    resource: String,
    frontier: u64,
    records: usize,
    out: String,
}

/// `permguard host audit …`.
pub(super) fn audit(
    globals: &Globals,
    action: AuditAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    let host = online_host(globals, trace, false)?;
    match action {
        AuditAction::Query {
            class,
            resource,
            from,
            to,
            cursor,
            limit,
        } => {
            let page = host
                .audit_records(
                    &class,
                    &AuditQuery {
                        resource,
                        from: seconds(from)?,
                        to: seconds(to)?,
                        cursor,
                        limit,
                        malformed: None,
                    },
                )
                .map_err(failed)?;
            render_json(&page, globals, trace)?;
        }
        AuditAction::Checkpoints {
            class,
            resource,
            period,
        } => {
            let held = host
                .audit_checkpoints(&class, &AuditCheckpointQuery { resource, period })
                .map_err(failed)?;
            render_json(&held, globals, trace)?;
        }
        AuditAction::Export {
            class,
            resource,
            frontier,
            out,
        } => {
            let reserved = reserve(globals, &out)?;
            let export = audit_export(host.as_ref(), &class, &resource, frontier)?;
            fill(reserved, &export)?;
            render_json(
                &ExportWritten {
                    records: export.pages.iter().map(|page| page.records.len()).sum(),
                    class: export.class,
                    resource: export.resource,
                    frontier: export.frontier,
                    out: rooted_file(globals, &out).display().to_string(),
                },
                globals,
                trace,
            )?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Every page of a trail's export at the frontier its first page fixed.
fn audit_export(
    host: &dyn Operations,
    class: &str,
    resource: &str,
    frontier: Option<u64>,
) -> Result<AuditExportFile, Failure> {
    let first = host
        .audit_export(
            class,
            &AuditExportQuery {
                resource: resource.to_owned(),
                frontier,
                cursor: None,
                limit: Some(1000),
                malformed: None,
            },
        )
        .map_err(failed)?;
    let frontier = first.frontier;
    let mut cursor = first.next_cursor.clone();
    let mut pages = vec![first];
    while let Some(next) = cursor {
        if pages.len() >= MAX_PAGES {
            return Err(Failure::unavailable(
                "the Host kept answering the export's cursor: nothing was written",
            ));
        }
        let page = host
            .audit_export(
                class,
                &AuditExportQuery {
                    resource: resource.to_owned(),
                    frontier: Some(frontier),
                    cursor: Some(next),
                    limit: Some(1000),
                    malformed: None,
                },
            )
            .map_err(failed)?;
        if page.frontier != frontier {
            return Err(Failure::unavailable(
                "a later page of the export answered another frontier: nothing was written",
            ));
        }
        cursor = page.next_cursor.clone();
        pages.push(page);
    }
    Ok(AuditExportFile {
        class: class.to_owned(),
        resource: resource.to_owned(),
        frontier,
        pages,
    })
}

/// `permguard host config …`.
pub(super) fn config(
    globals: &Globals,
    action: HostConfigAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    let host = online_host(globals, trace, false)?;
    match action {
        HostConfigAction::Show { effective: _ } => {
            render_json(&host.effective_config().map_err(failed)?, globals, trace)?;
        }
        HostConfigAction::Revisions => {
            render_json(&host.config_revisions().map_err(failed)?, globals, trace)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// `permguard host status`.
pub(super) fn status(globals: &Globals, trace: &Trace) -> Result<ExitCode, Failure> {
    let host = online_host(globals, trace, false)?;
    render_json(&host.status().map_err(failed)?, globals, trace)?;
    Ok(ExitCode::SUCCESS)
}

/// `permguard host plans …`.
pub(super) fn plans(
    globals: &Globals,
    action: PlansAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    let host = online_host(globals, trace, false)?;
    match action {
        PlansAction::List { status } => {
            render_json(
                &host.plans(status.as_deref()).map_err(failed)?,
                globals,
                trace,
            )?;
        }
        PlansAction::Approve { plan_id } => {
            let approved = host
                .approve_plan(
                    &plan_id,
                    &ApprovePlan {
                        request_id: request_id(),
                    },
                )
                .map_err(failed)?;
            render_json(&approved, globals, trace)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// What `host backup prepare` prints: the answer without the token, which went to its file.
#[derive(Debug, Serialize)]
struct BackupPreparedOut {
    operation_id: String,
    manifest: String,
    expires_at: String,
    receipt: permguard_host::api::Receipt,
    token_out: String,
}

/// The token in a `--backup-token-file`, as `prepare` wrote it.
fn token_of(globals: &Globals, path: &std::path::Path) -> Result<String, Failure> {
    let bytes = crate::confirm::read_named(
        &rooted_file(globals, path),
        "--backup-token-file",
        "snapshot token",
        4096,
    )?;
    let token = String::from_utf8(bytes)
        .map_err(|_| Failure::usage("--backup-token-file does not hold a snapshot token"))?;
    let token = token.trim();
    if token.is_empty() {
        return Err(Failure::usage(
            "--backup-token-file does not hold a snapshot token",
        ));
    }
    Ok(token.to_owned())
}

/// `permguard host backup …` (TC-3).
pub(super) fn backup(
    globals: &Globals,
    action: crate::args::HostBackupAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    use crate::args::HostBackupAction;
    use permguard_host::api::backups::{AbortBackup, FinalizeBackup};

    let host = online_host(globals, trace, false)?;
    match action {
        HostBackupAction::Prepare { token_out } => {
            // The token's file first: a prepared backup always has its token somewhere, and a
            // file already there prepares nothing.
            let reserved = reserve(globals, &token_out)?;
            let prepared = host.prepare_backup().map_err(failed)?;
            if let Err(written) = reserved.fill(prepared.token.as_bytes()) {
                // The token exists nowhere else: abort the backup now rather than leave the Host
                // without mutations until the barrier expires (after the TC-3 review).
                let aborted = host.abort_backup(&AbortBackup {
                    token: prepared.token.clone(),
                });
                return Err(Failure::unavailable(match aborted {
                    Ok(_) => format!("{}; the backup was aborted", written.message),
                    Err(_) => format!(
                        "{}; the backup could not be aborted and holds mutations until {}",
                        written.message, prepared.expires_at
                    ),
                }));
            }
            render_json(
                &BackupPreparedOut {
                    operation_id: prepared.operation_id,
                    manifest: prepared.manifest,
                    expires_at: prepared.expires_at,
                    receipt: prepared.receipt,
                    token_out: rooted_file(globals, &token_out).display().to_string(),
                },
                globals,
                trace,
            )?;
        }
        HostBackupAction::Finalize {
            backup_token_file,
            snapshot_id,
        } => {
            let token = token_of(globals, &backup_token_file)?;
            let ended = host
                .finalize_backup(&FinalizeBackup { token, snapshot_id })
                .map_err(failed)?;
            render_json(&ended, globals, trace)?;
        }
        HostBackupAction::Abort { backup_token_file } => {
            let token = token_of(globals, &backup_token_file)?;
            let ended = host.abort_backup(&AbortBackup { token }).map_err(failed)?;
            render_json(&ended, globals, trace)?;
        }
        HostBackupAction::List => render_json(&host.backups().map_err(failed)?, globals, trace)?,
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unreachable)]

    use std::cell::RefCell;

    use permguard_control_client::catalog::Failure as ClientFailure;
    use permguard_host::api::Planned;
    use permguard_host::api::audit::{AuditCheckpoints, AuditExportPage, AuditRecordPage};
    use permguard_host::api::config::{Effective, Revisions};
    use permguard_host::api::keys::{KeyBundlePage, KeyRevoked, RingRotated, RingView, Rings};
    use permguard_host::api::plans::{PlanApproved, PlanList};

    use super::*;

    /// A Host answering bundle and export pages from a script, and remembering what it was
    /// asked.
    #[derive(Default)]
    struct Pages {
        bundle: Vec<KeyBundlePage>,
        export: Vec<AuditExportPage>,
        asked_bundle: RefCell<Vec<KeyBundleQuery>>,
        asked_export: RefCell<Vec<AuditExportQuery>>,
        endless: bool,
    }

    fn bundle_page(
        manifest: &str,
        items: &[&str],
        next: Option<&str>,
        total: u64,
    ) -> KeyBundlePage {
        KeyBundlePage {
            resource: "host".to_owned(),
            manifest: manifest.to_owned(),
            bundle_digest: format!("digest-of-{manifest}"),
            total,
            items: items.iter().map(|item| (*item).to_owned()).collect(),
            next_cursor: next.map(str::to_owned),
        }
    }

    fn export_page(frontier: u64, next: Option<&str>) -> AuditExportPage {
        AuditExportPage {
            class: "security".to_owned(),
            resource: "host".to_owned(),
            records: Vec::new(),
            gaps: Vec::new(),
            frontier,
            next_cursor: next.map(str::to_owned),
            anchor: None,
            checkpoints: Vec::new(),
            omitted: 0,
            keys: None,
            verification_keys: None,
        }
    }

    impl Operations for Pages {
        fn key_bundle(&self, query: &KeyBundleQuery) -> Result<KeyBundlePage, ClientFailure> {
            let mut asked = self.asked_bundle.borrow_mut();
            asked.push(query.clone());
            if self.endless {
                return Ok(bundle_page("m", &["x"], Some("again"), 1));
            }
            Ok(self.bundle[asked.len() - 1].clone())
        }

        fn audit_export(
            &self,
            _class: &str,
            query: &AuditExportQuery,
        ) -> Result<AuditExportPage, ClientFailure> {
            let mut asked = self.asked_export.borrow_mut();
            asked.push(query.clone());
            Ok(self.export[asked.len() - 1].clone())
        }

        fn rings(&self) -> Result<Rings, ClientFailure> {
            unreachable!()
        }
        fn ring(&self, _: &str) -> Result<RingView, ClientFailure> {
            unreachable!()
        }
        fn rotate_ring(&self, _: &str, _: &RotateRing) -> Result<RingRotated, ClientFailure> {
            unreachable!()
        }
        fn plan_key_revoke(&self, _: &str, _: &PlanKeyRevoke) -> Result<Planned, ClientFailure> {
            unreachable!()
        }
        fn run_key_revoke(&self, _: &str, _: &RunKeyRevoke) -> Result<KeyRevoked, ClientFailure> {
            unreachable!()
        }
        fn audit_records(&self, _: &str, _: &AuditQuery) -> Result<AuditRecordPage, ClientFailure> {
            unreachable!()
        }
        fn audit_checkpoints(
            &self,
            _: &str,
            _: &AuditCheckpointQuery,
        ) -> Result<AuditCheckpoints, ClientFailure> {
            unreachable!()
        }
        fn effective_config(&self) -> Result<Effective, ClientFailure> {
            unreachable!()
        }
        fn config_revisions(&self) -> Result<Revisions, ClientFailure> {
            unreachable!()
        }
        fn plans(&self, _: Option<&str>) -> Result<PlanList, ClientFailure> {
            unreachable!()
        }
        fn approve_plan(&self, _: &str, _: &ApprovePlan) -> Result<PlanApproved, ClientFailure> {
            unreachable!()
        }
        fn prepare_backup(
            &self,
        ) -> Result<permguard_host::api::backups::BackupPrepared, ClientFailure> {
            unreachable!()
        }
        fn finalize_backup(
            &self,
            _: &permguard_host::api::backups::FinalizeBackup,
        ) -> Result<permguard_host::api::backups::BackupEnded, ClientFailure> {
            unreachable!()
        }
        fn abort_backup(
            &self,
            _: &permguard_host::api::backups::AbortBackup,
        ) -> Result<permguard_host::api::backups::BackupEnded, ClientFailure> {
            unreachable!()
        }
        fn backups(&self) -> Result<permguard_host::api::backups::BackupList, ClientFailure> {
            unreachable!()
        }
    }

    /// TC-2, after the review: a bundle's later pages present the first page's manifest and the
    /// cursor before them, and their items are all kept, in order.
    #[test]
    fn a_bundle_walks_every_page_at_its_first_frontier() {
        let host = Pages {
            bundle: vec![
                bundle_page("m", &["a", "b"], Some("c1"), 5),
                bundle_page("m", &["c", "d"], Some("c2"), 5),
                bundle_page("m", &["e"], None, 5),
            ],
            ..Pages::default()
        };
        let Ok(file) = bundle(&host, "host") else {
            panic!("walked");
        };
        assert_eq!(file.items, ["a", "b", "c", "d", "e"]);
        assert_eq!(
            (file.manifest.as_str(), file.resource.as_str()),
            ("m", "host")
        );
        let asked = host.asked_bundle.borrow();
        assert_eq!(asked.len(), 3);
        assert_eq!(
            (asked[0].frontier.as_deref(), asked[0].cursor.as_deref()),
            (None, None)
        );
        assert_eq!(
            (asked[1].frontier.as_deref(), asked[1].cursor.as_deref()),
            (Some("m"), Some("c1"))
        );
        assert_eq!(
            (asked[2].frontier.as_deref(), asked[2].cursor.as_deref()),
            (Some("m"), Some("c2"))
        );
    }

    /// A page of another frontier, a count the pages do not reach, a cursor that never ends:
    /// each refused, nothing written.
    #[test]
    fn a_bundle_that_does_not_hold_together_is_refused() {
        let moved = Pages {
            bundle: vec![
                bundle_page("m", &["a"], Some("c1"), 2),
                bundle_page("other", &["b"], None, 2),
            ],
            ..Pages::default()
        };
        assert!(bundle(&moved, "host").is_err());
        let short = Pages {
            bundle: vec![bundle_page("m", &["a"], None, 2)],
            ..Pages::default()
        };
        assert!(bundle(&short, "host").is_err());
        let endless = Pages {
            endless: true,
            ..Pages::default()
        };
        assert!(bundle(&endless, "host").is_err());
        assert_eq!(endless.asked_bundle.borrow().len(), MAX_PAGES);
    }

    /// An export's later pages present its first page's frontier and keep every page; a page of
    /// another frontier is refused.
    #[test]
    fn an_export_walks_every_page_at_its_first_frontier() {
        let host = Pages {
            export: vec![
                export_page(7, Some("c1")),
                export_page(7, Some("c2")),
                export_page(7, None),
            ],
            ..Pages::default()
        };
        let Ok(file) = audit_export(&host, "security", "host", None) else {
            panic!("walked");
        };
        assert_eq!((file.pages.len(), file.frontier), (3, 7));
        let asked = host.asked_export.borrow();
        assert_eq!(
            (asked[0].frontier, asked[0].cursor.as_deref()),
            (None, None)
        );
        assert_eq!(
            (asked[1].frontier, asked[1].cursor.as_deref()),
            (Some(7), Some("c1"))
        );
        assert_eq!(
            (asked[2].frontier, asked[2].cursor.as_deref()),
            (Some(7), Some("c2"))
        );
        let moved = Pages {
            export: vec![export_page(7, Some("c1")), export_page(8, None)],
            ..Pages::default()
        };
        assert!(audit_export(&moved, "security", "host", None).is_err());
    }

    /// TC-2, after the review: an `--out` file is claimed before the Host is asked, refused when
    /// it exists, removed when nothing fills it, and owner-only when filled.
    #[test]
    fn an_out_file_is_claimed_new_and_removed_unfilled() {
        let directory = std::env::temp_dir().join(format!(
            "permguard-cli-reserved-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("a directory");
        let path = directory.join("plan.json");
        let claimed = Reserved::claim(&path).unwrap_or_else(|_| panic!("claimed"));
        assert!(path.exists(), "claimed before the Host is asked");
        assert!(
            Reserved::claim(&path).is_err(),
            "an existing file is refused"
        );
        drop(claimed);
        assert!(!path.exists(), "an unfilled claim leaves nothing");
        let claimed = Reserved::claim(&path).unwrap_or_else(|_| panic!("claimed again"));
        if claimed.fill(b"{}").is_err() {
            panic!("filled");
        }
        assert_eq!(std::fs::read(&path).expect("read"), b"{}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// The file `bundle export` writes is the file `ledgers import --bundle` reads, and a file of
    /// the manifest and the items alone still reads.
    #[test]
    fn a_bundle_file_reads_back_as_written() {
        let written = serde_json::to_vec(&BundleFile {
            resource: "host".to_owned(),
            manifest: "m".to_owned(),
            bundle_digest: "d".to_owned(),
            items: vec!["a".to_owned()],
        })
        .expect("serialized");
        let read: BundleFile = serde_json::from_slice(&written).expect("read back");
        assert_eq!((read.manifest.as_str(), read.items.len()), ("m", 1));
        let minimal: BundleFile =
            serde_json::from_slice(br#"{"manifest":"m","items":[]}"#).expect("still reads");
        assert!(minimal.resource.is_empty());
        assert!(
            serde_json::from_slice::<BundleFile>(br#"{"manifest":"m","items":[],"x":1}"#).is_err()
        );
    }
}
