// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The workspace commands: parse, call the engine module, report.
//!
//! The engine is `engine::workspace`; this file owns arguments, transport and
//! output — every answer is a [`crate::output::Report`], so terminal, JSON
//! and YAML all work for every command, from the same data.

use std::path::PathBuf;
use std::process::ExitCode;

use crate::args::{Globals, ObjectsAction, RemoteAction};
use crate::commands::objects::{inspect_report, write_human};
use crate::failure::{EXIT_READY, Failure};
use crate::narrator;
use crate::session::{open_store, render, resolve_endpoint};
use crate::trace::Trace;
use permguard_control_client::AnyRemote;
use permguard_control_client::TlsOptions;

use crate::reference;
use crate::workspace_out;

/// One workspace operation, dispatched below.
pub enum WorkspaceOp {
    Init {
        name: String,
        languages: Vec<String>,
    },
    Remote(RemoteAction),
    Clone {
        url: String,
        directory: Option<PathBuf>,
    },
    Checkout {
        reference: String,
    },
    Pull,
    Refresh,
    Validate,
    Plan,
    Apply {
        message: String,
    },
    History,
    Status,
    Objects(ObjectsAction),
    Verify,
}

fn lock_holder() -> String {
    format!(
        "pid {} since {}",
        std::process::id(),
        httpdate_now().unwrap_or_else(|| "now".to_owned())
    )
}

/// A human-readable UTC timestamp without a clock dependency beyond std.
fn httpdate_now() -> Option<String> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(format!("unix:{seconds}"))
}

/// The workspace commands: parse, call the engine module, report. The engine
/// is `engine::workspace`; the CLI owns arguments, transport and output —
/// every answer is a [`output::Report`], so terminal, JSON and YAML all work
/// for every command.
pub fn workspace_command(
    globals: &Globals,
    op: WorkspaceOp,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    use std::io::Write as _;

    use permguard_cli::engine::workspace::PlanAction;
    use permguard_cli::engine::{FsStore, Store as _, Workspace};
    use workspace_out::*;

    let store = FsStore::new(&globals.workdir);
    let ws = Workspace::open(&store);
    let format = globals.output;

    // One mutating command at a time per workspace — the git `index.lock`
    // discipline. Read-only commands never take it; `clone` locks the
    // directory it creates, not this one.
    // Reading never takes the lock; `objects prune` removes files, so it does —
    // which is also what makes a grace period unnecessary here: a fetch in
    // flight holds this same lock.
    let mutating = !matches!(
        op,
        WorkspaceOp::History
            | WorkspaceOp::Objects(ObjectsAction::List { .. } | ObjectsAction::Cat { .. })
            | WorkspaceOp::Verify
            | WorkspaceOp::Clone { .. }
    );
    let _workspace_lock = if mutating && store.exists(".permguard") {
        Some(
            permguard_cli::engine::lock::LockGuard::acquire(&store, &lock_holder())
                .map_err(Failure::usage)?,
        )
    } else {
        None
    };

    fn usage<E: std::fmt::Display>(error: E) -> Failure {
        Failure::usage(error)
    }

    let tls = TlsOptions {
        ca_file: globals.tls_ca_file.clone(),
        cert_file: globals.tls_cert_file.clone(),
        key_file: globals.tls_key_file.clone(),
        server_name: globals.tls_server_name.clone(),
        skip_verify: globals.tls_skip_verify,
    }
    .rooted_at(&globals.workdir);

    // The fallback chain of the documentation: the tracked ledger's remote
    // wins; a remote the workspace does not know falls back to the CLI's own
    // configuration; and that falls back to the localhost default.
    let fallback_url = |trace: &Trace| -> Result<String, Failure> {
        let store = open_store(globals, trace)?;
        let endpoint = resolve_endpoint(
            "control-plane.endpoint",
            globals.control_endpoint.as_deref(),
            &store,
            trace,
        )?;
        Ok(endpoint.to_string())
    };
    let connect = |url: &str| -> Result<AnyRemote, Failure> {
        trace.say(format!("remote: {url}"));
        AnyRemote::connect(url, &tls, narrator::for_run(globals.verbose)).map_err(usage)
    };

    // Connects to the remote the workspace tracks, pre-bound to its GUIDs.
    let tracked_remote = |trace: &Trace| -> Result<AnyRemote, Failure> {
        let config = ws.config().map_err(usage)?;
        let ledger = config
            .ledger
            .clone()
            .ok_or_else(|| Failure::usage("no tracked ledger: run `permguard checkout` first"))?;
        let url = match config.remotes.get(&ledger.remote) {
            Some(remote) => remote.url.clone(),
            None => fallback_url(trace)?,
        };
        let remote = connect(&url)?;
        if !ledger.zone_id.is_empty() {
            remote.bind(&ledger.zone_id, &ledger.ledger_id);
        }
        Ok(remote)
    };

    let author = std::env::var("PERMGUARD_AUTHOR")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "unknown".to_owned());

    let plan_lines = |actions: &[PlanAction]| -> Vec<PlanLine> {
        actions
            .iter()
            .map(|action| match action {
                PlanAction::Create(policy) => PlanLine {
                    op: "create",
                    partition: policy.partition.clone(),
                    name: policy.name.clone(),
                    id: policy.id.clone(),
                    alias: policy.alias.clone(),
                },
                PlanAction::Update(policy) => PlanLine {
                    op: "update",
                    partition: policy.partition.clone(),
                    name: policy.name.clone(),
                    id: policy.id.clone(),
                    alias: policy.alias.clone(),
                },
                PlanAction::Delete {
                    partition,
                    name,
                    id,
                } => PlanLine {
                    op: "delete",
                    partition: partition.clone(),
                    name: name.clone(),
                    id: id.clone(),
                    alias: None,
                },
            })
            .collect()
    };
    // What a plan changes that no policy names: the manifest, and a
    // partition's schema. They are commit content like everything else, so
    // they belong in the report rather than in a surprise.
    let shape_lines = |plan: &permguard_cli::engine::workspace::Plan| -> Vec<PlanLine> {
        let mut lines = Vec::new();
        if plan.manifest_changed {
            lines.push(PlanLine {
                op: "update",
                partition: "manifest".to_owned(),
                name: "manifest".to_owned(),
                id: String::new(),
                alias: None,
            });
        }
        for partition in &plan.other_changes {
            lines.push(PlanLine {
                op: "update",
                partition: partition.clone(),
                name: "schema".to_owned(),
                id: String::new(),
                alias: None,
            });
        }

        lines
    };

    match op {
        WorkspaceOp::Init { name, languages } => {
            let adopted = store.exists("manifest.yml") || store.exists("manifest.yaml");
            let refs: Vec<&str> = languages.iter().map(String::as_str).collect();
            ws.init(&name, &refs).map_err(usage)?;
            render(
                &InitReport {
                    name,
                    languages,
                    adopted_manifest: adopted,
                },
                format,
                trace,
            )?;
        }
        WorkspaceOp::Remote(action) => match action {
            RemoteAction::Add { name, url } => {
                // Verified before it is remembered: the discovery document
                // is the proof the URL is a Permguard plane.
                let remote = connect(&url)?;
                remote.verify_discovery().map_err(usage)?;
                let mut config = ws.config().map_err(usage)?;
                config.remotes.insert(
                    name.clone(),
                    permguard_cli::engine::workspace::config::RemoteConfig {
                        url: url.clone(),
                        tls_ca_file: None,
                    },
                );
                ws.save_config(&config).map_err(usage)?;
                render(
                    &RemoteChangedReport {
                        action: "added",
                        name,
                        url: Some(url),
                    },
                    format,
                    trace,
                )?;
            }
            RemoteAction::List => {
                let config = ws.config().map_err(usage)?;
                let remotes = config
                    .remotes
                    .iter()
                    .map(|(name, remote)| RemoteLine {
                        name: name.clone(),
                        url: remote.url.clone(),
                    })
                    .collect();
                render(&RemoteListReport { remotes }, format, trace)?;
            }
            RemoteAction::Remove { name } => {
                let mut config = ws.config().map_err(usage)?;
                if config.remotes.remove(&name).is_none() {
                    return Err(Failure::usage(format!("no remote `{name}`")));
                }
                ws.save_config(&config).map_err(usage)?;
                render(
                    &RemoteChangedReport {
                        action: "removed",
                        name,
                        url: None,
                    },
                    format,
                    trace,
                )?;
            }
        },
        WorkspaceOp::Clone { url, directory } => {
            let (base, zone, ledger) = reference::parse_clone_url(&url).map_err(usage)?;
            let target = directory.unwrap_or_else(|| PathBuf::from(&ledger));
            let target = globals.workdir.join(target);
            // Like git: cloning into an existing, non-empty directory is
            // refused rather than silently merged into.
            if target.exists()
                && std::fs::read_dir(&target)
                    .map(|mut entries| entries.next().is_some())
                    .unwrap_or(false)
            {
                return Err(Failure::usage(format!(
                    "destination `{}` already exists and is not empty",
                    target.display()
                )));
            }
            std::fs::create_dir_all(&target).map_err(|error| {
                Failure::usage(format!("creating {}: {error}", target.display()))
            })?;
            let store = FsStore::new(&target);
            let ws = Workspace::open(&store);
            let mut config = permguard_cli::engine::workspace::config::WorkspaceConfig::new();
            config.remotes.insert(
                "origin".to_owned(),
                permguard_cli::engine::workspace::config::RemoteConfig {
                    url: base.clone(),
                    tls_ca_file: None,
                },
            );
            ws.save_config(&config).map_err(usage)?;
            let remote = connect(&base)?;
            let pulled = ws
                .checkout(&remote, "origin", &zone, &ledger, "main")
                .map_err(usage)?;
            render(
                &PullReport {
                    action: "clone",
                    reference: Some(format!("origin/{zone}/{ledger}")),
                    directory: Some(target.display().to_string()),
                    counter: pulled.counter,
                    head: pulled.head,
                    fetched: pulled.fetched,
                    materialized: pulled.materialized,
                },
                format,
                trace,
            )?;
        }
        WorkspaceOp::Checkout { reference } => {
            let (remote_name, zone, ledger, r#ref) =
                reference::parse_reference(&reference).map_err(usage)?;
            let mut config = ws.config().map_err(usage)?;
            let url = match config.remotes.get(&remote_name) {
                Some(remote) => remote.url.clone(),
                None => {
                    // The fallback chain: CLI configuration, then the
                    // localhost default — and the resolved URL is remembered
                    // under the name, so the next command finds it.
                    let url = fallback_url(trace)?;
                    config.remotes.insert(
                        remote_name.clone(),
                        permguard_cli::engine::workspace::config::RemoteConfig {
                            url: url.clone(),
                            tls_ca_file: None,
                        },
                    );
                    ws.save_config(&config).map_err(usage)?;
                    url
                }
            };
            let remote = connect(&url)?;
            let pulled = ws
                .checkout(&remote, &remote_name, &zone, &ledger, &r#ref)
                .map_err(usage)?;
            render(
                &PullReport {
                    action: "checkout",
                    reference: Some(reference),
                    directory: None,
                    counter: pulled.counter,
                    head: pulled.head,
                    fetched: pulled.fetched,
                    materialized: pulled.materialized,
                },
                format,
                trace,
            )?;
        }
        WorkspaceOp::Pull => {
            let remote = tracked_remote(trace)?;
            let pulled = ws.pull(&remote).map_err(usage)?;
            render(
                &PullReport {
                    action: "pull",
                    reference: None,
                    directory: None,
                    counter: pulled.counter,
                    head: pulled.head,
                    fetched: pulled.fetched,
                    materialized: pulled.materialized,
                },
                format,
                trace,
            )?;
        }
        WorkspaceOp::Refresh | WorkspaceOp::Validate => {
            let snapshot = ws.refresh().map_err(usage)?;
            render(
                &ValidateReport {
                    policies: snapshot.policies.len(),
                    objects: snapshot.objects.len(),
                    root: snapshot.root.to_string(),
                },
                format,
                trace,
            )?;
        }
        WorkspaceOp::Plan => {
            let (_, plan) = ws.plan().map_err(usage)?;
            let mut changes = plan_lines(&plan.actions);
            changes.extend(shape_lines(&plan));
            render(
                &PlanReport {
                    changes,
                    unchanged: plan.unchanged,
                },
                format,
                trace,
            )?;
        }
        WorkspaceOp::Apply { message } => {
            let remote = tracked_remote(trace)?;
            let (_, plan) = ws.plan().map_err(usage)?;
            let mut changes = plan_lines(&plan.actions);
            changes.extend(shape_lines(&plan));
            let applied = ws.apply(&remote, &author, &message).map_err(|error| {
                // The compare-and-swap lost: somebody applied first. The way
                // out is always the same, so say it here, once.
                if error.message.contains("ref_conflict") || error.message.contains("ref moved") {
                    Failure::usage(format!(
                        "{error}. Someone applied before you: run `permguard pull`, \
                         review, and apply again"
                    ))
                } else {
                    usage(error)
                }
            })?;
            render(
                &ApplyReport {
                    changes,
                    r#ref: "main".to_owned(),
                    counter: applied.counter,
                    head: applied.head,
                    uploaded: applied.uploaded,
                },
                format,
                trace,
            )?;
        }
        WorkspaceOp::Status => {
            let status = ws.status().map_err(usage)?;
            let (create, update, delete) = status
                .plan
                .as_ref()
                .map(|plan| {
                    let count = |wanted: &str| {
                        plan.actions
                            .iter()
                            .filter(|action| match action {
                                PlanAction::Create(_) => wanted == "create",
                                PlanAction::Update(_) => wanted == "update",
                                PlanAction::Delete { .. } => wanted == "delete",
                            })
                            .count()
                    };
                    (count("create"), count("update"), count("delete"))
                })
                .unwrap_or((0, 0, 0));
            render(
                &StatusReport {
                    workspace: status.manifest_name,
                    languages: status.languages,
                    remote: status.ledger.as_ref().map(|ledger| ledger.remote.clone()),
                    remote_url: status.remote_url,
                    zone: status.ledger.as_ref().map(|ledger| ledger.zone.clone()),
                    ledger: status.ledger.as_ref().map(|ledger| ledger.ledger.clone()),
                    r#ref: status.r#ref,
                    counter: status
                        .checkpoint
                        .as_ref()
                        .map(|checkpoint| checkpoint.counter),
                    head: status
                        .checkpoint
                        .as_ref()
                        .map(|checkpoint| checkpoint.head.clone()),
                    pending_create: create,
                    pending_update: update,
                    pending_delete: delete,
                    sources_valid: status.plan.is_some(),
                },
                format,
                trace,
            )?;
        }
        WorkspaceOp::History => {
            let commits = ws
                .history()
                .map_err(usage)?
                .into_iter()
                .map(|(digest, commit)| HistoryLine {
                    commit: digest.to_string(),
                    author: commit.author,
                    author_at: commit.author_at,
                    message: commit.message,
                })
                .collect();
            render(&HistoryReport { commits }, format, trace)?;
        }
        WorkspaceOp::Objects(action) => match action {
            ObjectsAction::List { tracked, staged } => {
                let objects = permguard_cli::engine::workspace::inventory::inventory(&store)
                    .map_err(usage)?
                    .into_iter()
                    .filter(|record| {
                        (!tracked && !staged)
                            || (tracked && record.tracked)
                            || (staged && record.staged)
                    })
                    .map(|record| ObjectLine {
                        digest: record.digest.to_string(),
                        kind: record.kind,
                        tracked: record.tracked,
                        staged: record.staged,
                        label: record.label,
                    })
                    .collect();
                render(&ObjectsReport { objects }, format, trace)?;
            }
            ObjectsAction::Prune { dry_run } => {
                let pruned = permguard_cli::engine::workspace::prune::prune(&store, !dry_run)
                    .map_err(usage)?;
                render(
                    &workspace_out::PruneReport {
                        applied: pruned.applied,
                        bytes: pruned.bytes(),
                        kept: pruned.kept,
                        reclaimed: pruned
                            .reclaimed
                            .iter()
                            .map(|object| workspace_out::PruneLine {
                                digest: object.digest.to_string(),
                                kind: object.kind,
                                bytes: object.bytes,
                            })
                            .collect(),
                    },
                    format,
                    trace,
                )?;
            }
            ObjectsAction::Cat {
                digest,
                raw,
                content,
                inspect,
                human,
            } => {
                use permguard_objects::object::{self, Object};
                let digest = permguard_objects::digest::Digest::parse(&digest).map_err(usage)?;
                let bytes = permguard_cli::engine::workspace::inventory::get(&store, &digest)
                    .map_err(usage)?
                    .ok_or_else(|| Failure::usage("no such local object"))?;
                if raw {
                    // The exact stored bytes, no banner: this view exists to be piped.
                    let _ = std::io::stdout().write_all(&bytes);
                    return Ok(ExitCode::SUCCESS);
                }
                let decoded = object::decode(&bytes)
                    .map_err(|error| Failure::usage(format!("{digest}: {error}")))?;
                if inspect {
                    render(&inspect_report(&digest, &bytes, &decoded), format, trace)?;
                    return Ok(ExitCode::SUCCESS);
                }
                match (&decoded, content, human) {
                    // The default for a blob is its content; asking for it
                    // explicitly on anything else is an error, not a guess.
                    (Object::Blob(blob), _, false) if !human => {
                        let _ = std::io::stdout().write_all(&blob.data);
                    }
                    (_, true, _) => {
                        return Err(Failure::usage(format!(
                            "{digest} is not a blob and has no content: use --inspect or --human"
                        )));
                    }
                    _ => {
                        // The human reading, also the default for trees and commits.
                        let mut out = std::io::stdout();
                        let _ = write_human(&mut out, &digest, &decoded);
                    }
                }
            }
        },
        WorkspaceOp::Verify => {
            let remote = tracked_remote(trace)?;
            let verified = ws.verify(&remote).map_err(usage)?;
            render(
                &VerifyReport {
                    r#ref: verified.r#ref,
                    head: verified.head,
                    counter: verified.counter,
                    statement_verified: true,
                    local_closure_objects: verified.local_closure_objects,
                },
                format,
                trace,
            )?;
        }
    }
    Ok(ExitCode::from(EXIT_READY))
}
