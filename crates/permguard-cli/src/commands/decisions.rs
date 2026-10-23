// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `permguard decisions` — read what a data plane recorded.
//!
//! # The position belongs to the caller
//!
//! The control plane keeps no cursor, so two people tailing the same ledger do
//! not interfere, and no reader can back-pressure the plane that is deciding.
//! The offset it returns is opaque and bound to the scope that issued it: an
//! offset from one tenant presented under another is refused rather than
//! reinterpreted.
//!
//! # What `--verify` actually checks
//!
//! Without a key set: that the records are a contiguous, unaltered chain,
//! which is what the records alone can prove. With `--keys`: also that the
//! batches were signed by a key that set publishes — which is what makes the
//! answer independent of the server that served it. The report says which of
//! the two happened, because "verified" that quietly skipped the signatures is
//! worse than no verification at all.

use std::process::ExitCode;

use permguard_control_client::decisions::{self, DecisionLog, ReadError, ReadScope, ReadWindow};
use permguard_core::Jwk;
use permguard_decisions::envelope::Signed;
use permguard_decisions::{chain, merkle, record};
use serde_json::Value;

use crate::args::{DecisionsAction, DecisionsQuery, Globals};
use crate::decision_out::{
    DecisionArchive, DecisionArchiveScope, DecisionArchiveSummary, DecisionLine, DecisionReport,
    DecisionSignersReport, DecisionsReport, EventLine, Verified,
};
use crate::failure::{EXIT_READY, Failure};
use crate::session::{open_store, render};
use crate::target::{self, Asked};
use crate::trace::Trace;

/// How many pages `export` and `get` will walk before giving up.
///
/// A bound rather than a loop: a command that walks forever on a store that
/// keeps growing is a command nobody can put in a script.
const MAX_PAGES: usize = 10_000;

/// Runs the command.
pub fn decisions(globals: &Globals, action: &DecisionsAction) -> Result<ExitCode, Failure> {
    match action {
        DecisionsAction::List(query) => list(globals, query, false),
        DecisionsAction::Tail { query, follow } => tail(globals, query, *follow),
        DecisionsAction::Get { id, query } => get(globals, query, id),
        DecisionsAction::Signers {
            query,
            from_seq,
            until_seq,
        } => signers(globals, query, *from_seq, *until_seq),
        DecisionsAction::Export(query) => list(globals, query, true),
        DecisionsAction::Verify { file, keys } => verify_file(globals, file, keys),
    }
}

/// One page, or a whole finite snapshot.
///
/// # Why an export captures a bound
///
/// An export that stopped when the stream was empty would never stop on a busy ledger: records
/// keep arriving and `more` keeps being true. So the first page's watermark becomes this export's
/// fixed end, echoed on every page after it, and records that arrive later belong to a later
/// export. That is one field, and it is the difference between a command that finishes and one
/// that cannot be put in a script.
fn list(globals: &Globals, query: &DecisionsQuery, everything: bool) -> Result<ExitCode, Failure> {
    let trace = Trace::new(globals.verbose);
    let (reader, scope) = connect(globals, query, &trace)?;
    let keys = key_set(globals, query)?;

    let mut read = Read {
        records: Vec::new(),
        proof: Vec::new(),
        inclusion: Vec::new(),
        next: String::new(),
        more: false,
    };
    let mut window = ReadWindow {
        from: query.from.clone(),
        limit_records: query.limit,
        proof: proofs_asked(query, everything),
        ..ReadWindow::default()
    };
    let mut decisions_read = 0usize;
    let mut walked = 0usize;
    for page_number in 0..MAX_PAGES {
        walked = page_number + 1;
        let page = reader.read(&scope, &window).map_err(read_failure)?;
        if everything && page_number == 0 {
            // The snapshot this export is of. Every page after this one is bounded by it.
            window.until = Some(page.high_watermark.clone());
            trace.say(format!(
                "exporting the snapshot at `{}`; records written after it belong to a later export",
                page.high_watermark
            ));
        }
        read.more = page.more;
        read.next.clone_from(&page.next);
        window.from = Some(page.next);
        decisions_read += page
            .records
            .iter()
            .filter(|record| record.get("kind").and_then(Value::as_str) == Some("decision"))
            .count();
        read.proof.extend(page.proof);
        read.inclusion.extend(page.inclusion);
        read.records.extend(page.records);
        // An empty page is not the end: filtering and scan bounds mean a page may match nothing
        // while still advancing. The export stops from `more` against its own bound, and nothing
        // else.
        if !read.more {
            break;
        }
        if everything {
            continue;
        }
        // A page is `--limit` decisions, not `--limit` records. The stream carries marker events
        // beside the decisions, and a limit counted in records handed back one decision fewer
        // than asked. So the read goes on until the decisions add up, asking each time only for
        // what is still missing: the server bounds a page by records, so the last one cannot
        // overshoot and leave `next` past decisions that were never shown.
        if decisions_read >= query.limit {
            break;
        }
        window.limit_records = query.limit - decisions_read;
    }

    let truncated = export_truncated(everything, walked, read.more);
    let evidence = everything.then(|| {
        (
            read.records.clone(),
            read.proof.clone(),
            read.inclusion.clone(),
            DecisionArchiveSummary {
                next: read.next.clone(),
                more: read.more,
                truncated,
            },
        )
    });
    let report = report(&scope, read, query, keys.as_deref());
    match evidence {
        Some((records, envelopes, inclusion, summary)) => {
            let unverified_report = unverified(&report);
            render(
                &DecisionArchive {
                    format: permguard_core::domains::interface::DECISIONS_EXPORT_V1.to_owned(),
                    scope_binding: archive_scope(&scope),
                    summary,
                    records,
                    envelopes,
                    inclusion,
                    report: Some(report),
                },
                globals.output,
                &trace,
            )?;
            if truncated {
                // Printed, so the work is not thrown away, and then refused, so nothing downstream
                // reads part of a snapshot as the whole of one.
                return Err(Failure::usage(format!(
                    "this export stopped after {MAX_PAGES} pages and the snapshot is not \
                     finished: what was read is above"
                ))
                .named(
                    "validation",
                    permguard_core::codes::client::EXPORT_TRUNCATED,
                ));
            }
            unverified_report?;
        }
        None => {
            render(&report, globals.output, &trace)?;
            unverified(&report)?;
        }
    }

    Ok(ExitCode::from(EXIT_READY))
}

/// Whether a read asks for envelopes and paths: an export always, being an offline-verifiable
/// archive whatever `--verify` says (WP-6.3b); a list when it verifies.
fn proofs_asked(query: &DecisionsQuery, everything: bool) -> bool {
    query.verify || everything
}

/// Whether an export stopped at this command's own page bound rather than at its snapshot's end.
fn export_truncated(everything: bool, walked: usize, more: bool) -> bool {
    everything && walked == MAX_PAGES && more
}

/// The scope an archive binds its records to.
fn archive_scope(scope: &ReadScope) -> DecisionArchiveScope {
    match scope {
        ReadScope::Tenant { zone, ledger } => DecisionArchiveScope::Tenant {
            zone: zone.clone(),
            ledger: ledger.clone(),
        },
        ReadScope::Stream { pdp_id, instance } => DecisionArchiveScope::Stream {
            pdp: pdp_id.clone(),
            instance: instance.clone(),
        },
    }
}

/// The read scope an archive's records were bound to.
fn read_scope(scope: &DecisionArchiveScope) -> ReadScope {
    match scope {
        DecisionArchiveScope::Tenant { zone, ledger } => ReadScope::Tenant {
            zone: zone.clone(),
            ledger: ledger.clone(),
        },
        DecisionArchiveScope::Stream { pdp, instance } => ReadScope::Stream {
            pdp_id: pdp.clone(),
            instance: instance.clone(),
        },
    }
}

/// Checks a decision export without asking the server that supplied it another question
/// (WP-6.3b, F-07): a record altered, a record of another scope, an envelope not signed by the
/// keys given, or a stream archive missing part of a batch exits `2`. A tenant view is a
/// subsequence by design: what proves each of its records is its own inclusion path.
fn verify_file(globals: &Globals, file: &str, keys: &str) -> Result<ExitCode, Failure> {
    let trace = Trace::new(globals.verbose);
    let named = crate::session::rooted(globals, file);
    trace.say(format!(
        "verifying the decision archive at {} without contacting a server",
        named.display()
    ));
    let text = std::fs::read_to_string(&named).map_err(|error| {
        Failure::usage(format!("reading {}: {error}", named.display())).named(
            "validation",
            permguard_core::codes::client::DECISION_EXPORT_UNREADABLE,
        )
    })?;
    let archive = parse_archive(&text).map_err(|error| {
        Failure::usage(format!(
            "{} is not a Permguard decision export: {error}",
            named.display()
        ))
        .named(
            "validation",
            permguard_core::codes::client::DECISION_EXPORT_MALFORMED,
        )
    })?;
    let (verified, report) = verify_archive(archive, &read_keys(globals, keys)?)?;
    render(&report, globals.output, &trace)?;
    if !verified {
        // A verification that ran and did not pass: exit 2 (TC-1, owner decision).
        return Err(Failure::not_passed(
            "this export cannot account for every record it contains: see the report above",
            permguard_core::codes::client::DECISIONS_UNVERIFIED,
        ));
    }

    Ok(ExitCode::from(EXIT_READY))
}

/// Whether every record belongs to the scope the archive binds them to (after the review): a
/// stream's records name its producer and instance; a tenant's decisions name one ledger, the one
/// bound when it is bound by names (the records carry names, a binding by ids is checked through
/// the inclusion paths alone).
fn bound(scope: &DecisionArchiveScope, records: &[Value]) -> bool {
    let text = |record: &Value, path: &[&str]| -> Option<String> {
        let mut held = record;
        for segment in path {
            held = held.get(*segment)?;
        }
        held.as_str().map(str::to_owned)
    };
    match scope {
        DecisionArchiveScope::Stream { pdp, instance } => records.iter().all(|record| {
            text(record, &["stream", "id"]).as_deref() == Some(pdp.as_str())
                && text(record, &["stream", "instance"]).as_deref() == Some(instance.as_str())
        }),
        DecisionArchiveScope::Tenant { zone, ledger } => {
            let mut tenants: Vec<(String, String)> = records
                .iter()
                .filter(|record| text(record, &["kind"]).as_deref() == Some("decision"))
                .map(|record| {
                    (
                        text(record, &["store", "zone"]).unwrap_or_default(),
                        text(record, &["store", "ledger"]).unwrap_or_default(),
                    )
                })
                .collect();
            tenants.sort();
            tenants.dedup();
            let is_id = |name: &str| {
                matches!(
                    permguard_core::catalog::Selector::parse(name),
                    permguard_core::catalog::Selector::Id(_)
                )
            };
            let by_ids = is_id(zone) || is_id(ledger);
            match tenants.as_slice() {
                [] => true,
                [(held_zone, held_ledger)] => {
                    by_ids || (held_zone == zone && held_ledger == ledger)
                }
                _ => false,
            }
        }
    }
}

/// Whether a stream archive holds whole batches: its records are exactly the sequences the
/// envelopes the keys verify cover, so none was removed from either end of one (after the
/// review). A tenant archive is a subsequence by design and its paths are what proves it.
fn whole(
    scope: &DecisionArchiveScope,
    records: &[Value],
    envelopes: &[Value],
    keys: &[Jwk],
) -> bool {
    if matches!(scope, DecisionArchiveScope::Tenant { .. }) {
        return true;
    }
    let mut covered = std::collections::BTreeSet::new();
    for entry in envelopes {
        let range = match super::host_proof::host_batch(
            entry,
            Some(keys),
            permguard_core::domains::protected::DECISION_BATCH,
        ) {
            Some(Ok(batch)) => Some((batch.first_seq, batch.last_seq)),
            Some(Err(())) => None,
            None => serde_json::from_value::<Signed>(entry.clone())
                .ok()
                .and_then(|signed| signed.verify(keys).ok())
                .map(|attested| (attested.first_seq, attested.last_seq)),
        };
        if let Some((first, last)) = range {
            covered.extend(first..=last);
        }
    }
    let held: std::collections::BTreeSet<u64> = records
        .iter()
        .filter_map(|record| record.get("seq").and_then(Value::as_u64))
        .collect();
    held.len() == records.len() && held == covered
}

/// An archive, from JSON or YAML.
fn parse_archive(text: &str) -> Result<DecisionArchive, String> {
    serde_json::from_str(text)
        .or_else(|_| serde_norway::from_str(text))
        .map_err(|error| error.to_string())
}

/// Whether `archive` verifies under `keys`, and its report: refused before anything is checked
/// for another format or a truncated export. Verified means the chain or every inclusion path
/// holds, no signature failed, and a non-empty archive carries at least one envelope the keys
/// verify: an archive stripped of its envelopes is well-formed and attributed to nobody.
fn verify_archive(
    archive: DecisionArchive,
    keys: &[Jwk],
) -> Result<(bool, DecisionsReport), Failure> {
    if archive.format != permguard_core::domains::interface::DECISIONS_EXPORT_V1 {
        return Err(Failure::usage(format!(
            "the archive declares export format `{}`; this CLI verifies `{}`",
            archive.format,
            permguard_core::domains::interface::DECISIONS_EXPORT_V1
        ))
        .named(
            "validation",
            permguard_core::codes::client::DECISION_EXPORT_TYPE_UNSUPPORTED,
        ));
    }
    if archive.summary.truncated {
        return Err(Failure::usage(
            "the file is a truncated export, so it cannot establish a complete snapshot",
        )
        .named(
            "validation",
            permguard_core::codes::client::DECISION_EXPORT_TRUNCATED,
        ));
    }
    let scope = read_scope(&archive.scope_binding);
    let checked = verify(
        &scope,
        &archive.records,
        &archive.envelopes,
        &archive.inclusion,
        Some(keys),
    );
    let attributed = archive.records.is_empty() || checked.signatures > 0;
    let verified = checked.holds()
        && attributed
        && bound(&archive.scope_binding, &archive.records)
        && whole(
            &archive.scope_binding,
            &archive.records,
            &archive.envelopes,
            keys,
        );
    let query = DecisionsQuery {
        zone: None,
        ledger: None,
        pdp: None,
        instance: None,
        from: None,
        limit: archive.records.len().max(1),
        since: None,
        decision: None,
        verify: false,
        keys: None,
        ignore_workspace: true,
    };
    let mut report = report(
        &scope,
        Read {
            records: archive.records,
            proof: Vec::new(),
            inclusion: Vec::new(),
            next: archive.summary.next,
            more: archive.summary.more,
        },
        &query,
        Some(keys),
    );
    report.verified = Some(checked);
    Ok((verified, report))
}

/// A read asked to verify whose proof did not hold: it ran and its subject did not pass, exit 2
/// (TC-1, owner decision of 2026-10-10).
fn unverified(report: &crate::decision_out::DecisionsReport) -> Result<(), Failure> {
    match &report.verified {
        Some(verified) if !verified.holds() => Err(Failure::not_passed(
            "these decisions did not verify: see the report above",
            permguard_core::codes::client::DECISIONS_UNVERIFIED,
        )),
        _ => Ok(()),
    }
}

/// The stream, as it arrives.
fn tail(globals: &Globals, query: &DecisionsQuery, follow: bool) -> Result<ExitCode, Failure> {
    let trace = Trace::new(globals.verbose);
    let (reader, scope) = connect(globals, query, &trace)?;
    let keys = key_set(globals, query)?;
    // No `until`: a tail is deliberately unbounded, which is what makes it a tail. It reads from
    // `next`, and idles when it has caught up.
    let mut window = ReadWindow {
        from: query.from.clone(),
        limit_records: query.limit,
        proof: query.verify,
        ..ReadWindow::default()
    };

    loop {
        let page = reader.read(&scope, &window).map_err(read_failure)?;
        let more = page.more;
        window.from = Some(page.next.clone());
        if !page.records.is_empty() {
            let report = report(
                &scope,
                Read {
                    records: page.records,
                    proof: page.proof,
                    inclusion: page.inclusion,
                    next: page.next,
                    more,
                },
                query,
                keys.as_deref(),
            );
            render(&report, globals.output, &trace)?;
            // A followed tail stops at the first page that does not verify: what follows a
            // record the store cannot account for is not read as if it were.
            unverified(&report)?;
        }
        if !follow {
            break;
        }
        if !more {
            // Idle rather than busy: a tail that spins is a tail that costs
            // the control plane more than the decisions do.
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    Ok(ExitCode::from(EXIT_READY))
}

/// One decision, by the identifier its caller was given back.
fn get(globals: &Globals, query: &DecisionsQuery, id: &str) -> Result<ExitCode, Failure> {
    let trace = Trace::new(globals.verbose);
    let (reader, scope) = connect(globals, query, &trace)?;
    // Bounded to a snapshot like an export: a search for one identifier over a stream that keeps
    // growing would otherwise never conclude that the identifier is absent.
    let mut window = ReadWindow {
        from: query.from.clone(),
        limit_records: query.limit.max(500),
        ..ReadWindow::default()
    };

    for page_number in 0..MAX_PAGES {
        let page = reader.read(&scope, &window).map_err(read_failure)?;
        if page_number == 0 {
            window.until = Some(page.high_watermark.clone());
        }
        if let Some(record) = page
            .records
            .iter()
            .find(|record| record.get("id").and_then(Value::as_str) == Some(id))
        {
            let report = DecisionReport {
                record: record.clone(),
            };
            render(&report, globals.output, &trace)?;

            return Ok(ExitCode::from(EXIT_READY));
        }
        if !page.more {
            break;
        }
        window.from = Some(page.next);
    }

    // A plane writes its record locally before it answers, and ships it to the control plane in
    // batches afterwards — so a decision made a moment ago is durable, and not yet here. The
    // refusal says so, or a script reads "not found" as "never happened".
    Err(Failure::usage(format!(
        "no decision in this scope carries the identifier `{id}` — a plane ships its records to \
         the control plane in batches, so a decision made moments ago may not have arrived yet: \
         retry in a few seconds before concluding it does not exist"
    ))
    .named(
        "not_found",
        permguard_core::codes::stream::DECISION_NOT_FOUND,
    ))
}

/// The reader, and what it is reading.
/// Which key signed which stretch of one producer stream, public keys included.
fn signers(
    globals: &Globals,
    query: &DecisionsQuery,
    from_seq: Option<u64>,
    until_seq: Option<u64>,
) -> Result<ExitCode, Failure> {
    let trace = Trace::new(globals.verbose);
    let (reader, scope) = connect(globals, query, &trace)?;
    let ReadScope::Stream { pdp_id, instance } = scope else {
        return Err(Failure::usage(
            "a signer manifest belongs to one producer stream: name it with --pdp and --instance",
        ));
    };

    let document = reader
        .signers(
            &pdp_id,
            &instance,
            from_seq.unwrap_or(0),
            until_seq.unwrap_or(0),
        )
        .map_err(read_failure)?;
    render(
        &DecisionSignersReport {
            scope: format!("{pdp_id}/{instance}"),
            document,
        },
        globals.output,
        &trace,
    )?;

    Ok(ExitCode::from(EXIT_READY))
}

fn connect(
    globals: &Globals,
    query: &DecisionsQuery,
    trace: &Trace,
) -> Result<(Box<dyn DecisionLog>, ReadScope), Failure> {
    let store = open_store(globals, trace)?;

    // A producer stream is named outright; anything else is one tenant's
    // records, resolved the way every other command resolves a store.
    if let (Some(pdp_id), Some(instance)) = (&query.pdp, &query.instance) {
        let target = target::resolve(
            "control-plane.endpoint",
            globals.control_endpoint.as_deref(),
            &Asked {
                zone: None,
                ledger: None,
                ignore_workspace: true,
            },
            globals,
            &store,
            trace,
        )?;
        trace.say(format!(
            "reading the whole stream of {pdp_id}/{instance} from {}",
            target.endpoint
        ));
        let reader = decisions::client(
            &target.endpoint,
            &target::tls(globals, &store, trace)?,
            crate::narrator::for_run(globals.verbose),
        )
        .map_err(Failure::usage)?;

        return Ok((
            reader,
            ReadScope::Stream {
                pdp_id: pdp_id.clone(),
                instance: instance.clone(),
            },
        ));
    }

    let target = target::resolve(
        "control-plane.endpoint",
        globals.control_endpoint.as_deref(),
        &Asked {
            zone: query.zone.clone(),
            ledger: query.ledger.clone(),
            ignore_workspace: query.ignore_workspace,
        },
        globals,
        &store,
        trace,
    )?;
    let (Some(zone), Some(ledger)) = (target.zone.clone(), target.ledger.clone()) else {
        return Err(Failure::usage(
            "which decisions? name a zone and a ledger (--zone/--ledger), stand in a workspace, \
             or read a whole producer stream with --pdp/--instance",
        ));
    };
    trace.say(format!("reading {zone}/{ledger} from {}", target.endpoint));
    let reader = decisions::client(
        &target.endpoint,
        &target::tls(globals, &store, trace)?,
        crate::narrator::for_run(globals.verbose),
    )
    .map_err(Failure::usage)?;

    Ok((reader, ReadScope::Tenant { zone, ledger }))
}

/// The producer's published key set, when one was given.
fn key_set(globals: &Globals, query: &DecisionsQuery) -> Result<Option<Vec<Jwk>>, Failure> {
    let Some(path) = &query.keys else {
        return Ok(None);
    };
    read_keys(globals, path).map(Some)
}

/// The key set at `path`, a JWKS.
fn read_keys(globals: &Globals, path: &str) -> Result<Vec<Jwk>, Failure> {
    // `-w` says where a relative path is read from, and this is one.
    let named = crate::session::rooted(globals, path);
    let text = std::fs::read_to_string(&named)
        .map_err(|error| Failure::usage(format!("reading {}: {error}", named.display())))?;
    let parsed: Value = serde_json::from_str(&text)
        .map_err(|error| Failure::usage(format!("{path} is not a JWKS: {error}")))?;
    let keys = parsed.get("keys").cloned().unwrap_or(parsed);

    serde_json::from_value(keys)
        .map_err(|error| Failure::usage(format!("{path} is not a JWKS: {error}")))
}

/// What one or more pages came back with.
struct Read {
    records: Vec<Value>,
    proof: Vec<Value>,
    inclusion: Vec<Value>,
    next: String,
    more: bool,
}

/// Turns records into the report, filtering and verifying as asked.
fn report(
    scope: &ReadScope,
    page: Read,
    query: &DecisionsQuery,
    keys: Option<&[Jwk]>,
) -> DecisionsReport {
    let Read {
        records,
        proof,
        inclusion,
        next,
        more,
    } = page;
    // Verification runs over everything that came back, before any filtering:
    // a chain with a record removed from it is not a chain, and filtering
    // first would make every filtered read look broken.
    let verified = query
        .verify
        .then(|| verify(scope, &records, &proof, &inclusion, keys));

    let mut decisions = Vec::new();
    let mut events = Vec::new();
    for record in records {
        let kind = record
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let seq = record
            .get("seq")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let at = string(&record, "at");
        if kind != "decision" {
            events.push(EventLine {
                seq,
                detail: describe(&kind, &record),
                kind,
            });
            continue;
        }
        if let Some(since) = &query.since
            && at.as_str() < since.as_str()
        {
            continue;
        }
        let permit = record
            .get("decision")
            .and_then(Value::as_bool)
            .unwrap_or_default();
        let outcome = crate::decision_out::outcome_of(&record);
        if let Some(wanted) = query.decision
            && !wanted.admits(&outcome)
        {
            continue;
        }

        decisions.push(DecisionLine {
            seq,
            at,
            decision: permit,
            outcome,
            subject: party(&record, "subject"),
            action: record
                .get("action")
                .and_then(|action| action.get("name"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            resource: party(&record, "resource"),
            commit: record
                .get("store")
                .and_then(|store| store.get("commit"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            policies: record
                .get("policies")
                .and_then(Value::as_array)
                .map(|policies| {
                    policies
                        .iter()
                        .filter_map(|policy| policy.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
            absent_inputs: record
                .get("inputs")
                .and_then(|inputs| inputs.get("absent"))
                .and_then(Value::as_array)
                .map(|names| {
                    names
                        .iter()
                        .filter_map(|name| name.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
            id: string(&record, "id"),
            latency_us: record
                .get("latency_us")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
        });
    }

    DecisionsReport {
        scope: match scope {
            ReadScope::Tenant { zone, ledger } => format!("{zone}/{ledger}"),
            ReadScope::Stream { pdp_id, instance } => format!("{pdp_id} · {instance}"),
        },
        decisions,
        events,
        next,
        more,
        verified,
    }
}

/// Re-computes what the records and the envelopes say about themselves.
///
/// Which proof applies is decided by the scope, not by preference:
///
/// ```text
/// producer stream  →  a contiguous history      →  the chain proves it
/// tenant view      →  a subsequence of one      →  the inclusion path does
/// ```
///
/// Running the chain check over a tenant page would report a failure of
/// arithmetic as a failure of integrity: the records in between belong to
/// other tenants, and their absence is the design working, not a break.
fn verify(
    scope: &ReadScope,
    records: &[Value],
    proof: &[Value],
    inclusion: &[Value],
    keys: Option<&[Jwk]>,
) -> Verified {
    let (mut verified, mut failed) = (0, 0);
    let mut roots: Vec<(String, bool)> = Vec::new();
    // The batches the producing Hosts' engines sealed (WP-6.2b): their roots are attributed only
    // when their signatures verify under the keys given.
    let mut host_batches = Vec::new();
    for entry in proof {
        match super::host_proof::host_batch(
            entry,
            keys,
            permguard_core::domains::protected::DECISION_BATCH,
        ) {
            Some(Ok(batch)) => {
                verified += usize::from(keys.is_some());
                roots.push((batch.merkle_root.clone(), keys.is_some()));
                host_batches.push(batch);
            }
            Some(Err(())) => failed += usize::from(keys.is_some()),
            None => {}
        }
    }
    let legacy: Vec<&Value> = proof
        .iter()
        .filter(|entry| {
            entry.get("format").and_then(Value::as_str) != Some(super::host_proof::HOST_FORMAT)
        })
        .collect();
    if let Some(keys) = keys {
        for &envelope in &legacy {
            let signed = serde_json::from_value::<Signed>(envelope.clone())
                .ok()
                .map(|signed| signed.verify(keys));
            match signed {
                Some(Ok(attested)) => {
                    verified += 1;
                    roots.push((attested.merkle_root, true));
                }
                Some(Err(_)) | None => failed += 1,
            }
        }
    } else {
        // Without a key set the roots are still usable for the arithmetic —
        // they simply are not *attributed*, and the report says so.
        for &envelope in &legacy {
            if let Ok(signed) = serde_json::from_value::<Signed>(envelope.clone())
                && let Ok(attested) = signed.envelope()
            {
                roots.push((attested.merkle_root, false));
            }
        }
    }

    match scope {
        ReadScope::Stream { .. } => {
            let (chain_ok, detail) = match chain::verify(records, None) {
                // An empty page is not a broken chain: there is nothing to check.
                Err(chain::ChainError::Empty) => (true, None),
                Err(error) => (false, Some(error.to_string())),
                // A chain that holds is not yet a chain anybody *signed*. When
                // a proof came back, bind its head to a head the producer
                // attested — the whole point of reading a stream is to check it
                // without trusting the server that served it. With no proof
                // asked for, the chain result stands alone and the report says
                // signatures were not checked.
                Ok(_) if proof.is_empty() => (true, None),
                Ok(verified) if attested(&verified, records, proof, &host_batches) => (true, None),
                Ok(_) => (
                    false,
                    Some(
                        "the records form a chain, and no envelope in the proof attests its head: \
                         this run is well-formed and unattributed"
                            .to_owned(),
                    ),
                ),
            };

            Verified {
                proof: "chain",
                chain: Some(chain_ok),
                chain_detail: detail,
                included: None,
                not_included: None,
                signatures: verified,
                signatures_failed: failed,
                signatures_checked: keys.is_some(),
            }
        }
        ReadScope::Tenant { .. } => {
            let (included, missing) = included(records, inclusion, &roots);

            Verified {
                proof: "inclusion",
                chain: None,
                chain_detail: None,
                included: Some(included),
                not_included: Some(missing),
                signatures: verified,
                signatures_failed: failed,
                signatures_checked: keys.is_some(),
            }
        }
    }
}

/// Whether the signed envelopes attest the run that was verified.
///
/// The chain proves the records follow one another; the envelope proves a
/// producer said so. Checking one without the other leaves the case that
/// matters: a store serving a well-formed history nobody signed — including a
/// *replaced* one, internally perfect, presented beside the genuine envelopes.
/// Range overlap alone would accept that, so the two are bound by digest:
/// every batch boundary that falls inside the run must name a head the run
/// actually digests to.
///
/// A run may still end mid-batch — a page boundary is not a batch boundary —
/// and its final records are then bound by the *next* page's chain check
/// rather than by a head of their own.
fn attested(
    verified: &permguard_decisions::Verified,
    records: &[Value],
    proof: &[Value],
    host_batches: &[super::host_proof::HostBatch],
) -> bool {
    let digests: std::collections::BTreeMap<u64, String> = records
        .iter()
        .filter_map(|record| {
            let seq = record.get("seq").and_then(Value::as_u64)?;

            record::digest_of(record).ok().map(|digest| (seq, digest))
        })
        .collect();
    // `(first, last, head)` of each batch of the verified stream: a legacy envelope naming it, or
    // a Host batch naming its `host_id` and run.
    let mut envelopes: Vec<(u64, u64, String)> = proof
        .iter()
        .filter_map(|signed| {
            serde_json::from_value::<Signed>(signed.clone())
                .ok()
                .and_then(|signed| signed.envelope().ok())
        })
        .filter(|envelope| envelope.stream == verified.stream)
        .map(|envelope| (envelope.first_seq, envelope.last_seq, envelope.head))
        .collect();
    envelopes.extend(
        host_batches
            .iter()
            .filter(|batch| {
                batch.producer == verified.stream.id && batch.run == verified.stream.instance
            })
            .map(|batch| (batch.first_seq, batch.last_seq, batch.head.clone())),
    );

    // Every attested head inside the run must be a digest the run reaches.
    // One that is not means the records and the signatures describe two
    // different histories, and "verified" must not be the answer.
    for (_, last, head) in &envelopes {
        if (verified.first_seq..=verified.last_seq).contains(last)
            && digests.get(last) != Some(head)
        {
            return false;
        }
    }

    // And the run's own head must be under some signature: attested exactly,
    // or carried by a batch that extends past the page.
    envelopes
        .iter()
        .any(|(first, last, _)| (*first..=*last).contains(&verified.last_seq))
}

/// How many records reach a root the producer attested, and how many do not.
///
/// A record is proven when its own digest, carried up its path, reaches a root
/// that came from a signed envelope. Recomputing the leaf from the record
/// itself is the part that matters: taking the leaf from the proof would prove
/// that the proof is consistent with itself.
fn included(records: &[Value], inclusion: &[Value], roots: &[(String, bool)]) -> (usize, usize) {
    let mut proven = 0;
    let mut missing = 0;
    for record in records {
        let seq = record
            .get("seq")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let Ok(leaf) = record::digest_of(record) else {
            missing += 1;
            continue;
        };
        // By its sequence and its leaf: a tenant page spans runs that each begin at 1, so a
        // sequence alone would take another run's path (WP-6.3b, after the review).
        let Some(path) = inclusion.iter().find(|entry| {
            entry.get("seq").and_then(Value::as_u64) == Some(seq)
                && entry.get("leaf").and_then(Value::as_str) == Some(leaf.as_str())
        }) else {
            missing += 1;
            continue;
        };
        let steps: Vec<merkle::Step> = path
            .get("path")
            .cloned()
            .and_then(|steps| serde_json::from_value(steps).ok())
            .unwrap_or_default();
        let reached = merkle::recompute(&leaf, &steps);
        if roots.iter().any(|(root, _)| root == &reached) {
            proven += 1;
        } else {
            missing += 1;
        }
    }

    (proven, missing)
}

fn describe(kind: &str, record: &Value) -> String {
    match kind {
        "marker" => format!(
            "sampling permits={}, build {}",
            record
                .get("sampling")
                .and_then(|sampling| sampling.get("permits"))
                .and_then(Value::as_str)
                .unwrap_or("?"),
            record
                .get("pdp")
                .and_then(|pdp| pdp.get("version"))
                .and_then(Value::as_str)
                .unwrap_or("?")
        ),
        "discontinuity" => format!(
            "the stream ended ({}); {} record(s) lost, continues as {}",
            string(record, "reason"),
            record
                .get("lost")
                .and_then(|lost| lost.get("count_estimate"))
                .and_then(Value::as_u64)
                .unwrap_or_default(),
            string(record, "successor")
        ),
        other => other.to_owned(),
    }
}

fn party(record: &Value, member: &str) -> String {
    let Some(party) = record.get(member) else {
        return String::new();
    };

    format!(
        "{}:{}",
        party
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        party.get("id").and_then(Value::as_str).unwrap_or_default()
    )
}

fn string(record: &Value, member: &str) -> String {
    record
        .get(member)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn read_failure(error: ReadError) -> Failure {
    match error {
        // The one refusal a consumer must act on rather than retry: it lost
        // records, and it is being told where the remaining ones begin.
        ReadError::Expired {
            oldest,
            oldest_sequence,
            requested_sequence,
        } => Failure::usage(format!(
            "this offset stands at {requested_sequence} and the oldest still held is \
             {oldest_sequence}: the {} records in between left on the retention schedule. Resume \
             from `{oldest}`, and record the gap — this is retention working, not the store being \
             broken",
            oldest_sequence.saturating_sub(requested_sequence)
        ))
        .named("not_found", permguard_core::codes::stream::OFFSET_EXPIRED),
        ReadError::Refused { code, detail } => Failure::usage(detail).named("validation", code),
        ReadError::Unavailable(detail) => Failure::unavailable(detail).named(
            "unavailable",
            permguard_core::codes::client::DECISION_LOG_UNREACHABLE,
        ),
    }
}

#[cfg(test)]
mod host_verify {
    //! WP-6.2b (owner decision of 2026-10-19): a page of decisions a Host's stream recorded is
    //! verified through the `host-batch-v1` entry its engine sealed, as `events verify` does.

    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use permguard_decisions::record::{
        ActionRef, Body, Build, Commitments, DecisionBody, GENESIS, Inputs, MarkerBody, Party,
        Reason, Record, Sampling, StoreRef, Stream,
    };

    use super::super::host_proof::testing::{Key, sealed};
    use super::*;

    fn build() -> Build {
        Build {
            version: "0.1.0".to_owned(),
            build: None,
            engines: None,
        }
    }

    /// A marker and a decision of the run `[7; 16]` of the Host `[1; 16]`, chained.
    fn records() -> Vec<Value> {
        let mut prev = GENESIS.to_owned();
        (1..=2u64)
            .map(|seq| {
                let body = if seq == 1 {
                    Body::Marker(Box::new(MarkerBody {
                        predecessor: None,
                        pdp: build(),
                        sampling: Sampling {
                            permits: "1.0".to_owned(),
                        },
                        commitments: Commitments {
                            alg: "HMAC-SHA256".to_owned(),
                            key_version: "v1".to_owned(),
                        },
                    }))
                } else {
                    Body::Decision(Box::new(DecisionBody {
                        id: "d-2".to_owned(),
                        pdp: build(),
                        store: StoreRef {
                            zone: "acme".to_owned(),
                            ledger: "main".to_owned(),
                            commit: "sha256:ec1773bf".to_owned(),
                            counter: 1,
                            profile: "default".to_owned(),
                        },
                        subject: Party {
                            kind: "User".to_owned(),
                            id: "pseudo:v1:9f2c".to_owned(),
                            properties: None,
                        },
                        resource: Party {
                            kind: "Document".to_owned(),
                            id: "budget".to_owned(),
                            properties: None,
                        },
                        action: ActionRef {
                            name: "read".to_owned(),
                        },
                        principal: None,
                        inputs: Inputs::default(),
                        decision: true,
                        outcome: None,
                        causes: None,
                        policies: vec!["policy-1".to_owned()],
                        reason: Reason {
                            code: "200".to_owned(),
                        },
                        trace: None,
                        request_id: None,
                        context: None,
                        latency_us: 143,
                        event: None,
                        interface: None,
                        actor: None,
                        question: None,
                        descriptors: None,
                    }))
                };
                let value = Record {
                    v: permguard_decisions::record::VERSION,
                    stream: Stream::new("01".repeat(16), "07".repeat(16)),
                    seq,
                    prev: prev.clone(),
                    at: "2026-10-19T10:00:00Z".to_owned(),
                    body,
                }
                .to_value()
                .expect("a record");
                prev = record::digest_of(&value).expect("a digest");
                value
            })
            .collect()
    }

    /// The records, their Host entry and one path per record.
    fn page(key: &Key) -> (Vec<Value>, Vec<Value>, Vec<Value>) {
        let records = records();
        let bytes: Vec<Vec<u8>> = records
            .iter()
            .map(|record| permguard_stream::jcs::canonicalize(record).expect("canonical"))
            .collect();
        let leaves: Vec<String> = records
            .iter()
            .map(|record| record::digest_of(record).expect("a digest"))
            .collect();
        let root = merkle::root(&leaves).expect("a root");
        let proof = vec![sealed(
            key,
            permguard_core::domains::protected::DECISION_BATCH,
            permguard_core::domains::digest::DECISION_RECORD,
            &"01".repeat(16),
            &"07".repeat(16),
            1,
            &bytes,
        )];
        let inclusion = (0..2)
            .map(|at| {
                serde_json::json!({
                    "seq": at + 1,
                    "leaf": leaves[at],
                    "root": root,
                    "path": merkle::path(&leaves, at).expect("a path"),
                })
            })
            .collect();
        (records, proof, inclusion)
    }

    #[test]
    fn a_tenant_page_of_host_records_is_included_under_its_sealing_key() {
        let key = Key::new("k1");
        let (records, proof, inclusion) = page(&key);
        let tenant = ReadScope::Tenant {
            zone: "acme".to_owned(),
            ledger: "main".to_owned(),
        };
        let verified = verify(&tenant, &records, &proof, &inclusion, Some(&[key.jwk()]));
        assert_eq!(verified.included, Some(2));
        assert_eq!(verified.not_included, Some(0));
        assert_eq!((verified.signatures, verified.signatures_failed), (1, 0));
        let refused = verify(
            &tenant,
            &records,
            &proof,
            &inclusion,
            Some(&[Key::new("k1").jwk()]),
        );
        assert_eq!(refused.signatures_failed, 1);
    }

    #[test]
    fn a_host_run_read_as_a_stream_is_attested_by_its_batch() {
        let key = Key::new("k1");
        let (records, proof, inclusion) = page(&key);
        let stream = ReadScope::Stream {
            pdp_id: "01".repeat(16),
            instance: "07".repeat(16),
        };
        let verified = verify(&stream, &records, &proof, &inclusion, Some(&[key.jwk()]));
        assert_eq!(verified.chain, Some(true), "{:?}", verified.chain_detail);
        // A batch of another run attests nothing of this one.
        let other = vec![sealed(
            &key,
            permguard_core::domains::protected::DECISION_BATCH,
            permguard_core::domains::digest::DECISION_RECORD,
            &"01".repeat(16),
            &"08".repeat(16),
            1,
            &[b"{}".to_vec(), b"{}".to_vec()],
        )];
        let unattested = verify(&stream, &records, &other, &inclusion, Some(&[key.jwk()]));
        assert_eq!(unattested.chain, Some(false));
    }
}

#[cfg(test)]
mod archive_verify {
    //! WP-6.3b (owner decision of 2026-10-20, F-07): `decisions export` writes a self-contained
    //! archive, and `decisions verify --file --keys` checks it offline.

    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use permguard_decisions::record::{
        Body, Build, Commitments, GENESIS, MarkerBody, Record, Sampling, Stream,
    };

    use super::super::host_proof::testing::{Key, sealed};
    use super::*;

    /// Three markers of the run `run`, two hex digits repeated, of the Host `[1; 16]`, chained.
    fn records_of(run: &str) -> Vec<Value> {
        let mut prev = GENESIS.to_owned();
        (1..=3u64)
            .map(|seq| {
                let value = Record {
                    v: permguard_decisions::record::VERSION,
                    stream: Stream::new("01".repeat(16), run.repeat(16)),
                    seq,
                    prev: prev.clone(),
                    at: "2026-10-20T10:00:00Z".to_owned(),
                    body: Body::Marker(Box::new(MarkerBody {
                        predecessor: None,
                        pdp: Build {
                            version: "0.1.0".to_owned(),
                            build: None,
                            engines: None,
                        },
                        sampling: Sampling {
                            permits: "1.0".to_owned(),
                        },
                        commitments: Commitments {
                            alg: "HMAC-SHA256".to_owned(),
                            key_version: format!("v{seq}"),
                        },
                    })),
                }
                .to_value()
                .expect("a record");
                prev = record::digest_of(&value).expect("a digest");
                value
            })
            .collect()
    }

    /// An export of `scope` signed by `key`.
    fn archive(key: &Key, scope: DecisionArchiveScope) -> DecisionArchive {
        archive_of(key, scope, "07")
    }

    /// An export of `scope` of the run `run`, signed by `key`.
    fn archive_of(key: &Key, scope: DecisionArchiveScope, run: &str) -> DecisionArchive {
        let records = records_of(run);
        let bytes: Vec<Vec<u8>> = records
            .iter()
            .map(|record| permguard_stream::jcs::canonicalize(record).expect("canonical"))
            .collect();
        let leaves: Vec<String> = records
            .iter()
            .map(|record| record::digest_of(record).expect("a digest"))
            .collect();
        let root = merkle::root(&leaves).expect("a root");
        DecisionArchive {
            format: permguard_core::domains::interface::DECISIONS_EXPORT_V1.to_owned(),
            scope_binding: scope,
            summary: DecisionArchiveSummary::default(),
            envelopes: vec![sealed(
                key,
                permguard_core::domains::protected::DECISION_BATCH,
                permguard_core::domains::digest::DECISION_RECORD,
                &"01".repeat(16),
                &run.repeat(16),
                1,
                &bytes,
            )],
            inclusion: (0..records.len())
                .map(|at| {
                    serde_json::json!({
                        "seq": at + 1,
                        "leaf": leaves[at],
                        "root": root,
                        "path": merkle::path(&leaves, at).expect("a path"),
                    })
                })
                .collect(),
            records,
            report: None,
        }
    }

    fn scopes() -> [DecisionArchiveScope; 2] {
        [
            DecisionArchiveScope::Stream {
                pdp: "01".repeat(16),
                instance: "07".repeat(16),
            },
            DecisionArchiveScope::Tenant {
                zone: "acme".to_owned(),
                ledger: "main".to_owned(),
            },
        ]
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "permguard-decision-archive-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("a directory");
        root
    }

    fn globals(workdir: &std::path::Path) -> Globals {
        Globals {
            output: crate::output::OutputFormat::Json,
            verbose: false,
            workdir: workdir.to_path_buf(),
            config: None,
            control_endpoint: None,
            data_endpoint: None,
            host_endpoint: None,
            volume: None,
            token_file: None,
            tls_ca_file: None,
            tls_cert_file: None,
            tls_key_file: None,
            tls_server_name: None,
            tls_skip_verify: false,
        }
    }

    /// The archive at `archive.json` and the key set at `keys.json` below a fresh directory.
    fn written(tag: &str, archive: &DecisionArchive, key: &Key) -> std::path::PathBuf {
        let root = scratch(tag);
        std::fs::write(
            root.join("archive.json"),
            serde_json::to_vec(archive).expect("JSON"),
        )
        .expect("written");
        std::fs::write(
            root.join("keys.json"),
            serde_json::to_vec(&serde_json::json!({"keys": [key.jwk()]})).expect("JSON"),
        )
        .expect("written");
        root
    }

    #[test]
    fn a_decision_export_is_a_self_contained_archive() {
        let key = Key::new("k1");
        for scope in scopes() {
            let held = archive(&key, scope.clone());
            let json = serde_json::to_string(&held).expect("JSON");
            assert!(
                !json.contains("\"report\""),
                "the terminal page is not archived"
            );
            let read = parse_archive(&json).expect("it reads back");
            assert_eq!(
                read.format,
                permguard_core::domains::interface::DECISIONS_EXPORT_V1
            );
            assert_eq!(read.scope_binding, scope);
            assert_eq!(read.records, held.records);
            assert_eq!(read.envelopes, held.envelopes);
            assert_eq!(read.inclusion, held.inclusion);
            let yaml = serde_norway::to_string(&held).expect("YAML");
            assert_eq!(
                parse_archive(&yaml).expect("it reads").records,
                held.records
            );
        }
    }

    #[test]
    fn an_untouched_decision_export_verifies_offline() {
        let key = Key::new("k1");
        for scope in scopes() {
            let (verified, report) = verify_archive(archive(&key, scope.clone()), &[key.jwk()])
                .ok()
                .expect("checked");
            assert!(verified, "{scope:?}: {:?}", report.verified);
            let root = written(
                &format!(
                    "untouched-{}",
                    matches!(scope, DecisionArchiveScope::Stream { .. })
                ),
                &archive(&key, scope),
                &key,
            );
            assert!(verify_file(&globals(&root), "archive.json", "keys.json").is_ok());
        }
    }

    #[test]
    fn an_altered_record_in_a_decision_export_exits_2() {
        let key = Key::new("k1");
        for scope in scopes() {
            let mut altered = archive(&key, scope.clone());
            altered.records[1]["commitments"]["key_version"] = serde_json::json!("v9");
            let (verified, _) = verify_archive(altered.clone(), &[key.jwk()])
                .ok()
                .expect("checked");
            assert!(!verified, "{scope:?}");
            let root = written(
                &format!(
                    "altered-{}",
                    matches!(scope, DecisionArchiveScope::Stream { .. })
                ),
                &altered,
                &key,
            );
            let refused = verify_file(&globals(&root), "archive.json", "keys.json")
                .expect_err("an altered record");
            assert_eq!(refused.status, crate::failure::EXIT_NOT_READY);
            assert_eq!(
                refused.code,
                permguard_core::codes::client::DECISIONS_UNVERIFIED
            );

            // Its envelopes stripped: well-formed and attributed to nobody.
            let mut stripped = archive(&key, scope.clone());
            stripped.envelopes.clear();
            assert!(
                !verify_archive(stripped, &[key.jwk()])
                    .ok()
                    .expect("checked")
                    .0
            );
            // Signed by a key the set does not hold.
            let other = Key::new("k1");
            assert!(
                !verify_archive(archive(&key, scope), &[other.jwk()])
                    .ok()
                    .expect("checked")
                    .0
            );
        }
    }

    #[test]
    fn a_decision_export_that_cannot_be_read_or_parsed_is_refused() {
        let key = Key::new("k1");
        let root = written("unreadable", &archive(&key, scopes()[0].clone()), &key);
        let refused =
            verify_file(&globals(&root), "missing.json", "keys.json").expect_err("no such file");
        assert_eq!(refused.status, crate::failure::EXIT_USAGE);
        assert_eq!(
            refused.code,
            permguard_core::codes::client::DECISION_EXPORT_UNREADABLE
        );
        std::fs::write(root.join("garbage.json"), b"{ not an archive").expect("written");
        let refused =
            verify_file(&globals(&root), "garbage.json", "keys.json").expect_err("not an archive");
        assert_eq!(refused.status, crate::failure::EXIT_USAGE);
        assert_eq!(
            refused.code,
            permguard_core::codes::client::DECISION_EXPORT_MALFORMED
        );
    }

    #[test]
    fn a_decision_export_of_another_format_or_truncated_is_refused() {
        let key = Key::new("k1");
        let mut other = archive(&key, scopes()[0].clone());
        other.format = permguard_core::domains::interface::EVENTS_EXPORT_V1ALPHA1.to_owned();
        let refused = verify_archive(other, &[key.jwk()]).expect_err("another format");
        assert_eq!(refused.status, crate::failure::EXIT_USAGE);
        assert_eq!(
            refused.code,
            permguard_core::codes::client::DECISION_EXPORT_TYPE_UNSUPPORTED
        );
        let mut truncated = archive(&key, scopes()[0].clone());
        truncated.summary.truncated = true;
        let refused = verify_archive(truncated, &[key.jwk()]).expect_err("truncated");
        assert_eq!(
            refused.code,
            permguard_core::codes::client::DECISION_EXPORT_TRUNCATED
        );
    }

    #[test]
    fn the_command_line_names_decisions_verify() {
        use clap::Parser as _;

        let parsed = crate::args::Cli::try_parse_from([
            "permguard",
            "decisions",
            "verify",
            "--file",
            "decisions.json",
            "--keys",
            "keys.json",
        ])
        .expect("parsed");
        assert!(matches!(
            parsed.command,
            Some(crate::args::Command::Decisions {
                action: DecisionsAction::Verify { ref file, ref keys },
            }) if file == "decisions.json" && keys == "keys.json"
        ));
        for missing in [
            vec![
                "permguard",
                "decisions",
                "verify",
                "--file",
                "decisions.json",
            ],
            vec!["permguard", "decisions", "verify", "--keys", "keys.json"],
        ] {
            assert!(crate::args::Cli::try_parse_from(missing).is_err());
        }
    }

    /// After the review: a stream archive relabelled to another producer or instance does not
    /// verify, and a tenant archive's decisions name one ledger, the bound one when it is bound
    /// by names.
    #[test]
    fn an_archive_bound_to_another_scope_does_not_verify() {
        let key = Key::new("k1");
        let mut relabelled = archive(&key, scopes()[0].clone());
        relabelled.scope_binding = DecisionArchiveScope::Stream {
            pdp: "02".repeat(16),
            instance: "07".repeat(16),
        };
        assert!(
            !verify_archive(relabelled, &[key.jwk()])
                .ok()
                .expect("checked")
                .0
        );

        let decision = |zone: &str, ledger: &str| serde_json::json!({"kind": "decision", "store": {"zone": zone, "ledger": ledger}});
        let tenant = |zone: &str, ledger: &str| DecisionArchiveScope::Tenant {
            zone: zone.to_owned(),
            ledger: ledger.to_owned(),
        };
        let held = [decision("acme", "main"), decision("acme", "main")];
        assert!(bound(&tenant("acme", "main"), &held));
        assert!(!bound(&tenant("other", "main"), &held), "relabelled");
        assert!(!bound(&tenant("acme", "audit"), &held), "relabelled");
        assert!(
            !bound(
                &tenant("acme", "main"),
                &[decision("acme", "main"), decision("other", "main")]
            ),
            "two tenants in one view"
        );
        assert!(bound(
            &tenant(
                "00000000-0000-4000-8000-000000000001",
                "00000000-0000-4000-8000-000000000002"
            ),
            &held
        ));
    }

    /// After the review: a stream archive holds whole batches, so a record removed from either
    /// end does not verify.
    #[test]
    fn a_record_removed_from_either_end_of_a_stream_archive_does_not_verify() {
        let key = Key::new("k1");
        let stream = scopes()[0].clone();
        let mut tail = archive(&key, stream.clone());
        tail.records.pop();
        assert!(!verify_archive(tail, &[key.jwk()]).ok().expect("checked").0);
        let mut head = archive(&key, stream);
        head.records.remove(0);
        assert!(!verify_archive(head, &[key.jwk()]).ok().expect("checked").0);
    }

    /// After the review: a tenant archive spanning two runs, each starting at 1, pairs each
    /// record with its own path, by sequence and leaf.
    #[test]
    fn a_tenant_archive_of_two_runs_verifies() {
        let key = Key::new("k1");
        let tenant = scopes()[1].clone();
        let mut both = archive_of(&key, tenant.clone(), "07");
        let other = archive_of(&key, tenant, "08");
        both.records.extend(other.records);
        both.envelopes.extend(other.envelopes);
        both.inclusion.extend(other.inclusion);
        let (verified, report) = verify_archive(both, &[key.jwk()]).ok().expect("checked");
        assert!(verified, "{:?}", report.verified);
        assert_eq!(report.verified.and_then(|held| held.included), Some(6));
    }

    /// After the review: an export always carries its proofs, and is truncated only when it
    /// stopped at its own page bound with more of its snapshot to read.
    #[test]
    fn an_export_carries_its_proofs_and_says_when_it_is_truncated() {
        use clap::Parser as _;

        let parsed =
            crate::args::Cli::try_parse_from(["permguard", "decisions", "export"]).expect("parsed");
        let Some(crate::args::Command::Decisions {
            action: DecisionsAction::Export(query),
        }) = parsed.command
        else {
            panic!("an export");
        };
        assert!(!query.verify);
        assert!(proofs_asked(&query, true), "an export");
        assert!(!proofs_asked(&query, false), "a list that does not verify");
        assert!(export_truncated(true, MAX_PAGES, true));
        assert!(
            !export_truncated(true, MAX_PAGES, false),
            "the snapshot ended"
        );
        assert!(
            !export_truncated(true, MAX_PAGES - 1, true),
            "the bound not reached"
        );
        assert!(!export_truncated(false, MAX_PAGES, true), "not an export");
    }
}
