// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `permguard events` — read what a data plane recorded, and check it.
//!
//! # The position belongs to the caller
//!
//! The control plane keeps no cursor, so two people tailing the same ledger do not interfere, and
//! no reader can back-pressure the plane that is recording. The offset it returns is opaque,
//! signed, and bound to the scope and the filters it was issued for: an offset from one tenant
//! presented under another is refused rather than reinterpreted, and one whose filters were widened
//! after the fact starts a new read rather than quietly widening this one.
//!
//! # Why `export` finishes and `tail` does not
//!
//! An export captures the watermark of its first page and echoes it on every page after, so it
//! terminates on a ledger that is still recording — events written after it belong to a later
//! export. A tail deliberately carries no bound: it reads from `next` and idles when caught up.
//! One field, two behaviours, and no second code path.
//!
//! # What `--verify` actually checks
//!
//! Every record's digest against its inclusion path, and the path against the root its envelope
//! attests. With `--keys`, also that the envelope was signed by a key that set publishes — which is
//! what makes the answer independent of the server that served it. The report says which of the
//! two happened, because "verified" that quietly skipped the signatures is worse than no
//! verification at all.

use std::process::ExitCode;

use permguard_control_client::events::{
    self, EventLog, ReadError, ReadFilters, ReadScope, ReadWindow,
};
use permguard_core::Jwk;
use permguard_events::envelope::Signed;
use permguard_events::{chain, merkle_of, record};
use serde_json::Value;

use crate::args::{EventsAction, EventsQuery, Globals};
use crate::event_out::{
    ArchiveScope, Coverage, EventArchive, EventLine, EventReport, EventsReport, History,
    SignersReport, Verified,
};
use crate::failure::{EXIT_READY, Failure};
use crate::session::{open_store, render};
use crate::target::{self, Asked};
use crate::trace::Trace;

/// How many pages `export`, `get` and `verify` will walk before giving up.
///
/// A bound rather than a loop: a command that walks for ever on a store that keeps growing is a
/// command nobody can put in a script.
///
/// Reaching it is **not** a successful export. It used to be: the loop ran out, whatever had been
/// read was printed, and the command exited `0` — so a snapshot that stopped a third of the way
/// through was indistinguishable, to a script, from one that finished. What the bound protects
/// against is an endless command; it must not turn a partial answer into a complete-looking one.
const MAX_PAGES: usize = 10_000;

/// Runs the command.
pub fn events(globals: &Globals, action: &EventsAction) -> Result<ExitCode, Failure> {
    match action {
        EventsAction::List(query) => list(globals, query, false),
        EventsAction::Tail { query, follow } => tail(globals, query, *follow),
        EventsAction::Get { event_id, query } => get(globals, query, event_id),
        EventsAction::Signers(query) => signers(globals, query),
        EventsAction::Export(query) => list(globals, query, true),
        EventsAction::Verify { file, query } => match file {
            Some(file) => verify_file(globals, query, file),
            None => verify(globals, query),
        },
    }
}

/// One page, or a whole finite snapshot.
fn list(globals: &Globals, query: &EventsQuery, everything: bool) -> Result<ExitCode, Failure> {
    let trace = Trace::new(globals.verbose);
    let (reader, scope) = connect(globals, query, &trace)?;
    let keys = key_set(globals, query)?;

    let mut read = Read::default();
    let mut window = window_of(query);
    if everything {
        // An export is an offline-verifiable artifact, not a long `list`. Always carry the signed
        // envelopes and inclusion paths; `--verify` controls whether this command also checks them
        // before writing, not whether the exported file contains its evidence.
        window.proof = true;
    }
    let pages = if everything { MAX_PAGES } else { 1 };
    let mut walked = 0;
    for page_number in 0..pages {
        let page = reader.read(&scope, &window).map_err(read_failure)?;
        if everything && page_number == 0 {
            window.until = Some(page.high_watermark.clone());
            trace.say(format!(
                "exporting the snapshot at `{}`; events written after it belong to a later export",
                page.high_watermark
            ));
        }
        read.absorb(page, &mut window);
        walked = page_number + 1;
        // An empty page is not the end: filtering and scan bounds mean a page may match nothing
        // while still advancing. The export stops from `more` against its own bound.
        if !everything || !read.more {
            break;
        }
    }
    // Stopped by this command's own bound rather than by the snapshot ending. Only an export can
    // be truncated this way: a single page was asked to read one page and did.
    let truncated = everything && walked == pages && read.more;
    let resume = read.next.clone();

    let evidence = everything.then(|| {
        (
            read.records.clone(),
            read.proof.clone(),
            read.inclusion.clone(),
        )
    });
    let mut answer = report(&scope, read, query, keys.as_deref());
    answer.truncated = truncated;
    if let Some((records, envelopes, inclusion)) = evidence {
        render(
            &EventArchive {
                format: "permguard.events.export.v1alpha1".to_owned(),
                scope_binding: archive_scope(&scope),
                summary: answer,
                records,
                envelopes,
                inclusion,
            },
            globals.output,
            &trace,
        )?;
    } else {
        render(&answer, globals.output, &trace)?;
    }

    if truncated {
        // Printed, so the work is not thrown away, and then refused, so nothing downstream reads
        // a third of a snapshot as the whole of one.
        return Err(Failure::usage(format!(
            "this export stopped after {pages} pages and the snapshot is not finished: what was \
             read is above, and `--from {resume}` continues it"
        ))
        .named("validation", "export_truncated"));
    }

    Ok(ExitCode::from(EXIT_READY))
}

/// The stream, as it arrives.
fn tail(globals: &Globals, query: &EventsQuery, follow: bool) -> Result<ExitCode, Failure> {
    let trace = Trace::new(globals.verbose);
    let (reader, scope) = connect(globals, query, &trace)?;
    let keys = key_set(globals, query)?;
    // No `until`: a tail is deliberately unbounded, which is what makes it a tail.
    let mut window = window_of(query);

    loop {
        let page = reader.read(&scope, &window).map_err(read_failure)?;
        let more = page.more;
        window.from = Some(page.next.clone());
        if !page.records.is_empty() {
            let mut read = Read::default();
            read.absorb(page, &mut ReadWindow::default());
            render(
                &report(&scope, read, query, keys.as_deref()),
                globals.output,
                &trace,
            )?;
        }
        if !follow {
            break;
        }
        if !more {
            // Idle rather than busy: a tail that spins costs the control plane more than the
            // events do.
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    Ok(ExitCode::from(EXIT_READY))
}

/// One occurrence, by the identifier its caller stated.
fn get(globals: &Globals, query: &EventsQuery, event_id: &str) -> Result<ExitCode, Failure> {
    let trace = Trace::new(globals.verbose);
    let (reader, scope) = connect(globals, query, &trace)?;
    let (zone, ledger) = match &scope {
        ReadScope::Tenant { zone, ledger } | ReadScope::Stream { zone, ledger, .. } => {
            (zone.clone(), ledger.clone())
        }
    };

    match reader.get(&zone, &ledger, event_id).map_err(read_failure)? {
        Some(record) => {
            render(&EventReport { record }, globals.output, &trace)?;

            Ok(ExitCode::from(EXIT_READY))
        }
        None => Err(Failure::usage(format!(
            "no event in `{zone}/{ledger}` carries the identifier `{event_id}`"
        ))
        .named("not_found", "event_not_found")),
    }
}

/// Which key signed which stretch of each producer stream, public keys included.
fn signers(globals: &Globals, query: &EventsQuery) -> Result<ExitCode, Failure> {
    let trace = Trace::new(globals.verbose);
    let (reader, scope) = connect(globals, query, &trace)?;
    let (zone, ledger) = match &scope {
        ReadScope::Tenant { zone, ledger } | ReadScope::Stream { zone, ledger, .. } => {
            (zone.clone(), ledger.clone())
        }
    };

    let document = reader.signers(&zone, &ledger).map_err(read_failure)?;
    render(
        &SignersReport {
            scope: format!("{zone}/{ledger}"),
            document,
        },
        globals.output,
        &trace,
    )?;

    Ok(ExitCode::from(EXIT_READY))
}

/// Walks a finite snapshot and checks everything it can.
fn verify(globals: &Globals, query: &EventsQuery) -> Result<ExitCode, Failure> {
    let trace = Trace::new(globals.verbose);
    let keys = verification_keys(globals, query)?;
    let (reader, scope) = connect(globals, query, &trace)?;

    let mut read = Read::default();
    let mut window = window_of(query);
    // Proofs are the point of this command, whatever the flag said.
    window.proof = true;
    let mut walked = 0;
    for page_number in 0..MAX_PAGES {
        let page = reader.read(&scope, &window).map_err(read_failure)?;
        if page_number == 0 {
            window.until = Some(page.high_watermark.clone());
        }
        read.absorb(page, &mut window);
        walked = page_number + 1;
        if !read.more {
            break;
        }
    }
    // A verification that did not reach the end of its own snapshot has verified a prefix. Saying
    // "it holds" about that is the same lie as a truncated export reporting success.
    let truncated = walked == MAX_PAGES && read.more;
    let resume = read.next.clone();

    let checked = check(&scope, &read, Some(&keys));
    let holds = checked.holds();
    let mut report = report(&scope, read, query, Some(&keys));
    report.truncated = truncated;
    report.verified = Some(checked);
    render(&report, globals.output, &trace)?;

    if truncated {
        return Err(Failure::usage(format!(
            "this verification stopped after {MAX_PAGES} pages and did not reach the end of the \
             snapshot: what was checked is above, and `--from {resume}` continues it"
        ))
        .named("validation", "export_truncated"));
    }

    // A verification that failed is a failed command: a script that ran this and looked only at
    // the exit status must not be told everything is fine.
    if !holds {
        return Err(Failure::usage(
            "this store cannot account for every record it returned: see the report above"
                .to_owned(),
        )
        .named("validation", "events_unverified"));
    }

    Ok(ExitCode::from(EXIT_READY))
}

/// Checks an export without asking the server that supplied it another question.
fn verify_file(globals: &Globals, query: &EventsQuery, file: &str) -> Result<ExitCode, Failure> {
    let trace = Trace::new(globals.verbose);
    let named = crate::session::rooted(globals, file);
    trace.say(format!(
        "verifying the event archive at {} without contacting a server",
        named.display()
    ));
    let text = std::fs::read_to_string(&named).map_err(|error| {
        Failure::usage(format!("reading {}: {error}", named.display()))
            .named("validation", "event_export_unreadable")
    })?;
    let archive: EventArchive = serde_json::from_str(&text)
        .or_else(|_| serde_norway::from_str(&text))
        .map_err(|error| {
            Failure::usage(format!(
                "{} is not a Permguard event export: {error}",
                named.display()
            ))
            .named("validation", "event_export_malformed")
        })?;
    if archive.format != "permguard.events.export.v1alpha1" {
        return Err(Failure::usage(format!(
            "{} declares export format `{}`; this CLI verifies \
             `permguard.events.export.v1alpha1`",
            named.display(),
            archive.format
        ))
        .named("validation", "event_export_type_unsupported"));
    }
    let scope = read_scope(&archive.scope_binding);
    let keys = verification_keys(globals, query)?;
    let read = Read {
        records: archive.records,
        proof: archive.envelopes,
        inclusion: archive.inclusion,
        next: archive.summary.next,
        oldest_available: archive.summary.oldest_available,
        high_watermark: archive.summary.high_watermark,
        more: archive.summary.more,
        examined: archive.summary.coverage.examined,
        scan_bounded: archive.summary.coverage.scan_bounded,
    };
    let checked = check(&scope, &read, Some(&keys));
    let holds = checked.holds();
    let mut answer = report(&scope, read, query, Some(&keys));
    answer.truncated = archive.summary.truncated;
    answer.verified = Some(checked);
    render(&answer, globals.output, &trace)?;
    if answer.truncated {
        return Err(Failure::usage(
            "the file is a truncated export, so it cannot establish a complete snapshot",
        )
        .named("validation", "event_export_truncated"));
    }
    if !holds {
        return Err(Failure::usage(
            "this export cannot account for every record it contains: see the report above",
        )
        .named("validation", "events_unverified"));
    }

    Ok(ExitCode::from(EXIT_READY))
}

/// What the pages accumulated.
#[derive(Clone, Default)]
struct Read {
    records: Vec<Value>,
    proof: Vec<Value>,
    inclusion: Vec<Value>,
    next: String,
    oldest_available: String,
    high_watermark: String,
    more: bool,
    examined: u64,
    scan_bounded: bool,
}

impl Read {
    fn absorb(&mut self, page: events::Page, window: &mut ReadWindow) {
        self.more = page.more;
        self.next.clone_from(&page.next);
        if self.oldest_available.is_empty() {
            self.oldest_available = page.oldest_available;
        }
        self.high_watermark = page.high_watermark;
        self.examined += page.coverage.examined;
        self.scan_bounded |= page.coverage.scan_bounded;
        self.records.extend(page.records);
        for envelope in page.proof {
            if !self.proof.contains(&envelope) {
                self.proof.push(envelope);
            }
        }
        self.inclusion.extend(page.inclusion);
        window.from = Some(page.next);
    }
}

/// The window a query asks for.
fn window_of(query: &EventsQuery) -> ReadWindow {
    ReadWindow {
        from: query.from.clone(),
        until: None,
        limit_records: query.limit,
        limit_bytes: query.limit_bytes.unwrap_or_default(),
        proof: query.verify,
        filters: ReadFilters {
            event_types: query.event_types.clone(),
            producer: None,
            instance: None,
            profile: query.profile.clone(),
            policy_partition: query.policy_partition.clone(),
            kind: query.kind.clone(),
            event_id: None,
            since: query.since.clone(),
            until_time: query.until.clone(),
            history: query.history.clone(),
        },
    }
}

/// The reader, and what it is reading.
fn connect(
    globals: &Globals,
    query: &EventsQuery,
    trace: &Trace,
) -> Result<(Box<dyn EventLog>, ReadScope), Failure> {
    let store = open_store(globals, trace)?;
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
    // Both, always: an event lives in one ledger, and a producer stream is named *inside* one
    // rather than beside it — the same producer may record for several tenants.
    let (Some(zone), Some(ledger)) = (target.zone.clone(), target.ledger.clone()) else {
        return Err(Failure::usage(
            "which events? name a zone and a ledger (--zone/--ledger), or stand in a workspace",
        ));
    };
    trace.say(format!("reading {zone}/{ledger} from {}", target.endpoint));

    let reader = events::client(
        &target.endpoint,
        &target::tls(globals),
        crate::narrator::for_run(globals.verbose),
    )
    .map_err(Failure::usage)?;

    // A producer stream is named outright; anything else is one tenant's records.
    let scope = match (&query.producer, &query.instance) {
        (Some(producer), Some(instance)) => ReadScope::Stream {
            zone,
            ledger,
            class: query
                .producer_class
                .clone()
                .unwrap_or_else(|| permguard_events::PRODUCER_CLASS_DATA_PLANE.to_owned()),
            producer: producer.clone(),
            instance: instance.clone(),
        },
        _ => ReadScope::Tenant { zone, ledger },
    };

    Ok((reader, scope))
}

fn archive_scope(scope: &ReadScope) -> ArchiveScope {
    match scope {
        ReadScope::Tenant { zone, ledger } => ArchiveScope::Tenant {
            zone: zone.clone(),
            ledger: ledger.clone(),
        },
        ReadScope::Stream {
            zone,
            ledger,
            class,
            producer,
            instance,
        } => ArchiveScope::Stream {
            zone: zone.clone(),
            ledger: ledger.clone(),
            producer_class: class.clone(),
            producer: producer.clone(),
            instance: instance.clone(),
        },
    }
}

fn read_scope(scope: &ArchiveScope) -> ReadScope {
    match scope {
        ArchiveScope::Tenant { zone, ledger } => ReadScope::Tenant {
            zone: zone.clone(),
            ledger: ledger.clone(),
        },
        ArchiveScope::Stream {
            zone,
            ledger,
            producer_class,
            producer,
            instance,
        } => ReadScope::Stream {
            zone: zone.clone(),
            ledger: ledger.clone(),
            class: producer_class.clone(),
            producer: producer.clone(),
            instance: instance.clone(),
        },
    }
}

/// The producer's published key set, when one was named.
fn key_set(globals: &Globals, query: &EventsQuery) -> Result<Option<Vec<Jwk>>, Failure> {
    let Some(path) = &query.keys else {
        return Ok(None);
    };
    // `-w` says where a relative path is read from, and this is one.
    let named = crate::session::rooted(globals, path);
    let text = std::fs::read_to_string(&named).map_err(|error| {
        Failure::usage(format!("reading {}: {error}", named.display()))
            .named("validation", "keys_unreadable")
    })?;
    let parsed: Value = serde_json::from_str(&text).map_err(|error| {
        Failure::usage(format!(
            "{} is not a JWKS document: {error}",
            named.display()
        ))
        .named("validation", "keys_malformed")
    })?;
    let values = parsed
        .get("keys")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| {
            Failure::usage(format!(
                "{} is a JWKS document with no `keys` array",
                named.display()
            ))
            .named("validation", "keys_malformed")
        })?;
    let keys: Vec<Jwk> = values
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            serde_json::from_value(value).map_err(|error| {
                Failure::usage(format!(
                    "{} has a malformed key at index {index}: {error}",
                    named.display()
                ))
                .named("validation", "keys_malformed")
            })
        })
        .collect::<Result<_, _>>()?;
    if keys.is_empty() {
        return Err(Failure::usage(format!(
            "{} publishes no verification keys",
            named.display()
        ))
        .named("validation", "keys_empty"));
    }

    Ok(Some(keys))
}

/// The trust anchor an independent verification requires.
fn verification_keys(globals: &Globals, query: &EventsQuery) -> Result<Vec<Jwk>, Failure> {
    key_set(globals, query)?.ok_or_else(|| {
        Failure::usage(
            "independent event verification requires the producer's JWKS: pass `--keys <FILE>`"
                .to_owned(),
        )
        .named("validation", "event_keys_required")
    })
}

/// The page, as the report prints it.
fn report(
    scope: &ReadScope,
    read: Read,
    query: &EventsQuery,
    keys: Option<&[Jwk]>,
) -> EventsReport {
    let verified = query.verify.then(|| check(scope, &read, keys));

    EventsReport {
        scope: match scope {
            ReadScope::Tenant { zone, ledger } => format!("{zone}/{ledger}"),
            ReadScope::Stream {
                zone,
                ledger,
                producer,
                instance,
                ..
            } => format!("{zone}/{ledger} · {producer}/{instance}"),
        },
        events: read.records.iter().map(line).collect(),
        next: read.next,
        oldest_available: read.oldest_available,
        high_watermark: read.high_watermark,
        more: read.more,
        // Set by the caller, which is the only place that knows whether its own page bound was
        // what stopped it.
        truncated: false,
        coverage: Coverage {
            contiguous: matches!(scope, ReadScope::Stream { .. }) && query.event_types.is_empty(),
            examined: read.examined,
            scan_bounded: read.scan_bounded,
        },
        verified,
    }
}

/// One record, as a line.
fn line(record: &Value) -> EventLine {
    let text = |path: &[&str]| -> String {
        let mut held = record;
        for segment in path {
            let Some(next) = held.get(*segment) else {
                return String::new();
            };
            held = next;
        }

        held.as_str().unwrap_or_default().to_owned()
    };

    EventLine {
        seq: record
            .get("seq")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        event_id: text(&["event_id"]),
        event_type: text(&["event_type"]),
        kind: text(&["kind"]),
        occurred_at: text(&["occurred_at"]),
        observed_at: text(&["observed_at"]),
        profile: text(&["profile"]),
        policy_partitions: record
            .get("policy_partitions")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        commit: text(&["commit"]),
        producer: text(&["stream", "producer", "id"]),
        instance: text(&["stream", "producer", "instance"]),
        history: record.get("history_key").and_then(|held| {
            Some(History {
                pins: strings(held.get("pins")?),
                values: strings(held.get("values")?),
                digest: held.get("digest")?.as_str()?.to_owned(),
            })
        }),
    }
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Checks what was read, as far as the scope allows.
fn check(scope: &ReadScope, read: &Read, keys: Option<&[Jwk]>) -> Verified {
    // A producer stream is a contiguous history, so the chain is what proves it. A tenant view is
    // a subsequence, so it is not — and reporting a chain result for one would be reporting a
    // failure of arithmetic as a failure of integrity.
    let (proof, chain, chain_detail) = match scope {
        ReadScope::Stream { .. } => match chain::verify(&read.records, None) {
            Ok(_) => ("chain".to_owned(), Some(true), None),
            Err(error) => ("chain".to_owned(), Some(false), Some(error.to_string())),
        },
        ReadScope::Tenant { .. } => ("inclusion".to_owned(), None, None),
    };

    // Decode and shape-check every envelope even when no key set was supplied. With keys, retain
    // only envelopes whose signature verifies. A Merkle path is evidence only when its root is one
    // of these envelopes' roots and both the envelope and record belong to the requested scope.
    let mut envelopes = Vec::new();
    let mut signatures = 0;
    let mut signatures_failed = 0;
    let mut malformed_envelopes = 0;
    for value in &read.proof {
        let Ok(signed) = serde_json::from_value::<Signed>(value.clone()) else {
            signatures_failed += usize::from(keys.is_some());
            malformed_envelopes += 1;
            continue;
        };
        let decoded = match keys {
            Some(keys) => match signed.verify(keys) {
                Ok(envelope) => {
                    signatures += 1;
                    Some(envelope)
                }
                Err(_) => {
                    signatures_failed += 1;
                    None
                }
            },
            None => {
                let protected = signed.protected().ok().filter(|header| {
                    header.alg == permguard_events::envelope::ALGORITHM
                        && header.typ == permguard_events::envelope::BATCH_TYPE
                });
                protected.and_then(|_| {
                    signed
                        .envelope()
                        .ok()
                        .filter(|envelope| envelope.check_shape().is_ok())
                })
            }
        };
        if let Some(envelope) = decoded {
            envelopes.push(envelope);
        } else if keys.is_none() {
            malformed_envelopes += 1;
        }
    }

    let mut included = 0;
    let mut not_included = 0;
    for (record, path) in read.records.iter().zip(&read.inclusion) {
        let parsed = record::validate(record).ok().filter(valid_occurrence);
        let record_stream = parsed.as_ref().map(|record| &record.stream);
        let root = path.get("root").and_then(Value::as_str);
        let covered = match (record_stream, root) {
            (Some(stream), Some(root)) => {
                scope_contains(scope, stream)
                    && envelopes.iter().any(|envelope| {
                        envelope.stream == *stream
                            && envelope.merkle_root == root
                            && record
                                .get("seq")
                                .and_then(Value::as_u64)
                                .is_some_and(|seq| {
                                    (envelope.first_seq..=envelope.last_seq).contains(&seq)
                                })
                    })
            }
            _ => false,
        };
        if covered && accounts_for(record, path) {
            included += 1;
        } else {
            not_included += 1;
        }
    }
    // A record with no path at all is a record the store could not account for, which is the same
    // answer as a path that does not check out.
    not_included += read.records.len().saturating_sub(read.inclusion.len());
    // An export containing an envelope that is not even a well-formed event-batch attestation is
    // not wholly verified merely because another envelope happened to cover all returned records.
    not_included += malformed_envelopes;

    Verified {
        proof,
        chain,
        chain_detail,
        included,
        not_included,
        signatures,
        signatures_failed,
        signatures_checked: keys.is_some(),
    }
}

/// Whether the registered payload agrees with the record fields used for filtering and display.
fn valid_occurrence(record: &record::Record) -> bool {
    if record.event_type != permguard_languages::event::EVENT_TYPE {
        return false;
    }
    let Ok(body) =
        serde_json::from_value::<permguard_languages::event::OccurrenceBody>(record.event.clone())
    else {
        return false;
    };
    let Ok(occurrence) = body.read() else {
        return false;
    };

    occurrence.event_id == record.event_id
        && occurrence.kind == record.kind
        && occurrence.occurred_at == record.occurred_at
}

fn scope_contains(scope: &ReadScope, stream: &permguard_events::Stream) -> bool {
    match scope {
        ReadScope::Tenant { zone, ledger } => stream.zone == *zone && stream.ledger == *ledger,
        ReadScope::Stream {
            zone,
            ledger,
            class,
            producer,
            instance,
        } => {
            stream.zone == *zone
                && stream.ledger == *ledger
                && stream.producer.class == *class
                && stream.producer.id == *producer
                && stream.producer.instance == *instance
        }
    }
}

/// Whether an inclusion path accounts for its record.
fn accounts_for(record: &Value, path: &Value) -> bool {
    let Ok(digest) = record::digest_of(record) else {
        return false;
    };
    let Some(leaf) = path.get("leaf").and_then(Value::as_str) else {
        return false;
    };
    if leaf != digest {
        return false;
    }
    let Some(root) = path.get("root").and_then(Value::as_str) else {
        return false;
    };
    let Some(steps) = path.get("path").cloned().and_then(|held| {
        serde_json::from_value::<Vec<permguard_decisions::merkle::Step>>(held).ok()
    }) else {
        return false;
    };

    merkle_of(leaf, &steps) == root
}

/// Turns a read refusal into the answer a person can act on.
fn read_failure(error: ReadError) -> Failure {
    match error {
        // The one refusal a consumer must act on rather than retry: it lost records, and it is
        // being told where the remaining ones begin.
        ReadError::Expired {
            oldest,
            oldest_sequence,
            requested_sequence,
        } => Failure::usage(format!(
            "this offset stands at {requested_sequence} and the oldest still held is \
             {oldest_sequence}: the {} events in between left on the retention schedule. Resume \
             from `{oldest}`, and record the gap — this is retention working, not the store being \
             broken",
            oldest_sequence.saturating_sub(requested_sequence)
        ))
        .named("not_found", "offset_expired"),
        ReadError::Refused { code, detail } => Failure::usage(detail).named("validation", code),
        ReadError::Unavailable(detail) => {
            Failure::internal(detail).named("unavailable", "event_store_unreachable")
        }
    }
}
