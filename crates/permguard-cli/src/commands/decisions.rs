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

use crate::args::{Decision, DecisionsAction, DecisionsQuery, Globals};
use crate::decision_out::{
    DecisionLine, DecisionReport, DecisionSignersReport, DecisionsReport, EventLine, Verified,
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
        proof: query.verify,
        ..ReadWindow::default()
    };
    for page_number in 0..if everything { MAX_PAGES } else { 1 } {
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
        read.proof.extend(page.proof);
        read.inclusion.extend(page.inclusion);
        read.records.extend(page.records);
        // An empty page is not the end: filtering and scan bounds mean a page may match nothing
        // while still advancing. The export stops from `more` against its own bound, and nothing
        // else.
        if !everything || !read.more {
            break;
        }
    }

    let report = report(&scope, read, query, keys.as_deref());
    render(&report, globals.output, &trace)?;

    Ok(ExitCode::from(EXIT_READY))
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

    Err(Failure::usage(format!(
        "no decision in this scope carries the identifier `{id}`"
    ))
    .named("not_found", "decision_not_found"))
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
            &target::tls(globals),
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
        &target::tls(globals),
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
    // `-w` says where a relative path is read from, and this is one.
    let named = crate::session::rooted(globals, path);
    let text = std::fs::read_to_string(&named)
        .map_err(|error| Failure::usage(format!("reading {}: {error}", named.display())))?;
    let parsed: Value = serde_json::from_str(&text)
        .map_err(|error| Failure::usage(format!("{path} is not a JWKS: {error}")))?;
    let keys = parsed.get("keys").cloned().unwrap_or(parsed);

    serde_json::from_value(keys)
        .map(Some)
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
        if let Some(wanted) = query.decision
            && permit != matches!(wanted, Decision::Permit)
        {
            continue;
        }

        decisions.push(DecisionLine {
            seq,
            at,
            decision: permit,
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
    if let Some(keys) = keys {
        for envelope in proof {
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
        for envelope in proof {
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
                Ok(verified) if attested(&verified, records, proof) => (true, None),
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
fn attested(verified: &permguard_decisions::Verified, records: &[Value], proof: &[Value]) -> bool {
    let digests: std::collections::BTreeMap<u64, String> = records
        .iter()
        .filter_map(|record| {
            let seq = record.get("seq").and_then(Value::as_u64)?;

            record::digest_of(record).ok().map(|digest| (seq, digest))
        })
        .collect();
    let envelopes: Vec<_> = proof
        .iter()
        .filter_map(|signed| {
            serde_json::from_value::<Signed>(signed.clone())
                .ok()
                .and_then(|signed| signed.envelope().ok())
        })
        .filter(|envelope| envelope.stream == verified.stream)
        .collect();

    // Every attested head inside the run must be a digest the run reaches.
    // One that is not means the records and the signatures describe two
    // different histories, and "verified" must not be the answer.
    for envelope in &envelopes {
        if (verified.first_seq..=verified.last_seq).contains(&envelope.last_seq)
            && digests.get(&envelope.last_seq) != Some(&envelope.head)
        {
            return false;
        }
    }

    // And the run's own head must be under some signature: attested exactly,
    // or carried by a batch that extends past the page.
    envelopes
        .iter()
        .any(|envelope| (envelope.first_seq..=envelope.last_seq).contains(&verified.last_seq))
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
        let Some(path) = inclusion
            .iter()
            .find(|entry| entry.get("seq").and_then(Value::as_u64) == Some(seq))
        else {
            missing += 1;
            continue;
        };
        let steps: Vec<merkle::Step> = path
            .get("path")
            .cloned()
            .and_then(|steps| serde_json::from_value(steps).ok())
            .unwrap_or_default();
        let Ok(leaf) = record::digest_of(record) else {
            missing += 1;
            continue;
        };
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
        .named("not_found", "offset_expired"),
        ReadError::Refused { code, detail } => Failure::usage(detail).named("validation", code),
        ReadError::Unavailable(detail) => {
            Failure::internal(detail).named("unavailable", "decision_log_unreachable")
        }
    }
}
