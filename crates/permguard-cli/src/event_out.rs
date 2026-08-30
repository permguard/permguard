// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What `permguard events` prints, in the CLI's one output contract.
//!
//! One struct per answer, `Serialize` plus a terminal rendering, so `-o terminal`, `-o json` and
//! `-o yaml` all come from the same data and none of them can drift from the others.
//!
//! The terminal rendering speaks the product's change dialect: a decision event's verdict is `+`
//! green or `-` red, a history-only event is `~` dim, identifiers are cyan, chrome is dim, and one
//! bold summary line states the outcome. A person scanning a page of events is looking for the
//! denies and the errors, and those are the coloured ones.

use std::io::{self, Write};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::output::Report;
use crate::style;

/// A page of events, and what checking them concluded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventsReport {
    /// What was read: `acme/agent-governance`, or a producer stream.
    pub scope: String,
    /// One line per event.
    pub events: Vec<EventLine>,
    /// The offset to resume from, which belongs to the caller.
    pub next: String,
    /// The oldest offset still held, to resume from deliberately after a gap.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub oldest_available: String,
    /// The exclusive end this read observed. Echo it to bound an export.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub high_watermark: String,
    /// Whether the store holds more right now.
    pub more: bool,
    /// Whether this command stopped at its own page bound rather than at the end of the snapshot.
    ///
    /// Distinct from `more`, and the distinction is the point: `more` says the store has grown
    /// since, which is ordinary for a tail, while this says *these results are a prefix* of the
    /// snapshot that was asked for. A reader that treated the two as one would take an export that
    /// gave up as an export that finished.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
    /// What this page proves about what it covers.
    pub coverage: Coverage,
    /// What verification concluded, when it was asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<Verified>,
}

/// What a page proves about what it covers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Coverage {
    /// Whether the records are a contiguous run whose chain links across them.
    pub contiguous: bool,
    /// How many positions the store examined to produce this page.
    pub examined: u64,
    /// Whether a scan bound stopped this page before its record or byte bound did.
    pub scan_bounded: bool,
}

/// One event, as a reader sees it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLine {
    /// Where it sits in its producer's history.
    pub seq: u64,
    /// The caller's identifier for the occurrence.
    pub event_id: String,
    /// The registered contract it is.
    pub event_type: String,
    /// The runtime's own word for what happened.
    pub kind: String,
    /// When it happened, as the caller stated it.
    pub occurred_at: String,
    /// When this plane accepted it.
    pub observed_at: String,
    /// The profile the submission selected.
    pub profile: String,
    /// The partitions it was addressed to.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub policy_partitions: Vec<String>,
    /// The immutable commit the partitions were loaded from.
    pub commit: String,
    /// The producer that recorded it.
    pub producer: String,
    /// Which incarnation of it.
    pub instance: String,
    /// The Dogwood history key's pins and values, when the schema derives one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<History>,
}

/// The history key a record carries, explicitly.
///
/// The values and not only the digest, which is the whole point of storing them in the signed
/// record: an investigator looking at an event has to be able to see *which* values put it in that
/// partition, not just that two records agree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct History {
    pub pins: Vec<String>,
    pub values: Vec<String>,
    pub digest: String,
}

/// What `--verify` established, and what it did not.
///
/// Which proof applies is decided by the scope, not by preference. A **producer stream** is a
/// contiguous history, so the chain is what proves it. A **tenant view** is a subsequence — the
/// records in between belong to other tenants and must not be disclosed — so the chain cannot be
/// checked across it, and the inclusion path is what proves each record instead. Reporting a chain
/// result for a tenant page would be reporting a failure of arithmetic as a failure of integrity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verified {
    /// Which proof applies here: `chain` or `inclusion`.
    pub proof: String,
    /// Whether the records are a contiguous, unaltered chain. Stream scope only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain: Option<bool>,
    /// What broke it, when something did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_detail: Option<String>,
    /// How many records proved to be in a batch this producer signed.
    pub included: usize,
    /// How many did not — each one is a record the store cannot account for.
    pub not_included: usize,
    /// How many batch signatures verified against the given key set.
    pub signatures: usize,
    /// How many did not.
    pub signatures_failed: usize,
    /// Stated rather than implied: without a key set, signatures are not checked.
    pub signatures_checked: bool,
}

impl Verified {
    /// Whether everything that was checked held.
    pub fn holds(&self) -> bool {
        self.chain.unwrap_or(true)
            && self.not_included == 0
            && (!self.signatures_checked || self.signatures_failed == 0)
    }
}

/// One occurrence, whole.
#[derive(Debug, Clone, Serialize)]
pub struct EventReport {
    pub record: Value,
}

/// Which key signed which stretch of each producer stream of one ledger.
#[derive(Debug, Clone, Serialize)]
pub struct SignersReport {
    pub scope: String,
    /// The signers document as the server rendered it: `{"streams": [...]}`.
    pub document: Value,
}

/// A finite, independently verifiable event export.
///
/// The summary is for people; the canonical records, signed envelopes and inclusion paths are the
/// evidence. Keeping them in one versioned document is what makes `events verify --file` an
/// offline operation rather than another read from the server being checked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventArchive {
    pub format: String,
    pub scope_binding: ArchiveScope,
    pub summary: EventsReport,
    pub records: Vec<Value>,
    pub envelopes: Vec<Value>,
    pub inclusion: Vec<Value>,
}

/// The authorization/integrity scope an exported offset and its records belong to.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArchiveScope {
    Tenant {
        zone: String,
        ledger: String,
    },
    Stream {
        zone: String,
        ledger: String,
        producer_class: String,
        producer: String,
        instance: String,
    },
}

impl Report for EventArchive {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        self.summary.render_terminal(out)
    }
}

impl Report for EventsReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(out)?;
        writeln!(
            out,
            "  {} {}",
            style::dim("scope   "),
            style::id(&self.scope)
        )?;
        writeln!(out)?;

        for line in &self.events {
            // A decision kind's verdict is not in the record — the decision log holds it — so what
            // is coloured here is what the event *is*: an error stands out, everything else is
            // ordinary history.
            let symbol = match line.kind.as_str() {
                "error" => style::delete("-"),
                "response" => style::create("+"),
                _ => style::dim("~"),
            };
            writeln!(
                out,
                "  {symbol} {:>6}  {}  {} {}",
                line.seq,
                style::dim(&line.occurred_at),
                style::id(&line.event_id),
                style::dim(&line.kind),
            )?;
            writeln!(
                out,
                "         {} {} {} {}",
                style::dim("at commit"),
                style::id(short(&line.commit)),
                style::dim("profile"),
                style::id(&line.profile),
            )?;
            if let Some(history) = &line.history {
                writeln!(
                    out,
                    "         {} {}",
                    style::dim("history  "),
                    style::id(&history.pins.join(", "))
                )?;
            }
        }

        writeln!(out)?;
        writeln!(
            out,
            "  {} {} examined, {} returned{}",
            style::dim("coverage   "),
            self.coverage.examined,
            self.events.len(),
            if self.coverage.scan_bounded {
                " (a scan bound stopped this page: read on)"
            } else {
                ""
            }
        )?;

        if let Some(verified) = &self.verified {
            if let Some(intact) = verified.chain {
                let chain = if intact {
                    style::create("intact")
                } else {
                    style::delete("BROKEN")
                };
                writeln!(out, "  {} {chain}", style::dim("chain      "))?;
                if let Some(detail) = &verified.chain_detail {
                    writeln!(out, "  {} {detail}", style::dim("           "))?;
                }
            }
            let inclusion = if verified.not_included == 0 {
                style::create(&format!(
                    "{} record(s) proven in a signed batch",
                    verified.included
                ))
            } else {
                style::delete(&format!(
                    "{} record(s) NOT accounted for",
                    verified.not_included
                ))
            };
            writeln!(out, "  {} {inclusion}", style::dim("inclusion  "))?;
            let signatures = if verified.signatures_checked {
                format!(
                    "{} verified, {} failed",
                    verified.signatures, verified.signatures_failed
                )
            } else {
                // Said outright rather than left to be inferred from a zero: "verified" that
                // quietly skipped the signatures is worse than no verification at all.
                "not checked (no key set given: pass --keys)".to_owned()
            };
            writeln!(out, "  {} {signatures}", style::dim("signatures "))?;
        }

        writeln!(out)?;
        // Truncation is said before anything else, and said as a refusal rather than as progress:
        // these results are a *prefix* of the snapshot that was asked for, and a reader who took
        // "More to read." for the ordinary tail message would take a third of an export as the
        // whole of one.
        let summary = if self.truncated {
            "Incomplete: this export stopped at its own page bound. Continue from `next`."
        } else {
            match (self.events.is_empty(), self.more) {
                (true, true) => "No events on this page. There is more — read on from `next`.",
                (true, false) => "No events.",
                (false, true) => "More to read.",
                (false, false) => "Caught up.",
            }
        };
        let summary = if self.truncated {
            style::delete(summary)
        } else {
            style::bold(summary)
        };
        writeln!(out, "  {summary}")?;
        if self.more {
            writeln!(out, "  {} {}", style::dim("next"), style::id(&self.next))?;
        }
        writeln!(out)?;

        Ok(())
    }
}

impl Report for SignersReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(out)?;
        writeln!(
            out,
            "  {} {}",
            style::dim("scope   "),
            style::id(&self.scope)
        )?;

        let streams = self
            .document
            .get("streams")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if streams.is_empty() {
            writeln!(out)?;
            writeln!(out, "  {}", style::dim("nothing has been signed yet"))?;
            writeln!(out)?;

            return Ok(());
        }

        for stream in &streams {
            let field = |name: &str| {
                stream
                    .get(name)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            writeln!(out)?;
            writeln!(
                out,
                "  {} {}  {} {}  {} {}",
                style::dim("producer"),
                style::id(&field("producer")),
                style::dim("instance"),
                style::id(&field("instance")),
                style::dim("acked"),
                stream.get("acked").and_then(Value::as_u64).unwrap_or(0)
            )?;
            for span in stream
                .get("spans")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                writeln!(
                    out,
                    "    {} {:>12}  {}",
                    style::dim("from"),
                    span.get("from").and_then(Value::as_u64).unwrap_or(0),
                    style::id(span.get("kid").and_then(Value::as_str).unwrap_or_default())
                )?;
            }
        }
        writeln!(out)?;
        writeln!(
            out,
            "  {}",
            style::dim("the public keys ride in the JSON output: -o json")
        )?;
        writeln!(out)?;

        Ok(())
    }
}

impl Report for EventReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        let text = serde_json::to_string_pretty(&self.record).unwrap_or_default();
        writeln!(out)?;
        for line in text.lines() {
            writeln!(out, "  {line}")?;
        }
        writeln!(out)?;

        Ok(())
    }
}

/// A digest, short enough to read and long enough to be unambiguous here.
fn short(digest: &str) -> &str {
    let held = digest.strip_prefix("sha256:").unwrap_or(digest);

    held.get(..12).unwrap_or(held)
}
