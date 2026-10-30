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

pub use permguard_cli::events::{EventReport, EventsReport};

use crate::output::Report;
use crate::style;

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
        // Truncation is part of the answer: a reader shown a silent prefix would take it for the
        // whole, and the cursor is how they get the rest.
        if self
            .document
            .get("truncated")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            let next = self.document.get("next");
            let cursor = next
                .map(|held| {
                    let field = |name: &str| {
                        held.get(name)
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned()
                    };
                    format!(
                        "{}/{}/{}",
                        field("producer_class"),
                        field("producer"),
                        field("instance")
                    )
                })
                .unwrap_or_default();
            writeln!(
                out,
                "  {} more streams follow: resume with --after {}",
                style::dim("truncated"),
                style::id(&cursor)
            )?;
            writeln!(out)?;
        }
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
