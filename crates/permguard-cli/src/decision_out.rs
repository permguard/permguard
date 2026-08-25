// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What `permguard decisions` prints, in the CLI's one output contract.
//!
//! One struct per answer, `Serialize` plus a terminal rendering, so
//! `-o terminal`, `-o json` and `-o yaml` all come from the same data and none
//! of them can drift from the others.
//!
//! The terminal rendering speaks the product's change dialect: `+` for a
//! permit, `-` for a deny, identifiers in their own colour, chrome dim, and
//! one bold summary line stating the outcome. A person scanning a page of
//! decisions is looking for the denies, and they are the red ones.

use std::io::{self, Write};

use serde::Serialize;
use serde_json::Value;

use crate::output::Report;
use crate::style;

/// A page of decisions, and what checking them concluded.
#[derive(Debug, Clone, Serialize)]
pub struct DecisionsReport {
    /// What was read: `acme/main-ledger`, or a producer stream.
    pub scope: String,
    /// One line per decision.
    pub decisions: Vec<DecisionLine>,
    /// Records that are not decisions — the epochs and the endings.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<EventLine>,
    /// The offset to resume from, which belongs to the caller.
    pub next: String,
    /// Whether the store holds more right now.
    pub more: bool,
    /// What verification concluded, when it was asked for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<Verified>,
}

/// One decision, as a reader sees it.
#[derive(Debug, Clone, Serialize)]
pub struct DecisionLine {
    /// Where it sits in its producer's history.
    pub seq: u64,
    /// When it was answered.
    pub at: String,
    /// The answer.
    pub decision: bool,
    /// Who asked, as recorded — pseudonymised at the source.
    pub subject: String,
    /// What was asked for.
    pub action: String,
    /// What it was about.
    pub resource: String,
    /// The exact policy state that produced the answer.
    pub commit: String,
    /// Which policies decided.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<String>,
    /// The decision's own identifier.
    pub id: String,
    /// How long the plane took.
    pub latency_us: u64,
}

/// A record that is not a decision: an epoch, or an ending.
#[derive(Debug, Clone, Serialize)]
pub struct EventLine {
    /// Where it sits.
    pub seq: u64,
    /// `marker` or `discontinuity`.
    pub kind: String,
    /// What it says, in one line.
    pub detail: String,
}

/// What `--verify` established, and what it did not.
///
/// Which of the two proofs applies is decided by the scope, not by preference.
/// A **producer stream** is a contiguous history, so the chain is what proves
/// it. A **tenant view** is a subsequence — the records in between belong to
/// other tenants and must not be disclosed — so the chain cannot be checked
/// across it, and the inclusion path is what proves each record instead.
/// Reporting a chain result for a tenant page would be reporting a failure of
/// arithmetic as a failure of integrity.
#[derive(Debug, Clone, Serialize)]
pub struct Verified {
    /// Which proof applies here: `chain` or `inclusion`.
    pub proof: &'static str,
    /// Whether the records are a contiguous, unaltered chain. Stream scope only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain: Option<bool>,
    /// What broke it, when something did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_detail: Option<String>,
    /// How many records proved to be in a batch this producer signed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub included: Option<usize>,
    /// How many did not — each one is a record the store cannot account for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_included: Option<usize>,
    /// How many batch signatures verified against the given key set.
    pub signatures: usize,
    /// How many did not.
    pub signatures_failed: usize,
    /// Stated rather than implied: without a key set, signatures are not checked.
    pub signatures_checked: bool,
}

impl Report for DecisionsReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(out)?;
        writeln!(
            out,
            "  {} {}",
            style::dim("scope   "),
            style::id(&self.scope)
        )?;
        writeln!(out)?;

        for event in &self.events {
            writeln!(
                out,
                "  {} {:>6}  {}  {}",
                style::dim("~"),
                event.seq,
                style::dim(&event.kind),
                event.detail
            )?;
        }

        for line in &self.decisions {
            let symbol = if line.decision {
                style::create("+")
            } else {
                style::delete("-")
            };
            writeln!(
                out,
                "  {symbol} {:>6}  {}  {} {} {}",
                line.seq,
                style::dim(&line.at),
                style::id(&line.subject),
                line.action,
                style::id(&line.resource),
            )?;
            writeln!(
                out,
                "         {} {} {}",
                style::dim("at commit"),
                style::id(short(&line.commit)),
                style::dim(&format!("[{} µs]", line.latency_us))
            )?;
            for policy in &line.policies {
                writeln!(
                    out,
                    "         {} {}",
                    style::dim("policy"),
                    style::id(policy)
                )?;
            }
        }

        if let Some(verified) = &self.verified {
            writeln!(out)?;
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
            if let Some(included) = verified.included {
                let missing = verified.not_included.unwrap_or_default();
                let inclusion = if missing == 0 {
                    style::create(&format!("{included} record(s) proven in a signed batch"))
                } else {
                    style::delete(&format!("{missing} record(s) NOT accounted for"))
                };
                writeln!(out, "  {} {inclusion}", style::dim("inclusion  "))?;
            }
            let signatures = if verified.signatures_checked {
                format!(
                    "{} verified, {} failed",
                    verified.signatures, verified.signatures_failed
                )
            } else {
                // Said out loud, because "verified" that quietly skipped the
                // signatures is worse than no verification at all.
                "not checked — pass --keys with the producer's published key set".to_owned()
            };
            writeln!(out, "  {} {signatures}", style::dim("signatures "))?;
        }

        writeln!(out)?;
        let counts = format!(
            "{} decision(s), {} permitted, {} denied.",
            self.decisions.len(),
            self.decisions.iter().filter(|line| line.decision).count(),
            self.decisions.iter().filter(|line| !line.decision).count(),
        );
        writeln!(out, "{}", style::bold(&counts))?;
        if self.more {
            writeln!(
                out,
                "{}",
                style::dim(&format!("More held. Resume with --from {}", self.next))
            )?;
        }

        Ok(())
    }
}

/// One decision, in full.
#[derive(Debug, Clone, Serialize)]
pub struct DecisionReport {
    /// The record, verbatim: what the producer signed, not a rendering of it.
    pub record: Value,
}

impl Report for DecisionReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        let field = |name: &str| {
            self.record
                .get(name)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let permit = self
            .record
            .get("decision")
            .and_then(Value::as_bool)
            .unwrap_or_default();
        let verdict = if permit {
            style::create("PERMIT")
        } else {
            style::delete("DENY")
        };

        writeln!(out)?;
        writeln!(out, "  {} {verdict}", style::dim("decision"))?;
        writeln!(
            out,
            "  {} {}",
            style::dim("id      "),
            style::id(&field("id"))
        )?;
        writeln!(out, "  {} {}", style::dim("at      "), field("at"))?;

        let store = self.record.get("store").cloned().unwrap_or(Value::Null);
        let store_field = |name: &str| {
            store
                .get(name)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        writeln!(
            out,
            "  {} {}",
            style::dim("ledger  "),
            style::id(&format!(
                "{}/{}",
                store_field("zone"),
                store_field("ledger")
            ))
        )?;
        writeln!(
            out,
            "  {} {} {}",
            style::dim("commit  "),
            style::id(&store_field("commit")),
            style::dim(&format!(
                "[counter {}]",
                store.get("counter").and_then(Value::as_u64).unwrap_or(0)
            ))
        )?;

        for (label, member) in [("subject ", "subject"), ("resource", "resource")] {
            if let Some(party) = self.record.get(member) {
                let text = format!(
                    "{}:{}",
                    party
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                    party.get("id").and_then(Value::as_str).unwrap_or_default()
                );
                writeln!(out, "  {} {}", style::dim(label), style::id(&text))?;
            }
        }
        if let Some(action) = self
            .record
            .get("action")
            .and_then(|action| action.get("name"))
        {
            writeln!(
                out,
                "  {} {}",
                style::dim("action  "),
                action.as_str().unwrap_or_default()
            )?;
        }
        for policy in self
            .record
            .get("policies")
            .and_then(Value::as_array)
            .unwrap_or(&Vec::new())
        {
            writeln!(
                out,
                "    {} {}",
                style::dim("policy"),
                style::id(policy.as_str().unwrap_or_default())
            )?;
        }

        writeln!(out)?;
        writeln!(
            out,
            "{}",
            style::bold(if permit { "Permitted." } else { "Denied." })
        )?;

        Ok(())
    }
}

/// The first twelve characters of a digest — enough to recognise, short enough
/// to read in a column.
fn short(digest: &str) -> &str {
    let end = digest.len().min(19);

    &digest[..end]
}
