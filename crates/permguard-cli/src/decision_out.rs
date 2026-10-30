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

use serde::{Deserialize, Serialize};
use serde_json::Value;

use permguard_cli::decisions::INDETERMINATE;
pub use permguard_cli::decisions::{DecisionsReport, outcome_of};

use crate::output::Report;
use crate::style;

/// What `decisions export` writes (WP-6.3b, owner decision of 2026-10-20): a self-contained
/// archive `decisions verify --file` checks offline, records, envelopes and inclusion paths with
/// the scope they were read under, in the format `permguard.decisions.export.v1`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionArchive {
    pub format: String,
    pub scope_binding: DecisionArchiveScope,
    pub summary: DecisionArchiveSummary,
    pub records: Vec<Value>,
    pub envelopes: Vec<Value>,
    pub inclusion: Vec<Value>,
    /// The page as the terminal shows it; never written to the archive.
    #[serde(skip)]
    pub report: Option<DecisionsReport>,
}

/// The scope an archive's records were read under, which decides how they are proved: a producer
/// stream by its chain, a tenant view by its inclusion paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DecisionArchiveScope {
    Tenant { zone: String, ledger: String },
    Stream { pdp: String, instance: String },
}

/// Where an export stopped, and whether it reached the end of its snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionArchiveSummary {
    pub next: String,
    pub more: bool,
    pub truncated: bool,
}

impl Report for DecisionArchive {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        match &self.report {
            Some(report) => report.render_terminal(out),
            None => writeln!(
                out,
                "  {} records archived as {}",
                self.records.len(),
                self.format
            ),
        }
    }
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
            } else if line.outcome == INDETERMINATE {
                style::modify("!")
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
            for name in &line.absent_inputs {
                writeln!(
                    out,
                    "         {} {}",
                    style::dim("without input"),
                    style::id(name)
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
        let indeterminate = self
            .decisions
            .iter()
            .filter(|line| line.outcome == INDETERMINATE)
            .count();
        let permitted = self.decisions.iter().filter(|line| line.decision).count();
        let counts = format!(
            "{} decision(s), {permitted} permitted, {} denied, {indeterminate} indeterminate.",
            self.decisions.len(),
            self.decisions.len() - permitted - indeterminate,
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

/// Which key signed which stretch of one producer stream.
#[derive(Debug, Clone, Serialize)]
pub struct DecisionSignersReport {
    pub scope: String,
    /// The signers document as the server rendered it: `{"acked": …, "spans": […]}`.
    pub document: Value,
}

impl Report for DecisionSignersReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(out)?;
        writeln!(
            out,
            "  {} {}  {} {}",
            style::dim("stream"),
            style::id(&self.scope),
            style::dim("acked"),
            self.document
                .get("acked")
                .and_then(Value::as_u64)
                .unwrap_or(0)
        )?;

        let spans = self
            .document
            .get("spans")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if spans.is_empty() {
            writeln!(out)?;
            writeln!(out, "  {}", style::dim("nothing has been signed yet"))?;
            writeln!(out)?;

            return Ok(());
        }
        for span in &spans {
            writeln!(
                out,
                "    {} {:>12}  {}",
                style::dim("from"),
                span.get("from").and_then(Value::as_u64).unwrap_or(0),
                style::id(span.get("kid").and_then(Value::as_str).unwrap_or_default())
            )?;
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

impl Report for DecisionReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        let field = |name: &str| {
            self.record
                .get(name)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let outcome = outcome_of(&self.record);
        let verdict = match outcome.as_str() {
            "permit" => style::create("PERMIT"),
            INDETERMINATE => style::modify("INDETERMINATE"),
            _ => style::delete("DENY"),
        };

        writeln!(out)?;
        writeln!(out, "  {} {verdict}", style::dim("decision"))?;
        // What made it indeterminate, by code: never a policy, so never a deny.
        if let Some(causes) = self.record.get("causes").and_then(Value::as_array) {
            let causes: Vec<&str> = causes.iter().filter_map(Value::as_str).collect();
            writeln!(out, "  {} {}", style::dim("causes  "), causes.join(", "))?;
        }
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
            style::bold(match outcome.as_str() {
                "permit" => "Permitted.",
                INDETERMINATE => "Not evaluated: refused, and not by a policy.",
                _ => "Denied.",
            })
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

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use serde_json::json;

    /// The report as plain text, ANSI sequences stripped: the wording, never the paint.
    fn terminal<R: Report>(report: &R) -> String {
        let mut out = Vec::new();
        report
            .render_terminal(&mut out)
            .expect("the report renders");
        let rendered = String::from_utf8(out).expect("the rendering is UTF-8");

        let mut plain = String::with_capacity(rendered.len());
        let mut characters = rendered.chars();
        while let Some(character) = characters.next() {
            if character == '\u{1b}' {
                for inner in characters.by_ref() {
                    if inner.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                plain.push(character);
            }
        }
        plain
    }

    use permguard_cli::decisions::DecisionLine;

    fn line(seq: u64, decision: bool, outcome: &str) -> DecisionLine {
        DecisionLine {
            seq,
            at: "2026-10-03T10:00:00Z".to_owned(),
            decision,
            outcome: outcome.to_owned(),
            subject: "User::pseudo".to_owned(),
            action: "read".to_owned(),
            resource: "Document::budget".to_owned(),
            commit: "sha256:ec1773bf".to_owned(),
            policies: Vec::new(),
            absent_inputs: Vec::new(),
            id: format!("id-{seq}"),
            latency_us: 1,
        }
    }

    /// A record's outcome is its `outcome`, and a record written before the member existed reads
    /// as its `decision` says.
    #[test]
    fn the_outcome_is_the_member_or_the_decision_of_a_record_before_it() {
        assert_eq!(
            outcome_of(&json!({"decision": false, "outcome": "indeterminate"})),
            "indeterminate"
        );
        assert_eq!(outcome_of(&json!({"decision": true})), "permit");
        assert_eq!(outcome_of(&json!({"decision": false})), "deny");
    }

    /// `--decision deny` keeps what a policy refused or nothing permitted, never an evaluation
    /// that failed; `--decision indeterminate` keeps exactly that.
    #[test]
    fn the_filter_never_counts_an_indeterminate_decision_as_a_deny() {
        use crate::args::Decision;
        use permguard_cli::decisions::Outcome;

        // The flag's value, as the command hands it to the library.
        let admits = |decision: Decision, outcome: &str| Outcome::from(decision).admits(outcome);

        for (outcome, permit, deny, indeterminate) in [
            ("permit", true, false, false),
            ("deny", false, true, false),
            ("deny_by_default", false, true, false),
            ("indeterminate", false, false, true),
        ] {
            assert_eq!(admits(Decision::Permit, outcome), permit, "{outcome}");
            assert_eq!(admits(Decision::Deny, outcome), deny, "{outcome}");
            assert_eq!(
                admits(Decision::Indeterminate, outcome),
                indeterminate,
                "{outcome}"
            );
        }
    }

    /// An indeterminate record is shown and counted as what it is, not as a deny.
    #[test]
    fn an_indeterminate_decision_is_shown_and_counted_apart_from_a_deny() {
        let listed = terminal(&DecisionsReport {
            scope: "acme/main-ledger".to_owned(),
            decisions: vec![
                line(1, true, "permit"),
                line(2, false, "deny"),
                line(3, false, "indeterminate"),
            ],
            events: Vec::new(),
            next: "3".to_owned(),
            more: false,
            verified: None,
        });
        assert!(
            listed.contains("3 decision(s), 1 permitted, 1 denied, 1 indeterminate."),
            "{listed}"
        );
        assert!(
            listed.contains("  ! "),
            "the indeterminate line is marked apart: {listed}"
        );

        let shown = terminal(&DecisionReport {
            record: json!({
                "decision": false,
                "outcome": "indeterminate",
                "causes": ["evaluation_deadline_exceeded", "evaluation_failed"],
                "reason": {"code": "evaluation_indeterminate"},
            }),
        });
        assert!(shown.contains("INDETERMINATE"), "{shown}");
        assert!(!shown.contains("DENY"), "{shown}");
        assert!(
            shown.contains("evaluation_deadline_exceeded, evaluation_failed"),
            "the causes, by code: {shown}"
        );
    }
}
