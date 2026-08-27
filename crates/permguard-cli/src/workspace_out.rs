// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The workspace commands' answers — one [`Report`] per command, so every
//! one of them renders on the terminal, as JSON and as YAML from the same
//! data, and none can quietly support one format and not another.
//!
//! The terminal dialect is Permguard's own change language: `+`/`~`/`-` symbols,
//! identifiers in their own color, and a bold summary line that states the
//! outcome — output that says what happened, not that something happened.

use std::io::{self, Write};

use serde::Serialize;

use permguard_control_client::catalog::{Ledger, Zone};

use crate::output::Report;
use crate::style;

/// One planned change, as every format carries it.
#[derive(Debug, Clone, Serialize)]
pub struct PlanLine {
    /// `create` | `update` | `delete`.
    pub op: &'static str,
    pub partition: String,
    pub name: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
}

fn render_plan_lines(lines: &[PlanLine], out: &mut dyn Write) -> io::Result<()> {
    for line in lines {
        let (symbol, painted) = match line.op {
            "create" => (
                style::create("+"),
                style::create(&format!("{}/{}", line.partition, line.name)),
            ),
            "update" => (
                style::modify("~"),
                style::modify(&format!("{}/{}", line.partition, line.name)),
            ),
            _ => (
                style::delete("-"),
                style::delete(&format!("{}/{}", line.partition, line.name)),
            ),
        };
        writeln!(out, "  {symbol} {painted}  {}", style::id(&line.id))?;
    }
    Ok(())
}

fn plan_summary(lines: &[PlanLine], unchanged: usize) -> String {
    let count = |op: &str| lines.iter().filter(|line| line.op == op).count();
    format!(
        "{} {} to create, {} to update, {} to delete {}",
        style::bold("Plan:"),
        style::create(&count("create").to_string()),
        style::modify(&count("update").to_string()),
        style::delete(&count("delete").to_string()),
        style::dim(&format!("({unchanged} unchanged).")),
    )
}

/// `plan`.
#[derive(Debug, Serialize)]
pub struct PlanReport {
    pub changes: Vec<PlanLine>,
    /// The tracked policies the plan leaves alone — context for the counts.
    pub unchanged: usize,
}

impl Report for PlanReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        if self.changes.is_empty() {
            return writeln!(
                out,
                "{} The remote ledger already matches this workspace.",
                style::bold("No changes.")
            );
        }
        writeln!(out, "The following changes would be applied:\n")?;
        render_plan_lines(&self.changes, out)?;
        writeln!(out, "\n{}", plan_summary(&self.changes, self.unchanged))
    }
}

/// `apply`.
#[derive(Debug, Serialize)]
pub struct ApplyReport {
    pub changes: Vec<PlanLine>,
    pub r#ref: String,
    pub counter: u64,
    pub head: String,
    pub uploaded: usize,
}

impl Report for ApplyReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        if self.changes.is_empty() && self.uploaded == 0 {
            writeln!(
                out,
                "{} The remote ledger already matches this workspace.",
                style::bold("No changes.")
            )?;
        } else {
            render_plan_lines(&self.changes, out)?;
            writeln!(out)?;
        }
        writeln!(
            out,
            "{} Ref `{}` advanced to counter {} — {} objects uploaded.",
            style::ok(&style::bold("Apply complete.")),
            self.r#ref,
            self.counter,
            self.uploaded
        )?;
        writeln!(out, "  head {}", style::id(&self.head))
    }
}

/// `pull`, `checkout`, `clone` — the converging commands.
#[derive(Debug, Serialize)]
pub struct PullReport {
    /// What the command was: `pull` | `checkout` | `clone`.
    pub action: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directory: Option<String>,
    pub counter: u64,
    pub head: String,
    pub fetched: usize,
    pub materialized: Vec<String>,
}

impl Report for PullReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        if let Some(reference) = &self.reference {
            writeln!(out, "{} {}", style::dim("From"), reference)?;
        }
        if self.counter == 0 {
            return writeln!(
                out,
                "{} The ledger is empty — the first `apply` will create its history.",
                style::bold("Bound.")
            );
        }
        for path in &self.materialized {
            writeln!(out, "  {} {}", style::create("+"), style::create(path))?;
        }
        let outcome = match self.action {
            "clone" => "Clone complete.",
            "checkout" => "Checkout complete.",
            _ => "Already up to date.",
        };
        let outcome = if self.fetched > 0 && self.action == "pull" {
            "Pull complete."
        } else {
            outcome
        };
        write!(out, "{} ", style::ok(&style::bold(outcome)))?;
        if let Some(directory) = &self.directory {
            write!(out, "Into `{directory}` — ")?;
        }
        writeln!(
            out,
            "counter {}, {} objects fetched, {} files written (signed head verified).",
            self.counter,
            self.fetched,
            self.materialized.len()
        )?;
        writeln!(out, "  head {}", style::id(&self.head))
    }
}

/// `refresh` / `validate`.
#[derive(Debug, Serialize)]
pub struct ValidateReport {
    pub policies: usize,
    pub objects: usize,
    pub root: String,
}

impl Report for ValidateReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(
            out,
            "{} {} policies across {} objects.",
            style::ok(&style::bold("Valid.")),
            self.policies,
            self.objects
        )?;
        writeln!(out, "  root {}", style::id(&self.root))
    }
}

/// `init`.
#[derive(Debug, Serialize)]
pub struct InitReport {
    pub name: String,
    pub languages: Vec<String>,
    pub adopted_manifest: bool,
}

impl Report for InitReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(
            out,
            "{} `{}` ({}){}",
            style::ok(&style::bold("Initialized.")),
            self.name,
            self.languages.join(", "),
            if self.adopted_manifest {
                " — existing manifest adopted"
            } else {
                ""
            }
        )
    }
}

/// `remote list`.
#[derive(Debug, Serialize)]
pub struct RemoteListReport {
    pub remotes: Vec<RemoteLine>,
}

#[derive(Debug, Serialize)]
pub struct RemoteLine {
    pub name: String,
    pub url: String,
}

impl Report for RemoteListReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        if self.remotes.is_empty() {
            return writeln!(
                out,
                "no remotes: add one with `permguard remote add <name> <url>`"
            );
        }
        let widest = self
            .remotes
            .iter()
            .map(|remote| remote.name.len())
            .max()
            .unwrap_or(0);
        for remote in &self.remotes {
            writeln!(out, "{:widest$}  {}", remote.name, style::id(&remote.url))?;
        }
        Ok(())
    }
}

/// `remote add` / `remote remove`.
#[derive(Debug, Serialize)]
pub struct RemoteChangedReport {
    pub action: &'static str,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl Report for RemoteChangedReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        match &self.url {
            Some(url) => writeln!(
                out,
                "{} `{}` -> {} (discovery verified)",
                style::ok(&style::bold("Remote added.")),
                self.name,
                style::id(url)
            ),
            None => writeln!(out, "{} `{}`", style::bold("Remote removed."), self.name),
        }
    }
}

/// `history`.
#[derive(Debug, Serialize)]
pub struct HistoryReport {
    pub commits: Vec<HistoryLine>,
}

#[derive(Debug, Serialize)]
pub struct HistoryLine {
    pub commit: String,
    pub author: String,
    pub author_at: i64,
    pub message: String,
}

impl Report for HistoryReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        if self.commits.is_empty() {
            return writeln!(out, "no history yet: nothing has been applied or pulled");
        }
        for (at, line) in self.commits.iter().enumerate() {
            if at > 0 {
                writeln!(out)?;
            }
            writeln!(out, "{}", style::modify(&format!("commit {}", line.commit)))?;
            writeln!(out, "{} {}", style::dim("Author:"), line.author)?;
            writeln!(out, "{} {}", style::dim("Date:  "), when(line.author_at))?;
            writeln!(out, "\n    {}", line.message)?;
        }
        Ok(())
    }
}

/// `objects list`.
#[derive(Debug, Serialize)]
pub struct ObjectsReport {
    pub objects: Vec<ObjectLine>,
}

/// One object of the local store: what it is, who reaches it, and what a
/// person calls it.
#[derive(Debug, Serialize)]
pub struct ObjectLine {
    pub digest: String,
    pub kind: &'static str,
    pub tracked: bool,
    pub staged: bool,
    /// The name the walk found — a blob's path (and alias), a tree's
    /// directory, a commit's subject. Absent for an orphan nothing names.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl Report for ObjectsReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        for line in &self.objects {
            let origin = match (line.tracked, line.staged) {
                (true, true) => "tracked+staged",
                (true, false) => "tracked",
                (false, true) => "staged",
                (false, false) => "orphan",
            };
            writeln!(
                out,
                "{} {:6} {:<14} {}",
                style::id(&line.digest),
                line.kind,
                style::dim(origin),
                line.label.as_deref().unwrap_or_default(),
            )?;
        }
        let count = |kind: &str| self.objects.iter().filter(|line| line.kind == kind).count();
        writeln!(
            out,
            "{}",
            style::bold(&format!(
                "{} objects — {} commit(s), {} tree(s), {} blob(s).",
                self.objects.len(),
                count("commit"),
                count("tree"),
                count("blob"),
            ))
        )
    }
}

/// `objects cat --inspect` — every field of one object, typed.
#[derive(Debug, Serialize)]
pub struct InspectObjectReport {
    pub digest: String,
    pub kind: &'static str,
    /// The stored (canonical CBOR) size in bytes.
    pub stored_size: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_size: Option<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub entries: Vec<InspectEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<InspectCommit>,
}

#[derive(Debug, Serialize)]
pub struct InspectEntry {
    pub name: String,
    pub kind: &'static str,
    pub digest: String,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub annotations: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
pub struct InspectCommit {
    pub tree: String,
    pub manifest: String,
    pub predecessors: Vec<String>,
    pub author: String,
    pub author_at: i64,
    pub message: String,
}

impl Report for InspectObjectReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(
            out,
            "{} {}",
            style::dim("digest:     "),
            style::id(&self.digest)
        )?;
        writeln!(out, "{} {}", style::dim("kind:       "), self.kind)?;
        writeln!(
            out,
            "{} {} bytes",
            style::dim("stored:     "),
            self.stored_size
        )?;
        if let Some(media_type) = &self.media_type {
            writeln!(out, "{} {media_type}", style::dim("media type: "))?;
        }
        if let Some(size) = self.content_size {
            writeln!(out, "{} {size} bytes", style::dim("content:    "))?;
        }
        if let Some(commit) = &self.commit {
            writeln!(
                out,
                "{} {}",
                style::dim("tree:       "),
                style::id(&commit.tree)
            )?;
            writeln!(
                out,
                "{} {}",
                style::dim("manifest:   "),
                style::id(&commit.manifest)
            )?;
            for predecessor in &commit.predecessors {
                writeln!(
                    out,
                    "{} {}",
                    style::dim("parent:     "),
                    style::id(predecessor)
                )?;
            }
            writeln!(out, "{} {}", style::dim("author:     "), commit.author)?;
            writeln!(
                out,
                "{} {}",
                style::dim("authored at:"),
                when(commit.author_at)
            )?;
            writeln!(out, "{} {}", style::dim("message:    "), commit.message)?;
        }
        for entry in &self.entries {
            writeln!(
                out,
                "  {:6} {} {}",
                entry.kind,
                style::id(&entry.digest),
                style::bold(&entry.name)
            )?;
            for (key, value) in &entry.annotations {
                writeln!(out, "         {} {key}={value}", style::dim("@"))?;
            }
        }
        Ok(())
    }
}

/// `verify`.
#[derive(Debug, Serialize)]
pub struct VerifyReport {
    pub r#ref: String,
    pub head: String,
    pub counter: u64,
    pub statement_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_closure_objects: Option<usize>,
}

impl Report for VerifyReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(
            out,
            "{} signed head statement for `{}` checks out against the key ring",
            style::ok("✓"),
            self.r#ref
        )?;
        writeln!(
            out,
            "{} counter {} — no rollback, no equivocation",
            style::ok("✓"),
            self.counter
        )?;
        match self.local_closure_objects {
            Some(objects) => writeln!(
                out,
                "{} local closure whole: {} objects hash-verified from {}",
                style::ok("✓"),
                objects,
                style::id(&self.head)
            ),
            None => writeln!(out, "{} no local checkpoint yet", style::dim("-")),
        }
    }
}

/// `status` — the workspace at a glance, `.permguard` read for you.
#[derive(Debug, Serialize)]
pub struct StatusReport {
    pub workspace: String,
    pub languages: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ledger: Option<String>,
    pub r#ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counter: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    pub pending_create: usize,
    pub pending_update: usize,
    pub pending_delete: usize,
    pub sources_valid: bool,
}

impl Report for StatusReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(
            out,
            "{} {} ({})",
            style::dim("Workspace:"),
            style::bold(&self.workspace),
            self.languages.join(", ")
        )?;
        match (&self.remote, &self.zone, &self.ledger) {
            (Some(remote), Some(zone), Some(ledger)) => {
                writeln!(
                    out,
                    "{} {remote}/{zone}/{ledger} {}",
                    style::dim("Tracking: "),
                    style::dim(&format!(
                        "({})",
                        self.remote_url.as_deref().unwrap_or("url unknown")
                    ))
                )?;
            }
            _ => writeln!(
                out,
                "{} nothing — run `permguard checkout <remote>/<zone>/<ledger>`",
                style::dim("Tracking: ")
            )?,
        }
        match (&self.counter, &self.head) {
            (Some(counter), Some(head)) => {
                writeln!(
                    out,
                    "{} `{}` at counter {counter}",
                    style::dim("Ref:      "),
                    self.r#ref
                )?;
                writeln!(out, "{} {}", style::dim("Head:     "), style::id(head))?;
            }
            _ => writeln!(
                out,
                "{} `{}` — no checkpoint yet (nothing pulled or applied)",
                style::dim("Ref:      "),
                self.r#ref
            )?,
        }
        writeln!(out)?;
        if !self.sources_valid {
            return writeln!(
                out,
                "{} the sources do not build — run `permguard validate` for the details",
                style::delete("✗")
            );
        }
        if self.pending_create + self.pending_update + self.pending_delete == 0 {
            writeln!(
                out,
                "{} Nothing to apply: the workspace matches the tracked head.",
                style::ok(&style::bold("Clean."))
            )
        } else {
            writeln!(
                out,
                "{} {} to create, {} to update, {} to delete — run `permguard plan` to see them.",
                style::bold("Pending:"),
                style::create(&self.pending_create.to_string()),
                style::modify(&self.pending_update.to_string()),
                style::delete(&self.pending_delete.to_string()),
            )
        }
    }
}

/// An epoch second, rendered for a person: RFC 3339 in UTC.
///
/// Terminal only — the machine formats keep the raw epoch, which is what a
/// script wants to sort and subtract. A person wants a date.
fn when(seconds: impl TryInto<i64>) -> String {
    permguard_core::time::to_rfc3339(seconds.try_into().unwrap_or_default())
}

// --- the catalog answers, as reports -----------------------------------------------------------
//
// The client crate answers with `Zone` and `Ledger`; how they read is this
// crate's business, like every other report.

/// A verb done to one zone: created, renamed, deleted, or just looked at.
#[derive(Debug, Serialize)]
pub struct ZoneReport {
    pub action: &'static str,
    #[serde(flatten)]
    pub zone: Zone,
}

impl Report for ZoneReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        // The change dialect, exactly as `plan` speaks it: the verb decides
        // the sigil, the identifier gets its own colour, the chrome stays dim.
        writeln!(
            out,
            "{} {} {}",
            sigil(self.action),
            style::bold(&format!("zone {}", self.zone.name)),
            style::dim(self.action),
        )?;
        writeln!(
            out,
            "  {} {}",
            style::dim("id:     "),
            style::id(&self.zone.id)
        )?;
        writeln!(
            out,
            "  {} {}",
            style::dim("created:"),
            when(self.zone.created_at)
        )?;
        writeln!(
            out,
            "  {} {}",
            style::dim("updated:"),
            when(self.zone.updated_at)
        )
    }
}

/// The sigil of a catalog verb: what `plan` prints for the same kind of change.
fn sigil(action: &str) -> String {
    match action {
        "created" => style::create("+"),
        "updated" | "renamed" => style::modify("~"),
        "deleted" => style::delete("-"),
        _ => " ".to_owned(),
    }
}

#[derive(Debug, Serialize)]
pub struct ZoneListReport {
    pub zones: Vec<Zone>,
    /// The page this listing is, when the caller asked for one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,
}

impl Report for ZoneListReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        if self.zones.is_empty() {
            return writeln!(
                out,
                "no zones yet: create one with `permguard zones create <name>`"
            );
        }

        writeln!(out, "{}", style::dim(&format!("{:<38} name", "id")))?;
        for zone in &self.zones {
            writeln!(out, "{:<38} {}", style::id(&zone.id), zone.name)?;
        }
        writeln!(out)?;
        let summary = match self.page {
            Some(page) => format!("{} zone(s) on page {page}.", self.zones.len()),
            None => format!("{} zone(s).", self.zones.len()),
        };
        writeln!(out, "{}", style::bold(&summary))
    }
}

#[derive(Debug, Serialize)]
pub struct LedgerReport {
    pub action: &'static str,
    #[serde(flatten)]
    pub ledger: Ledger,
}

impl Report for LedgerReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(
            out,
            "{} {} {}",
            sigil(self.action),
            style::bold(&format!("ledger {}", self.ledger.name)),
            style::dim(self.action),
        )?;
        writeln!(
            out,
            "  {} {}",
            style::dim("id:     "),
            style::id(&self.ledger.id)
        )?;
        writeln!(
            out,
            "  {} {}",
            style::dim("zone:   "),
            style::id(&self.ledger.zone_id)
        )?;
        writeln!(
            out,
            "  {} {}",
            style::dim("created:"),
            when(self.ledger.created_at)
        )?;
        writeln!(
            out,
            "  {} {}",
            style::dim("updated:"),
            when(self.ledger.updated_at)
        )
    }
}

#[derive(Debug, Serialize)]
pub struct LedgerListReport {
    pub zone: String,
    pub ledgers: Vec<Ledger>,
    /// The page this listing is, when the caller asked for one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,
}

impl Report for LedgerListReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        if self.ledgers.is_empty() {
            return writeln!(out, "the zone `{}` holds no ledgers yet", self.zone);
        }

        writeln!(out, "{}", style::dim(&format!("{:<38} name", "id")))?;
        for ledger in &self.ledgers {
            writeln!(out, "{:<38} {}", style::id(&ledger.id), ledger.name)?;
        }
        writeln!(out)?;
        let summary = match self.page {
            Some(page) => format!(
                "{} ledger(s) in `{}` on page {page}.",
                self.ledgers.len(),
                self.zone
            ),
            None => format!("{} ledger(s) in `{}`.", self.ledgers.len(), self.zone),
        };
        writeln!(out, "{}", style::bold(&summary))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    /// Renders a report to text — colors off would need a TTY anyway, and
    /// these run piped, so the bytes are exactly what a script would see.
    /// Renders a report to plain text: ANSI sequences are stripped, so the
    /// assertions hold whether or not stdout is a terminal with colors on —
    /// what is asserted is the wording, never the paint.
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
                // Skip to the end of the escape sequence.
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

    fn line(op: &'static str) -> PlanLine {
        PlanLine {
            op,
            partition: "app".into(),
            name: "rules.cedar".into(),
            id: "0193-id".into(),
            alias: Some("readers".into()),
        }
    }

    #[test]
    fn a_plan_marks_every_change_and_sums_them_up() {
        let text = terminal(&PlanReport {
            changes: vec![line("create"), line("update"), line("delete")],
            unchanged: 2,
        });

        assert!(text.contains("would be applied"), "{text}");
        assert!(
            text.contains("1 to create, 1 to update, 1 to delete"),
            "{text}"
        );

        let empty = terminal(&PlanReport {
            changes: vec![],
            unchanged: 0,
        });
        assert!(empty.contains("No changes."), "{empty}");
    }

    #[test]
    fn an_apply_states_the_outcome_and_the_head() {
        let text = terminal(&ApplyReport {
            changes: vec![line("create")],
            r#ref: "main".into(),
            counter: 7,
            head: "sha256:abcd".into(),
            uploaded: 4,
        });

        assert!(text.contains("Apply complete."), "{text}");
        assert!(text.contains("counter 7"), "{text}");
        assert!(text.contains("sha256:abcd"), "{text}");

        let noop = terminal(&ApplyReport {
            changes: vec![],
            r#ref: "main".into(),
            counter: 7,
            head: "sha256:abcd".into(),
            uploaded: 0,
        });
        assert!(noop.contains("No changes."), "{noop}");
    }

    #[test]
    fn the_converging_commands_name_their_own_outcome() {
        let base = PullReport {
            action: "pull",
            reference: Some("origin/acme/main".into()),
            directory: None,
            counter: 3,
            head: "sha256:ff".into(),
            fetched: 2,
            materialized: vec!["app/x.cedar".into()],
        };
        assert!(terminal(&base).contains("Pull complete."));

        let clone = PullReport {
            action: "clone",
            directory: Some("lab".into()),
            ..base
        };
        let text = terminal(&clone);
        assert!(text.contains("Clone complete."), "{text}");
        assert!(text.contains("Into `lab`"), "{text}");

        let empty = PullReport {
            action: "checkout",
            reference: None,
            directory: None,
            counter: 0,
            head: String::new(),
            fetched: 0,
            materialized: vec![],
        };
        assert!(terminal(&empty).contains("Bound."), "an empty ledger binds");
    }

    #[test]
    fn validate_init_and_remotes_render() {
        let text = terminal(&ValidateReport {
            policies: 3,
            objects: 9,
            root: "sha256:aa".into(),
        });
        assert!(text.contains("3"), "{text}");

        let text = terminal(&InitReport {
            name: "lab".into(),
            languages: vec!["cedar".into(), "rego".into()],
            adopted_manifest: true,
        });
        assert!(text.contains("lab"), "{text}");

        let text = terminal(&RemoteListReport {
            remotes: vec![RemoteLine {
                name: "origin".into(),
                url: "https://permguard.acme.com".into(),
            }],
        });
        assert!(text.contains("origin"), "{text}");
        assert!(terminal(&RemoteListReport { remotes: vec![] }).contains("no remotes"));

        let added = terminal(&RemoteChangedReport {
            action: "added",
            name: "origin".into(),
            url: Some("https://x".into()),
        });
        assert!(added.contains("discovery verified"), "{added}");
        let removed = terminal(&RemoteChangedReport {
            action: "removed",
            name: "origin".into(),
            url: None,
        });
        assert!(removed.contains("Remote removed."), "{removed}");
    }

    #[test]
    fn history_reads_like_a_log() {
        let text = terminal(&HistoryReport {
            commits: vec![HistoryLine {
                commit: "sha256:aa".into(),
                author: "nicola".into(),
                author_at: 1,
                message: "first".into(),
            }],
        });
        assert!(text.contains("commit sha256:aa"), "{text}");
        assert!(text.contains("first"), "{text}");
        assert!(terminal(&HistoryReport { commits: vec![] }).contains("no history yet"));
    }

    #[test]
    fn objects_and_inspection_render_every_shape() {
        let text = terminal(&ObjectsReport {
            objects: vec![
                ObjectLine {
                    digest: "sha256:aa".into(),
                    kind: "blob",
                    tracked: true,
                    staged: true,
                    label: None,
                },
                ObjectLine {
                    digest: "sha256:bb".into(),
                    kind: "tree",
                    tracked: false,
                    staged: false,
                    label: None,
                },
            ],
        });
        assert!(text.contains("tracked+staged"), "{text}");
        assert!(text.contains("orphan"), "{text}");
        assert!(text.contains("2 objects"), "{text}");

        let blob = terminal(&InspectObjectReport {
            digest: "sha256:aa".into(),
            kind: "blob",
            stored_size: 10,
            media_type: Some("application/vnd.permguard.policy.cedar".into()),
            content_size: Some(42),
            entries: vec![],
            commit: None,
        });
        assert!(blob.contains("cedar"), "{blob}");

        let commit = terminal(&InspectObjectReport {
            digest: "sha256:cc".into(),
            kind: "commit",
            stored_size: 10,
            media_type: None,
            content_size: None,
            entries: vec![],
            commit: Some(InspectCommit {
                tree: "sha256:t".into(),
                manifest: "sha256:m".into(),
                predecessors: vec!["sha256:p".into()],
                author: "nicola".into(),
                author_at: 5,
                message: "msg".into(),
            }),
        });
        assert!(commit.contains("sha256:p"), "{commit}");

        let tree = terminal(&InspectObjectReport {
            digest: "sha256:dd".into(),
            kind: "tree",
            stored_size: 10,
            media_type: None,
            content_size: None,
            entries: vec![InspectEntry {
                name: "rules.cedar".into(),
                kind: "blob",
                digest: "sha256:aa".into(),
                annotations: [("permguard.policy.id".to_owned(), "0193".to_owned())]
                    .into_iter()
                    .collect(),
            }],
            commit: None,
        });
        assert!(tree.contains("rules.cedar"), "{tree}");
        assert!(tree.contains("permguard.policy.id"), "{tree}");
    }

    #[test]
    fn verify_and_status_state_their_conclusions() {
        let text = terminal(&VerifyReport {
            r#ref: "main".into(),
            head: "sha256:aa".into(),
            counter: 4,
            statement_verified: true,
            local_closure_objects: Some(13),
        });
        assert!(text.contains("no rollback"), "{text}");
        assert!(text.contains("13 objects"), "{text}");

        let fresh = terminal(&VerifyReport {
            r#ref: "main".into(),
            head: "sha256:aa".into(),
            counter: 4,
            statement_verified: true,
            local_closure_objects: None,
        });
        assert!(fresh.contains("no local checkpoint"), "{fresh}");

        let clean = terminal(&StatusReport {
            workspace: "lab".into(),
            languages: vec!["cedar".into()],
            remote: Some("origin".into()),
            remote_url: Some("https://x".into()),
            zone: Some("acme".into()),
            ledger: Some("main-ledger".into()),
            r#ref: "main".into(),
            counter: Some(2),
            head: Some("sha256:aa".into()),
            pending_create: 0,
            pending_update: 0,
            pending_delete: 0,
            sources_valid: true,
        });
        assert!(clean.contains("Clean."), "{clean}");
        assert!(clean.contains("origin/acme/main-ledger"), "{clean}");

        let pending = terminal(&StatusReport {
            workspace: "lab".into(),
            languages: vec![],
            remote: None,
            remote_url: None,
            zone: None,
            ledger: None,
            r#ref: "main".into(),
            counter: None,
            head: None,
            pending_create: 2,
            pending_update: 1,
            pending_delete: 0,
            sources_valid: true,
        });
        assert!(pending.contains("Tracking:  nothing"), "{pending}");
        assert!(pending.contains("2 to create"), "{pending}");

        let broken = terminal(&StatusReport {
            sources_valid: false,
            ..StatusReport {
                workspace: "lab".into(),
                languages: vec![],
                remote: None,
                remote_url: None,
                zone: None,
                ledger: None,
                r#ref: "main".into(),
                counter: None,
                head: None,
                pending_create: 0,
                pending_update: 0,
                pending_delete: 0,
                sources_valid: false,
            }
        });
        assert!(broken.contains("do not build"), "{broken}");
    }
}

/// The answer to `permguard check`, in every format.
///
/// The server's decision, verbatim — the terminal rendering says what happened
/// and cites the policies that decided it, `-o json` prints what the PDP sent.
/// A deny is a decision, not a failure, and it reads like one.
#[derive(Debug, Clone, Serialize)]
pub struct CheckReport {
    /// The store the question was about, and where that came from.
    pub zone: String,
    pub ledger: String,
    pub store_from: &'static str,
    /// What was asked.
    pub subject: String,
    pub action: String,
    pub resource: String,
    /// The verdict.
    pub decision: bool,
    /// The decision's own identifier, for the audit trail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// The policies that decided it, by identity.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<String>,
    /// The operator-facing reason, when the server sent one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// One line per boxcarred evaluation, in the order they were asked.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evaluations: Vec<CheckLine>,
}

/// One boxcarred decision.
#[derive(Debug, Clone, Serialize)]
pub struct CheckLine {
    pub decision: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl CheckReport {
    /// Reads the answer beside the request that produced it.
    pub fn of(
        payload: &serde_json::Value,
        answer: &serde_json::Value,
        store_from: &'static str,
    ) -> Self {
        let text = |value: &serde_json::Value, field: &str| {
            value
                .get(field)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let entity = |field: &str| match payload.get(field) {
            Some(entity) => format!("{}:{}", text(entity, "type"), text(entity, "id")),
            None => String::new(),
        };
        let context = answer.get("context");

        Self {
            zone: text(payload, "zone"),
            ledger: text(payload, "ledger"),
            store_from,
            subject: entity("subject"),
            action: payload
                .get("action")
                .map(|action| text(action, "name"))
                .unwrap_or_default(),
            resource: entity("resource"),
            decision: answer
                .get("decision")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            id: context
                .and_then(|context| context.get("id"))
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned),
            policies: policies(context),
            reason: reason(context),
            evaluations: answer
                .get("evaluations")
                .and_then(serde_json::Value::as_array)
                .map(|entries| {
                    entries
                        .iter()
                        .map(|entry| CheckLine {
                            decision: entry
                                .get("decision")
                                .and_then(serde_json::Value::as_bool)
                                .unwrap_or(false),
                            request_id: entry
                                .get("request_id")
                                .and_then(serde_json::Value::as_str)
                                .map(ToOwned::to_owned),
                            policies: policies(entry.get("context")),
                            reason: reason(entry.get("context")),
                        })
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}

fn policies(context: Option<&serde_json::Value>) -> Vec<String> {
    context
        .and_then(|context| context.get("policies"))
        .and_then(serde_json::Value::as_array)
        .map(|policies| {
            policies
                .iter()
                .filter_map(|policy| policy.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The operator's half of the reason: the full one, which is what somebody
/// running a CLI is.
fn reason(context: Option<&serde_json::Value>) -> Option<String> {
    let reason = context?.get("reason_admin")?;
    let message = reason.get("message")?.as_str()?;

    Some(message.to_owned())
}

impl Report for CheckReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        let verdict = if self.decision {
            style::create("PERMIT")
        } else {
            style::delete("DENY")
        };
        writeln!(out)?;
        writeln!(out, "  {} {verdict}", style::dim("decision"))?;
        writeln!(
            out,
            "  {} {} {}",
            style::dim("ledger  "),
            style::id(&format!("{}/{}", self.zone, self.ledger)),
            style::dim(&format!("[{}]", self.store_from))
        )?;
        writeln!(
            out,
            "  {} {} {} {}",
            style::dim("request "),
            style::id(&self.subject),
            self.action,
            style::id(&self.resource)
        )?;
        if let Some(reason) = &self.reason {
            let symbol = if self.decision {
                style::create("+")
            } else {
                style::delete("-")
            };
            writeln!(out, "  {symbol} {reason}")?;
        }
        for policy in &self.policies {
            writeln!(out, "    {} {}", style::dim("policy"), style::id(policy))?;
        }
        for (index, line) in self.evaluations.iter().enumerate() {
            let symbol = if line.decision {
                style::create("+")
            } else {
                style::delete("-")
            };
            let named = line
                .request_id
                .clone()
                .unwrap_or_else(|| format!("#{index}"));
            writeln!(
                out,
                "  {symbol} {} {}",
                style::id(&named),
                line.reason.clone().unwrap_or_default()
            )?;
        }
        if let Some(id) = &self.id {
            writeln!(out, "  {} {}", style::dim("decision id"), style::id(id))?;
        }
        writeln!(out)?;

        let summary = if self.evaluations.is_empty() {
            if self.decision {
                "Permitted.".to_owned()
            } else {
                "Denied.".to_owned()
            }
        } else {
            let permitted = self.evaluations.iter().filter(|line| line.decision).count();
            format!(
                "{} of {} evaluations permitted.",
                permitted,
                self.evaluations.len()
            )
        };
        writeln!(out, "{}", style::bold(&summary))?;

        Ok(())
    }
}

/// One object a prune took, or would take.
#[derive(Debug, Clone, Serialize)]
pub struct PruneLine {
    pub digest: String,
    pub kind: &'static str,
    pub bytes: u64,
}

/// The answer to `permguard objects prune`, in every format.
///
/// The change dialect, in its subtractive form: a `-` per object, the bytes it
/// held, and a bold line stating what happened. A dry run says *would* and
/// means it — nothing on disk moved.
#[derive(Debug, Clone, Serialize)]
pub struct PruneReport {
    /// Whether anything was actually removed.
    pub applied: bool,
    /// What went, or would go.
    pub reclaimed: Vec<PruneLine>,
    /// Bytes freed, or that would be freed.
    pub bytes: u64,
    /// Objects kept because something reaches them.
    pub kept: usize,
}

impl Report for PruneReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(out)?;
        for line in &self.reclaimed {
            writeln!(
                out,
                "  {} {} {}",
                style::delete("-"),
                style::id(&line.digest),
                style::dim(&format!("({}, {})", line.kind, bytes_of(line.bytes)))
            )?;
        }
        if !self.reclaimed.is_empty() {
            writeln!(out)?;
        }

        let summary = match (self.reclaimed.len(), self.applied) {
            (0, _) => "Nothing to prune. Every object is reached by the tracked head or the staged snapshot.".to_owned(),
            (count, true) => format!(
                "Pruned {count} object(s), {} reclaimed. {} kept.",
                bytes_of(self.bytes),
                self.kept
            ),
            (count, false) => format!(
                "Would prune {count} object(s), {} reclaimed. Nothing was removed — run without --dry-run.",
                bytes_of(self.bytes)
            ),
        };
        writeln!(out, "{}", style::bold(&summary))?;

        Ok(())
    }
}

/// Bytes as a person reads them.
fn bytes_of(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "kB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// `test --list`: the cases and what each one claims, decided against nothing.
#[derive(Debug, Serialize)]
pub struct TestListReport {
    pub cases: Vec<TestListLine>,
}

#[derive(Debug, Serialize)]
pub struct TestListLine {
    pub name: String,
    pub source: String,
    pub request: String,
    pub expects: String,
}

impl Report for TestListReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        for case in &self.cases {
            writeln!(out, "  {}", case.name)?;
            writeln!(
                out,
                "    {} {}",
                style::dim("expects"),
                style::dim(&case.expects)
            )?;
            writeln!(
                out,
                "    {} {}",
                style::dim("request"),
                style::id(&case.request)
            )?;
        }
        writeln!(out)?;
        writeln!(
            out,
            "{}",
            style::bold(&format!("{} case(s), decided none.", self.cases.len()))
        )
    }
}

/// `test`.
///
/// A case that failed says what it expected and what it got on its own lines, because
/// the two together are the whole message and a reader should not have to reconstruct
/// it from a diff.
#[derive(Debug, Serialize)]
pub struct TestReport {
    pub cases: Vec<TestCaseLine>,
    pub passed: usize,
    pub failed: usize,
    /// What was actually asked: these sources, or a named plane. A report that does not say
    /// cannot be read six months later, and `--remote` makes the two look alike.
    pub asked: String,
}

#[derive(Debug, Serialize)]
pub struct TestCaseLine {
    pub name: String,
    pub source: String,
    pub profile: String,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub problems: Vec<String>,
}

impl Report for TestReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        // Padded to the longest name so the outcomes line up: the column is what
        // makes a run of thirty cases scannable instead of readable.
        let width = self
            .cases
            .iter()
            .map(|case| case.name.chars().count())
            .max()
            .unwrap_or_default();

        for case in &self.cases {
            let mark = if case.passed {
                style::ok("ok  ")
            } else {
                style::delete("fail")
            };
            let decided = match (case.decision, case.policies.as_slice()) {
                (Some(true), []) => "permit".to_owned(),
                (Some(true), cited) => format!("permit by {}", cited.join(", ")),
                (Some(false), []) => "deny, nothing permitted it".to_owned(),
                (Some(false), cited) => format!("deny by {}", cited.join(", ")),
                (None, _) => "not evaluated".to_owned(),
            };
            let padding = " ".repeat(width.saturating_sub(case.name.chars().count()));
            writeln!(
                out,
                "  {mark}  {}{padding}  {}",
                case.name,
                style::dim(&format!("[{}] {decided}", case.profile))
            )?;
            for problem in &case.problems {
                writeln!(out, "        {}", style::delete(problem))?;
            }
            if !case.passed {
                writeln!(out, "        {}", style::dim(&case.source))?;
            }
        }
        writeln!(out)?;
        writeln!(out, "  {} {}", style::dim("asked"), style::dim(&self.asked))?;
        writeln!(out)?;

        let summary = format!(
            "{} case(s), {} passed, {} failed.",
            self.cases.len(),
            self.passed,
            self.failed
        );

        if self.failed == 0 {
            writeln!(out, "{}", style::ok(&style::bold(&summary)))
        } else {
            writeln!(out, "{}", style::delete(&style::bold(&summary)))
        }
    }
}
