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
                "{} The workspace matches the tracked head.",
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
        // An apply with nothing to send advanced nothing, and must not say it did: "No changes"
        // followed by "advanced" is two sentences contradicting each other about one command.
        if self.changes.is_empty() && self.uploaded == 0 {
            writeln!(
                out,
                "{} The workspace matches the tracked head; ref `{}` stays at counter {}.",
                style::bold("No changes."),
                self.r#ref,
                self.counter
            )?;

            return writeln!(out, "  head {}", style::id(&self.head));
        }
        render_plan_lines(&self.changes, out)?;
        writeln!(out)?;
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
    /// Files advanced to the incoming head's content.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub updated: Vec<String>,
    /// Files the incoming head dropped.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub removed: Vec<String>,
    /// The counter held before the pull, when one was held. Not serialized: it
    /// is here to tell "nothing to do" from "the ref moved", and `counter`
    /// already carries where the workspace landed.
    #[serde(skip)]
    pub previous_counter: Option<u64>,
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
        for path in &self.updated {
            writeln!(out, "  {} {}", style::modify("~"), style::modify(path))?;
        }
        for path in &self.removed {
            writeln!(out, "  {} {}", style::delete("-"), style::delete(path))?;
        }
        // "Already up to date" has to mean the pull found nothing to do, not
        // that it fetched nothing: a refused pull leaves its objects in the
        // store, so `pull --resolved` fetches none and still moves the ref.
        let moved = self.fetched > 0
            || !self.materialized.is_empty()
            || !self.updated.is_empty()
            || !self.removed.is_empty()
            || self
                .previous_counter
                .is_some_and(|held| held != self.counter);
        let outcome = match self.action {
            "clone" => "Clone complete.",
            "checkout" => "Checkout complete.",
            _ if moved => "Pull complete.",
            _ => "Already up to date.",
        };
        write!(out, "{} ", style::ok(&style::bold(outcome)))?;
        if let Some(directory) = &self.directory {
            write!(out, "Into `{directory}` — ")?;
        }
        // Written, advanced and removed are counted apart: "files written"
        // alone read like a no-op success on the pull that advanced content.
        writeln!(
            out,
            "counter {}, {} objects fetched, {} files written, {} advanced, {} removed (signed \
             head verified).",
            self.counter,
            self.fetched,
            self.materialized.len(),
            self.updated.len(),
            self.removed.len()
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
    /// When it was authored, as RFC 3339 in UTC — the form every timestamp this CLI emits takes.
    pub author_at: String,
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
            writeln!(out, "{} {}", style::dim("Date:  "), line.author_at)?;
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
    /// When it was authored, as RFC 3339 in UTC — the form every timestamp this CLI emits takes.
    pub author_at: String,
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
            writeln!(out, "{} {}", style::dim("authored at:"), commit.author_at)?;
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
    /// The URL the next `pull` or `apply` would go to: the tracked remote's when the workspace
    /// names one, the CLI's configured endpoint otherwise — the same fallback `apply` takes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_url: Option<String>,
    /// Whether `remote_url` is a remote this workspace configured. `false` with a URL present is
    /// the fallback: the tracked remote was never added, or was removed.
    pub remote_configured: bool,
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
                // The path `apply` would take, said the way `apply` takes it. "url unknown" for
                // a remote that had been removed, while `apply` went ahead through the CLI's
                // fallback, was two commands describing one workspace differently.
                let where_to = match (self.remote_url.as_deref(), self.remote_configured) {
                    (Some(url), true) => format!("({url})"),
                    (Some(url), false) => format!(
                        "({url} — remote `{remote}` is not configured; the CLI's endpoint stands in)"
                    ),
                    (None, _) => "(url unknown)".to_owned(),
                };
                writeln!(
                    out,
                    "{} {remote}/{zone}/{ledger} {}",
                    style::dim("Tracking: "),
                    style::dim(&where_to)
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

/// An epoch second, rendered as RFC 3339 in UTC — the one form every timestamp this CLI emits
/// takes, in every format.
///
/// The machine formats used to keep the raw epoch here while `inspect` and the decision log
/// carried RFC 3339, so a script reading two commands parsed two shapes, and `--since` could not
/// take back what `history` printed. One form, everywhere.
fn when(seconds: impl TryInto<i64>) -> String {
    permguard_core::time::to_rfc3339(seconds.try_into().unwrap_or_default())
}

// --- the catalog answers, as reports -----------------------------------------------------------
//
// The client crate answers with `Zone` and `Ledger`; how they read is this
// crate's business, like every other report.

/// One zone, as this CLI reports it: the server's answer, its timestamps in the form every report
/// uses.
#[derive(Debug, Clone, Serialize)]
pub struct ZoneView {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
}

impl From<Zone> for ZoneView {
    fn from(zone: Zone) -> Self {
        Self {
            id: zone.id,
            name: zone.name,
            created_at: when(zone.created_at),
            updated_at: when(zone.updated_at),
        }
    }
}

/// One ledger, as this CLI reports it.
#[derive(Debug, Clone, Serialize)]
pub struct LedgerView {
    pub id: String,
    pub zone_id: String,
    pub name: String,
    /// The ledger's default ref.
    pub default_ref: String,
    pub created_at: String,
    pub updated_at: String,
}

impl From<Ledger> for LedgerView {
    fn from(ledger: Ledger) -> Self {
        Self {
            id: ledger.id,
            zone_id: ledger.zone_id,
            name: ledger.name,
            default_ref: ledger.default_ref,
            created_at: when(ledger.created_at),
            updated_at: when(ledger.updated_at),
        }
    }
}

/// A verb done to one zone: created, renamed, deleted, or just looked at.
#[derive(Debug, Serialize)]
pub struct ZoneReport {
    pub action: &'static str,
    #[serde(flatten)]
    pub zone: ZoneView,
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
        writeln!(out, "  {} {}", style::dim("created:"), self.zone.created_at)?;
        writeln!(out, "  {} {}", style::dim("updated:"), self.zone.updated_at)
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
    pub zones: Vec<ZoneView>,
    /// The page this listing is, when the caller asked for one — `null` otherwise, and present
    /// either way: a consumer reads one shape whether or not `--page` was given.
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
    pub ledger: LedgerView,
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
            self.ledger.created_at
        )?;
        writeln!(
            out,
            "  {} {}",
            style::dim("updated:"),
            self.ledger.updated_at
        )
    }
}

#[derive(Debug, Serialize)]
pub struct LedgerListReport {
    pub zone: String,
    pub ledgers: Vec<LedgerView>,
    /// The page this listing is, when the caller asked for one — `null` otherwise, and present
    /// either way.
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
        assert!(
            !noop.contains("advanced"),
            "an apply that sent nothing did not advance the ref: {noop}"
        );
        assert!(noop.contains("counter 7"), "{noop}");
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
            updated: vec![],
            removed: vec![],
            previous_counter: Some(2),
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
            updated: vec![],
            removed: vec![],
            previous_counter: None,
        };
        assert!(terminal(&empty).contains("Bound."), "an empty ledger binds");
    }

    #[test]
    fn a_pull_that_only_moves_the_ref_still_says_it_pulled() {
        // What `pull --resolved` looks like after a refused pull: the objects
        // are already in the store, the tree was reconciled by hand, so
        // nothing is fetched and nothing is written — and the ref still moves.
        let resolved = PullReport {
            action: "pull",
            reference: None,
            directory: None,
            counter: 8,
            head: "sha256:ff".into(),
            fetched: 0,
            materialized: vec![],
            updated: vec![],
            removed: vec![],
            previous_counter: Some(7),
        };
        let text = terminal(&resolved);
        assert!(
            text.contains("Pull complete."),
            "a pull that advanced the ref cannot claim there was nothing to do: {text}"
        );

        let standing = PullReport {
            counter: 7,
            ..resolved
        };
        assert!(
            terminal(&standing).contains("Already up to date."),
            "a pull that changed nothing says so"
        );
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
                author_at: "1970-01-01T00:00:01Z".into(),
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
                author_at: "1970-01-01T00:00:05Z".into(),
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
            remote_configured: true,
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
        assert!(!clean.contains("stands in"), "{clean}");

        // The remote was removed: the URL the fallback takes is shown, and named as the fallback.
        let fallback = terminal(&StatusReport {
            workspace: "lab".into(),
            languages: vec!["cedar".into()],
            remote: Some("origin".into()),
            remote_url: Some("http://127.0.0.1:6443".into()),
            remote_configured: false,
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
        assert!(fallback.contains("http://127.0.0.1:6443"), "{fallback}");
        assert!(
            fallback.contains("is not configured"),
            "a fallback URL says it is one: {fallback}"
        );

        let pending = terminal(&StatusReport {
            workspace: "lab".into(),
            languages: vec![],
            remote: None,
            remote_url: None,
            remote_configured: false,
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
                remote_configured: false,
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
///
/// Every field is present in every answer. A consumer reads one shape whether the decision was a
/// permit, a deny, a batch or a request the policies never saw: `policies` is `[]` rather than
/// absent, `id` and `reason` are `null` rather than missing.
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
    /// Whether the policies saw the request at all. `false` is the deny a plane answers a request
    /// it could not evaluate with — a subject type the schema does not declare, a partition that
    /// failed — and `error` says why. A script that has to tell "no" from "the question never
    /// reached a policy" reads this, not the exit code: a deny is an answer either way.
    pub evaluated: bool,
    /// The decision's own identifier, for the audit trail. Absent for a batch, which is an answer
    /// about decisions rather than one of them.
    pub id: Option<String>,
    /// The policies that decided it, named the way `test` names them: by the alias their author
    /// wrote where this workspace tracks one, by identity otherwise.
    pub policies: Vec<String>,
    /// The same policies by identity alone — what the plane cited, and what the audit record
    /// carries.
    pub policy_ids: Vec<String>,
    /// The operator-facing reason, when the server sent one.
    pub reason: Option<String>,
    /// Why the request could not be evaluated, when it could not.
    pub error: Option<String>,
    /// One line per boxcarred evaluation, in the order they were asked. Empty for a plain request.
    pub evaluations: Vec<CheckLine>,
}

/// One boxcarred decision, with the same fields as the whole answer.
#[derive(Debug, Clone, Serialize)]
pub struct CheckLine {
    pub decision: bool,
    pub evaluated: bool,
    pub request_id: Option<String>,
    pub policies: Vec<String>,
    pub policy_ids: Vec<String>,
    pub reason: Option<String>,
    pub error: Option<String>,
}

impl CheckReport {
    /// Reads the answer beside the request that produced it.
    ///
    /// `aliases` names the policies: identity → the alias its author wrote, from the head the
    /// workspace tracks. Empty outside a checkout, where the identity is all there is.
    pub fn of(
        payload: &serde_json::Value,
        answer: &serde_json::Value,
        store_from: &'static str,
        aliases: &std::collections::BTreeMap<String, String>,
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
        let (reason, error) = reasons(context);
        let policy_ids = policies(context);

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
            evaluated: error.is_none(),
            id: context
                .and_then(|context| context.get("id"))
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned),
            policies: named(&policy_ids, aliases),
            policy_ids,
            reason,
            error,
            evaluations: answer
                .get("evaluations")
                .and_then(serde_json::Value::as_array)
                .map(|entries| {
                    entries
                        .iter()
                        .map(|entry| {
                            let context = entry.get("context");
                            let (reason, error) = reasons(context);
                            let policy_ids = policies(context);

                            CheckLine {
                                decision: entry
                                    .get("decision")
                                    .and_then(serde_json::Value::as_bool)
                                    .unwrap_or(false),
                                evaluated: error.is_none(),
                                request_id: entry
                                    .get("request_id")
                                    .and_then(serde_json::Value::as_str)
                                    .map(ToOwned::to_owned),
                                policies: named(&policy_ids, aliases),
                                policy_ids,
                                reason,
                                error,
                            }
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

/// The policies by the names a person reads: the alias where one is tracked, the identity
/// otherwise — the rule `test` names them by, so a failed case and the decision it corresponds to
/// finally share a name.
fn named(ids: &[String], aliases: &std::collections::BTreeMap<String, String>) -> Vec<String> {
    ids.iter()
        .map(|id| aliases.get(id).cloned().unwrap_or_else(|| id.clone()))
        .collect()
}

/// The operator's half of the reason, and — when its code says the request was never evaluated —
/// the error it is.
///
/// The plane answers an evaluation it could not perform as a deny whose `reason_admin` carries
/// code `500`, the same thing the local run calls a refusal. The code used to be dropped here,
/// which left a deny nothing permitted and a deny nothing evaluated printing the same way.
fn reasons(context: Option<&serde_json::Value>) -> (Option<String>, Option<String>) {
    let Some(reason) = context.and_then(|context| context.get("reason_admin")) else {
        return (None, None);
    };
    let message = reason
        .get("message")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned);
    let code = reason
        .get("code")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let error = if code == "500" { message.clone() } else { None };

    (message, error)
}

/// A policy as a person reads it: the alias, with the identity it stands for beside it.
fn policy_named(name: &str, id: &str) -> String {
    if name == id {
        style::id(id)
    } else {
        format!("{} {}", style::bold(name), style::dim(id))
    }
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
        match (&self.error, &self.reason) {
            // Not a deny the policies reached: said as what it is, on its own line.
            (Some(error), _) => writeln!(out, "  {} {error}", style::delete("!"))?,
            (None, Some(reason)) => {
                let symbol = if self.decision {
                    style::create("+")
                } else {
                    style::delete("-")
                };
                writeln!(out, "  {symbol} {reason}")?;
            }
            (None, None) => {}
        }
        for (policy, id) in self.policies.iter().zip(&self.policy_ids) {
            writeln!(
                out,
                "    {} {}",
                style::dim("policy"),
                policy_named(policy, id)
            )?;
        }
        for (index, line) in self.evaluations.iter().enumerate() {
            let named = line
                .request_id
                .clone()
                .unwrap_or_else(|| format!("#{index}"));
            match &line.error {
                Some(error) => {
                    writeln!(
                        out,
                        "  {} {} {error}",
                        style::delete("!"),
                        style::id(&named)
                    )?;
                }
                None => {
                    let symbol = if line.decision {
                        style::create("+")
                    } else {
                        style::delete("-")
                    };
                    writeln!(
                        out,
                        "  {symbol} {} {}",
                        style::id(&named),
                        line.reason.clone().unwrap_or_default()
                    )?;
                }
            }
            for (policy, id) in line.policies.iter().zip(&line.policy_ids) {
                writeln!(
                    out,
                    "      {} {}",
                    style::dim("policy"),
                    policy_named(policy, id)
                )?;
            }
        }
        if let Some(id) = &self.id {
            writeln!(out, "  {} {}", style::dim("decision id"), style::id(id))?;
        }
        writeln!(out)?;

        let summary = if self.evaluations.is_empty() {
            match (self.decision, self.evaluated) {
                (true, _) => "Permitted.".to_owned(),
                (false, true) => "Denied.".to_owned(),
                (false, false) => "Not evaluated — denied.".to_owned(),
            }
        } else {
            let permitted = self.evaluations.iter().filter(|line| line.decision).count();
            let unevaluated = self
                .evaluations
                .iter()
                .filter(|line| !line.evaluated)
                .count();
            let mut summary = format!(
                "{} of {} evaluations permitted.",
                permitted,
                self.evaluations.len()
            );
            if unevaluated > 0 {
                summary.push_str(&format!(" {unevaluated} not evaluated."));
            }
            summary
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

/// A case file that did not read as cases, and why. Part of the run's answer, not a reason for
/// the run not to happen: one broken file used to switch off the whole suite.
#[derive(Debug, Clone, Serialize)]
pub struct UnreadableLine {
    pub source: String,
    pub problem: String,
}

/// `test --list`: the cases and what each one claims, decided against nothing.
#[derive(Debug, Serialize)]
pub struct TestListReport {
    pub cases: Vec<TestListLine>,
    /// The files that could not be read as cases. Empty when every file read.
    pub unreadable: Vec<UnreadableLine>,
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
        for held in &self.unreadable {
            writeln!(out, "  {} {}", style::delete("!"), held.source)?;
            writeln!(out, "    {}", style::delete(&held.problem))?;
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
    /// The files that could not be read as cases. Not counted among `failed` — they are not cases
    /// — and the run is not green while one is present, whatever its cases decided.
    pub unreadable: Vec<UnreadableLine>,
}

/// One case's outcome. Every field is present in every line — `decision` is `null` when the
/// request was not evaluated, the lists are `[]` when empty — so a consumer reads one shape for
/// a permit, a deny, a refusal and a batch alike.
#[derive(Debug, Serialize)]
pub struct TestCaseLine {
    pub name: String,
    pub source: String,
    pub profile: String,
    pub passed: bool,
    /// The decision reached; `null` when the request could not be evaluated.
    pub decision: Option<bool>,
    /// The policies that decided, by alias where one is authored.
    pub policies: Vec<String>,
    /// One per boxcarred evaluation, as `id=permit`. Empty for a plain request.
    pub evaluations: Vec<String>,
    /// The refusal, when the request could not be evaluated.
    pub error: Option<String>,
    /// Why the case failed. Empty when it passed.
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
            // A boxcarred request has no single policy to cite: what it decided is what
            // each of its evaluations decided, and the batch is their conjunction.
            let decided = if !case.evaluations.is_empty() {
                format!(
                    "{} — {}",
                    match case.decision {
                        Some(true) => "permit",
                        Some(false) => "deny",
                        None => "not evaluated",
                    },
                    case.evaluations.join(" ")
                )
            } else {
                match (case.decision, case.policies.as_slice()) {
                    (Some(true), []) => "permit".to_owned(),
                    (Some(true), cited) => format!("permit by {}", cited.join(", ")),
                    (Some(false), []) => "deny, nothing permitted it".to_owned(),
                    (Some(false), cited) => format!("deny by {}", cited.join(", ")),
                    (None, _) => "not evaluated".to_owned(),
                }
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
        for held in &self.unreadable {
            writeln!(
                out,
                "  {}  {}  {}",
                style::delete("fail"),
                held.source,
                style::dim("[not a list of cases]")
            )?;
            writeln!(out, "        {}", style::delete(&held.problem))?;
        }
        writeln!(out)?;
        writeln!(out, "  {} {}", style::dim("asked"), style::dim(&self.asked))?;
        writeln!(out)?;

        let mut summary = format!(
            "{} case(s), {} passed, {} failed.",
            self.cases.len(),
            self.passed,
            self.failed
        );
        if !self.unreadable.is_empty() {
            summary.push_str(&format!(
                " {} file(s) could not be read as cases.",
                self.unreadable.len()
            ));
        }

        if self.failed == 0 && self.unreadable.is_empty() {
            writeln!(out, "{}", style::ok(&style::bold(&summary)))
        } else {
            writeln!(out, "{}", style::delete(&style::bold(&summary)))
        }
    }
}
