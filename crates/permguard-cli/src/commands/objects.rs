// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The views `objects cat` offers: a typed inspection, and a reading for
//! people. The raw and content views are byte passthroughs and live at the
//! call site; these two are renderings, so they live together here.

use crate::style;
use crate::workspace_out;

/// The typed view of one object, for `objects cat --inspect`.
pub fn inspect_report(
    digest: &permguard_objects::digest::Digest,
    bytes: &[u8],
    decoded: &permguard_objects::object::Object,
) -> workspace_out::InspectObjectReport {
    use permguard_objects::object::{Kind, Object};
    use workspace_out::{InspectCommit, InspectEntry, InspectObjectReport};

    let kind_name = |kind: &Kind| match kind {
        Kind::Blob => "blob",
        Kind::Tree => "tree",
        Kind::Commit => "commit",
    };
    let mut report = InspectObjectReport {
        digest: digest.to_string(),
        kind: "blob",
        stored_size: bytes.len(),
        media_type: None,
        content_size: None,
        entries: Vec::new(),
        commit: None,
    };
    match decoded {
        Object::Blob(blob) => {
            report.media_type = Some(blob.media_type.clone());
            report.content_size = Some(blob.data.len());
        }
        Object::Tree(tree) => {
            report.kind = "tree";
            report.entries = tree
                .entries
                .iter()
                .map(|entry| InspectEntry {
                    name: entry.name.clone(),
                    kind: kind_name(&entry.kind),
                    digest: entry.digest.to_string(),
                    annotations: entry.annotations.clone(),
                })
                .collect();
        }
        Object::Commit(commit) => {
            report.kind = "commit";
            report.commit = Some(InspectCommit {
                tree: commit.tree.to_string(),
                manifest: commit.manifest.to_string(),
                predecessors: commit.predecessors.iter().map(|p| p.to_string()).collect(),
                author: commit.author.clone(),
                author_at: commit.author_at,
                message: commit.message.clone(),
            });
        }
    }
    report
}

/// The reading for people, for `objects cat --human`: a commit like a log
/// entry, a tree as a listing, a blob as its text.
pub fn write_human(
    out: &mut dyn std::io::Write,
    digest: &permguard_objects::digest::Digest,
    decoded: &permguard_objects::object::Object,
) -> std::io::Result<()> {
    use permguard_objects::object::{Kind, Object};
    match decoded {
        Object::Blob(blob) => {
            writeln!(
                out,
                "{} {} ({}, {} bytes)",
                style::bold("blob"),
                style::id(&digest.to_string()),
                blob.media_type,
                blob.data.len()
            )?;
            writeln!(out)?;
            out.write_all(&blob.data)?;
            if !blob.data.ends_with(b"\n") {
                writeln!(out)?;
            }
        }
        Object::Tree(tree) => {
            writeln!(
                out,
                "{} {} ({} entries)",
                style::bold("tree"),
                style::id(&digest.to_string()),
                tree.entries.len()
            )?;
            for entry in &tree.entries {
                let kind = match entry.kind {
                    Kind::Blob => "blob",
                    Kind::Tree => "tree",
                    Kind::Commit => "commit",
                };
                writeln!(
                    out,
                    "  {:6} {}  {}",
                    kind,
                    style::id(&entry.digest.to_string()),
                    style::bold(&entry.name)
                )?;
                for (key, value) in &entry.annotations {
                    writeln!(out, "         {}", style::dim(&format!("{key} = {value}")))?;
                }
            }
        }
        Object::Commit(commit) => {
            writeln!(
                out,
                "{} {}",
                style::bold("commit"),
                style::id(&digest.to_string())
            )?;
            writeln!(out, "tree     {}", style::id(&commit.tree.to_string()))?;
            writeln!(out, "manifest {}", style::id(&commit.manifest.to_string()))?;
            for predecessor in &commit.predecessors {
                writeln!(out, "parent   {}", style::id(&predecessor.to_string()))?;
            }
            writeln!(
                out,
                "author   {} at {}",
                commit.author,
                permguard_core::time::to_rfc3339(commit.author_at)
            )?;
            writeln!(out)?;
            writeln!(out, "    {}", commit.message)?;
        }
    }
    Ok(())
}
