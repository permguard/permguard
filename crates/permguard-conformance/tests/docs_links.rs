// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Every documentation URL the product ships reaches a page the documentation site builds
//! (BUG-0057): the chart's alert runbooks, the README, the crates' READMEs and the shipped
//! configurations. A runbook an operator is paged to must not answer "page not found".
//!
//! A URL `https://docs.permguard.com/<path>` is a page when `website/<path>.md`, or
//! `website/<path>/index.md`, exists; the root is `website/index.md`. A fragment may name a section
//! not yet written, so only the page is checked.

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

const SITE: &str = "https://docs.permguard.com";

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

/// The files that ship a documentation URL to an operator or a reader.
fn shipped(root: &Path) -> Vec<PathBuf> {
    let mut files = vec![root.join("README.md")];
    let mut walk = vec![root.join("charts")];
    while let Some(directory) = walk.pop() {
        for entry in std::fs::read_dir(&directory).expect("the directory reads") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                walk.push(path);
            } else if path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| matches!(extension, "yaml" | "yml" | "tpl" | "md" | "txt"))
            {
                files.push(path);
            }
        }
    }
    for entry in std::fs::read_dir(root.join("crates")).expect("the crates read") {
        let crate_dir = entry.expect("an entry").path();
        if !crate_dir.is_dir() {
            continue;
        }
        for file in std::fs::read_dir(&crate_dir).expect("a crate reads") {
            let path = file.expect("an entry").path();
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            if name == "README.md" || (name.starts_with("config.") && name.ends_with(".yml")) {
                files.push(path);
            }
        }
    }
    files
}

/// Every documentation URL in `text`, as written.
fn urls(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find(SITE) {
        let tail = &rest[at..];
        let end = tail
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ')' | '>' | '`' | ']'))
            .unwrap_or(tail.len());
        found.push(
            tail[..end]
                .trim_end_matches(['.', ',', ';', ':'])
                .to_owned(),
        );
        rest = &tail[end..];
    }
    found
}

/// The site page a URL names, when the site builds one.
fn page(root: &Path, url: &str) -> Option<PathBuf> {
    let path = url.strip_prefix(SITE)?;
    let path = path.split(['#', '?']).next().unwrap_or_default();
    let path = path.trim_matches('/');
    let website = root.join("website");
    let candidates = if path.is_empty() {
        vec![website.join("index.md")]
    } else {
        vec![
            website.join(format!("{path}.md")),
            website.join(path).join("index.md"),
        ]
    };
    candidates.into_iter().find(|candidate| candidate.is_file())
}

#[test]
fn every_shipped_documentation_url_reaches_a_page_the_site_builds() {
    let root = repository();
    let mut checked = 0;
    let mut missing = Vec::new();
    for file in shipped(&root) {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        for url in urls(&text) {
            checked += 1;
            if page(&root, &url).is_none() {
                missing.push(format!(
                    "{}: {url}",
                    file.strip_prefix(&root).unwrap_or(&file).display()
                ));
            }
        }
    }
    assert!(
        checked >= 20,
        "the runbooks and the README are read: {checked}"
    );
    assert!(
        missing.is_empty(),
        "documentation URLs that reach no page the site builds:\n{}",
        missing.join("\n")
    );
}

#[test]
fn a_url_names_its_page_and_never_a_fragment() {
    let root = repository();
    assert!(page(&root, "https://docs.permguard.com/").is_some());
    assert!(
        page(
            &root,
            "https://docs.permguard.com/how-it-works/evidence#failure-modes"
        )
        .is_some()
    );
    assert!(page(&root, "https://docs.permguard.com/observability").is_none());
    assert_eq!(
        urls("see (https://docs.permguard.com/a/b#c), and \"https://docs.permguard.com/d\""),
        [
            "https://docs.permguard.com/a/b#c",
            "https://docs.permguard.com/d"
        ]
    );
}
