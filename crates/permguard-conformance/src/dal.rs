// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The data access inventory: which sources reach durable state by themselves (iteration 03,
//! WP-25.2, `1-architecture/8-architecture-storage-operations.md` store contracts).
//!
//! A domain reaches its durable state through a store contract, and a backend implements the
//! contract. Until a domain is moved behind its contract it reads and writes through the storage
//! library, or the filesystem, itself. This check reads the source of every crate that holds
//! durable state as a syntax tree and finds each file that does:
//!
//! | Reach               | Seen as                                                                    |
//! | ------------------- | -------------------------------------------------------------------------- |
//! | the filesystem      | a path or a `use` under `std::fs` or `tokio::fs`                           |
//! | the storage library | a path or a `use` under `permguard_host::storage`; inside `permguard-host`, under `crate::storage`, or `storage` after `self` and `super` |
//!
//! A `use` counts as the reach it brings in, so a renamed import (`use std::fs as files;`) and a
//! glob are found where they are written. A macro's arguments are read token by token, so
//! `format!("{}", std::fs::read_to_string(p)?)` is found too. Test code (`#[cfg(test)]` items,
//! never `cfg(not(test))`, and the files a `#[cfg(test)] mod name;` loads) is not scanned. A
//! module that re-exports the filesystem is found as the reach it is; a file that only calls such
//! a module's own functions is not, as in the durability inventory. A file this build's parser
//! does not read is reported, not skipped.
//!
//! `dal.json` says what each reaching file is:
//!
//! | List         | Holds                                                                       |
//! | ------------ | --------------------------------------------------------------------------- |
//! | `scope`      | the crates that hold durable state: the ones read                           |
//! | `backends`   | the directories and files whose purpose is to reach storage, each with why  |
//! | `configured` | the files that read or write what a configuration names, on any backend     |
//! | `direct`     | every other file that reaches storage today, with the package that moves it |
//!
//! A reaching file that is in no list fails the check, so no new direct access is added. An entry
//! of `configured` or `direct` whose file no longer reaches storage fails it too, so `direct` only
//! shrinks: the package that moves a domain behind its contract removes the entries it emptied.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Deserialize;
use syn::visit::Visit;

use crate::durability::{is_test_gated, sources, test_module_files};

/// This file: its documentation and its tests name the paths it looks for.
const SELF: &str = "crates/permguard-conformance/src/dal.rs";

/// The crate whose own `crate::storage` is the storage library.
const LIBRARY_CRATE: &str = "permguard-host";

/// A directory or a file whose purpose is to reach storage.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Backend {
    /// A directory, ending in `/`, or a file, relative to the repository root.
    pub path: String,
    /// What it is a backend of.
    pub reason: String,
}

/// A file that reaches storage itself until a package moves it behind a store contract.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Direct {
    /// The file, relative to the repository root.
    pub source: String,
    /// The package of iteration 03 that moves it: `WP-26.1`.
    pub until: String,
}

/// A file that reads or writes what a configuration names, whatever the backend: an invitation an
/// operator mounted, the material a development start generates.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Configured {
    /// The file, relative to the repository root.
    pub source: String,
    /// What it reads or writes, and why that is not a store's state.
    pub reason: String,
}

/// `dal.json`.
#[derive(Debug, Clone, Deserialize)]
pub struct Rules {
    /// The crates read, by directory name under `crates/`.
    pub scope: Vec<String>,
    pub backends: Vec<Backend>,
    pub configured: Vec<Configured>,
    pub direct: Vec<Direct>,
}

/// One place a file reaches storage.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Reach {
    pub source: String,
    pub line: usize,
    /// `filesystem`, `storage library` or `unparsed`.
    pub what: String,
    /// The path as it is written.
    pub detail: String,
}

/// What the check refuses.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Violation {
    pub source: String,
    pub line: usize,
    pub detail: String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}: {}", self.source, self.line, self.detail)
    }
}

/// Reads `dal.json` beside this crate.
pub fn rules(root: &Path) -> Result<Rules, String> {
    let path = root.join("crates/permguard-conformance/dal.json");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// The crate a source belongs to: the directory under `crates/`.
fn crate_of(relative: &str) -> Option<&str> {
    relative.strip_prefix("crates/")?.split('/').next()
}

/// Every reach in the scoped sources under `root`, outside the backends.
pub fn reaches(root: &Path, rules: &Rules) -> Vec<Reach> {
    let mut found = Vec::new();
    let sources = sources(root);
    // A `#[cfg(test)] mod name;` makes the file it names test code, wherever it lives.
    let mut test_files = BTreeSet::new();
    for path in &sources {
        if let Ok(text) = std::fs::read_to_string(path) {
            test_files.extend(test_module_files(path, &text));
        }
    }
    for path in sources {
        if test_files.contains(&path) {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let Some(name) = crate_of(&relative) else {
            continue;
        };
        if relative == SELF || !rules.scope.iter().any(|scoped| scoped == name) {
            continue;
        }
        if is_backend(&relative, &rules.backends) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        found.extend(scan(&relative, name, &text));
    }
    found.sort();
    found
}

/// Whether `relative` is one of the backends, or below one.
pub fn is_backend(relative: &str, backends: &[Backend]) -> bool {
    backends.iter().any(|backend| {
        if backend.path.ends_with('/') {
            relative.starts_with(&backend.path)
        } else {
            relative == backend.path
        }
    })
}

/// What the rules do not cover among `found`, and what the rules name that is no longer so.
///
/// `exists` says whether a path of the rules is there: a directory for a path ending in `/`.
pub fn judge(found: &[Reach], rules: &Rules, exists: &dyn Fn(&str) -> bool) -> Vec<Violation> {
    let mut violations = Vec::new();
    let mut reaching: BTreeMap<&str, &Reach> = BTreeMap::new();
    for reach in found {
        reaching.entry(reach.source.as_str()).or_insert(reach);
    }
    let listed: BTreeSet<&str> = rules
        .direct
        .iter()
        .map(|direct| direct.source.as_str())
        .chain(rules.configured.iter().map(|given| given.source.as_str()))
        .collect();
    for (source, first) in &reaching {
        if !listed.contains(source) {
            violations.push(Violation {
                source: (*source).to_owned(),
                line: first.line,
                detail: format!(
                    "reaches the {} itself (`{}`): go through a store contract, or list the file \
                     in dal.json",
                    first.what, first.detail
                ),
            });
        }
    }
    let mut seen = BTreeSet::new();
    for given in &rules.configured {
        if !seen.insert(given.source.as_str()) {
            violations.push(Violation {
                source: given.source.clone(),
                line: 0,
                detail: "listed twice in dal.json".to_owned(),
            });
        }
        if !reaching.contains_key(given.source.as_str()) {
            violations.push(Violation {
                source: given.source.clone(),
                line: 0,
                detail: "a `configured` entry for a file that no longer reaches storage: remove it"
                    .to_owned(),
            });
        }
        if given.reason.trim().is_empty() {
            violations.push(Violation {
                source: given.source.clone(),
                line: 0,
                detail: "a `configured` entry without a reason".to_owned(),
            });
        }
    }
    for direct in &rules.direct {
        if !seen.insert(direct.source.as_str()) {
            violations.push(Violation {
                source: direct.source.clone(),
                line: 0,
                detail: "listed twice in dal.json".to_owned(),
            });
        }
        if !reaching.contains_key(direct.source.as_str()) {
            violations.push(Violation {
                source: direct.source.clone(),
                line: 0,
                detail: "a `direct` entry for a file that no longer reaches storage: remove it"
                    .to_owned(),
            });
        }
        if !is_package(&direct.until) {
            violations.push(Violation {
                source: direct.source.clone(),
                line: 0,
                detail: format!("`until` is not a package, `WP-<n>.<m>`: `{}`", direct.until),
            });
        }
    }
    for backend in &rules.backends {
        if !exists(&backend.path) {
            violations.push(Violation {
                source: backend.path.clone(),
                line: 0,
                detail: "a backend that is not in the repository".to_owned(),
            });
        }
        if backend.reason.trim().is_empty() {
            violations.push(Violation {
                source: backend.path.clone(),
                line: 0,
                detail: "a backend without a reason".to_owned(),
            });
        }
    }
    violations.sort();
    violations
}

/// The violations in the sources under `root`.
pub fn check(root: &Path, rules: &Rules) -> Vec<Violation> {
    let found = reaches(root, rules);
    judge(&found, rules, &|path| {
        let full = root.join(path);
        if path.ends_with('/') {
            full.is_dir()
        } else {
            full.is_file()
        }
    })
}

/// Whether `text` names a package: `WP-`, digits, a dot, digits.
fn is_package(text: &str) -> bool {
    text.strip_prefix("WP-")
        .and_then(|rest| rest.split_once('.'))
        .is_some_and(|(phase, package)| {
            !phase.is_empty()
                && !package.is_empty()
                && phase.bytes().all(|b| b.is_ascii_digit())
                && package.bytes().all(|b| b.is_ascii_digit())
        })
}

/// The reaches in one file's source; `krate` is the crate the file belongs to.
pub fn scan(source: &str, krate: &str, text: &str) -> Vec<Reach> {
    let file = match syn::parse_file(text) {
        Ok(file) => file,
        Err(error) => {
            // Loud, not silent: a parser that lags the compiler would otherwise switch the check
            // off for the file.
            return vec![Reach {
                source: source.to_owned(),
                line: error.span().start().line,
                what: "unparsed".to_owned(),
                detail: format!("the file does not parse: {error}"),
            }];
        }
    };
    let mut scanner = Scanner {
        source,
        in_library_crate: krate == LIBRARY_CRATE,
        found: Vec::new(),
    };
    scanner.visit_file(&file);
    scanner.found
}

struct Scanner<'a> {
    source: &'a str,
    in_library_crate: bool,
    found: Vec<Reach>,
}

impl Scanner<'_> {
    /// What a path reaches, read from its first segments.
    fn reach_of(&self, segments: &[String]) -> Option<&'static str> {
        let names: Vec<&str> = segments.iter().map(String::as_str).collect();
        match names.as_slice() {
            ["std" | "tokio", "fs", ..] => Some("filesystem"),
            ["permguard_host", "storage", ..] => Some("storage library"),
            _ if self.in_library_crate => {
                let local = names
                    .iter()
                    .find(|name| !matches!(**name, "crate" | "self" | "super"));
                let relative = names
                    .first()
                    .is_some_and(|first| matches!(*first, "crate" | "self" | "super"));
                (relative && local == Some(&"storage")).then_some("storage library")
            }
            _ => None,
        }
    }

    fn judge_path(&mut self, segments: &[String], line: usize) {
        if let Some(what) = self.reach_of(segments) {
            self.found.push(Reach {
                source: self.source.to_owned(),
                line,
                what: what.to_owned(),
                detail: segments.join("::"),
            });
        }
    }

    /// Every `use` path a tree names, each judged whole: `use std::{fs, io};` names `std::fs`.
    fn record_use(&mut self, tree: &syn::UseTree, prefix: &mut Vec<String>, line: usize) {
        match tree {
            syn::UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                self.record_use(&path.tree, prefix, line);
                prefix.pop();
            }
            syn::UseTree::Name(name) => {
                prefix.push(name.ident.to_string());
                self.judge_path(prefix, line);
                prefix.pop();
            }
            syn::UseTree::Rename(rename) => {
                prefix.push(rename.ident.to_string());
                self.judge_path(prefix, line);
                prefix.pop();
            }
            syn::UseTree::Glob(_) => self.judge_path(prefix, line),
            syn::UseTree::Group(group) => {
                for tree in &group.items {
                    self.record_use(tree, prefix, line);
                }
            }
        }
    }

    /// The paths among a macro's tokens: runs of identifiers joined by `::`.
    fn scan_tokens(&mut self, tokens: proc_macro2::TokenStream) {
        let mut run: Vec<String> = Vec::new();
        let mut line = 0;
        let mut colons = 0;
        for token in tokens {
            match token {
                proc_macro2::TokenTree::Ident(ident) => {
                    if run.is_empty() || colons == 2 {
                        if run.is_empty() {
                            line = ident.span().start().line;
                        }
                        run.push(ident.to_string());
                    } else {
                        self.judge_path(&run, line);
                        line = ident.span().start().line;
                        run = vec![ident.to_string()];
                    }
                    colons = 0;
                }
                proc_macro2::TokenTree::Punct(punct) if punct.as_char() == ':' => colons += 1,
                proc_macro2::TokenTree::Group(group) => {
                    self.judge_path(&run, line);
                    run.clear();
                    colons = 0;
                    self.scan_tokens(group.stream());
                }
                _ => {
                    self.judge_path(&run, line);
                    run.clear();
                    colons = 0;
                }
            }
        }
        self.judge_path(&run, line);
    }
}

impl<'ast> Visit<'ast> for Scanner<'_> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        let attrs: &[syn::Attribute] = match item {
            syn::Item::Const(i) => &i.attrs,
            syn::Item::Enum(i) => &i.attrs,
            syn::Item::Fn(i) => &i.attrs,
            syn::Item::Impl(i) => &i.attrs,
            syn::Item::Macro(i) => &i.attrs,
            syn::Item::Mod(i) => &i.attrs,
            syn::Item::Static(i) => &i.attrs,
            syn::Item::Struct(i) => &i.attrs,
            syn::Item::Trait(i) => &i.attrs,
            syn::Item::Type(i) => &i.attrs,
            syn::Item::Use(i) => &i.attrs,
            _ => &[],
        };
        if is_test_gated(attrs) {
            return;
        }
        syn::visit::visit_item(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if !is_test_gated(&item.attrs) {
            syn::visit::visit_impl_item_fn(self, item);
        }
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let line = syn::spanned::Spanned::span(item).start().line;
        self.record_use(&item.tree, &mut Vec::new(), line);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        let segments: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        let line = syn::spanned::Spanned::span(path).start().line;
        self.judge_path(&segments, line);
        syn::visit::visit_path(self, path);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.scan_tokens(mac.tokens.clone());
        syn::visit::visit_macro(self, mac);
    }
}
