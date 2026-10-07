// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The durability inventory: one storage library, and nothing beside it (WP-1.11).
//!
//! Every temporary, rename, hard link, flush and tail cut on a Permguard volume goes through
//! `permguard-host::storage`. This check reads every crate's source as a syntax tree and finds
//! the primitives anywhere else:
//!
//! | Primitive              | Seen as                                                                          |
//! | ---------------------- | -------------------------------------------------------------------------------- |
//! | rename, link, copy, write | `std::fs::{rename, hard_link, copy, write}`, however imported or named: a call, a function pointer, a method named as a function |
//! | flush                  | a method call `.sync_all()` or `.sync_data()`                                    |
//! | tail cut               | a method call `.set_len(..)`                                                     |
//! | ad-hoc publication     | a string literal naming a temporary: ending in `.tmp`, `.next`, `.new` or `.staged`, or holding `.tmp-` |
//!
//! A `use` is resolved before a path is judged, so `use std::fs::rename as publish;` followed by
//! `publish(a, b)`, `use std::fs as filesystem;` followed by `filesystem::rename(a, b)`, a
//! function pointer `let f = std::fs::rename;` and a method named as a function
//! (`File::sync_all(&f)`) are all what they are; a wrapper module re-exporting the function is
//! seen through its own `use`. Literals inside macros (`format!("{name}.tmp")`) are read token
//! by token. Test code (`#[cfg(test)]` items, never `cfg(not(test))`, and `tests/` directories)
//! is not scanned: a test damages files on purpose. A file this build's parser does not read is
//! reported, not skipped. What remains outside the library is listed in `durability.json` with
//! its exact path, symbol and reason, or the check fails; one entry covers every use of that
//! primitive in that item.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use syn::visit::Visit;

/// The directory whose code may use the primitives: the storage library.
pub const LIBRARY: &str = "crates/permguard-host/src/storage/";
/// This file: it names the patterns it looks for.
const SELF: &str = "crates/permguard-conformance/src/durability.rs";

/// One allowed use of a primitive outside the library.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Allowed {
    /// The file, relative to the repository root.
    pub source: String,
    /// The function, method or `impl` block the use sits in, as `Type::name` or `name`.
    pub item: String,
    /// Which primitive, as the inventory names it.
    pub primitive: String,
    /// Why the library cannot be used there.
    pub reason: String,
}

/// The allow-list file.
#[derive(Debug, Clone, Deserialize)]
pub struct Allowlist {
    pub allowed: Vec<Allowed>,
}

/// One use of a primitive outside the library.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Violation {
    pub source: String,
    pub line: usize,
    pub item: String,
    pub primitive: String,
    pub detail: String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} in `{}`: {} ({})",
            self.source, self.line, self.item, self.primitive, self.detail
        )
    }
}

/// Reads `durability.json` beside this crate.
pub fn allowlist(root: &Path) -> Result<Allowlist, String> {
    let path = root.join("crates/permguard-conformance/durability.json");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Every Rust source under `crates/*/src/` of `root`, outside the library.
pub fn sources(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let crates = root.join("crates");
    let Ok(entries) = std::fs::read_dir(&crates) else {
        return found;
    };
    for entry in entries.flatten() {
        collect(&entry.path().join("src"), &mut found);
    }
    found.sort();
    found
}

fn collect(dir: &Path, into: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, into);
        } else if path.extension().is_some_and(|e| e == "rs") {
            into.push(path);
        }
    }
}

/// The violations in the sources under `root` that the allow-list does not cover, and the
/// allow-list entries that cover nothing (a stale entry is a violation too).
pub fn check(root: &Path, allowlist: &Allowlist) -> Vec<Violation> {
    let mut found = Vec::new();
    for path in sources(root) {
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if relative.starts_with(LIBRARY) || relative == SELF {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        found.extend(scan(&relative, &text));
    }
    judge(found, allowlist)
}

/// Splits `found` into what the allow-list covers and what it does not, and reports stale
/// entries as violations of their own.
pub fn judge(found: Vec<Violation>, allowlist: &Allowlist) -> Vec<Violation> {
    let mut used: BTreeSet<usize> = BTreeSet::new();
    let mut remaining = Vec::new();
    for violation in found {
        let covering = allowlist.allowed.iter().position(|allowed| {
            allowed.source == violation.source
                && allowed.item == violation.item
                && allowed.primitive == violation.primitive
        });
        match covering {
            Some(index) => {
                used.insert(index);
            }
            None => remaining.push(violation),
        }
    }
    for (index, allowed) in allowlist.allowed.iter().enumerate() {
        if !used.contains(&index) {
            remaining.push(Violation {
                source: allowed.source.clone(),
                line: 0,
                item: allowed.item.clone(),
                primitive: allowed.primitive.clone(),
                detail: "an allow-list entry nothing in the code needs".to_owned(),
            });
        }
    }
    remaining.sort();
    remaining
}

/// The primitives in one file's source.
pub fn scan(source: &str, text: &str) -> Vec<Violation> {
    let file = match syn::parse_file(text) {
        Ok(file) => file,
        Err(error) => {
            // Loud, not silent: a parser that lags the compiler would otherwise switch the check
            // off for the file.
            return vec![Violation {
                source: source.to_owned(),
                line: error.span().start().line,
                item: "<file>".to_owned(),
                primitive: "unparsed".to_owned(),
                detail: format!("the file does not parse: {error}"),
            }];
        }
    };
    let mut visitor = Scanner {
        source,
        imports: BTreeMap::new(),
        module_aliases: BTreeSet::new(),
        item: Vec::new(),
        found: Vec::new(),
    };
    visitor.visit_file(&file);
    visitor.found
}

/// What the three `std::fs` functions are called in a file, after its `use` items.
const FS_FUNCTIONS: &[&str] = &["rename", "hard_link", "copy", "write"];
const FLUSHES: &[&str] = &["sync_all", "sync_data"];
const TEMP_ENDINGS: &[&str] = &[".tmp", ".next", ".new", ".staged"];

struct Scanner<'a> {
    source: &'a str,
    /// Local name → the `std::fs` function it names.
    imports: BTreeMap<String, &'static str>,
    /// Local names of the `std::fs` module itself: whatever `use std::fs as x` made.
    module_aliases: BTreeSet<String>,
    /// The enclosing items, outermost first.
    item: Vec<String>,
    found: Vec<Violation>,
}

impl Scanner<'_> {
    fn item_name(&self) -> String {
        if self.item.is_empty() {
            "<file>".to_owned()
        } else {
            self.item.join("::")
        }
    }

    fn report(&mut self, line: usize, primitive: &str, detail: String) {
        self.found.push(Violation {
            source: self.source.to_owned(),
            line,
            item: self.item_name(),
            primitive: primitive.to_owned(),
            detail,
        });
    }

    /// Resolves a path expression to a `std::fs` function, through the file's imports.
    fn fs_function(&self, path: &syn::Path) -> Option<&'static str> {
        let segments: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        let names: Vec<&str> = segments.iter().map(String::as_str).collect();
        match names.as_slice() {
            ["std", "fs", f] => FS_FUNCTIONS.iter().copied().find(|known| known == f),
            [module, f] if *module == "fs" || self.module_aliases.contains(*module) => {
                FS_FUNCTIONS.iter().copied().find(|known| known == f)
            }
            [one] => self.imports.get(*one).copied(),
            _ => None,
        }
    }

    /// A method named as a function: `File::sync_all(&file)`, `std::fs::File::set_len(&f, 0)`.
    fn method_as_function(path: &syn::Path) -> Option<(&'static str, String)> {
        if path.segments.len() < 2 {
            return None;
        }
        let last = path.segments.last()?.ident.to_string();
        if FLUSHES.contains(&last.as_str()) {
            Some(("flush", last))
        } else if last == "set_len" {
            Some(("truncate", last))
        } else {
            None
        }
    }

    /// Every string literal among `tokens`, however deep: what a macro's arguments hold.
    fn scan_tokens(&mut self, tokens: proc_macro2::TokenStream) {
        for token in tokens {
            match token {
                proc_macro2::TokenTree::Group(group) => self.scan_tokens(group.stream()),
                proc_macro2::TokenTree::Literal(literal) => {
                    if let Ok(text) = syn::parse_str::<syn::LitStr>(&literal.to_string()) {
                        self.judge_literal(&text.value(), literal.span().start().line);
                    }
                }
                _ => {}
            }
        }
    }

    fn judge_literal(&mut self, value: &str, line: usize) {
        if TEMP_ENDINGS.iter().any(|ending| value.ends_with(ending)) || value.contains(".tmp-") {
            self.report(line, "temporary", format!("a temporary's name `{value}`"));
        }
    }

    fn record_use(&mut self, tree: &syn::UseTree, prefix: &mut Vec<String>) {
        match tree {
            syn::UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                self.record_use(&path.tree, prefix);
                prefix.pop();
            }
            syn::UseTree::Name(name) => {
                let ident = name.ident.to_string();
                if is_std_fs(prefix)
                    && let Some(known) = FS_FUNCTIONS.iter().copied().find(|k| *k == ident)
                {
                    self.imports.insert(ident, known);
                }
            }
            syn::UseTree::Rename(rename) => {
                let ident = rename.ident.to_string();
                if is_std_fs(prefix)
                    && let Some(known) = FS_FUNCTIONS.iter().copied().find(|k| *k == ident)
                {
                    self.imports.insert(rename.rename.to_string(), known);
                }
                // `use std::fs as filesystem;`: the module under another name.
                if prefix.len() == 1 && prefix[0] == "std" && ident == "fs" {
                    self.module_aliases.insert(rename.rename.to_string());
                }
            }
            syn::UseTree::Group(group) => {
                for tree in &group.items {
                    self.record_use(tree, prefix);
                }
            }
            syn::UseTree::Glob(_) => {
                if is_std_fs(prefix) {
                    for known in FS_FUNCTIONS {
                        self.imports.insert((*known).to_owned(), known);
                    }
                }
            }
        }
    }
}

fn is_std_fs(prefix: &[String]) -> bool {
    matches!(
        prefix
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice(),
        ["std", "fs"] | ["fs"]
    )
}

/// Whether an item is compiled only for tests: `#[cfg(test)]`, or `all(..)`/`any(..)` with
/// `test` as a direct leaf. `not(test)` and a feature whose name contains `test` are production.
fn is_test_gated(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr
                .parse_args::<syn::Meta>()
                .is_ok_and(|meta| cfg_is_test(&meta))
    })
}

fn cfg_is_test(meta: &syn::Meta) -> bool {
    match meta {
        syn::Meta::Path(path) => path.is_ident("test"),
        syn::Meta::List(list) if list.path.is_ident("all") || list.path.is_ident("any") => list
            .parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            )
            .is_ok_and(|leaves| leaves.iter().any(cfg_is_test)),
        _ => false,
    }
}

impl<'ast> Visit<'ast> for Scanner<'_> {
    /// An attribute's literals are documentation and configuration, never a file name.
    fn visit_attribute(&mut self, _: &'ast syn::Attribute) {}

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if is_test_gated(&item.attrs) {
            return;
        }
        self.record_use(&item.tree, &mut Vec::new());
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if is_test_gated(&item.attrs) {
            return;
        }
        self.item.push(item.ident.to_string());
        syn::visit::visit_item_mod(self, item);
        self.item.pop();
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if is_test_gated(&item.attrs) {
            return;
        }
        self.item.push(item.sig.ident.to_string());
        syn::visit::visit_item_fn(self, item);
        self.item.pop();
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if is_test_gated(&item.attrs) {
            return;
        }
        let name = match &*item.self_ty {
            syn::Type::Path(path) => path
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default(),
            _ => "<impl>".to_owned(),
        };
        self.item.push(name);
        syn::visit::visit_item_impl(self, item);
        self.item.pop();
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if is_test_gated(&item.attrs) {
            return;
        }
        self.item.push(item.sig.ident.to_string());
        syn::visit::visit_impl_item_fn(self, item);
        self.item.pop();
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if is_test_gated(&item.attrs) {
            return;
        }
        self.item.push(item.sig.ident.to_string());
        syn::visit::visit_trait_item_fn(self, item);
        self.item.pop();
    }

    fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
        if is_test_gated(&item.attrs) {
            return;
        }
        self.item.push(item.ident.to_string());
        syn::visit::visit_item_const(self, item);
        self.item.pop();
    }

    fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
        if is_test_gated(&item.attrs) {
            return;
        }
        self.item.push(item.ident.to_string());
        syn::visit::visit_item_static(self, item);
        self.item.pop();
    }

    /// Every path expression: a call's function, a function pointer taken, a method named as a
    /// function.
    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        let line = path
            .path
            .segments
            .last()
            .map_or(0, |s| s.ident.span().start().line);
        if let Some(function) = self.fs_function(&path.path) {
            self.report(line, function, format!("`std::fs::{function}`"));
        } else if let Some((primitive, method)) = Self::method_as_function(&path.path) {
            self.report(line, primitive, format!("`{method}` named as a function"));
        }
        syn::visit::visit_expr_path(self, path);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.scan_tokens(mac.tokens.clone());
        syn::visit::visit_macro(self, mac);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let method = call.method.to_string();
        if FLUSHES.contains(&method.as_str()) {
            self.report(
                call.method.span().start().line,
                "flush",
                format!("a method call `.{method}()`"),
            );
        } else if method == "set_len" {
            self.report(
                call.method.span().start().line,
                "truncate",
                "a method call `.set_len(..)`".to_owned(),
            );
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
        self.judge_literal(&literal.value(), literal.span().start().line);
    }
}
