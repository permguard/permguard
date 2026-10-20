// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Only the catalog facade writes the catalog (WP-7.3a, owner decision of 2026-10-20).
//!
//! The `Catalog` trait lives in `permguard-core`, which cannot name the Host's `Applying` token,
//! so the type system does not hold that a zone or a ledger changes only inside the WP-3.6
//! transaction, as it holds it for grants and refs. This check holds it instead: it reads every
//! crate's production source as a syntax tree and finds each call of a writing method, as a
//! method call, a path call or a function pointer, outside the files listed in [`ALLOWED`].
//! Test code is not scanned, as in [`crate::durability`].
//!
//! The names are matched without types: the Control Plane's API client has methods of the same
//! names, which send a request to the facade rather than write the store, so its files are
//! listed too.
//!
//! What it does not see, by construction: a call inside a macro whose body does not read as a
//! list of expressions, a write in a file the allow-list names (the whole of the API client's
//! sources and the CLI's catalog commands), and a write through a method under another name
//! that wraps one of these in an allowed file.

use std::collections::BTreeSet;
use std::path::Path;

use syn::visit::Visit;

use crate::durability::{is_test_gated, sources, test_module_files};

/// The catalog's writing methods: the plain ones and the ones carrying a revision and an
/// operation id.
pub const WRITES: &[&str] = &[
    "create_zone",
    "rename_zone",
    "delete_zone",
    "create_ledger",
    "rename_ledger",
    "delete_ledger",
    "create_zone_with",
    "rename_zone_with",
    "delete_zone_with",
    "create_ledger_with",
    "rename_ledger_with",
    "delete_ledger_with",
];

/// The files that may call a writing method, each with why.
pub const ALLOWED: &[(&str, &str)] = &[
    (
        "crates/permguard-control-plane/src/catalog/zones.rs",
        "the facade: every write runs inside `CatalogFacade::mutate`, the WP-3.6 transaction",
    ),
    (
        "crates/permguard-control-plane/src/catalog/ledgers.rs",
        "the facade: every write runs inside `CatalogFacade::mutate`, the WP-3.6 transaction",
    ),
    (
        "crates/permguard-core/src/catalog.rs",
        "the trait: a plain method delegates to the one carrying a revision",
    ),
    (
        "crates/permguard-control-client/src/",
        "the API's client: a request to the facade, not a write of the store",
    ),
    (
        "crates/permguard-cli/src/commands/catalog.rs",
        "the CLI's catalog commands, through the API's client",
    ),
];

/// This file: it names the methods it looks for.
const SELF: &str = "crates/permguard-conformance/src/catalog_writers.rs";

/// One call of a writing method outside the allowed files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Write {
    pub source: String,
    pub line: usize,
    pub method: String,
}

impl std::fmt::Display for Write {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}: `{}` writes the catalog outside its facade",
            self.source, self.line, self.method
        )
    }
}

/// The calls of a writing method in the production sources under `root` outside [`ALLOWED`],
/// and a file this build's parser does not read.
pub fn check(root: &Path) -> Vec<Write> {
    let sources = sources(root);
    let mut test_files = BTreeSet::new();
    for path in &sources {
        if let Ok(text) = std::fs::read_to_string(path) {
            test_files.extend(test_module_files(path, &text));
        }
    }
    let mut found = Vec::new();
    for path in sources {
        if test_files.contains(&path) {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if relative == SELF
            || ALLOWED
                .iter()
                .any(|(allowed, _)| relative.starts_with(allowed))
        {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        found.extend(scan(&relative, &text));
    }
    found
}

/// The calls of a writing method in one file's production source.
pub fn scan(source: &str, text: &str) -> Vec<Write> {
    let file = match syn::parse_file(text) {
        Ok(file) => file,
        Err(error) => {
            return vec![Write {
                source: source.to_owned(),
                line: error.span().start().line,
                method: format!("<unparsed: {error}>"),
            }];
        }
    };
    let mut scanner = Scanner {
        source,
        found: Vec::new(),
    };
    scanner.visit_file(&file);
    scanner.found
}

struct Scanner<'a> {
    source: &'a str,
    found: Vec<Write>,
}

impl Scanner<'_> {
    fn judge(&mut self, ident: &syn::Ident) {
        let name = ident.to_string();
        if WRITES.contains(&name.as_str()) {
            self.found.push(Write {
                source: self.source.to_owned(),
                line: ident.span().start().line,
                method: name,
            });
        }
    }
}

impl<'ast> Visit<'ast> for Scanner<'_> {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if !is_test_gated(&item.attrs) {
            syn::visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if !is_test_gated(&item.attrs) {
            syn::visit::visit_item_fn(self, item);
        }
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if !is_test_gated(&item.attrs) {
            syn::visit::visit_item_impl(self, item);
        }
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if !is_test_gated(&item.attrs) {
            syn::visit::visit_impl_item_fn(self, item);
        }
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if !is_test_gated(&item.attrs) {
            syn::visit::visit_trait_item_fn(self, item);
        }
    }

    /// `catalog.create_zone(..)`.
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.judge(&call.method);
        syn::visit::visit_expr_method_call(self, call);
    }

    /// `Catalog::create_zone(&*catalog, ..)`, `<FileCatalog as Catalog>::create_zone(..)`, and
    /// the method taken as a function pointer. A bare path of one segment is a local function, a
    /// handler named like the operation: a trait's method cannot be imported bare.
    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if (path.qself.is_some() || path.path.segments.len() > 1)
            && let Some(last) = path.path.segments.last()
        {
            self.judge(&last.ident);
        }
        syn::visit::visit_expr_path(self, path);
    }

    /// A macro's tokens, read as an expression list when they parse as one: `assert!(..)`.
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if let Ok(exprs) = mac.parse_body_with(
            syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated,
        ) {
            for expr in &exprs {
                self.visit_expr(expr);
            }
        }
    }
}
