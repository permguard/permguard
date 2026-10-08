// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The mutation engine as the only writer of security state (WP-3.6).
//!
//! A domain's mutators take the engine's token, `Applying`, which only the engine builds. This
//! check reads every crate's source as a syntax tree and keeps it so:
//!
//! | Rule                 | A violation                                                                   |
//! | -------------------- | ----------------------------------------------------------------------------- |
//! | token built          | a struct expression of the token outside the engine, however it was imported   |
//! | token forged         | a function outside the engine returning the token, or an `impl` of it there     |
//! | token copied         | `Clone`, `Copy` or `Default` derived on the token or implemented for it          |
//! | state written        | in a guarded store, a call that writes its state, inside a function that does not take the token |
//! | state reached        | in a guarded store, its state's field reached inside a function that does not take the token  |
//!
//! `use …::Applying as Token` is resolved, so a renamed import is the token; a function holds the
//! token only when a parameter is exactly `&Applying<'_>`, not an `Option` of it or a type that
//! merely names it. An append inside a wrapper function, whatever it is called, needs the token
//! in that wrapper's own signature; a wrapper elsewhere still reaches the state's field here,
//! which is judged the same way. Macro arguments are read token by token. Test code
//! (`#[cfg(test)]` items and the files their `mod name;` loads) is not scanned. A file the parser
//! does not read is reported, not skipped. `mutations.json` names the engine, the token and
//! every guarded store with the calls that write it, the fields that hold it, and the functions
//! that may reach it without a token, each with its reason.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Deserialize;
use syn::visit::Visit;

use crate::durability::{Violation, is_test_gated, sources, test_module_files};

/// A function of a guarded store that may reach its state without the token.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Exempt {
    pub item: String,
    pub reason: String,
}

/// One store the engine guards.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Guarded {
    /// The file, from the workspace root.
    pub source: String,
    /// The method and function names that write its state.
    pub calls: Vec<String>,
    /// The fields that hold it.
    #[serde(default)]
    pub fields: Vec<String>,
    /// The functions that reach it without a token: reading it, or rewriting what it holds.
    #[serde(default)]
    pub exempt: Vec<Exempt>,
    /// What those calls write.
    pub state: String,
}

/// `mutations.json`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Rules {
    /// The engine's file, the one place the token is built.
    pub engine: String,
    /// The token's type name.
    pub token: String,
    pub guarded: Vec<Guarded>,
}

/// Reads `mutations.json` beside this crate.
pub fn rules(root: &Path) -> Result<Rules, String> {
    let path = root.join("crates/permguard-conformance/mutations.json");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// The violations in the sources under `root`, and every guarded store that no longer writes
/// through the calls `rules` names (a stale rule guards nothing).
pub fn check(root: &Path, rules: &Rules) -> Vec<Violation> {
    let sources = sources(root);
    let mut test_files = BTreeSet::new();
    for path in &sources {
        if let Ok(text) = std::fs::read_to_string(path) {
            test_files.extend(test_module_files(path, &text));
        }
    }
    let mut found = Vec::new();
    let mut writes = BTreeSet::new();
    for path in sources {
        if test_files.contains(&path) {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let scanned = scan(&relative, &text, rules);
        if scanned.writes > 0 {
            writes.insert(relative.clone());
        }
        found.extend(scanned.violations);
    }
    for guarded in &rules.guarded {
        if !writes.contains(&guarded.source) {
            found.push(Violation {
                source: guarded.source.clone(),
                line: 0,
                item: "<file>".to_owned(),
                primitive: "stale rule".to_owned(),
                detail: format!(
                    "`mutations.json` guards {} through {:?}, and the file makes no such call",
                    guarded.state, guarded.calls
                ),
            });
        }
    }
    found.sort();
    found
}

/// What one file holds.
#[derive(Debug, Default)]
pub struct Scanned {
    pub violations: Vec<Violation>,
    /// How many guarded writes it makes, inside functions that take the token.
    pub writes: usize,
}

/// The violations in one file's source, `source` being its path from the workspace root.
pub fn scan(source: &str, text: &str, rules: &Rules) -> Scanned {
    let file = match syn::parse_file(text) {
        Ok(file) => file,
        Err(error) => {
            return Scanned {
                violations: vec![Violation {
                    source: source.to_owned(),
                    line: error.span().start().line,
                    item: "<file>".to_owned(),
                    primitive: "unparsed".to_owned(),
                    detail: format!("the file does not parse: {error}"),
                }],
                writes: 0,
            };
        }
    };
    let mut scanner = Scanner {
        source,
        engine: source == rules.engine,
        guarded: rules
            .guarded
            .iter()
            .find(|guarded| guarded.source == source),
        tokens: BTreeSet::from([rules.token.clone()]),
        item: Vec::new(),
        holding: Vec::new(),
        scanned: Scanned::default(),
    };
    // Renamed imports first, wherever they sit in the file.
    for item in &file.items {
        if let syn::Item::Use(import) = item {
            scanner.aliases(&import.tree, &rules.token);
        }
    }
    scanner.visit_file(&file);
    scanner.scanned
}

struct Scanner<'a> {
    source: &'a str,
    /// This file is the engine.
    engine: bool,
    /// This file is a guarded store.
    guarded: Option<&'a Guarded>,
    /// The names the token goes by here.
    tokens: BTreeSet<String>,
    /// The enclosing items, for the report.
    item: Vec<String>,
    /// Whether each enclosing function takes the token.
    holding: Vec<bool>,
    scanned: Scanned,
}

impl Scanner<'_> {
    fn aliases(&mut self, tree: &syn::UseTree, token: &str) {
        match tree {
            syn::UseTree::Path(path) => self.aliases(&path.tree, token),
            syn::UseTree::Rename(rename) if rename.ident == token => {
                self.tokens.insert(rename.rename.to_string());
            }
            syn::UseTree::Group(group) => {
                for tree in &group.items {
                    self.aliases(tree, token);
                }
            }
            _ => {}
        }
    }

    fn report(&mut self, line: usize, rule: &str, detail: String) {
        self.scanned.violations.push(Violation {
            source: self.source.to_owned(),
            line,
            item: self
                .item
                .last()
                .cloned()
                .unwrap_or_else(|| "<file>".to_owned()),
            primitive: rule.to_owned(),
            detail,
        });
    }

    /// Whether `ty` is exactly a reference to the token.
    fn is_token_reference(&self, ty: &syn::Type) -> bool {
        match ty {
            syn::Type::Reference(reference) => match &*reference.elem {
                syn::Type::Path(path) => path.qself.is_none() && self.is_token_path(&path.path),
                _ => false,
            },
            syn::Type::Paren(inner) => self.is_token_reference(&inner.elem),
            _ => false,
        }
    }

    /// Whether the enclosing function may reach the guarded state: it takes the token, or it is
    /// exempt by name.
    fn allowed(&self) -> bool {
        self.holding.last().copied().unwrap_or(false)
            || self.guarded.is_some_and(|guarded| {
                self.item
                    .last()
                    .is_some_and(|item| guarded.exempt.iter().any(|exempt| &exempt.item == item))
            })
    }

    fn mentions(&self, ty: &syn::Type) -> bool {
        struct Finder<'n> {
            names: &'n BTreeSet<String>,
            found: bool,
        }
        impl<'ast> Visit<'ast> for Finder<'_> {
            fn visit_path_segment(&mut self, segment: &'ast syn::PathSegment) {
                if self.names.contains(&segment.ident.to_string()) {
                    self.found = true;
                }
                syn::visit::visit_path_segment(self, segment);
            }
        }
        let mut finder = Finder {
            names: &self.tokens,
            found: false,
        };
        finder.visit_type(ty);
        finder.found
    }

    fn is_token_path(&self, path: &syn::Path) -> bool {
        path.segments
            .last()
            .is_some_and(|segment| self.tokens.contains(&segment.ident.to_string()))
    }

    /// Enters a function: its name, whether it takes the token, and whether it hands one out.
    fn function(
        &mut self,
        name: String,
        signature: &syn::Signature,
        line: usize,
        visit: impl FnOnce(&mut Self),
    ) {
        let holding = signature.inputs.iter().any(|input| match input {
            syn::FnArg::Typed(typed) => self.is_token_reference(&typed.ty),
            syn::FnArg::Receiver(_) => false,
        });
        if !self.engine
            && let syn::ReturnType::Type(_, ty) = &signature.output
            && self.mentions(ty)
        {
            self.item.push(name.clone());
            self.report(
                line,
                "token forged",
                "a function outside the engine hands out the token".to_owned(),
            );
            self.item.pop();
        }
        self.item.push(name);
        self.holding.push(holding);
        visit(self);
        self.holding.pop();
        self.item.pop();
    }

    fn write(&mut self, method: &str, line: usize) {
        let Some(guarded) = self.guarded else {
            return;
        };
        if !guarded.calls.iter().any(|call| call == method) {
            return;
        }
        if self.allowed() {
            self.scanned.writes += 1;
        } else {
            let state = guarded.state.clone();
            self.report(
                line,
                "state written",
                format!(
                    "`{method}` writes {state} inside a function that does not take the engine's token"
                ),
            );
        }
    }
}

impl<'ast> Visit<'ast> for Scanner<'_> {
    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        if is_test_gated(&module.attrs) {
            return;
        }
        self.item.push(module.ident.to_string());
        syn::visit::visit_item_mod(self, module);
        self.item.pop();
    }

    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        if is_test_gated(&function.attrs) {
            return;
        }
        let line = function.sig.ident.span().start().line;
        self.function(
            function.sig.ident.to_string(),
            &function.sig,
            line,
            |scanner| {
                syn::visit::visit_item_fn(scanner, function);
            },
        );
    }

    fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
        if is_test_gated(&function.attrs) {
            return;
        }
        let line = function.sig.ident.span().start().line;
        self.function(
            function.sig.ident.to_string(),
            &function.sig,
            line,
            |scanner| {
                syn::visit::visit_impl_item_fn(scanner, function);
            },
        );
    }

    fn visit_trait_item_fn(&mut self, function: &'ast syn::TraitItemFn) {
        if is_test_gated(&function.attrs) {
            return;
        }
        let line = function.sig.ident.span().start().line;
        self.function(
            function.sig.ident.to_string(),
            &function.sig,
            line,
            |scanner| {
                syn::visit::visit_trait_item_fn(scanner, function);
            },
        );
    }

    fn visit_item_impl(&mut self, block: &'ast syn::ItemImpl) {
        if is_test_gated(&block.attrs) {
            return;
        }
        if self.mentions(&block.self_ty) {
            let line = block.impl_token.span.start().line;
            match &block.trait_ {
                Some((_, path, _))
                    if path.segments.last().is_some_and(|segment| {
                        matches!(
                            segment.ident.to_string().as_str(),
                            "Clone" | "Copy" | "Default"
                        )
                    }) =>
                {
                    self.report(
                        line,
                        "token copied",
                        "the token implements a trait that makes one from another or from nothing"
                            .to_owned(),
                    );
                }
                None if !self.engine => self.report(
                    line,
                    "token forged",
                    "an inherent `impl` of the token outside the engine".to_owned(),
                ),
                _ => {}
            }
        }
        syn::visit::visit_item_impl(self, block);
    }

    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        if self.tokens.contains(&item.ident.to_string()) {
            for attr in &item.attrs {
                if !attr.path().is_ident("derive") {
                    continue;
                }
                let derived = attr
                    .parse_args_with(
                        syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
                    )
                    .map(|paths| {
                        paths
                            .iter()
                            .filter_map(|path| path.segments.last())
                            .map(|segment| segment.ident.to_string())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                if let Some(copied) = derived
                    .iter()
                    .find(|name| matches!(name.as_str(), "Clone" | "Copy" | "Default"))
                {
                    self.report(
                        item.ident.span().start().line,
                        "token copied",
                        format!("the token derives `{copied}`"),
                    );
                }
            }
        }
        syn::visit::visit_item_struct(self, item);
    }

    fn visit_expr_struct(&mut self, expression: &'ast syn::ExprStruct) {
        if !self.engine && self.is_token_path(&expression.path) {
            let line = expression
                .path
                .segments
                .last()
                .map_or(0, |segment| segment.ident.span().start().line);
            self.report(
                line,
                "token built",
                "the engine's token is built outside the engine".to_owned(),
            );
        }
        syn::visit::visit_expr_struct(self, expression);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.write(&call.method.to_string(), call.method.span().start().line);
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func
            && let Some(segment) = path.path.segments.last()
        {
            // `Journal::append(&mut journal, …)`: judged here, and its path not again below.
            self.write(
                &segment.ident.to_string(),
                segment.ident.span().start().line,
            );
            for argument in &call.args {
                self.visit_expr(argument);
            }
            return;
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if let Some(guarded) = self.guarded
            && let syn::Member::Named(name) = &field.member
            && guarded.fields.iter().any(|held| name == held)
            && !self.allowed()
        {
            let state = guarded.state.clone();
            self.report(
                name.span().start().line,
                "state reached",
                format!(
                    "`{name}` holds {state}, reached inside a function that does not take the engine's token"
                ),
            );
        }
        syn::visit::visit_expr_field(self, field);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if let Some(guarded) = self.guarded
            && !self.allowed()
        {
            let mut names = Vec::new();
            idents(mac.tokens.clone(), &mut names);
            if let Some(name) = names.iter().find(|name| {
                guarded.calls.iter().any(|call| call == *name)
                    || guarded.fields.iter().any(|field| field == *name)
            }) {
                let state = guarded.state.clone();
                let line = mac
                    .path
                    .segments
                    .last()
                    .map_or(0, |segment| segment.ident.span().start().line);
                self.report(
                    line,
                    "state written",
                    format!(
                        "a macro names `{name}`, which reaches {state}, inside a function that does not take the engine's token"
                    ),
                );
            }
        }
        syn::visit::visit_macro(self, mac);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        // A method named as a value, `let write = Journal::append;`, is a write by another name.
        if let Some(segment) = path.path.segments.last()
            && path.path.segments.len() > 1
        {
            self.write(
                &segment.ident.to_string(),
                segment.ident.span().start().line,
            );
        }
        syn::visit::visit_expr_path(self, path);
    }
}

/// Every identifier of a token stream, groups included.
fn idents(tokens: proc_macro2::TokenStream, into: &mut Vec<String>) {
    for tree in tokens {
        match tree {
            proc_macro2::TokenTree::Ident(ident) => into.push(ident.to_string()),
            proc_macro2::TokenTree::Group(group) => idents(group.stream(), into),
            _ => {}
        }
    }
}
