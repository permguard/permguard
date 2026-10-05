// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A Rego module as Regorus's parser reads it: its package, the rules and functions it declares,
//! the functions it calls, and the alias its package metadata carries.
//!
//! Everything here comes from the parsed tree (`Engine::get_ast_as_json`), never from scanning the
//! source: identity, package ownership, which rules a module answers and which built-ins it uses
//! are what the parser decided the module says (REGO-04, REGO-05, REGO-07). The one thing the
//! parser does not model is the `# METADATA` comment block, so the alias is read from the comment
//! lines that head the package the parser located, and nowhere else.

use std::collections::BTreeSet;

use serde_json::Value;

/// The built-ins a module may call: every built-in of the pinned Regorus except the ones that read
/// the clock, draw randomness, reach the network or the environment, sleep, write outside the
/// decision, or compile a schema whose `$ref` could name a remote document (REGO-01, LANG-03).
///
/// A positive list: a built-in a later Regorus adds is refused until it is reviewed and listed
/// here, and a test proves every name is one the pinned engine knows.
pub const ALLOWED_BUILTINS: &[&str] = &[
    "__builtin_sets.intersection",
    "__builtin_sets.union",
    "abs",
    "array.concat",
    "array.reverse",
    "array.slice",
    "base64.decode",
    "base64.encode",
    "base64.is_valid",
    "base64url.decode",
    "base64url.encode",
    "base64url.encode_no_pad",
    "bits.and",
    "bits.lsh",
    "bits.negate",
    "bits.or",
    "bits.rsh",
    "bits.xor",
    "ceil",
    "concat",
    "contains",
    "count",
    "endswith",
    "floor",
    "format_int",
    "glob.match",
    "glob.quote_meta",
    "graph.reachable",
    "graph.reachable_paths",
    "hex.decode",
    "hex.encode",
    "indexof",
    "indexof_n",
    "intersection",
    "is_array",
    "is_boolean",
    "is_null",
    "is_number",
    "is_object",
    "is_set",
    "is_string",
    "json.filter",
    "json.is_valid",
    "json.marshal",
    "json.marshal_with_options",
    "json.patch",
    "json.remove",
    "json.unmarshal",
    "lower",
    "max",
    "min",
    "net.cidr_contains",
    "net.cidr_expand",
    "net.cidr_is_valid",
    "numbers.range",
    "numbers.range_step",
    "object.filter",
    "object.get",
    "object.keys",
    "object.remove",
    "object.subset",
    "object.union",
    "object.union_n",
    "print",
    "product",
    "regex.find_n",
    "regex.is_valid",
    "regex.match",
    "regex.replace",
    "regex.split",
    "regex.template_match",
    "replace",
    "round",
    "semver.compare",
    "semver.is_valid",
    "sort",
    "split",
    "sprintf",
    "startswith",
    "strings.any_prefix_match",
    "strings.any_suffix_match",
    "strings.count",
    "strings.replace_n",
    "strings.reverse",
    "substring",
    "sum",
    "time.add_date",
    "time.clock",
    "time.date",
    "time.diff",
    "time.format",
    "time.parse_duration_ns",
    "time.parse_ns",
    "time.parse_rfc3339_ns",
    "time.weekday",
    "to_number",
    "trim",
    "trim_left",
    "trim_prefix",
    "trim_right",
    "trim_space",
    "trim_suffix",
    "type_name",
    "union",
    "units.parse",
    "units.parse_bytes",
    "upper",
    "urlquery.decode",
    "urlquery.decode_object",
    "urlquery.encode",
    "urlquery.encode_object",
    "uuid.parse",
    "walk",
    "yaml.is_valid",
    "yaml.marshal",
    "yaml.unmarshal",
];

/// The built-ins the owner's decision names as refused: with [`ALLOWED_BUILTINS`], every built-in
/// the pinned Regorus registers.
///
/// A call is checked against the positive list. A `with … as` replacement is checked against this
/// one, because its value may equally be a local variable: Regorus treats it as a function only
/// when it resolves to no value and names a built-in, so naming a refused one is what is refused.
pub const REFUSED_BUILTINS: &[&str] = &[
    "time.now_ns",
    "rand.intn",
    "uuid.rfc4122",
    "http.send",
    "opa.runtime",
    "test.sleep",
    "trace",
    "json.match_schema",
    "json.verify_schema",
];

/// How large a package's `# METADATA` block may be, in bytes of YAML.
const MAX_METADATA_BYTES: usize = 16 * 1024;

/// How deep brackets — `[`, `{` and `(` — may nest in a module.
///
/// Regorus's parser recurses on nesting, and the check runs before it does, wherever a module is
/// parsed: authoring, the Control Plane's acceptance of a push, the Data Plane's load.
pub const MAX_NESTING: usize = 16;

/// How much parse work a module may cost: the sum over its bytes of `2^depth - 1`, where only `[`
/// and `{` count toward the depth.
///
/// Regorus parses a nested array, object or set literal at a cost that doubles with every level
/// and multiplies by the content inside it: one literal 16 levels deep takes about 24 ms, the same
/// literal holding a thousand elements about 2 s, one 24 levels deep about 33 s. The weight of a
/// byte is the factor its depth costs, so the budget bounds the parse at about a second, while a
/// real policy nesting literals a few levels deep stays far below it.
pub const MAX_PARSE_WORK: u64 = 1 << 21;

/// One module, as the parser reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    /// The package path as Regorus reports it, `data.billing`: the one value every gate uses.
    pub package: String,
    /// The 1-based line the `package` keyword is on.
    pub package_line: usize,
    /// Every rule the module declares, by its head path relative to the package: `allow`, `deny`.
    pub rules: BTreeSet<String>,
    /// The functions the module defines, which its own calls may name.
    pub functions: BTreeSet<String>,
    /// Every function the module calls, by the dotted name it is called with.
    pub calls: BTreeSet<String>,
    /// Every name a `with … as` substitutes, by its dotted path: what a replaced function or
    /// built-in would dispatch to.
    pub replacements: BTreeSet<String>,
}

/// Refuses a module that nests deeper than [`MAX_NESTING`] or costs more than [`MAX_PARSE_WORK`]
/// to parse, scanning outside strings and comments, where a bracket is syntax.
///
/// Every byte counts toward the work at the depth it sits at, the bytes of a string included: a
/// string inside a literal is content the parser carries through every level around it.
pub fn check_nesting(source: &str) -> Result<(), String> {
    // Every open bracket, and whether it is a literal's — the levels the work's depth counts.
    let mut open: Vec<bool> = Vec::new();
    let (mut deepest, mut levels, mut work) = (0usize, 0usize, 0u64);
    let (mut string, mut raw, mut escaped, mut comment) = (false, false, false, false);
    for c in source.bytes() {
        work = work.saturating_add((1u64 << levels.min(63)) - 1);
        if comment {
            comment = c != b'\n';
        } else if raw {
            raw = c != b'`';
        } else if string {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                string = false;
            }
        } else {
            match c {
                b'"' => string = true,
                b'`' => raw = true,
                b'#' => comment = true,
                b'[' | b'{' | b'(' => {
                    open.push(c != b'(');
                    levels += usize::from(c != b'(');
                }
                b']' | b'}' | b')' => levels -= usize::from(open.pop() == Some(true)),
                _ => {}
            }
            deepest = deepest.max(open.len());
        }
        if deepest > MAX_NESTING {
            return Err(format!(
                "rego: the module nests brackets more than the {MAX_NESTING} levels a module may"
            ));
        }
        if work > MAX_PARSE_WORK {
            return Err(format!(
                "rego: the module's nested literals cost more to parse than a module may: the \
                 work, each byte weighted by 2^depth - 1, passes {MAX_PARSE_WORK}"
            ));
        }
    }

    Ok(())
}

/// Parses one module with Regorus and reads its tree: the nesting and parse-work bounds first, then
/// the parser on a stack segment sized for them.
pub fn parse(source: &str) -> Result<Parsed, String> {
    check_nesting(source)?;
    let mut engine = regorus::Engine::new();
    let package =
        crate::headroom::ample(|| engine.add_policy("policy.rego".to_owned(), source.to_owned()))
            .map_err(|error| format!("rego: {error}"))?;
    let tree = engine
        .get_ast_as_json()
        .map_err(|error| format!("rego: the parsed module cannot be read: {error}"))?;
    let tree: Value = serde_json::from_str(&tree)
        .map_err(|error| format!("rego: the parsed module cannot be read: {error}"))?;
    let ast = &tree[0]["ast"];

    let package_line = ast["package"]["span"]["line"]
        .as_u64()
        .and_then(|line| usize::try_from(line).ok())
        .ok_or_else(|| "rego: the module declares no package".to_owned())?;

    let mut rules = BTreeSet::new();
    let mut functions = BTreeSet::new();
    for rule in ast["rules"].as_array().into_iter().flatten() {
        if let Some(default) = rule.get("Default") {
            if let Some(name) = path(&default["refr"]) {
                rules.insert(name);
            }
        } else if let Some(spec) = rule.get("Spec") {
            for (kind, head) in spec["head"].as_object().into_iter().flatten() {
                let Some(name) = path(&head["refr"]) else {
                    continue;
                };
                if kind == "Func" {
                    functions.insert(name.clone());
                }
                rules.insert(name);
            }
        }
    }

    let (mut calls, mut replacements) = (BTreeSet::new(), BTreeSet::new());
    collect_calls(ast, &mut calls, &mut replacements)?;

    Ok(Parsed {
        package,
        package_line,
        rules,
        functions,
        calls,
        replacements,
    })
}

/// Refuses a module that calls a built-in outside [`ALLOWED_BUILTINS`].
///
/// A call is to a listed built-in, to a function the module defines, or to a document under
/// `data` — another package's function. Anything else is refused at load, so a name the pinned
/// engine leaves inert today cannot become active with an upgrade.
pub fn check_builtins(parsed: &Parsed) -> Result<(), String> {
    // `with lower as time.now_ns` dispatches `lower` to the clock without a call naming it.
    if let Some(name) = parsed
        .replacements
        .iter()
        .find(|name| REFUSED_BUILTINS.contains(&name.as_str()))
    {
        return Err(format!(
            "rego: `with … as {name}` substitutes a built-in this runtime refuses: only pure, \
             deterministic built-ins are allowed, so the clock, randomness, UUIDs, the network \
             and the environment cannot reach a decision"
        ));
    }
    for call in &parsed.calls {
        let allowed = ALLOWED_BUILTINS.contains(&call.as_str())
            || parsed.functions.contains(call)
            || call.starts_with("data.");
        if !allowed {
            return Err(format!(
                "rego: `{call}` is not a built-in this runtime allows: only pure, deterministic \
                 built-ins are, so the clock, randomness, UUIDs, the network and the environment \
                 cannot reach a decision"
            ));
        }
    }

    Ok(())
}

/// The alias the module's package metadata declares: `custom.alias` of the `# METADATA` block
/// whose comment lines end immediately above the `package` line.
///
/// A metadata block anywhere else — above a rule, after the package — annotates something else
/// and is never an alias. The block is YAML behind the `# ` prefix, bounded, parsed strictly; an
/// alias that is not a string or falls outside the identity grammar is refused, not ignored.
pub fn alias(source: &str, parsed: &Parsed) -> Result<Option<String>, String> {
    let lines: Vec<&str> = source.lines().collect();
    // The comment lines heading the package, nearest first.
    let mut block = Vec::new();
    let mut at = parsed.package_line.saturating_sub(1);
    while at > 0 {
        let line = lines.get(at - 1).map_or("", |line| line.trim());
        if !line.starts_with('#') {
            break;
        }
        block.push(line);
        at -= 1;
    }
    block.reverse();
    let Some(header) = block.iter().position(|line| *line == "# METADATA") else {
        return Ok(None);
    };
    let mut yaml = String::new();
    for line in &block[header + 1..] {
        let rest = line.trim_start_matches('#');
        yaml.push_str(rest.strip_prefix(' ').unwrap_or(rest));
        yaml.push('\n');
    }
    if yaml.len() > MAX_METADATA_BYTES {
        return Err(format!(
            "rego: the package metadata is {} bytes, more than the {MAX_METADATA_BYTES} allowed",
            yaml.len()
        ));
    }
    let metadata: serde_norway::Value = serde_norway::from_str(&yaml)
        .map_err(|error| format!("rego: the package metadata is not YAML: {error}"))?;
    // Package metadata only: a block that declares another scope is not about the package.
    // OPA admits `package` and `subpackages` above a package; `document` and `rule` annotate rules.
    if let Some(scope) = metadata.get("scope") {
        let scope = scope
            .as_str()
            .ok_or_else(|| "rego: the metadata `scope` is not a string".to_owned())?;
        if !matches!(scope, "package" | "subpackages") {
            return Ok(None);
        }
    }
    let Some(alias) = metadata
        .get("custom")
        .and_then(|custom| custom.get("alias"))
    else {
        return Ok(None);
    };
    let alias = alias
        .as_str()
        .ok_or_else(|| "rego: `custom.alias` is not a string".to_owned())?;
    crate::role::identity_alias(alias).map_err(|error| format!("rego: {error}"))?;

    Ok(Some(alias.to_owned()))
}

/// A reference as a dotted path: `allow`, `time.now_ns`, and `time["now_ns"]` as Regorus resolves
/// it, `time.now_ns`; `None` for one indexed by anything but a string.
fn path(reference: &Value) -> Option<String> {
    if let Some(var) = reference.get("Var") {
        return var["value"].as_str().map(ToOwned::to_owned);
    }
    if let Some(bracket) = reference.get("RefBrack") {
        let base = path(&bracket["refr"])?;
        let field = bracket["index"].get("String")?["value"].as_str()?;
        return Some(format!("{base}.{field}"));
    }
    let dot = reference.get("RefDot")?;
    let base = path(&dot["refr"])?;
    let field = dot["field"].get(1)?.as_str()?;

    Some(format!("{base}.{field}"))
}

/// Gathers every call and every `with … as` value in the tree. A call whose function is not a
/// path is refused rather than skipped: what it would dispatch to cannot be checked.
fn collect_calls(
    node: &Value,
    calls: &mut BTreeSet<String>,
    replacements: &mut BTreeSet<String>,
) -> Result<(), String> {
    match node {
        Value::Object(members) => {
            if let Some(call) = members.get("Call") {
                let name = path(&call["fcn"]).ok_or_else(|| {
                    "rego: a call names its function by an expression; only a path can be checked \
                     against the built-ins this runtime allows"
                        .to_owned()
                })?;
                calls.insert(name);
            }
            for modifier in members
                .get("with_mods")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                replacements.extend(path(&modifier["as"]));
            }
            for member in members.values() {
                collect_calls(member, calls, replacements)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_calls(item, calls, replacements)?;
            }
        }
        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODULE: &str = "# METADATA\n# custom:\n#   alias: billing-ro\npackage billing\nimport rego.v1\n\
default allow := false\nallow if { helper(input.x); count([1]) > 0 }\n\
deny contains msg if { msg := \"x\" }\nhelper(x) if { x > 1 }\n";

    fn nested(levels: usize, inner: &str) -> String {
        format!(
            "package p\nx := {}{inner}{}\n",
            "[".repeat(levels),
            "]".repeat(levels)
        )
    }

    #[test]
    fn brackets_nest_at_most_the_bound_and_deeper_is_refused_before_the_parser() {
        let deepest = nested(MAX_NESTING, "1");
        parse(&deepest).expect("a module at the bound parses");

        // Unparsable past the bound, so the error proves the scan refused it, not the parser: a
        // parenthesis counts as a level too.
        let deeper = format!("package p\nx := {}1", "(".repeat(MAX_NESTING + 1));
        let error = parse(&deeper).expect_err("one level past the bound is refused");
        assert!(error.contains("nests brackets"), "{error}");

        // A literal 24 levels deep takes Regorus about half a minute: refused at once instead.
        let started = std::time::Instant::now();
        let error = parse(&nested(24, "1")).expect_err("refused");
        assert!(error.contains("nests brackets"), "{error}");
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn many_moderately_nested_literals_exhaust_the_parse_work_budget() {
        // 12 levels is within the depth bound; the content multiplies the work by 2^12 a byte.
        let content = vec!["1"; 600].join(",");
        let heavy = nested(12, &content);
        check_nesting(&nested(12, "1")).expect("one such literal is cheap");
        let error = parse(&heavy).expect_err("its content passes the budget");
        assert!(error.contains("cost more to parse"), "{error}");

        // Ordinary policies stay far below it.
        check_nesting(MODULE).expect("a real module is within both bounds");
    }

    #[test]
    fn brackets_in_strings_raw_strings_and_comments_are_not_syntax() {
        let open = "[".repeat(MAX_NESTING * 4);
        let module = format!("package p\n# {open}\nx := \"{open}\\\"{open}\"\ny := `{open}`\n");
        parse(&module).expect("text is not nesting");
    }

    #[test]
    fn the_parsed_module_names_its_package_rules_functions_and_calls() {
        let parsed = parse(MODULE).expect("parses");
        assert_eq!(parsed.package, "data.billing");
        assert_eq!(parsed.package_line, 4);
        assert!(parsed.rules.contains("allow") && parsed.rules.contains("deny"));
        assert!(parsed.functions.contains("helper"));
        assert!(parsed.calls.contains("helper") && parsed.calls.contains("count"));
        assert!(check_builtins(&parsed).is_ok());
        assert_eq!(alias(MODULE, &parsed), Ok(Some("billing-ro".to_owned())));
    }

    /// REGO-01: a refused built-in, or one the list does not name, is refused at load; a function
    /// of another package is not a built-in.
    #[test]
    fn a_built_in_outside_the_allow_list_is_refused() {
        for call in REFUSED_BUILTINS {
            let source = format!("package p\nimport rego.v1\nallow if {{ x := {call}(1); x }}\n");
            let parsed = parse(&source).expect("parses");
            let refused = check_builtins(&parsed).expect_err("refused");
            assert!(refused.contains(call), "{refused}");
        }
        let other =
            parse("package p\nimport rego.v1\nallow if { data.lib.ok(1) }\n").expect("parses");
        assert!(check_builtins(&other).is_ok());
        let unknown = parse("package p\nimport rego.v1\nallow if { crypto.sha256(\"a\") }\n")
            .expect("parses");
        assert!(
            check_builtins(&unknown).is_err(),
            "an unlisted name is refused"
        );
    }

    /// A refused built-in reached by an indexed name or substituted with `with` is refused too:
    /// both dispatch to it without a call that spells it with dots.
    #[test]
    fn a_refused_built_in_named_by_index_or_substituted_is_refused() {
        for (source, named) in [
            ("x := time[\"now_ns\"]()", "time.now_ns"),
            ("x := rand[\"intn\"](\"a\", 9)", "rand.intn"),
            (
                "x := y if { y := print() with print as time.now_ns }",
                "time.now_ns",
            ),
            (
                "x := y if { y := lower(\"a\") with lower as uuid[\"rfc4122\"] }",
                "uuid.rfc4122",
            ),
            (
                "x := y if { y := indexof(\"a\", \"b\") with indexof as rand.intn }",
                "rand.intn",
            ),
        ] {
            let module = format!("package p\nimport rego.v1\n{source}\n");
            let parsed = parse(&module).unwrap_or_else(|error| panic!("{source}: {error}"));
            let refused = check_builtins(&parsed).expect_err(source);
            assert!(refused.contains(named), "{source}: {refused}");
        }

        // A call through an expression cannot be checked: Regorus refuses this one itself, and
        // `collect_calls` refuses any it would accept.
        parse("package p\nimport rego.v1\nx := time[input.f]()\n")
            .expect_err("an indexed call by expression is refused");

        // Replacing a document with a value, or a built-in with an allowed one, stays allowed.
        let fine = parse(
            "package p\nimport rego.v1\nx := y if { y := lower(\"a\") with input.u as \"b\" with lower as upper }\n",
        )
        .expect("parses");
        check_builtins(&fine).expect("allowed");
    }

    /// The allow-list names only built-ins the pinned engine knows, and none of the refused ones.
    #[test]
    fn every_allowed_built_in_is_one_the_pinned_engine_knows() {
        for name in ALLOWED_BUILTINS
            .iter()
            .filter(|name| !name.starts_with("__"))
        {
            assert!(!REFUSED_BUILTINS.contains(name), "{name}");
            let mut engine = regorus::Engine::new();
            engine
                .add_policy(
                    "p.rego".to_owned(),
                    format!("package p\nimport rego.v1\nallow if {{ x := {name}(); x }}\n"),
                )
                .expect("parses");
            if let Err(error) = engine.eval_rule("data.p.allow".to_owned()) {
                assert!(
                    !error.to_string().contains("could not find function"),
                    "`{name}` is not a built-in of the pinned engine"
                );
            }
        }
    }

    /// REGO-04: only the block heading the package is its metadata; a block above a rule, a block
    /// declaring another scope and a detached block are not; a malformed or non-string alias is
    /// refused.
    #[test]
    fn only_the_metadata_heading_the_package_carries_its_alias() {
        let rule_scope = "package p\nimport rego.v1\n# METADATA\n# custom:\n#   alias: decoy\nallow if { true }\n";
        let parsed = parse(rule_scope).expect("parses");
        assert_eq!(alias(rule_scope, &parsed), Ok(None));

        let other_scope = "# METADATA\n# scope: rule\n# custom:\n#   alias: decoy\npackage p\n";
        let parsed = parse(other_scope).expect("parses");
        assert_eq!(alias(other_scope, &parsed), Ok(None));

        let document_scope =
            "# METADATA\n# scope: document\n# custom:\n#   alias: decoy\npackage p\n";
        let parsed = parse(document_scope).expect("parses");
        assert_eq!(alias(document_scope, &parsed), Ok(None));

        let odd_scope = "# METADATA\n# scope: 42\n# custom:\n#   alias: decoy\npackage p\n";
        let parsed = parse(odd_scope).expect("parses");
        assert!(
            alias(odd_scope, &parsed).is_err(),
            "a non-string scope is refused"
        );

        let detached = "# METADATA\n# custom:\n#   alias: decoy\n\npackage p\n";
        let parsed = parse(detached).expect("parses");
        assert_eq!(
            alias(detached, &parsed),
            Ok(None),
            "a blank line detaches the block"
        );

        for (source, why) in [
            (
                "# METADATA\n# custom:\n#   alias: 42\npackage p\n",
                "not a string",
            ),
            (
                "# METADATA\n# custom:\n#   alias: Not Valid\npackage p\n",
                "outside the grammar",
            ),
            ("# METADATA\n# custom: [unclosed\npackage p\n", "not YAML"),
        ] {
            let parsed = parse(source).expect("parses");
            assert!(alias(source, &parsed).is_err(), "{why}");
        }
    }
}
