// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The annotations of each policy of a Dogwood source, read as upstream's grammar reads them
//! (DOGWOOD-07, owner decision of 2026-10-21).
//!
//! # Why a reader of its own
//!
//! The alias of a Dogwood policy file is its `@id("…")` annotation, and an alias is identity. Upstream
//! parses annotations, but its public API exposes them only on the lowered set, and lowering needs
//! the action schema — which the place that asks for an alias, a source on its own, does not have.
//! Upstream also keeps a value's escapes verbatim and lets a repeated key pass, the last one winning.
//!
//! So this reads the prefix of each policy the way `parser/grammar.pest` describes it:
//!
//! ```text
//! policy     = annotation* effect "(" scope ")" cond* ";"
//! annotation = "@" any_ident ("(" string ")")?
//! def_decl   = "def" … ";"
//! string     = "\"" ("\\" ANY | !"\"" !"\\" ANY)* "\""
//! WHITESPACE = " " | "\t" | "\r" | "\n"
//! COMMENT    = "//" (!("\n" | "\r") ANY)*
//! ```
//!
//! An `@id` in a comment or in a string of a policy's body is text, not an annotation, and a
//! line-by-line search could not tell them apart. A value's escapes are decoded by Cedar's own
//! parser — the grammar's string is Cedar's — and the alias is then held to the common identity
//! grammar. Upstream's parse of the same source is the authority this mirrors: at compile, the
//! lowered set's annotations must name the same raw values policy by policy ([`agrees_with`]).
//!
//! Two bodies are raw text upstream, `block_inner`: a `temporal { … }` block and a `def`'s body.
//! Inside them only strings and balanced braces count, never a comment, and they are read so here.
//! A leading byte-order mark is dropped, as upstream drops it. Upstream's "raw" value is the string
//! with every leading and trailing quote trimmed, so `@id("a\"")` lowers as `a\`: this reader keeps
//! `a\"`, the two disagree, and the load is refused — never a different alias accepted.

/// The annotation that carries a policy's alias.
pub const ID: &str = "id";

/// One annotation as written: its key, and its value with the escapes as the source spells them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Annotation {
    pub key: String,
    pub raw: Option<String>,
}

/// The annotations of every policy of `source`, in source order; a macro declaration is not a
/// policy and has none.
pub fn read(source: &str) -> Result<Vec<Vec<Annotation>>, String> {
    let mut policies = Vec::new();
    let mut rest = skip_trivia(source.strip_prefix('\u{FEFF}').unwrap_or(source));
    while !rest.is_empty() {
        if keyword(rest, "def") {
            rest = skip_trivia(skip_statement(rest, true)?);
            continue;
        }
        let mut annotations = Vec::new();
        while let Some(after) = rest.strip_prefix('@') {
            let after = skip_trivia(after);
            let key_length = after
                .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
                .unwrap_or(after.len());
            let key = &after[..key_length];
            if key.is_empty() || key.starts_with(|character: char| character.is_ascii_digit()) {
                return Err("dogwood: an annotation names no key after `@`".to_owned());
            }
            rest = skip_trivia(&after[key_length..]);
            let mut raw = None;
            if let Some(after) = rest.strip_prefix('(') {
                let (value, after) = string(skip_trivia(after))?;
                let after = skip_trivia(after);
                rest = after.strip_prefix(')').ok_or_else(|| {
                    format!("dogwood: the annotation `@{key}` does not close its value")
                })?;
                raw = Some(value.to_owned());
            }
            annotations.push(Annotation {
                key: key.to_owned(),
                raw,
            });
            rest = skip_trivia(rest);
        }
        rest = skip_trivia(skip_statement(rest, false)?);
        policies.push(annotations);
    }

    Ok(policies)
}

/// The alias `source` declares: its one `@id`, decoded and held to the identity grammar.
///
/// A file is one stored unit with one alias (owner decision of 2026-10-21): a second `@id`, on
/// another policy or on the same one, is refused rather than resolved, and so is an `@id` without
/// a value. None is no alias.
pub fn alias(source: &str) -> Result<Option<String>, String> {
    alias_of(&read(source)?)
}

/// The alias of what [`read`] returned.
pub fn alias_of(policies: &[Vec<Annotation>]) -> Result<Option<String>, String> {
    let ids: Vec<&Option<String>> = policies
        .iter()
        .flatten()
        .filter(|annotation| annotation.key == ID)
        .map(|annotation| &annotation.raw)
        .collect();
    let raw = match ids.as_slice() {
        [] => return Ok(None),
        [Some(raw)] => raw,
        [None] => return Err("dogwood: `@id` names no value".to_owned()),
        _ => {
            return Err(format!(
                "dogwood: the file declares `@id` {} times, and a file is one policy unit with \
                 one alias: split it into one file per `@id`",
                ids.len()
            ));
        }
    };
    let alias = decode(raw)?;
    crate::role::identity_alias(&alias).map_err(|error| format!("dogwood: {error}"))?;

    Ok(Some(alias))
}

/// A string's raw contents, decoded by Cedar's own parser.
pub fn decode(raw: &str) -> Result<String, String> {
    let text = format!("@{ID}(\"{raw}\") permit (principal, action, resource);");
    let policy = cedar_policy::Policy::parse(None, &text)
        .map_err(|_| format!("dogwood: the `@{ID}` value `\"{raw}\"` is not a valid string"))?;

    policy
        .annotation(ID)
        .map(str::to_owned)
        .ok_or_else(|| format!("dogwood: the `@{ID}` value `\"{raw}\"` does not decode"))
}

/// Whether the raw `@id` of each policy, as this reader read it, is what upstream's parse gave the
/// lowered rule of the same index.
pub fn agrees_with(read: &[Option<String>], lowered: &[Option<String>]) -> Result<(), String> {
    if read == lowered {
        return Ok(());
    }

    Err(format!(
        "dogwood: the policies' `@{ID}` annotations read as {read:?} and upstream's parse lowered \
         them as {lowered:?}; an alias is identity, so the two must agree"
    ))
}

/// Whether `rest` starts with `word` followed by a word boundary.
fn keyword(rest: &str, word: &str) -> bool {
    rest.strip_prefix(word).is_some_and(|after| {
        !after.starts_with(|character: char| character.is_ascii_alphanumeric() || character == '_')
    })
}

/// Skips whitespace and line comments.
fn skip_trivia(source: &str) -> &str {
    let mut rest = source.trim_start_matches([' ', '\t', '\r', '\n']);
    while let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['\n', '\r']).unwrap_or(after.len());
        rest = after[end..].trim_start_matches([' ', '\t', '\r', '\n']);
    }
    rest
}

/// A string literal at the start of `rest`: its raw contents, and what follows it.
fn string(rest: &str) -> Result<(&str, &str), String> {
    let body = rest
        .strip_prefix('"')
        .ok_or_else(|| "dogwood: an annotation's value is not a string".to_owned())?;
    let mut escaped = false;
    for (at, character) in body.char_indices() {
        match character {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => return Ok((&body[..at], &body[at + 1..])),
            _ => {}
        }
    }

    Err("dogwood: a string is not closed".to_owned())
}

/// Skips one statement — a policy, or a macro declaration when `def` — through its closing
/// top-level `;`, stepping over strings, comments and brackets, and over the raw bodies upstream
/// reads as `block_inner`: a `temporal { … }` block, and a `def`'s body.
fn skip_statement(source: &str, def: bool) -> Result<&str, String> {
    let mut depth: usize = 0;
    let mut rest = source;
    let mut body_pending = def;
    // The identifier just read, if the last token was one: what tells `temporal {` apart.
    let mut word: Option<&str> = None;
    while let Some(character) = rest.chars().next() {
        if rest.starts_with("//") {
            let end = rest.find(['\n', '\r']).unwrap_or(rest.len());
            rest = &rest[end..];
            continue;
        }
        if character == '"' {
            rest = string(rest)?.1;
            word = None;
            continue;
        }
        if character.is_ascii_alphabetic() || character == '_' {
            let length = rest
                .find(|held: char| !(held.is_ascii_alphanumeric() || held == '_'))
                .unwrap_or(rest.len());
            word = Some(&rest[..length]);
            rest = &rest[length..];
            continue;
        }
        if matches!(character, ' ' | '\t' | '\r' | '\n') {
            rest = &rest[1..];
            continue;
        }
        match character {
            '{' if body_pending || word == Some("temporal") => {
                body_pending = false;
                word = None;
                rest = raw_block(rest)?;
                continue;
            }
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ';' if depth == 0 => return Ok(&rest[1..]),
            _ => {}
        }
        word = None;
        rest = &rest[character.len_utf8()..];
    }

    Err("dogwood: a policy is not closed with `;`".to_owned())
}

/// Skips a raw body from its `{` through its matching `}`: strings and nested braces count,
/// comments do not, as upstream's `block_inner` reads it.
fn raw_block(source: &str) -> Result<&str, String> {
    let mut depth: usize = 0;
    let mut rest = source;
    while let Some(character) = rest.chars().next() {
        if character == '"' {
            rest = string(rest)?.1;
            continue;
        }
        match character {
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Ok(&rest[1..]);
                }
            }
            _ => {}
        }
        rest = &rest[character.len_utf8()..];
    }

    Err("dogwood: a block is not closed with `}`".to_owned())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    const BODY: &str = "permit (principal, action, resource) when { true };\n";

    #[test]
    fn the_annotations_of_each_policy_are_read_where_the_grammar_puts_them() {
        let source = format!(
            "// @id(\"in-a-comment\")\n@id(\"first\")\n@advice ( \"a; b\" )\n@flag\n{BODY}\
             def cedar m(?x) {{ ?x == \"@id(\\\"no\\\")\" }};\n\
             permit (principal, action, resource) when {{ context.s == \"@id(\\\"in-a-string\\\");\" }};\n"
        );
        let policies = read(&source).expect("it reads");
        assert_eq!(policies.len(), 2, "the macro is not a policy");
        assert_eq!(
            policies[0],
            [
                Annotation {
                    key: "id".to_owned(),
                    raw: Some("first".to_owned())
                },
                Annotation {
                    key: "advice".to_owned(),
                    raw: Some("a; b".to_owned())
                },
                Annotation {
                    key: "flag".to_owned(),
                    raw: None
                },
            ]
        );
        assert!(
            policies[1].is_empty(),
            "text in a body is not an annotation"
        );
        assert_eq!(alias(&source).expect("one alias"), Some("first".to_owned()));
    }

    #[test]
    fn escapes_are_decoded_by_cedar_and_the_alias_holds_to_the_identity_grammar() {
        assert_eq!(
            alias(&format!("@id(\"read\\u{{2d}}after\")\n{BODY}")).expect("decoded"),
            Some("read-after".to_owned())
        );
        for refused in [
            "@id(\"Upper\")",
            "@id(\"\")",
            "@id(\"bad\\q\")",
            "@id(\"a b\")",
        ] {
            assert!(
                alias(&format!("{refused}\n{BODY}")).is_err(),
                "`{refused}` is refused"
            );
        }
    }

    #[test]
    fn a_file_carries_at_most_one_id_and_never_an_empty_one() {
        assert_eq!(alias(BODY).expect("none"), None);
        let twice_on_one = format!("@id(\"a\")\n@id(\"a\")\n{BODY}");
        let on_two = format!("@id(\"a\")\n{BODY}@id(\"b\")\n{BODY}");
        for refused in [twice_on_one, on_two] {
            let why = alias(&refused).expect_err("more than one");
            assert!(why.contains("2 times"), "{why}");
        }
        let empty = alias(&format!("@id\n{BODY}")).expect_err("no value");
        assert!(empty.contains("no value"), "{empty}");
    }

    #[test]
    fn a_comment_in_a_body_hides_its_semicolons_and_quotes() {
        let source = "@id(\"a\")\npermit (principal, action, resource)\nwhen { // a ; and a \" here\n  true\n};\n@advice(\"b\")\npermit (principal, action, resource);\n";
        let policies = read(source).expect("it reads");
        assert_eq!(policies.len(), 2, "{policies:?}");
        assert_eq!(policies[1][0].key, "advice");
    }

    /// After the review: a `temporal` block and a `def` body are raw text upstream, where `//` is
    /// not a comment; a leading byte-order mark is dropped; a key starts with a letter.
    #[test]
    fn raw_bodies_and_a_byte_order_mark_are_read_as_upstream_reads_them() {
        let temporal = "@id(\"a\")\npermit (principal, action, resource) when temporal { formerly within 1h Drupe::Action::\"Login\"::response{} // note };\n";
        assert_eq!(alias(temporal).expect("one policy"), Some("a".to_owned()));
        let def = "def cedar m() { 1 // c };\n@id(\"b\")\npermit (principal, action, resource);\n";
        assert_eq!(read(def).expect("it reads").len(), 1);
        assert_eq!(alias(def).expect("one alias"), Some("b".to_owned()));
        assert_eq!(
            alias(&format!("\u{FEFF}@id(\"c\")\n{BODY}")).expect("the mark is dropped"),
            Some("c".to_owned())
        );
        assert!(read(&format!("@1id(\"d\")\n{BODY}")).is_err());
    }

    /// An escaped quote does not end a string: the value runs to the quote that does.
    #[test]
    fn an_escaped_quote_does_not_end_a_string() {
        let source = format!("@id(\"x\")\n@advice(\"a\\\")\")\n{BODY}");
        let policies = read(&source).expect("it reads");
        assert_eq!(policies[0][1].raw.as_deref(), Some("a\\\")"));
        assert_eq!(alias(&source).expect("one alias"), Some("x".to_owned()));
    }

    #[test]
    fn the_reading_agrees_with_upstream_or_the_load_is_refused() {
        let read = [Some("a".to_owned()), None];
        assert!(agrees_with(&read, &read).is_ok());
        for lowered in [
            vec![Some("b".to_owned()), None],
            vec![Some("a".to_owned())],
            vec![None, None],
        ] {
            assert!(agrees_with(&read, &lowered).is_err(), "{lowered:?}");
        }
    }

    #[test]
    fn an_unclosed_source_is_refused_rather_than_read_short() {
        for broken in [
            "@id(\"a\") permit (principal, action, resource)",
            "@id(\"a) permit (principal, action, resource);",
            "@id(\"a\" permit (principal, action, resource);",
            "@ (\"a\") permit (principal, action, resource);",
        ] {
            assert!(read(broken).is_err(), "`{broken}` is refused");
        }
    }
}
