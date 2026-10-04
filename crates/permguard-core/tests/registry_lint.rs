// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The two registries are the only place a domain string or a stable code may be spelled.
//!
//! A domain string is part of what a signature means and a code is what a client branches on, so
//! both are contracts, and a contract spelled twice is two chances to drift. These tests walk every
//! crate's non-test sources and fail both ways: on a literal the registries do not own, and on a
//! registered value spelled as a literal instead of through its constant. The exceptions are listed
//! in `SPELLING_EXCEPTIONS`, each one narrow and explained.
//!
//! Test code is skipped on purpose: a test that pins the exact bytes of a wire format *should*
//! spell them, so that a change to a registry constant fails a test somewhere.

use std::fs;
use std::path::{Path, PathBuf};

use permguard_core::{codes, domains};

/// Every `.rs` file under `crates/*/src`, except the registries themselves.
fn sources() -> Vec<PathBuf> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let mut files = Vec::new();
    collect(&crates, &mut files);
    files.sort();
    files
        .into_iter()
        .filter(|path| {
            let text = path.to_string_lossy();
            text.contains("/src/")
                && !text.contains("/tests/")
                && !text.ends_with("permguard-core/src/domains.rs")
                && !text.ends_with("permguard-core/src/codes.rs")
        })
        .collect()
}

fn collect(directory: &Path, into: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            collect(&path, into);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            into.push(path);
        }
    }
}

/// The lines of a file that are code rather than test code or comments.
///
/// A `#[cfg(test)]` skips the item it marks — a test module, a test-only function, constant or
/// import — and reads on, so production code after it is still checked: a test module is not
/// always the last item of its file. Comment lines are skipped because documentation quotes the
/// strings.
fn code_lines(path: &Path) -> Vec<(usize, String)> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let all: Vec<&str> = text.lines().collect();
    let mut lines = Vec::new();
    let mut index = 0;
    while index < all.len() {
        let trimmed = all[index].trim_start();
        if trimmed.starts_with("#[cfg(test)]") {
            // The item the attribute marks starts at the first line that is not an attribute.
            let mut item = index + 1;
            while item < all.len() && all[item].trim_start().starts_with("#[") {
                item += 1;
            }
            if item >= all.len() {
                break;
            }
            // Skip to the end of the item: a `;` or a closing brace at depth zero.
            let mut depth = 0i32;
            while item < all.len() {
                let line = all[item];
                depth += line.matches('{').count() as i32 - line.matches('}').count() as i32;
                let ends = depth <= 0 && (line.trim_end().ends_with(';') || line.contains('}'));
                item += 1;
                if ends {
                    break;
                }
            }
            index = item;
            continue;
        }
        if !trimmed.starts_with("//") {
            lines.push((index + 1, all[index].to_owned()));
        }
        index += 1;
    }
    lines
}

/// Every double-quoted literal on a line, without the quotes, with `\n` escapes decoded.
fn literals(line: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = line;
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('"') else {
            break;
        };
        found.push(after[..end].replace("\\n", "\n"));
        rest = &after[end + 1..];
    }
    found
}

fn looks_like_domain(literal: &str) -> bool {
    literal.starts_with("permguard.")
        || literal.starts_with("application/vnd.permguard")
        || literal.starts_with("urn:permguard:")
}

#[test]
fn test_no_domain_literal_is_spelled_outside_the_registry() {
    let registered: Vec<&str> = domains::all().into_iter().map(|(_, value)| value).collect();
    let mut offences = Vec::new();

    for path in sources() {
        for (number, line) in code_lines(&path) {
            // Generated protobuf packages are named by the build script, not by this registry.
            if line.contains("include_proto!") {
                continue;
            }
            for literal in literals(&line) {
                // A registered value is caught whatever its shape — `host-local` looks like no
                // domain, and is one.
                if looks_like_domain(&literal) || registered.contains(&literal.as_str()) {
                    let known = if registered.contains(&literal.as_str()) {
                        "registered"
                    } else {
                        "unregistered"
                    };
                    offences.push(format!(
                        "{}:{number}: {literal:?} ({known})",
                        path.display()
                    ));
                }
            }
        }
    }

    assert!(
        offences.is_empty(),
        "domain strings spelled outside `permguard_core::domains` (use the constant):\n{}",
        offences.join("\n")
    );
}

/// The call shapes through which a stable code enters the program.
const CODE_SHAPES: [&str; 13] = [
    "ApiError::new(",
    "malformed(",
    "Refusal::new(",
    "Malformed::new(",
    "code: \"",
    "refusal(",
    "invalid(",
    "rejected(",
    "Refused::new(",
    "reason: \"",
    "reason = \"",
    "refused(\"",
    "\"code\":\"",
];

/// Whether the line at `position` builds a code: it names a shape, or one of the two lines before
/// it opens one, as `ApiError::new(` does when its class and code follow on lines of their own.
fn shaped_at(lines: &[(usize, String)], position: usize) -> bool {
    CODE_SHAPES
        .iter()
        .any(|shape| lines[position].1.contains(shape))
        // A class beside a literal, as in a `(code, ErrorClass::…, reason)` tuple, makes it a code.
        || lines[position].1.contains("ErrorClass::")
        || (1..=2).any(|back| {
            position
                .checked_sub(back)
                .and_then(|earlier| lines.get(earlier))
                .is_some_and(|(_, earlier)| {
                    CODE_SHAPES
                        .iter()
                        .any(|shape| earlier.trim_end().ends_with(shape.trim_end_matches('"')))
                })
        })
}

#[test]
fn test_every_stable_code_is_registered() {
    let registered: Vec<&str> = codes::all().into_iter().map(|(_, value)| value).collect();
    let classes = [
        "validation",
        "conflict",
        "not_found",
        "unavailable",
        "internal",
    ];
    let mut offences = Vec::new();

    for path in sources() {
        // The supervised worker's `refused` frames carry words of its own pipe (`frame_malformed`,
        // `compile_refused`, …), read back only by its parent in the same file and never answered
        // on a wire: they are not stable codes. Only the lines of those calls are skipped; the
        // rest of the file is read like any other.
        let worker = path.ends_with("permguard-languages/src/worker.rs");
        let lines = code_lines(&path);
        for (position, (number, line)) in lines.iter().enumerate() {
            let in_frame = worker
                && (0..=2).any(|back| {
                    position
                        .checked_sub(back)
                        .and_then(|earlier| lines.get(earlier))
                        .is_some_and(|(_, earlier)| earlier.contains("refused("))
                });
            if in_frame || !shaped_at(&lines, position) {
                continue;
            }
            for literal in literals(line) {
                let snake = !literal.is_empty()
                    && literal
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                    && literal.contains('_');
                if snake
                    && !classes.contains(&literal.as_str())
                    && !registered.contains(&literal.as_str())
                {
                    offences.push(format!("{}:{number}: {literal:?}", path.display()));
                }
            }
        }
    }

    assert!(
        offences.is_empty(),
        "stable codes spelled outside `permguard_core::codes`:\n{}",
        offences.join("\n")
    );
}

/// Where a registered code's spelling may appear outside `permguard_core::codes`, and why. Every
/// entry is narrow: a pattern a line must contain, never a whole file.
const SPELLING_EXCEPTIONS: [(&str, &str); 1] = [
    // The metric label vocabularies are a registry of their own: a label value that is spelled
    // like a code is a word of that registry, declared there.
    ("permguard-core/src/metrics.rs", "label!("),
];

/// A line with every metric label value at a recording site, `(labels::NAME, "value")`, blanked:
/// that literal is a word of the label registry, not a stable code on a wire. Only the literal
/// inside the tuple is excepted; the rest of the line is still read.
fn without_label_values(line: &str) -> String {
    let mut out = String::new();
    let mut rest = line;
    while let Some(start) = rest.find("(labels::") {
        out.push_str(&rest[..start]);
        let tuple = &rest[start..];
        let value = tuple
            .find(", \"")
            .filter(|comma| !tuple[..*comma].contains(')'))
            .and_then(|comma| {
                let opened = comma + 3;
                tuple[opened..]
                    .find('"')
                    .map(|closed| (opened, opened + closed))
            });
        match value {
            Some((opened, closed)) => {
                out.push_str(&tuple[..opened - 1]);
                rest = &tuple[closed + 1..];
            }
            None => {
                out.push_str("(labels::");
                rest = &tuple["(labels::".len()..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// The class names: they are also spelled as codes, and every use of them is a class.
const CLASSES: [&str; 5] = [
    "validation",
    "conflict",
    "not_found",
    "unavailable",
    "internal",
];

/// Whether the line at `position` sits inside a `label!( … )` vocabulary of `metrics.rs`.
fn inside_label_vocabulary(lines: &[(usize, String)], position: usize) -> bool {
    lines[..=position]
        .iter()
        .rev()
        .map(|(_, line)| line.trim())
        .find(|line| line.starts_with("label!(") || line.starts_with(");"))
        .is_some_and(|line| line.starts_with("label!("))
}

#[test]
fn test_no_registered_code_is_spelled_outside_the_registry() {
    let registered: Vec<&str> = codes::all().into_iter().map(|(_, value)| value).collect();
    let mut offences = Vec::new();

    for path in sources() {
        let shown = path.display().to_string();
        let lines = code_lines(&path);
        for (position, (number, line)) in lines.iter().enumerate() {
            let excepted = SPELLING_EXCEPTIONS.iter().any(|(file, pattern)| {
                shown.ends_with(file)
                    && (line.contains(pattern)
                        || (*pattern == "label!(" && inside_label_vocabulary(&lines, position)))
            });
            if excepted {
                continue;
            }
            let shaped = CODE_SHAPES.iter().any(|shape| line.contains(shape));
            // Where a refusal is built with its class as an enum, a class-like literal on the same
            // line, or on the line after the class, is the code:
            // `ApiError::new(ErrorClass::Internal, "internal", …)`.
            let class_given = (shaped && line.contains("ErrorClass::"))
                || position
                    .checked_sub(1)
                    .and_then(|previous| lines.get(previous))
                    .is_some_and(|(_, previous)| previous.trim_start().starts_with("ErrorClass::"));
            for literal in literals(&without_label_values(line)) {
                if !registered.contains(&literal.as_str())
                    || (CLASSES.contains(&literal.as_str()) && !class_given)
                {
                    continue;
                }
                // A one-word code is also an ordinary word; it is a code where a code is built.
                if literal.contains('_') || shaped {
                    offences.push(format!("{shown}:{number}: {literal:?}"));
                }
            }
        }
    }

    assert!(
        offences.is_empty(),
        "registered stable codes spelled outside `permguard_core::codes` (use the constant):\n{}",
        offences.join("\n")
    );
}

/// The scanner skips what a `#[cfg(test)]` marks, a test module included, and reads on after it.
#[test]
fn test_the_scanner_skips_test_items_and_test_modules_and_reads_on() {
    let path =
        std::env::temp_dir().join(format!("permguard-registry-lint-{}.rs", std::process::id()));
    fs::write(
        &path,
        "fn before() {}\n\
         #[cfg(test)]\n\
         #[allow(dead_code)]\n\
         fn only_in_tests() {\n    let hidden = \"inside the test item\";\n}\n\
         #[cfg(test)]\n\
         const ALSO_TEST: &str = \"a test constant\";\n\
         fn after() { let seen = \"production after the item\"; }\n\
         #[cfg(test)]\n\
         mod tests {\n    fn t() { let x = \"in the test module\"; }\n}\n\
         fn last() { let seen = \"production after the module\"; }\n",
    )
    .expect("the sample file is written");

    let read: Vec<String> = code_lines(&path)
        .into_iter()
        .map(|(_, line)| line)
        .collect();
    let _ = fs::remove_file(&path);

    for seen in ["production after the item", "production after the module"] {
        assert!(
            read.iter().any(|line| line.contains(seen)),
            "`{seen}` was not read: {read:#?}"
        );
    }
    for skipped in [
        "inside the test item",
        "a test constant",
        "in the test module",
    ] {
        assert!(
            !read.iter().any(|line| line.contains(skipped)),
            "`{skipped}` was read: {read:#?}"
        );
    }
}

#[test]
fn test_only_the_label_value_of_a_recording_tuple_is_excepted() {
    assert_eq!(
        literals(&without_label_values(
            r#"metrics.count(&M, &[(labels::REASON, "out_of_order")]); f("stream_closed")"#
        )),
        vec!["stream_closed".to_owned()]
    );
    assert_eq!(
        literals(&without_label_values(
            r#"(labels::OUTCOME, "ok"), (labels::REASON, "x")"#
        )),
        Vec::<String>::new()
    );
}

/// A compatibility-only code is read, never generated: no production source names `legacy`.
#[test]
fn test_no_production_path_generates_a_compatibility_only_code() {
    let mut offences = Vec::new();
    for path in sources() {
        for (number, line) in code_lines(&path) {
            if line.contains("codes::legacy") || line.contains("legacy::") {
                offences.push(format!("{}:{number}", path.display()));
            }
        }
    }
    assert!(
        offences.is_empty(),
        "compatibility-only codes named by production code:\n{}",
        offences.join("\n")
    );
}

/// A function that names a failure's stable code — `fn reason`, `fn code` — answers registered
/// codes only, one-word codes included: `"timeout"` is as much a code as `"connect_failed"`.
#[test]
fn test_a_function_that_names_a_code_answers_registered_codes_only() {
    let registered: Vec<&str> = codes::all().into_iter().map(|(_, value)| value).collect();
    let mut offences = Vec::new();
    for path in sources() {
        let mut inside = false;
        for (number, line) in code_lines(&path) {
            let trimmed = line.trim_start();
            if trimmed.contains("fn ") {
                inside = trimmed.contains("fn reason(") || trimmed.contains("fn code(");
            }
            if !inside || !line.contains("=> \"") {
                continue;
            }
            for literal in literals(&line) {
                if !registered.contains(&literal.as_str()) {
                    offences.push(format!("{}:{number}: {literal:?}", path.display()));
                }
            }
        }
    }
    assert!(
        offences.is_empty(),
        "codes named by a code function and not registered:\n{}",
        offences.join("\n")
    );
}
