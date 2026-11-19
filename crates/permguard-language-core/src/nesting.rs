// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! How deep a Cedar-grammar text nests, read before any parser runs: Cedar's own and Dogwood's,
//! which is Cedar's grammar with temporal operators (BUG-0237). Their parsers recurse on nesting,
//! so the depth of the text is the depth of the stack they need, and one pushed text nested deep
//! enough would overflow it, an abort no guard catches.

/// Which grammar a text is in: what nests differs between the two.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Grammar {
    /// A policy: `if … then … else` nests in its branches without a bracket, and an `else if`
    /// chain is a recursion per link for the parser and the evaluator alike. Every `if` counts as a
    /// level, conservatively: a real policy holds a few. A member chain, `a.b.c`, nests one level
    /// per link too, and a `has` path costs time that grows with its square.
    Policy,
    /// A schema: `Set<…>` nests on angle brackets, which a schema uses for nothing else.
    Schema,
}

/// The deepest nesting of `text`, scanning as a splitter does: outside strings and line comments,
/// where a bracket or a keyword is syntax.
pub fn depth(text: &str, grammar: Grammar) -> usize {
    let bytes = text.as_bytes();
    let (mut depth, mut deepest, mut ifs, mut chain) = (0usize, 0usize, 0usize, 0usize);
    let word = |c: Option<&u8>| c.is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_');
    let (mut in_string, mut escaped, mut in_comment) = (false, false, false);
    for (at, &c) in bytes.iter().enumerate() {
        if in_comment {
            in_comment = c != b'\n';
        } else if in_string {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_string = false;
            }
        } else {
            // A member chain, `a.b.c` or a `has a.b.c` path, folds into one node per link: a run
            // of consecutive `.` is a level per link. Cedar has no decimal literal outside a
            // string, so a `.` there is always a member access; any other token ends the run.
            if grammar == Grammar::Policy {
                if c == b'.' {
                    chain += 1;
                } else if !(word(Some(&c)) || c.is_ascii_whitespace()) {
                    chain = 0;
                }
            }
            match c {
                b'"' => in_string = true,
                b'/' if bytes.get(at + 1) == Some(&b'/') => in_comment = true,
                b'{' | b'(' | b'[' => depth += 1,
                b'<' if grammar == Grammar::Schema => depth += 1,
                b'}' | b')' | b']' => depth = depth.saturating_sub(1),
                b'>' if grammar == Grammar::Schema => depth = depth.saturating_sub(1),
                b'i' if grammar == Grammar::Policy
                    && bytes.get(at + 1) == Some(&b'f')
                    && !word(at.checked_sub(1).and_then(|before| bytes.get(before)))
                    && !word(bytes.get(at + 2)) =>
                {
                    ifs += 1;
                }
                _ => {}
            }
            deepest = deepest.max(depth + ifs + chain);
        }
    }
    deepest
}
