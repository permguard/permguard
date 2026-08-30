// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Putting a caller's own string into a URL without letting it become part of the URL's grammar.
//!
//! # Why this exists as a module rather than as a call at each site
//!
//! Identifiers here are **opaque**: an occurrence id is whatever a caller sent, and the ingestion
//! contract asks only that it is not empty. Interpolating one straight into a path or a query is
//! therefore not a formatting convenience, it is a parsing decision made by the caller — `a/b`
//! addresses a different route, `a?x=1` adds a parameter nobody sent, `a#b` truncates the request
//! at a fragment, and `a&b` splits one value into two. The same id stays perfectly readable over
//! gRPC, where there is no grammar to collide with, so the two transports disagree about what a
//! ledger holds. For an audit product that is the worst shape a bug can take: not an error, a
//! different answer.
//!
//! The control plane already percent-decodes what it receives. This is the other half of that
//! contract, in one place, so a new call site inherits it instead of re-deciding it.

/// The RFC 3986 *unreserved* set: everything else is escaped.
///
/// Deliberately the smallest safe set rather than a per-component one. A value escaped this way is
/// correct in a path segment and in a query value alike, so there is one function to reach for and
/// no second question about which component this string is going into. The cost is a few extra
/// escapes in places that would have tolerated the character; the benefit is that no call site has
/// to be right about the difference.
///
/// `+` is escaped for a reason worth naming: the control plane reads `+` in a query as a space, so
/// a value carrying one would come back changed rather than rejected.
fn unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// One caller-supplied value, safe to place in a path segment or a query value.
///
/// Encodes the UTF-8 bytes, so non-ASCII identifiers survive the round trip exactly rather than
/// being dropped or replaced.
pub fn value(held: &str) -> String {
    let mut out = String::with_capacity(held.len());
    for byte in held.as_bytes() {
        match unreserved(*byte) {
            true => out.push(char::from(*byte)),
            false => out.push_str(&format!("%{byte:02X}")),
        }
    }

    out
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    /// The characters that would otherwise change what the request means.
    #[test]
    fn the_delimiters_of_a_url_are_escaped() {
        for (held, expected) in [
            ("a/b", "a%2Fb"),
            ("a?b", "a%3Fb"),
            ("a#b", "a%23b"),
            ("a&b", "a%26b"),
            ("a=b", "a%3Db"),
            ("a b", "a%20b"),
            // Read back as a space by the plane, so it may not travel as itself.
            ("a+b", "a%2Bb"),
            // Already-encoded input must not be double-read: the percent is data here.
            ("a%2Fb", "a%252Fb"),
        ] {
            assert_eq!(value(held), expected, "`{held}`");
        }
    }

    /// What is safe stays readable, so an ordinary id is still legible in a log line.
    #[test]
    fn an_ordinary_identifier_is_left_alone() {
        for held in [
            "01J8Z9-login-request",
            "demo-1788033699-read-inside-window",
            "a.b_c-d~e",
        ] {
            assert_eq!(value(held), held, "`{held}` needs no escaping");
        }
    }

    /// Non-ASCII survives as its UTF-8 bytes rather than being lost.
    #[test]
    fn unicode_travels_as_its_bytes() {
        assert_eq!(value("café"), "caf%C3%A9");
        assert_eq!(value("日本"), "%E6%97%A5%E6%9C%AC");
    }
}
