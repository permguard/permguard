// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a caller's own name for its request may be, wherever it is read.
//!
//! A caller may send an `X-Request-Id`. It is echoed on the answer and kept in the decision it led
//! to, so it is written out twice; one rule decides whether it is believed, for every surface that
//! reads it: plain ASCII letters, digits, `-` and `_`, at most [`MAXIMUM`] of them. A value outside
//! the rule is treated as absent — not rejected, because a malformed id is not worth failing a
//! request over, and not kept, because a value that can contain anything is a way of writing
//! anything into every place that records it.

/// The longest caller-supplied request id that is believed: long enough for a UUID or a trace id.
pub const MAXIMUM: usize = 64;

/// Whether `id` may be used as a caller's request id.
pub fn admits(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAXIMUM
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// `id`, when the rule admits it.
pub fn admitted(id: &str) -> Option<&str> {
    admits(id).then_some(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_only_a_short_run_of_plain_characters_is_believed() {
        assert!(admits("trace-0123456789abcdef"));
        assert!(admits(&"a".repeat(MAXIMUM)));
        for refused in [
            "",
            "has space",
            "has\nnewline",
            "has\"quote",
            "has=equals",
            &"a".repeat(MAXIMUM + 1),
        ] {
            assert!(!admits(refused), "`{refused}` was believed");
        }
    }
}
