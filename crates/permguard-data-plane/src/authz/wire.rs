// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `permguard.pdp.v1` payloads: what a PEP sends, and what it gets back.
//!
//! # Lineage, stated plainly
//!
//! The shape is **OpenID AuthZEN Authorization API 1.0** — `subject`,
//! `action`, `resource`, `context` in, `{decision, context}` out, with
//! `evaluations[]` for boxcarring and `options.evaluations_semantic` for how a
//! batch resolves. What the standard leaves to the implementation, this profile
//! fills in; what the standard does not cover, this profile adds as extensions
//! the standard itself provides for (a receiver ignores what it does not know).
//! The Search APIs are deliberately **not** served, and their absence from the
//! metadata document is — per the standard's own rule — how a PEP learns that.
//!
//! We do not claim conformance. We implement the contract and say where we
//! differ, which is worth more than a badge.
//!
//! # Where we differ, and why
//!
//! | | Standard | Here |
//! | --- | --- | --- |
//! | Policy store | the URL the PEP was configured with | **`zone` and `ledger` in the payload**, required |
//! | Search APIs | optional | not served |
//! | `principal`, `entities` | — | extensions: who is asking, and the entity graph |
//! | Reasons | free-form `context` | `reason_admin` / `reason_user`, the disclosure split the whole server speaks |
//!
//! One endpoint that carries the store in the body is the choice a caller
//! asked for: a PEP that talks to several ledgers keeps one address and one
//! connection pool, and the ledger becomes data — which is also what makes a
//! request loggable and auditable as one record. A payload that names neither
//! is **refused**, never answered against a default: silently deciding against
//! the wrong policy store is the one failure mode nobody can debug.

// The payloads themselves live beside the engines, so that a plane serving a request and
// `permguard test` deciding one off disk cannot disagree about what a request is.
pub use permguard_languages::request::*;

/// The trace a request belongs to, taken from its `traceparent`.
///
/// [W3C Trace Context](https://www.w3.org/TR/trace-context/), and nothing more:
/// the two identifiers, parsed strictly. A decision that cannot be joined to
/// the request that caused it is half an investigation, and the join is one
/// standard header — but a header a caller controls, so a value that is not
/// the documented shape is dropped rather than recorded as if it were.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    /// The trace.
    pub trace_id: String,
    /// The span that asked.
    pub span_id: String,
}

impl TraceContext {
    /// Reads a `traceparent` header value.
    ///
    /// `version-traceid-spanid-flags`, hex, fixed widths. The all-zero
    /// identifiers the specification calls invalid are refused, because a
    /// decision joined to trace zero is worse than one joined to nothing.
    pub fn parse(header: &str) -> Option<Self> {
        let mut parts = header.trim().split('-');
        let version = parts.next()?;
        let trace_id = parts.next()?;
        let span_id = parts.next()?;
        let _flags = parts.next()?;
        if parts.next().is_some() || version.len() != 2 {
            return None;
        }
        let hex = |value: &str, width: usize| {
            value.len() == width
                && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                && value.bytes().any(|byte| byte != b'0')
        };
        if !hex(trace_id, 32) || !hex(span_id, 16) {
            return None;
        }

        Some(Self {
            trace_id: trace_id.to_ascii_lowercase(),
            span_id: span_id.to_ascii_lowercase(),
        })
    }
}

#[cfg(test)]
mod trace_tests {
    use super::TraceContext;

    #[test]
    fn a_well_formed_traceparent_is_read() {
        let parsed = TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
            .expect("it parses");

        assert_eq!(parsed.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(parsed.span_id, "00f067aa0ba902b7");
    }

    #[test]
    fn anything_else_is_dropped_rather_than_recorded() {
        for header in [
            "",
            "00-4bf92f35-00f067aa0ba902b7-01",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
            "00-zzzz2f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        ] {
            assert_eq!(
                TraceContext::parse(header),
                None,
                "a caller controls this header: {header}"
            );
        }
    }
}
