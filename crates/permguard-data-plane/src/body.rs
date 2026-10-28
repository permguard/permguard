// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! How an evaluation interface reads a REST body (WP-7.5b, IFACE-06).
//!
//! Strictly, before anything is deserialized: one JSON value, no member named twice at any level,
//! open containers included. A JSON object with a duplicated name has no single meaning, and the
//! usual reading — the last one wins — would let a proxy and the plane see two different
//! requests in the same bytes.

use axum::http::HeaderMap;
use axum::http::header::CONTENT_TYPE;
use permguard_core::{ApiError, ErrorClass};
use serde_json::Value;

/// The JSON value of `body`, read strictly, or the refusal `what` names: a body that is not
/// declared JSON, is not one JSON value, or names a member twice.
pub(crate) fn json(headers: &HeaderMap, body: &[u8], what: &str) -> Result<Value, ApiError> {
    if !declared_json(headers) {
        return Err(malformed(format!(
            "{what}: the body is not declared `application/json`"
        )));
    }
    permguard_stream::jcs::parse_strict(body).map_err(|error| match error {
        // An integer past ±2^53 is a number the transports do not carry exactly: refused as
        // what it is, the code gRPC answers for it (IFACE-06).
        permguard_stream::jcs::CanonicalError::OutOfRange(_) => ApiError::new(
            ErrorClass::Validation,
            permguard_core::codes::notp::VALUE_UNREPRESENTABLE,
            format!(
                "{what}: {error}; numbers travel on both transports only inside ±2^53, so send \
                 anything larger as the string it is"
            ),
        ),
        error => malformed(format!("{what}: {error}")),
    })
}

/// `value` in the scalar domain both transports carry exactly (IFACE-06), or the refusal
/// `value_unrepresentable`.
pub(crate) fn lossless(value: Value) -> Result<Value, ApiError> {
    permguard_languages::request::lossless(value).map_err(|unrepresentable| {
        ApiError::new(
            ErrorClass::Validation,
            unrepresentable.code,
            unrepresentable.message,
        )
    })
}

/// The refusal of a body that cannot be read as the interface's payload.
pub(crate) fn malformed(message: String) -> ApiError {
    ApiError::new(
        ErrorClass::Validation,
        permguard_core::codes::notp::PAYLOAD_MALFORMED,
        message,
    )
}

/// Whether the body is declared JSON: `application/json`, or a `+json` type, as the JSON
/// extractor this replaced required.
fn declared_json(headers: &HeaderMap) -> bool {
    let Some(declared) = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let essence = declared
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    essence == "application/json"
        || essence
            .split_once('/')
            .is_some_and(|(kind, subtype)| kind == "application" && subtype.ends_with("+json"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use axum::http::HeaderValue;

    use super::*;

    fn declared(content_type: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_str(content_type).expect("a header"),
        );
        headers
    }

    /// IFACE-06: a member named twice is refused at every level, an open container included; a
    /// body not declared JSON is refused; one strict value is read.
    #[test]
    fn a_body_is_one_strict_json_value_declared_as_json() {
        let json_headers = declared("application/json; charset=utf-8");
        let read = json(&json_headers, br#"{"a": {"b": 1}}"#, "a test").expect("read");
        assert_eq!(read, serde_json::json!({"a": {"b": 1}}));

        for duplicated in [
            &br#"{"a": 1, "a": 2}"#[..],
            &br#"{"context": {"ip": "1", "ip": "2"}}"#[..],
            &br#"{"evaluations": [{"x": 1, "x": 1}]}"#[..],
        ] {
            let refused = json(&json_headers, duplicated, "a test").expect_err("refused");
            assert_eq!(
                refused.code(),
                permguard_core::codes::notp::PAYLOAD_MALFORMED
            );
            assert_eq!(refused.class(), ErrorClass::Validation);
        }
        assert!(json(&json_headers, br#"{"a": 1} {"a": 2}"#, "a test").is_err());
        let beyond =
            json(&json_headers, br#"{"n": 9007199254740993}"#, "a test").expect_err("past 2^53");
        assert_eq!(
            beyond.code(),
            permguard_core::codes::notp::VALUE_UNREPRESENTABLE
        );

        assert!(json(&declared("application/problem+json"), b"{}", "a test").is_ok());
        for undeclared in [
            declared("text/plain"),
            declared("text/x+json"),
            HeaderMap::new(),
        ] {
            let refused = json(&undeclared, b"{}", "a test").expect_err("refused");
            assert_eq!(
                refused.code(),
                permguard_core::codes::notp::PAYLOAD_MALFORMED
            );
        }
    }
}
