// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The strict query string of the evidence reads (WP-5.5; owner decision of 2026-10-16).
//!
//! Hand-parsed rather than deserialised, because an offset is opaque and must survive
//! percent-encoding untouched. Strict, because a parameter a read does not name, one named twice,
//! or a value that does not parse is a caller's mistake that must be told, never a read quietly
//! widened, narrowed or turned into a tail.

use permguard_core::{ApiError, ErrorClass, codes};

/// The parameters of a query, each a name the read takes.
#[derive(Debug, Default)]
pub struct Query {
    pairs: Vec<(String, String)>,
}

fn invalid(message: impl Into<String>) -> ApiError {
    ApiError::new(
        ErrorClass::Validation,
        codes::common::INVALID_ARGUMENT,
        message,
    )
}

/// Reads `query`, refusing a parameter outside `allowed`, one given twice unless `repeatable`,
/// one without a value, and two spellings of one parameter (`limit` and `limit_records`).
pub fn parse(
    query: Option<&str>,
    allowed: &[&str],
    repeatable: &[&str],
) -> Result<Query, ApiError> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for pair in query.unwrap_or_default().split('&') {
        if pair.is_empty() {
            continue;
        }
        let Some((name, value)) = pair.split_once('=') else {
            return Err(invalid(format!("`{}` has no value", percent_decode(pair))));
        };
        let name = percent_decode(name);
        if !allowed.contains(&name.as_str()) {
            return Err(invalid(format!(
                "`{name}` is not a parameter of this request: it takes {}",
                allowed.join(", ")
            )));
        }
        let spelling = |name: &str| {
            if name == "limit" {
                "limit_records"
            } else {
                name
            }
            .to_owned()
        };
        if !repeatable.contains(&name.as_str())
            && pairs
                .iter()
                .any(|(held, _)| spelling(held) == spelling(&name))
        {
            return Err(invalid(format!("`{name}` is given more than once")));
        }
        pairs.push((name, percent_decode(value)));
    }
    Ok(Query { pairs })
}

impl Query {
    /// The value of `name`, when given.
    pub fn value(&self, name: &str) -> Option<String> {
        self.pairs
            .iter()
            .find(|(held, _)| held == name)
            .map(|(_, value)| value.clone())
    }

    /// Every value of a repeatable `name`, in order.
    pub fn values(&self, name: &str) -> Vec<String> {
        self.pairs
            .iter()
            .filter(|(held, _)| held == name)
            .map(|(_, value)| value.clone())
            .collect()
    }

    /// `name` as a number, when given: refused when it does not parse.
    pub fn number<T: std::str::FromStr>(&self, name: &str) -> Result<Option<T>, ApiError> {
        self.value(name)
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| invalid(format!("`{name}` is a number, not `{value}`")))
            })
            .transpose()
    }

    /// `wait_ms`, a tail's wait for its next record (iteration 04, `7-contracts/5` Request): zero
    /// when absent; beside `until` it is refused, since an export never waits.
    pub fn wait(&self) -> Result<std::time::Duration, ApiError> {
        wait_of(
            self.number::<u64>("wait_ms")?.unwrap_or(0),
            self.value("until").is_some(),
        )
    }

    /// `limit_records`, or its older spelling `limit`.
    pub fn limit_records(&self) -> Result<Option<usize>, ApiError> {
        match self.number("limit_records")? {
            Some(limit) => Ok(Some(limit)),
            None => self.number("limit"),
        }
    }

    /// `name` as `true` or `false`, false when absent.
    pub fn flag(&self, name: &str) -> Result<bool, ApiError> {
        match self.value(name).as_deref() {
            None | Some("false") => Ok(false),
            Some("true") => Ok(true),
            Some(other) => Err(invalid(format!(
                "`{name}` is `true` or `false`, not `{other}`"
            ))),
        }
    }

    /// `until`, a frontier this build issued, when given: refused when it is not one, rather than
    /// turning the read into a tail.
    pub fn frontier(&self, name: &str) -> Result<Option<permguard_stream::Frontier>, ApiError> {
        self.value(name)
            .map(|value| {
                permguard_stream::Frontier::decode(&value).ok_or_else(|| {
                    invalid(format!("`{name}` is not a frontier this server issued"))
                })
            })
            .transpose()
    }
}

/// A tail's wait of `wait_ms` milliseconds, on every transport: refused beside `until`, since an
/// export never waits (iteration 04, `7-contracts/5` Request).
pub fn wait_of(wait_ms: u64, until: bool) -> Result<std::time::Duration, ApiError> {
    if wait_ms > 0 && until {
        return Err(invalid(
            "`wait_ms` waits on a tail: an export, with `until`, never waits".to_owned(),
        ));
    }
    Ok(std::time::Duration::from_millis(wait_ms))
}

/// Whether a page answers a tail that waits: it holds records, or says more is to be read past
/// what it examined, as a filtered read that scanned its bound without a match does; a refusal
/// answers at once. Only an empty page at the end of what the stream holds goes on waiting.
pub fn answers<T, E>(page: &Result<permguard_stream::Block<T>, E>) -> bool {
    match page {
        Ok(page) => !page.records.is_empty() || page.more,
        Err(_) => true,
    }
}

/// The parameters every bounded read takes.
pub const WINDOW: [&str; 7] = [
    "from",
    "until",
    "limit",
    "limit_records",
    "limit_bytes",
    "proof",
    "wait_ms",
];

pub fn percent_decode(value: &str) -> String {
    let bytes = value.replace('+', " ").into_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let pair = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or_default();
            if let Ok(byte) = u8::from_str_radix(pair, 16) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn code(error: ApiError) -> String {
        error.code().to_owned()
    }

    /// BUG-0170: an unknown parameter is refused naming the request, never calling a delete a
    /// read; what it takes is listed.
    #[test]
    fn an_unknown_parameter_names_the_request_not_a_read() {
        let Err(refused) = parse(
            Some("request_id=d1&expected_revision=1&foo=1"),
            &["request_id", "expected_revision"],
            &[],
        ) else {
            panic!("an unknown parameter is refused");
        };
        let said = refused.to_string();
        assert!(
            said.contains("is not a parameter of this request"),
            "{said}"
        );
        assert!(!said.contains("read"), "{said}");
        assert!(said.contains("request_id, expected_revision"), "{said}");
    }

    /// WP-5.5: a read takes the parameters it names, each once, with values that parse; anything
    /// else is a validation refusal, never ignored.
    #[test]
    fn a_query_takes_its_parameters_once_and_refuses_the_rest() {
        let allowed = [
            "from",
            "limit",
            "limit_records",
            "proof",
            "until",
            "event_type",
        ];
        let query = parse(
            Some("from=abc%3D&limit=5&event_type=a&event_type=b&proof=true&&"),
            &allowed,
            &["event_type"],
        )
        .expect("parses");
        assert_eq!(query.value("from").as_deref(), Some("abc="));
        assert_eq!(query.limit_records().expect("a number"), Some(5));
        assert_eq!(query.values("event_type"), vec!["a", "b"]);
        assert!(query.flag("proof").expect("a flag"));
        assert_eq!(query.frontier("until").expect("absent"), None);

        for (case, text) in [
            ("unknown", "from=a&color=red"),
            ("repeated", "from=a&from=b"),
            ("two spellings", "limit=1&limit_records=2"),
            ("no value", "proof"),
        ] {
            assert_eq!(
                code(parse(Some(text), &allowed, &["event_type"]).expect_err(case)),
                codes::common::INVALID_ARGUMENT,
                "{case}"
            );
        }
        let malformed = parse(Some("limit=many&proof=yes&until=x"), &allowed, &[]).expect("parses");
        assert!(malformed.limit_records().is_err());
        assert!(malformed.flag("proof").is_err());
        assert!(malformed.frontier("until").is_err());
    }
}
