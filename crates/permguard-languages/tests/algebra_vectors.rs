// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The typed decision algebra, frozen as vectors.
//!
//! `tests/vectors/algebra.json` is the languages model's `resolve` written out: every row of the
//! truth table another implementation — a plane in another language, a CLI deciding offline —
//! must reproduce. `P:<policy>` and `D:<policy>` name the deciding policy, `A` abstains and `E`
//! fails. The file is edited only by a change to the algebra, never to make a test pass.

#![allow(clippy::expect_used)]

use permguard_languages::{Verdict, resolve};
use serde_json::Value;

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/algebra.json");
    let text = std::fs::read_to_string(path).expect("the vector file is readable");
    serde_json::from_str(&text).expect("the vector file is JSON")
}

fn verdict(symbol: &str) -> Verdict {
    match symbol.split_once(':') {
        Some(("P", policy)) => Verdict::permit(vec![policy.to_owned()]),
        Some(("D", policy)) => Verdict::deny(vec![policy.to_owned()]),
        // A partition whose deny rule decided beside a failure of its own.
        Some(("DE", policy)) => {
            Verdict::deny_despite_failure(vec![policy.to_owned()], "the vector's failure")
        }
        // An engine's fail-closed deny: a failure that no deny rule determined.
        None if symbol == "DE" => Verdict::deny_despite_failure(Vec::new(), "the vector's failure"),
        None if symbol == "A" => Verdict::abstain(),
        None if symbol == "E" => Verdict::engine_failed("the vector's failure"),
        other => panic!("not a verdict symbol: {other:?}"),
    }
}

#[test]
fn test_every_row_of_the_algebra_resolves_as_the_vectors_state() {
    let vectors = vectors();
    let cases = vectors["cases"].as_array().expect("cases");
    assert!(cases.len() >= 14, "the whole table is covered");
    for case in cases {
        let name = case["name"].as_str().expect("a name");
        let verdicts = case["verdicts"]
            .as_array()
            .expect("verdicts")
            .iter()
            .map(|symbol| verdict(symbol.as_str().expect("a symbol")));
        let outcome = resolve(verdicts);

        assert_eq!(
            outcome.resolution.as_str(),
            case["resolution"].as_str().expect("a resolution"),
            "{name}"
        );
        let determining: Vec<&str> = outcome.determining().iter().map(String::as_str).collect();
        let expected: Vec<&str> = case["determining"]
            .as_array()
            .expect("determining")
            .iter()
            .map(|policy| policy.as_str().expect("a policy"))
            .collect();
        assert_eq!(
            determining, expected,
            "{name}: the policies a decision cites"
        );
        assert_eq!(
            outcome.permitted(),
            outcome.resolution.as_str() == "permit",
            "{name}: only a permit permits"
        );
        if let Some(failures) = case.get("failures") {
            assert_eq!(
                outcome.errors.len() as u64,
                failures.as_u64().expect("a count"),
                "{name}: every failure is kept, beside a deny too"
            );
        }
    }
}
