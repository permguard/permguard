// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The strict JSON profile round-trips: what this crate writes, it reads back as the same value,
//! and the strict reader takes exactly the canonical bytes back.

#![allow(clippy::unwrap_used)]

use permguard_stream::jcs;
use proptest::collection::{btree_map, vec};
use proptest::prelude::*;
use serde_json::Value;

fn json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        // The profile carries integers within ±2^53; anything beyond is refused by design.
        (-(jcs::MAX_INTEGER as i64)..=(jcs::MAX_INTEGER as i64))
            .prop_map(|value| Value::Number(value.into())),
        // Escapes and non-ASCII included: canonical string escaping is half of RFC 8785.
        "(?s).{0,12}".prop_map(Value::String),
    ];

    leaf.prop_recursive(4, 64, 4, |inner| {
        prop_oneof![
            vec(inner.clone(), 0..4).prop_map(Value::Array),
            btree_map("(?s).{0,8}", inner, 0..4)
                .prop_map(|members| Value::Object(members.into_iter().collect())),
        ]
    })
}

proptest! {
    #[test]
    fn canonical_bytes_decode_back_to_the_value(value in json_value()) {
        let bytes = jcs::canonicalize(&value).unwrap();

        prop_assert_eq!(jcs::decode_canonical(&bytes).unwrap(), value.clone());
        prop_assert_eq!(jcs::parse_strict(&bytes).unwrap(), value);
    }

    #[test]
    fn canonicalization_is_a_fixed_point_through_the_strict_reader(value in json_value()) {
        let once = jcs::canonicalize(&value).unwrap();
        let twice = jcs::canonicalize(&jcs::parse_strict(&once).unwrap()).unwrap();

        prop_assert_eq!(once, twice);
    }

    #[test]
    fn any_other_spelling_of_the_value_is_not_canonical(value in json_value()) {
        let canonical = jcs::canonicalize(&value).unwrap();
        let pretty = serde_json::to_vec_pretty(&value).unwrap();

        // The strict reader still accepts the pretty spelling as JSON …
        prop_assert_eq!(jcs::parse_strict(&pretty).unwrap(), value);
        // … and the canonical decoder accepts only the canonical bytes.
        prop_assert_eq!(jcs::decode_canonical(&pretty).is_ok(), pretty == canonical);
    }
}
