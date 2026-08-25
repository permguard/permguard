// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used)]

use permguard_decisions::jcs;
use proptest::collection::{btree_map, vec};
use proptest::prelude::*;
use serde_json::Value;

fn json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|value| Value::Number(value.into())),
        "[a-z0-9 _.-]{0,16}".prop_map(Value::String),
    ];

    leaf.prop_recursive(4, 64, 4, |inner| {
        prop_oneof![
            vec(inner.clone(), 0..4).prop_map(Value::Array),
            btree_map("[a-z][a-z0-9_]{0,8}", inner, 0..4)
                .prop_map(|members| Value::Object(members.into_iter().collect())),
        ]
    })
}

proptest! {
    #[test]
    fn canonical_json_is_a_fixed_point(value in json_value()) {
        let canonical = jcs::canonicalize(&value).unwrap();
        let reparsed: Value = serde_json::from_slice(&canonical).unwrap();

        prop_assert_eq!(jcs::canonicalize(&reparsed).unwrap(), canonical);
    }

    #[test]
    fn decision_record_digests_are_stable_for_equivalent_json_values(value in json_value()) {
        let canonical = jcs::canonicalize(&value).unwrap();
        let reparsed: Value = serde_json::from_slice(&canonical).unwrap();

        prop_assert_eq!(
            permguard_decisions::record::digest_of(&value).unwrap(),
            permguard_decisions::record::digest_of(&reparsed).unwrap()
        );
    }
}
