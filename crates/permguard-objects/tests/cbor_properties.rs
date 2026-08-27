// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use permguard_objects::cbor::{self, Value};
use permguard_objects::manifest::{
    KIND_POLICY, Manifest, PROFILE_PDP_V1, Partition, Profile, ProvidedRuntime, Requirement,
    Runtime, check_load_gate,
};
use permguard_objects::semver::{Constraint, Version};
use proptest::collection::{btree_map, vec};
use proptest::prelude::*;

fn cbor_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        any::<bool>().prop_map(Value::Bool),
        any::<i32>().prop_map(|value| Value::Int(i64::from(value))),
        vec(any::<u8>(), 0..16).prop_map(Value::Bytes),
        "[a-z0-9 _.-]{0,16}".prop_map(Value::Text),
    ];

    leaf.prop_recursive(4, 64, 4, |inner| {
        prop_oneof![
            vec(inner.clone(), 0..4).prop_map(Value::Array),
            btree_map("[a-z][a-z0-9_]{0,8}", inner, 0..4).prop_map(|members| {
                Value::Map(
                    members
                        .into_iter()
                        .map(|(key, value)| (Value::Text(key), value))
                        .collect(),
                )
            }),
        ]
    })
}

fn version() -> impl Strategy<Value = Version> {
    (0u64..4, 0u64..16, 0u64..32).prop_map(|(major, minor, patch)| Version {
        major,
        minor,
        patch,
    })
}

fn constraint() -> impl Strategy<Value = Constraint> {
    prop_oneof![
        version().prop_map(Constraint::Exact),
        version().prop_map(Constraint::AtLeast),
        (version(), version()).prop_filter_map("ordered semver range", |(lower, upper)| {
            (upper > lower).then_some(Constraint::Range(lower, upper))
        }),
    ]
}

fn manifest() -> impl Strategy<Value = Manifest> {
    (
        "[a-z][a-z0-9]{0,8}",
        "[a-z][a-z0-9]{0,8}",
        constraint(),
        constraint(),
        vec("[a-z][a-z0-9.+-]{0,12}/[a-z][a-z0-9.+-]{0,12}", 1..4),
    )
        .prop_map(
            |(
                runtime_name,
                partition_name,
                language_constraint,
                engine_constraint,
                media_types,
            )| {
                let mut runtimes = BTreeMap::new();
                runtimes.insert(
                    runtime_name.clone(),
                    Runtime {
                        language: Requirement {
                            name: "cedar".to_owned(),
                            constraint: language_constraint,
                        },
                        engine: Requirement {
                            name: "cedar-rs".to_owned(),
                            constraint: engine_constraint,
                        },
                    },
                );

                let mut partitions = BTreeMap::new();
                partitions.insert(
                    partition_name.clone(),
                    Partition {
                        runtime: runtime_name,
                        media_types,
                        schema: false,
                        input: None,
                    },
                );

                let mut profiles = BTreeMap::new();
                profiles.insert(
                    "default".to_owned(),
                    Profile {
                        r#type: PROFILE_PDP_V1.to_owned(),
                        partitions: vec![partition_name],
                    },
                );

                Manifest {
                    kind: KIND_POLICY.to_owned(),
                    name: "ledger".to_owned(),
                    description: "property generated".to_owned(),
                    author: "Permguard".to_owned(),
                    license: "Apache-2.0".to_owned(),
                    runtimes,
                    partitions,
                    profiles,
                }
            },
        )
}

proptest! {
    #[test]
    fn canonical_cbor_is_a_fixed_point(value in cbor_value()) {
        let encoded = cbor::encode(&value);
        let decoded = cbor::decode_canonical(&encoded).unwrap();

        prop_assert_eq!(cbor::encode(&decoded), encoded);
    }

    #[test]
    fn arbitrary_cbor_bytes_are_either_rejected_or_canonical(data in vec(any::<u8>(), 0..128)) {
        if let Ok(value) = cbor::decode_canonical(&data) {
            prop_assert_eq!(cbor::encode(&value), data);
        }
    }

    #[test]
    fn manifests_round_trip_through_the_normative_cbor_shape(manifest in manifest()) {
        let encoded = manifest.encode();
        let decoded = Manifest::decode(&encoded).unwrap();

        prop_assert_eq!(decoded, manifest);
    }
}

#[test]
fn the_manifest_load_gate_stays_fail_closed_for_unmet_runtime_constraints() {
    let mut manifest = Manifest {
        kind: KIND_POLICY.to_owned(),
        name: "ledger".to_owned(),
        ..Manifest::default()
    };
    manifest.runtimes.insert(
        "runtime".to_owned(),
        Runtime {
            language: Requirement {
                name: "cedar".to_owned(),
                constraint: Constraint::parse(">=9.0.0").unwrap(),
            },
            engine: Requirement {
                name: "cedar-rs".to_owned(),
                constraint: Constraint::parse(">=9.0.0").unwrap(),
            },
        },
    );

    assert!(
        check_load_gate(
            &manifest,
            &[ProvidedRuntime {
                language_name: "cedar".to_owned(),
                language_version: Version::parse("1.0.0").unwrap(),
                engine_name: "cedar-rs".to_owned(),
                engine_version: Version::parse("1.0.0").unwrap(),
            }]
        )
        .is_err(),
        "a consumer outside the declared semantic range must not load the ledger"
    );
}
