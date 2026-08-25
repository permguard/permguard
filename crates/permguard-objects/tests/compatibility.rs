// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;

use permguard_objects::manifest::{
    KIND_POLICY, Manifest, PROFILE_PDP_V1, Partition, Profile, Requirement, Runtime,
};
use permguard_objects::semver::Constraint;

fn fixture_manifest() -> Manifest {
    let mut runtimes = BTreeMap::new();
    runtimes.insert(
        "cedar".to_owned(),
        Runtime {
            language: Requirement {
                name: "cedar".to_owned(),
                constraint: Constraint::parse(">=4.4.0 <5.0.0").expect("constraint parses"),
            },
            engine: Requirement {
                name: "cedar-rs".to_owned(),
                constraint: Constraint::parse(">=4.4.0 <5.0.0").expect("constraint parses"),
            },
        },
    );

    let mut partitions = BTreeMap::new();
    partitions.insert(
        "authz".to_owned(),
        Partition {
            runtime: "cedar".to_owned(),
            media_types: vec!["application/vnd.cedar.policy".to_owned()],
            schema: false,
        },
    );

    let mut profiles = BTreeMap::new();
    profiles.insert(
        "default".to_owned(),
        Profile {
            r#type: PROFILE_PDP_V1.to_owned(),
            partitions: vec!["authz".to_owned()],
        },
    );

    Manifest {
        kind: KIND_POLICY.to_owned(),
        name: "compat-ledger".to_owned(),
        description: "v1 compatibility fixture".to_owned(),
        author: "Permguard".to_owned(),
        license: "Apache-2.0".to_owned(),
        runtimes,
        partitions,
        profiles,
    }
}

#[test]
fn v1_manifest_fixture_decodes_to_the_current_model() {
    let expected_hex = include_str!("fixtures/compat/v1/manifest.cbor.hex").trim();
    let encoded = fixture_manifest().encode();

    assert_eq!(hex(&encoded), expected_hex);
    assert_eq!(
        Manifest::decode(&from_hex(expected_hex).expect("fixture is hex"))
            .expect("fixture decodes"),
        fixture_manifest()
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn from_hex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err("odd hex length".to_owned());
    }

    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks_exact(2) {
        let high = nibble(pair[0])?;
        let low = nibble(pair[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(format!("not lowercase hex: {byte}")),
    }
}
