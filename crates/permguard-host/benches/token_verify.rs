// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! TS-9: what token verification adds to a decision on a member, measured on the path a request
//! takes: the eight steps of `2-security/8` On a member (size, header, Ed25519 signature, issuer,
//! times, audience, the held status list, binding), then the authorization of the evaluation the
//! token's grant allows.
//!
//! ```text
//! cargo bench -p permguard-host --bench token_verify
//! ```
//!
//! It prints p50, p99 and p99.9 of one verification and fails when p99 passes its budget: a
//! hundredth of the decision objective of TS-5 (`bench/slo.json`, `p99_ms.disabled`), so token
//! verification can never be what moves a member past its objective.

use std::hint::black_box;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use permguard_core::authz::{Resource, operations};
use permguard_host::authz::access_tokens::{Anchor, verify};
use permguard_host::membership::token_status::{HeldList, HeldLists, PinnedKey};
use permguard_objects::status_list::{ENTRIES, StatusList};
use ring::signature::{Ed25519KeyPair, KeyPair as _};

const ISSUER: &str = "urn:permguard:iam:0198f2aa-0000-7000-8000-000000000001";
const MEMBER: &str = "member:0198f2aa-0000-7000-8000-000000000002";
const URI: &str = "https://iam.example/iam/v1/status-lists/0198f2aa-0000-7000-8000-000000000003";
const WARMUP: usize = 2_000;
const ITERATIONS: usize = 50_000;
/// The decision objective of TS-5 with the decision log disabled, as `bench/slo.json` publishes it.
fn decision_p99() -> Duration {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../bench/slo.json");
    let slo: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).expect("bench/slo.json reads"))
            .expect("bench/slo.json is JSON");
    let millis = slo["p99_ms"]["disabled"]
        .as_f64()
        .expect("bench/slo.json names p99_ms.disabled");
    Duration::from_secs_f64(millis / 1000.0)
}

fn main() {
    let pair = Ed25519KeyPair::from_seed_unchecked(&[5; 32]).expect("a key");
    let now = 1_800_000_000_u64;
    let anchor = Anchor {
        issuer: ISSUER.to_owned(),
        tenant: "default".to_owned(),
        keys: vec![PinnedKey {
            kid: "iam.tokens:k1".to_owned(),
            algorithm: "EdDSA",
            public_key: pair.public_key().as_ref().to_vec(),
        }],
        member: MEMBER.to_owned(),
        groups: vec!["group:eu".to_owned()],
        authority: Some("0198f2aa000070008000000000000001".to_owned()),
        bound_administration: false,
    };
    // A list as large as the IAM Host opens one, the token's entry in its middle.
    let lists = HeldLists::in_memory();
    lists
        .accept(HeldList {
            issuer: ISSUER.to_owned(),
            uri: URI.to_owned(),
            iat: now - 10,
            exp: now + 3_600,
            ttl: 300,
            list: StatusList::new(2, ENTRIES).expect("a list"),
            digest: [7; 32],
            token: String::new(),
        })
        .expect("held");
    let header = serde_json::json!({"alg": "EdDSA", "kid": "iam.tokens:k1", "typ": "at+jwt"});
    let claims = serde_json::json!({
        "iss": ISSUER, "permguard_tenant": "default", "sub": "sa:billing", "client_id": "billing",
        "aud": [MEMBER], "permguard_family": "application",
        "scope": "decision.evaluate event.submit",
        "permguard_target": ["plane/data/zone/0198f2aa-0000-7000-8000-000000000010/*"],
        "iat": now, "nbf": now, "exp": now + 3_600,
        "jti": "0198f2aa-0000-7000-8000-000000000020",
        "status": {"status_list": {"idx": ENTRIES / 2, "uri": URI}},
    });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let token = format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(pair.sign(signing_input.as_bytes()))
    );
    let ledger = Resource::ledger(
        "data",
        "0198f2aa-0000-7000-8000-000000000010",
        "0198f2aa-0000-7000-8000-000000000011",
    );
    let anchors = [anchor];

    let once = || {
        let verified = verify(black_box(&token), &anchors, &lists, None, now).expect("verified");
        assert!(
            verified
                .grant
                .permits(operations::DECISION_EVALUATE, &ledger)
        );
        black_box(verified);
    };
    for _ in 0..WARMUP {
        once();
    }
    let mut samples = Vec::with_capacity(ITERATIONS);
    for _ in 0..ITERATIONS {
        let start = Instant::now();
        once();
        samples.push(start.elapsed());
    }
    samples.sort_unstable();
    let at = |quantile: f64| {
        samples[((samples.len() as f64 * quantile) as usize).min(samples.len() - 1)]
    };
    let (p50, p99, p999) = (at(0.50), at(0.99), at(0.999));
    let objective = decision_p99();
    let budget = objective / 100;
    println!(
        "token verification on a member, {ITERATIONS} runs: p50 {p50:?}, p99 {p99:?}, p99.9 {p999:?}; \
         budget p99 {budget:?}, a hundredth of the {objective:?} decision objective"
    );
    if p99 > budget {
        eprintln!("FAIL: token verification p99 {p99:?} passes its budget {budget:?}");
        std::process::exit(1);
    }
}
