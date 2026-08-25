// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The client half of trust: verify a signed head statement against the
//! published key ring, then apply the `(counter, digest)` freshness table
//! against the persisted checkpoint. Fail-closed at every step.

use base64::Engine as _;
use permguard_objects::digest::Digest;
use permguard_objects::statement::{Freshness, HeadStatement, SignedHead, check_freshness};
use serde::Deserialize;

use crate::checkpoint::Checkpoint;

/// The published ring, as the JWKS document carries it.
#[derive(Debug, Deserialize)]
struct JwkSet {
    #[serde(default)]
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    #[serde(default)]
    crv: Option<String>,
    x: String,
    #[serde(default)]
    alg: String,
}

/// Verifies one envelope end to end and returns the statement it attests:
///
/// 1. the `kid` must name a ring key that is `OKP`/`Ed25519` — the pinned
///    profile, nothing else verifies;
/// 2. the Ed25519 signature must verify;
/// 3. the statement must name the expected zone, ledger and ref;
/// 4. the `(counter, digest)` table must not answer rollback or equivocation.
pub fn verify_statement(
    jwks: &[u8],
    envelope: &[u8],
    expected_zone: &str,
    expected_ledger: &str,
    expected_ref: &str,
    checkpoint: Option<&Checkpoint>,
) -> Result<HeadStatement, String> {
    let ring: JwkSet = serde_json::from_slice(jwks)
        .map_err(|error| format!("the key ring does not parse: {error}"))?;

    let signed = SignedHead::decode(envelope)
        .map_err(|error| format!("the head statement does not parse: {error}"))?;
    let kid = signed
        .kid()
        .map_err(|error| format!("the head statement names no key: {error}"))?;
    let kid = String::from_utf8_lossy(&kid).into_owned();

    let key = ring
        .keys
        .iter()
        .find(|key| key.kid == kid)
        .ok_or_else(|| format!("the ring has no key `{kid}`"))?;
    if key.kty != "OKP" || key.crv.as_deref() != Some("Ed25519") || key.alg != "EdDSA" {
        return Err(format!("key `{kid}` is not the pinned Ed25519 profile"));
    }
    let public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&key.x)
        .map_err(|error| format!("key `{kid}` does not decode: {error}"))?;

    let statement = signed
        .verify(&public_key)
        .map_err(|error| format!("the head statement does not verify: {error}"))?;

    if statement.zone != expected_zone || statement.ledger != expected_ledger {
        return Err(format!(
            "the statement attests zone `{}` ledger `{}`, not the tracked ledger",
            statement.zone, statement.ledger
        ));
    }
    if statement.r#ref != expected_ref {
        return Err(format!(
            "the statement attests the ref `{}`, not `{expected_ref}`",
            statement.r#ref
        ));
    }

    let last = match checkpoint {
        Some(checkpoint) => Some((
            checkpoint.counter,
            Digest::parse(&checkpoint.head)
                .map_err(|_| "the persisted checkpoint is corrupt".to_owned())?,
        )),
        None => None,
    };
    let verdict = check_freshness(
        last.as_ref().map(|(counter, digest)| (*counter, digest)),
        (statement.counter, &statement.digest),
    );
    match verdict {
        Freshness::Newer | Freshness::Same => Ok(statement),
        Freshness::Rollback => Err(format!(
            "rollback: the server presented counter {} below the accepted {}",
            statement.counter,
            last.map(|(c, _)| c).unwrap_or_default()
        )),
        Freshness::Equivocation => Err(format!(
            "equivocation: the server presented a different head for counter {}",
            statement.counter
        )),
    }
}
