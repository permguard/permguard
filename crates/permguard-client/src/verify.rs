// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The client half of trust: verify a signed head statement against the
//! published key ring, then apply the `(counter, ref_digest)` freshness table
//! against the persisted checkpoint. Fail-closed at every step.

use base64::Engine as _;
use permguard_objects::crypto::suite::Suite;
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
    y: Option<String>,
    #[serde(default)]
    alg: String,
}

/// Verifies one envelope end to end and returns the statement it attests:
///
/// 1. the `kid` must name a ring key of a pinned profile, its `alg`, `kty` and `crv` one suite's:
///    `EdDSA`/`OKP`/`Ed25519` or `ES256`/`EC`/`P-256`, nothing else verifies;
/// 2. the signature must verify under that suite;
/// 3. the statement must name the expected zone, ledger and ref;
/// 4. the `(counter, ref_digest)` table must not answer rollback or equivocation; a checkpoint
///    written before the ref digest falls back to `(counter, head)`.
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
        .find(|key| {
            // The kid the key is published under, or the bare thumbprint of exactly this key
            // that a statement signed before the rings names (WP-3.1).
            key.kid == kid
                || (key.kty == "OKP"
                    && permguard_objects::crypto::thumbprint::selects(
                        &permguard_core::Jwk::okp(
                            &key.kid,
                            key.crv.as_deref().unwrap_or_default(),
                            &key.alg,
                            &key.x,
                        ),
                        &kid,
                    ))
        })
        .ok_or_else(|| format!("the ring has no key `{kid}`"))?;
    let suite = Suite::from_jws_alg(&key.alg)
        .filter(|suite| key.kty == suite.kty() && key.crv.as_deref() == Some(suite.crv()))
        .ok_or_else(|| format!("key `{kid}` is not a pinned profile, Ed25519 or P-256"))?;
    let decode = |part: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(part)
            .map_err(|error| format!("key `{kid}` does not decode: {error}"))
    };
    // The encoding the suite verifies with: Ed25519's 32 bytes, P-256's uncompressed SEC1 point.
    let public_key = match suite {
        Suite::Ed25519Sha256V1 => decode(&key.x)?,
        Suite::P256Sha256V1 => {
            let y = key
                .y
                .as_deref()
                .ok_or_else(|| format!("key `{kid}` has no `y`"))?;
            let (x, y) = (decode(&key.x)?, decode(y)?);
            if x.len() != 32 || y.len() != 32 {
                return Err(format!("key `{kid}` is not a P-256 point"));
            }
            [&[0x04][..], &x, &y].concat()
        }
    };

    let statement = signed
        .verify(suite, &public_key)
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

    let corrupt = |_| "the persisted checkpoint is corrupt".to_owned();
    // The checkpoint's ref digest when it holds one, its head when it was written before.
    let (last, presented) = match checkpoint {
        Some(Checkpoint {
            counter,
            ref_digest: Some(ref_digest),
            ..
        }) => (
            Some((*counter, Digest::parse(ref_digest).map_err(corrupt)?)),
            &statement.ref_digest,
        ),
        Some(checkpoint) => (
            Some((
                checkpoint.counter,
                Digest::parse(&checkpoint.head).map_err(corrupt)?,
            )),
            &statement.digest,
        ),
        None => (None, &statement.ref_digest),
    };
    let verdict = check_freshness(
        last.as_ref().map(|(counter, digest)| (*counter, digest)),
        (statement.counter, presented),
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
