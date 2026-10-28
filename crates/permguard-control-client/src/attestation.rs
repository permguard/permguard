// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The PEP's verifier of a signed native decision response (WP-6.6c,
//! `3-data-plane/2-data-plane-pdp.md`, signed response).
//!
//! ```text
//! request bytes sent ─┐
//! response bytes ─────┼─▶ strict JSON, the attestation split off
//! pinned data.attest ─┤   ─▶ flattened JWS: canonical base64url, JCS header {alg, kid, typ}
//! expectation ────────┘   ─▶ the pinned key the kid names, the signature over protected.payload
//!                         ─▶ the closed JCS payload, every form exact
//!                         ─▶ audience, both digests recomputed, ids, decision, evidence, policy,
//!                            lifetime within the advertised validity and skew
//!                         ─▶ the nonce, outstanding, spent: accepted
//! ```
//!
//! Offline: nothing here reaches the network. A mismatch invalidates the attestation and is
//! answered as [`Refused`], naming the binding that failed; it never becomes a deny. The nonce is
//! spent only once everything else verified, so a forged response cannot burn a genuine one.

use std::collections::BTreeSet;

use base64::Engine as _;
use permguard_core::Jwk;
use permguard_languages::attestation::{Payload, Policy};
use permguard_objects::crypto::suite::Suite;
use serde::Deserialize;
use serde_json::Value;

/// Why an attestation does not verify: the binding that failed, and what was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    /// The binding: `response`, `attestation`, `encoding`, `header`, `type`, `algorithm`, `key`,
    /// `signature`, `payload`, `audience`, `request_digest`, `response_digest`, `request_ids`,
    /// `decision`, `evidence`, `policy`, `lifetime`, `nonce`.
    pub binding: &'static str,
    pub detail: String,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the attestation does not verify ({}): {}",
            self.binding, self.detail
        )
    }
}

impl std::error::Error for Refused {}

fn failed_at(binding: &'static str, detail: impl Into<String>) -> Refused {
    Refused {
        binding,
        detail: detail.into(),
    }
}

/// The nonces a PEP issued and has not seen answered: outstanding until a verified response
/// spends one, never accepted twice.
pub trait Nonces {
    /// Spends `nonce`: `true` when it was outstanding, and it no longer is.
    fn spend(&mut self, nonce: &str) -> bool;
}

/// The simplest replay cache: the outstanding nonces in memory, unbounded, as many as the PEP
/// issued and has not seen answered.
#[derive(Debug, Default)]
pub struct Outstanding {
    held: BTreeSet<String>,
}

impl Outstanding {
    /// Records `nonce` as sent and not yet answered.
    pub fn issue(&mut self, nonce: impl Into<String>) {
        self.held.insert(nonce.into());
    }
}

impl Nonces for Outstanding {
    fn spend(&mut self, nonce: &str) -> bool {
        self.held.remove(nonce)
    }
}

/// What the PEP expects of the response it asked for.
#[derive(Debug, Clone)]
pub struct Expectation<'a> {
    /// Its own authenticated principal, as the PDP authorizes it.
    pub audience: &'a str,
    /// The PEP's clock, epoch seconds.
    pub now: i64,
    /// The `validity_seconds` discovery advertised.
    pub validity_seconds: u32,
    /// The `clock_skew_seconds` discovery advertised.
    pub clock_skew_seconds: u32,
    /// The exact policy state the PEP requires. `None` skips this binding: a PEP that passes it
    /// must check the returned [`Payload::policy`] itself, since the contract requires it.
    pub policy: Option<&'a Policy>,
}

/// The closed protected header.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    kid: String,
    typ: String,
}

/// The closed flattened JWS.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Flattened {
    protected: String,
    payload: String,
    signature: String,
}

/// Verifies the response `response` received to the request `request` it sent, under the pinned
/// `data.attest` keys `keys`, and spends its nonce from `nonces`: the payload when everything
/// binds, the failed binding otherwise.
pub fn verify(
    request: &[u8],
    response: &[u8],
    keys: &[Jwk],
    expected: &Expectation<'_>,
    nonces: &mut dyn Nonces,
) -> Result<Payload, Refused> {
    // Strict JSON both ways: one value, no duplicated member at any level.
    let sent = permguard_languages::attestation::strict_json(request).map_err(|error| {
        failed_at(
            "request_digest",
            format!("the request is not strict JSON: {error}"),
        )
    })?;
    let sent: permguard_languages::CheckRequest = serde_json::from_value(sent)
        .map_err(|error| failed_at("request_digest", format!("the request is not one: {error}")))?;
    let mut received =
        permguard_languages::attestation::strict_json(response).map_err(|error| {
            failed_at(
                "response",
                format!("the response is not strict JSON: {error}"),
            )
        })?;
    let Some(members) = received.as_object_mut() else {
        return Err(failed_at("response", "the response is not an object"));
    };
    let Some(attestation) = members.remove("attestation") else {
        return Err(failed_at(
            "attestation",
            "the response carries no attestation",
        ));
    };
    let flattened: Flattened = serde_json::from_value(attestation).map_err(|error| {
        failed_at(
            "attestation",
            format!("not a closed flattened JWS: {error}"),
        )
    })?;

    let protected = decoded(&flattened.protected)?;
    let payload_bytes = decoded(&flattened.payload)?;
    let signature = decoded(&flattened.signature)?;

    // The header: exactly its JCS bytes, closed, this type, this algorithm.
    let header = permguard_languages::attestation::canonical_json(&protected)
        .map_err(|error| failed_at("header", format!("not a JCS object: {error}")))?;
    let header: Header = serde_json::from_value(header)
        .map_err(|error| failed_at("header", format!("not the closed header: {error}")))?;
    if header.typ != permguard_core::domains::protected::DECISION_RESPONSE {
        return Err(failed_at(
            "type",
            format!("`{}` is not a signed decision response", header.typ),
        ));
    }
    // The artifact is signed in EdDSA; anything else is another algorithm, refused before a key
    // is consulted.
    if header.alg != Suite::Ed25519Sha256V1.jws_alg() {
        return Err(failed_at(
            "algorithm",
            format!("`{}` is not EdDSA", header.alg),
        ));
    }
    let key = keys
        .iter()
        .find(|key| key.kid == header.kid)
        .ok_or_else(|| {
            failed_at(
                "key",
                format!("`{}` is no pinned `data.attest` key", header.kid),
            )
        })?;
    if key.usage != "sig"
        || key.alg != header.alg
        || key.kty != "OKP"
        || key.crv.as_deref() != Some("Ed25519")
    {
        return Err(failed_at(
            "key",
            format!("`{}` is not an Ed25519 signing key", header.kid),
        ));
    }
    let public_key =
        decoded(&key.x).map_err(|_| failed_at("key", "the pinned key does not decode"))?;
    if public_key.len() != Suite::Ed25519Sha256V1.public_key_len() {
        return Err(failed_at(
            "key",
            "the pinned key is not an Ed25519 public key",
        ));
    }
    Suite::Ed25519Sha256V1
        .verify(
            &public_key,
            format!("{}.{}", flattened.protected, flattened.payload).as_bytes(),
            &signature,
        )
        .map_err(|error| failed_at("signature", error.to_string()))?;

    // The payload: its JCS bytes, closed, every form exact.
    let payload = permguard_languages::attestation::canonical_json(&payload_bytes)
        .map_err(|error| failed_at("payload", format!("not a JCS object: {error}")))?;
    let payload: Payload = serde_json::from_value(payload)
        .map_err(|error| failed_at("payload", format!("not the closed payload: {error}")))?;
    payload
        .check()
        .map_err(|error| failed_at("payload", error))?;

    if payload.audience != expected.audience {
        return Err(failed_at(
            "audience",
            format!("addressed to `{}`", payload.audience),
        ));
    }
    let request_digest = permguard_languages::attestation::request_digest(&sent)
        .map_err(|error| failed_at("request_digest", error.to_string()))?;
    if payload.request_digest != request_digest {
        return Err(failed_at(
            "request_digest",
            "the response answers another request",
        ));
    }
    if Some(payload.request_nonce.as_str()) != sent.request_nonce.as_deref() {
        return Err(failed_at(
            "nonce",
            "the payload names another nonce than the one sent",
        ));
    }
    let response_digest = permguard_languages::attestation::response_value_digest(&received)
        .map_err(|error| failed_at("response_digest", error.to_string()))?;
    if payload.response_digest != response_digest {
        return Err(failed_at(
            "response_digest",
            "the payload signs another answer",
        ));
    }
    // What the payload says of the answer, against the answer it is beside.
    if received.get("decision").and_then(Value::as_bool) != Some(payload.decision) {
        return Err(failed_at("decision", "the payload states another decision"));
    }
    let (ids, evidence) = answered(&received);
    if ids != payload.request_ids {
        return Err(failed_at(
            "request_ids",
            "the payload names other evaluations",
        ));
    }
    let signed_evidence = serde_json::to_value(&payload.evidence)
        .map_err(|error| failed_at("evidence", error.to_string()))?;
    if evidence != Some(&signed_evidence) {
        return Err(failed_at(
            "evidence",
            "the payload states other evidence than the answer",
        ));
    }
    if let Some(policy) = expected.policy
        && *policy != payload.policy
    {
        return Err(failed_at("policy", "decided under another policy state"));
    }

    // The lifetime: no longer than advertised, and current within the advertised skew.
    let issued = permguard_languages::attestation::instant(&payload.issued_at, "issued_at")
        .map_err(|error| failed_at("lifetime", error))?;
    let expires = permguard_languages::attestation::instant(&payload.expires_at, "expires_at")
        .map_err(|error| failed_at("lifetime", error))?;
    let skew = i64::from(expected.clock_skew_seconds);
    if expires - issued > i64::from(expected.validity_seconds) {
        return Err(failed_at("lifetime", "valid for longer than advertised"));
    }
    if expected.now.saturating_add(skew) < issued {
        return Err(failed_at("lifetime", "issued in the future"));
    }
    if expected.now.saturating_sub(skew) > expires {
        return Err(failed_at("lifetime", "expired"));
    }

    // Everything binds: only now is the nonce spent.
    if !nonces.spend(&payload.request_nonce) {
        return Err(failed_at(
            "nonce",
            "not an outstanding nonce: unknown, or already spent",
        ));
    }
    Ok(payload)
}

/// One base64url value, its canonical encoding without padding only.
fn decoded(part: &str) -> Result<Vec<u8>, Refused> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|error| failed_at("encoding", format!("not canonical base64url: {error}")))
}

fn evidence_of(decision: &Value) -> Option<&Value> {
    decision
        .get("context")
        .and_then(|context| context.get("evidence"))
}

/// The request ids the answer carries, in order, and the evidence a signature binds: the single
/// decision's, or a batch's last evaluation's.
fn answered(response: &Value) -> (Vec<Option<String>>, Option<&Value>) {
    let id = |decision: &Value| {
        decision
            .get("request_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    };
    match response.get("evaluations").and_then(Value::as_array) {
        Some(evaluations) => (
            evaluations.iter().map(id).collect(),
            evaluations.last().and_then(evidence_of),
        ),
        None => (vec![id(response)], evidence_of(response)),
    }
}

#[cfg(test)]
mod tests;
