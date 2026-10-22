// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The signed decision response of `permguard.api.pdp.native.v1` (WP-6.6): the nonce that asks
//! for it, the evidence object every decision carries, and the two digests an attestation binds.
//!
//! ```text
//! request_digest  = "sha256:" ‖ hex(SHA-256("permguard.decision.request.v1\n"       ‖ JCS(normalized request)))
//! response_digest = "sha256:" ‖ hex(SHA-256("permguard.decision.response-body.v1\n" ‖ JCS(response, no attestation)))
//! ```
//!
//! The normalized request is the question as the plane decides it, with every default it applies
//! written out (decided autonomously under the owner's delegation of 2026-10-22, the blueprint
//! naming the request but not its form):
//!
//! ```json
//! {
//!   "interface": "permguard.api.pdp.native.v1",
//!   "store": {"zone": "…", "ledger": "…", "profile": "…"},
//!   "semantic": "execute_all",
//!   "request_id": null,
//!   "request_nonce": "…",
//!   "asserted_principal": null,
//!   "evaluations": [{"subject": {…}, "resource": {…}, "action": {…}, "context": {…},
//!                    "partition_inputs": {…}, "request_id": null}]
//! }
//! ```
//!
//! One entry per evaluation asked, a request without `evaluations[]` asking one; each with what it
//! inherits resolved into it. Every name is read as the plane reads it, trimmed, and an empty one
//! is absent, so a padded name and its trimmed form are one question. An absent `context` or `properties` stays absent: absence and an
//! empty container mean different things to a policy. What the transport carries beside the body
//! — the trace, the header's request id, the deadline — is not the question and is left out.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

use crate::request::{
    ActionBody, CheckRequest, CheckResponse, DEFAULT_PROFILE, EntityBody, INTERFACE, Semantic,
    named,
};

/// The fewest bytes a `request_nonce` decodes to.
pub const NONCE_MIN_BYTES: usize = 16;

/// The most bytes a `request_nonce` decodes to.
pub const NONCE_MAX_BYTES: usize = 64;

/// The bytes a `request_nonce` names: base64url without padding, the canonical encoding only,
/// 16 to 64 bytes. Anything else is not a nonce the contract defines.
pub fn nonce_bytes(nonce: &str) -> Result<Vec<u8>, String> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(nonce)
        .map_err(|error| {
            format!(
                "`request_nonce` is not base64url without padding in its canonical form: {error}"
            )
        })?;
    if !(NONCE_MIN_BYTES..=NONCE_MAX_BYTES).contains(&bytes.len()) {
        return Err(format!(
            "`request_nonce` decodes to {} bytes; it takes {NONCE_MIN_BYTES} to {NONCE_MAX_BYTES}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

/// What a deployment promises about recording a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceMode {
    /// Recorded durably before the answer, or not answered.
    Required,
    /// Recorded when it can be, the answer saying which.
    BestEffort,
    /// No record promised.
    Disabled,
}

/// What became of one decision's record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    /// Recorded, at the position the evidence names.
    Durable,
    /// A permit the sampling rate left out.
    SampledOut,
    /// Not recorded, and counted as a loss.
    Dropped,
    /// No log.
    Disabled,
}

/// Where a durable record sits: the Host that wrote it, its run and its sequence there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Position {
    /// The Host's id, a lowercase hyphenated UUID.
    pub host_id: String,
    /// The run, as the record's stream names it: 32 lowercase hex digits.
    pub run: String,
    /// The sequence in the run, unsigned decimal text.
    pub sequence: String,
}

/// The evidence of one decision: closed, every member present, `null` where it names nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub mode: EvidenceMode,
    pub status: EvidenceStatus,
    pub record_id: Option<String>,
    pub position: Option<Position>,
}

impl Evidence {
    /// A decision recorded under `mode`, as `record_id` at `position`.
    pub fn durable(mode: EvidenceMode, record_id: String, position: Position) -> Self {
        Self {
            mode,
            status: EvidenceStatus::Durable,
            record_id: Some(record_id),
            position: Some(position),
        }
    }

    /// A decision `mode` left unrecorded with `status`.
    pub fn unrecorded(mode: EvidenceMode, status: EvidenceStatus) -> Self {
        Self {
            mode,
            status,
            record_id: None,
            position: None,
        }
    }

    /// A decision made with no log.
    pub fn disabled() -> Self {
        Self::unrecorded(EvidenceMode::Disabled, EvidenceStatus::Disabled)
    }

    /// Whether this evidence is one the contract allows for a decision that `permitted` or not:
    /// a durable status names its record and its position and no other status names either;
    /// `required` answers only durable, `disabled` only disabled, and only a permit is sampled
    /// out.
    pub fn check(&self, permitted: bool) -> Result<(), String> {
        let durable = self.status == EvidenceStatus::Durable;
        if durable != self.record_id.is_some() || durable != self.position.is_some() {
            return Err(
                "a durable status names its record and its position, and no other status names \
                 either"
                    .to_owned(),
            );
        }
        match (self.mode, self.status) {
            (EvidenceMode::Required, EvidenceStatus::Durable)
            | (EvidenceMode::Disabled, EvidenceStatus::Disabled)
            | (
                EvidenceMode::BestEffort,
                EvidenceStatus::Durable | EvidenceStatus::Dropped | EvidenceStatus::SampledOut,
            ) => {}
            (mode, status) => {
                return Err(format!(
                    "`{}` evidence cannot be `{}`",
                    to_text(&mode),
                    to_text(&status)
                ));
            }
        }
        if self.status == EvidenceStatus::SampledOut && !permitted {
            return Err("only a permit is sampled out".to_owned());
        }
        if let Some(position) = &self.position {
            position_forms(position)?;
        }
        Ok(())
    }
}

fn to_text<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_default()
}

/// The canonical forms of a durable position.
fn position_forms(position: &Position) -> Result<(), String> {
    if !is_uuid(&position.host_id) {
        return Err("`position.host_id` is not a lowercase hyphenated UUID".to_owned());
    }
    if position.run.len() != 32 || !is_lower_hex(&position.run) {
        return Err("`position.run` is not 32 lowercase hex digits".to_owned());
    }
    if !is_decimal_u64(&position.sequence) {
        return Err("`position.sequence` is not unsigned decimal text".to_owned());
    }
    Ok(())
}

/// Whether `text` is a UUID in its canonical lowercase hyphenated form.
pub fn is_uuid(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(at, byte)| match at {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(byte),
        })
}

fn is_lower_hex(text: &str) -> bool {
    text.bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Whether `text` is a `u64` in canonical decimal: digits only, no sign, no leading zero.
pub fn is_decimal_u64(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'))
        && text.parse::<u64>().is_ok()
}

/// Whether `text` is `sha256:` and 64 lowercase hex digits.
pub fn is_sha256(text: &str) -> bool {
    text.strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && is_lower_hex(hex))
}

/// The question `request` asks, as the request digest covers it: see the module's documentation.
pub fn normalized(request: &CheckRequest) -> Value {
    let semantic = request
        .options
        .as_ref()
        .and_then(|options| options.evaluations_semantic)
        .unwrap_or_default();
    let evaluations: Vec<Value> = if request.evaluations.is_empty() {
        vec![evaluation(
            request.subject.as_ref(),
            request.resource.as_ref(),
            request.action.as_ref(),
            request.context.as_ref(),
            &request.partition_inputs,
            named(&request.request_id),
        )]
    } else {
        request
            .evaluations
            .iter()
            .map(|asked| {
                evaluation(
                    asked.subject.as_ref().or(request.subject.as_ref()),
                    asked.resource.as_ref().or(request.resource.as_ref()),
                    asked.action.as_ref().or(request.action.as_ref()),
                    asked.context.as_ref().or(request.context.as_ref()),
                    asked
                        .partition_inputs
                        .as_ref()
                        .unwrap_or(&request.partition_inputs),
                    named(&asked.request_id),
                )
            })
            .collect()
    };
    json!({
        "interface": INTERFACE,
        "store": {
            "zone": named(&request.zone),
            "ledger": named(&request.ledger),
            "profile": named(&request.profile).unwrap_or_else(|| DEFAULT_PROFILE.to_owned()),
        },
        "semantic": semantic_text(semantic),
        "request_id": named(&request.request_id),
        "request_nonce": request.request_nonce,
        "asserted_principal": request.principal.as_ref().map(entity),
        "evaluations": evaluations,
    })
}

fn semantic_text(semantic: Semantic) -> String {
    to_text(&semantic)
}

fn evaluation(
    subject: Option<&EntityBody>,
    resource: Option<&EntityBody>,
    action: Option<&ActionBody>,
    context: Option<&Map<String, Value>>,
    partition_inputs: &crate::input::PartitionInputs,
    request_id: Option<String>,
) -> Value {
    let mut members = Map::new();
    members.insert("subject".to_owned(), subject.map(entity).into());
    members.insert("resource".to_owned(), resource.map(entity).into());
    members.insert("action".to_owned(), action.map(action_value).into());
    if let Some(context) = context {
        members.insert("context".to_owned(), Value::Object(context.clone()));
    }
    members.insert(
        "partition_inputs".to_owned(),
        serde_json::to_value(partition_inputs).unwrap_or(Value::Null),
    );
    members.insert("request_id".to_owned(), request_id.into());
    Value::Object(members)
}

fn entity(body: &EntityBody) -> Value {
    let mut members = Map::new();
    members.insert("type".to_owned(), named(&body.kind).into());
    members.insert("id".to_owned(), named(&body.id).into());
    if let Some(properties) = &body.properties {
        members.insert("properties".to_owned(), Value::Object(properties.clone()));
    }
    Value::Object(members)
}

fn action_value(body: &ActionBody) -> Value {
    let mut members = Map::new();
    members.insert("name".to_owned(), named(&body.name).into());
    if let Some(properties) = &body.properties {
        members.insert("properties".to_owned(), Value::Object(properties.clone()));
    }
    Value::Object(members)
}

/// Why a digest could not be taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestError(pub String);

impl std::fmt::Display for DigestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DigestError {}

fn digest(domain: &str, value: &Value) -> Result<String, DigestError> {
    let canonical = permguard_stream::jcs::canonicalize(value)
        .map_err(|error| DigestError(format!("{error:?}")))?;
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(&canonical);
    Ok(format!(
        "sha256:{}",
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

/// The request digest of `request`.
pub fn request_digest(request: &CheckRequest) -> Result<String, DigestError> {
    digest(
        permguard_core::domains::digest::DECISION_REQUEST,
        &normalized(request),
    )
}

/// The response digest of `response`: its JSON as the plane answers it, without `attestation`.
pub fn response_digest(response: &CheckResponse) -> Result<String, DigestError> {
    let mut value =
        serde_json::to_value(response).map_err(|error| DigestError(error.to_string()))?;
    if let Some(members) = value.as_object_mut() {
        members.remove("attestation");
    }
    response_value_digest(&value)
}

/// The response digest of a response already read as JSON, `attestation` removed: what a verifier
/// recomputes from the bytes it received.
pub fn response_value_digest(response: &Value) -> Result<String, DigestError> {
    digest(
        permguard_core::domains::digest::DECISION_RESPONSE_BODY,
        response,
    )
}

/// A flattened JWS: the three base64url values REST carries as `attestation` and gRPC as its
/// message of the same name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    pub protected: String,
    pub payload: String,
    pub signature: String,
}

/// The `v` of the payload this build writes and reads.
pub const PAYLOAD_VERSION: u32 = 1;

/// The exact policy state a decision was made under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// The Host whose head statement vouched for it, a canonical UUID.
    pub authority_host_id: String,
    pub zone_id: String,
    pub ledger_id: String,
    /// The resolved ref.
    #[serde(rename = "ref")]
    pub reference: String,
    /// The commit, `sha256:` and 64 lowercase hex digits.
    pub commit: String,
    /// The head statement's counter, unsigned decimal text.
    pub counter: String,
    /// The resolved profile.
    pub profile: String,
}

/// The closed payload of `permguard.decision.response.v1`: every member required, no other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    pub v: u32,
    pub interface: String,
    pub request_digest: String,
    pub request_nonce: String,
    /// One per effective evaluation in response order, one for the single endpoint.
    pub request_ids: Vec<Option<String>>,
    /// `ActorContext.authorization_principal`, exactly.
    pub audience: String,
    pub policy: Policy,
    pub decision: bool,
    pub response_digest: String,
    pub evidence: Evidence,
    /// Whole-second UTC RFC 3339.
    pub issued_at: String,
    pub expires_at: String,
}

impl Payload {
    /// Checks every form the contract fixes, beyond the closed shape: the version and interface,
    /// the digests, the nonce, the UUIDs, the counter, the evidence and the times, `issued_at`
    /// strictly before `expires_at`.
    pub fn check(&self) -> Result<(), String> {
        if self.v != PAYLOAD_VERSION {
            return Err(format!(
                "payload version {} is not {PAYLOAD_VERSION}",
                self.v
            ));
        }
        if self.interface != INTERFACE {
            return Err(format!("`{}` is not the native interface", self.interface));
        }
        for (name, digest) in [
            ("request_digest", &self.request_digest),
            ("response_digest", &self.response_digest),
            ("policy.commit", &self.policy.commit),
        ] {
            if !is_sha256(digest) {
                return Err(format!(
                    "`{name}` is not `sha256:` and 64 lowercase hex digits"
                ));
            }
        }
        nonce_bytes(&self.request_nonce)?;
        if self.request_ids.is_empty() {
            return Err("`request_ids` names no evaluation".to_owned());
        }
        if self.audience.is_empty() {
            return Err("`audience` is empty".to_owned());
        }
        for (name, id) in [
            ("policy.authority_host_id", &self.policy.authority_host_id),
            ("policy.zone_id", &self.policy.zone_id),
            ("policy.ledger_id", &self.policy.ledger_id),
        ] {
            if !is_uuid(id) {
                return Err(format!("`{name}` is not a lowercase hyphenated UUID"));
            }
        }
        if !is_decimal_u64(&self.policy.counter) {
            return Err("`policy.counter` is not unsigned decimal text".to_owned());
        }
        if self.policy.reference.is_empty() || self.policy.profile.is_empty() {
            return Err("`policy.ref` and `policy.profile` name something".to_owned());
        }
        self.evidence.check(self.decision)?;
        let issued = instant(&self.issued_at, "issued_at")?;
        let expires = instant(&self.expires_at, "expires_at")?;
        if issued >= expires {
            return Err("`issued_at` is not before `expires_at`".to_owned());
        }
        Ok(())
    }

    /// The payload's bytes: its JCS form, what the JWS carries.
    pub fn canonical(&self) -> Result<Vec<u8>, DigestError> {
        let value = serde_json::to_value(self).map_err(|error| DigestError(error.to_string()))?;
        permguard_stream::jcs::canonicalize(&value)
            .map_err(|error| DigestError(format!("{error:?}")))
    }
}

/// A whole-second UTC instant, `YYYY-MM-DDTHH:MM:SSZ`, in epoch seconds.
pub fn instant(text: &str, name: &str) -> Result<i64, String> {
    let well_formed = text.len() == 20
        && text.ends_with('Z')
        && text
            .as_bytes()
            .iter()
            .enumerate()
            .all(|(at, byte)| match at {
                4 | 7 => *byte == b'-',
                10 => *byte == b'T',
                13 | 16 => *byte == b':',
                19 => *byte == b'Z',
                _ => byte.is_ascii_digit(),
            });
    let seconds = well_formed
        .then(|| permguard_core::time::from_rfc3339(text))
        .flatten();
    match seconds {
        Some(seconds) if permguard_core::time::to_rfc3339(seconds) == text => Ok(seconds),
        _ => Err(format!("`{name}` is not a whole-second UTC instant")),
    }
}

#[cfg(test)]
mod tests;
