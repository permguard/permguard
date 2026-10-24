// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Plan receipts and dual control (WP-3.9, owner decisions of 2026-10-11).
//!
//! A destructive operation runs in two steps. The plan step answers a capability receipt, a
//! COSE_Sign1 `permguard.operation.plan.v1` under the Host's `host.operations` key, and keeps the
//! plan in `host/state/replay`; the run step presents the receipt, which must be the one the plan
//! step answered, byte for byte, to the planner it names.
//!
//! | Label | Receipt field        | What it binds                                                 |
//! | ----- | -------------------- | ------------------------------------------------------------- |
//! | 1     | `plan_id`            | 16 bytes, the plan                                            |
//! | 2     | `operation`          | `grant.revoke`, `keys.revoke`, `membership.revoke`, `identity.reset`, `restore` |
//! | 3     | `target`             | the exact resource                                            |
//! | 4     | `revision`           | the target's revision or epoch the plan was made at           |
//! | 5     | `principal`          | the planner, who alone runs it                                |
//! | 6     | `plan_digest`        | what the plan changes ([`plan_digest`])                       |
//! | 7     | `expires`            | seconds; 10 minutes on, a day when approvals are required     |
//! | 8     | `nonce`              | 16 bytes                                                      |
//! | 9     | `approvals_required` | how many principals other than the planner must approve        |
//! | 10    | `host_id`            | 16 bytes, the Host                                            |
//! | 11    | `created_at`         | seconds                                                       |
//!
//! With `operations.dual_control` in force (required by `regulated`), an identity reset and a key
//! revocation require one approval: a principal other than the planner, holding the operation's
//! grant. Each approval is attested by the Host as a COSE_Sign1 `permguard.operation.approval.v1`
//! under `host.operations` over {1 `plan_digest`, 2 `principal`, 3 `approved_at`, 4 `host_id`};
//! operators authenticate by mTLS and hold no signing key.

use std::time::Duration;

use permguard_core::domains::digest::OPERATION_PLAN_BODY;
use permguard_core::domains::protected;
use permguard_core::keys::Sign as _;
use permguard_objects::cbor::{self, Value};
use permguard_objects::cose::Sign1;
use permguard_objects::digest::Digest;
use sha2::{Digest as _, Sha256};

use crate::audit::checkpoint::Keys;
use crate::audit::record::{Labelled, RecordError, hex, id16, uint};
use crate::keys::ring::{HOST_OPERATIONS, Ring};

/// An operator's revocation of a grant.
pub const GRANT_REVOKE: &str = "grant.revoke";
/// An operator's revocation of a ring key.
pub const KEYS_REVOKE: &str = "keys.revoke";
/// An operator's revocation of a membership.
pub const MEMBERSHIP_REVOKE: &str = "membership.revoke";
/// The Host identity's reset.
pub const IDENTITY_RESET: &str = "identity.reset";
/// The restore of a snapshot onto the volume, offline (WP-7.9).
pub const RESTORE: &str = "restore";
/// Every operation a receipt may name.
pub const OPERATIONS: &[&str] = &[
    GRANT_REVOKE,
    KEYS_REVOKE,
    MEMBERSHIP_REVOKE,
    IDENTITY_RESET,
    RESTORE,
];

/// How long a plan that requires no approval may be run after it was made.
pub const LIFETIME: Duration = Duration::from_secs(10 * 60);
/// How long a plan that requires approvals lives, approvals and run included.
pub const APPROVED_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);
/// The most bytes a receipt or an approval envelope takes.
pub const MAX_ENVELOPE_BYTES: usize = 16 * 1024;

type Result<T> = std::result::Result<T, RecordError>;

/// How many approvals `operation` requires, with dual control in force or not (owner decision
/// of 2026-10-11): one for an identity reset and a key revocation under it, none otherwise.
pub fn approvals_required(operation: &str, dual_control: bool) -> u64 {
    u64::from(dual_control && matches!(operation, IDENTITY_RESET | KEYS_REVOKE | RESTORE))
}

/// How long a plan requiring `approvals` lives.
pub fn lifetime(approvals: u64) -> Duration {
    if approvals == 0 {
        LIFETIME
    } else {
        APPROVED_LIFETIME
    }
}

/// The canonical bytes of what a plan changes: the CBOR map {1 operation, 2 target, 3 revision,
/// 4 {parameter: value}}, registered as `plan_body` in `contracts/cbor/operation-plan.json`.
pub fn plan_body(
    operation: &str,
    target: &str,
    revision: u64,
    parameters: &[(&str, &str)],
) -> Vec<u8> {
    let body = Value::Map(vec![
        (Value::Int(1), Value::Text(operation.to_owned())),
        (Value::Int(2), Value::Text(target.to_owned())),
        (
            Value::Int(3),
            Value::Int(i64::try_from(revision).unwrap_or(i64::MAX)),
        ),
        (
            Value::Int(4),
            Value::Map(
                parameters
                    .iter()
                    .map(|(name, value)| {
                        (
                            Value::Text((*name).to_owned()),
                            Value::Text((*value).to_owned()),
                        )
                    })
                    .collect(),
            ),
        ),
    ]);
    cbor::encode(&body).unwrap_or_default()
}

/// What a plan changes: SHA-256 over `digest::OPERATION_PLAN_BODY` and its [`plan_body`].
pub fn plan_digest(
    operation: &str,
    target: &str,
    revision: u64,
    parameters: &[(&str, &str)],
) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(OPERATION_PLAN_BODY.as_bytes());
    hasher.update(plan_body(operation, target, revision, parameters));
    let raw: [u8; 32] = hasher.finalize().into();
    #[allow(clippy::expect_used)]
    Digest::parse(&format!("sha256:{}", hex(&raw))).expect("a SHA-256 renders as a digest")
}

/// One plan receipt's payload (labels 1 to 11, owner decision of 2026-10-11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanReceipt {
    pub plan_id: [u8; 16],
    pub operation: String,
    pub target: String,
    pub revision: u64,
    pub principal: String,
    pub plan_digest: Digest,
    pub expires: u64,
    pub nonce: [u8; 16],
    pub approvals_required: u64,
    pub host_id: [u8; 16],
    pub created_at: u64,
}

impl PlanReceipt {
    /// The canonical bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        cbor::encode(&Value::Map(vec![
            (Value::Int(1), Value::Bytes(self.plan_id.to_vec())),
            (Value::Int(2), Value::Text(self.operation.clone())),
            (Value::Int(3), Value::Text(self.target.clone())),
            (Value::Int(4), uint(self.revision)?),
            (Value::Int(5), Value::Text(self.principal.clone())),
            (Value::Int(6), Value::Text(self.plan_digest.to_string())),
            (Value::Int(7), uint(self.expires)?),
            (Value::Int(8), Value::Bytes(self.nonce.to_vec())),
            (Value::Int(9), uint(self.approvals_required)?),
            (Value::Int(10), Value::Bytes(self.host_id.to_vec())),
            (Value::Int(11), uint(self.created_at)?),
        ]))
        .map_err(|error| RecordError::Cbor(error.to_string()))
    }

    /// Reads the canonical bytes, refusing an unknown label, a missing one, a value of another
    /// type and an operation no receipt names.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(RecordError::TooLarge(bytes.len()));
        }
        let value =
            cbor::decode_canonical(bytes).map_err(|error| RecordError::Cbor(error.to_string()))?;
        let mut map = Labelled::new(value, 11)?;
        let receipt = Self {
            plan_id: id16(map.bytes(1)?)?,
            operation: map.text(2)?,
            target: map.text(3)?,
            revision: map.uint(4)?,
            principal: map.text(5)?,
            plan_digest: map.digest(6)?,
            expires: map.uint(7)?,
            nonce: id16(map.bytes(8)?)?,
            approvals_required: map.uint(9)?,
            host_id: id16(map.bytes(10)?)?,
            created_at: map.uint(11)?,
        };
        map.finish()?;
        if !OPERATIONS.contains(&receipt.operation.as_str()) {
            return Err(RecordError::Malformed(
                "the receipt names no operation a plan names".to_owned(),
            ));
        }
        Ok(receipt)
    }
}

/// One approval's payload (labels 1 to 4, owner decision of 2026-10-11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    pub plan_digest: Digest,
    pub principal: String,
    pub approved_at: u64,
    pub host_id: [u8; 16],
}

impl Approval {
    /// The canonical bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        cbor::encode(&Value::Map(vec![
            (Value::Int(1), Value::Text(self.plan_digest.to_string())),
            (Value::Int(2), Value::Text(self.principal.clone())),
            (Value::Int(3), uint(self.approved_at)?),
            (Value::Int(4), Value::Bytes(self.host_id.to_vec())),
        ]))
        .map_err(|error| RecordError::Cbor(error.to_string()))
    }

    /// Reads the canonical bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(RecordError::TooLarge(bytes.len()));
        }
        let value =
            cbor::decode_canonical(bytes).map_err(|error| RecordError::Cbor(error.to_string()))?;
        let mut map = Labelled::new(value, 4)?;
        let approval = Self {
            plan_digest: map.digest(1)?,
            principal: map.text(2)?,
            approved_at: map.uint(3)?,
            host_id: id16(map.bytes(4)?)?,
        };
        map.finish()?;
        Ok(approval)
    }
}

/// What signs a receipt and an approval: the Host's `host.operations` ring.
pub trait PlanSigner: Send + Sync {
    /// The COSE_Sign1 `permguard.operation.plan.v1` over `receipt`.
    fn sign_receipt(&self, receipt: &PlanReceipt) -> std::result::Result<Vec<u8>, String>;
    /// The COSE_Sign1 `permguard.operation.approval.v1` over `approval`.
    fn sign_approval(&self, approval: &Approval) -> std::result::Result<Vec<u8>, String>;
}

impl PlanSigner for Ring {
    fn sign_receipt(&self, receipt: &PlanReceipt) -> std::result::Result<Vec<u8>, String> {
        let payload = receipt.encode().map_err(|error| error.to_string())?;
        sign(self, protected::OPERATION_PLAN, payload)
    }

    fn sign_approval(&self, approval: &Approval) -> std::result::Result<Vec<u8>, String> {
        let payload = approval.encode().map_err(|error| error.to_string())?;
        sign(self, protected::OPERATION_APPROVAL, payload)
    }
}

/// A COSE_Sign1 of `content_type` over `payload` by the active `host.operations` key, under its
/// kid; a key that turns between the kid and the signature is refused.
fn sign(ring: &Ring, content_type: &str, payload: Vec<u8>) -> std::result::Result<Vec<u8>, String> {
    if ring.id() != HOST_OPERATIONS {
        return Err(format!(
            "a plan is signed under `{HOST_OPERATIONS}`, not `{}`",
            ring.id()
        ));
    }
    let kid = ring.active_key_id().map_err(|error| error.to_string())?;
    let envelope = Sign1::sign_with(
        ring.suite(),
        content_type,
        kid.as_str().as_bytes(),
        payload,
        |bytes| {
            let signature =
                permguard_core::keys::Sign::sign(ring, bytes).map_err(|e| e.to_string())?;
            if signature.key_id() != &kid {
                return Err("the signing key rotated mid-signature".to_owned());
            }
            Ok(signature.bytes().to_vec())
        },
    )
    .map_err(|error| error.to_string())?;
    envelope.encode().map_err(|error| error.to_string())
}

/// The payload of a receipt envelope, **without verifying** its signature: what the Host reads
/// of a receipt presented to it before comparing it with the one it keeps.
pub fn read_receipt(envelope: &[u8]) -> std::result::Result<PlanReceipt, String> {
    if envelope.len() > MAX_ENVELOPE_BYTES {
        return Err(format!(
            "{} bytes; a plan receipt takes up to {MAX_ENVELOPE_BYTES}",
            envelope.len()
        ));
    }
    let sign1 = Sign1::decode(envelope).map_err(|error| error.to_string())?;
    let header = sign1.header().map_err(|error| error.to_string())?;
    if header.content_type != protected::OPERATION_PLAN {
        return Err("the envelope is not a plan receipt".to_owned());
    }
    PlanReceipt::decode(sign1.payload_unverified()).map_err(|error| error.to_string())
}

/// Verifies a receipt with `host.operations` keys kept apart and answers its payload.
pub fn verify_receipt(keys: &Keys, envelope: &[u8]) -> std::result::Result<PlanReceipt, String> {
    let (payload, _, _) =
        keys.verify_envelope(envelope, protected::OPERATION_PLAN, MAX_ENVELOPE_BYTES)?;
    PlanReceipt::decode(&payload).map_err(|error| error.to_string())
}

/// Verifies an approval with `host.operations` keys kept apart and answers its payload.
pub fn verify_approval(keys: &Keys, envelope: &[u8]) -> std::result::Result<Approval, String> {
    let (payload, _, _) =
        keys.verify_envelope(envelope, protected::OPERATION_APPROVAL, MAX_ENVELOPE_BYTES)?;
    Approval::decode(&payload).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests;
