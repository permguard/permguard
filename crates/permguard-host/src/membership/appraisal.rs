// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Assurance appraisal (WP-4.2; owner decisions of 2026-10-10).
//!
//! The coordinator is the relying party. For every control a task requires it accepts one class of
//! evidence: the member's declaration, an operator's approval or a verifier's attestation. Its
//! appraisal policy names the least class each control needs, and the classes are a threshold:
//! a stronger one satisfies a weaker requirement, never the reverse. What it accepted is an
//! [`AssuranceBinding`] signed in the manifest, with an expiry. A task is admitted only under a
//! current accepted binding: under another policy revision, expired or revoked, it admits nothing,
//! and it never falls back to the declaration.
//!
//! Evidence is appraised by a [`Verifier`] registered in the composition, against a nonce bound to
//! the coordinator, the membership and the state appraised; no verifier ships, so with none
//! registered `attested` is refused. The evidence is kept by its digest alone.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use permguard_core::assurance::{AssuranceProfile, Control, EvidenceClass};
use permguard_core::authz::Resource;
use permguard_core::domains::digest;
use permguard_objects::cbor::Value;
use permguard_objects::digest::Digest;

use super::MembershipError;
use super::record::{
    AssuranceBinding, Claim, HostRef, Manifest, OperatorApproval, Status, Task, Verdict,
    check_reason, evidence_digest, result_digest,
};

/// The most pieces of evidence one appraisal takes.
pub const MAX_EVIDENCE_ITEMS: usize = 4;
/// The most bytes one piece of evidence takes.
pub const MAX_EVIDENCE_BYTES: usize = 64 * 1024;
/// The longest verifier id.
pub const MAX_VERIFIER_ID_BYTES: usize = 64;
/// The longest a binding may last: a year, as a manifest does (owner decision of 2026-10-10).
pub const MAX_BINDING_SECONDS: u64 = 365 * 86_400;

/// The coordinator's appraisal policy: the least class each control needs, and the longest a
/// binding lasts. Configured as `membership.appraisal`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    controls: BTreeMap<Control, EvidenceClass>,
    max_binding_seconds: u64,
}

impl Policy {
    pub fn new(controls: BTreeMap<Control, EvidenceClass>, max_binding: Duration) -> Self {
        Self {
            controls,
            // The configuration refuses zero and more than a year; clamped here all the same.
            max_binding_seconds: max_binding.as_secs().clamp(1, MAX_BINDING_SECONDS),
        }
    }

    /// The least class `control` needs; `None` when the policy does not appraise it.
    pub fn wants(&self, control: Control) -> Option<EvidenceClass> {
        self.controls.get(&control).copied()
    }

    pub fn max_binding_seconds(&self) -> u64 {
        self.max_binding_seconds
    }

    /// The canonical policy: the controls sorted by name, each with its least class, and the
    /// longest binding.
    pub fn encode(&self) -> Vec<u8> {
        let mut controls: Vec<(&str, &str)> = self
            .controls
            .iter()
            .map(|(control, class)| (control.name(), class.as_str()))
            .collect();
        controls.sort_unstable();
        let value = Value::Map(vec![
            (
                Value::Int(1),
                Value::Array(
                    controls
                        .into_iter()
                        .map(|(control, class)| {
                            Value::Array(vec![
                                Value::Text(control.to_owned()),
                                Value::Text(class.to_owned()),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                Value::Int(2),
                Value::Int(i64::try_from(self.max_binding_seconds).unwrap_or(i64::MAX)),
            ),
        ]);
        permguard_objects::cbor::encode(&value).expect("a policy always encodes")
    }

    /// The revision a binding names: SHA-256 of the canonical policy under its domain.
    pub fn revision(&self) -> Digest {
        let mut input = digest::MEMBERSHIP_APPRAISAL_POLICY.as_bytes().to_vec();
        input.extend_from_slice(&self.encode());
        Digest::compute(&input)
    }
}

impl Default for Policy {
    /// No control appraised: a task requiring one is unapprovable.
    fn default() -> Self {
        Self::new(
            BTreeMap::new(),
            permguard_core::config::DEFAULT_MEMBERSHIP_APPRAISAL_MAX_BINDING,
        )
    }
}

/// What a verifier accepted from one piece of evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Appraised {
    /// The controls the evidence shows, by the verifier's own reference values.
    pub controls: Vec<Control>,
    /// Until when its result stands.
    pub expires_at: u64,
}

/// A verifier of attestation evidence, registered in the composition (owner decision of
/// 2026-10-10): it appraises evidence for a member against a nonce and its own reference values.
/// The Host keeps the evidence's digest and the verifier's id, never the evidence.
pub trait Verifier: Send + Sync {
    /// Appraises `evidence` for `member`: the evidence must be bound to `nonce`, fresh, and match
    /// the verifier's reference values; the answer is the controls it accepts and until when.
    fn appraise(
        &self,
        member: &HostRef,
        nonce: &[u8; 32],
        evidence: &[u8],
        now: u64,
    ) -> Result<Appraised, String>;
}

/// The verifiers a composition registered, by id.
#[derive(Clone, Default)]
pub struct Verifiers(BTreeMap<String, Arc<dyn Verifier>>);

impl fmt::Debug for Verifiers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.0.keys()).finish()
    }
}

impl Verifiers {
    pub fn register(mut self, id: impl Into<String>, verifier: Arc<dyn Verifier>) -> Self {
        self.0.insert(id.into(), verifier);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn get(&self, id: &str) -> Option<&Arc<dyn Verifier>> {
        self.0.get(id)
    }
}

/// The nonce evidence for one appraisal is bound to: the coordinator, the membership and the state
/// appraised, so a result serves one revision.
pub fn nonce(coordinator: &[u8; 16], membership_id: &[u8; 16], state: &Digest) -> [u8; 32] {
    let mut input = digest::MEMBERSHIP_ASSURANCE_NONCE.as_bytes().to_vec();
    input.extend_from_slice(coordinator);
    input.extend_from_slice(membership_id);
    input.extend_from_slice(state.to_string().as_bytes());
    *Digest::compute(&input).raw()
}

/// An operator's approval of one control, as a request carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    pub control: Control,
    pub reason: String,
    pub expires_at: u64,
}

/// One piece of evidence for a registered verifier.
#[derive(Clone, PartialEq, Eq)]
pub struct Evidence {
    pub verifier: String,
    pub evidence: Vec<u8>,
}

impl fmt::Debug for Evidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Privacy-sensitive: never in a log line.
        f.debug_struct("Evidence")
            .field("verifier", &self.verifier)
            .field("bytes", &self.evidence.len())
            .finish()
    }
}

/// What an appraisal is asked to appraise.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub membership_id: &'a [u8; 16],
    pub member: &'a HostRef,
    pub declared: AssuranceProfile,
    pub tasks: &'a [Task],
    pub approvals: &'a [Approval],
    pub evidence: &'a [Evidence],
    /// The authenticated principal asking.
    pub principal: &'a str,
    pub nonce: &'a [u8; 32],
    pub now: u64,
}

/// What an appraisal accepted: the binding, and the operator approvals it was given, which the
/// audit keeps whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub binding: Option<AssuranceBinding>,
    pub approvals: Vec<OperatorApproval>,
}

/// One required control as the policy and the declaration stand: what the member view shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    pub control: Control,
    /// The least class the policy wants; `None` when it does not appraise the control.
    pub wants: Option<EvidenceClass>,
    /// Whether the member's declaration meets it.
    pub declared: bool,
}

/// What a task admission answers: the binding it stands on and the latest a lease may run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admitted {
    /// The binding's digest; `None` when the task requires no control.
    pub binding: Option<Digest>,
    /// No lease outlives the binding; `None` when no binding bounds it.
    pub not_after: Option<u64>,
}

/// The controls `tasks` require, each with the tasks requiring it.
pub fn required(tasks: &[Task]) -> Result<BTreeMap<Control, Vec<String>>, MembershipError> {
    let mut required: BTreeMap<Control, Vec<String>> = BTreeMap::new();
    for task in tasks {
        for name in &task.assurance_requirements {
            let control: Control = name.parse().map_err(MembershipError::Invalid)?;
            if control.name() != name {
                return Err(MembershipError::Invalid(format!(
                    "`{name}` is not spelled as the control `{control}`"
                )));
            }
            let ids = required.entry(control).or_default();
            if !ids.contains(&task.task_id) {
                ids.push(task.task_id.clone());
            }
        }
    }
    for ids in required.values_mut() {
        ids.sort_unstable();
    }
    Ok(required)
}

fn declares(declared: AssuranceProfile, control: Control) -> bool {
    declared.at_least(control.floor())
}

/// The coordinator's appraisal: its policy and the verifiers it trusts.
#[derive(Debug, Clone, Default)]
pub struct Appraisal {
    pub policy: Policy,
    pub verifiers: Verifiers,
}

impl Appraisal {
    pub fn new(policy: Policy, verifiers: Verifiers) -> Self {
        Self { policy, verifiers }
    }

    /// Each control `tasks` require, with the class the policy wants and whether `declared`
    /// meets it.
    pub fn requirements(
        &self,
        tasks: &[Task],
        declared: AssuranceProfile,
    ) -> Result<Vec<Requirement>, MembershipError> {
        Ok(required(tasks)?
            .into_keys()
            .map(|control| Requirement {
                control,
                wants: self.policy.wants(control),
                declared: declares(declared, control),
            })
            .collect())
    }

    /// Appraises what `request` offers for the controls its tasks require: the binding it
    /// accepts, or the refusal naming what falls short.
    pub fn appraise(&self, request: &Request<'_>) -> Result<Outcome, MembershipError> {
        let required = required(request.tasks)?;
        let now = request.now;
        if required.is_empty() {
            if !request.approvals.is_empty() || !request.evidence.is_empty() {
                return Err(MembershipError::Invalid(
                    "no task requires a control: approvals and evidence appraise nothing"
                        .to_owned(),
                ));
            }
            return Ok(Outcome {
                binding: None,
                approvals: Vec::new(),
            });
        }
        let mut wanted = BTreeMap::new();
        for control in required.keys() {
            let class = self.policy.wants(*control).ok_or_else(|| {
                MembershipError::AssuranceRefused(format!(
                    "the appraisal policy does not appraise `{control}`, which a task requires"
                ))
            })?;
            wanted.insert(*control, class);
        }

        // The operator's approvals: one per control a task requires, each with its reason and an
        // expiry ahead.
        let mut approved: BTreeMap<Control, (OperatorApproval, Digest)> = BTreeMap::new();
        for approval in request.approvals {
            let Some(task_ids) = required.get(&approval.control) else {
                return Err(MembershipError::Invalid(format!(
                    "no task requires `{}`: an approval of it appraises nothing",
                    approval.control
                )));
            };
            check_reason(&approval.reason).map_err(|error| MembershipError::Invalid(error.0))?;
            if approval.expires_at <= now {
                return Err(MembershipError::Invalid(format!(
                    "the approval of `{}` has already expired",
                    approval.control
                )));
            }
            let record = OperatorApproval {
                membership_id: *request.membership_id,
                control: approval.control,
                principal: request.principal.to_owned(),
                task_ids: task_ids.clone(),
                reason: approval.reason.clone(),
                expires_at: approval.expires_at,
                approved_at: now,
            };
            let digest = record.digest()?;
            if approved
                .insert(approval.control, (record, digest))
                .is_some()
            {
                return Err(MembershipError::Invalid(format!(
                    "`{}` is approved twice",
                    approval.control
                )));
            }
        }

        // The evidence, each piece for the verifier it names, against this revision's nonce.
        if request.evidence.len() > MAX_EVIDENCE_ITEMS {
            return Err(MembershipError::Invalid(format!(
                "at most {MAX_EVIDENCE_ITEMS} pieces of evidence"
            )));
        }
        let mut attested: BTreeMap<Control, (String, Digest, u64)> = BTreeMap::new();
        for item in request.evidence {
            if item.evidence.is_empty() || item.evidence.len() > MAX_EVIDENCE_BYTES {
                return Err(MembershipError::Invalid(format!(
                    "a piece of evidence takes 1 to {MAX_EVIDENCE_BYTES} bytes"
                )));
            }
            if item.verifier.is_empty()
                || item.verifier.len() > MAX_VERIFIER_ID_BYTES
                || item.verifier.chars().any(char::is_control)
            {
                return Err(MembershipError::Invalid(format!(
                    "a verifier id is printable text of 1 to {MAX_VERIFIER_ID_BYTES} bytes"
                )));
            }
            let verifier = self.verifiers.get(&item.verifier).ok_or_else(|| {
                MembershipError::AssuranceUnavailable(format!(
                    "no verifier `{}` is registered on this Host",
                    item.verifier
                ))
            })?;
            let appraised = verifier
                .appraise(request.member, request.nonce, &item.evidence, now)
                .map_err(|reason| {
                    // The verifier's words may quote the evidence: logged, never answered or
                    // audited.
                    tracing::warn!(
                        event.name = "host.assurance_evidence_refused",
                        component = "host",
                        verifier = %item.verifier,
                        reason = %reason,
                        "a verifier refused a piece of attestation evidence"
                    );
                    MembershipError::AssuranceRefused(format!(
                        "the verifier `{}` refused the evidence",
                        item.verifier
                    ))
                })?;
            if appraised.expires_at <= now {
                return Err(MembershipError::AssuranceRefused(format!(
                    "the verifier `{}` answered a result already expired",
                    item.verifier
                )));
            }
            let digest = evidence_digest(&item.verifier, &item.evidence)?;
            for control in appraised.controls {
                if !required.contains_key(&control) {
                    continue;
                }
                let later = attested
                    .get(&control)
                    .is_none_or(|(_, _, expires)| appraised.expires_at > *expires);
                if later {
                    attested.insert(
                        control,
                        (item.verifier.clone(), digest.clone(), appraised.expires_at),
                    );
                }
            }
        }

        // For each control the strongest evidence offered, which must meet the policy.
        let mut claims = Vec::new();
        let mut expires_at = now.saturating_add(self.policy.max_binding_seconds());
        let mut short = Vec::new();
        let mut unattestable = false;
        for (control, wants) in &wanted {
            let (claim, until) = if let Some((verifier, digest, until)) = attested.get(control) {
                (
                    Claim {
                        control: *control,
                        class: EvidenceClass::Attested,
                        by: verifier.clone(),
                        record: Some(digest.clone()),
                    },
                    Some(*until),
                )
            } else if let Some((record, digest)) = approved.get(control) {
                (
                    Claim {
                        control: *control,
                        class: EvidenceClass::OperatorApproved,
                        by: record.principal.clone(),
                        record: Some(digest.clone()),
                    },
                    Some(record.expires_at),
                )
            } else if declares(request.declared, *control) {
                (
                    Claim {
                        control: *control,
                        class: EvidenceClass::Declared,
                        by: request.declared.as_str().to_owned(),
                        record: None,
                    },
                    None,
                )
            } else {
                unattestable |= *wants == EvidenceClass::Attested;
                short.push(format!(
                    "`{control}` needs `{wants}`, and nothing was offered"
                ));
                continue;
            };
            if claim.class < *wants {
                unattestable |= *wants == EvidenceClass::Attested;
                short.push(format!(
                    "`{control}` needs `{wants}`, and only `{}` was offered",
                    claim.class
                ));
                continue;
            }
            if let Some(until) = until {
                expires_at = expires_at.min(until);
            }
            claims.push(claim);
        }
        if !short.is_empty() {
            // A control wants an attestation this Host has no verifier to give: unavailable here,
            // whatever is offered.
            if unattestable && self.verifiers.is_empty() {
                return Err(MembershipError::AssuranceUnavailable(format!(
                    "no verifier is registered on this Host: {}",
                    short.join("; ")
                )));
            }
            return Err(MembershipError::AssuranceRefused(short.join("; ")));
        }
        claims.sort_by(|a, b| a.control.name().cmp(b.control.name()));
        let mut task_ids: Vec<String> = required.values().flatten().cloned().collect();
        task_ids.sort_unstable();
        task_ids.dedup();
        let policy_revision = self.policy.revision();
        let result_digest = result_digest(request.member, &task_ids, &policy_revision, &claims)?;
        Ok(Outcome {
            binding: Some(AssuranceBinding {
                member: request.member.clone(),
                task_ids,
                policy_revision,
                claims,
                result_digest,
                appraised_by: request.principal.to_owned(),
                issued_at: now,
                expires_at,
                verdict: Verdict::Accepted,
            }),
            approvals: approved.into_values().map(|(record, _)| record).collect(),
        })
    }

    /// `binding` revoked by `principal` at `now`: it admits nothing from then on, and keeps what it
    /// had accepted for the record.
    pub fn revoked(binding: &AssuranceBinding, principal: &str, now: u64) -> AssuranceBinding {
        AssuranceBinding {
            appraised_by: principal.to_owned(),
            expires_at: binding.expires_at.min(now.max(binding.issued_at)),
            verdict: Verdict::Revoked,
            ..binding.clone()
        }
    }

    /// The attested claim whose verifier is no longer registered, if any: its result no longer
    /// stands (owner decision of 2026-10-10).
    fn orphaned_attestation<'b>(&self, binding: &'b AssuranceBinding) -> Option<&'b Claim> {
        binding.claims.iter().find(|claim| {
            claim.class == EvidenceClass::Attested && self.verifiers.get(&claim.by).is_none()
        })
    }

    /// Whether `binding` stands now: accepted, unexpired, under the current policy, and every
    /// attestation's verifier still registered.
    pub fn is_current(&self, binding: &AssuranceBinding, now: u64) -> bool {
        binding.verdict == Verdict::Accepted
            && now < binding.expires_at
            && binding.policy_revision == self.policy.revision()
            && self.orphaned_attestation(binding).is_none()
    }

    /// Admits a task of an active `manifest` over `resource`: the binding it stands on and the
    /// latest a lease may run. A task requiring controls needs a current accepted binding whose
    /// claims meet the policy as it is now; it never falls back to the declaration.
    pub fn admit(
        &self,
        manifest: &Manifest,
        task_id: &str,
        resource: &Resource,
        now: u64,
    ) -> Result<Admitted, MembershipError> {
        if manifest.status != Status::Active {
            return Err(MembershipError::Invalid(format!(
                "the membership is {}: no task is admitted",
                manifest.status
            )));
        }
        let task = manifest
            .tasks
            .iter()
            .find(|task| task.task_id == task_id)
            .ok_or_else(|| {
                MembershipError::Invalid(format!("the membership grants no task `{task_id}`"))
            })?;
        if !task.selector.contains(resource) {
            return Err(MembershipError::Invalid(format!(
                "`{resource}` is outside the task's selector"
            )));
        }
        let required = required(std::slice::from_ref(task))?;
        if required.is_empty() {
            return Ok(Admitted {
                binding: None,
                not_after: None,
            });
        }
        let binding = manifest.assurance_binding.as_ref().ok_or_else(|| {
            MembershipError::AssuranceRefused(format!(
                "the task `{task_id}` requires controls and the membership has no assurance binding"
            ))
        })?;
        if binding.verdict != Verdict::Accepted {
            return Err(MembershipError::AssuranceRefused(
                "the assurance binding was revoked".to_owned(),
            ));
        }
        if now >= binding.expires_at {
            return Err(MembershipError::AssuranceRefused(
                "the assurance binding has expired: appraise the member again".to_owned(),
            ));
        }
        if binding.policy_revision != self.policy.revision() {
            return Err(MembershipError::AssuranceRefused(
                "the assurance binding was appraised under another policy: appraise the member \
                 again"
                    .to_owned(),
            ));
        }
        if !binding.covers(task_id) {
            return Err(MembershipError::AssuranceRefused(format!(
                "the assurance binding does not cover the task `{task_id}`"
            )));
        }
        if let Some(claim) = self.orphaned_attestation(binding) {
            return Err(MembershipError::AssuranceRefused(format!(
                "the verifier `{}` that attested `{}` is no longer registered: appraise the \
                 member again",
                claim.by, claim.control
            )));
        }
        for control in required.keys() {
            let wants = self.policy.wants(*control).ok_or_else(|| {
                MembershipError::AssuranceRefused(format!(
                    "the appraisal policy does not appraise `{control}`"
                ))
            })?;
            match binding.claim(*control) {
                Some(claim) if claim.class >= wants => {}
                _ => {
                    return Err(MembershipError::AssuranceRefused(format!(
                        "`{control}` needs `{wants}` and the binding does not hold it"
                    )));
                }
            }
        }
        Ok(Admitted {
            binding: Some(binding.digest()?),
            not_after: Some(binding.expires_at),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests;
