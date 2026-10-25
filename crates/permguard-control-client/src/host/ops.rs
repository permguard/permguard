// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host listener's key rings, audit trails, configuration and plans, as a client sees them
//! (TC-2): what the `host keys`, `host audit`, `host config` and `host plans` commands reach,
//! over REST and gRPC alike. The answers are the Host API's own views; bytes the views spell
//! base64url travel raw on gRPC and are spelled back here.

use permguard_host::api::Planned;
use permguard_host::api::audit::{
    AuditAnchorView, AuditCheckpointQuery, AuditCheckpointView, AuditCheckpoints, AuditExportPage,
    AuditExportQuery, AuditGapView, AuditQuery, AuditRecordPage, AuditRecordView,
};
use permguard_host::api::config::{Effective, Revision, Revisions, Setting};
use permguard_host::api::keys::{
    KeyBundlePage, KeyBundleQuery, KeyRevoked, KeyView, PlanKeyRevoke, RingRotated, RingSummary,
    RingView, Rings, RotateRing, RunKeyRevoke,
};
use permguard_host::api::plans::{ApprovalView, ApprovePlan, PlanApproved, PlanList, PlanView};

use super::{GrpcHost, RestHost, json, query_value, segment, usage};
use crate::catalog::Failure;
use crate::host_proto as map;
use crate::host_v1 as proto;

/// The Host's key rings, audit trails, configuration and plans (TC-2).
pub trait Operations {
    /// `GET /host/v1/keys`, `KeyService.ListKeyRings`.
    fn rings(&self) -> Result<Rings, Failure>;
    /// `GET /host/v1/keys/{ring}`, `KeyService.GetKeyRing`.
    fn ring(&self, ring: &str) -> Result<RingView, Failure>;
    /// `POST /host/v1/keys/{ring}/rotate`, `KeyService.RotateKeyRing`.
    fn rotate_ring(&self, ring: &str, request: &RotateRing) -> Result<RingRotated, Failure>;
    /// `POST /host/v1/keys/{ring}/revoke/plan`, `KeyService.PlanKeyRevoke`.
    fn plan_key_revoke(&self, ring: &str, request: &PlanKeyRevoke) -> Result<Planned, Failure>;
    /// `POST /host/v1/keys/{ring}/revoke/run`, `KeyService.RunKeyRevoke`.
    fn run_key_revoke(&self, ring: &str, request: &RunKeyRevoke) -> Result<KeyRevoked, Failure>;
    /// `GET /host/v1/keys/bundle`, `KeyService.GetKeyBundle`: one page.
    fn key_bundle(&self, query: &KeyBundleQuery) -> Result<KeyBundlePage, Failure>;
    /// `GET /host/v1/audit/{class}/records`, `EvidenceService.ListAuditRecords`.
    fn audit_records(&self, class: &str, query: &AuditQuery) -> Result<AuditRecordPage, Failure>;
    /// `GET /host/v1/audit/{class}/checkpoints`, `EvidenceService.ListAuditCheckpoints`.
    fn audit_checkpoints(
        &self,
        class: &str,
        query: &AuditCheckpointQuery,
    ) -> Result<AuditCheckpoints, Failure>;
    /// `GET /host/v1/audit/{class}/export`, `EvidenceService.ExportAudit`: one page.
    fn audit_export(
        &self,
        class: &str,
        query: &AuditExportQuery,
    ) -> Result<AuditExportPage, Failure>;
    /// `GET /host/v1/config/effective`, `OperationsService.GetEffectiveConfig`.
    fn effective_config(&self) -> Result<Effective, Failure>;
    /// `GET /host/v1/config/revisions`, `OperationsService.ListConfigRevisions`.
    fn config_revisions(&self) -> Result<Revisions, Failure>;
    /// `GET /host/v1/plans?status`, `OperationsService.ListPlans`.
    fn plans(&self, status: Option<&str>) -> Result<PlanList, Failure>;
    /// `POST /host/v1/plans/{id}/approve`, `OperationsService.ApprovePlan`.
    fn approve_plan(&self, plan_id: &str, request: &ApprovePlan) -> Result<PlanApproved, Failure>;
}

/// `?name=value&…` of the members given, percent-encoded; empty when none is.
fn query(members: &[(&str, Option<String>)]) -> String {
    let given: Vec<String> = members
        .iter()
        .filter_map(|(name, value)| {
            value
                .as_ref()
                .map(|value| format!("{name}={}", query_value(value)))
        })
        .collect();
    if given.is_empty() {
        String::new()
    } else {
        format!("?{}", given.join("&"))
    }
}

impl Operations for RestHost {
    fn rings(&self) -> Result<Rings, Failure> {
        self.get("/host/v1/keys")
    }

    fn ring(&self, ring: &str) -> Result<RingView, Failure> {
        self.get(&format!("/host/v1/keys/{}", segment(ring)?))
    }

    fn rotate_ring(&self, ring: &str, request: &RotateRing) -> Result<RingRotated, Failure> {
        self.post(
            &format!("/host/v1/keys/{}/rotate", segment(ring)?),
            &json(request)?,
        )
    }

    fn plan_key_revoke(&self, ring: &str, request: &PlanKeyRevoke) -> Result<Planned, Failure> {
        self.post(
            &format!("/host/v1/keys/{}/revoke/plan", segment(ring)?),
            &json(request)?,
        )
    }

    fn run_key_revoke(&self, ring: &str, request: &RunKeyRevoke) -> Result<KeyRevoked, Failure> {
        self.post(
            &format!("/host/v1/keys/{}/revoke/run", segment(ring)?),
            &json(request)?,
        )
    }

    fn key_bundle(&self, asked: &KeyBundleQuery) -> Result<KeyBundlePage, Failure> {
        self.get(&format!(
            "/host/v1/keys/bundle{}",
            query(&[
                ("resource", Some(asked.resource.clone())),
                ("frontier", asked.frontier.clone()),
                ("cursor", asked.cursor.clone()),
                ("limit", asked.limit.map(|limit| limit.to_string())),
            ])
        ))
    }

    fn audit_records(&self, class: &str, asked: &AuditQuery) -> Result<AuditRecordPage, Failure> {
        self.get(&format!(
            "/host/v1/audit/{}/records{}",
            segment(class)?,
            query(&[
                ("resource", Some(asked.resource.clone())),
                ("from", asked.from.map(|from| from.to_string())),
                ("to", asked.to.map(|to| to.to_string())),
                ("cursor", asked.cursor.clone()),
                ("limit", asked.limit.map(|limit| limit.to_string())),
            ])
        ))
    }

    fn audit_checkpoints(
        &self,
        class: &str,
        asked: &AuditCheckpointQuery,
    ) -> Result<AuditCheckpoints, Failure> {
        self.get(&format!(
            "/host/v1/audit/{}/checkpoints{}",
            segment(class)?,
            query(&[
                ("resource", Some(asked.resource.clone())),
                ("period", asked.period.clone()),
            ])
        ))
    }

    fn audit_export(
        &self,
        class: &str,
        asked: &AuditExportQuery,
    ) -> Result<AuditExportPage, Failure> {
        self.get(&format!(
            "/host/v1/audit/{}/export{}",
            segment(class)?,
            query(&[
                ("resource", Some(asked.resource.clone())),
                (
                    "frontier",
                    asked.frontier.map(|frontier| frontier.to_string())
                ),
                ("cursor", asked.cursor.clone()),
                ("limit", asked.limit.map(|limit| limit.to_string())),
            ])
        ))
    }

    fn effective_config(&self) -> Result<Effective, Failure> {
        self.get("/host/v1/config/effective")
    }

    fn config_revisions(&self) -> Result<Revisions, Failure> {
        self.get("/host/v1/config/revisions")
    }

    fn plans(&self, status: Option<&str>) -> Result<PlanList, Failure> {
        self.get(&format!(
            "/host/v1/plans{}",
            query(&[("status", status.map(str::to_owned))])
        ))
    }

    fn approve_plan(&self, plan_id: &str, request: &ApprovePlan) -> Result<PlanApproved, Failure> {
        self.post(
            &format!("/host/v1/plans/{}/approve", segment(plan_id)?),
            &json(request)?,
        )
    }
}

/// An empty string is no value on gRPC.
fn blank(text: Option<&String>) -> String {
    text.cloned().unwrap_or_default()
}

fn ring_in(answer: proto::GetKeyRingResponse) -> RingView {
    RingView {
        ring: answer.ring,
        epoch: answer.epoch,
        digest: answer.digest,
        binding: answer.binding.as_deref().map(map::b64),
        cache_max_age: answer.cache_max_age,
        keys: answer
            .keys
            .into_iter()
            .map(|key| KeyView {
                kid: key.kid,
                kty: key.kty,
                crv: key.crv,
                x: key.x,
                y: key.y,
                alg: key.alg,
                usage: key.r#use,
            })
            .collect(),
    }
}

fn records_in(records: Vec<proto::AuditRecord>) -> Vec<AuditRecordView> {
    records
        .into_iter()
        .map(|record| AuditRecordView {
            seq: record.seq,
            at: record.at,
            action: record.action,
            outcome: record.outcome,
            digest: record.digest,
            record: map::b64(&record.record),
        })
        .collect()
}

fn gaps_in(gaps: Vec<proto::AuditGap>) -> Vec<AuditGapView> {
    gaps.into_iter()
        .map(|gap| AuditGapView {
            kind: gap.kind,
            from_seq: gap.from_seq,
            to_seq: gap.to_seq,
            count: gap.count,
            through: gap.through,
        })
        .collect()
}

fn anchor_in(anchor: Option<proto::AuditAnchor>) -> Option<AuditAnchorView> {
    anchor.map(|anchor| AuditAnchorView {
        low_watermark: anchor.low_watermark,
        through: anchor.through,
        checkpoint: anchor.checkpoint,
    })
}

fn checkpoints_in(checkpoints: Vec<proto::AuditCheckpoint>) -> Vec<AuditCheckpointView> {
    checkpoints
        .into_iter()
        .map(|checkpoint| AuditCheckpointView {
            name: checkpoint.name,
            envelope: map::b64(&checkpoint.envelope),
            witness: checkpoint.witness.as_deref().map(map::b64),
        })
        .collect()
}

fn plan_in(plan: proto::OperationPlan) -> PlanView {
    PlanView {
        plan_id: plan.plan_id,
        operation: plan.operation,
        target: plan.target,
        revision: plan.revision,
        principal: plan.principal,
        plan_digest: plan.plan_digest,
        expires: plan.expires,
        approvals_required: plan.approvals_required,
        approvals: plan
            .approvals
            .into_iter()
            .map(|approval| ApprovalView {
                principal: approval.principal,
                approved_at: approval.approved_at,
                approval: map::b64(&approval.approval),
            })
            .collect(),
        status: plan.status,
        receipt: map::b64(&plan.receipt),
    }
}

impl GrpcHost {
    fn keys_client(&self) -> proto::key_service_client::KeyServiceClient<crate::grpc::AuthChannel> {
        proto::key_service_client::KeyServiceClient::new(self.0.channel())
    }

    pub(super) fn operations_client(
        &self,
    ) -> proto::operations_service_client::OperationsServiceClient<crate::grpc::AuthChannel> {
        proto::operations_service_client::OperationsServiceClient::new(self.0.channel())
    }
}

impl Operations for GrpcHost {
    fn rings(&self) -> Result<Rings, Failure> {
        let answer = self
            .0
            .run(
                "ListKeyRings",
                self.keys_client()
                    .list_key_rings(proto::ListKeyRingsRequest {}),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(Rings {
            rings: answer
                .rings
                .into_iter()
                .map(|ring| RingSummary {
                    ring: ring.ring,
                    keys: ring.keys,
                    digest: ring.digest,
                    epoch: ring.epoch,
                })
                .collect(),
        })
    }

    fn ring(&self, ring: &str) -> Result<RingView, Failure> {
        segment(ring)?;
        let answer = self
            .0
            .run(
                "GetKeyRing",
                self.keys_client().get_key_ring(proto::GetKeyRingRequest {
                    ring: ring.to_owned(),
                }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(ring_in(answer))
    }

    fn rotate_ring(&self, ring: &str, request: &RotateRing) -> Result<RingRotated, Failure> {
        segment(ring)?;
        let answer = self
            .0
            .run(
                "RotateKeyRing",
                self.keys_client()
                    .rotate_key_ring(proto::RotateKeyRingRequest {
                        ring: ring.to_owned(),
                        request_id: request.request_id.clone(),
                        expected_epoch: request.expected_epoch,
                    }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(RingRotated {
            receipt: map::receipt(answer.receipt),
            kid: answer.kid,
        })
    }

    fn plan_key_revoke(&self, ring: &str, request: &PlanKeyRevoke) -> Result<Planned, Failure> {
        segment(ring)?;
        let answer = self
            .0
            .run(
                "PlanKeyRevoke",
                self.keys_client()
                    .plan_key_revoke(proto::PlanKeyRevokeRequest {
                        ring: ring.to_owned(),
                        request_id: request.request_id.clone(),
                        kid: request.kid.clone(),
                        reason: request.reason.clone(),
                        compromised_at: request.compromised_at.clone(),
                        expected_epoch: request.expected_epoch,
                    }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(Planned {
            plan_id: answer.plan_id,
            plan_digest: answer.plan_digest,
            expires: answer.expires,
            revision: answer.revision,
            receipt: map::b64(&answer.receipt),
            approvals_required: answer.approvals_required,
        })
    }

    fn run_key_revoke(&self, ring: &str, request: &RunKeyRevoke) -> Result<KeyRevoked, Failure> {
        segment(ring)?;
        let receipt = map::raw(&request.receipt).map_err(usage)?;
        let answer = self
            .0
            .run(
                "RunKeyRevoke",
                self.keys_client()
                    .run_key_revoke(proto::RunKeyRevokeRequest {
                        ring: ring.to_owned(),
                        request_id: request.request_id.clone(),
                        receipt,
                    }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(KeyRevoked {
            receipt: map::receipt(answer.receipt),
            kid: answer.kid,
        })
    }

    fn key_bundle(&self, asked: &KeyBundleQuery) -> Result<KeyBundlePage, Failure> {
        let answer = self
            .0
            .run(
                "GetKeyBundle",
                self.keys_client()
                    .get_key_bundle(proto::GetKeyBundleRequest {
                        resource: asked.resource.clone(),
                        frontier: blank(asked.frontier.as_ref()),
                        cursor: blank(asked.cursor.as_ref()),
                        limit: asked.limit,
                    }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(KeyBundlePage {
            resource: answer.resource,
            manifest: map::b64(&answer.manifest),
            bundle_digest: answer.bundle_digest,
            total: answer.total,
            items: answer.items.iter().map(|item| map::b64(item)).collect(),
            next_cursor: answer.next_cursor,
        })
    }

    fn audit_records(&self, class: &str, asked: &AuditQuery) -> Result<AuditRecordPage, Failure> {
        segment(class)?;
        let answer = self
            .0
            .run(
                "ListAuditRecords",
                self.evidence_client()
                    .list_audit_records(proto::ListAuditRecordsRequest {
                        class: class.to_owned(),
                        resource: asked.resource.clone(),
                        from: asked.from,
                        to: asked.to,
                        cursor: blank(asked.cursor.as_ref()),
                        limit: asked.limit,
                    }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(AuditRecordPage {
            class: answer.class,
            resource: answer.resource,
            records: records_in(answer.records),
            gaps: gaps_in(answer.gaps),
            frontier: answer.frontier,
            next_cursor: answer.next_cursor,
            anchor: anchor_in(answer.anchor),
        })
    }

    fn audit_checkpoints(
        &self,
        class: &str,
        asked: &AuditCheckpointQuery,
    ) -> Result<AuditCheckpoints, Failure> {
        segment(class)?;
        let answer = self
            .0
            .run(
                "ListAuditCheckpoints",
                self.evidence_client()
                    .list_audit_checkpoints(proto::ListAuditCheckpointsRequest {
                        class: class.to_owned(),
                        resource: asked.resource.clone(),
                        period: blank(asked.period.as_ref()),
                    }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(AuditCheckpoints {
            class: answer.class,
            resource: answer.resource,
            checkpoints: checkpoints_in(answer.checkpoints),
            omitted: answer.omitted,
            keys: answer.keys.map(ring_in),
            verification_keys: answer.verification_keys,
        })
    }

    fn audit_export(
        &self,
        class: &str,
        asked: &AuditExportQuery,
    ) -> Result<AuditExportPage, Failure> {
        segment(class)?;
        let answer = self
            .0
            .run(
                "ExportAudit",
                self.evidence_client()
                    .export_audit(proto::ExportAuditRequest {
                        class: class.to_owned(),
                        resource: asked.resource.clone(),
                        frontier: asked.frontier,
                        cursor: blank(asked.cursor.as_ref()),
                        limit: asked.limit,
                    }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(AuditExportPage {
            class: answer.class,
            resource: answer.resource,
            records: records_in(answer.records),
            gaps: gaps_in(answer.gaps),
            frontier: answer.frontier,
            next_cursor: answer.next_cursor,
            anchor: anchor_in(answer.anchor),
            checkpoints: checkpoints_in(answer.checkpoints),
            omitted: answer.omitted,
            keys: answer.keys.map(ring_in),
            verification_keys: answer.verification_keys,
        })
    }

    fn effective_config(&self) -> Result<Effective, Failure> {
        let answer = self
            .0
            .run(
                "GetEffectiveConfig",
                self.operations_client()
                    .get_effective_config(proto::GetEffectiveConfigRequest {}),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(Effective {
            revision: answer.revision,
            settings: answer
                .settings
                .into_iter()
                .map(|setting| Setting {
                    key: setting.key,
                    value: setting.value,
                    masked: setting.masked,
                    origin: setting.origin,
                    class: setting.class,
                })
                .collect(),
        })
    }

    fn config_revisions(&self) -> Result<Revisions, Failure> {
        let answer = self
            .0
            .run(
                "ListConfigRevisions",
                self.operations_client()
                    .list_config_revisions(proto::ListConfigRevisionsRequest {}),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(Revisions {
            revisions: answer
                .revisions
                .into_iter()
                .map(|revision| Revision {
                    journal: revision.journal,
                    revision: revision.revision,
                    operation: revision.operation,
                    target: revision.target,
                    at: revision.at,
                    by: revision.by,
                })
                .collect(),
        })
    }

    fn plans(&self, status: Option<&str>) -> Result<PlanList, Failure> {
        let answer = self
            .0
            .run(
                "ListPlans",
                self.operations_client()
                    .list_plans(proto::ListPlansRequest {
                        status: status.unwrap_or_default().to_owned(),
                    }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(PlanList {
            plans: answer.plans.into_iter().map(plan_in).collect(),
        })
    }

    fn approve_plan(&self, plan_id: &str, request: &ApprovePlan) -> Result<PlanApproved, Failure> {
        segment(plan_id)?;
        let answer = self
            .0
            .run(
                "ApprovePlan",
                self.operations_client()
                    .approve_plan(proto::ApprovePlanRequest {
                        plan_id: plan_id.to_owned(),
                        request_id: request.request_id.clone(),
                    }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(PlanApproved {
            receipt: map::receipt(answer.receipt),
            plan: plan_in(answer.plan.unwrap_or_default()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TC-2: a query keeps each value inside its member, whatever it holds, and names only the
    /// members given.
    #[test]
    fn a_query_names_the_given_members_escaped() {
        assert_eq!(query(&[("status", None)]), "");
        assert_eq!(
            query(&[
                ("resource", Some("plane/control/zone/z&1".to_owned())),
                ("from", None),
                ("limit", Some("5".to_owned())),
            ]),
            "?resource=plane%2Fcontrol%2Fzone%2Fz%261&limit=5"
        );
    }
}
