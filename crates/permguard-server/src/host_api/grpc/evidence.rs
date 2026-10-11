// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `permguard.host.v1.EvidenceService`: the audit routes (WP-3.7), each rpc one call into the
//! facade the REST routes call; bytes the facade answers base64url travel raw. The stream rpcs
//! are a later package's and `UNIMPLEMENTED` until it lands.

use tonic::{Request, Response, Status};

use permguard_host::api::audit::{
    AuditAnchorView, AuditCheckpointQuery, AuditCheckpointView, AuditExportQuery, AuditGapView,
    AuditQuery, AuditRecordView,
};

use super::super::v1;
use super::super::v1::evidence_service_server::EvidenceService;
use super::{Answer, Served, raw, ring_out, unimplemented};

fn given(text: String) -> Option<String> {
    (!text.is_empty()).then_some(text)
}

fn records(records: Vec<AuditRecordView>) -> Result<Vec<v1::AuditRecord>, Status> {
    records
        .into_iter()
        .map(|record| {
            Ok(v1::AuditRecord {
                seq: record.seq,
                at: record.at,
                action: record.action,
                outcome: record.outcome,
                digest: record.digest,
                record: raw(&record.record)?,
            })
        })
        .collect()
}

fn gaps(gaps: Vec<AuditGapView>) -> Vec<v1::AuditGap> {
    gaps.into_iter()
        .map(|gap| v1::AuditGap {
            kind: gap.kind,
            from_seq: gap.from_seq,
            to_seq: gap.to_seq,
            count: gap.count,
            through: gap.through,
        })
        .collect()
}

fn anchor(anchor: Option<AuditAnchorView>) -> Option<v1::AuditAnchor> {
    anchor.map(|anchor| v1::AuditAnchor {
        low_watermark: anchor.low_watermark,
        through: anchor.through,
        checkpoint: anchor.checkpoint,
    })
}

fn checkpoints(checkpoints: Vec<AuditCheckpointView>) -> Result<Vec<v1::AuditCheckpoint>, Status> {
    checkpoints
        .into_iter()
        .map(|checkpoint| {
            Ok(v1::AuditCheckpoint {
                name: checkpoint.name,
                envelope: raw(&checkpoint.envelope)?,
                witness: checkpoint.witness.as_deref().map(raw).transpose()?,
            })
        })
        .collect()
}

#[tonic::async_trait]
impl EvidenceService for Served {
    async fn list_audit_records(
        &self,
        request: Request<v1::ListAuditRecordsRequest>,
    ) -> Answer<v1::ListAuditRecordsResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let request = request.into_inner();
        let page = self
            .api
            .audit_records(
                &actor,
                &request.class,
                &AuditQuery {
                    resource: request.resource,
                    from: request.from,
                    to: request.to,
                    cursor: given(request.cursor),
                    limit: request.limit,
                    malformed: None,
                },
            )
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::ListAuditRecordsResponse {
            class: page.class,
            resource: page.resource,
            records: records(page.records)?,
            gaps: gaps(page.gaps),
            frontier: page.frontier,
            next_cursor: page.next_cursor,
            anchor: anchor(page.anchor),
        }))
    }

    async fn list_audit_checkpoints(
        &self,
        request: Request<v1::ListAuditCheckpointsRequest>,
    ) -> Answer<v1::ListAuditCheckpointsResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let request = request.into_inner();
        let held = self
            .api
            .audit_checkpoints(
                &actor,
                &request.class,
                &AuditCheckpointQuery {
                    resource: request.resource,
                    period: given(request.period),
                },
            )
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::ListAuditCheckpointsResponse {
            class: held.class,
            resource: held.resource,
            checkpoints: checkpoints(held.checkpoints)?,
            keys: held.keys.map(ring_out).transpose()?,
            omitted: held.omitted,
            verification_keys: held.verification_keys,
        }))
    }

    async fn export_audit(
        &self,
        request: Request<v1::ExportAuditRequest>,
    ) -> Answer<v1::ExportAuditResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let request = request.into_inner();
        let page = self
            .api
            .audit_export(
                &actor,
                &request.class,
                &AuditExportQuery {
                    resource: request.resource,
                    frontier: request.frontier,
                    cursor: given(request.cursor),
                    limit: request.limit,
                    malformed: None,
                },
            )
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::ExportAuditResponse {
            class: page.class,
            resource: page.resource,
            records: records(page.records)?,
            gaps: gaps(page.gaps),
            frontier: page.frontier,
            next_cursor: page.next_cursor,
            anchor: anchor(page.anchor),
            checkpoints: checkpoints(page.checkpoints)?,
            keys: page.keys.map(ring_out).transpose()?,
            omitted: page.omitted,
            verification_keys: page.verification_keys,
        }))
    }

    async fn list_streams(
        &self,
        _: Request<v1::ListStreamsRequest>,
    ) -> Answer<v1::ListStreamsResponse> {
        Err(unimplemented("the streams"))
    }

    async fn ship_stream_batch(
        &self,
        _: Request<v1::ShipStreamBatchRequest>,
    ) -> Answer<v1::ShipStreamBatchResponse> {
        Err(unimplemented("the streams"))
    }

    async fn get_stream_frontier(
        &self,
        _: Request<v1::GetStreamFrontierRequest>,
    ) -> Answer<v1::GetStreamFrontierResponse> {
        Err(unimplemented("the streams"))
    }

    async fn list_stream_records(
        &self,
        _: Request<v1::ListStreamRecordsRequest>,
    ) -> Answer<v1::ListStreamRecordsResponse> {
        Err(unimplemented("the streams"))
    }

    async fn list_stream_signers(
        &self,
        _: Request<v1::ListStreamSignersRequest>,
    ) -> Answer<v1::ListStreamSignersResponse> {
        Err(unimplemented("the streams"))
    }

    async fn list_stream_subscriptions(
        &self,
        _: Request<v1::ListStreamSubscriptionsRequest>,
    ) -> Answer<v1::ListStreamSubscriptionsResponse> {
        Err(unimplemented("the streams"))
    }

    async fn list_stream_gaps(
        &self,
        _: Request<v1::ListStreamGapsRequest>,
    ) -> Answer<v1::ListStreamGapsResponse> {
        Err(unimplemented("the streams"))
    }

    async fn list_stream_anchors(
        &self,
        _: Request<v1::ListStreamAnchorsRequest>,
    ) -> Answer<v1::ListStreamAnchorsResponse> {
        Err(unimplemented("the streams"))
    }
}
