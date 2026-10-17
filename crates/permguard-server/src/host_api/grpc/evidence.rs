// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `permguard.host.v1.EvidenceService`: the audit routes (WP-3.7) and the stream reads
//! (WP-5.7a), each rpc one call into the facade the REST routes call; bytes the facade answers
//! base64url travel raw. `ShipStreamBatch` is not served: batches travel on the membership's
//! task transport (owner decision of 2026-10-17).

use tonic::{Request, Response, Status};

use permguard_host::api::audit::{
    AuditAnchorView, AuditCheckpointQuery, AuditCheckpointView, AuditExportQuery, AuditGapView,
    AuditQuery, AuditRecordView,
};

use permguard_host::api::streams::{AnchorView, StreamQuery};

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
        request: Request<v1::ListStreamsRequest>,
    ) -> Answer<v1::ListStreamsResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let streams = self
            .api
            .streams_list(&actor)
            .map_err(|refusal| self.refuse(refusal))?
            .streams;
        Ok(Response::new(v1::ListStreamsResponse {
            streams: streams
                .into_iter()
                .map(|stream| v1::StreamDescriptor {
                    plane: stream.plane,
                    stream_type: stream.stream_type,
                    version: stream.version,
                    role: stream.role,
                    retention: stream.retention,
                    ring: stream.ring,
                    task: stream.task,
                    resources: stream
                        .resources
                        .into_iter()
                        .map(|resource| v1::StreamResource {
                            resource: resource.resource,
                            state: resource.state,
                        })
                        .collect(),
                })
                .collect(),
        }))
    }

    async fn ship_stream_batch(
        &self,
        _: Request<v1::ShipStreamBatchRequest>,
    ) -> Answer<v1::ShipStreamBatchResponse> {
        // Batches travel on the membership's task transport (WP-5.7, owner decision).
        Err(unimplemented("a batch over the Host API"))
    }

    async fn get_stream_frontier(
        &self,
        request: Request<v1::GetStreamFrontierRequest>,
    ) -> Answer<v1::GetStreamFrontierResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let request = request.into_inner();
        let frontier = self
            .api
            .stream_frontier(
                &actor,
                &request.plane,
                &request.stream_type,
                &query(request.resource),
            )
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::GetStreamFrontierResponse {
            resource: frontier.resource,
            producer: frontier
                .producer
                .into_iter()
                .map(|run| v1::StreamProducerRun {
                    run: run.run,
                    ended: run.ended,
                    last_seq: run.last_seq,
                    sealed: run.sealed,
                    acknowledged: run.acknowledged,
                    low_watermark: run.low_watermark,
                })
                .collect(),
            consumer: frontier
                .consumer
                .into_iter()
                .map(|run| v1::StreamConsumerRun {
                    producer: run.producer,
                    run: run.run,
                    acked: run.acked,
                    oldest_retained: run.oldest_retained,
                })
                .collect(),
        }))
    }

    async fn list_stream_records(
        &self,
        request: Request<v1::ListStreamRecordsRequest>,
    ) -> Answer<v1::ListStreamRecordsResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let request = request.into_inner();
        let page = self
            .api
            .stream_records(
                &actor,
                &request.plane,
                &request.stream_type,
                &StreamQuery {
                    resource: request.resource,
                    producer: given(request.producer),
                    run: given(request.run),
                    from: request.from,
                    limit: request.limit,
                    malformed: None,
                },
            )
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::ListStreamRecordsResponse {
            resource: page.resource,
            run: page.run,
            records: page
                .records
                .into_iter()
                .map(|record| {
                    Ok(v1::StreamRecord {
                        seq: record.seq,
                        record: raw(&record.record)?,
                        digest: record.digest,
                    })
                })
                .collect::<Result<_, Status>>()?,
            next: page.next,
            gap: page
                .gap
                .map(|gap| {
                    Ok::<_, Status>(v1::StreamGap {
                        low_watermark: gap.low_watermark,
                        anchor: Some(stream_anchor(gap.anchor)?),
                    })
                })
                .transpose()?,
        }))
    }

    async fn list_stream_signers(
        &self,
        request: Request<v1::ListStreamSignersRequest>,
    ) -> Answer<v1::ListStreamSignersResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let request = request.into_inner();
        let runs = self
            .api
            .stream_signers(
                &actor,
                &request.plane,
                &request.stream_type,
                &query(request.resource),
            )
            .map_err(|refusal| self.refuse(refusal))?
            .runs;
        Ok(Response::new(v1::ListStreamSignersResponse {
            runs: runs
                .into_iter()
                .map(|run| v1::StreamRunSigners {
                    role: run.role,
                    producer: run.producer,
                    run: run.run,
                    spans: run
                        .spans
                        .into_iter()
                        .map(|span| v1::StreamSpan {
                            from_seq: span.from_seq,
                            kid: span.kid,
                            jwk: span.jwk,
                        })
                        .collect(),
                })
                .collect(),
        }))
    }

    async fn list_stream_subscriptions(
        &self,
        request: Request<v1::ListStreamSubscriptionsRequest>,
    ) -> Answer<v1::ListStreamSubscriptionsResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let request = request.into_inner();
        let subscriptions = self
            .api
            .stream_subscriptions(
                &actor,
                &request.plane,
                &request.stream_type,
                &query(request.resource),
            )
            .map_err(|refusal| self.refuse(refusal))?
            .subscriptions;
        Ok(Response::new(v1::ListStreamSubscriptionsResponse {
            subscriptions: subscriptions
                .into_iter()
                .map(|subscription| v1::StreamSubscription {
                    membership: subscription.membership,
                    task: subscription.task,
                    required: subscription.required,
                    state: subscription.state,
                    reason: subscription.reason,
                    acked: subscription
                        .acked
                        .into_iter()
                        .map(|ack| v1::StreamRunAck {
                            run: ack.run,
                            acked: ack.acked,
                        })
                        .collect(),
                })
                .collect(),
        }))
    }

    async fn list_stream_gaps(
        &self,
        request: Request<v1::ListStreamGapsRequest>,
    ) -> Answer<v1::ListStreamGapsResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let request = request.into_inner();
        let gaps = self
            .api
            .stream_gaps(
                &actor,
                &request.plane,
                &request.stream_type,
                &query(request.resource),
            )
            .map_err(|refusal| self.refuse(refusal))?
            .gaps;
        Ok(Response::new(v1::ListStreamGapsResponse {
            gaps: gaps
                .into_iter()
                .map(|gap| v1::StreamGapEntry {
                    role: gap.role,
                    producer: gap.producer,
                    run: gap.run,
                    low_watermark: gap.low_watermark,
                })
                .collect(),
        }))
    }

    async fn list_stream_anchors(
        &self,
        request: Request<v1::ListStreamAnchorsRequest>,
    ) -> Answer<v1::ListStreamAnchorsResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let request = request.into_inner();
        let anchors = self
            .api
            .stream_anchors(
                &actor,
                &request.plane,
                &request.stream_type,
                &query(request.resource),
            )
            .map_err(|refusal| self.refuse(refusal))?
            .anchors;
        Ok(Response::new(v1::ListStreamAnchorsResponse {
            anchors: anchors
                .into_iter()
                .map(stream_anchor)
                .collect::<Result<_, Status>>()?,
        }))
    }
}

/// The query of a stream read naming only its resource.
fn query(resource: String) -> StreamQuery {
    StreamQuery {
        resource,
        ..StreamQuery::default()
    }
}

/// An anchor as gRPC carries it: its CBOR raw.
fn stream_anchor(anchor: AnchorView) -> Result<v1::StreamAnchor, Status> {
    Ok(v1::StreamAnchor {
        role: anchor.role,
        producer: anchor.producer,
        run: anchor.run,
        through: anchor.through,
        low_watermark: anchor.low_watermark,
        terminal_head: anchor.terminal_head,
        covering: anchor.covering,
        anchor: raw(&anchor.anchor)?,
    })
}
