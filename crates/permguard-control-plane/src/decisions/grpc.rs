// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The decision log's gRPC shape: the same contract as the HTTP one, answered
//! by the same code.
//!
//! # Why the payloads are bytes
//!
//! A record's digest is taken over its canonical JSON, and the chain that binds
//! every record to a signed head is taken over those digests. Re-encoding a
//! record as protobuf and back would change the bytes and break every digest
//! after it — so the wire carries exactly what was signed, and this surface
//! carries the wire. That is not laziness about the schema: it is the only
//! shape under which two transports can deliver the *same* record.
//!
//! # Refusals
//!
//! `out_of_order` is a field rather than a status, because nothing is wrong:
//! the store simply needs an earlier batch first. Everything else is a status
//! carrying this product's class and code in its metadata, so a gRPC caller
//! and an HTTP caller branch on the same vocabulary.

use permguard_decisions::envelope::Batch;
use serde_json::Value;
use tonic::{Request, Response, Status};

use super::http::DecisionFacade;
use super::store::Scope;
use super::{Accepted, Refused, ingest, measure, read};
use crate::v1::decision_log_server::DecisionLog;
use crate::v1::{
    DecisionSignerSpan, GetDecisionSignersRequest, GetDecisionSignersResponse, ReadRequest,
    ReadResponse, ShipRequest, ShipResponse,
};

/// The metadata keys a refusal's class and code travel in.
const CLASS: &str = "permguard-error-class";
const CODE: &str = "permguard-error-code";

#[tonic::async_trait]
impl DecisionLog for DecisionFacade {
    async fn ship(&self, request: Request<ShipRequest>) -> Result<Response<ShipResponse>, Status> {
        let started = std::time::Instant::now();
        let batch: Batch =
            serde_json::from_slice(&request.into_inner().batch).map_err(|error| {
                self.metrics
                    .count(&measure::REFUSALS, &[("reason", "malformed")]);

                refusal(
                    Status::invalid_argument(format!("this is not a decision batch: {error}")),
                    "validation",
                    "malformed_batch",
                )
            })?;

        let keys = self.accepted_keys().map_err(|error| {
            refusal(
                Status::unavailable(format!(
                    "this plane cannot verify signatures right now: {error}"
                )),
                "unavailable",
                "keys_unavailable",
            )
        })?;

        // Off the runtime's threads, exactly as on HTTP: accepting a batch is
        // appends and fsyncs across several files.
        let outcome = {
            let (facade, batch) = (self.clone(), batch.clone());
            tokio::task::spawn_blocking(move || {
                match ingest::accept(&facade.store, &batch, &keys) {
                    // A rotated producer ring is a file to re-read, not a
                    // plane to restart.
                    Err(Refused::Unattributable(_)) => {
                        ingest::accept(&facade.store, &batch, &facade.reload_producers())
                    }
                    other => other,
                }
            })
            .await
            .unwrap_or_else(|error| Err(Refused::Unavailable(error.to_string())))
        };
        self.metrics.observe(
            &measure::INGEST_SECONDS,
            &[],
            started.elapsed().as_secs_f64(),
        );

        match outcome {
            Ok(Accepted::Ok { acked, stored }) => {
                self.metrics.count(
                    &measure::BATCHES,
                    &[("outcome", if stored == 0 { "replay" } else { "ok" })],
                );
                self.count_records(&batch.records);
                self.publish_acked(&batch, acked);

                Ok(Response::new(ShipResponse {
                    acked,
                    stored,
                    out_of_order: false,
                    expected_seq: 0,
                }))
            }
            Ok(Accepted::OutOfOrder { expected_seq }) => {
                self.metrics
                    .count(&measure::BATCHES, &[("outcome", "out_of_order")]);

                Ok(Response::new(ShipResponse {
                    acked: 0,
                    stored: 0,
                    out_of_order: true,
                    expected_seq,
                }))
            }
            Err(refused) => {
                self.metrics
                    .count(&measure::REFUSALS, &[("reason", reason_of(&refused))]);
                if matches!(refused, Refused::Conflict { .. }) {
                    self.metrics.count(&measure::CLOSED, &[]);
                }

                Err(status_of(&refused))
            }
        }
    }

    /// The same signers document the HTTP binding serves, field for field.
    async fn get_signers(
        &self,
        request: Request<GetDecisionSignersRequest>,
    ) -> Result<Response<GetDecisionSignersResponse>, Status> {
        let asked = request.into_inner();
        if asked.pdp.is_empty() || asked.instance.is_empty() {
            return Err(refusal(
                Status::invalid_argument(
                    "a signer manifest belongs to one producer stream: set `pdp` and `instance`",
                ),
                "validation",
                "stream_required",
            ));
        }

        let view = self
            .signers_of(&asked.pdp, &asked.instance, asked.from_seq, asked.until_seq)
            .map_err(|error| {
                refusal(
                    Status::unavailable(error.to_string()),
                    "unavailable",
                    "store_unavailable",
                )
            })?;

        let spans = view
            .spans
            .into_iter()
            .map(|span| {
                Ok(DecisionSignerSpan {
                    from_seq: span.from,
                    kid: span.kid,
                    jwk: serde_json::to_vec(&span.jwk).map_err(|error| {
                        refusal(
                            Status::internal(error.to_string()),
                            "internal",
                            "signer_malformed",
                        )
                    })?,
                })
            })
            .collect::<Result<Vec<_>, Status>>()?;

        Ok(Response::new(GetDecisionSignersResponse {
            acked: view.acked,
            spans,
        }))
    }

    async fn read(&self, request: Request<ReadRequest>) -> Result<Response<ReadResponse>, Status> {
        let asked = request.into_inner();
        let scope = if !asked.pdp.is_empty() && !asked.instance.is_empty() {
            Scope::Stream {
                pdp_id: asked.pdp,
                instance: asked.instance,
            }
        } else if !asked.zone.is_empty() && !asked.ledger.is_empty() {
            Scope::Tenant {
                zone: asked.zone,
                ledger: asked.ledger,
            }
        } else {
            return Err(refusal(
                Status::invalid_argument(
                    "name a zone and a ledger, or one producer stream with `pdp` and `instance`",
                ),
                "validation",
                "scope_required",
            ));
        };
        let kind = match scope {
            Scope::Stream { .. } => "stream",
            Scope::Tenant { .. } => "tenant",
        };
        // The same window the HTTP binding builds, from the same fields: `limit_records` where a
        // caller states it, and the older `limit` where it does not.
        let window = permguard_stream::Window {
            from: (!asked.from.is_empty()).then_some(asked.from),
            until: (!asked.until.is_empty())
                .then(|| permguard_stream::Frontier::decode(&asked.until))
                .flatten(),
            limit_records: usize::try_from(if asked.limit_records > 0 {
                asked.limit_records
            } else {
                asked.limit
            })
            .unwrap_or_default(),
            limit_bytes: asked.limit_bytes,
            proof: asked.proof,
        };

        // Off the runtime's threads, exactly as on HTTP.
        let page = {
            let (store, scope, key) = (self.store.clone(), scope.clone(), self.cursor_key.clone());
            tokio::task::spawn_blocking(move || read::read(&store, &scope, &key, &window))
                .await
                .unwrap_or_else(|error| Err(read::ReadError::Unavailable(error.to_string())))
        };
        match page {
            Ok(page) => {
                self.metrics
                    .count(&measure::READS, &[("scope", kind), ("outcome", "ok")]);

                Ok(Response::new(ReadResponse {
                    records: page.records.iter().map(render).collect(),
                    next: page.next,
                    more: page.more,
                    proof: page.proof.iter().map(render).collect(),
                    inclusion: page.inclusion.iter().map(render).collect(),
                    oldest_available: page.oldest_available,
                    high_watermark: page.high_watermark,
                    coverage: Some(crate::v1::ReadCoverage {
                        contiguous: page.coverage.contiguous,
                        examined: page.coverage.examined as u64,
                        scan_bounded: page.coverage.scan_bounded,
                    }),
                }))
            }
            Err(
                ref expired @ read::ReadError::Expired {
                    ref oldest,
                    oldest_sequence,
                    requested_sequence,
                },
            ) => {
                self.metrics
                    .count(&measure::READS, &[("scope", kind), ("outcome", "expired")]);

                // The oldest offset and the size of the gap travel in the metadata, so a consumer
                // learns where to resume and how much it lost from the refusal itself — the same
                // three facts the HTTP binding puts in its body.
                let mut status = refusal(
                    Status::not_found(expired.to_string()),
                    "not_found",
                    "offset_expired",
                );
                let metadata = status.metadata_mut();
                if let Ok(value) = oldest.parse() {
                    metadata.insert("permguard-oldest-offset", value);
                }
                if let Ok(value) = oldest_sequence.to_string().parse() {
                    metadata.insert("permguard-oldest-sequence", value);
                }
                if let Ok(value) = requested_sequence.to_string().parse() {
                    metadata.insert("permguard-requested-sequence", value);
                }

                Err(status)
            }
            Err(error) => {
                self.metrics
                    .count(&measure::READS, &[("scope", kind), ("outcome", "refused")]);

                Err(refusal(
                    Status::invalid_argument(error.to_string()),
                    "validation",
                    "offset_invalid",
                ))
            }
        }
    }
}

impl DecisionFacade {
    fn count_records(&self, records: &[Value]) {
        for record in records {
            if let Some((zone, ledger)) = super::store::tenancy(record) {
                self.metrics.count(
                    &measure::RECORDS,
                    &[("zone", zone.as_str()), ("ledger", ledger.as_str())],
                );
            }
        }
    }
}

fn render(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap_or_default()
}

fn reason_of(refused: &Refused) -> &'static str {
    match refused {
        Refused::Unattributable(_) => "unattributable",
        Refused::Unverifiable(_) => "unverifiable",
        Refused::Conflict { .. } => "conflict",
        Refused::Closed(_) => "closed",
        Refused::Unavailable(_) => "unavailable",
    }
}

fn status_of(refused: &Refused) -> Status {
    match refused {
        Refused::Unattributable(detail) => refusal(
            Status::invalid_argument(detail.clone()),
            "validation",
            "batch_unattributable",
        ),
        Refused::Unverifiable(detail) => refusal(
            Status::invalid_argument(detail.clone()),
            "validation",
            "batch_unverifiable",
        ),
        Refused::Conflict { .. } => refusal(
            Status::failed_precondition(refused.to_string()),
            "conflict",
            "stream_conflict",
        ),
        Refused::Closed(_) => refusal(
            Status::failed_precondition(refused.to_string()),
            "conflict",
            "stream_closed",
        ),
        // The one a shipper must treat as *retry*, never as *drop*.
        Refused::Unavailable(detail) => refusal(
            Status::unavailable(detail.clone()),
            "unavailable",
            "store_unavailable",
        ),
    }
}

/// Attaches this product's class and code, so both transports say one thing.
fn refusal(mut status: Status, class: &'static str, code: &'static str) -> Status {
    if let (Ok(class), Ok(code)) = (class.parse(), code.parse()) {
        status.metadata_mut().insert(CLASS, class);
        status.metadata_mut().insert(CODE, code);
    }

    status
}
