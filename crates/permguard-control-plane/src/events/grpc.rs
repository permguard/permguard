// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The event store's gRPC shape.
//!
//! Field for field the HTTP surface, over the same facade: one validation path, one authorization
//! decision, one store. A deployment picks a transport, not a set of semantics.
//!
//! # The one thing a transport owns
//!
//! How a refusal is said. gRPC has no status codes to reuse, so the classes map onto its own and
//! the structured half — the class and the code a client switches on — rides as metadata rather
//! than being parsed out of a sentence.

use tonic::{Request, Response, Status};

use permguard_core::{ApiError, Disclosure, ErrorClass};

use super::http::EventFacade;
use super::ingest::{Accepted, Batch, Refused};
use super::read::{self, Filters};
use super::store::Scope;
use crate::v1::event_log_server::EventLog;
use crate::v1::{
    EventCoverage, EventEndpoints, EventOffsets, GetEventConfigurationRequest,
    GetEventConfigurationResponse, GetRecordRequest, GetRecordResponse, IngestBatchRequest,
    IngestBatchResponse, ListRecordsRequest, ListRecordsResponse,
};

/// The gRPC metadata keys carrying the structured half of a refusal.
pub const GRPC_ERROR_CLASS: &str = "x-permguard-error-class";
pub const GRPC_ERROR_CODE: &str = "x-permguard-error-code";

#[tonic::async_trait]
impl EventLog for EventFacade {
    async fn ingest_batch(
        &self,
        request: Request<IngestBatchRequest>,
    ) -> Result<Response<IngestBatchResponse>, Status> {
        let asked = request.into_inner();
        let records = asked
            .records
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                serde_json::from_slice(bytes).map_err(|error| {
                    status_of(
                        &ApiError::new(
                            ErrorClass::Validation,
                            "payload_malformed",
                            format!("record {index} is not JSON: {error}"),
                        ),
                        self.disclosure,
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let batch = Batch {
            signature: serde_json::from_slice(&asked.envelope).map_err(|error| {
                status_of(
                    &ApiError::new(
                        ErrorClass::Validation,
                        "payload_malformed",
                        format!("the envelope is not a signed batch: {error}"),
                    ),
                    self.disclosure,
                )
            })?,
            records,
        };

        let facade = self.clone();
        let answered = tokio::task::spawn_blocking(move || facade.ingest(&batch))
            .await
            .unwrap_or_else(|error| Err(Refused::Unavailable(error.to_string())));

        match answered {
            Ok(Accepted::Ok { acked, stored }) => Ok(Response::new(IngestBatchResponse {
                acked,
                stored,
                expected_seq: 0,
            })),
            // Not an error: the shipper ran ahead and is being told exactly where to resume, which
            // is an answer it acts on rather than a failure it retries blindly.
            Ok(Accepted::OutOfOrder { expected_seq }) => Ok(Response::new(IngestBatchResponse {
                acked: expected_seq.saturating_sub(1),
                stored: 0,
                expected_seq,
            })),
            Err(refused) => Err(status_of(&api_error(&refused), self.disclosure)),
        }
    }

    async fn list_records(
        &self,
        request: Request<ListRecordsRequest>,
    ) -> Result<Response<ListRecordsResponse>, Status> {
        let asked = request.into_inner();
        let (scope, kind) = scope_of(&asked)?;
        // Same resolution as the HTTP list, so the two transports narrow to the same records.
        let scope = match read::canonical(self.catalog.as_ref(), scope) {
            Ok(scope) => scope,
            Err(error) => return Err(read_status(error, self.disclosure)),
        };
        let filters = filters_of(&asked);
        let window = permguard_stream::Window {
            from: (!asked.from.is_empty()).then(|| asked.from.clone()),
            until: (!asked.until.is_empty())
                .then(|| permguard_stream::Frontier::decode(&asked.until))
                .flatten(),
            limit_records: usize::try_from(asked.limit_records).unwrap_or_default(),
            limit_bytes: asked.limit_bytes,
            proof: asked.proof,
        };

        let facade = self.clone();
        let page =
            tokio::task::spawn_blocking(move || facade.read(&scope, &filters, &window, kind))
                .await
                .unwrap_or_else(|error| Err(read::ReadError::Unavailable(error.to_string())));

        match page {
            Ok(page) => Ok(Response::new(ListRecordsResponse {
                records: page.records.iter().map(render).collect(),
                next: page.next,
                more: page.more,
                oldest_available: page.oldest_available,
                high_watermark: page.high_watermark,
                proof: page.proof.iter().map(render).collect(),
                inclusion: page.inclusion.iter().map(render).collect(),
                coverage: Some(EventCoverage {
                    contiguous: page.coverage.contiguous,
                    examined: page.coverage.examined as u64,
                    scan_bounded: page.coverage.scan_bounded,
                }),
            })),
            Err(error) => Err(read_status(error, self.disclosure)),
        }
    }

    async fn get_record(
        &self,
        request: Request<GetRecordRequest>,
    ) -> Result<Response<GetRecordResponse>, Status> {
        let asked = request.into_inner();
        if asked.zone.is_empty() || asked.ledger.is_empty() {
            return Err(status_of(
                &ApiError::new(
                    ErrorClass::Validation,
                    "store_required",
                    "one occurrence is read inside one ledger: name `zone` and `ledger`",
                ),
                self.disclosure,
            ));
        }
        // Resolved the same way the HTTP surface resolves it, so a reader gets one answer whichever
        // transport asked: a name and an identity address the same ledger, and a scope nobody holds
        // is a refusal rather than an empty answer.
        let scope = match read::canonical(
            self.catalog.as_ref(),
            Scope::Tenant {
                zone: asked.zone,
                ledger: asked.ledger,
            },
        ) {
            Ok(scope) => scope,
            Err(error) => return Err(read_status(error, self.disclosure)),
        };

        let facade = self.clone();
        let event_id = asked.event_id;
        let found = tokio::task::spawn_blocking(move || {
            read::get(&facade.store, &scope, &event_id, &facade.cursor_key)
        })
        .await
        .unwrap_or_else(|error| Err(read::ReadError::Unavailable(error.to_string())));

        match found {
            Ok(Some(record)) => Ok(Response::new(GetRecordResponse {
                record: render(&record),
            })),
            Ok(None) => Err(status_of(
                &ApiError::new(
                    ErrorClass::NotFound,
                    "event_not_found",
                    "no event in this ledger carries that identifier",
                ),
                self.disclosure,
            )),
            Err(error) => Err(read_status(error, self.disclosure)),
        }
    }

    /// The same configuration the HTTP binding publishes, field for field.
    ///
    /// Built from the one [`super::configuration::document`] both transports call, so a producer
    /// cannot learn a different interface depending on how it asked — which, for a document whose
    /// whole job is telling a producer where to ship, would be the discovery chain lying.
    async fn get_event_configuration(
        &self,
        _request: Request<GetEventConfigurationRequest>,
    ) -> Result<Response<GetEventConfigurationResponse>, Status> {
        let document =
            super::configuration::document(&self.base_url, &self.base_url, &self.accepted_types());

        Ok(Response::new(GetEventConfigurationResponse {
            r#interface: document.interface,
            store: document.store,
            endpoints: Some(EventEndpoints {
                ingest: document.endpoints.ingest,
                records: document.endpoints.records,
                record: document.endpoints.record,
                tenant_records: document.endpoints.tenant_records,
            }),
            event_types: document.event_types,
            capabilities: document.capabilities,
            offsets: Some(EventOffsets {
                api: document.offsets.api,
                format: document.offsets.format,
                editable: document.offsets.editable,
            }),
        }))
    }
}

/// Which records a request is asking for.
fn scope_of(asked: &ListRecordsRequest) -> Result<(Scope, &'static str), Status> {
    if !asked.producer.is_empty() && !asked.instance.is_empty() {
        if asked.zone.is_empty() || asked.ledger.is_empty() {
            return Err(Status::invalid_argument(
                "a producer stream is named inside one ledger: state `zone` and `ledger` too",
            ));
        }

        return Ok((
            Scope::Stream {
                zone: asked.zone.clone(),
                ledger: asked.ledger.clone(),
                class: match asked.producer_class.is_empty() {
                    true => permguard_events::PRODUCER_CLASS_DATA_PLANE.to_owned(),
                    false => asked.producer_class.clone(),
                },
                producer: asked.producer.clone(),
                instance: asked.instance.clone(),
            },
            "stream",
        ));
    }
    if asked.zone.is_empty() || asked.ledger.is_empty() {
        return Err(Status::invalid_argument(
            "name a zone and a ledger, or one producer stream with `producer` and `instance`",
        ));
    }

    Ok((
        Scope::Tenant {
            zone: asked.zone.clone(),
            ledger: asked.ledger.clone(),
        },
        "tenant",
    ))
}

/// What a request narrows to.
///
/// `producer`/`instance` narrow a *tenant* read; on a stream read they already selected the scope,
/// so repeating them as filters would be checking what the directory already guarantees.
fn filters_of(asked: &ListRecordsRequest) -> Filters {
    let some = |value: &str| (!value.is_empty()).then(|| value.to_owned());
    let stream_scoped = !asked.producer.is_empty() && !asked.instance.is_empty();

    Filters {
        event_types: asked.event_types.clone(),
        producer: (!stream_scoped).then(|| some(&asked.producer)).flatten(),
        instance: (!stream_scoped).then(|| some(&asked.instance)).flatten(),
        profile: some(&asked.profile),
        policy_partition: some(&asked.policy_partition),
        kind: some(&asked.kind),
        event_id: some(&asked.event_id),
        since: some(&asked.since),
        until_time: some(&asked.until_time),
        history: some(&asked.history),
    }
}

fn api_error(refused: &Refused) -> ApiError {
    let class = match refused {
        Refused::Unattributable(_) | Refused::Unverifiable(_) | Refused::Unregistered(_) => {
            ErrorClass::Validation
        }
        Refused::Fork { .. } | Refused::Closed(_) => ErrorClass::Conflict,
        Refused::Unavailable(_) => ErrorClass::Unavailable,
    };

    ApiError::new(class, refused.code(), refused.to_string())
}

/// A read refusal, as gRPC says it.
fn read_status(error: read::ReadError, disclosure: Disclosure) -> Status {
    match error {
        ref expired @ read::ReadError::Expired {
            ref oldest,
            oldest_sequence,
            requested_sequence,
        } => {
            let mut status = status_of(
                &ApiError::new(ErrorClass::NotFound, "offset_expired", expired.to_string()),
                disclosure,
            );
            // The same three facts the HTTP body carries, so a consumer records the same gap
            // whichever way it asked.
            let metadata = status.metadata_mut();
            for (name, value) in [
                ("permguard-oldest-offset", oldest.clone()),
                ("permguard-oldest-sequence", oldest_sequence.to_string()),
                (
                    "permguard-requested-sequence",
                    requested_sequence.to_string(),
                ),
            ] {
                if let Ok(held) = value.parse() {
                    metadata.insert(name, held);
                }
            }

            status
        }
        read::ReadError::Offset(refused) => status_of(
            &ApiError::new(
                ErrorClass::Validation,
                "offset_invalid",
                refused.to_string(),
            ),
            disclosure,
        ),
        read::ReadError::Unknown(detail) => status_of(
            &ApiError::new(ErrorClass::NotFound, "ledger_not_held", detail),
            disclosure,
        ),
        read::ReadError::Unavailable(detail) => status_of(
            &ApiError::new(ErrorClass::Unavailable, "event_store_unavailable", detail),
            disclosure,
        ),
        // Not `not_found`: the search stopped at a bound this store chose, so whether the record
        // is here was never established. Reporting it as an absence would be this store answering
        // a question about the caller's data that it did not ask.
        ref exhausted @ read::ReadError::SearchExhausted { .. } => status_of(
            &ApiError::new(
                ErrorClass::Unavailable,
                "search_exhausted",
                exhausted.to_string(),
            ),
            disclosure,
        ),
    }
}

fn status_of(failed: &ApiError, disclosure: Disclosure) -> Status {
    let message = failed.disclosed_message(disclosure);
    let mut status = match failed.class() {
        ErrorClass::Validation => Status::invalid_argument(message),
        ErrorClass::NotFound => Status::not_found(message),
        ErrorClass::Conflict => Status::failed_precondition(message),
        ErrorClass::Unavailable => Status::unavailable(message),
        ErrorClass::Internal => Status::internal(message),
    };
    let metadata = status.metadata_mut();
    if let Ok(class) = tonic::metadata::MetadataValue::try_from(failed.class().as_str()) {
        metadata.insert(GRPC_ERROR_CLASS, class);
    }
    if let Ok(code) = tonic::metadata::MetadataValue::try_from(failed.code()) {
        metadata.insert(GRPC_ERROR_CODE, code);
    }

    status
}

/// One value as the bytes the wire carries it as.
fn render(value: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap_or_default()
}
