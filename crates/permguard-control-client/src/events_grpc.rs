// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Shipping events over gRPC: the same operation, the same answers.
//!
//! Which transport a deployment uses is a deployment's business — a mesh that terminates gRPC, a
//! proxy that only speaks HTTP — and it must not change what a shipper has to reason about. So
//! both clients return the same types, and the distinction that matters is preserved on both:
//! **retry** against **stop**.

use tonic::Request;

use crate::decisions::ShipError;
use crate::events::{
    Coverage, EventReader, EventSink, Page, ReadError, ReadScope, ReadWindow, Shipped,
};
use crate::grpc::GrpcChannel;
use crate::narrate::Narrator;
use crate::tls::TlsOptions;
use crate::v1::event_log_client::EventLogClient;
use crate::v1::{GetRecordRequest, IngestBatchRequest, ListRecordsRequest};

/// The metadata a refusal's code travels in.
const CODE: &str = "permguard-error-code";

/// The gRPC client.
pub struct GrpcEventSink {
    endpoint: GrpcChannel,
}

impl GrpcEventSink {
    /// Connects to `url` with `tls`.
    pub fn connect(
        url: &str,
        tls: &TlsOptions,
        narrator: Box<dyn Narrator>,
    ) -> Result<Self, String> {
        Ok(Self {
            endpoint: GrpcChannel::connect(url, tls, narrator)?,
        })
    }

    fn client(&self) -> EventLogClient<tonic::transport::Channel> {
        EventLogClient::new(self.endpoint.channel())
            .max_decoding_message_size(crate::MAX_RESPONSE_BYTES as usize)
            // A batch carries up to ten thousand records: tonic's 4 MiB default is not a number
            // anybody chose for that, and a shipper whose batches are refused by its own client
            // would report the control plane as the problem.
            .max_encoding_message_size(crate::MAX_RESPONSE_BYTES as usize)
    }

    fn code_of(status: &tonic::Status) -> String {
        status
            .metadata()
            .get(CODE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("unknown")
            .to_owned()
    }
}

impl EventSink for GrpcEventSink {
    fn ship(&self, batch: &permguard_events::Batch) -> Result<Shipped, ShipError> {
        let request = IngestBatchRequest {
            envelope: serde_json::to_vec(&batch.signature).map_err(|error| {
                ShipError::Unavailable(format!("the envelope does not render: {error}"))
            })?,
            records: batch
                .records
                .iter()
                .map(|record| serde_json::to_vec(record).unwrap_or_default())
                .collect(),
        };

        let answer = self.endpoint.run(
            "EventLog/IngestBatch",
            self.client().ingest_batch(Request::new(request)),
        );

        match answer {
            Ok(answer) if answer.expected_seq > 0 => Ok(Shipped::OutOfOrder {
                expected_seq: answer.expected_seq,
            }),
            Ok(answer) => Ok(Shipped::Acknowledged {
                acked: answer.acked,
            }),
            Err(status) if status.code() == tonic::Code::Unavailable => {
                Err(ShipError::Unavailable(status.message().to_owned()))
            }
            Err(status) => Err(ShipError::Rejected {
                code: Self::code_of(&status),
                detail: status.message().to_owned(),
            }),
        }
    }
}

impl EventReader for GrpcEventSink {
    fn read(&self, scope: &ReadScope, window: &ReadWindow) -> Result<Page, ReadError> {
        let mut request = ListRecordsRequest {
            from: window.from.clone().unwrap_or_default(),
            until: window.until.clone().unwrap_or_default(),
            limit_records: u32::try_from(window.limit_records).unwrap_or_default(),
            limit_bytes: window.limit_bytes,
            proof: window.proof,
            event_types: window.filters.event_types.clone(),
            profile: window.filters.profile.clone().unwrap_or_default(),
            policy_partition: window.filters.policy_partition.clone().unwrap_or_default(),
            kind: window.filters.kind.clone().unwrap_or_default(),
            event_id: window.filters.event_id.clone().unwrap_or_default(),
            since: window.filters.since.clone().unwrap_or_default(),
            until_time: window.filters.until_time.clone().unwrap_or_default(),
            history: window.filters.history.clone().unwrap_or_default(),
            ..ListRecordsRequest::default()
        };
        match scope {
            ReadScope::Tenant { zone, ledger } => {
                request.zone.clone_from(zone);
                request.ledger.clone_from(ledger);
                // On a tenant read these narrow; on a stream read they select the scope, and
                // repeating them would be checking what the directory already guarantees.
                request.producer = window.filters.producer.clone().unwrap_or_default();
                request.instance = window.filters.instance.clone().unwrap_or_default();
            }
            ReadScope::Stream {
                zone,
                ledger,
                class,
                producer,
                instance,
            } => {
                request.zone.clone_from(zone);
                request.ledger.clone_from(ledger);
                request.producer_class.clone_from(class);
                request.producer.clone_from(producer);
                request.instance.clone_from(instance);
            }
        }

        let answer = self.endpoint.run(
            "EventLog/ListRecords",
            self.client().list_records(Request::new(request)),
        );

        match answer {
            Ok(answer) => Ok(Page {
                records: parse_all("record", &answer.records)?,
                next: answer.next,
                more: answer.more,
                oldest_available: answer.oldest_available,
                high_watermark: answer.high_watermark,
                proof: parse_all("proof", &answer.proof)?,
                inclusion: parse_all("inclusion path", &answer.inclusion)?,
                coverage: answer
                    .coverage
                    .map(|held| Coverage {
                        contiguous: held.contiguous,
                        examined: held.examined,
                        scan_bounded: held.scan_bounded,
                    })
                    .unwrap_or_default(),
            }),
            Err(status) => Err(read_error(&status)),
        }
    }

    fn signers(&self, zone: &str, ledger: &str) -> Result<serde_json::Value, ReadError> {
        let request = crate::v1::GetSignersRequest {
            zone: zone.to_owned(),
            ledger: ledger.to_owned(),
            from_seq: 0,
            until_seq: 0,
        };

        let answer = self.endpoint.run(
            "EventLog/GetSigners",
            self.client().get_signers(Request::new(request)),
        );

        // Rendered into the same document the HTTP transport serves, so a caller switching
        // transports reads one shape.
        match answer {
            Ok(answer) => {
                let streams = answer
                    .streams
                    .into_iter()
                    .map(|held| {
                        let spans = held
                            .spans
                            .into_iter()
                            .map(|span| {
                                let jwk: serde_json::Value = serde_json::from_slice(&span.jwk)
                                    .map_err(|error| {
                                        ReadError::Unavailable(format!(
                                            "a signer key was unreadable: {error}"
                                        ))
                                    })?;

                                Ok(serde_json::json!({
                                    "from": span.from_seq,
                                    "kid": span.kid,
                                    "jwk": jwk,
                                }))
                            })
                            .collect::<Result<Vec<_>, ReadError>>()?;

                        Ok(serde_json::json!({
                            "producer_class": held.producer_class,
                            "producer": held.producer,
                            "instance": held.instance,
                            "acked": held.acked,
                            "spans": spans,
                        }))
                    })
                    .collect::<Result<Vec<_>, ReadError>>()?;

                Ok(serde_json::json!({ "streams": streams }))
            }
            Err(status) => Err(read_error(&status)),
        }
    }

    fn get(
        &self,
        zone: &str,
        ledger: &str,
        event_id: &str,
    ) -> Result<Option<serde_json::Value>, ReadError> {
        let answer = self.endpoint.run(
            "EventLog/GetRecord",
            self.client().get_record(Request::new(GetRecordRequest {
                zone: zone.to_owned(),
                ledger: ledger.to_owned(),
                event_id: event_id.to_owned(),
            })),
        );

        match answer {
            Ok(answer) => serde_json::from_slice(&answer.record)
                .map(Some)
                .map_err(|error| {
                    ReadError::Unavailable(format!(
                        "the gRPC answer's event record was not JSON: {error}"
                    ))
                }),
            // Absence is an answer, not a failure.
            Err(status) if Self::code_of(&status) == "event_not_found" => Ok(None),
            Err(status) => Err(read_error(&status)),
        }
    }
}

/// A read refusal, from the status it arrived as.
fn read_error(status: &tonic::Status) -> ReadError {
    let metadata = |name: &str| {
        status
            .metadata()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };
    if GrpcEventSink::code_of(status) == "offset_expired" {
        return ReadError::Expired {
            oldest: metadata("permguard-oldest-offset"),
            oldest_sequence: metadata("permguard-oldest-sequence").parse().unwrap_or(0),
            requested_sequence: metadata("permguard-requested-sequence")
                .parse()
                .unwrap_or(0),
        };
    }
    if status.code() == tonic::Code::Unavailable {
        return ReadError::Unavailable(status.message().to_owned());
    }

    ReadError::Refused {
        code: GrpcEventSink::code_of(status),
        detail: status.message().to_owned(),
    }
}

fn parse_all(label: &str, values: &[Vec<u8>]) -> Result<Vec<serde_json::Value>, ReadError> {
    values
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            serde_json::from_slice(bytes).map_err(|error| {
                ReadError::Unavailable(format!(
                    "the gRPC page's {label} {index} was not JSON: {error}"
                ))
            })
        })
        .collect()
}
