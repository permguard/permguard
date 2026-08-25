// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The decision log over gRPC: the same two operations, the same answers.
//!
//! Which transport a deployment uses is a deployment's business — a mesh that
//! terminates gRPC, a proxy that only speaks HTTP — and it must not change what
//! a shipper or a reader has to reason about. So both clients return the same
//! types, and the one difference that matters is preserved on both: **retry**
//! against **stop**. A shipper that retried a batch nobody can verify loops
//! forever; one that dropped a batch the store merely could not take right now
//! loses records that were durable on its own disk.

use serde_json::Value;
use tonic::Request;

use crate::decisions::{DecisionReader, DecisionSink, Page, ReadError, ShipError, Shipped};
use crate::grpc::GrpcChannel;
use crate::narrate::Narrator;
use crate::tls::TlsOptions;
use crate::v1::decision_log_client::DecisionLogClient;
use crate::v1::{ReadRequest, ShipRequest};

/// The metadata a refusal's code travels in.
const CODE: &str = "permguard-error-code";

/// The gRPC client.
pub struct GrpcSink {
    endpoint: GrpcChannel,
}

impl GrpcSink {
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

    fn client(&self) -> DecisionLogClient<tonic::transport::Channel> {
        DecisionLogClient::new(self.endpoint.channel())
            // A read page carries up to a thousand records plus their proofs:
            // tonic's 4 MiB default is not a number anybody chose for that.
            .max_decoding_message_size(crate::MAX_RESPONSE_BYTES as usize)
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

impl DecisionSink for GrpcSink {
    fn ship(&self, batch: &Value) -> Result<Shipped, ShipError> {
        let request = ShipRequest {
            batch: serde_json::to_vec(batch).unwrap_or_default(),
        };
        let answer = self.endpoint.run(
            "DecisionLog/Ship",
            self.client().ship(Request::new(request)),
        );

        match answer {
            Ok(answer) => {
                if answer.out_of_order {
                    return Ok(Shipped::OutOfOrder {
                        expected_seq: answer.expected_seq,
                    });
                }

                Ok(Shipped::Acknowledged {
                    acked: answer.acked,
                    stored: answer.stored,
                })
            }
            // Unavailable and "no answer at all" are the retryable cases: the
            // records are still on this plane's disk either way.
            Err(status)
                if matches!(
                    status.code(),
                    tonic::Code::Unavailable
                        | tonic::Code::DeadlineExceeded
                        | tonic::Code::ResourceExhausted
                ) =>
            {
                Err(ShipError::Unavailable(status.message().to_owned()))
            }
            Err(status) => Err(ShipError::Rejected {
                code: Self::code_of(&status),
                detail: status.message().to_owned(),
            }),
        }
    }
}

impl DecisionReader for GrpcSink {
    fn read(
        &self,
        scope: &crate::decisions::ReadScope,
        offset: Option<&str>,
        limit: usize,
        proof: bool,
    ) -> Result<Page, ReadError> {
        let mut request = ReadRequest {
            from: offset.unwrap_or_default().to_owned(),
            limit: u32::try_from(limit).unwrap_or(100),
            proof,
            ..ReadRequest::default()
        };
        match scope {
            crate::decisions::ReadScope::Tenant { zone, ledger } => {
                request.zone = zone.clone();
                request.ledger = ledger.clone();
            }
            crate::decisions::ReadScope::Stream { pdp_id, instance } => {
                request.pdp = pdp_id.clone();
                request.instance = instance.clone();
            }
        }

        let answer = self.endpoint.run(
            "DecisionLog/Read",
            self.client().read(Request::new(request)),
        );

        match answer {
            Ok(answer) => Ok(Page {
                records: answer
                    .records
                    .iter()
                    .map(Vec::as_slice)
                    .map(parse)
                    .collect(),
                next: answer.next,
                more: answer.more,
                proof: answer.proof.iter().map(Vec::as_slice).map(parse).collect(),
                inclusion: answer
                    .inclusion
                    .iter()
                    .map(Vec::as_slice)
                    .map(parse)
                    .collect(),
            }),
            Err(status) if Self::code_of(&status) == "offset_expired" => Err(ReadError::Expired {
                oldest: status
                    .metadata()
                    .get("permguard-oldest-offset")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_owned(),
            }),
            Err(status) if status.code() == tonic::Code::Unavailable => {
                Err(ReadError::Unavailable(status.message().to_owned()))
            }
            Err(status) => Err(ReadError::Refused {
                code: Self::code_of(&status),
                detail: status.message().to_owned(),
            }),
        }
    }
}

fn parse(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap_or(Value::Null)
}
