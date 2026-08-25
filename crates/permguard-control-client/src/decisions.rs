// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Shipping decision batches to a control plane, and reading them back.
//!
//! # What the answers mean to a shipper
//!
//! The distinction that matters is **retry** against **stop**, and it is not a
//! matter of taste: a shipper that retries a batch nobody can verify loops
//! forever, and one that drops a batch the store merely could not take right
//! now loses records that were durable on its own disk.
//!
//! ```text
//! 200 ok            → truncate the spool by `acked`
//! 409 out_of_order  → resend from `expected_seq`; nothing was lost
//! 4xx anything else → STOP and alarm: this is an incident, not a retry
//! 5xx / no answer   → retry with backoff; the records are still here
//! ```

use serde::Deserialize;
use serde_json::Value;

use crate::endpoint::Endpoint;
use crate::http::Client;
use crate::tls::TlsOptions;

/// How long one shipment may take.
///
/// Generous next to a decision, tight next to a spool that fills: the point of
/// a deadline here is that a hung socket must not stop the next round, not
/// that the control plane is fast.
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// What the control plane said about a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shipped {
    /// Durable through `acked`. The producer may truncate by it.
    Acknowledged {
        /// The highest contiguous durable sequence.
        acked: u64,
        /// How many records this call added. Zero for a replay.
        stored: u64,
    },
    /// The shipper ran ahead. Nothing was stored, and nothing was lost.
    OutOfOrder {
        /// Where to resume from.
        expected_seq: u64,
    },
}

/// Why a shipment did not land.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShipError {
    /// The store could not take it right now, or could not be reached.
    ///
    /// **Retry.** The records are still on the producer's disk.
    Unavailable(String),
    /// The batch was refused on its merits: a signature that does not verify,
    /// a chain that does not hold, a conflict, a closed stream.
    ///
    /// **Stop and alarm.** Retrying cannot change any of those answers, and a
    /// shipper spinning on one is a shipper that never notices the incident.
    Rejected {
        /// The code the server used, so an operator can search for it.
        code: String,
        /// What it said.
        detail: String,
    },
}

impl std::fmt::Display for ShipError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(detail) => write!(formatter, "{detail}"),
            Self::Rejected { code, detail } => write!(formatter, "{detail} ({code})"),
        }
    }
}

/// Both halves of the decision log, over whichever transport the URL names.
pub trait DecisionLog: DecisionSink + DecisionReader {}

impl<T: DecisionSink + DecisionReader> DecisionLog for T {}

/// The client for an endpoint, chosen by its scheme.
///
/// Which transport a deployment uses is its own business — a mesh that
/// terminates gRPC, a proxy that only speaks HTTP — and it must not change
/// what a shipper or a reader has to reason about. So the two clients answer
/// with the same types, and callers never branch on the scheme themselves.
pub fn client(
    url: &str,
    tls: &crate::tls::TlsOptions,
    narrator: Box<dyn crate::narrate::Narrator>,
) -> Result<Box<dyn DecisionLog>, String> {
    if url.starts_with("grpc://") || url.starts_with("grpcs://") {
        return Ok(Box::new(crate::decisions_grpc::GrpcSink::connect(
            url, tls, narrator,
        )?));
    }

    Ok(Box::new(HttpSink::connect(url, tls, narrator)?))
}

/// Where a data plane ships what it decided.
pub trait DecisionSink: Send + Sync {
    /// Ships one signed batch.
    fn ship(&self, batch: &Value) -> Result<Shipped, ShipError>;
}

/// Which records a reader is asking for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadScope {
    /// One tenant's records.
    Tenant {
        /// The zone that owns them.
        zone: String,
        /// The ledger they were decided from.
        ledger: String,
    },
    /// One producer's whole stream — the privileged, deployment-wide read.
    Stream {
        /// The producer.
        pdp_id: String,
        /// Which incarnation of it.
        instance: String,
    },
}

/// One page of records, and where to continue.
#[derive(Debug, Clone, Deserialize)]
pub struct Page {
    /// The records, verbatim, exactly as the producer signed them.
    pub records: Vec<Value>,
    /// The opaque offset to present next.
    pub next: String,
    /// Whether the scope holds more right now.
    #[serde(default)]
    pub more: bool,
    /// The signed envelopes attesting these records, when asked for.
    #[serde(default)]
    pub proof: Vec<Value>,
    /// One inclusion path per record, when asked for.
    ///
    /// What a tenant-scoped reader verifies with: its page is a subsequence of
    /// a producer's stream, so the chain cannot be checked across it.
    #[serde(default)]
    pub inclusion: Vec<Value>,
}

/// Why a read did not answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    /// The offset is older than what the scope still holds.
    Expired {
        /// Where the remaining records begin.
        oldest: String,
    },
    /// The server refused, and said why.
    Refused {
        /// The code it used.
        code: String,
        /// What it said.
        detail: String,
    },
    /// It could not be reached.
    Unavailable(String),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Expired { .. } => write!(
                formatter,
                "this offset is older than what the store still holds: records between it and the oldest available one have left on the retention schedule"
            ),
            Self::Refused { code, detail } => write!(formatter, "{detail} ({code})"),
            Self::Unavailable(detail) => write!(formatter, "{detail}"),
        }
    }
}

/// Reading decisions back from a control plane.
pub trait DecisionReader {
    /// Reads one page of `scope`, from `offset`.
    fn read(
        &self,
        scope: &ReadScope,
        offset: Option<&str>,
        limit: usize,
        proof: bool,
    ) -> Result<Page, ReadError>;
}

/// The HTTP shipper.
pub struct HttpSink {
    endpoint: Endpoint,
    client: Client,
}

impl HttpSink {
    /// Connects to `url` with `tls`, narrating each exchange to `narrator`.
    pub fn connect(
        url: &str,
        tls: &TlsOptions,
        narrator: Box<dyn crate::narrate::Narrator>,
    ) -> Result<Self, String> {
        let endpoint = Endpoint::parse(url).map_err(|error| error.to_string())?;
        let client = Client::new(TIMEOUT, tls.clone(), endpoint.is_tls())
            .map_err(|error| error.to_string())?
            .with_narrator(narrator);

        Ok(Self { endpoint, client })
    }
}

#[derive(Debug, Deserialize)]
struct Acknowledgement {
    acked: u64,
    stored: u64,
}

#[derive(Debug, Deserialize)]
struct Ahead {
    expected_seq: u64,
}

impl DecisionSink for HttpSink {
    fn ship(&self, batch: &Value) -> Result<Shipped, ShipError> {
        let response = self
            .client
            .request(
                &self.endpoint,
                "POST",
                "/decisions/v1/batches",
                Some(&batch.to_string()),
            )
            // No answer at all is the retryable case, always: the records are
            // still here, and the store may simply be restarting.
            .map_err(|error| ShipError::Unavailable(error.to_string()))?;

        match response.status {
            200..=299 => serde_json::from_str::<Acknowledgement>(&response.body)
                .map(|answer| Shipped::Acknowledged {
                    acked: answer.acked,
                    stored: answer.stored,
                })
                .map_err(|error| {
                    // An acknowledgement that cannot be read is not an
                    // acknowledgement: the producer must not truncate on it.
                    ShipError::Unavailable(format!("the acknowledgement was unreadable: {error}"))
                }),
            409 => serde_json::from_str::<Ahead>(&response.body)
                .map(|answer| Shipped::OutOfOrder {
                    expected_seq: answer.expected_seq,
                })
                .map_err(|error| ShipError::Unavailable(error.to_string())),
            500..=599 => Err(ShipError::Unavailable(format!(
                "the control plane answered {}: {}",
                response.status,
                first_line(&response.body)
            ))),
            status => {
                let parsed: Value = serde_json::from_str(&response.body).unwrap_or(Value::Null);
                let field = |name: &str| {
                    parsed
                        .get(name)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned()
                };
                let code = match field("code").as_str() {
                    "" => format!("http_{status}"),
                    code => code.to_owned(),
                };
                let detail = match field("message").as_str() {
                    "" => first_line(&response.body),
                    message => message.to_owned(),
                };

                Err(ShipError::Rejected { code, detail })
            }
        }
    }
}

impl DecisionReader for HttpSink {
    fn read(
        &self,
        scope: &ReadScope,
        offset: Option<&str>,
        limit: usize,
        proof: bool,
    ) -> Result<Page, ReadError> {
        let mut path = match scope {
            ReadScope::Tenant { zone, ledger } => {
                format!("/zones/{zone}/ledgers/{ledger}/decisions/v1/records?limit={limit}")
            }
            ReadScope::Stream { pdp_id, instance } => {
                format!("/decisions/v1/records?pdp={pdp_id}&instance={instance}&limit={limit}")
            }
        };
        if proof {
            path.push_str("&proof=true");
        }
        if let Some(offset) = offset {
            // The offset is opaque and base64url, so it is already safe in a
            // query string: encoding it again would change it.
            path.push_str(&format!("&from={offset}"));
        }

        let response = self
            .client
            .request(&self.endpoint, "GET", &path, None)
            .map_err(|error| ReadError::Unavailable(error.to_string()))?;

        if (200..300).contains(&response.status) {
            return serde_json::from_str(&response.body).map_err(|error| {
                ReadError::Unavailable(format!("the page was unreadable: {error}"))
            });
        }

        let parsed: Value = serde_json::from_str(&response.body).unwrap_or(Value::Null);
        let field = |name: &str| {
            parsed
                .get(name)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        if field("code") == "offset_expired" {
            return Err(ReadError::Expired {
                oldest: field("oldest"),
            });
        }

        Err(ReadError::Refused {
            code: match field("code").as_str() {
                "" => format!("http_{}", response.status),
                code => code.to_owned(),
            },
            detail: match field("message").as_str() {
                "" => first_line(&response.body),
                message => message.to_owned(),
            },
        })
    }
}

fn first_line(body: &str) -> String {
    body.lines()
        .next()
        .unwrap_or_default()
        .chars()
        .take(200)
        .collect()
}
