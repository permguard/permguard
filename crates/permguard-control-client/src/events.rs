// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Shipping events to a control plane, and reading them back.
//!
//! # Retry against stop
//!
//! The one distinction that matters, preserved identically on both transports. A shipper that
//! retried a batch nobody can verify loops for ever; one that dropped a batch the store merely
//! could not take right now loses records that were durable on its own disk — and for events that
//! second failure also changes what the plane's future decisions mean, because the journal is the
//! history they read.
//!
//! So [`ShipError::Unavailable`] is *retry* and [`ShipError::Rejected`] is *stop and page
//! somebody*, and no answer is ever mapped from one to the other for convenience.
//!
//! # Why this is not the decision client
//!
//! Same shape, different evidence: a different route, a different envelope type, a different
//! digest domain. Sharing the client would mean one type could reach the other's endpoint, and the
//! whole point of domain separation is that it cannot.

use serde::Deserialize;
use serde_json::Value;

/// Why shipping did not land.
///
/// The decision log's own type, re-exported rather than copied: the retry-against-stop
/// distinction is the same distinction, and two enums would be two chances to map one onto the
/// other differently.
pub use crate::decisions::ShipError;
use crate::encode;
use crate::endpoint::Endpoint;
use crate::http::Client;
use crate::tls::TlsOptions;

/// How long one exchange may take.
///
/// Generous next to a decision, tight next to a journal that fills: the point of a deadline here
/// is that a hung socket must not stop the next round.
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Where events are shipped: `POST /events/v1alpha1/batches`.
pub const BATCHES_PATH: &str = "/events/v1alpha1/batches";

/// What shipping one batch concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shipped {
    /// The store holds everything through `acked`, durably.
    Acknowledged {
        /// The highest contiguous durable sequence. The producer advances by this and nothing else.
        acked: u64,
    },
    /// The store needs an earlier batch first. Nothing was stored, and nothing is lost.
    OutOfOrder {
        /// What to resend from.
        expected_seq: u64,
    },
}

/// Where a data plane ships what it recorded.
pub trait EventSink: Send + Sync {
    /// Ships one signed batch.
    fn ship(&self, batch: &permguard_events::Batch) -> Result<Shipped, ShipError>;
}

/// The HTTP client.
pub struct HttpEventSink {
    pub(crate) endpoint: Endpoint,
    pub(crate) client: Client,
}

impl HttpEventSink {
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
}

#[derive(Debug, Deserialize)]
struct Ahead {
    expected_seq: u64,
}

impl EventSink for HttpEventSink {
    fn ship(&self, batch: &permguard_events::Batch) -> Result<Shipped, ShipError> {
        let body = serde_json::to_string(batch).map_err(|error| {
            ShipError::Unavailable(format!("the batch does not render: {error}"))
        })?;
        let response = self
            .client
            .request(&self.endpoint, "POST", BATCHES_PATH, Some(&body))
            .map_err(|error| ShipError::Unavailable(error.to_string()))?;

        if (200..300).contains(&response.status) {
            let held: Acknowledgement = serde_json::from_str(&response.body).map_err(|error| {
                ShipError::Unavailable(format!("the acknowledgement was unreadable: {error}"))
            })?;

            return Ok(Shipped::Acknowledged { acked: held.acked });
        }

        let parsed: Value = serde_json::from_str(&response.body).unwrap_or(Value::Null);
        let field = |name: &str| {
            parsed
                .get(name)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        // Not an error: the store needs an earlier batch, and the next round reads from what it
        // acknowledged. Retrying this one unchanged would be refused again for ever.
        if field("code") == "out_of_order"
            && let Ok(ahead) = serde_json::from_str::<Ahead>(&response.body)
        {
            return Ok(Shipped::OutOfOrder {
                expected_seq: ahead.expected_seq,
            });
        }
        // A store that is down, overloaded, or behind a proxy that is: retry.
        if response.status >= 500 || response.status == 429 {
            return Err(ShipError::Unavailable(match field("message").as_str() {
                "" => format!("the control plane answered {}", response.status),
                message => message.to_owned(),
            }));
        }

        Err(ShipError::Rejected {
            code: match field("code").as_str() {
                "" => format!("http_{}", response.status),
                code => code.to_owned(),
            },
            detail: match field("message").as_str() {
                "" => response.body.chars().take(200).collect(),
                message => message.to_owned(),
            },
        })
    }
}

/// Which records a reader is asking for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadScope {
    /// One tenant's records, merged from every producer that contributed.
    Tenant { zone: String, ledger: String },
    /// One producer's whole stream — the administrative read.
    Stream {
        zone: String,
        ledger: String,
        class: String,
        producer: String,
        instance: String,
    },
}

/// How far a reader wants to go, from where, and narrowed to what.
#[derive(Debug, Clone, Default)]
pub struct ReadWindow {
    /// The opaque offset a previous page returned. `None` starts at the oldest still held.
    pub from: Option<String>,
    /// The export bound, echoed from the first page's `high_watermark`. `None` is a tail.
    pub until: Option<String>,
    /// How many records at most. `0` takes the server's default.
    pub limit_records: usize,
    /// How many bytes at most. `0` takes the server's default.
    pub limit_bytes: u64,
    /// Whether to ask for the signed envelopes and inclusion paths.
    pub proof: bool,
    /// What to narrow to.
    pub filters: ReadFilters,
}

/// The declared filters. Each narrows; none widens what the scope may return.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReadFilters {
    pub event_types: Vec<String>,
    pub producer: Option<String>,
    pub instance: Option<String>,
    pub profile: Option<String>,
    pub policy_partition: Option<String>,
    pub kind: Option<String>,
    pub event_id: Option<String>,
    pub since: Option<String>,
    pub until_time: Option<String>,
    pub history: Option<String>,
}

/// What a page proves about what it covers.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Coverage {
    #[serde(default)]
    pub contiguous: bool,
    #[serde(default)]
    pub examined: u64,
    #[serde(default)]
    pub scan_bounded: bool,
}

/// One page of events, and where to continue.
#[derive(Debug, Clone, Deserialize)]
pub struct Page {
    /// The records, verbatim, exactly as the producer signed them.
    pub records: Vec<Value>,
    /// The opaque offset to present next, even for an empty page.
    pub next: String,
    /// Whether there is more, against this read's `until` or the returned watermark.
    #[serde(default)]
    pub more: bool,
    /// The oldest offset the scope still holds.
    #[serde(default)]
    pub oldest_available: String,
    /// The exclusive end this read observed, opaque. Echo it as `until` to bound an export.
    #[serde(default)]
    pub high_watermark: String,
    /// The signed envelopes attesting these records, when asked for.
    #[serde(default)]
    pub proof: Vec<Value>,
    /// One inclusion path per record, when asked for.
    #[serde(default)]
    pub inclusion: Vec<Value>,
    #[serde(default)]
    pub coverage: Coverage,
}

/// Why a read did not answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    /// The offset is older than what the scope still holds.
    Expired {
        oldest: String,
        oldest_sequence: u64,
        requested_sequence: u64,
    },
    /// The server refused, and said why.
    Refused { code: String, detail: String },
    /// It could not be reached.
    Unavailable(String),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Expired {
                oldest_sequence,
                requested_sequence,
                ..
            } => write!(
                formatter,
                "this offset stands at {requested_sequence} and the oldest still held is \
                 {oldest_sequence}: the {} records in between left on the retention schedule",
                oldest_sequence.saturating_sub(*requested_sequence)
            ),
            Self::Refused { code, detail } => write!(formatter, "{detail} ({code})"),
            Self::Unavailable(detail) => write!(formatter, "{detail}"),
        }
    }
}

/// Reading events back from a control plane.
pub trait EventReader {
    /// Reads one bounded, filtered block of `scope`.
    fn read(&self, scope: &ReadScope, window: &ReadWindow) -> Result<Page, ReadError>;

    /// Reads one occurrence, by the identifier its caller stated.
    fn get(&self, zone: &str, ledger: &str, event_id: &str) -> Result<Option<Value>, ReadError>;

    /// Which key signed which stretch of each producer stream of one ledger, public keys
    /// included — what `verify --keys` wants, fetched once and kept.
    ///
    /// The shape is the signers document both transports serve: `{"streams": [...]}`, each stream
    /// carrying its producer, its durable frontier and its spans.
    fn signers(&self, zone: &str, ledger: &str) -> Result<Value, ReadError>;
}

/// Both halves of the event log, over one connection.
pub trait EventLog: EventSink + EventReader + Send + Sync {}

impl<T: EventSink + EventReader + Send + Sync> EventLog for T {}

impl EventReader for HttpEventSink {
    fn read(&self, scope: &ReadScope, window: &ReadWindow) -> Result<Page, ReadError> {
        // Every caller-supplied value is escaped on the way in. A zone, a ledger and a producer
        // are names somebody chose, and a name carrying `/` or `&` would otherwise address a
        // different route or add a parameter nobody sent.
        let mut path = match scope {
            ReadScope::Tenant { zone, ledger } => format!(
                "/v1/zones/{}/ledgers/{}/events/v1alpha1/records?",
                encode::value(zone),
                encode::value(ledger)
            ),
            ReadScope::Stream {
                zone,
                ledger,
                class,
                producer,
                instance,
            } => format!(
                "/events/v1alpha1/records?zone={}&ledger={}&producer_class={}&producer={}\
                 &instance={}",
                encode::value(zone),
                encode::value(ledger),
                encode::value(class),
                encode::value(producer),
                encode::value(instance)
            ),
        };
        if window.limit_records > 0 {
            path.push_str(&format!("&limit_records={}", window.limit_records));
        }
        if window.limit_bytes > 0 {
            path.push_str(&format!("&limit_bytes={}", window.limit_bytes));
        }
        if window.proof {
            path.push_str("&proof=true");
        }
        // Offsets and watermarks are opaque, and escaped like everything else rather than trusted
        // to be safe: base64url happens to be, and the plane percent-decodes what it receives, so
        // escaping is exact either way. Uniformity is the point — the next value added here
        // inherits the rule instead of needing somebody to notice it.
        if let Some(from) = &window.from {
            path.push_str(&format!("&from={}", encode::value(from)));
        }
        if let Some(until) = &window.until {
            path.push_str(&format!("&until={}", encode::value(until)));
        }
        for event_type in &window.filters.event_types {
            path.push_str(&format!("&event_type={}", encode::value(event_type)));
        }
        for (name, value) in [
            ("producer", &window.filters.producer),
            ("instance", &window.filters.instance),
            ("profile", &window.filters.profile),
            ("policy_partition", &window.filters.policy_partition),
            ("kind", &window.filters.kind),
            ("event_id", &window.filters.event_id),
            ("since", &window.filters.since),
            ("until_time", &window.filters.until_time),
            ("history", &window.filters.history),
        ] {
            if let Some(held) = value {
                path.push_str(&format!("&{name}={}", encode::value(held)));
            }
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

        Err(read_refusal(&response.body, response.status))
    }

    fn signers(&self, zone: &str, ledger: &str) -> Result<Value, ReadError> {
        let path = format!(
            "/v1/zones/{}/ledgers/{}/events/v1alpha1/signers",
            encode::value(zone),
            encode::value(ledger)
        );
        let response = self
            .client
            .request(&self.endpoint, "GET", &path, None)
            .map_err(|error| ReadError::Unavailable(error.to_string()))?;

        if (200..300).contains(&response.status) {
            return serde_json::from_str(&response.body).map_err(|error| {
                ReadError::Unavailable(format!("the manifest was unreadable: {error}"))
            });
        }

        Err(read_refusal(&response.body, response.status))
    }

    fn get(&self, zone: &str, ledger: &str, event_id: &str) -> Result<Option<Value>, ReadError> {
        // The identifier is whatever the caller sent — the ingestion contract asks only that it is
        // not empty — so it is escaped rather than trusted to be a path segment. Unescaped, `a/b`
        // would address a different route and `a?x=1` would add a parameter, while the same record
        // stayed perfectly readable over gRPC: one ledger, two answers.
        let path = format!(
            "/events/v1alpha1/records/{}?zone={}&ledger={}",
            encode::value(event_id),
            encode::value(zone),
            encode::value(ledger)
        );
        let response = self
            .client
            .request(&self.endpoint, "GET", &path, None)
            .map_err(|error| ReadError::Unavailable(error.to_string()))?;

        if (200..300).contains(&response.status) {
            return serde_json::from_str(&response.body)
                .map(Some)
                .map_err(|error| ReadError::Unavailable(format!("unreadable: {error}")));
        }
        let refused = read_refusal(&response.body, response.status);
        // Absence is an answer, not a failure: a caller asking whether an identifier is here
        // should be able to hear "no" without treating it as an outage.
        if matches!(&refused, ReadError::Refused { code, .. } if code == "event_not_found") {
            return Ok(None);
        }

        Err(refused)
    }
}

/// The refusal a body describes.
fn read_refusal(body: &str, status: u16) -> ReadError {
    let parsed: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let field = |name: &str| {
        parsed
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let number = |name: &str| parsed.get(name).and_then(Value::as_u64).unwrap_or_default();

    if field("code") == "offset_expired" {
        return ReadError::Expired {
            oldest: field("oldest_available"),
            oldest_sequence: number("oldest_sequence"),
            requested_sequence: number("requested_sequence"),
        };
    }
    if status >= 500 || status == 429 {
        return ReadError::Unavailable(match field("message").as_str() {
            "" => format!("the control plane answered {status}"),
            message => message.to_owned(),
        });
    }

    ReadError::Refused {
        code: match field("code").as_str() {
            "" => format!("http_{status}"),
            code => code.to_owned(),
        },
        detail: match field("message").as_str() {
            "" => body.chars().take(200).collect(),
            message => message.to_owned(),
        },
    }
}

/// The client for whichever transport the URL names.
///
/// One function, so a caller states an address and not a protocol: a deployment that terminates
/// gRPC and one behind an HTTP proxy read the same events with the same code.
pub fn client(
    url: &str,
    tls: &TlsOptions,
    narrator: Box<dyn crate::narrate::Narrator>,
) -> Result<Box<dyn EventLog>, String> {
    if url.starts_with("grpc") {
        return Ok(Box::new(crate::events_grpc::GrpcEventSink::connect(
            url, tls, narrator,
        )?));
    }

    Ok(Box::new(HttpEventSink::connect(url, tls, narrator)?))
}
