// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The stream reads (WP-5.7a, owner decisions of 2026-10-17): what the Host's stream engine
//! produces and consumes, under `streams.read`.
//!
//! | Route                                              | Answers                                         |
//! | -------------------------------------------------- | ----------------------------------------------- |
//! | `GET /host/v1/streams`                             | each descriptor and role, its resources' states |
//! | `GET /host/v1/streams/{plane}/{type}/frontier`     | the producer's runs and each consumer run       |
//! | `GET /host/v1/streams/{plane}/{type}/records`      | one page of a run, and the gap below it         |
//! | `GET /host/v1/streams/{plane}/{type}/signers`      | each run's signer spans                         |
//! | `GET /host/v1/streams/{plane}/{type}/subscriptions`| the producer's subscriptions                    |
//! | `GET /host/v1/streams/{plane}/{type}/gaps`         | each run with a deleted prefix                  |
//! | `GET /host/v1/streams/{plane}/{type}/anchors`      | each run's prefix anchor                        |
//!
//! The list is authorized on `host`, every other read on its resource, before anything else the
//! query names is read. The Host defines what it reads, [`StreamReads`]; the stream engine,
//! which the Host does not depend on, answers it.

use serde::{Deserialize, Serialize};

use permguard_core::authz::{Actor, Resource, operations};
use permguard_core::{ErrorClass, codes};

use super::{HostApi, Refusal};

/// The most records one page carries, and how many when the query does not say.
pub const MAX_RECORDS: u32 = 1000;
pub const DEFAULT_RECORDS: u32 = 100;

/// One descriptor and role the engine serves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamView {
    pub plane: String,
    pub stream_type: String,
    pub version: u32,
    /// `producer` or `consumer`.
    pub role: String,
    /// `evidence` or `history`.
    pub retention: String,
    pub ring: String,
    /// The membership task that ships the stream, when one does.
    pub task: Option<String>,
    pub resources: Vec<ResourceState>,
}

/// One resource of a stream and where it stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceState {
    pub resource: String,
    /// `open`, `forked`, `behind` (a drain left records unshipped) or `held` (a consumer).
    pub state: String,
}

/// One run as the producer holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProducerRun {
    /// Hex.
    pub run: String,
    pub ended: bool,
    pub last_seq: u64,
    pub sealed: u64,
    /// The least acknowledgement of the required subscriptions, when one holds the run.
    pub acknowledged: Option<u64>,
    /// The first sequence still held: 1 unless a prefix went.
    pub low_watermark: u64,
}

/// One run as a consumer holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumerRun {
    /// Hex: the producer Host and its run.
    pub producer: String,
    pub run: String,
    pub acked: u64,
    pub oldest_retained: u64,
}

/// `GET …/frontier`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frontier {
    pub resource: String,
    pub producer: Vec<ProducerRun>,
    pub consumer: Vec<ConsumerRun>,
}

/// One record of a page, its bytes base64url and its digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordView {
    pub seq: u64,
    pub record: String,
    pub digest: String,
}

/// What a read below the first sequence still held reaches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GapView {
    pub low_watermark: u64,
    pub anchor: AnchorView,
}

/// `GET …/records`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordPage {
    pub resource: String,
    pub run: String,
    pub records: Vec<RecordView>,
    /// Where the next page starts, when the run holds more.
    pub next: Option<u64>,
    pub gap: Option<GapView>,
}

/// One signer span.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpanView {
    pub from_seq: u64,
    pub kid: String,
    /// The public key as JSON.
    pub jwk: String,
}

/// One run's spans, for a role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunSigners {
    pub role: String,
    /// Hex; for a consumer run, the producer Host.
    pub producer: String,
    pub run: String,
    pub spans: Vec<SpanView>,
}

/// One subscription of the producer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionView {
    /// The membership's id, as text.
    pub membership: String,
    pub task: String,
    pub required: bool,
    /// `active`, `paused` or `stopped`, with its reason when it has one.
    pub state: String,
    pub reason: Option<String>,
    /// Each run's acknowledgement.
    pub acked: Vec<RunAck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunAck {
    pub run: String,
    pub acked: u64,
}

/// One run whose prefix went.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GapEntry {
    pub role: String,
    pub producer: String,
    pub run: String,
    pub low_watermark: u64,
}

/// One run's anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorView {
    pub role: String,
    pub producer: String,
    pub run: String,
    pub through: u64,
    pub low_watermark: u64,
    pub terminal_head: String,
    /// How many deleted batches it covers.
    pub covering: u64,
    /// The anchor's deterministic CBOR, base64url.
    pub anchor: String,
}

/// `GET /host/v1/streams`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamList {
    pub streams: Vec<StreamView>,
}

/// `GET …/signers`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerList {
    pub runs: Vec<RunSigners>,
}

/// `GET …/subscriptions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionList {
    pub subscriptions: Vec<SubscriptionView>,
}

/// `GET …/gaps`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GapList {
    pub gaps: Vec<GapEntry>,
}

/// `GET …/anchors`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorList {
    pub anchors: Vec<AnchorView>,
}

/// The reads the Host's stream engine answers.
pub trait StreamReads: Send + Sync {
    fn list(&self) -> Result<Vec<StreamView>, String>;
    /// `None` when the engine serves no such stream.
    fn frontier(
        &self,
        plane: &str,
        stream_type: &str,
        resource: &str,
    ) -> Result<Option<Frontier>, String>;
    /// The producer's current run, or the consumer run `producer` and `run` name.
    #[allow(clippy::too_many_arguments)]
    fn records(
        &self,
        plane: &str,
        stream_type: &str,
        resource: &str,
        run: Option<(&[u8; 16], &[u8; 16])>,
        from: u64,
        limit: usize,
    ) -> Result<Option<RecordPage>, String>;
    fn signers(
        &self,
        plane: &str,
        stream_type: &str,
        resource: &str,
    ) -> Result<Option<Vec<RunSigners>>, String>;
    fn subscriptions(
        &self,
        plane: &str,
        stream_type: &str,
        resource: &str,
    ) -> Result<Option<Vec<SubscriptionView>>, String>;
    fn gaps(
        &self,
        plane: &str,
        stream_type: &str,
        resource: &str,
    ) -> Result<Option<Vec<GapEntry>>, String>;
    fn anchors(
        &self,
        plane: &str,
        stream_type: &str,
        resource: &str,
    ) -> Result<Option<Vec<AnchorView>>, String>;
}

/// The query of a stream read: its resource, and for `records` where to read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamQuery {
    pub resource: String,
    /// `records`: the producer Host of a consumer run, hex.
    #[serde(default)]
    pub producer: Option<String>,
    /// `records`: the consumer run, hex.
    #[serde(default)]
    pub run: Option<String>,
    /// `records`: the first sequence, 1 when absent.
    #[serde(default)]
    pub from: Option<u64>,
    /// `records`: 1 to 1000, 100 when absent.
    #[serde(default)]
    pub limit: Option<u32>,
    /// A parameter the transport could not read, refused once the resource is admitted.
    #[serde(skip)]
    pub malformed: Option<String>,
}

fn invalid(detail: impl Into<String>) -> Refusal {
    Refusal::new(
        ErrorClass::Validation,
        codes::common::INVALID_ARGUMENT,
        detail,
    )
}

fn unavailable(detail: impl Into<String>) -> Refusal {
    Refusal::new(
        ErrorClass::Unavailable,
        codes::stream::STORE_UNAVAILABLE,
        detail,
    )
}

/// The engine refused the read: logged here, answered without its detail, which may name
/// another resource's directory or run (after the review).
fn engine_failed(detail: String) -> Refusal {
    tracing::warn!(
        event.name = "host.stream.read_failed",
        component = "host",
        error = %detail,
        "the stream engine could not answer a read"
    );
    unavailable("the stream engine could not answer the read")
}

fn unknown(plane: &str, stream_type: &str) -> Refusal {
    Refusal::new(
        ErrorClass::NotFound,
        codes::stream::STREAM_UNKNOWN,
        format!("this Host serves no stream `{plane}/{stream_type}`"),
    )
}

fn hex16(name: &str, text: &str) -> Result<[u8; 16], Refusal> {
    let bytes: Option<Vec<u8>> = (text.len() == 32)
        .then(|| {
            (0..32)
                .step_by(2)
                .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
                .collect::<Option<Vec<u8>>>()
        })
        .flatten();
    bytes
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| invalid(format!("`{name}` is 32 hexadecimal characters")))
}

impl HostApi {
    /// The engine's reads, or the refusal a process without them answers.
    fn stream_reads(&self) -> Result<&dyn StreamReads, Refusal> {
        self.streams
            .as_deref()
            .ok_or_else(|| unavailable("no stream engine is open on this process"))
    }

    /// The resource of a stream read, `streams.read` admitted on it first, then what the
    /// transport could not read refused.
    fn stream_resource(
        &self,
        actor: &Actor,
        query: &StreamQuery,
    ) -> Result<(String, super::Admitted<'_>), Refusal> {
        let resource = Resource::parse(&query.resource)
            .map_err(|error| invalid(format!("`resource`: {error}")))?;
        let admitted = self.admit_on(actor, operations::STREAMS_READ, &resource)?;
        if let Some(malformed) = &query.malformed {
            return Err(invalid(malformed.clone()));
        }
        Ok((resource.to_string(), admitted))
    }

    /// `GET /host/v1/streams`: under `streams.read` on `host`.
    pub fn streams_list(&self, actor: &Actor) -> Result<StreamList, Refusal> {
        let _admitted = self.admit(actor, operations::STREAMS_READ)?;
        Ok(StreamList {
            streams: self.stream_reads()?.list().map_err(engine_failed)?,
        })
    }

    /// `GET /host/v1/streams/{plane}/{type}/frontier`.
    pub fn stream_frontier(
        &self,
        actor: &Actor,
        plane: &str,
        stream_type: &str,
        query: &StreamQuery,
    ) -> Result<Frontier, Refusal> {
        let (resource, _admitted) = self.stream_resource(actor, query)?;
        self.stream_reads()?
            .frontier(plane, stream_type, &resource)
            .map_err(engine_failed)?
            .ok_or_else(|| unknown(plane, stream_type))
    }

    /// `GET /host/v1/streams/{plane}/{type}/records`: one page, the gap with its anchor when the
    /// page starts below what the run holds.
    pub fn stream_records(
        &self,
        actor: &Actor,
        plane: &str,
        stream_type: &str,
        query: &StreamQuery,
    ) -> Result<RecordPage, Refusal> {
        let (resource, _admitted) = self.stream_resource(actor, query)?;
        let run = match (&query.producer, &query.run) {
            (Some(producer), Some(run)) => Some((hex16("producer", producer)?, hex16("run", run)?)),
            (None, None) => None,
            _ => {
                return Err(invalid(
                    "a consumer run is named by both `producer` and `run`",
                ));
            }
        };
        let limit = query.limit.unwrap_or(DEFAULT_RECORDS);
        if limit == 0 || limit > MAX_RECORDS {
            return Err(invalid(format!("`limit` is 1 to {MAX_RECORDS}")));
        }
        let from = query.from.unwrap_or(1);
        if from == 0 {
            return Err(invalid("`from` is a sequence, 1 or later"));
        }
        self.stream_reads()?
            .records(
                plane,
                stream_type,
                &resource,
                run.as_ref().map(|(producer, run)| (producer, run)),
                from,
                limit as usize,
            )
            .map_err(engine_failed)?
            .ok_or_else(|| unknown(plane, stream_type))
    }

    /// `GET /host/v1/streams/{plane}/{type}/signers`.
    pub fn stream_signers(
        &self,
        actor: &Actor,
        plane: &str,
        stream_type: &str,
        query: &StreamQuery,
    ) -> Result<SignerList, Refusal> {
        let (resource, _admitted) = self.stream_resource(actor, query)?;
        Ok(SignerList {
            runs: self
                .stream_reads()?
                .signers(plane, stream_type, &resource)
                .map_err(engine_failed)?
                .ok_or_else(|| unknown(plane, stream_type))?,
        })
    }

    /// `GET /host/v1/streams/{plane}/{type}/subscriptions`.
    pub fn stream_subscriptions(
        &self,
        actor: &Actor,
        plane: &str,
        stream_type: &str,
        query: &StreamQuery,
    ) -> Result<SubscriptionList, Refusal> {
        let (resource, _admitted) = self.stream_resource(actor, query)?;
        Ok(SubscriptionList {
            subscriptions: self
                .stream_reads()?
                .subscriptions(plane, stream_type, &resource)
                .map_err(engine_failed)?
                .ok_or_else(|| unknown(plane, stream_type))?,
        })
    }

    /// `GET /host/v1/streams/{plane}/{type}/gaps`.
    pub fn stream_gaps(
        &self,
        actor: &Actor,
        plane: &str,
        stream_type: &str,
        query: &StreamQuery,
    ) -> Result<GapList, Refusal> {
        let (resource, _admitted) = self.stream_resource(actor, query)?;
        Ok(GapList {
            gaps: self
                .stream_reads()?
                .gaps(plane, stream_type, &resource)
                .map_err(engine_failed)?
                .ok_or_else(|| unknown(plane, stream_type))?,
        })
    }

    /// `GET /host/v1/streams/{plane}/{type}/anchors`.
    pub fn stream_anchors(
        &self,
        actor: &Actor,
        plane: &str,
        stream_type: &str,
        query: &StreamQuery,
    ) -> Result<AnchorList, Refusal> {
        let (resource, _admitted) = self.stream_resource(actor, query)?;
        Ok(AnchorList {
            anchors: self
                .stream_reads()?
                .anchors(plane, stream_type, &resource)
                .map_err(engine_failed)?
                .ok_or_else(|| unknown(plane, stream_type))?,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::{Arc, Mutex};

    use super::super::testing::{actor, admin, facade};
    use super::*;

    /// An engine serving `data/decisions` alone, remembering the run and range each read asks.
    #[derive(Default)]
    struct Asked(Mutex<Vec<AskedRead>>);

    /// The run, first sequence and limit one records read asked.
    type AskedRead = (Option<([u8; 16], [u8; 16])>, u64, usize);

    impl StreamReads for Asked {
        fn list(&self) -> Result<Vec<StreamView>, String> {
            Ok(Vec::new())
        }
        fn frontier(
            &self,
            plane: &str,
            stream_type: &str,
            resource: &str,
        ) -> Result<Option<Frontier>, String> {
            Ok(
                ((plane, stream_type) == ("data", "decisions")).then(|| Frontier {
                    resource: resource.to_owned(),
                    ..Frontier::default()
                }),
            )
        }
        fn records(
            &self,
            plane: &str,
            stream_type: &str,
            resource: &str,
            run: Option<(&[u8; 16], &[u8; 16])>,
            from: u64,
            limit: usize,
        ) -> Result<Option<RecordPage>, String> {
            self.0.lock().expect("held").push((
                run.map(|(producer, run)| (*producer, *run)),
                from,
                limit,
            ));
            Ok(
                ((plane, stream_type) == ("data", "decisions")).then(|| RecordPage {
                    resource: resource.to_owned(),
                    run: String::new(),
                    records: Vec::new(),
                    next: None,
                    gap: None,
                }),
            )
        }
        fn signers(&self, _: &str, _: &str, _: &str) -> Result<Option<Vec<RunSigners>>, String> {
            Err("the engine failed".to_owned())
        }
        fn subscriptions(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<Option<Vec<SubscriptionView>>, String> {
            Ok(None)
        }
        fn gaps(&self, _: &str, _: &str, _: &str) -> Result<Option<Vec<GapEntry>>, String> {
            Ok(Some(Vec::new()))
        }
        fn anchors(&self, _: &str, _: &str, _: &str) -> Result<Option<Vec<AnchorView>>, String> {
            Ok(Some(Vec::new()))
        }
    }

    /// The code of a domain refusal.
    fn code(refusal: Refusal) -> String {
        match refusal {
            Refusal::Api(error) => error.code().to_owned(),
            other => panic!("not a domain refusal: {other:?}"),
        }
    }

    const READER: &str = "spiffe://acme/operators/streams";

    /// `api` with a reader allowed `streams.read` on `plane/data` and below.
    async fn with_reader(api: HostApi) -> HostApi {
        api.create_grant(
            &admin(),
            super::super::CreateGrant {
                request_id: "reader".to_owned(),
                expected_revision: None,
                principal: READER.to_owned(),
                operations: vec![operations::STREAMS_READ.to_owned()],
                selector: permguard_core::authz::Selector::under(
                    Resource::parse("plane/data").expect("a resource"),
                )
                .to_string(),
                resource_types: vec!["*".to_owned()],
                constraints: Default::default(),
                expires_at: None,
            },
        )
        .await
        .expect("the reader is issued");
        api
    }

    fn reader() -> Actor {
        actor(READER)
    }

    fn query(resource: &str) -> StreamQuery {
        StreamQuery {
            resource: resource.to_owned(),
            ..StreamQuery::default()
        }
    }

    /// WP-5.7a: the reads take `streams.read`, authorized on the resource before anything else
    /// the query names; without an engine they are `store_unavailable`; a stream the engine does
    /// not serve is `stream_unknown`.
    #[tokio::test]
    async fn the_stream_reads_authorize_first_and_say_what_they_lack() {
        let ledger = "plane/data/zone/z/ledger/l";
        let bare = with_reader(facade("streams-bare")).await;
        let refused = bare
            .stream_frontier(&reader(), "data", "decisions", &query(ledger))
            .expect_err("no engine");
        assert_eq!(code(refused), codes::stream::STORE_UNAVAILABLE);

        let api = with_reader(facade("streams-read"))
            .await
            .with_streams(Arc::new(Asked::default()));
        assert!(
            api.streams_list(&admin())
                .expect("listed")
                .streams
                .is_empty()
        );
        let malformed = StreamQuery {
            malformed: Some("`from` is a number".to_owned()),
            ..query(ledger)
        };
        let stranger = api
            .stream_frontier(&actor("stranger"), "data", "decisions", &malformed)
            .expect_err("no grant");
        assert!(
            matches!(&stranger, Refusal::Denied(denial) if denial.http_status() == 403),
            "authorized before it is read"
        );
        assert_eq!(
            code(
                api.stream_frontier(&reader(), "data", "decisions", &malformed)
                    .expect_err("malformed")
            ),
            codes::common::INVALID_ARGUMENT
        );
        // The list takes `streams.read` on `host`: the public `keys.read` there is not it.
        let stranger_list = api.streams_list(&actor("stranger")).expect_err("no grant");
        assert!(matches!(&stranger_list, Refusal::Denied(denial) if denial.http_status() == 403));
        // An unknown stream is answered only to a caller with the grant: a stranger cannot tell
        // which streams exist.
        let stranger_unknown = api
            .stream_frontier(&actor("stranger"), "data", "nothing", &query(ledger))
            .expect_err("no grant");
        assert!(
            matches!(&stranger_unknown, Refusal::Denied(denial) if denial.http_status() == 403)
        );
        assert_eq!(
            code(
                api.stream_frontier(&reader(), "data", "nothing", &query(ledger))
                    .expect_err("unknown")
            ),
            codes::stream::STREAM_UNKNOWN
        );
        assert_eq!(
            code(
                api.stream_subscriptions(&reader(), "data", "nothing", &query(ledger))
                    .expect_err("unknown")
            ),
            codes::stream::STREAM_UNKNOWN
        );
        assert_eq!(
            code(
                api.stream_signers(&reader(), "data", "decisions", &query(ledger))
                    .expect_err("the engine failed")
            ),
            codes::stream::STORE_UNAVAILABLE
        );
        assert_eq!(
            code(
                api.stream_frontier(&reader(), "data", "decisions", &query("zone:x"))
                    .expect_err("out of the grammar")
            ),
            codes::common::INVALID_ARGUMENT
        );
    }

    /// WP-5.7a: a records read names a consumer run by both its producer and run, in hex, or
    /// neither; `from` is 1 or later, `limit` 1 to 1000, and what reaches the engine is what was
    /// asked.
    #[tokio::test]
    async fn a_records_read_is_bounded_and_names_a_whole_run() {
        let ledger = "plane/data/zone/z/ledger/l";
        let asked = Arc::new(Asked::default());
        let api = with_reader(facade("streams-records"))
            .await
            .with_streams(Arc::clone(&asked) as Arc<dyn StreamReads>);
        let producer = "00".repeat(16);
        let run = "ff".repeat(16);
        for refused in [
            StreamQuery {
                producer: Some(producer.clone()),
                ..query(ledger)
            },
            StreamQuery {
                run: Some(run.clone()),
                ..query(ledger)
            },
            StreamQuery {
                producer: Some("not hex".to_owned()),
                run: Some(run.clone()),
                ..query(ledger)
            },
            StreamQuery {
                from: Some(0),
                ..query(ledger)
            },
            StreamQuery {
                limit: Some(0),
                ..query(ledger)
            },
            StreamQuery {
                limit: Some(MAX_RECORDS + 1),
                ..query(ledger)
            },
        ] {
            assert_eq!(
                code(
                    api.stream_records(&reader(), "data", "decisions", &refused)
                        .expect_err("refused")
                ),
                codes::common::INVALID_ARGUMENT,
                "{refused:?}"
            );
        }
        assert!(
            asked.0.lock().expect("held").is_empty(),
            "nothing refused reached the engine"
        );
        api.stream_records(&reader(), "data", "decisions", &query(ledger))
            .expect("the producer's run");
        api.stream_records(
            &reader(),
            "data",
            "decisions",
            &StreamQuery {
                producer: Some(producer),
                run: Some(run),
                from: Some(7),
                limit: Some(MAX_RECORDS),
                ..query(ledger)
            },
        )
        .expect("a consumer run");
        assert_eq!(
            *asked.0.lock().expect("held"),
            vec![
                (None, 1, DEFAULT_RECORDS as usize),
                (Some(([0; 16], [0xff; 16])), 7, MAX_RECORDS as usize)
            ]
        );
    }
}
