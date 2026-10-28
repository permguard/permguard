// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The load: closed-loop clients, each on its own thread with its own connection, sending the
//! workload's requests in turn and timing every answer.
//!
//! A client is what a PEP is: HTTP/1.1 with keep-alive, or the release's own gRPC client over one
//! HTTP/2 channel. Each client's first request is sent before the step's clock starts, so a step
//! measures answering, not connecting.

use std::collections::BTreeMap;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use serde_json::Value;

use super::report::{Step, percentiles};

/// The interfaces a run drives.
pub const INTERFACES: [&str; 2] = ["http", "grpc"];

/// The codes a plane answers when it is at a bound: the only answers counted as refusals. Anything
/// else — a refused connection, a reset, a per-principal `429`, an untyped status — is an error,
/// so a broken client or network can never pass for a plane saying no. The generic `unavailable`
/// is not among them: the gRPC client also names a transport failure so.
pub const OVERLOAD_CODES: [&str; 3] = [
    permguard_core::codes::pdp_native::EVALUATION_AT_CAPACITY,
    permguard_core::codes::pdp_native::LOAD_AT_CAPACITY,
    permguard_core::codes::pdp_native::DECISION_UNRECORDABLE,
];

/// How long a client waits for one answer: the release's gRPC client's own bound, applied to both
/// interfaces so they measure the same thing near the refusal point.
pub const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);

/// The code the gate files the transport's shed under: the generic `unavailable` with the
/// shed's own message, which a transport failure named with the same code never carries.
pub const SHED: &str = "unavailable (request bound)";

/// An answer the plane typed as an overload refusal, or what else it was.
fn refusal_or_error(code: Option<String>, message: &str, otherwise: String) -> Outcome {
    match code {
        Some(code) if OVERLOAD_CODES.contains(&code.as_str()) => Outcome::Refused(code),
        Some(code)
            if code == permguard_core::codes::common::UNAVAILABLE
                && message == permguard_core::limits::OVERLOADED =>
        {
            Outcome::Refused(SHED.to_owned())
        }
        _ => Outcome::Failed(otherwise),
    }
}

/// One request of a workload, ready to send.
#[derive(Debug, Clone)]
pub struct Request {
    pub payload: Value,
    pub decision: bool,
}

/// What one exchange came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The expected decision.
    Answered,
    /// A typed overload refusal, with its code.
    Refused(String),
    /// Anything else, with what it was.
    Failed(String),
}

/// A client of one interface.
enum Client {
    Http(HttpClient),
    Grpc(Box<dyn permguard_control_client::pdp::Pdp>),
}

impl Client {
    fn new(interface: &str, http: &str, grpc: &str) -> Result<Self, String> {
        match interface {
            "http" => Ok(Self::Http(HttpClient::new(http)?)),
            "grpc" => Ok(Self::Grpc(permguard_control_client::pdp::client(
                grpc,
                &permguard_control_client::tls::TlsOptions::default(),
                Box::new(permguard_control_client::narrate::Silent),
            )?)),
            other => Err(format!("no interface `{other}`")),
        }
    }

    fn send(&mut self, request: &Request) -> Outcome {
        match self {
            Self::Http(client) => match client.post(
                // The batch's own path for a batch, as the release's client does.
                if request.payload.get("evaluations").is_some() {
                    permguard_languages::request::EVALUATIONS_PATH
                } else {
                    permguard_languages::request::EVALUATION_PATH
                },
                Bytes::from(request.payload.to_string()),
            ) {
                Ok((200, body)) => judge(&body, request.decision),
                // `503` is the plane's "come back"; the code in the body says which bound refused.
                // Without one it is not a typed refusal, and the gate says so.
                Ok((503, body)) => {
                    let body = serde_json::from_slice::<Value>(&body).unwrap_or_default();
                    refusal_or_error(
                        body["code"].as_str().map(str::to_owned),
                        body["message"].as_str().unwrap_or_default(),
                        "untyped_503".to_owned(),
                    )
                }
                Ok((status, _)) => Outcome::Failed(format!("status_{status}")),
                Err(error) => Outcome::Failed(error),
            },
            Self::Grpc(client) => match client.evaluate(&request.payload) {
                Ok(answer) if answer["decision"].as_bool() == Some(request.decision) => {
                    Outcome::Answered
                }
                Ok(_) => Outcome::Failed("wrong_decision".to_owned()),
                Err(failure) => {
                    let kind = format!("{}:{}", failure.class, failure.reason);
                    refusal_or_error(Some(failure.reason), &failure.detail, kind)
                }
            },
        }
    }
}

/// An answered body against the expected decision.
fn judge(body: &[u8], expected: bool) -> Outcome {
    match serde_json::from_slice::<Value>(body) {
        Ok(answer) if answer["decision"].as_bool() == Some(expected) => Outcome::Answered,
        Ok(_) => Outcome::Failed("wrong_decision".to_owned()),
        Err(_) => Outcome::Failed("unreadable_answer".to_owned()),
    }
}

/// HTTP/1.1 with keep-alive, on a runtime of its own thread.
struct HttpClient {
    runtime: tokio::runtime::Runtime,
    authority: String,
    sender: Option<hyper::client::conn::http1::SendRequest<Full<Bytes>>>,
}

impl HttpClient {
    fn new(url: &str) -> Result<Self, String> {
        let authority = url
            .strip_prefix("http://")
            .ok_or("the benchmark's HTTP client speaks plain HTTP on loopback only")?
            .trim_end_matches('/')
            .to_owned();
        Ok(Self {
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?,
            authority,
            sender: None,
        })
    }

    fn post(&mut self, path: &str, body: Bytes) -> Result<(u16, Bytes), String> {
        let authority = self.authority.clone();
        let sender = self.sender.take();
        let (result, sender) = self.runtime.block_on(async move {
            let mut sender = match sender {
                Some(sender) if !sender.is_closed() => sender,
                _ => match connect(&authority).await {
                    Ok(sender) => sender,
                    Err(error) => return (Err(error), None),
                },
            };
            let request = match http::Request::post(path)
                .header(http::header::HOST, authority.as_str())
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Full::new(body))
            {
                Ok(request) => request,
                Err(error) => return (Err(error.to_string()), None),
            };
            let exchange = async {
                let response = sender
                    .send_request(request)
                    .await
                    .map_err(|error| format!("connection: {error}"))?;
                let status = response.status().as_u16();
                let body = response
                    .into_body()
                    .collect()
                    .await
                    .map_err(|error| format!("body: {error}"))?;
                Ok::<_, String>((status, body.to_bytes()))
            };
            match tokio::time::timeout(CLIENT_TIMEOUT, exchange).await {
                Ok(Ok(answer)) => (Ok(answer), Some(sender)),
                Ok(Err(error)) => (Err(error), None),
                // The connection is in an unknown state: the next request opens another.
                Err(_) => (Err("client_timeout".to_owned()), None),
            }
        });
        self.sender = sender;
        result
    }
}

async fn connect(
    authority: &str,
) -> Result<hyper::client::conn::http1::SendRequest<Full<Bytes>>, String> {
    let stream = tokio::net::TcpStream::connect(authority)
        .await
        .map_err(|error| format!("connect: {error}"))?;
    let _ = stream.set_nodelay(true);
    let (sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .map_err(|error| format!("handshake: {error}"))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(sender)
}

/// Where a step sends its requests.
#[derive(Debug, Clone)]
pub struct Target {
    pub interface: String,
    pub http: String,
    pub grpc: String,
}

/// One step: `concurrency` clients for `duration`, each cycling through `requests`.
pub fn step(
    target: &Target,
    requests: &[Request],
    concurrency: usize,
    duration: Duration,
    process: Option<&super::probe::Process>,
) -> Result<Step, String> {
    let requests = Arc::new(requests.to_vec());
    // The clients connect and send one request each, then the step starts for all of them at once.
    let ready = Arc::new(Barrier::new(concurrency + 1));
    let start = Arc::new(Barrier::new(concurrency + 1));
    let deadline = Arc::new(std::sync::OnceLock::<Instant>::new());
    let mut workers = Vec::with_capacity(concurrency);
    for index in 0..concurrency {
        let (target, requests, ready, start, deadline) = (
            target.clone(),
            Arc::clone(&requests),
            Arc::clone(&ready),
            Arc::clone(&start),
            Arc::clone(&deadline),
        );
        workers.push(std::thread::spawn(move || -> Result<Tally, String> {
            let client = Client::new(&target.interface, &target.http, &target.grpc);
            let mut client = match client {
                Ok(client) => client,
                Err(error) => {
                    ready.wait();
                    start.wait();
                    return Err(error);
                }
            };
            let _ = client.send(&requests[index % requests.len()]);
            ready.wait();
            start.wait();
            let until = *deadline.get().unwrap_or(&Instant::now());
            let mut tally = Tally::default();
            let mut next = index;
            while Instant::now() < until {
                let request = &requests[next % requests.len()];
                next += 1;
                let sent = Instant::now();
                let outcome = client.send(request);
                tally.record(outcome, sent.elapsed());
            }
            Ok(tally)
        }));
    }
    ready.wait();
    let measuring = process.map(super::probe::Process::begin);
    let began = Instant::now();
    let _ = deadline.set(began + duration);
    start.wait();
    let mut total = Tally::default();
    let mut failure = None;
    for worker in workers {
        match worker.join() {
            Ok(Ok(tally)) => total.merge(tally),
            Ok(Err(error)) => failure = Some(error),
            Err(_) => failure = Some("a client thread panicked".to_owned()),
        }
    }
    let seconds = began.elapsed().as_secs_f64();
    let (cpu_seconds, peak_rss_bytes) = match (process, measuring) {
        (Some(process), Some(measuring)) => process.end(measuring),
        _ => (None, None),
    };
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(total.step(concurrency, seconds, cpu_seconds, peak_rss_bytes))
}

/// What one client saw.
#[derive(Debug, Default)]
struct Tally {
    answered: Vec<f64>,
    refused: Vec<f64>,
    errors: u64,
    refusal_codes: BTreeMap<String, u64>,
    error_kinds: BTreeMap<String, u64>,
}

impl Tally {
    fn record(&mut self, outcome: Outcome, took: Duration) {
        let ms = took.as_secs_f64() * 1000.0;
        match outcome {
            Outcome::Answered => self.answered.push(ms),
            Outcome::Refused(code) => {
                self.refused.push(ms);
                *self.refusal_codes.entry(code).or_default() += 1;
            }
            Outcome::Failed(kind) => {
                self.errors += 1;
                *self.error_kinds.entry(kind).or_default() += 1;
            }
        }
    }

    fn merge(&mut self, other: Tally) {
        self.answered.extend(other.answered);
        self.refused.extend(other.refused);
        self.errors += other.errors;
        for (code, n) in other.refusal_codes {
            *self.refusal_codes.entry(code).or_default() += n;
        }
        for (kind, n) in other.error_kinds {
            *self.error_kinds.entry(kind).or_default() += n;
        }
    }

    fn step(
        mut self,
        concurrency: usize,
        seconds: f64,
        cpu_seconds: Option<f64>,
        peak_rss_bytes: Option<u64>,
    ) -> Step {
        let ok = self.answered.len() as u64;
        Step {
            concurrency,
            seconds,
            ok,
            refused: self.refused.len() as u64,
            errors: self.errors,
            refusal_codes: self.refusal_codes,
            error_kinds: self.error_kinds,
            latency_ms: percentiles(&mut self.answered).unwrap_or(super::report::Percentiles {
                p50: 0.0,
                p95: 0.0,
                p99: 0.0,
                max: 0.0,
            }),
            refusal_latency_ms: percentiles(&mut self.refused),
            throughput_rps: if seconds > 0.0 {
                ok as f64 / seconds
            } else {
                0.0
            },
            cpu_seconds,
            peak_rss_bytes,
        }
    }
}

/// The workload's requests, addressed to the benchmark's zone and ledger.
pub fn requests(
    example: &std::path::Path,
    workload: &super::report::Workload,
) -> Result<Vec<Request>, String> {
    workload
        .requests
        .iter()
        .map(|expected| {
            let path = example.join(&expected.file);
            let mut payload: Value = serde_json::from_str(
                &std::fs::read_to_string(&path)
                    .map_err(|error| format!("{}: {error}", path.display()))?,
            )
            .map_err(|error| format!("{}: {error}", path.display()))?;
            payload["zone"] = Value::String(super::server::ZONE.to_owned());
            payload["ledger"] = Value::String(super::server::LEDGER.to_owned());
            payload["profile"] = Value::String(workload.profile.clone());
            Ok(Request {
                payload,
                decision: expected.decision,
            })
        })
        .collect()
}

/// Waits until every request of `requests` is answered as expected over `target`: the ledger is
/// mirrored, verified and loaded.
pub fn wait_serving(target: &Target, requests: &[Request], within: Duration) -> Result<(), String> {
    let deadline = Instant::now() + within;
    let mut client = Client::new(&target.interface, &target.http, &target.grpc)?;
    let mut last = Outcome::Failed("never asked".to_owned());
    while Instant::now() < deadline {
        if requests.iter().all(|request| {
            last = client.send(request);
            last == Outcome::Answered
        }) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err(format!(
        "the plane did not answer the dataset as expected within {within:?}: {last:?}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_an_answer_is_judged_against_the_expected_decision() {
        assert_eq!(judge(br#"{"decision": true}"#, true), Outcome::Answered);
        assert_eq!(
            judge(br#"{"decision": false}"#, true),
            Outcome::Failed("wrong_decision".to_owned())
        );
        assert_eq!(
            judge(b"not json", false),
            Outcome::Failed("unreadable_answer".to_owned())
        );
    }

    /// Only a code the plane answers at a bound is a refusal; a transport failure, an unknown code
    /// or an untyped status is an error.
    #[test]
    fn test_only_a_typed_overload_code_is_a_refusal() {
        assert_eq!(
            refusal_or_error(
                Some("evaluation_at_capacity".to_owned()),
                "",
                "x".to_owned()
            ),
            Outcome::Refused("evaluation_at_capacity".to_owned())
        );
        assert_eq!(
            refusal_or_error(
                Some("transport".to_owned()),
                "",
                "unavailable:transport".to_owned()
            ),
            Outcome::Failed("unavailable:transport".to_owned())
        );
        assert_eq!(
            refusal_or_error(None, "", "untyped_503".to_owned()),
            Outcome::Failed("untyped_503".to_owned())
        );
        // The generic code is the shed only with the shed's own message: a transport failure the
        // gRPC client names `unavailable` stays an error.
        assert_eq!(
            refusal_or_error(
                Some("unavailable".to_owned()),
                permguard_core::limits::OVERLOADED,
                "x".to_owned()
            ),
            Outcome::Refused(SHED.to_owned())
        );
        assert_eq!(
            refusal_or_error(
                Some("unavailable".to_owned()),
                "transport error",
                "unavailable:unavailable".to_owned()
            ),
            Outcome::Failed("unavailable:unavailable".to_owned())
        );
    }

    #[test]
    fn test_a_tally_splits_answers_refusals_and_failures() {
        let mut tally = Tally::default();
        tally.record(Outcome::Answered, Duration::from_millis(2));
        tally.record(Outcome::Answered, Duration::from_millis(4));
        tally.record(
            Outcome::Refused("evaluation_at_capacity".to_owned()),
            Duration::from_millis(1),
        );
        tally.record(
            Outcome::Failed("status_500".to_owned()),
            Duration::from_millis(9),
        );
        let step = tally.step(4, 2.0, None, None);
        assert_eq!((step.ok, step.refused, step.errors), (2, 1, 1));
        assert_eq!(step.refusal_codes["evaluation_at_capacity"], 1);
        assert_eq!(step.error_kinds["status_500"], 1);
        assert_eq!(step.throughput_rps, 1.0);
        assert_eq!(step.latency_ms.p99, 4.0);
        assert!(step.refusal_latency_ms.is_some());
    }
}
