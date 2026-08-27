// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Asking a data plane for a decision: the client half of
//! `permguard.pdp.v1`.
//!
//! # Why it lives here
//!
//! This crate is where a client's *transport* decisions live — which scheme
//! means which protocol, what TLS material is presented, how a refusal
//! becomes a value a caller can act on. The catalog and NOTP already ride on
//! that; a decision request is one more question asked of a Permguard
//! deployment, and duplicating the endpoint/TLS/error plumbing in the CLI to
//! keep the crate's name literal would be the wrong trade.
//!
//! # One payload, two transports
//!
//! The payload is the profile's JSON, verbatim: it is what a caller wrote and
//! what the server documents, so the CLI never re-shapes a request behind an
//! operator's back. Over `http`/`https` it is the body of a `POST`; over
//! `grpc`/`grpcs` it is mapped onto the generated request and back, so the
//! answer is the same JSON either way and `-o json` prints what the server
//! decided rather than what this client made of it.

use serde_json::{Map, Value};

use crate::catalog::Failure;
use crate::endpoint::Endpoint;
use crate::http::Client;
use crate::tls::TlsOptions;

/// How long one decision may take. A PDP that has not answered in five
/// seconds is not going to.
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// A data plane, as a caller asking for decisions sees it.
pub trait Pdp {
    /// Asks for a decision. The payload is the profile's own JSON; the answer
    /// is the server's, unchanged.
    fn evaluate(&self, payload: &Value) -> Result<Value, Failure>;

    /// What `permguard.pdp.v1` offers at this endpoint.
    fn configuration(&self) -> Result<Value, Failure>;
}

/// The client for an endpoint, chosen by its scheme.
///
/// `narrator` is told about each exchange — the CLI's `-v`, a server's
/// tracing — and [`crate::narrate::Silent`] for a caller that does not care.
pub fn client(
    url: &str,
    tls: &TlsOptions,
    narrator: Box<dyn crate::narrate::Narrator>,
) -> Result<Box<dyn Pdp>, String> {
    if url.starts_with("grpc://") || url.starts_with("grpcs://") {
        return Ok(Box::new(crate::grpc::GrpcPdp::connect(url, tls, narrator)?));
    }
    let endpoint = Endpoint::parse(url).map_err(|error| error.to_string())?;

    Ok(Box::new(HttpPdp::new(endpoint, tls.clone(), narrator)?))
}

/// The HTTP surface: a `POST` of the payload, and the answer as it came.
struct HttpPdp {
    endpoint: Endpoint,
    client: Client,
}

impl HttpPdp {
    fn new(
        endpoint: Endpoint,
        tls: TlsOptions,
        narrator: Box<dyn crate::narrate::Narrator>,
    ) -> Result<Self, String> {
        let client = Client::new(TIMEOUT, tls, endpoint.is_tls())
            .map_err(|error| error.to_string())?
            .with_narrator(narrator);

        Ok(Self { endpoint, client })
    }

    fn call(&self, method: &str, path: &str, body: Option<&str>) -> Result<Value, Failure> {
        let response = self
            .client
            .request(&self.endpoint, method, path, body)
            .map_err(|error| Failure {
                class: "unavailable".to_owned(),
                reason: error.reason().to_owned(),
                detail: error.to_string(),
                usage: false,
            })?;
        let parsed: Value = serde_json::from_str(&response.body).map_err(|error| Failure {
            class: "internal".to_owned(),
            reason: "decode_failed".to_owned(),
            detail: format!("the answer to {method} {path} was unreadable: {error}"),
            usage: false,
        })?;

        if (200..300).contains(&response.status) {
            return Ok(parsed);
        }

        // A refusal, in the shape every Permguard API shares. A deny is not
        // one of these: it arrives as a 200 with `decision: false`.
        Err(refusal(&parsed, response.status))
    }
}

impl Pdp for HttpPdp {
    fn evaluate(&self, payload: &Value) -> Result<Value, Failure> {
        // The boxcarred path when the caller boxcarred, the single one
        // otherwise: the same server handler answers both, and using the
        // documented address for each is what makes a capture readable.
        let path = if payload
            .get("evaluations")
            .and_then(Value::as_array)
            .is_some_and(|evaluations| !evaluations.is_empty())
        {
            permguard_languages::request::EVALUATIONS_PATH
        } else {
            permguard_languages::request::EVALUATION_PATH
        };

        self.call("POST", path, Some(&payload.to_string()))
    }

    fn configuration(&self) -> Result<Value, Failure> {
        // The interface's own constant, so the client cannot ask for a path the plane does not
        // mount — and cannot keep asking for one it used to.
        self.call(
            "GET",
            permguard_languages::request::CONFIGURATION_PATH,
            None,
        )
    }
}

/// Turns a server's refusal body into a value a caller can branch on.
fn refusal(parsed: &Value, status: u16) -> Failure {
    let field = |name: &str| {
        parsed
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let message = field("message");

    Failure {
        class: match field("class").as_str() {
            "" => "unavailable".to_owned(),
            class => class.to_owned(),
        },
        reason: match field("code").as_str() {
            "" => format!("http_{status}"),
            code => code.to_owned(),
        },
        detail: if message.is_empty() {
            format!("the endpoint refused the request with status {status}")
        } else {
            message
        },
        // A payload the server would not read is the caller's to fix.
        usage: (400..500).contains(&status),
    }
}

// The JSON→proto conversions used to live here, and answered a payload they could not represent
// by dropping the part they could not — a `context` that was not an object became no context, a
// number past 2^53 became a different number. They are gone rather than deprecated: the gRPC
// binding builds its request in `grpc.rs`, where every one of those is a refusal, and a lossy
// helper left in reach is a lossy helper somebody reaches for.

/// A decision request built from parts, for callers that have the parts
/// rather than a document — the CLI's `check` with flags, a test, an SDK.
pub fn payload(
    zone: &str,
    ledger: &str,
    subject: (&str, &str),
    action: &str,
    resource: (&str, &str),
    context: Map<String, Value>,
) -> Value {
    serde_json::json!({
        "zone": zone,
        "ledger": ledger,
        "subject": {"type": subject.0, "id": subject.1},
        "action": {"name": action},
        "resource": {"type": resource.0, "id": resource.1},
        "context": Value::Object(context),
    })
}
