// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The same request, over both transports, with the same answer.
//!
//! P8 makes REST and gRPC adapters over one service object, so a request may differ by transport
//! only in framing. This runner checks that on real sockets: [`serve`] binds a plane's HTTP router
//! and its gRPC routes on two ephemeral ports, a test drives the same operation through the
//! production client once per URL, and [`assert_parity`] requires the two [`Outcome`]s to be equal:
//! the same canonical value when the plane answered, the same `{class, code}` when it refused.
//!
//! The production client is the instrument on purpose. It is the code that turns a REST error body
//! and gRPC status metadata into one `Failure`, so a field lost between server and client on one
//! transport shows up here as a difference rather than in a deployment.
//!
//! ```no_run
//! # use permguard_conformance::parity::{assert_parity, outcome, serve};
//! # fn routes() -> (axum::Router, tonic::service::Routes) { unimplemented!() }
//! # fn ask(url: &str) -> Result<serde_json::Value, permguard_control_client::catalog::Failure> { unimplemented!() }
//! let (http, grpc) = routes();
//! let served = serve(http, grpc);
//! assert_parity("get an unknown zone", outcome(ask(&served.http)), outcome(ask(&served.grpc)));
//! ```

use std::net::SocketAddr;

use permguard_control_client::catalog::Failure;
use permguard_core::ErrorClass;
use serde::Serialize;
use serde_json::Value;

/// What one transport answered, reduced to what must not differ between transports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The plane answered; the value as canonical JSON.
    Answered(Value),
    /// The plane refused, with its class and stable code.
    Refused { class: String, code: String },
}

impl Outcome {
    /// The value with each named member's value replaced by `"<minted>"` at every depth:
    /// identifiers and timestamps a mutation mints, which two separate calls cannot share.
    ///
    /// Replaced rather than removed, so a member that one transport omits still makes the two
    /// outcomes differ.
    #[must_use]
    pub fn masked(self, members: &[&str]) -> Self {
        match self {
            Self::Answered(value) => Self::Answered(mask(value, members)),
            refused => refused,
        }
    }
}

fn mask(value: Value, members: &[&str]) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(name, value)| {
                    if members.contains(&name.as_str()) {
                        (name, Value::String("<minted>".to_owned()))
                    } else {
                        (name, mask(value, members))
                    }
                })
                .collect(),
        ),
        Value::Array(items) => {
            Value::Array(items.into_iter().map(|item| mask(item, members)).collect())
        }
        other => other,
    }
}

/// The outcome of one client call.
///
/// A refusal must name one of the five error classes: a class the taxonomy does not know is a
/// contract violation on that transport, and it fails here rather than comparing equal to itself.
pub fn outcome<T: Serialize>(result: Result<T, Failure>) -> Outcome {
    match result {
        Ok(answer) => Outcome::Answered(
            serde_json::to_value(answer).expect("a client answer serializes as JSON"),
        ),
        Err(failure) => {
            assert!(
                ErrorClass::ALL
                    .iter()
                    .any(|class| class.as_str() == failure.class),
                "`{}` is not an error class of the taxonomy (code `{}`: {})",
                failure.class,
                failure.reason,
                failure.detail
            );
            Outcome::Refused {
                class: failure.class,
                code: failure.reason,
            }
        }
    }
}

/// The HTTP status and the gRPC code the central mapping gives a refusal of `class` and `code`.
///
/// Equal outcomes are not enough on their own: a client reads the class from the body or the
/// metadata, so a transport answering `500` with a `validation` body would still compare equal. A
/// suite that can see the raw answers checks them against this.
pub fn expected_statuses(class: &str, code: &str) -> (u16, i32) {
    let class: ErrorClass = class
        .parse()
        .unwrap_or_else(|error| panic!("a refusal names its class: {error}"));
    // The mapping takes the static codes of the registry; a test leaks the few it compares.
    let code: &'static str = Box::leak(code.to_owned().into_boxed_str());
    let refusal = permguard_core::ApiError::new(class, code, "");

    (refusal.http_status(), refusal.grpc_code().number())
}

/// Fails the test, naming the case, unless the raw statuses are the ones `{class, code}` maps to.
#[track_caller]
pub fn assert_statuses(case: &str, class: &str, code: &str, http_status: u16, grpc_code: i32) {
    let (http, grpc) = expected_statuses(class, code);
    assert_eq!(
        (http_status, grpc_code),
        (http, grpc),
        "`{case}`: `{class}/{code}` must answer HTTP {http} and gRPC {grpc}"
    );
}

/// Fails the test, naming the case, unless both transports gave the same outcome.
#[track_caller]
pub fn assert_parity(case: &str, http: Outcome, grpc: Outcome) {
    assert_eq!(
        http, grpc,
        "`{case}`: REST answered {http:?} and gRPC answered {grpc:?}"
    );
}

/// A plane served on both transports.
pub struct Served {
    /// The REST base URL, `http://127.0.0.1:<port>`.
    pub http: String,
    /// The gRPC URL, `grpc://127.0.0.1:<port>`.
    pub grpc: String,
}

/// Serves `http` and `grpc` on two ephemeral loopback ports, for the life of the test process.
///
/// The servers run on their own thread and runtime, so a test drives them with the blocking
/// production client from its own thread, exactly as the command line does.
pub fn serve(http: axum::Router, grpc: tonic::service::Routes) -> Served {
    let http_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port is free");
    let grpc_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port is free");
    let http_address = address(&http_listener);
    let grpc_address = address(&grpc_listener);
    for listener in [&http_listener, &grpc_listener] {
        listener
            .set_nonblocking(true)
            .expect("the listener goes non-blocking for tokio");
    }

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the server runtime starts");
        runtime.block_on(async move {
            let http_listener =
                tokio::net::TcpListener::from_std(http_listener).expect("tokio adopts it");
            let grpc_listener =
                tokio::net::TcpListener::from_std(grpc_listener).expect("tokio adopts it");
            let http = axum::serve(http_listener, http);
            let grpc = tonic::transport::Server::builder()
                .add_routes(grpc)
                .serve_with_incoming(tonic::transport::server::TcpIncoming::from(grpc_listener));
            let _ = tokio::join!(http, grpc);
        });
    });

    Served {
        http: format!("http://{http_address}"),
        grpc: format!("grpc://{grpc_address}"),
    }
}

fn address(listener: &std::net::TcpListener) -> SocketAddr {
    listener.local_addr().expect("the address is known")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn refused(class: &str, code: &str) -> Result<Value, Failure> {
        Err(Failure {
            class: class.to_owned(),
            reason: code.to_owned(),
            detail: "refused".to_owned(),
            usage: true,
        })
    }

    #[test]
    fn test_equal_outcomes_pass_and_the_message_is_not_part_of_the_contract() {
        assert_parity(
            "answered",
            outcome(Ok(json!({"a": 1, "b": [2]}))),
            outcome(Ok(json!({"b": [2], "a": 1}))),
        );
        let mut other_message = refused("validation", "invalid_name");
        if let Err(failure) = &mut other_message {
            failure.detail = "a different sentence".to_owned();
        }
        assert_parity(
            "refused",
            outcome(refused("validation", "invalid_name")),
            outcome(other_message),
        );
    }

    #[test]
    #[should_panic(expected = "REST answered")]
    fn test_a_different_code_fails() {
        assert_parity(
            "codes differ",
            outcome(refused("validation", "invalid_name")),
            outcome(refused("validation", "payload_malformed")),
        );
    }

    #[test]
    #[should_panic(expected = "REST answered")]
    fn test_a_different_class_fails() {
        assert_parity(
            "classes differ",
            outcome(refused("not_found", "zone_not_found")),
            outcome(refused("validation", "zone_not_found")),
        );
    }

    #[test]
    #[should_panic(expected = "REST answered")]
    fn test_an_answer_against_a_refusal_fails() {
        assert_parity(
            "one answered",
            outcome(Ok(json!({}))),
            outcome(refused("internal", "internal")),
        );
    }

    #[test]
    #[should_panic(expected = "not an error class")]
    fn test_a_class_outside_the_taxonomy_fails() {
        let _ = outcome(refused("unavailable-ish", "x"));
    }

    #[test]
    fn test_masking_replaces_minted_values_at_every_depth_and_keeps_an_omission_visible() {
        let minted = Outcome::Answered(json!({"id": 1, "name": "a", "inner": [{"id": 2, "x": 3}]}));
        assert_eq!(
            minted.masked(&["id"]),
            Outcome::Answered(
                json!({"id": "<minted>", "name": "a", "inner": [{"id": "<minted>", "x": 3}]})
            )
        );
        let omitted = Outcome::Answered(json!({"name": "a"}));
        assert_ne!(
            Outcome::Answered(json!({"id": 1, "name": "a"})).masked(&["id"]),
            omitted.masked(&["id"]),
            "a member one transport omits is still a difference"
        );
    }

    #[test]
    fn test_the_expected_statuses_follow_the_central_mapping() {
        assert_eq!(expected_statuses("validation", "invalid_name"), (400, 3));
        assert_eq!(expected_statuses("conflict", "name_taken"), (409, 6));
        assert_eq!(expected_statuses("conflict", "zone_not_empty"), (409, 9));
        assert_eq!(expected_statuses("not_found", "zone_not_found"), (404, 5));
        assert_statuses("ok", "internal", "internal", 500, 13);
    }

    #[test]
    #[should_panic(expected = "must answer HTTP 400")]
    fn test_a_status_that_does_not_follow_the_class_fails() {
        assert_statuses("500 for validation", "validation", "invalid_name", 500, 3);
    }
}
