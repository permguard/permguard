// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The HTTP transport against a server-shaped stub on a real socket.
//!
//! What is asserted is the **wire**: CBOR bodies under the NOTP media type,
//! the negotiated batch compression applied and undone, the discovery check
//! that must pass before a URL is trusted, and the refusal shape a caller
//! reads. A stub rather than the real plane on purpose — this suite is about
//! what leaves and enters the socket, not about what a server decides.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::HashMap;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpListener;
use std::sync::Arc;

use permguard_control_client::narrate::Silent;
use permguard_control_client::remote::Remote;
use permguard_control_client::remote_http::HttpRemote;
use permguard_control_client::tls::TlsOptions;
use permguard_notp::{
    CommitPushRequest, FetchObjectsRequest, NegotiatePullRequest, NegotiatePullResponse,
    NegotiatePushRequest, NegotiatePushResponse, ObjectClaim, UploadObjectsRequest,
    UploadObjectsResponse,
};
use permguard_objects::digest::Digest;
use permguard_objects::{cbor, compress};

/// What the stub was asked, so a test can assert on the bytes that arrived.
type Seen = Arc<std::sync::Mutex<Vec<(String, Vec<u8>)>>>;

struct Stub {
    address: String,
    seen: Seen,
}

/// Serves one canned answer per `(method, path)`, remembering every request
/// body it received. One exchange per connection: the client sends
/// `Connection: close` and reads to EOF.
fn serve(routes: HashMap<(String, String), (u16, Vec<u8>)>) -> Stub {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a port is free");
    let address = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let routes = Arc::new(routes);
    let seen: Seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let routes = Arc::clone(&routes);
            let recorded = Arc::clone(&recorded);
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().expect("clones"));
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
                    return;
                }
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or("").to_owned();
                let path = parts.next().unwrap_or("").to_owned();

                let mut length = 0usize;
                loop {
                    let mut header = String::new();
                    if reader.read_line(&mut header).unwrap_or(0) == 0 {
                        return;
                    }
                    let header = header.trim();
                    if header.is_empty() {
                        break;
                    }
                    if let Some(value) = header
                        .to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(str::trim)
                        .and_then(|value| value.parse().ok())
                    {
                        length = value;
                    }
                }
                let mut body = vec![0u8; length];
                if length > 0 {
                    reader.read_exact(&mut body).expect("the body reads");
                }
                if let Ok(mut recorded) = recorded.lock() {
                    recorded.push((path.clone(), body));
                }

                let (status, answer) = routes.get(&(method, path)).cloned().unwrap_or((
                    404,
                    br#"{"class":"not_found","code":"not_found","message":"nothing answers"}"#
                        .to_vec(),
                ));
                let head = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/octet-stream\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n",
                    answer.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&answer);
                let _ = stream.shutdown(std::net::Shutdown::Both);
            });
        }
    });

    Stub { address, seen }
}

fn route(
    routes: &mut HashMap<(String, String), (u16, Vec<u8>)>,
    method: &str,
    path: &str,
    status: u16,
    body: Vec<u8>,
) {
    routes.insert((method.to_owned(), path.to_owned()), (status, body));
}

const ZONE: &str = "z-1";
const LEDGER: &str = "l-1";

fn base() -> String {
    format!("/v1/zones/{ZONE}/ledgers/{LEDGER}")
}

fn connected(stub: &Stub) -> HttpRemote {
    let remote = HttpRemote::connect(
        &format!("http://{}", stub.address),
        &TlsOptions::default(),
        Box::new(Silent),
    )
    .expect("the endpoint parses");
    remote.bind(ZONE, LEDGER);
    remote
}

/// The advertised ref: a CBOR map of head, counter and the statement bytes.
fn ref_answer(head: &Digest, counter: u64, statement: &[u8]) -> Vec<u8> {
    cbor::encode(&cbor::Value::Map(vec![
        (cbor::Value::Int(1), cbor::Value::Text(head.to_string())),
        (cbor::Value::Int(2), cbor::Value::Int(counter as i64)),
        (cbor::Value::Int(3), cbor::Value::Bytes(statement.to_vec())),
    ]))
}

#[test]
fn discovery_must_answer_as_a_plane_before_a_url_is_trusted() {
    let mut routes = HashMap::new();
    route(
        &mut routes,
        "GET",
        "/.well-known/server-configuration",
        200,
        br#"{"plane":"control-plane"}"#.to_vec(),
    );
    let stub = serve(routes);
    assert!(connected(&stub).verify_discovery().is_ok());

    // Something answers, but it is not a Permguard plane.
    let mut routes = HashMap::new();
    route(
        &mut routes,
        "GET",
        "/.well-known/server-configuration",
        200,
        br#"{"hello":"world"}"#.to_vec(),
    );
    let imposter = serve(routes);
    let error = connected(&imposter)
        .verify_discovery()
        .expect_err("an imposter is refused");
    assert!(error.contains("not with a Permguard plane"), "{error}");
}

#[test]
fn an_advertised_ref_is_read_and_an_absent_one_is_not_an_error() {
    let head = Digest::compute(b"head");
    let mut routes = HashMap::new();
    route(
        &mut routes,
        "GET",
        &format!("{}/refs/main", base()),
        200,
        ref_answer(&head, 4, b"envelope"),
    );
    let stub = serve(routes);
    let remote = connected(&stub);

    let answered = remote
        .get_ref("main")
        .expect("the ref reads")
        .expect("the ref exists");
    assert_eq!(answered.head, head.to_string());
    assert_eq!(answered.counter, 4);
    assert_eq!(answered.statement, b"envelope");

    // A ref the server does not have: `None`, not a failure — an empty
    // ledger is a legal state, and the first apply creates its history.
    assert!(remote.get_ref("feature/none").expect("answers").is_none());
}

#[test]
fn a_push_rides_cbor_and_honours_the_advertised_compression() {
    let d1 = Digest::compute(b"1");
    let mut routes = HashMap::new();
    route(
        &mut routes,
        "POST",
        &format!("{}/notp/push/negotiate", base()),
        200,
        NegotiatePushResponse {
            missing: vec![d1.clone()],
            max_batch_bytes: 8 * 1024 * 1024,
            max_batch_objects: 1000,
            compression: Some("deflate".into()),
        }
        .encode(),
    );
    route(
        &mut routes,
        "POST",
        &format!("{}/notp/objects", base()),
        200,
        UploadObjectsResponse {
            received: vec![d1.clone()],
        }
        .encode(),
    );
    let stub = serve(routes);
    let remote = connected(&stub);

    let negotiated = remote
        .negotiate_push(&NegotiatePushRequest {
            r#ref: "main".into(),
            new_head: d1.clone(),
            expected_old: None,
            closure: vec![ObjectClaim {
                digest: d1.clone(),
                size: 3,
            }],
        })
        .expect("the negotiation answers");
    assert_eq!(negotiated.missing, vec![d1]);
    assert_eq!(negotiated.compression.as_deref(), Some("deflate"));

    // The upload that follows must arrive compressed, and say so — the
    // client echoes what the server advertised, never assumes it.
    let payload = b"permit(principal, action, resource); // compressible".repeat(4);
    remote
        .upload(&UploadObjectsRequest {
            objects: vec![payload.clone()],
            compression: None,
        })
        .expect("the upload lands");

    let seen = stub.seen.lock().expect("the stub recorded");
    let (_, body) = seen
        .iter()
        .find(|(path, _)| path.ends_with("/notp/objects"))
        .expect("the upload was seen");
    let decoded = UploadObjectsRequest::decode(body).expect("the body is a NOTP message");
    assert_eq!(decoded.compression.as_deref(), Some("deflate"));
    let inflated = compress::inflate(&decoded.objects[0], 1 << 20).expect("it inflates");
    assert_eq!(inflated, payload, "the bytes survive the pipe");
    assert!(
        decoded.objects[0].len() < payload.len(),
        "and they actually got smaller"
    );
}

#[test]
fn a_pull_undoes_the_compression_the_server_applied() {
    let object = b"permit(principal, action, resource);".to_vec();
    let digest = Digest::compute(&object);
    let mut routes = HashMap::new();
    route(
        &mut routes,
        "POST",
        &format!("{}/notp/pull/negotiate", base()),
        200,
        NegotiatePullResponse {
            head: digest.clone(),
            counter: 1,
            statement: b"envelope".to_vec(),
            missing: vec![digest.clone()],
            max_batch_bytes: 8 * 1024 * 1024,
            max_batch_objects: 1000,
            compression: Some("deflate".into()),
        }
        .encode(),
    );
    route(
        &mut routes,
        "POST",
        &format!("{}/notp/objects/fetch", base()),
        200,
        permguard_notp::FetchObjectsResponse {
            objects: vec![compress::deflate(&object)],
            compression: Some("deflate".into()),
        }
        .encode(),
    );
    let stub = serve(routes);
    let remote = connected(&stub);

    let negotiated = remote
        .negotiate_pull(&NegotiatePullRequest {
            r#ref: "main".into(),
            at: None,
            have: Vec::new(),
        })
        .expect("the negotiation answers");
    assert_eq!(negotiated.missing, vec![digest.clone()]);

    let fetched = remote
        .fetch(&FetchObjectsRequest {
            digests: vec![digest],
            accept_compression: None,
        })
        .expect("the fetch answers");
    assert_eq!(
        fetched.objects,
        vec![object],
        "the caller sees raw canonical bytes, whatever rode the wire"
    );
    assert!(fetched.compression.is_none());
}

#[test]
fn a_refusal_carries_the_servers_own_words() {
    let mut routes = HashMap::new();
    route(
        &mut routes,
        "POST",
        &format!("{}/notp/push/commit", base()),
        409,
        br#"{"class":"conflict","code":"ref_conflict","message":"the ref moved: negotiate again from the current head"}"#.to_vec(),
    );
    let stub = serve(routes);

    let error = connected(&stub)
        .commit_push(&CommitPushRequest {
            r#ref: "main".into(),
            new_head: Digest::compute(b"new"),
            expected_old: Some(Digest::compute(b"old")),
        })
        .expect_err("a conflict is a refusal");
    assert!(error.contains("the ref moved"), "{error}");
    assert!(error.contains("ref_conflict"), "{error}");
}

#[test]
fn an_unbound_remote_says_so_instead_of_guessing_a_ledger() {
    let stub = serve(HashMap::new());
    let remote = HttpRemote::connect(
        &format!("http://{}", stub.address),
        &TlsOptions::default(),
        Box::new(Silent),
    )
    .expect("the endpoint parses");

    let error = remote.get_ref("main").expect_err("nothing is bound yet");
    assert!(error.contains("not bound to a ledger"), "{error}");
}

#[test]
fn nothing_listening_is_a_clean_error_not_a_hang() {
    let remote = HttpRemote::connect(
        "http://127.0.0.1:1",
        &TlsOptions::default(),
        Box::new(Silent),
    )
    .expect("the endpoint parses");
    remote.bind(ZONE, LEDGER);

    assert!(remote.keyring().is_err());
}
