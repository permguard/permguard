// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A server assembled outside the workspace serves a Plane the workspace does not know beside an
//! open-source one, and stops in order when its program says so.
//!
//! | What the program does                  | What it proves                                      |
//! | -------------------------------------- | --------------------------------------------------- |
//! | registers two Planes, composes, serves | the kit is enough: no command line, no signal       |
//! | asks its own Plane's route             | its routes are served by the kit's listener         |
//! | asks the Data Plane's discovery        | an open-source Plane is reused as it is             |
//! | reads its task's flag                  | its background work starts and stops with the server |
//! | resolves its shutdown future           | drained and stopped in order                        |

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use permguard_external_plane_fixture::edition;
use permguard_server::plane::{PlaneAddresses, SETTING_DATA_GRPC_ADDR, SETTING_DATA_HTTP_ADDR};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// A loopback address nothing listens on yet.
fn free_address() -> &'static str {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let address = listener.local_addr().expect("its address").to_string();
    Box::leak(address.into_boxed_str())
}

/// `GET path` over plain HTTP/1.1: the status line and the body.
async fn get(address: &str, path: &str) -> (String, String) {
    let mut last = String::new();
    for _ in 0..100 {
        match tokio::net::TcpStream::connect(address).await {
            Ok(mut stream) => {
                let request =
                    format!("GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n");
                stream.write_all(request.as_bytes()).await.expect("sent");
                let mut answer = Vec::new();
                stream.read_to_end(&mut answer).await.expect("answered");
                let answer = String::from_utf8_lossy(&answer).into_owned();
                let (head, body) = answer.split_once("\r\n\r\n").unwrap_or((&answer, ""));
                let status = head.lines().next().unwrap_or_default().to_owned();
                return (status, body.to_owned());
            }
            Err(error) => last = error.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{address} never listened: {last}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plane_the_workspace_does_not_know_is_served_beside_an_open_source_one() {
    let dir = std::env::temp_dir().join(format!("permguard-external-plane-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the fixture directory");
    let file = dir.join("config.yml");
    std::fs::write(
        &file,
        format!(
            "assurance:\n  profile: development\nworking_dir: {}\nhost:\n  addr: \"off\"\n",
            dir.join("volume").to_str().expect("a UTF-8 path")
        ),
    )
    .expect("the configuration file");

    let working = Arc::new(AtomicBool::new(false));
    let (fixture_http, fixture_grpc) = (free_address(), free_address());
    let (data_http, data_grpc) = (free_address(), free_address());
    let app = edition(
        Arc::clone(&working),
        PlaneAddresses::env(
            "PERMGUARD_FIXTURE_HTTP_ADDR",
            fixture_http,
            "PERMGUARD_FIXTURE_GRPC_ADDR",
            fixture_grpc,
        ),
    )
    .expect("the Planes are registered")
    .compose();
    let config = app
        .config_from(
            Some(&file),
            [
                (SETTING_DATA_HTTP_ADDR.to_owned(), data_http.to_owned()),
                (SETTING_DATA_GRPC_ADDR.to_owned(), data_grpc.to_owned()),
            ],
        )
        .expect("the server's configuration");

    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let program = async {
        // The fixture's own Plane answers on the listener the kit bound for it.
        let (status, body) = get(fixture_http, "/fixture/v1/ping").await;
        assert!(status.contains("200"), "{status}");
        assert_eq!(body, "pong 9.9.9");
        assert!(working.load(Ordering::SeqCst), "its background task runs");

        // The open-source Data Plane answers beside it, from its own module, unchanged.
        let (status, body) = get(data_http, "/.well-known/permguard-pdp-v1-configuration").await;
        assert!(status.contains("200"), "{status}: {body}");

        stop.send(()).expect("the server is still running");
    };
    let (served, ()) = tokio::join!(
        app.serve_until(&config, &file, async {
            let _ = stopped.await;
        }),
        program
    );
    served.expect("the server started, drained and stopped");
    assert!(
        !working.load(Ordering::SeqCst),
        "its background task stopped"
    );
}
