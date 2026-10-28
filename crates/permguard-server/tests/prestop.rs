// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `drain`, the `preStop` command (TD-1): it signals the server and returns, or, with a wait, waits
//! for it to exit and reports a server that outlives the wait as a failure; a server already gone is
//! drained. A child process stands in for the container's server.

#![cfg(unix)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::os::unix::process::ExitStatusExt as _;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use permguard_server::prestop::drain;

fn spawn(script: &str) -> Child {
    Command::new("sh")
        .args(["-c", script])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the stand-in server starts")
}

#[tokio::test]
async fn drain_signals_the_server_and_waits_for_it_to_exit() {
    // `exec`, so the signal reaches `sleep` itself, which SIGTERM ends.
    let mut server = spawn("exec sleep 60");
    let pid = server.id();
    // The parent reaps the child, as the container runtime reaps a container's process 1: until
    // then an exited process still answers to its id.
    let reaper = std::thread::spawn(move || server.wait().expect("the server is reaped"));

    let mut out = Vec::new();
    drain(pid, Duration::from_secs(20), &mut out)
        .await
        .expect("the server drains inside the budget");

    let status = reaper.join().expect("the reaper finishes");
    assert_eq!(status.signal(), Some(15), "the server was ended by SIGTERM");
    assert_eq!(
        String::from_utf8(out).unwrap(),
        format!("the server (process {pid}) drained and exited\n")
    );
}

#[tokio::test]
async fn drain_without_a_wait_asks_and_returns() {
    let mut server = spawn("exec sleep 60");
    let pid = server.id();
    let started = std::time::Instant::now();

    let mut out = Vec::new();
    drain(pid, Duration::ZERO, &mut out)
        .await
        .expect("the request is sent");

    assert!(
        started.elapsed() < Duration::from_secs(2),
        "it did not wait"
    );
    assert_eq!(
        String::from_utf8(out).unwrap(),
        format!("asked the server (process {pid}) to drain\n")
    );
    let status = server.wait().expect("the server is reaped");
    assert_eq!(status.signal(), Some(15), "the request was SIGTERM");
}

#[tokio::test]
async fn drain_reports_a_server_that_outlives_its_budget() {
    // A server that ignores the request: the shell ignores SIGTERM, and so does its `sleep`.
    let mut server = spawn("trap '' TERM; sleep 60");
    let pid = server.id();
    std::thread::sleep(Duration::from_millis(200));

    let started = std::time::Instant::now();
    let error = drain(pid, Duration::from_secs(1), &mut Vec::new())
        .await
        .expect_err("a server still running after the budget is a failure");
    let waited = started.elapsed();

    assert!(
        error
            .to_string()
            .contains("still running 1s after it was asked to drain"),
        "{error:#}"
    );
    assert!(
        waited >= Duration::from_secs(1),
        "the whole budget was given: {waited:?}"
    );
    assert!(waited < Duration::from_secs(5), "and no more: {waited:?}");
    server.kill().expect("the stand-in is stopped");
    server.wait().expect("and reaped");
}

#[tokio::test]
async fn drain_finds_nothing_to_drain_when_the_server_is_gone() {
    let mut server = spawn("exit 0");
    let pid = server.id();
    server.wait().expect("the server exits and is reaped");

    let mut out = Vec::new();
    drain(pid, Duration::from_secs(5), &mut out)
        .await
        .expect("a server already gone has nothing to drain");

    assert_eq!(
        String::from_utf8(out).unwrap(),
        format!("no server is running as process {pid}: nothing to drain\n")
    );
}

#[tokio::test]
async fn drain_refuses_process_zero() {
    // Process 0 would signal the whole process group: never what a hook means.
    let error = drain(0, Duration::from_secs(1), &mut Vec::new())
        .await
        .expect_err("process 0 is refused");

    assert!(error.to_string().contains("positive"), "{error:#}");
}
