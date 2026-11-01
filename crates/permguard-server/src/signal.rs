// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a process shutdown is, when nobody says otherwise — and what a reload is.
//!
//! The contracts take an opaque future, so the question "what counts as a shutdown" has exactly one
//! answer per build and it lives here. For a server in a container the answer is SIGTERM — that is
//! what an orchestrator sends before it eventually sends SIGKILL — with SIGINT for the operator who
//! is watching it in a terminal.
//!
//! SIGHUP is the other half of that vocabulary and means the opposite: re-read what can be re-read,
//! and keep running. It is what `certbot`, `cert-manager` hooks and every operator who has ever
//! renewed a certificate already expect to work — so it works, and *what* gets re-read is decided by
//! the binary rather than here.

use std::sync::Arc;

use tokio::task::JoinHandle;
use tracing::info;
#[cfg(any(unix, windows))]
use tracing::warn;

use permguard_core::BoxFuture;

/// What a build does when it is asked to re-read what it can.
pub type ReloadHandler = Arc<dyn Fn() + Send + Sync>;

/// Resolves when the process is asked to stop.
///
/// The signal that arrived is recorded, because "why did it go away" is the first question asked
/// about a process that went away, and an orchestrator's SIGTERM and an operator's Ctrl-C are very
/// different answers.
///
/// Listening starts when this is called and not when the returned future is first awaited. The two
/// are not the same moment: a process is asked to stop at times it did not pick, and startup is one
/// of them — an orchestrator that cancels a rollout sends SIGTERM to a container that is still
/// preparing its volume. Until a handler exists, SIGTERM does what the kernel does with it by
/// default and ends the process where it stands: no orderly stop, no sealed trail, nothing said
/// about why it went away. Registering here and awaiting later is what makes "asked to stop while
/// starting" mean the same thing as "asked to stop while serving".
pub fn process_shutdown() -> BoxFuture<'static, ()> {
    let signalled = listen_for_shutdown();

    Box::pin(async move {
        let received = signalled.await;

        info!(
            event.name = "server.signal",
            signal = received,
            "asked to stop"
        );
    })
}

/// Runs `handler` every time the process is sent SIGHUP, until the returned task is dropped.
///
/// A failure to register the handler is recorded and does not stop the server. A build that cannot
/// be told to reload still serves; one that refused to start because of it would be strictly worse.
#[cfg(unix)]
pub fn on_hangup(handler: ReloadHandler) -> JoinHandle<()> {
    use tokio::signal::unix::{SignalKind, signal};

    tokio::spawn(async move {
        let mut hangup = match signal(SignalKind::hangup()) {
            Ok(hangup) => hangup,
            Err(error) => {
                warn!(
                    event.name = "server.reload_unavailable",
                    error = %error,
                    "this process cannot be asked to re-read its material without restarting"
                );

                return;
            }
        };

        while hangup.recv().await.is_some() {
            info!(
                event.name = "server.reload",
                signal = "SIGHUP",
                "asked to re-read what can be re-read"
            );

            handler();
        }
    })
}

/// Registers nothing, on a platform with no such signal.
#[cfg(not(unix))]
pub fn on_hangup(_handler: ReloadHandler) -> JoinHandle<()> {
    tokio::spawn(async {})
}

/// Registers both stop signals now and returns what resolves when either of them arrives.
///
/// Either one may fail to register, and neither failure is fatal: a server that refused to start
/// because it could not be interrupted from a terminal would be worse than one that can only be
/// stopped by an orchestrator, and the other way round. What it cannot listen for it says once,
/// rather than leaving the operator to discover it by sending a signal nothing answers.
#[cfg(unix)]
fn listen_for_shutdown() -> BoxFuture<'static, &'static str> {
    use tokio::signal::unix::SignalKind;

    let terminate = listen(SignalKind::terminate(), "SIGTERM");
    let interrupt = listen(SignalKind::interrupt(), "SIGINT");

    Box::pin(async move {
        match (terminate, interrupt) {
            (Some(mut terminate), Some(mut interrupt)) => tokio::select! {
                _ = terminate.recv() => "SIGTERM",
                _ = interrupt.recv() => "SIGINT",
            },
            (Some(mut terminate), None) => {
                terminate.recv().await;

                "SIGTERM"
            }
            (None, Some(mut interrupt)) => {
                interrupt.recv().await;

                "SIGINT"
            }
            // Nothing left to listen for. The server still serves; it just cannot be asked to stop,
            // and waiting is the honest answer — resolving would stop a server nobody asked to stop.
            (None, None) => std::future::pending().await,
        }
    })
}

/// Starts listening for one signal, or says why it could not.
#[cfg(unix)]
fn listen(
    kind: tokio::signal::unix::SignalKind,
    name: &'static str,
) -> Option<tokio::signal::unix::Signal> {
    match tokio::signal::unix::signal(kind) {
        Ok(stream) => Some(stream),
        Err(error) => {
            warn!(
                event.name = "server.signal_unavailable",
                signal = name,
                error = %error,
                "this process cannot be asked to stop with this signal"
            );

            None
        }
    }
}

/// Windows has no SIGTERM: a process is asked to stop by Ctrl-C, by Ctrl-Break (what a service
/// wrapper or a parent sends a console process group), by its console being closed and by the
/// system shutting down. Each is registered here, now, as the Unix signals are; one that cannot be
/// registered is said once and the others still stop the server (1-architecture-server).
#[cfg(windows)]
fn listen_for_shutdown() -> BoxFuture<'static, &'static str> {
    use tokio::signal::windows;

    let interrupt = registered(windows::ctrl_c(), "CTRL_C");
    let broken = registered(windows::ctrl_break(), "CTRL_BREAK");
    let closed = registered(windows::ctrl_close(), "CTRL_CLOSE");
    let shutdown = registered(windows::ctrl_shutdown(), "CTRL_SHUTDOWN");

    Box::pin(async move {
        // A listener that could not be registered never resolves: the others still can, and with
        // none the server cannot be asked to stop, which waiting says honestly.
        let interrupt = async move {
            match interrupt {
                Some(mut listener) => listener.recv().await,
                None => std::future::pending().await,
            }
        };
        let broken = async move {
            match broken {
                Some(mut listener) => listener.recv().await,
                None => std::future::pending().await,
            }
        };
        let closed = async move {
            match closed {
                Some(mut listener) => listener.recv().await,
                None => std::future::pending().await,
            }
        };
        let shutdown = async move {
            match shutdown {
                Some(mut listener) => listener.recv().await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            _ = interrupt => "CTRL_C",
            _ = broken => "CTRL_BREAK",
            _ = closed => "CTRL_CLOSE",
            _ = shutdown => "CTRL_SHUTDOWN",
        }
    })
}

/// A Windows console event listener, or why it could not be registered.
#[cfg(windows)]
fn registered<T>(listener: std::io::Result<T>, name: &'static str) -> Option<T> {
    match listener {
        Ok(listener) => Some(listener),
        Err(error) => {
            warn!(
                event.name = "server.signal_unavailable",
                signal = name,
                error = %error,
                "this process cannot be asked to stop with this console event"
            );

            None
        }
    }
}

/// Registers nothing ahead of time, on a platform where there is nothing to register ahead of time:
/// `ctrl_c` installs its handler on the first poll and there is no earlier hook to use.
#[cfg(not(any(unix, windows)))]
fn listen_for_shutdown() -> BoxFuture<'static, &'static str> {
    Box::pin(async {
        let _ = tokio::signal::ctrl_c().await;

        "SIGINT"
    })
}
