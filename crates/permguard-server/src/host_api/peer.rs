// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The peer channel, the responder's half (WP-2.3): the stream the Host listener serves for
//! `permguard.host.v1.IdentityService/PeerChannel`. The frames the peer sends go to a
//! [`Responder`] and its answers go back, until the session is refused or the peer closes.
//!
//! The initiator's half, how a member reaches its coordinators, is the client library's: a Host
//! that only dials out links it and no listener. It is named here for the server that composes
//! both.

use std::sync::Arc;

use tokio::sync::mpsc;
use tonic::Streaming;
use tonic::codegen::BoxStream;

use permguard_core::codes;
use permguard_host::session::{Frame, Responder};

pub use permguard_client::peer::{
    Connection, Established, HANDSHAKE, IDLE, MAX_MESSAGE_BYTES, PeerClient, PeerConnector,
    PeerError, channel_path, initiate, member_client,
};
use permguard_client::peer::{QUEUE, Receiving, frame_of, refused, wire_of};

use super::v1;

/// The frames a stream of `receiver` yields, as a response body.
fn stream_of(
    receiver: mpsc::Receiver<Result<v1::PeerFrame, tonic::Status>>,
) -> BoxStream<v1::PeerFrame> {
    Box::pin(Receiving(receiver))
}

/// Serves one PeerChannel stream with `responder`: the handshake bounded by [`HANDSHAKE`], the
/// established session kept until the peer closes. Any refusal is sent as its code, then the
/// stream ends.
pub(crate) fn respond(
    mut responder: Responder,
    mut inbound: Streaming<v1::PeerFrame>,
) -> BoxStream<v1::PeerFrame> {
    let (sender, receiver) = mpsc::channel(QUEUE);
    tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + HANDSHAKE;
        loop {
            // An answer that is gone, the listener's drain ended it (BUG-0222), ends the session
            // at once: the inbound stream is released and the connection can finish.
            let closed = sender.clone();
            let next = if responder.session().is_some() {
                let read = tokio::select! {
                    () = closed.closed() => return,
                    read = tokio::time::timeout(IDLE, inbound.message()) => read,
                };
                match read {
                    Ok(next) => next,
                    Err(_) => {
                        tracing::info!(
                            event.name = "host.session_idle",
                            component = "host",
                            "a peer session stayed silent past its idle bound; the channel is closed"
                        );
                        return;
                    }
                }
            } else {
                let read = tokio::select! {
                    () = closed.closed() => return,
                    read = tokio::time::timeout_at(deadline, inbound.message()) => read,
                };
                match read {
                    Ok(next) => next,
                    Err(_) => {
                        let refusal = responder.abort("the handshake took too long");
                        let _ = sender.send(Ok(refused(&refusal))).await;
                        return;
                    }
                }
            };
            let frame = match next {
                Ok(Some(frame)) => frame,
                // The peer closed, or the connection went: nothing more to answer.
                Ok(None) | Err(_) => {
                    if responder.session().is_none() {
                        responder.abort("the channel closed before the session was established");
                    }
                    return;
                }
            };
            let Some(frame) = frame_of(frame) else {
                let refusal = responder.abort("a frame carrying nothing");
                let _ = sender.send(Ok(refused(&refusal))).await;
                return;
            };
            match responder.receive(frame) {
                Ok(frames) => {
                    for frame in frames {
                        if sender.send(Ok(wire_of(frame))).await.is_err() {
                            return;
                        }
                    }
                }
                Err(refusal) => {
                    let _ = sender.send(Ok(refused(&refusal))).await;
                    return;
                }
            }
            // A task session that became a watch belongs to it from here (WP-4.4).
            if let Some(watch) = responder.take_watch() {
                serve_watch(watch, &mut inbound, &sender).await;
                return;
            }
        }
    });
    stream_of(receiver)
}

/// Sends what `watch` yields until it ends: hints when queued, a heartbeat when quiet. Anything
/// the member sends, or its closing, ends the watch; a refusal is sent as its code.
async fn serve_watch(
    mut watch: Box<dyn permguard_host::session::Watching>,
    inbound: &mut Streaming<v1::PeerFrame>,
    sender: &mpsc::Sender<Result<v1::PeerFrame, tonic::Status>>,
) {
    let notify = Arc::new(tokio::sync::Notify::new());
    let waker = Arc::clone(&notify);
    watch.on_hint(Box::new(move || waker.notify_one()));
    loop {
        let frame = match watch.poll() {
            Ok(Some(frame)) => Some(frame),
            Ok(None) => {
                tokio::select! {
                    () = notify.notified() => None,
                    () = tokio::time::sleep(watch.interval()) => match watch.heartbeat() {
                        Ok(frame) => Some(frame),
                        Err(refusal) => {
                            let _ = sender.send(Ok(refused(&refusal))).await;
                            return;
                        }
                    },
                    // The answer is gone: the listener's drain ended it (BUG-0222).
                    () = sender.closed() => return,
                    // The session belongs to its watch: anything the member sends ends it, as
                    // the in-process session answers.
                    next = inbound.message() => {
                        if matches!(next, Ok(Some(_))) {
                            let _ = sender
                                .send(Ok(wire_of(Frame::Refusal {
                                    code: codes::common::INVALID_ARGUMENT.to_owned(),
                                })))
                                .await;
                        }
                        return;
                    }
                }
            }
            Err(refusal) => {
                let _ = sender.send(Ok(refused(&refusal))).await;
                return;
            }
        };
        if let Some(frame) = frame
            && sender.send(Ok(wire_of(Frame::Task(frame)))).await.is_err()
        {
            return;
        }
    }
}
