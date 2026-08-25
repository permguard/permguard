// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Bounding how many sockets one surface holds at once.
//!
//! # Why the permit rides on the stream
//!
//! A connection is not a request. It is a task, a TLS session and its buffers, and it lasts as long
//! as the client keeps it — which for an attacker is "forever". Limiting requests does nothing about
//! it: a client that opens ten thousand connections and sends nothing on any of them has spent none
//! of the request budget.
//!
//! So the permit is taken when the connection is accepted and released when the stream is dropped,
//! which happens exactly when the connection ends. There is nowhere to leak it, and no bookkeeping to
//! get wrong: the type system holds the count.
//!
//! # Refused, not queued
//!
//! A connection over the limit is closed immediately. Waiting for a slot would keep the socket open
//! for as long as the wait, which is the resource being defended — an attacker would get the same
//! outcome for the same effort, and legitimate clients would wait behind them.
//!
//! # One address cannot hold the pool
//!
//! The pool limit alone has a failure mode the pool cannot see: one client opening every slot and
//! sitting on them takes the surface away from everybody else while the global numbers still read as
//! healthy. So beside the semaphore there is a per-address count, read off the socket before any
//! handshake, with the same discipline as the permit: incremented at accept, decremented by `Drop`.
//! Addresses named in `peer_exempt` — a load balancer, a health checker — skip the per-address bound
//! and still count toward the pool, because exemption means "not suspicious", never "unlimited".
//!
//! # A connection is not forever, and a response must move
//!
//! Two more things ride on the stream itself. A lifetime, when one is configured: past it, the next
//! read or write fails and the connection ends — which is what lets a deployment behind a balancer
//! rotate connections instead of watching one live for a week. And a write-stall bound, always: a
//! response is written into the peer's TCP window, and a peer that stops reading stalls it forever —
//! slowloris on the way out, which none of the request-path bounds can see.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use axum_server::accept::Accept;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, Sleep};

use permguard_core::{Limits, Metrics};

use crate::measure::{ACCEPTED, CONNECTIONS, REFUSED};

/// The `component` every record of a refusal carries.
const COMPONENT: &str = "transport";

/// Accepts connections only while the surface is under its limit.
#[derive(Clone)]
pub struct LimitedAcceptor<A> {
    inner: A,
    permits: Arc<Semaphore>,
    /// How many sockets each address is holding right now. Zero-valued entries are removed, so the
    /// map's size is the number of distinct connected addresses — bounded by the pool.
    peers: Arc<Mutex<HashMap<IpAddr, PeerHeld>>>,
    limits: Limits,
    /// Whether the limit is currently being hit, so saturation is reported once per episode rather
    /// than once per refused connection — which under an attack is the same as not reporting it.
    saturated: Arc<AtomicBool>,
    /// What the limit is, kept because the semaphore can only say how much of it is left — and at
    /// the moment worth reporting, that is zero.
    capacity: u32,
    /// How many are held right now. Kept beside the semaphore rather than derived from it: a permit
    /// is released when a stream is dropped, and a count read at that moment would be off by the one
    /// still being released.
    held: Arc<AtomicI64>,
    surface: &'static str,
    metrics: Metrics,
}

impl<A> LimitedAcceptor<A> {
    /// Wraps `inner`, admitting what `limits` allows.
    pub fn new(inner: A, limits: Limits) -> Self {
        let connections = limits.connections();

        Self {
            inner,
            permits: Arc::new(Semaphore::new(connections as usize)),
            peers: Arc::new(Mutex::new(HashMap::new())),
            limits,
            saturated: Arc::new(AtomicBool::new(false)),
            capacity: connections,
            held: Arc::new(AtomicI64::new(0)),
            surface: "surface",
            metrics: Metrics::none(),
        }
    }

    /// Admits `address`'s connection against the per-address bound, or says no.
    ///
    /// The count comes down when the returned guard is dropped — the same discipline as the permit,
    /// and for the same reason: there is no release path to forget.
    fn admit_peer(&self, address: Option<IpAddr>) -> Result<Option<PeerReleased>, ()> {
        let bound = self.limits.connections_per_peer();
        let Some(address) = address else {
            // A stream with no address is not a TCP socket — a test harness, a Unix socket. There is
            // nothing to count by, and refusing it would make the bound a way to break every
            // non-TCP caller for no defensive gain.
            return Ok(None);
        };

        if bound == 0 || self.limits.is_peer_exempt(address) {
            return Ok(None);
        }

        let mut peers = match self.peers.lock() {
            Ok(peers) => peers,
            // A poisoned map means an accept panicked mid-update. Failing open here would turn one
            // panic into an unbounded surface; failing closed turns it into refusals somebody sees.
            Err(_) => return Err(()),
        };
        let entry = peers.entry(address).or_default();

        if entry.held >= bound {
            if !entry.warned {
                entry.warned = true;

                tracing::warn!(
                    event.name = "transport.peer_saturated",
                    component = COMPONENT,
                    peer.address = %address,
                    limit = bound,
                    "one address is holding as many connections as it is allowed to; refusing its next ones"
                );
            }

            return Err(());
        }

        entry.held += 1;

        Ok(Some(PeerReleased {
            peers: Arc::clone(&self.peers),
            address,
        }))
    }

    /// Records what this acceptor admits and refuses, under the name `surface`.
    pub fn measured(mut self, surface: &'static str, metrics: Metrics) -> Self {
        self.surface = surface;
        self.metrics = metrics;

        self
    }
}

impl<A: std::fmt::Debug> std::fmt::Debug for LimitedAcceptor<A> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LimitedAcceptor")
            .field("available", &self.permits.available_permits())
            .finish_non_exhaustive()
    }
}

impl<A, I, S> Accept<I, S> for LimitedAcceptor<A>
where
    A: Accept<I, S> + Send + 'static,
    A::Future: Send,
    A::Stream: Send,
    A::Service: Send,
    I: PeerIp + Send + 'static,
    S: Send + 'static,
{
    type Stream = Guarded<A::Stream>;
    type Service = A::Service;
    type Future = Pin<
        Box<dyn std::future::Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>,
    >;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        // Taken before the handshake, so a client that never finishes one still costs a slot rather
        // than an unbounded number of them.
        let permit = match Arc::clone(&self.permits).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                // Counted every time, unlike the log record: the whole point of the number is that a
                // refusal rate is visible, and one warning per episode cannot express a rate.
                self.metrics
                    .count(&REFUSED, &[("surface", self.surface), ("scope", "pool")]);

                if !self.saturated.swap(true, Ordering::SeqCst) {
                    tracing::warn!(
                        event.name = "transport.connections_saturated",
                        component = COMPONENT,
                        limit = self.capacity,
                        "refusing connections until one is released"
                    );
                }

                return Box::pin(async {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "the surface is holding as many connections as it is allowed to",
                    ))
                });
            }
        };

        // After the pool permit, so a refusal here has already proven the pool had room: what ran
        // out was this one client's share. Dropping the permit on the way out returns the slot.
        let peer = match self.admit_peer(stream.peer_ip()) {
            Ok(peer) => peer,
            Err(()) => {
                self.metrics
                    .count(&REFUSED, &[("surface", self.surface), ("scope", "peer")]);

                drop(permit);

                return Box::pin(async {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "this address is holding as many connections as one address is allowed to",
                    ))
                });
            }
        };

        self.saturated.store(false, Ordering::SeqCst);

        self.metrics.count(&ACCEPTED, &[("surface", self.surface)]);
        let held = self.held.fetch_add(1, Ordering::SeqCst) + 1;
        self.metrics
            .set(&CONNECTIONS, &[("surface", self.surface)], held as f64);

        let accepting = self.inner.accept(stream, service);
        let released = Released {
            held: Arc::clone(&self.held),
            surface: self.surface,
            metrics: self.metrics.clone(),
        };
        let deadline = self
            .limits
            .connection_lifetime()
            .map(|lifetime| Instant::now() + lifetime);
        let stall = self.limits.write_stall_timeout();

        Box::pin(async move {
            // `?` here would drop `released` — and the peer guard with it — on a failed handshake,
            // which is exactly right: a connection that never became one must not be counted as held.
            let (stream, service) = accepting.await?;

            Ok((
                Guarded {
                    inner: stream,
                    deadline,
                    stall,
                    stalled: None,
                    _permit: permit,
                    _released: released,
                    _peer: peer,
                },
                service,
            ))
        })
    }
}

/// What a stream can say about who is on the other end.
///
/// The acceptor is generic over its stream, and most streams — TLS wrappers, test doubles — have no
/// address. Only the raw TCP socket does, which is exactly where the per-address bound has to be
/// applied: before any handshake has cost anything.
pub trait PeerIp {
    /// The address of the peer, when there is one.
    fn peer_ip(&self) -> Option<IpAddr>;
}

impl PeerIp for tokio::net::TcpStream {
    fn peer_ip(&self) -> Option<IpAddr> {
        self.peer_addr().ok().map(|address| address.ip())
    }
}

/// One address's standing with the acceptor.
#[derive(Debug, Default)]
struct PeerHeld {
    held: u32,
    /// Whether this address has already been warned about, so an attack is one record rather than a
    /// record per refused socket — which under an attack is the same as no record at all.
    warned: bool,
}

/// Takes one off an address's count when it is dropped, and forgets addresses holding nothing.
#[derive(Debug)]
struct PeerReleased {
    peers: Arc<Mutex<HashMap<IpAddr, PeerHeld>>>,
    address: IpAddr,
}

impl Drop for PeerReleased {
    fn drop(&mut self) {
        let Ok(mut peers) = self.peers.lock() else {
            return;
        };

        if let Some(entry) = peers.get_mut(&self.address) {
            entry.held = entry.held.saturating_sub(1);

            // Removed rather than left at zero, so the map holds connected addresses and not a
            // history of everybody who ever connected — which an attacker with addresses to spare
            // would otherwise grow without bound.
            if entry.held == 0 {
                peers.remove(&self.address);
            }
        }
    }
}

/// Takes one off the held count when it is dropped, whenever and wherever that happens.
///
/// A field rather than a `Drop` on [`Guarded`] itself, because a stream that failed its handshake is
/// dropped before it ever becomes one — and the count has to come down either way.
#[derive(Debug)]
struct Released {
    held: Arc<AtomicI64>,
    surface: &'static str,
    metrics: Metrics,
}

impl Drop for Released {
    fn drop(&mut self) {
        let held = self.held.fetch_sub(1, Ordering::SeqCst) - 1;
        self.metrics
            .set(&CONNECTIONS, &[("surface", self.surface)], held as f64);
    }
}

/// A stream that holds a connection permit for as long as it exists.
///
/// Neither field is ever read. They are here so that dropping the stream returns the permit and takes
/// the connection back off the count, which is the whole mechanism: there is no release path to
/// forget, because there is no release path.
pub struct Guarded<I> {
    inner: I,
    /// When this connection has lived long enough, whatever it is doing. `None` means unbounded.
    deadline: Option<Instant>,
    /// How long a write may make no progress.
    stall: Duration,
    /// Armed while a write is pending and cleared by the first byte that moves. A write that outlives
    /// it is a peer that stopped reading, and the connection ends instead of waiting for a TCP
    /// window that is never going to open.
    stalled: Option<Pin<Box<Sleep>>>,
    _permit: OwnedSemaphorePermit,
    _released: Released,
    _peer: Option<PeerReleased>,
}

impl<I> Guarded<I> {
    /// Fails the poll when the connection has outlived its lifetime.
    ///
    /// Checked on reads and writes rather than by a timer, because a connection that is doing
    /// nothing is already bounded by the idle machinery above this — the header timeout, the
    /// keep-alive ping — and each of those ends in a poll that lands here.
    fn expired(&self) -> Option<io::Error> {
        let deadline = self.deadline?;

        if Instant::now() < deadline {
            return None;
        }

        Some(io::Error::new(
            io::ErrorKind::TimedOut,
            "the connection reached its configured lifetime",
        ))
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for Guarded<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(expired) = self.expired() {
            return Poll::Ready(Err(expired));
        }

        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for Guarded<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(expired) = self.expired() {
            return Poll::Ready(Err(expired));
        }

        match Pin::new(&mut self.inner).poll_write(context, bytes) {
            Poll::Ready(result) => {
                // A byte moved, or the write failed on its own: either way the peer is not stalled.
                self.stalled = None;

                Poll::Ready(result)
            }
            Poll::Pending => {
                let stall = self.stall;
                let timer = self
                    .stalled
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(stall)));

                match timer.as_mut().poll(context) {
                    Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "the peer stopped reading its response",
                    ))),
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        slices: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(context, slices)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    /// A guarded stream holding one of `permits`, counted into `held`.
    fn guarded(permits: &Arc<Semaphore>, held: &Arc<AtomicI64>) -> Guarded<tokio::io::Empty> {
        held.fetch_add(1, Ordering::SeqCst);

        Guarded {
            inner: tokio::io::empty(),
            deadline: None,
            stall: Duration::from_secs(30),
            stalled: None,
            _permit: Arc::clone(permits)
                .try_acquire_owned()
                .expect("a slot is free"),
            _released: Released {
                held: Arc::clone(held),
                surface: "test",
                metrics: Metrics::none(),
            },
            _peer: None,
        }
    }

    #[tokio::test]
    async fn test_a_permit_is_held_for_the_life_of_the_stream_and_no_longer() {
        let permits = Arc::new(Semaphore::new(2));
        let held = Arc::new(AtomicI64::new(0));

        let first = guarded(&permits, &held);
        let second = guarded(&permits, &held);

        assert_eq!(permits.available_permits(), 0);
        assert!(
            Arc::clone(&permits).try_acquire_owned().is_err(),
            "a third connection was admitted over the limit"
        );

        // Dropping is the release. There is no other path, which is the point.
        drop(first);
        assert_eq!(permits.available_permits(), 1);

        drop(second);
        assert_eq!(permits.available_permits(), 2);
    }

    /// A writer that never accepts a byte: the peer's TCP window, closed forever.
    struct NeverWrites;

    impl AsyncWrite for NeverWrites {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for NeverWrites {
        fn poll_read(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_peer_that_stops_reading_is_given_up_on() {
        use tokio::io::AsyncWriteExt;

        let permits = Arc::new(Semaphore::new(1));
        let held = Arc::new(AtomicI64::new(0));
        let mut guarded = Guarded {
            inner: NeverWrites,
            deadline: None,
            stall: Duration::from_secs(30),
            stalled: None,
            _permit: Arc::clone(&permits)
                .try_acquire_owned()
                .expect("a slot is free"),
            _released: Released {
                held: Arc::clone(&held),
                surface: "test",
                metrics: Metrics::none(),
            },
            _peer: None,
        };

        // Paused time: the thirty seconds pass instantly, and the write that made no progress fails
        // instead of waiting for a window that is never going to open.
        let outcome = guarded.write_all(b"an answer nobody reads").await;
        let error = outcome.expect_err("a stalled write must fail");

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_connection_past_its_lifetime_is_ended() {
        use tokio::io::AsyncReadExt;

        let permits = Arc::new(Semaphore::new(1));
        let held = Arc::new(AtomicI64::new(0));
        let mut guarded = Guarded {
            inner: tokio::io::empty(),
            deadline: Some(Instant::now() + Duration::from_secs(60)),
            stall: Duration::from_secs(30),
            stalled: None,
            _permit: Arc::clone(&permits)
                .try_acquire_owned()
                .expect("a slot is free"),
            _released: Released {
                held: Arc::clone(&held),
                surface: "test",
                metrics: Metrics::none(),
            },
            _peer: None,
        };

        tokio::time::advance(Duration::from_secs(61)).await;

        let mut buffer = [0_u8; 4];
        let error = guarded
            .read(&mut buffer)
            .await
            .expect_err("a read past the lifetime must fail");

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn test_one_address_is_bounded_and_an_exempt_one_is_not() {
        let acceptor = LimitedAcceptor::new(
            (),
            Limits::new()
                .with_connections(10)
                .with_connections_per_peer(2)
                .with_peer_exempt(vec!["10.0.0.0/8".parse().expect("a valid block")]),
        );
        let bounded: IpAddr = "203.0.113.7".parse().expect("an address");
        let exempt: IpAddr = "10.1.2.3".parse().expect("an address");

        let first = acceptor.admit_peer(Some(bounded)).expect("under the bound");
        let _second = acceptor.admit_peer(Some(bounded)).expect("at the bound");

        assert!(
            acceptor.admit_peer(Some(bounded)).is_err(),
            "a third connection from one address was admitted over its bound"
        );

        // Dropping is the release, and the freed share is usable again.
        drop(first);
        let _third = acceptor
            .admit_peer(Some(bounded))
            .expect("a released share is admitted again");

        // An exempt address never consumes a share, however many it opens.
        for _ in 0..5 {
            assert!(
                acceptor
                    .admit_peer(Some(exempt))
                    .expect("exempt is always admitted")
                    .is_none()
            );
        }

        // A stream with no address at all — not TCP — is not the per-address bound's business.
        assert!(acceptor.admit_peer(None).expect("admitted").is_none());
    }

    #[tokio::test]
    async fn test_the_held_count_comes_back_down() {
        // A gauge that only goes up reads as a leak that is not there, and hides the saturation that
        // is. Whatever else happens to a stream, dropping it takes one off.
        let permits = Arc::new(Semaphore::new(4));
        let held = Arc::new(AtomicI64::new(0));

        let streams: Vec<_> = (0..3).map(|_| guarded(&permits, &held)).collect();
        assert_eq!(held.load(Ordering::SeqCst), 3);

        drop(streams);
        assert_eq!(held.load(Ordering::SeqCst), 0);
    }
}
