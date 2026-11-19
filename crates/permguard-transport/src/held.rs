// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The connections a client certificate authenticated, and ending them when it is revoked
//! (BUG-0101).
//!
//! A revocation list is checked at the TLS handshake, which is once per connection: a client that
//! keeps its connection open would keep what its certificate authenticated past the revocation, for
//! as long as it kept the connection busy. So each surface holds the certificate chain of every
//! connection a client certificate authenticated, and a reload verifies them again with the
//! verifier it just built: a connection whose certificate the list in force now revokes ends at
//! once, whatever it is doing, and the reload counts it.
//!
//! Only a revocation ends a connection here. A certificate that expires while connected, or an
//! authority taken out of the bundle, is the next handshake's to refuse, as the configuration
//! change is: the list is the instrument that says "this certificate, now".

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};

use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::ClientCertVerifier;
use rustls::{CertificateError, Error};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The connections of one surface that a client certificate authenticated.
#[derive(Default)]
pub(crate) struct Held {
    next: AtomicU64,
    connections: Mutex<HashMap<u64, Entry>>,
}

/// One connection: the chain its client presented, and the switch that ends it.
struct Entry {
    chain: Vec<CertificateDer<'static>>,
    ending: Arc<Ending>,
}

impl Held {
    /// Records a connection `chain` authenticated, its end entity first. What it returns ends the
    /// connection when the chain is revoked, and takes it off the record when dropped.
    pub(crate) fn hold(self: &Arc<Self>, chain: Vec<CertificateDer<'static>>) -> Holding {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let ending = Arc::new(Ending::default());
        if let Ok(mut connections) = self.connections.lock() {
            connections.insert(
                id,
                Entry {
                    chain,
                    ending: Arc::clone(&ending),
                },
            );
        }

        Holding {
            ending,
            held: Arc::downgrade(self),
            id,
        }
    }

    /// Verifies every held connection's chain with `verifier` and ends each one whose certificate
    /// is revoked. Returns how many it ended.
    pub(crate) fn end_revoked(&self, verifier: &dyn ClientCertVerifier) -> usize {
        let Ok(connections) = self.connections.lock() else {
            return 0;
        };
        let now = UnixTime::now();
        let mut ended = 0;
        for entry in connections.values() {
            let Some((end_entity, intermediates)) = entry.chain.split_first() else {
                continue;
            };
            if entry.ending.is_ended() {
                continue;
            }
            if let Err(Error::InvalidCertificate(CertificateError::Revoked)) =
                verifier.verify_client_cert(end_entity, intermediates, now)
            {
                entry.ending.end();
                ended += 1;
            }
        }

        ended
    }

    /// How many connections are held.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.connections.lock().map_or(0, |held| held.len())
    }
}

/// The switch of one connection.
#[derive(Default)]
struct Ending {
    ended: AtomicBool,
    /// The read waiting on the connection, woken when it ends: an idle connection is always
    /// reading, so this is what reaches it.
    reader: Mutex<Option<Waker>>,
}

impl Ending {
    fn end(&self) {
        self.ended.store(true, Ordering::SeqCst);
        let waiting = self.reader.lock().ok().and_then(|mut reader| reader.take());
        if let Some(waker) = waiting {
            waker.wake();
        }
    }

    fn is_ended(&self) -> bool {
        self.ended.load(Ordering::SeqCst)
    }
}

/// A connection's place in [`Held`]: its switch, and its removal when the connection goes.
pub(crate) struct Holding {
    ending: Arc<Ending>,
    held: Weak<Held>,
    id: u64,
}

impl Drop for Holding {
    fn drop(&mut self) {
        if let Some(held) = self.held.upgrade()
            && let Ok(mut connections) = held.connections.lock()
        {
            connections.remove(&self.id);
        }
    }
}

/// A stream that fails every read and write once its client certificate is revoked; one no
/// certificate authenticated is never ended here.
pub struct Revocable<S> {
    inner: S,
    holding: Option<Holding>,
}

impl<S> Revocable<S> {
    pub(crate) fn new(inner: S, holding: Option<Holding>) -> Self {
        Self { inner, holding }
    }

    /// The stream underneath.
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    fn revoked(&self) -> Option<io::Error> {
        self.holding
            .as_ref()
            .filter(|holding| holding.ending.is_ended())
            .map(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "the client certificate of this connection was revoked",
                )
            })
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Revocable<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(revoked) = self.revoked() {
            return Poll::Ready(Err(revoked));
        }
        let read = Pin::new(&mut self.inner).poll_read(context, buffer);
        if read.is_pending()
            && let Some(holding) = &self.holding
        {
            if let Ok(mut reader) = holding.ending.reader.lock() {
                *reader = Some(context.waker().clone());
            }
            // Ended between the check above and the waker stored: seen now, not lost.
            if let Some(revoked) = self.revoked() {
                return Poll::Ready(Err(revoked));
            }
        }

        read
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Revocable<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(revoked) = self.revoked() {
            return Poll::Ready(Err(revoked));
        }

        Pin::new(&mut self.inner).poll_write(context, bytes)
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
        if let Some(revoked) = self.revoked() {
            return Poll::Ready(Err(revoked));
        }

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

    #[test]
    fn a_connection_leaves_the_record_when_it_goes() {
        let held = Arc::new(Held::default());
        let first = held.hold(vec![CertificateDer::from(vec![1u8])]);
        let second = held.hold(vec![CertificateDer::from(vec![2u8])]);
        assert_eq!(held.len(), 2);
        drop(first);
        assert_eq!(held.len(), 1);
        drop(second);
        assert_eq!(held.len(), 0);
    }

    #[tokio::test]
    async fn an_ended_connection_fails_its_pending_read_at_once() {
        use tokio::io::AsyncReadExt as _;

        let held = Arc::new(Held::default());
        let holding = held.hold(vec![CertificateDer::from(vec![1u8])]);
        let ending = Arc::clone(&holding.ending);
        let (client, _server) = tokio::io::duplex(64);
        let mut stream = Revocable::new(client, Some(holding));

        let reading = tokio::spawn(async move {
            let mut buffer = [0u8; 8];
            stream.read(&mut buffer).await
        });
        tokio::task::yield_now().await;
        ending.end();
        let read = tokio::time::timeout(std::time::Duration::from_secs(2), reading)
            .await
            .expect("the read wakes")
            .expect("joined");
        assert_eq!(
            read.expect_err("the read fails").kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
