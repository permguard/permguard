// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a surface refuses to spend on any one client.
//!
//! A server with no limits is not neutral about abuse — it is on the attacker's side. Every one of
//! these bounds a resource that is otherwise unbounded, and each answers a different way of taking a
//! process down without a single valid request:
//!
//! | | what it bounds | what it stops |
//! | --- | --- | --- |
//! | `connections` | sockets held at once | opening thousands and leaving them |
//! | `handshake_timeout` | time spent before TLS finishes | starting a handshake and never finishing it |
//! | `header_timeout` | time spent sending a request head | sending a header a byte at a time |
//! | `request_timeout` | time spent serving one request | a handler, or a body, that never ends |
//! | `concurrent_requests` | requests in flight | arriving faster than they can be served |
//! | `body_bytes` | bytes read from one body | announcing a megabyte and sending a gigabyte |
//! | `connections_per_peer` | sockets held by one address | one client occupying the whole pool |
//! | `header_bytes` | bytes of one request head | a header stuffed until memory notices |
//! | `connection_lifetime` | how long one socket may exist | a connection becoming permanent |
//! | `write_stall_timeout` | a response making no progress | a client that stops reading its answer |
//!
//! None of them is a rate limiter, and that is deliberate: rate limiting needs to know who a client
//! *is* over time, which is a decision about identity rather than about resources, and belongs in
//! front of this — in an ingress, or in a build that has a notion of tenant.
//!
//! # Why one set rather than one per surface
//!
//! The same reason the reload cadence is one setting: three copies of five numbers is three chances
//! to set two of them. The surfaces do have different profiles — the public one faces the world and
//! the administrative one faces a handful of named operators — but a single set of defensible
//! defaults beats a per-surface scheme nobody fills in.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

/// How many sockets one surface will hold at once.
///
/// Each one costs a task, a TLS session and its buffers. A thousand is far above what this product
/// sees and far below what a machine notices.
const DEFAULT_CONNECTIONS: u32 = 1_024;

/// How many of one surface's sockets a single address may hold.
///
/// The pool limit alone has a failure mode the pool cannot see: one client opening `connections`
/// sockets and sitting on them takes the surface away from everybody else while every global number
/// still reads as healthy. A quarter of the pool is room enough for any legitimate client — including
/// a NAT with hundreds of users behind it — while leaving three quarters that one address cannot
/// touch.
///
/// Zero disables it. Behind a load balancer the address seen here is the balancer's, so the cap
/// becomes a de-facto global one: there, either exempt the balancer with `peer_exempt` or disable
/// this and let the ingress do the counting.
const DEFAULT_CONNECTIONS_PER_PEER: u32 = 256;

/// How long a write may sit without moving a byte before the client is given up on.
///
/// The request path is bounded end to end, but a *response* is written into the peer's TCP window,
/// and a peer that stops reading stalls it forever — the mirror image of slowloris, on the way out.
/// Thirty seconds of zero progress is not a slow link; it is a client that is not there.
const DEFAULT_WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(30);

/// How many requests one surface will have in flight at once.
///
/// Beyond this a request is refused rather than queued: a queue under overload is a way of failing
/// slowly for everybody instead of quickly for the requests that could not be served anyway.
const DEFAULT_CONCURRENT_REQUESTS: u32 = 256;

/// How long one request may take before it is given up on.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a client has to finish a TLS handshake.
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a client has to send a complete request head.
///
/// This is the one that answers slowloris: a client that sends `GET / HTTP/1.1` one byte a minute
/// never reaches a handler, so nothing a handler is wrapped in can time it out. Only the connection
/// limit would bound it, and a thousand sockets is nothing to spend.
const DEFAULT_HEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// How many bytes one request head may carry.
///
/// Sixty-four kilobytes holds any legitimate set of headers several times over — a large JWT, a
/// tracing baggage, a cookie jar — and turns "the biggest head a client can make us buffer" from a
/// number in hyper's documentation into a number of ours, with a test on it.
const DEFAULT_HEADER_BYTES: usize = 64 * 1024;

/// How many bytes one request body may carry.
///
/// A megabyte, which is orders of magnitude more than anything here reads: the discovery documents
/// take no body at all, and an administrative RPC carries a few hundred bytes.
const DEFAULT_BODY_BYTES: usize = 1024 * 1024;

/// The bounds every surface serves within.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    connections: u32,
    connections_per_peer: u32,
    peer_exempt: Vec<PeerBlock>,
    concurrent_requests: u32,
    request_timeout: Duration,
    handshake_timeout: Duration,
    header_timeout: Duration,
    header_bytes: usize,
    body_bytes: usize,
    connection_lifetime: Option<Duration>,
    write_stall_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connections: DEFAULT_CONNECTIONS,
            connections_per_peer: DEFAULT_CONNECTIONS_PER_PEER,
            peer_exempt: Vec::new(),
            concurrent_requests: DEFAULT_CONCURRENT_REQUESTS,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            header_timeout: DEFAULT_HEADER_TIMEOUT,
            header_bytes: DEFAULT_HEADER_BYTES,
            body_bytes: DEFAULT_BODY_BYTES,
            // None, and deliberately: a gRPC channel that legitimately lives for days is normal, and
            // a default that beheads it would be this library deciding a policy the deployment did
            // not ask for. The per-peer cap is what bounds hoarding; this exists for deployments that
            // additionally want connections to rotate — behind a load balancer that needs to
            // rebalance, most commonly.
            connection_lifetime: None,
            write_stall_timeout: DEFAULT_WRITE_STALL_TIMEOUT,
        }
    }
}

impl Limits {
    /// Returns the defaults, which are what a deployment that says nothing gets.
    pub fn new() -> Self {
        Self::default()
    }

    /// Bounds how many sockets one surface holds at once.
    pub fn with_connections(mut self, connections: u32) -> Self {
        self.connections = connections;

        self
    }

    /// Bounds how many sockets a single address may hold. Zero disables the bound.
    pub fn with_connections_per_peer(mut self, connections: u32) -> Self {
        self.connections_per_peer = connections;

        self
    }

    /// Exempts addresses from the per-peer bound. They still count toward the pool.
    pub fn with_peer_exempt(mut self, exempt: Vec<PeerBlock>) -> Self {
        self.peer_exempt = exempt;

        self
    }

    /// Bounds how long one connection may exist, however busy it is. `None` leaves it unbounded.
    pub fn with_connection_lifetime(mut self, lifetime: Option<Duration>) -> Self {
        self.connection_lifetime = lifetime;

        self
    }

    /// Bounds how long a write may make no progress before the client is given up on.
    pub fn with_write_stall_timeout(mut self, timeout: Duration) -> Self {
        self.write_stall_timeout = timeout;

        self
    }

    /// Bounds how many requests one surface has in flight at once.
    pub fn with_concurrent_requests(mut self, requests: u32) -> Self {
        self.concurrent_requests = requests;

        self
    }

    /// Bounds how long one request may take.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;

        self
    }

    /// Bounds how long a client has to finish a TLS handshake.
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;

        self
    }

    /// Bounds how long a client has to send a complete request head.
    pub fn with_header_timeout(mut self, timeout: Duration) -> Self {
        self.header_timeout = timeout;

        self
    }

    /// Bounds how many bytes one request head may carry.
    pub fn with_header_bytes(mut self, bytes: usize) -> Self {
        self.header_bytes = bytes;

        self
    }

    /// Bounds how many bytes one request body may carry.
    pub fn with_body_bytes(mut self, bytes: usize) -> Self {
        self.body_bytes = bytes;

        self
    }

    /// Returns how many sockets one surface holds at once.
    pub fn connections(&self) -> u32 {
        self.connections
    }

    /// Returns how many sockets a single address may hold, zero meaning unbounded.
    pub fn connections_per_peer(&self) -> u32 {
        self.connections_per_peer
    }

    /// Returns the addresses exempt from the per-peer bound.
    pub fn peer_exempt(&self) -> &[PeerBlock] {
        &self.peer_exempt
    }

    /// Returns whether `address` is exempt from the per-peer bound.
    pub fn is_peer_exempt(&self, address: IpAddr) -> bool {
        self.peer_exempt.iter().any(|block| block.contains(address))
    }

    /// Returns how long one connection may exist, when that is bounded at all.
    pub fn connection_lifetime(&self) -> Option<Duration> {
        self.connection_lifetime
    }

    /// Returns how long a write may make no progress.
    pub fn write_stall_timeout(&self) -> Duration {
        self.write_stall_timeout
    }

    /// Returns how many requests one surface has in flight at once.
    pub fn concurrent_requests(&self) -> u32 {
        self.concurrent_requests
    }

    /// Returns how long one request may take.
    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// Returns how long a client has to finish a TLS handshake.
    pub fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    /// Returns how long a client has to send a complete request head.
    pub fn header_timeout(&self) -> Duration {
        self.header_timeout
    }

    /// Returns how many bytes one request head may carry.
    pub fn header_bytes(&self) -> usize {
        self.header_bytes
    }

    /// Returns how many bytes one request body may carry.
    pub fn body_bytes(&self) -> usize {
        self.body_bytes
    }
}

/// One address, or a block of them: `10.7.0.4`, `10.0.0.0/8`, `::1`, `fd00::/8`.
///
/// Std-only on purpose — this crate's dependency list is a contract — and the matching is the only
/// thing a prefix is: the first `prefix` bits, compared. An IPv4 block never matches an IPv6 address
/// or the other way round, because 10.0.0.0/8 saying something about `::a00:0` helps nobody.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerBlock {
    address: IpAddr,
    prefix: u8,
}

impl PeerBlock {
    /// Returns whether `address` is inside this block.
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(block), IpAddr::V4(candidate)) => {
                let width = u32::from(self.prefix);
                let mask = if width == 0 {
                    0
                } else {
                    u32::MAX << (32 - width)
                };

                u32::from(block) & mask == u32::from(candidate) & mask
            }
            (IpAddr::V6(block), IpAddr::V6(candidate)) => {
                let width = u32::from(self.prefix);
                let mask = if width == 0 {
                    0
                } else {
                    u128::MAX << (128 - width)
                };

                u128::from(block) & mask == u128::from(candidate) & mask
            }
            _ => false,
        }
    }
}

impl FromStr for PeerBlock {
    type Err = InvalidPeerBlock;

    fn from_str(written: &str) -> Result<Self, Self::Err> {
        let written = written.trim();
        let (address, prefix) = match written.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (written, None),
        };
        let address: IpAddr = address.parse().map_err(|_| InvalidPeerBlock {
            written: written.to_owned(),
            detail: "the address part is not an IP address",
        })?;
        let width = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix = match prefix {
            None => width,
            Some(prefix) => {
                let prefix: u8 = prefix.parse().map_err(|_| InvalidPeerBlock {
                    written: written.to_owned(),
                    detail: "the prefix is not a number",
                })?;

                if prefix > width {
                    return Err(InvalidPeerBlock {
                        written: written.to_owned(),
                        detail: "the prefix is wider than the address",
                    });
                }

                prefix
            }
        };

        Ok(Self { address, prefix })
    }
}

/// Something that is not an address or a block of them, and what is wrong with it.
#[derive(Debug)]
pub struct InvalidPeerBlock {
    written: String,
    detail: &'static str,
}

impl fmt::Display for InvalidPeerBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "`{}` is not an address or an address block: {}",
            self.written, self.detail
        )
    }
}

impl std::error::Error for InvalidPeerBlock {}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn test_a_deployment_that_says_nothing_is_still_bounded() {
        // The property that matters: every one of these has a number, so there is no way to end up
        // with a surface that will hold sockets, or wait, or read, without limit.
        let limits = Limits::new();

        assert!(limits.connections() > 0);
        assert!(limits.connections_per_peer() > 0);
        assert!(limits.write_stall_timeout() > Duration::ZERO);
        assert!(limits.concurrent_requests() > 0);
        assert!(limits.body_bytes() > 0);
        assert!(limits.header_bytes() > 0);
        assert!(limits.request_timeout() > Duration::ZERO);
        assert!(limits.handshake_timeout() > Duration::ZERO);
        assert!(limits.header_timeout() > Duration::ZERO);
    }

    #[test]
    fn test_the_handshake_is_given_less_time_than_the_request_it_precedes() {
        // A handshake that may take as long as a whole request is a handshake an attacker can hold
        // open for as long as a request, for a fraction of the effort.
        let limits = Limits::new();

        assert!(limits.handshake_timeout() < limits.request_timeout());
        assert!(limits.header_timeout() < limits.request_timeout());
    }

    #[test]
    fn test_one_peer_cannot_hold_the_whole_pool_by_default() {
        // The property the per-peer bound exists for. If a default change ever breaks it, the pool
        // limit goes back to being something one client can spend alone.
        let limits = Limits::new();

        assert!(limits.connections_per_peer() < limits.connections());
    }

    #[test]
    fn test_a_block_contains_what_it_says_and_nothing_else() {
        let block: PeerBlock = "10.0.0.0/8".parse().expect("a valid block");

        assert!(block.contains("10.255.1.2".parse().expect("an address")));
        assert!(!block.contains("11.0.0.1".parse().expect("an address")));
        // The other family is never a match, whatever the bits say.
        assert!(!block.contains("::a00:0".parse().expect("an address")));

        let single: PeerBlock = "192.168.1.5".parse().expect("a bare address is a /32");

        assert!(single.contains("192.168.1.5".parse().expect("an address")));
        assert!(!single.contains("192.168.1.6".parse().expect("an address")));

        let six: PeerBlock = "fd00::/8".parse().expect("a valid v6 block");

        assert!(six.contains("fd12::1".parse().expect("an address")));
        assert!(!six.contains("fe80::1".parse().expect("an address")));

        let everything: PeerBlock = "0.0.0.0/0".parse().expect("the whole of v4");

        assert!(everything.contains("203.0.113.7".parse().expect("an address")));
    }

    #[test]
    fn test_what_is_not_a_block_is_refused() {
        for written in [
            "",
            "10.0.0.0/33",
            "::1/129",
            "10.0.0.0/x",
            "not-an-ip",
            "10.0.0.0/8/9",
        ] {
            assert!(
                written.parse::<PeerBlock>().is_err(),
                "accepted {written:?}"
            );
        }
    }

    #[test]
    fn test_exemption_is_matched_through_the_limits() {
        let limits =
            Limits::new().with_peer_exempt(vec!["127.0.0.0/8".parse().expect("a valid block")]);

        assert!(limits.is_peer_exempt("127.0.0.1".parse().expect("an address")));
        assert!(!limits.is_peer_exempt("10.0.0.1".parse().expect("an address")));
    }

    #[test]
    fn test_every_bound_is_settable() {
        let limits = Limits::new()
            .with_connections(1)
            .with_connections_per_peer(7)
            .with_concurrent_requests(2)
            .with_request_timeout(Duration::from_secs(3))
            .with_handshake_timeout(Duration::from_secs(4))
            .with_header_timeout(Duration::from_secs(6))
            .with_connection_lifetime(Some(Duration::from_secs(8)))
            .with_write_stall_timeout(Duration::from_secs(9))
            .with_header_bytes(10)
            .with_body_bytes(5);

        assert_eq!(limits.connections(), 1);
        assert_eq!(limits.connections_per_peer(), 7);
        assert_eq!(limits.connection_lifetime(), Some(Duration::from_secs(8)));
        assert_eq!(limits.write_stall_timeout(), Duration::from_secs(9));
        assert_eq!(limits.header_bytes(), 10);
        assert_eq!(limits.concurrent_requests(), 2);
        assert_eq!(limits.request_timeout(), Duration::from_secs(3));
        assert_eq!(limits.handshake_timeout(), Duration::from_secs(4));
        assert_eq!(limits.header_timeout(), Duration::from_secs(6));
        assert_eq!(limits.body_bytes(), 5);
    }
}
