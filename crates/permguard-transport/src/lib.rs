// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! One listener for every Permguard surface.
//!
//! The public surface, the administrative surface and telemetry all end up serving an `axum::Router`
//! — gRPC included, because `tonic` can hand its routes over as one. So the part that is easy to get
//! wrong is written once, here, instead of three times: binding, TLS, mutual TLS, revocation,
//! re-reading material that changed, and a shutdown that lets connections in flight finish.
//!
//! # Binding happens before serving
//!
//! The listener is bound synchronously, before any task is spawned. A port that is already taken is
//! then a failure to *start*, reported by the service that could not start — not something a client
//! discovers later by failing to connect.
//!
//! # What TLS means here
//!
//! * a certificate and key make the listener authenticate **itself**;
//! * adding a client authority makes it demand a certificate **back**, and a client that presents
//!   none — or one that authority did not sign — never reaches the application at all;
//! * adding a revocation list makes that authority able to take a certificate back before it
//!   expires, which is the difference between a compromised client being cut off today and being
//!   cut off whenever its certificate happened to run out;
//! * the protocol floor defaults to 1.3, and 1.2 has to be asked for by name.
//!
//! # What revocation is checked against
//!
//! The **client certificate**, and not the authority above it. Revoking an authority is not
//! something a list expresses usefully — it is done by taking the authority out of the bundle this
//! listener trusts, which is a configuration change and takes effect on the next reload. Checking
//! the whole chain instead would mean every issuer in it needs a published, current list, and the
//! failure when one is missing is that every client is refused. That is a worse failure than the one
//! it prevents.
//!
//! # Who the client is
//!
//! A mutual handshake knows exactly which certificate was presented; a request handler, by default,
//! does not. Every connection here carries what it learned into each request as an
//! [`Arc<PeerIdentity>`](permguard_core::PeerIdentity) extension — which is what makes authorisation, as
//! opposed to authentication, possible at all.

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used, clippy::expect_used)]

mod digest;
mod gate;
mod guard;
mod identity;
mod material;
mod measure;
mod reload;
mod request;
mod surface;

pub use digest::digest;
pub use gate::PeerGateLayer;
pub use guard::LimitedAcceptor;
pub use identity::{PeerAcceptor, WithPeer, fingerprint, identity_of};
pub use material::{load_certificates, load_key, load_revocations, server_config};
pub use measure::{
    ACCEPTED, CERTIFICATE_EXPIRY, CONNECTIONS, CRL_EXPIRY, LATENCY, REFUSED, REQUESTS,
};
pub use reload::{Reloaded, reload_all};
pub use request::RequestId;
pub use surface::{Listener, Surface};
