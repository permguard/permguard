// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Peer Host sessions on the Host listener (WP-2.3): the `IdentityService.PeerChannel` stream
//! gets a [`Responder`] here, or the reason this listener serves none.
//!
//! A peer Host is not an operator: no grant is asked. The channel is admitted by the listener's
//! mutual TLS and `admin.allow`, and the session by the proof and the peer's pin (owner decision
//! of 2026-10-08). The REST `sessions/hello` and `sessions/prove` routes are refused: peer
//! sessions are never independent stateless POSTs.

use serde::{Deserialize, Serialize};

use permguard_core::api::ErrorClass;
use permguard_core::{ChannelBinding, PeerIdentity, PeerSessionsReport, codes};

use super::{HostApi, Refusal};
use crate::session::record::Role;
use crate::session::{Context, Known, Responder};

/// Whether the listener serves peer sessions, as `GET /host/v1/status` answers it: `reason` is
/// always present, `null` when there is nothing to say.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerSessionsView {
    pub served: bool,
    pub reason: Option<String>,
}

impl From<PeerSessionsReport> for PeerSessionsView {
    fn from(report: PeerSessionsReport) -> Self {
        Self {
            served: report.served,
            reason: report.reason.map(str::to_owned),
        }
    }
}

/// What the composition hands the facade for peer sessions.
#[derive(Clone)]
pub struct PeerSessions {
    /// What the configuration amounts to.
    pub report: PeerSessionsReport,
    /// The identity, pins, time and audit a session needs; without an identity, none.
    pub context: Option<Context>,
}

impl PeerSessions {
    /// No peer sessions: no listener serves them.
    pub fn none() -> Self {
        Self {
            report: PeerSessionsReport {
                served: false,
                reason: Some(PeerSessionsReport::NO_LISTENER),
            },
            context: None,
        }
    }
}

fn unserveable(message: impl Into<String>) -> Refusal {
    Refusal::new(
        ErrorClass::Unavailable,
        codes::host::PEER_SESSIONS_UNSERVEABLE,
        message,
    )
}

impl HostApi {
    /// The responder of one `PeerChannel` stream, on a connection that presented `peer`'s
    /// certificate and exported `binding`; refused when the listener serves no peer sessions,
    /// the connection is not mutual TLS 1.3, or no identity is open.
    pub fn peer_responder(
        &self,
        peer: Option<&PeerIdentity>,
        binding: Option<&ChannelBinding>,
    ) -> Result<Responder, Refusal> {
        let sessions = &self.peer_sessions;
        let unserveable = |reason: String| {
            let code = codes::host::PEER_SESSIONS_UNSERVEABLE;
            // Refused before any frame is read, and recorded and counted all the same.
            if let Some(context) = &sessions.context {
                context.refused(
                    Role::Responder,
                    &Known::default(),
                    &crate::session::Refusal {
                        code,
                        reason: reason.clone(),
                    },
                );
            }
            Refusal::new(ErrorClass::Unavailable, code, reason)
        };
        if !sessions.report.served {
            return Err(unserveable(format!(
                "this listener serves no peer sessions: {}",
                sessions.report.reason.unwrap_or("not configured")
            )));
        }
        if peer.is_none() {
            return Err(unserveable(
                "a peer session needs a client certificate on the connection".to_owned(),
            ));
        }
        let Some(binding) = binding else {
            return Err(unserveable(
                "a peer session needs a TLS 1.3 connection, end to end: this one exports no \
                 channel binding"
                    .to_owned(),
            ));
        };
        let Some(context) = &sessions.context else {
            return Err(Refusal::new(
                ErrorClass::Unavailable,
                codes::host::IDENTITY_UNAVAILABLE,
                "no Host identity is open on this process",
            ));
        };
        if context.identity.is_retired() {
            return Err(unserveable(
                "the Host identity was reset: this process proves nothing with it".to_owned(),
            ));
        }
        // One proof exchange authenticates one connection: a second channel on it is refused.
        if !binding.claim() {
            return Err(unserveable(
                "this connection already carried a peer session: one proof exchange \
                 authenticates one connection"
                    .to_owned(),
            ));
        }
        Ok(Responder::new(context.clone(), *binding.exporter()))
    }

    /// `POST /host/v1/sessions/hello` and `…/sessions/prove` over REST: refused, whoever asks.
    /// A session is bound to one connection and runs on the `PeerChannel` stream only (owner
    /// decision of 2026-10-08).
    pub fn session_over_rest(&self) -> Refusal {
        unserveable(
            "peer sessions run on the `permguard.host.v1.IdentityService/PeerChannel` stream, \
             never as separate requests",
        )
    }

    /// Whether the listener serves peer sessions.
    pub fn peer_sessions(&self) -> PeerSessionsView {
        self.peer_sessions.report.into()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::Arc;

    use super::*;
    use crate::api::testing::{facade, reopen, scratch};
    use crate::session::peers::Peers;

    fn refused_with(refusal: Refusal) -> &'static str {
        refusal.error().expect("an error").code()
    }

    fn peer() -> PeerIdentity {
        PeerIdentity::new("CN=peer", Some("peer".to_owned()), "00", "01")
    }

    #[test]
    fn a_listener_that_serves_no_peer_sessions_refuses_the_channel_and_says_why() {
        let api = facade("sessions-none");
        assert_eq!(
            api.peer_sessions(),
            PeerSessionsView {
                served: false,
                reason: Some("no_listener".to_owned())
            }
        );
        let refused = api
            .peer_responder(Some(&peer()), Some(&ChannelBinding::new([1; 32])))
            .err()
            .expect("refused");
        assert_eq!(
            refused_with(refused),
            codes::host::PEER_SESSIONS_UNSERVEABLE
        );
    }

    #[test]
    fn a_served_channel_needs_a_client_certificate_a_binding_and_an_identity() {
        let root = scratch("sessions-served");
        let (mut api, _, volume) = reopen(&root, Vec::new());
        let counted = Arc::new(Refusals::default());
        let served = PeerSessionsReport {
            served: true,
            reason: None,
        };
        let context = Context {
            identity: Arc::clone(api.identity.as_ref().expect("an identity")),
            peers: Arc::new(Peers::open(&volume, &[]).expect("the peers")),
            time: Arc::clone(&api.time),
            declared_assurance: permguard_core::assurance::AssuranceProfile::Development,
            audit: None,
            metrics: permguard_core::Metrics::new(
                Arc::clone(&counted) as Arc<dyn permguard_core::metrics::Recorder>
            ),
            service: None,
        };
        api.peer_sessions = PeerSessions {
            report: served,
            context: Some(context),
        };
        let binding = ChannelBinding::new([1; 32]);
        api.peer_responder(Some(&peer()), Some(&binding))
            .map(|_| ())
            .expect("a responder for a mutual TLS 1.3 connection");
        // One proof exchange per connection: the same binding a second time is refused, and
        // every request of the connection shares it.
        assert_eq!(
            refused_with(
                api.peer_responder(Some(&peer()), Some(&binding.clone()))
                    .err()
                    .expect("a second session on one connection")
            ),
            codes::host::PEER_SESSIONS_UNSERVEABLE
        );
        api.peer_responder(Some(&peer()), Some(&ChannelBinding::new([1; 32])))
            .map(|_| ())
            .expect("another connection, another session");
        for refused in [
            api.peer_responder(None, Some(&binding)).err(),
            api.peer_responder(Some(&peer()), None).err(),
        ] {
            assert_eq!(
                refused_with(refused.expect("refused")),
                codes::host::PEER_SESSIONS_UNSERVEABLE
            );
        }
        // Every refusal at the gate is counted (and recorded) like a refused session: the
        // second channel, the connection without a certificate, the one without a binding.
        assert_eq!(
            *counted.0.lock().expect("the counts"),
            vec![codes::host::PEER_SESSIONS_UNSERVEABLE; 3]
        );
        api.peer_sessions.context = None;
        assert_eq!(
            refused_with(
                api.peer_responder(Some(&peer()), Some(&binding))
                    .err()
                    .expect("refused")
            ),
            codes::host::IDENTITY_UNAVAILABLE
        );
    }

    #[test]
    fn the_rest_session_routes_are_refused() {
        assert_eq!(
            refused_with(facade("sessions-rest").session_over_rest()),
            codes::host::PEER_SESSIONS_UNSERVEABLE
        );
    }

    /// The reason of every refused session counted.
    #[derive(Debug, Default)]
    struct Refusals(std::sync::Mutex<Vec<&'static str>>);

    impl permguard_core::metrics::Recorder for Refusals {
        fn record(
            &self,
            metric: &permguard_core::Metric,
            labels: &[permguard_core::Label<'_>],
            _value: f64,
        ) {
            if metric.name() == crate::session::SESSIONS.name()
                && let Some((_, reason)) = labels.iter().find(|(name, _)| name.as_str() == "reason")
            {
                let reason = codes::all()
                    .into_iter()
                    .map(|(_, code)| code)
                    .find(|code| code == reason)
                    .expect("a registered code");
                self.0.lock().expect("the counts").push(reason);
            }
        }

        fn snapshot(&self) -> Vec<permguard_core::Sample> {
            Vec::new()
        }
    }
}
