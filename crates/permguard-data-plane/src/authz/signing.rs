// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The signed native decision response (WP-6.6b, `3-data-plane/2-data-plane-pdp.md`).
//!
//! ```text
//! request_nonce + authenticated audience
//!   ─▶ decided, recorded ─▶ Payload { request and response digests, policy state, evidence,
//!                                     issued_at, expires_at }
//!   ─▶ JCS bytes ─▶ the Host's `Signer<DecisionResponseV1>` over `data.attest`
//!   ─▶ `attestation` {protected, payload, signature}
//! ```
//!
//! The Plane hands the Host a payload and never a `sign(bytes)`: the protected header, the
//! signing input and the key are the Host's. Local key or HSM only: nothing here reaches the
//! network, and a signer that cannot sign refuses the answer rather than send it unsigned.

use std::sync::Arc;
use std::time::Duration;

use permguard_languages::attestation::Attestation;

/// What signs a response's payload bytes, and the time it is signed at.
pub trait ResponseSigner: Send + Sync {
    /// Signs `payload`, the payload's JCS bytes, as a `permguard.decision.response.v1` JWS.
    fn sign(&self, payload: &[u8]) -> Result<Attestation, String>;

    /// The time a response signed now carries, epoch seconds.
    fn now(&self) -> i64;

    /// Whether a response could be signed now, asked before anything is decided or recorded.
    fn ready(&self) -> Result<(), String> {
        Ok(())
    }
}

impl ResponseSigner
    for permguard_host::composition::Signer<permguard_host::composition::DecisionResponseV1>
{
    fn sign(&self, payload: &[u8]) -> Result<Attestation, String> {
        let parts = permguard_host::composition::Signer::sign(
            self,
            &permguard_host::composition::Jws::<permguard_host::composition::DecisionResponseV1>::new(
                payload,
            ),
        )
        .map_err(|error| error.to_string())?;
        Ok(Attestation {
            protected: parts.protected,
            payload: parts.payload,
            signature: parts.signature,
        })
    }

    fn now(&self) -> i64 {
        self.signing_time()
    }

    /// The clock trusted and a key active, as signing will require.
    fn ready(&self) -> Result<(), String> {
        permguard_host::composition::Signer::ready(self).map_err(|error| error.to_string())
    }
}

/// Response signing, as this plane offers it.
#[derive(Clone)]
pub struct ResponseSigning {
    pub signer: Arc<dyn ResponseSigner>,
    /// The lifetime every signed response is given, and discovery publishes.
    pub validity: Duration,
    /// The clock skew discovery tells a verifier to allow.
    pub clock_skew: Duration,
}

impl std::fmt::Debug for ResponseSigning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseSigning")
            .field("validity", &self.validity)
            .field("clock_skew", &self.clock_skew)
            .finish_non_exhaustive()
    }
}

/// Who asks for a signature, as the transport authenticated them, and the request digest taken
/// before the transport filled anything into the body. A request with no nonce asks for nothing;
/// one with a nonce from nobody authenticated is refused `401` where this plane signs, since the
/// audience is the authenticated principal or there is none.
pub fn asker(
    actor: &permguard_core::authz::Actor,
    request: &permguard_languages::CheckRequest,
    signing: Option<&ResponseSigning>,
) -> Result<super::decide::Asker, permguard_core::AccessDenial> {
    if request.request_nonce.is_none() {
        return Ok(super::decide::Asker::default());
    }
    let audience = match actor {
        permguard_core::authz::Actor::Authenticated(context) => {
            Some(context.authorization_principal().as_str().to_owned())
        }
        _ => None,
    };
    if audience.is_none() && signing.is_some() {
        return Err(permguard_core::AccessDenial::unauthenticated(
            "a signed response is addressed to an authenticated caller, and this request has none",
        ));
    }
    Ok(super::decide::Asker::of(audience, request))
}
