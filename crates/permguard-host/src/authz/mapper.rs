// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The certificate mapper: the one certificate a Host maps to a principal, its bootstrap's.
//!
//! | Credential                     | Principal                       |
//! | ------------------------------ | ------------------------------- |
//! | the bootstrap fingerprint      | `cert:sha256:<fingerprint>`     |
//!
//! Every other caller is an access token of the Authority Plane, which the token authenticator
//! in front of this one decides, or anonymous. A certificate's common name and distinguished name
//! are labels and map nothing; a certificate that is not the bootstrap's, presented without a
//! token, is unauthenticated, whatever the public grants say. A digest reads `sha256:<hex>` and
//! bare `<hex>` alike, case-insensitively.

use std::fmt;

use permguard_core::authz::{Actor, ActorContext, Authenticator, Credential, Principal};
use permguard_core::{AccessDenial, PeerIdentity};

/// Why the mapper did not build: a configuration mistake, named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapperError {
    /// A fingerprint that is not one.
    Invalid(String),
}

impl fmt::Display for MapperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(detail) => f.write_str(detail),
        }
    }
}

impl std::error::Error for MapperError {}

/// The mapper, built once from the bootstrap commitment.
#[derive(Default)]
pub struct PrincipalMapper {
    /// The bootstrap certificate's fingerprint in lowercase hex, and its principal.
    bootstrap: Option<(String, Principal)>,
}

impl fmt::Debug for PrincipalMapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrincipalMapper")
            .field("bootstrap", &self.bootstrap.is_some())
            .finish()
    }
}

impl PrincipalMapper {
    /// Builds the mapper from the bootstrap commitment's fingerprint, when the store holds one.
    pub fn new(bootstrap_fingerprint: Option<&str>) -> Result<Self, MapperError> {
        let bootstrap = bootstrap_fingerprint
            .map(|fingerprint| {
                let hex = digest_hex(fingerprint).ok_or_else(|| {
                    MapperError::Invalid(format!(
                        "the bootstrap fingerprint `{fingerprint}` is not `sha256:<64 hex>`"
                    ))
                })?;
                let principal = Principal::new(format!("cert:sha256:{hex}"))
                    .map_err(|error| MapperError::Invalid(error.to_string()))?;
                Ok((hex, principal))
            })
            .transpose()?;
        Ok(Self { bootstrap })
    }

    /// A mapper with no bootstrap: every certificate is unmapped, nobody is anonymous.
    pub fn empty() -> Self {
        Self::default()
    }

    /// How many certificates the mapper maps: the bootstrap's, or none.
    pub fn rules(&self) -> usize {
        usize::from(self.bootstrap.is_some())
    }

    fn map_peer(&self, peer: &PeerIdentity) -> Option<ActorContext> {
        let (hex, principal) = self.bootstrap.as_ref()?;
        (peer.fingerprint().eq_ignore_ascii_case(hex)).then(|| {
            ActorContext::new(
                principal.clone(),
                Credential::Certificate,
                Some(peer.label().to_owned()),
            )
        })
    }
}

impl Authenticator for PrincipalMapper {
    fn authenticate(
        &self,
        peer: Option<&PeerIdentity>,
        bearer: Option<&str>,
    ) -> Result<Actor, AccessDenial> {
        if bearer.is_some() {
            return Err(AccessDenial::unauthenticated(
                "this surface holds no key set of the Authority Plane to verify a bearer token with",
            ));
        }
        if let Some(peer) = peer {
            if let Some(context) = self.map_peer(peer) {
                return Ok(Actor::Authenticated(context));
            }
            return Ok(Actor::Unmapped {
                reason: format!(
                    "certificate sha256:{} is not the bootstrap principal's",
                    peer.fingerprint()
                ),
            });
        }
        Ok(Actor::Anonymous)
    }
}

/// The 64 lowercase hex characters of a `sha256:<hex>` or bare `<hex>` digest.
pub(crate) fn digest_hex(text: &str) -> Option<String> {
    let text = text.trim().to_ascii_lowercase();
    let hex = text.strip_prefix("sha256:").unwrap_or(&text);
    (hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit())).then(|| hex.to_owned())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn peer(fingerprint: &str) -> PeerIdentity {
        PeerIdentity::new(
            "CN=operator,O=Acme",
            Some("operator".to_owned()),
            fingerprint,
            "01",
        )
    }

    #[test]
    fn the_bootstrap_fingerprint_maps_and_nothing_presented_is_anonymous() {
        let mapper =
            PrincipalMapper::new(Some(&format!("sha256:{}", "BB".repeat(32)))).expect("builds");
        assert_eq!(mapper.rules(), 1);
        let actor = mapper
            .authenticate(Some(&peer(&"bb".repeat(32))), None)
            .expect("answers");
        let Actor::Authenticated(context) = actor else {
            panic!("authenticated");
        };
        assert_eq!(
            context.authorization_principal().as_str(),
            format!("cert:sha256:{}", "bb".repeat(32))
        );
        assert_eq!(context.credential(), Credential::Certificate);
        assert_eq!(context.display(), Some("operator"));
        let stranger = mapper
            .authenticate(Some(&peer(&"cc".repeat(32))), None)
            .expect("answers");
        assert!(matches!(stranger, Actor::Unmapped { .. }));
        assert_eq!(stranger.without_grant().http_status(), 401);
        assert_eq!(
            mapper.authenticate(None, None).expect("answers"),
            Actor::Anonymous
        );
        assert!(
            mapper.authenticate(None, Some("eyJ...")).is_err(),
            "a bearer is the token authenticator's"
        );
        assert!(PrincipalMapper::new(Some("nonsense")).is_err());
        assert_eq!(PrincipalMapper::empty().rules(), 0);
    }
}
