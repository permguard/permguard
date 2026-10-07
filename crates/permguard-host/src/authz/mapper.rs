// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The credential mapper: from what the transport authenticated to one `authorization_principal`
//! (owner decision, 2026-10-06).
//!
//! | Rule                           | Principal                       |
//! | ------------------------------ | ------------------------------- |
//! | `san_uri: <exact URI>`         | the URI, verbatim               |
//! | `spki: sha256:<hex>`           | `spki:sha256:<hex>`             |
//! | `oidc: {issuer, audience, …}`  | `oidc:<issuer>#<claim value>`   |
//! | the bootstrap fingerprint      | `cert:sha256:<fingerprint>`     |
//!
//! A certificate's common name and distinguished name are labels and map nothing. A credential
//! that matches no rule is unauthenticated, whatever the public grants say. Two rules that
//! collapse to one identifier fail startup, and no rule may produce the reserved `anonymous`.
//!
//! Order, when a request carries more than one credential: a mapped certificate wins and any
//! bearer token goes unread; an unmapped certificate beside a bearer token lets the token decide,
//! since the holder of a stranger's certificate who also holds a verifiable token is that token's
//! subject; a certificate with several URI names takes the first, in certificate order, that a
//! rule names. A digest rule reads `sha256:<hex>` and bare `<hex>` alike, case-insensitively.

use std::collections::BTreeMap;
use std::fmt;

use permguard_core::authz::{ANONYMOUS, Actor, ActorContext, Authenticator, Credential, Principal};
use permguard_core::{AccessDenial, PeerIdentity};

use super::oidc::{OidcRule, Verifier};

/// One rule of `host.principals[]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    /// An mTLS certificate carrying exactly this URI among its subject alternative names.
    SanUri(String),
    /// An mTLS certificate whose subject public key info hashes to this, as `sha256:<hex>`.
    Spki(String),
    /// A bearer token from a pinned OIDC issuer.
    Oidc(OidcRule),
}

/// Why the mapper did not build: a configuration mistake, named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapperError {
    /// Two rules produce one identifier.
    Collision {
        principal: String,
        first: String,
        second: String,
    },
    /// A rule that is not one: an empty URI, a malformed digest, the reserved principal.
    Invalid(String),
    /// An OIDC rule whose key set could not be read.
    Keys(String),
}

impl fmt::Display for MapperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Collision {
                principal,
                first,
                second,
            } => write!(
                f,
                "two credential rules collapse to the principal `{principal}`: {first} and {second}"
            ),
            Self::Invalid(detail) => f.write_str(detail),
            Self::Keys(detail) => write!(f, "an OIDC key set could not be read: {detail}"),
        }
    }
}

impl std::error::Error for MapperError {}

/// The mapper, built once from the configuration.
pub struct PrincipalMapper {
    san_uris: BTreeMap<String, Principal>,
    spki: BTreeMap<String, Principal>,
    certificates: BTreeMap<String, Principal>,
    oidc: Vec<Verifier>,
}

impl fmt::Debug for PrincipalMapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrincipalMapper")
            .field("san_uris", &self.san_uris.len())
            .field("spki", &self.spki.len())
            .field("certificates", &self.certificates.len())
            .field("oidc", &self.oidc.len())
            .finish()
    }
}

impl PrincipalMapper {
    /// Builds the mapper from `rules`, plus the bootstrap commitment's fingerprint when the
    /// store holds one. Every identifier is checked for validity and against every other. Token
    /// expiry reads the operating system's clocks through a guard of its own; a server hands its
    /// Host's guard with [`PrincipalMapper::with_time`].
    pub fn new(rules: &[Rule], bootstrap_fingerprint: Option<&str>) -> Result<Self, MapperError> {
        Self::with_time(
            rules,
            bootstrap_fingerprint,
            std::sync::Arc::new(crate::time::TimeGuard::system(
                permguard_core::config::DEFAULT_TIME_MAX_CLOCK_SKEW,
            )),
        )
    }

    /// [`PrincipalMapper::new`], with token expiry and key-set staleness read from `time`
    /// (WP-2.12).
    pub fn with_time(
        rules: &[Rule],
        bootstrap_fingerprint: Option<&str>,
        time: std::sync::Arc<crate::time::TimeGuard>,
    ) -> Result<Self, MapperError> {
        let mut seen: BTreeMap<Principal, String> = BTreeMap::new();
        let mut claim = |principal: Principal, rule: String| -> Result<(), MapperError> {
            if principal.as_str() == ANONYMOUS {
                return Err(MapperError::Invalid(format!(
                    "{rule} maps to the reserved principal `{ANONYMOUS}`"
                )));
            }
            if let Some(first) = seen.get(&principal) {
                return Err(MapperError::Collision {
                    principal: principal.to_string(),
                    first: first.clone(),
                    second: rule,
                });
            }
            seen.insert(principal, rule);
            Ok(())
        };
        let mut san_uris = BTreeMap::new();
        let mut spki = BTreeMap::new();
        let mut certificates = BTreeMap::new();
        let mut oidc = Vec::new();
        for (position, rule) in rules.iter().enumerate() {
            match rule {
                Rule::SanUri(uri) => {
                    let uri = uri.trim();
                    if uri.is_empty() || !uri.contains(':') {
                        return Err(MapperError::Invalid(format!(
                            "host.principals[{position}].san_uri `{uri}` is not a URI"
                        )));
                    }
                    let principal = Principal::new(uri).map_err(|error| {
                        MapperError::Invalid(format!(
                            "host.principals[{position}].san_uri: {error}"
                        ))
                    })?;
                    claim(
                        principal.clone(),
                        format!("host.principals[{position}].san_uri"),
                    )?;
                    san_uris.insert(uri.to_owned(), principal);
                }
                Rule::Spki(digest) => {
                    let hex = digest_hex(digest).ok_or_else(|| {
                        MapperError::Invalid(format!(
                            "host.principals[{position}].spki `{digest}` is not `sha256:<64 hex>`"
                        ))
                    })?;
                    let principal = Principal::new(format!("spki:sha256:{hex}"))
                        .map_err(|error| MapperError::Invalid(error.to_string()))?;
                    claim(
                        principal.clone(),
                        format!("host.principals[{position}].spki"),
                    )?;
                    spki.insert(hex, principal);
                }
                Rule::Oidc(rule) => {
                    let verifier =
                        Verifier::new(rule.clone(), position, std::sync::Arc::clone(&time))?;
                    // Every subject of the issuer shares one prefix; two rules on one issuer
                    // and claim would both produce it, so the prefix is what collides.
                    claim(
                        Principal::new(verifier.principal_prefix())
                            .map_err(|error| MapperError::Invalid(error.to_string()))?,
                        format!("host.principals[{position}].oidc"),
                    )?;
                    oidc.push(verifier);
                }
            }
        }
        if let Some(fingerprint) = bootstrap_fingerprint {
            let hex = digest_hex(fingerprint).ok_or_else(|| {
                MapperError::Invalid(format!(
                    "the bootstrap fingerprint `{fingerprint}` is not `sha256:<64 hex>`"
                ))
            })?;
            let principal = Principal::new(format!("cert:sha256:{hex}"))
                .map_err(|error| MapperError::Invalid(error.to_string()))?;
            claim(principal.clone(), "the bootstrap commitment".to_owned())?;
            certificates.insert(hex, principal);
        }
        Ok(Self {
            san_uris,
            spki,
            certificates,
            oidc,
        })
    }

    /// A mapper with no rules: every credential is unmapped, nobody is anonymous.
    pub fn empty() -> Self {
        Self {
            san_uris: BTreeMap::new(),
            spki: BTreeMap::new(),
            certificates: BTreeMap::new(),
            oidc: Vec::new(),
        }
    }

    /// How many rules the mapper holds, the bootstrap included.
    pub fn rules(&self) -> usize {
        self.san_uris.len() + self.spki.len() + self.certificates.len() + self.oidc.len()
    }

    fn map_peer(&self, peer: &PeerIdentity) -> Option<ActorContext> {
        let display = Some(peer.label().to_owned());
        for uri in peer.san_uris() {
            if let Some(principal) = self.san_uris.get(uri) {
                return Some(ActorContext::new(
                    principal.clone(),
                    Credential::SanUri,
                    display,
                ));
            }
        }
        if let Some(principal) = peer
            .spki_sha256()
            .and_then(|digest| self.spki.get(&digest.to_ascii_lowercase()))
        {
            return Some(ActorContext::new(
                principal.clone(),
                Credential::Spki,
                display,
            ));
        }
        if let Some(principal) = self
            .certificates
            .get(&peer.fingerprint().to_ascii_lowercase())
        {
            return Some(ActorContext::new(
                principal.clone(),
                Credential::Certificate,
                display,
            ));
        }
        None
    }
}

impl Authenticator for PrincipalMapper {
    fn authenticate(
        &self,
        peer: Option<&PeerIdentity>,
        bearer: Option<&str>,
    ) -> Result<Actor, AccessDenial> {
        if let Some(peer) = peer {
            if let Some(context) = self.map_peer(peer) {
                return Ok(Actor::Authenticated(context));
            }
            if bearer.is_none() {
                return Ok(Actor::Unmapped {
                    reason: format!(
                        "certificate sha256:{} with {} URI name(s) matches no rule",
                        peer.fingerprint(),
                        peer.san_uris().len()
                    ),
                });
            }
        }
        if let Some(token) = bearer {
            if self.oidc.is_empty() {
                return Err(AccessDenial::unauthenticated(
                    "this deployment accepts no bearer token",
                ));
            }
            let mut last = None;
            for verifier in &self.oidc {
                match verifier.verify(token) {
                    Ok(Some(context)) => return Ok(Actor::Authenticated(context)),
                    Ok(None) => {}
                    Err(denial) => last = Some(denial),
                }
            }
            return Err(last.unwrap_or_else(|| {
                AccessDenial::unauthenticated("the bearer token names no configured issuer")
            }));
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

    fn peer(uris: &[&str], spki: &str, fingerprint: &str) -> PeerIdentity {
        PeerIdentity::new(
            "CN=billing,O=Acme",
            Some("billing".to_owned()),
            fingerprint,
            "01",
        )
        .with_san_uris(uris.iter().map(|uri| (*uri).to_owned()).collect())
        .with_spki_sha256(spki)
    }

    #[test]
    fn a_san_uri_maps_verbatim_and_a_common_name_maps_nothing() {
        let mapper =
            PrincipalMapper::new(&[Rule::SanUri("spiffe://acme/billing".to_owned())], None)
                .expect("builds");
        let actor = mapper
            .authenticate(
                Some(&peer(
                    &["spiffe://acme/billing"],
                    &"00".repeat(32),
                    &"11".repeat(32),
                )),
                None,
            )
            .expect("answers");
        let Actor::Authenticated(context) = actor else {
            panic!("authenticated");
        };
        assert_eq!(
            context.authorization_principal().as_str(),
            "spiffe://acme/billing"
        );
        assert_eq!(context.credential(), Credential::SanUri);
        assert_eq!(context.display(), Some("billing"));
        // The same common name, another URI: a stranger.
        let stranger = mapper
            .authenticate(
                Some(&peer(
                    &["spiffe://acme/people"],
                    &"00".repeat(32),
                    &"11".repeat(32),
                )),
                None,
            )
            .expect("answers");
        assert!(matches!(stranger, Actor::Unmapped { .. }));
        assert_eq!(stranger.without_grant().http_status(), 401);
    }

    #[test]
    fn a_pinned_key_and_the_bootstrap_fingerprint_map_and_nothing_presented_is_anonymous() {
        let mapper = PrincipalMapper::new(
            &[Rule::Spki(format!("sha256:{}", "AA".repeat(32)))],
            Some(&"bb".repeat(32)),
        )
        .expect("builds");
        let by_key = mapper
            .authenticate(Some(&peer(&[], &"aa".repeat(32), &"cc".repeat(32))), None)
            .expect("answers");
        assert!(
            matches!(by_key, Actor::Authenticated(context) if context.authorization_principal().as_str() == format!("spki:sha256:{}", "aa".repeat(32)))
        );
        let by_fingerprint = mapper
            .authenticate(Some(&peer(&[], &"00".repeat(32), &"BB".repeat(32))), None)
            .expect("answers");
        assert!(
            matches!(by_fingerprint, Actor::Authenticated(context) if context.credential() == Credential::Certificate)
        );
        assert_eq!(
            mapper.authenticate(None, None).expect("answers"),
            Actor::Anonymous
        );
        assert!(
            mapper.authenticate(None, Some("eyJ...")).is_err(),
            "no issuer, no bearer"
        );
    }

    #[test]
    fn colliding_rules_and_the_reserved_principal_fail_startup() {
        let collision = PrincipalMapper::new(
            &[
                Rule::Spki(format!("sha256:{}", "aa".repeat(32))),
                Rule::Spki("AA".repeat(32)),
            ],
            None,
        );
        assert!(matches!(collision, Err(MapperError::Collision { .. })));
        assert!(matches!(
            PrincipalMapper::new(&[Rule::SanUri("anonymous".to_owned())], None),
            Err(MapperError::Invalid(_))
        ));
        assert!(matches!(
            PrincipalMapper::new(&[Rule::Spki("sha256:zz".to_owned())], None),
            Err(MapperError::Invalid(_))
        ));
        assert!(matches!(
            PrincipalMapper::new(&[Rule::SanUri("spiffe://acme/x".to_owned())], Some("bad")),
            Err(MapperError::Invalid(_))
        ));
    }
}
