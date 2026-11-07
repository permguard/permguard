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
    Oidc(Box<OidcRule>),
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
    oidc: Vec<std::sync::Arc<Verifier>>,
    /// The local users a session or a provider subject may act as (WP-8.1); none, every
    /// credential maps as before.
    accounts: std::sync::OnceLock<Accounts>,
}

/// What the mapper consults for local users (WP-8.1, `1-architecture/1` Local users and
/// authentication methods).
pub struct Accounts {
    pub directory: std::sync::Arc<super::directory::Directory>,
    /// The password sign-in, when `password` is among the methods.
    pub signin: Option<std::sync::Arc<super::signin::SignIn>>,
    /// Whether `oidc` is among the methods.
    pub oidc: bool,
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
                    // The Host mints these itself, for its roles, local users, providers' subjects and
                    // service accounts: a certificate naming one would act as a role or as somebody
                    // else (WP-8.1), or as a service account without its credential (WP-11.2).
                    if super::directory::is_reserved(uri) {
                        return Err(MapperError::Invalid(format!(
                            "host.principals[{position}].san_uri `{uri}` names a principal the Host reserves"
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
                        Verifier::new((**rule).clone(), position, std::sync::Arc::clone(&time))?;
                    // Every subject of the issuer shares one prefix; two rules on one issuer
                    // and claim would both produce it, so the prefix is what collides.
                    claim(
                        Principal::new(verifier.principal_prefix())
                            .map_err(|error| MapperError::Invalid(error.to_string()))?,
                        format!("host.principals[{position}].oidc"),
                    )?;
                    oidc.push(std::sync::Arc::new(verifier));
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
            accounts: std::sync::OnceLock::new(),
        })
    }

    /// A mapper with no rules: every credential is unmapped, nobody is anonymous.
    pub fn empty() -> Self {
        Self {
            san_uris: BTreeMap::new(),
            spki: BTreeMap::new(),
            certificates: BTreeMap::new(),
            oidc: Vec::new(),
            accounts: std::sync::OnceLock::new(),
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

impl PrincipalMapper {
    /// Lets sessions and linked provider subjects act as local users, and admits only the
    /// methods `accounts` names. Set once, at composition.
    pub fn attach_accounts(&self, accounts: Accounts) {
        let _ = self.accounts.set(accounts);
    }

    /// A verified provider token, as the actor it is: the local user its subject is linked to,
    /// or whose email it verifies when the provider links by email; otherwise its own subject.
    /// A disabled user is refused, never mapped to its subject.
    fn as_user(
        &self,
        verifier: &Verifier,
        verified: super::oidc::Verified,
    ) -> Result<Actor, AccessDenial> {
        let Some(accounts) = self.accounts.get() else {
            return Ok(Actor::Authenticated(verified.context));
        };
        let subject = verified
            .context
            .authorization_principal()
            .as_str()
            .to_owned();
        let user = accounts.directory.user_of_subject(&subject).or_else(|| {
            verifier
                .rule()
                .link_email
                .then(|| {
                    verified
                        .verified_email
                        .as_deref()
                        .and_then(|email| accounts.directory.user_by_email(email))
                })
                .flatten()
        });
        let Some(user) = user else {
            return Ok(Actor::Authenticated(verified.context));
        };
        if user.status != super::directory::UserStatus::Active {
            return Err(AccessDenial::unauthenticated(
                "the local user this token signs in as is disabled",
            ));
        }
        let principal = Principal::new(user.principal())
            .map_err(|error| AccessDenial::unauthenticated(error.to_string()))?;
        Ok(Actor::Authenticated(ActorContext::new(
            principal,
            Credential::Oidc,
            Some(format!("{} ({})", user.name, verifier.name())),
        )))
    }

    /// A password session, as its user.
    fn as_session(&self, token: &str) -> Result<Actor, AccessDenial> {
        let Some(signin) = self
            .accounts
            .get()
            .and_then(|accounts| accounts.signin.as_ref())
        else {
            return Err(AccessDenial::unauthenticated(
                "this deployment admits no password sign-in",
            ));
        };
        let session = signin.session(token).ok_or_else(|| {
            AccessDenial::unauthenticated("the session is not valid: sign in again")
        })?;
        if session.opened == super::sessions::Opened::EnrollFactor {
            return Err(AccessDenial::unauthenticated(
                "this session serves only the enrollment of a second factor",
            ));
        }
        let principal = Principal::new(super::directory::user_principal(&session.user))
            .map_err(|error| AccessDenial::unauthenticated(error.to_string()))?;
        Ok(Actor::Authenticated(ActorContext::new(
            principal,
            Credential::Password,
            Some(session.user),
        )))
    }

    /// The identity providers, in configuration order: what the refresh task fetches for, the
    /// Host API reports and the health report watches.
    pub fn providers(&self) -> Vec<std::sync::Arc<Verifier>> {
        self.oidc.clone()
    }

    /// The provider of this name.
    pub fn provider(&self, name: &str) -> Option<std::sync::Arc<Verifier>> {
        self.oidc
            .iter()
            .find(|verifier| verifier.name() == name)
            .cloned()
    }

    /// Keeps every fetched provider's key set under `host/authz/oidc/` and restores what is kept
    /// there, so a restart without network serves keys still within their `max_stale`.
    pub fn attach_key_cache(
        &self,
        volume: &crate::storage::volume::Volume,
    ) -> Result<(), crate::storage::StorageError> {
        if !self
            .oidc
            .iter()
            .any(|verifier| verifier.rule().keys.is_fetched())
        {
            return Ok(());
        }
        let authz = volume.host().subdir(super::store::DIRECTORY, true)?;
        for verifier in &self.oidc {
            verifier.attach_cache(authz.subdir(super::oidc::CACHE_DIRECTORY, true)?);
        }
        Ok(())
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
            if token.starts_with(super::sessions::TOKEN_PREFIX) {
                return self.as_session(token);
            }
            if self.accounts.get().is_some_and(|accounts| !accounts.oidc) {
                return Err(AccessDenial::unauthenticated(
                    "this deployment admits no identity provider token",
                ));
            }
            if self.oidc.is_empty() {
                return Err(AccessDenial::unauthenticated(
                    "this deployment accepts no bearer token",
                ));
            }
            let mut last = None;
            for verifier in &self.oidc {
                match verifier.verify_token(token) {
                    Ok(Some(verified)) => return self.as_user(verifier, verified),
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

/// Who a request on the Server Host surface acts as: a live password session, enrollment-only
/// sessions included, since the routes that take one decide what it may do; nobody without one.
/// The surface's authentication boundary, so a session token reaches the routes that read it
/// rather than being refused as a credential no rule maps (WP-8.1).
pub struct SessionBearers(pub std::sync::Arc<super::signin::SignIn>);

impl Authenticator for SessionBearers {
    fn authenticate(
        &self,
        _peer: Option<&permguard_core::PeerIdentity>,
        bearer: Option<&str>,
    ) -> Result<Actor, permguard_core::AccessDenial> {
        let Some(token) = bearer else {
            return Ok(Actor::Anonymous);
        };
        let session = self.0.session(token).ok_or_else(|| {
            permguard_core::AccessDenial::unauthenticated("the session is not valid: sign in again")
        })?;
        let principal = Principal::new(super::directory::user_principal(&session.user))
            .map_err(|error| permguard_core::AccessDenial::unauthenticated(error.to_string()))?;
        Ok(Actor::Authenticated(ActorContext::new(
            principal,
            Credential::Password,
            Some(session.user),
        )))
    }
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

        // A certificate never names a principal the Host mints for its roles, users and providers.
        for reserved in [
            "role:admins",
            "user:alice",
            "oidc:https://login.example",
            "spki:sha256:00",
            "sa:billing",
            "SA:billing",
            "Role:admins",
        ] {
            assert!(
                matches!(
                    PrincipalMapper::new(&[Rule::SanUri(reserved.to_owned())], None),
                    Err(MapperError::Invalid(_))
                ),
                "{reserved}"
            );
        }
    }

    #[test]
    fn sessions_and_provider_subjects_act_as_local_users_and_only_the_admitted_methods_sign_in() {
        use super::super::directory::{Change, Directory};
        use super::super::lockout::Lockout;
        use super::super::oidc::{KeySource, OidcRule};
        use super::super::sessions::Sessions;
        use super::super::signin::{Mfa, Policy, SignIn};
        use crate::operations::mutation::{Applying, Mutations};
        use crate::storage::volume::Volume;
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use ring::signature::{Ed25519KeyPair, KeyPair as _};
        use std::sync::Arc;
        use std::time::Duration;

        let root = std::env::temp_dir().join(format!("pg-mapper-accounts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch");
        let pair = Ed25519KeyPair::from_seed_unchecked(&[4u8; 32]).expect("a seed");
        let jwks = root.join("jwks.json");
        std::fs::write(
            &jwks,
            serde_json::to_vec(&serde_json::json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k", "x": URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())}]})).expect("json"),
        )
        .expect("written");
        let rule = |link_email: bool| OidcRule {
            name: "idp".to_owned(),
            issuer: "https://idp.example".to_owned(),
            audience: "permguard".to_owned(),
            algorithms: vec!["EdDSA".to_owned()],
            claim: "sub".to_owned(),
            keys: KeySource::File(jwks.clone()),
            ca_file: None,
            refresh: Duration::from_secs(3_600),
            max_stale: Duration::from_secs(3_600),
            clients: Vec::new(),
            token_types: vec!["JWT".to_owned()],
            link_email,
        };
        let token = |sub: &str, email: Option<&str>| {
            let exp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("now")
                .as_secs()
                + 600;
            let mut claims = serde_json::json!({"iss": "https://idp.example", "aud": "permguard", "exp": exp, "sub": sub});
            if let Some(email) = email {
                claims["email"] = serde_json::json!(email);
                claims["email_verified"] = serde_json::json!(true);
            }
            let signed = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","kid":"k"}"#),
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("json"))
            );
            format!(
                "{signed}.{}",
                URL_SAFE_NO_PAD.encode(pair.sign(signed.as_bytes()).as_ref())
            )
        };
        let volume = Volume::claim(
            &root.join("volume"),
            permguard_core::assurance::AssuranceProfile::Development,
        )
        .expect("claimed");
        let (directory, _) = Directory::open(&volume).expect("the directory");
        let change = |op: u8, change: Change| {
            directory
                .apply(&Applying::for_tests(op), change, "admin", 1, None)
                .expect("applied");
        };
        let phc = super::super::password::hash("a long enough secret").expect("hashed");
        change(
            1,
            Change::CreateUser {
                name: "paperino".to_owned(),
                email: Some("paperino@hotmail.com".to_owned()),
                display: None,
                password: Some(phc.clone()),
            },
        );
        change(
            2,
            Change::CreateUser {
                name: "linked".to_owned(),
                email: None,
                display: None,
                password: None,
            },
        );
        change(
            3,
            Change::Link {
                name: "linked".to_owned(),
                subject: "oidc:https://idp.example#0042".to_owned(),
            },
        );
        let time = Arc::new(crate::time::TimeGuard::system(Duration::from_secs(30)));
        let signin = Arc::new(SignIn::new(
            Arc::clone(&directory),
            Arc::new(Sessions::new(
                Duration::from_secs(3_600),
                Duration::from_secs(600),
                Arc::clone(&time),
            )),
            Arc::new(Mutations::open_offline(&volume, "test").expect("the engine")),
            Lockout::new(
                5,
                Duration::from_secs(900),
                Duration::from_secs(900),
                Arc::clone(&time),
            ),
            Policy {
                min_length: 12,
                mfa: Mfa::Off,
            },
            None,
            "test",
            time,
        ));
        let principal = |mapper: &PrincipalMapper, bearer: &str| match mapper
            .authenticate(None, Some(bearer))
        {
            Ok(Actor::Authenticated(context)) => {
                Ok(context.authorization_principal().as_str().to_owned())
            }
            Ok(other) => panic!("{other:?}"),
            Err(denial) => Err(denial.message().to_owned()),
        };

        let both = PrincipalMapper::new(&[Rule::Oidc(Box::new(rule(true)))], None).expect("builds");
        both.attach_accounts(Accounts {
            directory: Arc::clone(&directory),
            signin: Some(Arc::clone(&signin)),
            oidc: true,
        });
        let (session, _) = signin
            .sign_in("paperino", "a long enough secret", None, None)
            .expect("signed in");
        assert_eq!(principal(&both, &session).as_deref(), Ok("user:paperino"));
        assert_eq!(
            principal(&both, &token("0042", None)).as_deref(),
            Ok("user:linked"),
            "an explicit link"
        );
        assert_eq!(
            principal(&both, &token("p-77", Some("Paperino@Hotmail.com"))).as_deref(),
            Ok("user:paperino"),
            "a verified email"
        );
        assert_eq!(
            principal(&both, &token("nobody", None)).as_deref(),
            Ok("oidc:https://idp.example#nobody"),
            "no user: its own subject"
        );
        assert!(principal(&both, "pgs_forged").is_err());

        let no_email_link =
            PrincipalMapper::new(&[Rule::Oidc(Box::new(rule(false)))], None).expect("builds");
        no_email_link.attach_accounts(Accounts {
            directory: Arc::clone(&directory),
            signin: None,
            oidc: true,
        });
        assert_eq!(
            principal(&no_email_link, &token("p-77", Some("paperino@hotmail.com"))).as_deref(),
            Ok("oidc:https://idp.example#p-77"),
            "a provider without `link: email` never maps by email"
        );
        assert!(
            principal(&no_email_link, &session)
                .expect_err("no password method")
                .contains("no password sign-in")
        );

        let password_only =
            PrincipalMapper::new(&[Rule::Oidc(Box::new(rule(true)))], None).expect("builds");
        password_only.attach_accounts(Accounts {
            directory: Arc::clone(&directory),
            signin: Some(Arc::clone(&signin)),
            oidc: false,
        });
        assert!(
            principal(&password_only, &token("0042", None))
                .expect_err("no oidc method")
                .contains("no identity provider")
        );

        change(
            4,
            Change::SetStatus {
                name: "linked".to_owned(),
                active: false,
            },
        );
        assert!(
            principal(&both, &token("0042", None))
                .expect_err("disabled")
                .contains("disabled"),
            "never its own subject instead"
        );
    }
}
