// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The OIDC adapter: authentication only, everything pinned.
//!
//! Issuer, audience, algorithms and the claim that names the subject come from the rule; the
//! verification keys come from a JWKS file the deployment keeps beside its configuration,
//! looked at again once half the stale window has passed (one stat per half-window, a read only
//! when the file changed) and held for at most `max_stale` after the last successful look. A key
//! set past that window makes authentication unavailable; nothing here ever fetches over the
//! network (a URL refresh comes later, owner decision of 2026-10-06).
//!
//! A token is a compact JWS: `RS256`, `ES256` or `EdDSA`, the algorithm taken from the rule and
//! compared with the header's, never obeyed. The principal is `oidc:<issuer>#<claim value>`.

use std::path::PathBuf;
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use permguard_core::AccessDenial;
use permguard_core::authz::{ActorContext, Credential, Principal};

use super::mapper::MapperError;

/// One `host.principals[].oidc` rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcRule {
    pub issuer: String,
    pub audience: String,
    pub algorithms: Vec<String>,
    pub claim: String,
    pub jwks_file: PathBuf,
    pub max_stale: Duration,
}

/// The algorithms the adapter verifies.
const ALGORITHMS: &[&str] = &["RS256", "ES256", "EdDSA"];

/// A token longer than this is refused before it is split: an identity token is a few hundred
/// bytes, and the bound keeps a hostile header from costing a base64 decode of its own size.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// A key of the set, parsed once.
#[derive(Debug, Clone)]
enum Key {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    P256 { point: Vec<u8> },
    Ed25519 { public: Vec<u8> },
}

#[derive(Debug, Clone)]
struct Loaded {
    keys: Vec<(Option<String>, Key)>,
    /// When the file was last found to say these are the keys: loaded, or seen unchanged.
    at: SystemTime,
    /// When the file was last looked at, whatever it said: one stat per half-window.
    checked: SystemTime,
    modified: Option<SystemTime>,
}

/// The verifier of one issuer.
pub struct Verifier {
    rule: OidcRule,
    position: usize,
    loaded: RwLock<Loaded>,
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verifier")
            .field("issuer", &self.rule.issuer)
            .finish_non_exhaustive()
    }
}

impl Verifier {
    /// Builds the verifier and loads its key set once; a rule that cannot be honoured fails.
    pub fn new(rule: OidcRule, position: usize) -> Result<Self, MapperError> {
        let at = format!("host.principals[{position}].oidc");
        if rule.issuer.trim().is_empty() || rule.audience.trim().is_empty() {
            return Err(MapperError::Invalid(format!(
                "{at}: issuer and audience are required"
            )));
        }
        if rule.claim.trim().is_empty() {
            return Err(MapperError::Invalid(format!("{at}: claim is required")));
        }
        if rule.algorithms.is_empty() {
            return Err(MapperError::Invalid(format!(
                "{at}: algorithms names at least one of {}",
                ALGORITHMS.join(", ")
            )));
        }
        if let Some(unknown) = rule
            .algorithms
            .iter()
            .find(|algorithm| !ALGORITHMS.contains(&algorithm.as_str()))
        {
            return Err(MapperError::Invalid(format!(
                "{at}: `{unknown}` is not an algorithm this adapter verifies ({})",
                ALGORITHMS.join(", ")
            )));
        }
        if rule.max_stale.is_zero() {
            return Err(MapperError::Invalid(format!("{at}: max_stale is positive")));
        }
        let loaded =
            load(&rule.jwks_file).map_err(|detail| MapperError::Keys(format!("{at}: {detail}")))?;
        Ok(Self {
            rule,
            position,
            loaded: RwLock::new(loaded),
        })
    }

    /// `oidc:<issuer>#`: what every principal of this issuer starts with.
    pub fn principal_prefix(&self) -> String {
        format!("oidc:{}#", self.rule.issuer)
    }

    /// The rule's position, for a log line.
    pub fn position(&self) -> usize {
        self.position
    }

    /// Reloads the key set when the file changed. Off the request path: a maintenance pass calls
    /// it; `verify` only consults what is loaded and refuses a set past its stale window.
    /// Looks at the key set's file again: unchanged restarts the stale window, since the file is
    /// the deployment's statement that these are the keys; changed is read anew; unreadable is
    /// an error that leaves the loaded set to age out. `verify` calls it once half the window
    /// has passed; a maintenance pass may call it earlier.
    pub fn refresh(&self) -> Result<bool, String> {
        let now = SystemTime::now();
        let modified = std::fs::metadata(&self.rule.jwks_file)
            .and_then(|metadata| metadata.modified())
            .map_err(|error| format!("reading {}: {error}", self.rule.jwks_file.display()));
        let mut held = self
            .loaded
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        held.checked = now;
        let modified = modified?;
        if held.modified == Some(modified) {
            held.at = now;
            return Ok(false);
        }
        drop(held);
        let loaded = load(&self.rule.jwks_file)?;
        *self
            .loaded
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = loaded;
        Ok(true)
    }

    /// Verifies `token`: `Ok(None)` when it names another issuer, the actor when it verifies,
    /// a denial when it names this issuer and does not.
    pub fn verify(&self, token: &str) -> Result<Option<ActorContext>, AccessDenial> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(AccessDenial::unauthenticated(
                "the bearer token is longer than any identity token this adapter accepts",
            ));
        }
        let mut parts = token.split('.');
        let (Some(header), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(AccessDenial::unauthenticated(
                "the bearer token is not a compact JWS",
            ));
        };
        let decode = |part: &str, what: &str| {
            URL_SAFE_NO_PAD.decode(part).map_err(|_| {
                AccessDenial::unauthenticated(format!("the token's {what} is not base64url"))
            })
        };
        let claims: serde_json::Value = serde_json::from_slice(&decode(payload, "payload")?)
            .map_err(|_| AccessDenial::unauthenticated("the token's payload is not JSON"))?;
        if claims.get("iss").and_then(serde_json::Value::as_str) != Some(self.rule.issuer.as_str())
        {
            return Ok(None);
        }
        let header: serde_json::Value = serde_json::from_slice(&decode(header, "header")?)
            .map_err(|_| AccessDenial::unauthenticated("the token's header is not JSON"))?;
        let algorithm = header
            .get("alg")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| AccessDenial::unauthenticated("the token names no algorithm"))?;
        if !self
            .rule
            .algorithms
            .iter()
            .any(|allowed| allowed == algorithm)
        {
            return Err(AccessDenial::unauthenticated(format!(
                "the token's algorithm `{algorithm}` is not one this issuer is pinned to"
            )));
        }
        let kid = header.get("kid").and_then(serde_json::Value::as_str);
        // Half-way through the stale window the file is looked at again, by the one request that
        // finds the half-window passed: a stat, a read only when it changed, never a network
        // fetch. A file that cannot be read leaves the loaded set to age out below.
        let due = {
            let held = self
                .loaded
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            SystemTime::now()
                .duration_since(held.checked)
                .is_ok_and(|since| since >= self.rule.max_stale / 2)
        };
        if due && let Err(detail) = self.refresh() {
            tracing::warn!(
                event.name = "oidc.keys_not_refreshed",
                component = "host",
                issuer = %self.rule.issuer,
                error = %detail,
                "the issuer's key set could not be re-read; the loaded set serves until its stale window ends"
            );
        }
        let loaded = self
            .loaded
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if SystemTime::now()
            .duration_since(loaded.at)
            .is_ok_and(|age| age > self.rule.max_stale)
        {
            return Err(AccessDenial::unauthenticated(
                "the issuer's verification keys are past their stale window; authentication is \
                 unavailable until they are refreshed",
            ));
        }
        let candidates: Vec<&Key> = loaded
            .keys
            .iter()
            .filter(|(held, _)| kid.is_none() || held.as_deref() == kid)
            .map(|(_, key)| key)
            .collect();
        if candidates.is_empty() {
            return Err(AccessDenial::unauthenticated(
                "the token names a key the issuer's key set does not hold",
            ));
        }
        // Everything before the last dot: the header and the payload as sent, byte for byte.
        let signed = &token.as_bytes()[..token.len() - signature.len() - 1];
        let signature = decode(signature, "signature")?;
        let verified = candidates
            .iter()
            .any(|key| verify_with(key, algorithm, signed, &signature));
        if !verified {
            return Err(AccessDenial::unauthenticated(
                "the token's signature does not verify",
            ));
        }
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|since| since.as_secs())
            .unwrap_or(0);
        match claims.get("exp").and_then(serde_json::Value::as_u64) {
            Some(exp) if exp > now => {}
            _ => {
                return Err(AccessDenial::unauthenticated(
                    "the token has expired or carries no expiry",
                ));
            }
        }
        if claims
            .get("nbf")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|nbf| nbf > now)
        {
            return Err(AccessDenial::unauthenticated("the token is not yet valid"));
        }
        let audience_ok = match claims.get("aud") {
            Some(serde_json::Value::String(aud)) => aud == &self.rule.audience,
            Some(serde_json::Value::Array(auds)) => auds
                .iter()
                .any(|aud| aud.as_str() == Some(self.rule.audience.as_str())),
            _ => false,
        };
        if !audience_ok {
            return Err(AccessDenial::unauthenticated(
                "the token's audience is not this deployment",
            ));
        }
        let subject = claims
            .get(&self.rule.claim)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                AccessDenial::unauthenticated(format!(
                    "the token carries no `{}` claim to name its subject",
                    self.rule.claim
                ))
            })?;
        let principal =
            Principal::new(format!("{}{subject}", self.principal_prefix())).map_err(|error| {
                AccessDenial::unauthenticated(format!("the token's subject: {error}"))
            })?;
        Ok(Some(ActorContext::new(
            principal,
            Credential::Oidc,
            Some(format!("{}@{}", subject, self.rule.issuer)),
        )))
    }
}

fn verify_with(key: &Key, algorithm: &str, signed: &[u8], signature: &[u8]) -> bool {
    match (key, algorithm) {
        (Key::Rsa { n, e }, "RS256") => ring::signature::RsaPublicKeyComponents { n, e }
            .verify(
                &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                signed,
                signature,
            )
            .is_ok(),
        (Key::P256 { point }, "ES256") => ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_FIXED,
            point,
        )
        .verify(signed, signature)
        .is_ok(),
        (Key::Ed25519 { public }, "EdDSA") => {
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public)
                .verify(signed, signature)
                .is_ok()
        }
        _ => false,
    }
}

fn load(path: &std::path::Path) -> Result<Loaded, String> {
    let bytes =
        std::fs::read(path).map_err(|error| format!("reading {}: {error}", path.display()))?;
    let modified = std::fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok();
    let set: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("{} is not JSON: {error}", path.display()))?;
    let keys = set
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("{} holds no `keys` array", path.display()))?;
    let mut parsed = Vec::new();
    for (index, key) in keys.iter().enumerate() {
        let field = |name: &str| -> Result<Vec<u8>, String> {
            let text = key
                .get(name)
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| format!("keys[{index}] has no `{name}`"))?;
            URL_SAFE_NO_PAD
                .decode(text)
                .map_err(|_| format!("keys[{index}].{name} is not base64url"))
        };
        let kid = key
            .get("kid")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let kty = key
            .get("kty")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let crv = key
            .get("crv")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let key = match (kty, crv) {
            ("RSA", _) => Key::Rsa {
                n: field("n")?,
                e: field("e")?,
            },
            ("EC", "P-256") => {
                let (x, y) = (field("x")?, field("y")?);
                if x.len() != 32 || y.len() != 32 {
                    return Err(format!("keys[{index}] is not a P-256 point"));
                }
                let mut point = Vec::with_capacity(65);
                point.push(0x04);
                point.extend(x);
                point.extend(y);
                Key::P256 { point }
            }
            ("OKP", "Ed25519") => Key::Ed25519 {
                public: field("x")?,
            },
            _ => {
                return Err(format!(
                    "keys[{index}] is of a type this adapter does not verify ({kty} {crv})"
                ));
            }
        };
        parsed.push((kid, key));
    }
    if parsed.is_empty() {
        return Err(format!("{} holds no key", path.display()));
    }
    let now = SystemTime::now();
    Ok(Loaded {
        keys: parsed,
        at: now,
        checked: now,
        modified,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pg-oidc-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory is created");
        dir
    }

    fn issuer(dir: &std::path::Path) -> (Ed25519KeyPair, OidcRule) {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[3u8; 32]).expect("a seed");
        let jwks = serde_json::json!({"keys": [{
            "kty": "OKP", "crv": "Ed25519", "kid": "k1", "alg": "EdDSA", "use": "sig",
            "x": URL_SAFE_NO_PAD.encode(pair.public_key().as_ref()),
        }]});
        let file = dir.join("jwks.json");
        std::fs::write(&file, serde_json::to_vec(&jwks).expect("json")).expect("written");
        (
            pair,
            OidcRule {
                issuer: "https://login.example".to_owned(),
                audience: "permguard".to_owned(),
                algorithms: vec!["EdDSA".to_owned()],
                claim: "sub".to_owned(),
                jwks_file: file,
                max_stale: Duration::from_secs(3600),
            },
        )
    }

    fn token(
        pair: &Ed25519KeyPair,
        header: serde_json::Value,
        claims: serde_json::Value,
    ) -> String {
        let signed = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("json")),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("json"))
        );
        let signature = pair.sign(signed.as_bytes());
        format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
    }

    fn soon() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("now")
            .as_secs()
            + 600
    }

    #[test]
    fn a_pinned_token_verifies_and_names_the_principal_from_the_claim() {
        let dir = scratch("verifies");
        let (pair, rule) = issuer(&dir);
        let verifier = Verifier::new(rule, 0).expect("builds");
        let token = token(
            &pair,
            serde_json::json!({"alg": "EdDSA", "kid": "k1"}),
            serde_json::json!({"iss": "https://login.example", "aud": "permguard", "exp": soon(), "sub": "alice"}),
        );
        let actor = verifier
            .verify(&token)
            .expect("verifies")
            .expect("this issuer");
        assert_eq!(
            actor.authorization_principal().as_str(),
            "oidc:https://login.example#alice"
        );
        assert_eq!(actor.credential(), Credential::Oidc);
    }

    #[test]
    fn another_issuer_is_not_this_verifiers_and_a_wrong_audience_algorithm_signature_or_expiry_is_refused()
     {
        let dir = scratch("refuses");
        let (pair, rule) = issuer(&dir);
        let verifier = Verifier::new(rule, 0).expect("builds");
        let other = token(
            &pair,
            serde_json::json!({"alg": "EdDSA"}),
            serde_json::json!({"iss": "https://other.example", "aud": "permguard", "exp": soon(), "sub": "a"}),
        );
        assert!(verifier.verify(&other).expect("answers").is_none());
        let wrong_aud = token(
            &pair,
            serde_json::json!({"alg": "EdDSA"}),
            serde_json::json!({"iss": "https://login.example", "aud": "else", "exp": soon(), "sub": "a"}),
        );
        assert!(verifier.verify(&wrong_aud).is_err());
        let wrong_alg = token(
            &pair,
            serde_json::json!({"alg": "none"}),
            serde_json::json!({"iss": "https://login.example", "aud": "permguard", "exp": soon(), "sub": "a"}),
        );
        assert!(
            verifier.verify(&wrong_alg).is_err(),
            "the header is compared, never obeyed"
        );
        let expired = token(
            &pair,
            serde_json::json!({"alg": "EdDSA"}),
            serde_json::json!({"iss": "https://login.example", "aud": "permguard", "exp": 1, "sub": "a"}),
        );
        assert!(verifier.verify(&expired).is_err());
        let mut tampered = token(
            &pair,
            serde_json::json!({"alg": "EdDSA"}),
            serde_json::json!({"iss": "https://login.example", "aud": "permguard", "exp": soon(), "sub": "a"}),
        );
        tampered.replace_range(tampered.len() - 2.., "AA");
        assert!(verifier.verify(&tampered).is_err());
        assert!(verifier.verify("not.a.jws.at.all").is_err());
        let no_subject = token(
            &pair,
            serde_json::json!({"alg": "EdDSA"}),
            serde_json::json!({"iss": "https://login.example", "aud": "permguard", "exp": soon()}),
        );
        assert!(verifier.verify(&no_subject).is_err());
    }

    #[test]
    fn the_key_set_is_looked_at_again_half_way_and_ages_out_only_when_the_file_is_gone() {
        let dir = scratch("stale");
        let (pair, mut rule) = issuer(&dir);
        rule.max_stale = Duration::from_millis(20);
        let file = rule.jwks_file.clone();
        let jwks = std::fs::read(&file).expect("the key set reads");
        let verifier = Verifier::new(rule, 0).expect("builds");
        let token = token(
            &pair,
            serde_json::json!({"alg": "EdDSA"}),
            serde_json::json!({"iss": "https://login.example", "aud": "permguard", "exp": soon(), "sub": "a"}),
        );
        // Past half the window with the file in place: `verify` looks again by itself and the
        // window restarts, so the token keeps verifying well past the original window.
        std::thread::sleep(Duration::from_millis(12));
        assert!(verifier.verify(&token).expect("verifies").is_some());
        std::thread::sleep(Duration::from_millis(12));
        assert!(
            verifier.verify(&token).expect("verifies").is_some(),
            "the window restarted when the file was seen unchanged"
        );
        // The file gone: the look fails, the loaded set ages past the window, authentication is
        // unavailable until the file is back and looked at again.
        std::fs::remove_file(&file).expect("removed");
        std::thread::sleep(Duration::from_millis(25));
        let refused = verifier.verify(&token).expect_err("stale");
        assert!(refused.message().contains("stale window"), "{refused}");
        std::fs::write(&file, &jwks).expect("restored");
        std::thread::sleep(Duration::from_millis(12));
        assert!(verifier.verify(&token).expect("verifies").is_some());
        // A new key in the file is read when the file changes.
        let other = Ed25519KeyPair::from_seed_unchecked(&[9u8; 32]).expect("a seed");
        let rotated = serde_json::json!({"keys": [{
            "kty": "OKP", "crv": "Ed25519", "kid": "k2", "alg": "EdDSA", "use": "sig",
            "x": URL_SAFE_NO_PAD.encode(other.public_key().as_ref()),
        }]});
        std::thread::sleep(Duration::from_millis(12));
        std::fs::write(&file, serde_json::to_vec(&rotated).expect("json")).expect("rotated");
        assert!(verifier.refresh().expect("refreshes"), "the file changed");
        assert!(verifier.verify(&token).is_err(), "the old key is gone");
        let fresh = self::token(
            &other,
            serde_json::json!({"alg": "EdDSA", "kid": "k2"}),
            serde_json::json!({"iss": "https://login.example", "aud": "permguard", "exp": soon(), "sub": "b"}),
        );
        assert!(verifier.verify(&fresh).expect("verifies").is_some());
    }

    #[test]
    fn a_rule_that_cannot_be_honoured_fails_startup() {
        let dir = scratch("rules");
        let (_, rule) = issuer(&dir);
        let mut no_keys = rule.clone();
        no_keys.jwks_file = dir.join("missing.json");
        assert!(matches!(
            Verifier::new(no_keys, 0),
            Err(MapperError::Keys(_))
        ));
        let mut bad_alg = rule.clone();
        bad_alg.algorithms = vec!["HS256".to_owned()];
        assert!(matches!(
            Verifier::new(bad_alg, 0),
            Err(MapperError::Invalid(_))
        ));
        let mut no_claim = rule;
        no_claim.claim = String::new();
        assert!(matches!(
            Verifier::new(no_claim, 0),
            Err(MapperError::Invalid(_))
        ));
    }
}
