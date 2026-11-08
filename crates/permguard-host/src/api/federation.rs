// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Federation (`2-security/8` Federation and the security token service): who a token request is
//! for. A service account's credential, a client assertion, a password session or a provider's
//! token is proved here, and handed to the security token service as a [`Subject`]; how a token
//! is then shaped and issued is [`super::token_endpoint`]'s alone.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use permguard_core::authz::Principal;

use super::HostApi;
use super::token_endpoint::{
    ACCESS_TOKEN_TYPE, ClientProof, ID_TOKEN_TYPE, JWT_BEARER, JWT_TOKEN_TYPE, MAX_ASSERTION_BYTES,
    MAX_ASSERTION_LIFETIME, TokenRefusal, TokenRequest,
};
use super::tokens::Tokens;
use crate::authz::credentials;
use crate::authz::directory::{
    AccountStatus, CredentialMaterial, ServiceAccount, UserStatus, service_account_principal,
    user_principal,
};

/// How long before this process first served the endpoint an assertion may have been made: a
/// client signs one right before it asks, and its clock may run a little behind.
const ASSERTION_TOLERANCE: u64 = 5;

/// The client assertions seen, each refused a second time within its lifetime. They are held in
/// memory: one made before this process first served the endpoint is refused, so a restart
/// opens no window to replay an assertion seen before it.
#[derive(Default)]
pub(super) struct Replays {
    seen: Mutex<HashMap<(String, String), u64>>,
    since: Mutex<Option<u64>>,
}

impl Replays {
    /// When this process first served the endpoint, recorded at its first request.
    pub(super) fn since(&self, now: u64) -> u64 {
        *self
            .since
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_or_insert(now)
    }

    fn first_use(&self, account: &str, jti: &str, expires_at: u64, now: u64) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        seen.retain(|_, until| *until > now);
        seen.insert((account.to_owned(), jti.to_owned()), expires_at)
            .is_none()
    }
}

/// Who a request is for, once its proof held.
pub(super) struct Subject {
    pub(super) principal: Principal,
    pub(super) client_id: String,
    pub(super) account: Option<ServiceAccount>,
    pub(super) credential_id: Option<[u8; 16]>,
    /// The latest a token for it may expire: its credential's expiry, its session's end.
    pub(super) expires_by: Option<u64>,
}

pub(super) fn client_failed() -> TokenRefusal {
    TokenRefusal::InvalidClient("the client could not be authenticated".to_owned())
}

pub(super) fn decode_part(part: &str) -> Option<serde_json::Value> {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).ok()?).ok()
}

impl HostApi {
    /// The service account a `client_credentials` request proves, by exactly one proof.
    pub(super) fn authenticate_client(
        &self,
        tokens: &Tokens,
        request: &TokenRequest,
        proof: &ClientProof,
        now: u64,
    ) -> Result<Subject, TokenRefusal> {
        let identities = self
            .identities
            .as_ref()
            .ok_or_else(|| TokenRefusal::Unavailable("no directory is open".to_owned()))?;
        let assertion =
            request.client_assertion.is_some() || request.client_assertion_type.is_some();
        let certificate = !assertion && proof.basic.is_none();
        if proof.basic.is_some() && assertion {
            return Err(TokenRefusal::InvalidRequest(
                "one client proof: a secret or an assertion, not both".to_owned(),
            ));
        }
        let name = match (&proof.basic, &request.client_id) {
            (Some((basic, _)), Some(form)) if basic != form => {
                return Err(TokenRefusal::InvalidRequest(
                    "the client_id differs from the Basic credentials'".to_owned(),
                ));
            }
            (Some((basic, _)), _) => basic.clone(),
            (None, Some(form)) => form.clone(),
            (None, None) if assertion => String::new(),
            (None, None) => {
                return Err(TokenRefusal::InvalidClient(
                    "no client proof: a secret, an assertion or a certificate with client_id"
                        .to_owned(),
                ));
            }
        };
        if let Some((_, secret)) = &proof.basic {
            // An unknown account, a malformed secret and an account holding no secret each cost
            // one Argon2id, as a wrong secret against one credential does: the answer's time
            // says no more than its content. An account holding several secrets costs one each.
            let account = identities.directory.service_account(&name);
            let secrets: Vec<(crate::authz::directory::Credential, String)> = account
                .as_ref()
                .filter(|_| credentials::is_secret(secret))
                .map(|account| {
                    account
                        .live_credentials(now)
                        .filter_map(|credential| match &credential.material {
                            CredentialMaterial::Secret { phc } => {
                                Some((credential.clone(), phc.clone()))
                            }
                            _ => None,
                        })
                        .collect()
                })
                .unwrap_or_default();
            if secrets.is_empty() {
                crate::authz::password::burn(secret);
                return Err(client_failed());
            }
            let matched = secrets
                .into_iter()
                .find(|(_, phc)| crate::authz::password::verify(secret, phc));
            let (Some(account), Some((credential, _))) = (account, matched) else {
                return Err(client_failed());
            };
            return active_subject(account, &credential);
        }
        if assertion {
            if request.client_assertion_type.as_deref() != Some(JWT_BEARER) {
                return Err(TokenRefusal::InvalidRequest(format!(
                    "client_assertion_type is `{JWT_BEARER}`"
                )));
            }
            let jwt = request
                .client_assertion
                .as_deref()
                .ok_or_else(|| TokenRefusal::InvalidRequest("no client_assertion".to_owned()))?;
            return self.assertion_subject(tokens, jwt, &name, now);
        }
        if certificate {
            let account = identities
                .directory
                .service_account(&name)
                .ok_or_else(client_failed)?;
            // An SPKI binding matches the certificate's key, a SAN URI binding its SAN URIs: a SAN
            // URI spelled as a digest never matches a key.
            let matches = |binding: &str| {
                if binding.starts_with("spki:sha256:") {
                    proof.spki.as_deref() == Some(binding)
                } else {
                    proof.san_uris.iter().any(|uri| uri == binding)
                }
            };
            let credential = account
                .live_credentials(now)
                .find(|credential| {
                    matches!(&credential.material, CredentialMaterial::Binding { binding }
                        if matches(binding))
                })
                .cloned()
                .ok_or_else(client_failed)?;
            return active_subject(account, &credential);
        }
        Err(client_failed())
    }

    /// The service account a client assertion proves (RFC 7523 §3).
    fn assertion_subject(
        &self,
        tokens: &Tokens,
        jwt: &str,
        client_id: &str,
        now: u64,
    ) -> Result<Subject, TokenRefusal> {
        let identities = self
            .identities
            .as_ref()
            .ok_or_else(|| TokenRefusal::Unavailable("no directory is open".to_owned()))?;
        if jwt.len() > MAX_ASSERTION_BYTES {
            return Err(client_failed());
        }
        let mut parts = jwt.split('.');
        let (Some(protected), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(client_failed());
        };
        let header = decode_part(protected).ok_or_else(client_failed)?;
        let claims = decode_part(payload).ok_or_else(client_failed)?;
        let text = |value: &serde_json::Value, name: &str| {
            value
                .get(name)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        };
        let (Some(alg), Some(kid)) = (text(&header, "alg"), text(&header, "kid")) else {
            return Err(client_failed());
        };
        let (Some(issuer), Some(subject), Some(jti)) = (
            text(&claims, "iss"),
            text(&claims, "sub"),
            text(&claims, "jti"),
        ) else {
            return Err(client_failed());
        };
        if issuer != subject || (!client_id.is_empty() && client_id != subject) {
            return Err(client_failed());
        }
        let endpoint = format!("{}/iam/v1/token", tokens.base_url);
        let audience_holds = match claims.get("aud") {
            Some(serde_json::Value::String(one)) => *one == endpoint || *one == tokens.issuer,
            Some(serde_json::Value::Array(many)) => many.iter().any(|one| {
                one.as_str()
                    .is_some_and(|one| one == endpoint || one == tokens.issuer)
            }),
            _ => false,
        };
        let expires_at = claims.get("exp").and_then(serde_json::Value::as_u64);
        let Some(expires_at) =
            expires_at.filter(|exp| *exp > now && *exp <= now + MAX_ASSERTION_LIFETIME)
        else {
            return Err(client_failed());
        };
        if !audience_holds || jti.is_empty() || jti.len() > 128 {
            return Err(client_failed());
        }
        // Made after this process first served the endpoint, and not in its future: a replay
        // across a restart is refused, since the assertions seen before it are not remembered.
        // RFC 7523 leaves `iat` out at will: one without it counts as made the longest an
        // assertion lives before its `exp`.
        let issued_at = claims
            .get("iat")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(|| expires_at.saturating_sub(MAX_ASSERTION_LIFETIME));
        if issued_at.saturating_add(ASSERTION_TOLERANCE) < tokens.replays.since(now)
            || issued_at > now.saturating_add(ASSERTION_TOLERANCE)
        {
            return Err(client_failed());
        }
        let account = identities
            .directory
            .service_account(&subject)
            .ok_or_else(client_failed)?;
        let credential = account
            .live_credentials(now)
            .find(|credential| {
                matches!(&credential.material, CredentialMaterial::Key { key_id, algorithm, .. }
                    if *key_id == kid && *algorithm == alg)
            })
            .cloned()
            .ok_or_else(client_failed)?;
        let CredentialMaterial::Key { key, .. } = &credential.material else {
            return Err(client_failed());
        };
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| client_failed())?;
        let algorithm: &dyn ring::signature::VerificationAlgorithm = match alg.as_str() {
            credentials::EDDSA => &ring::signature::ED25519,
            credentials::ES256 => &ring::signature::ECDSA_P256_SHA256_FIXED,
            _ => return Err(client_failed()),
        };
        ring::signature::UnparsedPublicKey::new(algorithm, key)
            .verify(format!("{protected}.{payload}").as_bytes(), &signature)
            .map_err(|_| client_failed())?;
        // Verified, then recorded: an assertion is used once within its lifetime.
        if !tokens.replays.first_use(&subject, &jti, expires_at, now) {
            return Err(client_failed());
        }
        active_subject(account, &credential)
    }

    /// The person a token exchange is for: a password session, or a provider's token.
    pub(super) fn exchanged_subject(
        &self,
        request: &TokenRequest,
    ) -> Result<Subject, TokenRefusal> {
        let identities = self
            .identities
            .as_ref()
            .ok_or_else(|| TokenRefusal::Unavailable("no directory is open".to_owned()))?;
        let token = request
            .subject_token
            .as_deref()
            .ok_or_else(|| TokenRefusal::InvalidRequest("no subject_token".to_owned()))?;
        // RFC 8693 §3: an access token is one this IAM Host issued, its password session; a
        // provider's token is a JWT or an ID token. The type says which is verified, never both.
        let session = match request.subject_token_type.as_deref() {
            Some(ACCESS_TOKEN_TYPE) => true,
            Some(JWT_TOKEN_TYPE | ID_TOKEN_TYPE) => false,
            _ => {
                return Err(TokenRefusal::InvalidRequest(format!(
                    "subject_token_type is `{ACCESS_TOKEN_TYPE}` for a session of this IAM Host, \
                     `{JWT_TOKEN_TYPE}` or `{ID_TOKEN_TYPE}` for a provider's token"
                )));
            }
        };
        // RFC 8693 §2.2.2: a subject token not valid, or not acceptable, is `invalid_request`.
        let invalid = || TokenRefusal::InvalidRequest("the subject token is not valid".to_owned());
        if session {
            let session = identities
                .signin
                .as_ref()
                .and_then(|signin| signin.session(token))
                .ok_or_else(invalid)?;
            // A session that serves only the enrollment of a second factor proves a password
            // alone, which is what the factor is there to refuse: it is exchanged for nothing.
            if session.opened == crate::authz::sessions::Opened::EnrollFactor {
                return Err(invalid());
            }
            let user = identities
                .directory
                .user(&session.user)
                .filter(|user| user.status == UserStatus::Active)
                .ok_or_else(invalid)?;
            return Ok(Subject {
                principal: Principal::new(user_principal(&user.name)).map_err(|_| invalid())?,
                client_id: "password-session".to_owned(),
                account: None,
                credential_id: None,
                expires_by: Some(session.expires_at),
            });
        }
        // A provider's token, only where `oidc` is among the deployment's methods, and as the
        // mapper reads it: the user its subject is linked to, or whose email it verifies when the
        // provider links by email; a disabled user is refused, never its bare subject.
        let providers: &[std::sync::Arc<crate::authz::oidc::Verifier>] =
            if identities.exchange_provider_tokens {
                &identities.providers
            } else {
                &[]
            };
        for verifier in providers {
            if let Ok(Some(verified)) = verifier.verify_token(token) {
                let subject = verified.context.authorization_principal().clone();
                let linked = identities
                    .directory
                    .user_of_subject(subject.as_str())
                    .or_else(|| {
                        verifier
                            .rule()
                            .link_email
                            .then(|| {
                                verified
                                    .verified_email
                                    .as_deref()
                                    .and_then(|email| identities.directory.user_by_email(email))
                            })
                            .flatten()
                    });
                let principal = match linked {
                    Some(user) if user.status == UserStatus::Active => {
                        Principal::new(user_principal(&user.name)).map_err(|_| invalid())?
                    }
                    Some(_) => return Err(invalid()),
                    None => subject,
                };
                return Ok(Subject {
                    principal,
                    client_id: format!("oidc:{}", verifier.name()),
                    account: None,
                    credential_id: None,
                    // Never past the provider's token it was exchanged for.
                    expires_by: Some(verified.expires_at),
                });
            }
        }
        Err(invalid())
    }
}

/// The subject of `account` proved by `credential`, while both are good.
fn active_subject(
    account: ServiceAccount,
    credential: &crate::authz::directory::Credential,
) -> Result<Subject, TokenRefusal> {
    if account.status != AccountStatus::Active {
        return Err(client_failed());
    }
    Ok(Subject {
        principal: Principal::new(service_account_principal(&account.name))
            .map_err(|_| client_failed())?,
        client_id: credential.id_text(),
        credential_id: Some(credential.id),
        expires_by: credential.expires_at,
        account: Some(account),
    })
}
