// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Access tokens for a client (`2-security/7` The client): a service account's token, obtained at
//! the Authority Plane's token endpoint with an access key and its secret key, held while it
//! serves and obtained again a minute before it expires. Over REST or gRPC as the endpoint's scheme
//! says. Nothing here prints, traces or logs a token or a secret: `Debug` of every type that holds
//! one masks it.

use std::sync::Mutex;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::authority::TokenAsk;
use crate::catalog::Failure;
use crate::endpoint::Endpoint;
use crate::tls::{Credential, TlsOptions};

/// How long before its `exp` a token is obtained again.
pub const REFRESH_AHEAD: Duration = Duration::from_secs(60);

/// A token, and when it stops serving (seconds since the epoch).
#[derive(Clone)]
pub struct Issued {
    pub token: Credential,
    pub expires_at: u64,
}

impl std::fmt::Debug for Issued {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issued")
            .field("token", &Credential::MASK)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// A client's tokens from one Authority Plane.
pub struct TokenSource {
    endpoint: Endpoint,
    url: String,
    access_key: String,
    secret_key: Zeroizing<String>,
    scope: Option<String>,
    tls: TlsOptions,
    held: Mutex<Option<Issued>>,
}

impl std::fmt::Debug for TokenSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenSource")
            .field("endpoint", &self.endpoint.to_string())
            .field("access_key", &self.access_key)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

fn usage(detail: impl Into<String>) -> Failure {
    Failure {
        class: "validation".to_owned(),
        reason: permguard_core::codes::client::USAGE.to_owned(),
        detail: detail.into(),
        usage: true,
    }
}

fn refused(detail: impl Into<String>) -> Failure {
    Failure {
        class: "unauthenticated".to_owned(),
        reason: permguard_core::codes::common::UNAUTHENTICATED.to_owned(),
        detail: detail.into(),
        usage: false,
    }
}

impl TokenSource {
    /// A source for `access_key` at the Authority Plane `url` (`https://` or `grpcs://`), its
    /// secret `secret_key`, asking `scope`, the account's whole when `None`. The TLS options name
    /// the authority the Authority Plane is checked against; a bearer they carry is never sent
    /// there.
    pub fn new(
        url: &str,
        access_key: &str,
        secret_key: Zeroizing<String>,
        scope: Option<String>,
        mut tls: TlsOptions,
    ) -> Result<Self, Failure> {
        let endpoint = Endpoint::parse(url).map_err(|error| usage(error.to_string()))?;
        if !endpoint.is_tls() {
            return Err(usage(
                "a secret key is sent only over TLS: the Authority Plane's endpoint is https:// \
                 or grpcs://",
            ));
        }
        if tls.skip_verify {
            return Err(usage(
                "a secret key is sent only over verified TLS: --tls-skip-verify would hand it to \
                 whoever answered; trust the Authority Plane's authority instead",
            ));
        }
        if access_key.trim().is_empty() || secret_key.trim().is_empty() {
            return Err(usage("a client names its access key and its secret key"));
        }
        tls.token = None;
        Ok(Self {
            endpoint,
            url: url.to_owned(),
            access_key: access_key.trim().to_owned(),
            secret_key,
            scope: scope.filter(|scope| !scope.trim().is_empty()),
            tls,
            held: Mutex::new(None),
        })
    }

    /// The access key the source obtains tokens with.
    pub fn access_key(&self) -> &str {
        &self.access_key
    }

    /// The token to send: the one held while it serves past [`REFRESH_AHEAD`], otherwise a new
    /// one from the Authority Plane.
    pub fn token(&self) -> Result<Issued, Failure> {
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(issued) = held.as_ref()
            && issued.expires_at > permguard_core::time::unix_now() + REFRESH_AHEAD.as_secs()
        {
            return Ok(issued.clone());
        }
        let issued = self.obtain()?;
        *held = Some(issued.clone());
        Ok(issued)
    }

    /// Drops the token held: a surface refused it, and the next call obtains another.
    pub fn forget(&self) {
        *self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    /// Holds `issued`, a token obtained before and kept by the caller, when it still serves.
    pub fn hold(&self, issued: Issued) {
        if issued.expires_at > permguard_core::time::unix_now() + REFRESH_AHEAD.as_secs() {
            *self
                .held
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(issued);
        }
    }

    fn obtain(&self) -> Result<Issued, Failure> {
        let authority =
            crate::authority::client(&self.url, &self.tls, Box::new(crate::narrate::Silent))
                .map_err(usage)?;
        let answer = authority.issue_token(&TokenAsk {
            access_key: self.access_key.clone(),
            secret_key: self.secret_key.clone(),
            scope: self.scope.clone(),
            lifetime: None,
        })?;
        if !answer.token_type.eq_ignore_ascii_case("bearer")
            || !permguard_host::authz::access_tokens::is_access_token(&answer.access_token)
        {
            return Err(refused(
                "the token endpoint issued something other than an access token",
            ));
        }
        Ok(Issued {
            token: Credential::new(answer.access_token.into_bytes()),
            expires_at: permguard_core::time::unix_now().saturating_add(answer.expires_in),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_source_refuses_the_clear_and_an_unverified_authority() {
        let secret = || Zeroizing::new("pgsk_x".to_owned());
        assert!(
            TokenSource::new(
                "http://127.0.0.1:8443",
                "pgak_A",
                secret(),
                None,
                TlsOptions::default()
            )
            .is_err()
        );
        let skip = TlsOptions {
            skip_verify: true,
            ..TlsOptions::default()
        };
        assert!(
            TokenSource::new("https://authority:8443", "pgak_A", secret(), None, skip).is_err()
        );
        assert!(
            TokenSource::new(
                "https://authority:8443",
                "",
                secret(),
                None,
                TlsOptions::default()
            )
            .is_err()
        );
        let source = TokenSource::new(
            "grpcs://authority:8443",
            "pgak_A",
            secret(),
            Some(" ".to_owned()),
            TlsOptions::default(),
        )
        .unwrap_or_else(|_| unreachable!("a source"));
        assert_eq!(source.access_key(), "pgak_A");
        assert!(!format!("{source:?}").contains("pgsk_"));
    }
}
