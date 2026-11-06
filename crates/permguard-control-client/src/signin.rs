// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Password sign-in on a Server Host surface (WP-8.1, `6-contracts/8` Sign-in): what `permguard
//! login`, `logout`, `password` and `factor` reach. A password travels only in a request body;
//! the session token comes back once and is the caller's to keep.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::catalog::Failure;
use crate::endpoint::Endpoint;
use crate::http::Client;
use crate::tls::TlsOptions;

/// What a sign-in answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Opened {
    pub token: String,
    pub user: String,
    pub expires_at: u64,
    pub opened: String,
}

/// What `GET /auth/v1/session` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionView {
    pub user: String,
    pub expires_at: u64,
    pub opened: String,
}

/// A factor's enrollment: its secret and the URI an authenticator application scans, once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrollment {
    pub secret: String,
    pub uri: String,
}

/// A Host waiting for its first administrator (WP-8.2): never the code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupStatus {
    pub waiting: bool,
    /// `generated`, `secret` or `recovery`.
    pub origin: String,
    /// RFC 3339.
    pub expires_at: String,
}

/// What a setup asks: the code, and the first administrator it makes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupRequest {
    pub code: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// The first administrator a setup made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupCompleted {
    pub user: String,
    pub principal: String,
    /// The grant of `authz.admin` on `host`.
    pub grant: Option<String>,
    pub origin: String,
}

/// The Server Host surface at `url`, signing in.
pub struct SignIn {
    client: Client,
    endpoint: Endpoint,
}

impl SignIn {
    /// Reaches `url` with `tls`; the session, once there is one, is `tls.token`.
    pub fn new(
        url: &str,
        tls: &TlsOptions,
        narrator: Box<dyn crate::narrate::Narrator>,
    ) -> Result<Self, String> {
        let endpoint = Endpoint::parse(url).map_err(|error| error.to_string())?;
        if endpoint.is_grpc() {
            return Err(format!(
                "`{url}` is a gRPC address: sign-in is on the Server Host surface, http or https"
            ));
        }
        let client = Client::new(
            std::time::Duration::from_secs(30),
            tls.clone(),
            endpoint.is_tls(),
        )
        .map_err(|error| error.to_string())?
        .with_narrator(narrator);
        Ok(Self { client, endpoint })
    }

    fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<Option<String>, Failure> {
        let response = self
            .client
            .request(&self.endpoint, method, path, body)
            .map_err(|error| Failure {
                class: "unavailable".to_owned(),
                reason: error.reason().to_owned(),
                detail: error.to_string(),
                usage: false,
            })?;
        if response.status == 204 {
            return Ok(None);
        }
        if (200..300).contains(&response.status) {
            return Ok(Some(response.body));
        }
        let refusal: serde_json::Value = serde_json::from_str(&response.body).unwrap_or_default();
        Err(Failure {
            class: if response.status == 401 {
                "unauthenticated"
            } else {
                "refused"
            }
            .to_owned(),
            reason: refusal
                .get("code")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(permguard_core::codes::client::HTTP_STATUS)
                .to_owned(),
            detail: refusal
                .get("message")
                .and_then(serde_json::Value::as_str)
                .map_or_else(
                    || format!("{method} {path} answered {}", response.status),
                    str::to_owned,
                ),
            usage: matches!(response.status, 400 | 401 | 403),
        })
    }

    fn read<T: for<'de> Deserialize<'de>>(body: Option<String>, what: &str) -> Result<T, Failure> {
        serde_json::from_str(body.as_deref().unwrap_or_default()).map_err(|error| Failure {
            class: "internal".to_owned(),
            reason: permguard_core::codes::client::DECODE_FAILED.to_owned(),
            detail: format!("the answer to {what} was unreadable: {error}"),
            usage: false,
        })
    }

    /// `GET /auth/v1/setup`: whether the Host waits for its first administrator, `None` when it
    /// does not. What Permguard Admin asks before it offers a setup.
    pub fn setup_status(&self) -> Result<Option<SetupStatus>, Failure> {
        match self.send("GET", "/auth/v1/setup", None) {
            Ok(answer) => Self::read(answer, "the setup status").map(Some),
            Err(failure) if failure.reason == "setup.closed" => Ok(None),
            Err(failure) => Err(failure),
        }
    }

    /// `POST /auth/v1/setup`: the first administrator, made with the Host's setup code.
    pub fn setup(&self, request: &SetupRequest) -> Result<SetupCompleted, Failure> {
        let body = serde_json::to_string(request).map_err(|error| Failure {
            class: "internal".to_owned(),
            reason: permguard_core::codes::client::DECODE_FAILED.to_owned(),
            detail: error.to_string(),
            usage: false,
        })?;
        let answer = self.send("POST", "/auth/v1/setup", Some(&body))?;
        Self::read(answer, "the setup")
    }

    /// `POST /auth/v1/sessions`.
    pub fn sign_in(
        &self,
        name: &str,
        password: &str,
        code: Option<&str>,
    ) -> Result<Opened, Failure> {
        let mut body = json!({"name": name, "password": password});
        if let Some(code) = code {
            body["code"] = json!(code);
        }
        let answer = self.send("POST", "/auth/v1/sessions", Some(&body.to_string()))?;
        Self::read(answer, "the sign-in")
    }

    /// `DELETE /auth/v1/sessions/current`.
    pub fn sign_out(&self) -> Result<(), Failure> {
        self.send("DELETE", "/auth/v1/sessions/current", None)
            .map(|_| ())
    }

    /// `GET /auth/v1/session`.
    pub fn session(&self) -> Result<SessionView, Failure> {
        let answer = self.send("GET", "/auth/v1/session", None)?;
        Self::read(answer, "the session")
    }

    /// `POST /auth/v1/password`.
    pub fn change_password(&self, current: &str, new: &str) -> Result<(), Failure> {
        let body = json!({"current": current, "new": new}).to_string();
        self.send("POST", "/auth/v1/password", Some(&body))
            .map(|_| ())
    }

    /// `POST /auth/v1/factor`.
    pub fn begin_factor(&self, password: &str) -> Result<Enrollment, Failure> {
        let body = json!({"password": password}).to_string();
        let answer = self.send("POST", "/auth/v1/factor", Some(&body))?;
        Self::read(answer, "the enrollment")
    }

    /// `POST /auth/v1/factor/confirm`.
    pub fn confirm_factor(&self, code: &str) -> Result<(), Failure> {
        let body = json!({"code": code}).to_string();
        self.send("POST", "/auth/v1/factor/confirm", Some(&body))
            .map(|_| ())
    }
}
