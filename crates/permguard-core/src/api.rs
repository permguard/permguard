// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! One shape for every refusal, whatever the wire and whatever the domain.
//!
//! Every API this product exposes answers a failure with the same three fields:
//!
//! * a **class** — which *kind* of thing went wrong, from a closed set a client can switch on;
//! * a **code** — the stable, machine-readable name of the exact condition (`name_taken`,
//!   `not_found`); the contract scripts and SDKs branch on;
//! * a **message** — one sentence for a person, free to be reworded between releases.
//!
//! HTTP carries them as a JSON body, gRPC as a status plus metadata, and both derive their status
//! code *from the class* — so adding an error never means choosing an HTTP code and a gRPC code and
//! hoping they agree.
//!
//! # What leaves the building, and what stays
//!
//! An error may also carry an **internal detail** — a path, an io error, a line of context. That
//! detail is for the operator, not the caller: it always goes to the log at full fidelity, and it
//! reaches the wire only when the deployment's [`Disclosure`] says so. The two audiences are the
//! whole design: the person debugging the server reads everything, the client on the other side of
//! the wire learns exactly what it needs to act and nothing that maps the inside.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Which kind of thing went wrong: the closed set every API shares.
///
/// The class decides the transport status on every wire, so the mapping lives here, once:
///
/// | class | HTTP | gRPC |
/// | --- | --- | --- |
/// | `validation` | 422 | `INVALID_ARGUMENT` |
/// | `conflict` | 409 | `ALREADY_EXISTS` / `FAILED_PRECONDITION`¹ |
/// | `not_found` | 404 | `NOT_FOUND` |
/// | `unavailable` | 503 | `UNAVAILABLE` |
/// | `internal` | 500 | `INTERNAL` |
///
/// ¹ gRPC distinguishes two conflicts HTTP folds into one 409; the adapter reads the code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    /// The request itself is malformed: a name that breaks the rules, a missing field.
    Validation,
    /// The request is well-formed and the world disagrees: a taken name, a zone that is not empty.
    Conflict,
    /// Nothing answers to what was named.
    NotFound,
    /// The service cannot answer right now, and retrying is reasonable.
    Unavailable,
    /// The service failed. The caller did nothing wrong and can fix nothing.
    Internal,
}

impl ErrorClass {
    /// The class as it is written on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Validation => "validation",
            Self::Conflict => "conflict",
            Self::NotFound => "not_found",
            Self::Unavailable => "unavailable",
            Self::Internal => "internal",
        }
    }
}

/// How much a refusal on the wire says about the inside of the server.
///
/// This is a property of the *deployment*, not of the error: the same failure answers differently
/// on a workstation and on an exposed endpoint. The default is [`Disclosure::Minimal`], because the
/// safe posture has to be the one a deployment gets by saying nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Disclosure {
    /// Internal details travel in the response. For a surface only its developers can reach.
    Full,
    /// Internal details go to the log and the wire gets the class, the code and a safe sentence.
    #[default]
    Minimal,
}

impl Disclosure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Minimal => "minimal",
        }
    }
}

impl std::str::FromStr for Disclosure {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "full" => Ok(Self::Full),
            "minimal" => Ok(Self::Minimal),
            other => Err(format!(
                "`{other}` is not an error-detail level: expected `full` or `minimal`"
            )),
        }
    }
}

/// One refusal, before any wire has shaped it.
#[derive(Debug, Clone)]
pub struct ApiError {
    class: ErrorClass,
    code: &'static str,
    message: String,
    /// What the operator needs and the caller must not get uninvited: paths, io errors, context.
    internal: Option<String>,
}

impl ApiError {
    /// Builds a refusal whose message is safe for any wire.
    pub fn new(class: ErrorClass, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            class,
            code,
            message: message.into(),
            internal: None,
        }
    }

    /// Attaches the detail that goes to the log always, and to the wire only under
    /// [`Disclosure::Full`].
    pub fn with_internal(mut self, detail: impl Into<String>) -> Self {
        self.internal = Some(detail.into());

        self
    }

    pub fn class(&self) -> ErrorClass {
        self.class
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    /// The message as `disclosure` allows it to leave: the safe sentence, with the internal detail
    /// appended only where the deployment asked for it.
    pub fn disclosed_message(&self, disclosure: Disclosure) -> String {
        match (disclosure, &self.internal) {
            (Disclosure::Full, Some(internal)) => format!("{}: {internal}", self.message),
            _ => self.message.clone(),
        }
    }

    /// The detail that stays inside, for the record the server writes about itself.
    pub fn internal_detail(&self) -> Option<&str> {
        self.internal.as_deref()
    }

    /// What the wire carries, in the one shape every API answers.
    pub fn on_the_wire(&self, disclosure: Disclosure) -> WireError {
        WireError {
            class: self.class,
            code: self.code.to_owned(),
            message: self.disclosed_message(disclosure),
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}/{})",
            self.message,
            self.class.as_str(),
            self.code
        )
    }
}

impl std::error::Error for ApiError {}

/// The refusal as it is serialised: the same three fields on every wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireError {
    /// Which kind of thing went wrong.
    pub class: ErrorClass,
    /// The stable name of the exact condition.
    pub code: String,
    /// One sentence for a person.
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_internal_detail_leaves_only_when_asked() {
        let error = ApiError::new(
            ErrorClass::Internal,
            "catalog_failed",
            "the catalog store failed",
        )
        .with_internal("replacing /var/lib/permguard/data/zones/zones.json: permission denied");

        let guarded = error.on_the_wire(Disclosure::Minimal);
        assert_eq!(guarded.message, "the catalog store failed");
        assert!(!guarded.message.contains("/var/lib"), "a path escaped");

        let open = error.on_the_wire(Disclosure::Full);
        assert!(open.message.contains("permission denied"));

        // Whatever the wire got, the log gets everything.
        assert!(error.internal_detail().is_some());
    }

    #[test]
    fn test_the_default_posture_is_the_safe_one() {
        assert_eq!(Disclosure::default(), Disclosure::Minimal);
    }
}
