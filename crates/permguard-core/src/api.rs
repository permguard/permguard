// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! One shape for every refusal, whatever the wire and whatever the domain.
//!
//! Every API this product exposes answers a failure with the same three fields:
//!
//! * a **class** — which *kind* of thing went wrong, from a closed set a client can switch on;
//! * a **code** — the stable, machine-readable name of the exact condition (`name_taken`,
//!   `not_found`); the contract scripts and SDKs branch on. Every code is registered in
//!   [`crate::codes`];
//! * a **message** — one sentence for a person, free to be reworded between releases.
//!
//! HTTP carries them as a JSON body, gRPC as a status plus metadata, and both derive their status
//! code *from the class*, here and nowhere else — so adding an error never means choosing an HTTP
//! code and a gRPC code in six adapters and hoping they agree. An adapter asks [`ApiError::http_status`]
//! and [`ApiError::grpc_code`] and renders the answer.
//!
//! # Authentication and authorization are not classes
//!
//! A caller that presented no credentials, or invalid ones, and a caller that is known but holds no
//! grant for what it named are told apart on every wire: `401` against `403`, `UNAUTHENTICATED`
//! against `PERMISSION_DENIED`. Neither is a domain refusal, so neither carries a class; they are an
//! [`AccessDenial`], with a code and a sentence, and never reveal whether the thing named exists.
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

use crate::codes;

/// The gRPC metadata key carrying a refusal's class.
///
/// gRPC's status line has one message string; the class and the code — the fields a client switches
/// on — ride as metadata so no client ever parses them out of a sentence. One key pair for every
/// surface and every client, so a refusal reads the same whichever service answered it.
pub const GRPC_ERROR_CLASS: &str = "permguard-error-class";
/// The gRPC metadata key carrying a refusal's stable code.
pub const GRPC_ERROR_CODE: &str = "permguard-error-code";

/// Which kind of thing went wrong: the closed set every API shares.
///
/// The class decides the transport status on every wire, so the mapping lives here, once:
///
/// | class | HTTP | gRPC |
/// | --- | --- | --- |
/// | `validation` | 400 | `INVALID_ARGUMENT` |
/// | `conflict` | 409 | `FAILED_PRECONDITION`, or `ALREADY_EXISTS` for `name_taken`¹ |
/// | `not_found` | 404 | `NOT_FOUND` |
/// | `unavailable` | 503 | `UNAVAILABLE` |
/// | `internal` | 500 | `INTERNAL` |
///
/// ¹ gRPC distinguishes two conflicts HTTP folds into one 409; [`ApiError::grpc_code`] reads the code.
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
    /// Every class, in the order the contract lists them.
    pub const ALL: [ErrorClass; 5] = [
        Self::Validation,
        Self::Conflict,
        Self::NotFound,
        Self::Unavailable,
        Self::Internal,
    ];

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

    /// The HTTP status this class answers with.
    pub fn http_status(self) -> u16 {
        match self {
            Self::Validation => 400,
            Self::Conflict => 409,
            Self::NotFound => 404,
            Self::Unavailable => 503,
            Self::Internal => 500,
        }
    }

    /// The gRPC status this class answers with, before the code refines it.
    pub fn grpc_code(self) -> GrpcCode {
        match self {
            Self::Validation => GrpcCode::InvalidArgument,
            Self::Conflict => GrpcCode::FailedPrecondition,
            Self::NotFound => GrpcCode::NotFound,
            Self::Unavailable => GrpcCode::Unavailable,
            Self::Internal => GrpcCode::Internal,
        }
    }
}

impl std::str::FromStr for ErrorClass {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|class| class.as_str() == value)
            .ok_or_else(|| format!("`{value}` is not an error class"))
    }
}

/// A gRPC status code, named without depending on any gRPC implementation.
///
/// The numbers are the ones every gRPC runtime uses, so an adapter converts by number or by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcCode {
    InvalidArgument,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    FailedPrecondition,
    Internal,
    Unavailable,
    Unauthenticated,
}

impl GrpcCode {
    /// The numeric status code.
    pub fn number(self) -> i32 {
        match self {
            Self::InvalidArgument => 3,
            Self::NotFound => 5,
            Self::AlreadyExists => 6,
            Self::PermissionDenied => 7,
            Self::FailedPrecondition => 9,
            Self::Internal => 13,
            Self::Unavailable => 14,
            Self::Unauthenticated => 16,
        }
    }

    /// The status name as gRPC spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::NotFound => "NOT_FOUND",
            Self::AlreadyExists => "ALREADY_EXISTS",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::FailedPrecondition => "FAILED_PRECONDITION",
            Self::Internal => "INTERNAL",
            Self::Unavailable => "UNAVAILABLE",
            Self::Unauthenticated => "UNAUTHENTICATED",
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
    ///
    /// `code` is one of [`crate::codes`]; the registration test fails the build on any other literal.
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

    /// The HTTP status of this refusal.
    pub fn http_status(&self) -> u16 {
        self.class.http_status()
    }

    /// The gRPC status of this refusal.
    ///
    /// gRPC tells apart the two conflicts HTTP folds into 409: a name that exists already, and a
    /// precondition — an occupied zone, a closed stream — that the caller has to clear first.
    pub fn grpc_code(&self) -> GrpcCode {
        match (self.class, self.code) {
            (ErrorClass::Conflict, codes::catalog::NAME_TAKEN) => GrpcCode::AlreadyExists,
            (class, _) => class.grpc_code(),
        }
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

/// A caller turned away before any domain question was asked.
///
/// Not an [`ApiError`]: it has no class, because the five classes describe a request the service
/// considered, and this request was never considered. The two variants are never interchangeable —
/// answering `403` to a caller that showed nothing would tell it that something exists behind the
/// door, and answering `401` to a caller the service knows would send it to fix a certificate that
/// is not the problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessDenial {
    /// Required credentials are absent or invalid: `401`, `UNAUTHENTICATED`.
    Unauthenticated { code: &'static str, message: String },
    /// The principal is known and holds no grant covering what it named: `403`, `PERMISSION_DENIED`.
    Forbidden { code: &'static str, message: String },
}

impl AccessDenial {
    /// A caller that presented no usable credentials.
    pub fn unauthenticated(message: impl Into<String>) -> Self {
        Self::Unauthenticated {
            code: codes::common::UNAUTHENTICATED,
            message: message.into(),
        }
    }

    /// A known caller without standing for what it named.
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::Forbidden {
            code: codes::common::FORBIDDEN,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Unauthenticated { code, .. } | Self::Forbidden { code, .. } => code,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Unauthenticated { message, .. } | Self::Forbidden { message, .. } => message,
        }
    }

    pub fn http_status(&self) -> u16 {
        match self {
            Self::Unauthenticated { .. } => 401,
            Self::Forbidden { .. } => 403,
        }
    }

    pub fn grpc_code(&self) -> GrpcCode {
        match self {
            Self::Unauthenticated { .. } => GrpcCode::Unauthenticated,
            Self::Forbidden { .. } => GrpcCode::PermissionDenied,
        }
    }

    /// What the wire carries: the code and the sentence, nothing about what exists.
    pub fn on_the_wire(&self) -> WireDenial {
        WireDenial {
            code: self.code().to_owned(),
            message: self.message().to_owned(),
        }
    }
}

impl fmt::Display for AccessDenial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.message(), self.code())
    }
}

impl std::error::Error for AccessDenial {}

/// An access denial as it is serialised.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireDenial {
    /// `unauthenticated` or `forbidden`.
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
            codes::catalog::CATALOG_FAILED,
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

    #[test]
    fn test_the_class_decides_both_statuses_once() {
        let expected = [
            (ErrorClass::Validation, 400, GrpcCode::InvalidArgument),
            (ErrorClass::Conflict, 409, GrpcCode::FailedPrecondition),
            (ErrorClass::NotFound, 404, GrpcCode::NotFound),
            (ErrorClass::Unavailable, 503, GrpcCode::Unavailable),
            (ErrorClass::Internal, 500, GrpcCode::Internal),
        ];
        for (class, http, grpc) in expected {
            assert_eq!(class.http_status(), http, "{}", class.as_str());
            assert_eq!(class.grpc_code(), grpc, "{}", class.as_str());
            assert_eq!(class.as_str().parse::<ErrorClass>(), Ok(class));
        }
    }

    #[test]
    fn test_a_taken_name_is_the_one_conflict_grpc_calls_already_exists() {
        let taken = ApiError::new(
            ErrorClass::Conflict,
            codes::catalog::NAME_TAKEN,
            "the name is taken",
        );
        let occupied = ApiError::new(
            ErrorClass::Conflict,
            codes::catalog::NOT_EMPTY,
            "the zone is not empty",
        );

        assert_eq!(taken.grpc_code(), GrpcCode::AlreadyExists);
        assert_eq!(occupied.grpc_code(), GrpcCode::FailedPrecondition);
        assert_eq!(taken.http_status(), occupied.http_status());
    }

    #[test]
    fn test_a_denial_tells_missing_credentials_from_missing_standing() {
        let missing = AccessDenial::unauthenticated("present a client certificate");
        let known = AccessDenial::forbidden("this surface does not answer this peer");

        assert_eq!(missing.http_status(), 401);
        assert_eq!(missing.grpc_code(), GrpcCode::Unauthenticated);
        assert_eq!(known.http_status(), 403);
        assert_eq!(known.grpc_code(), GrpcCode::PermissionDenied);
        assert_eq!(missing.on_the_wire().code, "unauthenticated");
        assert_eq!(known.on_the_wire().code, "forbidden");
    }
}
