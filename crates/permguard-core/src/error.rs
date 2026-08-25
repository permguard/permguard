// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What can go wrong, said in a way a caller can act on.
//!
//! Every contract in this crate reports a typed error rather than an opaque one, and the reason is
//! not tidiness. A caller that cannot tell *why* something failed has to treat every failure the
//! same, and treating "this secret does not exist" the same as "the store is unreachable" is how a
//! system ends up denying access during an outage — or, worse, allowing it.
//!
//! Each contract has its own error type, because the questions differ: a store can report a record
//! that is not there, a secret store must distinguish absence from denial, a service can only really
//! say that it failed to come up and why. What they share is that every variant is something the
//! caller might reasonably branch on, and everything else — a bad path, a malformed file, a socket
//! that would not bind — collapses into `Backend`, which carries the original cause.
//!
//! Applications still use `anyhow`. The binary and the surfaces do, and they should: an application
//! wants a chain of context to print. A *contract* wants a value the other side can match on.

use std::fmt;

/// The cause an error carries when the reason is not one the caller can branch on.
///
/// Boxed rather than typed because the interesting part has already been captured by the variant;
/// this is what a human reads afterwards.
pub type Cause = Box<dyn std::error::Error + Send + Sync>;

/// What can go wrong reading or writing a record.
#[derive(Debug)]
pub enum StorageError {
    /// The key was never written, or was written and then removed.
    ///
    /// Distinct from a failure: a caller asking whether something exists has its answer.
    NotFound {
        /// The key that was asked for.
        key: String,
    },
    /// The store could not be reached or would not answer.
    ///
    /// Retryable in a way the others are not, which is the whole point of it being its own variant.
    Unavailable(Cause),
    /// Anything else the backend reported.
    Backend(Cause),
}

/// What can go wrong resolving secret material.
#[derive(Debug)]
pub enum SecretError {
    /// No secret is registered under that reference.
    NotFound {
        /// The reference that was asked for.
        reference: String,
    },
    /// The store knows the secret and refused to hand it over.
    ///
    /// The distinction from [`SecretError::NotFound`] matters: one is a configuration mistake, the
    /// other is a policy decision, and answering them the same way tells an attacker which is which.
    Denied {
        /// The reference that was refused.
        reference: String,
    },
    /// The store could not be reached or would not answer.
    ///
    /// The variant that must never be mistaken for absence. A secret store that is down and a secret
    /// that does not exist look identical to a caller that only has one failure — and a build that
    /// treats them the same either fails open during an outage or fails shut forever.
    Unavailable(Cause),
    /// Anything else the backend reported.
    Backend(Cause),
}

/// What can go wrong signing with, or publishing, a key.
#[derive(Debug)]
pub enum KeyError {
    /// No key is signing yet.
    ///
    /// Its own variant because it is the one failure a caller must never paper over: a deployment
    /// whose key ring is still coming up has to refuse to sign, not sign under something no verifier
    /// has been given a chance to fetch.
    NotReady {
        /// What the manager is waiting for.
        detail: String,
    },
    /// The key store could not be reached or would not answer.
    Unavailable(Cause),
    /// Anything else the manager reported.
    Backend(Cause),
}

/// What can go wrong recording an audit event.
#[derive(Debug)]
pub enum AuditError {
    /// The destination could not be reached or would not answer.
    Unavailable(Cause),
    /// Anything else the sink reported.
    Backend(Cause),
}

/// What can go wrong bringing a service up or taking it down.
#[derive(Debug)]
pub enum ServiceError {
    /// The address it was told to listen on is already in use.
    ///
    /// Nearly always another copy of the same process, and worth saying so rather than making an
    /// operator read a generic message and guess.
    AddressInUse {
        /// The address that was refused.
        address: String,
    },
    /// The configuration it read does not describe something it can do.
    Configuration {
        /// What was wrong with it.
        detail: String,
    },
    /// Anything else that stopped it.
    Failed(Cause),
}

macro_rules! typed_error {
    ($name:ident { $($variant:pat => $message:expr),+ $(,)? }) => {
        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    $($variant => write!(formatter, "{}", $message),)+
                }
            }
        }

        impl std::error::Error for $name {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                match self {
                    Self::Backend(cause) => Some(cause.as_ref()),
                    _ => self.cause(),
                }
            }
        }
    };
}

impl StorageError {
    /// Wraps any error as a backend failure.
    pub fn backend(cause: impl Into<Cause>) -> Self {
        Self::Backend(cause.into())
    }

    /// Wraps any error as the store being unreachable.
    pub fn unavailable(cause: impl Into<Cause>) -> Self {
        Self::Unavailable(cause.into())
    }

    /// Reports whether trying again could plausibly succeed.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Unavailable(_))
    }

    fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unavailable(cause) | Self::Backend(cause) => Some(cause.as_ref()),
            Self::NotFound { .. } => None,
        }
    }
}

typed_error!(StorageError {
    Self::NotFound { key } => format!("no record under `{key}`"),
    Self::Unavailable(cause) => format!("the record store is unavailable: {cause}"),
    Self::Backend(cause) => format!("the record store failed: {cause}"),
});

impl SecretError {
    /// Wraps any error as a backend failure.
    pub fn backend(cause: impl Into<Cause>) -> Self {
        Self::Backend(cause.into())
    }

    /// Wraps any error as the store being unreachable.
    pub fn unavailable(cause: impl Into<Cause>) -> Self {
        Self::Unavailable(cause.into())
    }

    /// Reports whether trying again could plausibly succeed.
    ///
    /// This is the question a caller has to be able to ask. A build that cannot resolve a signing key
    /// should refuse and retry when the store is down, and refuse permanently when the reference is
    /// simply wrong — and those are opposite behaviours.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Unavailable(_))
    }

    fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unavailable(cause) | Self::Backend(cause) => Some(cause.as_ref()),
            Self::NotFound { .. } | Self::Denied { .. } => None,
        }
    }
}

typed_error!(SecretError {
    Self::NotFound { reference } => format!("no secret named `{reference}`"),
    Self::Denied { reference } => format!("access to the secret `{reference}` was denied"),
    Self::Unavailable(cause) => format!("the secret store is unavailable: {cause}"),
    Self::Backend(cause) => format!("the secret store failed: {cause}"),
});

impl KeyError {
    /// Wraps any error as a backend failure.
    pub fn backend(cause: impl Into<Cause>) -> Self {
        Self::Backend(cause.into())
    }

    /// Wraps any error as the key store being unreachable.
    pub fn unavailable(cause: impl Into<Cause>) -> Self {
        Self::Unavailable(cause.into())
    }

    /// Reports that nothing is signing yet, and what is being waited for.
    pub fn not_ready(detail: impl Into<String>) -> Self {
        Self::NotReady {
            detail: detail.into(),
        }
    }

    /// Reports whether trying again could plausibly succeed.
    ///
    /// A key ring that is not ready yet becomes ready on its own, which is exactly the case a caller
    /// should retry rather than fail permanently on.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Unavailable(_) | Self::NotReady { .. })
    }

    fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unavailable(cause) | Self::Backend(cause) => Some(cause.as_ref()),
            Self::NotReady { .. } => None,
        }
    }
}

typed_error!(KeyError {
    Self::NotReady { detail } => format!("no key is signing yet: {detail}"),
    Self::Unavailable(cause) => format!("the key store is unavailable: {cause}"),
    Self::Backend(cause) => format!("the key store failed: {cause}"),
});

impl AuditError {
    /// Wraps any error as a backend failure.
    pub fn backend(cause: impl Into<Cause>) -> Self {
        Self::Backend(cause.into())
    }

    /// Wraps any error as the destination being unreachable.
    pub fn unavailable(cause: impl Into<Cause>) -> Self {
        Self::Unavailable(cause.into())
    }

    /// Reports whether trying again could plausibly succeed.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Unavailable(_))
    }

    fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unavailable(cause) | Self::Backend(cause) => Some(cause.as_ref()),
        }
    }
}

typed_error!(AuditError {
    Self::Unavailable(cause) => format!("the audit destination is unavailable: {cause}"),
    Self::Backend(cause) => format!("the audit destination failed: {cause}"),
});

impl ServiceError {
    /// Wraps any error as a plain failure.
    pub fn failed(cause: impl Into<Cause>) -> Self {
        Self::Failed(cause.into())
    }

    /// Reports that the configuration does not describe something this service can do.
    pub fn configuration(detail: impl Into<String>) -> Self {
        Self::Configuration {
            detail: detail.into(),
        }
    }

    fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Failed(cause) => Some(cause.as_ref()),
            Self::AddressInUse { .. } | Self::Configuration { .. } => None,
        }
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AddressInUse { address } => {
                write!(formatter, "{address} is already in use")
            }
            Self::Configuration { detail } => write!(formatter, "{detail}"),
            Self::Failed(cause) => write!(formatter, "{cause}"),
        }
    }
}

impl std::error::Error for ServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_absence_and_unavailability_are_different_answers() {
        let absent = SecretError::NotFound {
            reference: "signing-key".to_owned(),
        };
        let down = SecretError::unavailable(std::io::Error::other("connection refused"));

        // The distinction a caller has to be able to make, and the reason these are typed at all.
        assert!(!absent.is_retryable());
        assert!(down.is_retryable());
    }

    #[test]
    fn test_denial_does_not_read_as_absence() {
        let denied = SecretError::Denied {
            reference: "signing-key".to_owned(),
        };

        assert!(format!("{denied}").contains("denied"));
        assert!(!format!("{denied}").contains("no secret"));
    }

    #[test]
    fn test_a_backend_failure_keeps_the_cause_it_was_given() {
        let error = StorageError::backend(std::io::Error::other("disk went away"));

        assert!(format!("{error}").contains("disk went away"));
        assert!(std::error::Error::source(&error).is_some());
    }

    #[test]
    fn test_an_address_in_use_says_which_one() {
        let error = ServiceError::AddressInUse {
            address: "0.0.0.0:7556".to_owned(),
        };

        assert!(format!("{error}").contains("0.0.0.0:7556"));
    }

    #[test]
    fn test_every_error_is_a_std_error_so_anyhow_can_still_carry_it() {
        fn accepts(_: impl std::error::Error + Send + Sync + 'static) {}

        accepts(StorageError::NotFound { key: "a".into() });
        accepts(SecretError::NotFound {
            reference: "a".into(),
        });
        accepts(AuditError::backend(std::io::Error::other("x")));
        accepts(ServiceError::configuration("no address"));
    }
}
