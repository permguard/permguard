// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The audit contract Permguard records against.
//!
//! An audit trail is the one place in this workspace where personal data may legitimately appear, and
//! the type system says so out loud: [`Subject`] distinguishes a part of the system from a person, so
//! a sink always knows which of the two it is holding. Everything else — the lifecycle log — carries
//! no personal data at all, which is what keeps retention, access control, and data-subject requests
//! a concern of one component instead of the whole stream.

use std::fmt;
use std::str::FromStr;

use crate::error::AuditError;
use crate::future::{BoxFuture, ready};

/// What an audit destination answers with.
pub type Result<T> = std::result::Result<T, AuditError>;
use crate::pseudonym::Pseudonymizer;

/// Where a deployment writes its audit trail.
///
/// An enum in configuration, a trait in code — the same arrangement as
/// [`SecretProvider`](crate::secrets::SecretProvider), for the same reason: this names which
/// implementation a binary should build, and the binary stays the only place that names the type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuditDestination {
    /// Into the process's own log stream, and from there wherever the log stream goes.
    ///
    /// The default, and the right one when something else is already collecting logs durably. It is
    /// also the one with no integrity of its own: whatever holds the log decides whether a record can
    /// be altered after the fact.
    #[default]
    Tracing,
    /// Into a file the process appends to, chained so that a later edit is detectable.
    File,
}

impl AuditDestination {
    /// Returns the name this destination is written as.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tracing => "tracing",
            Self::File => "file",
        }
    }

    /// Every destination a configuration may name.
    pub const ALL: [Self; 2] = [Self::Tracing, Self::File];
}

impl FromStr for AuditDestination {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> anyhow::Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "tracing" | "log" | "" => Ok(Self::Tracing),
            "file" | "directory" => Ok(Self::File),
            other => anyhow::bail!(
                "`{other}` is not an audit destination: expected one of {}",
                Self::ALL.map(|destination| destination.as_str()).join(", ")
            ),
        }
    }
}

impl fmt::Display for AuditDestination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// How sensitive what a record names is, and therefore what may be done with it.
///
/// Kept apart from *what kind of thing* the subject is, because the two answer different questions
/// and change independently. The kind is domain vocabulary — a continuity is not a person and not a
/// component. The sensitivity is the handling rule that retention, access control and data-subject
/// requests key on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Sensitivity {
    /// Names nothing outside the running process. Free to keep, free to show.
    Public,
    /// Already opaque, but linkable: the same value identifies the same thing over time.
    ///
    /// Still personal data whenever the thing behind it turns out to be a person, which is why this
    /// is its own level rather than a synonym for public.
    Pseudonymous,
    /// Names a person. Never reaches a log in the clear.
    Personal,
}

impl Sensitivity {
    /// Returns the name this level is written as, for the `audit.subject.sensitivity` field.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Pseudonymous => "pseudonymous",
            Self::Personal => "personal",
        }
    }
}

/// Who or what an audit event is about.
///
/// Not everything a Permguard record names is a person or a component. A continuity has no person behind
/// it that anything here knows of; an exchange may be authorised by a capability — a key — with no
/// identity attached at all. Forcing those into "principal or system" would either overstate what is
/// known about them or lose them entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subject<'a> {
    /// A part of the running system: a host, a service, a component.
    System(&'a str),
    /// A person or an account that acted.
    Principal(&'a str),
    /// A continuity: an identity that persists across exchanges with no person named behind it.
    Continuity(&'a str),
    /// A capability presented instead of an identity — a key thumbprint, typically.
    Capability(&'a str),
    /// The event names nothing identifiable at all.
    Anonymous,
}

impl<'a> Subject<'a> {
    /// Returns the underlying value, when there is one.
    ///
    /// Reading a [`Subject::Principal`] in the clear is a deliberate act: this is the call to look for
    /// in review, and the one [`Subject::render`] exists to avoid.
    pub fn value(&self) -> Option<&'a str> {
        match self {
            Self::System(value)
            | Self::Principal(value)
            | Self::Continuity(value)
            | Self::Capability(value) => Some(value),
            Self::Anonymous => None,
        }
    }

    /// Returns how sensitive this subject is, and therefore how it must be handled.
    pub fn sensitivity(&self) -> Sensitivity {
        match self {
            Self::System(_) | Self::Anonymous => Sensitivity::Public,
            Self::Continuity(_) | Self::Capability(_) => Sensitivity::Pseudonymous,
            Self::Principal(_) => Sensitivity::Personal,
        }
    }

    /// Reports whether this subject names a person.
    pub fn is_personal(&self) -> bool {
        self.sensitivity() == Sensitivity::Personal
    }

    /// Returns the name of this kind, for the `audit.subject.kind` field of a record.
    ///
    /// A record says which kind it carried even when the value itself is masked, so an operator can
    /// see that a person was involved without seeing who.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::System(_) => "system",
            Self::Principal(_) => "principal",
            Self::Continuity(_) => "continuity",
            Self::Capability(_) => "capability",
            Self::Anonymous => "anonymous",
        }
    }

    /// Renders this subject the way the privacy policy in force says it may appear.
    ///
    /// Only a principal is transformed. A continuity and a capability are already opaque, and putting
    /// them through a pseudonymiser would break the one thing they are for: recognising the same
    /// continuity, or the same key, across records and across an investigation.
    pub fn render(&self, policy: Option<&dyn Pseudonymizer>) -> String {
        match (self, policy) {
            (Self::Principal(value), Some(policy)) => policy.pseudonymize(value),
            _ => self.to_string(),
        }
    }
}

impl fmt::Display for Subject<'_> {
    /// Renders everything as itself except a principal, which never formats readable.
    ///
    /// Formatting is the accident-prone path — an interpolation in a diagnostic, a `{}` in a message —
    /// so it is the path that must not reveal a person by default.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::System(value) | Self::Continuity(value) | Self::Capability(value) => {
                formatter.write_str(value)
            }
            Self::Principal(value) => {
                write!(formatter, "{}", crate::redact::Masked::full(value))
            }
            Self::Anonymous => formatter.write_str("-"),
        }
    }
}

/// One thing worth recording: what happened, who it was about, and what it was done to.
///
/// The subject is the actor — who did it, or who it concerns. The target is the thing acted on, and
/// it is separate because the two answer different questions and only one of them can be a person.
/// An audit trail that records "somebody administered this deployment" without recording *what* they
/// administered is a trail that can establish blame and not much else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditEvent<'a> {
    action: &'a str,
    subject: Subject<'a>,
    target: Option<&'a str>,
    continuity_id: Option<&'a str>,
    continuity_position: Option<u64>,
}

impl<'a> AuditEvent<'a> {
    /// Builds an event describing `action` performed by or about `subject`.
    pub fn new(action: &'a str, subject: Subject<'a>) -> Self {
        Self {
            action,
            subject,
            target: None,
            continuity_id: None,
            continuity_position: None,
        }
    }

    /// Names what the action was done to.
    ///
    /// A target is never a person — that is what the subject is for — so it reaches a sink as it was
    /// written, with no masking and no pseudonymisation.
    pub fn on(mut self, target: &'a str) -> Self {
        self.target = Some(target);

        self
    }

    /// Adds the stable continuity/lineage identifier associated with this event.
    pub fn with_continuity_id(mut self, continuity_id: &'a str) -> Self {
        self.continuity_id = Some(continuity_id);

        self
    }

    /// Adds the PCA position associated with this event.
    pub fn at_continuity_position(mut self, position: u64) -> Self {
        self.continuity_position = Some(position);

        self
    }

    /// Returns what the action was done to, when the event names something.
    pub fn target(&self) -> Option<&'a str> {
        self.target
    }

    /// Returns the stable continuity/lineage identifier, when present.
    pub fn continuity_id(&self) -> Option<&'a str> {
        self.continuity_id
    }

    /// Returns the PCA position, when present.
    pub fn continuity_position(&self) -> Option<u64> {
        self.continuity_position
    }

    /// Builds an event about a part of the system.
    pub fn system(action: &'a str, subject: &'a str) -> Self {
        Self::new(action, Subject::System(subject))
    }

    /// Builds an event about a person or an account.
    pub fn principal(action: &'a str, subject: &'a str) -> Self {
        Self::new(action, Subject::Principal(subject))
    }

    /// Builds an event about a continuity.
    pub fn continuity(action: &'a str, subject: &'a str) -> Self {
        Self::new(action, Subject::Continuity(subject))
    }

    /// Builds an event about the capability that authorised it.
    pub fn capability(action: &'a str, subject: &'a str) -> Self {
        Self::new(action, Subject::Capability(subject))
    }

    /// Builds an event that names nothing identifiable.
    pub fn anonymous(action: &'a str) -> Self {
        Self::new(action, Subject::Anonymous)
    }

    /// Returns what happened.
    pub fn action(&self) -> &str {
        self.action
    }

    /// Returns what it happened to.
    pub fn subject(&self) -> Subject<'a> {
        self.subject
    }
}

/// The destination audit events are recorded to.
///
/// Implementations are shared across tasks, so they are `Send + Sync` and take `&self`.
pub trait AuditSink: Send + Sync {
    /// Returns the name of this implementation, for banners and diagnostics.
    fn name(&self) -> &'static str;

    /// Releases whatever this sink is holding, before the process goes away.
    ///
    /// The host calls it during shutdown, within the configured budget. A sink that batches records,
    /// holds a connection to a collector, or has a file to flush does that work here — an audit trail
    /// that loses its tail because the process exited first is an audit trail with a hole in it.
    fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
        ready(Ok(()))
    }

    /// Records one event under the privacy policy in force, or reports why it could not be recorded.
    ///
    /// The policy is a parameter rather than something the sink was built with, because the sink is
    /// composed before the configuration that decides the policy has been read. It is also why the
    /// sink still receives the [`Subject`] itself: a destination that legitimately holds identities —
    /// an access-controlled audit store, say — can read it, and one that writes to a log stream calls
    /// [`Subject::render`] and writes what comes back.
    fn record<'a>(
        &'a self,
        event: &'a AuditEvent<'a>,
        policy: Option<&'a dyn Pseudonymizer>,
    ) -> BoxFuture<'a, Result<()>>;
}
