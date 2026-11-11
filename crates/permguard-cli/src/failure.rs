// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! How the CLI fails: the structured refusal it prints, and the exit
//! statuses scripts depend on.
//!
//! The statuses are an interface — documented in the crate root, asserted in
//! the tests — so they live beside the type that carries them rather than
//! being scattered across the commands.

use crate::output::OutputFormat;
/// Every plane it asked about is ready.
pub const EXIT_READY: u8 = 0;
/// No plane answered.
pub const EXIT_UNREACHABLE: u8 = 1;
/// Planes answered, and not all of them are ready.
pub const EXIT_NOT_READY: u8 = 2;
/// The command line, or something it named, was wrong. `EX_USAGE`, from `sysexits`.
pub const EXIT_USAGE: u8 = 64;
/// The plane could not answer right now, and retrying is reasonable: it did not answer at all,
/// or it refused for something that will change without the operator — a ledger with no history
/// yet. `EX_UNAVAILABLE`, from `sysexits`.
pub const EXIT_UNAVAILABLE: u8 = 69;
/// The command failed for an internal reason. `EX_SOFTWARE`, from `sysexits`.
pub const EXIT_SOFTWARE: u8 = 70;

/// A command that could not be carried out.
pub struct Failure {
    /// The closed category a generic handler switches on.
    pub class: String,
    /// The stable name of the exact condition, for a script that parses structured errors.
    pub code: String,
    pub message: String,
    pub status: u8,
}

impl Failure {
    /// Something the operator typed, or named, is wrong. They can fix it.
    pub fn usage(message: impl std::fmt::Display) -> Self {
        Self {
            class: "validation".to_owned(),
            code: permguard_core::codes::client::USAGE.to_owned(),
            message: message.to_string(),
            status: EXIT_USAGE,
        }
    }

    /// The plane could not answer right now: unreachable, or refusing until the world changes.
    /// Nothing the operator typed is wrong and nothing in this CLI failed, so retrying later is
    /// the right response — and the status says so, apart from the `70` a script pages somebody
    /// for.
    pub fn unavailable(message: impl std::fmt::Display) -> Self {
        Self {
            class: "unavailable".to_owned(),
            code: "unavailable".to_owned(),
            message: message.to_string(),
            status: EXIT_UNAVAILABLE,
        }
    }

    /// The command ran and its subject did not pass (TC-1): a failed verification, exit 2.
    pub fn not_passed(message: impl std::fmt::Display, code: &str) -> Self {
        Self {
            class: "validation".to_owned(),
            code: code.to_owned(),
            message: message.to_string(),
            status: EXIT_NOT_READY,
        }
    }

    /// Something failed that the operator did not ask for.
    pub fn internal(message: impl std::fmt::Display) -> Self {
        Self {
            class: "internal".to_owned(),
            code: "internal".to_owned(),
            message: message.to_string(),
            status: EXIT_SOFTWARE,
        }
    }

    /// A refusal a client crate reported, under the class and code the server
    /// named it with.
    ///
    /// One conversion, used by every command that talks to a plane: whether a
    /// refusal is the caller's to fix is the server's judgement, and repeating
    /// that mapping per command is how two commands come to disagree about the
    /// same refusal. The class `unavailable` — the plane's, or the transport's
    /// for a plane that did not answer — is neither the caller's nor this
    /// CLI's, and gets its own status: `ledger_empty` used to exit `70`
    /// beside a decode failure, and a data plane still syncing read as the CLI
    /// being broken.
    pub fn from_client(failure: &permguard_control_client::catalog::Failure) -> Self {
        let failed = if failure.usage {
            Self::usage(&failure.detail)
        } else if failure.class == "unavailable" {
            Self::unavailable(&failure.detail)
        } else {
            Self::internal(&failure.detail)
        };

        failed.named(failure.class.clone(), failure.reason.clone())
    }

    /// The same failure, under the class and code the server named it with.
    pub fn named(mut self, class: impl Into<String>, code: impl Into<String>) -> Self {
        self.class = class.into();
        self.code = code.into();

        self
    }
}

impl Failure {
    /// Writes this refusal to the run's diagnostics in the shape the caller
    /// asked for, and answers with the exit status it carries.
    ///
    /// Here rather than in `main` because the wording, the structure and the
    /// status are one contract: a script reads all three, and they must be
    /// decided in one place.
    pub fn report(&self, format: OutputFormat) -> u8 {
        let text = match format {
            OutputFormat::Terminal => match self.code.as_str() {
                // The generic codes say nothing the sentence does not; the
                // specific ones are what a person greps the docs for.
                "usage" | "unavailable" | "internal" => format!("error: {}\n", self.message),
                code => format!("error: {} ({code})\n", self.message),
            },
            OutputFormat::Json => format!("{}\n", self.structured()),
            OutputFormat::Yaml => {
                let class = if self.class.is_empty() {
                    String::new()
                } else {
                    format!("class: {}\n", self.class)
                };
                format!(
                    "{class}code: {}\nmessage: {}\n",
                    self.code,
                    serde_json::json!(self.message)
                )
            }
        };
        let _ = crate::streams::err(|out| out.write_all(text.as_bytes()));

        self.status
    }

    /// `{class, code, message}`; a denial, `unauthenticated` or `forbidden`, has no class on the
    /// wire and none here: `{code, message}`.
    fn structured(&self) -> serde_json::Value {
        let mut value = serde_json::json!({
            "class": self.class,
            "code": self.code,
            "message": self.message,
        });
        if self.class.is_empty()
            && let Some(fields) = value.as_object_mut()
        {
            fields.remove("class");
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reported(class: &str, usage: bool) -> permguard_control_client::catalog::Failure {
        permguard_control_client::catalog::Failure {
            class: class.to_owned(),
            reason: "some_code".to_owned(),
            detail: "what happened".to_owned(),
            usage,
        }
    }

    /// The three statuses a script branches on, from the three kinds of failure a client reports:
    /// fix the command line, retry later, page somebody.
    #[test]
    fn a_client_failure_exits_with_the_status_its_class_earns() {
        assert_eq!(
            Failure::from_client(&reported("not_found", true)).status,
            EXIT_USAGE
        );
        assert_eq!(
            Failure::from_client(&reported("unavailable", false)).status,
            EXIT_UNAVAILABLE
        );
        assert_eq!(
            Failure::from_client(&reported("internal", false)).status,
            EXIT_SOFTWARE
        );
    }

    /// The server's class and code survive the conversion, whatever the status.
    #[test]
    fn the_server_names_the_failure() {
        let failed = Failure::from_client(&reported("unavailable", false));
        assert_eq!(failed.class, "unavailable");
        assert_eq!(failed.code, "some_code");
        assert_eq!(failed.message, "what happened");
    }

    /// A denial carries a code and no class, as on the wire: never an empty `class`.
    #[test]
    fn a_denial_is_reported_without_a_class() {
        let denied = Failure::from_client(&permguard_control_client::catalog::Failure {
            class: String::new(),
            reason: "forbidden".to_owned(),
            detail: "no scope".to_owned(),
            usage: true,
        });
        assert_eq!(
            denied.structured(),
            serde_json::json!({"code": "forbidden", "message": "no scope"})
        );
        assert_eq!(
            Failure::internal("broken").structured(),
            serde_json::json!({"class": "internal", "code": "internal", "message": "broken"})
        );
    }
}
