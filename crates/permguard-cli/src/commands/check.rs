// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `permguard check` — ask a data plane for a decision.
//!
//! # Two ways to ask
//!
//! A **document**, which is the profile's own payload, from a file or standard
//! input — what a test suite keeps in version control and what an SDK would
//! send. Or **flags**, for the question a person asks at a terminal:
//!
//! ```text
//! permguard check -f request.json
//! cat request.json | permguard check -f -
//! permguard check --subject user:alice --action read --resource document:budget
//! ```
//!
//! # Which store the question is about
//!
//! [`crate::target`] answers that, once, for every command: the flags win, a
//! workspace comes next, and the document's own `zone`/`ledger` are the
//! fallback. Standing in a checked-out ledger, `check` therefore asks about
//! *that* ledger — the whole point of standing there — and
//! `--ignore-workspace` sends the document untouched.
//!
//! # What comes back
//!
//! The server's answer, unchanged, through the CLI's one output contract:
//! `terminal`, `json` and `yaml` from the same data. A **deny is an answer**,
//! so it prints as a decision and exits 0; only a request that could not be
//! evaluated is a failure with a non-zero exit.

use std::io::Read as _;
use std::process::ExitCode;

use serde_json::{Map, Value};

use permguard_control_client::pdp;

use crate::args::{CheckArgs, Globals};
use crate::failure::{EXIT_READY, Failure};
use crate::session::{open_store, render};
use crate::target::{self, Asked};
use crate::trace::Trace;
use crate::workspace_out::CheckReport;

/// Runs the command.
pub fn check(globals: &Globals, args: &CheckArgs) -> Result<ExitCode, Failure> {
    let trace = Trace::new(globals.verbose);
    let store = open_store(globals, &trace)?;
    let asked = Asked {
        zone: args.zone.clone(),
        ledger: args.ledger.clone(),
        ignore_workspace: args.ignore_workspace,
    };
    let target = target::resolve(
        "data-plane.endpoint",
        globals.data_endpoint.as_deref(),
        &asked,
        globals,
        &store,
        &trace,
    )?;

    let mut payload = document(args)?;
    apply_store(&mut payload, &target)?;
    if let Some(profile) = &args.profile {
        payload["profile"] = Value::String(profile.clone());
    }
    trace.say(format!(
        "asking {} about {}",
        target.endpoint,
        store_of(&payload)
    ));

    let client = pdp::client(
        &target.endpoint,
        &target::tls(globals),
        crate::narrator::for_run(globals.verbose),
    )
    .map_err(Failure::usage)?;
    let answer = client
        .evaluate(&payload)
        .map_err(|failure| Failure::from_client(&failure))?;

    let report = CheckReport::of(&payload, &answer, target.origin);

    render(&report, globals.output, &trace)?;

    // A deny is an answer, not a failure: a script that branches on the exit
    // code of `check` would be a script that cannot tell a deny from a PDP
    // that is down. It branches on `decision` instead.
    Ok(ExitCode::from(EXIT_READY))
}

/// The request: a document, or the flags that describe one.
fn document(args: &CheckArgs) -> Result<Value, Failure> {
    if let Some(path) = &args.file {
        let text = if path == "-" {
            let mut text = String::new();
            std::io::stdin()
                .read_to_string(&mut text)
                .map_err(|error| Failure::usage(format!("reading the request: {error}")))?;
            text
        } else {
            std::fs::read_to_string(path)
                .map_err(|error| Failure::usage(format!("reading {path}: {error}")))?
        };
        let payload: Value = serde_json::from_str(&text)
            .map_err(|error| Failure::usage(format!("the request is not valid JSON: {error}")))?;
        if !payload.is_object() {
            return Err(Failure::usage(
                "a request is a JSON object — the payload `permguard.pdp.v1` documents",
            ));
        }

        return Ok(payload);
    }

    // The terminal form. Every part is required, because a decision about an
    // unnamed subject or resource is not a decision.
    let subject = pair(args.subject.as_deref(), "--subject", "user:alice")?;
    let resource = pair(args.resource.as_deref(), "--resource", "document:budget")?;
    let action = args.action.clone().ok_or_else(|| {
        Failure::usage(
            "--action names the operation, e.g. --action read (or -f to send a document)",
        )
    })?;
    let context = match &args.context {
        None => Map::new(),
        Some(text) => serde_json::from_str::<Map<String, Value>>(text)
            .map_err(|error| Failure::usage(format!("--context is a JSON object: {error}")))?,
    };

    Ok(pdp::payload(
        "",
        "",
        (&subject.0, &subject.1),
        &action,
        (&resource.0, &resource.1),
        context,
    ))
}

/// `type:id`, the shape a person types.
fn pair(value: Option<&str>, flag: &str, example: &str) -> Result<(String, String), Failure> {
    let value = value.ok_or_else(|| {
        Failure::usage(format!(
            "{flag} is `type:id`, e.g. {flag} {example} (or -f to send a document)"
        ))
    })?;

    match value.split_once(':') {
        Some((kind, id)) if !kind.trim().is_empty() && !id.trim().is_empty() => {
            Ok((kind.to_owned(), id.to_owned()))
        }
        _ => Err(Failure::usage(format!(
            "{flag} is `type:id`, e.g. {flag} {example}"
        ))),
    }
}

/// Puts the resolved store into the payload, and refuses a request that names
/// none — the same rule the server enforces, said before a round trip.
fn apply_store(payload: &mut Value, target: &target::Target) -> Result<(), Failure> {
    if target.names_store() {
        payload["zone"] = Value::String(target.zone.clone().unwrap_or_default());
        payload["ledger"] = Value::String(target.ledger.clone().unwrap_or_default());
    }
    let named = |field: &str| {
        payload
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
    };
    if named("zone") && named("ledger") {
        return Ok(());
    }

    Err(Failure::usage(
        "this request names no zone and ledger: state them in the document, pass --zone and \
         --ledger, or run inside a workspace that tracks a ledger",
    ))
}

fn store_of(payload: &Value) -> String {
    let field = |name: &str| {
        payload
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };

    format!("{}/{}", field("zone"), field("ledger"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn args() -> CheckArgs {
        CheckArgs {
            file: None,
            zone: None,
            ledger: None,
            profile: None,
            subject: None,
            action: None,
            resource: None,
            context: None,
            ignore_workspace: false,
        }
    }

    #[test]
    fn the_flag_form_builds_the_documented_payload() {
        let mut asked = args();
        asked.subject = Some("user:alice".to_owned());
        asked.action = Some("read".to_owned());
        asked.resource = Some("document:budget".to_owned());
        asked.context = Some(r#"{"time": "2026-08-24T10:00:00Z"}"#.to_owned());

        let payload = document(&asked)
            .map_err(|failure| failure.message)
            .expect("the flags describe a request");
        assert_eq!(payload["subject"]["type"], "user");
        assert_eq!(payload["subject"]["id"], "alice");
        assert_eq!(payload["action"]["name"], "read");
        assert_eq!(payload["resource"]["type"], "document");
        assert_eq!(payload["context"]["time"], "2026-08-24T10:00:00Z");
    }

    #[test]
    fn a_half_written_flag_is_refused_with_the_shape_it_wanted() {
        let mut asked = args();
        asked.subject = Some("alice".to_owned());
        asked.action = Some("read".to_owned());
        asked.resource = Some("document:budget".to_owned());

        let refused = document(&asked)
            .err()
            .map(|failure| failure.message)
            .expect("`alice` is not `type:id`");
        assert!(refused.contains("type:id"), "{refused}");
    }

    #[test]
    fn the_workspace_overrides_the_document_and_ignore_workspace_does_not() {
        let mut payload = serde_json::json!({
            "zone": "from-file", "ledger": "from-file",
            "subject": {"type": "user", "id": "alice"}
        });
        let workspace = target::Target {
            endpoint: "http://127.0.0.1:7656".to_owned(),
            zone: Some("acme".to_owned()),
            ledger: Some("main-ledger".to_owned()),
            origin: "workspace",
        };
        apply_store(&mut payload, &workspace)
            .map_err(|failure| failure.message)
            .expect("the store is named");
        assert_eq!(payload["zone"], "acme");
        assert_eq!(payload["ledger"], "main-ledger");

        let mut untouched = serde_json::json!({"zone": "from-file", "ledger": "from-file"});
        let ignored = target::Target {
            endpoint: "http://127.0.0.1:7656".to_owned(),
            zone: None,
            ledger: None,
            origin: "payload",
        };
        apply_store(&mut untouched, &ignored)
            .map_err(|failure| failure.message)
            .expect("the document names its own");
        assert_eq!(untouched["zone"], "from-file");
    }

    #[test]
    fn a_request_that_names_no_store_anywhere_is_refused_before_the_round_trip() {
        let mut payload = serde_json::json!({"subject": {"type": "user", "id": "alice"}});
        let nothing = target::Target {
            endpoint: "http://127.0.0.1:7656".to_owned(),
            zone: None,
            ledger: None,
            origin: "payload",
        };

        let refused = apply_store(&mut payload, &nothing)
            .err()
            .map(|failure| failure.message)
            .expect("there is no default store");
        assert!(refused.contains("--zone"), "{refused}");
    }
}
