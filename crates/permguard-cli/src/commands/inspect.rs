// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `inspect`: ask every configured plane what it is and whether it is ready,
//! and turn the answers into an exit status a deployment can gate on.

use std::process::ExitCode;
use std::time::Duration;

use crate::args::Globals;
use crate::failure::Failure;
use crate::inspect;
use crate::session::{open_store, render, resolve_endpoint};
use crate::trace::{self, Trace};
use crate::{EXIT_NOT_READY, EXIT_READY, EXIT_UNREACHABLE};
use permguard_control_client::TlsOptions;
use permguard_control_client::http::Client;

pub fn inspect_command(
    globals: &Globals,
    timeout: u64,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    let store = open_store(globals, trace)?;
    let control = resolve_endpoint(
        "control-plane.endpoint",
        globals.control_endpoint.as_deref(),
        &store,
        trace,
    )?;
    let data = resolve_endpoint(
        "data-plane.endpoint",
        globals.data_endpoint.as_deref(),
        &store,
        trace,
    )?;

    let tls = TlsOptions {
        ca_file: globals.tls_ca_file.clone(),
        cert_file: globals.tls_cert_file.clone(),
        key_file: globals.tls_key_file.clone(),
        server_name: globals.tls_server_name.clone(),
        skip_verify: globals.tls_skip_verify,
    }
    .rooted_at(&globals.workdir);
    let needs_tls = control.is_tls() || data.is_tls();

    if needs_tls {
        if tls.skip_verify {
            // Said whether or not narration was asked for: an operator who does not know this is on
            // believes they checked something they did not.
            trace::warn(
                "TLS certificate verification is disabled: the endpoint is not authenticated",
            );
        }

        trace.say(format!(
            "TLS: {}, trust anchors from {}",
            if tls.is_mutual() {
                "mutual"
            } else {
                "server authentication only"
            },
            tls.ca_file
                .as_deref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "the platform store".to_owned())
        ));
    }

    let client =
        Client::new(Duration::from_secs(timeout.max(1)), tls, needs_tls).map_err(Failure::usage)?;
    let report = inspect::inspect(&client, &control, &data, trace);

    render(&report, globals.output, trace)?;

    // The report is the answer, so a plane that is down is not an error. What the status carries is
    // the one thing a script cannot read from a report it did not parse: nothing answered, so there
    // was no runtime to inspect, is a different situation from a runtime that answered and is not
    // serving yet.
    Ok(ExitCode::from(if report.reachable == 0 {
        EXIT_UNREACHABLE
    } else if report.ready < report.total {
        EXIT_NOT_READY
    } else {
        EXIT_READY
    }))
}
