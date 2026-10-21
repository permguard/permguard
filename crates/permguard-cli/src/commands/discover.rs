// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `discover <url>`: walk the discovery chain from one address (WP-7.4b).

use std::process::ExitCode;
use std::time::Duration;

use crate::args::Globals;
use crate::discover::{Clients, DiscoverError};
use crate::failure::{EXIT_READY, EXIT_UNAVAILABLE, Failure};
use crate::session::{open_store, render};
use crate::trace::{self, Trace};
use permguard_control_client::http::Client;

pub fn discover_command(
    globals: &Globals,
    url: &str,
    timeout: u64,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    // The address the operator typed is judged first: a typo is a usage error, never hidden behind
    // a configuration that does not read (after the review).
    crate::discover::start_address(url).map_err(Failure::usage)?;
    let store = open_store(globals, trace)?;
    // The TLS flags as `inspect` reads them, the operator's token left out: discovery is
    // unauthenticated, and a link may name another host.
    let mut home = crate::target::tls(globals, &store, trace)?;
    home.token = None;
    if home.skip_verify {
        trace::warn("TLS certificate verification is disabled: the endpoint is not authenticated");
    }
    // Every other host a document names is reached presenting no client certificate.
    let mut away = home.clone();
    away.cert_file = None;
    away.key_file = None;
    away.key_pem = None;
    let within = Duration::from_secs(timeout.max(1));
    // TLS is made ready whatever the first address: a link may lead to an HTTPS one.
    let home = Client::new(within, home, true).map_err(Failure::usage)?;
    let away = Client::new(within, away, true).map_err(Failure::usage)?;
    let report = crate::discover::discover(
        Clients {
            home: &home,
            away: &away,
        },
        url,
        trace,
    )
    .map_err(|error| match error {
        DiscoverError::Address(why) => Failure::usage(why),
        DiscoverError::Unreachable(why) => Failure::unavailable(why),
    })?;
    render(&report, globals.output, trace)?;
    Ok(ExitCode::from(if report.complete {
        EXIT_READY
    } else {
        EXIT_UNAVAILABLE
    }))
}
