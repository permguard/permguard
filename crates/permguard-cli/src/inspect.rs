// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the planes are, and whether they are willing to be sent work.
//!
//! # Why a plane that answers is not therefore healthy
//!
//! A plane reports two states, and they mean different things: `live` answers "is this process
//! wedged", and a `false` means *restart me*; `ready` answers "should I be sent work", and it goes
//! false at the very first instant of shutdown, before anything is closed, so a load balancer stops
//! routing while the process finishes what it already has.
//!
//! So the three-way distinction is not decoration. A plane that is draining, a plane still warming
//! up and a plane that is wedged all answer their socket, and each sends an operator somewhere
//! different: wait, wait, and restart. Collapsing them into "ok" — reporting readiness by whether a
//! TCP connection succeeded — states the one thing that was never in question.

use std::io::{self, Write};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use permguard_core::time;
use serde::{Deserialize, Serialize};

use crate::output::Report;
use crate::trace::Trace;
use permguard_control_client::Endpoint;
use permguard_control_client::http::Client;

/// What a plane reports itself to be.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Answers, and is willing to be sent work.
    Ready,
    /// Answers, and is not willing to be sent work: starting up, draining, or unable to say.
    Degraded,
    /// Answers, and reports itself wedged. It has to be restarted.
    Unhealthy,
    /// Did not answer.
    Unreachable,
}

impl Status {
    /// The status as it is written in a report.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Degraded => "degraded",
            Self::Unhealthy => "unhealthy",
            Self::Unreachable => "unreachable",
        }
    }

    /// Whether the plane answered at all.
    pub fn is_reachable(self) -> bool {
        self != Self::Unreachable
    }
}

/// What one plane answered.
#[derive(Debug, Serialize)]
pub struct PlaneInspection {
    /// The plane that was asked about.
    pub plane: &'static str,
    /// Where it was asked.
    pub endpoint: Endpoint,
    /// What it reports itself to be.
    pub status: Status,
    /// The stable code for a status that is not [`Status::Ready`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    /// The same thing, in a sentence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// How long the whole probe took, in milliseconds.
    pub latency_ms: u64,
    /// Whether the plane reports itself live, when it said.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live: Option<bool>,
    /// Whether the plane reports itself ready, when it said.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ready: Option<bool>,
    /// The plane the endpoint says it is, which is not always the one that was asked for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reported_plane: Option<String>,
    /// The product the endpoint says it is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    /// The version it was built as.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The commit it was built from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
}

/// Everything the planes answered, and when they were asked.
#[derive(Debug, Serialize)]
pub struct InspectReport {
    /// When the planes were probed, in UTC.
    pub checked_at: String,
    /// How many planes were probed.
    pub total: usize,
    /// How many answered.
    pub reachable: usize,
    /// How many are willing to be sent work.
    pub ready: usize,
    /// One entry per plane, in the order they were asked.
    pub planes: Vec<PlaneInspection>,
}

/// Probes every plane and reports what each one is.
pub fn inspect(
    client: &Client,
    control_endpoint: &Endpoint,
    data_endpoint: &Endpoint,
    trace: &Trace,
) -> InspectReport {
    let planes = vec![
        probe(client, "control", control_endpoint, trace),
        probe(client, "data", data_endpoint, trace),
    ];
    let reachable = planes
        .iter()
        .filter(|plane| plane.status.is_reachable())
        .count();
    let ready = planes
        .iter()
        .filter(|plane| plane.status == Status::Ready)
        .count();

    InspectReport {
        checked_at: time::to_rfc3339(now()),
        total: planes.len(),
        reachable,
        ready,
        planes,
    }
}

/// Asks one endpoint what it is and how it is, and turns whatever happens into a line of the report.
fn probe(
    client: &Client,
    plane: &'static str,
    endpoint: &Endpoint,
    trace: &Trace,
) -> PlaneInspection {
    trace.say(format!(
        "probing the {plane} plane at {endpoint}{}",
        if endpoint.is_tls() { " over TLS" } else { "" }
    ));

    let started = Instant::now();
    let outcome = read_plane(client, endpoint, trace);
    let latency_ms = elapsed_ms(started);

    match outcome {
        Err(unreachable) => PlaneInspection {
            plane,
            endpoint: endpoint.clone(),
            status: Status::Unreachable,
            reason: Some(unreachable.reason),
            detail: Some(unreachable.detail),
            latency_ms,
            live: None,
            ready: None,
            reported_plane: None,
            product: None,
            version: None,
            commit: None,
        },
        Ok(answered) => {
            let (status, reason, detail) = classify(&answered.health);

            PlaneInspection {
                plane,
                endpoint: endpoint.clone(),
                status,
                reason,
                detail,
                latency_ms,
                live: answered.health.live(),
                ready: answered.health.ready(),
                reported_plane: Some(answered.info.plane),
                product: Some(answered.info.product),
                version: Some(answered.info.version),
                commit: Some(answered.info.commit),
            }
        }
    }
}

/// Turns what a plane said about itself into a status an operator can act on.
fn classify(health: &HealthAnswer) -> (Status, Option<&'static str>, Option<String>) {
    match health {
        // Unable to say. Reported as not willing to be sent work, because an unverified plane is
        // not a plane that has said it is ready — claiming otherwise is the one mistake that
        // matters here.
        HealthAnswer::Unknown { reason, detail } => (
            Status::Degraded,
            Some(reason),
            Some(format!("its identity is known, but {detail}")),
        ),
        HealthAnswer::Known { live, ready } => match (live, ready) {
            (false, _) => (
                Status::Unhealthy,
                Some("not_live"),
                Some("it reports itself wedged and has to be restarted".to_owned()),
            ),
            (true, false) => (
                Status::Degraded,
                Some("not_ready"),
                Some(
                    "it is live but not willing to be sent work: starting up, or draining"
                        .to_owned(),
                ),
            ),
            (true, true) => (Status::Ready, None, None),
        },
    }
}

/// One plane's two answers.
struct PlaneAnswer {
    info: PlaneInfo,
    health: HealthAnswer,
}

/// Why a plane counts as not having answered.
struct Unreachable {
    reason: &'static str,
    detail: String,
}

/// What a plane said about its health, including that it did not say.
enum HealthAnswer {
    Known {
        live: bool,
        ready: bool,
    },
    Unknown {
        reason: &'static str,
        detail: String,
    },
}

impl HealthAnswer {
    fn live(&self) -> Option<bool> {
        match self {
            Self::Known { live, .. } => Some(*live),
            Self::Unknown { .. } => None,
        }
    }

    fn ready(&self) -> Option<bool> {
        match self {
            Self::Known { ready, .. } => Some(*ready),
            Self::Unknown { .. } => None,
        }
    }
}

/// Asks a plane what it is, and then how it is.
///
/// Identity first: an endpoint that cannot say what it is has not been reached, and there is nothing
/// to report a health for. Health second, and a failure there is not fatal — a plane that named
/// itself and then would not answer `/health` is a real state, and one worth seeing.
fn read_plane(
    client: &Client,
    endpoint: &Endpoint,
    trace: &Trace,
) -> Result<PlaneAnswer, Unreachable> {
    let info: PlaneInfo =
        fetch(client, endpoint, "/version", trace).map_err(|failure| Unreachable {
            reason: failure.reason,
            detail: failure.detail,
        })?;
    let health = match fetch::<HealthBody>(client, endpoint, "/health", trace) {
        Ok(body) => HealthAnswer::Known {
            live: body.live,
            ready: body.ready,
        },
        Err(failure) => HealthAnswer::Unknown {
            reason: "health_unreadable",
            detail: failure.detail,
        },
    };

    Ok(PlaneAnswer { info, health })
}

/// A request that did not produce a body this CLI could read.
struct Failure {
    reason: &'static str,
    detail: String,
}

/// Asks for one path and decodes what came back.
fn fetch<T: for<'de> Deserialize<'de>>(
    client: &Client,
    endpoint: &Endpoint,
    path: &str,
    trace: &Trace,
) -> Result<T, Failure> {
    trace.say(format!("GET {endpoint}{path}"));

    let response = client.get(endpoint, path).map_err(|error| {
        trace.say(format!("GET {endpoint}{path} failed: {error}"));

        Failure {
            reason: error.reason(),
            detail: error.to_string(),
        }
    })?;

    trace.say(format!("GET {endpoint}{path} answered {}", response.status));

    if response.status != 200 {
        return Err(Failure {
            reason: "http_status",
            detail: format!("`{endpoint}{path}` answered {}", response.status),
        });
    }

    serde_json::from_str(&response.body).map_err(|error| Failure {
        reason: "decode_failed",
        detail: format!("`{endpoint}{path}` answered something unreadable: {error}"),
    })
}

/// Seconds since the Unix epoch. A clock set before 1970 reports the epoch rather than failing.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| i64::try_from(since.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}

/// Milliseconds since an instant, saturating rather than wrapping.
fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// What `/version` answers.
#[derive(Debug, Deserialize)]
struct PlaneInfo {
    plane: String,
    product: String,
    version: String,
    commit: String,
}

/// What `/health` answers.
#[derive(Debug, Deserialize)]
struct HealthBody {
    live: bool,
    ready: bool,
}

impl Report for InspectReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(out, "Permguard server inspect")?;
        writeln!(out, "  checked at: {}", self.checked_at)?;
        writeln!(out)?;

        for plane in &self.planes {
            writeln!(out, "{} plane", plane.plane)?;
            writeln!(out, "  endpoint: {}", plane.endpoint)?;
            writeln!(out, "  status:   {}", plane.status.as_str())?;

            if let Some(reason) = plane.reason {
                writeln!(out, "  reason:   {reason}")?;
            }

            if let Some(detail) = plane.detail.as_deref() {
                writeln!(out, "  detail:   {detail}")?;
            }

            if let Some(product) = plane.product.as_deref() {
                writeln!(out, "  product:  {product}")?;
            }

            if let Some(version) = plane.version.as_deref() {
                writeln!(out, "  version:  {version}")?;
            }

            if let Some(commit) = plane.commit.as_deref() {
                writeln!(out, "  commit:   {commit}")?;
            }

            if let (Some(live), Some(ready)) = (plane.live, plane.ready) {
                writeln!(out, "  health:   live={live} ready={ready}")?;
            }

            writeln!(out, "  latency:  {}ms", plane.latency_ms)?;

            if let Some(reported) = plane.reported_plane.as_deref()
                && reported != plane.plane
            {
                writeln!(
                    out,
                    "  warning:  this endpoint reports itself as the {reported} plane"
                )?;
            }

            writeln!(out)?;
        }

        writeln!(
            out,
            "{} of {} planes ready, {} reachable",
            self.ready, self.total, self.reachable
        )
    }
}
