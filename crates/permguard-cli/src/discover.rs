// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `discover <url>`: the discovery chain, walked from one address (WP-7.4b, owner decision of
//! 2026-10-21).
//!
//! ```text
//! process   <url>/.well-known/server-configuration   host_id, the Host's state, every plane
//! plane     each plane's own document                its state, every interface and its stage
//! interface each interface's own document            version, component, state, stage, limits
//! ```
//!
//! The walk starts from whichever document the address answers: a document naming `planes` is
//! the process's, and follows each plane's link; any other is the walk's first plane. Every link
//! is followed over HTTP or HTTPS under the same TLS flags as `inspect`, and the operator's token
//! is never sent: discovery is unauthenticated, and a link may name another host. The operator's
//! client certificate is presented to the start address's host alone (after the review).
//!
//! A link that does not answer is a line of the report and makes the exit `69`, unavailable, as an
//! address that answers nothing does; an interface refused `interface_retired` is shown as
//! retired, never as a failure. A plane served only over gRPC is listed by its endpoint, which
//! this walk does not follow. A hostile document cannot hold the walk: at most [`MAX_PLANES`]
//! planes and [`MAX_INTERFACES`] interfaces per plane are followed, the rest counted, and an
//! address already read in the walk is not read again.

use std::collections::HashSet;
use std::io::{self, Write};

use serde::{Deserialize, Serialize};

use crate::output::{Report, printable};
use crate::trace::Trace;
use permguard_control_client::Endpoint;
use permguard_control_client::http::Client;

/// The well-known path every layer of the chain starts from.
const WELL_KNOWN: &str = "/.well-known/server-configuration";

/// The most planes one process document has followed.
pub const MAX_PLANES: usize = 64;

/// The most interfaces one plane document has followed.
pub const MAX_INTERFACES: usize = 256;

/// Why the walk did not start, or did not get past its first document.
#[derive(Debug)]
pub enum DiscoverError {
    /// The start address is not one this walk reads: a usage error.
    Address(String),
    /// The start address did not answer a document.
    Unreachable(String),
}

/// What the walk found from one address.
#[derive(Debug, Serialize)]
pub struct DiscoverReport {
    /// The address the walk started from.
    pub url: String,
    /// The process document, when the address answered one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessView>,
    /// Every plane reached, the process document's or the address's own.
    pub planes: Vec<PlaneView>,
    /// The planes the process document listed beyond [`MAX_PLANES`], not followed.
    #[serde(skip_serializing_if = "is_zero")]
    pub not_followed: usize,
    /// Whether every link answered.
    pub complete: bool,
}

/// The process document's own members.
#[derive(Debug, Serialize)]
pub struct ProcessView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    pub state: String,
}

/// One plane, as the chain describes it.
#[derive(Debug, Serialize)]
pub struct PlaneView {
    pub plane: String,
    /// The plane's phase, as its document or the process document names it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Where its document lives, when it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration: Option<String>,
    /// Its gRPC endpoint, when it is served only over gRPC; not followed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grpc_endpoint: Option<String>,
    /// Why its document could not be read, when it could not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unreachable: Option<String>,
    pub interfaces: Vec<InterfaceView>,
    /// The interfaces it listed beyond [`MAX_INTERFACES`], not followed.
    #[serde(skip_serializing_if = "is_zero")]
    pub not_followed: usize,
}

/// One interface, as its plane lists it and its own document describes it.
#[derive(Debug, Serialize)]
pub struct InterfaceView {
    pub id: String,
    pub configuration: String,
    /// The stage the plane document gives.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sunset: Option<String>,
    /// The interface document's common header, when it answered one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<Header>,
    /// Whether the interface is retired: its document refused `interface_retired`.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub retired: bool,
    /// Whether its address was already read in this walk, and not read again.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub repeated: bool,
    /// Why its document could not be read, when it could not and is not retired.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unreachable: Option<String>,
}

/// An interface document's common header (WP-7.4a), and its limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub component: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub stage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sunset: Option<String>,
    #[serde(default)]
    pub limits: serde_json::Map<String, serde_json::Value>,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(count: &usize) -> bool {
    *count == 0
}

/// One HTTP or HTTPS address, as an endpoint and a path: the endpoint's own parser judges the
/// scheme and the authority.
fn split(url: &str) -> Result<(Endpoint, String), String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("`{url}` is not a URL"))?;
    if !matches!(scheme, "http" | "https") {
        return Err(format!(
            "`{url}` is not an HTTP or HTTPS address: discovery documents are read over HTTP"
        ));
    }
    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    let endpoint = Endpoint::parse(&format!("{scheme}://{authority}"))
        .map_err(|invalid| invalid.to_string())?;
    Ok((endpoint, path.to_owned()))
}

/// The authority of an address, `host:port` as written, for telling the start host apart.
fn authority(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    Some(rest.split('/').next().unwrap_or(rest))
}

/// The start address as the walk reads it: an HTTP or HTTPS address, its trailing slash and
/// well-known path dropped. Anything else is the operator's mistake, a usage error.
pub fn start_address(url: &str) -> Result<String, String> {
    let trimmed = url.trim_end_matches('/');
    let base = trimmed.strip_suffix(WELL_KNOWN).unwrap_or(trimmed);
    split(base)?;
    Ok(base.to_owned())
}

/// The two clients a walk uses: one presenting the operator's client certificate, for the start
/// address's host, and one presenting nothing, for every other host a document names.
pub struct Clients<'a> {
    pub home: &'a Client,
    pub away: &'a Client,
}

/// A walk in progress.
struct Walk<'a> {
    clients: Clients<'a>,
    home: String,
    visited: HashSet<String>,
    trace: &'a Trace,
}

impl Walk<'_> {
    /// What one GET answered: a status and a body, or why there was none.
    fn get(&mut self, url: &str) -> Result<(u16, String), String> {
        let (endpoint, path) = split(url)?;
        let client = if authority(url) == Some(self.home.as_str()) {
            self.clients.home
        } else {
            self.clients.away
        };
        self.trace.say(format!("GET {url}"));
        let response = client
            .get(&endpoint, &path)
            .map_err(|error| format!("`{url}` did not answer: {error}"))?;
        Ok((response.status, response.body))
    }

    /// A document's JSON, from a `200`.
    fn document(&mut self, url: &str) -> Result<serde_json::Value, String> {
        let (status, body) = self.get(url)?;
        if status != 200 {
            return Err(format!("`{url}` answered {status}"));
        }
        serde_json::from_str(&body)
            .map_err(|error| format!("`{url}` answered something unreadable: {error}"))
    }

    /// Every interface a plane document lists, each followed to its own document; the surplus
    /// past [`MAX_INTERFACES`] counted.
    fn interfaces(&mut self, plane: &serde_json::Value) -> (Vec<InterfaceView>, usize) {
        let Some(listed) = plane
            .get("interfaces")
            .and_then(serde_json::Value::as_object)
        else {
            return (Vec::new(), 0);
        };
        let surplus = listed.len().saturating_sub(MAX_INTERFACES);
        let views = listed
            .iter()
            .take(MAX_INTERFACES)
            .map(|(id, link)| self.interface(id, link))
            .collect();
        (views, surplus)
    }

    fn interface(&mut self, id: &str, link: &serde_json::Value) -> InterfaceView {
        let configuration = text(link, "configuration").unwrap_or_default();
        let mut view = InterfaceView {
            id: id.to_owned(),
            configuration: configuration.clone(),
            stage: text(link, "stage"),
            sunset: text(link, "sunset"),
            header: None,
            retired: false,
            repeated: false,
            unreachable: None,
        };
        if configuration.is_empty() {
            view.unreachable = Some("its link names no configuration".to_owned());
            return view;
        }
        if !self.visited.insert(configuration.clone()) {
            view.repeated = true;
            return view;
        }
        match self.get(&configuration) {
            Ok((200, body)) => match serde_json::from_str::<Header>(&body) {
                Ok(header) => view.header = Some(header),
                Err(error) => {
                    view.unreachable = Some(format!(
                        "`{configuration}` answered something unreadable: {error}"
                    ));
                }
            },
            Ok((status, body)) => {
                let code = serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|refusal| text(&refusal, "code"));
                if code.as_deref() == Some(permguard_core::codes::common::INTERFACE_RETIRED) {
                    view.retired = true;
                } else {
                    view.unreachable = Some(format!("`{configuration}` answered {status}"));
                }
            }
            Err(why) => view.unreachable = Some(why),
        }
        view
    }
}

fn text(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

/// Walks the chain from `url`, the address of a process or a plane.
pub fn discover(
    clients: Clients<'_>,
    url: &str,
    trace: &Trace,
) -> Result<DiscoverReport, DiscoverError> {
    let base = start_address(url).map_err(DiscoverError::Address)?;
    let mut walk = Walk {
        clients,
        home: authority(&base).unwrap_or_default().to_owned(),
        visited: HashSet::new(),
        trace,
    };
    let root_url = format!("{base}{WELL_KNOWN}");
    walk.visited.insert(root_url.clone());
    let root = walk
        .document(&root_url)
        .map_err(DiscoverError::Unreachable)?;
    let mut report = DiscoverReport {
        url: url.to_owned(),
        process: None,
        planes: Vec::new(),
        not_followed: 0,
        complete: true,
    };
    if root.get("planes").is_some() {
        report.process = Some(ProcessView {
            host_id: text(&root, "host_id"),
            state: text(&root, "state").unwrap_or_default(),
        });
        let empty = serde_json::Map::new();
        let planes = root
            .get("planes")
            .and_then(serde_json::Value::as_object)
            .unwrap_or(&empty);
        report.not_followed = planes.len().saturating_sub(MAX_PLANES);
        for (name, link) in planes.iter().take(MAX_PLANES) {
            let mut view = PlaneView {
                plane: name.clone(),
                state: text(link, "state"),
                configuration: text(link, "server_configuration"),
                grpc_endpoint: text(link, "grpc_endpoint"),
                unreachable: None,
                interfaces: Vec::new(),
                not_followed: 0,
            };
            if let Some(configuration) = view.configuration.clone()
                && walk.visited.insert(configuration.clone())
            {
                match walk.document(&configuration) {
                    Ok(plane) => {
                        view.state = text(&plane, "state").or(view.state);
                        (view.interfaces, view.not_followed) = walk.interfaces(&plane);
                    }
                    Err(why) => view.unreachable = Some(why),
                }
            }
            report.planes.push(view);
        }
    } else {
        let (interfaces, not_followed) = walk.interfaces(&root);
        report.planes.push(PlaneView {
            plane: text(&root, "plane").unwrap_or_default(),
            state: text(&root, "state"),
            configuration: Some(root_url),
            grpc_endpoint: None,
            unreachable: None,
            interfaces,
            not_followed,
        });
    }
    report.complete = report.planes.iter().all(|plane| {
        plane.unreachable.is_none()
            && plane
                .interfaces
                .iter()
                .all(|interface| interface.unreachable.is_none())
    });
    Ok(report)
}

impl Report for DiscoverReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(out, "discovery from {}", printable(&self.url))?;
        if let Some(process) = &self.process {
            writeln!(
                out,
                "  host:     {}",
                printable(process.host_id.as_deref().unwrap_or("(no identity yet)"))
            )?;
            writeln!(out, "  state:    {}", printable(&process.state))?;
        }
        for plane in &self.planes {
            writeln!(out)?;
            let name = if plane.plane.is_empty() {
                "(unnamed)"
            } else {
                plane.plane.as_str()
            };
            writeln!(out, "{}", printable(name))?;
            if let Some(state) = &plane.state {
                writeln!(out, "  state:    {}", printable(state))?;
            }
            if let Some(endpoint) = &plane.grpc_endpoint {
                writeln!(out, "  grpc:     {} (not followed)", printable(endpoint))?;
            }
            if let Some(why) = &plane.unreachable {
                writeln!(out, "  unreachable: {}", printable(why))?;
            }
            for interface in &plane.interfaces {
                writeln!(
                    out,
                    "  interface {} ({})",
                    printable(&interface.id),
                    printable(interface.stage.as_deref().unwrap_or("no stage"))
                )?;
                if interface.stage.as_deref() == Some("deprecated") {
                    match &interface.sunset {
                        Some(sunset) => writeln!(
                            out,
                            "    warning: deprecated, served until {}",
                            printable(sunset)
                        )?,
                        None => writeln!(out, "    warning: deprecated")?,
                    }
                }
                if interface.retired {
                    writeln!(out, "    retired: its document refuses `interface_retired`")?;
                }
                if interface.repeated {
                    writeln!(out, "    already read in this walk")?;
                }
                if let Some(header) = &interface.header {
                    writeln!(
                        out,
                        "    {} {}, {}{}",
                        printable(&header.component),
                        printable(&header.state),
                        printable(&header.stage),
                        if header.version.is_empty() {
                            String::new()
                        } else {
                            format!(", version {}", printable(&header.version))
                        }
                    )?;
                    for (name, value) in &header.limits {
                        writeln!(
                            out,
                            "    limit {}: {}",
                            printable(name),
                            printable(&value.to_string())
                        )?;
                    }
                }
                if let Some(why) = &interface.unreachable {
                    writeln!(out, "    unreachable: {}", printable(why))?;
                }
            }
            if plane.not_followed > 0 {
                writeln!(
                    out,
                    "  not followed: {} more interfaces",
                    plane.not_followed
                )?;
            }
        }
        if self.not_followed > 0 {
            writeln!(out, "not followed: {} more planes", self.not_followed)?;
        }
        writeln!(out)?;
        writeln!(
            out,
            "{}",
            if self.complete {
                "every link answered"
            } else {
                "some links did not answer"
            }
        )
    }
}
