// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Which planes this process serves and where each is reached: resolved from the configuration
//! the listeners bind with, so a document and a socket never disagree, and so a plane can name its
//! own published address without the server (the crate boundaries refactoring, RD-1).

use super::settings::{
    SETTING_RUNTIME_OPTIONAL_PLANES, SETTING_RUNTIME_PLANES, addresses_for_plane,
};
use crate::Config;

/// One plane's entry in the server-configuration document.
///
/// The document composes from what is actually loaded: a plane that is not
/// selected by the runtime, or has no HTTP address, contributes nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredPlane {
    /// The plane's public name — `control-plane` or `data-plane`, the same
    /// words the logs and metrics use, so a bare ambiguous `control` never
    /// names a plane on a wire.
    pub id: &'static str,
    /// The plane's HTTP base URL, scheme included — `https` when the plane's
    /// HTTP surface resolved TLS, `http` otherwise.
    pub http_base: String,
}

/// Which plane, as a value rather than a string.
///
/// # Why this is not a `&str`
///
/// Four places matched on a plane id and wrote `_ => data-plane`, so every typo, every future
/// plane and every empty string was silently the data plane — and the answer was a plausible
/// document about the wrong process. A closed set makes the wrong id unrepresentable, and
/// [`PlaneId::parse`] makes the boundary where a string becomes one explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaneId {
    Control,
    Data,
    Authority,
}

impl PlaneId {
    /// The id as configuration and modules spell it: `control`, `data`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Data => "data",
            Self::Authority => "authority",
        }
    }

    /// The name a document and a log line use, which is not the same word.
    pub const fn public_name(self) -> &'static str {
        match self {
            Self::Control => "control-plane",
            Self::Data => "data-plane",
            Self::Authority => "authority-plane",
        }
    }

    /// Where this plane is told to advertise itself.
    pub const fn advertised_url_setting(self) -> &'static str {
        match self {
            Self::Control => super::settings::SETTING_CONTROL_HTTP_ADVERTISED_URL,
            Self::Data => super::settings::SETTING_DATA_HTTP_ADVERTISED_URL,
            Self::Authority => super::settings::SETTING_AUTHORITY_HTTP_ADVERTISED_URL,
        }
    }

    /// Where this plane's gRPC is told to advertise itself.
    pub const fn grpc_advertised_url_setting(self) -> &'static str {
        match self {
            Self::Control => super::settings::SETTING_CONTROL_GRPC_ADVERTISED_URL,
            Self::Data => super::settings::SETTING_DATA_GRPC_ADVERTISED_URL,
            Self::Authority => super::settings::SETTING_AUTHORITY_GRPC_ADVERTISED_URL,
        }
    }

    /// The plane a module id names, or `None` for a name this build does not host.
    pub fn parse(id: &str) -> Option<Self> {
        match id {
            "control" => Some(Self::Control),
            "data" => Some(Self::Data),
            "authority" => Some(Self::Authority),
            _ => None,
        }
    }
}

/// The planes this process serves over HTTP, and the address each publishes.
///
/// # Where it binds and where it is reached are two different things
///
/// A listener binds an address; a document publishes one. Behind a Kubernetes Service, an Ingress
/// or a load balancer they are not the same string — and `0.0.0.0` is not a string at all as far
/// as a client is concerned: it is how a process says *every interface*, and nothing can dial it.
/// A document naming it sends every client that follows a link nowhere, which is worse than
/// publishing no link, because the client has no way to tell.
///
/// So a plane may be told what to advertise, and that is what it advertises. Absent that, the
/// address it binds is the best available guess and is used — correct for a process reachable at
/// the address it listens on, which is every local run and plenty of deployments.
///
/// The **scheme** comes from that endpoint's own TLS settings, never from a global one: a plane
/// serving HTTPS while its document says `http://` is a document that cannot be followed either.
pub fn discovered_planes(config: &Config) -> Vec<DiscoveredPlane> {
    const KNOWN: [&str; 3] = ["authority", "control", "data"];

    let mut planes = Vec::new();
    for id in KNOWN {
        if !plane_enabled(config, id) {
            continue;
        }
        let Some(addresses) = addresses_for_plane(id) else {
            continue;
        };
        let Ok(Some(addr)) = addresses.http().resolve(config) else {
            continue;
        };
        let scheme = match addresses.http_tls().resolve(config) {
            Ok(Some(_)) => "https",
            _ => "http",
        };
        let Some(plane) = PlaneId::parse(id) else {
            continue;
        };
        let advertised =
            advertised_url(config, plane).unwrap_or_else(|| format!("{scheme}://{addr}"));

        planes.push(DiscoveredPlane {
            id: plane.public_name(),
            http_base: advertised,
        });
    }
    planes
}

/// The planes this process serves over gRPC, with or without HTTP beside it: enabled, a gRPC
/// address (owner decision of 2026-11-15: a client that speaks gRPC alone finds every plane here,
/// as a client that speaks HTTP alone finds every plane's document).
///
/// The endpoint's scheme follows its own TLS settings, like every published address here.
pub fn grpc_planes(config: &Config) -> Vec<(&'static str, String)> {
    const KNOWN: [&str; 3] = ["authority", "control", "data"];

    let mut planes = Vec::new();
    for id in KNOWN {
        if !plane_enabled(config, id) {
            continue;
        }
        let Some(addresses) = addresses_for_plane(id) else {
            continue;
        };
        let Ok(Some(addr)) = addresses.grpc().resolve(config) else {
            continue;
        };
        let scheme = match addresses.grpc_tls().resolve(config) {
            Ok(Some(_)) => "https",
            _ => "http",
        };
        let Some(plane) = PlaneId::parse(id) else {
            continue;
        };
        // Where it is reached, by the rule its HTTP follows (owner decision of 2026-11-15): what
        // it was told to advertise; else, sharing the HTTP listener's address, what that listener
        // advertises, the same port behind the same name; else where it binds.
        let shared = matches!(addresses.http().resolve(config), Ok(Some(http)) if http == addr);
        let advertised = config
            .setting(plane.grpc_advertised_url_setting())
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .map(|url| url.trim_end_matches('/').to_owned())
            .or_else(|| shared.then(|| advertised_url(config, plane)).flatten());

        planes.push((
            plane.public_name(),
            advertised.unwrap_or_else(|| format!("{scheme}://{addr}")),
        ));
    }

    planes
}

/// What this plane was told to advertise, when it was told anything.
///
/// A trailing slash is trimmed: every caller of this appends a path, and `…//catalog/v1/zones` is not the
/// address anybody meant.
pub fn advertised_url(config: &Config, plane: PlaneId) -> Option<String> {
    config
        .setting(plane.advertised_url_setting())
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(|url| url.trim_end_matches('/').to_owned())
}

/// Whether an address is one a client could dial, or only one a process can bind.
///
/// `0.0.0.0` and `[::]` mean *every interface* to a listener and nothing at all to a caller. A
/// deployment that binds one without saying what to advertise publishes links nobody can follow,
/// and the only moment anybody can be told is startup.
pub fn is_wildcard_address(addr: &str) -> bool {
    let host = if let Some(rest) = addr.strip_prefix('[') {
        // `[::]:7443` — bracketed, so the host ends at the bracket and the colons inside it are
        // the address's own.
        rest.split_once(']').map_or(rest, |(host, _)| host)
    } else {
        match addr.rsplit_once(':') {
            // A port is digits. Anything else after the last colon means the colons belong to a
            // bare IPv6 address, which is the whole string.
            Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
                // …unless the part before it still holds colons, in which case this is bare IPv6
                // too and the "port" is one of its groups.
                if host.contains(':') { addr } else { host }
            }
            _ => addr,
        }
    };

    matches!(host, "0.0.0.0" | "::" | "" | "[::]")
}

/// The planes whose published address nobody can dial, for the warning at startup.
pub fn unroutable_planes(config: &Config) -> Vec<&'static str> {
    let wildcard = |url: &str| {
        url.split_once("://")
            .is_some_and(|(_, rest)| is_wildcard_address(rest))
    };
    let mut planes: Vec<&'static str> = discovered_planes(config)
        .into_iter()
        .filter(|plane| wildcard(&plane.http_base))
        .map(|plane| plane.id)
        .collect();
    // A gRPC endpoint nobody can dial is the same mistake (owner decision of 2026-11-15).
    for (id, endpoint) in grpc_planes(config) {
        if wildcard(&endpoint) && !planes.contains(&id) {
            planes.push(id);
        }
    }
    planes
}

/// The HTTP base URL (`scheme://addr`) the Server Host operations surface answers on.
///
/// What the deployment advertises wins; the bound address is the fallback, with the scheme its
/// own TLS settings imply — exactly the rule the planes follow, because a link that cannot be
/// followed is the same mistake on any surface.
pub fn host_http_base(config: &Config) -> Option<String> {
    if let Some(advertised) = config.telemetry_advertised_url() {
        return Some(advertised.to_owned());
    }

    let addr = config.telemetry_addr()?;
    let scheme = match config.telemetry_tls() {
        Some(_) => "https",
        None => "http",
    };

    Some(format!("{scheme}://{addr}"))
}

/// The base URL of the Host listener (WP-2.5), when `admin.addr` is set: what the deployment
/// advertises (`admin.advertised_url`) wins, the bound address is the fallback, always `https`
/// since the listener is refused without TLS.
pub fn host_api_base(config: &Config) -> Option<String> {
    let bound = config.admin_addr()?;
    Some(
        config
            .admin_advertised_url()
            .map_or_else(|| format!("https://{bound}"), str::to_owned),
    )
}

/// The HTTP base URL (`scheme://addr`) one plane answers on, when it is
/// loaded and has an HTTP address — for a plane module composing its own
/// configuration document.
pub fn plane_http_base(config: &Config, plane: PlaneId) -> Option<String> {
    discovered_planes(config)
        .into_iter()
        .find(|held| held.id == plane.public_name())
        .map(|held| held.http_base)
}

/// Whether a selected plane gates readiness: every one does unless `runtime.optional_planes` names it.
pub fn plane_required(config: &Config, id: &str) -> bool {
    !config
        .setting(SETTING_RUNTIME_OPTIONAL_PLANES)
        .is_some_and(|value| value.split(',').map(str::trim).any(|plane| plane == id))
}

pub fn plane_enabled(config: &Config, id: &str) -> bool {
    config
        .setting(SETTING_RUNTIME_PLANES)
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|plane| !plane.is_empty())
                .any(|plane| plane == id)
        })
        .unwrap_or(true)
}
