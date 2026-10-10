// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The three listener classes and what each listener of a process demands of its clients
//! (WP-2.11, owner decisions of 2026-10-10).
//!
//! | Class          | Minimum                                                       | Refused at Bootstrap, from `production`                          |
//! | -------------- | ------------------------------------------------------------- | ---------------------------------------------------------------- |
//! | `host`         | TLS; mTLS; Host proof for peers; Host grants for operators    | no TLS; no client CA beyond a development loopback (WP-2.5)      |
//! | `plane_public` | TLS; explicit deployment auth policy; deny by default         | the clear on a bind that is not loopback, unless `upstream_tls`  |
//! | `telemetry`    | loopback or private bind; TLS outside that trust              | the clear on a public IP literal                                 |
//!
//! No class widens authentication silently: what a listener demands is refused when it falls
//! below the class, or published, in the process discovery document and `GET /host/v1/status`,
//! as one [`ListenerReport`] per listener. A report names no address, certificate or peer.

use std::net::IpAddr;

use serde::Serialize;

use crate::tls::TlsSettings;

/// The Host listener's surface name.
pub const HOST_LISTENER: &str = "host-api";
/// The telemetry listener's surface name.
pub const TELEMETRY_LISTENER: &str = "telemetry";

/// Which class a listener is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenerClass {
    Host,
    PlanePublic,
    Telemetry,
}

impl ListenerClass {
    /// The word a report spells.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::PlanePublic => "plane_public",
            Self::Telemetry => "telemetry",
        }
    }
}

/// What a listener demands of a client before it reaches a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenerAuthentication {
    /// The clear: nothing.
    None,
    /// TLS the process serves, no client certificate.
    Tls,
    /// TLS the process serves, a client certificate demanded.
    MutualTls,
    /// The clear behind an ingress or a sidecar the deployment says terminates TLS.
    UpstreamTls,
}

impl ListenerAuthentication {
    /// The word a report spells.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Tls => "tls",
            Self::MutualTls => "mutual_tls",
            Self::UpstreamTls => "upstream_tls",
        }
    }
}

/// One listener as discovery and the Host status publish it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListenerReport {
    /// The surface: `host-api`, `telemetry`, or a Plane's `<plane>-<protocol>`.
    pub name: String,
    pub class: ListenerClass,
    pub authentication: ListenerAuthentication,
    /// Whether an allow list names which authenticated clients it answers.
    pub client_allow: bool,
    /// `1.2` or `1.3` when the process serves TLS on it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_min_version: Option<&'static str>,
}

impl ListenerReport {
    /// The report of `name`, of `class`, serving `tls` or the clear, and in the clear behind a
    /// declared upstream termination when `terminated_upstream`.
    pub fn of(
        name: impl Into<String>,
        class: ListenerClass,
        tls: Option<&TlsSettings>,
        terminated_upstream: bool,
        client_allow: bool,
    ) -> Self {
        let authentication = match tls {
            Some(tls) if tls.is_mutual() => ListenerAuthentication::MutualTls,
            Some(_) => ListenerAuthentication::Tls,
            None if terminated_upstream => ListenerAuthentication::UpstreamTls,
            None => ListenerAuthentication::None,
        };
        Self {
            name: name.into(),
            class,
            authentication,
            client_allow,
            tls_min_version: tls.map(|tls| tls.min_version().as_str()),
        }
    }
}

/// The IP address a bind names literally, port or brackets aside; `None` for a host name.
pub fn ip_literal(address: &str) -> Option<IpAddr> {
    if let Ok(socket) = address.parse::<std::net::SocketAddr>() {
        return Some(socket.ip());
    }
    if let Ok(ip) = address.trim_matches(['[', ']']).parse::<IpAddr>() {
        return Some(ip);
    }
    address
        .rsplit_once(':')
        .and_then(|(host, _)| host.trim_matches(['[', ']']).parse().ok())
}

/// Whether a bind accepts connections from this host only: `localhost`, `::1` or `127.*`.
pub fn is_loopback_bind(address: &str) -> bool {
    crate::config::is_loopback(address)
}

/// Whether `ip` is reachable beyond the trust of a host and its private networks: not loopback,
/// not a wildcard, not private (RFC 1918, RFC 6598, IPv6 unique local) and not link-local.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_private()
                || v4.is_link_local()
                || (a == 100 && (64..128).contains(&b)))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn only_an_address_beyond_the_host_and_its_private_networks_is_public() {
        for address in [
            "127.0.0.1:5443",
            "0.0.0.0:5443",
            "[::]:5443",
            "[::1]:5443",
            "10.1.2.3:5443",
            "172.16.0.1:5443",
            "172.31.255.255:5443",
            "192.168.1.1:5443",
            "100.64.0.1:5443",
            "100.127.255.255:5443",
            "169.254.1.1:5443",
            "[fd00::1]:5443",
            "[fe80::1]:5443",
            "[::ffff:10.0.0.1]:5443",
        ] {
            let ip = ip_literal(address).expect("a literal");
            assert!(!is_public_ip(ip), "{address}");
        }
        for address in [
            "203.0.113.7:5443",
            "172.32.0.1:5443",
            "100.128.0.1:5443",
            "8.8.8.8",
            "[2001:db8::1]:5443",
            "[::ffff:203.0.113.7]:5443",
        ] {
            let ip = ip_literal(address).expect("a literal");
            assert!(is_public_ip(ip), "{address}");
        }
        assert_eq!(ip_literal("permguard:5443"), None);
        assert_eq!(ip_literal("localhost"), None);
    }

    #[test]
    fn a_report_says_what_the_listener_demands_and_never_where_it_is() {
        let plain = ListenerReport::of("x", ListenerClass::PlanePublic, None, false, false);
        assert_eq!(plain.authentication, ListenerAuthentication::None);
        assert_eq!(plain.tls_min_version, None);
        let upstream = ListenerReport::of("x", ListenerClass::PlanePublic, None, true, false);
        assert_eq!(upstream.authentication, ListenerAuthentication::UpstreamTls);
        let tls = TlsSettings::new("c", "k");
        let served = ListenerReport::of("x", ListenerClass::PlanePublic, Some(&tls), true, false);
        assert_eq!(served.authentication, ListenerAuthentication::Tls);
        assert_eq!(served.tls_min_version, Some("1.3"));
        let mutual = tls.with_client_ca("ca");
        let mutual = ListenerReport::of("x", ListenerClass::Host, Some(&mutual), false, true);
        assert_eq!(mutual.authentication, ListenerAuthentication::MutualTls);
        let json = serde_json::to_value(&mutual).expect("serializes");
        assert_eq!(
            json,
            serde_json::json!({
                "name": "x",
                "class": "host",
                "authentication": "mutual_tls",
                "client_allow": true,
                "tls_min_version": "1.3",
            })
        );
        let json = serde_json::to_value(&plain).expect("serializes");
        assert!(json.get("tls_min_version").is_none(), "{json}");
    }
}
