// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Where a plane is, and what it takes to talk to it.
//!
//! # Why the scheme carries the transport, and nothing else
//!
//! An endpoint is a URL: `http://host:port` is plain, `https://host:port` is TLS. Mutual TLS is not
//! a third scheme — it is `https://` plus a client certificate, supplied separately.
//!
//! The alternative, a scheme per security posture — `mtls://` — reads well and then has to answer a
//! question it cannot: what an `mtls://` endpoint means when no client certificate was configured.
//! Either it is a lie or it is a second place the posture is declared, and two declarations of one
//! fact eventually disagree. The scheme says how to reach the host; the material says who we are
//! when we get there.

use std::fmt;

use http::Uri;
use serde::Serialize;

/// The default port of each scheme, which an endpoint may leave out.
const HTTP_PORT: u16 = 80;
const HTTPS_PORT: u16 = 443;

/// A plane's address, parsed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoint {
    /// Whether reaching it means a TLS handshake.
    tls: bool,
    /// Whether it is reached over gRPC (`grpc`, `grpcs`) rather than REST (TC-1).
    grpc: bool,
    /// The host, as written.
    host: String,
    /// The port, defaulted from the scheme when the endpoint left it out.
    port: u16,
    /// The endpoint in its one canonical form (DEC-0017): the scheme in lower case, the host and
    /// port as written, no path. What a report quotes back and what a connection is made to, so
    /// `HTTPS://host:6443/` and `https://host:6443` are one endpoint everywhere.
    written: String,
}

impl Endpoint {
    /// Reads an endpoint, or says what is wrong with it: the one grammar every surface that reads
    /// an endpoint goes through (DEC-0017). Schemes `http`, `https`, `grpc`, `grpcs`, in any case;
    /// a port, when written, is `1..=65535`; userinfo, a query and a fragment are refused; a path
    /// of `/` is no path, and any longer one is refused.
    pub fn parse(written: &str) -> Result<Self, Invalid> {
        // A fragment never reaches a server, and a query would be silently dropped: refused, so
        // what the endpoint says is what is used (BUG-0110).
        if written.contains('#') {
            return Err(Invalid::new(
                written,
                "it carries a fragment, and an endpoint is a scheme, a host and a port only",
            ));
        }
        let uri = written.parse::<Uri>().map_err(|error| {
            // `tls:host:port` and `host:port` are the two shapes people write when they expect a
            // scheme to be a mode rather than a URL scheme, and both fail here as a bare parse
            // error that explains nothing.
            if written.contains(':') && !written.contains("://") {
                return Invalid::new(
                    written,
                    "an endpoint is a URL: write http://host:port or https://host:port for REST, \
                     grpc://host:port or grpcs://host:port for gRPC",
                );
            }

            if let Some((_, rest)) = written.split_once("://")
                && rest.is_empty()
            {
                return Invalid::new(written, "it names no host");
            }

            Invalid::new(written, &error.to_string())
        })?;
        let scheme = uri.scheme_str().unwrap_or_default().to_ascii_lowercase();
        let (tls, grpc) = match scheme.as_str() {
            "http" => (false, false),
            "https" => (true, false),
            "grpc" => (false, true),
            "grpcs" => (true, true),
            "" => {
                return Err(Invalid::new(
                    written,
                    "an endpoint is a URL: write http://host:port or https://host:port for REST, \
                     grpc://host:port or grpcs://host:port for gRPC",
                ));
            }
            other => {
                return Err(Invalid::new(
                    written,
                    &format!(
                        "`{other}` is not a scheme this CLI speaks: use https:// for REST or \
                         grpcs:// for gRPC (http:// and grpc:// without TLS)"
                    ),
                ));
            }
        };
        let host = uri
            .host()
            .ok_or_else(|| Invalid::new(written, "it names no host"))?
            .to_owned();
        let authority = uri
            .authority()
            .map(|held| held.as_str())
            .unwrap_or_default();
        if authority.contains('@') {
            return Err(Invalid::new(
                written,
                "it carries user information, and credentials never travel in an endpoint",
            ));
        }
        if uri.query().is_some() {
            return Err(Invalid::new(
                written,
                "it carries a query, and an endpoint is a scheme, a host and a port only",
            ));
        }
        if !uri.path().chars().all(|character| character == '/') {
            return Err(Invalid::new(
                written,
                "it carries a path, and an endpoint is a host and a port only",
            ));
        }
        // A port that is written is one a socket can have: `:99999` was read as no port, and the
        // scheme's default port was dialled instead (BUG-0020).
        let default = if tls { HTTPS_PORT } else { HTTP_PORT };
        // `[::1]` holds colons of its own: a port follows the bracket, never inside it.
        let written_port = if authority.ends_with(']') {
            None
        } else {
            authority.rsplit_once(':').map(|(_, digits)| digits)
        };
        let port = match written_port {
            None | Some("") => default,
            Some(digits) => digits
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or_else(|| {
                    Invalid::new(
                        written,
                        &format!("the port `{digits}` is not one from 1 to 65535"),
                    )
                })?,
        };

        Ok(Self {
            tls,
            grpc,
            port,
            host,
            written: format!("{scheme}://{authority}"),
        })
    }

    /// Whether reaching this endpoint means a TLS handshake.
    pub fn is_tls(&self) -> bool {
        self.tls
    }

    /// Whether this endpoint is reached over gRPC: the scheme chose the transport (TC-1).
    pub fn is_grpc(&self) -> bool {
        self.grpc
    }

    /// The host, which is also the name a certificate is checked against.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The `host:port` to connect to.
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// What a `Host:` header should carry.
    ///
    /// The port is repeated unless it is the scheme's default, which is what a virtual host expects.
    pub fn host_header(&self) -> String {
        let default = if self.tls { HTTPS_PORT } else { HTTP_PORT };

        if self.port == default {
            return self.host.clone();
        }

        self.authority()
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.written)
    }
}

impl Serialize for Endpoint {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.written)
    }
}

/// An endpoint that could not be read, and why.
#[derive(Debug)]
pub struct Invalid {
    written: String,
    detail: String,
}

impl Invalid {
    fn new(written: &str, detail: &str) -> Self {
        Self {
            written: written.to_owned(),
            detail: detail.to_owned(),
        }
    }
}

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "`{}` is not a valid endpoint: {}",
            self.written, self.detail
        )
    }
}

impl std::error::Error for Invalid {}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn test_a_plain_endpoint_is_not_tls() {
        let endpoint = Endpoint::parse("http://127.0.0.1:6443").expect("a valid endpoint");

        assert!(!endpoint.is_tls());
        assert_eq!(endpoint.authority(), "127.0.0.1:6443");
        assert_eq!(endpoint.host_header(), "127.0.0.1:6443");
        assert_eq!(endpoint.to_string(), "http://127.0.0.1:6443");
    }

    #[test]
    fn test_https_is_tls_and_defaults_to_its_own_port() {
        let endpoint = Endpoint::parse("https://control.example.com").expect("a valid endpoint");

        assert!(endpoint.is_tls());
        assert_eq!(endpoint.authority(), "control.example.com:443");
        // The default port is not repeated, which is what a virtual host expects.
        assert_eq!(endpoint.host_header(), "control.example.com");
    }

    #[test]
    fn test_the_scheme_chooses_the_transport() {
        for (written, tls, grpc) in [
            ("http://127.0.0.1:6443", false, false),
            ("https://127.0.0.1:6443", true, false),
            ("grpc://127.0.0.1:6443", false, true),
            ("grpcs://127.0.0.1:6443", true, true),
        ] {
            let endpoint = Endpoint::parse(written).expect("a valid endpoint");
            assert_eq!(
                (endpoint.is_tls(), endpoint.is_grpc()),
                (tls, grpc),
                "{written}"
            );
        }
    }

    #[test]
    fn test_what_is_refused_and_why() {
        for (written, expected) in [
            ("127.0.0.1:6443", "an endpoint is a URL"),
            ("localhost:6443", "an endpoint is a URL"),
            // The shape someone writes when they expect the scheme to name a security posture.
            ("tls:127.0.0.1:6443", "an endpoint is a URL"),
            ("mtls://127.0.0.1:6443", "not a scheme this CLI speaks"),
            ("http://127.0.0.1:6443/version", "carries a path"),
            ("http://", "names no host"),
            // BUG-0020, BUG-0110, DEC-0017.
            ("http://host:99999", "is not one from 1 to 65535"),
            ("https://host:65536", "is not one from 1 to 65535"),
            ("http://host:0", "is not one from 1 to 65535"),
            ("http://user:secret@host:6443", "user information"),
            ("http://host:6443?x=1", "query"),
            ("http://host:6443#top", "fragment"),
            ("grpc://host:6443/path", "carries a path"),
        ] {
            let error = Endpoint::parse(written).expect_err(written).to_string();

            assert!(error.contains(expected), "for {written}: {error}");
        }

        // The canonical form: lower-case scheme, no trailing `/`, the default port left implicit.
        for (written, canonical, authority) in [
            (
                "HTTPS://Host.example:6443/",
                "https://Host.example:6443",
                "Host.example:6443",
            ),
            (
                "GRPC://127.0.0.1:6443/",
                "grpc://127.0.0.1:6443",
                "127.0.0.1:6443",
            ),
            (
                "grpcs://127.0.0.1:6443//",
                "grpcs://127.0.0.1:6443",
                "127.0.0.1:6443",
            ),
            ("http://host", "http://host", "host:80"),
            ("https://host", "https://host", "host:443"),
            ("http://[::1]:6443", "http://[::1]:6443", "[::1]:6443"),
            ("http://[::1]", "http://[::1]", "[::1]:80"),
        ] {
            let endpoint = Endpoint::parse(written).expect(written);
            assert_eq!(endpoint.to_string(), canonical, "{written}");
            assert_eq!(endpoint.authority(), authority, "{written}");
        }

        let missing_scheme = Endpoint::parse("127.0.0.1:6443")
            .expect_err("an endpoint without a scheme")
            .to_string();
        for scheme in ["http://", "https://", "grpc://", "grpcs://"] {
            assert!(
                missing_scheme.contains(scheme),
                "the guidance omits {scheme}: {missing_scheme}"
            );
        }
    }
}
