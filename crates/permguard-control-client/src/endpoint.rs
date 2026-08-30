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
    /// The host, as written.
    host: String,
    /// The port, defaulted from the scheme when the endpoint left it out.
    port: u16,
    /// The endpoint as it was written, which is what a report should quote back.
    written: String,
}

impl Endpoint {
    /// Reads an endpoint, or says what is wrong with it.
    pub fn parse(written: &str) -> Result<Self, Invalid> {
        let uri = written.parse::<Uri>().map_err(|error| {
            // `tls:host:port` and `host:port` are the two shapes people write when they expect a
            // scheme to be a mode rather than a URL scheme, and both fail here as a bare parse
            // error that explains nothing.
            if written.contains(':') && !written.contains("://") {
                return Invalid::new(
                    written,
                    "an endpoint is a URL: write http://host:port, or https://host:port for TLS",
                );
            }

            if let Some((_, rest)) = written.split_once("://")
                && rest.is_empty()
            {
                return Invalid::new(written, "it names no host");
            }

            Invalid::new(written, &error.to_string())
        })?;
        let scheme = uri.scheme_str().unwrap_or_default();
        let tls = match scheme {
            "http" => false,
            "https" => true,
            "" => {
                return Err(Invalid::new(
                    written,
                    "an endpoint is a URL: write http://host:port, or https://host:port for TLS",
                ));
            }
            other => {
                return Err(Invalid::new(
                    written,
                    &format!("`{other}` is not a scheme this CLI speaks: use http:// or https://"),
                ));
            }
        };
        let host = uri
            .host()
            .ok_or_else(|| Invalid::new(written, "it names no host"))?
            .to_owned();

        if uri.path() != "" && uri.path() != "/" {
            return Err(Invalid::new(
                written,
                "it carries a path, and an endpoint is a host and a port only",
            ));
        }

        Ok(Self {
            tls,
            port: uri
                .port_u16()
                .unwrap_or(if tls { HTTPS_PORT } else { HTTP_PORT }),
            host,
            written: written.to_owned(),
        })
    }

    /// Whether reaching this endpoint means a TLS handshake.
    pub fn is_tls(&self) -> bool {
        self.tls
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
    fn test_what_is_refused_and_why() {
        for (written, expected) in [
            ("127.0.0.1:6443", "an endpoint is a URL"),
            ("localhost:6443", "an endpoint is a URL"),
            ("grpc://127.0.0.1:6443", "not a scheme this CLI speaks"),
            // The shape someone writes when they expect the scheme to name a security posture.
            ("tls:127.0.0.1:6443", "an endpoint is a URL"),
            ("mtls://127.0.0.1:6443", "not a scheme this CLI speaks"),
            ("http://127.0.0.1:6443/version", "carries a path"),
            ("http://", "names no host"),
        ] {
            let error = Endpoint::parse(written).expect_err(written).to_string();

            assert!(error.contains(expected), "for {written}: {error}");
        }
    }
}
