// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Where a plane's listeners read their addresses and their TLS material from: configuration
//! only, which the server binds and every document publishes.

use std::env;

use anyhow::{Context, Result};

use super::settings::{PlaneEndpointKeys, PlaneTlsKeys, parse_bool, tls_for};
use crate::{Config, TlsSettings};

/// Where a plane listener reads its address from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaneAddress {
    /// Use `public.http.addr` from the active config file.
    ConfigPublicHttp,
    /// Use `public.grpc.addr` from the active config file.
    ConfigPublicGrpc,
    /// Read an environment variable and fall back to a static default.
    Env {
        variable: &'static str,
        default: &'static str,
    },
    /// Read a declared setting from the effective config.
    Setting {
        enabled_key: &'static str,
        addr_key: &'static str,
    },
}

impl PlaneAddress {
    /// Builds an environment-backed address source.
    pub const fn env(variable: &'static str, default: &'static str) -> Self {
        Self::Env { variable, default }
    }

    pub const fn setting(enabled_key: &'static str, addr_key: &'static str) -> Self {
        Self::Setting {
            enabled_key,
            addr_key,
        }
    }

    /// The address this source names under `config`, or `None` when it is turned off.
    pub fn resolve(self, config: &Config) -> Result<Option<String>> {
        match self {
            Self::ConfigPublicHttp => Ok(config.public_http_addr().map(ToOwned::to_owned)),
            Self::ConfigPublicGrpc => Ok(config.public_grpc_addr().map(ToOwned::to_owned)),
            Self::Env { variable, default } => Ok(Some(
                env::var(variable)
                    .ok()
                    .map(|value| value.trim().to_owned())
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| default.to_owned()),
            )),
            Self::Setting {
                enabled_key,
                addr_key,
            } => {
                if let Some(enabled) = config.setting(enabled_key)
                    && !parse_bool(enabled).with_context(|| format!("reading {enabled_key}"))?
                {
                    return Ok(None);
                }

                Ok(config.setting(addr_key).map(ToOwned::to_owned))
            }
        }
    }
}

/// Where a plane's HTTP and gRPC listeners read their addresses from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaneAddresses {
    http: PlaneAddress,
    grpc: PlaneAddress,
    http_tls: PlaneTls,
    grpc_tls: PlaneTls,
}

impl PlaneAddresses {
    /// Where the HTTP listener reads its address from.
    pub const fn http(&self) -> PlaneAddress {
        self.http
    }

    /// Where the gRPC listener reads its address from.
    pub const fn grpc(&self) -> PlaneAddress {
        self.grpc
    }

    /// Where the HTTP listener reads its TLS material from.
    pub const fn http_tls(&self) -> PlaneTls {
        self.http_tls
    }

    /// Where the gRPC listener reads its TLS material from.
    pub const fn grpc_tls(&self) -> PlaneTls {
        self.grpc_tls
    }

    /// Uses the configured public HTTP and gRPC addresses.
    pub const fn config_public() -> Self {
        Self {
            http: PlaneAddress::ConfigPublicHttp,
            grpc: PlaneAddress::ConfigPublicGrpc,
            http_tls: PlaneTls::Public,
            grpc_tls: PlaneTls::Public,
        }
    }

    /// Uses environment-backed HTTP and gRPC addresses.
    pub const fn env(
        http_variable: &'static str,
        http_default: &'static str,
        grpc_variable: &'static str,
        grpc_default: &'static str,
    ) -> Self {
        Self {
            http: PlaneAddress::env(http_variable, http_default),
            grpc: PlaneAddress::env(grpc_variable, grpc_default),
            http_tls: PlaneTls::Public,
            grpc_tls: PlaneTls::Public,
        }
    }

    /// Uses declared settings for HTTP and gRPC addresses.
    pub const fn settings(http: PlaneEndpointKeys, grpc: PlaneEndpointKeys) -> Self {
        Self {
            http: PlaneAddress::setting(http.enabled, http.addr),
            grpc: PlaneAddress::setting(grpc.enabled, grpc.addr),
            http_tls: PlaneTls::setting(http.tls),
            grpc_tls: PlaneTls::setting(grpc.tls),
        }
    }
}

/// Where a plane listener reads TLS material from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaneTls {
    /// Use process-level `public.tls`, when configured.
    Public,
    /// Read plane/protocol-specific TLS settings and fall back to process-level `public.tls`.
    Setting { keys: PlaneTlsKeys },
}

impl PlaneTls {
    pub const fn setting(keys: PlaneTlsKeys) -> Self {
        Self::Setting { keys }
    }

    /// The TLS material this source names under `config`, or `None` for a clear endpoint.
    pub fn resolve(self, config: &Config) -> Result<Option<TlsSettings>> {
        match self {
            Self::Public => Ok(config.public_tls()),
            Self::Setting { keys } => tls_for(config, keys),
        }
    }

    /// Whether the endpoint declares an upstream TLS termination (WP-2.11).
    pub fn terminated_upstream(self, config: &Config) -> Result<bool> {
        match self {
            Self::Public => Ok(config.public_tls_terminated_upstream()),
            Self::Setting { keys } => super::settings::terminated_upstream_for(config, keys),
        }
    }
}
