// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Plane public listeners of a process: refused at Bootstrap where they fall below their
//! class, and published with the Host listener and telemetry (WP-2.11, owner decisions of
//! 2026-10-10).
//!
//! From `production` up, a Plane public listener serving in the clear on a bind that is not
//! loopback is refused, unless the deployment declares that an ingress or a sidecar terminates
//! TLS in front of it (`tls.terminated_upstream`, the relaxation `regulated` refuses). A
//! declaration beside TLS the process serves itself is refused in every profile. What remains is
//! published, one [`ListenerReport`] per listener, in the process discovery document and
//! `GET /host/v1/status`.

use anyhow::{Result, bail};

use permguard_core::assurance::AssuranceProfile;
use permguard_core::listener::{ListenerClass, ListenerReport, is_loopback_bind};
use permguard_core::{Config, TlsSettings};

use super::discovery::{PlaneId, plane_enabled};
use super::settings::addresses_for_plane;
use super::{ListenerEndpoints as _, PlaneAddresses};

/// The protocol label of a listener serving HTTP alone.
pub(crate) const HTTP: &str = "http";
/// The protocol label of a listener serving gRPC alone.
pub(crate) const GRPC: &str = "grpc";
/// The protocol label of one listener serving HTTP and gRPC on a shared address.
pub(crate) const SHARED: &str = "http+grpc";

/// One listener a Plane's addresses resolve to.
#[derive(Debug, Clone)]
pub(crate) struct Endpoint {
    pub(crate) addr: String,
    pub(crate) protocol: &'static str,
    pub(crate) tls: Option<TlsSettings>,
    pub(crate) terminated_upstream: bool,
}

impl Endpoint {
    /// The name a report gives the listener of the plane `id`: `control-http`, `data-grpc`, or
    /// `control-http-grpc` for one listener serving both.
    fn name(&self, id: &str) -> String {
        format!("{id}-{}", self.protocol.replace('+', "-"))
    }

    fn report(&self, id: &str) -> ListenerReport {
        ListenerReport::of(
            self.name(id),
            ListenerClass::PlanePublic,
            self.tls.as_ref(),
            self.terminated_upstream,
            self.tls.as_ref().is_some_and(|tls| !tls.allow().is_empty()),
        )
    }

    /// Refuses the endpoint where it falls below the Plane public class under `config`.
    fn check(&self, config: &Config, id: &str) -> Result<()> {
        let name = self.name(id);
        if self.tls.is_some() && self.terminated_upstream {
            bail!(
                "the {name} listener declares that an ingress or a sidecar terminates TLS in front \
                 of it (`tls.terminated_upstream`) and serves TLS itself: state one of them"
            );
        }
        let production = config
            .assurance()
            .profile()
            .at_least(AssuranceProfile::Production);
        if production
            && self.tls.is_none()
            && !self.terminated_upstream
            && !is_loopback_bind(&self.addr)
        {
            bail!(
                "the {name} listener serves in the clear on {}: from the `{}` profile a Plane \
                 public listener beyond loopback serves TLS (`tls.cert` and `tls.key`), or the \
                 deployment declares that an ingress or a sidecar terminates TLS in front of it \
                 (`tls.terminated_upstream: true`, the relaxation `tls.terminated_upstream`)",
                self.addr,
                config.assurance().profile()
            );
        }
        Ok(())
    }
}

/// The startup check: every listener of the `planes` a server registered, by module id and
/// addresses, that `config` selects, against the Plane public class.
pub(crate) fn check(config: &Config, planes: &[(&'static str, PlaneAddresses)]) -> Result<()> {
    for (id, addresses) in planes {
        if !plane_enabled(config, id) {
            continue;
        }
        for endpoint in addresses.endpoints(config, id)? {
            endpoint.check(config, id)?;
        }
    }
    unused_public_addresses(config, planes)
}

/// Refuses the process's public listen address when no plane of this server listens there: on
/// the all-in-one each plane listens at its own address, and `--public-http-addr` (or
/// `public.http.addr`, or `PERMGUARD_PUBLIC_HTTP_ADDR`) accepted there moved nothing while the
/// effective configuration reported it in force (BUG-0182, DEC-0006).
fn unused_public_addresses(
    config: &Config,
    planes: &[(&'static str, PlaneAddresses)],
) -> Result<()> {
    use permguard_core::config::{SETTING_PUBLIC_GRPC_ADDR, SETTING_PUBLIC_HTTP_ADDR};
    use permguard_core::planes::PlaneAddress;
    let enabled: Vec<&PlaneAddresses> = planes
        .iter()
        .filter(|(id, _)| plane_enabled(config, id))
        .map(|(_, addresses)| addresses)
        .collect();
    for (setting, used, flag) in [
        (
            SETTING_PUBLIC_HTTP_ADDR,
            enabled
                .iter()
                .any(|addresses| addresses.http() == PlaneAddress::ConfigPublicHttp),
            "--public-http-addr",
        ),
        (
            SETTING_PUBLIC_GRPC_ADDR,
            enabled
                .iter()
                .any(|addresses| addresses.grpc() == PlaneAddress::ConfigPublicGrpc),
            "--public-grpc-addr",
        ),
    ] {
        let supplied = config
            .supplied_settings()
            .find(|(key, _, _)| *key == setting);
        if let Some((_, value, origin)) = supplied
            && !used
        {
            bail!(
                "{setting} ({flag}) is `{value}`, from the {}, and no plane of this server \
                 listens on the process's public address: each plane listens at its own \
                 (`controlPlane.public`, `dataPlane.public`). Set those, or leave this one out",
                origin.as_str()
            );
        }
    }
    Ok(())
}

/// Every listener of the process, sorted by name: the Host listener and telemetry from the
/// configuration, and each first-party Plane's, derived from the configuration as discovery
/// derives its planes. A Plane whose endpoints do not resolve is left out, the others kept; the
/// start refuses it anyway.
pub fn listeners(config: &Config) -> Vec<ListenerReport> {
    let mut reports = config.core_listeners();
    for plane in [PlaneId::Control, PlaneId::Data] {
        if !plane_enabled(config, plane.as_str()) {
            continue;
        }
        let Some(addresses) = addresses_for_plane(plane.as_str()) else {
            continue;
        };
        if let Ok(endpoints) = addresses.endpoints(config, plane.public_name()) {
            reports.extend(
                endpoints
                    .iter()
                    .map(|endpoint| endpoint.report(plane.as_str())),
            );
        }
    }
    reports.sort_by(|a, b| a.name.cmp(&b.name));
    reports
}

#[cfg(test)]
mod tests;
