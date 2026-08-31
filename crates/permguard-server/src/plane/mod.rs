// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Planes: an API bundle that can be hosted alone or beside others.
//!
//! A plane is a [`PlaneModule`] — HTTP routes, gRPC services, a name — that
//! the process mounts as a lifecycle [`Service`] on its own listeners.
//! [`PlaneServer`] is the bootstrap every shipped binary shares: one plane
//! for the standalone servers, several for the all-in-one, the same
//! composition either way.
//!
//! The parts around it, split by domain: [`settings`] (the setting keys and
//! the configuration-file sections that feed them), [`discovery`] (what the
//! well-known documents say about which planes are loaded), and
//! [`factories`] (what the composition root builds: rings, catalogs, sinks).

use std::env;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use axum::Router;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse as _, Response};
use tracing::{info, warn};

use permguard_core::{
    BoxFuture, BuildSettings, Config, Metrics, ProductIdentity, ServerContext, Service,
    TlsSettings, ready,
};
use permguard_std::audit::TracingAuditSink;
use permguard_std::keys::KeyService;
use permguard_std::metrics::Registry;
use permguard_std::pseudonym::HmacPseudonymizer;
use permguard_std::storage::MemoryStorage;
use permguard_telemetry::TelemetryService;
use permguard_transport::Surface;

use crate::{App, DefaultServerHost};

pub mod discovery;
pub mod factories;
pub mod settings;

pub use discovery::{
    DiscoveredPlane, InterfaceLink, PlaneConfiguration, PlaneId, discovered_planes,
    plane_configuration, plane_http_base, server_configuration_document, streams_route,
};
pub use factories::build_settings;
pub use settings::*;

use discovery::plane_enabled;
use factories::{
    audit_sink_for, catalog_for, control_signing_keys_for, data_signing_keys_for, key_manager_for,
    secret_store_for,
};
use settings::{parse_bool, tls_for};

/// A plane API bundle that can be hosted alone or beside other planes.
pub trait PlaneModule: Send + Sync + 'static {
    /// Stable plane id used in runtime selection, for example `control`.
    fn id(&self) -> &'static str;

    /// Component name written in logs and metrics.
    fn component(&self) -> &'static str;

    /// Human-readable service name used in startup errors.
    fn description(&self) -> &'static str;

    /// Builds this plane's HTTP router.
    fn http_routes(&self, context: &ServerContext<'_>) -> Router;

    /// Builds this plane's gRPC router.
    fn grpc_routes(&self, context: &ServerContext<'_>) -> Router;

    /// Background work this plane runs beside its listeners.
    ///
    /// Most planes contribute none: they answer requests and that is all. A
    /// plane that keeps state current — a mirroring data plane, say — hands
    /// its loop over here, so it starts and stops with the process instead of
    /// inventing a lifecycle of its own.
    fn services(&self) -> Vec<Box<dyn Service>> {
        Vec::new()
    }

    /// The transport limits this plane's surfaces run under.
    ///
    /// The configured limits, unless a plane knows better. The hook exists
    /// because limits compose across layers, and the transport is the outer
    /// one: a body ceiling below what a plane's own protocol advertises turns
    /// the advertisement into a lie — the control plane negotiates NOTP
    /// batches of `notp.max_batch_bytes` and must therefore accept a request
    /// that large, whatever the generic default says.
    fn limits(&self, config: &permguard_core::Config) -> permguard_core::Limits {
        config.limits().clone()
    }

    /// The evidence streams this plane serves under a configuration.
    ///
    /// Declared rather than discovered, so the composition can refuse two streams claiming one
    /// directory at startup instead of letting the second writer find out. A plane that serves
    /// none declares none, which is the default.
    fn streams(&self, config: &permguard_core::Config) -> Vec<permguard_stream::StreamDescriptor> {
        let _ = config;

        Vec::new()
    }

    /// What this plane requires of a configuration before the process starts.
    ///
    /// The hook exists because a plane's own requirements are the plane's, and the server has no
    /// way to know them: whether an event producer has been named, whether a retention floor
    /// covers the runtimes a build carries. Checked at startup rather than at the first request,
    /// because both are configuration mistakes, and a configuration mistake should stop a process
    /// rather than start one that refuses every request for a reason nobody is watching for.
    ///
    /// The default requires nothing.
    fn startup_check(&self, config: &permguard_core::Config) -> anyhow::Result<()> {
        let _ = config;

        Ok(())
    }
}

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

    fn resolve(self, config: &Config) -> Result<Option<String>> {
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

    fn resolve(self, config: &Config) -> Result<Option<TlsSettings>> {
        match self {
            Self::Public => Ok(config.public_tls()),
            Self::Setting { keys } => tls_for(config, keys),
        }
    }
}

/// A plane mounted as a lifecycle service.
pub struct PlaneService {
    /// Shared rather than owned, so the composition can also register the plane's startup check
    /// without holding the module twice. One module, asked two questions at two moments.
    module: std::sync::Arc<dyn PlaneModule>,
    addresses: PlaneAddresses,
    running: Mutex<Vec<Surface>>,
}

impl PlaneService {
    /// Hosts `module` at `addresses`.
    pub fn new(module: Box<dyn PlaneModule>, addresses: PlaneAddresses) -> Self {
        Self {
            module: std::sync::Arc::from(module),
            addresses,
            running: Mutex::new(Vec::new()),
        }
    }

    /// The module this plane hosts, for the composition's own checks.
    pub fn module(&self) -> std::sync::Arc<dyn PlaneModule> {
        std::sync::Arc::clone(&self.module)
    }
}

impl Service for PlaneService {
    fn name(&self) -> &'static str {
        self.module.component()
    }

    fn start<'a>(&'a self, context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if !plane_enabled(context.config(), self.module.id()) {
                info!(
                    event.name = "plane.disabled",
                    component = self.module.component(),
                    plane = self.module.id(),
                    "plane is not selected by runtime configuration"
                );

                return Ok(());
            }

            let http_addr = self.addresses.http.resolve(context.config())?;
            let grpc_addr = self.addresses.grpc.resolve(context.config())?;
            let http_tls = self.addresses.http_tls.resolve(context.config())?;
            let grpc_tls = self.addresses.grpc_tls.resolve(context.config())?;

            let surfaces = match (http_addr, grpc_addr, http_tls, grpc_tls) {
                (None, None, _, _) => {
                    info!(
                        event.name = "plane.disabled",
                        component = self.module.component(),
                        plane = self.module.id(),
                        "no plane address is configured"
                    );

                    return Ok(());
                }
                (Some(addr), Some(grpc), http_tls, grpc_tls) if addr == grpc => {
                    if http_tls != grpc_tls {
                        anyhow::bail!(
                            "{} HTTP and gRPC share `{addr}` but declare different TLS policies: \
                             use the same TLS policy or split the HTTP and gRPC addresses",
                            self.module.description()
                        );
                    }

                    vec![(
                        addr,
                        "http+grpc",
                        shared_port(
                            self.module.http_routes(context),
                            self.module.grpc_routes(context),
                        ),
                        http_tls,
                    )]
                }
                (Some(addr), Some(grpc), http_tls, grpc_tls) => {
                    // One plane, one role port is the documented shape; two addresses is a
                    // deliberate override and stays one, but it should never be an accident a
                    // deployment discovers from a firewall rule.
                    warn!(
                        event.name = "plane.split_ports",
                        component = self.module.component(),
                        plane = self.module.id(),
                        http = %addr,
                        grpc = %grpc,
                        "this plane splits HTTP and gRPC across two addresses; the canonical \
                         shape is one role port serving both"
                    );

                    vec![
                        (addr, "http", self.module.http_routes(context), http_tls),
                        (grpc, "grpc", self.module.grpc_routes(context), grpc_tls),
                    ]
                }
                (Some(addr), None, http_tls, _) => {
                    vec![(addr, "http", self.module.http_routes(context), http_tls)]
                }
                (None, Some(addr), _, grpc_tls) => {
                    vec![(addr, "grpc", self.module.grpc_routes(context), grpc_tls)]
                }
            };

            for (configured, protocol, router, tls) in surfaces {
                let surface = self
                    .start_surface(context, configured, protocol, router, tls)
                    .await?;
                self.running
                    .lock()
                    .map_err(|_| {
                        anyhow!("the {} surface lock is poisoned", self.module.description())
                    })?
                    .push(surface);
            }

            Ok(())
        })
    }

    fn stop<'a>(&'a self, context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        let surfaces = match self.running.lock() {
            Ok(mut running) => std::mem::take(&mut *running),
            Err(_) => {
                return ready(Err(anyhow!(
                    "the {} surface lock is poisoned",
                    self.module.description()
                )));
            }
        };

        Box::pin(async move {
            for surface in surfaces {
                let address = surface
                    .stop(context.config().shutdown_timeout())
                    .await
                    .with_context(|| {
                        format!(
                            "waiting for the {} surface to finish",
                            self.module.description()
                        )
                    })?;

                info!(
                    event.name = "plane.stopped_listening",
                    component = self.module.component(),
                    plane = self.module.id(),
                    address = %address,
                    "stopped listening"
                );
            }

            Ok(())
        })
    }
}

impl PlaneService {
    async fn start_surface(
        &self,
        context: &ServerContext<'_>,
        configured: String,
        protocol: &'static str,
        router: Router,
        secured: Option<TlsSettings>,
    ) -> Result<Surface> {
        if let Some(settings) = &secured {
            settings
                .validate()
                .with_context(|| format!("validating TLS for {protocol}"))?;
        }

        let surface = Surface::listener(self.module.component(), configured.as_str(), router)
            .tls(secured.as_ref())
            .limits(self.module.limits(context.config()))
            .metrics(context.metrics().clone())
            .start()
            .await
            .with_context(|| format!("starting the {} surface", self.module.description()))?;

        let bound = surface.address();

        info!(
            event.name = "plane.listening",
            component = self.module.component(),
            plane = self.module.id(),
            protocol,
            address = %bound,
            tls = secured.is_some(),
            mtls = secured.as_ref().is_some_and(TlsSettings::is_mutual),
            "listening"
        );

        // Beside the line that says where it listens, because that is where an operator looks and
        // because the two addresses are only confusing together. A plane that binds every
        // interface and was told nothing to advertise publishes discovery links naming `0.0.0.0`,
        // which nothing can dial — and the symptom afterwards is a client that cannot connect,
        // with no error anywhere near this process.
        //
        // Warned rather than refused: a process reachable at the address it binds is the normal
        // local case. Said *here* rather than in a startup check, because those run while the
        // configuration is still being assembled — before the log subscriber exists, so nobody
        // hears them.
        if protocol.contains("http")
            && let Some(plane) = discovery::PlaneId::parse(self.module.id())
            && let Some(published) = discovery::plane_http_base(context.config(), plane)
            && published
                .split_once("://")
                .is_some_and(|(_, rest)| discovery::is_wildcard_address(rest))
        {
            tracing::warn!(
                event.name = "plane.unroutable_advertisement",
                component = self.module.component(),
                plane = self.module.id(),
                published = published.as_str(),
                "this plane publishes an address nothing can dial: it binds every interface and \
                 was told none to advertise, so every client that follows a discovery link goes \
                 nowhere. Set `public.http.advertised_url` to where clients actually reach it"
            );
        }

        Ok(surface)
    }
}

/// Shared bootstrap for single-plane and all-in-one binaries.
pub struct PlaneServer {
    identity: ProductIdentity,
    build_settings: BuildSettings,
    planes: Vec<PlaneService>,
}

impl PlaneServer {
    /// Starts a server with no planes registered yet.
    pub fn new(identity: ProductIdentity, build_settings: BuildSettings) -> Self {
        Self {
            identity,
            build_settings,
            planes: Vec::new(),
        }
    }

    /// Adds a plane to the process.
    pub fn with_plane(mut self, module: Box<dyn PlaneModule>, addresses: PlaneAddresses) -> Self {
        self.planes.push(PlaneService::new(module, addresses));
        self
    }

    /// Runs the composed process.
    pub async fn run(self) -> ExitCode {
        let binary_name = self.identity.binary_name();
        let version = self.build_settings.version();

        let mut app = App::new(
            self.identity,
            self.build_settings,
            Box::new(DefaultServerHost::new()),
            Box::new(MemoryStorage::new()),
            Box::new(TracingAuditSink::new(binary_name, version)),
        )
        .with_metrics(Metrics::new(Arc::new(Registry::new())))
        .with_provisioner(permguard_std::provision::prepare)
        .with_secrets_factory(secret_store_for)
        .with_audit_factory(move |config, keys| audit_sink_for(binary_name, config, keys))
        .with_keys_factory(key_manager_for)
        .with_catalog_factory(catalog_for)
        .with_control_signing_keys_factory(control_signing_keys_for)
        .with_data_signing_keys_factory(data_signing_keys_for)
        .with_pseudonymizer_factory(|key, key_version| {
            Box::new(HmacPseudonymizer::new(key, key_version))
        })
        .with_reload_handler(|| {
            permguard_transport::reload_all();
        })
        .with_declared_settings(declared_settings_for(&self.planes))
        .with_section_settings("runtime", runtime_settings)
        .with_service(Box::new(
            TelemetryService::new().with_configuration(server_configuration_document),
        ))
        .with_service(Box::new(KeyService::new()));

        for section in section_settings_for(&self.planes) {
            app = app.with_section_settings(section.name, move |value| {
                plane_settings(value, section.keys)
            });

            // The data plane's `mirrors.servers` and `decisions.log.server`
            // are lists and structures, so they cannot ride the setting
            // layers: they are attached as structured configuration, and their
            // shape is checked while somebody is watching.
            if section.name == "controlPlane" {
                app = app.with_structured_section(section.name, |config, value| {
                    let config =
                        config.with_decision_producer_keys(settings::producer_keys(value)?);

                    Ok(config.with_event_producer_keys(settings::event_producer_keys(value)?))
                });
            }

            if section.name == "dataPlane" {
                app = app.with_structured_section(section.name, |config, value| {
                    let config = config.with_mirror_sources(settings::mirror_sources(value)?)?;
                    // The subscriptions this plane imports history from: a list of three-part
                    // entries, so it travels here rather than through the setting layers.
                    let config = config.with_pull_ledgers(settings::pull_ledgers(value)?);
                    let config =
                        config.with_pull_producer_keys(settings::pull_producer_keys(value)?);
                    let config =
                        config.with_events_destination(settings::events_destination(value)?)?;
                    let (destination, include) = settings::log_destination(value)?;

                    config.with_log_destination(destination, include)
                });
            }
        }

        // A configured administrative surface that nothing serves.
        //
        // `admin.addr`, `admin.tls` and `admin.allow` are read and validated — mutual TLS
        // demanded, the allow list required outside development — and then no listener binds them.
        // The planes registered here serve one public surface and one Server Host operations
        // surface. The catalog's mutations, policy push and audit reads are answered on the public
        // surface.
        //
        // The danger is not the missing listener. It is an operator reading a configuration that
        // names an admin address behind mutual TLS and an allow list, concluding that
        // administration is separated, and leaving the public endpoint open to the cluster. So a
        // configuration that describes the boundary is refused until something serves it: the
        // check disappears on its own the day a plane answers there.
        app = app.with_startup_check(|config| {
            let Some(address) = config.admin_addr() else {
                return Ok(());
            };

            anyhow::bail!(
                "`admin.addr` is {address}, and this build serves no administrative surface: the \
                 catalog's mutations, the policy push and the audit reads are answered on the \
                 public endpoint. Remove the setting and restrict the public endpoint instead — \
                 leaving it describes a separation that does not exist. \
                 docs/operations/administrative-surface.md says what does protect it"
            );
        });

        // Every stream every selected plane declares, registered once — a validation pass, by
        // design: the registry lives for this check and is dropped with it, because nothing at
        // runtime consumes it yet. Discovery serves the descriptors directly (`/v1/streams` on
        // each plane), and a long-lived registry arrives with the stream runtime itself. What
        // this pass buys today is that the first directory collision is a refusal here, at
        // startup, rather than a runtime surprise on a volume.
        // A nesting between two directories that predate the versioned layout is tolerated and
        // logged — an existing volume keeps starting — and anything involving a new stream is
        // refused outright.
        let modules: Vec<std::sync::Arc<dyn PlaneModule>> =
            self.planes.iter().map(PlaneService::module).collect();
        app = app.with_startup_check(move |config| {
            let mut registry = permguard_stream::StreamRegistry::new();
            let mut serving_any = false;
            for module in &modules {
                if !plane_enabled(config, module.id()) {
                    continue;
                }
                for descriptor in module.streams(config) {
                    // A disabled stream is declared — discovery lists it as disabled — but it
                    // owns no directory and registers nothing: only writers can collide.
                    if !descriptor.enabled {
                        continue;
                    }
                    serving_any = true;
                    let identity = descriptor.identity.to_string();
                    match registry.register(descriptor) {
                        Ok(permguard_stream::Registered::Clean) => {}
                        Ok(permguard_stream::Registered::Tolerated { with }) => warn!(
                            event.name = "streams.legacy_nesting",
                            component = module.component(),
                            stream = %identity,
                            beside = %with,
                            "two pre-layout streams nest their directories; the versioned \
                             layout under data/streams separates what a future migration moves"
                        ),
                        Err(refused) => anyhow::bail!(
                            "registering the streams of the {}: {refused}",
                            module.description()
                        ),
                    }
                }
            }

            // The versioned layout is claimed before any stream serves: the marker under
            // `data/streams` says which rule the directories below it follow, and a root laid
            // out by a rule this build does not know is refused rather than guessed at.
            if serving_any {
                permguard_stream::layout::claim(&config.data_directory())
                    .map_err(|error| anyhow::anyhow!("claiming the stream layout: {error}"))?;
            }

            Ok(())
        });

        for plane in self.planes {
            // What this plane requires of the configuration, before anything binds — but only
            // when the runtime actually selects the plane. A process told to host `control`
            // alone must not be stopped by the data plane's requirements, and must not run the
            // data plane's background work either: `runtime.planes` selects the plane whole,
            // checks and services included, not merely its listeners.
            let module = plane.module();
            app = app.with_startup_check(move |config| {
                if !plane_enabled(config, module.id()) {
                    return Ok(());
                }

                module.startup_check(config)
            });
            // The plane's own background work first: it starts before the
            // listeners it feeds, and stops after them.
            for service in plane.module.services() {
                app = app.with_service(Box::new(SelectedService {
                    plane: plane.module.id(),
                    inner: service,
                }));
            }
            app = app.with_service(Box::new(plane));
        }

        app.run().await
    }
}

/// A plane's background service, started only when the runtime selects its plane.
///
/// The listeners already honour `runtime.planes`; this makes the plane's services honour the same
/// selection, so a disabled plane contributes nothing at all — no checks, no listeners, no loops.
struct SelectedService {
    plane: &'static str,
    inner: Box<dyn Service>,
}

impl Service for SelectedService {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn start<'a>(&'a self, context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        if !plane_enabled(context.config(), self.plane) {
            return Box::pin(std::future::ready(Ok(())));
        }

        self.inner.start(context)
    }

    fn stop<'a>(&'a self, context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        // Delegated unconditionally: a service that never started has nothing to release and
        // must say so gracefully, and one that did start must always be given its stop.
        self.inner.stop(context)
    }
}

/// HTTP and gRPC on one port, with each protocol answering its own "no such thing".
///
/// # Why this is not a plain `merge`
///
/// The gRPC router carries a fallback of its own — the `UNIMPLEMENTED` a gRPC client expects for a
/// method a server does not serve — and merging hands that fallback every unmatched path. So an
/// **HTTP** client asking a shared port for a path that does not exist was answered `200 OK`, with
/// `content-type: application/grpc`, `grpc-status: 12` and an empty body. Nothing was wrong with
/// the server and nothing was wrong with the request except the path, and the one thing the answer
/// did not say was *404*.
///
/// That is worse than unhelpful for discovery in particular: a client probing for a document, or a
/// person checking whether an endpoint they read about is still served, is told "yes, 200" by a
/// port that serves nothing there.
///
/// So the fallback asks which protocol is speaking — a gRPC request says so in its content type —
/// and answers in that protocol's own vocabulary.
fn shared_port(http: Router, grpc: Router) -> Router {
    http.merge(grpc).fallback(unmatched)
}

/// The answer for a path neither surface serves.
async fn unmatched(headers: HeaderMap) -> Response {
    let grpc = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/grpc"));

    if grpc {
        // What tonic answers for a method it does not serve: the status rides in the trailer-style
        // header, not in the HTTP status, which is how gRPC works.
        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/grpc"),
                (
                    header::HeaderName::from_static("grpc-status"),
                    // 12 is UNIMPLEMENTED.
                    "12",
                ),
            ],
        )
            .into_response();
    }

    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"class":"not_found","code":"route_unknown","message":"this plane serves no such path"}"#,
    )
        .into_response()
}
