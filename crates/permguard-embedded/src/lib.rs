#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used, clippy::expect_used)]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Data Plane embedded in an application, over a Host composed for it
//! (`11-refactoring/1-dependencies.md`, Publication boundary: applications are not expected to
//! assemble the runtime manually).
//!
//! `permguard_data_plane::embedded` takes a Host the application composed by hand. This package
//! composes it: `permguard-runtime` opens the Host on its volume from the configuration file a
//! server reads, with the implementations that file names, and runs the Data Plane as one of its
//! services, with no listener.
//!
//! ```text
//! Embedded::builder(identity, build) ── engine(..), worker_executable(..), metrics(..)
//!        │ build()
//!        ▼
//!   (Embedded, Started)
//!        │                         │
//!        │ serve(config, file,     │ handle().await ── evaluate, submit, health
//!        │       shutdown)         │
//!        ▼                         ▼
//!   the Host's life: opened, its services and the Plane's started, drained and stopped in order
//! ```
//!
//! | Rule            | Here                                                                           |
//! | --------------- | ------------------------------------------------------------------------------ |
//! | the Host        | composed here from the configuration: identity, rings, streams, authorization  |
//! | the volume      | claimed by `serve`, held until it returns                                      |
//! | the runtime     | the caller's: `serve` is a future the application drives, and none is created  |
//! | signals         | none installed: the application's `shutdown` future ends the Host              |
//! | listeners       | none: no Plane listener, no Host listener, no telemetry endpoint               |
//! | configuration   | the server's file and contract; `runtime.planes` is `data`, whatever it says   |
//! | authorization   | the Host's: access tokens, and the public grants the configuration declares    |
//! | synchronization | a verified local mirror; a Host with no listener joins no coordinator          |
//! | the network     | nothing by default; each adapter is a feature the application selects          |
//!
//! `serve` borrows nothing from the application and is not `Send`: it runs where it is awaited,
//! beside the application's own work, as a server's start runs in its `main`.

use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context as _, Result};
use permguard_core::planes::settings::{
    AUTHORITY_SETTINGS, PlaneSettingKeys, SETTING_RUNTIME_OPTIONAL_PLANES, SETTING_RUNTIME_PLANES,
    authority_settings, plane_settings, runtime_settings,
};
use permguard_core::{BoxFuture, BuildSettings, Config, Metrics, ProductIdentity};
use permguard_data_plane::embedded::Hosted;
use permguard_offline::factories::{
    audit_sink_for, catalog_for, data_signing_keys_for, key_manager_for, secret_store_for,
};
use permguard_runtime::Composition;
use permguard_runtime::host::DefaultServerHost;
use permguard_runtime::planes::{DeclaredStreams, data_plane_section, register_streams};
use permguard_std::audit::TracingAuditSink;
use permguard_std::storage::MemoryStorage;

pub use permguard_data_plane::embedded::{
    Actor, CheckRequest, CheckResponse, Engine, Handle, Health, Refused, Started, SubmitRequest,
    SubmitResponse, TraceContext,
};
pub use permguard_languages::Unregistered;

/// The Plane this package embeds, as `runtime.planes` names it.
const PLANE: &str = "data";
/// The section of the configuration file the Data Plane owns.
const SECTION: &str = "dataPlane";

/// What an application sets before the Host is composed.
pub struct Builder {
    identity: ProductIdentity,
    build_settings: BuildSettings,
    metrics: Metrics,
    worker: Option<std::path::PathBuf>,
    engines: Vec<Engine>,
}

impl Builder {
    /// Registers an engine the application links itself, as
    /// [`permguard_data_plane::embedded::Builder::engine`] does: never beside the feature that
    /// selects the same language.
    pub fn engine(mut self, engine: Engine) -> Self {
        self.engines.push(engine);
        self
    }

    /// Names the dedicated evaluation worker, `permguard-evaluation-worker`: an absolute path to
    /// a regular file its owner may execute and nobody else may write.
    pub fn worker_executable(mut self, executable: impl Into<std::path::PathBuf>) -> Self {
        self.worker = Some(executable.into());
        self
    }

    /// Where the numbers the Host and the Plane record go; nothing is recorded otherwise.
    pub fn metrics(mut self, metrics: Metrics) -> Self {
        self.metrics = metrics;
        self
    }

    /// Composes the Host and the Data Plane it runs, and the promise of the Plane's handle.
    ///
    /// The engines are registered here, before any configuration is read: reading one checks it
    /// against the catalogue, and the catalogue is sealed by its first read. An engine whose
    /// language the process already carries is refused.
    pub fn build(self) -> Result<(Embedded, Started), Unregistered> {
        for engine in self.engines {
            permguard_languages::register(engine)?;
        }
        let (hosted, started) = Hosted::new();
        let hosted = match self.worker {
            Some(worker) => hosted.worker_executable(worker),
            None => hosted,
        };
        let binary_name = self.identity.binary_name();
        let version = self.build_settings.version();
        let mut declared = vec![SETTING_RUNTIME_PLANES, SETTING_RUNTIME_OPTIONAL_PLANES];
        declared.extend(AUTHORITY_SETTINGS);
        declared.extend(PlaneSettingKeys::DATA.settings());

        let composition = Composition::new(
            self.identity,
            self.build_settings,
            Box::new(DefaultServerHost::new()),
            Box::new(MemoryStorage::new()),
            Box::new(TracingAuditSink::new(binary_name, version)),
        )
        .with_metrics(self.metrics)
        // The implementations the configuration names, as a server resolves them.
        .with_secrets_factory(secret_store_for)
        .with_audit_factory(move |config| audit_sink_for(binary_name, config))
        .with_keys_factory(key_manager_for)
        .with_catalog_factory(catalog_for)
        .with_data_signing_keys_factory(data_signing_keys_for)
        // The configuration a server's Data Plane reads, read the same way.
        .with_declared_settings(declared)
        .with_section_settings("runtime", runtime_settings)
        .with_section_settings("authority", authority_settings)
        .with_section_settings(SECTION, |value| {
            plane_settings(value, PlaneSettingKeys::DATA)
        })
        .with_structured_section(SECTION, data_plane_section)
        // The Plane declares itself to the Host before any service starts, and is required.
        .with_plane_declaration(|config| {
            Some((
                PLANE,
                true,
                permguard_data_plane::embedded::declaration(config),
            ))
        })
        .with_startup_check(|config| {
            register_streams(
                config,
                vec![DeclaredStreams {
                    component: permguard_data_plane::COMPONENT,
                    description: "embedded Data Plane",
                    streams: permguard_data_plane::embedded::streams(config),
                }],
            )
        })
        .with_startup_check(permguard_data_plane::embedded::startup_check)
        .with_service(Box::new(hosted));

        Ok((Embedded { composition }, started))
    }
}

/// A Host composed for the application, with the Data Plane as its one Plane.
pub struct Embedded {
    composition: Composition,
}

impl Embedded {
    /// A builder for the product `identity` names, at the version `build_settings` states.
    pub fn builder(identity: ProductIdentity, build_settings: BuildSettings) -> Builder {
        Builder {
            identity,
            build_settings,
            metrics: Metrics::none(),
            worker: None,
            engines: Vec::new(),
        }
    }

    /// Adds what the composition does not carry by itself: a peer connector, a reload handler, a
    /// service of the application's own. The composition is `permguard-runtime`'s, and every
    /// adapter it names may be composed here.
    pub fn compose(mut self, compose: impl FnOnce(Composition) -> Composition) -> Self {
        self.composition = compose(self.composition);
        self
    }

    /// Fetches the Authority Plane's key set and status lists with the client library, over the
    /// transport the scheme of `authority.url` or `authority.endpoint` names: for an application
    /// whose callers present access tokens issued elsewhere. Without it, a configuration naming
    /// an Authority Plane elsewhere refuses the start.
    #[cfg(feature = "authority-refresh")]
    pub fn with_authority_refresh(self) -> Self {
        use permguard_client::authority_refresh;

        self.compose(|composition| {
            composition.with_authority_refresh(|trust, source, observing| {
                let refreshing = authority_refresh::drive(
                    trust,
                    authority_refresh::Source {
                        url: source.url,
                        ca: source.ca,
                        allow_http: source.allow_http,
                    },
                    authority_refresh::Observing {
                        health: observing.health,
                        metrics: observing.metrics,
                        time: observing.time,
                    },
                )?;
                Ok(Box::new(refreshing) as Box<dyn std::any::Any + Send>)
            })
        })
    }

    /// The effective configuration of `config_file`, read as a server reads it: the file, the
    /// environment, and `runtime.planes` set to the Data Plane, which is the one Plane here.
    pub fn config(&self, config_file: &Path) -> Result<Config> {
        self.composition
            .config_from(
                Some(config_file),
                [(SETTING_RUNTIME_PLANES.to_owned(), PLANE.to_owned())],
            )
            // Reached by its application: no listener is bound, whatever address the file names.
            .map(Config::embedded)
            .with_context(|| {
                format!(
                    "reading the configuration of the embedded Data Plane from {}",
                    config_file.display()
                )
            })
    }

    /// Opens the Host on its volume, starts its services and the Data Plane, and runs until
    /// `shutdown` resolves; then drains and stops everything in order and releases the volume.
    ///
    /// The future is the Host's whole life, on the caller's runtime: the application awaits it
    /// beside its own work. What it returns is what a server's start returns: an error when the
    /// Host could not start, or did not drain within its budget.
    pub async fn serve<S>(self, config: &Config, config_file: &Path, shutdown: S) -> Result<()>
    where
        S: Future<Output = ()> + Send + 'static,
    {
        // A factory, since a composition may serve more than once; this one serves once, and a
        // second ask finds the signal already taken and stops at once.
        let signal: Arc<Mutex<Option<BoxFuture<'static, ()>>>> =
            Arc::new(Mutex::new(Some(Box::pin(shutdown))));
        let composition = self.composition.with_shutdown_signal(move || {
            signal
                .lock()
                .ok()
                .and_then(|mut held| held.take())
                .unwrap_or_else(|| Box::pin(std::future::ready(())))
        });
        // The banner a terminal start announces itself with is a server's: nothing is printed.
        let mut out = std::io::sink();
        composition.serve(config, config_file, &mut out).await
    }
}
