// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! App class: the object a binary composes its edition of the product out of.
//!
//! The app owns nothing it could have resolved itself. Identity, build metadata, server host,
//! storage, audit sink, secret store, and services are all handed to it by the binary, which is the
//! only place in a build that names a concrete implementation.
//!
//! What it composes is `permguard-runtime`'s [`Composition`] (the crate boundaries refactoring,
//! RD-15), headless. [`App::kit`] is that composition with the adapters every server has, the
//! listeners it publishes and the peer sessions over the Host listener's certificate; what a
//! program owns beside them is a feature it selects: the command line that drives it (`cli`), the
//! process's signals (`signals`), the Authority Plane's client (`authority-refresh`).

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;

use permguard_core::{
    AuditSink, BoxFuture, BuildSettings, Catalog, Config, ConfigSection, Metrics, ProductIdentity,
    Realm, RealmConfig, SecretStore, ServerHost, Service, Storage, Value,
};

use permguard_runtime::Composition;

/// The command line that drives a composed server: its parser, its offline commands, its exit
/// statuses. A binary's, selected with `cli`.
#[cfg(feature = "cli")]
mod cli;
#[cfg(feature = "cli")]
pub use cli::exit_code_of;
#[cfg(feature = "cli")]
pub use permguard_offline::{migrate, migrate_on};

#[cfg(feature = "cli")]
/// Checks an audit trail and returns what it found, in one line a human reads.
///
/// Registered by the binary for the same reason as everything else: this crate knows that a trail
/// can be verified, and only the composition root knows what the trail is made of.
type AuditVerifier =
    Box<dyn Fn(&Path, Option<&Path>, Option<&Path>) -> Result<String> + Send + Sync>;

/// A content-addressed tree on the volume and the check of its files: what `volume verify` reads.
pub use permguard_host::storage::verify::VerifiedTree;

#[cfg(feature = "cli")]
/// Reads a key ring on disk and returns its public keys as a JWKS document.
///
/// Registered by the binary for the same reason as the verifier: this crate knows a ring's public
/// keys can be exported, and only the composition root knows what a ring on disk is made of.
type KeysExporter = Box<dyn Fn(&Path) -> Result<String> + Send + Sync>;

/// A composed command-line application: one identity, one command set, one set of collaborators.
pub struct App {
    /// The Host as this build composes it, with a server's adapters.
    composition: Composition,
    #[cfg(feature = "cli")]
    audit_verifier: Option<AuditVerifier>,
    #[cfg(feature = "cli")]
    verified_trees: Vec<VerifiedTree>,
    #[cfg(feature = "cli")]
    keys_exporter: Option<KeysExporter>,
}

/// What the composition answers, the app answers: its identity, its collaborators, the context a
/// command runs against and every factory the configuration names.
impl std::ops::Deref for App {
    type Target = Composition;

    fn deref(&self) -> &Composition {
        &self.composition
    }
}

impl App {
    /// Composes a server from the identity it presents and the collaborators it always needs: the
    /// kit, with no process ownership. It publishes its listeners and, as a member, reaches its
    /// coordinators over the Host listener's own certificate; it installs no signal handler, parses
    /// no command line and opens no client of its own. Whoever assembles it says when it stops
    /// ([`Self::with_shutdown_signal`]) and adds what its program selects.
    ///
    /// Everything a build may or may not have — secrets, services, extra settings — is added on top,
    /// so a collaborator introduced later never changes this signature.
    pub fn kit(
        identity: ProductIdentity,
        build_settings: BuildSettings,
        server: Box<dyn ServerHost>,
        storage: Box<dyn Storage>,
        audit: Box<dyn AuditSink>,
    ) -> Self {
        Self {
            composition: Composition::new(identity, build_settings, server, storage, audit)
                // How this Host, as a member, reaches its coordinators: over the Host listener's
                // own certificate, verifying them against its client CA; without one, a join is
                // refused.
                .with_peer_connector(|config, session| {
                    permguard_client::peer::connector(config.admin_tls().as_ref(), session)
                })
                // Every listener and what it demands of its clients (WP-2.11).
                .with_listeners(crate::plane::listeners::listeners),
            #[cfg(feature = "cli")]
            audit_verifier: None,
            #[cfg(feature = "cli")]
            verified_trees: Vec::new(),
            #[cfg(feature = "cli")]
            keys_exporter: None,
        }
    }

    /// The effective configuration of `config_file`, read as every start reads it: the file, the
    /// environment and the settings this composition declares.
    pub fn config(&self, config_file: &Path) -> Result<Config> {
        self.composition
            .config_from(Some(config_file), Vec::<(String, String)>::new())
    }

    /// Opens the Host on its volume, starts every service and listener, and serves until `shutdown`
    /// resolves; then drains and stops everything in order and releases the volume.
    ///
    /// The future is the server's whole life, on the caller's runtime: a program that owns its
    /// process another way awaits it and says when it ends. Nothing is parsed, no signal handler
    /// is installed and no log subscriber is set: those are the program's.
    pub async fn serve_until<S>(
        self,
        config: &Config,
        config_file: &Path,
        shutdown: S,
    ) -> Result<()>
    where
        S: Future<Output = ()> + Send + 'static,
    {
        // A factory, since a composition may serve more than once; this one serves once, and a
        // second ask finds the signal already taken and stops at once.
        let signal: Arc<std::sync::Mutex<Option<BoxFuture<'static, ()>>>> =
            Arc::new(std::sync::Mutex::new(Some(Box::pin(shutdown))));
        let composition = self.composition.with_shutdown_signal(move || {
            signal
                .lock()
                .ok()
                .and_then(|mut held| held.take())
                .unwrap_or_else(|| Box::pin(std::future::ready(())))
        });
        // The banner a terminal start announces itself with is the command line's.
        let mut out = std::io::sink();
        composition.serve(config, config_file, &mut out).await
    }

    /// A server that owns its process: it stops on the process's signals and reloads on a hangup.
    #[cfg(feature = "signals")]
    pub fn with_process_signals(mut self) -> Self {
        self.composition = self
            .composition
            .with_process_shutdown(crate::signal::process_shutdown)
            .with_hangup_listener(crate::signal::on_hangup);

        self
    }

    /// The Authority Plane's key set and lists, fetched by the client library's Authority surface
    /// over the transport the source's scheme names (RD-11).
    #[cfg(feature = "authority-refresh")]
    pub fn with_authority_client(mut self) -> Self {
        self.composition = self
            .composition
            .with_authority_refresh(|trust, source, observing| {
                let refreshing = crate::authority_refresh::drive(
                    trust,
                    crate::authority_refresh::Source {
                        url: source.url,
                        ca: source.ca,
                        allow_http: source.allow_http,
                    },
                    crate::authority_refresh::Observing {
                        health: observing.health,
                        metrics: observing.metrics,
                        time: observing.time,
                    },
                )?;
                Ok(Box::new(refreshing) as Box<dyn std::any::Any + Send>)
            });

        self
    }

    /// The server a Permguard binary is: the kit, the process's signals and the Authority Plane's
    /// client.
    #[cfg(all(feature = "signals", feature = "authority-refresh"))]
    pub fn new(
        identity: ProductIdentity,
        build_settings: BuildSettings,
        server: Box<dyn ServerHost>,
        storage: Box<dyn Storage>,
        audit: Box<dyn AuditSink>,
    ) -> Self {
        Self::kit(identity, build_settings, server, storage, audit)
            .with_process_signals()
            .with_authority_client()
    }

    /// Adds the secret store this build resolves secret material from.
    pub fn with_secrets(mut self, secrets: Box<dyn SecretStore>) -> Self {
        self.composition = self.composition.with_secrets(secrets);

        self
    }

    /// Installs somewhere for the numbers this process records about itself to go.
    ///
    /// Without one, every measurement in every crate is a branch and a return, and `/metrics`
    /// publishes liveness and readiness alone. Which registry it is, is a decision for the
    /// composition root, exactly like the audit sink and the key ring.
    pub fn with_metrics(mut self, metrics: Metrics) -> Self {
        self.composition = self.composition.with_metrics(metrics);

        self
    }

    /// Supplies the step that prepares the volume before anything is validated.
    ///
    /// A build that registers none simply never creates anything, which is the right behaviour for
    /// one that is always given its material.
    pub fn with_provisioner<F>(mut self, provisioner: F) -> Self
    where
        F: Fn(&Config) -> Result<()> + Send + Sync + 'static,
    {
        self.composition = self.composition.with_provisioner(provisioner);

        self
    }

    /// Supplies the secret store this build resolves references from.
    ///
    /// A build that registers none can still run: it simply has nowhere to resolve a secret, and
    /// anything that needs one refuses rather than inventing a default.
    pub fn with_secrets_factory<F>(mut self, factory: F) -> Self
    where
        F: Fn(&Config) -> Result<Option<Box<dyn SecretStore>>> + Send + Sync + 'static,
    {
        self.composition = self.composition.with_secrets_factory(factory);

        self
    }

    /// Supplies the key ring this build signs with and publishes.
    ///
    /// A factory for the same reason as the secret store: where the keys live and how long each of
    /// them lives are configuration, and the app is composed before any configuration has been read.
    pub fn with_keys_factory<F>(mut self, factory: F) -> Self
    where
        F: Fn(
                &Config,
                &permguard_host::keys::registry::Opener<'_>,
            ) -> Result<Option<Arc<permguard_host::keys::ring::Ring>>>
            + Send
            + Sync
            + 'static,
    {
        self.composition = self.composition.with_keys_factory(factory);

        self
    }

    /// Supplies how this build keeps zones and ledgers.
    /// Names how the control plane's signing ring is built.
    pub fn with_control_signing_keys_factory<F>(mut self, factory: F) -> Self
    where
        F: Fn(
                &Config,
                &permguard_host::keys::registry::Opener<'_>,
            ) -> Result<Option<Arc<permguard_host::keys::ring::Ring>>>
            + Send
            + Sync
            + 'static,
    {
        self.composition = self.composition.with_control_signing_keys_factory(factory);

        self
    }

    /// Names how the data plane's signing ring is built.
    pub fn with_data_signing_keys_factory<F>(mut self, factory: F) -> Self
    where
        F: Fn(
                &Config,
                &permguard_host::keys::registry::Opener<'_>,
            ) -> Result<Option<Arc<permguard_host::keys::ring::Ring>>>
            + Send
            + Sync
            + 'static,
    {
        self.composition = self.composition.with_data_signing_keys_factory(factory);

        self
    }

    pub fn with_catalog_factory<F>(mut self, factory: F) -> Self
    where
        F: Fn(&Config) -> Result<Option<Arc<dyn Catalog>>> + Send + Sync + 'static,
    {
        self.composition = self.composition.with_catalog_factory(factory);

        self
    }

    /// Supplies the audit destinations this build offers a deployment a choice of.
    ///
    /// The sink handed to [`App::new`] stays the one used when the factory names none, so a build
    /// with a single destination needs none of this.
    pub fn with_audit_factory<F>(mut self, factory: F) -> Self
    where
        F: Fn(&Config) -> Result<Option<Arc<dyn AuditSink>>> + Send + Sync + 'static,
    {
        self.composition = self.composition.with_audit_factory(factory);

        self
    }

    /// Supplies how this build assembles one realm from its resolved configuration.
    ///
    /// A build that composes this can host realms; one that does not, cannot — and if a configuration
    /// declares a realm anyway, [`App::realms_for`] refuses to start rather than silently hosting
    /// none, because a realm nobody serves is a client's token nobody will verify.
    pub fn with_realm_factory<F>(mut self, factory: F) -> Self
    where
        F: Fn(&Config, &RealmConfig) -> Result<Realm> + Send + Sync + 'static,
    {
        self.composition = self.composition.with_realm_factory(factory);

        self
    }

    /// Registers the external witness asked to co-sign every audit checkpoint (WP-3.7): none
    /// ships, and a build that registers none seals its checkpoints alone.
    pub fn with_checkpoint_witness(
        mut self,
        witness: Arc<dyn permguard_host::audit::checkpoint::CheckpointWitness>,
    ) -> Self {
        self.composition = self.composition.with_checkpoint_witness(witness);

        self
    }

    pub fn with_plane_declaration<F>(mut self, declare: F) -> Self
    where
        F: Fn(&Config) -> Option<(&'static str, bool, permguard_host::composition::Declaration)>
            + Send
            + Sync
            + 'static,
    {
        self.composition = self.composition.with_plane_declaration(declare);

        self
    }

    /// Names the subsystems this build lays out through the storage library, with the layout
    /// versions it reads for each (WP-1.9). A volume laying out anything else, or a version
    /// outside the set, is refused at start.
    pub fn with_layouts(
        mut self,
        layouts: Vec<(&'static str, permguard_host::storage::migrate::Reads)>,
    ) -> Self {
        self.composition = self.composition.with_layouts(layouts);

        self
    }

    /// Supplies what this build does when it is asked to re-read what it can.
    ///
    /// Registered by the binary rather than resolved here, because the server host has no idea what
    /// a certificate is: the composition root knows it composed a transport, and hands over the
    /// function that re-reads it. A build that registers none simply cannot be asked, and says so
    /// once at startup instead of silently ignoring the signal.
    pub fn with_reload_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn() + Send + Sync + 'static,
    {
        self.composition = self.composition.with_reload_handler(handler);

        self
    }

    /// Supplies what counts as being asked to stop.
    ///
    /// A build that registers none waits for a process signal, which is what a server in a container
    /// should do. A test registers one that resolves immediately, or on its own command, and never
    /// has to send itself a signal to check the shutdown sequence.
    pub fn with_shutdown_signal<F>(mut self, factory: F) -> Self
    where
        F: Fn() -> BoxFuture<'static, ()> + Send + Sync + 'static,
    {
        self.composition = self.composition.with_shutdown_signal(factory);

        self
    }

    /// Registers a service the server host is expected to start, after the ones already registered.
    /// Adds a check the assembled configuration must pass before anything starts.
    ///
    /// Runs on every path that builds a config, `serve` and the named actions alike: a
    /// configuration that is wrong for this build is wrong whatever it was asked to do.
    pub fn with_startup_check<F>(mut self, check: F) -> Self
    where
        F: Fn(&Config) -> Result<()> + Send + Sync + 'static,
    {
        self.composition = self.composition.with_startup_check(check);

        self
    }

    pub fn with_service(mut self, service: Box<dyn Service>) -> Self {
        self.composition = self.composition.with_service(service);

        self
    }

    /// Registers a typed configuration section this build understands.
    ///
    /// This is how a capability outside this workspace gets configuration of its own shape — nested,
    /// typed, validated — rather than the flat string settings [`App::with_declared_settings`] gives.
    /// Registering claims the section name, so a file that declares it is accepted and a file that
    /// misspells it is still rejected.
    ///
    /// The section is parsed from the configuration file and validated before anything starts; a build
    /// whose section does not make sense fails where a human is watching.
    /// # Panics
    ///
    /// When two types claim the same section name. It is a mistake in how a binary was composed, not
    /// something a deployment can cause, and the alternative — the last registration silently winning
    /// — means one crate's configuration is read into the other's type at runtime.
    pub fn with_config_section<T: ConfigSection>(mut self) -> Self {
        self.composition = self.composition.with_config_section::<T>();

        self
    }

    /// Declares extra setting keys this build understands, on top of the typed ones.
    ///
    /// A key that is not declared is discarded at every configuration layer.
    pub fn with_declared_settings<I, S>(mut self, keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.composition = self.composition.with_declared_settings(keys);

        self
    }

    /// Claims configuration-file sections this build parses itself.
    ///
    /// A section nobody claims is reported as an error, so a typo never passes silently.
    pub fn with_claimed_sections<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.composition = self.composition.with_claimed_sections(names);

        self
    }

    /// Claims a configuration-file section and turns it into settings of the configuration-file layer.
    ///
    /// This is how a capability outside this workspace gets its own YAML section without either crate
    /// knowing about the other: the section is claimed, `reader` converts it to setting pairs, and
    /// those pairs travel through the same precedence layers as everything else. Only keys the build
    /// also declared with [`App::with_declared_settings`] survive into the config.
    pub fn with_section_settings<N, F>(mut self, name: N, reader: F) -> Self
    where
        N: Into<String>,
        F: Fn(&Value) -> Result<Vec<(String, String)>> + Send + Sync + 'static,
    {
        self.composition = self.composition.with_section_settings(name, reader);

        self
    }

    /// Claims a configuration-file section and lets it attach structured configuration to the config.
    ///
    /// The twin of [`App::with_section_settings`], for what a flat setting cannot express: a list.
    /// The section is claimed the same way, and `apply` runs once the layers are resolved, so it sees
    /// the configuration the process will actually run with.
    pub fn with_structured_section<F>(mut self, name: &'static str, apply: F) -> Self
    where
        F: Fn(Config, &Value) -> Result<Config> + Send + Sync + 'static,
    {
        self.composition = self.composition.with_structured_section(name, apply);

        self
    }
}
