// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The composition of a Host, headless (the crate boundaries refactoring, RD-15): the object a
//! build composes its edition of the product out of, and the start that opens the Host on its
//! volume, registers its Planes and runs the server host it was handed.
//!
//! The composition owns nothing it could have resolved itself. Identity, build metadata, server
//! host, storage, audit sink, secret store, and services are all handed to it by the binary, which
//! is the only place in a build that names a concrete implementation.
//!
//! What reaches outside the process is an adapter the build composes, and never this package's:
//!
//! | Adapter                                 | Without it                                           |
//! | --------------------------------------- | ---------------------------------------------------- |
//! | [`Composition::with_peer_connector`]    | this Host reaches no coordinator: a join is refused  |
//! | [`Composition::with_authority_refresh`] | an Authority Plane named elsewhere refuses the start |
//! | [`Composition::with_process_shutdown`]  | the start needs a composed shutdown signal           |
//! | [`Composition::with_hangup_listener`]   | no reload is heard                                   |
//! | [`Composition::with_listeners`]         | the Host publishes no listener                       |
//!
//! No listener is bound here, no signal handler installed and no runtime created: the start runs
//! on the Tokio runtime of whoever calls it.

use std::env;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};

use permguard_core::{
    AuditRecorder, AuditSink, BoxFuture, BuildSettings, Catalog, Config, ConfigFile, ConfigSection,
    KeyManager, Layers, LogFormat, Metrics, ProductIdentity, Pseudonymizer, Realm, RealmConfig,
    Realms, SecretStore, ServerContext, ServerHost, Service, Storage, Value,
};

use permguard_offline::custodian_for;
use permguard_offline::keys::resolve_root;

use crate::banner::Banner;

/// What a build does when it is asked to re-read what it can.
pub type ReloadHandler = Arc<dyn Fn() + Send + Sync>;

/// Listens for the request to reload and calls the handler each time, until its task is aborted.
type HangupListener = Box<dyn Fn(ReloadHandler) -> tokio::task::JoinHandle<()> + Send + Sync>;

/// Builds how this Host, as a member, reaches its coordinators, from the Host listener's
/// configuration and the session context it initiates with; nothing when the configuration gives
/// it no certificate to reach them with.
type PeerConnectorFactory = Box<
    dyn Fn(
            &Config,
            &permguard_host::session::Context,
        ) -> Result<Option<Arc<dyn permguard_host::membership::member::Connector>>>
        + Send
        + Sync,
>;

/// Where the Authority Plane's key set and status lists are fetched from.
#[derive(Debug, Clone)]
pub struct AuthoritySource {
    /// `authority.endpoint`, else `authority.url`, without a trailing slash.
    pub url: String,
    /// `authority.tls.ca`, beside the system's authorities.
    pub ca: Option<std::path::PathBuf>,
    /// Whether a clear transport is accepted: under `development` alone.
    pub allow_http: bool,
}

/// Where the standing of what was fetched is reported.
#[derive(Clone)]
pub struct AuthorityObserving {
    /// The readiness the standing degrades.
    pub health: permguard_core::server::Health,
    /// The numbers the fetch records.
    pub metrics: Metrics,
    /// The Host's one time service.
    pub time: Arc<permguard_host::time::TimeGuard>,
}

/// Starts the fetch of the Authority Plane's key set and status lists into the trust this Host
/// verifies tokens with; what it returns is held for as long as the Host runs, and stops the fetch
/// when dropped.
type AuthorityRefresh = Box<
    dyn Fn(
            Arc<permguard_host::authz::AuthorityTrust>,
            AuthoritySource,
            AuthorityObserving,
        ) -> Result<Box<dyn std::any::Any + Send>>
        + Send
        + Sync,
>;

/// Every listener of the process and what it demands of its clients, as discovery publishes them.
type ListenerReports =
    Box<dyn Fn(&Config) -> Vec<permguard_core::listener::ListenerReport> + Send + Sync>;

/// Turns one configuration-file section into settings of the configuration-file layer.
type SectionReader = Box<dyn Fn(&Value) -> Result<Vec<(String, String)>> + Send + Sync>;

/// A check a composed build makes on the assembled configuration.
type StartupCheck = Box<dyn Fn(&Config) -> Result<()> + Send + Sync>;

/// Builds the secret store the effective configuration names.
///
/// A factory because where secrets live is configuration, and the
/// app is composed before any configuration has been read. The binary still names the type.
type SecretStoreFactory =
    Box<dyn Fn(&Config) -> Result<Option<Box<dyn SecretStore>>> + Send + Sync>;

/// What `authorization_for` opens on the volume: the authorization every Plane and the Host
/// listener decide with, the authenticator in front of it, the Authority Plane's key set and lists
/// tokens verify under, and the recovery principal's commitment.
struct HostAuthz {
    authorization: Arc<permguard_host::authz::Authorization>,
    authenticator: Arc<dyn permguard_core::authz::Authenticator>,
    /// The Authority Plane's key set and status lists, as this Host holds them.
    trust: Arc<permguard_host::authz::AuthorityTrust>,
    bootstrap: Arc<permguard_host::authz::BootstrapStore>,
}

/// Builds one of the Host's rings (WP-3.1): laid out on the volume, a legacy ring migrated
/// first, opened, bound by the identity and recorded by the audit; its rotation reads the Host's
/// time guard (WP-2.12).
type RingFactory = Box<
    dyn Fn(
            &Config,
            &permguard_host::keys::registry::Opener<'_>,
        ) -> Result<Option<Arc<permguard_host::keys::ring::Ring>>>
        + Send
        + Sync,
>;

/// Builds the catalog of zones and ledgers a deployment keeps, from its effective configuration.
type CatalogFactory = Box<dyn Fn(&Config) -> Result<Option<Arc<dyn Catalog>>> + Send + Sync>;

/// Builds the audit destination the effective configuration names.
///
/// Returning nothing means "the one this app was composed with", so a build that offers a choice of
/// destinations and a build that has exactly one are the same code path.
///
/// The Host's rings are composed after the audit engine, which records their transitions
/// (WP-3.1): a destination is built before them and is handed none.
type AuditSinkFactory = Box<dyn Fn(&Config) -> Result<Option<Arc<dyn AuditSink>>> + Send + Sync>;

/// Builds one realm — its keys, its trail, its pseudonymisation — from its resolved configuration.
///
/// A single factory rather than one per collaborator, because a realm is those collaborators wired to
/// its own directories, and assembling them is exactly the concrete-construction work that belongs in
/// the composition root and nowhere else. The app calls it once per realm the file declares and puts
/// the results in a registry; it never names a key manager or a sink itself.
type RealmFactory = Box<dyn Fn(&Config, &RealmConfig) -> Result<Realm> + Send + Sync>;

/// What a Plane declares to the Host under a configuration, when the configuration selects it.
type PlaneDeclarationFactory = Box<
    dyn Fn(&Config) -> Option<(&'static str, bool, permguard_host::composition::Declaration)>
        + Send
        + Sync,
>;

/// Parses one registered section out of a configuration file and keeps it on the config.
///
/// The closure is what carries the section's type from where it was registered to where the file is
/// read, so nothing between the two has to name it.
type SectionParser = Box<dyn Fn(Config, &Value) -> Result<Config> + Send + Sync>;

/// Produces the future that resolves when the server is asked to stop.
///
/// It is a factory rather than a future because a future is consumed by awaiting it, and an app may
/// serve more than once in a process — a test certainly does.
type ShutdownFactory = Box<dyn Fn() -> BoxFuture<'static, ()> + Send + Sync>;

/// Prepares whatever the effective configuration needs and does not have.
///
/// Runs before validation, so validation sees the finished picture and reports what is still missing
/// in the same words whether it was generated or supplied.
type Provisioner = Box<dyn Fn(&Config) -> Result<()> + Send + Sync>;

/// A composed Host: one identity, one set of collaborators, and the adapters that reach outside it.
pub struct Composition {
    identity: ProductIdentity,
    build_settings: BuildSettings,
    server: Box<dyn ServerHost>,
    storage: Box<dyn Storage>,
    /// Shared rather than owned outright, so work that outlives a call can still record — see
    /// [`AuditRecorder`].
    audit: Arc<dyn AuditSink>,
    secrets: Option<Box<dyn SecretStore>>,
    /// Where the numbers this process records about itself go. A handle that discards until a
    /// build installs something, so nothing has to check whether it is there.
    metrics: Metrics,
    services: Vec<Box<dyn Service>>,
    /// Checks a composed build makes on the assembled configuration.
    ///
    /// The layered pipeline validates a setting against the contract; these validate it against
    /// *this* build — a configuration that names a surface nothing here serves, say. Whoever
    /// composes the binary knows what it serves; the contract does not.
    startup_checks: Vec<StartupCheck>,
    shutdown_factory: Option<ShutdownFactory>,
    secrets_factory: Option<SecretStoreFactory>,
    keys_factory: Option<RingFactory>,
    catalog_factory: Option<CatalogFactory>,
    control_signing_keys_factory: Option<RingFactory>,
    data_signing_keys_factory: Option<RingFactory>,
    audit_factory: Option<AuditSinkFactory>,
    realm_factory: Option<RealmFactory>,
    checkpoint_witness: Option<Arc<dyn permguard_host::audit::checkpoint::CheckpointWitness>>,
    /// Every subsystem laid out by the storage library this build reads, and at which versions
    /// (WP-1.9): what a volume's manifests are checked against before the server serves.
    layouts: Vec<(&'static str, permguard_host::storage::migrate::Reads)>,
    plane_declarations: Vec<PlaneDeclarationFactory>,
    reload_handler: Option<ReloadHandler>,
    provisioner: Option<Provisioner>,
    declared_settings: Vec<String>,
    claimed_sections: Vec<String>,
    section_readers: Vec<(String, SectionReader)>,
    section_parsers: Vec<(&'static str, SectionParser)>,
    /// The process's own stop signals, when whoever owns the process listens for them.
    process_shutdown: Option<ShutdownFactory>,
    hangup_listener: Option<HangupListener>,
    peer_connector: Option<PeerConnectorFactory>,
    authority_refresh: Option<AuthorityRefresh>,
    listeners: Option<ListenerReports>,
}

impl Composition {
    /// Composes an application from the identity it presents and the collaborators it always needs.
    ///
    /// Everything a build may or may not have — secrets, services, extra settings — is added on top,
    /// so a collaborator introduced later never changes this signature.
    pub fn new(
        identity: ProductIdentity,
        build_settings: BuildSettings,
        server: Box<dyn ServerHost>,
        storage: Box<dyn Storage>,
        audit: Box<dyn AuditSink>,
    ) -> Self {
        Self {
            identity,
            build_settings,
            server,
            storage,
            audit: Arc::from(audit),
            secrets: None,
            metrics: Metrics::none(),
            services: Vec::new(),
            startup_checks: Vec::new(),
            shutdown_factory: None,
            secrets_factory: None,
            keys_factory: None,
            catalog_factory: None,
            control_signing_keys_factory: None,
            data_signing_keys_factory: None,
            audit_factory: None,
            realm_factory: None,
            checkpoint_witness: None,
            layouts: Vec::new(),
            plane_declarations: Vec::new(),
            reload_handler: None,
            provisioner: None,
            declared_settings: Vec::new(),
            claimed_sections: Vec::new(),
            section_readers: Vec::new(),
            section_parsers: Vec::new(),
            process_shutdown: None,
            hangup_listener: None,
            peer_connector: None,
            authority_refresh: None,
            listeners: None,
        }
    }

    /// Adds the secret store this build resolves secret material from.
    pub fn with_secrets(mut self, secrets: Box<dyn SecretStore>) -> Self {
        self.secrets = Some(secrets);

        self
    }

    /// Installs somewhere for the numbers this process records about itself to go.
    ///
    /// Without one, every measurement in every crate is a branch and a return, and `/metrics`
    /// publishes liveness and readiness alone. Which registry it is, is a decision for the
    /// composition root, exactly like the audit sink and the key ring.
    pub fn with_metrics(mut self, metrics: Metrics) -> Self {
        // The schema version is the first series: a dashboard reads which label vocabulary it is
        // looking at before it reads anything else.
        metrics.publish_schema();
        self.metrics = metrics;

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
        self.provisioner = Some(Box::new(provisioner));

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
        self.secrets_factory = Some(Box::new(factory));

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
        self.keys_factory = Some(Box::new(factory));

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
        self.control_signing_keys_factory = Some(Box::new(factory));

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
        self.data_signing_keys_factory = Some(Box::new(factory));

        self
    }

    pub fn with_catalog_factory<F>(mut self, factory: F) -> Self
    where
        F: Fn(&Config) -> Result<Option<Arc<dyn Catalog>>> + Send + Sync + 'static,
    {
        self.catalog_factory = Some(Box::new(factory));

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
        self.audit_factory = Some(Box::new(factory));

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
        self.realm_factory = Some(Box::new(factory));

        self
    }

    /// Registers the external witness asked to co-sign every audit checkpoint (WP-3.7): none
    /// ships, and a build that registers none seals its checkpoints alone.
    pub fn with_checkpoint_witness(
        mut self,
        witness: Arc<dyn permguard_host::audit::checkpoint::CheckpointWitness>,
    ) -> Self {
        self.checkpoint_witness = Some(witness);

        self
    }

    /// Supplies what a Plane declares to the Host, registered before any service starts: its
    /// handles reach it through [`ServerContext::plane_handles`] and nothing else.
    /// Whether `config` selects the Plane `id` among the ones this build declares.
    /// Whether this Host is a member: it runs a Data Plane and no Control Plane, so it joins a
    /// coordinator rather than coordinating.
    fn is_member(&self, config: &Config) -> bool {
        self.runs_plane(config, "data") && !self.runs_plane(config, "control")
    }

    fn runs_plane(&self, config: &Config, id: &str) -> bool {
        self.plane_declarations
            .iter()
            .filter_map(|declare| declare(config))
            .any(|(plane, _, _)| plane == id)
    }

    pub fn with_plane_declaration<F>(mut self, declare: F) -> Self
    where
        F: Fn(&Config) -> Option<(&'static str, bool, permguard_host::composition::Declaration)>
            + Send
            + Sync
            + 'static,
    {
        self.plane_declarations.push(Box::new(declare));

        self
    }

    /// Names the subsystems this build lays out through the storage library, with the layout
    /// versions it reads for each (WP-1.9). A volume laying out anything else, or a version
    /// outside the set, is refused at start.
    pub fn with_layouts(
        mut self,
        layouts: Vec<(&'static str, permguard_host::storage::migrate::Reads)>,
    ) -> Self {
        self.layouts = layouts;
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
        self.reload_handler = Some(Arc::new(handler));

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
        self.shutdown_factory = Some(Box::new(factory));

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
        self.startup_checks.push(Box::new(check));
        self
    }

    pub fn with_service(mut self, service: Box<dyn Service>) -> Self {
        self.services.push(service);

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
        assert!(
            !self
                .section_parsers
                .iter()
                .any(|(name, _)| *name == T::NAME),
            "two types claim the configuration section `{}`",
            T::NAME
        );

        self.claimed_sections.push(T::NAME.to_owned());
        self.section_parsers.push((
            T::NAME,
            Box::new(|config: Config, value: &Value| Ok(config.with_section(T::parse(value)?))),
        ));

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
        self.declared_settings
            .extend(keys.into_iter().map(Into::into));

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
        self.claimed_sections
            .extend(names.into_iter().map(Into::into));

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
        let name = name.into();

        self.claimed_sections.push(name.clone());
        self.section_readers.push((name, Box::new(reader)));

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
        // A section may be claimed twice — once for its settings, once for the
        // list beside them — and the list of known sections an error prints is
        // read by a person: name it once.
        if !self.claimed_sections.iter().any(|claimed| claimed == name) {
            self.claimed_sections.push(name.to_owned());
        }
        self.section_parsers.push((name, Box::new(apply)));

        self
    }

    /// Supplies the process's own stop signals: what the start waits for when no shutdown signal
    /// was composed and the configuration asks for no recovery drain.
    pub fn with_process_shutdown<F>(mut self, listen: F) -> Self
    where
        F: Fn() -> BoxFuture<'static, ()> + Send + Sync + 'static,
    {
        self.process_shutdown = Some(Box::new(listen));

        self
    }

    /// Supplies how a request to reload is heard: called with the reload handler for exactly as
    /// long as the server runs, its task aborted when the run ends.
    pub fn with_hangup_listener<F>(mut self, listen: F) -> Self
    where
        F: Fn(ReloadHandler) -> tokio::task::JoinHandle<()> + Send + Sync + 'static,
    {
        self.hangup_listener = Some(Box::new(listen));

        self
    }

    /// Supplies how this Host, as a member, reaches its coordinators (WP-2.3).
    pub fn with_peer_connector<F>(mut self, connect: F) -> Self
    where
        F: Fn(
                &Config,
                &permguard_host::session::Context,
            )
                -> Result<Option<Arc<dyn permguard_host::membership::member::Connector>>>
            + Send
            + Sync
            + 'static,
    {
        self.peer_connector = Some(Box::new(connect));

        self
    }

    /// Supplies the fetch of the Authority Plane's key set and status lists, for a Host whose
    /// Authority Plane runs in another process.
    pub fn with_authority_refresh<F>(mut self, refresh: F) -> Self
    where
        F: Fn(
                Arc<permguard_host::authz::AuthorityTrust>,
                AuthoritySource,
                AuthorityObserving,
            ) -> Result<Box<dyn std::any::Any + Send>>
            + Send
            + Sync
            + 'static,
    {
        self.authority_refresh = Some(Box::new(refresh));

        self
    }

    /// Supplies the listeners of the process, as the Host API and discovery publish them.
    pub fn with_listeners<F>(mut self, report: F) -> Self
    where
        F: Fn(&Config) -> Vec<permguard_core::listener::ListenerReport> + Send + Sync + 'static,
    {
        self.listeners = Some(Box::new(report));

        self
    }

    /// Returns where the numbers this process records about itself go.
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Returns the identity this application presents as.
    pub fn identity(&self) -> &ProductIdentity {
        &self.identity
    }

    /// Returns the build metadata layer this application was composed with.
    pub fn build_settings(&self) -> &BuildSettings {
        &self.build_settings
    }

    /// Returns the server host this application runs.
    pub fn server(&self) -> &dyn ServerHost {
        self.server.as_ref()
    }

    /// Returns the store this application runs against.
    pub fn storage(&self) -> &dyn Storage {
        self.storage.as_ref()
    }

    /// Returns the audit sink this application records to.
    pub fn audit(&self) -> &dyn AuditSink {
        self.audit.as_ref()
    }

    /// Returns the secret store, when this build composed one.
    pub fn secrets(&self) -> Option<&dyn SecretStore> {
        self.secrets.as_deref()
    }

    /// Returns the services registered with this application, in registration order.
    pub fn services(&self) -> &[Box<dyn Service>] {
        &self.services
    }

    /// Assembles the context the server host and its services run against.
    ///
    /// Public because a command a downstream build adds needs the same context the `serve` command
    /// gets, without reassembling it by hand.
    pub fn context<'a>(
        &'a self,
        config: &'a Config,
        pseudonymizer: Option<&'a dyn Pseudonymizer>,
        keys: Option<Arc<dyn KeyManager>>,
    ) -> ServerContext<'a> {
        let mut context = ServerContext::new(
            self.identity,
            config,
            self.storage.as_ref(),
            self.audit.as_ref(),
        )
        .with_services(&self.services)
        .with_metrics(self.metrics.clone());

        if let Some(pseudonymizer) = pseudonymizer {
            context = context.with_pseudonymizer(pseudonymizer);
        }

        if let Some(keys) = keys {
            context = context.with_keys(keys);
        }

        context
    }

    /// Builds the way spawned work records audit events: the same sink, the same policy.
    pub fn recorder(
        &self,
        audit: &Arc<dyn AuditSink>,
        pseudonymizer: Option<&Arc<dyn Pseudonymizer>>,
    ) -> AuditRecorder {
        let recorder = AuditRecorder::new(Arc::clone(audit));

        match pseudonymizer {
            Some(policy) => recorder.with_policy(Arc::clone(policy)),
            None => recorder,
        }
    }

    /// Builds the audit destination the effective configuration names.
    pub fn audit_for(&self, config: &Config) -> Result<Arc<dyn AuditSink>> {
        let chosen = match &self.audit_factory {
            Some(factory) => factory(config)?,
            None => None,
        };

        Ok(chosen.unwrap_or_else(|| Arc::clone(&self.audit)))
    }

    /// Builds the catalog the effective configuration names, when this build composes one.
    pub fn catalog_for(&self, config: &Config) -> Result<Option<Arc<dyn Catalog>>> {
        match &self.catalog_factory {
            Some(factory) => factory(config),
            None => Ok(None),
        }
    }

    /// Builds the control plane's signing ring, `control.attest`, when this build composes one.
    pub fn control_signing_keys_for(
        &self,
        config: &Config,
        rings: &permguard_host::keys::registry::Opener<'_>,
    ) -> Result<Option<Arc<permguard_host::keys::ring::Ring>>> {
        match &self.control_signing_keys_factory {
            Some(factory) => factory(config, rings),
            None => Ok(None),
        }
    }

    /// Builds the data plane's signing ring, `data.attest`, when this build composes one.
    pub fn data_signing_keys_for(
        &self,
        config: &Config,
        rings: &permguard_host::keys::registry::Opener<'_>,
    ) -> Result<Option<Arc<permguard_host::keys::ring::Ring>>> {
        match &self.data_signing_keys_factory {
            Some(factory) => factory(config, rings),
            None => Ok(None),
        }
    }

    /// Builds the Host's operations ring, `host.operations`, when the configuration enables it.
    pub fn keys_for(
        &self,
        config: &Config,
        rings: &permguard_host::keys::registry::Opener<'_>,
    ) -> Result<Option<Arc<permguard_host::keys::ring::Ring>>> {
        if !config.keys_enabled() {
            return Ok(None);
        }

        let factory = self
            .keys_factory
            .as_ref()
            .context("signing keys are enabled but this build composes no key manager")?;

        factory(config, rings)
    }

    /// Builds the registry of realms this deployment hosts.
    ///
    /// Empty for a plain single-issuer server, which is the ordinary case and needs no factory. When
    /// realms *are* declared, a build without a realm factory is refused rather than started serving
    /// none — a declared realm nobody serves is a client's token nobody can verify, discovered far
    /// from here. Each realm is assembled once, in order, by the same factory; nothing is spawned.
    pub fn realms_for(&self, config: &Config) -> Result<Realms> {
        if config.realms().is_empty() {
            return Ok(Realms::default());
        }

        let factory = self.realm_factory.as_ref().context(
            "the configuration declares realms but this build composes no realm factory",
        )?;

        let mut realms = Vec::with_capacity(config.realms().len());
        for realm in config.realms() {
            realms.push(
                factory(config, realm)
                    .with_context(|| format!("assembling the realm `{}`", realm.name()))?,
            );
        }

        Ok(Realms::new(realms))
    }

    /// The Host identity of `volume`: opened when provisioned; provisioned here only under the
    /// `development` profile, refused otherwise until `permguard host identity provision` ran
    /// (owner decision of 2026-10-08); matched to `host.identity.witness`, which the
    /// `production` profile and above require. Answers whether this start provisioned it.
    fn host_identity_for(
        &self,
        config: &Config,
        volume: &permguard_host::storage::volume::Volume,
        time: &Arc<permguard_host::time::TimeGuard>,
        custodian: &Arc<permguard_host::keys::custody::Custodian>,
    ) -> Result<(
        Arc<permguard_host::identity::Identity>,
        bool,
        Config,
        permguard_host::keys::custody::Prepared,
    )> {
        use permguard_core::assurance::Relaxation;
        use permguard_core::config::KeyCustody;
        use permguard_host::identity::{self, Identity, IdentityError};
        use permguard_host::keys::ring::HOST_IDENTITY;

        let (_, keys) = identity::directories(volume).with_context(|| {
            format!(
                "opening the identity directory on {}",
                volume.host().path().display()
            )
        })?;
        // A reset a crash interrupted is completed offline before the Host starts: its INIT may
        // already be gone, and provisioning over it would leave the old keys and rings behind.
        if identity::reset::marked(volume)
            .map_err(|error| anyhow::anyhow!("{error}"))?
            .is_some()
        {
            bail!(
                "an identity reset began on this volume and did not complete: run `permguard host \
                 identity reset run --volume {}` to complete it",
                volume.root().display()
            );
        }
        let witness = identity_witness_checked(config, volume)?;
        // Before anything is written to the identity: its custody, a relaxation of the Host the
        // profile may forbid (owner decision of 2026-10-08, until the custody providers of
        // WP-3.2), and its witness, which a replaced or rolled-back volume fails.
        let config = match custodian.custody_of(HOST_IDENTITY) {
            KeyCustody::Development => config
                .clone()
                .with_host_relaxation(Relaxation::CustodyPlaintext),
            KeyCustody::File | KeyCustody::Pkcs11 | KeyCustody::Kms => config.clone(),
        };
        config
            .assurance()
            .check(&config.relaxations_in_force())
            .map_err(|refused| {
                anyhow::anyhow!(
                    "{refused}; keys held in plaintext are the `development` custody: set \
                     `operations.keys.custody` to `file`, `pkcs11` or `kms`"
                )
            })?;
        // The identity's keys through its custody's provider (WP-3.2): a `file` custody seals a
        // key it finds in plaintext, and rewraps one the previous KEK wrapped, before it opens.
        let stored = identity::stored_public(
            permguard_host::storage::Dir::open(keys.path())
                .context("opening the identity's keys")?,
        );
        let mut prepared = permguard_host::keys::custody::Prepared::default();
        let (opened, provisioned) = if witness.is_some() {
            let host_id = identity::host_id_of(volume)
                .map_err(|error| anyhow::anyhow!("{error}"))?
                .context("the identity's INIT names no Host")?;
            let suite = identity::suite_of(volume)
                .map_err(|error| anyhow::anyhow!("{error}"))?
                .unwrap_or(identity::Suite::Ed25519Sha256V1);
            let (provider, done) = custodian
                .provider(HOST_IDENTITY, host_id, keys, stored, suite)
                .map_err(|error| anyhow::anyhow!("{error}"))
                .context("preparing the custody of the Host identity's keys")?;
            prepared = done;
            (Identity::open(volume, provider), false)
        } else {
            let suite = config
                .host_identity_suite()
                .and_then(identity::Suite::from_name)
                .unwrap_or(identity::Suite::Ed25519Sha256V1);
            let now = time.now_secs();
            (
                Identity::provision_with(
                    volume,
                    |host_id| {
                        custodian
                            .provider(HOST_IDENTITY, *host_id, keys, stored, suite)
                            .map(|(provider, _)| provider)
                            .map_err(IdentityError::from)
                    },
                    suite,
                    now,
                    now.saturating_mul(1000),
                ),
                true,
            )
        };
        let opened = opened
            .map_err(|error| anyhow::anyhow!("{error}"))
            .with_context(|| {
                format!(
                    "opening the Host identity on {}",
                    volume.host().path().display()
                )
            })?;
        if provisioned
            && let Some(expected) = config.host_identity_witness()
            && expected != opened.witness()
        {
            bail!("`host.identity.witness` names another identity than the one just provisioned");
        }
        // What a reset provisions the next identity with (WP-4.1): the same custody, its keys
        // bound to the `host_id` the reset mints.
        let provisioner =
            permguard_offline::volume::provisioner(custodian, volume, opened.suite())?;
        Ok((
            Arc::new(opened.with_provisioner(provisioner)),
            provisioned,
            config,
            prepared,
        ))
    }

    /// The Host-local `audit.pseudonym` root (WP-3.3), when pseudonymisation is on: resolved
    /// from the secret store, at least 256 bits, witnessed per reference and version on the
    /// volume, and bound to this Host. A version that now yields other material refuses the start.
    pub fn pseudonym_root_for(
        &self,
        config: &Config,
        secrets: Option<&dyn SecretStore>,
        volume: &permguard_host::storage::volume::Volume,
        host_id: [u8; 16],
    ) -> Result<Option<permguard_host::secrets::HostLocal>> {
        if !config.audit_pseudonym_enabled() {
            return Ok(None);
        }
        let reference = config
            .audit_pseudonym_key_ref()
            .context("audit pseudonymisation is enabled but names no secret")?;
        let secrets = secrets
            .context("audit pseudonymisation is enabled but this build resolved no secret store")?;
        let root = resolve_root(
            secrets,
            volume,
            reference,
            config.audit_pseudonym_key_version(),
            "the audit pseudonymisation key",
            "audit-pseudonym",
        )?;
        Ok(Some(permguard_host::secrets::HostLocal::new(root, host_id)))
    }

    /// Builds the privacy policy the effective configuration asks for: pseudonyms of principals
    /// in the records a sink renders, under the Host-local key of the resource `host`.
    ///
    /// Returns nothing when pseudonymisation is off, which is the default: principals then reach a
    /// sink masked.
    pub fn pseudonymizer_for(
        &self,
        config: &Config,
        secrets: Option<&dyn SecretStore>,
        volume: &permguard_host::storage::volume::Volume,
        host_id: [u8; 16],
    ) -> Result<Option<Box<dyn Pseudonymizer>>> {
        let Some(local) = self.pseudonym_root_for(config, secrets, volume, host_id)? else {
            return Ok(None);
        };
        Ok(Some(Box::new(
            local
                .pseudonymizer(permguard_host::audit::HOST)
                .map_err(|error| anyhow::anyhow!("{error}"))?,
        )))
    }

    /// The stream engine of this Host on `volume`, the decision log and the event journal
    /// registered on it as producers (WP-5.1, owner decision), sealing their batches under
    /// `data_attest` when the Host holds it (WP-5.2), each batch kept `acknowledged_retention`
    /// after its coordinators acknowledged it (WP-7.9b).
    #[allow(clippy::too_many_arguments)]
    fn stream_engine(
        &self,
        volume: &permguard_host::storage::volume::Volume,
        identity: &permguard_host::identity::Identity,
        operations: &Arc<permguard_host::keys::ring::Ring>,
        data_attest: Option<&Arc<permguard_host::keys::ring::Ring>>,
        time: &Arc<permguard_host::time::TimeGuard>,
        members: &Arc<std::sync::OnceLock<Arc<permguard_host::membership::Store>>>,
        acknowledged_retention: std::time::Duration,
        ceiling: Option<permguard_core::decisions::IncludeSection>,
    ) -> Result<StreamParts, permguard_stream::engine::StreamError> {
        let engine = permguard_stream::engine::Streams::open(
            volume,
            identity,
            Arc::clone(operations),
            Arc::clone(time),
        )?;
        let mut decisions = engine.register_producer(
            permguard_decisions::stream::descriptor(),
            permguard_decisions::stream::Codec,
        )?;
        // The event log is a `history` stream: kept whole until the Data Plane registers the
        // floor its loaded contracts read from (WP-6.2a).
        let mut events = engine
            .register_producer(
                permguard_events::stream::descriptor(),
                permguard_events::stream::Codec,
            )?
            .with_retention_floor(Arc::new(permguard_stream::engine::retention::KeepWhole));
        if let Some(ring) = data_attest {
            decisions = decisions.with_signer(Arc::clone(ring))?;
            events = events.with_signer(Arc::clone(ring))?;
        }
        // Each batch kept after its coordinators acknowledged it, so one restored from a
        // snapshot is resent what it lost (WP-7.9b).
        decisions = decisions.with_acknowledged_retention(acknowledged_retention);
        events = events.with_acknowledged_retention(acknowledged_retention);
        // Their consumers, what this Host ingests as a coordinator over `decisions.ship` and
        // `events.ship` (WP-5.3), kept as long as the task shipping them says (WP-5.6b).
        let retention = |task| {
            Arc::new(crate::stream_gc::ShipRetention {
                members: Arc::clone(members),
                task,
            })
        };
        let decision_consumer = engine
            .register_consumer(
                permguard_decisions::stream::descriptor(),
                permguard_decisions::stream::Codec,
            )?
            .with_retention_source(retention(
                permguard_host::membership::record::TaskType::DecisionsShip,
            ));
        // What the decision store accepts in clear, held over what a coordinator ingests exactly
        // as over the Control Plane's own ingest (`controlPlane.decisions.accept`).
        let decision_consumer = match ceiling {
            Some(ceiling) => decision_consumer.with_admission(Arc::new(move |bytes: &[u8]| {
                let record: serde_json::Value =
                    serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
                match permguard_decisions::ceiling::beyond(&record, &ceiling) {
                    Some(member) => Err(permguard_decisions::ceiling::refusal(&member)),
                    None => Ok(()),
                }
            })),
            None => decision_consumer,
        };
        // The events' also keeps the origins this Host imports as long as its Data Plane's
        // windows read them (WP-6.2c2b1).
        let event_retention = Arc::new(crate::stream_gc::EventRetention {
            ship: crate::stream_gc::ShipRetention {
                members: Arc::clone(members),
                task: permguard_host::membership::record::TaskType::EventsShip,
            },
            consumer: std::sync::OnceLock::new(),
        });
        let event_consumer = engine
            .register_consumer(
                permguard_events::stream::descriptor(),
                permguard_events::stream::Codec,
            )?
            .with_retention_source(Arc::clone(&event_retention)
                as Arc<dyn permguard_stream::engine::retention::RetentionSource>);
        let decision_consumer = Arc::new(decision_consumer);
        let event_consumer = Arc::new(event_consumer);
        let _ = event_retention
            .consumer
            .set(Arc::downgrade(&event_consumer));
        Ok((
            permguard_stream::engine::Served::default()
                .with(permguard_decisions::stream::STREAM, Arc::new(decisions))
                .with(permguard_events::stream::STREAM, Arc::new(events))
                // What the Control Plane's public decision reads answer from (WP-6.1b).
                .with_consumer(
                    permguard_decisions::stream::STREAM,
                    Arc::clone(&decision_consumer),
                )
                // And its public event reads (WP-6.2b).
                .with_consumer(
                    permguard_events::stream::STREAM,
                    Arc::clone(&event_consumer),
                ),
            decision_consumer,
            event_consumer,
        ))
    }

    /// The coordinator root (WP-3.3), when `operations.secrets.coordinator_root_ref` names one:
    /// resolved, at least 256 bits, witnessed, at `operations.secrets.zone_key_version`, with this
    /// Host as the authority of the zones it coordinates.
    pub fn coordinator_for(
        &self,
        config: &Config,
        secrets: Option<&dyn SecretStore>,
        volume: &permguard_host::storage::volume::Volume,
        host_id: [u8; 16],
    ) -> Result<Option<permguard_host::secrets::Coordinator>> {
        let Some(reference) = config.secrets_coordinator_root_ref() else {
            return Ok(None);
        };
        let secrets = secrets.context(
            "`operations.secrets.coordinator_root_ref` is set and this build resolved no secret \
             store",
        )?;
        let root = resolve_root(
            secrets,
            volume,
            reference,
            config.secrets_zone_key_version(),
            "the coordinator root",
            "coordinator",
        )?;
        Ok(Some(permguard_host::secrets::Coordinator::new(
            root, host_id,
        )))
    }

    /// Builds the secret store the effective configuration names.
    pub fn secrets_for(&self, config: &Config) -> Result<Option<Box<dyn SecretStore>>> {
        match &self.secrets_factory {
            Some(factory) => factory(config),
            None => Ok(None),
        }
    }

    /// Builds the effective config for one action, from every precedence layer.
    ///
    /// Every action shares the same layered config, so a command added later needs no loading logic
    /// of its own: it declares which layers it contributes and reads the result.
    ///
    /// `config_file` is the file the action reads, when it reads one, and `command_line` what its
    /// arguments set: whoever parses the command line names both.
    pub fn config_from<I>(&self, config_file: Option<&Path>, command_line: I) -> Result<Config>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let file = match config_file {
            Some(path) => Some((path, self.load(path)?)),
            None => None,
        };

        let file_inputs = match &file {
            Some((path, parsed)) => self.file_inputs(path, parsed)?,
            None => Vec::new(),
        };

        let environment: Vec<(String, String)> = env::vars().collect();
        let command_line: Vec<(String, String)> = command_line.into_iter().collect();
        let mut config = Config::from_layers(
            self.build_settings,
            self.declared_settings.clone(),
            Layers::new()
                .with_file(file_inputs.clone())
                .with_environment(environment.clone())
                .with_command_line(command_line.clone()),
        )
        .map_err(|error| {
            // A value refused from the file is reported by the file and the key the operator
            // wrote, never only by an environment variable they did not set (BUG-0121).
            let Some((path, _)) = &file else {
                return error;
            };
            let said = format!("{error:#}");
            // The longest name the message carries: `PERMGUARD_LOG` is inside `PERMGUARD_LOG_LEVEL`.
            let from_file = file_inputs
                .iter()
                .filter(|(key, _)| {
                    said.contains(key.as_str())
                        && !environment.iter().any(|(set, _)| set == key)
                        && !command_line.iter().any(|(set, _)| set == key)
                })
                .max_by_key(|(key, _)| key.len());
            let Some((key, value)) = from_file else {
                return error;
            };
            let yaml = std::fs::read_to_string(path)
                .ok()
                .and_then(|text| permguard_core::config_file::yaml_key_of(&text, key, value));
            let named = match yaml {
                Some(yaml) => format!(
                    "`{yaml}` in the configuration file {} ({key})",
                    path.display()
                ),
                None => format!("{key}, set in the configuration file {}", path.display()),
            };
            anyhow::anyhow!("{}", said.replacen(key.as_str(), &named, 1))
        })?;

        // Realms are structured, not flat settings, so they are attached here rather than merged
        // through the layered pipeline above. They come only from the file today; a database is the
        // same seam tomorrow. Resolution against the server's values happens inside `with_realms`.
        // Anything else structured — the tasks a mirroring plane narrows — arrives through
        // `with_structured_section`, claimed by whoever owns the section.
        if let Some((path, parsed)) = &file {
            config = config
                .with_realms(parsed.realms())
                .with_context(|| format!("in the configuration file {}", path.display()))?;
            // The public grants are relaxations like any other (BUG-0202, BUG-0318): checked
            // against the profile before anything binds, naming the entry the profile refuses,
            // and published in the assurance block when they stand.
            let auth = parsed
                .host_auth()
                .with_context(|| format!("in the configuration file {}", path.display()))?;
            auth.check(&config.assurance()).map_err(|refused| {
                anyhow::anyhow!("in the configuration file {}: {refused}", path.display())
            })?;
            for relaxation in auth.relaxations() {
                config = config.with_host_relaxation(relaxation);
            }
        }

        let config = match &file {
            Some((path, parsed)) => self.apply_sections(config, path, parsed)?,
            None => config,
        };

        // A `PERMGUARD_*` variable no setting reads is a typo or a retired name: refused by name
        // rather than ignored (WP-2.9). After the realms, whose secret prefixes it exempts.
        let names: Vec<String> = env::vars().map(|(name, _)| name).collect();
        config.check_environment(names.iter().map(String::as_str))?;

        for check in &self.startup_checks {
            check(&config)?;
        }

        Ok(config)
    }

    /// The Host's authorization (`2-security/8` Authorization): the access tokens of the
    /// Authority Plane, verified with the key set and lists this Host holds; the recovery
    /// principal's certificate; and `host.authz.public[]`, what anybody may do without a token.
    fn authorization_for(
        &self,
        config: &Config,
        config_file: &Path,
        file: &ConfigFile,
        volume: &permguard_host::storage::volume::Volume,
        time: &Arc<permguard_host::time::TimeGuard>,
        mutations: &Arc<permguard_host::operations::mutation::Mutations>,
    ) -> Result<HostAuthz> {
        use permguard_host::authz::access_tokens::TokenAuthenticator;
        use permguard_host::authz::{
            AuthorityTrust, Authorization, BootstrapStore, PrincipalMapper, PublicGrant,
        };

        let auth = file
            .host_auth()
            .with_context(|| format!("in the configuration file {}", config_file.display()))?;
        // A coordinator is never a member of another: only a member joins from an invitation
        // (TD-5).
        if config.host_join().is_some() && !self.is_member(config) {
            bail!(
                "host.join is a member's: this Host runs a Control Plane, or no Data Plane, and \
                 never joins another coordinator; remove host.join"
            );
        }
        let bootstrap = BootstrapStore::open(volume).with_context(|| {
            format!(
                "opening the recovery principal's commitment on {}",
                volume.host().path().display()
            )
        })?;
        // A commitment a crash left open is committed or failed before anything reads it.
        mutations
            .recover(&permguard_host::operations::grants::Grants(&bootstrap))
            .context("recovering the bootstrap commitment a crash left open")?;
        // A development volume this server provisions: the operator certificate `autogenerate`
        // wrote, `tls/client.pem`, is the bootstrap principal when the volume commits none, so the
        // client it hands out acts (BUG-0066). Never above `development`: there the bootstrap is
        // committed offline, by an operator, with `permguard host grants bootstrap`.
        let operator = config.working_dir().join("tls").join("client.pem");
        if config.autogenerate()
            && config.assurance().profile()
                == permguard_core::assurance::AssuranceProfile::Development
            && bootstrap.bootstrap().is_none()
            && operator.is_file()
        {
            let pem = std::fs::read(&operator)
                .with_context(|| format!("reading {}", operator.display()))?;
            if let Some(held) = permguard_host::operations::grants::bootstrap_development_operator(
                mutations,
                &bootstrap,
                &pem,
                time.now_secs(),
            )
            .map_err(|error| anyhow::anyhow!("{error}"))
            .with_context(|| {
                format!(
                    "committing {} as the development volume's bootstrap principal",
                    operator.display()
                )
            })? {
                tracing::warn!(
                    event.name = "authz.bootstrap_development",
                    component = "server",
                    fingerprint = %held.fingerprint,
                    "the operator certificate autogenerate wrote is the bootstrap principal of this \
                     development volume"
                );
            }
        }
        let held = bootstrap.bootstrap();
        let mapper = PrincipalMapper::new(held.as_ref().map(|held| held.fingerprint.as_str()))
            .context("reading the bootstrap commitment")?;
        let public: Vec<PublicGrant> = auth
            .public
            .iter()
            .map(|grant| PublicGrant {
                operations: grant.operations.clone(),
                selector: grant.selector.clone(),
                resource_types: grant.resource_types.clone(),
            })
            .collect();
        if !public.is_empty() {
            // A warning, not a note: what the grants name is answered to anybody, and the
            // assurance block publishes it as `authz.public` (BUG-0318).
            tracing::warn!(
                // The event is named after the relaxation it reports.
                event.name = permguard_core::domains::assurance::RELAX_AUTHZ_PUBLIC,
                component = "server",
                grants = public.len(),
                assurance = config.assurance().profile().as_str(),
                development_mode = config.development_mode(),
                "the configuration declares public grants: what they name needs no credential"
            );
        }
        // The Authority Plane this Host verifies tokens for: its URL, and the audience every
        // token names. Without a URL, the Authority Plane of this process announces itself; with
        // none in it either, every token is refused.
        let issuer = config
            .setting(permguard_core::planes::settings::SETTING_AUTHORITY_URL)
            .map(str::trim)
            .filter(|url| !url.is_empty());
        let development = config.assurance().profile()
            == permguard_core::assurance::AssuranceProfile::Development;
        if let Some(url) = issuer {
            permguard_core::authz::check_service_url(url, development)
                .map_err(|error| anyhow::anyhow!("authority.url: {error}"))?;
        }
        // Where the keys and lists are fetched, when not at the issuer: either transport.
        if let Some(endpoint) = config
            .setting(permguard_core::planes::settings::SETTING_AUTHORITY_ENDPOINT)
            .map(str::trim)
            .filter(|endpoint| !endpoint.is_empty())
        {
            permguard_core::authz::check_authority_endpoint(endpoint, development)
                .map_err(|error| anyhow::anyhow!("authority.endpoint: {error}"))?;
        }
        let audience = config
            .setting(permguard_core::planes::settings::SETTING_AUTHORITY_AUDIENCE)
            .map(str::trim)
            .filter(|audience| !audience.is_empty())
            .unwrap_or(permguard_host::authz::authority::DEFAULT_AUDIENCE);
        let trust = Arc::new(
            AuthorityTrust::kept_in(volume, issuer, audience, time.now_secs()).with_context(
                || {
                    format!(
                        "opening the Authority Plane's keys and lists on {}",
                        volume.host().path().display()
                    )
                },
            )?,
        );
        tracing::info!(
            event.name = "authz.opened",
            component = "server",
            issuer = issuer.unwrap_or("this process"),
            audience,
            keys = trust.keys().len(),
            bootstrap = held.is_some(),
            "the Host verifies the Authority Plane's tokens"
        );
        let authorization = Arc::new(
            Authorization::public_only(&public).with_bootstrap(held.map(|held| held.principal)),
        );
        let authenticator: Arc<dyn permguard_core::authz::Authenticator> =
            Arc::new(TokenAuthenticator {
                trust: Arc::clone(&trust) as Arc<dyn permguard_host::authz::access_tokens::Trust>,
                inner: Arc::new(mapper),
                time: Arc::clone(time),
            });
        Ok(HostAuthz {
            authorization,
            authenticator,
            trust,
            bootstrap,
        })
    }

    /// Reads and parses the configuration file, rejecting sections nothing in this build accounts for.
    pub fn load(&self, config_file: &Path) -> Result<ConfigFile> {
        let file = ConfigFile::load(config_file)?;

        file.reject_unknown_sections(self.claimed_sections.iter().map(String::as_str))
            .with_context(|| format!("parsing the configuration file {}", config_file.display()))?;

        Ok(file)
    }

    /// Parses every registered section the file declares and keeps it on the config.
    fn apply_sections(
        &self,
        mut config: Config,
        config_file: &Path,
        file: &ConfigFile,
    ) -> Result<Config> {
        for (name, parse) in &self.section_parsers {
            let Some(value) = file.section(name) else {
                continue;
            };

            config = parse(config, value)
                .with_context(|| format!("in the configuration file {}", config_file.display()))?;
        }

        Ok(config)
    }

    /// The configuration-file layer, typed settings plus whatever the registered readers contribute.
    fn file_inputs(&self, config_file: &Path, file: &ConfigFile) -> Result<Vec<(String, String)>> {
        let mut settings = file.settings();

        for (name, reader) in &self.section_readers {
            let Some(section) = file.section(name) else {
                continue;
            };

            settings.extend(reader(section).with_context(|| {
                format!(
                    "reading the `{name}` section of the configuration file {}",
                    config_file.display()
                )
            })?);
        }

        Ok(settings)
    }

    /// Validates that the effective config can start a server, announces the build, then runs the
    /// composed server host.
    ///
    /// The banner is rendered only for the `terminal` format. In `json` the output stream belongs to a
    /// log pipeline, and six lines of ASCII art in the middle of it are something a parser has to be
    /// told to ignore. What the banner says that matters — which build this is — is said by the build
    /// record instead, which every format gets.
    pub async fn serve(
        &self,
        config: &Config,
        config_file: &Path,
        out: &mut dyn Write,
    ) -> Result<()> {
        // First, before anything that takes time. Preparing a volume generates keys and writes them
        // down, and a stop signal that arrives while that is happening is a stop signal the process
        // has to survive — the alternative is dying where it stands, halfway through writing the
        // material it will be asked for on the next start. What this resolves to is awaited far
        // below; that it is listening starts here.
        let shutdown = match (&self.shutdown_factory, &self.process_shutdown) {
            (Some(factory), _) => factory(),
            // A recovery drain (TD-2) stops as soon as it has started: Load has resumed what an
            // earlier drain left, and the drain that follows ships the rest or says it did not.
            (None, _) if config.shutdown_recover_drain() => {
                Box::pin(async {}) as permguard_core::BoxFuture<'static, ()>
            }
            // The process's own stop signals, which whoever owns the process listens for: this
            // package installs no signal handler.
            (None, Some(listen)) => listen(),
            (None, None) => bail!(
                "this composition was given no way to be stopped: compose a shutdown signal, or \
                 the process's own"
            ),
        };

        // The process and the volume are private before the claim writes or reads anything on it
        // (TS-5): core dumps disabled, no root, every entry the process's own and owner-only, no
        // link. A volume not yet created has nothing to judge, and is created owner-only. From
        // `production` a shortfall stops Bootstrap; below, each is logged with its code.
        let hardened =
            permguard_host::hardening::harden(config.working_dir(), config.assurance().profile())
                .with_context(|| {
                format!(
                    "verifying the process and the volume at {} are private",
                    config.working_dir().display()
                )
            })?;
        for shortfall in &hardened.reported {
            tracing::warn!(
                event.name = "host.hardening_reported",
                code = shortfall.code,
                detail = %shortfall.detail,
                "accepted under `development`, refused from `production`"
            );
        }
        tracing::info!(
            event.name = "host.hardened",
            directories = hardened.directories,
            files = hardened.files,
            reported = hardened.reported.len(),
            "the process and the volume were verified private"
        );

        // The volume is claimed before anything writes to it — the provisioner, the stores — and
        // held until this returns: a second process on the same mount fails here instead of writing
        // beside this one. The configuration states no assurance profile yet (WP-07), so a volume
        // without a claim is served as under `development`.
        let volume = permguard_host::storage::volume::Volume::claim(
            config.working_dir(),
            config.assurance().profile(),
        )
        .with_context(|| format!("claiming the volume at {}", config.working_dir().display()))?;
        tracing::info!(
            event.name = "volume.claimed",
            volume_id = %volume.id_hex(),
            generation = volume.generation(),
            "this process holds the volume"
        );
        // A volume restored for forensics is never served; another restore is logged (WP-7.9).
        if let Some(reason) = permguard_host::restore::serving_refused(&volume)
            .with_context(|| format!("reading the restore of {}", config.working_dir().display()))?
        {
            bail!("{reason}");
        }
        if let Some(restored) = permguard_host::restore::marked(&volume)
            .with_context(|| format!("reading the restore of {}", config.working_dir().display()))?
        {
            tracing::info!(
                event.name = "volume.restored",
                mode = restored.mode.as_str(),
                generation = restored.generation,
                "this volume was restored: every remote task opens its session for a fresh lease"
            );
        }

        // The Host's one time service (WP-2.12), opened against the high-water mark the volume
        // keeps: a clock set back across a restart is in anomaly from here on.
        let time = Arc::new(
            permguard_host::time::TimeGuard::open(
                &volume,
                Arc::new(permguard_host::time::SystemClock),
                Arc::new(permguard_host::time::SystemMonotonic::new()),
                config.time_max_clock_skew(),
            )
            .with_context(|| {
                format!(
                    "opening the clock's high-water mark on {}",
                    volume.host().path().display()
                )
            })?,
        );

        // The filesystem prerequisites probed and the volume's tuple qualified (WP-1.3, TS-5): a
        // failed probe is refused under every profile, an unqualified, incomplete or stale record
        // from `production`. Discovery publishes the qualification and its evidence id only.
        let storage = self
            .load(config_file)?
            .volume()
            .with_context(|| format!("in the configuration file {}", config_file.display()))?;
        let standing = qualify_volume(&volume, &storage, config.assurance().profile(), time.now())
            .with_context(|| {
                format!(
                    "qualifying the volume at {} for the `{}` profile",
                    config.working_dir().display(),
                    config.assurance().profile()
                )
            })?;
        let config = &config
            .clone()
            .with_storage_report(permguard_core::volume::StorageReport {
                qualification: standing.as_str().to_owned(),
                evidence: standing.evidence().map(str::to_owned),
            });

        // The Host's quota and emergency floor (BUG-0062): the volume measured now when the Host has
        // a quota, and judged by a pass once the Host serves.
        let host_quota =
            crate::storage_quota::for_volume(&volume, &storage).with_context(|| {
                format!(
                    "opening the storage quota of the volume at {}",
                    config.working_dir().display()
                )
            })?;

        // No subsystem is served while a migration is between two sides, and no layout this build
        // does not read is served at all (WP-1.9): an interrupted migration is landed by its
        // command, a downgrade is possible only where every active layout is understood.
        // The rings' own layouts are always read here: this build lays them out (WP-3.1).
        let mut layouts = self.layouts.clone();
        layouts.extend(permguard_host::keys::migration::layouts());
        layouts.extend(permguard_host::audit::jsonl::layouts());
        layouts.extend(permguard_decisions::archive::layouts());
        layouts.extend(permguard_events::archive::layouts());
        permguard_host::storage::migrate::check_servable(&volume, &layouts).with_context(|| {
            format!("checking the layouts on {}", config.working_dir().display())
        })?;

        if let Some(provisioner) = &self.provisioner {
            provisioner(config).with_context(|| {
                format!("preparing the volume at {}", config.working_dir().display())
            })?;
        }

        config.validate().with_context(|| {
            format!(
                "validating the configuration loaded from {}",
                config_file.display()
            )
        })?;

        // The store is built first: everything that needs a secret needs it to exist, the
        // key-encryption key of the `file` custody included (WP-3.2).
        let resolved = self.secrets_for(config)?;
        let secrets = resolved.as_deref().or(self.secrets.as_deref());
        // The backups' recovery key (TS-5): resolved, its id its fingerprint, which every snapshot
        // manifest binds from here on; from `production` the whole backup policy is declared.
        let recovery_key_id = permguard_offline::volume::recovery_key_id_from(config, secrets)
            .context("resolving the backups' recovery key")?;
        let shortfalls =
            permguard_offline::volume::backup_policy_shortfalls(config, recovery_key_id.as_deref());
        if !shortfalls.is_empty() {
            if config
                .assurance()
                .profile()
                .at_least(permguard_core::assurance::AssuranceProfile::Production)
            {
                bail!(
                    "{}: from the `{}` profile every backup is encrypted under a recovery key and \
                     kept under a tested retention and destruction policy; declare {}",
                    permguard_core::codes::storage::BACKUP_POLICY_INCOMPLETE,
                    config.assurance().profile(),
                    shortfalls.join(", ")
                );
            }
            tracing::warn!(
                event.name = "host.backup_policy_incomplete",
                code = permguard_core::codes::storage::BACKUP_POLICY_INCOMPLETE,
                missing = %shortfalls.join(", "),
                "accepted under `development`, refused from `production`"
            );
        }
        let config = &match recovery_key_id {
            Some(id) => config.clone().with_backup_recovery_key_id(id),
            None => config.clone(),
        };
        // The service objectives (TS-5): bounded whatever the profile; from `production` every one
        // declared and consistent with the subsystem bounds that act on it.
        let objectives = self
            .load(config_file)?
            .objectives()
            .with_context(|| format!("in the configuration file {}", config_file.display()))?;
        let validation = objectives_checked(config, &objectives, &storage)?;
        let config = &config
            .clone()
            .with_objectives_report(objectives.report(validation));
        // The identity's witness before the custody writes the key-encryption key's.
        identity_witness_checked(config, &volume)?;
        // Each ring's provider, from its custody (WP-3.2): the identity's first.
        let custodian = custodian_for(config, secrets, &volume)?;

        // The Host identity (WP-2.2), before anything is recorded under it: opened and verified,
        // or provisioned when the profile allows it, and matched to its external witness.
        let (host_identity, provisioned, config, identity_custody) =
            self.host_identity_for(config, &volume, &time, &custodian)?;
        let config = &config;

        tracing::info!(
            event.name = "host.identity_opened",
            host_id = %host_identity.host_id_text(),
            epoch = host_identity.epoch(),
            fingerprint = %host_identity.fingerprint(),
            boot_id = %permguard_host::identity::record::uuid_text(&host_identity.boot_id()),
            provisioned,
            "the Host identity is open"
        );

        if config.log_format() == LogFormat::Terminal {
            let banner = Banner::new(&self.identity, config);

            write!(out, "{}", banner.render_full()).context("writing the startup banner")?;
            out.flush().context("flushing the startup banner")?;
        }

        // The Host-local pseudonym root (WP-3.3): the sinks' policy for the resource `host`, and
        // the audit engine's per-resource pseudonyms below.
        let pseudonym_root =
            self.pseudonym_root_for(config, secrets, &volume, host_identity.host_id())?;
        let pseudonymizer: Option<Arc<dyn Pseudonymizer>> = match &pseudonym_root {
            Some(local) => Some(Arc::new(
                local
                    .pseudonymizer(permguard_host::audit::HOST)
                    .map_err(|error| anyhow::anyhow!("{error}"))?,
            )),
            None => None,
        };
        // The coordinator root (WP-3.3): the zone keys this Host derives as its own authority.
        let coordinator =
            self.coordinator_for(config, secrets, &volume, host_identity.host_id())?;

        // Before the first record is written, not after: the damage a silent key change does is
        // done by the records made under it.
        // Per Host (BUG-0079): a reset's new identity derives new keys under the same labels.
        let host_scope = permguard_host::identity::witness::HostScope::of(
            config.working_dir(),
            &host_identity.host_id(),
        );
        crate::witness::check_for(config, pseudonymizer.as_deref(), &host_scope)?;

        let destination = self.audit_for(config)?;
        // The audit engine (WP-3.5): every record of the process in a trail per (class,
        // resource) under `host/audit/trails`, whatever `audit.destination` says; the sink the
        // destination chose sees every record too, the log stream by default, nothing under
        // `file` (owner decisions of 2026-10-07).
        // The legacy JSON-lines audit chain in `audit.directory` (WP-3.8).
        crate::checkpoints::lay_out_legacy(
            &volume,
            &config.audit_directory(),
            config.assurance().profile(),
            config.working_dir(),
            time.now_secs(),
        )?;
        // A version 1 decision spool its shipper sent whole (WP-6.1c), before any plane opens it.
        permguard_offline::legacy_spool::archive_at_start(
            &volume,
            config.working_dir(),
            config.log_spool_directory(),
            config.assurance().profile(),
            time.now_secs(),
        );
        // The Control Plane's event store, where releases before kept it by default inside the
        // legacy event history, moved to where it is kept now before anything opens either
        // (BUG-0122, BUG-0124).
        if config.event_store_directory_is_default() {
            permguard_offline::legacy_events::relocate_event_store(
                &config
                    .working_dir()
                    .join(permguard_core::config::LEGACY_EVENT_STORE_DIRECTORY),
                &config.event_store_directory(),
            )?;
        }
        // The legacy event journals and the retired pull's store once shipped and older than every
        // window (WP-6.2d), before the Data Plane opens them.
        permguard_offline::legacy_events::archive_at_start(
            &volume,
            &config.events_directory(),
            permguard_offline::legacy_events::bounds_of(config),
            config_file,
            config.assurance().profile(),
            time.now_secs(),
        );
        let audit_engine = {
            use permguard_host::audit::{Engine, Stamp, config_revision};

            let settings = config.effective_settings();
            let revision = config_revision(
                settings
                    .iter()
                    .map(|setting| (setting.key.as_str(), setting.value.as_deref())),
            );
            let stamp = Stamp {
                host_id: host_identity.host_id(),
                boot_id: host_identity.boot_id(),
                build: config.version().to_owned(),
                config_revision: revision,
            };
            let pseudonyms =
                pseudonym_root.map(permguard_host::audit::pseudonym::ResourcePseudonyms::new);
            Arc::new(
                Engine::open(&volume, stamp, Arc::clone(&time), pseudonyms)
                    .map_err(|error| anyhow::anyhow!("{error}"))
                    .with_context(|| {
                        format!(
                            "opening the audit trails on {}",
                            volume.host().path().display()
                        )
                    })?,
            )
        };
        // Sealed `access` and `operations` days older than `audit.retention` go; sealed
        // `security` ones only past `audit.retention_security`, kept for ever when it is unset
        // (owner decisions of 2026-10-07 and 2026-10-11).
        audit_engine.retain_for(config.audit_retention());
        if let Some(retention) = config.audit_retention_security() {
            audit_engine.retain_security_for(retention);
        }
        if let Some(witness) = &self.checkpoint_witness {
            audit_engine.witness_with(Arc::clone(witness));
        }
        let also = match config.audit_destination() {
            permguard_core::AuditDestination::Tracing => Some(destination),
            permguard_core::AuditDestination::File => None,
        };
        // The security-mutation journal (WP-3.6), its records written as every other record is:
        // the audit engine under the privacy policy, and the destination too. Its open intents
        // are resolved once each domain is open, the grants just below.
        let mutations = Arc::new(
            permguard_host::operations::mutation::Mutations::open(
                &volume,
                Arc::new(permguard_host::operations::mutation::HostProjection::new(
                    Arc::clone(&audit_engine),
                    pseudonymizer.clone(),
                    also.clone(),
                )),
                Arc::clone(&time),
            )
            .with_context(|| {
                format!(
                    "opening the mutation journal on {}",
                    volume.host().path().display()
                )
            })?,
        );
        // A rotation of the identity a crash left open is resolved now; the grants are below.
        mutations
            .recover(&permguard_host::identity::Identities(&host_identity))
            .context("recovering the identity mutations a crash left open")?;
        // The provisioning is recorded by the start that provisions, or, when that start was
        // refused before it could record it, by the next one: a Host identity never goes without
        // its record (BUG-0084). An identity a reset provisioned is recorded by the reset, under
        // `host:<host_id>`; a trail whose older part retention deleted is not second-guessed.
        let host_id = host_identity.host_id_text();
        let reset_target = format!("host:{host_id}");
        let unrecorded = !provisioned
            && audit_engine
                .holds(
                    permguard_host::audit::Class::Security,
                    permguard_host::audit::HOST,
                    &[
                        (
                            permguard_host::identity::AUDIT_PROVISIONED,
                            host_id.as_str(),
                        ),
                        (
                            permguard_host::identity::reset::AUDIT_RESET,
                            reset_target.as_str(),
                        ),
                    ],
                )
                .map_err(|error| anyhow::anyhow!("{error}"))
                .context("reading the record of the identity's provisioning")?
                == Some(false);
        if unrecorded {
            tracing::warn!(
                event.name = "host.identity_provisioning_recorded_late",
                component = "host",
                "the Host identity had no provisioning record: a start refused after it provisioned \
                 the identity; recorded now"
            );
        }
        if provisioned || unrecorded {
            audit_engine
                .append(
                    &permguard_core::AuditEvent::new(
                        permguard_host::identity::AUDIT_PROVISIONED,
                        permguard_core::Subject::System("host"),
                    )
                    .on(&host_identity.host_id_text()),
                    None,
                )
                .map_err(|error| anyhow::anyhow!("{error}"))
                .context("recording the identity's provisioning")?;
        }
        // What the identity's custody did at this start: its keys sealed in place or rewrapped.
        for (kind, slots) in [
            (
                permguard_host::keys::record::Kind::Sealed,
                &identity_custody.sealed,
            ),
            (
                permguard_host::keys::record::Kind::Rewrapped,
                &identity_custody.rewrapped,
            ),
        ] {
            for slot in slots {
                permguard_host::keys::ring::Recorder::record(
                    audit_engine.as_ref(),
                    permguard_host::keys::ring::HOST_IDENTITY,
                    &permguard_host::keys::record::Entry {
                        seq: 0,
                        kind,
                        kid: format!("{}:epoch-{slot}", permguard_host::keys::ring::HOST_IDENTITY),
                        epoch: host_identity.epoch(),
                        at: time.now_secs(),
                        operation_id: None,
                        reason: None,
                        jwk: None,
                        compromised_at: None,
                    },
                );
            }
        }
        let audit: Arc<dyn AuditSink> = Arc::new(permguard_host::audit::HostAuditSink::new(
            Arc::clone(&audit_engine),
            also,
        ));
        let catalog = self.catalog_for(config)?;
        // The Host's rings (WP-3.1): laid out under `host/keys`, a legacy `ring.json` directory
        // migrated first, every set bound by the identity and every transition recorded by the
        // audit engine; an operator's rotation or revocation a crash left open resolved now.
        let opener = permguard_host::keys::registry::Opener {
            volume: &volume,
            host_id: host_identity.host_id(),
            custodian: Arc::clone(&custodian),
            time: Arc::clone(&time),
            binder: Some(Arc::clone(&host_identity) as Arc<dyn permguard_host::keys::ring::Binder>),
            recorder: Some(
                Arc::clone(&audit_engine) as Arc<dyn permguard_host::keys::ring::Recorder>
            ),
            profile: config.assurance().profile(),
        };
        let keys = self
            .keys_for(config, &opener)
            .context("opening the host.operations key ring")?;
        // Every ended day of every trail sealed under `host.operations` (WP-3.7); without the
        // ring nothing is sealed, so nothing is deleted.
        if let Some(ring) = &keys {
            audit_engine
                .seal_with(Arc::clone(ring)
                    as Arc<dyn permguard_host::audit::checkpoint::CheckpointSigner>);
        }
        let control_signing_keys = self
            .control_signing_keys_for(config, &opener)
            .context("opening the control.attest key ring")?;
        let data_signing_keys = self
            .data_signing_keys_for(config, &opener)
            .context("opening the data.attest key ring")?;
        // The access tokens' ring, on the Host of a Server running the Authority Plane alone: no
        // other Host signs a token.
        let authority_host = self.runs_plane(config, "authority");
        let authority_tokens_keys = if authority_host {
            Some(
                permguard_offline::factories::authority_tokens_keys_for(config, &opener)
                    .context("opening the authority.tokens key ring")?,
            )
        } else {
            None
        };
        let key_registry = Arc::new(permguard_host::keys::registry::Registry::new(
            Some(Arc::clone(&host_identity)),
            [
                &keys,
                &control_signing_keys,
                &data_signing_keys,
                &authority_tokens_keys,
            ]
            .into_iter()
            .flatten()
            .cloned()
            .collect(),
        ));
        mutations
            .recover(key_registry.as_ref())
            .context("recovering the key ring mutations a crash left open")?;
        // No ring publishes, activates, retires or archives a key while a backup barrier holds:
        // the snapshot holds the rings it was inventoried with (BUG-0207).
        for ring in key_registry.rings() {
            ring.set_hold(Arc::new(mutations.barrier()));
        }
        // The Host's stream engine (WP-5.1), its runs signed under `host.operations`: the decision
        // log and the event journal registered on it, their Planes' adoption WP-6.1 and WP-6.2's.
        // The memberships a consumer's retention reads, bound once they are open below.
        let retention_members = Arc::new(std::sync::OnceLock::new());
        let mut prunables: Vec<Arc<dyn permguard_stream::engine::retention::Prunable>> = Vec::new();
        // What the Host API reads of the streams (WP-5.7a).
        let mut stream_reads: Option<Arc<dyn permguard_host::api::streams::StreamReads>> = None;
        let (streams, ingests) = match keys.as_ref() {
            Some(operations) => {
                let (served, decisions, events) = self
                    .stream_engine(
                        &volume,
                        &host_identity,
                        operations,
                        data_signing_keys.as_ref(),
                        &time,
                        &retention_members,
                        config.stream_acknowledged_retention(),
                        config.decision_ceiling(),
                    )
                    .map_err(|error| anyhow::anyhow!("{error}"))
                    .context("opening the stream engine")?;
                // What the garbage collection runs (WP-5.6b): every producer and consumer.
                prunables = served.prunables();
                prunables.push(Arc::clone(&decisions) as _);
                prunables.push(Arc::clone(&events) as _);
                stream_reads = Some(Arc::new(
                    served
                        .reads()
                        .with(Arc::clone(&decisions) as _)
                        .with(Arc::clone(&events) as _),
                ));
                (Some(Arc::new(served)), Some((decisions, events)))
            }
            None => (None, None),
        };
        // The memberships (WP-4.1): the store on the volume, whatever surface serves it, so a
        // membership mutation a crash left open is resolved before anything reads it.
        let members = permguard_host::membership::Store::open(&volume).with_context(|| {
            format!(
                "opening the memberships on {}",
                volume.host().path().display()
            )
        })?;
        // The root version keys are delivered at, what the member view compares a receipt with
        // (BUG-0097).
        if let Some(coordinator) = &coordinator {
            members.hold_root_version(coordinator.version().get());
        }
        mutations
            .recover(&permguard_host::membership::Memberships(&members))
            .context("recovering the membership mutations a crash left open")?;
        let members_joined: Arc<dyn permguard_host::authz::bootstrap::Joined> =
            Arc::clone(&members) as _;
        // The volume's backups (WP-7.8): a prepare a restart cut short is aborted, and recorded.
        // Recovery first: an ending a crash left open is judged on its own write, then what is
        // still prepared is cut.
        let backups =
            permguard_host::operations::backup::Backups::open(&volume).with_context(|| {
                format!("opening the backups on {}", volume.host().path().display())
            })?;
        mutations
            .recover(&backups)
            .context("recovering the backup mutations a crash left open")?;
        let cut = backups
            .cut(time.now_secs())
            .context("aborting the backups a restart cut short")?;
        if !cut.is_empty() {
            let recorded = backups.record_cut(&mutations, &cut, time.now_secs());
            tracing::warn!(
                event.name = "host.backup_cut",
                component = "server",
                backups = cut.len(),
                recorded,
                "a restart cut a prepared backup short: it is aborted"
            );
        }
        let backups = Arc::new(backups);
        let _ = retention_members.set(Arc::clone(&members));
        // Retention deletes a day of an exported trail only once its seal is acknowledged
        // (WP-5.9, owner decision).
        audit_engine.gate_retention_with(Arc::new(
            permguard_host::membership::egress::ExportFloor {
                store: Arc::clone(&members),
            },
        ));
        let keys: Option<Arc<dyn KeyManager>> = keys.map(|ring| ring as Arc<dyn KeyManager>);
        let operations_ring = keys.clone();

        // Every issuer this deployment hosts, each with its own keys and trail, built once here. A
        // plain single-issuer server has none and this is the empty registry.
        let realms = self.realms_for(config)?;

        // The same silent-key-change guard the server just passed, once per realm against its own
        // witness — before any realm record is written, for the same reason.
        for realm in realms.all() {
            crate::witness::check_realm(config, realm, None)?;
        }

        record_build(&self.identity, config, self.server.name());
        if let Some(deprecated) = crate::checkpoints::destination_deprecation(config) {
            tracing::warn!(
                event.name = "audit.destination_deprecated",
                component = "host",
                "{deprecated}"
            );
        }

        // Registered for exactly as long as the server runs. An app may serve more than once in a
        // process — a test certainly does — and a handler left behind by the previous run would be
        // a second listener for the same signal.
        let hangup = match (&self.reload_handler, &self.hangup_listener) {
            (Some(handler), Some(listen)) => Some(listen(Arc::clone(handler))),
            _ => None,
        };

        let recorder = self.recorder(&audit, pseudonymizer.as_ref());
        let mut context = self
            .context(config, pseudonymizer.as_deref(), keys)
            .with_audit(audit.as_ref())
            .with_realms(realms);
        // An `operations` record the engine could not write degrades the Host's readiness.
        audit_engine.observe(context.health().clone());
        // The process document names the Host by its id (WP-7.4a).
        context
            .health()
            .lifecycle()
            .set_host_id(host_identity.host_id_text());
        // `host status` publishes where the volume stands, the compatibility mode included (TS-5).
        if let Some(report) = config.storage_report() {
            context.health().lifecycle().set_storage(report.clone());
        }
        mutations.observe(context.health().clone());
        // `production` admits the ring in files on this volume, and the Host says so until it
        // moves to a PKCS#11 token or a KMS: whoever holds the volume signs every token.
        if let Some(advice) = authority_host
            .then(|| permguard_offline::factories::authority_tokens_custody_advice(config))
            .flatten()
        {
            tracing::warn!(
                event.name = "keys.token_custody",
                component = "server",
                "{advice}"
            );
            context.health().lifecycle().degrade(
                permguard_core::lifecycle::HOST,
                permguard_offline::factories::TOKEN_CUSTODY,
                advice,
            );
        }

        if let Some(catalog) = catalog {
            context = context.with_catalog(catalog);
        }

        // Bootstrap is behind us: the volume is claimed and the configuration validated, and the
        // Host's own state is opening. No listener is bound yet, so nothing earlier is observable.
        context.health().lifecycle().advance(
            permguard_core::lifecycle::HOST,
            permguard_core::lifecycle::Phase::Load,
        );

        // The authorization and its authenticator: the Authority Plane's tokens, what the
        // configuration declares public, and the recovery principal's certificate. Built before the
        // Planes register, since every Plane decides with them.
        let file = self.load(config_file)?;
        let HostAuthz {
            authorization,
            authenticator,
            trust,
            bootstrap,
        } = self.authorization_for(config, config_file, &file, &volume, &time, &mutations)?;
        context = context.with_authenticator(authenticator);
        let bootstrap_principal = bootstrap.bootstrap().map(|held| held.principal);

        // The Host API facade (WP-2.5), when the deployment has a Host listener: the replay
        // journal on the volume, the grant store, every ring this process composes and the
        // lifecycle, built once and served by both transports. Without `admin.addr` nothing is
        // opened: a volume without a listener keeps no replay window.
        // Who serves a ledger under this Host's memberships, for the Plane that provides
        // `policy.mirror` (WP-4.4); none without a Host listener.
        let mut serving: Option<Arc<permguard_host::api::HostApi>> = None;
        // The handler of `policy.mirror` is the Control Plane's, which is composed after the task
        // sessions: they route to a slot it fills (WP-7.12). The watches' hub is shared the same
        // way, so a commit's hint reaches every watch of the ledger.
        let mirror_slot = Arc::new(permguard_host::membership::task::Deferred::default());
        // The same slot serves the local task of a Host running both Planes (WP-7.7).
        let local_mirror_slot = Arc::clone(&mirror_slot);
        // And `events.import`'s, which the Control Plane serves from the event consumer
        // (WP-6.2c1).
        let import_slot = Arc::new(permguard_host::membership::task::Deferred::default());
        let watch_hub = Arc::new(permguard_host::membership::watch::Hub::default());
        // The coordinator side of the re-pin pass, with the Host API's member side (WP-4.5).
        let mut local_shipper: Option<Arc<permguard_host::membership::local::LocalShipping>> = None;
        let mut repinning_coordinator: Option<
            Arc<permguard_host::membership::service::Coordinating>,
        > = None;
        // A member opens every session, so it needs no listener to be one (`1-architecture/3`, A
        // member with no listener): a Host embedded in an application composes the same membership
        // side with no ingress, when the Host listener's TLS block names the client identity it
        // dials out with. A served Host composes it beside its listener, as before.
        let dials_out =
            config.is_embedded() && config.admin_tls().is_some_and(|tls| tls.is_mutual());
        if config.admin_addr().is_some() || dials_out {
            use permguard_host::api::{Assurance, Composition, Effective, HostApi, Replay};

            let (replay, recovery) = Replay::open(&volume, time.now_secs()).with_context(|| {
                format!(
                    "opening the replay journal on {}",
                    volume.host().path().display()
                )
            })?;
            let replay = replay.with_time(Arc::clone(&time));
            // An approval a crash left open is committed when its frame is durable (WP-3.9).
            mutations
                .recover(&replay)
                .context("recovering the plans' mutations a crash left open")?;
            tracing::info!(
                event.name = "host_api.replay_opened",
                component = "server",
                held = replay.held(),
                recovered_truncated_bytes = recovery.truncated_bytes,
                "the replay journal is open"
            );
            // The peers a session accepts: the configured pins and the memberships' (WP-4.1).
            let peers = Arc::new(
                permguard_host::session::peers::Peers::open(&volume, config.host_peers())
                    .with_context(|| {
                        format!(
                            "opening the pinned peers on {}",
                            volume.host().path().display()
                        )
                    })?,
            );
            peers.with_source(
                Arc::clone(&members) as Arc<dyn permguard_host::session::peers::PinSource>
            );
            // The task contracts this Host registered: its own and those its selected Planes
            // declare (WP-4.4), so an approval names no task this Host cannot serve.
            let capabilities = self
                .plane_declarations
                .iter()
                .filter_map(|declare| declare(config))
                .fold(
                    permguard_host::membership::Capabilities::host(),
                    |capabilities, (_, _, declaration)| capabilities.with_declared(&declaration),
                );
            // Without a coordinator root this Host serves no zone keys: it does not offer the
            // coordinator's side of `zone.secrets`, so an approval naming it is refused
            // `task_unserved` instead of signing a task nothing can deliver (BUG-0096).
            let capabilities = if coordinator.is_none() {
                use permguard_host::membership::record::TaskType;
                capabilities.without(TaskType::ZoneSecrets, TaskType::ZoneSecrets.provider())
            } else {
                capabilities
            };
            // The appraisal policy configured; no verifier ships, so `attested` is refused until a
            // composition registers one (WP-4.2, owner decision).
            let appraisal = permguard_host::membership::appraisal::Appraisal::new(
                permguard_host::membership::appraisal::Policy::new(
                    config.membership_appraisal_controls().clone(),
                    config.membership_appraisal_max_binding(),
                ),
                permguard_host::membership::appraisal::Verifiers::default(),
            );
            // The open task sessions, shared by the PeerChannel and the sessions route. A contract
            // the Planes declared answers `not_served_yet` until its package registers the handler
            // (WP-4.4, owner decision).
            // The Host serves `zone.secrets` itself once it holds a coordinator root (WP-4.7).
            let handlers = match coordinator.clone() {
                Some(coordinator) => permguard_host::membership::task::TaskHandlers::default()
                    .register(
                        permguard_host::membership::record::TaskType::ZoneSecrets,
                        permguard_host::membership::zone::VERSION,
                        Arc::new(permguard_host::membership::zone::ZoneSecrets {
                            coordinator,
                            store: Arc::clone(&members),
                            time: Arc::clone(&time),
                        }),
                    )
                    .map_err(|error| anyhow::anyhow!("{error}"))?,
                None => permguard_host::membership::task::TaskHandlers::default(),
            };
            // The Host keeps the checkpoints its members export (WP-5.9).
            let handlers = handlers
                .register(
                    permguard_host::membership::record::TaskType::AuditCheckpoints,
                    permguard_host::membership::egress::VERSION,
                    Arc::new(permguard_host::membership::egress::AuditCheckpoints {
                        store: Arc::clone(&members),
                        time: Arc::clone(&time),
                    }),
                )
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            // The ship tasks' ingest, on the stream engine's consumers (WP-5.3).
            let handlers = match ingests.clone() {
                Some((decisions, events)) => handlers
                    .register(
                        permguard_host::membership::record::TaskType::DecisionsShip,
                        permguard_stream::engine::ingest::VERSION,
                        Arc::new(permguard_stream::engine::ingest::Ingest {
                            consumer: decisions,
                            pins: Arc::clone(&members)
                                as Arc<dyn permguard_stream::engine::ingest::StreamPins>,
                        }),
                    )
                    .and_then(|handlers| {
                        handlers.register(
                            permguard_host::membership::record::TaskType::EventsShip,
                            permguard_stream::engine::ingest::VERSION,
                            Arc::new(permguard_stream::engine::ingest::Ingest {
                                consumer: events,
                                pins: Arc::clone(&members)
                                    as Arc<dyn permguard_stream::engine::ingest::StreamPins>,
                            }),
                        )
                    })
                    .map_err(|error| anyhow::anyhow!("{error}"))?,
                None => handlers,
            };
            let handlers = handlers
                .register(
                    permguard_host::membership::record::TaskType::PolicyMirror,
                    1,
                    Arc::clone(&mirror_slot)
                        as Arc<dyn permguard_host::membership::task::TaskHandler>,
                )
                .and_then(|handlers| {
                    handlers.register(
                        permguard_host::membership::record::TaskType::EventsImport,
                        permguard_host::membership::import::VERSION,
                        Arc::clone(&import_slot)
                            as Arc<dyn permguard_host::membership::task::TaskHandler>,
                    )
                })
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            let tasks = Arc::new(permguard_host::membership::task::Tasks {
                appraisal: Arc::new(appraisal.clone()),
                handlers,
                hub: Arc::clone(&watch_hub),
                ..permguard_host::membership::task::Tasks::default()
            });
            // What a coordinator serves on a proven session: an enrollment, a manifest fetch, a
            // revocation asked by its member, and its task sessions.
            let coordinating = Arc::new(permguard_host::membership::service::Coordinating {
                store: Arc::clone(&members),
                mutations: Arc::clone(&mutations),
                identity: Arc::clone(&host_identity),
                keys: Arc::clone(&key_registry),
                capabilities: capabilities.clone(),
                time: Arc::clone(&time),
                tasks: Arc::clone(&tasks),
            });
            // No ring of this Host activates a prepublished key before every membership pins its
            // epoch (WP-4.5).
            for ring in key_registry.rings() {
                ring.set_gate(Arc::new(permguard_host::membership::repin::PinGate {
                    store: Arc::clone(&members),
                }));
            }
            repinning_coordinator = Some(Arc::clone(&coordinating));
            let session_context = permguard_host::session::Context {
                identity: Arc::clone(&host_identity),
                peers,
                time: Arc::clone(&time),
                declared_assurance: config.assurance().profile(),
                audit: Some(Arc::clone(&audit_engine)),
                metrics: context.metrics().clone(),
                service: Some(coordinating as Arc<dyn permguard_host::session::Service>),
            };
            // How this Host, as a member, reaches its coordinators: over the Host listener's own
            // certificate, verifying them against its client CA; without one, a join is refused.
            // The connection itself is an adapter's: without one composed, as without a
            // certificate, this Host reaches no coordinator.
            let connector = match &self.peer_connector {
                Some(connect) => connect(config, &session_context)
                    .context("building the peer client of the Host listener")?,
                None => None,
            };
            let api = HostApi::new(Composition {
                authorization: Arc::clone(&authorization),
                replay,
                keys: Arc::clone(&key_registry),
                health: context.health().clone(),
                // The profile in force, the controls added and the relaxations the values amount
                // to: the block discovery publishes too (WP-2.8).
                assurance: Assurance::of(
                    &config.assurance().report(&config.relaxations_in_force()),
                ),
                // The settings, and the public grants beside them (BUG-0202): a structured section
                // with no variable, read from the file the authorization was built from.
                effective: Effective::of(config.effective_settings()).with_public_grants(
                    file.host_auth()
                        .with_context(|| {
                            format!("in the configuration file {}", config_file.display())
                        })?
                        .public
                        .into_iter()
                        .map(|grant| permguard_host::api::config::PublicGrant {
                            operations: grant.operations,
                            selector: grant.selector.to_string(),
                            resource_types: grant.resource_types,
                        }),
                ),
                // The trail every Host API mutation is recorded in, as the audit routes name it
                // (BUG-0095): never the name of the sink.
                trail: format!(
                    "{}:{}",
                    permguard_host::audit::Class::Security.as_str(),
                    permguard_host::audit::HOST
                ),
                mutations: Some(Arc::clone(&mutations)),
                identity: Some(Arc::clone(&host_identity)),
                time: Arc::clone(&time),
                // Peer Host sessions (WP-2.3): the pinned peers and what the listener's
                // configuration amounts to; the PeerChannel refuses when it serves none.
                peer_sessions: permguard_host::api::sessions::PeerSessions {
                    report: config.peer_sessions(),
                    context: Some(session_context.clone()),
                },
                // Every listener and what it demands of its clients (WP-2.11), as discovery
                // publishes them.
                listeners: match &self.listeners {
                    Some(report) => report(config),
                    None => Vec::new(),
                },
                audit: Some(Arc::clone(&audit_engine)),
                memberships: Some(Arc::new(permguard_host::api::members::MembershipService {
                    store: Arc::clone(&members),
                    capabilities: capabilities.clone(),
                    connector,
                    appraisal,
                    live: Arc::clone(&tasks.live),
                    // The streams a re-pin cuts over (WP-5.2).
                    streams: streams.clone().map(|engine| {
                        engine as Arc<dyn permguard_host::composition::StreamCutovers>
                    }),
                    // The batches its ship tasks deliver (WP-5.4).
                    shipping: streams.clone().map(|engine| {
                        engine as Arc<dyn permguard_host::composition::StreamShipping>
                    }),
                    // The origins' history its `events.import` tasks deliver, into the event
                    // consumer, for the ledgers a shared consistency mode names (WP-6.2c2a).
                    importing: ingests.as_ref().and_then(|(_, events)| {
                        import_ledgers(config).map(|ledgers| {
                            Arc::new(permguard_host::membership::member::import::Importing {
                                engine: Arc::clone(events)
                                    as Arc<dyn permguard_host::composition::StreamImport>,
                                ledgers,
                            })
                        })
                    }),
                })),
            });
            let api = match stream_reads.clone() {
                Some(reads) => api.with_streams(reads),
                None => api,
            };
            // The volume a drain receipt names (TD-2).
            let api = api.with_volume(volume.id(), volume.generation());
            // An approval stands for its ttl, and while the approver's token is valid (BUG-0099).
            let api = api.with_approvals(
                config.dual_control_approval_ttl(),
                Arc::clone(&trust) as Arc<dyn permguard_host::authz::access_tokens::TokenStanding>,
            );
            // The application-consistent snapshot's barrier (WP-7.8).
            let api = api.with_backups(
                Arc::clone(&backups),
                config.backup_recovery_key_id().map(str::to_owned),
                config.backup_encryption_profile().map(str::to_owned),
            );
            // A Host running both Planes ships its Data Plane's decisions and events to its own
            // Control Plane through local tasks, verified under its own `data.attest`: what the
            // Control Plane's public reads answer from, with no membership.
            let both_planes = {
                let selected: Vec<&'static str> = self
                    .plane_declarations
                    .iter()
                    .filter_map(|declare| declare(config))
                    .map(|(plane, _, _)| plane)
                    .collect();
                selected.contains(&"control") && selected.contains(&"data")
            };
            let local_shipping = match (both_planes, &streams, &ingests, &data_signing_keys) {
                (true, Some(engine), Some((decisions, events)), Some(data_attest)) => {
                    let pins = Arc::new(permguard_stream::engine::ingest::LocalPins {
                        ring: Arc::clone(data_attest),
                    });
                    Some(Arc::new(
                        permguard_host::membership::local::LocalShipping::new(
                            Arc::clone(engine)
                                as Arc<dyn permguard_host::composition::StreamShipping>,
                            Arc::clone(engine)
                                as Arc<dyn permguard_host::composition::StreamCutovers>,
                            Arc::new(permguard_stream::engine::ingest::Ingest {
                                consumer: Arc::clone(decisions),
                                pins: Arc::clone(&pins)
                                    as Arc<dyn permguard_stream::engine::ingest::StreamPins>,
                            }),
                            Arc::new(permguard_stream::engine::ingest::Ingest {
                                consumer: Arc::clone(events),
                                pins: pins as Arc<dyn permguard_stream::engine::ingest::StreamPins>,
                            }),
                            host_identity.host_id(),
                            Arc::clone(data_attest),
                        ),
                    ))
                }
                _ => None,
            };
            let api = match local_shipping.clone() {
                Some(local) => api.with_local_shipping(local),
                None => api,
            };
            local_shipper = local_shipping;
            let api = Arc::new(api);
            serving = Some(Arc::clone(&api));
            context = context.with_host_handles(api);
        }

        // The Host: every generic capability once. The Planes' rings, the audit recorder and the
        // secret store reach a Plane only as the handles its declaration grants (P1); the rings are
        // also handed to the Host's own maintenance pass.
        // Readiness, the log and the trail hear of every clock anomaly, one already found at
        // Bootstrap included; a periodic pass notices a jump when no request reads the time.
        time.observe(Arc::new(crate::time::HostClockObserver::new(
            context.health().clone(),
            Some(recorder.clone()),
        )));
        let _ticking = crate::time::tick(Arc::clone(&time));
        // The ended days a stopped process left unsealed, sealed now and every hour after.
        let _sweeping = crate::checkpoints::sweep(Arc::clone(&audit_engine));
        // Readiness held while a measured lag or headroom is past its objective's margin (TS-5).
        let _objectives = crate::objectives::drive(
            objectives.clone(),
            crate::objectives::Sources {
                health: context.health().clone(),
                metrics: context.metrics().clone(),
                backups: Arc::clone(&backups),
                spool_capacity: (permguard_core::planes::discovery::plane_enabled(config, "data")
                    && config.log_enabled())
                .then(|| config.log_spool_bytes()),
                time: Arc::clone(&time),
                volume_created: volume_created(&volume, &time),
                qualification_expires_at: match &standing {
                    permguard_host::storage::qualify::Standing::Qualified {
                        expires_at, ..
                    } if config
                        .assurance()
                        .profile()
                        .at_least(permguard_core::assurance::AssuranceProfile::Production) =>
                    {
                        *expires_at
                    }
                    _ => None,
                },
                shipping: serving
                    .as_ref()
                    .filter(|api| api.ships_streams())
                    .map(Arc::clone),
            },
        );
        // Readiness held while free space is at the emergency floor; the quota measured and reported.
        let _storage = crate::storage_quota::watch(
            host_quota,
            context.health().clone(),
            context.metrics().clone(),
        );
        // The streams' garbage collection, at start and every hour, off the request path (WP-5.6b).
        let _pruning =
            crate::stream_gc::drive(prunables, Arc::clone(&audit_engine), Arc::clone(&time));
        // The Authority Plane's key set and lists, fetched from `authority.endpoint`, else from
        // `authority.url`, off the request path, when the Authority Plane runs in another process
        // (`2-security/8` Keys and lists on a Plane), over the transport its scheme names. Beside
        // it, the Authority Plane hands them over in-process.
        let _authority = (!authority_host)
            .then(|| {
                [
                    permguard_core::planes::settings::SETTING_AUTHORITY_ENDPOINT,
                    permguard_core::planes::settings::SETTING_AUTHORITY_URL,
                ]
                .into_iter()
                .find_map(|setting| {
                    config
                        .setting(setting)
                        .map(str::trim)
                        .filter(|url| !url.is_empty())
                        .map(|url| url.trim_end_matches('/').to_owned())
                })
            })
            .flatten()
            .map(|url| {
                // The fetch is an adapter's: a composition that names an Authority Plane elsewhere
                // and has no client to fetch its keys with would refuse every token, silently.
                let refresh = self.authority_refresh.as_ref().context(
                    "the configuration names an Authority Plane elsewhere, and this composition \
                     has no client to fetch its key set and status lists with",
                )?;
                refresh(
                    Arc::clone(&trust),
                    AuthoritySource {
                        url,
                        // Relative to the volume, as every TLS path of the configuration is.
                        ca: config
                            .setting(permguard_core::planes::settings::SETTING_AUTHORITY_TLS_CA)
                            .map(|path| config.resolve(path)),
                        allow_http: config.assurance().profile()
                            == permguard_core::assurance::AssuranceProfile::Development,
                    },
                    AuthorityObserving {
                        health: context.health().clone(),
                        metrics: context.metrics().clone(),
                        time: Arc::clone(&time),
                    },
                )
            })
            .transpose()?;
        if !authority_host
            && config
                .setting(permguard_core::planes::settings::SETTING_AUTHORITY_URL)
                .is_none()
        {
            tracing::warn!(
                event.name = "authz.authority_unset",
                component = "server",
                "no Authority Plane runs in this process and authority.url names none elsewhere: \
                 every access token is refused, and only public grants and the bootstrap \
                 principal act here"
            );
        }
        // Members silent past their thresholds suspended, then revoked (WP-4.6).
        let _dormancy = repinning_coordinator
            .as_ref()
            .map(|coordinating| crate::dormancy::drive(Arc::clone(coordinating)));
        // The zone keys this Host's memberships as a member grant, received and confirmed (WP-4.7).
        let zone_keys = Arc::new(
            permguard_host::secrets::ZoneKeys::open(&volume)
                .context("opening the delivered zone keys")?,
        );
        let _receiving = serving
            .as_ref()
            .map(|api| crate::zone::drive(Arc::clone(api), Arc::clone(&zone_keys)));
        // A member joins the coordinator its configured invitation names, by itself (TD-5).
        let _joining = match (config.host_join(), serving.as_ref()) {
            (Some(join), Some(api)) => Some(crate::join::drive(
                Arc::clone(api),
                join.clone(),
                context.health().clone(),
            )?),
            (Some(_), None) if config.is_embedded() => bail!(
                "host.join needs the client identity this Host dials out with: set \
                 `admin.tls.cert`, `admin.tls.key` and `admin.tls.client_ca`; an embedded Host \
                 binds no listener and joins through its membership side"
            ),
            (Some(_), None) => bail!(
                "host.join needs this Host's listener (`admin.addr` and its TLS): the join is \
                 made through its membership side"
            ),
            (None, _) => None,
        };
        // Streams an incomplete drain left are shipped again before the Host leaves Load
        // (WP-5.8, owner decision): one pass within the drain budget.
        if let Some(api) = serving.as_ref() {
            crate::shipping::resume(api, config.shutdown_drain_timeout()).await;
        }
        // The local ship tasks run on their own short pass: the Control Plane reads what this
        // Host decided within seconds, not at the next re-pin pass.
        let _local_shipping = local_shipper.map(crate::shipping::drive_local);
        // A `shared-bounded` member imports on a pass its bound can meet, every half of it, and
        // the re-pin pass leaves the import to it (BUG-0130).
        let shared_bounded =
            config.events_pull_mode() == permguard_core::config::Consistency::SharedBounded;
        let _importing = serving
            .as_ref()
            .filter(|_| shared_bounded)
            .map(|api| crate::imports::drive(Arc::clone(api), config.events_pull_max_staleness()));
        let _repinning = match (repinning_coordinator, serving.as_ref()) {
            (Some(coordinating), Some(api)) => Some(crate::repin::drive(
                coordinating,
                Arc::clone(api),
                crate::repin::Egress {
                    enforce: config
                        .assurance()
                        .requires(permguard_core::assurance::Control::AuditExternalCheckpoints),
                    max_lag: config.audit_checkpoints_max_lag(),
                },
                !shared_bounded,
            )),
            _ => None,
        };
        // Where the profile requires the checkpoints to leave the volume and nothing here can
        // send them, the Host says so from the start (WP-5.9, after the review).
        if _repinning.is_none()
            && config
                .assurance()
                .requires(permguard_core::assurance::Control::AuditExternalCheckpoints)
        {
            context.health().lifecycle().degrade(
                permguard_core::lifecycle::HOST,
                "audit_egress",
                "no Host listener composes a membership side: the audit checkpoints cannot leave \
                 the volume",
            );
        }
        // The version in force of every layout, as the start steps left them: a Plane reads those
        // it declared (WP-6.2d).
        let laid_out = permguard_host::storage::migrate::status(&volume)
            .context("reading the layouts")?
            .into_iter()
            .map(|status| (status.manifest.subsystem, status.manifest.active.version));
        let mut host = permguard_host::composition::Host::builder()
            .layouts(laid_out)
            .audit(recorder)
            .authorization(authorization)
            .time(Arc::clone(&time))
            .host_id(host_identity.host_id())
            // A Plane's security mutations run in the Host's transaction (WP-3.6): the Control
            // Plane's ref updates (WP-7.12).
            .mutations(Arc::clone(&mutations))
            // What the Control Plane's garbage collection keeps (WP-7.3c).
            .holds(Arc::new(
                permguard_host::holds::HoldStore::open(&volume).context("opening the holds")?,
            ))
            .task_slot(
                permguard_host::membership::record::TaskType::PolicyMirror,
                1,
                mirror_slot,
            )
            .task_slot(
                permguard_host::membership::record::TaskType::EventsImport,
                permguard_host::membership::import::VERSION,
                import_slot,
            )
            .watch_hub(watch_hub);
        if let Some(streams) = streams {
            host = host.streams(streams);
        }
        // The zone keys this Host holds as coordinator, or else those it received as a member, as
        // they stood at start (WP-4.7, owner decision): a key received later serves from the next.
        if coordinator.is_none() {
            for handle in members
                .delivered_handles(&zone_keys)
                .context("reading the delivered zone keys")?
            {
                host = host.zone_key(handle);
            }
        }
        if let Some(coordinator) = coordinator {
            use permguard_host::secrets::{ZoneHandle, ZonePurpose};
            host = host
                .zone_key(ZoneHandle::coordinated(
                    ZonePurpose::DecisionCommitment,
                    coordinator.clone(),
                ))
                .zone_key(ZoneHandle::coordinated(
                    ZonePurpose::AuditPseudonym,
                    coordinator,
                ));
        }
        // The Host's own ring, for the one Plane artifact on it whose payload the Host writes, an
        // export manifest (WP-7.10): the composition refuses any other.
        if let Some(keys) = operations_ring {
            host = host.ring(permguard_host::composition::HOST_OPERATIONS, keys);
        }
        // A Host running both Planes mirrors its own Control Plane through a local task beside
        // its memberships' (WP-7.7): no configured URL, its own `control.attest` the pinned set.
        let selected: Vec<&'static str> = self
            .plane_declarations
            .iter()
            .filter_map(|declare| declare(config))
            .map(|(plane, _, _)| plane)
            .collect();
        let both_planes_mirror =
            selected.contains(&"control") && selected.contains(&"data") && config.mirrors_enabled();
        let local_mirror = both_planes_mirror
            .then(|| control_signing_keys.clone())
            .flatten();
        if both_planes_mirror && local_mirror.is_none() {
            tracing::warn!(
                event.name = "sync.local_unavailable",
                component = "server",
                "this process hosts both Planes and mirrors, but its Control Plane signs under no \
                 `control.attest` ring: its own ledgers cannot be verified, so it does not mirror them"
            );
        }
        // The access tokens' ring rotates with the Host's other rings, and signs for the Authority
        // Plane alone.
        if let Some(keys) = authority_tokens_keys.clone() {
            let keys: Arc<dyn KeyManager> = keys;
            context = context.with_maintained_ring("authority-tokens", Arc::clone(&keys));
            host = host.ring(permguard_host::composition::AUTHORITY_TOKENS, keys);
        }
        host = host.authority_trust(Arc::clone(&trust)).volume(&volume);
        if let Some(keys) = control_signing_keys {
            let keys: Arc<dyn KeyManager> = keys;
            context = context.with_maintained_ring("control-signing", Arc::clone(&keys));
            host = host.ring(permguard_host::composition::CONTROL_ATTEST, keys);
        }
        if let Some(keys) = data_signing_keys {
            let keys: Arc<dyn KeyManager> = keys;
            context = context.with_maintained_ring("data-signing", Arc::clone(&keys));
            host = host.ring(permguard_host::composition::DATA_ATTEST, keys);
        }
        // The member side of `policy.mirror` too (WP-7.2a): the Data Plane's mirror round opens
        // its task sessions through it, and the local task's beside them (WP-7.7).
        let members = serving
            .as_ref()
            .map(|api| Arc::clone(api) as Arc<dyn permguard_host::composition::MirrorTasks>);
        let mirror_tasks = match local_mirror {
            Some(control_attest) => Some(Arc::new(
                permguard_host::membership::local::LocalMirrors::new(
                    members,
                    host_identity.host_id(),
                    local_mirror_slot as Arc<dyn permguard_host::membership::task::TaskHandler>,
                    control_attest,
                ),
            )
                as Arc<dyn permguard_host::composition::MirrorTasks>),
            None => members,
        };
        if let Some(tasks) = mirror_tasks {
            host = host.mirror_tasks(tasks);
        }
        if let Some(api) = serving {
            host = host
                // The garbage-collection jobs the Planes provide to the Host API (WP-7.11b).
                .gc_jobs(api.gc_jobs())
                .memberships(api);
        }
        let host = host.build();
        // On a member its bootstrap principal is watched, whatever surface it reaches: every use
        // once joined is audited and reported, and the report cleared on a tick (WP-12.4).
        let mut bootstrap_tick = None;
        if self.is_member(config) {
            match (context.authenticator(), bootstrap_principal) {
                (Some(inner), Some(principal)) => {
                    let watch = Arc::new(permguard_host::authz::bootstrap::BootstrapWatch::new(
                        inner,
                        principal,
                        Arc::clone(&members_joined),
                        Some(Arc::clone(&audit_engine)),
                        context.health().clone(),
                        Arc::clone(&time),
                    ));
                    context = context.with_authenticator(
                        Arc::clone(&watch) as Arc<dyn permguard_core::authz::Authenticator>
                    );
                    bootstrap_tick = Some(tokio::spawn(async move {
                        let mut every = tokio::time::interval(std::time::Duration::from_secs(60));
                        loop {
                            every.tick().await;
                            watch.expire();
                        }
                    }));
                }
                (_, None) if members_joined.memberships() == 0 => tracing::warn!(
                    event.name = "host.bootstrap_missing",
                    component = "server",
                    "this member has no bootstrap principal and no membership: nobody administers \
                     it; commit one offline (`permguard host grants bootstrap`)"
                ),
                _ => {}
            }
        }
        // Every selected Plane registers before any service starts, so its state opens with its
        // handles in place, and two Planes claiming one thing stop the start.
        for declare in &self.plane_declarations {
            let Some((plane, required, declaration)) = declare(config) else {
                continue;
            };
            // Listed from here on, in Bootstrap: a Plane is never omitted from what the Host
            // reports, whatever it binds later.
            context.health().lifecycle().enter(
                plane,
                permguard_core::lifecycle::Kind::Plane,
                required,
                permguard_core::lifecycle::Phase::Bootstrap,
            );
            let registration = host
                .register(declaration)
                .with_context(|| format!("registering the {plane} plane with the Host"))?;
            context = context.with_plane_handles(plane, Arc::new(registration));
        }

        let outcome = self.server.run(&context, shutdown).await;

        if let Some(hangup) = hangup {
            hangup.abort();
        }
        if let Some(tick) = bootstrap_tick {
            tick.abort();
        }

        outcome
    }
}

/// Records which build is running, as the first record of the stream.
///
/// In `json` there is no banner, so this record is the only thing that says which build produced
/// everything after it — and a stream nobody can attribute to a build is a stream nobody can act on.
/// In `terminal` the banner says the same thing to a human; the record is emitted either way so the
/// two formats carry the same information.
pub fn record_build(identity: &ProductIdentity, config: &Config, host: &str) {
    tracing::info!(
        event.name = "server.build",
        service.name = identity.binary_name(),
        service.version = config.version(),
        server.host = host,
        log.level = config.log_level().as_str(),
        log.format = config.log_format().as_str(),
        otel.enabled = config.otel_enabled(),
        process.pid = std::process::id(),
        "build"
    );
}

/// The service objectives judged under the profile (TS-5): missing or inconsistent ones refused
/// from `production`, reported below. Answers the validation state discovery publishes.
fn objectives_checked(
    config: &Config,
    objectives: &permguard_core::objectives::Objectives,
    storage: &permguard_core::volume::VolumeConfig,
) -> Result<&'static str> {
    use permguard_core::codes::storage as codes;

    let data = permguard_core::planes::discovery::plane_enabled(config, "data");
    let limits = permguard_core::objectives::Limits {
        mirrors_stale_after: (data && config.mirrors_enabled())
            .then(|| config.mirrors_stale_after()),
        decision_spool_age: (data && config.log_enabled()).then(|| config.log_spool_age()),
        audit_checkpoints_max_lag: config.audit_checkpoints_max_lag(),
        backup_retention: config.backup_retention(),
        host_quota_bytes: storage.quotas.host.bytes,
    };
    let missing = objectives.missing();
    let inconsistent = objectives.inconsistencies(&limits);
    let production = config
        .assurance()
        .profile()
        .at_least(permguard_core::assurance::AssuranceProfile::Production);
    if production && !missing.is_empty() {
        bail!(
            "{}: from the `{}` profile every service objective is declared; add {} to \
             `objectives`",
            codes::OBJECTIVES_INCOMPLETE,
            config.assurance().profile(),
            missing.join(", ")
        );
    }
    if production && !inconsistent.is_empty() {
        bail!(
            "{}: {}",
            codes::OBJECTIVES_INCONSISTENT,
            inconsistent.join("; ")
        );
    }
    if !missing.is_empty() {
        tracing::warn!(
            event.name = "host.objectives_incomplete",
            code = codes::OBJECTIVES_INCOMPLETE,
            missing = %missing.join(", "),
            "accepted under `development`, refused from `production`"
        );
    }
    for found in &inconsistent {
        tracing::warn!(
            event.name = "host.objectives_inconsistent",
            code = codes::OBJECTIVES_INCONSISTENT,
            detail = %found,
            "accepted under `development`, refused from `production`"
        );
    }
    Ok(if missing.is_empty() && inconsistent.is_empty() {
        "validated"
    } else {
        "incomplete"
    })
}

/// When the volume was created, in seconds: its `VOLUME_ID`, written once, at creation. Read from
/// the file, so a restart never moves it; the guarded time when it cannot be read.
fn volume_created(
    volume: &permguard_host::storage::volume::Volume,
    time: &permguard_host::time::TimeGuard,
) -> u64 {
    std::fs::symlink_metadata(
        volume
            .host()
            .path()
            .join(permguard_host::storage::volume::VOLUME_ID),
    )
    .and_then(|metadata| metadata.modified())
    .ok()
    .and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok())
    .map_or_else(|| time.now_secs(), |since| since.as_secs())
}

/// Probes the filesystem under the volume's `host/state` and qualifies its tuple for `profile`
/// (WP-1.3, TS-5) at `now`, the Host's guarded time, logging what was found; the refusal carries
/// the reason's registered code.
fn qualify_volume(
    volume: &permguard_host::storage::volume::Volume,
    storage: &permguard_core::volume::VolumeConfig,
    profile: permguard_core::assurance::AssuranceProfile,
    now: i64,
) -> Result<permguard_host::storage::qualify::Standing> {
    use permguard_host::storage::{probe, qualify};

    let state = volume
        .host()
        .subdir("state", true)
        .context("opening the state directory the probe works in")?;
    let report = probe::probe(
        &state,
        &probe::Request {
            floors: storage.floors,
            reserve_bytes: 0,
        },
    )?;
    let tuple = qualify::running_tuple(&report.identity, storage);
    let standing = qualify::qualify(&report.identity, storage, profile, now)?;
    tracing::info!(
        event.name = "volume.qualified",
        qualification = standing.as_str(),
        evidence = standing.evidence().unwrap_or(""),
        storage_class = %tuple.storage_class,
        driver = %tuple.driver,
        filesystem = %tuple.filesystem,
        version = %tuple.version,
        device = %report.identity.device,
        "the volume passed the probe"
    );
    if !matches!(standing, qualify::Standing::Qualified { .. }) {
        tracing::warn!(
            event.name = "volume.unqualified",
            code = permguard_core::codes::storage::UNQUALIFIED,
            qualification = standing.as_str(),
            "the volume is not qualified: accepted below `production`, or under its published \
             compatibility mode, and never under `regulated`"
        );
    }
    Ok(standing)
}

/// The most bytes a witness file holds: `sha256:`, 64 hex characters, and room for line ends.
const WITNESS_FILE_MAX_BYTES: u64 = 128;

/// The Host identity's witness on `volume`, checked against `config` before anything is written
/// to the volume — the key-encryption key's witness included (WP-3.2): a replaced or rolled-back
/// volume, or one never provisioned where the profile requires it, is refused first.
fn identity_witness_checked(
    config: &Config,
    volume: &permguard_host::storage::volume::Volume,
) -> Result<Option<String>> {
    use permguard_core::assurance::{AssuranceProfile, Control};

    let assurance = config.assurance();
    let witness = permguard_host::identity::witness_of(volume)
        .map_err(|error| anyhow::anyhow!("{error}"))
        .context("reading the Host identity's INIT")?;
    // The witness from its file, when the orchestrator mounts one per replica: a file not there
    // yet is a witness not recorded yet, said below as one. A witness is a line: a file that is
    // not a regular one, or longer than one, holds none.
    let from_file = match config.host_identity_witness_file() {
        Some(path) => match std::fs::metadata(path) {
            Ok(meta) if !meta.is_file() || meta.len() > WITNESS_FILE_MAX_BYTES => bail!(
                "`host.identity.witness_file` {} is not a file holding one witness",
                path.display()
            ),
            Ok(_) => Some(
                std::fs::read_to_string(path)
                    .with_context(|| {
                        format!("reading `host.identity.witness_file` {}", path.display())
                    })?
                    .trim()
                    .to_owned(),
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "reading `host.identity.witness_file` {}: {error}",
                    path.display()
                ));
            }
        },
        None => None,
    };
    if let Some(stated) = from_file.as_deref() {
        let hex = stated.strip_prefix("sha256:").unwrap_or_default();
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            bail!(
                "`host.identity.witness_file` holds no witness: `sha256:` and 64 lowercase hex \
                 characters, as `permguard host identity provision` prints it"
            );
        }
    }
    let expected = config.host_identity_witness().or(from_file.as_deref());
    if witness.is_none() && assurance.profile() != AssuranceProfile::Development {
        bail!(
            "the Host identity is not provisioned on {}: under the `{}` profile it is \
             created by `permguard host identity provision --volume <path>` before the first \
             start, which prints the witness to keep outside the volume",
            volume.root().display(),
            assurance.profile()
        );
    }
    match (expected, &witness) {
        (Some(expected), Some(held)) if expected != held => bail!(
            "`host.identity.witness` does not match this volume's identity: the volume was \
             replaced or rolled back, or the witness is another Host's"
        ),
        // The value is not printed here: a witness copied from the volume it is meant to check
        // checks nothing. It is the one recorded at provisioning, outside the volume.
        (None, Some(_)) if assurance.requires(Control::IdentityWitness) => bail!(
            "the `{}` profile requires `host.identity.witness`, the value `permguard host \
             identity provision` printed and the operator kept outside the volume{}",
            assurance.profile(),
            config
                .host_identity_witness_file()
                .map(|path| format!(
                    ", in {}: record it there (a chart prints it in the Pod's `identity` log)",
                    path.display()
                ))
                .unwrap_or_default()
        ),
        _ => {}
    }
    Ok(witness)
}

/// The stream engine as the server composes it: the producers it serves, and the decision and
/// event consumers the ship tasks' ingest keeps (WP-5.3).
type StreamParts = (
    permguard_stream::engine::Served,
    Arc<permguard_stream::engine::Consumer<permguard_decisions::stream::Codec>>,
    Arc<permguard_stream::engine::Consumer<permguard_events::stream::Codec>>,
);

/// The ledgers the member side imports (WP-6.2c2a, owner decision of 2026-10-19): `ledgers[]` of
/// the pull configuration, under a shared consistency mode; `None` when there are none. A ledger
/// whose zone or ledger is not an identifier is left out, said once.
fn import_ledgers(config: &Config) -> Option<Vec<permguard_core::authz::Resource>> {
    if !config.events_pull_mode().is_shared() {
        return None;
    }
    let ledgers: Vec<permguard_core::authz::Resource> = config
        .events_pull_ledgers()
        .iter()
        .filter_map(|held| {
            let named = format!("plane/data/zone/{}/ledger/{}", held.zone, held.ledger);
            match permguard_core::authz::Resource::parse(&named) {
                Ok(resource) => Some(resource),
                Err(error) => {
                    tracing::warn!(
                        event.name = "host.membership.import_ledger_invalid",
                        component = "host",
                        resource = %named,
                        error = %error,
                        "a configured ledger names no resource: it is not imported"
                    );
                    None
                }
            }
        })
        .collect();
    (!ledgers.is_empty()).then_some(ledgers)
}
