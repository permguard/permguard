// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! App class: the object a binary composes its edition of the product out of.
//!
//! The app owns nothing it could have resolved itself. Identity, build metadata, server host,
//! storage, audit sink, secret store, and services are all handed to it by the binary, which is the
//! only place in a build that names a concrete implementation.

use std::env;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::{Command as ClapCommand, CommandFactory, FromArgMatches};

use permguard_core::{
    AuditRecorder, AuditSink, BoxFuture, BuildSettings, Catalog, Config, ConfigFile, ConfigSection,
    KeyManager, Layers, LogFormat, Metrics, ProductIdentity, Pseudonymizer, Realm, RealmConfig,
    Realms, SecretStore, ServerContext, ServerHost, Service, Storage, Value,
};

use crate::banner::Banner;
use crate::command::{Action, AuditCommand, Cli, Command, KeysCommand};
use crate::signal::ReloadHandler;
use crate::{logging, signal, witness};

/// Turns one configuration-file section into settings of the configuration-file layer.
type SectionReader = Box<dyn Fn(&Value) -> Result<Vec<(String, String)>> + Send + Sync>;

/// Builds the privacy policy from the key and key version the effective configuration named.
///
/// It is a factory rather than a composed instance because the key is configuration, and the app is
/// composed before any configuration has been read. The binary still names the concrete type — the
/// closure it passes is the only place that does — so the composition root keeps its job.
type PseudonymizerFactory = Box<dyn Fn(&[u8], &str) -> Box<dyn Pseudonymizer> + Send + Sync>;

/// Builds the secret store the effective configuration names.
///
/// A factory for the same reason as the pseudonymiser: where secrets live is configuration, and the
/// app is composed before any configuration has been read. The binary still names the type.
type SecretStoreFactory =
    Box<dyn Fn(&Config) -> Result<Option<Box<dyn SecretStore>>> + Send + Sync>;

/// Builds the key ring the effective configuration names.
///
/// It hands back an `Arc` rather than a `Box` because a key ring is maintained by work that outlives
/// any single call — see [`ServerContext::with_keys`](permguard_core::ServerContext::with_keys).
type KeyManagerFactory = Box<dyn Fn(&Config) -> Result<Option<Arc<dyn KeyManager>>> + Send + Sync>;

/// Builds the catalog of zones and ledgers a deployment keeps, from its effective configuration.
type CatalogFactory = Box<dyn Fn(&Config) -> Result<Option<Arc<dyn Catalog>>> + Send + Sync>;

/// Builds a plane's signing ring — a separate ring from the one sealing the audit trail, on
/// purpose. The control plane's signs what it serves (git-like head statements today); the data
/// plane's will sign the decision responses it returns.
type PlaneSigningKeysFactory =
    Box<dyn Fn(&Config) -> Result<Option<Arc<dyn KeyManager>>> + Send + Sync>;

/// Builds the audit destination the effective configuration names.
///
/// Returning nothing means "the one this app was composed with", so a build that offers a choice of
/// destinations and a build that has exactly one are the same code path.
///
/// It is handed the key ring because a destination may want to sign what it writes — the file trail
/// seals its head with it — and the ring is composed by the same pass.
type AuditSinkFactory = Box<
    dyn Fn(&Config, Option<&Arc<dyn KeyManager>>) -> Result<Option<Arc<dyn AuditSink>>>
        + Send
        + Sync,
>;

/// Builds one realm — its keys, its trail, its pseudonymisation — from its resolved configuration.
///
/// A single factory rather than one per collaborator, because a realm is those collaborators wired to
/// its own directories, and assembling them is exactly the concrete-construction work that belongs in
/// the composition root and nowhere else. The app calls it once per realm the file declares and puts
/// the results in a registry; it never names a key manager or a sink itself.
type RealmFactory = Box<dyn Fn(&Config, &RealmConfig) -> Result<Realm> + Send + Sync>;

/// Checks an audit trail and returns what it found, in one line a human reads.
///
/// Registered by the binary for the same reason as everything else: this crate knows that a trail
/// can be verified, and only the composition root knows what the trail is made of.
type AuditVerifier = Box<dyn Fn(&Path, Option<&Path>) -> Result<String> + Send + Sync>;

/// Reads a key ring on disk and returns its public keys as a JWKS document.
///
/// Registered by the binary for the same reason as the verifier: this crate knows a ring's public
/// keys can be exported, and only the composition root knows what a ring on disk is made of.
type KeysExporter = Box<dyn Fn(&Path) -> Result<String> + Send + Sync>;

/// The shortest key material worth deriving anything from.
///
/// Sixteen bytes is the floor, not the recommendation: what belongs in that secret is 32 random
/// bytes. Checked against what the store returned, not against what configuration said, because
/// configuration no longer knows.
const MINIMUM_KEY_LENGTH: usize = 16;

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

/// A composed command-line application: one identity, one command set, one set of collaborators.
pub struct App {
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
    pseudonymizer_factory: Option<PseudonymizerFactory>,
    shutdown_factory: Option<ShutdownFactory>,
    secrets_factory: Option<SecretStoreFactory>,
    keys_factory: Option<KeyManagerFactory>,
    catalog_factory: Option<CatalogFactory>,
    control_signing_keys_factory: Option<PlaneSigningKeysFactory>,
    data_signing_keys_factory: Option<PlaneSigningKeysFactory>,
    audit_factory: Option<AuditSinkFactory>,
    realm_factory: Option<RealmFactory>,
    audit_verifier: Option<AuditVerifier>,
    keys_exporter: Option<KeysExporter>,
    reload_handler: Option<ReloadHandler>,
    provisioner: Option<Provisioner>,
    declared_settings: Vec<String>,
    claimed_sections: Vec<String>,
    section_readers: Vec<(String, SectionReader)>,
    section_parsers: Vec<(&'static str, SectionParser)>,
}

impl App {
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
            pseudonymizer_factory: None,
            shutdown_factory: None,
            secrets_factory: None,
            keys_factory: None,
            catalog_factory: None,
            control_signing_keys_factory: None,
            data_signing_keys_factory: None,
            audit_factory: None,
            realm_factory: None,
            audit_verifier: None,
            keys_exporter: None,
            reload_handler: None,
            provisioner: None,
            declared_settings: Vec::new(),
            claimed_sections: Vec::new(),
            section_readers: Vec::new(),
            section_parsers: Vec::new(),
        }
    }

    /// Adds the secret store this build resolves secret material from.
    pub fn with_secrets(mut self, secrets: Box<dyn SecretStore>) -> Self {
        self.secrets = Some(secrets);

        self
    }

    /// Supplies the pseudonymiser this build uses when the configuration turns pseudonymisation on.
    ///
    /// A build that registers none and is then asked to pseudonymise refuses to start, rather than
    /// recording less carefully than it was told to.
    /// Installs somewhere for the numbers this process records about itself to go.
    ///
    /// Without one, every measurement in every crate is a branch and a return, and `/metrics`
    /// publishes liveness and readiness alone. Which registry it is, is a decision for the
    /// composition root, exactly like the audit sink and the key ring.
    pub fn with_metrics(mut self, metrics: Metrics) -> Self {
        self.metrics = metrics;

        self
    }

    pub fn with_pseudonymizer_factory<F>(mut self, factory: F) -> Self
    where
        F: Fn(&[u8], &str) -> Box<dyn Pseudonymizer> + Send + Sync + 'static,
    {
        self.pseudonymizer_factory = Some(Box::new(factory));

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
        F: Fn(&Config) -> Result<Option<Arc<dyn KeyManager>>> + Send + Sync + 'static,
    {
        self.keys_factory = Some(Box::new(factory));

        self
    }

    /// Supplies how this build keeps zones and ledgers.
    /// Names how the control plane's signing ring is built.
    pub fn with_control_signing_keys_factory<F>(mut self, factory: F) -> Self
    where
        F: Fn(&Config) -> Result<Option<Arc<dyn KeyManager>>> + Send + Sync + 'static,
    {
        self.control_signing_keys_factory = Some(Box::new(factory));

        self
    }

    /// Names how the data plane's signing ring is built.
    pub fn with_data_signing_keys_factory<F>(mut self, factory: F) -> Self
    where
        F: Fn(&Config) -> Result<Option<Arc<dyn KeyManager>>> + Send + Sync + 'static,
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
        F: Fn(&Config, Option<&Arc<dyn KeyManager>>) -> Result<Option<Arc<dyn AuditSink>>>
            + Send
            + Sync
            + 'static,
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

    /// Supplies how this build checks an audit trail.
    ///
    /// A build that registers none says so when asked, rather than reporting a trail as sound
    /// because nothing looked at it.
    pub fn with_audit_verifier<F>(mut self, verifier: F) -> Self
    where
        F: Fn(&Path, Option<&Path>) -> Result<String> + Send + Sync + 'static,
    {
        self.audit_verifier = Some(Box::new(verifier));

        self
    }

    /// Supplies how this build exports a key ring's public keys as a JWKS document.
    ///
    /// A build that registers none says so when asked, rather than pretending it cannot reach a ring
    /// it simply was not told how to read.
    pub fn with_keys_exporter<F>(mut self, exporter: F) -> Self
    where
        F: Fn(&Path) -> Result<String> + Send + Sync + 'static,
    {
        self.keys_exporter = Some(Box::new(exporter));

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

    /// Stamps this application's identity and version onto a `clap` command.
    ///
    /// A build that defines its own parser calls this so its usage text, description, and `--version`
    /// match the product it actually is.
    pub fn decorate(&self, command: ClapCommand) -> ClapCommand {
        command
            .name(self.identity.binary_name())
            .about(self.identity.about())
            .version(self.build_settings.version())
    }

    /// Parses this application's own command set, exiting the process on a usage error.
    pub fn parse(&self) -> Cli {
        let matches = self.decorate(Cli::command()).get_matches();

        match Cli::from_arg_matches(&matches) {
            Ok(cli) => cli,
            Err(error) => error.exit(),
        }
    }

    /// Parses the command line and runs what it resolved to, mapping the outcome to an exit code.
    pub async fn run(self) -> ExitCode {
        let action = match self.parse().action() {
            Some(action) => action,
            None => Cli::command()
                .error(
                    clap::error::ErrorKind::MissingRequiredArgument,
                    "a configuration file is required to start the server",
                )
                .exit(),
        };

        match self.run_action(&action).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{}: {error:#}", self.identity.binary_name());

                ExitCode::FAILURE
            }
        }
    }

    /// Builds the config, installs the log subscriber it asks for, then runs the action.
    ///
    /// Installing a subscriber is a process-global effect, so it happens here and only here: this is
    /// the path a process takes exactly once. [`App::dispatch`] deliberately does not do it, because a
    /// test or a downstream command may take that path more than once in the same process.
    async fn run_action(&self, action: &Action) -> Result<()> {
        let config = self.config_for(action)?;

        // Held for the whole run: dropping it flushes and shuts down the
        // OTLP pipeline, when one was turned on.
        let _telemetry = logging::install(&config)?;

        let mut out = io::stdout();

        self.execute(action, &config, &mut out).await?;
        out.flush().context("flushing standard output")?;

        Ok(())
    }

    /// Runs one action, writing whatever it produces to standard output.
    ///
    /// The output stream is not held locked across the run: the log subscriber writes to the same
    /// stream, possibly from another thread, and a lock held for the whole run would block it.
    pub async fn dispatch(&self, action: &Action) -> Result<()> {
        let mut out = io::stdout();

        self.dispatch_to(action, &mut out).await?;
        out.flush().context("flushing standard output")?;

        Ok(())
    }

    /// Runs one action against a caller-provided output stream.
    pub async fn dispatch_to(&self, action: &Action, out: &mut dyn Write) -> Result<()> {
        let config = self.config_for(action)?;

        self.execute(action, &config, out).await
    }

    /// Runs one action against a config that has already been built.
    async fn execute(&self, action: &Action, config: &Config, out: &mut dyn Write) -> Result<()> {
        match action {
            Action::Serve(args) => self.serve(config, args.config_file(), out).await,
            Action::Named(Command::Version) => self.version(config, out),
            Action::Named(Command::Audit {
                what: AuditCommand::Verify { directory, keys },
            }) => self.verify_audit(directory, keys.as_deref(), out),
            Action::Named(Command::Keys {
                what: KeysCommand::Export { directory },
            }) => self.export_keys(directory, out),
        }
    }

    /// Checks an audit trail and reports what verifying it found.
    fn verify_audit(
        &self,
        directory: &Path,
        keys: Option<&Path>,
        out: &mut dyn Write,
    ) -> Result<()> {
        let verifier = self
            .audit_verifier
            .as_ref()
            .context("this build cannot check an audit trail")?;

        let summary = verifier(directory, keys)
            .with_context(|| format!("checking the audit trail in {}", directory.display()))?;

        writeln!(out, "{summary}").context("writing the result")?;

        Ok(())
    }

    /// Prints a key ring's public keys as a JWKS document.
    fn export_keys(&self, directory: &Path, out: &mut dyn Write) -> Result<()> {
        let exporter = self
            .keys_exporter
            .as_ref()
            .context("this build cannot export a key ring")?;

        let document = exporter(directory)
            .with_context(|| format!("exporting the key ring in {}", directory.display()))?;

        writeln!(out, "{document}").context("writing the key set")?;

        Ok(())
    }

    /// Assembles the context the server host and its services run against.
    ///
    /// Public because a command a downstream build adds needs the same context the `serve` command
    /// gets, without reassembling it by hand.
    pub fn context<'a>(
        &'a self,
        config: &'a Config,
        pseudonymizer: Option<&'a dyn Pseudonymizer>,
        secrets: Option<&'a dyn SecretStore>,
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

        if let Some(secrets) = secrets.or(self.secrets.as_deref()) {
            context = context.with_secrets(secrets);
        }

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
    pub fn audit_for(
        &self,
        config: &Config,
        keys: Option<&Arc<dyn KeyManager>>,
    ) -> Result<Arc<dyn AuditSink>> {
        let chosen = match &self.audit_factory {
            Some(factory) => factory(config, keys)?,
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

    /// Builds the control plane's signing ring, when this build composes one.
    pub fn control_signing_keys_for(&self, config: &Config) -> Result<Option<Arc<dyn KeyManager>>> {
        match &self.control_signing_keys_factory {
            Some(factory) => factory(config),
            None => Ok(None),
        }
    }

    /// Builds the data plane's signing ring, when this build composes one.
    pub fn data_signing_keys_for(&self, config: &Config) -> Result<Option<Arc<dyn KeyManager>>> {
        match &self.data_signing_keys_factory {
            Some(factory) => factory(config),
            None => Ok(None),
        }
    }

    /// Builds the key ring the effective configuration names.
    pub fn keys_for(&self, config: &Config) -> Result<Option<Arc<dyn KeyManager>>> {
        if !config.keys_enabled() {
            return Ok(None);
        }

        let factory = self
            .keys_factory
            .as_ref()
            .context("signing keys are enabled but this build composes no key manager")?;

        factory(config)
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

    /// Builds the privacy policy the effective configuration asks for.
    ///
    /// Returns nothing when pseudonymisation is off, which is the default: principals then reach a
    /// sink masked. Fails when it is on and this build has no pseudonymiser to satisfy it.
    pub fn pseudonymizer_for(
        &self,
        config: &Config,
        secrets: Option<&dyn SecretStore>,
    ) -> Result<Option<Box<dyn Pseudonymizer>>> {
        if !config.audit_pseudonym_enabled() {
            return Ok(None);
        }

        let factory = self.pseudonymizer_factory.as_ref().context(
            "audit pseudonymisation is enabled but this build composes no pseudonymiser",
        )?;

        let reference = config
            .audit_pseudonym_key_ref()
            .context("audit pseudonymisation is enabled but names no secret")?;
        let secrets = secrets
            .context("audit pseudonymisation is enabled but this build resolved no secret store")?;

        // The reference is safe to name in an error; the material it resolves to never is.
        let key = secrets.resolve(reference).with_context(|| {
            format!(
                "resolving the audit pseudonymisation key `{}` from the {} secret store",
                reference.name(),
                secrets.name()
            )
        })?;

        if key.expose().len() < MINIMUM_KEY_LENGTH {
            bail!(
                "the secret `{}` is shorter than {MINIMUM_KEY_LENGTH} bytes, which is too short to \
                 derive pseudonyms from",
                reference.name()
            );
        }

        Ok(Some(factory(
            key.expose(),
            config.audit_pseudonym_key_version(),
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
    pub fn config_for(&self, action: &Action) -> Result<Config> {
        let file = match action {
            Action::Serve(args) => Some((args.config_file(), self.load(args.config_file())?)),
            Action::Named(_) => None,
        };

        let file_inputs = match &file {
            Some((path, parsed)) => self.file_inputs(path, parsed)?,
            None => Vec::new(),
        };

        let mut config = Config::from_layers(
            self.build_settings,
            self.declared_settings.clone(),
            Layers::new()
                .with_file(file_inputs)
                .with_environment(env::vars())
                .with_command_line(action.setting_inputs()),
        )?;

        // Realms are structured, not flat settings, so they are attached here rather than merged
        // through the layered pipeline above. They come only from the file today; a database is the
        // same seam tomorrow. Resolution against the server's values happens inside `with_realms`.
        // Anything else structured — the servers a mirroring plane follows — arrives through
        // `with_structured_section`, claimed by whoever owns the section.
        if let Some((path, parsed)) = &file {
            config = config
                .with_realms(parsed.realms())
                .with_context(|| format!("in the configuration file {}", path.display()))?;
        }

        match &file {
            Some((path, parsed)) => self.apply_sections(config, path, parsed),
            None => Ok(config),
        }
    }

    /// Reads and parses the configuration file, rejecting sections nothing in this build accounts for.
    fn load(&self, config_file: &Path) -> Result<ConfigFile> {
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
    async fn serve(&self, config: &Config, config_file: &Path, out: &mut dyn Write) -> Result<()> {
        // First, before anything that takes time. Preparing a volume generates keys and writes them
        // down, and a stop signal that arrives while that is happening is a stop signal the process
        // has to survive — the alternative is dying where it stands, halfway through writing the
        // material it will be asked for on the next start. What this resolves to is awaited far
        // below; that it is listening starts here.
        let shutdown = match &self.shutdown_factory {
            Some(factory) => factory(),
            None => signal::process_shutdown(),
        };

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

        if config.log_format() == LogFormat::Terminal {
            let banner = Banner::new(&self.identity, config);

            write!(out, "{}", banner.render_full()).context("writing the startup banner")?;
            out.flush().context("flushing the startup banner")?;
        }

        // The store is built first: everything that needs a secret needs it to exist.
        let resolved = self.secrets_for(config)?;
        let secrets = resolved.as_deref().or(self.secrets.as_deref());
        let pseudonymizer: Option<Arc<dyn Pseudonymizer>> =
            self.pseudonymizer_for(config, secrets)?.map(Arc::from);

        // Before the first record is written, not after: the damage a silent key change does is
        // done by the records made under it.
        witness::check(config, pseudonymizer.as_deref())?;

        let keys = self.keys_for(config)?;
        let audit = self.audit_for(config, keys.as_ref())?;
        let catalog = self.catalog_for(config)?;
        let control_signing_keys = self.control_signing_keys_for(config)?;
        let data_signing_keys = self.data_signing_keys_for(config)?;

        // Every issuer this deployment hosts, each with its own keys and trail, built once here. A
        // plain single-issuer server has none and this is the empty registry.
        let realms = self.realms_for(config)?;

        // The same silent-key-change guard the server just passed, once per realm against its own
        // witness — before any realm record is written, for the same reason.
        for realm in realms.all() {
            witness::check_realm(config, realm)?;
        }

        logging::record_build(&self.identity, config, self.server.name());

        // Registered for exactly as long as the server runs. An app may serve more than once in a
        // process — a test certainly does — and a handler left behind by the previous run would be
        // a second listener for the same signal.
        let hangup = self
            .reload_handler
            .as_ref()
            .map(|handler| signal::on_hangup(Arc::clone(handler)));

        let mut context = self
            .context(config, pseudonymizer.as_deref(), secrets, keys)
            .with_audit(audit.as_ref())
            .with_recorder(self.recorder(&audit, pseudonymizer.as_ref()))
            .with_realms(realms);

        if let Some(catalog) = catalog {
            context = context.with_catalog(catalog);
        }

        if let Some(keys) = control_signing_keys {
            context = context.with_control_signing_keys(keys);
        }

        if let Some(keys) = data_signing_keys {
            context = context.with_data_signing_keys(keys);
        }

        let outcome = self.server.run(&context, shutdown).await;

        if let Some(hangup) = hangup {
            hangup.abort();
        }

        outcome
    }

    /// Runs the value-only `version` path: short banner, then the version. The server host stays idle.
    fn version(&self, config: &Config, out: &mut dyn Write) -> Result<()> {
        let banner = Banner::new(&self.identity, config);

        write!(out, "{}", banner.render_short()).context("writing the short banner")?;
        writeln!(out, "{}", config.version()).context("writing the version")?;

        Ok(())
    }
}
