// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! App class: the object a binary composes its edition of the product out of.
//!
//! The app owns nothing it could have resolved itself. Identity, build metadata, server host,
//! storage, audit sink, secret store, and services are all handed to it by the binary, which is the
//! only place in a build that names a concrete implementation.
//!
//! What it composes is `permguard-runtime`'s [`Composition`] (the crate boundaries refactoring,
//! RD-15), headless: the app is that composition with the command line that drives it and the
//! adapters of a server, the process's signals, the peer sessions over the Host listener's
//! certificate, the Authority Plane's client and the listeners it publishes.

use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::{Command as ClapCommand, CommandFactory, FromArgMatches};

use permguard_core::{
    AuditSink, BoxFuture, BuildSettings, Catalog, Config, ConfigSection, Metrics, ProductIdentity,
    Realm, RealmConfig, SecretStore, ServerHost, Service, Storage, Value,
};

pub use permguard_offline::{migrate, migrate_on};
use permguard_runtime::Composition;

use crate::banner::Banner;
use crate::command::{
    Action, AuditCommand, Cli, Command, KeysCommand, MigrateCommand, StreamsCommand, VolumeCommand,
};
use crate::{logging, signal};

/// Checks an audit trail and returns what it found, in one line a human reads.
///
/// Registered by the binary for the same reason as everything else: this crate knows that a trail
/// can be verified, and only the composition root knows what the trail is made of.
type AuditVerifier =
    Box<dyn Fn(&Path, Option<&Path>, Option<&Path>) -> Result<String> + Send + Sync>;

/// A content-addressed tree on the volume and the check of its files: what `volume verify` reads.
pub use permguard_host::storage::verify::VerifiedTree;

/// Reads a key ring on disk and returns its public keys as a JWKS document.
///
/// Registered by the binary for the same reason as the verifier: this crate knows a ring's public
/// keys can be exported, and only the composition root knows what a ring on disk is made of.
type KeysExporter = Box<dyn Fn(&Path) -> Result<String> + Send + Sync>;

/// A composed command-line application: one identity, one command set, one set of collaborators.
pub struct App {
    /// The Host as this build composes it, with a server's adapters.
    composition: Composition,
    audit_verifier: Option<AuditVerifier>,
    verified_trees: Vec<VerifiedTree>,
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
            composition: Composition::new(identity, build_settings, server, storage, audit)
                // A server owns its process: it stops on the process's signals and reloads on a
                // hangup.
                .with_process_shutdown(signal::process_shutdown)
                .with_hangup_listener(signal::on_hangup)
                // How this Host, as a member, reaches its coordinators: over the Host listener's
                // own certificate, verifying them against its client CA; without one, a join is
                // refused.
                .with_peer_connector(|config, session| {
                    permguard_client::peer::connector(config.admin_tls().as_ref(), session)
                })
                // The Authority Plane's key set and lists, fetched by the client library's
                // Authority surface over the transport the source's scheme names (RD-11).
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
                })
                // Every listener and what it demands of its clients (WP-2.11).
                .with_listeners(crate::plane::listeners::listeners),
            audit_verifier: None,
            verified_trees: Vec::new(),
            keys_exporter: None,
        }
    }

    /// Supplies how this build checks an audit trail.
    ///
    /// A build that registers none says so when asked, rather than reporting a trail as sound
    /// because nothing looked at it.
    pub fn with_audit_verifier<F>(mut self, verifier: F) -> Self
    where
        F: Fn(&Path, Option<&Path>, Option<&Path>) -> Result<String> + Send + Sync + 'static,
    {
        self.audit_verifier = Some(Box::new(verifier));

        self
    }

    /// Supplies the content-addressed trees the planes keep, which `volume verify` checks beside
    /// every journal of the storage library.
    pub fn with_verified_trees(mut self, trees: Vec<VerifiedTree>) -> Self {
        self.verified_trees = trees;

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

    /// Stamps this application's identity and version onto a `clap` command.
    ///
    /// A build that defines its own parser calls this so its usage text, description, and `--version`
    /// match the product it actually is.
    pub fn decorate(&self, command: ClapCommand) -> ClapCommand {
        // `bin_name` too: clap otherwise names the program after `argv[0]`, `<name>.exe` on
        // Windows, in some help and not in the rest.
        command
            .name(self.identity().binary_name())
            .bin_name(self.identity().binary_name())
            .about(self.identity().about())
            .version(self.build_settings().version())
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
                eprintln!("{}: {error:#}", self.identity().binary_name());

                exit_code_of(&error)
            }
        }
    }

    /// Builds the config, installs the log subscriber it asks for, then runs the action.
    ///
    /// Installing a subscriber is a process-global effect, so it happens here and only here: this is
    /// the path a process takes exactly once. [`App::dispatch`] deliberately does not do it, because a
    /// test or a downstream command may take that path more than once in the same process.
    async fn run_action(&self, action: &Action) -> Result<()> {
        // `drain` is a signal and nothing else: no configuration to read, no log pipeline to start,
        // so nothing in the container's environment can stop a `preStop` hook from asking.
        if let Action::Named(Command::Drain { pid, wait }) = action {
            let mut out = io::stdout();
            crate::prestop::drain(*pid, std::time::Duration::from_secs(*wait), &mut out).await?;
            out.flush().context("flushing standard output")?;
            return Ok(());
        }
        let config = self.config_for(action)?;

        // Held for the whole run: dropping it flushes and shuts down the
        // OTLP pipeline, when one was turned on.
        let _telemetry = logging::install(&config)?;
        logging::count_drops_into(self.metrics().clone());

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
        if let Action::Named(Command::Drain { pid, wait }) = action {
            return crate::prestop::drain(*pid, std::time::Duration::from_secs(*wait), out).await;
        }
        let config = self.config_for(action)?;

        self.execute(action, &config, out).await
    }

    /// Runs one action against a config that has already been built.
    async fn execute(&self, action: &Action, config: &Config, out: &mut dyn Write) -> Result<()> {
        match action {
            Action::Serve(args) => {
                self.composition
                    .serve(config, args.config_file(), out)
                    .await
            }
            Action::Named(Command::Version) => self.version(config, out),
            Action::Named(Command::Audit {
                what:
                    AuditCommand::Verify {
                        directory,
                        keys,
                        checkpoint,
                    },
            }) => self.verify_audit(directory, keys.as_deref(), checkpoint.as_deref(), out),
            Action::Named(Command::Keys {
                what: KeysCommand::Export { directory },
            }) => self.export_keys(directory, out),
            Action::Named(Command::Streams {
                what: StreamsCommand::Verify { directory, keys },
            }) => verify_streams(directory, keys, out),
            Action::Named(Command::Volume {
                what:
                    VolumeCommand::Claim {
                        volume,
                        generation,
                        next,
                        create,
                    },
            }) => match (generation, next) {
                (Some(generation), false) => claim_volume(volume, *generation, out),
                _ => advance_volume_claim(volume, *create, out),
            },
            Action::Named(Command::Volume {
                what: VolumeCommand::Verify { volume, sample },
            }) => verify_volume(volume, *sample, &self.verified_trees, out),
            Action::Named(Command::Migrate {
                what: MigrateCommand::Events { volume, backup, .. },
            }) => crate::legacy_events::migrate_events(
                volume,
                backup,
                config.working_dir(),
                &config.events_directory(),
                crate::legacy_events::bounds_of(config),
                out,
            ),
            Action::Named(Command::Migrate { what }) => migrate(what, out),
            Action::Named(Command::Drain { pid, wait }) => {
                crate::prestop::drain(*pid, std::time::Duration::from_secs(*wait), out).await
            }
        }
    }

    /// Checks an audit trail and reports what verifying it found.
    fn verify_audit(
        &self,
        directory: &Path,
        keys: Option<&Path>,
        checkpoint: Option<&Path>,
        out: &mut dyn Write,
    ) -> Result<()> {
        let verifier = self
            .audit_verifier
            .as_ref()
            .context("this build cannot check an audit trail")?;

        let summary = verifier(directory, keys, checkpoint)
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

    /// Builds the effective config for one action, from every precedence layer.
    ///
    /// Every action shares the same layered config, so a command added later needs no loading logic
    /// of its own: it declares which layers it contributes and reads the result.
    pub fn config_for(&self, action: &Action) -> Result<Config> {
        let file = match action {
            Action::Serve(args) => Some(args.config_file()),
            // The offline archive of the legacy event history reads the server's configuration as
            // the server does (WP-6.2d): where the history is, and what it is measured against.
            Action::Named(Command::Migrate {
                what: MigrateCommand::Events { config, .. },
            }) => Some(config.as_path()),
            Action::Named(_) => None,
        };

        self.composition.config_from(file, action.setting_inputs())
    }

    /// Runs the value-only `version` path: short banner, then the version. The server host stays idle.
    fn version(&self, config: &Config, out: &mut dyn Write) -> Result<()> {
        let banner = Banner::new(self.identity(), config);

        write!(out, "{}", banner.render_short()).context("writing the short banner")?;
        writeln!(out, "{}", config.version()).context("writing the version")?;

        Ok(())
    }
}

/// `streams verify <dir> --keys <file>` (WP-5.7c): the report, and a [`NegativeCheck`] when a
/// check found an alteration.
fn verify_streams(directory: &Path, keys: &Path, out: &mut dyn Write) -> Result<()> {
    let descriptors = [
        permguard_decisions::stream::descriptor(),
        permguard_events::stream::descriptor(),
    ];
    let text = std::fs::read_to_string(keys)
        .with_context(|| format!("reading the keys in {}", keys.display()))?;
    // Both streams are signed under one ring, `data.attest`.
    debug_assert!(
        descriptors
            .iter()
            .all(|descriptor| descriptor.ring == descriptors[0].ring)
    );
    let keys = permguard_stream::engine::verify::Keys::from_document(&text, descriptors[0].ring)
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("reading the keys in {}", keys.display()))?;
    let report = permguard_stream::engine::verify::verify_directory(directory, &keys, &descriptors)
        .map_err(|error| anyhow::anyhow!("{error}"))
        .with_context(|| format!("checking the stream in {}", directory.display()))?;
    writeln!(out, "{}", report.render()).context("writing the result")?;
    if !report.sound() {
        return Err(anyhow::Error::new(crate::command::NegativeCheck(format!(
            "the stream in {} does not verify: {} finding(s)",
            directory.display(),
            report.findings.len()
        ))));
    }
    Ok(())
}

/// The exit status of a failed run: an incomplete drain is its own status, `75`, so an
/// orchestrator never reads it as clean and never as an ordinary failure; a completed negative
/// check is `2`; anything else is `1`.
pub fn exit_code_of(error: &anyhow::Error) -> ExitCode {
    if error.chain().any(|cause| {
        cause
            .downcast_ref::<crate::command::NegativeCheck>()
            .is_some()
    }) {
        return ExitCode::from(2);
    }
    if error.chain().any(|cause| {
        cause
            .downcast_ref::<permguard_core::IncompleteDrain>()
            .is_some()
    }) {
        return ExitCode::from(permguard_core::EXIT_DRAIN_INCOMPLETE);
    }

    ExitCode::FAILURE
}

/// Records a new claim generation on the volume at `root`, as the orchestrator or the operator asks.
fn claim_volume(root: &Path, generation: u64, out: &mut dyn Write) -> Result<()> {
    let previous = permguard_host::storage::volume::set_claim(root, generation)
        .with_context(|| format!("claiming the volume at {}", root.display()))?;

    writeln!(
        out,
        "the volume at {} is claimed at generation {generation} (was {previous})",
        root.display()
    )
    .context("writing the result")?;

    Ok(())
}

/// Moves the claim of the volume at `root` one generation forward (TD-1).
fn advance_volume_claim(root: &Path, create: bool, out: &mut dyn Write) -> Result<()> {
    let advanced = permguard_host::storage::volume::advance_claim(root, create)
        .with_context(|| format!("claiming the volume at {}", root.display()))?;
    let id: String = advanced
        .volume_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    // The volume's id is printed too: a drain receipt names it, and the drain controller binds the
    // receipt to the volume this line says was claimed (TD-2).
    writeln!(
        out,
        "the volume at {} (id {id}) is claimed at generation {} (was {})",
        root.display(),
        advanced.generation,
        advanced.previous
    )
    .context("writing the result")?;

    Ok(())
}

/// Checks the volume at `root` offline, every journal of the storage library and every tree the
/// planes declare, and fails when anything is found. Holds the volume's lock throughout, so it never
/// reads beside a process that writes.
/// A path from the configuration file, resolved against the file's own directory when relative:
/// a key set travels with the file that names it, as a realm file does.
fn verify_volume(
    root: &Path,
    sample: Option<u16>,
    trees: &[VerifiedTree],
    out: &mut dyn Write,
) -> Result<()> {
    use permguard_host::storage::verify::{self, Budget, Mode};

    let held = permguard_host::storage::volume::hold(root)
        .with_context(|| format!("holding the volume at {}", root.display()))?;
    let mode = match sample {
        None => Mode::Full,
        Some(per_mille) => Mode::Sample {
            per_mille,
            seed: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs()),
        },
    };
    let report = verify::volume(
        root,
        Some(held.generation()),
        trees,
        mode,
        &mut Budget::unbounded(),
    )
    .with_context(|| format!("verifying the volume at {}", root.display()))?;
    for finding in &report.findings {
        writeln!(out, "{}: {}", finding.path.display(), finding.what)
            .context("writing a finding")?;
    }
    writeln!(
        out,
        "{} files and {} bytes checked, {} findings",
        report.files_checked,
        report.bytes_read,
        report.findings.len()
    )
    .context("writing the result")?;
    if !report.findings.is_empty() {
        bail!(
            "the volume at {} holds {} damaged files; nothing was repaired",
            root.display(),
            report.findings.len()
        );
    }

    Ok(())
}
