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
use crate::command::{
    Action, AuditCommand, Cli, Command, KeysCommand, MigrateCommand, VolumeCommand,
};
use crate::signal::ReloadHandler;
use crate::{logging, signal, witness};

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

/// Builds the key ring the effective configuration names.
///
/// It hands back an `Arc` rather than a `Box` because a key ring is maintained by work that outlives
/// any single call — see [`ServerContext::with_keys`](permguard_core::ServerContext::with_keys).
/// Resolves the root `reference` names at the text `version` (`vN`), witnessed on `volume`; the
/// errors name the reference and never the material (WP-3.3).
fn resolve_root(
    secrets: &dyn SecretStore,
    volume: &permguard_host::storage::volume::Volume,
    reference: &permguard_core::SecretRef,
    version: &str,
    what: &str,
    role: &str,
) -> Result<permguard_host::secrets::Root> {
    let version: permguard_host::secrets::KeyVersion = version
        .parse()
        .map_err(|error| anyhow::anyhow!("{error}"))
        .with_context(|| format!("reading the version of {what}"))?;
    let witnesses = permguard_host::secrets::Witnesses::open(volume)
        .map_err(|error| anyhow::anyhow!("{error}"))
        .context("opening the secrets' witnesses")?;
    permguard_host::secrets::resolve(secrets, &witnesses, reference, version, role)
        .map_err(|error| anyhow::anyhow!("{error}"))
        .with_context(|| {
            format!(
                "resolving {what} `{}` from the {} secret store",
                reference.name(),
                secrets.name()
            )
        })
}

/// The PKCS#11 token of the `pkcs11` custody (WP-3.2), when this build has the `pkcs11` feature.
#[cfg(feature = "pkcs11")]
struct Token(Arc<crate::custody::pkcs11::Hsm>);

#[cfg(feature = "pkcs11")]
impl Token {
    fn remote(&self) -> Arc<dyn permguard_host::keys::custody::Remote> {
        Arc::new(crate::custody::pkcs11::SharedHsm(Arc::clone(&self.0)))
    }

    fn kek(
        &self,
        label: &str,
        version: u64,
    ) -> Result<Arc<dyn permguard_host::keys::custody::Wrap>> {
        Ok(Arc::new(crate::custody::pkcs11::HsmKek::open(
            Arc::clone(&self.0),
            label,
            version,
        )?))
    }
}

#[cfg(feature = "pkcs11")]
fn token_for(config: &Config, secrets: Option<&dyn SecretStore>) -> Result<Token> {
    let module = config
        .keys_pkcs11_module()
        .context("the `pkcs11` custody needs `operations.keys.pkcs11.module`")?;
    let label = config
        .keys_pkcs11_token_label()
        .context("the `pkcs11` custody needs `operations.keys.pkcs11.token_label`")?;
    let reference = config
        .keys_pkcs11_pin_ref()
        .context("the `pkcs11` custody needs `operations.keys.pkcs11.pin_ref`")?;
    let secrets = secrets.context(
        "the token PIN is resolved from the secret store, and this build resolved none: set \
         `operations.secrets.provider`",
    )?;
    let pin = secrets
        .resolve(reference)
        .with_context(|| format!("resolving the token PIN `{}`", reference.name()))?;
    let pin = zeroize::Zeroizing::new(
        std::str::from_utf8(pin.expose())
            .context("the token PIN is text")?
            .trim()
            .to_owned(),
    );
    Ok(Token(crate::custody::pkcs11::Hsm::open(
        crate::custody::pkcs11::Token {
            module: std::path::PathBuf::from(module),
            label: label.to_owned(),
            pin,
        },
    )?))
}

/// Without the `pkcs11` feature, no token: the custody is refused by name.
#[cfg(not(feature = "pkcs11"))]
struct Token;

#[cfg(not(feature = "pkcs11"))]
impl Token {
    fn remote(&self) -> Arc<dyn permguard_host::keys::custody::Remote> {
        unreachable!("no token is ever opened without the `pkcs11` feature")
    }

    fn kek(
        &self,
        _label: &str,
        _version: u64,
    ) -> Result<Arc<dyn permguard_host::keys::custody::Wrap>> {
        unreachable!("no token is ever opened without the `pkcs11` feature")
    }
}

#[cfg(not(feature = "pkcs11"))]
fn token_for(_config: &Config, _secrets: Option<&dyn SecretStore>) -> Result<Token> {
    bail!(
        "the `pkcs11` custody needs a build with the `pkcs11` feature; this one was built without \
         it"
    )
}

/// The Vault Transit client of the `kms` custody (WP-3.2): its token from the secret store.
fn transit_for(
    config: &Config,
    secrets: Option<&dyn SecretStore>,
) -> Result<Arc<crate::custody::Transit>> {
    let address = config.keys_kms_address().context(
        "the `kms` custody reaches a Vault, and `operations.keys.kms.address` names none",
    )?;
    let reference = config
        .keys_kms_token_ref()
        .context("the `kms` custody authenticates with `operations.keys.kms.token_ref`")?;
    let secrets = secrets.context(
        "the KMS token is resolved from the secret store, and this build resolved none: set \
         `operations.secrets.provider`",
    )?;
    let token = secrets
        .resolve(reference)
        .with_context(|| format!("resolving the KMS token `{}`", reference.name()))?;
    let token = zeroize::Zeroizing::new(
        std::str::from_utf8(token.expose())
            .context("the KMS token is text")?
            .trim()
            .to_owned(),
    );
    crate::custody::Transit::start(crate::custody::Endpoint {
        address: address.to_owned(),
        mount: config.keys_kms_mount().to_owned(),
        token,
        ca: config.keys_kms_ca(),
    })
}

/// What `authorization_for` opens on the volume (WP-2.4, WP-2.5): the authorization every Plane
/// and the Host listener decide with, the credential mapper, and the grant store the Host API
/// mutates.
struct HostAuthz {
    authorization: Arc<permguard_host::authz::Authorization>,
    authenticator: Arc<dyn permguard_core::authz::Authenticator>,
    store: Arc<permguard_host::authz::GrantStore>,
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

/// Checks an audit trail and returns what it found, in one line a human reads.
///
/// Registered by the binary for the same reason as everything else: this crate knows that a trail
/// can be verified, and only the composition root knows what the trail is made of.
type AuditVerifier = Box<dyn Fn(&Path, Option<&Path>) -> Result<String> + Send + Sync>;

/// What a Plane declares to the Host under a configuration, when the configuration selects it.
type PlaneDeclarationFactory = Box<
    dyn Fn(&Config) -> Option<(&'static str, bool, permguard_host::composition::Declaration)>
        + Send
        + Sync,
>;

/// A content-addressed tree on the volume and the check of its files: what `volume verify` reads.
pub type VerifiedTree = (
    std::path::PathBuf,
    Arc<permguard_host::storage::verify::ObjectCheck>,
);

/// Reads a key ring on disk and returns its public keys as a JWKS document.
///
/// Registered by the binary for the same reason as the verifier: this crate knows a ring's public
/// keys can be exported, and only the composition root knows what a ring on disk is made of.
type KeysExporter = Box<dyn Fn(&Path) -> Result<String> + Send + Sync>;

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
    audit_verifier: Option<AuditVerifier>,
    verified_trees: Vec<VerifiedTree>,
    /// Every subsystem laid out by the storage library this build reads, and at which versions
    /// (WP-1.9): what a volume's manifests are checked against before the server serves.
    layouts: Vec<(&'static str, permguard_host::storage::migrate::Reads)>,
    plane_declarations: Vec<PlaneDeclarationFactory>,
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
            startup_checks: Vec::new(),
            shutdown_factory: None,
            secrets_factory: None,
            keys_factory: None,
            catalog_factory: None,
            control_signing_keys_factory: None,
            data_signing_keys_factory: None,
            audit_factory: None,
            realm_factory: None,
            audit_verifier: None,
            verified_trees: Vec::new(),
            layouts: Vec::new(),
            plane_declarations: Vec::new(),
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

    /// Supplies what a Plane declares to the Host, registered before any service starts: its
    /// handles reach it through [`ServerContext::plane_handles`] and nothing else.
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
        let config = self.config_for(action)?;

        // Held for the whole run: dropping it flushes and shuts down the
        // OTLP pipeline, when one was turned on.
        let _telemetry = logging::install(&config)?;
        logging::count_drops_into(self.metrics.clone());

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
            Action::Named(Command::Volume {
                what: VolumeCommand::Claim { volume, generation },
            }) => claim_volume(volume, *generation, out),
            Action::Named(Command::Volume {
                what: VolumeCommand::Verify { volume, sample },
            }) => verify_volume(volume, *sample, &self.verified_trees, out),
            Action::Named(Command::Migrate { what }) => migrate(what, out),
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
        let provisioner = crate::offline::provisioner(custodian, volume, opened.suite())?;
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

    /// Reads and parses the configuration file, rejecting sections nothing in this build accounts for.
    /// Opens `host/authz/` on the volume, builds the credential mapper from `host.principals[]`
    /// and the bootstrap commitment, and the authorization from the store plus
    /// `host.authz.public[]`. A rule that cannot be honoured, or two that collide, stop the start.
    fn authorization_for(
        &self,
        config: &Config,
        config_file: &Path,
        file: &ConfigFile,
        volume: &permguard_host::storage::volume::Volume,
        time: &Arc<permguard_host::time::TimeGuard>,
        mutations: &permguard_host::operations::mutation::Mutations,
    ) -> Result<HostAuthz> {
        use permguard_host::authz::{
            Authorization, GrantStore, PrincipalMapper, PublicGrant, Rule,
        };

        let auth = file
            .host_auth()
            .with_context(|| format!("in the configuration file {}", config_file.display()))?;
        let (store, recovery) = GrantStore::open(volume).with_context(|| {
            format!(
                "opening the grant store on {}",
                volume.host().path().display()
            )
        })?;
        // A grant mutation a crash left open is committed or failed before anything reads the
        // store; then the expiry of grants past their time, each one operation (WP-3.6).
        let recovered = mutations
            .recover(&permguard_host::operations::grants::Grants(&store))
            .context("recovering the grant mutations a crash left open")?;
        tracing::debug!(
            event.name = "host.mutations_recovered_for",
            domain = permguard_host::operations::grants::DOMAIN,
            "the grant mutations are resolved"
        );
        // An expiry that cannot be written does not stop the start: a grant past its time allows
        // nothing all the same, and the Host reports `degraded: security_mutations` meanwhile.
        let expiry =
            permguard_host::operations::grants::expire_due(mutations, &store, time.now_secs());
        tracing::info!(
            event.name = "authz.opened",
            component = "server",
            grants = store.records().len(),
            revision = store.revision(),
            expired = expiry.expired.len(),
            expiry_unwritten = expiry.unwritten.len(),
            reconciled = recovered.reconciled.len(),
            failed = recovered.failed.len(),
            recovered_truncated_bytes = recovery.truncated_bytes,
            bootstrap = store.bootstrap().is_some(),
            "the grant store is open"
        );
        let rules: Vec<Rule> = auth
            .principals
            .iter()
            .map(|rule| match rule {
                permguard_core::authz::PrincipalRule::SanUri(uri) => Rule::SanUri(uri.clone()),
                permguard_core::authz::PrincipalRule::Spki(digest) => Rule::Spki(digest.clone()),
                permguard_core::authz::PrincipalRule::Oidc(oidc) => {
                    Rule::Oidc(permguard_host::authz::OidcRule {
                        issuer: oidc.issuer.clone(),
                        audience: oidc.audience.clone(),
                        algorithms: oidc.algorithms.clone(),
                        claim: oidc.claim.clone(),
                        jwks_file: resolve_beside(config_file, &oidc.jwks_file),
                        max_stale: oidc.max_stale,
                    })
                }
            })
            .collect();
        let bootstrap = store.bootstrap();
        let mapper = PrincipalMapper::with_time(
            &rules,
            bootstrap.as_ref().map(|held| held.fingerprint.as_str()),
            Arc::clone(time),
        )
        .context("building the credential mapper from host.principals")?;
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
            tracing::info!(
                event.name = "authz.public",
                component = "server",
                grants = public.len(),
                development_mode = config.development_mode(),
                "the configuration declares public grants: what they name needs no credential"
            );
        }
        let authorization =
            Arc::new(Authorization::new(Arc::clone(&store), &public).with_time(Arc::clone(time)));
        tracing::info!(
            event.name = "authz.mapper",
            component = "server",
            rules = mapper.rules(),
            "the credential mapper is built"
        );
        Ok(HostAuthz {
            authorization,
            authenticator: Arc::new(mapper),
            store,
        })
    }

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

        // No subsystem is served while a migration is between two sides, and no layout this build
        // does not read is served at all (WP-1.9): an interrupted migration is landed by its
        // command, a downgrade is possible only where every active layout is understood.
        // The rings' own layouts are always read here: this build lays them out (WP-3.1).
        let mut layouts = self.layouts.clone();
        layouts.extend(permguard_host::keys::migration::layouts());
        permguard_host::storage::migrate::check_servable(&volume, &layouts).with_context(|| {
            format!("checking the layouts on {}", config.working_dir().display())
        })?;

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
        witness::check(config, pseudonymizer.as_deref())?;

        let destination = self.audit_for(config)?;
        // The audit engine (WP-3.5): every record of the process in a trail per (class,
        // resource) under `host/audit/trails`, whatever `audit.destination` says; the sink the
        // destination chose sees every record too, the log stream by default, nothing under
        // `file` (owner decisions of 2026-10-07).
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
        // `access` and `operations` day files older than `audit.retention` go; `security` ones
        // stay until WP-3.7's checkpoints (owner decision of 2026-10-07).
        audit_engine.retain_for(config.audit_retention());
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
        if provisioned {
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
        let control_signing_keys = self
            .control_signing_keys_for(config, &opener)
            .context("opening the control.attest key ring")?;
        let data_signing_keys = self
            .data_signing_keys_for(config, &opener)
            .context("opening the data.attest key ring")?;
        let key_registry = Arc::new(permguard_host::keys::registry::Registry::new(
            Some(Arc::clone(&host_identity)),
            [&keys, &control_signing_keys, &data_signing_keys]
                .into_iter()
                .flatten()
                .cloned()
                .collect(),
        ));
        mutations
            .recover(key_registry.as_ref())
            .context("recovering the key ring mutations a crash left open")?;
        // The memberships (WP-4.1): the store on the volume, whatever surface serves it, so a
        // membership mutation a crash left open is resolved before anything reads it.
        let members = permguard_host::membership::Store::open(&volume).with_context(|| {
            format!(
                "opening the memberships on {}",
                volume.host().path().display()
            )
        })?;
        mutations
            .recover(&permguard_host::membership::Memberships(&members))
            .context("recovering the membership mutations a crash left open")?;
        let keys: Option<Arc<dyn KeyManager>> = keys.map(|ring| ring as Arc<dyn KeyManager>);

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

        let recorder = self.recorder(&audit, pseudonymizer.as_ref());
        let mut context = self
            .context(config, pseudonymizer.as_deref(), keys)
            .with_audit(audit.as_ref())
            .with_realms(realms);
        // An `operations` record the engine could not write degrades the Host's readiness.
        audit_engine.observe(context.health().clone());
        mutations.observe(context.health().clone());

        if let Some(catalog) = catalog {
            context = context.with_catalog(catalog);
        }

        // Bootstrap is behind us: the volume is claimed and the configuration validated, and the
        // Host's own state is opening. No listener is bound yet, so nothing earlier is observable.
        context.health().lifecycle().advance(
            permguard_core::lifecycle::HOST,
            permguard_core::lifecycle::Phase::Load,
        );

        // The authorization store and the credential mapper (WP-2.4): the grants on the volume,
        // what the configuration declares public, and the rules that turn a credential into a
        // principal. Built before the Planes register, since every Plane decides with them.
        let file = self.load(config_file)?;
        let HostAuthz {
            authorization,
            authenticator,
            store: grants,
        } = self.authorization_for(config, config_file, &file, &volume, &time, &mutations)?;
        context = context.with_authenticator(authenticator);

        // The Host API facade (WP-2.5), when the deployment has a Host listener: the replay
        // journal on the volume, the grant store, every ring this process composes and the
        // lifecycle, built once and served by both transports. Without `admin.addr` nothing is
        // opened: a volume without a listener keeps no replay window.
        if config.admin_addr().is_some() {
            use permguard_host::api::{Assurance, Composition, Effective, HostApi, Replay};

            let (replay, recovery) = Replay::open(&volume, time.now_secs()).with_context(|| {
                format!(
                    "opening the replay journal on {}",
                    volume.host().path().display()
                )
            })?;
            let replay = replay.with_time(Arc::clone(&time));
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
            // The task types this Host's Planes act in: none until the Planes declare their task
            // handlers (WP-4.4), so an approval names no task this Host cannot serve.
            let capabilities = permguard_host::membership::Capabilities::default();
            // The appraisal policy configured; no verifier ships, so `attested` is refused until a
            // composition registers one (WP-4.2, owner decision).
            let appraisal = permguard_host::membership::appraisal::Appraisal::new(
                permguard_host::membership::appraisal::Policy::new(
                    config.membership_appraisal_controls().clone(),
                    config.membership_appraisal_max_binding(),
                ),
                permguard_host::membership::appraisal::Verifiers::default(),
            );
            // The open task sessions, shared by the PeerChannel and the sessions route; no task
            // handler is registered until the Planes declare theirs (WP-4.4).
            let tasks = Arc::new(permguard_host::membership::task::Tasks {
                live: Arc::default(),
                appraisal: Arc::new(appraisal.clone()),
                handlers: permguard_host::membership::task::TaskHandlers::default(),
            });
            // What a coordinator serves on a proven session: an enrollment, a manifest fetch, a
            // revocation asked by its member, and its task sessions.
            let coordinating = permguard_host::membership::service::Coordinating {
                store: Arc::clone(&members),
                mutations: Arc::clone(&mutations),
                identity: Arc::clone(&host_identity),
                keys: Arc::clone(&key_registry),
                capabilities: capabilities.clone(),
                time: Arc::clone(&time),
                tasks: Arc::clone(&tasks),
            };
            let session_context = permguard_host::session::Context {
                identity: Arc::clone(&host_identity),
                peers,
                time: Arc::clone(&time),
                declared_assurance: config.assurance().profile(),
                audit: Some(Arc::clone(&audit_engine)),
                metrics: context.metrics().clone(),
                service: Some(Arc::new(coordinating)),
            };
            // How this Host, as a member, reaches its coordinators: over the Host listener's own
            // certificate, verifying them against its client CA; without one, a join is refused.
            let connector = crate::host_api::peer::member_client(config.admin_tls().as_ref())
                .context("building the peer client of the Host listener")?
                .map(|tls| {
                    Arc::new(crate::host_api::peer::PeerConnector::new(
                        session_context.clone(),
                        tls,
                    )) as Arc<dyn permguard_host::membership::member::Connector>
                });
            let api = HostApi::new(Composition {
                authorization: Arc::clone(&authorization),
                store: Some(grants),
                replay,
                keys: Arc::clone(&key_registry),
                health: context.health().clone(),
                // The profile in force, the controls added and the relaxations the values amount
                // to: the block discovery publishes too (WP-2.8).
                assurance: Assurance::of(
                    &config.assurance().report(&config.relaxations_in_force()),
                ),
                effective: Effective::of(config.effective_settings()),
                trail: audit.name().to_owned(),
                mutations: Some(Arc::clone(&mutations)),
                identity: Some(Arc::clone(&host_identity)),
                time: Arc::clone(&time),
                // Peer Host sessions (WP-2.3): the pinned peers and what the listener's
                // configuration amounts to; the PeerChannel refuses when it serves none.
                peer_sessions: permguard_host::api::sessions::PeerSessions {
                    report: config.peer_sessions(),
                    context: Some(session_context.clone()),
                },
                memberships: Some(Arc::new(permguard_host::api::members::MembershipService {
                    store: Arc::clone(&members),
                    capabilities: capabilities.clone(),
                    connector,
                    appraisal,
                    live: Arc::clone(&tasks.live),
                })),
            });
            context = context.with_host_handles(Arc::new(api));
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
        let mut host = permguard_host::composition::Host::builder()
            .audit(recorder)
            .authorization(authorization)
            .time(Arc::clone(&time))
            .host_id(host_identity.host_id());
        // The zone keys this Host holds as coordinator; delivered keys arrive with WP-11.
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
        let host = host.build();
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
    if witness.is_none() && assurance.profile() != AssuranceProfile::Development {
        bail!(
            "the Host identity is not provisioned on {}: under the `{}` profile it is \
             created by `permguard host identity provision --volume <path>` before the first \
             start, which prints the witness to keep outside the volume",
            volume.root().display(),
            assurance.profile()
        );
    }
    match (config.host_identity_witness(), &witness) {
        (Some(expected), Some(held)) if expected != held => bail!(
            "`host.identity.witness` does not match this volume's identity: the volume was \
             replaced or rolled back, or the witness is another Host's"
        ),
        // The value is not printed here: a witness copied from the volume it is meant to check
        // checks nothing. It is the one recorded at provisioning, outside the volume.
        (None, Some(_)) if assurance.requires(Control::IdentityWitness) => bail!(
            "the `{}` profile requires `host.identity.witness`, the value `permguard host \
             identity provision` printed and the operator kept outside the volume",
            assurance.profile()
        ),
        _ => {}
    }
    Ok(witness)
}

/// Each ring's provider from its custody (WP-3.2, owner decisions of 2026-10-08): the
/// key-encryption key of the `file` custody resolved from the secret store and witnessed,
/// with the previous one a rotation leaves behind.
pub(crate) fn custodian_for(
    config: &Config,
    secrets: Option<&dyn SecretStore>,
    volume: &permguard_host::storage::volume::Volume,
) -> Result<Arc<permguard_host::keys::custody::Custodian>> {
    use permguard_core::config::KeyCustody;
    use permguard_host::keys::ring::{CONTROL_ATTEST, DATA_ATTEST, HOST_IDENTITY, HOST_OPERATIONS};

    let custodies: Vec<(&'static str, KeyCustody)> =
        [HOST_IDENTITY, HOST_OPERATIONS, CONTROL_ATTEST, DATA_ATTEST]
            .into_iter()
            .map(|ring| (ring, config.keys_custody_of(ring)))
            .collect();
    let uses = |wanted: KeyCustody| {
        config
            .keys_custodies()
            .iter()
            .any(|(_, custody)| *custody == wanted)
    };
    // The KMS, when a ring or the KEK lives there: one client for both.
    let kms = if uses(KeyCustody::Kms)
        || (uses(KeyCustody::File)
            && config.keys_kek_provider() == permguard_core::config::KekProvider::Kms)
    {
        Some(transit_for(config, secrets)?)
    } else {
        None
    };
    // The PKCS#11 token, when a ring or the KEK lives there.
    let hsm = if uses(KeyCustody::Pkcs11)
        || (uses(KeyCustody::File)
            && config.keys_kek_provider() == permguard_core::config::KekProvider::Pkcs11)
    {
        Some(token_for(config, secrets)?)
    } else {
        None
    };
    let keks = if uses(KeyCustody::File) {
        keks_for(config, secrets, volume, kms.as_ref(), hsm.as_ref())
            .map(Some)
            .map_err(|error| format!("{error:#}"))
    } else {
        Ok(None)
    };
    let mut custodian = permguard_host::keys::custody::Custodian::new(
        move |ring| {
            custodies
                .iter()
                .find(|(held, _)| *held == ring)
                .map_or(KeyCustody::Development, |(_, custody)| *custody)
        },
        keks,
    );
    if let Some(kms) = kms {
        custodian = custodian.with_kms(kms);
    }
    if let Some(hsm) = hsm {
        custodian = custodian.with_hsm(hsm.remote());
    }
    Ok(Arc::new(custodian))
}

/// The key-encryption key of the `file` custody, and the previous one.
fn keks_for(
    config: &Config,
    secrets: Option<&dyn SecretStore>,
    volume: &permguard_host::storage::volume::Volume,
    kms: Option<&Arc<crate::custody::Transit>>,
    hsm: Option<&Token>,
) -> Result<permguard_host::keys::custody::Keks> {
    use permguard_core::config::KekProvider;
    use permguard_host::keys::custody::Wrap as KeyWrap;
    use permguard_host::keys::custody::{Keks, SecretKek};

    match config.keys_kek_provider() {
        KekProvider::Secret => {}
        KekProvider::Kms => {
            let transit = kms.context("the KEK is in the KMS, and no KMS is configured")?;
            let version = |text: &str| -> Result<u64> {
                text.parse::<permguard_host::secrets::KeyVersion>()
                    .map(|version| version.get())
                    .map_err(|error| anyhow::anyhow!("{error}"))
            };
            let reference = config.keys_kek_ref().context(
                "the KEK in the KMS is the Transit key `operations.keys.kek_ref` names, and it \
                 names none",
            )?;
            let current: Arc<dyn KeyWrap> = Arc::new(crate::custody::TransitKek::open(
                Arc::clone(transit),
                reference.name(),
                version(config.keys_kek_version())?,
            )?);
            let previous = match config.keys_previous_kek() {
                Some((reference, previous)) => Some(Arc::new(crate::custody::TransitKek::open(
                    Arc::clone(transit),
                    reference.name(),
                    version(previous)?,
                )?) as Arc<dyn KeyWrap>),
                None => None,
            };
            return Ok(Keks { current, previous });
        }
        KekProvider::Pkcs11 => {
            let token = hsm.context("the KEK is in a PKCS#11 token, and none is configured")?;
            let reference = config.keys_kek_ref().context(
                "the KEK in the token is the AES key `operations.keys.kek_ref` labels, and it \
                 names none",
            )?;
            let version = |text: &str| -> Result<u64> {
                text.parse::<permguard_host::secrets::KeyVersion>()
                    .map(|version| version.get())
                    .map_err(|error| anyhow::anyhow!("{error}"))
            };
            let current = token.kek(reference.name(), version(config.keys_kek_version())?)?;
            let previous = match config.keys_previous_kek() {
                Some((reference, previous)) => {
                    Some(token.kek(reference.name(), version(previous)?)?)
                }
                None => None,
            };
            return Ok(Keks { current, previous });
        }
    }
    let secrets = secrets.context(
        "the `file` custody resolves its key-encryption key from the secret store, and this \
         build resolved none: set `operations.secrets.provider`",
    )?;
    let reference = config.keys_kek_ref().context(
        "the `file` custody seals every private key under a key-encryption key, and \
         `operations.keys.kek_ref` names none",
    )?;
    let kek = |reference: &permguard_core::SecretRef, version: &str, what: &str| {
        let root = resolve_root(secrets, volume, reference, version, what, "key-encryption")?;
        let kek = SecretKek::from_root(reference.name(), &root)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        Ok::<Arc<dyn KeyWrap>, anyhow::Error>(Arc::new(kek))
    };
    let current = kek(
        reference,
        config.keys_kek_version(),
        "the key-encryption key",
    )?;
    let previous = match config.keys_previous_kek() {
        Some((reference, version)) => {
            Some(kek(reference, version, "the previous key-encryption key")?)
        }
        None => None,
    };
    Ok(Keks { current, previous })
}

/// The exit status of a failed run: an incomplete drain is its own status, `75`, so an
/// orchestrator never reads it as clean and never as an ordinary failure; anything else is `1`.
pub fn exit_code_of(error: &anyhow::Error) -> ExitCode {
    if error.chain().any(|cause| {
        cause
            .downcast_ref::<permguard_core::IncompleteDrain>()
            .is_some()
    }) {
        return ExitCode::from(permguard_core::EXIT_DRAIN_INCOMPLETE);
    }

    ExitCode::FAILURE
}

/// `migrate keys` (WP-3.1): every legacy ring with a `ring.json` migrated into `host/keys/<ring>`
/// with the backup declared, offline, holding the volume.
fn migrate_keys(
    volume_root: &std::path::Path,
    backup: &str,
    overrides: &[String],
    out: &mut dyn Write,
) -> Result<()> {
    use permguard_host::keys::migration::{lay_out, needs_migration};
    use permguard_host::keys::ring::{CONTROL_ATTEST, DATA_ATTEST, HOST_OPERATIONS};
    use permguard_host::storage::volume::hold;

    if backup.trim().is_empty() {
        anyhow::bail!("`--backup` names the external backup taken before the migration");
    }
    let mut directories = vec![
        (
            HOST_OPERATIONS,
            volume_root.join("operations/keys/operations"),
        ),
        (CONTROL_ATTEST, volume_root.join("operations/keys/control")),
        (DATA_ATTEST, volume_root.join("operations/keys/data")),
    ];
    for given in overrides {
        let (ring, directory) = given
            .split_once('=')
            .with_context(|| format!("`--legacy {given}` is not `<ring>=<directory>`"))?;
        let held = directories
            .iter_mut()
            .find(|(name, _)| *name == ring)
            .with_context(|| format!("`{ring}` is not a ring with a legacy directory"))?;
        held.1 = std::path::PathBuf::from(directory);
    }
    let volume = hold(volume_root)
        .with_context(|| format!("holding the volume at {}", volume_root.display()))?;
    let now = permguard_host::authz::store::now();
    for (ring, directory) in directories {
        if !needs_migration(&volume, ring, Some(&directory))
            .with_context(|| format!("reading the layout of {ring}"))?
        {
            writeln!(out, "{ring}: nothing to migrate at {}", directory.display())
                .context("writing the result")?;
            continue;
        }
        lay_out(
            &volume,
            ring,
            Some(&directory),
            permguard_core::assurance::AssuranceProfile::Production,
            Some(backup.to_owned()),
            now,
        )
        .with_context(|| format!("migrating the legacy ring of {ring}"))?;
        writeln!(
            out,
            "{ring}: migrated from {} into host/keys/{ring}; the private halves of its retired \
             keys stay in the old directory until `migrate finalize --subsystem {}` removes it",
            directory.display(),
            permguard_host::keys::migration::subsystem(ring)
        )
        .context("writing the result")?;
    }
    Ok(())
}

/// Runs one `migrate` command offline, holding the volume (WP-1.9).
fn migrate(what: &MigrateCommand, out: &mut dyn Write) -> Result<()> {
    use permguard_host::storage::migrate::{self, Layout};
    use permguard_host::storage::volume::hold;

    let now = permguard_host::authz::store::now();
    let (volume_root, subsystem) = match what {
        MigrateCommand::Status { volume } => (volume, None),
        MigrateCommand::Recover { volume, subsystem }
        | MigrateCommand::Rollback { volume, subsystem }
        | MigrateCommand::Finalize { volume, subsystem } => (volume, Some(subsystem.as_str())),
        MigrateCommand::Keys {
            volume,
            backup,
            legacy,
        } => return migrate_keys(volume, backup, legacy, out),
    };
    let volume = hold(volume_root)
        .with_context(|| format!("holding the volume at {}", volume_root.display()))?;
    match (what, subsystem) {
        (MigrateCommand::Status { .. }, _) => {
            let all = migrate::status(&volume).context("reading the layouts")?;
            if all.is_empty() {
                writeln!(out, "no subsystem is laid out on {}", volume_root.display())
                    .context("writing the result")?;
            }
            for status in all {
                let previous = status
                    .manifest
                    .previous
                    .as_ref()
                    .map(|p| format!(", previous version {} in {}", p.version, p.directory))
                    .unwrap_or_default();
                let kept = status
                    .commit
                    .as_ref()
                    .map(|commit| {
                        format!(
                            ", old generation kept for {}s",
                            now.saturating_sub(commit.committed_at)
                        )
                    })
                    .unwrap_or_default();
                writeln!(
                    out,
                    "{}: version {} generation {} in {} ({}{previous}{kept})",
                    status.manifest.subsystem,
                    status.manifest.active.version,
                    status.manifest.active.generation,
                    status.manifest.active.directory,
                    status.phase.as_str()
                )
                .context("writing the result")?;
            }
        }
        (MigrateCommand::Recover { .. }, Some(subsystem)) => {
            let layout = Layout::open(&volume, subsystem)
                .with_context(|| format!("opening the layout of {subsystem}"))?;
            let found = layout
                .recover(now)
                .with_context(|| format!("recovering the migration of {subsystem}"))?;
            writeln!(
                out,
                "{subsystem}: found {}, now {}",
                found.as_str(),
                layout
                    .status()?
                    .map_or("not laid out", |status| status.phase.as_str())
            )
            .context("writing the result")?;
        }
        (MigrateCommand::Rollback { .. }, Some(subsystem)) => {
            Layout::open(&volume, subsystem)
                .with_context(|| format!("opening the layout of {subsystem}"))?
                .rollback(now)
                .with_context(|| format!("rolling back the migration of {subsystem}"))?;
            writeln!(out, "{subsystem}: rolled back to the previous generation")
                .context("writing the result")?;
        }
        (MigrateCommand::Finalize { .. }, Some(subsystem)) => {
            Layout::open(&volume, subsystem)
                .with_context(|| format!("opening the layout of {subsystem}"))?
                .finalize(now)
                .with_context(|| format!("finalizing the migration of {subsystem}"))?;
            writeln!(out, "{subsystem}: finalized; the old generation is removed")
                .context("writing the result")?;
        }
        _ => unreachable!("every command names its subsystem or needs none"),
    }
    Ok(())
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

/// Checks the volume at `root` offline, every journal of the storage library and every tree the
/// planes declare, and fails when anything is found. Holds the volume's lock throughout, so it never
/// reads beside a process that writes.
/// A path from the configuration file, resolved against the file's own directory when relative:
/// a key set travels with the file that names it, as a realm file does.
fn resolve_beside(config_file: &Path, path: &Path) -> std::path::PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    config_file
        .parent()
        .map_or_else(|| path.to_path_buf(), |directory| directory.join(path))
}

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
