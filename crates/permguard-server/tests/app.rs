// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! How an application composes, and what each command does with what it was composed from.
//!
//! Here rather than beside the code because these need a configuration file on disk, a fake service,
//! a fake policy and a shutdown that resolves on command — that is a harness, and a harness in
//! `app.rs` would be longer than `App` itself.

use std::env;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser};

use permguard_core::{
    BoxFuture, BuildSettings, Config, ConfigSection, ProductIdentity, Pseudonymizer, Secret,
    SecretRef, SecretStore, ServerContext, Service, Value,
};
use permguard_server::{Action, App, Cli, Command, DefaultServerHost};
use permguard_std::audit::{RecordingAuditSink, TracingAuditSink};
use permguard_std::storage::MemoryStorage;

const SERVABLE: &str = "public:\n  http: 0.0.0.0:5556\n";

/// A secret store of the kind a build outside this workspace would compose.
struct StubSecrets;

impl SecretStore for StubSecrets {
    fn name(&self) -> &'static str {
        "stub-secrets"
    }

    fn resolve(
        &self,
        _reference: &SecretRef,
    ) -> std::result::Result<Secret, permguard_core::SecretError> {
        Ok(Secret::new(b"0123456789abcdef0123456789abcdef".to_vec()))
    }
}

/// What the services of a test observed, in the order they observed it.
#[derive(Clone, Default)]
struct Journal(Arc<Mutex<Vec<String>>>);

impl Journal {
    fn record(&self, entry: String) -> Result<()> {
        self.0
            .lock()
            .map_err(|_| anyhow::anyhow!("the journal lock is poisoned"))?
            .push(entry);

        Ok(())
    }

    fn entries(&self) -> Vec<String> {
        self.0
            .lock()
            .map(|entries| entries.clone())
            .unwrap_or_default()
    }
}

/// A service of the kind a build outside this workspace would register.
struct StubService {
    name: &'static str,
    journal: Journal,
}

impl StubService {
    /// A service that records nothing, for tests that only care that it was registered.
    fn new(name: &'static str) -> Self {
        Self {
            name,
            journal: Journal::default(),
        }
    }

    /// A service that writes each lifecycle step it goes through to a shared journal.
    fn recording(name: &'static str, journal: &Journal) -> Self {
        Self {
            name,
            journal: journal.clone(),
        }
    }
}

impl Service for StubService {
    fn name(&self) -> &'static str {
        self.name
    }

    fn start<'a>(&'a self, _context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { self.journal.record(format!("{} started", self.name)) })
    }

    fn stop<'a>(&'a self, _context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { self.journal.record(format!("{} stopped", self.name)) })
    }
}

fn identity() -> ProductIdentity {
    ProductIdentity::new(
        "demo-x",
        "Demo X",
        "A Demonstrated Tagline",
        "Demo X command line interface",
        "<art>",
    )
}

/// An app that is asked to stop as soon as it is up.
///
/// Without this every test that serves would sit waiting for a process signal that never comes.
fn app() -> App {
    app_waiting().with_shutdown_signal(|| Box::pin(std::future::ready(())))
}

fn app_waiting() -> App {
    App::new(
        identity(),
        BuildSettings::new("9.9.9", "2026", "Test Holder"),
        Box::new(DefaultServerHost::new()),
        Box::new(MemoryStorage::new()),
        Box::new(RecordingAuditSink::new()),
    )
}

/// Writes a configuration file under the test's own directory and returns its path.
fn config_file(name: &str, contents: &str) -> std::path::PathBuf {
    // Unique per process and per thread: a fixed name is shared with every other run.
    let dir = env::temp_dir().join(format!(
        "permguard-app-test-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    fs::create_dir_all(&dir).expect("creating the fixture directory");

    let path = dir.join(format!("{name}.yml"));
    fs::write(&path, contents).expect("writing the fixture configuration file");

    path
}

fn serve_action(path: &Path) -> Action {
    serve_action_with(path, &[])
}

fn serve_action_with(path: &Path, extra: &[&str]) -> Action {
    let mut argv = vec!["demo-x", path.to_str().expect("a UTF-8 path")];
    argv.extend_from_slice(extra);

    Cli::try_parse_from(argv)
        .expect("the default action parses")
        .action()
        .expect("the invocation resolves to an action")
}

async fn output_of(app: &App, action: &Action) -> String {
    let mut out = Vec::new();

    app.dispatch_to(action, &mut out)
        .await
        .expect("the command runs");

    String::from_utf8(out).expect("the output is valid UTF-8")
}

#[tokio::test]
async fn test_version_renders_the_short_banner_of_the_supplied_identity() {
    let out = output_of(&app(), &Action::Named(Command::Version)).await;

    assert!(out.starts_with("The official Demo X - Copyright © 2022 Nitro Agility S.r.l.\n"));
    assert!(out.contains("A Demonstrated Tagline"));
    assert!(!out.contains("<art>"));
    assert!(out.trim_end().ends_with("9.9.9"));
}

#[tokio::test]
async fn test_the_terminal_format_renders_the_banner_and_nothing_else() {
    let path = config_file("servable", SERVABLE);
    let action = serve_action_with(&path, &["--log-format", "terminal"]);
    let out = output_of(&app(), &action).await;

    assert!(out.starts_with("<art>"));
    assert!(out.contains("The official Demo X - Copyright © 2022 Nitro Agility S.r.l."));
    // The lifecycle goes to the log, so the banner is all the command itself prints.
    assert!(out.trim_end().ends_with("Version 9.9.9 (build unknown)"));
}

#[tokio::test]
async fn test_the_json_format_prints_no_banner_at_all() {
    let path = config_file("servable-json", SERVABLE);
    let out = output_of(&app(), &serve_action(&path)).await;

    assert!(
        out.is_empty(),
        "json output belongs to the log pipeline: {out:?}"
    );
}

#[tokio::test]
async fn test_serve_runs_against_the_composed_collaborators() {
    let path = config_file("collaborators", SERVABLE);
    let app = app();

    app.dispatch_to(&serve_action(&path), &mut Vec::new())
        .await
        .expect("the command runs");

    // The run went through the collaborators this app was composed with, not defaults of its own.
    assert_eq!(app.storage().name(), "memory");
    assert_eq!(app.audit().name(), "recording");
    assert_eq!(app.server().name(), "default");
}

#[tokio::test]
async fn test_serve_takes_every_registered_service_through_its_whole_lifecycle() {
    let path = config_file("lifecycle", SERVABLE);
    let journal = Journal::default();
    let app = app()
        .with_service(Box::new(StubService::recording("admin", &journal)))
        .with_service(Box::new(StubService::recording("discovery", &journal)));

    app.dispatch_to(&serve_action(&path), &mut Vec::new())
        .await
        .expect("the command runs");

    assert_eq!(
        journal.entries(),
        vec![
            "admin started",
            "discovery started",
            "discovery stopped",
            "admin stopped",
        ]
    );
}

#[tokio::test]
async fn test_serve_starts_the_registered_services() {
    let path = config_file("services", SERVABLE);
    let app = app()
        .with_service(Box::new(StubService::new("admin")))
        .with_service(Box::new(StubService::new("discovery")));

    app.dispatch_to(&serve_action(&path), &mut Vec::new())
        .await
        .expect("the command runs");

    assert_eq!(
        app.services()
            .iter()
            .map(|service| service.name())
            .collect::<Vec<_>>(),
        vec!["admin", "discovery"]
    );
}

#[test]
fn test_the_context_carries_the_registered_services_and_secret_store() {
    let app = app()
        .with_secrets(Box::new(StubSecrets))
        .with_service(Box::new(StubService::new("admin")));
    let config = Config::default();

    let context = app.context(&config, None, None, None);

    assert_eq!(context.services().len(), 1);
    assert_eq!(
        context.secrets().map(SecretStore::name),
        Some("stub-secrets")
    );
}

#[test]
fn test_a_build_without_a_secret_store_composes_a_context_without_one() {
    let config = Config::default();

    assert!(app().context(&config, None, None, None).secrets().is_none());
}

#[tokio::test]
async fn test_serve_rejects_a_config_that_declares_no_web_address() {
    let path = config_file("no-public", "admin:\n  addr: 127.0.0.1:5557\n");

    let error = app()
        .dispatch_to(&serve_action(&path), &mut Vec::new())
        .await
        .expect_err("a config with no public address is invalid");

    assert!(format!("{error:#}").contains("public listen address"));
}

#[tokio::test]
async fn test_an_unclaimed_configuration_section_is_rejected_with_the_file_path() {
    let path = config_file(
        "unclaimed",
        "public:\n  http: 0.0.0.0:5556\nsso:\n  issuer: x\n",
    );

    let error = app()
        .dispatch_to(&serve_action(&path), &mut Vec::new())
        .await
        .expect_err("nobody claimed the section");

    let message = format!("{error:#}");
    assert!(message.contains("sso"));
    assert!(message.contains(path.to_str().expect("a UTF-8 path")));
}

#[tokio::test]
async fn test_a_claimed_configuration_section_is_accepted() {
    let path = config_file(
        "claimed",
        "public:\n  http: 0.0.0.0:5556\nsso:\n  issuer: x\n",
    );
    let app = app().with_claimed_sections(["sso"]);

    app.dispatch_to(&serve_action(&path), &mut Vec::new())
        .await
        .expect("the claimed section is accepted");
}

/// A section reader of the kind a capability outside this workspace would register.
fn sso_settings(section: &Value) -> Result<Vec<(String, String)>> {
    let issuer = section
        .get("issuer")
        .and_then(|value| value.as_str())
        .context("the `sso` section declares no `issuer`")?;

    Ok(vec![("PERMGUARD_SSO_ISSUER".to_owned(), issuer.to_owned())])
}

const WITH_SSO: &str = "public:\n  http: 0.0.0.0:5556\nsso:\n  issuer: https://idp\n";

#[test]
fn test_a_claimed_section_feeds_a_declared_setting_through_the_file_layer() {
    let path = config_file("sso-declared", WITH_SSO);
    let app = app()
        .with_declared_settings(["PERMGUARD_SSO_ISSUER"])
        .with_section_settings("sso", sso_settings);

    let config = app
        .config_for(&serve_action(&path))
        .expect("the config builds");

    assert_eq!(config.setting("PERMGUARD_SSO_ISSUER"), Some("https://idp"));
}

#[test]
fn test_a_section_setting_the_build_never_declared_is_discarded() {
    let path = config_file("sso-undeclared", WITH_SSO);
    let app = app().with_section_settings("sso", sso_settings);

    let config = app
        .config_for(&serve_action(&path))
        .expect("the config builds");

    assert_eq!(config.setting("PERMGUARD_SSO_ISSUER"), None);
}

#[test]
fn test_a_failing_section_reader_names_the_section_and_the_file() {
    let path = config_file(
        "sso-broken",
        "public:\n  http: 0.0.0.0:5556\nsso:\n  wrong: x\n",
    );
    let app = app()
        .with_declared_settings(["PERMGUARD_SSO_ISSUER"])
        .with_section_settings("sso", sso_settings);

    let error = app
        .config_for(&serve_action(&path))
        .expect_err("the section reader rejects the section");

    let message = format!("{error:#}");
    assert!(message.contains("`sso`"));
    assert!(message.contains(path.to_str().expect("a UTF-8 path")));
}

/// A policy of the kind the binary's factory would build.
struct StubPolicy(String);

impl Pseudonymizer for StubPolicy {
    fn key_version(&self) -> &str {
        &self.0
    }

    fn pseudonymize(&self, value: &str) -> String {
        format!("{}:{}", self.0, value.len())
    }
}

const PSEUDONYM_ON: &str = "public:\n  http: 0.0.0.0:5556\noperations:\n  secrets:\n    provider: environment\n    env_prefix: PERMGUARD_APP_TEST\n  audit:\n    pseudonym:\n      enabled: true\n      key_ref: audit-pseudonym\n      key_version: \"v7\"\n";

/// A store holding the one secret these tests name.
fn secrets() -> Box<dyn SecretStore> {
    Box::new(StubSecrets)
}

/// A store whose material is too short to derive anything from.
struct ShortSecret;

impl SecretStore for ShortSecret {
    fn name(&self) -> &'static str {
        "short"
    }

    fn resolve(
        &self,
        _reference: &SecretRef,
    ) -> std::result::Result<Secret, permguard_core::SecretError> {
        Ok(Secret::new(b"tiny".to_vec()))
    }
}

#[test]
fn test_a_configuration_that_leaves_pseudonymisation_off_builds_no_policy() {
    let path = config_file("pseudonym-off", SERVABLE);
    let config = app()
        .config_for(&serve_action(&path))
        .expect("the config builds");

    assert!(!config.audit_pseudonym_enabled());
    assert!(
        app()
            .pseudonymizer_for(&config, None)
            .expect("no policy is needed")
            .is_none()
    );
}

#[test]
fn test_the_policy_is_built_from_the_configured_key_and_version() {
    let path = config_file("pseudonym-on", PSEUDONYM_ON);
    let app = app().with_pseudonymizer_factory(|key, version| {
        assert_eq!(key, b"0123456789abcdef0123456789abcdef");

        Box::new(StubPolicy(version.to_owned()))
    });
    let config = app
        .config_for(&serve_action(&path))
        .expect("the config builds");

    let store = secrets();
    let policy = app
        .pseudonymizer_for(&config, Some(store.as_ref()))
        .expect("the policy builds")
        .expect("the configuration asked for one");

    assert_eq!(policy.key_version(), "v7");
}

#[test]
fn test_asking_for_pseudonymisation_a_build_cannot_provide_refuses() {
    let path = config_file("pseudonym-unsupported", PSEUDONYM_ON);
    let app = app();
    let config = app
        .config_for(&serve_action(&path))
        .expect("the config builds");

    let store = secrets();
    let error = match app.pseudonymizer_for(&config, Some(store.as_ref())) {
        Err(error) => error,
        Ok(_) => panic!("this build composes no pseudonymiser"),
    };

    assert!(format!("{error:#}").contains("composes no pseudonymiser"));
}

#[test]
fn test_asking_for_pseudonymisation_with_nowhere_to_resolve_the_key_refuses() {
    let path = config_file("pseudonym-no-store", PSEUDONYM_ON);
    let app = app().with_pseudonymizer_factory(|key, version| {
        Box::new(StubPolicy(format!("{version}:{}", key.len())))
    });
    let config = app
        .config_for(&serve_action(&path))
        .expect("the config builds");

    // A build that can pseudonymise but has nowhere to get the key refuses, rather than deriving
    // pseudonyms from something it invented.
    let error = match app.pseudonymizer_for(&config, None) {
        Err(error) => error,
        Ok(_) => panic!("there is no secret store"),
    };

    assert!(format!("{error:#}").contains("no secret store"));
}

#[test]
fn test_a_secret_too_short_to_derive_from_is_refused() {
    let path = config_file("pseudonym-short", PSEUDONYM_ON);
    let app = app().with_pseudonymizer_factory(|key, version| {
        Box::new(StubPolicy(format!("{version}:{}", key.len())))
    });
    let config = app
        .config_for(&serve_action(&path))
        .expect("the config builds");
    let store: Box<dyn SecretStore> = Box::new(ShortSecret);

    let error = match app.pseudonymizer_for(&config, Some(store.as_ref())) {
        Err(error) => error,
        Ok(_) => panic!("the secret is too short"),
    };

    let message = format!("{error:#}");
    assert!(message.contains("too short"), "{message}");
    // The reference may be named; what it resolved to may not.
    assert!(!message.contains("tiny"), "{message}");
}

/// A section of the kind a crate outside this workspace would define — and not about keys.
#[derive(Debug, serde::Deserialize)]
struct RateLimit {
    requests_per_minute: u32,
    #[serde(default)]
    burst: Option<u32>,
}

impl ConfigSection for RateLimit {
    const NAME: &'static str = "rate_limit";

    fn validate(&self) -> Result<()> {
        if self.requests_per_minute == 0 {
            anyhow::bail!("a rate limit of zero requests per minute stops everything");
        }

        Ok(())
    }
}

const WITH_RATE_LIMIT: &str =
    "public:\n  http: 0.0.0.0:5556\nrate_limit:\n  requests_per_minute: 600\n  burst: 50\n";

#[test]
fn test_a_registered_section_arrives_typed_and_nested() {
    let path = config_file("section-typed", WITH_RATE_LIMIT);
    let app = app().with_config_section::<RateLimit>();

    let config = app
        .config_for(&serve_action(&path))
        .expect("the config builds");
    let limit = config
        .section::<RateLimit>()
        .expect("the section was declared");

    assert_eq!(limit.requests_per_minute, 600);
    assert_eq!(limit.burst, Some(50));
}

#[test]
fn test_registering_a_section_claims_its_name() {
    let path = config_file("section-claimed", WITH_RATE_LIMIT);

    // Unregistered, the section is an unknown one and the file is refused.
    assert!(app().config_for(&serve_action(&path)).is_err());

    // Registered, the same file is accepted.
    assert!(
        app()
            .with_config_section::<RateLimit>()
            .config_for(&serve_action(&path))
            .is_ok()
    );
}

#[test]
fn test_a_registered_section_a_file_leaves_out_reads_back_as_absent() {
    let path = config_file("section-absent", SERVABLE);

    let config = app()
        .with_config_section::<RateLimit>()
        .config_for(&serve_action(&path))
        .expect("the config builds");

    assert!(config.section::<RateLimit>().is_none());
}

#[test]
fn test_a_section_that_does_not_parse_names_itself_and_the_file() {
    let path = config_file(
        "section-malformed",
        "public:\n  http: 0.0.0.0:5556\nrate_limit:\n  requests_per_minute: plenty\n",
    );

    let error = app()
        .with_config_section::<RateLimit>()
        .config_for(&serve_action(&path))
        .expect_err("`plenty` is not a number");

    let message = format!("{error:#}");
    assert!(message.contains("rate_limit"));
    assert!(message.contains(path.to_str().expect("a UTF-8 path")));
}

#[test]
fn test_a_section_that_does_not_validate_stops_the_start() {
    let path = config_file(
        "section-invalid",
        "public:\n  http: 0.0.0.0:5556\nrate_limit:\n  requests_per_minute: 0\n",
    );

    let error = app()
        .with_config_section::<RateLimit>()
        .config_for(&serve_action(&path))
        .expect_err("a rate limit of zero is refused");

    assert!(format!("{error:#}").contains("stops everything"));
}

#[test]
fn test_decorate_stamps_the_identity_onto_a_parser() {
    let app = app();
    let command = app.decorate(Cli::command());

    assert_eq!(command.get_name(), "demo-x");
    assert_eq!(
        command.get_about().map(ToString::to_string),
        Some("Demo X command line interface".to_owned())
    );
    assert_eq!(
        command.get_version().map(ToString::to_string),
        Some("9.9.9".to_owned())
    );
}

#[test]
fn test_the_app_hands_back_exactly_the_collaborators_it_was_composed_with() {
    let app = App::new(
        identity(),
        BuildSettings::new("9.9.9", "2026", "Test Holder"),
        Box::new(DefaultServerHost::new()),
        Box::new(MemoryStorage::new()),
        Box::new(TracingAuditSink::new("demo-x", "9.9.9")),
    );

    assert_eq!(app.identity().binary_name(), "demo-x");
    assert_eq!(app.build_settings().version(), "9.9.9");
    assert_eq!(app.server().name(), "default");
    assert_eq!(app.storage().name(), "memory");
    assert_eq!(app.audit().name(), "tracing");
    assert!(app.secrets().is_none());
    assert!(app.services().is_empty());
}
