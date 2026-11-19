// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The command line of a composed server: the parser, the commands that run with no server, and
//! the exit status of each outcome. Selected with `cli`: a server assembled from the kit by a
//! program that parses nothing links none of it.

use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Command as ClapCommand, CommandFactory, FromArgMatches};

use permguard_core::Config;
use permguard_offline::migrate;

use super::{App, VerifiedTree};
use crate::banner::Banner;
use crate::command::{
    Action, AuditCommand, Cli, Command, KeysCommand, MigrateCommand, StreamsCommand, VolumeCommand,
};
use crate::logging;

impl App {
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
            }) => {
                // The store releases before kept inside the history by default moves out first,
                // under the volume's hold, as at start (BUG-0122, BUG-0124).
                if config.event_store_directory_is_default() {
                    let _held = permguard_host::storage::volume::hold(volume)
                        .with_context(|| format!("holding the volume at {}", volume.display()))?;
                    crate::legacy_events::relocate_event_store(
                        &config
                            .working_dir()
                            .join(permguard_core::config::LEGACY_EVENT_STORE_DIRECTORY),
                        &config.event_store_directory(),
                    )?;
                }
                crate::legacy_events::migrate_events(
                    volume,
                    backup,
                    config.working_dir(),
                    &config.events_directory(),
                    crate::legacy_events::bounds_of(config),
                    out,
                )
            }
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
