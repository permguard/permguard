// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The offline commands on the `postgresql-s3` backend (iteration 03, WP-28.1): the stores a
//! stopped server keeps in its database and its bucket, opened from its configuration.
//!
//! The backend's adapter is the official binary's (`shared-backend`): a program that embeds the
//! command line as a library, Permguard Admin, links none and is told so.

use std::path::Path;

use crate::failure::Failure;

/// The shared backend `config` names, opened, its schema the build's; `None` when the
/// configuration keeps its state on a volume.
pub(crate) fn open(
    config: &permguard_core::Config,
) -> Result<Option<permguard_host::backend::Shared>, Failure> {
    if config.storage_backend().has_volume() {
        return Ok(None);
    }
    opened(config).map(Some)
}

#[cfg(feature = "shared-backend")]
fn opened(config: &permguard_core::Config) -> Result<permguard_host::backend::Shared, Failure> {
    let secrets = permguard_offline::factories::secret_store_for(config)
        .map_err(|error| Failure::usage(format!("the secret store: {error:#}")))?;
    permguard_s3::backend::open(config, secrets.as_deref()).map_err(|error| {
        Failure::unavailable(format!(
            "opening the `{}` storage backend: {error:#}",
            config.storage_backend().as_str()
        ))
    })
}

#[cfg(not(feature = "shared-backend"))]
fn opened(config: &permguard_core::Config) -> Result<permguard_host::backend::Shared, Failure> {
    Err(unsupported(config))
}

/// The refusal of a build that links no shared backend: Permguard Admin's, which embeds the
/// command line as a library.
#[cfg(not(feature = "shared-backend"))]
fn unsupported(config: &permguard_core::Config) -> Failure {
    Failure::usage(permguard_core::volume::unsupported(
        config.storage_backend(),
        "this build of the command line",
    ))
    .named(
        "conflict",
        permguard_core::codes::storage::BACKEND_UNSUPPORTED,
    )
}

/// The configuration an offline command on the shared backend reads: `--server-config`, the
/// server's own file.
pub(crate) fn config_of(server_config: Option<&Path>) -> Result<permguard_core::Config, Failure> {
    super::offline_ops::server_config_of(server_config)
}

/// What `migrate import` answers: the deployment the database now keeps, and each store carried.
#[derive(Debug, serde::Serialize)]
pub(crate) struct Imported {
    /// The volume's id, which the deployment keeps and the Host identity names.
    deployment: String,
    stores: Vec<ImportedStore>,
}

#[derive(Debug, serde::Serialize)]
struct ImportedStore {
    store: &'static str,
    records: usize,
}

impl crate::output::Report for Imported {
    fn render_terminal(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(out, "Imported into postgresql-s3")?;
        writeln!(out, "deployment  {}", self.deployment)?;
        for store in &self.stores {
            writeln!(out, "{:<22}{}", store.store, store.records)?;
        }
        Ok(())
    }
}

/// `permguard migrate import` (iteration 03, WP-28.1): the stopped volume at `volume` into the
/// `postgresql-s3` backend the server's configuration names, its working directory the volume.
pub(crate) fn import(
    volume: &Path,
    server_config: Option<&Path>,
    trace: &crate::trace::Trace,
) -> Result<Imported, Failure> {
    let config = shared_config(
        server_config,
        "name the server's configuration on `postgresql-s3`",
    )?;
    let same = |path: &Path| std::fs::canonicalize(path).ok();
    if same(volume).is_none() || same(volume) != same(config.working_dir()) {
        return Err(Failure::usage(format!(
            "the configuration's working directory is {}, not the volume {}: on `postgresql-s3` it \
             keeps the instance's own files, those of the volume it was, and the import reads the \
             volume's Planes from it",
            config.working_dir().display(),
            volume.display()
        )));
    }
    imported(&config, volume, trace)
}

#[cfg(feature = "shared-backend")]
fn imported(
    config: &permguard_core::Config,
    volume: &Path,
    trace: &crate::trace::Trace,
) -> Result<Imported, Failure> {
    let held = super::host::claim(volume, trace)?;
    let host_id = permguard_host::identity::host_id_of(&held)
        .map_err(|error| Failure::unavailable(format!("reading the Host identity: {error}")))?
        .ok_or_else(|| {
            Failure::usage(
                "the volume holds no Host identity: a server never started on it, and there is \
                 nothing to import",
            )
        })?;
    let custodian = permguard_offline::volume::custodian(config, &held)
        .map_err(|error| Failure::usage(format!("the custody of the keys: {error:#}")))?;
    let sealer = custodian
        .sealer(host_id)
        .map_err(|error| Failure::usage(format!("the custody of the secrets: {error}")))?;
    let connected = connected(config)?;
    let imported =
        permguard_s3::import::volume(config, &held, &connected, std::sync::Arc::new(sealer))
            .map_err(|error| Failure::unavailable(format!("importing the volume: {error:#}")))?;
    trace.say(format!(
        "imported {} store(s) of the volume",
        imported.stores.len()
    ));
    Ok(Imported {
        deployment: permguard_host::identity::record::uuid_text(&imported.deployment),
        stores: imported
            .stores
            .into_iter()
            .map(|(store, records)| ImportedStore { store, records })
            .collect(),
    })
}

#[cfg(not(feature = "shared-backend"))]
fn imported(
    config: &permguard_core::Config,
    _volume: &Path,
    _trace: &crate::trace::Trace,
) -> Result<Imported, Failure> {
    Err(unsupported(config))
}

/// The configuration of an offline command on the shared backend: `--server-config`, refused when
/// it keeps its state on a volume, where `on_files` says what to do instead.
fn shared_config(
    server_config: Option<&Path>,
    on_files: &str,
) -> Result<permguard_core::Config, Failure> {
    let config = config_of(server_config)?;
    if config.storage_backend().has_volume() {
        return Err(Failure::usage(format!(
            "the configuration keeps its state on a volume, `{}`: {on_files}",
            config.storage_backend().as_str()
        )));
    }
    Ok(config)
}

/// The database and the bucket `config` names, connected and checked as a start checks them.
#[cfg(feature = "shared-backend")]
fn connected(config: &permguard_core::Config) -> Result<permguard_s3::backend::Connected, Failure> {
    let secrets = permguard_offline::factories::secret_store_for(config)
        .map_err(|error| Failure::usage(format!("the secret store: {error:#}")))?;
    permguard_s3::backend::connect(config, secrets.as_deref()).map_err(|error| {
        Failure::unavailable(format!("opening the `postgresql-s3` backend: {error:#}"))
    })
}

/// What `host audit copy` answers.
#[derive(Debug, serde::Serialize)]
pub(crate) struct AuditCopied {
    trails: usize,
    /// The directory `audit verify --directory` reads.
    directory: String,
    /// The `host.operations` keys, the JWKS `audit verify --keys` reads.
    keys: String,
}

impl crate::output::Report for AuditCopied {
    fn render_terminal(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(out, "Copied {} trail(s)", self.trails)?;
        writeln!(out, "trails  {}", self.directory)?;
        writeln!(out, "keys    {}", self.keys)
    }
}

/// `permguard host audit copy --out <dir>` (iteration 03, WP-28.1, decision X101): the trails a
/// stopped server keeps on `postgresql-s3`, laid out as on files, and the keys of the ring that
/// signs their checkpoints, for the server binary's `audit verify`.
pub(crate) fn audit_copy(
    globals: &crate::args::Globals,
    server_config: Option<&Path>,
    out: &Path,
    trace: &crate::trace::Trace,
) -> Result<std::process::ExitCode, Failure> {
    let config = shared_config(
        server_config,
        "`audit verify --directory <volume>` reads its trails where they are",
    )?;
    let out = super::host::rooted_file(globals, out);
    if std::fs::symlink_metadata(&out).is_ok() {
        return Err(Failure::usage(format!(
            "{} exists: name a new directory",
            out.display()
        )));
    }
    let copied = audit_copied(&config, &out)?;
    crate::session::render(&copied, globals.output, trace)?;
    Ok(std::process::ExitCode::SUCCESS)
}

#[cfg(feature = "shared-backend")]
fn audit_copied(config: &permguard_core::Config, out: &Path) -> Result<AuditCopied, Failure> {
    use permguard_host::storage::Dir;

    let connected = connected(config)?;
    let (trails, ring) = permguard_s3::backend::audit(&connected);
    let written = |what: &str, error: &dyn std::fmt::Display| {
        Failure::unavailable(format!("writing {what} to {}: {error}", out.display()))
    };
    let root = Dir::create_root(out).map_err(|error| written("the copy", &error))?;
    let directory = root
        .subdir("trails", true)
        .map_err(|error| written("the trails", &error))?;
    let copied = permguard_host::audit::store::export(trails.as_ref(), &directory)
        .map_err(|error| Failure::unavailable(format!("copying the trails: {error}")))?;
    let keys = permguard_host::keys::ring::export_of(
        ring.as_ref(),
        "the database's `host.operations` ring",
    )
    .map_err(|error| {
        Failure::unavailable(format!("reading the `host.operations` keys: {error}"))
    })?;
    permguard_host::storage::write::replace_bytes(&root, KEYS_FILE, keys.as_bytes())
        .map_err(|error| written("the keys", &error))?;
    Ok(AuditCopied {
        trails: copied,
        directory: directory.path().display().to_string(),
        keys: root.child_path(KEYS_FILE).display().to_string(),
    })
}

#[cfg(not(feature = "shared-backend"))]
fn audit_copied(config: &permguard_core::Config, _out: &Path) -> Result<AuditCopied, Failure> {
    Err(unsupported(config))
}

/// The file the copy keeps the `host.operations` keys in, beside its trails.
#[cfg(feature = "shared-backend")]
const KEYS_FILE: &str = "host.operations.keys.json";

/// What `evidence rotate-cursor-root` answers.
#[derive(Debug, serde::Serialize)]
pub(crate) struct CursorRootRotated {
    store: String,
    /// Whether the store held a root to rotate; none issues until the next ask mints one.
    rotated: bool,
}

impl crate::output::Report for CursorRootRotated {
    fn render_terminal(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        if self.rotated {
            writeln!(
                out,
                "The cursor root of `{}` rotated: the previous is still accepted",
                self.store
            )
        } else {
            writeln!(
                out,
                "`{}` holds no issuing root: nothing rotated, the next ask mints one",
                self.store
            )
        }
    }
}

/// `permguard evidence rotate-cursor-root --store <store>` (iteration 03, WP-28.1, decision
/// X110), offline, the servers stopped.
pub(crate) fn rotate_cursor_root(
    globals: &crate::args::Globals,
    server_config: Option<&Path>,
    store: &str,
    trace: &crate::trace::Trace,
) -> Result<std::process::ExitCode, Failure> {
    let config = shared_config(
        server_config,
        "on files the rotation is the move of `CURSOR_KEY` to `CURSOR_KEY.previous` beside the \
         store",
    )?;
    let rotated = rotated(&config, store)?;
    crate::session::render(
        &CursorRootRotated {
            store: store.to_owned(),
            rotated,
        },
        globals.output,
        trace,
    )?;
    Ok(std::process::ExitCode::SUCCESS)
}

#[cfg(feature = "shared-backend")]
fn rotated(config: &permguard_core::Config, store: &str) -> Result<bool, Failure> {
    permguard_s3::backend::rotate_cursor_root(&connected(config)?, store).map_err(|error| {
        Failure::unavailable(format!("rotating the cursor root of `{store}`: {error:#}"))
    })
}

#[cfg(not(feature = "shared-backend"))]
fn rotated(config: &permguard_core::Config, _store: &str) -> Result<bool, Failure> {
    Err(unsupported(config))
}
