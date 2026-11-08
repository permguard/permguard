// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The command line as a service account (iteration 02, TC-7, `2-security/7` Access tokens): its
//! client, from the flags or the configuration, obtains an application token at the IAM Host's
//! token endpoint; a command that reaches a Data Plane sends it when no `--token-file` is given.
//! The token is kept under `~/.permguard/tokens/`, in a file only its owner reads, keyed by the
//! client and what it asked for, the role it elevates to among it, and reused until a minute
//! before it expires. Nothing here traces
//! a secret, a key or a token: the trace names the client and the expiry.
//!
//! A person's token is the person's session exchanged at the IAM Host (RFC 8693): [`exchange`].

use std::path::{Path, PathBuf};
use std::time::Duration;

use permguard_control_client::endpoint::Endpoint;
use permguard_control_client::tls::{Credential, TlsOptions};
use permguard_control_client::token_source::{Asked, Issued, Proof, REFRESH_AHEAD, TokenSource};

use crate::args::Globals;
use crate::failure::Failure;
use crate::settings::Store;
use crate::trace::Trace;

/// How long a token request may take.
const TIMEOUT: Duration = Duration::from_secs(15);
/// The most a key or cache file may hold.
const FILE_MAX: u64 = 64 * 1024;

/// The client the flags or the configuration name, when there is one: its source for `asked`.
pub fn source(
    globals: &Globals,
    asked: Asked,
    trace: &Trace,
) -> Result<Option<TokenSource>, Failure> {
    let store = crate::session::open_store(globals, trace)?;
    source_with(globals, &store, asked, trace)
}

/// A person's own token for `asked`: the session `--token-file` holds, exchanged at the IAM Host
/// (RFC 8693), when there is one. The session goes where it was opened, a flag always winning over
/// the configuration: `--iam-endpoint`, else the `iam` command's own Host, `--host-endpoint`, else
/// `auth.client.iam_endpoint`, else `host.endpoint`. Reached as the command's Host, its connection
/// is the Host's, unchanged; reached as the IAM Host, it is the IAM Host's.
pub fn exchange(
    globals: &Globals,
    asked: Asked,
    trace: &Trace,
) -> Result<Option<TokenSource>, Failure> {
    let store = crate::session::open_store(globals, trace)?;
    let as_iam = globals.iam_endpoint.clone().or_else(|| {
        globals
            .host_endpoint
            .is_none()
            .then(|| iam_endpoint(globals, &store))
            .flatten()
    });
    let (endpoint, mut tls) = match as_iam {
        Some(endpoint) => (endpoint, iam_tls(globals, &store, trace)?),
        None => (
            crate::session::resolve_endpoint_url(
                "host.endpoint",
                globals.host_endpoint.as_deref(),
                &store,
                trace,
            )?,
            crate::target::tls(globals, &store, trace)?,
        ),
    };
    let Some(session) = tls.token.take() else {
        return Ok(None);
    };
    let endpoint = Endpoint::parse(&endpoint)
        .map_err(|error| Failure::usage(format!("the IAM Host's endpoint: {error}")))?;
    trace.say(format!(
        "the session is exchanged for the person's token at {endpoint}"
    ));
    TokenSource::new(endpoint, "", Proof::Session(session), asked, tls, TIMEOUT)
        .map(Some)
        .map_err(|failure| Failure::from_client(&failure))
}

/// The IAM Host's own connection: never the Data Plane's server name, and its own authority when
/// one is stated. A client certificate is presented whatever the proof: a listener requiring mutual
/// TLS admits a secret, a key or a session only over it, and an administration token is bound to it
/// (RFC 8705); beside another proof it is the connection's, never the proof. It is the IAM Host's
/// own, `auth.client.tls_cert_file` and its key, when stated, and the planes' otherwise.
fn iam_tls(globals: &Globals, store: &Store, trace: &Trace) -> Result<TlsOptions, Failure> {
    let mut tls = crate::target::tls(globals, store, trace)?;
    tls.server_name = None;
    let path = |flag: &Option<PathBuf>, key: &str| match flag {
        Some(flag) if flag.is_absolute() => Some(flag.clone()),
        Some(flag) => Some(globals.workdir.join(flag)),
        None => crate::target::configured(key, store, globals),
    };
    if let Some(authority) = path(&globals.iam_tls_ca_file, "auth.client.tls_ca_file") {
        tls.ca_file = Some(authority);
    }
    match (
        path(&globals.iam_tls_cert_file, "auth.client.tls_cert_file"),
        path(&globals.iam_tls_key_file, "auth.client.tls_key_file"),
    ) {
        (Some(certificate), Some(key)) => {
            trace.say(format!(
                "the IAM Host's connection presents {}",
                certificate.display()
            ));
            tls.cert_file = Some(certificate);
            tls.key_file = Some(key);
            tls.key_pem = None;
        }
        (None, None) => {}
        _ => {
            return Err(Failure::usage(
                "the IAM Host's client certificate needs its key: --iam-tls-cert-file and \
                 --iam-tls-key-file together, or auth.client.tls_cert_file and tls_key_file",
            ));
        }
    }
    Ok(tls)
}

/// The IAM Host a client names: `--iam-endpoint` or `auth.client.iam_endpoint`.
fn iam_endpoint(globals: &Globals, store: &Store) -> Option<String> {
    globals.iam_endpoint.clone().or_else(|| {
        crate::target::setting_value("auth.client.iam_endpoint", store).map(|(value, _)| value)
    })
}

fn source_with(
    globals: &Globals,
    store: &Store,
    asked: Asked,
    trace: &Trace,
) -> Result<Option<TokenSource>, Failure> {
    let client_id = match &globals.client_id {
        Some(flag) => Some(flag.clone()),
        None => crate::target::setting_value("auth.client.id", store).map(|(value, _)| value),
    };
    let Some(client_id) = client_id else {
        return Ok(None);
    };
    if client_id.trim().is_empty() {
        return Err(Failure::usage(
            "the client is named by its service account: an empty auth.client.id names nobody",
        ));
    }
    let path = |flag: &Option<PathBuf>, key: &str| match flag {
        Some(flag) if flag.is_absolute() => Some(flag.clone()),
        Some(flag) => Some(globals.workdir.join(flag)),
        None => crate::target::configured(key, store, globals),
    };
    let secret_file = path(&globals.client_secret_file, "auth.client.secret_file");
    let key_file = path(&globals.client_key_file, "auth.client.key_file");
    let mut tls = iam_tls(globals, store, trace)?;
    tls.token = None;
    let proof = match (secret_file, key_file) {
        (Some(_), Some(_)) => {
            return Err(Failure::usage(
                "the client proves itself one way: a secret file or a key file, not both",
            ));
        }
        (Some(secret), None) => Proof::Secret(crate::token::read(&secret).map_err(|why| {
            Failure::usage(why.replacen("the token file", "the client secret", 1))
        })?),
        (None, Some(key)) => Proof::Key(private_file(&key, "the client key")?),
        (None, None) if tls.cert_file.is_some() || tls.key_pem.is_some() => Proof::Certificate,
        (None, None) => {
            return Err(Failure::usage(format!(
                "the client `{client_id}` has no proof: --client-secret-file, --client-key-file, \
                 or a client certificate bound to it"
            )));
        }
    };
    let endpoint = iam_endpoint(globals, store).ok_or_else(|| {
        Failure::usage(
            "the client obtains its tokens at the IAM Host: --iam-endpoint or \
             auth.client.iam_endpoint",
        )
    })?;
    let endpoint = Endpoint::parse(&endpoint)
        .map_err(|error| Failure::usage(format!("--iam-endpoint: {error}")))?;
    trace.say(format!(
        "the client `{client_id}` obtains its tokens at {endpoint}"
    ));
    TokenSource::new(endpoint, &client_id, proof, asked, tls, TIMEOUT)
        .map(Some)
        .map_err(|failure| Failure::from_client(&failure))
}

/// A file only its owner reads, of at most [`FILE_MAX`] bytes: never a link or a FIFO, and the file
/// read is the file checked.
fn private_file(path: &Path, what: &str) -> Result<Credential, Failure> {
    use std::io::Read as _;

    let refused = |why: String| Failure::usage(format!("{what} {}: {why}", path.display()));
    let named = std::fs::symlink_metadata(path).map_err(|error| refused(error.to_string()))?;
    if !named.is_file() {
        return Err(refused("is not a regular file".to_owned()));
    }
    let file = std::fs::File::open(path).map_err(|error| refused(error.to_string()))?;
    let opened = file
        .metadata()
        .map_err(|error| refused(error.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if (opened.dev(), opened.ino()) != (named.dev(), named.ino()) {
            return Err(refused("changed while it was read".to_owned()));
        }
        if opened.mode() & 0o077 != 0 {
            return Err(refused(
                "may be read by others than its owner: chmod 600 it".to_owned(),
            ));
        }
        if opened.uid() != rustix::process::getuid().as_raw() {
            return Err(refused("belongs to another user".to_owned()));
        }
    }
    if !opened.is_file() || opened.len() > FILE_MAX {
        return Err(refused("is not a file of at most 64 KiB".to_owned()));
    }
    let mut bytes = Vec::new();
    file.take(FILE_MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| refused(error.to_string()))?;
    Ok(Credential::new(bytes))
}

/// What a Data Plane command asks for, from the configuration: `auth.client.scope` (by default
/// `decision.evaluate`), `audience` and `target`, comma-separated, elevated to `auth.client.role`
/// when one is set. Under a role the audience may be left out: the IAM Host addresses a member's
/// role to its member, and refuses a role that needs an audience.
fn data_plane_ask(store: &Store) -> Result<Asked, Failure> {
    let list = |key: &str| -> Vec<String> {
        crate::target::setting_value(key, store)
            .map(|(value, _)| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|held| !held.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    let scope = crate::target::setting_value("auth.client.scope", store)
        .map(|(value, _)| value.replace(',', " "))
        .unwrap_or_else(|| "decision.evaluate".to_owned());
    let role = crate::target::setting_value("auth.client.role", store).map(|(value, _)| value);
    let audience = list("auth.client.audience");
    if audience.is_empty() && role.is_none() {
        return Err(Failure::usage(
            "a client's Data Plane token is addressed: auth.client.audience, \
             member:<id> or group:<name>, or elevated to a member's role, auth.client.role",
        ));
    }
    let asked = Asked {
        scope,
        audience,
        target: list("auth.client.target"),
    };
    match role {
        Some(role) => asked
            .elevated(&role)
            .map_err(|failure| Failure::from_client(&failure)),
        None => Ok(asked),
    }
}

/// The TLS options a command that reaches a Data Plane sends with: the operator's, and, without a
/// `--token-file`, the configured client's token.
pub fn data_plane_tls(
    globals: &Globals,
    store: &Store,
    trace: &Trace,
) -> Result<TlsOptions, Failure> {
    let mut options = crate::target::tls(globals, store, trace)?;
    if options.token.is_some() {
        return Ok(options);
    }
    let configured = globals.client_id.is_some()
        || crate::target::setting_value("auth.client.id", store).is_some();
    if !configured {
        return Ok(options);
    }
    let asked = data_plane_ask(store)?;
    let cache = cache_path(globals, store, &asked)?;
    let Some(source) = source_with(globals, store, asked, trace)? else {
        return Ok(options);
    };
    if let Some(held) = cache.as_deref().and_then(read_cached) {
        source.hold(held);
    }
    let issued = source
        .token()
        .map_err(|failure| Failure::from_client(&failure))?;
    if let Some(cache) = &cache {
        write_cached(cache, &issued);
    }
    trace.say(format!(
        "acting with the client's token, valid until {}",
        permguard_core::time::to_rfc3339(i64::try_from(issued.expires_at).unwrap_or(i64::MAX))
    ));
    options.token = Some(issued.token);
    Ok(options)
}

/// Drops the token kept for the configured client and ask: a Data Plane refused it, revoked or
/// suspended, and the next command obtains another rather than sending it again.
pub fn forget(globals: &Globals, store: &Store) {
    let Ok(asked) = data_plane_ask(store) else {
        return;
    };
    if let Ok(Some(path)) = cache_path(globals, store, &asked) {
        let _ = std::fs::remove_file(path);
    }
}

/// Where the token for this client and this ask is kept: none without a home directory.
fn cache_path(globals: &Globals, store: &Store, asked: &Asked) -> Result<Option<PathBuf>, Failure> {
    let Ok(home) = crate::settings::home_directory() else {
        return Ok(None);
    };
    let client = globals
        .client_id
        .clone()
        .or_else(|| crate::target::setting_value("auth.client.id", store).map(|(value, _)| value))
        .unwrap_or_default();
    let endpoint = globals
        .iam_endpoint
        .clone()
        .or_else(|| {
            crate::target::setting_value("auth.client.iam_endpoint", store).map(|(value, _)| value)
        })
        .unwrap_or_default();
    // Not a secret, a name: which client, where, for what.
    let key = format!(
        "{client}\n{endpoint}\n{}\n{}\n{}",
        asked.scope,
        asked.audience.join(" "),
        asked.target.join(" ")
    );
    let digest = ring::digest::digest(&ring::digest::SHA256, key.as_bytes());
    let name: String = digest.as_ref()[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(Some(
        home.join(".permguard")
            .join("tokens")
            .join(format!("{name}.json")),
    ))
}

/// Whether `directory` is the user's own and only theirs: a cache anybody else could write or
/// read is not used.
fn private_directory(directory: &Path) -> bool {
    let Ok(held) = std::fs::symlink_metadata(directory) else {
        return false;
    };
    if !held.is_dir() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        held.uid() == rustix::process::getuid().as_raw() && held.mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn read_cached(path: &Path) -> Option<Issued> {
    if !path.parent().is_some_and(private_directory) {
        return None;
    }
    let held = private_file(path, "the token cache").ok()?;
    let value: serde_json::Value = serde_json::from_slice(held.expose()).ok()?;
    let token = value["token"].as_str()?;
    let expires_at = value["expires_at"].as_u64()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    (expires_at > now + REFRESH_AHEAD.as_secs()).then(|| Issued {
        token: Credential::new(token.as_bytes().to_vec()),
        expires_at,
    })
}

/// Keeps `issued` for the next command, in a directory and a file only their owner reads; a cache
/// that cannot be written costs the next command a request, never this one.
fn write_cached(path: &Path, issued: &Issued) {
    use std::io::Write as _;

    let Some(directory) = path.parent() else {
        return;
    };
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    if builder.create(directory).is_err() || !private_directory(directory) {
        return;
    }
    let Ok(token) = std::str::from_utf8(issued.token.expose()) else {
        return;
    };
    let body = serde_json::json!({"token": token, "expires_at": issued.expires_at}).to_string();
    let mut suffix = [0u8; 8];
    if ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut suffix).is_err() {
        return;
    }
    let aside = directory.join(format!(
        ".{}.part",
        suffix
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let written = options
        .open(&aside)
        .and_then(|mut file| file.write_all(body.as_bytes()))
        .and_then(|()| std::fs::rename(&aside, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&aside);
    }
}
