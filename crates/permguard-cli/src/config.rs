// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Reading and writing the CLI's own configuration.
//!
//! Four commands, and every one of them iterates [`SETTINGS`](crate::settings::SETTINGS) rather than
//! naming settings itself:
//!
//! * `show` reports every setting, its value, and which layer that value came from;
//! * `get` prints one value and nothing else, so a script can read it;
//! * `set` writes one value into the file, after checking it is one;
//! * `reset` takes a value back out, so it falls through to the environment or the default.

use std::io::{self, Write};

use serde::Serialize;

use crate::output::Report;
use crate::settings::{self, ConfigFile, Origin, Setting, Store};
use permguard_control_client::Endpoint;

/// What went wrong doing something to the configuration.
#[derive(Debug)]
pub enum Error {
    /// The store could not be read or written.
    Store(settings::Error),
    /// A key that is not a setting.
    UnknownKey { key: String },
    /// A value that is not valid for its setting.
    InvalidValue { key: String, detail: String },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(f, "{error}"),
            Self::UnknownKey { key } => {
                write!(
                    f,
                    "`{key}` is not a setting. The settings are: {}",
                    settings::keys()
                )
            }
            Self::InvalidValue { key, detail } => write!(f, "{key}: {detail}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<settings::Error> for Error {
    fn from(error: settings::Error) -> Self {
        Self::Store(error)
    }
}

/// Reports every setting, its value, and where that value came from.
///
/// The origin is the point. A `show` that prints values alone answers "what is configured" and
/// leaves the question an operator actually has — *why is it that, and where do I change it* — to be
/// answered by reading three places by hand.
pub fn show(store: &Store) -> ShowReport {
    let settings = settings::SETTINGS
        .iter()
        .map(|setting| {
            let resolved = settings::resolve(setting, store.file(), None, &settings::environment);

            SettingReport {
                key: setting.key,
                value: resolved.value,
                origin: resolved.origin,
                description: setting.description,
                env: setting.env,
                default: setting.default,
            }
        })
        .collect();

    ShowReport {
        config_file: store.path().display().to_string(),
        config_file_exists: store.exists(),
        settings,
    }
}

/// Reports one value, and nothing else.
pub fn get(store: &Store, key: &str) -> Result<GetReport, Error> {
    let setting = require(key)?;
    let resolved = settings::resolve(setting, store.file(), None, &settings::environment);

    Ok(GetReport {
        key: setting.key,
        value: resolved.value,
        origin: resolved.origin,
    })
}

/// Writes one value into the file.
pub fn set(store: &mut Store, key: &str, value: &str) -> Result<ChangeReport, Error> {
    let setting = require(key)?;

    validate(setting, value)?;

    let previous = store.file().get(setting).map(ToOwned::to_owned);

    store.file_mut().set(setting, Some(value.to_owned()));
    store.save()?;

    Ok(ChangeReport {
        action: "set",
        config_file: store.path().display().to_string(),
        changes: vec![Change {
            key: setting.key,
            previous,
            value: Some(value.to_owned()),
            effective: effective(setting, store.file()),
        }],
    })
}

/// Takes settings back out of the file: one of them, or all of them.
///
/// What it resets is the *file*, and only the file. An endpoint that comes from the environment goes
/// on coming from the environment, and the report says so — a reset that claimed to restore defaults
/// while a variable still overrode them would be the most misleading thing here.
pub fn reset(store: &mut Store, key: Option<&str>) -> Result<ChangeReport, Error> {
    let targets: Vec<&Setting> = match key {
        Some(key) => vec![require(key)?],
        None => settings::SETTINGS.iter().collect(),
    };
    let mut changes = Vec::new();

    for setting in targets {
        let previous = store.file().get(setting).map(ToOwned::to_owned);

        store.file_mut().set(setting, None);
        changes.push(Change {
            key: setting.key,
            previous,
            value: None,
            effective: effective(setting, store.file()),
        });
    }

    store.save()?;

    Ok(ChangeReport {
        action: "reset",
        config_file: store.path().display().to_string(),
        changes,
    })
}

/// Creates the file if it is not there, so that a first `config` command leaves something to edit.
pub fn ensure(store: &Store) -> Result<bool, Error> {
    if store.exists() {
        return Ok(false);
    }

    store.save()?;

    Ok(true)
}

/// What a setting resolves to now, after a change to the file.
fn effective(setting: &Setting, file: &ConfigFile) -> Effective {
    let resolved = settings::resolve(setting, file, None, &settings::environment);

    Effective {
        value: resolved.value,
        origin: resolved.origin,
    }
}

fn require(key: &str) -> Result<&'static Setting, Error> {
    settings::setting(key).ok_or_else(|| Error::UnknownKey {
        key: key.to_owned(),
    })
}

/// Checks a value before it is written, rather than when something tries to use it.
///
/// A configuration file that accepts anything moves the mistake from the command that made it to
/// whatever command runs next, which is where it is hardest to understand.
fn validate(setting: &Setting, value: &str) -> Result<(), Error> {
    if setting.key.ends_with(".endpoint") {
        Endpoint::parse(value).map_err(|error| Error::InvalidValue {
            key: setting.key.to_owned(),
            detail: error.to_string(),
        })?;
    }

    Ok(())
}

/// One setting, as `show` reports it.
#[derive(Debug, Serialize)]
pub struct SettingReport {
    pub key: &'static str,
    pub value: String,
    pub origin: Origin,
    pub description: &'static str,
    pub env: &'static str,
    pub default: &'static str,
}

/// Every setting, and the file they are kept in.
#[derive(Debug, Serialize)]
pub struct ShowReport {
    pub config_file: String,
    pub config_file_exists: bool,
    pub settings: Vec<SettingReport>,
}

impl Report for ShowReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(out, "Permguard CLI configuration")?;
        writeln!(
            out,
            "  file: {}{}",
            self.config_file,
            if self.config_file_exists {
                ""
            } else {
                " (not created yet)"
            }
        )?;
        writeln!(out)?;

        let width = self
            .settings
            .iter()
            .map(|setting| setting.key.len())
            .max()
            .unwrap_or_default();

        for setting in &self.settings {
            writeln!(
                out,
                "  {:width$}  {}  [{}]",
                setting.key,
                setting.value,
                setting.origin.as_str()
            )?;
        }

        Ok(())
    }
}

/// One value, as `get` reports it.
#[derive(Debug, Serialize)]
pub struct GetReport {
    pub key: &'static str,
    pub value: String,
    pub origin: Origin,
}

impl Report for GetReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        // The value alone, on a line of its own: `get` exists to be read by something else.
        writeln!(out, "{}", self.value)
    }
}

/// What a setting resolves to after a change.
#[derive(Debug, Serialize)]
pub struct Effective {
    pub value: String,
    pub origin: Origin,
}

/// One setting that changed.
#[derive(Debug, Serialize)]
pub struct Change {
    pub key: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub effective: Effective,
}

/// What `set` and `reset` did.
#[derive(Debug, Serialize)]
pub struct ChangeReport {
    pub action: &'static str,
    pub config_file: String,
    pub changes: Vec<Change>,
}

impl Report for ChangeReport {
    fn render_terminal(&self, out: &mut dyn Write) -> io::Result<()> {
        for change in &self.changes {
            match &change.value {
                Some(value) => writeln!(out, "{} set to {value}", change.key)?,
                None => writeln!(out, "{} reset", change.key)?,
            }

            // Saying what the setting is *now* is the part that stops a support call: a file that
            // was written while an environment variable overrides it looks like a command that did
            // nothing.
            if change.effective.origin != Origin::File {
                writeln!(
                    out,
                    "  in effect: {} [{}]",
                    change.effective.value, change.effective.origin
                )?;
            }
        }

        writeln!(out, "written to {}", self.config_file)
    }
}
