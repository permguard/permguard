// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the CLI is configured with, where each value came from, and the file it is kept in.
//!
//! # Four layers, in one order
//!
//! A value is read from the first layer that states it:
//!
//! 1. a **flag**, which is what the operator just typed and therefore always wins;
//! 2. the **environment**, which is how a deployment or a CI job states a context;
//! 3. the **configuration file**, which is how a person states their own context once;
//! 4. the **default** compiled in, which is a local development runtime.
//!
//! The order is the same one the planes resolve their own configuration in, and it is the only order
//! that makes both automation and interactive use work: an environment that could override a flag
//! would make a typed argument unpredictable, and a file that could override the environment would
//! make one developer's machine unable to run against staging.
//!
//! # Why the settings are a table
//!
//! Every setting is a row in [`SETTINGS`], carrying its key, its environment variable, its default,
//! and how it is read from and written to the file. `show`, `get`, `set` and `reset` all iterate that
//! table rather than naming settings themselves, so a new setting is one row and cannot be added to
//! three of the four commands.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Where the configuration file lives, under the user's home.
const CONFIG_DIRECTORY: &str = ".permguard";
const CONFIG_FILE: &str = "config.yml";

/// What is written at the top of a file this CLI creates.
const FILE_HEADER: &str = "\
# The Permguard command-line configuration.
#
# Values here are overridden by the matching environment variable, and by a flag on the command
# line. `permguard config show` reports which layer each value came from.
#
# Edit with `permguard config set <key> <value>`.
";

/// The layer a value came from.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// Compiled in.
    Default,
    /// Read from the configuration file.
    File,
    /// Read from the environment.
    Environment,
    /// Typed on the command line.
    Flag,
}

impl Origin {
    /// The origin as it is written in a report.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::File => "file",
            Self::Environment => "environment",
            Self::Flag => "flag",
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One thing that can be configured.
pub struct Setting {
    /// How it is named on the command line and in the file.
    pub key: &'static str,
    /// What it is, in a sentence.
    pub description: &'static str,
    /// The environment variable that states it.
    pub env: &'static str,
    /// The value compiled in.
    pub default: &'static str,
    /// Reads it out of a configuration file.
    read: fn(&ConfigFile) -> Option<&str>,
    /// Writes it into a configuration file, or removes it.
    write: fn(&mut ConfigFile, Option<String>),
}

/// Every setting there is.
pub const SETTINGS: &[Setting] = &[
    Setting {
        key: "control-plane.endpoint",
        description: "Where the control plane is reached",
        env: "PERMGUARD_CONTROL_PLANE_ENDPOINT",
        default: "http://127.0.0.1:6443",
        read: |file| file.control_plane.endpoint.as_deref(),
        write: |file, value| file.control_plane.endpoint = value,
    },
    Setting {
        key: "data-plane.endpoint",
        description: "Where the data plane is reached",
        env: "PERMGUARD_DATA_PLANE_ENDPOINT",
        default: "http://127.0.0.1:7443",
        read: |file| file.data_plane.endpoint.as_deref(),
        write: |file, value| file.data_plane.endpoint = value,
    },
];

/// Returns the setting a key names.
pub fn setting(key: &str) -> Option<&'static Setting> {
    SETTINGS.iter().find(|setting| setting.key == key)
}

/// Every key there is, for an error message that has to list them.
pub fn keys() -> String {
    SETTINGS
        .iter()
        .map(|setting| setting.key)
        .collect::<Vec<_>>()
        .join(", ")
}

/// A value, and the layer it came from.
#[derive(Debug)]
pub struct Resolved {
    pub value: String,
    pub origin: Origin,
}

/// Reads one setting through every layer, in order.
///
/// The environment is read through a function rather than directly, which is what makes the order
/// testable without a process to set variables in.
pub fn resolve(
    setting: &Setting,
    file: &ConfigFile,
    flag: Option<&str>,
    environment: &dyn Fn(&str) -> Option<String>,
) -> Resolved {
    if let Some(value) = flag {
        return Resolved {
            value: value.to_owned(),
            origin: Origin::Flag,
        };
    }

    if let Some(value) = environment(setting.env).filter(|value| !value.is_empty()) {
        return Resolved {
            value,
            origin: Origin::Environment,
        };
    }

    if let Some(value) = (setting.read)(file) {
        return Resolved {
            value: value.to_owned(),
            origin: Origin::File,
        };
    }

    Resolved {
        value: setting.default.to_owned(),
        origin: Origin::Default,
    }
}

/// Reads a variable out of the real environment.
pub fn environment(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// The configuration file's contents.
///
/// A setting nothing has set is absent rather than written as its default, so that a default which
/// changes in a later release reaches a file written by an earlier one. A file full of pinned
/// defaults is a file that silently stops tracking the product.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ConfigFile {
    #[serde(skip_serializing_if = "Section::is_empty")]
    control_plane: Section,
    #[serde(skip_serializing_if = "Section::is_empty")]
    data_plane: Section,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
struct Section {
    #[serde(skip_serializing_if = "Option::is_none")]
    endpoint: Option<String>,
}

impl Section {
    fn is_empty(&self) -> bool {
        self.endpoint.is_none()
    }
}

impl ConfigFile {
    /// Whether the file states anything at all.
    pub fn is_empty(&self) -> bool {
        SETTINGS
            .iter()
            .all(|setting| (setting.read)(self).is_none())
    }

    /// States a setting, or removes it when given nothing.
    pub fn set(&mut self, setting: &Setting, value: Option<String>) {
        (setting.write)(self, value);
    }

    /// Reads a setting, as the file states it.
    pub fn get(&self, setting: &Setting) -> Option<&str> {
        (setting.read)(self)
    }
}

/// The configuration file, and where it is.
#[derive(Debug)]
pub struct Store {
    path: PathBuf,
    file: ConfigFile,
}

impl Store {
    /// Reads the file, if there is one.
    ///
    /// A file that is not there is not an error: it means every setting is at its default, which is
    /// a perfectly good state for a machine nobody has configured yet. A file that is there and
    /// unreadable *is* an error — silently continuing with defaults would run a command against a
    /// different server than the one the operator configured.
    pub fn open(path: PathBuf) -> Result<Self, Error> {
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Self {
                    path,
                    file: ConfigFile::default(),
                });
            }
            Err(source) => return Err(Error::Read { path, source }),
        };
        let file = serde_norway::from_str(&text).map_err(|error| Error::Parse {
            path: path.clone(),
            detail: error.to_string(),
        })?;

        Ok(Self { path, file })
    }

    /// Where the file is, whether or not it exists.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether the file exists on disk.
    pub fn exists(&self) -> bool {
        self.path.is_file()
    }

    /// What the file states.
    pub fn file(&self) -> &ConfigFile {
        &self.file
    }

    /// What the file states, to be changed.
    pub fn file_mut(&mut self) -> &mut ConfigFile {
        &mut self.file
    }

    /// Writes the file, creating the directory it lives in.
    ///
    /// The directory is created private to the user. It is where credentials and endpoints of
    /// production systems end up, and a home directory shared with other accounts is not unusual on
    /// the machines this runs on.
    pub fn save(&self) -> Result<(), Error> {
        if let Some(directory) = self.path.parent() {
            create_private_directory(directory).map_err(|source| Error::Write {
                path: directory.to_path_buf(),
                source,
            })?;
        }

        let body = serde_norway::to_string(&self.file).map_err(|error| Error::Encode {
            detail: error.to_string(),
        })?;
        // An empty document serialises as `{}`, which is technically a map and reads like a mistake.
        let body = if self.file.is_empty() {
            String::new()
        } else {
            body
        };

        fs::write(&self.path, format!("{FILE_HEADER}{body}")).map_err(|source| Error::Write {
            path: self.path.clone(),
            source,
        })
    }
}

/// Creates a directory only the user can read.
#[cfg(unix)]
fn create_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    if path.is_dir() {
        return Ok(());
    }

    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)
}

/// Where the configuration file is, given what the operator asked for.
///
/// An explicit path wins, because a CI job that has to be reproducible cannot depend on whose home
/// directory it happens to run in.
pub fn config_path(explicit: Option<&str>) -> Result<PathBuf, Error> {
    if let Some(path) = explicit {
        return Ok(PathBuf::from(path));
    }

    Ok(home_directory()?.join(CONFIG_DIRECTORY).join(CONFIG_FILE))
}

/// The user's home directory, from the environment.
fn home_directory() -> Result<PathBuf, Error> {
    for name in ["HOME", "USERPROFILE"] {
        if let Some(home) = environment(name).filter(|home| !home.is_empty()) {
            return Ok(PathBuf::from(home));
        }
    }

    Err(Error::NoHome)
}

/// Every way the configuration file can fail us.
#[derive(Debug)]
pub enum Error {
    NoHome,
    Read { path: PathBuf, source: io::Error },
    Write { path: PathBuf, source: io::Error },
    Parse { path: PathBuf, detail: String },
    Encode { detail: String },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoHome => write!(
                f,
                "no home directory: neither HOME nor USERPROFILE is set, so pass --config with a path"
            ),
            Self::Read { path, source } => write!(f, "reading {}: {source}", path.display()),
            Self::Write { path, source } => write!(f, "writing {}: {source}", path.display()),
            Self::Parse { path, detail } => {
                write!(f, "{} is not valid configuration: {detail}", path.display())
            }
            Self::Encode { detail } => write!(f, "encoding the configuration: {detail}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn control() -> &'static Setting {
        setting("control-plane.endpoint").expect("the control plane endpoint is a setting")
    }

    fn nothing(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn test_a_setting_nothing_states_is_its_default() {
        let resolved = resolve(control(), &ConfigFile::default(), None, &nothing);

        assert_eq!(resolved.value, "http://127.0.0.1:6443");
        assert_eq!(resolved.origin, Origin::Default);
    }

    #[test]
    fn test_each_layer_overrides_the_one_below_it() {
        let mut file = ConfigFile::default();
        file.set(control(), Some("http://from-file:6443".to_owned()));

        let from_file = resolve(control(), &file, None, &nothing);

        assert_eq!(from_file.value, "http://from-file:6443");
        assert_eq!(from_file.origin, Origin::File);

        let environment =
            |name: &str| (name == control().env).then(|| "http://from-environment:6443".to_owned());
        let from_environment = resolve(control(), &file, None, &environment);

        assert_eq!(from_environment.value, "http://from-environment:6443");
        assert_eq!(from_environment.origin, Origin::Environment);

        let from_flag = resolve(
            control(),
            &file,
            Some("http://from-flag:6443"),
            &environment,
        );

        assert_eq!(from_flag.value, "http://from-flag:6443");
        assert_eq!(from_flag.origin, Origin::Flag);
    }

    /// An exported-but-empty variable is how a shell unsets one in practice, and it should mean
    /// "nothing stated here" rather than "the endpoint is the empty string".
    #[test]
    fn test_an_empty_environment_variable_states_nothing() {
        let environment = |_: &str| Some(String::new());
        let resolved = resolve(control(), &ConfigFile::default(), None, &environment);

        assert_eq!(resolved.origin, Origin::Default);
    }

    #[test]
    fn test_a_file_only_carries_what_was_set() {
        let mut file = ConfigFile::default();

        assert!(file.is_empty());

        file.set(control(), Some("http://one:6443".to_owned()));

        let written = serde_norway::to_string(&file).expect("a file serialises");

        assert!(written.contains("controlPlane"), "{written}");
        assert!(written.contains("http://one:6443"), "{written}");
        // The setting nobody stated is absent, not pinned to today's default.
        assert!(!written.contains("dataPlane"), "{written}");

        file.set(control(), None);

        assert!(file.is_empty());
    }
}
