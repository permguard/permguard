// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `clone` and the ledger a workspace tracks: a new workspace bound to one ledger of a remote and
//! pulled whole, and the remote a later pull asks. One code path for `permguard clone` and
//! `permguard pull` and for a program that embeds the engine: the binary adds the arguments, the
//! fallback of its own configuration and the output, nothing else.

use std::path::Path;

use permguard_control_client::{AnyRemote, FsStore, Store as _};

use super::config::{RemoteConfig, WorkspaceConfig};
use super::{DEFAULT_IGNORES, DEFAULT_REF, PullOutcome, Result, Workspace, err};
use crate::engine::remote::Remote;

/// The name a clone gives the remote it was cloned from.
pub const ORIGIN: &str = "origin";

/// What `.permguardignore` is called in a workspace.
const IGNORE_FILE: &str = ".permguardignore";

/// Clones `zone`/`ledger` of the remote at `base` into `target`, over `remote`, connected to that
/// same URL by the caller.
///
/// Like git, a destination that exists and is not empty is refused rather than merged into. The
/// workspace names `base` as `origin`, gets the `.permguardignore` that `init` writes, and checks
/// out the ledger's default ref. A clone that fails half-way leaves the folder it created; whether
/// to remove it is the caller's choice.
pub fn clone(
    target: &Path,
    base: &str,
    zone: &str,
    ledger: &str,
    remote: &dyn Remote,
) -> Result<PullOutcome> {
    if target.exists()
        && std::fs::read_dir(target)
            .map(|mut entries| entries.next().is_some())
            .unwrap_or(false)
    {
        return Err(err(format!(
            "destination `{}` already exists and is not empty",
            target.display()
        )));
    }
    std::fs::create_dir_all(target)
        .map_err(|error| err(format!("creating {}: {error}", target.display())))?;
    let store = FsStore::new(target);
    let workspace = Workspace::open(&store);
    let mut config = WorkspaceConfig::new();
    config.remotes.insert(
        ORIGIN.to_owned(),
        RemoteConfig {
            url: base.to_owned(),
            tls_ca_file: None,
        },
    );
    workspace.save_config(&config)?;
    // The same neighbours `init` excuses, so a clone that grows a README or a `tests/` folder is
    // not dirty from its first commit.
    if !store.exists(IGNORE_FILE) {
        store
            .write(IGNORE_FILE, DEFAULT_IGNORES.as_bytes())
            .map_err(err)?;
    }
    workspace.checkout(remote, ORIGIN, zone, ledger, DEFAULT_REF)
}

/// The ledger a workspace tracks, and where it is pulled from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tracked {
    /// The name of its remote in the workspace.
    pub remote: String,
    /// The URL the workspace records for that remote; `None` when it records none, and the caller
    /// decides where the remote is.
    pub url: Option<String>,
    pub zone_id: String,
    pub ledger_id: String,
}

impl Tracked {
    /// Binds a remote to the tracked ledger's ids, when the workspace knows them: a binding written
    /// before the ids were recorded leaves the remote to resolve the names.
    pub fn bind(&self, remote: &AnyRemote) {
        if !self.zone_id.is_empty() {
            remote.bind(&self.zone_id, &self.ledger_id);
        }
    }
}

impl Workspace<'_> {
    /// The ledger this workspace tracks: refused when it tracks none.
    pub fn tracked(&self) -> Result<Tracked> {
        let config = self.config()?;
        let ledger = config
            .ledger
            .ok_or_else(|| err("no tracked ledger: run `permguard checkout` first"))?;
        let url = config
            .remotes
            .get(&ledger.remote)
            .map(|remote| remote.url.clone());
        Ok(Tracked {
            remote: ledger.remote,
            url,
            zone_id: ledger.zone_id,
            ledger_id: ledger.ledger_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("permguard-clone-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("a directory");
        root
    }

    #[test]
    fn a_workspace_tracking_nothing_says_so() {
        let store = FsStore::new(scratch("untracked"));
        let workspace = Workspace::open(&store);
        let refused = workspace.tracked().expect_err("not a workspace");
        assert!(refused.message.contains("not a workspace"), "{refused}");
        workspace
            .save_config(&WorkspaceConfig::new())
            .expect("saved");
        let refused = workspace.tracked().expect_err("tracks nothing");
        assert!(refused.message.contains("no tracked ledger"), "{refused}");
    }

    #[test]
    fn the_tracked_ledger_names_its_remote_and_its_url() {
        let store = FsStore::new(scratch("tracked"));
        let workspace = Workspace::open(&store);
        let mut config = WorkspaceConfig::new();
        config.remotes.insert(
            ORIGIN.to_owned(),
            RemoteConfig {
                url: "https://plane.example:9443".to_owned(),
                tls_ca_file: None,
            },
        );
        config.ledger = Some(super::super::config::LedgerConfig {
            remote: ORIGIN.to_owned(),
            zone: "commerce".to_owned(),
            ledger: "orders".to_owned(),
            zone_id: "z-1".to_owned(),
            ledger_id: "l-1".to_owned(),
        });
        workspace.save_config(&config).expect("saved");
        assert_eq!(
            workspace.tracked().expect("tracked"),
            Tracked {
                remote: ORIGIN.to_owned(),
                url: Some("https://plane.example:9443".to_owned()),
                zone_id: "z-1".to_owned(),
                ledger_id: "l-1".to_owned(),
            }
        );
    }

    #[test]
    fn a_ledger_without_a_remote_url_leaves_the_url_to_the_caller() {
        let store = FsStore::new(scratch("no-url"));
        let workspace = Workspace::open(&store);
        let mut config = WorkspaceConfig::new();
        config.ledger = Some(super::super::config::LedgerConfig {
            remote: "elsewhere".to_owned(),
            zone: "commerce".to_owned(),
            ledger: "orders".to_owned(),
            ..Default::default()
        });
        workspace.save_config(&config).expect("saved");
        let tracked = workspace.tracked().expect("tracked");
        assert_eq!(tracked.url, None);
        assert_eq!(tracked.remote, "elsewhere");
    }
}
