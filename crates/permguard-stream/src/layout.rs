// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Where a stream lives on disk, decided by one rule instead of by each writer.
//!
//! # The layout
//!
//! ```text
//! <data root>/streams/<plane>/<stream type>/<role>/
//! <data root>/streams/LAYOUT              — the version marker, `v1`
//! ```
//!
//! One directory per (plane, type, role): planes hosted in one process cannot overwrite each
//! other, a producer and a consumer of the same stream keep separate trees, and a backup that
//! wants "everything the data plane produced" is one path.
//!
//! # What this does **not** do
//!
//! It moves nothing. The streams that predate this layout — the decision spool at
//! `data/decisions/spool`, the event journals under `data/events` and the stores beside them —
//! keep the directories they already write, registered as legacy in the
//! [registry](crate::descriptor::StreamRegistry). Recorded evidence is not something a version
//! bump relocates silently; when those streams move, they move by an explicit migration that
//! says so. What the versioned layout owns today is every stream that did not exist yet.

use std::path::{Path, PathBuf};

use crate::descriptor::{Role, StreamIdentity};

/// The current layout version, written to the marker the first time the layout is used.
pub const LAYOUT_VERSION: &str = "v1";

/// The marker file's name, directly under the streams root.
pub const LAYOUT_MARKER: &str = "LAYOUT";

/// The directory every versioned stream lives under.
pub fn streams_root(data_root: &Path) -> PathBuf {
    data_root.join("streams")
}

/// The directory one stream keeps its data in.
pub fn stream_directory(data_root: &Path, identity: &StreamIdentity, role: Role) -> PathBuf {
    streams_root(data_root)
        .join(identity.plane())
        .join(identity.stream_type())
        .join(role.as_str())
}

/// The legacy directories a pre-layout volume may hold, for the composition's startup report.
///
/// Names, not judgements: the composition decides what to log. Listed here so the knowledge of
/// what "old" looks like lives beside the definition of "new".
pub fn legacy_roots(data_root: &Path) -> [PathBuf; 2] {
    [data_root.join("decisions"), data_root.join("events")]
}

/// Reads the marker, or claims the root for the current version when it is unclaimed.
///
/// A root marked with a version this build does not know is refused rather than reinterpreted:
/// a future layout may mean the same directories differently, and guessing against recorded
/// evidence is the one wrong answer.
pub fn claim(data_root: &Path) -> std::io::Result<String> {
    let root = streams_root(data_root);
    let marker = root.join(LAYOUT_MARKER);

    match std::fs::read_to_string(&marker) {
        Ok(held) => {
            let held = held.trim().to_owned();
            if held != LAYOUT_VERSION {
                return Err(std::io::Error::other(format!(
                    "the streams root {} is laid out as `{held}` and this build writes \
                     `{LAYOUT_VERSION}`: refusing to guess what its directories mean",
                    root.display()
                )));
            }

            Ok(held)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(&root)?;
            std::fs::write(&marker, format!("{LAYOUT_VERSION}\n"))?;

            Ok(LAYOUT_VERSION.to_owned())
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn the_directory_is_plane_then_type_then_role() {
        let identity = StreamIdentity::new("data-plane", "events").unwrap();

        assert_eq!(
            stream_directory(Path::new("data"), &identity, Role::Producer),
            PathBuf::from("data/streams/data-plane/events/producer")
        );
    }

    #[test]
    fn an_unclaimed_root_is_claimed_and_a_claimed_one_agrees() {
        let root = std::env::temp_dir().join(format!("layout-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);

        assert_eq!(claim(&root).unwrap(), LAYOUT_VERSION);
        assert_eq!(
            claim(&root).unwrap(),
            LAYOUT_VERSION,
            "claiming twice is reading"
        );

        // A root laid out by a build this one does not know is refused, not guessed at.
        std::fs::write(streams_root(&root).join(LAYOUT_MARKER), "v9\n").unwrap();
        assert!(claim(&root).is_err());

        std::fs::remove_dir_all(&root).ok();
    }
}
