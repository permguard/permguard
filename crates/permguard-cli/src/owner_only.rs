// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Owner-only files on Windows (BUG-0325): what the mode does on Unix, an access list does there.
//! Every file and folder this command writes for its owner alone is restricted when it is
//! written, and every one it reads as its owner's is refused when its access list grants anybody
//! else, the way a mode open to the group or to others is refused on Unix.

use std::path::Path;

/// Restricts `path`, which this command just created, to its owner: on Windows a protected access
/// list; elsewhere nothing, the mode having done it at creation.
pub(crate) fn restrict(path: &Path) -> Result<(), String> {
    permguard_owner_only::restrict_to_owner(path)
        .map_err(|error| format!("restricting {} to its owner: {error}", path.display()))
}

/// Why `path` is not its owner's alone, on Windows: the principals its access list grants and how
/// to restrict it; `None` when it is, and always elsewhere.
pub(crate) fn open_to_others(path: &Path) -> Option<String> {
    #[cfg(windows)]
    {
        match permguard_owner_only::access_beyond_owner(path) {
            Ok(beyond) if beyond.is_empty() => None,
            Ok(beyond) => Some(format!(
                "may be read by others than its owner ({}): restrict it with \
                 `icacls \"{}\" /inheritance:r /grant:r \"%USERNAME%:F\"`",
                beyond.join(", "),
                path.display()
            )),
            Err(error) => Some(format!("its access list cannot be read: {error}")),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        None
    }
}
