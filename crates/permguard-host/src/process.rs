// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The process the Host runs as, and what it leaves behind when it dies (TS-5).
//!
//! The Host runs as a dedicated user, never as root: a root process ignores the modes that keep
//! its volume private, and owns whatever it creates as root. And a Host that crashes writes no core
//! file: one would hold every key, secret and request the process had in memory, on a disk outside
//! the volume's protection. [`disable_core_dumps`] sets the core-file limit to zero, soft and hard,
//! and on Linux also marks the process not dumpable, which keeps a core from a `core_pattern` pipe
//! that ignores the limit, and keeps other processes of the same user from attaching to it. Both are
//! read back: a disabling that did not take is reported, never assumed.

/// The process's effective user id; `None` where there is none (Windows).
#[cfg(unix)]
pub fn effective_uid() -> Option<u32> {
    Some(rustix::process::geteuid().as_raw())
}

#[cfg(not(unix))]
pub fn effective_uid() -> Option<u32> {
    None
}

/// Whether the process runs as root.
pub fn runs_as_root() -> bool {
    effective_uid() == Some(0)
}

/// Disables core dumps for this process and the processes it starts, and verifies it: an error
/// says what is still enabled.
#[cfg(unix)]
pub fn disable_core_dumps() -> Result<(), String> {
    use rustix::process::{Resource, Rlimit};

    let none = Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    rustix::process::setrlimit(Resource::Core, none)
        .map_err(|error| format!("setting the core-file limit to zero: {error}"))?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|error| format!("marking the process not dumpable: {error}"))?;
    core_dumps_disabled()
}

#[cfg(not(unix))]
pub fn disable_core_dumps() -> Result<(), String> {
    Err("this platform offers no way to disable core dumps the Host verifies".to_owned())
}

/// Whether core dumps are disabled, read from the process itself.
#[cfg(unix)]
pub fn core_dumps_disabled() -> Result<(), String> {
    let limit = rustix::process::getrlimit(rustix::process::Resource::Core);
    if limit.current != Some(0) || limit.maximum != Some(0) {
        return Err(format!(
            "the core-file limit reads {} soft and {} hard, not zero",
            or_unlimited(limit.current),
            or_unlimited(limit.maximum)
        ));
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    match rustix::process::dumpable_behavior() {
        Ok(rustix::process::DumpableBehavior::NotDumpable) => {}
        Ok(other) => return Err(format!("the process is still dumpable ({other:?})")),
        Err(error) => return Err(format!("reading whether the process is dumpable: {error}")),
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn core_dumps_disabled() -> Result<(), String> {
    Err("this platform offers no way to read whether core dumps are disabled".to_owned())
}

#[cfg(unix)]
fn or_unlimited(limit: Option<u64>) -> String {
    limit.map_or_else(|| "unlimited".to_owned(), |limit| limit.to_string())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn the_effective_uid_is_the_process_s() {
        assert_eq!(effective_uid(), Some(rustix::process::geteuid().as_raw()));
        assert_eq!(runs_as_root(), effective_uid() == Some(0));
    }

    /// Disabling is read back, and stays disabled: the hard limit cannot be raised again by a
    /// process that is not privileged.
    #[test]
    fn core_dumps_are_disabled_and_verified() {
        disable_core_dumps().expect("core dumps are disabled");
        core_dumps_disabled().expect("and read back as disabled");
        let limit = rustix::process::getrlimit(rustix::process::Resource::Core);
        assert_eq!((limit.current, limit.maximum), (Some(0), Some(0)));
        // Idempotent: a second Bootstrap in the same process disables them again.
        disable_core_dumps().expect("again");
    }
}
