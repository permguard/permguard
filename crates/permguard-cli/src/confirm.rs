// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `--confirm-file <receipt>`: the plan a run consumes, read whole from the file the plan step
//! wrote (TC-1), since WP-3.9 the COSE plan receipt itself. A receipt never travels in argv; what
//! it holds is never echoed in a refusal, which names the file and what is wrong with it, and
//! nothing it contains.

use std::path::Path;

use crate::failure::Failure;

/// Reads the receipt `confirm_file` names as raw bytes, a `what` of at most `most` bytes: refused
/// when no file was named, when it cannot be read, when it is empty or larger. What it holds is
/// the caller's to check, and never echoed.
pub fn read_bytes(
    confirm_file: Option<&Path>,
    what: &str,
    most: usize,
) -> Result<Vec<u8>, Failure> {
    let path = confirm_file.ok_or_else(|| {
        Failure::usage(format!(
            "--confirm-file names the {what} the plan step wrote"
        ))
    })?;
    read_named(path, "--confirm-file", what, most)
}

/// [`read_bytes`] of the file the flag `flag` named: its refusals name that flag (TC-3).
pub fn read_named(path: &Path, flag: &str, what: &str, most: usize) -> Result<Vec<u8>, Failure> {
    let size = std::fs::metadata(path)
        .map_err(|error| Failure::usage(format!("{flag} {}: {error}", path.display())))?
        .len();
    if size == 0 {
        return Err(Failure::usage(format!(
            "{flag} {} is empty",
            path.display()
        )));
    }
    if size > most as u64 {
        return Err(Failure::usage(format!(
            "{flag} {} is {size} bytes; a {what} takes up to {most}",
            path.display()
        )));
    }
    std::fs::read(path)
        .map_err(|error| Failure::usage(format!("{flag} {}: {error}", path.display())))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn a_confirm_file_is_read_whole_within_its_bound() {
        let dir = std::env::temp_dir().join(format!("permguard-confirm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("created");
        let good = dir.join("good.plan");
        std::fs::write(&good, [0x84, 0x40, 0xA0]).expect("written");
        let Ok(read) = read_bytes(Some(&good), "plan", 16) else {
            panic!("a plan reads")
        };
        assert_eq!(read, vec![0x84, 0x40, 0xA0]);

        let Err(missing) = read_bytes(None, "plan", 16) else {
            panic!("nothing named")
        };
        assert_eq!(missing.status, crate::failure::EXIT_USAGE);
        let empty = dir.join("empty.plan");
        std::fs::write(&empty, []).expect("written");
        let Err(empty) = read_bytes(Some(&empty), "plan", 16) else {
            panic!("empty")
        };
        assert!(empty.message.contains("is empty"), "{}", empty.message);
        let secret = "capability-0123456789-do-not-print";
        let large = dir.join("large.plan");
        std::fs::write(&large, secret).expect("written");
        let Err(refused) = read_bytes(Some(&large), "plan", 16) else {
            panic!("over its bound")
        };
        assert!(
            refused.message.contains("takes up to 16"),
            "{}",
            refused.message
        );
        assert!(!refused.message.contains(secret), "{}", refused.message);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
