// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The operator's bearer token, read from its file the one way the CLI reads it, so a program that
//! embeds the CLI refuses the same files the command does.

use std::path::Path;

use permguard_control_client::tls::Credential;

/// The most a token file may hold: a token is a line, not a document.
const TOKEN_FILE_MAX: u64 = 64 * 1024;

/// Reads the bearer token from `path`: refused when it is not a regular file, when others than
/// its owner may read it, when it is empty or larger than a token, or when it is not one printable
/// word (TC-1, owner decision of 2026-10-10). The path is checked before it is opened, so a FIFO
/// never blocks the command, and the handle is checked to be that same file.
pub fn read(path: &Path) -> Result<Credential, String> {
    use std::io::Read as _;

    let refused = |why: &str| format!("the token file {}: {why}", path.display());
    // A regular file before it is opened: opening a FIFO would wait for a writer forever.
    let named =
        std::fs::metadata(path).map_err(|error| refused(&format!("cannot be read: {error}")))?;
    if !named.is_file() {
        return Err(refused("is not a regular file"));
    }
    let file =
        std::fs::File::open(path).map_err(|error| refused(&format!("cannot be read: {error}")))?;
    let metadata = file
        .metadata()
        .map_err(|error| refused(&format!("cannot be read: {error}")))?;
    // And the file opened is the file checked: a path swapped between the two is refused.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if (named.dev(), named.ino()) != (metadata.dev(), metadata.ino()) {
            return Err(refused("changed while it was being read"));
        }
    }
    if !metadata.is_file() {
        return Err(refused("is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(refused(
                "is open to its group or to others: restrict it to its owner (chmod 600)",
            ));
        }
    }
    let mut text = String::new();
    file.take(TOKEN_FILE_MAX + 1)
        .read_to_string(&mut text)
        .map_err(|error| refused(&format!("cannot be read: {error}")))?;
    if text.len() as u64 > TOKEN_FILE_MAX {
        return Err(refused("is larger than any token"));
    }
    let token = text.trim();
    if token.is_empty() {
        return Err(refused("is empty"));
    }
    if !token.bytes().all(|byte| (0x21..0x7f).contains(&byte)) {
        return Err(refused("does not hold one printable word"));
    }
    Ok(Credential::new(token.as_bytes().to_vec()))
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn written(tag: &str, contents: &str, mode: u32) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("permguard-token-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a directory");
        let path = dir.join("token");
        std::fs::write(&path, contents).expect("written");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        path
    }

    #[test]
    fn the_owners_token_is_read_trimmed() {
        let token = read(&written("ok", "op-token\n", 0o600)).expect("read");
        assert_eq!(token.expose(), b"op-token");
    }

    #[test]
    fn a_token_others_can_read_is_refused_without_its_value() {
        let refused = read(&written("open", "op-token-secret\n", 0o644)).expect_err("refused");
        assert!(refused.contains("chmod 600"), "{refused}");
        assert!(!refused.contains("op-token-secret"), "{refused}");
    }

    #[test]
    fn an_empty_or_spaced_token_is_refused() {
        assert!(
            read(&written("empty", "  \n", 0o600))
                .expect_err("empty")
                .contains("is empty")
        );
        assert!(
            read(&written("words", "two words\n", 0o600))
                .expect_err("two words")
                .contains("one printable word")
        );
    }

    #[test]
    fn a_folder_is_not_a_token_file() {
        let dir = written("folder", "x", 0o600);
        let refused = read(dir.parent().expect("a folder")).expect_err("refused");
        assert!(refused.contains("not a regular file"), "{refused}");
    }
}
