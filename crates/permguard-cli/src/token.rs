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
///
/// A file written on Windows is read as it comes: its CRLF is trimmed, a UTF-8 byte order mark is
/// dropped, and UTF-16, what Windows PowerShell 5 writes with `>`, is refused with how to save it.
/// On Windows the owner check is not made: an ACL check is a known gap (6-command-line § 1).
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
    let mut bytes = Vec::new();
    file.take(TOKEN_FILE_MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| refused(&format!("cannot be read: {error}")))?;
    if bytes.len() as u64 > TOKEN_FILE_MAX {
        return Err(refused("is larger than any token"));
    }
    let text = decode(&bytes).map_err(refused)?;
    let token = text.trim();
    if token.is_empty() {
        return Err(refused("is empty"));
    }
    if !token.bytes().all(|byte| (0x21..0x7f).contains(&byte)) {
        return Err(refused("does not hold one printable word"));
    }
    Ok(Credential::new(token.as_bytes().to_vec()))
}

/// The file's text: UTF-8, its byte order mark dropped. UTF-16 is named, never read as garbage.
fn decode(bytes: &[u8]) -> Result<&str, &'static str> {
    if bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF]) {
        return Err(
            "is UTF-16, as Windows PowerShell 5 writes with `>`: save it as UTF-8, \
                    for example with `Set-Content -Encoding ascii`",
        );
    }
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    std::str::from_utf8(bytes).map_err(|_| "is not UTF-8 text: save it as UTF-8")
}

/// Writes `token` to `path` for its owner alone, as [`read`] requires: written beside it, then
/// renamed over it, so a reader finds the old token or the new one, never half of one. On Unix
/// the file is created `0600` and its folder `0700` when it makes one; on Windows the file lands
/// in the user's profile, the folder only its owner reads there (6-command-line § 1).
pub fn write(path: &Path, token: &str) -> Result<(), String> {
    use std::io::Write as _;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.exists() {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder
            .create(parent)
            .map_err(|error| format!("creating {}: {error}", parent.display()))?;
    }
    let aside = parent.join(format!(
        ".{}.{}.part",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("session"),
        std::process::id()
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
        .and_then(|mut file| {
            file.write_all(token.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()
        })
        .and_then(|()| std::fs::rename(&aside, path));
    written.map_err(|error| {
        let _ = std::fs::remove_file(&aside);
        format!("writing {}: {error}", path.display())
    })
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
    fn a_token_written_on_windows_is_read() {
        let crlf = read(&written("crlf", "op-token\r\n", 0o600)).expect("CRLF");
        assert_eq!(crlf.expose(), b"op-token");
        let bom = read(&written("bom", "\u{feff}op-token\r\n", 0o600)).expect("a UTF-8 BOM");
        assert_eq!(bom.expose(), b"op-token");
    }

    #[test]
    fn a_utf16_token_is_refused_with_how_to_save_it() {
        let dir = written("utf16", "", 0o600);
        // `echo op-token > token` in Windows PowerShell 5: UTF-16 LE with its byte order mark.
        let mut utf16 = vec![0xFF, 0xFE];
        utf16.extend("op-token\r\n".encode_utf16().flat_map(u16::to_le_bytes));
        std::fs::write(&dir, utf16).expect("written");
        let refused = read(&dir).expect_err("UTF-16");
        assert!(
            refused.contains("UTF-16") && refused.contains("UTF-8"),
            "{refused}"
        );
        assert!(!refused.contains("op-token"), "{refused}");
    }

    #[test]
    fn a_folder_is_not_a_token_file() {
        let dir = written("folder", "x", 0o600);
        let refused = read(dir.parent().expect("a folder")).expect_err("refused");
        assert!(refused.contains("not a regular file"), "{refused}");
    }
}
