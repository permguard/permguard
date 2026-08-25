// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Terminal styling — the change dialect every workspace command
//! speak: `+` green, `~` yellow, `-` red, identifiers cyan, chrome dim.
//!
//! Color is a property of *where the output lands*, never of the data:
//! enabled only when stdout is a terminal, `NO_COLOR` is unset and `TERM`
//! is not `dumb` — piped output stays byte-clean without asking.

use std::io::IsTerminal as _;
use std::sync::OnceLock;

fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::io::stdout().is_terminal()
            && std::env::var_os("NO_COLOR").is_none()
            && std::env::var("TERM")
                .map(|term| term != "dumb")
                .unwrap_or(true)
    })
}

fn paint(code: &str, text: &str) -> String {
    if enabled() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

/// Something being created.
pub fn create(text: &str) -> String {
    paint("32", text)
}

/// Something being changed in place.
pub fn modify(text: &str) -> String {
    paint("33", text)
}

/// Something being removed.
pub fn delete(text: &str) -> String {
    paint("31", text)
}

/// An identifier — a digest, a GUID — set apart from the prose.
pub fn id(text: &str) -> String {
    paint("36", text)
}

/// Chrome: labels, timestamps, the quiet parts.
pub fn dim(text: &str) -> String {
    paint("90", text)
}

/// The line that states the outcome.
pub fn bold(text: &str) -> String {
    paint("1", text)
}

/// A verified fact — the good kind.
pub fn ok(text: &str) -> String {
    paint("32", text)
}
