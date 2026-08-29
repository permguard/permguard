// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The identity block: the ASCII art and the three lines under it.
//!
//! It is assembled here rather than stored as one frozen string because it is
//! *styled*: the art in Permguard cyan, the tagline bold, the small print dim
//! — and styling is a property of where the output lands, so it has to be
//! decided when the banner is rendered, not when the binary is compiled.
//! Piped or `NO_COLOR`, the very same call returns plain text (see `style`).

use std::sync::OnceLock;

use permguard_core::brand;

use crate::style;
use crate::version::version;

/// Prefix for the art. The art's own left edge sits one column in, so three
/// spaces here put it at column four — where the wording below it starts.
const ART_INDENT: &str = "   ";

/// Prefix for the wording under the art.
const TEXT_INDENT: &str = "    ";

/// The banner shown by every help, by the bare `permguard`, and by `version`.
///
/// Built once. It is stamped onto every command in the tree, and the tree is
/// built on every invocation, so building it per command would be the same few
/// hundred bytes of gradient computed fifty times to say one thing.
pub fn banner() -> &'static str {
    static BANNER: OnceLock<String> = OnceLock::new();

    BANNER.get_or_init(|| render(style::depth())).as_str()
}

/// The banner with no colour at all.
///
/// What every consumer that is not a terminal sees, and the only form worth
/// asserting on: clap keeps `before_help` as a styled string and drops the
/// escapes when it renders it back, so comparing against the coloured banner
/// compares two different things whenever a developer runs the suite in a
/// terminal.
#[cfg(test)]
pub(crate) fn plain() -> String {
    render(style::Depth::None)
}

fn render(depth: style::Depth) -> String {
    let art = style::brand_gradient(depth, brand::PERMGUARD_ART);
    let mut lines: Vec<String> = art
        .lines()
        .map(|line| format!("{ART_INDENT}{line}"))
        .collect();

    lines.push(String::new());
    lines.push(format!(
        "{TEXT_INDENT}{}",
        style::bold_with(depth, brand::PERMGUARD_TAGLINE)
    ));
    lines.push(format!("{TEXT_INDENT}{}", brand::PERMGUARD_CLI_TITLE));

    // The same sentence the planes print at startup, so "which build am I
    // talking to" reads identically whether it came from a server log or from
    // `permguard --help`.
    let build = version();
    lines.push(format!(
        "{TEXT_INDENT}{}",
        style::dim_with(
            depth,
            &format!("Version {} (build {})", build.version, build.commit)
        )
    ));

    lines.push(format!(
        "{TEXT_INDENT}{}",
        style::dim_with(
            depth,
            &format!(
                "Copyright © {} {}",
                brand::PERMGUARD_COPYRIGHT_YEAR,
                brand::PERMGUARD_COPYRIGHT_HOLDER
            )
        )
    ));
    lines.push(format!(
        "{TEXT_INDENT}{}",
        style::dim_with(depth, &format!("Docs: {}", brand::PERMGUARD_CLI_DOCS_URL))
    ));

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_banner_indents_the_art_and_the_wording_to_the_same_column() {
        let rendered = plain();
        let lines: Vec<&str> = rendered.lines().collect();

        // Measured on the uncoloured banner: an escape sequence occupies bytes
        // and no columns, so the same art measured coloured answers a different
        // question than the one this test asks.
        let art_edge = lines[1].find('|');
        let text_edge = lines[lines.len() - 1].find("Docs:");

        assert!(art_edge.is_some(), "the art has a left edge to measure");
        assert_eq!(art_edge, text_edge);
    }

    #[test]
    fn test_the_banner_carries_the_product_wording() {
        let rendered = banner();

        assert!(rendered.contains(brand::PERMGUARD_TAGLINE));
        assert!(rendered.contains(brand::PERMGUARD_CLI_TITLE));
        assert!(rendered.contains(brand::PERMGUARD_COPYRIGHT_HOLDER));
        assert!(rendered.contains(brand::PERMGUARD_CLI_DOCS_URL));
    }

    #[test]
    fn test_the_banner_states_the_build_it_came_from() {
        let rendered = banner();
        let build = version();

        assert!(rendered.contains(&format!(
            "Version {} (build {})",
            build.version, build.commit
        )));
    }

    #[test]
    fn test_the_banner_is_plain_text_when_the_output_is_not_a_terminal() {
        assert!(!plain().contains('\x1b'));
    }
}
