// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Banner class: banner text assembled from a product identity and the effective config.

use permguard_core::{Config, ProductIdentity};

/// Startup text rendered on demand from the identity a binary supplied and the loaded config.
///
/// The class only returns rendered text: it reads no environment variable, file, clock, or network
/// resource, and it writes to no output stream.
pub struct Banner {
    art: String,
    product_name: String,
    tagline: String,
    version: String,
    commit: String,
    copyright_year: String,
    copyright_holder: String,
}

impl Banner {
    /// Builds the banner from the product identity and the effective config.
    ///
    /// Wording and artwork come from the identity; version and copyright come from the config, so a
    /// runtime override reaches the banner the same way it reaches everything else.
    pub fn new(identity: &ProductIdentity, config: &Config) -> Self {
        Self {
            art: identity.art().to_owned(),
            product_name: identity.product_name().to_owned(),
            tagline: identity.tagline().to_owned(),
            version: config.version().to_owned(),
            commit: config.commit().to_owned(),
            copyright_year: config.copyright_year().to_owned(),
            copyright_holder: config.copyright_holder().to_owned(),
        }
    }

    /// Returns the full startup banner used by commands that start the server.
    pub fn render_full(&self) -> String {
        format!(
            "{}\n{}\n{}\n\nVersion {} (build {})\n",
            self.art,
            self.official_line(),
            self.tagline,
            self.version,
            self.commit
        )
    }

    /// Returns the short banner used by commands that only return a value.
    pub fn render_short(&self) -> String {
        format!(
            "{}\n{}\nVersion {} (build {})\n",
            self.official_line(),
            self.tagline,
            self.version,
            self.commit
        )
    }

    fn official_line(&self) -> String {
        format!(
            "The official {} - Copyright © {} {}",
            self.product_name, self.copyright_year, self.copyright_holder
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    use permguard_core::{BuildSettings, Layers};

    const ART: &str = " ____ ___ ____\n|  _ \\_ _/ ___|";

    fn identity() -> ProductIdentity {
        ProductIdentity::new(
            "demo-x",
            "Demo X (Demonstration Exchange)",
            "A Demonstrated Tagline",
            "Demo X command line interface",
            ART,
        )
    }

    fn banner() -> Banner {
        let config = Config::from_layers(
            BuildSettings::new("9.9.9", "2026", "Test Holder"),
            Vec::<String>::new(),
            Layers::new(),
        )
        .expect("the layers build a config");

        Banner::new(&identity(), &config)
    }

    #[test]
    fn test_the_banner_takes_its_wording_from_the_identity() {
        let banner = banner();

        assert_eq!(banner.product_name, "Demo X (Demonstration Exchange)");
        assert_eq!(banner.tagline, "A Demonstrated Tagline");
        assert_eq!(banner.art, ART);
    }

    #[test]
    fn test_the_banner_takes_its_metadata_from_the_config() {
        let banner = banner();

        assert_eq!(banner.version, "9.9.9");
        assert_eq!(banner.copyright_year, "2026");
        assert_eq!(banner.copyright_holder, "Test Holder");
    }

    #[test]
    fn test_render_full_contains_the_ascii_art_and_metadata() {
        let rendered = banner().render_full();

        assert!(rendered.starts_with(" ____"));
        assert!(rendered.contains(
            "The official Demo X (Demonstration Exchange) - Copyright © 2026 Test Holder"
        ));
        assert!(rendered.contains("A Demonstrated Tagline"));
        assert!(rendered.contains("Version 9.9.9"));
    }

    #[test]
    fn test_render_short_omits_the_ascii_art() {
        let rendered = banner().render_short();

        assert!(!rendered.contains("____"));
        assert!(rendered.starts_with(
            "The official Demo X (Demonstration Exchange) - Copyright © 2026 Test Holder"
        ));
        assert!(rendered.contains("A Demonstrated Tagline"));
        assert!(rendered.contains("Version 9.9.9"));
    }

    #[test]
    fn test_both_render_modes_resolve_every_placeholder() {
        for rendered in [banner().render_full(), banner().render_short()] {
            for placeholder in ["<version>", "<copyright_year>", "<copyright_holder>"] {
                assert!(
                    !rendered.contains(placeholder),
                    "left {placeholder} unresolved"
                );
            }
        }
    }

    #[test]
    fn test_both_render_modes_end_with_a_newline() {
        assert!(banner().render_full().ends_with('\n'));
        assert!(banner().render_short().ends_with('\n'));
    }
}
