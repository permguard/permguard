// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The planes' setting keys, sections and TLS material, as `permguard_core::planes::settings`
//! declares them (the crate boundaries refactoring, RD-1: configuration is not the server's), and
//! the two questions only the server can answer, which settings and sections the planes it
//! composes declare.

pub use permguard_core::planes::settings::*;

use super::PlaneService;

pub(crate) fn declared_settings_for(planes: &[PlaneService]) -> Vec<&'static str> {
    let mut settings = vec![SETTING_RUNTIME_PLANES, SETTING_RUNTIME_OPTIONAL_PLANES];
    settings.extend(AUTHORITY_SETTINGS);

    for section in section_settings_for(planes) {
        settings.extend(section.keys.settings());
    }

    settings
}

pub(crate) fn section_settings_for(planes: &[PlaneService]) -> Vec<PlaneSection> {
    let mut sections = Vec::new();

    for plane in planes {
        match plane.module.id() {
            "control"
                if !sections
                    .iter()
                    .any(|section: &PlaneSection| section.name == "controlPlane") =>
            {
                sections.push(PlaneSection {
                    name: "controlPlane",
                    keys: PlaneSettingKeys::CONTROL,
                });
            }
            "data"
                if !sections
                    .iter()
                    .any(|section: &PlaneSection| section.name == "dataPlane") =>
            {
                sections.push(PlaneSection {
                    name: "dataPlane",
                    keys: PlaneSettingKeys::DATA,
                });
            }
            "authority"
                if !sections
                    .iter()
                    .any(|section: &PlaneSection| section.name == "authorityPlane") =>
            {
                sections.push(PlaneSection {
                    name: "authorityPlane",
                    keys: PlaneSettingKeys::AUTHORITY,
                });
            }
            _ => {}
        }
    }

    sections
}
