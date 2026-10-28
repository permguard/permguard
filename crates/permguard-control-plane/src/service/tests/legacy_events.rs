// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The legacy event journals the ring sharing this process is bound to (WP-6.2b). It opens a
//! legacy journal to write the state it reads, which only a test may do.

use super::*;

/// WP-6.2b: the names the ring sharing this process is trusted under are each legacy event
/// journal's producer, zone and ledger, read from its `STATE`; nothing without a data plane
/// keeping events and its signing ring.
#[test]
fn the_local_ring_is_bound_to_each_legacy_event_journal() {
    use permguard_core::config::{SETTING_EVENTS_ENABLED, SETTING_KEYS_ENABLED};

    let root = scratch("legacy-event-producers");
    let built = |pairs: &[(&str, &str)]| {
        let mut file: Vec<(String, String)> =
            vec![(SETTING_WORKING_DIR.to_owned(), root.display().to_string())];
        file.extend(
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned())),
        );
        permguard_core::Config::from_layers(
            permguard_server::plane::build_settings("0.0.0-test"),
            vec![permguard_server::plane::SETTING_RUNTIME_PLANES],
            permguard_core::config::Layers {
                file,
                ..Default::default()
            },
        )
        .expect("the test configuration builds")
    };
    let config = built(&[
        (SETTING_EVENTS_ENABLED, "true"),
        (SETTING_KEYS_ENABLED, "true"),
    ]);
    let events = config.events_directory();
    // `zone-1/copy` keeps a journal of `zone-1/ledger-1`'s stream: one binding, named once.
    for (zone, ledger, directory) in [
        ("zone-2", "ledger-1", "ledger-1"),
        ("zone-1", "ledger-1", "ledger-1"),
        ("zone-1", "ledger-1", "copy"),
    ] {
        let stream = permguard_events::Stream::new(
            permguard_events::Producer::data_plane("plane-before", "01931f2c"),
            zone,
            ledger,
        );
        drop(
            permguard_events::journal::Journal::open(
                events.join(zone).join(directory),
                stream,
                permguard_events::journal::Bounds::default(),
            )
            .expect("a legacy journal"),
        );
    }
    // A directory with no journal in it, and one whose state does not read.
    std::fs::create_dir_all(events.join("zone-1").join("empty")).expect("created");
    // A `STATE` that is not a file reads as nothing.
    std::fs::create_dir_all(
        events
            .join("zone-1")
            .join("broken")
            .join(permguard_events::journal::STATE_FILE),
    )
    .expect("created");

    assert_eq!(
        legacy_event_producers(&config),
        [
            (
                "plane-before".to_owned(),
                "zone-1".to_owned(),
                "ledger-1".to_owned()
            ),
            (
                "plane-before".to_owned(),
                "zone-2".to_owned(),
                "ledger-1".to_owned()
            ),
        ]
    );
    assert!(
        legacy_event_producers(&built(&[(SETTING_KEYS_ENABLED, "true")])).is_empty(),
        "no data plane keeping events"
    );
    assert!(
        legacy_event_producers(&built(&[(SETTING_EVENTS_ENABLED, "true")])).is_empty(),
        "no signing ring"
    );
}
