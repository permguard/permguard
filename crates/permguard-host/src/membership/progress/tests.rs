// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use crate::membership::tests::Host;

/// Reading what was never kept answers nothing and creates nothing on the volume.
#[test]
fn reading_progress_or_a_last_session_creates_no_directory() {
    let host = Host::new("progress-read");
    let id = [0x42; 16];
    assert!(
        host.store
            .progress(&id, "decisions")
            .expect("read")
            .is_none()
    );
    assert!(
        host.store
            .last_session(&id, "decisions")
            .expect("read")
            .is_none()
    );
    let members = host.volume().host().path().join(super::super::DIRECTORY);
    assert!(
        !members.join(super::DIRECTORY).exists(),
        "no `progress/` directory"
    );
}
