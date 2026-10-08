// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Every frame a peer Host sends on the PeerChannel (WP-2.3), and the identity it presents.

#![no_main]

use libfuzzer_sys::fuzz_target;

use permguard_host::identity::record::{Document, Succession};
use permguard_host::identity::{Suite, verify_published};
use permguard_host::session::record::{Challenge, Hello, Presentation, Transcript};
use permguard_objects::cose::Sign1;

fuzz_target!(|data: &[u8]| {
    // Whatever decodes re-encodes to the same bytes: each message has one encoding.
    if let Ok(hello) = Hello::decode(data) {
        assert_eq!(hello.encode().ok().as_deref(), Some(data));
    }
    if let Ok(challenge) = Challenge::decode(data) {
        assert_eq!(challenge.encode().ok().as_deref(), Some(data));
    }
    if let Ok(transcript) = Transcript::decode(data) {
        assert_eq!(transcript.encode().ok().as_deref(), Some(data));
    }
    if let Ok(presentation) = Presentation::decode(data) {
        assert_eq!(presentation.encode().ok().as_deref(), Some(data));
        // A presentation never verifies without a valid chain; it must never panic trying.
        let _ = verify_published(
            &presentation.document,
            &presentation.successions,
            &presentation.first_public_key,
        );
    }
    if let Ok(envelope) = Sign1::decode(data) {
        let _ = Document::decode(envelope.payload_unverified());
        let _ = Succession::decode(envelope.payload_unverified());
        let _ = Sign1::verify(&envelope, Suite::Ed25519Sha256V1, &[0; 32], "x");
    }
});
