// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The channel binding a peer Host session signs: each side takes it from its own connection, and
//! none ever travels in a frame.

use permguard_core::ChannelBinding;

/// The RFC 9266 label of the `tls-exporter` channel binding.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-Channel-Binding";

/// The `tls-exporter` channel binding of a connection (RFC 9266): 32 bytes exported with an
/// empty context, and only on TLS 1.3 (owner decision of 2026-10-08), RFC 9266 forbidding it on
/// TLS 1.2 without the extended master secret. `None` on any other connection, which then cannot
/// carry a peer Host session.
pub fn channel_binding<Data>(
    connection: &rustls::ConnectionCommon<Data>,
) -> Option<ChannelBinding> {
    if connection.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
        return None;
    }
    connection
        .export_keying_material([0u8; 32], EXPORTER_LABEL, Some(b""))
        .ok()
        .map(ChannelBinding::new)
}
