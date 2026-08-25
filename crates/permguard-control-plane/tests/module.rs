// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#[test]
fn module_metadata_identifies_control_plane() {
    let module = permguard_control_plane::module();

    assert_eq!(module.id(), "control");
    assert_eq!(module.component(), "control-plane");
    assert_eq!(module.description(), "control plane");
}
