// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The members a page names, as the gRPC page carries them: who they are is the domain's
//! (`permguard_control_plane::members`).

use std::collections::BTreeMap;

pub use permguard_control_plane::members::*;

/// The members as the gRPC page carries them, in Host id order.
pub fn to_proto(members: BTreeMap<String, MemberName>) -> Vec<crate::v1::MemberName> {
    members
        .into_iter()
        .map(|(host_id, member)| crate::v1::MemberName {
            host_id,
            member_id: member.member_id,
            name: member.name,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Names one Host id.
    struct One;

    impl NamesMembers for One {
        fn member_named(&self, host_id: &[u8; 16]) -> Option<MemberName> {
            (host_id[0] == 0xab).then(|| MemberName {
                member_id: "01a1b9de-8738-736e-9fff-609509b3fcbb".to_owned(),
                name: "lab-a".to_owned(),
            })
        }
    }

    #[test]
    fn the_grpc_page_carries_the_members_an_event_page_names() {
        let named = "ab".repeat(16);
        let records = [json!({"stream": {"producer": {"id": named, "instance": "run"}}})];
        let proto = to_proto(members_of(records.iter(), event_host, Some(&One)));
        assert_eq!(proto.len(), 1);
        assert_eq!(
            (proto[0].host_id.as_str(), proto[0].name.as_str()),
            (named.as_str(), "lab-a")
        );
    }
}
