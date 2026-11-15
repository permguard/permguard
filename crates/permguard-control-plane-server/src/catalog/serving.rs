// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The members serving a ledger, as the gRPC answer carries them: what they are is the domain's
//! (`permguard_control_plane::catalog::serving`).

use crate::v1;

pub use permguard_control_plane::catalog::serving::*;

/// The same member on gRPC.
pub fn wire(member: ServingMember) -> v1::ServingMember {
    v1::ServingMember {
        host_id: member.host_id,
        membership_id: member.membership_id,
        task_id: member.task_id,
        declared_assurance: member.declared_assurance,
        assurance_binding_status: member.assurance_binding_status.map(|binding| {
            v1::ServingAssurance {
                verdict: binding.verdict,
                current: binding.current,
                policy_revision: binding.policy_revision,
                claims: binding
                    .claims
                    .into_iter()
                    .map(|claim| v1::ServingClaim {
                        control: claim.control,
                        class: claim.class,
                        by: claim.by,
                    })
                    .collect(),
                expires_at: binding.expires_at,
            }
        }),
        lease_state: member.lease_state,
        last_session_at: member.last_session_at,
        progress: member.progress.map(|progress| v1::ServingProgress {
            report_seq: progress.report_seq,
            reported_at: progress.reported_at,
            received_at: progress.received_at,
            state: progress.state,
            checkpoint_digest: progress.checkpoint_digest,
            stale: progress.stale,
        }),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    /// gRPC carries the same member as HTTP, field for field.
    #[test]
    fn grpc_carries_the_member_http_shows() {
        let member = ServingMember {
            host_id: "member".to_owned(),
            membership_id: "membership".to_owned(),
            task_id: "mirror".to_owned(),
            declared_assurance: "production".to_owned(),
            assurance_binding_status: Some(ServingAssurance {
                verdict: "accepted".to_owned(),
                current: true,
                policy_revision: "sha256:00".to_owned(),
                claims: vec![ServingClaim {
                    control: "custody.hsm".to_owned(),
                    class: "attested".to_owned(),
                    by: "tpm-quote".to_owned(),
                }],
                expires_at: "2027-02-14T00:00:00Z".to_owned(),
            }),
            lease_state: "live".to_owned(),
            last_session_at: Some("2027-01-15T00:00:20Z".to_owned()),
            progress: Some(ServingProgress {
                report_seq: 7,
                reported_at: "2027-01-15T00:00:40Z".to_owned(),
                received_at: "2027-01-15T00:00:41Z".to_owned(),
                state: Some("serving".to_owned()),
                checkpoint_digest: Some("sha256:22".to_owned()),
                stale: true,
            }),
        };
        let http = serde_json::to_value(&member).expect("json");
        let grpc = wire(member);
        assert_eq!(http["host_id"], grpc.host_id);
        assert_eq!(http["membership_id"], grpc.membership_id);
        assert_eq!(http["task_id"], grpc.task_id);
        assert_eq!(http["declared_assurance"], grpc.declared_assurance);
        assert_eq!(http["lease_state"], grpc.lease_state);
        assert_eq!(
            http["last_session_at"].as_str(),
            grpc.last_session_at.as_deref()
        );
        let binding = grpc.assurance_binding_status.expect("a binding");
        let shown = &http["assurance_binding_status"];
        assert_eq!(shown["verdict"], binding.verdict);
        assert_eq!(shown["current"], binding.current);
        assert_eq!(shown["policy_revision"], binding.policy_revision);
        assert_eq!(shown["expires_at"], binding.expires_at);
        assert_eq!(shown["claims"][0]["control"], binding.claims[0].control);
        assert_eq!(shown["claims"][0]["class"], binding.claims[0].class);
        assert_eq!(shown["claims"][0]["by"], binding.claims[0].by);
        let progress = grpc.progress.expect("a report");
        let shown = &http["progress"];
        assert_eq!(shown["report_seq"], progress.report_seq);
        assert_eq!(shown["reported_at"], progress.reported_at);
        assert_eq!(shown["received_at"], progress.received_at);
        assert_eq!(shown["state"].as_str(), progress.state.as_deref());
        assert_eq!(
            shown["checkpoint_digest"].as_str(),
            progress.checkpoint_digest.as_deref()
        );
        assert_eq!(shown["stale"], progress.stale);
    }
}
