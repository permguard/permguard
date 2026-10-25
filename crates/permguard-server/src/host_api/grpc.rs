// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The gRPC binding of the Host API: `permguard.host.v1`, each served rpc one call into the
//! facade, the same facade the REST routes call. An rpc of the contract no package serves yet is
//! `UNIMPLEMENTED`, the protocol's own word for it, where REST has no route.

use std::sync::Arc;

use tonic::{Request, Response, Status};

use permguard_core::Disclosure;
use permguard_host::api::{self, HostApi, Refusal};

use super::v1;
use super::v1::grant_service_server::GrantService;
use super::v1::identity_service_server::IdentityService;
use super::v1::key_service_server::KeyService;
use super::v1::operations_service_server::OperationsService;
use super::wire;

mod evidence;
mod members;

type Answer<T> = Result<Response<T>, Status>;

/// What every rpc reaches: the facade and how much a refusal says.
#[derive(Clone)]
pub struct Served {
    api: Arc<HostApi>,
    disclosure: Disclosure,
}

impl Served {
    /// The services over `api`, refusing as `disclosure` allows. For the composition and tests.
    pub fn new(api: Arc<HostApi>, disclosure: Disclosure) -> Self {
        Self { api, disclosure }
    }

    fn refuse(&self, refusal: Refusal) -> Status {
        wire::grpc_refusal(&refusal, self.disclosure)
    }

    /// Runs `call` on the facade off the async workers (WP-7.8), refusing as any call does; a
    /// call that panicked is `internal`, with the class and code every refusal carries.
    async fn blocking<T: Send + 'static>(
        &self,
        call: impl FnOnce(&HostApi) -> Result<T, Refusal> + Send + 'static,
    ) -> Result<T, Status> {
        let api = Arc::clone(&self.api);
        match tokio::task::spawn_blocking(move || call(&api)).await {
            Ok(answered) => answered.map_err(|refusal| self.refuse(refusal)),
            Err(error) => Err(self.refuse(Refusal::new(
                permguard_core::ErrorClass::Internal,
                permguard_core::codes::common::INTERNAL,
                format!("the call did not finish: {error}"),
            ))),
        }
    }
}

fn unimplemented(what: &str) -> Status {
    Status::unimplemented(format!("{what} is not served by this build"))
}

fn grant(view: api::GrantView) -> v1::Grant {
    v1::Grant {
        grant_id: view.grant_id,
        principal: view.principal,
        operations: view.operations,
        selector: view.selector,
        resource_types: view.resource_types,
        constraints: view.constraints.into_iter().collect(),
        revision: view.revision,
        status: view.status,
        issued_by: view.issued_by,
        issued_at: view.issued_at,
        expires_at: view.expires_at,
    }
}

/// Bytes gRPC carries raw, as the facade reads them: base64url.
fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The bytes of a member the facade answers base64url, as gRPC carries them.
fn raw(text: &str) -> Result<Vec<u8>, Status> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|error| Status::internal(format!("a member did not decode: {error}")))
}

/// A ring's public set as gRPC carries it.
fn ring_out(view: api::RingView) -> Result<v1::GetKeyRingResponse, Status> {
    Ok(v1::GetKeyRingResponse {
        ring: view.ring,
        epoch: view.epoch,
        digest: view.digest,
        binding: view.binding.as_deref().map(raw).transpose()?,
        cache_max_age: view.cache_max_age,
        keys: view
            .keys
            .into_iter()
            .map(|key| v1::Jwk {
                kid: key.kid,
                kty: key.kty,
                crv: key.crv,
                x: key.x,
                y: key.y,
                alg: key.alg,
                r#use: key.usage,
            })
            .collect(),
    })
}

/// One plan of the plans store as gRPC carries it.
fn plan_out(plan: api::plans::PlanView) -> Result<v1::OperationPlan, Status> {
    Ok(v1::OperationPlan {
        plan_id: plan.plan_id,
        operation: plan.operation,
        target: plan.target,
        revision: plan.revision,
        principal: plan.principal,
        plan_digest: plan.plan_digest,
        expires: plan.expires,
        approvals_required: plan.approvals_required,
        approvals: plan
            .approvals
            .into_iter()
            .map(|approval| {
                Ok(v1::OperationPlanApproval {
                    principal: approval.principal,
                    approved_at: approval.approved_at,
                    approval: raw(&approval.approval)?,
                })
            })
            .collect::<Result<_, Status>>()?,
        status: plan.status,
        receipt: raw(&plan.receipt)?,
    })
}

fn receipt(receipt: api::Receipt) -> v1::Receipt {
    v1::Receipt {
        operation_id: receipt.operation_id,
        revision: receipt.revision,
        audit: Some(v1::AuditReference {
            trail: receipt.audit.trail,
            seq: receipt.audit.seq,
            digest: receipt.audit.digest,
        }),
    }
}

/// A garbage-collection report as gRPC carries it (WP-7.11b).
fn gc_report(report: permguard_host::gc::Report) -> v1::GcReport {
    v1::GcReport {
        entries: report
            .entries
            .into_iter()
            .map(|entry| v1::GcEntry {
                resource: entry.resource,
                candidates: entry.candidates,
                candidate_bytes: entry.candidate_bytes,
                removed: entry.removed,
                removed_bytes: entry.removed_bytes,
                kept: entry
                    .kept
                    .into_iter()
                    .map(|kept| v1::GcKept {
                        reason: kept.reason,
                        count: kept.count,
                    })
                    .collect(),
            })
            .collect(),
        resumes_at: report.resumes_at,
        skipped: report.skipped,
        omitted: report.omitted,
    }
}

fn blank(text: String) -> Option<String> {
    (!text.is_empty()).then_some(text)
}

#[tonic::async_trait]
impl IdentityService for Served {
    type PeerChannelStream = tonic::codegen::BoxStream<v1::PeerFrame>;

    /// A peer session (WP-2.3): no grant is asked, the listener's mutual TLS and the session's
    /// proof and pin admit it; the connection's own channel binding is the one signed.
    async fn peer_channel(
        &self,
        request: Request<tonic::Streaming<v1::PeerFrame>>,
    ) -> Answer<Self::PeerChannelStream> {
        let peer = request
            .extensions()
            .get::<Arc<permguard_core::PeerIdentity>>()
            .cloned();
        let binding = request
            .extensions()
            .get::<Arc<permguard_core::ChannelBinding>>()
            .cloned();
        let responder = self
            .api
            .peer_responder(peer.as_deref(), binding.as_deref())
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(super::peer::respond(
            responder,
            request.into_inner(),
        )))
    }

    async fn get_identity(
        &self,
        request: Request<v1::GetIdentityRequest>,
    ) -> Answer<v1::GetIdentityResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let view = self
            .api
            .identity(&actor)
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::GetIdentityResponse {
            document: raw(&view.document)?,
            successions: view
                .successions
                .iter()
                .map(|record| raw(record))
                .collect::<Result<_, _>>()?,
            first_public_key: raw(&view.first_public_key)?,
            protocol_versions: view.protocol_versions,
            host_id: view.host_id,
            epoch: view.epoch,
            fingerprint: view.fingerprint,
        }))
    }

    async fn verify_identity(
        &self,
        request: Request<v1::VerifyIdentityRequest>,
    ) -> Answer<v1::VerifyIdentityResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let proved = self
            .api
            .verify_identity(
                &actor,
                api::identity::VerifyIdentity {
                    address: asked.address,
                    host_id: asked.host_id,
                    fingerprint: asked.fingerprint,
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::VerifyIdentityResponse {
            host_id: proved.host_id,
            epoch: proved.epoch,
            fingerprint: proved.fingerprint,
            verified: proved.verified,
        }))
    }

    async fn rotate_identity(
        &self,
        request: Request<v1::RotateIdentityRequest>,
    ) -> Answer<v1::RotateIdentityResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let rotated = self
            .api
            .rotate_identity(
                &actor,
                api::RotateIdentity {
                    request_id: asked.request_id,
                    expected_epoch: asked.expected_epoch,
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::RotateIdentityResponse {
            receipt: Some(receipt(rotated.receipt)),
            succession: raw(&rotated.succession)?,
        }))
    }

    async fn plan_identity_reset(
        &self,
        request: Request<v1::PlanIdentityResetRequest>,
    ) -> Answer<v1::PlanIdentityResetResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let planned = self
            .api
            .plan_identity_reset(
                &actor,
                api::reset::PlanIdentityReset {
                    request_id: asked.request_id,
                    mode: asked.mode,
                    reason: asked.reason,
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::PlanIdentityResetResponse {
            plan_id: planned.plan_id,
            plan_digest: planned.plan_digest,
            expires: planned.expires,
            revision: planned.revision,
            receipt: raw(&planned.receipt)?,
            approvals_required: planned.approvals_required,
            mode: planned.mode,
            memberships: planned
                .memberships
                .into_iter()
                .map(|held| v1::ResetMembership {
                    membership_id: held.membership_id,
                    role: held.role,
                    status: held.status,
                    peer: Some(members::host_out(held.peer)),
                    address: held.address,
                    step: held.step,
                })
                .collect(),
        }))
    }

    async fn run_identity_reset(
        &self,
        request: Request<v1::RunIdentityResetRequest>,
    ) -> Answer<v1::RunIdentityResetResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let done = self
            .api
            .run_identity_reset(
                &actor,
                api::reset::RunIdentityReset {
                    request_id: asked.request_id,
                    receipt: b64(&asked.receipt),
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::RunIdentityResetResponse {
            receipt: Some(receipt(done.receipt)),
            old_host_id: done.old_host_id,
            host_id: done.host_id,
            fingerprint: done.fingerprint,
            witness: done.witness,
            ended: done
                .ended
                .into_iter()
                .map(|held| {
                    Ok(v1::ResetEnded {
                        membership_id: held.membership_id,
                        role: held.role,
                        status: held.status,
                        epoch: held.epoch,
                        manifest: held.manifest.as_deref().map(raw).transpose()?,
                    })
                })
                .collect::<Result<_, Status>>()?,
            orphaned: done
                .orphaned
                .into_iter()
                .map(|held| v1::ResetOrphaned {
                    membership_id: held.membership_id,
                    coordinator: Some(members::host_out(held.coordinator)),
                    address: held.address,
                })
                .collect(),
            restart_required: done.restart_required,
        }))
    }

    async fn list_ring_bindings(
        &self,
        request: Request<v1::ListRingBindingsRequest>,
    ) -> Answer<v1::ListRingBindingsResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let bindings = self
            .api
            .ring_bindings(&actor)
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::ListRingBindingsResponse {
            bindings: bindings
                .bindings
                .into_iter()
                .map(|binding| {
                    Ok(v1::RingBinding {
                        binding: raw(&binding.binding)?,
                        ring: binding.ring,
                        epoch: binding.epoch,
                    })
                })
                .collect::<Result<_, Status>>()?,
        }))
    }
}

#[tonic::async_trait]
impl GrantService for Served {
    async fn list_grants(
        &self,
        request: Request<v1::ListGrantsRequest>,
    ) -> Answer<v1::ListGrantsResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let listed = self
            .api
            .grants(
                &actor,
                blank(asked.principal).as_deref(),
                blank(asked.selector).as_deref(),
            )
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::ListGrantsResponse {
            revision: listed.revision,
            grants: listed.grants.into_iter().map(grant).collect(),
        }))
    }

    async fn create_grant(
        &self,
        request: Request<v1::CreateGrantRequest>,
    ) -> Answer<v1::CreateGrantResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let created = self
            .api
            .create_grant(
                &actor,
                api::CreateGrant {
                    request_id: asked.request_id,
                    expected_revision: asked.expected_revision,
                    principal: asked.principal,
                    operations: asked.operations,
                    selector: asked.selector,
                    resource_types: asked.resource_types,
                    constraints: asked.constraints.into_iter().collect(),
                    expires_at: asked.expires_at,
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::CreateGrantResponse {
            receipt: Some(receipt(created.receipt)),
            grant: Some(grant(created.grant)),
        }))
    }

    async fn plan_grant_revoke(
        &self,
        request: Request<v1::PlanGrantRevokeRequest>,
    ) -> Answer<v1::PlanGrantRevokeResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let planned = self
            .api
            .plan_revoke(
                &actor,
                &asked.grant_id,
                api::PlanRevoke {
                    request_id: asked.request_id,
                    expected_revision: asked.expected_revision,
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::PlanGrantRevokeResponse {
            plan_id: planned.plan_id,
            plan_digest: planned.plan_digest,
            expires: planned.expires,
            revision: planned.revision,
            receipt: raw(&planned.receipt)?,
            approvals_required: planned.approvals_required,
        }))
    }

    async fn run_grant_revoke(
        &self,
        request: Request<v1::RunGrantRevokeRequest>,
    ) -> Answer<v1::RunGrantRevokeResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let revoked = self
            .api
            .run_revoke(
                &actor,
                &asked.grant_id,
                api::RunRevoke {
                    request_id: asked.request_id,
                    receipt: b64(&asked.receipt),
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::RunGrantRevokeResponse {
            receipt: Some(receipt(revoked.receipt)),
            grant: Some(grant(revoked.grant)),
        }))
    }
}

#[tonic::async_trait]
impl KeyService for Served {
    async fn list_key_rings(
        &self,
        request: Request<v1::ListKeyRingsRequest>,
    ) -> Answer<v1::ListKeyRingsResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let rings = self
            .api
            .rings(&actor)
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::ListKeyRingsResponse {
            rings: rings
                .rings
                .into_iter()
                .map(|ring| v1::KeyRingSummary {
                    ring: ring.ring,
                    keys: ring.keys,
                    digest: ring.digest,
                    epoch: ring.epoch,
                })
                .collect(),
        }))
    }

    async fn get_key_ring(
        &self,
        request: Request<v1::GetKeyRingRequest>,
    ) -> Answer<v1::GetKeyRingResponse> {
        let view = self
            .api
            .ring(&request.into_inner().ring)
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(ring_out(view)?))
    }

    async fn rotate_key_ring(
        &self,
        request: Request<v1::RotateKeyRingRequest>,
    ) -> Answer<v1::RotateKeyRingResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let rotated = self
            .api
            .rotate_ring(
                &actor,
                &asked.ring,
                api::RotateRing {
                    request_id: asked.request_id,
                    expected_epoch: asked.expected_epoch,
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::RotateKeyRingResponse {
            receipt: Some(receipt(rotated.receipt)),
            kid: rotated.kid,
        }))
    }

    async fn plan_key_revoke(
        &self,
        request: Request<v1::PlanKeyRevokeRequest>,
    ) -> Answer<v1::PlanKeyRevokeResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let planned = self
            .api
            .plan_key_revoke(
                &actor,
                &asked.ring,
                api::PlanKeyRevoke {
                    request_id: asked.request_id,
                    kid: asked.kid,
                    reason: asked.reason,
                    compromised_at: asked.compromised_at,
                    expected_epoch: asked.expected_epoch,
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::PlanKeyRevokeResponse {
            plan_id: planned.plan_id,
            plan_digest: planned.plan_digest,
            expires: planned.expires,
            revision: planned.revision,
            receipt: raw(&planned.receipt)?,
            approvals_required: planned.approvals_required,
        }))
    }

    async fn run_key_revoke(
        &self,
        request: Request<v1::RunKeyRevokeRequest>,
    ) -> Answer<v1::RunKeyRevokeResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let revoked = self
            .api
            .run_key_revoke(
                &actor,
                &asked.ring,
                api::RunKeyRevoke {
                    request_id: asked.request_id,
                    receipt: b64(&asked.receipt),
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::RunKeyRevokeResponse {
            receipt: Some(receipt(revoked.receipt)),
            kid: revoked.kid,
        }))
    }

    async fn get_key_bundle(
        &self,
        request: Request<v1::GetKeyBundleRequest>,
    ) -> Answer<v1::GetKeyBundleResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let request = request.into_inner();
        // An empty string is no value, as an absent query member is on REST.
        let given = |text: String| (!text.is_empty()).then_some(text);
        let page = self
            .api
            .key_bundle(
                &actor,
                &api::KeyBundleQuery {
                    resource: request.resource,
                    frontier: given(request.frontier),
                    cursor: given(request.cursor),
                    limit: request.limit,
                },
            )
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::GetKeyBundleResponse {
            resource: page.resource,
            manifest: raw(&page.manifest)?,
            bundle_digest: page.bundle_digest,
            total: page.total,
            items: page
                .items
                .iter()
                .map(|item| raw(item))
                .collect::<Result<_, _>>()?,
            next_cursor: page.next_cursor,
        }))
    }

    async fn list_secrets(
        &self,
        _request: Request<v1::ListSecretsRequest>,
    ) -> Answer<v1::ListSecretsResponse> {
        Err(unimplemented("the secrets"))
    }

    async fn rotate_secret(
        &self,
        _request: Request<v1::RotateSecretRequest>,
    ) -> Answer<v1::RotateSecretResponse> {
        Err(unimplemented("secret rotation"))
    }
}

#[tonic::async_trait]
impl OperationsService for Served {
    async fn get_status(
        &self,
        request: Request<v1::GetStatusRequest>,
    ) -> Answer<v1::GetStatusResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let status = self
            .api
            .status(&actor)
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::GetStatusResponse {
            live: status.live,
            ready: status.ready,
            state: status.state,
            degraded: status
                .degraded
                .into_iter()
                .map(|degraded| v1::HostDegraded {
                    capability: degraded.capability,
                    reason: degraded.reason,
                })
                .collect(),
            components: status
                .components
                .into_iter()
                .map(|component| v1::HostComponent {
                    component: component.component,
                    kind: component.kind,
                    state: component.state,
                    required: component.required,
                    stalled_since: component.stalled_since,
                    last_success: component.last_success,
                    next_attempt: component.next_attempt,
                    reason: component.reason,
                })
                .collect(),
            assurance: Some(v1::Assurance {
                profile: status.assurance.profile,
                enforcement: status.assurance.enforcement,
                added_controls: status.assurance.added_controls,
                relaxations: status.assurance.relaxations,
            }),
            peer_sessions: Some(v1::PeerSessions {
                served: status.peer_sessions.served,
                reason: status.peer_sessions.reason,
            }),
            listeners: status
                .listeners
                .into_iter()
                .map(|listener| v1::HostListener {
                    name: listener.name,
                    class: listener.class,
                    authentication: listener.authentication,
                    client_allow: listener.client_allow,
                    tls_min_version: listener.tls_min_version,
                })
                .collect(),
        }))
    }

    async fn drain(&self, _request: Request<v1::DrainRequest>) -> Answer<v1::DrainResponse> {
        Err(unimplemented("draining"))
    }

    async fn maintenance(
        &self,
        _request: Request<v1::MaintenanceRequest>,
    ) -> Answer<v1::MaintenanceResponse> {
        Err(unimplemented("maintenance"))
    }

    async fn get_effective_config(
        &self,
        request: Request<v1::GetEffectiveConfigRequest>,
    ) -> Answer<v1::GetEffectiveConfigResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let effective = self
            .api
            .effective_config(&actor)
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::GetEffectiveConfigResponse {
            revision: effective.revision,
            settings: effective
                .settings
                .into_iter()
                .map(|setting| v1::Setting {
                    key: setting.key,
                    value: setting.value,
                    masked: setting.masked,
                    origin: setting.origin,
                    class: setting.class,
                })
                .collect(),
        }))
    }

    async fn list_config_revisions(
        &self,
        request: Request<v1::ListConfigRevisionsRequest>,
    ) -> Answer<v1::ListConfigRevisionsResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let listed = self
            .api
            .config_revisions(&actor)
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::ListConfigRevisionsResponse {
            revisions: listed
                .revisions
                .into_iter()
                .map(|revision| v1::ConfigRevision {
                    journal: revision.journal,
                    revision: revision.revision,
                    operation: revision.operation,
                    target: revision.target,
                    at: revision.at,
                    by: revision.by,
                })
                .collect(),
        }))
    }

    /// `POST /host/v1/backup/prepare` (WP-7.8): the inventory reads the whole volume, so it runs
    /// off the async workers, as every backup call does — each may wait on a prepare in progress.
    async fn prepare_backup(
        &self,
        request: Request<v1::PrepareBackupRequest>,
    ) -> Answer<v1::PrepareBackupResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let prepared = self
            .blocking(move |api| api.prepare_backup(&actor, api::backups::PrepareBackup {}))
            .await?;
        Ok(Response::new(v1::PrepareBackupResponse {
            operation_id: prepared.operation_id,
            manifest: prepared.manifest,
            token: prepared.token,
            expires_at: prepared.expires_at,
            receipt: Some(receipt(prepared.receipt)),
        }))
    }

    async fn finalize_backup(
        &self,
        request: Request<v1::FinalizeBackupRequest>,
    ) -> Answer<v1::FinalizeBackupResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let ended = self
            .blocking(move |api| {
                api.finalize_backup(
                    &actor,
                    api::backups::FinalizeBackup {
                        token: asked.token,
                        snapshot_id: asked.snapshot_id,
                    },
                )
            })
            .await?;
        Ok(Response::new(v1::FinalizeBackupResponse {
            backup: ended.backup,
            state: ended.state,
            snapshot_id: ended.snapshot_id,
            receipt: Some(receipt(ended.receipt)),
        }))
    }

    async fn abort_backup(
        &self,
        request: Request<v1::AbortBackupRequest>,
    ) -> Answer<v1::AbortBackupResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let ended = self
            .blocking(move |api| {
                api.abort_backup(&actor, api::backups::AbortBackup { token: asked.token })
            })
            .await?;
        Ok(Response::new(v1::AbortBackupResponse {
            backup: ended.backup,
            state: ended.state,
            snapshot_id: ended.snapshot_id,
            receipt: Some(receipt(ended.receipt)),
        }))
    }

    async fn list_backups(
        &self,
        request: Request<v1::ListBackupsRequest>,
    ) -> Answer<v1::ListBackupsResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let listed = self.blocking(move |api| api.list_backups(&actor)).await?;
        Ok(Response::new(v1::ListBackupsResponse {
            backups: listed
                .backups
                .into_iter()
                .map(|backup| v1::Backup {
                    operation_id: backup.operation_id,
                    at: backup.at,
                    state: backup.state,
                    snapshot_id: backup.snapshot_id,
                    ended_at: backup.ended_at,
                    manifest: backup.manifest,
                })
                .collect(),
        }))
    }

    /// `POST /host/v1/gc/{job}/plan` (WP-7.11b): the job's sweep is read off the async workers.
    async fn plan_gc(&self, request: Request<v1::PlanGcRequest>) -> Answer<v1::PlanGcResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let job = asked.job;
        let planned = self
            .blocking(move |api| {
                api.plan_gc(
                    &actor,
                    &job,
                    api::gc::PlanGc {
                        request_id: asked.request_id,
                        resource: blank(asked.resource),
                    },
                )
            })
            .await?;
        Ok(Response::new(v1::PlanGcResponse {
            receipt: raw(&planned.receipt)?,
            job: planned.job,
            resource: planned.resource,
            plan_id: planned.plan_id,
            plan_digest: planned.plan_digest,
            expires: planned.expires,
            approvals_required: planned.approvals_required,
            report: Some(gc_report(planned.report)),
        }))
    }

    /// `POST /host/v1/gc/{job}/run` (WP-7.11b).
    async fn run_gc(&self, request: Request<v1::RunGcRequest>) -> Answer<v1::RunGcResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let job = asked.job;
        let ran = self
            .blocking(move |api| {
                api.run_gc(
                    &actor,
                    &job,
                    api::gc::RunGc {
                        request_id: asked.request_id,
                        receipt: b64(&asked.receipt),
                    },
                )
            })
            .await?;
        Ok(Response::new(v1::RunGcResponse {
            job: ran.job,
            resource: ran.resource,
            plan_id: ran.plan_id,
            report: Some(gc_report(ran.report)),
            receipt: Some(receipt(ran.receipt)),
        }))
    }

    async fn get_storage_quota(
        &self,
        _request: Request<v1::GetStorageQuotaRequest>,
    ) -> Answer<v1::GetStorageQuotaResponse> {
        Err(unimplemented("the storage quota"))
    }

    async fn probe_storage(
        &self,
        _request: Request<v1::ProbeStorageRequest>,
    ) -> Answer<v1::ProbeStorageResponse> {
        Err(unimplemented("the storage probe"))
    }

    async fn list_plans(
        &self,
        request: Request<v1::ListPlansRequest>,
    ) -> Answer<v1::ListPlansResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let status = (!asked.status.is_empty()).then_some(asked.status);
        let listed = self
            .api
            .plans(&actor, status.as_deref())
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::ListPlansResponse {
            plans: listed
                .plans
                .into_iter()
                .map(plan_out)
                .collect::<Result<_, _>>()?,
        }))
    }

    async fn approve_plan(
        &self,
        request: Request<v1::ApprovePlanRequest>,
    ) -> Answer<v1::ApprovePlanResponse> {
        let actor = permguard_transport::actor_of(request.extensions());
        let asked = request.into_inner();
        let approved = self
            .api
            .approve_plan(
                &actor,
                &asked.plan_id,
                api::plans::ApprovePlan {
                    request_id: asked.request_id,
                },
            )
            .await
            .map_err(|refusal| self.refuse(refusal))?;
        Ok(Response::new(v1::ApprovePlanResponse {
            receipt: Some(receipt(approved.receipt)),
            plan: Some(plan_out(approved.plan)?),
        }))
    }
}
