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

/// The bytes of a member the facade answers base64url, as gRPC carries them.
fn raw(text: &str) -> Result<Vec<u8>, Status> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|error| Status::internal(format!("a member did not decode: {error}")))
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
        _request: Request<v1::PlanIdentityResetRequest>,
    ) -> Answer<v1::PlanIdentityResetResponse> {
        Err(unimplemented("identity reset"))
    }

    async fn run_identity_reset(
        &self,
        _request: Request<v1::RunIdentityResetRequest>,
    ) -> Answer<v1::RunIdentityResetResponse> {
        Err(unimplemented("identity reset"))
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
                    plan_id: asked.plan_id,
                    plan_digest: asked.plan_digest,
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
        Ok(Response::new(v1::GetKeyRingResponse {
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
        }))
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
                    plan_id: asked.plan_id,
                    plan_digest: asked.plan_digest,
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

    async fn prepare_backup(
        &self,
        _request: Request<v1::PrepareBackupRequest>,
    ) -> Answer<v1::PrepareBackupResponse> {
        Err(unimplemented("backups"))
    }

    async fn finalize_backup(
        &self,
        _request: Request<v1::FinalizeBackupRequest>,
    ) -> Answer<v1::FinalizeBackupResponse> {
        Err(unimplemented("backups"))
    }

    async fn abort_backup(
        &self,
        _request: Request<v1::AbortBackupRequest>,
    ) -> Answer<v1::AbortBackupResponse> {
        Err(unimplemented("backups"))
    }

    async fn list_backups(
        &self,
        _request: Request<v1::ListBackupsRequest>,
    ) -> Answer<v1::ListBackupsResponse> {
        Err(unimplemented("backups"))
    }

    async fn plan_gc(&self, _request: Request<v1::PlanGcRequest>) -> Answer<v1::PlanGcResponse> {
        Err(unimplemented("garbage collection"))
    }

    async fn run_gc(&self, _request: Request<v1::RunGcRequest>) -> Answer<v1::RunGcResponse> {
        Err(unimplemented("garbage collection"))
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
        _request: Request<v1::ListPlansRequest>,
    ) -> Answer<v1::ListPlansResponse> {
        Err(unimplemented("the plans"))
    }

    async fn approve_plan(
        &self,
        _request: Request<v1::ApprovePlanRequest>,
    ) -> Answer<v1::ApprovePlanResponse> {
        Err(unimplemented("plan approval"))
    }
}
