// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The REST binding of the Host API: `/host/v1/…`, each route one call into the facade.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{FromRequest, Path, RawQuery, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::de::DeserializeOwned;

use permguard_core::authz::operations;
use permguard_core::{ApiError, Disclosure, ErrorClass, codes};
use permguard_host::api::audit::{
    AuditCheckpointQuery, AuditCheckpointRequest, AuditExportQuery, AuditQuery,
};
use permguard_host::api::members::{
    AppraiseMember, ApproveMember, ChangeMember, ChangeMemberRecord, CreateInvite, JoinMembership,
    PlanMemberRevoke, RunMemberRevoke, SyncMembership, VerifyMember,
};
use permguard_host::api::reset::{PlanIdentityReset, RunIdentityReset};
use permguard_host::api::streams::StreamQuery;
use permguard_host::api::{
    HostApi, KeyBundleQuery, PlanKeyRevoke, Refusal, RotateIdentity, RotateRing, RunKeyRevoke,
    VerifyIdentity,
};
use permguard_transport::ActorOf;

use super::wire;

/// What every handler reaches: the facade and how much a refusal says.
#[derive(Clone)]
pub(crate) struct Served {
    api: Arc<HostApi>,
    disclosure: Disclosure,
}

impl Served {
    fn refuse(&self, refusal: &Refusal) -> Response {
        wire::http_refusal(refusal, self.disclosure)
    }
}

/// The routes of the Host API.
pub fn routes(api: Arc<HostApi>, disclosure: Disclosure) -> Router {
    host_routes().with_state(Served { api, disclosure })
}

/// What every Host serves about itself.
fn host_routes() -> Router<Served> {
    Router::new()
        .route("/host/v1/identity", get(identity))
        .route("/host/v1/identity/verify", post(verify_identity))
        .route("/host/v1/identity/rotate", post(rotate_identity))
        .route("/host/v1/identity/reset/plan", post(plan_identity_reset))
        .route("/host/v1/identity/reset/run", post(run_identity_reset))
        .route("/host/v1/ring-bindings", get(ring_bindings))
        .route("/host/v1/sessions/hello", post(session_over_rest))
        .route("/host/v1/sessions/prove", post(session_over_rest))
        .route("/host/v1/keys", get(list_rings))
        .route("/host/v1/keys/bundle", get(key_bundle))
        .route("/host/v1/keys/{ring}", get(get_ring))
        .route("/host/v1/keys/{ring}/rotate", post(rotate_ring))
        .route("/host/v1/keys/{ring}/revoke/plan", post(plan_key_revoke))
        .route("/host/v1/keys/{ring}/revoke/run", post(run_key_revoke))
        .route("/host/v1/members", get(list_members))
        .route(
            "/host/v1/members/invites",
            get(list_invites).post(create_invite),
        )
        .route("/host/v1/members/invites/{id}", delete(delete_invite))
        .route("/host/v1/members/enroll", post(enroll_over_rest))
        .route("/host/v1/members/{id}", get(get_member))
        .route("/host/v1/members/{id}/verify", post(verify_member))
        .route("/host/v1/members/{id}/approve", post(approve_member))
        .route("/host/v1/members/{id}/reject", post(reject_member))
        .route("/host/v1/members/{id}/suspend", post(suspend_member))
        .route("/host/v1/members/{id}/resume", post(resume_member))
        .route("/host/v1/members/{id}/fence", post(fence_member))
        .route("/host/v1/imports/gaps/accept", post(accept_import_gaps))
        .route("/host/v1/members/{id}/record", post(change_member_record))
        .route("/host/v1/members/{id}/appraise", post(appraise_member))
        .route("/host/v1/members/{id}/sessions", get(member_sessions))
        .route(
            "/host/v1/tasks/{task}/session",
            post(task_session_over_rest),
        )
        .route(
            "/host/v1/members/{id}/revoke/plan",
            post(plan_member_revoke),
        )
        .route("/host/v1/members/{id}/revoke/run", post(run_member_revoke))
        .route("/host/v1/memberships/join", post(join_membership))
        .route("/host/v1/memberships/{id}/sync", post(sync_membership))
        .route("/host/v1/audit/{class}/records", get(audit_records))
        .route(
            "/host/v1/audit/{class}/checkpoints",
            get(audit_checkpoints).post(audit_checkpoint),
        )
        .route("/host/v1/audit/{class}/export", get(audit_export))
        // The stream reads (WP-5.7a); batches travel on the task transport (owner decision).
        .route("/host/v1/streams", get(streams_list))
        .route(
            "/host/v1/streams/{plane}/{stream_type}/frontier",
            get(stream_frontier),
        )
        .route(
            "/host/v1/streams/{plane}/{stream_type}/records",
            get(stream_records),
        )
        .route(
            "/host/v1/streams/{plane}/{stream_type}/signers",
            get(stream_signers),
        )
        .route(
            "/host/v1/streams/{plane}/{stream_type}/subscriptions",
            get(stream_subscriptions),
        )
        .route(
            "/host/v1/streams/{plane}/{stream_type}/gaps",
            get(stream_gaps),
        )
        .route(
            "/host/v1/streams/{plane}/{stream_type}/anchors",
            get(stream_anchors),
        )
        .route("/host/v1/plans", get(list_plans))
        .route("/host/v1/plans/{id}/approve", post(approve_plan))
        .route("/host/v1/status", get(status))
        .route("/host/v1/config/effective", get(effective_config))
        .route("/host/v1/backup/prepare", post(prepare_backup))
        .route("/host/v1/backup/finalize", post(finalize_backup))
        .route("/host/v1/backup/abort", post(abort_backup))
        .route("/host/v1/backups", get(list_backups))
        .route("/host/v1/gc/{job}/plan", post(plan_gc))
        .route("/host/v1/gc/{job}/run", post(run_gc))
}

/// A closed JSON body: declared `application/json`, well formed, no member the shape does not
/// name. Anything else is `invalid_argument` in the shared shape; the one answer that stays the
/// framework's is the transport's body limit, a plain-text `413` from the `Surface`, which every
/// listener answers alike before any handler.
///
/// The media type is checked first and on purpose: a browser sends a `text/plain` POST cross-site
/// without a preflight, carrying the client certificate the listener authenticates with.
struct Closed<T>(T);

impl<T: DeserializeOwned> FromRequest<Served> for Closed<T> {
    type Rejection = Response;

    async fn from_request(request: Request, served: &Served) -> Result<Self, Response> {
        let refuse = |message: String| {
            served.refuse(&Refusal::Api(ApiError::new(
                ErrorClass::Validation,
                codes::common::INVALID_ARGUMENT,
                message,
            )))
        };
        let json = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"));
        if !json {
            return Err(refuse(
                "the body must be declared `Content-Type: application/json`".to_owned(),
            ));
        }
        let bytes = Bytes::from_request(request, served)
            .await
            .map_err(IntoResponse::into_response)?;
        serde_json::from_slice(&bytes).map(Closed).map_err(|error| {
            // A mutation without its request id answers what the contract and gRPC answer, not
            // a shape error (BUG-0089, DEC-0007).
            if error.to_string().starts_with("missing field `request_id`") {
                return served.refuse(&Refusal::Api(ApiError::new(
                    ErrorClass::Validation,
                    codes::host::REQUEST_ID_REQUIRED,
                    "every mutation carries a `request_id`",
                )));
            }
            refuse(format!("the body is not the request's shape: {error}"))
        })
    }
}

fn answer<T: serde::Serialize>(
    served: &Served,
    status: StatusCode,
    result: Result<T, Refusal>,
) -> Response {
    match result {
        Ok(value) => (status, Json(value)).into_response(),
        Err(refusal) => served.refuse(&refusal),
    }
}

/// Peer sessions are never separate requests: refused whoever asks, before any body is read
/// (WP-2.3).
async fn session_over_rest(State(served): State<Served>) -> Response {
    served.refuse(&served.api.session_over_rest())
}

async fn identity(State(served): State<Served>, ActorOf(actor): ActorOf) -> Response {
    answer(&served, StatusCode::OK, served.api.identity(&actor))
}

async fn verify_identity(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Closed(verify): Closed<VerifyIdentity>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.verify_identity(&actor, verify).await,
    )
}

async fn rotate_identity(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Closed(rotate): Closed<RotateIdentity>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.rotate_identity(&actor, rotate).await,
    )
}

async fn plan_identity_reset(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Closed(plan): Closed<PlanIdentityReset>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.plan_identity_reset(&actor, plan).await,
    )
}

async fn run_identity_reset(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Closed(run): Closed<RunIdentityReset>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.run_identity_reset(&actor, run).await,
    )
}

async fn ring_bindings(State(served): State<Served>, ActorOf(actor): ActorOf) -> Response {
    answer(&served, StatusCode::OK, served.api.ring_bindings(&actor))
}

async fn list_rings(State(served): State<Served>, ActorOf(actor): ActorOf) -> Response {
    answer(&served, StatusCode::OK, served.api.rings(&actor))
}

async fn key_bundle(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    RawQuery(query): RawQuery,
) -> Response {
    let ([resource, frontier, cursor, limit], malformed) = read_query(
        query.as_deref(),
        ["resource", "frontier", "cursor", "limit"],
    );
    if let Some(malformed) = malformed {
        return refuse_query(
            &served,
            &actor,
            &[operations::KEYS_READ],
            resource.as_deref(),
            &malformed,
        );
    }
    let query = KeyBundleQuery {
        resource: resource.unwrap_or_default(),
        frontier,
        cursor,
        // A limit that is not a number is out of range, and refused as one.
        limit: limit.map(|text| text.parse().unwrap_or(0)),
    };
    answer(
        &served,
        StatusCode::OK,
        served.api.key_bundle(&actor, &query),
    )
}

/// The numbers of a query, by name; one that does not read leaves a message the facade refuses
/// once the resource is admitted.
fn numbers<const N: usize>(
    names: [&str; N],
    values: [Option<String>; N],
    malformed: &mut Option<String>,
) -> [Option<u64>; N] {
    let mut read = [None; N];
    for (index, value) in values.into_iter().enumerate() {
        if let Some(text) = value {
            match text.parse::<u64>() {
                Ok(number) => read[index] = Some(number),
                Err(_) => {
                    malformed.get_or_insert_with(|| {
                        format!("`{}` is an unsigned integer", names[index])
                    });
                }
            }
        }
    }
    read
}

async fn streams_list(State(served): State<Served>, ActorOf(actor): ActorOf) -> Response {
    answer(&served, StatusCode::OK, served.api.streams_list(&actor))
}

/// The query of a stream read: `resource`, and for `records` `producer`, `run`, `from` and
/// `limit`.
fn stream_query(query: Option<&str>) -> StreamQuery {
    let ([resource, producer, run, from, limit], mut malformed) =
        read_query(query, ["resource", "producer", "run", "from", "limit"]);
    let [from, limit] = numbers(["from", "limit"], [from, limit], &mut malformed);
    StreamQuery {
        resource: resource.unwrap_or_default(),
        producer,
        run,
        from,
        // A limit beyond 32 bits is out of range, and refused as one.
        limit: limit.map(|limit| u32::try_from(limit).unwrap_or(0)),
        malformed,
    }
}

async fn stream_frontier(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path((plane, stream_type)): Path<(String, String)>,
    RawQuery(query): RawQuery,
) -> Response {
    let query = stream_query(query.as_deref());
    answer(
        &served,
        StatusCode::OK,
        served
            .api
            .stream_frontier(&actor, &plane, &stream_type, &query),
    )
}

async fn stream_records(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path((plane, stream_type)): Path<(String, String)>,
    RawQuery(query): RawQuery,
) -> Response {
    let query = stream_query(query.as_deref());
    answer(
        &served,
        StatusCode::OK,
        served
            .api
            .stream_records(&actor, &plane, &stream_type, &query),
    )
}

async fn stream_signers(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path((plane, stream_type)): Path<(String, String)>,
    RawQuery(query): RawQuery,
) -> Response {
    let query = stream_query(query.as_deref());
    answer(
        &served,
        StatusCode::OK,
        served
            .api
            .stream_signers(&actor, &plane, &stream_type, &query),
    )
}

async fn stream_subscriptions(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path((plane, stream_type)): Path<(String, String)>,
    RawQuery(query): RawQuery,
) -> Response {
    let query = stream_query(query.as_deref());
    answer(
        &served,
        StatusCode::OK,
        served
            .api
            .stream_subscriptions(&actor, &plane, &stream_type, &query),
    )
}

async fn stream_gaps(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path((plane, stream_type)): Path<(String, String)>,
    RawQuery(query): RawQuery,
) -> Response {
    let query = stream_query(query.as_deref());
    answer(
        &served,
        StatusCode::OK,
        served.api.stream_gaps(&actor, &plane, &stream_type, &query),
    )
}

async fn stream_anchors(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path((plane, stream_type)): Path<(String, String)>,
    RawQuery(query): RawQuery,
) -> Response {
    let query = stream_query(query.as_deref());
    answer(
        &served,
        StatusCode::OK,
        served
            .api
            .stream_anchors(&actor, &plane, &stream_type, &query),
    )
}

async fn audit_records(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(class): Path<String>,
    RawQuery(query): RawQuery,
) -> Response {
    let ([resource, from, to, cursor, limit], mut malformed) = read_query(
        query.as_deref(),
        ["resource", "from", "to", "cursor", "limit"],
    );
    let [from, to, limit] = numbers(["from", "to", "limit"], [from, to, limit], &mut malformed);
    let query = AuditQuery {
        resource: resource.unwrap_or_default(),
        from,
        to,
        cursor,
        // A limit beyond 32 bits is out of range, and refused as one.
        limit: limit.map(|limit| u32::try_from(limit).unwrap_or(0)),
        malformed,
    };
    answer(
        &served,
        StatusCode::OK,
        served.api.audit_records(&actor, &class, &query),
    )
}

async fn audit_checkpoints(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(class): Path<String>,
    RawQuery(query): RawQuery,
) -> Response {
    let ([resource, period, membership], malformed) =
        read_query(query.as_deref(), ["resource", "period", "membership"]);
    if let Some(malformed) = malformed {
        return refuse_query(
            &served,
            &actor,
            &[operations::AUDIT_READ],
            resource.as_deref(),
            &malformed,
        );
    }
    let query = AuditCheckpointQuery {
        resource: resource.unwrap_or_default(),
        period,
        membership,
    };
    answer(
        &served,
        StatusCode::OK,
        served.api.audit_checkpoints(&actor, &class, &query),
    )
}

async fn audit_checkpoint(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(class): Path<String>,
    Closed(request): Closed<AuditCheckpointRequest>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.audit_checkpoint(&actor, &class, &request),
    )
}

async fn audit_export(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(class): Path<String>,
    RawQuery(query): RawQuery,
) -> Response {
    let ([resource, frontier, cursor, limit], mut malformed) = read_query(
        query.as_deref(),
        ["resource", "frontier", "cursor", "limit"],
    );
    let [frontier, limit] = numbers(["frontier", "limit"], [frontier, limit], &mut malformed);
    let query = AuditExportQuery {
        resource: resource.unwrap_or_default(),
        frontier,
        cursor,
        limit: limit.map(|limit| u32::try_from(limit).unwrap_or(0)),
        malformed,
    };
    answer(
        &served,
        StatusCode::OK,
        served.api.audit_export(&actor, &class, &query),
    )
}

async fn get_ring(State(served): State<Served>, Path(ring): Path<String>) -> Response {
    match served.api.ring(&ring) {
        Ok(view) => {
            let mut response = (StatusCode::OK, Json(&view)).into_response();
            if let Ok(value) = HeaderValue::from_str(&format!("max-age={}", view.cache_max_age)) {
                response.headers_mut().insert(header::CACHE_CONTROL, value);
            }
            response
        }
        Err(refusal) => served.refuse(&refusal),
    }
}

async fn rotate_ring(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(ring): Path<String>,
    Closed(rotate): Closed<RotateRing>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.rotate_ring(&actor, &ring, rotate).await,
    )
}

async fn plan_key_revoke(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(ring): Path<String>,
    Closed(plan): Closed<PlanKeyRevoke>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.plan_key_revoke(&actor, &ring, plan).await,
    )
}

async fn run_key_revoke(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(ring): Path<String>,
    Closed(run): Closed<RunKeyRevoke>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.run_key_revoke(&actor, &ring, run).await,
    )
}

async fn list_invites(State(served): State<Served>, ActorOf(actor): ActorOf) -> Response {
    answer(&served, StatusCode::OK, served.api.invites(&actor))
}

async fn create_invite(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Closed(invite): Closed<CreateInvite>,
) -> Response {
    answer(
        &served,
        StatusCode::CREATED,
        served.api.create_invite(&actor, invite).await,
    )
}

/// `DELETE` carries no body: its request id is the query's `request_id`.
async fn delete_invite(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(id): Path<String>,
    RawQuery(query): RawQuery,
) -> Response {
    let ([request_id], malformed) = read_query(query.as_deref(), ["request_id"]);
    if let Some(malformed) = malformed {
        return refuse_query(
            &served,
            &actor,
            &[operations::MEMBERSHIP_ADMIN],
            None,
            &malformed,
        );
    }
    let request_id = request_id.unwrap_or_default();
    answer(
        &served,
        StatusCode::OK,
        served.api.delete_invite(&actor, &id, request_id).await,
    )
}

/// An enrollment is never a request of its own: refused whoever asks, before any body is read.
async fn enroll_over_rest(State(served): State<Served>) -> Response {
    served.refuse(&served.api.enroll_over_rest())
}

async fn task_session_over_rest(State(served): State<Served>) -> Response {
    served.refuse(&served.api.task_session_over_rest())
}

async fn member_sessions(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(id): Path<String>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.member_sessions(&actor, &id),
    )
}

async fn list_plans(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    RawQuery(query): RawQuery,
) -> Response {
    let ([status], malformed) = read_query(query.as_deref(), ["status"]);
    if let Some(malformed) = malformed {
        return refuse_query(
            &served,
            &actor,
            &[
                operations::GC_MANAGE,
                operations::IDENTITY_ADMIN,
                operations::KEYS_ADMIN,
                operations::MEMBERSHIP_ADMIN,
            ],
            None,
            &malformed,
        );
    }
    answer(
        &served,
        StatusCode::OK,
        served.api.plans(&actor, status.as_deref()),
    )
}

async fn approve_plan(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(id): Path<String>,
    Closed(approve): Closed<permguard_host::api::plans::ApprovePlan>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.approve_plan(&actor, &id, approve).await,
    )
}

/// Runs `call` on the facade off the async workers (WP-7.8): the backup calls read the whole
/// volume or wait on a prepare that does. A call that panicked is `internal`.
async fn blocking<T: serde::Serialize + Send + 'static>(
    served: &Served,
    call: impl FnOnce(&HostApi) -> Result<T, Refusal> + Send + 'static,
) -> Response {
    let api = Arc::clone(&served.api);
    match tokio::task::spawn_blocking(move || call(&api)).await {
        Ok(answered) => answer(served, StatusCode::OK, answered),
        Err(error) => served.refuse(&Refusal::new(
            ErrorClass::Internal,
            codes::common::INTERNAL,
            format!("the call did not finish: {error}"),
        )),
    }
}

/// `POST /host/v1/backup/prepare` (WP-7.8).
async fn prepare_backup(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Closed(prepare): Closed<permguard_host::api::backups::PrepareBackup>,
) -> Response {
    blocking(&served, move |api| api.prepare_backup(&actor, prepare)).await
}

async fn finalize_backup(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Closed(finalize): Closed<permguard_host::api::backups::FinalizeBackup>,
) -> Response {
    blocking(&served, move |api| api.finalize_backup(&actor, finalize)).await
}

async fn abort_backup(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Closed(abort): Closed<permguard_host::api::backups::AbortBackup>,
) -> Response {
    blocking(&served, move |api| api.abort_backup(&actor, abort)).await
}

async fn list_backups(State(served): State<Served>, ActorOf(actor): ActorOf) -> Response {
    blocking(&served, move |api| api.list_backups(&actor)).await
}

/// `POST /host/v1/gc/{job}/plan` (WP-7.11b): the job's sweep is read off the async workers.
async fn plan_gc(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(job): Path<String>,
    Closed(plan): Closed<permguard_host::api::gc::PlanGc>,
) -> Response {
    blocking(&served, move |api| api.plan_gc(&actor, &job, plan)).await
}

/// `POST /host/v1/gc/{job}/run` (WP-7.11b).
async fn run_gc(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(job): Path<String>,
    Closed(run): Closed<permguard_host::api::gc::RunGc>,
) -> Response {
    blocking(&served, move |api| api.run_gc(&actor, &job, run)).await
}

async fn list_members(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    RawQuery(query): RawQuery,
) -> Response {
    let ([status], malformed) = read_query(query.as_deref(), ["status"]);
    if let Some(malformed) = malformed {
        return refuse_query(
            &served,
            &actor,
            &[operations::MEMBERSHIP_READ],
            None,
            &malformed,
        );
    }
    answer(
        &served,
        StatusCode::OK,
        served.api.members(&actor, status.as_deref()),
    )
}

async fn get_member(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(id): Path<String>,
) -> Response {
    answer(&served, StatusCode::OK, served.api.member(&actor, &id))
}

async fn approve_member(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(id): Path<String>,
    Closed(approve): Closed<ApproveMember>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.approve_member(&actor, &id, approve).await,
    )
}

async fn reject_member(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(id): Path<String>,
    Closed(change): Closed<ChangeMember>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.reject_member(&actor, &id, change).await,
    )
}

async fn suspend_member(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(id): Path<String>,
    Closed(change): Closed<ChangeMember>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.suspend_member(&actor, &id, change).await,
    )
}

async fn resume_member(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(id): Path<String>,
    Closed(change): Closed<ChangeMember>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.resume_member(&actor, &id, change).await,
    )
}

async fn fence_member(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(id): Path<String>,
    Closed(change): Closed<ChangeMember>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.fence_member(&actor, &id, change).await,
    )
}

async fn accept_import_gaps(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Closed(accept): Closed<permguard_host::api::imports::AcceptImportGaps>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.accept_import_gaps(&actor, accept).await,
    )
}

async fn change_member_record(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(id): Path<String>,
    Closed(change): Closed<ChangeMemberRecord>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.change_member_record(&actor, &id, change).await,
    )
}

async fn appraise_member(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(id): Path<String>,
    Closed(appraise): Closed<AppraiseMember>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.appraise_member(&actor, &id, appraise).await,
    )
}

async fn plan_member_revoke(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(id): Path<String>,
    Closed(plan): Closed<PlanMemberRevoke>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.plan_member_revoke(&actor, &id, plan).await,
    )
}

async fn run_member_revoke(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(id): Path<String>,
    Closed(run): Closed<RunMemberRevoke>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.run_member_revoke(&actor, &id, run).await,
    )
}

async fn join_membership(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Closed(join): Closed<JoinMembership>,
) -> Response {
    answer(
        &served,
        StatusCode::CREATED,
        served.api.join_membership(&actor, join).await,
    )
}

async fn sync_membership(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(id): Path<String>,
    Closed(sync): Closed<SyncMembership>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.sync_membership(&actor, &id, sync).await,
    )
}

async fn verify_member(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(id): Path<String>,
    Closed(verify): Closed<VerifyMember>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.verify_member(&actor, &id, verify).await,
    )
}

async fn status(State(served): State<Served>, ActorOf(actor): ActorOf) -> Response {
    answer(&served, StatusCode::OK, served.api.status(&actor))
}

async fn effective_config(State(served): State<Served>, ActorOf(actor): ActorOf) -> Response {
    answer(&served, StatusCode::OK, served.api.effective_config(&actor))
}

/// The values of `names` in `query`, percent-decoded, and why the query is not one of them when
/// it is not: a parameter nobody declared, one given twice, one without a value or with an empty
/// one (BUG-0167, DEC-0019). The values read are kept beside the refusal, the first of a repeated
/// one, so the route still names the resource it authorizes on before it refuses.
fn query_members(query: Option<&str>, names: &[&str]) -> (Vec<Option<String>>, Option<String>) {
    let mut values: Vec<Option<String>> = vec![None; names.len()];
    let mut malformed = None;
    for pair in query.unwrap_or_default().split('&') {
        if pair.is_empty() {
            continue;
        }
        let Some((name, value)) = pair.split_once('=') else {
            malformed.get_or_insert_with(|| format!("`{}` has no value", percent_decode(pair)));
            continue;
        };
        let name = percent_decode(name);
        let Some(index) = names.iter().position(|wanted| *wanted == name) else {
            malformed.get_or_insert_with(|| {
                format!(
                    "`{name}` is not a parameter of this request: it takes {}",
                    names.join(", ")
                )
            });
            continue;
        };
        if values[index].is_some() {
            malformed.get_or_insert_with(|| format!("`{name}` is given more than once"));
            continue;
        }
        if value.is_empty() {
            malformed
                .get_or_insert_with(|| format!("`{name}` is empty: leave it out to mean none"));
            continue;
        }
        values[index] = Some(percent_decode(value));
    }
    (values, malformed)
}

/// [`query_members`] for `N` names.
fn read_query<const N: usize>(
    query: Option<&str>,
    names: [&str; N],
) -> ([Option<String>; N], Option<String>) {
    let (values, malformed) = query_members(query, &names);
    (
        <[Option<String>; N]>::try_from(values).unwrap_or_else(|_| std::array::from_fn(|_| None)),
        malformed,
    )
}

/// The answer to a query `refuse_query` found malformed: `invalid_argument`, but only to a
/// caller holding one of `operations` on the route's resource (`resource` when the query named
/// a well-formed one, the Host otherwise); anyone else is refused as the route refuses them, and
/// learns nothing of what the query said.
fn refuse_query(
    served: &Served,
    actor: &permguard_core::authz::Actor,
    operations: &[&str],
    resource: Option<&str>,
    malformed: &str,
) -> Response {
    let resource = resource
        .and_then(|resource| permguard_core::authz::Resource::parse(resource).ok())
        .unwrap_or_else(permguard_core::authz::Resource::host);
    served.refuse(
        &served
            .api
            .refuse_query(actor, operations, &resource, malformed),
    )
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let escaped = bytes[index] == b'%'
            && index + 2 < bytes.len()
            && bytes[index + 1].is_ascii_hexdigit()
            && bytes[index + 2].is_ascii_hexdigit();
        if escaped {
            let pair = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("00");
            decoded.push(u8::from_str_radix(pair, 16).unwrap_or(b'%'));
            index += 3;
            continue;
        }
        decoded.push(if bytes[index] == b'+' {
            b' '
        } else {
            bytes[index]
        });
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

// Roles, local users and identity providers (WP-8.1).

#[cfg(test)]
mod tests {
    #[test]
    fn query_members_decode_and_refuse_what_is_not_one_of_them() {
        let (values, malformed) = super::query_members(
            Some("selector=plane%2Fcontrol%2F*&principal=spiffe%3A%2F%2Facme%2Fa"),
            &["principal", "selector"],
        );
        assert_eq!(malformed, None);
        assert_eq!(values[0].as_deref(), Some("spiffe://acme/a"));
        assert_eq!(values[1].as_deref(), Some("plane/control/*"));
        assert_eq!(
            super::query_members(Some(""), &["principal"]),
            (vec![None], None),
            "an absent parameter is absent"
        );
        assert_eq!(
            super::percent_decode("a+b%2"),
            "a b%2",
            "a dangling escape is kept as written"
        );
        assert_eq!(super::percent_decode("%zz"), "%zz");
        assert_eq!(super::percent_decode("%41%4a"), "AJ");
        // BUG-0167: unknown, repeated, empty and valueless parameters are refused by name.
        for (query, said) in [
            ("principal=a&other=1", "`other` is not a parameter"),
            (
                "principal=a&principal=b",
                "`principal` is given more than once",
            ),
            ("principal=&selector=x", "`principal` is empty"),
            ("principal", "`principal` has no value"),
        ] {
            let (_, refused) = super::query_members(Some(query), &["principal", "selector"]);
            let Some(refused) = refused else {
                panic!("{query} was read as well formed");
            };
            assert!(refused.contains(said), "{query}: {refused}");
        }
    }
}
